#ifndef HARDWARE_PROFILE_H
#define HARDWARE_PROFILE_H

#include <cstdint>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <cctype>
#include <algorithm>
#include <thread>
#include <fstream>
#include <sstream>
#include <string>
#include <ctime>

#if defined(_WIN32) && !defined(__CYGWIN__)
#include <windows.h>
#else
#include <unistd.h>
#include <sys/sysinfo.h>
#endif

struct HardwareProfile {
    int logical_threads;
    double total_ram_gb;
    double available_ram_gb;
    bool is_wsl;
    bool is_windows;
    bool is_linux;
};

inline bool equals_ignore_case(const char* a, const char* b) {
    if (a == nullptr || b == nullptr) {
        return false;
    }
    while (*a && *b) {
        if (std::tolower(static_cast<unsigned char>(*a)) != std::tolower(static_cast<unsigned char>(*b))) {
            return false;
        }
        ++a;
        ++b;
    }
    return *a == '\0' && *b == '\0';
}

#if defined(__linux__) || defined(__CYGWIN__)
inline double read_meminfo_value_gb(const char* key) {
    FILE* f = fopen("/proc/meminfo", "r");
    if (!f) {
        return 0.0;
    }
    char name[64];
    unsigned long long kb = 0;
    char unit[32];
    while (fscanf(f, "%63[^:]: %llu %31s\n", name, &kb, unit) == 3) {
        if (strcmp(name, key) == 0) {
            fclose(f);
            return static_cast<double>(kb) / 1048576.0;
        }
    }
    fclose(f);
    return 0.0;
}

inline bool detect_wsl() {
    if (getenv("WSL_INTEROP") != nullptr || getenv("WSL_DISTRO_NAME") != nullptr) {
        return true;
    }
    FILE* f = fopen("/proc/version", "r");
    if (!f) {
        return false;
    }
    char buffer[512];
    const bool ok = fgets(buffer, sizeof(buffer), f) != nullptr &&
        (strstr(buffer, "Microsoft") != nullptr || strstr(buffer, "WSL") != nullptr);
    fclose(f);
    return ok;
}
#endif

inline HardwareProfile detect_hardware_profile() {
    HardwareProfile hw{};
    hw.logical_threads = std::max(1u, std::thread::hardware_concurrency());
    
#if defined(_WIN32) && !defined(__CYGWIN__)
    hw.is_windows = true;
    hw.is_linux = false;
    hw.is_wsl = false;
    MEMORYSTATUSEX mem_status;
    memset(&mem_status, 0, sizeof(mem_status));
    mem_status.dwLength = sizeof(mem_status);
    if (GlobalMemoryStatusEx(&mem_status)) {
        hw.total_ram_gb = static_cast<double>(mem_status.ullTotalPhys) / 1073741824.0;
        hw.available_ram_gb = static_cast<double>(mem_status.ullAvailPhys) / 1073741824.0;
    }
#else
    hw.is_windows = false;
    hw.is_linux = true;
    #if defined(__linux__) || defined(__CYGWIN__)
    hw.is_wsl = detect_wsl();
    #else
    hw.is_wsl = false;
    #endif
    const long page_size = sysconf(_SC_PAGESIZE);
    const long phys_pages = sysconf(_SC_PHYS_PAGES);
    if (page_size > 0 && phys_pages > 0) {
        hw.total_ram_gb = (static_cast<double>(page_size) * static_cast<double>(phys_pages)) / 1073741824.0;
    }
    #if defined(__linux__) || defined(__CYGWIN__)
    hw.available_ram_gb = read_meminfo_value_gb("MemAvailable");
    if (hw.available_ram_gb <= 0.0) {
        hw.available_ram_gb = read_meminfo_value_gb("MemFree");
    }
    #else
    hw.available_ram_gb = hw.total_ram_gb * 0.5;
    #endif
#endif
    
    if (hw.total_ram_gb <= 0.0) {
        hw.total_ram_gb = 4.0;
    }
    if (hw.available_ram_gb <= 0.0) {
        hw.available_ram_gb = std::max(1.0, hw.total_ram_gb * 0.5);
    }
    return hw;
}

inline double compute_safe_ram_gb(const HardwareProfile& hw, const char* profile_name) {
    double available_factor = 0.60;
    double total_factor = 0.50;
    if (equals_ignore_case(profile_name, "safe")) {
        available_factor = 0.45;
        total_factor = 0.35;
    } else if (equals_ignore_case(profile_name, "max")) {
        available_factor = 0.75;
        total_factor = 0.65;
    }
    if (hw.is_wsl) {
        available_factor -= 0.10;
        total_factor -= 0.10;
    }
    available_factor = std::max(0.20, available_factor);
    total_factor = std::max(0.20, total_factor);
    return std::max(0.5, std::min(hw.available_ram_gb * available_factor, hw.total_ram_gb * total_factor));
}

inline void print_hardware_info(const HardwareProfile& hw) {
    printf("[i] Hardware detectado: threads=%d | RAM total=%.1f GB | RAM disponivel=%.1f GB | %s%s\n",
           hw.logical_threads,
           hw.total_ram_gb,
           hw.available_ram_gb,
           hw.is_wsl ? "WSL " : "",
           hw.is_windows ? "Windows" : "Linux");
}

inline std::string get_profile_file_path() {
    const char* home = std::getenv("HOME");
    if (!home) {
        home = std::getenv("USERPROFILE");
    }
    if (home) {
        return std::string(home) + "/.qchaves_profile.json";
    }
    return ".qchaves_profile.json";
}

inline bool save_profile_to_json(const std::string& motor, const std::string& profile_mode, 
                                  int threads, int k, uint64_t n, double ram_gb) {
    std::string path = get_profile_file_path();
    std::ifstream infile(path);
    std::string json_content = "";
    
    if (infile.good()) {
        std::getline(infile, json_content, '\0');
    }
    infile.close();
    
    std::ofstream outfile(path);
    if (!outfile.is_open()) {
        return false;
    }
    
    outfile << "{\n";
    outfile << "  \"motor\": \"" << motor << "\",\n";
    outfile << "  \"profile\": \"" << profile_mode << "\",\n";
    outfile << "  \"threads\": " << threads << ",\n";
    outfile << "  \"k\": " << k << ",\n";
    outfile << "  \"n\": " << n << ",\n";
    outfile << "  \"ram_gb\": " << ram_gb << ",\n";
    outfile << "  \"timestamp\": " << time(nullptr) << "\n";
    outfile << "}\n";
    outfile.close();
    return true;
}

inline bool load_profile_from_json(const std::string& motor, int* out_threads, int* out_k, uint64_t* out_n) {
    std::string path = get_profile_file_path();
    std::ifstream infile(path);
    
    if (!infile.is_open()) {
        return false;
    }
    
    std::string content((std::istreambuf_iterator<char>(infile)),
                         std::istreambuf_iterator<char>());
    infile.close();
    
    if (content.find("\"motor\": \"" + motor + "\"") == std::string::npos) {
        return false;
    }
    
    auto extract_int = [&](const std::string& key) -> int {
        size_t pos = content.find("\"" + key + "\": ");
        if (pos == std::string::npos) return -1;
        pos += key.size() + 4;
        size_t end = content.find_first_of(",\n}", pos);
        if (end == std::string::npos) return -1;
        return std::stoi(content.substr(pos, end - pos));
    };
    
    if (out_threads) *out_threads = extract_int("threads");
    if (out_k) *out_k = extract_int("k");
    if (out_n) *out_n = extract_int("n");
    
    return true;
}

#endif
