#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <algorithm>
#include <thread>
#include <array>
#include <atomic>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cctype>
#include <limits>
#include <getopt.h>
#include <unistd.h>
#include <gmp.h>

// --- CONFIGURACAO UNITY BUILD (libsecp256k1 interna) ---
#define USE_BASIC_CONFIG 1
#define SECP256K1_WIDEMUL_INT128 1
#define SECP256K1_INLINE inline
#define SECP256K1_FE_INLINE inline
#define SECP256K1_SCALAR_INLINE inline

extern "C" {
    #define SECP256K1_CPLUSPLUS_TEST_OVERRIDE 1
    #include "../../libs/libsecp256k1/src/secp256k1.c"
    #include "../../libs/libsecp256k1/src/precomputed_ecmult.c"
    #include "../../libs/libsecp256k1/src/precomputed_ecmult_gen.c"
}

#include "../../libs/libsecp256k1/src/field_impl.h"
#include "../../libs/libsecp256k1/src/group_impl.h"
#include "../../libs/util.h"
#include "../../libs/base58/libbase58.h"
#include "../../libs/hash/sha256.h"
#include "../../libs/rmd160/rmd160.h"

#include <mutex>
#include <unordered_map>
#include <signal.h>

#define FLEET_SIZE 64
#define HALF_FLEET 32
#define JUMP_COUNT 64
#define TRAP_SHARDS 16
#define CHECKPOINT_VERSION 3
#define EARLY_TERMINATION_THRESHOLD 1000000ULL

struct Kangaroo {
    secp256k1_gej point;
    bool is_wild;
};

struct Jump {
    secp256k1_ge point;
};

struct XKey {
    unsigned char bytes[32];

    bool operator==(const XKey& other) const {
        return memcmp(bytes, other.bytes, sizeof(bytes)) == 0;
    }
};

struct XKeyHasher {
    size_t operator()(const XKey& key) const {
        uint64_t v0 = 0;
        uint64_t v1 = 0;
        uint64_t v2 = 0;
        uint64_t v3 = 0;
        memcpy(&v0, key.bytes + 0, 8);
        memcpy(&v1, key.bytes + 8, 8);
        memcpy(&v2, key.bytes + 16, 8);
        memcpy(&v3, key.bytes + 24, 8);
        return static_cast<size_t>(v0 ^ (v1 << 1) ^ (v2 << 2) ^ (v3 << 3));
    }
};

struct TrapEntry {
    XKey x;
    std::array<unsigned char, 32> distance_bytes;
    bool is_wild;
};

struct UInt192 {
    uint64_t lo;
    uint64_t mid;
    uint64_t hi;
};

struct ThreadContext {
    int id;
    Kangaroo fleet[FLEET_SIZE];
    UInt192 fleet_dists[FLEET_SIZE];
    unsigned char x_cache[FLEET_SIZE][32];
    bool x_cache_dirty;
    uint64_t hops;
    std::mutex mutex;
};

struct TrapShard {
    std::unordered_map<XKey, TrapEntry, XKeyHasher> table;
    std::mutex mutex;
};

struct DPCandidate {
    XKey x;
    std::array<unsigned char, 32> distance_bytes;
    bool is_wild;
};

using SnapshotMap = std::unordered_map<XKey, DPCandidate, XKeyHasher>;

std::vector<ThreadContext*> threads_data;
Jump jump_set[JUMP_COUNT];
UInt192 jump_dists[JUMP_COUNT];
mpz_t ORDER_N;
UInt192 RANGE_START_U192;
UInt192 RANGE_END_U192;
UInt192 RANGE_SPAN_U192;
int RANGE_BITS = 0;
bool HAS_RANGE_END = false;
secp256k1_context* ctx_global = nullptr;
secp256k1_gej TARGET_PUBKEY_GEJ;
unsigned char TARGET_PUBKEY_COMPRESSED[33];
std::atomic<uint64_t> TOTAL_HOPS(0);
std::atomic<uint64_t> TOTAL_TRAPS(0);
std::atomic<uint64_t> TOTAL_DPS(0);
std::atomic<uint64_t> TOTAL_FLUSHES(0);
std::atomic<bool> SHOULD_SAVE(false);
std::atomic<bool> KEY_FOUND_FLAG(false);
std::atomic<bool> FLUSH_IN_PROGRESS(false);
std::atomic<uint64_t> TIME_JUMPS_NS(0);
std::atomic<uint64_t> TIME_CACHE_NS(0);
std::atomic<uint64_t> TIME_TRAPS_NS(0);
std::atomic<uint64_t> TIME_ARCHIVE_NS(0);
std::array<TrapShard, TRAP_SHARDS> trap_shards;
uint64_t TRAP_CAPACITY = 0;
uint64_t TRAP_BYTES_ESTIMATE = 0;

int N_THREADS = 1;
int FLAG_BITRANGE = 0;
uint64_t DP_MASK = 0xFFFFF00000000000ULL;
double MAX_RAM_GB = 4.0;
std::string RANGE_START = "1";
std::string RANGE_END = "";
std::string TARGET_PUBKEY_HEX = "";
int ACTIVE_JUMP_COUNT = JUMP_COUNT;
int ACTIVE_WILD_COUNT = HALF_FLEET;
bool FLAG_AUTO_PROFILE = false;
std::string AUTO_PROFILE_MODE = "balanced";
bool OVERRIDE_THREADS = false;
bool OVERRIDE_DP = false;
bool OVERRIDE_RAM = false;
bool OVERRIDE_JUMPS = false;
bool OVERRIDE_WILD = false;

struct HardwareProfile {
    int logical_threads;
    double total_ram_gb;
    double available_ram_gb;
    bool is_wsl;
    bool is_windows;
    bool is_linux;
};

struct KangarooAutoConfig {
    int threads;
    int dp_bits;
    double ram_gb;
    int jumps;
    int wild;
    const char* profile_name;
};

static inline bool equals_ignore_case(const char* a, const char* b) {
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

double read_meminfo_value_gb(const char* key) {
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

bool detect_wsl() {
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

HardwareProfile detect_hardware_profile() {
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
    hw.is_wsl = detect_wsl();
    const long page_size = sysconf(_SC_PAGESIZE);
    const long phys_pages = sysconf(_SC_PHYS_PAGES);
    if (page_size > 0 && phys_pages > 0) {
        hw.total_ram_gb = (static_cast<double>(page_size) * static_cast<double>(phys_pages)) / 1073741824.0;
    }
    hw.available_ram_gb = read_meminfo_value_gb("MemAvailable");
    if (hw.available_ram_gb <= 0.0) {
        hw.available_ram_gb = read_meminfo_value_gb("MemFree");
    }
#endif
    if (hw.total_ram_gb <= 0.0) {
        hw.total_ram_gb = 4.0;
    }
    if (hw.available_ram_gb <= 0.0) {
        hw.available_ram_gb = std::max(1.0, hw.total_ram_gb * 0.5);
    }
    return hw;
}

double compute_safe_ram_gb(const HardwareProfile& hw, const char* profile_name) {
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

KangarooAutoConfig compute_kangaroo_auto_config(const HardwareProfile& hw, const std::string& profile_mode) {
    KangarooAutoConfig cfg{};
    cfg.profile_name = profile_mode.c_str();

    bool is_low_end = hw.logical_threads <= 4 || hw.total_ram_gb < 8.0;
    bool is_high_end = hw.logical_threads >= 16 && hw.total_ram_gb >= 32.0;

    int threads;
    int jumps;
    int wild;

    if (equals_ignore_case(profile_mode.c_str(), "safe")) {
        threads = std::max(1, hw.logical_threads / 2);
        if (is_low_end) {
            jumps = 16;
            wild = 8;
        } else if (is_high_end) {
            jumps = 48;
            wild = 32;
        } else {
            jumps = 32;
            wild = 24;
        }
    } else if (equals_ignore_case(profile_mode.c_str(), "max")) {
        threads = std::max(1, hw.logical_threads);
        if (hw.total_ram_gb >= 64.0) {
            jumps = 96;
            wild = 64;
        } else if (hw.total_ram_gb >= 32.0) {
            jumps = 64;
            wild = 48;
        } else {
            jumps = 64;
            wild = 40;
        }
    } else {
        threads = hw.logical_threads > 4 ? hw.logical_threads - 1 : hw.logical_threads;
        if (is_low_end) {
            jumps = 24;
            wild = 12;
        } else if (is_high_end) {
            jumps = 64;
            wild = 48;
        } else {
            jumps = 48;
            wild = 32;
        }
    }

    cfg.threads = std::max(1, std::min(threads, 256));
    cfg.ram_gb = compute_safe_ram_gb(hw, profile_mode.c_str());
    cfg.ram_gb = std::max(0.5, std::floor(cfg.ram_gb * 2.0) / 2.0);
    cfg.jumps = std::max(1, std::min(jumps, JUMP_COUNT));
    cfg.wild = std::max(0, std::min(wild, FLEET_SIZE));

    if (cfg.ram_gb >= 24.0) {
        cfg.dp_bits = 23;
    } else if (cfg.ram_gb >= 12.0) {
        cfg.dp_bits = 22;
    } else if (cfg.ram_gb >= 6.0) {
        cfg.dp_bits = 21;
    } else {
        cfg.dp_bits = 20;
    }

    if (equals_ignore_case(profile_mode.c_str(), "safe")) {
        cfg.dp_bits = std::max(cfg.dp_bits, 22);
    } else if (equals_ignore_case(profile_mode.c_str(), "max")) {
        cfg.dp_bits = std::max(20, cfg.dp_bits - 1);
    }
    cfg.dp_bits = std::max(1, std::min(cfg.dp_bits, 64));
    return cfg;
}

void apply_auto_profile_if_needed() {
    if (!FLAG_AUTO_PROFILE) {
        return;
    }
    const HardwareProfile hw = detect_hardware_profile();
    const KangarooAutoConfig cfg = compute_kangaroo_auto_config(hw, AUTO_PROFILE_MODE);

    if (!OVERRIDE_THREADS) {
        N_THREADS = cfg.threads;
    }
    if (!OVERRIDE_DP) {
        const int bits = cfg.dp_bits;
        if (bits <= 0) {
            DP_MASK = 0;
        } else if (bits == 64) {
            DP_MASK = ~0ULL;
        } else {
            DP_MASK = ~((1ULL << (64 - bits)) - 1);
        }
    }
    if (!OVERRIDE_RAM) {
        MAX_RAM_GB = cfg.ram_gb;
    }
    if (!OVERRIDE_JUMPS) {
        ACTIVE_JUMP_COUNT = cfg.jumps;
    }
    if (!OVERRIDE_WILD) {
        ACTIVE_WILD_COUNT = cfg.wild;
    }

    printf("[i] Hardware detectado: threads=%d | RAM total=%.1f GB | RAM disponivel=%.1f GB | %s%s\n",
           hw.logical_threads,
           hw.total_ram_gb,
           hw.available_ram_gb,
           hw.is_wsl ? "WSL " : "",
           hw.is_windows ? "Windows" : "Linux");
    printf("[i] Auto profile (%s): -t %d -d %d -m %.1f -j %d -w %d\n",
           AUTO_PROFILE_MODE.c_str(),
           cfg.threads,
           cfg.dp_bits,
           cfg.ram_gb,
           cfg.jumps,
           cfg.wild);
    if (OVERRIDE_THREADS || OVERRIDE_DP || OVERRIDE_RAM || OVERRIDE_JUMPS || OVERRIDE_WILD) {
        printf("[i] Overrides manuais preservados para flags explicitas.\n");
    }
}

void save_checkpoint();
bool load_checkpoint();
void export_mpz_32(mpz_t value, unsigned char out[32]);

static inline uint64_t bswap64_local(uint64_t value) {
#if defined(_MSC_VER)
    return _byteswap_uint64(value);
#else
    return __builtin_bswap64(value);
#endif
}

static inline uint64_t bytes_to_u64_be(const unsigned char* bytes) {
    uint64_t value = 0;
    memcpy(&value, bytes, sizeof(value));
    return bswap64_local(value);
}

UInt192 u192_zero() {
    return UInt192{0, 0, 0};
}

UInt192 u192_from_u64(uint64_t value) {
    return UInt192{value, 0, 0};
}

bool u192_is_zero(const UInt192& value) {
    return value.lo == 0 && value.mid == 0 && value.hi == 0;
}

int u192_compare(const UInt192& a, const UInt192& b) {
    if (a.hi != b.hi) return a.hi < b.hi ? -1 : 1;
    if (a.mid != b.mid) return a.mid < b.mid ? -1 : 1;
    if (a.lo != b.lo) return a.lo < b.lo ? -1 : 1;
    return 0;
}

int u192_bit_length(const UInt192& value) {
    if (value.hi != 0) {
        return 128 + (64 - __builtin_clzll(value.hi));
    }
    if (value.mid != 0) {
        return 64 + (64 - __builtin_clzll(value.mid));
    }
    if (value.lo != 0) {
        return 64 - __builtin_clzll(value.lo);
    }
    return 0;
}

void u192_add_u64_inplace(UInt192& value, uint64_t addend) {
    const uint64_t old_lo = value.lo;
    value.lo += addend;
    if (value.lo < old_lo) {
        const uint64_t old_mid = value.mid;
        value.mid += 1;
        if (value.mid < old_mid) {
            value.hi += 1;
        }
    }
}

void u192_add_inplace(UInt192& value, const UInt192& addend) {
    const uint64_t old_lo = value.lo;
    value.lo += addend.lo;
    uint64_t carry = value.lo < old_lo ? 1ULL : 0ULL;

    const uint64_t old_mid = value.mid;
    value.mid += addend.mid;
    if (value.mid < old_mid) {
        carry += 1ULL;
    }
    const uint64_t mid_before_carry = value.mid;
    value.mid += carry;
    carry = value.mid < mid_before_carry ? 1ULL : 0ULL;

    value.hi += addend.hi + carry;
}

UInt192 u192_add(const UInt192& a, const UInt192& b) {
    UInt192 result = a;
    u192_add_inplace(result, b);
    return result;
}

UInt192 u192_subtract(const UInt192& a, const UInt192& b) {
    UInt192 result = a;
    uint64_t borrow = result.lo < b.lo ? 1 : 0;
    result.lo -= b.lo;
    const uint64_t b_mid = b.mid + borrow;
    borrow = (result.mid < b_mid || (borrow && b_mid == 0)) ? 1 : 0;
    result.mid -= b_mid;
    result.hi -= b.hi + borrow;
    return result;
}

void u192_subtract_inplace(UInt192& value, const UInt192& sub) {
    value = u192_subtract(value, sub);
}

void u192_shift_left_one(UInt192& value) {
    value.hi = (value.hi << 1) | (value.mid >> 63);
    value.mid = (value.mid << 1) | (value.lo >> 63);
    value.lo <<= 1;
}

void u192_set_bit(UInt192& value, unsigned bit_index) {
    if (bit_index < 64U) {
        value.lo |= (1ULL << bit_index);
    } else if (bit_index < 128U) {
        value.mid |= (1ULL << (bit_index - 64U));
    } else if (bit_index < 192U) {
        value.hi |= (1ULL << (bit_index - 128U));
    }
}

UInt192 u192_div_u32(const UInt192& value, uint32_t divisor, uint32_t* remainder_out = nullptr) {
    UInt192 quotient = u192_zero();
    uint64_t remainder = 0;
    for (int part = 2; part >= 0; --part) {
        const uint64_t limb = part == 2 ? value.hi : (part == 1 ? value.mid : value.lo);
        const unsigned __int128 cur = (static_cast<unsigned __int128>(remainder) << 64) | limb;
        const uint64_t q = static_cast<uint64_t>(cur / divisor);
        remainder = static_cast<uint64_t>(cur % divisor);
        if (part == 2) quotient.hi = q;
        else if (part == 1) quotient.mid = q;
        else quotient.lo = q;
    }
    if (remainder_out != nullptr) {
        *remainder_out = static_cast<uint32_t>(remainder);
    }
    return quotient;
}

bool u192_from_mpz(mpz_t value, UInt192& out) {
    unsigned char bytes[32];
    export_mpz_32(value, bytes);
    for (int i = 0; i < 8; ++i) {
        if (bytes[i] != 0) {
            return false;
        }
    }
    out.hi = bytes_to_u64_be(bytes + 8);
    out.mid = bytes_to_u64_be(bytes + 16);
    out.lo = bytes_to_u64_be(bytes + 24);
    return true;
}

void u192_to_mpz(const UInt192& value, mpz_t out) {
    unsigned char bytes[24];
    for (int i = 0; i < 8; ++i) {
        bytes[i] = static_cast<unsigned char>((value.hi >> (56 - (i * 8))) & 0xFF);
        bytes[8 + i] = static_cast<unsigned char>((value.mid >> (56 - (i * 8))) & 0xFF);
        bytes[16 + i] = static_cast<unsigned char>((value.lo >> (56 - (i * 8))) & 0xFF);
    }
    mpz_import(out, 24, 1, 1, 1, 0, bytes);
}

void u192_set_pow2(UInt192& value, unsigned exponent) {
    value = u192_zero();
    u192_set_bit(value, exponent);
}

bool u192_to_u64(const UInt192& value, uint64_t& out) {
    if (value.hi != 0 || value.mid != 0) {
        return false;
    }
    out = value.lo;
    return true;
}

void u192_to_bytes32(const UInt192& value, unsigned char out[32]) {
    memset(out, 0, 32);
    for (int i = 0; i < 8; ++i) {
        out[8 + i] = static_cast<unsigned char>((value.hi >> (56 - (i * 8))) & 0xFF);
        out[16 + i] = static_cast<unsigned char>((value.mid >> (56 - (i * 8))) & 0xFF);
        out[24 + i] = static_cast<unsigned char>((value.lo >> (56 - (i * 8))) & 0xFF);
    }
}

bool u192_from_bytes32(const unsigned char in[32], UInt192& out) {
    for (int i = 0; i < 8; ++i) {
        if (in[i] != 0) {
            return false;
        }
    }
    out.hi = bytes_to_u64_be(in + 8);
    out.mid = bytes_to_u64_be(in + 16);
    out.lo = bytes_to_u64_be(in + 24);
    return true;
}

void signal_handler(int sig) {
    if (sig == SIGINT) {
        printf("\n[!] Interrupcao detectada. Finalizando e salvando...\n");
        SHOULD_SAVE = true;
    }
}

void write_mpz(FILE* f, mpz_t m) {
    size_t count = 0;
    unsigned char* data = (unsigned char*)mpz_export(NULL, &count, 1, 1, 1, 0, m);
    uint32_t len = (uint32_t)count;
    fwrite(&len, 4, 1, f);
    if (len > 0) {
        fwrite(data, 1, len, f);
    }
    free(data);
}

void read_mpz(FILE* f, mpz_t m) {
    uint32_t len = 0;
    if (fread(&len, 4, 1, f) != 1) {
        mpz_set_ui(m, 0);
        return;
    }
    if (len == 0) {
        mpz_set_ui(m, 0);
        return;
    }

    unsigned char* data = (unsigned char*)malloc(len);
    if (data == nullptr) {
        mpz_set_ui(m, 0);
        fseek(f, len, SEEK_CUR);
        return;
    }
    if (fread(data, 1, len, f) != len) {
        free(data);
        mpz_set_ui(m, 0);
        return;
    }
    mpz_import(m, len, 1, 1, 1, 0, data);
    free(data);
}

void export_mpz_32(mpz_t value, unsigned char out[32]) {
    memset(out, 0, 32);
    size_t count = 0;
    unsigned char* data = (unsigned char*)mpz_export(NULL, &count, 1, 1, 1, 0, value);
    if (data != nullptr) {
        if (count > 32) {
            memcpy(out, data + (count - 32), 32);
        } else if (count > 0) {
            memcpy(out + (32 - count), data, count);
        }
        free(data);
    }
}

void import_mpz_32(const unsigned char in[32], mpz_t value) {
    mpz_import(value, 32, 1, 1, 1, 0, in);
}

bool gej_from_mpz_scalar(mpz_t scalar_value, secp256k1_gej* out) {
    unsigned char scalar_bin[32];
    secp256k1_scalar scalar;
    int overflow = 0;

    export_mpz_32(scalar_value, scalar_bin);
    secp256k1_scalar_set_b32(&scalar, scalar_bin, &overflow);
    if (overflow) {
        return false;
    }
    secp256k1_ecmult_gen(&ctx_global->ecmult_gen_ctx, out, &scalar);
    return true;
}

bool gej_to_pubkey33(const secp256k1_gej* point, unsigned char out33[33]) {
    secp256k1_ge affine;
    secp256k1_gej tmp = *point;
    secp256k1_ge_set_gej(&affine, &tmp);
    secp256k1_fe_normalize(&affine.x);
    secp256k1_fe_normalize(&affine.y);
    secp256k1_eckey_pubkey_serialize33(&affine, out33);
    return true;
}

bool pubkey33_to_gej(const unsigned char in33[33], secp256k1_gej* out) {
    secp256k1_pubkey pub;
    secp256k1_ge ge;
    if (!secp256k1_ec_pubkey_parse(ctx_global, &pub, in33, 33)) {
        return false;
    }
    if (!secp256k1_pubkey_load(ctx_global, &ge, &pub)) {
        return false;
    }
    secp256k1_gej_set_ge(out, &ge);
    return true;
}

void rmd160toaddress_dst(const unsigned char* rmd, char* dst) {
    unsigned char digest[60];
    size_t pubaddress_size = 40;
    digest[0] = 0;
    memcpy(digest + 1, rmd, 20);
    sha256(digest, 21, digest + 21);
    sha256(digest + 21, 32, digest + 21);
    if (!b58enc(dst, &pubaddress_size, digest, 25)) {
        strcpy(dst, "(ADR_ERR)");
    }
}

void generate_wif(bool compressed, const unsigned char* priv_bytes, char* dst) {
    unsigned char raw[38];
    unsigned char checksum[32];
    raw[0] = 0x80;
    memcpy(raw + 1, priv_bytes, 32);
    int payload_len = 33;
    if (compressed) {
        raw[33] = 0x01;
        payload_len = 34;
    }
    sha256(raw, payload_len, checksum);
    sha256(checksum, 32, checksum);
    memcpy(raw + payload_len, checksum, 4);
    size_t wif_size = 53;
    if (!b58enc(dst, &wif_size, raw, payload_len + 4)) {
        strcpy(dst, "(WIF_ERR)");
    }
}

bool validate_hit(mpz_t key_found) {
    unsigned char priv_bytes[32];
    secp256k1_pubkey pubkey;
    unsigned char pub_serialized[33];
    size_t pub_len = sizeof(pub_serialized);

    export_mpz_32(key_found, priv_bytes);
    if (!secp256k1_ec_pubkey_create(ctx_global, &pubkey, priv_bytes)) {
        return false;
    }
    if (!secp256k1_ec_pubkey_serialize(ctx_global, pub_serialized, &pub_len, &pubkey, SECP256K1_EC_COMPRESSED)) {
        return false;
    }
    return pub_len == sizeof(TARGET_PUBKEY_COMPRESSED) &&
           memcmp(pub_serialized, TARGET_PUBKEY_COMPRESSED, sizeof(TARGET_PUBKEY_COMPRESSED)) == 0;
}

void print_hit_premium(mpz_t key_found) {
    unsigned char priv_bytes[32];
    secp256k1_pubkey pubkey;
    unsigned char pub_serialized[33];
    size_t pub_len = sizeof(pub_serialized);
    char address[50] = {0};
    char wif[56] = {0};
    char pub_hex[67] = {0};
    unsigned char sha256_res[32];
    unsigned char rmdhash[20];

    export_mpz_32(key_found, priv_bytes);
    if (!secp256k1_ec_pubkey_create(ctx_global, &pubkey, priv_bytes) ||
        !secp256k1_ec_pubkey_serialize(ctx_global, pub_serialized, &pub_len, &pubkey, SECP256K1_EC_COMPRESSED)) {
        fprintf(stderr, "\n[E] Falha ao serializar pubkey da chave encontrada.\n");
        return;
    }

    sha256(pub_serialized, 33, sha256_res);
    RMD160Data(sha256_res, 32, (char*)rmdhash);
    rmd160toaddress_dst(rmdhash, address);
    generate_wif(true, priv_bytes, wif);

    char* hex_priv = mpz_get_str(NULL, 16, key_found);
    char* dec_priv = mpz_get_str(NULL, 10, key_found);
    tohex_dst((char*)pub_serialized, 33, pub_hex);

    printf("\n\033[1;32m+----------------- Quantum Solution Detected -----------------+\033[0m\n");
    printf("\033[1;32m|  \033[1;92mSUCESSO! CHAVE ENCONTRADA\033[0m\n");
    printf("\033[1;32m|  \033[0mPuzzle ID      : \033[1;33m#%d\033[0m\n", FLAG_BITRANGE);
    printf("\033[1;32m|  \033[0mChave Privada  : \033[1;36m0x%s\033[0m\n", hex_priv);
    printf("\033[1;32m|  \033[0mChave (Dec)    : \033[0;37m%s\033[0m\n", dec_priv);
    printf("\033[1;32m|  \033[0mWIF Format     : \033[1;33m%s\033[0m\n", wif);
    printf("\033[1;32m|  \033[0mEndereco BTC   : \033[1;35m%s\033[0m\n", address);
    printf("\033[1;32m+-------------------------------------------------------------+\033[0m\n");

    FILE* keys = fopen("FOUND_KEYS.txt", "a+");
    if (keys != NULL) {
        fprintf(keys,
                "\n+------------------------------------------------------------------+\n"
                "| Quantum Solution Detected                                        |\n"
                "+------------------------------------------------------------------+\n"
                "| Puzzle ID     : #%d\n"
                "| Chave Privada : 0x%s\n"
                "| Chave (Dec)   : %s\n"
                "| WIF Format    : %s\n"
                "| Endereco BTC  : %s\n"
                "| Public Key    : 0x%s\n"
                "+------------------------------------------------------------------+\n",
                FLAG_BITRANGE, hex_priv, dec_priv, wif, address, pub_hex);
        fclose(keys);
    }

    free(hex_priv);
    free(dec_priv);
}

bool validate_and_print_hit(mpz_t key_found) {
    if (!validate_hit(key_found)) {
        fprintf(stderr, "\n[!] Colisao descartada: chave candidata nao corresponde a pubkey alvo.\n");
        return false;
    }
    print_hit_premium(key_found);
    return true;
}

void menu() {
    printf("Modo Kangaroo Standalone v2.0\n");
    printf("Uso: ./modo-kangaroo [opcoes]\n");
    printf("Opcoes:\n");
    printf("  --auto[=perfil]  Auto-detecta hardware e aplica tuning (safe|balanced|max)\n");
    printf("  -r <START:END>   Intervalo de busca em Hex (Ex: 1:FFFFFFFF)\n");
    printf("  -p <PUBKEY>      Chave Publica alvo em Hex (Comprimida ou Uncomprimida)\n");
    printf("  -t <threads>     Numero de threads (Default: 1)\n");
    printf("  -d <bits>        Numero de bits zero para Distinguished Points (Default: 20)\n");
    printf("  -m <GB>          Limite de RAM para tabela de traps (Default: 4.0)\n");
    printf("  -j <count>       Numero de saltos ativos (Max: %d, Default: %d)\n", JUMP_COUNT, JUMP_COUNT);
    printf("  -w <count>       Numero de kangaroos wild na frota (0-%d, Default: %d)\n", FLEET_SIZE, HALF_FLEET);
    printf("  -b <id>          Puzzle id opcional para nome de checkpoint\n");
    printf("  -h               Exibe este menu\n");
    exit(0);
}
size_t trap_shard_index(const XKey& key) {
    return XKeyHasher{}(key) % TRAP_SHARDS;
}

uint64_t approximate_trap_capacity() {
    double bytes_per_entry = 256.0;
    TRAP_BYTES_ESTIMATE = static_cast<uint64_t>(bytes_per_entry);
    double max_entries = (MAX_RAM_GB * 1073741824.0) / bytes_per_entry;
    if (max_entries < 1.0) {
        max_entries = 1.0;
    }
    return static_cast<uint64_t>(max_entries);
}

void reserve_trap_tables() {
    TRAP_CAPACITY = approximate_trap_capacity();
    const size_t per_shard = static_cast<size_t>((TRAP_CAPACITY / TRAP_SHARDS) + 1);
    for (size_t i = 0; i < TRAP_SHARDS; ++i) {
        trap_shards[i].table.reserve(per_shard);
    }
}

uint64_t current_trap_count() {
    return TOTAL_TRAPS.load(std::memory_order_relaxed);
}

std::string archive_filename_for_shard(size_t shard) {
    return "traps_archive_shard_" + std::to_string(shard) + ".bin";
}

static inline uint64_t elapsed_ns_since(const std::chrono::steady_clock::time_point& start) {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now() - start).count());
}

double estimated_trap_memory_gb(uint64_t trap_count) {
    return (static_cast<double>(trap_count) * static_cast<double>(TRAP_BYTES_ESTIMATE)) / 1073741824.0;
}

double estimated_seconds_to_capacity(uint64_t current_traps, double elapsed_seconds) {
    if (elapsed_seconds <= 0.0 || current_traps == 0 || current_traps >= TRAP_CAPACITY) {
        return 0.0;
    }
    const double traps_per_second = static_cast<double>(current_traps) / elapsed_seconds;
    if (traps_per_second <= 0.0) {
        return 0.0;
    }
    return static_cast<double>(TRAP_CAPACITY - current_traps) / traps_per_second;
}

double seconds_to_hours(double seconds) {
    return seconds / 3600.0;
}

void flush_traps_to_archive() {
    bool expected = false;
    if (!FLUSH_IN_PROGRESS.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
        return;
    }

    const auto flush_start = std::chrono::steady_clock::now();
    std::vector<std::unique_lock<std::mutex>> locks;
    locks.reserve(TRAP_SHARDS);
    for (size_t i = 0; i < TRAP_SHARDS; ++i) {
        locks.emplace_back(trap_shards[i].mutex);
    }

    uint64_t moved = 0;
    for (size_t i = 0; i < TRAP_SHARDS; ++i) {
        FILE* f = fopen(archive_filename_for_shard(i).c_str(), "ab");
        if (!f) {
            continue;
        }
        for (const auto& [key, entry] : trap_shards[i].table) {
            fwrite(&entry.is_wild, 1, 1, f);
            fwrite(entry.x.bytes, 1, 32, f);
            fwrite(entry.distance_bytes.data(), 1, entry.distance_bytes.size(), f);
            ++moved;
        }
        fclose(f);
        trap_shards[i].table.clear();
    }
    TOTAL_TRAPS.store(0, std::memory_order_relaxed);
    TOTAL_FLUSHES.fetch_add(1, std::memory_order_relaxed);
    TIME_ARCHIVE_NS.fetch_add(elapsed_ns_since(flush_start), std::memory_order_relaxed);
    FLUSH_IN_PROGRESS.store(false, std::memory_order_release);
    printf("\n[i] RAM cheia. %llu armadilhas movidas para archives por shard\n",
           (unsigned long long)moved);
}

bool traps_lookup(const XKey& key, TrapEntry& out) {
    TrapShard& shard = trap_shards[trap_shard_index(key)];
    std::lock_guard<std::mutex> lock(shard.mutex);
    auto it = shard.table.find(key);
    if (it == shard.table.end()) {
        return false;
    }
    out = it->second;
    return true;
}

bool traps_insert(const TrapEntry& entry) {
    TrapShard& shard = trap_shards[trap_shard_index(entry.x)];
    std::lock_guard<std::mutex> lock(shard.mutex);
    auto [it, inserted] = shard.table.emplace(entry.x, entry);
    if (inserted) {
        TOTAL_TRAPS.fetch_add(1, std::memory_order_relaxed);
    }
    return inserted;
}

enum class TrapProcessResult {
    inserted,
    existing_same_type,
    collision_other_type
};

TrapProcessResult traps_process_candidate(const DPCandidate& candidate, TrapEntry& existing) {
    TrapShard& shard = trap_shards[trap_shard_index(candidate.x)];
    std::lock_guard<std::mutex> lock(shard.mutex);

    auto it = shard.table.find(candidate.x);
    if (it != shard.table.end()) {
        existing = it->second;
        return it->second.is_wild == candidate.is_wild
            ? TrapProcessResult::existing_same_type
            : TrapProcessResult::collision_other_type;
    }

    TrapEntry entry;
    entry.x = candidate.x;
    entry.distance_bytes = candidate.distance_bytes;
    entry.is_wild = candidate.is_wild;
    shard.table.emplace(entry.x, entry);
    TOTAL_TRAPS.fetch_add(1, std::memory_order_relaxed);
    return TrapProcessResult::inserted;
}

bool parse_pubkey(const std::string& hex, secp256k1_gej* res, unsigned char compressed33[33]) {
    if (hex.empty() || (hex.size() % 2) != 0) {
        return false;
    }

    const size_t len = hex.length() / 2;
    if (len != 33 && len != 65) {
        return false;
    }

    unsigned char bin[65];
    memset(bin, 0, sizeof(bin));
    if (hexs2bin((char*)hex.c_str(), bin) == 0) {
        return false;
    }

    secp256k1_pubkey pub;
    secp256k1_ge ge;
    size_t out_len = 33;

    if (!secp256k1_ec_pubkey_parse(ctx_global, &pub, bin, len)) {
        return false;
    }
    if (!secp256k1_pubkey_load(ctx_global, &ge, &pub)) {
        return false;
    }
    secp256k1_gej_set_ge(res, &ge);
    if (!secp256k1_ec_pubkey_serialize(ctx_global, compressed33, &out_len, &pub, SECP256K1_EC_COMPRESSED)) {
        return false;
    }
    return out_len == 33;
}

bool write_gej_compressed(FILE* f, secp256k1_gej* p) {
    unsigned char serialized[33];
    if (!gej_to_pubkey33(p, serialized)) {
        return false;
    }
    return fwrite(serialized, 1, sizeof(serialized), f) == sizeof(serialized);
}

bool read_gej_compressed(FILE* f, secp256k1_gej* p) {
    unsigned char serialized[33];
    if (fread(serialized, 1, sizeof(serialized), f) != sizeof(serialized)) {
        return false;
    }
    return pubkey33_to_gej(serialized, p);
}

void refresh_x_cache_locked(ThreadContext* tc) {
    if (!tc->x_cache_dirty) {
        return;
    }
    secp256k1_ge affine_fleet[FLEET_SIZE];
    secp256k1_gej jacobian_fleet[FLEET_SIZE];
    for (int i = 0; i < FLEET_SIZE; ++i) {
        jacobian_fleet[i] = tc->fleet[i].point;
    }
    secp256k1_ge_set_all_gej_var(affine_fleet, jacobian_fleet, FLEET_SIZE);
    for (int i = 0; i < FLEET_SIZE; ++i) {
        tc->fleet[i].point = jacobian_fleet[i];
        secp256k1_fe_normalize(&affine_fleet[i].x);
        secp256k1_fe_get_b32(tc->x_cache[i], &affine_fleet[i].x);
    }
    tc->x_cache_dirty = false;
}

void fleet_gej_initial_jump(secp256k1_gej* res, const secp256k1_gej* start, int count) {
    *res = *start;
    for (int i = 0; i < count; ++i) {
        secp256k1_gej_add_ge_var(res, res, &jump_set[0].point, NULL);
    }
}

void initialize_thread_cache(ThreadContext* tc) {
    std::lock_guard<std::mutex> lock(tc->mutex);
    refresh_x_cache_locked(tc);
}

void add_jump_distance(UInt192& acc, const UInt192& jump) {
    u192_add_inplace(acc, jump);
}

void clamp_tame_to_range_if_needed(ThreadContext* tc, int idx) {
    if (!HAS_RANGE_END || tc->fleet[idx].is_wild) {
        return;
    }
    if (u192_compare(tc->fleet_dists[idx], RANGE_END_U192) <= 0) {
        return;
    }

    u192_subtract_inplace(tc->fleet_dists[idx], RANGE_SPAN_U192);

    mpz_t scalar_tmp;
    mpz_init(scalar_tmp);
    u192_to_mpz(tc->fleet_dists[idx], scalar_tmp);
    gej_from_mpz_scalar(scalar_tmp, &tc->fleet[idx].point);
    mpz_clear(scalar_tmp);
}

void generate_jump_set() {
    mpz_t d;
    mpz_init(d);
    const int half_bits = std::max(1, RANGE_BITS / 2);
    const int active_jump_count = std::max(1, ACTIVE_JUMP_COUNT);
    int min_exp = std::max(0, half_bits - (active_jump_count / 2));
    int max_exp = std::min(191, half_bits + (active_jump_count / 2) - 1);
    if ((max_exp - min_exp + 1) < active_jump_count) {
        min_exp = std::max(0, max_exp - active_jump_count + 1);
    }
    for (int i = 0; i < active_jump_count; ++i) {
        secp256k1_gej j_jacobian;
        const int exponent = std::min(191, min_exp + i);
        mpz_ui_pow_ui(d, 2, exponent);
        u192_set_pow2(jump_dists[i], static_cast<unsigned>(exponent));
        gej_from_mpz_scalar(d, &j_jacobian);
        secp256k1_ge_set_gej(&jump_set[i].point, &j_jacobian);
    }
    for (int i = active_jump_count; i < JUMP_COUNT; ++i) {
        jump_dists[i] = u192_zero();
        jump_set[i].point = jump_set[active_jump_count - 1].point;
    }
    mpz_clear(d);
}

uint64_t mix_thread_seed(uint64_t value) {
    value ^= value >> 33;
    value *= 0xff51afd7ed558ccdULL;
    value ^= value >> 33;
    value *= 0xc4ceb9fe1a85ec53ULL;
    value ^= value >> 33;
    return value;
}

void apply_seeded_jumps(secp256k1_gej* point, UInt192& distance, uint64_t seed, int rounds) {
    uint64_t state = mix_thread_seed(seed);
    for (int r = 0; r < rounds; ++r) {
        state = state * 6364136223846793005ULL + 1442695040888963407ULL;
        const int jump_idx = static_cast<int>((state >> 32) % std::max(1, ACTIVE_JUMP_COUNT));
        secp256k1_gej_add_ge_var(point, point, &jump_set[jump_idx].point, NULL);
        add_jump_distance(distance, jump_dists[jump_idx]);
    }
}

bool save_checkpoint_v2(FILE* f) {
    uint32_t version = CHECKPOINT_VERSION;
    uint64_t hops = TOTAL_HOPS.load();
    uint32_t num_thr = (uint32_t)threads_data.size();
    uint32_t active_jumps = (uint32_t)ACTIVE_JUMP_COUNT;
    uint32_t active_wild = (uint32_t)ACTIVE_WILD_COUNT;

    fwrite(&version, 4, 1, f);
    fwrite(&hops, 8, 1, f);
    fwrite(&num_thr, 4, 1, f);
    fwrite(&active_jumps, 4, 1, f);
    fwrite(&active_wild, 4, 1, f);

    for (uint32_t t = 0; t < num_thr; ++t) {
        ThreadContext* tc = threads_data[t];
        std::lock_guard<std::mutex> lock(tc->mutex);
        for (int i = 0; i < FLEET_SIZE; ++i) {
            fwrite(&tc->fleet[i].is_wild, 1, 1, f);
            if (!write_gej_compressed(f, &tc->fleet[i].point)) {
                return false;
            }
            unsigned char dist_bytes[32];
            u192_to_bytes32(tc->fleet_dists[i], dist_bytes);
            fwrite(dist_bytes, 1, sizeof(dist_bytes), f);
            fwrite(tc->x_cache[i], 1, 32, f);
        }
    }

    std::vector<std::unique_lock<std::mutex>> locks;
    locks.reserve(TRAP_SHARDS);
    for (size_t i = 0; i < TRAP_SHARDS; ++i) {
        locks.emplace_back(trap_shards[i].mutex);
    }

    uint64_t num_traps = 0;
    for (size_t i = 0; i < TRAP_SHARDS; ++i) {
        num_traps += trap_shards[i].table.size();
    }
    fwrite(&num_traps, 8, 1, f);

    for (size_t i = 0; i < TRAP_SHARDS; ++i) {
        for (const auto& [key, entry] : trap_shards[i].table) {
            fwrite(&entry.is_wild, 1, 1, f);
            fwrite(entry.x.bytes, 1, 32, f);
            fwrite(entry.distance_bytes.data(), 1, entry.distance_bytes.size(), f);
        }
    }
    return true;
}
bool load_checkpoint_v1(FILE* f) {
    uint64_t hops = 0;
    uint32_t num_thr = 0;
    fread(&hops, 8, 1, f);
    fread(&num_thr, 4, 1, f);
    TOTAL_HOPS.store(hops);

    for (uint32_t t = 0; t < num_thr; ++t) {
        ThreadContext* tc = new ThreadContext();
        tc->id = t;
        tc->hops = 0;
        tc->x_cache_dirty = true;
        for (int i = 0; i < FLEET_SIZE; ++i) {
            fread(&tc->fleet[i].is_wild, 1, 1, f);
            fread(&tc->fleet[i].point, sizeof(secp256k1_gej), 1, f);
            mpz_t distance;
            mpz_init(distance);
            read_mpz(f, distance);
            if (!u192_from_mpz(distance, tc->fleet_dists[i])) {
                mpz_clear(distance);
                delete tc;
                return false;
            }
            mpz_clear(distance);
        }
        initialize_thread_cache(tc);
        threads_data.push_back(tc);
    }

    uint64_t num_traps = 0;
    fread(&num_traps, 8, 1, f);
    for (uint64_t i = 0; i < num_traps; ++i) {
        TrapEntry entry;
        fread(&entry.is_wild, 1, 1, f);
        fread(entry.x.bytes, 1, 32, f);
        mpz_t distance;
        UInt192 dist_u192;
        unsigned char dist_bytes[32];
        mpz_init(distance);
        read_mpz(f, distance);
        if (!u192_from_mpz(distance, dist_u192)) {
            mpz_clear(distance);
            return false;
        }
        u192_to_bytes32(dist_u192, dist_bytes);
        memcpy(entry.distance_bytes.data(), dist_bytes, sizeof(dist_bytes));
        traps_insert(entry);
        mpz_clear(distance);
    }
    return true;
}

bool load_checkpoint_v3(FILE* f) {
    uint64_t hops = 0;
    uint32_t num_thr = 0;
    uint32_t active_jumps = JUMP_COUNT;
    uint32_t active_wild = HALF_FLEET;
    fread(&hops, 8, 1, f);
    fread(&num_thr, 4, 1, f);
    fread(&active_jumps, 4, 1, f);
    fread(&active_wild, 4, 1, f);
    TOTAL_HOPS.store(hops);
    ACTIVE_JUMP_COUNT = std::max(1, std::min((int)active_jumps, JUMP_COUNT));
    ACTIVE_WILD_COUNT = std::max(0, std::min((int)active_wild, FLEET_SIZE));

    for (uint32_t t = 0; t < num_thr; ++t) {
        ThreadContext* tc = new ThreadContext();
        tc->id = t;
        tc->hops = 0;
        tc->x_cache_dirty = true;
        for (int i = 0; i < FLEET_SIZE; ++i) {
            fread(&tc->fleet[i].is_wild, 1, 1, f);
            if (!read_gej_compressed(f, &tc->fleet[i].point)) {
                delete tc;
                return false;
            }
            unsigned char dist_bytes[32];
            fread(dist_bytes, 1, sizeof(dist_bytes), f);
            if (!u192_from_bytes32(dist_bytes, tc->fleet_dists[i])) {
                delete tc;
                return false;
            }
            fread(tc->x_cache[i], 1, 32, f);
        }
        threads_data.push_back(tc);
    }

    uint64_t num_traps = 0;
    fread(&num_traps, 8, 1, f);
    for (uint64_t i = 0; i < num_traps; ++i) {
        TrapEntry entry;
        fread(&entry.is_wild, 1, 1, f);
        fread(entry.x.bytes, 1, 32, f);
        fread(entry.distance_bytes.data(), 1, entry.distance_bytes.size(), f);
        traps_insert(entry);
    }
    return true;
}

bool load_checkpoint_v2(FILE* f) {
    uint64_t hops = 0;
    uint32_t num_thr = 0;
    fread(&hops, 8, 1, f);
    fread(&num_thr, 4, 1, f);
    TOTAL_HOPS.store(hops);
    ACTIVE_JUMP_COUNT = JUMP_COUNT;
    ACTIVE_WILD_COUNT = HALF_FLEET;

    for (uint32_t t = 0; t < num_thr; ++t) {
        ThreadContext* tc = new ThreadContext();
        tc->id = t;
        tc->hops = 0;
        tc->x_cache_dirty = true;
        for (int i = 0; i < FLEET_SIZE; ++i) {
            fread(&tc->fleet[i].is_wild, 1, 1, f);
            if (!read_gej_compressed(f, &tc->fleet[i].point)) {
                delete tc;
                return false;
            }
            unsigned char dist_bytes[32];
            fread(dist_bytes, 1, sizeof(dist_bytes), f);
            if (!u192_from_bytes32(dist_bytes, tc->fleet_dists[i])) {
                delete tc;
                return false;
            }
            fread(tc->x_cache[i], 1, 32, f);
        }
        threads_data.push_back(tc);
    }

    uint64_t num_traps = 0;
    fread(&num_traps, 8, 1, f);
    for (uint64_t i = 0; i < num_traps; ++i) {
        TrapEntry entry;
        fread(&entry.is_wild, 1, 1, f);
        fread(entry.x.bytes, 1, 32, f);
        fread(entry.distance_bytes.data(), 1, entry.distance_bytes.size(), f);
        traps_insert(entry);
    }
    return true;
}

void save_checkpoint() {
    char filename[256];
    if (FLAG_BITRANGE > 0) {
        sprintf(filename, "kangaroo_bit%d.ckp", FLAG_BITRANGE);
    } else {
        strcpy(filename, "kangaroo.ckp");
    }

    FILE* f = fopen(filename, "wb");
    if (!f) {
        return;
    }

    uint32_t magic = 0x474E414B;
    fwrite(&magic, 4, 1, f);
    if (!save_checkpoint_v2(f)) {
        fprintf(stderr, "\n[E] Falha ao salvar checkpoint.\n");
    } else {
        printf("\n[+] Checkpoint salvo: %s\n", filename);
    }
    fclose(f);
}

void build_current_snapshot(std::array<SnapshotMap, TRAP_SHARDS>& snapshots) {
    for (size_t i = 0; i < TRAP_SHARDS; ++i) {
        snapshots[i].clear();
    }

    for (auto* tc : threads_data) {
        std::lock_guard<std::mutex> lock(tc->mutex);
        for (int i = 0; i < FLEET_SIZE; ++i) {
            DPCandidate candidate;
            memcpy(candidate.x.bytes, tc->x_cache[i], 32);
            u192_to_bytes32(tc->fleet_dists[i], candidate.distance_bytes.data());
            candidate.is_wild = tc->fleet[i].is_wild;
            snapshots[trap_shard_index(candidate.x)].emplace(candidate.x, candidate);
        }
    }
}

bool process_archive_file(FILE* f, const SnapshotMap& snapshot) {
    while (!KEY_FOUND_FLAG) {
        TrapEntry archived;
        if (fread(&archived.is_wild, 1, 1, f) != 1) {
            break;
        }
        if (fread(archived.x.bytes, 1, 32, f) != 32) {
            break;
        }
        if (fread(archived.distance_bytes.data(), 1, archived.distance_bytes.size(), f) != archived.distance_bytes.size()) {
            break;
        }

        auto it = snapshot.find(archived.x);
        if (it == snapshot.end()) {
            continue;
        }
        if (it->second.is_wild == archived.is_wild) {
            continue;
        }

        mpz_t key_found;
        mpz_t archived_dist;
        mpz_t current_dist;
        mpz_init(key_found);
        mpz_init(archived_dist);
        mpz_init(current_dist);
        import_mpz_32(archived.distance_bytes.data(), archived_dist);
        import_mpz_32(it->second.distance_bytes.data(), current_dist);
        if (it->second.is_wild) {
            mpz_sub(key_found, archived_dist, current_dist);
        } else {
            mpz_sub(key_found, current_dist, archived_dist);
        }
        mpz_mod(key_found, key_found, ORDER_N);

        const bool ok = validate_and_print_hit(key_found);
        mpz_clear(key_found);
        mpz_clear(archived_dist);
        mpz_clear(current_dist);
        if (ok) {
            KEY_FOUND_FLAG = true;
            return true;
        }
    }
    return false;
}

void check_archive_collisions() {
    const auto archive_start = std::chrono::steady_clock::now();
    std::array<SnapshotMap, TRAP_SHARDS> snapshots;
    build_current_snapshot(snapshots);

    for (size_t shard = 0; shard < TRAP_SHARDS && !KEY_FOUND_FLAG; ++shard) {
        FILE* f = fopen(archive_filename_for_shard(shard).c_str(), "rb");
        if (!f) {
            continue;
        }
        if (process_archive_file(f, snapshots[shard])) {
            TIME_ARCHIVE_NS.fetch_add(elapsed_ns_since(archive_start), std::memory_order_relaxed);
            fclose(f);
            return;
        }
        fclose(f);
    }

    FILE* legacy = fopen("traps_archive.bin", "rb");
    if (legacy) {
        SnapshotMap merged;
        for (size_t shard = 0; shard < TRAP_SHARDS; ++shard) {
            merged.insert(snapshots[shard].begin(), snapshots[shard].end());
        }
        process_archive_file(legacy, merged);
        fclose(legacy);
    }

    TIME_ARCHIVE_NS.fetch_add(elapsed_ns_since(archive_start), std::memory_order_relaxed);
}

bool load_checkpoint() {
    char filename[256];
    if (FLAG_BITRANGE > 0) {
        sprintf(filename, "kangaroo_bit%d.ckp", FLAG_BITRANGE);
    } else {
        strcpy(filename, "kangaroo.ckp");
    }

    FILE* f = fopen(filename, "rb");
    if (!f) {
        return false;
    }

    uint32_t magic = 0;
    if (fread(&magic, 4, 1, f) != 1 || magic != 0x474E414B) {
        fclose(f);
        return false;
    }

    printf("[?] Checkpoint detectado: %s. Deseja retomar a busca? (s/n): ", filename);
    char c = getchar();
    if (c != 's' && c != 'S') {
        fclose(f);
        return false;
    }

    uint32_t version_or_legacy = 0;
    if (fread(&version_or_legacy, 4, 1, f) != 1) {
        fclose(f);
        return false;
    }

    bool ok = false;
    if (version_or_legacy == CHECKPOINT_VERSION) {
        ok = load_checkpoint_v3(f);
    } else if (version_or_legacy == 2) {
        ok = load_checkpoint_v2(f);
    } else {
        fseek(f, 4, SEEK_SET);
        ok = load_checkpoint_v1(f);
    }

    fclose(f);
    if (!ok) {
        return false;
    }

    printf("[+] Checkpoint carregado: %llu hops, %llu traps (%u threads).\n",
           (unsigned long long)TOTAL_HOPS.load(),
           (unsigned long long)current_trap_count(),
           (unsigned int)threads_data.size());
    return true;
}

int jump_index_from_x(const unsigned char x_bytes[32]) {
    const uint64_t x_val = bytes_to_u64_be(x_bytes + 24);
    return (int)(x_val % std::max(1, ACTIVE_JUMP_COUNT));
}

bool is_distinguished_point(const unsigned char x_bytes[32]) {
    const uint64_t x_prefix = bytes_to_u64_be(x_bytes);
    return (x_prefix & DP_MASK) == 0;
}

void prepare_thread_dp_candidates_locked(ThreadContext* tc, std::vector<DPCandidate>& out) {
    out.clear();
    out.reserve(FLEET_SIZE);
    for (int i = 0; i < FLEET_SIZE; ++i) {
        if (!is_distinguished_point(tc->x_cache[i])) {
            continue;
        }
        TOTAL_DPS.fetch_add(1, std::memory_order_relaxed);
        DPCandidate candidate;
        memcpy(candidate.x.bytes, tc->x_cache[i], 32);
        u192_to_bytes32(tc->fleet_dists[i], candidate.distance_bytes.data());
        candidate.is_wild = tc->fleet[i].is_wild;
        out.push_back(candidate);
    }
}

bool resolve_collision(const TrapEntry& entry, const DPCandidate& candidate) {
    if (entry.is_wild == candidate.is_wild) {
        return false;
    }

    mpz_t key_found;
    mpz_t entry_distance;
    mpz_t candidate_distance;
    mpz_init(key_found);
    mpz_init(entry_distance);
    mpz_init(candidate_distance);
    import_mpz_32(entry.distance_bytes.data(), entry_distance);
    import_mpz_32(candidate.distance_bytes.data(), candidate_distance);

    if (candidate.is_wild) {
        mpz_sub(key_found, entry_distance, candidate_distance);
    } else {
        mpz_sub(key_found, candidate_distance, entry_distance);
    }
    mpz_mod(key_found, key_found, ORDER_N);

    const bool ok = validate_and_print_hit(key_found);
    if (ok) {
        KEY_FOUND_FLAG = true;
    }

    mpz_clear(key_found);
    mpz_clear(entry_distance);
    mpz_clear(candidate_distance);
    return ok;
}

#if defined(USE_EARLY_TERMINATION) && USE_EARLY_TERMINATION == 1
void worker_thread_bruteforce(ThreadContext* tc) {
    secp256k1_gej current_point = tc->fleet[0].point;
    UInt192 current_dist = tc->fleet_dists[0];
    UInt192 thread_start = RANGE_START_U192;
    
    if (N_THREADS > 1) {
        UInt192 stride = u192_div_u32(RANGE_SPAN_U192, static_cast<uint32_t>(N_THREADS));
        for (int s = 0; s < tc->id; s++) {
            u192_add_inplace(thread_start, stride);
        }
    }

    while (!SHOULD_SAVE && !KEY_FOUND_FLAG) {
        unsigned char hash[20];
        secp->GetHash160(P2PKH, true, current_point, hash);
        
        for (size_t t = 0; t < targets.size(); t++) {
            if (memcmp(hash, targets[t].data(), 20) == 0) {
                printf("[!] Thread %d: CHAVE ENCONTRADA!\n", tc->id);
                KEY_FOUND_FLAG = true;
                return;
            }
        }
        
        secp256k1_gej_add_ge(&current_point, &current_point, &secp->generator);
        u192_add_u64_inplace(current_dist, 1);
        
        if (HAS_RANGE_END && u192_compare(current_dist, RANGE_END_U192) > 0) {
            break;
        }
        tc->hops++;
    }
}
#endif

void worker_thread(ThreadContext* tc) {
    std::vector<DPCandidate> candidates;

#if defined(USE_EARLY_TERMINATION) && USE_EARLY_TERMINATION == 1
    uint64_t range_span_64;
    if (u192_to_u64(RANGE_SPAN_U192, range_span_64) && range_span_64 < EARLY_TERMINATION_THRESHOLD) {
        printf("[i] Thread %d: Usando early termination para range pequeno (%llu chaves)\n",
               tc->id, (unsigned long long)range_span_64);
        worker_thread_bruteforce(tc);
        return;
    }
#endif

    while (!SHOULD_SAVE && !KEY_FOUND_FLAG) {
        {
            const auto jumps_start = std::chrono::steady_clock::now();
            std::lock_guard<std::mutex> lock(tc->mutex);
            for (int i = 0; i < FLEET_SIZE; ++i) {
                const int jump_idx = jump_index_from_x(tc->x_cache[i]);
                secp256k1_gej_add_ge_var(&tc->fleet[i].point, &tc->fleet[i].point, &jump_set[jump_idx].point, NULL);
                add_jump_distance(tc->fleet_dists[i], jump_dists[jump_idx]);
                clamp_tame_to_range_if_needed(tc, i);
            }
            tc->x_cache_dirty = true;
            TIME_JUMPS_NS.fetch_add(elapsed_ns_since(jumps_start), std::memory_order_relaxed);

            const auto cache_start = std::chrono::steady_clock::now();
            refresh_x_cache_locked(tc);
            prepare_thread_dp_candidates_locked(tc, candidates);
            TIME_CACHE_NS.fetch_add(elapsed_ns_since(cache_start), std::memory_order_relaxed);
        }

        const auto traps_start = std::chrono::steady_clock::now();
        for (const auto& candidate : candidates) {
            if (current_trap_count() >= TRAP_CAPACITY) {
                flush_traps_to_archive();
            }

            TrapEntry existing;
            const TrapProcessResult result = traps_process_candidate(candidate, existing);
            if (result == TrapProcessResult::collision_other_type) {
                if (resolve_collision(existing, candidate)) {
                    TIME_TRAPS_NS.fetch_add(elapsed_ns_since(traps_start), std::memory_order_relaxed);
                    return;
                }
            }
        }
        TIME_TRAPS_NS.fetch_add(elapsed_ns_since(traps_start), std::memory_order_relaxed);

        TOTAL_HOPS.fetch_add(FLEET_SIZE, std::memory_order_relaxed);
    }
}
void initialize_ranges() {
    mpz_t range_start_mpz;
    mpz_t range_end_mpz;
    mpz_t range_span_mpz;
    mpz_init_set_str(range_start_mpz, RANGE_START.c_str(), 16);
    mpz_init(range_end_mpz);
    mpz_init(range_span_mpz);

    if (!RANGE_END.empty()) {
        HAS_RANGE_END = true;
        mpz_set_str(range_end_mpz, RANGE_END.c_str(), 16);
        if (mpz_cmp(range_start_mpz, range_end_mpz) > 0) {
            fprintf(stderr, "[E] RANGE_START deve ser menor ou igual a RANGE_END.\n");
            exit(1);
        }
        mpz_sub(range_span_mpz, range_end_mpz, range_start_mpz);
        mpz_add_ui(range_span_mpz, range_span_mpz, 1);
    } else {
        mpz_sub_ui(range_end_mpz, ORDER_N, 1);
        mpz_sub(range_span_mpz, range_end_mpz, range_start_mpz);
        mpz_add_ui(range_span_mpz, range_span_mpz, 1);
    }

    if (!u192_from_mpz(range_start_mpz, RANGE_START_U192) ||
        !u192_from_mpz(range_end_mpz, RANGE_END_U192) ||
        !u192_from_mpz(range_span_mpz, RANGE_SPAN_U192)) {
        fprintf(stderr, "[E] Intervalo excede a representacao fixa de 192 bits.\n");
        mpz_clear(range_start_mpz);
        mpz_clear(range_end_mpz);
        mpz_clear(range_span_mpz);
        exit(1);
    }

    RANGE_BITS = std::max(1, u192_bit_length(RANGE_SPAN_U192));

    mpz_clear(range_start_mpz);
    mpz_clear(range_end_mpz);
    mpz_clear(range_span_mpz);
}

void initialize_new_search() {
    printf("[+] Iniciando nova busca com %d threads...\n", N_THREADS);
    const UInt192 thread_stride = N_THREADS > 1
        ? u192_div_u32(RANGE_SPAN_U192, static_cast<uint32_t>(N_THREADS))
        : u192_zero();

    for (int t = 0; t < N_THREADS; ++t) {
        ThreadContext* tc = new ThreadContext();
        tc->id = t;
        tc->hops = 0;
        tc->x_cache_dirty = true;

        mpz_t thread_start;
        mpz_init(thread_start);
        UInt192 thread_start_u192 = RANGE_START_U192;
        if (N_THREADS > 1) {
            for (int s = 0; s < t; ++s) {
                u192_add_inplace(thread_start_u192, thread_stride);
            }
        }
        u192_to_mpz(thread_start_u192, thread_start);

        secp256k1_gej tame_start_jacobian;
        if (!gej_from_mpz_scalar(thread_start, &tame_start_jacobian)) {
            fprintf(stderr, "[E] Erro ao inicializar ponto tame da thread %d.\n", t);
            mpz_clear(thread_start);
            delete tc;
            exit(1);
        }

        for (int i = 0; i < FLEET_SIZE; ++i) {
            if (i < (FLEET_SIZE - ACTIVE_WILD_COUNT)) {
                fleet_gej_initial_jump(&tc->fleet[i].point, &tame_start_jacobian, i);
                tc->fleet_dists[i] = thread_start_u192;
                u192_add_u64_inplace(tc->fleet_dists[i], static_cast<uint64_t>(i));
                tc->fleet[i].is_wild = false;
                clamp_tame_to_range_if_needed(tc, i);
            } else {
                tc->fleet[i].point = TARGET_PUBKEY_GEJ;
                tc->fleet_dists[i] = u192_zero();
                apply_seeded_jumps(
                    &tc->fleet[i].point,
                    tc->fleet_dists[i],
                    (static_cast<uint64_t>(t + 1) << 32) ^ static_cast<uint64_t>(i - (FLEET_SIZE - ACTIVE_WILD_COUNT) + 1),
                    6 + ((i - (FLEET_SIZE - ACTIVE_WILD_COUNT)) % 5));
                tc->fleet[i].is_wild = true;
            }
        }

        initialize_thread_cache(tc);
        threads_data.push_back(tc);
        mpz_clear(thread_start);
    }
}

void cleanup() {
    for (ThreadContext* tc : threads_data) {
        if (tc == nullptr) {
            continue;
        }
        delete tc;
    }
    threads_data.clear();

    mpz_clear(ORDER_N);

    if (ctx_global != nullptr) {
        secp256k1_context_destroy(ctx_global);
        ctx_global = nullptr;
    }
}

int main(int argc, char** argv) {
    signal(SIGINT, signal_handler);

    int c;
    static struct option long_options[] = {
        {"auto", optional_argument, nullptr, 1000},
        {"help", no_argument, nullptr, 'h'},
        {nullptr, 0, nullptr, 0}
    };
        while ((c = getopt_long(argc, argv, "hr:p:t:d:m:b:j:w:", long_options, nullptr)) != -1) {
        switch (c) {
            case 1000:
                FLAG_AUTO_PROFILE = true;
                if (optarg != nullptr && *optarg != '\0') {
                    if (equals_ignore_case(optarg, "safe") || equals_ignore_case(optarg, "balanced") || 
                        equals_ignore_case(optarg, "max") || equals_ignore_case(optarg, "benchmark")) {
                        AUTO_PROFILE_MODE = optarg;
                    }
                } else {
                    AUTO_PROFILE_MODE = "balanced";
                }
                break;
            case 'h':
                menu();
                break;
            case 'b':
                FLAG_BITRANGE = atoi(optarg);
                break;
            case 'r': {
                Tokenizer t;
                stringtokenizer(optarg, &t);
                if (t.n >= 1) {
                    RANGE_START = nextToken(&t);
                }
                if (t.n >= 2) {
                    RANGE_END = nextToken(&t);
                }
                freetokenizer(&t);
                break;
            }
            case 'p':
                TARGET_PUBKEY_HEX = optarg;
                break;
            case 't':
                N_THREADS = std::max(1, atoi(optarg));
                OVERRIDE_THREADS = true;
                break;
            case 'd': {
                int bits = atoi(optarg);
                if (bits > 64) {
                    bits = 64;
                }
                if (bits <= 0) {
                    DP_MASK = 0;
                } else if (bits == 64) {
                    DP_MASK = ~0ULL;
                } else {
                    DP_MASK = ~((1ULL << (64 - bits)) - 1);
                }
                OVERRIDE_DP = true;
                break;
            }
            case 'm':
                MAX_RAM_GB = std::max(0.1, atof(optarg));
                OVERRIDE_RAM = true;
                break;
            case 'j':
                ACTIVE_JUMP_COUNT = std::max(1, std::min(atoi(optarg), JUMP_COUNT));
                OVERRIDE_JUMPS = true;
                break;
            case 'w':
                ACTIVE_WILD_COUNT = std::max(0, std::min(atoi(optarg), FLEET_SIZE));
                OVERRIDE_WILD = true;
                break;
            default:
                menu();
                break;
        }
    }

    apply_auto_profile_if_needed();

    if (TARGET_PUBKEY_HEX.empty()) {
        fprintf(stderr, "[E] Chave publica alvo (-p) e obrigatoria.\n");
        return 1;
    }

    ctx_global = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    if (ctx_global == nullptr) {
        fprintf(stderr, "[E] Falha ao criar contexto secp256k1.\n");
        return 1;
    }

    mpz_init_set_str(ORDER_N, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16);
    initialize_ranges();
    reserve_trap_tables();

    if (!parse_pubkey(TARGET_PUBKEY_HEX, &TARGET_PUBKEY_GEJ, TARGET_PUBKEY_COMPRESSED)) {
        fprintf(stderr, "[E] Erro ao processar chave publica alvo.\n");
        cleanup();
        return 1;
    }

    printf("[+] Inicializando Jump Set (%d/%d saltos ativos)...\n", ACTIVE_JUMP_COUNT, JUMP_COUNT);
    generate_jump_set();
    printf("[i] Capacidade estimada de traps: %llu entries (%.0f bytes/entry)\n",
           (unsigned long long)TRAP_CAPACITY,
           (double)TRAP_BYTES_ESTIMATE);

    if (!load_checkpoint()) {
        initialize_new_search();
    }

    printf("[*] Kangaroo Engine Standalone pronto. DP Mask: %016llX | wild=%d tame=%d | jumps=%d\n",
           (unsigned long long)DP_MASK,
           ACTIVE_WILD_COUNT,
           FLEET_SIZE - ACTIVE_WILD_COUNT,
           ACTIVE_JUMP_COUNT);

    std::vector<std::thread> workers;
    for (int i = 0; i < (int)threads_data.size(); ++i) {
        workers.emplace_back(worker_thread, threads_data[i]);
    }

    auto start_time = std::chrono::high_resolution_clock::now();
    auto last_save = std::chrono::steady_clock::now();

    while (!KEY_FOUND_FLAG) {
        if (SHOULD_SAVE) {
            break;
        }

        auto now_check = std::chrono::steady_clock::now();
        if (std::chrono::duration_cast<std::chrono::minutes>(now_check - last_save).count() >= 5) {
            save_checkpoint();
            printf("[i] Verificando colisoes no arquivo de disco...\n");
            check_archive_collisions();
            last_save = now_check;
        }

        const double dur = std::chrono::duration<double>(
            std::chrono::high_resolution_clock::now() - start_time).count();
        const uint64_t current_hops = TOTAL_HOPS.load();
        const uint64_t traps = current_trap_count();
        const uint64_t dps = TOTAL_DPS.load();
        const uint64_t flushes = TOTAL_FLUSHES.load();
        const double jumps_ms = TIME_JUMPS_NS.load() / 1000000.0;
        const double cache_ms = TIME_CACHE_NS.load() / 1000000.0;
        const double traps_ms = TIME_TRAPS_NS.load() / 1000000.0;
        const double trap_mem_gb = estimated_trap_memory_gb(traps);
        const double eta_seconds = estimated_seconds_to_capacity(traps, dur);
        const double eta_hours = seconds_to_hours(eta_seconds);
        printf("STAT: %llu hops, %.2f hops/s, %llu traps, %.2f GB est, ETA %.2f h, %llu dps, %llu flush, T[j %.0fms c %.0fms t %.0fms]\r",
               (unsigned long long)current_hops,
               dur > 0.0 ? (double)current_hops / dur : 0.0,
               (unsigned long long)traps,
               trap_mem_gb,
               eta_hours,
               (unsigned long long)dps,
               (unsigned long long)flushes,
               jumps_ms,
               cache_ms,
               traps_ms);
        fflush(stdout);
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }

    if (SHOULD_SAVE) {
        save_checkpoint();
    }
    SHOULD_SAVE = true;

    for (auto& t : workers) {
        if (t.joinable()) {
            t.join();
        }
    }

    cleanup();
    return 0;
}
