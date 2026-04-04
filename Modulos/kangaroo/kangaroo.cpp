#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <algorithm>
#include <thread>
#include <getopt.h>
#include <unistd.h>
#include <gmp.h>

// --- CONFIGURAÇÃO UNITY BUILD (libsecp256k1 interna) ---
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

#define FLEET_SIZE 64
#define JUMP_COUNT 32

#include <unordered_map>
#include <signal.h>
#include <mutex>
#include <atomic>
#include <vector>

// Estruturas
struct Kangaroo {
    secp256k1_gej point;      // Ponto atual (Jacobiano)
    bool is_wild;             // Tipo (Tame ou Wild)
};

struct Jump {
    secp256k1_ge point;       // Ponto do salto (Afim)
};

struct TrapEntry {
    unsigned char x[32];      // Coordenada X completa
    mpz_t distance;           // Distância acumulada
    bool is_wild;             // Tipo de kangaroo que deixou a trap
};

struct ThreadContext {
    int id;
    Kangaroo fleet[64];
    mpz_t fleet_dists[64];
    uint64_t hops;
};

// Variáveis Globais (Estado do Algoritmo)
std::vector<ThreadContext*> threads_data;
Jump jump_set[JUMP_COUNT];
mpz_t jump_dists[JUMP_COUNT];
mpz_t ORDER_N;
secp256k1_context* ctx_global;
std::atomic<uint64_t> TOTAL_HOPS(0);
std::atomic<bool> SHOULD_SAVE(false);
std::atomic<bool> KEY_FOUND_FLAG(false);
std::mutex traps_mutex;

// Tabela de Traps (Memória Central)
std::unordered_map<std::string, TrapEntry> traps_table;

// Configurações CLI
int N_THREADS = 1;
int FLAG_BITRANGE = 0;
uint64_t DP_MASK = 0xFFFFF00000000000ULL; // Default 20 bits (top)
double MAX_RAM_GB = 4.0;
std::string RANGE_START = "1";
std::string RANGE_END = "";
std::string TARGET_PUBKEY_HEX = "";

// Handler para Ctrl+C
void signal_handler(int sig) {
    if (sig == SIGINT) {
        printf("\n[!] Interrupção detectada. Finalizando e salvando...\n");
        SHOULD_SAVE = true;
    }
}

// Helpers de Serialização
void save_checkpoint();
bool load_checkpoint();

void write_mpz(FILE* f, mpz_t m) {
    size_t count;
    unsigned char* data = (unsigned char*)mpz_export(NULL, &count, 1, 1, 1, 0, m);
    uint32_t len = (uint32_t)count;
    fwrite(&len, 4, 1, f);
    if (len > 0) fwrite(data, 1, len, f);
    free(data);
}

void read_mpz(FILE* f, mpz_t m) {
    uint32_t len;
    if (fread(&len, 4, 1, f) != 1) return;
    if (len > 0) {
        unsigned char* data = (unsigned char*)malloc(len);
        fread(data, 1, len, f);
        mpz_import(m, len, 1, 1, 1, 0, data);
        free(data);
    } else {
        mpz_set_ui(m, 0);
    }
}

void write_gej(FILE* f, secp256k1_gej* p) {
    fwrite(p, sizeof(secp256k1_gej), 1, f);
}

void read_gej(FILE* f, secp256k1_gej* p) {
    fread(p, sizeof(secp256k1_gej), 1, f);
}

// Helper para converter distância mpz para hex string (uso eventual em HIT)
std::string mpz_to_hex(mpz_t m) {
    char* s = mpz_get_str(NULL, 16, m);
    std::string res(s);
    free(s);
    return res;
}

std::string bytes_to_hex(const unsigned char* bytes) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (int i = 0; i < 32; i++) {
        ss << std::setw(2) << (int)bytes[i];
    }
    return ss.str();
}

void rmd160toaddress_dst(const unsigned char *rmd, char *dst) {
    unsigned char digest[60];
    size_t pubaddress_size = 40;
    digest[0] = 0; // P2PKH Version (Bitcoin Mainnet)
    memcpy(digest + 1, rmd, 20);
    sha256(digest, 21, digest + 21);
    sha256(digest + 21, 32, digest + 21);
    if (!b58enc(dst, &pubaddress_size, digest, 25)) {
        strcpy(dst, "(ADR_ERR)");
    }
}

void generate_wif(bool compressed, const unsigned char *priv_bytes, char *dst) {
    unsigned char raw[38];
    unsigned char checksum[32];
    raw[0] = 0x80; // WIF Prefix
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

void print_hit_premium(mpz_t key_found) {
    unsigned char priv_bytes[32];
    size_t count;
    memset(priv_bytes, 0, 32);
    unsigned char *exported = (unsigned char*)mpz_export(NULL, &count, 1, 1, 1, 0, key_found);
    if (count <= 32) memcpy(priv_bytes + (32 - count), exported, count);
    if (exported) free(exported);

    secp256k1_pubkey pubkey;
    unsigned char pub_serialized[33];
    size_t pub_len = 33;
    
    if (secp256k1_ec_pubkey_create(ctx_global, &pubkey, priv_bytes)) {
        secp256k1_ec_pubkey_serialize(ctx_global, pub_serialized, &pub_len, &pubkey, SECP256K1_EC_COMPRESSED);
    }

    char address[50], wif[56], pub_hex[67];
    unsigned char sha256_res[32], rmdhash[20];

    sha256(pub_serialized, 33, sha256_res);
    RMD160Data(sha256_res, 32, (char*)rmdhash);
    rmd160toaddress_dst(rmdhash, address);
    generate_wif(true, priv_bytes, wif);
    
    char *hex_priv = mpz_get_str(NULL, 16, key_found);
    char *dec_priv = mpz_get_str(NULL, 10, key_found);
    tohex_dst((char*)pub_serialized, 33, pub_hex);

    printf("\n\033[1;32m\u250c\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500"
           " Quantum Solution Detected "
           "\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2510\033[0m\n");
    printf("\033[1;32m\u2502\033[0m\n");
    printf("\033[1;32m\u2502  \033[1;92m\u2714 SUCESSO! CHAVE ENCONTRADA\033[0m\n");
    printf("\033[1;32m\u2502\033[0m\n");
    printf("\033[1;32m\u2502  \033[0mPuzzle ID      : \033[1;33m#%d\033[0m\n", FLAG_BITRANGE);
    printf("\033[1;32m\u2502  \033[0mChave Privada  : \033[1;36m0x%s\033[0m\n", hex_priv);
    printf("\033[1;32m\u2502  \033[0mChave (Dec)    : \033[0;37m%s\033[0m\n", dec_priv);
    printf("\033[1;32m\u2502  \033[0mWIF Format     : \033[1;33m%s\033[0m\n", wif);
    printf("\033[1;32m\u2502  \033[0mEndereco BTC   : \033[1;35m%s\033[0m\n", address);
    printf("\033[1;32m\u2502\033[0m\n");
    printf("\033[1;32m\u2514\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2518\033[0m\n");

    FILE *keys = fopen("FOUND_KEYS.txt", "a+");
    if (keys != NULL) {
        fprintf(keys, "\n+------------------------------------------------------------------+\n"
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
    if (hex_priv) free(hex_priv);
    if (dec_priv) free(dec_priv);
}

void menu() {
    printf("Modo Kangaroo Standalone v1.0\n");
    printf("Uso: ./modo-kangaroo [opções]\n");
    printf("Opções:\n");
    printf("  -r <START:END>   Intervalo de busca em Hex (Ex: 1:FFFFFFFF)\n");
    printf("  -p <PUBKEY>      Chave Pública alvo em Hex (Comprimida ou Uncomprimida)\n");
    printf("  -t <threads>     Número de threads (Default: 1)\n");
    printf("  -dp <bits>       Número de bits zero para Distinguished Points (Default: 20)\n");
    printf("  -mram <GB>       Limite de RAM para tabela de traps (Default: 4.0)\n");
    printf("  -h               Exibe este menu\n");
    exit(0);
}

// Inicializa a tabela de saltos: 2^0, 2^1, ..., 2^31
void generate_jump_set() {
    mpz_t d;
    mpz_init(d);
    
    for (int i = 0; i < JUMP_COUNT; i++) {
        mpz_ui_pow_ui(d, 2, i);
        mpz_set(jump_dists[i], d);
        
        // Calcular J = 2^i * G
        unsigned char scalar_bin[32];
        mpz_export(scalar_bin, NULL, 1, 1, 1, 0, d);
        
        // Inverter para Big Endian se necessário para a libsecp256k1
        // (mpz_export com os parâmetros acima já gera big endian)
        
        secp256k1_scalar s;
        int overflow;
        secp256k1_scalar_set_b32(&s, scalar_bin, &overflow);
        
        secp256k1_gej j_jacobian;
        secp256k1_ecmult_gen(&ctx_global->ecmult_gen_ctx, &j_jacobian, &s);
        
        secp256k1_ge_set_gej(&jump_set[i].point, &j_jacobian);
    }
    mpz_clear(d);
}

// Converte string hex para GEJ (Ponto da curva)
bool parse_pubkey(const std::string& hex, secp256k1_gej* res) {
    if (hex.empty()) return false;
    
    secp256k1_pubkey pub;
    unsigned char bin[65];
    int len = hex.length() / 2;
    hexs2bin((char*)hex.c_str(), bin);
    
    if (secp256k1_ec_pubkey_parse(ctx_global, &pub, bin, len)) {
        // secp256k1_pubkey armazena internamente GE
        // Precisamos converter para GEJ
        secp256k1_ge ge;
        memcpy(&ge, pub.data, sizeof(ge));
        secp256k1_gej_set_ge(res, &ge);
        return true;
    }
    return false;
}

void save_checkpoint() {
    char filename[256];
    if (FLAG_BITRANGE > 0) sprintf(filename, "kangaroo_bit%d.ckp", FLAG_BITRANGE);
    else strcpy(filename, "kangaroo.ckp");

    FILE* f = fopen(filename, "wb");
    if (!f) return;
    
    uint32_t magic = 0x474E414B; // 'KANG'
    fwrite(&magic, 4, 1, f);
    uint64_t hops = TOTAL_HOPS.load();
    fwrite(&hops, 8, 1, f);
    
    uint32_t num_thr = (uint32_t)threads_data.size();
    fwrite(&num_thr, 4, 1, f);

    for (uint32_t t = 0; t < num_thr; t++) {
        ThreadContext* tc = threads_data[t];
        for (int i = 0; i < 64; i++) {
            fwrite(&tc->fleet[i].is_wild, 1, 1, f);
            write_gej(f, &tc->fleet[i].point);
            write_mpz(f, tc->fleet_dists[i]);
        }
    }
    
    uint64_t num_traps = traps_table.size();
    fwrite(&num_traps, 8, 1, f);
    for (auto const& [key, entry] : traps_table) {
        fwrite(&entry.is_wild, 1, 1, f);
        fwrite(entry.x, 1, 32, f);
        write_mpz(f, (mpz_ptr)entry.distance);
    }
    
    fclose(f);
    printf("\n[+] Checkpoint salvo: %s\n", filename);
}

void flush_traps_to_archive() {
    FILE* f = fopen("traps_archive.bin", "ab");
    if (!f) return;
    
    for (auto const& [key, entry] : traps_table) {
        fwrite(&entry.is_wild, 1, 1, f);
        fwrite(entry.x, 1, 32, f);
        write_mpz(f, (mpz_ptr)entry.distance);
    }
    
    fclose(f);
    printf("\n[i] RAM cheia. %lu armadilhas movidas para traps_archive.bin\n", (unsigned long)traps_table.size());
    traps_table.clear();
}

void check_archive_collisions() {
    FILE* f = fopen("traps_archive.bin", "rb");
    if (!f) return;
    
    mpz_t dist_archived;
    mpz_init(dist_archived);

    while (!KEY_FOUND_FLAG) {
        bool is_wild_archived;
        if (fread(&is_wild_archived, 1, 1, f) != 1) break;
        unsigned char x_archived[32];
        fread(x_archived, 1, 32, f);
        read_mpz(f, dist_archived);
        
        // Comparar com a frota ATUAL de todas as threads
        for (auto* tc : threads_data) {
            for (int i = 0; i < 64; i++) {
                unsigned char x_current[32];
                secp256k1_ge affine_tmp;
                secp256k1_ge_set_gej(&affine_tmp, &tc->fleet[i].point);
                secp256k1_fe_normalize(&affine_tmp.x);
                secp256k1_fe_get_b32(x_current, &affine_tmp.x);
                
                if (memcmp(x_archived, x_current, 32) == 0 && is_wild_archived != tc->fleet[i].is_wild) {
                    KEY_FOUND_FLAG = true;
                    mpz_t key_found;
                    mpz_init(key_found);
                    if (tc->fleet[i].is_wild) mpz_sub(key_found, dist_archived, tc->fleet_dists[i]);
                    else mpz_sub(key_found, tc->fleet_dists[i], dist_archived);
                    mpz_mod(key_found, key_found, ORDER_N);
                    
                    printf("\n### HIT! COLISÃO COM ARQUIVO DE DISCO ENCONTRADA ###\n");
                    print_hit_premium(key_found);
                    
                    mpz_clear(key_found);
                    mpz_clear(dist_archived);
                    fclose(f);
                    return;
                }
            }
        }
    }
    mpz_clear(dist_archived);
    fclose(f);
}

bool load_checkpoint() {
    char filename[256];
    if (FLAG_BITRANGE > 0) sprintf(filename, "kangaroo_bit%d.ckp", FLAG_BITRANGE);
    else strcpy(filename, "kangaroo.ckp");

    FILE* f = fopen(filename, "rb");
    if (!f) return false;
    
    uint32_t magic;
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
    
    uint64_t hops;
    fread(&hops, 8, 1, f);
    TOTAL_HOPS.store(hops);

    uint32_t num_thr;
    fread(&num_thr, 4, 1, f);
    
    for (uint32_t t = 0; t < num_thr; t++) {
        ThreadContext* tc = new ThreadContext();
        tc->id = t;
        tc->hops = 0;
        for (int i = 0; i < 64; i++) {
            fread(&tc->fleet[i].is_wild, 1, 1, f);
            read_gej(f, &tc->fleet[i].point);
            mpz_init(tc->fleet_dists[i]);
            read_mpz(f, tc->fleet_dists[i]);
        }
        threads_data.push_back(tc);
    }
    
    uint64_t num_traps;
    fread(&num_traps, 8, 1, f);
    for (uint64_t i = 0; i < num_traps; i++) {
        TrapEntry te;
        fread(&te.is_wild, 1, 1, f);
        fread(te.x, 1, 32, f);
        mpz_init(te.distance);
        read_mpz(f, te.distance);
        
        std::string key((char*)te.x, 32);
        traps_table[key] = te;
    }
    
    fclose(f);
    printf("[+] Checkpoint carregado: %lu hops, %lu traps (%u threads).\n", hops, num_traps, num_thr);
    return true;
}

void fleet_gej_initial_jump(secp256k1_gej* res, const secp256k1_gej* start, int count) {
    *res = *start;
    for (int i = 0; i < count; i++) {
        secp256k1_gej_add_ge_var(res, res, &jump_set[0].point, NULL);
    }
}

void worker_thread(ThreadContext* tc) {
    while (!SHOULD_SAVE && !KEY_FOUND_FLAG) {
        for (int i = 0; i < 64; i++) {
            secp256k1_ge affine_tmp;
            secp256k1_ge_set_gej(&affine_tmp, &tc->fleet[i].point);
            
            unsigned char x_bytes[32];
            secp256k1_fe_normalize(&affine_tmp.x);
            secp256k1_fe_get_b32(x_bytes, &affine_tmp.x);
            
            uint64_t x_val;
            memcpy(&x_val, x_bytes + 24, 8);
            x_val = __builtin_bswap64(x_val);
            int jump_idx = x_val % JUMP_COUNT;

            secp256k1_gej_add_ge_var(&tc->fleet[i].point, &tc->fleet[i].point, &jump_set[jump_idx].point, NULL);
            
            mpz_add(tc->fleet_dists[i], tc->fleet_dists[i], jump_dists[jump_idx]);
            mpz_mod(tc->fleet_dists[i], tc->fleet_dists[i], ORDER_N);
        }

        // Batch Normalization
        secp256k1_ge affine_fleet[64];
        secp256k1_gej jacobian_fleet[64];
        for(int i=0; i<64; i++) jacobian_fleet[i] = tc->fleet[i].point;
        secp256k1_ge_set_all_gej_var(affine_fleet, jacobian_fleet, 64);

        for (int i = 0; i < 64; i++) {
            tc->fleet[i].point = jacobian_fleet[i]; 
            
            unsigned char x_out[32];
            secp256k1_fe_normalize(&affine_fleet[i].x);
            secp256k1_fe_get_b32(x_out, &affine_fleet[i].x);
            
            uint64_t x_prefix;
            memcpy(&x_prefix, x_out, 8);
            x_prefix = __builtin_bswap64(x_prefix);
            
            if ((x_prefix & DP_MASK) == 0) {
                std::string x_key((char*)x_out, 32);
                
                std::lock_guard<std::mutex> lock(traps_mutex);
                auto it = traps_table.find(x_key);
                
                if (it != traps_table.end()) {
                    if (it->second.is_wild != tc->fleet[i].is_wild) {
                        if (KEY_FOUND_FLAG) return;
                        KEY_FOUND_FLAG = true;
                        
                        mpz_t key_found;
                        mpz_init(key_found);
                        if (tc->fleet[i].is_wild) mpz_sub(key_found, it->second.distance, tc->fleet_dists[i]);
                        else mpz_sub(key_found, tc->fleet_dists[i], it->second.distance);
                        mpz_mod(key_found, key_found, ORDER_N);
                        
                        print_hit_premium(key_found);
                        
                        mpz_clear(key_found);
                        return;
                    }
                } else {
                    if (traps_table.size() * 100 > MAX_RAM_GB * 1073741824.0) {
                        flush_traps_to_archive();
                    }
                    TrapEntry te;
                    memcpy(te.x, x_out, 32);
                    mpz_init_set(te.distance, tc->fleet_dists[i]);
                    te.is_wild = tc->fleet[i].is_wild;
                    traps_table[x_key] = te;
                }
            }
        }
        TOTAL_HOPS += 64;
    }
}

int main(int argc, char** argv) {
    signal(SIGINT, signal_handler);
    int c;
    while ((c = getopt(argc, argv, "hr:p:t:d:m:b:")) != -1) {
        switch(c) {
            case 'h': menu(); break;
            case 'b': FLAG_BITRANGE = atoi(optarg); break;
            case 'r': {
                Tokenizer t;
                stringtokenizer(optarg, &t);
                if (t.n >= 1) RANGE_START = nextToken(&t);
                if (t.n >= 2) RANGE_END = nextToken(&t);
                freetokenizer(&t);
                break;
            }
            case 'p': TARGET_PUBKEY_HEX = optarg; break;
            case 't': N_THREADS = atoi(optarg); break;
            case 'd': {
                int bits = atoi(optarg);
                if (bits > 64) bits = 64;
                if (bits == 0) DP_MASK = 0;
                else DP_MASK = ~((1ULL << (64 - bits)) - 1);
                break;
            }
            case 'm': MAX_RAM_GB = atof(optarg); break;
        }
    }

    if (TARGET_PUBKEY_HEX.empty()) {
        fprintf(stderr, "[E] Chave pública alvo (-p) é obrigatória.\n");
        return 1;
    }

    // Inicialização do motor secp256k1 e GMP
    ctx_global = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    mpz_init_set_str(ORDER_N, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16);
    for(int i=0; i<JUMP_COUNT; i++) mpz_init(jump_dists[i]);
    
    printf("[+] Inicializando Jump Set (32 saltos)...\n");
    generate_jump_set();
    
    if (!load_checkpoint()) {
        printf("[+] Iniciando nova busca com %d threads...\n", N_THREADS);
        secp256k1_gej target_gej;
        if (!parse_pubkey(TARGET_PUBKEY_HEX, &target_gej)) {
            fprintf(stderr, "[E] Erro ao processar chave pública alvo.\n");
            return 1;
        }

        mpz_t start_range;
        mpz_init_set_str(start_range, RANGE_START.c_str(), 16);
        
        for (int t = 0; t < N_THREADS; t++) {
            ThreadContext* tc = new ThreadContext();
            tc->id = t;
            tc->hops = 0;
            
            mpz_t thread_start;
            mpz_init_set(thread_start, start_range);
            // Pequeno offset para cada thread para diversificar a busca inicial
            mpz_add_ui(thread_start, thread_start, t * 1000000ULL); 

            unsigned char scalar_bin[32];
            mpz_export(scalar_bin, NULL, 1, 1, 1, 0, thread_start);
            secp256k1_scalar s_start;
            int overflow;
            secp256k1_scalar_set_b32(&s_start, scalar_bin, &overflow);
            secp256k1_gej tame_start_jacobian;
            secp256k1_ecmult_gen(&ctx_global->ecmult_gen_ctx, &tame_start_jacobian, &s_start);

            for (int i = 0; i < 64; i++) {
                if (i < 32) {
                    fleet_gej_initial_jump(&tc->fleet[i].point, &tame_start_jacobian, i); 
                    mpz_init(tc->fleet_dists[i]);
                    mpz_set(tc->fleet_dists[i], thread_start);
                    mpz_add_ui(tc->fleet_dists[i], tc->fleet_dists[i], i); 
                    tc->fleet[i].is_wild = false;
                } else {
                    fleet_gej_initial_jump(&tc->fleet[i].point, &target_gej, i-32);
                    mpz_init_set_ui(tc->fleet_dists[i], i-32);
                    tc->fleet[i].is_wild = true;
                }
            }
            threads_data.push_back(tc);
            mpz_clear(thread_start);
        }
        mpz_clear(start_range);
    }

    printf("[*] Kangaroo Engine Standalone pronto. DP Mask: %016llX\n", (unsigned long long)DP_MASK);
 
    std::vector<std::thread> workers;
    for (int i = 0; i < (int)threads_data.size(); i++) {
        workers.push_back(std::thread(worker_thread, threads_data[i]));
    }

    auto start_time = std::chrono::high_resolution_clock::now();
    auto last_save = std::chrono::steady_clock::now();

    while (!KEY_FOUND_FLAG) {
        if (SHOULD_SAVE) break;

        auto now_check = std::chrono::steady_clock::now();
        if (std::chrono::duration_cast<std::chrono::minutes>(now_check - last_save).count() >= 5) {
            save_checkpoint();
            printf("[i] Verificando colisões no arquivo de disco...\n");
            check_archive_collisions();
            last_save = now_check;
        }

        double dur = std::chrono::duration<double>(std::chrono::high_resolution_clock::now() - start_time).count();
        uint64_t current_hops = TOTAL_HOPS.load();
        printf("STAT: %lu hops, %.2f hops/s, %lu traps\r", current_hops, (double)current_hops / dur, (unsigned long)traps_table.size());
        fflush(stdout);
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }

    if (SHOULD_SAVE) save_checkpoint();
    
    // Sinalizar para threads pararem (se ainda não pararam)
    SHOULD_SAVE = true; 
    
    for (auto& t : workers) {
        if (t.joinable()) t.join();
    }

    secp256k1_context_destroy(ctx_global);
    return 0;
}
