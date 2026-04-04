#include "cuckoo.h"
#include "xxhash/xxhash.h"
#include <stdlib.h>
#include <string.h>

extern "C" {

static inline uint64_t upperpower2(uint64_t x) {
    x--;
    x |= x >> 1;
    x |= x >> 2;
    x |= x >> 4;
    x |= x >> 8;
    x |= x >> 16;
    x |= x >> 32;
    x++;
    return x;
}

int cuckoo_init2(struct cuckoo * filter, uint64_t entries, double error) {
    filter->entries = entries;
    filter->error = error;
    
    uint64_t target_buckets = (uint64_t)((entries / CUCKOO_BUCKET_SIZE) / 0.95);
    if (target_buckets == 0) target_buckets = 1;
    filter->bucket_count = upperpower2(target_buckets);

    filter->bytes = filter->bucket_count * CUCKOO_BUCKET_SIZE;
    filter->bf = (uint8_t*)calloc(filter->bucket_count, CUCKOO_BUCKET_SIZE);
    
    if(!filter->bf) return 1;
    filter->b = 0;
    return 0;
}

static inline uint8_t get_fingerprint(uint64_t hash) {
    uint8_t fp = (uint8_t)(hash & 0xFF);
    if (fp == 0) fp = 1;
    return fp;
}

static inline uint64_t hash_fp(uint8_t fp) {
    uint64_t buf = fp;
    return XXH64(&buf, sizeof(buf), 0x5a5a5a5a);
}

int cuckoo_add(struct cuckoo * filter, const void * buffer, int len) {
    uint64_t hash = XXH64(buffer, len, 0x12345678);
    uint8_t fp = get_fingerprint(hash);
    
    uint64_t mask = filter->bucket_count - 1;
    uint64_t i1 = (hash >> 8) & mask;
    uint64_t i2 = (i1 ^ hash_fp(fp)) & mask;

    for(int i=0; i<CUCKOO_BUCKET_SIZE; i++) {
        if(filter->bf[i1 * CUCKOO_BUCKET_SIZE + i] == 0) {
            filter->bf[i1 * CUCKOO_BUCKET_SIZE + i] = fp;
            return 0;
        }
    }
    for(int i=0; i<CUCKOO_BUCKET_SIZE; i++) {
        if(filter->bf[i2 * CUCKOO_BUCKET_SIZE + i] == 0) {
            filter->bf[i2 * CUCKOO_BUCKET_SIZE + i] = fp;
            return 0;
        }
    }

    uint64_t i_kick = (hash & 512) ? i1 : i2;
    for(int n=0; n<CUCKOO_MAX_KICKS; n++) {
        int slot = hash % CUCKOO_BUCKET_SIZE;
        uint8_t kicked_fp = filter->bf[i_kick * CUCKOO_BUCKET_SIZE + slot];
        filter->bf[i_kick * CUCKOO_BUCKET_SIZE + slot] = fp;
        
        fp = kicked_fp;
        i_kick = (i_kick ^ hash_fp(fp)) & mask;
        
        for(int i=0; i<CUCKOO_BUCKET_SIZE; i++) {
            if(filter->bf[i_kick * CUCKOO_BUCKET_SIZE + i] == 0) {
                filter->bf[i_kick * CUCKOO_BUCKET_SIZE + i] = fp;
                return 0;
            }
        }
        hash = hash_fp(fp) + n; // mutate hash for pseudo-randomness in kick
    }
    
    return 1; 
}

int cuckoo_check(struct cuckoo * filter, const void * buffer, int len) {
    uint64_t hash = XXH64(buffer, len, 0x12345678);
    uint8_t fp = get_fingerprint(hash);
    
    uint64_t mask = filter->bucket_count - 1;
    uint64_t i1 = (hash >> 8) & mask;
    uint64_t i2 = (i1 ^ hash_fp(fp)) & mask;

    uint8_t* b1 = &filter->bf[i1 * CUCKOO_BUCKET_SIZE];
    if (b1[0] == fp || b1[1] == fp || b1[2] == fp || b1[3] == fp) return 1;

    uint8_t* b2 = &filter->bf[i2 * CUCKOO_BUCKET_SIZE];
    if (b2[0] == fp || b2[1] == fp || b2[2] == fp || b2[3] == fp) return 1;

    return 0;
}

int cuckoo_reset(struct cuckoo * filter) {
    if(filter->bf) {
        memset(filter->bf, 0, filter->bytes);
    }
    return 0;
}

void cuckoo_free(struct cuckoo * filter) {
    if(filter->bf) {
        free(filter->bf);
        filter->bf = NULL;
    }
    filter->entries = 0;
    filter->bytes = 0;
    filter->bucket_count = 0;
}

}
