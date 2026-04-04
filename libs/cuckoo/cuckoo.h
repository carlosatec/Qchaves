#ifndef CUCKOO_H
#define CUCKOO_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CUCKOO_BUCKET_SIZE 4
#define CUCKOO_MAX_KICKS 500

struct cuckoo {
    uint64_t entries;      // Number of expected items
    uint64_t bucket_count; // Total buckets
    uint8_t *bf;      // Fingerprint array (bucket_count * CUCKOO_BUCKET_SIZE)
    uint64_t bytes;        // Memory footprint
    double error;          // FPR configured
    uint8_t b;             // Header compatibility var if needed
};

// Initialize cuckoo filter
int cuckoo_init2(struct cuckoo * filter, uint64_t entries, double error);

// Add item to filter
int cuckoo_add(struct cuckoo * filter, const void * buffer, int len);

// Check if item is in filter
int cuckoo_check(struct cuckoo * filter, const void * buffer, int len);

// Reset filter
int cuckoo_reset(struct cuckoo * filter);

// Free memory
void cuckoo_free(struct cuckoo * filter);

#ifdef __cplusplus
}
#endif

#endif // CUCKOO_H
