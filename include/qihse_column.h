#ifndef QIHSE_COLUMN_H
#define QIHSE_COLUMN_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

/* Number of elements per columnar block.
 * Tuned to fit into L2/L3 cache blocks for Radix Partitioned Hash Joins. */
#define QIHSE_COLUMN_CHUNK_SIZE 65536

/**
 * @brief Identifies the data type of the column.
 */
typedef enum {
    QIHSE_COL_TYPE_INT32 = 0,
    QIHSE_COL_TYPE_INT64 = 1,
    QIHSE_COL_TYPE_FLOAT32 = 2,
    QIHSE_COL_TYPE_FLOAT64 = 3,
    QIHSE_COL_TYPE_STRING_DICT = 4
} qihse_column_type_t;

/**
 * @brief Adaptive Encoding Strategies dynamically chosen per chunk.
 */
typedef enum {
    QIHSE_ENCODING_RAW = 0,      /* Uncompressed contiguous array */
    QIHSE_ENCODING_RLE = 1,      /* Run-Length Encoded (for sorted/low-cardinality) */
    QIHSE_ENCODING_DELTA = 2,    /* Delta-Encoded (for monotonic timestamps) */
    QIHSE_ENCODING_BITPACK = 3   /* Bit-Packed (for constrained high-cardinality ints) */
} qihse_column_encoding_t;

/**
 * @brief Metadata header for a Columnar Chunk.
 * Aligned to OS Page Size (4KB) or Huge Page (2MB) to eliminate TLB misses 
 * during massive sequential SIMD scans.
 */
typedef struct __attribute__((aligned(4096))) qihse_column_chunk {
    qihse_column_type_t type;
    qihse_column_encoding_t encoding;
    
    size_t count;           /* Number of elements in this chunk */
    uint32_t dict_limit;    /* Cardinality tracking for dictionaries */
    uint32_t min_val;       /* Zone Map: minimum value for block skipping */
    uint32_t max_val;       /* Zone Map: maximum value for block skipping */
    
    void* data;             /* Points to the 4KB/2MB aligned contiguous payload */
    uint16_t* classifications;
    uint16_t* sci_compartments;
    struct qihse_column_chunk* next;
} qihse_column_chunk_t;

/**
 * @brief Opaque handle for the QIHSE Column Store.
 */
typedef struct qihse_column_store qihse_column_store_t;

qihse_column_store_t* qihse_column_store_create();
void qihse_column_store_destroy(qihse_column_store_t* store);

#include "qihse_auth.h"

bool qihse_column_create(qihse_column_store_t* store, const char* name, qihse_column_type_t type);
bool qihse_column_append_int32(qihse_column_store_t* store, const char* name, int32_t val, uint16_t classification, uint16_t sci_compartment);
bool qihse_column_append_int64(qihse_column_store_t* store, const char* name, int64_t val, uint16_t classification, uint16_t sci_compartment);
bool qihse_column_append_float32(qihse_column_store_t* store, const char* name, float val, uint16_t classification, uint16_t sci_compartment);
bool qihse_column_append_string(qihse_column_store_t* store, const char* name, const char* val, uint16_t classification, uint16_t sci_compartment);

/**
 * @brief SIMD-Accelerated Aggregation functions.
 * Expected to utilize load-and-blend AVX-512 mechanics rather than masked loads,
 * combined with __builtin_prefetch for software-level L1 staging.
 */
int64_t qihse_column_sum_int64_user(qihse_column_store_t* store, const char* name, qihse_user_t* user);
float qihse_column_sum_float32_user(qihse_column_store_t* store, const char* name, qihse_user_t* user);
bool qihse_column_minmax_float32_user(qihse_column_store_t* store, const char* name, qihse_user_t* user, float* out_min, float* out_max);

/**
 * @brief Keystone anchor-search index integration.
 *
 * Builds a sorted INT64 index over an INT64 column so that point and range
 * lookups can be served by qihse_keystone_anchor_search /
 * qihse_keystone_anchor_lower_bound / qihse_keystone_anchor_upper_bound in
 * O(log log N) (< 20ns) instead of binary search.
 *
 * The index materializes the column's INT64 values into a contiguous sorted
 * array together with the original (chunk, offset) row coordinates, so the
 * caller can recover per-row classification / SCI compartment metadata for
 * access-controlled aggregation.
 */

/**
 * @brief Materialize a sorted anchor index for an INT64 column.
 *
 * Walks every chunk of the named INT64 column, copies the (value, chunk, slot)
 * tuples into a growable buffer, sorts by value, and stores the result on the
 * column node. Subsequent qihse_column_lookup_int64_user /
 * qihse_column_range_count_int64_user calls use this index via the keystone
 * anchor search family.
 *
 * @param store Column store handle.
 * @param name INT64 column name.
 * @return true on success, false if the column does not exist or is not INT64.
 */
bool qihse_column_build_int64_index(qihse_column_store_t* store, const char* name);

/**
 * @brief Release any materialized anchor index for a column.
 */
void qihse_column_drop_int64_index(qihse_column_store_t* store, const char* name);

/**
 * @brief O(log log N) point lookup of an INT64 value via keystone anchor search.
 *
 * Requires qihse_column_build_int64_index to have been called. Returns the
 * first accessible row whose value equals `key`, or -1 if no accessible row
 * matches. Access control is enforced via qihse_auth_can_access.
 *
 * @return Row ordinal (>= 0) on hit, -1 on miss or error.
 */
int64_t qihse_column_lookup_int64_user(qihse_column_store_t* store, const char* name, int64_t key, qihse_user_t* user);

/**
 * @brief O(log log N) range count of accessible INT64 rows in [low, high].
 *
 * Uses qihse_keystone_anchor_lower_bound / qihse_keystone_anchor_upper_bound
 * to bracket the range, then walks the (typically tiny) bracket verifying
 * access control. Returns the number of accessible rows whose value lies in
 * the inclusive range [low, high].
 */
size_t qihse_column_range_count_int64_user(qihse_column_store_t* store, const char* name, int64_t low, int64_t high, qihse_user_t* user);

#endif /* QIHSE_COLUMN_H */
