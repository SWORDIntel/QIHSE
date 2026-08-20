#ifndef QIHSE_INDEX_SCAN_H
#define QIHSE_INDEX_SCAN_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "qihse_index_manager.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file qihse_index_scan.h
 * @brief Phase 3.5 — Index scan executor operator.
 *
 * Takes an index handle and a range/equality predicate, returns matching row
 * IDs. Designed to be used as input to other executors (join, sort, etc.).
 * This is a clean interface that the optimizer (qihse_optimizer.c, created by
 * another agent) can call.
 */

/** Predicate kind for an index scan. */
typedef enum {
    /** Exact equality: key == value(s). Works for BTREE and HASH. */
    QIHSE_SCAN_EQ = 0,
    /** Range: min <= key <= max. BTREE only. */
    QIHSE_SCAN_RANGE = 1,
    /** Prefix match: key starts with prefix. BTREE only (composite indexes). */
    QIHSE_SCAN_PREFIX = 2
} qihse_scan_pred_kind_t;

/** A scan predicate. */
typedef struct {
    qihse_scan_pred_kind_t kind;
    /* For EQ: the equality key (serialized). */
    const void* eq_key;
    size_t eq_key_len;
    /* For RANGE: min and max (either may be NULL for open-ended). */
    const void* min_key;
    size_t min_len;
    const void* max_key;
    size_t max_len;
    /* For PREFIX: the prefix bytes. */
    const void* prefix_key;
    size_t prefix_len;
} qihse_scan_pred_t;

/** Opaque handle for an index scan operator. */
typedef struct qihse_index_scan qihse_index_scan_t;

/**
 * @brief Creates an index scan operator over the given index and predicate.
 *        The scan is opened immediately and positioned at the first result.
 * @return Scan handle, or NULL if no results / invalid args.
 */
qihse_index_scan_t* qihse_index_scan_open(qihse_index_t* idx,
                                          const qihse_scan_pred_t* pred);

/**
 * @brief Fetches the next batch of matching row IDs.
 * @param scan    The scan operator.
 * @param out_buf Caller-allocated buffer of *out_count uint64_t values.
 * @param cap     Capacity of out_buf (max row IDs to fetch).
 * @param out_count Number of row IDs written.
 * @return true if at least one row was fetched, false at end of scan.
 */
bool qihse_index_scan_next(qihse_index_scan_t* scan,
                           uint64_t* out_buf, size_t cap,
                           size_t* out_count);

/**
 * @brief Fetches all matching row IDs into a dynamically allocated array.
 * @param scan     The scan operator.
 * @param out_buf  Set to a malloc'd array of row IDs (caller frees).
 * @param out_count Set to the number of row IDs.
 * @return true on success.
 */
bool qihse_index_scan_all(qihse_index_scan_t* scan,
                          uint64_t** out_buf, size_t* out_count);

/** Closes and frees the scan operator. */
void qihse_index_scan_close(qihse_index_scan_t* scan);

/**
 * @brief Convenience: one-shot equality scan on a hash or B+ tree index.
 *        Returns a single matching row ID (or none).
 * @return true if found.
 */
bool qihse_index_scan_eq(qihse_index_t* idx,
                         const void* key, size_t key_len,
                         uint64_t* row_id_out);

#ifdef __cplusplus
}
#endif

#endif /* QIHSE_INDEX_SCAN_H */
