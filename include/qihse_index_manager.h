#ifndef QIHSE_INDEX_MANAGER_H
#define QIHSE_INDEX_MANAGER_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "qihse_btree.h"
#include "qihse_hash_index.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file qihse_index_manager.h
 * @brief Phase 3.4/3.6 — Index manager tracking all indexes on a table.
 *
 * Supports BTREE, HASH, VECTOR_HNSW, and FTS_INVERTED index types. HNSW and
 * FTS are wrapped so they can be registered and maintained through the same
 * manager interface as native B+ tree and hash indexes.
 */

/** Index type enum (Phase 3.6). */
typedef enum {
    QIHSE_INDEX_BTREE = 0,
    QIHSE_INDEX_HASH = 1,
    QIHSE_INDEX_VECTOR_HNSW = 2,
    QIHSE_INDEX_FTS_INVERTED = 3
} qihse_index_type_t;

/** Column type for index definition (mirrors B+ tree col types). */
typedef enum {
    QIHSE_IDX_COL_INT32 = 0,
    QIHSE_IDX_COL_INT64 = 1,
    QIHSE_IDX_COL_FLOAT64 = 2,
    QIHSE_IDX_COL_STRING = 3
} qihse_idx_col_type_t;

/** A column in an index definition. */
typedef struct {
    qihse_idx_col_type_t type;
    char name[64];       /* column name */
} qihse_idx_col_def_t;

/** Opaque handle for a registered index. */
typedef struct qihse_index qihse_index_t;

/** Opaque handle for an index manager (per table). */
typedef struct qihse_index_manager qihse_index_manager_t;

/** Callbacks for non-native index types (HNSW, FTS wrappers). */
typedef struct {
    void*  (*create_fn)(void);
    void   (*destroy_fn)(void* handle);
    bool   (*insert_fn)(void* handle, uint64_t row_id,
                        const void* data, size_t data_len);
    bool   (*delete_fn)(void* handle, uint64_t row_id);
} qihse_index_wrapper_vtbl_t;

/* ---- Index manager lifecycle ---- */

qihse_index_manager_t* qihse_index_manager_create(void);
void qihse_index_manager_destroy(qihse_index_manager_t* mgr);

/* ---- Index registration ---- */

/**
 * @brief Registers a new B+ tree index on the given columns.
 * @param name Human-readable index name (NUL-terminated).
 * @param cols Column definitions.
 * @param ncol Number of columns (1 = single-column, >1 = composite).
 * @param fanout B+ tree fanout (0 => default 128).
 * @return Index handle, or NULL on failure.
 */
qihse_index_t* qihse_index_manager_add_btree(qihse_index_manager_t* mgr,
                                             const char* name,
                                             const qihse_idx_col_def_t* cols,
                                             size_t ncol,
                                             uint32_t fanout);

/**
 * @brief Registers a new hash index.
 */
qihse_index_t* qihse_index_manager_add_hash(qihse_index_manager_t* mgr,
                                            const char* name,
                                            const qihse_idx_col_def_t* cols,
                                            size_t ncol,
                                            size_t initial_capacity);

/**
 * @brief Registers a wrapper index (HNSW or FTS) using a vtable.
 */
qihse_index_t* qihse_index_manager_add_wrapped(qihse_index_manager_t* mgr,
                                               const char* name,
                                               qihse_index_type_t type,
                                               const qihse_idx_col_def_t* cols,
                                               size_t ncol,
                                               const qihse_index_wrapper_vtbl_t* vtbl);

/* ---- Index lookup ---- */

qihse_index_t* qihse_index_manager_find(const qihse_index_manager_t* mgr,
                                        const char* name);
bool qihse_index_manager_drop(qihse_index_manager_t* mgr, const char* name);
size_t qihse_index_manager_count(const qihse_index_manager_t* mgr);

/* ---- Index operations ---- */

/** Inserts a row into all indexes managed by this manager (synchronous). */
bool qihse_index_manager_insert_row(qihse_index_manager_t* mgr,
                                    uint64_t row_id,
                                    const qihse_idx_col_type_t* col_types,
                                    const void* const* col_values,
                                    const size_t* col_lens,
                                    size_t ncol);

/** Inserts a row into a single specific index. */
bool qihse_index_insert(qihse_index_t* idx,
                        uint64_t row_id,
                        const qihse_idx_col_type_t* col_types,
                        const void* const* col_values,
                        const size_t* col_lens,
                        size_t ncol);

/** Deletes a row from a single index. */
bool qihse_index_delete(qihse_index_t* idx,
                        uint64_t row_id,
                        const qihse_idx_col_type_t* col_types,
                        const void* const* col_values,
                        const size_t* col_lens,
                        size_t ncol);

/** Deletes a row from all indexes. */
bool qihse_index_manager_delete_row(qihse_index_manager_t* mgr,
                                    uint64_t row_id,
                                    const qihse_idx_col_type_t* col_types,
                                    const void* const* col_values,
                                    const size_t* col_lens,
                                    size_t ncol);

/* ---- Bulk load (sort-then-build) ---- */

/**
 * @brief Bulk-loads a B+ tree index from a sorted array of (row_id, key) pairs.
 *        Keys must already be in sort order. This is faster than per-row insert
 *        for initial index creation.
 * @return true on success.
 */
bool qihse_index_bulk_load(qihse_index_t* idx,
                           const uint64_t* row_ids,
                           const void* const* keys,
                           const size_t* key_lens,
                           size_t nrows);

/* ---- Accessors ---- */

qihse_index_type_t qihse_index_type(const qihse_index_t* idx);
const char* qihse_index_name(const qihse_index_t* idx);
size_t qihse_index_ncols(const qihse_index_t* idx);
const qihse_idx_col_def_t* qihse_index_cols(const qihse_index_t* idx);

/** Returns the underlying B+ tree handle (only valid for BTREE indexes). */
qihse_btree_t* qihse_index_btree(const qihse_index_t* idx);
/** Returns the underlying hash index handle (only valid for HASH indexes). */
qihse_hash_index_t* qihse_index_hash(const qihse_index_t* idx);
/** Returns the underlying wrapped handle (HNSW/FTS). */
void* qihse_index_wrapped_handle(const qihse_index_t* idx);

#ifdef __cplusplus
}
#endif

#endif /* QIHSE_INDEX_MANAGER_H */
