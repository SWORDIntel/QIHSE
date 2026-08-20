#ifndef QIHSE_BTREE_H
#define QIHSE_BTREE_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file qihse_btree.h
 * @brief Phase 3.1/3.3 — Cache-conscious B+ tree index with composite-key
 *        support, range scans, and prefix matching.
 *
 * The tree stores arbitrary byte-string keys that are already serialized in a
 * sort-preserving form (see qihse_btree_serialize_key). Each entry maps a key
 * to a single uint64_t row-id. Leaf nodes are linked in a singly-linked list
 * so range scans only require a single root-to-leaf descent followed by
 * sequential leaf traversal.
 *
 * All operations are guarded by a per-tree pthread rwlock for thread safety.
 */

/** Default fanout for fixed-width int64 keys. */
#define QIHSE_BTREE_DEFAULT_FANOUT 128

/** Page size used for node allocation (4 KB for TLB efficiency). */
#define QIHSE_BTREE_PAGE_SIZE 4096

/** Opaque handle for a B+ tree index. */
typedef struct qihse_btree qihse_btree_t;

/** Opaque handle for a forward range-scan cursor. */
typedef struct qihse_btree_cursor qihse_btree_cursor_t;

/**
 * @brief Creates a new B+ tree.
 * @param fanout Maximum number of entries per leaf node (0 => default 128).
 * @return New tree handle, or NULL on failure.
 */
qihse_btree_t* qihse_btree_create(uint32_t fanout);

/** Destroys a B+ tree and frees all nodes. */
void qihse_btree_destroy(qihse_btree_t* tree);

/**
 * @brief Inserts (or replaces) a key -> row_id mapping.
 * @return true on success, false on allocation failure.
 */
bool qihse_btree_insert(qihse_btree_t* tree,
                        const void* key, size_t key_len,
                        uint64_t row_id);

/**
 * @brief Deletes a key. The slot is marked empty; row_id_out (if non-NULL)
 *        receives the removed row id.
 * @return true if the key was present, false otherwise.
 */
bool qihse_btree_delete(qihse_btree_t* tree,
                        const void* key, size_t key_len,
                        uint64_t* row_id_out);

/**
 * @brief Point lookup: exact-match key -> row_id.
 * @return true if found (row_id written to *out), false otherwise.
 */
bool qihse_btree_lookup(qihse_btree_t* tree,
                        const void* key, size_t key_len,
                        uint64_t* out);

/**
 * @brief Opens a forward range-scan cursor over [min_key, max_key].
 *        Either bound may be NULL/0 to indicate an open-ended scan.
 *        The caller must close the cursor with qihse_btree_cursor_close().
 * @return New cursor positioned at the first in-range entry, or NULL if the
 *         range is empty.
 */
qihse_btree_cursor_t* qihse_btree_range_open(qihse_btree_t* tree,
                                             const void* min_key, size_t min_len,
                                             const void* max_key, size_t max_len);

/**
 * @brief Opens a prefix-scan cursor: all keys beginning with @prefix.
 *        This is the basis for composite-index prefix matching (an index on
 *        (a,b,c) can answer a=? or a=? AND b=? by scanning the matching prefix).
 */
qihse_btree_cursor_t* qihse_btree_prefix_open(qihse_btree_t* tree,
                                              const void* prefix, size_t prefix_len);

/** Advances the cursor to the next in-range entry.
 *  @return true if advanced, false at end of range (cursor now exhausted). */
bool qihse_btree_cursor_next(qihse_btree_cursor_t* cur);

/** Reads the current entry the cursor is positioned on.
 *  @return true if valid, false if cursor is exhausted. */
bool qihse_btree_cursor_get(const qihse_btree_cursor_t* cur,
                            const void** key_out, size_t* key_len_out,
                            uint64_t* row_id_out);

/** Closes and frees a cursor. */
void qihse_btree_cursor_close(qihse_btree_cursor_t* cur);

/** @return number of entries currently in the tree. */
size_t qihse_btree_size(const qihse_btree_t* tree);

/* ------------------------------------------------------------------ */
/* Composite / sort-preserving key serialization (Phase 3.3)          */
/* ------------------------------------------------------------------ */

/** Supported column value types for composite keys. */
typedef enum {
    QIHSE_BTREE_COL_INT32 = 0,
    QIHSE_BTREE_COL_INT64 = 1,
    QIHSE_BTREE_COL_FLOAT64 = 2,
    QIHSE_BTREE_COL_STRING = 3
} qihse_btree_col_type_t;

/** A single component of a composite key. */
typedef struct {
    qihse_btree_col_type_t type;
    const void* data;   /**< pointer to the column value */
    size_t len;         /**< byte length for STRING (excl. NUL); 0 for scalars */
} qihse_btree_col_t;

/**
 * @brief Serializes a composite key into a sort-preserving byte buffer.
 *
 * Encoding rules that preserve total order across mixed types:
 *  - int32/int64: big-endian with sign bit flipped (so negatives sort first).
 *  - float64: big-endian with sign bit flipped and magnitude bits flipped for
 *    negatives (standard IEEE-754 sortable encoding).
 *  - string: raw UTF-8 bytes followed by a 0x00 terminator; a 0x01 separator
 *    is appended so that a shorter string sorts before a longer prefix match.
 *
 * @param cols     Array of column components.
 * @param ncol     Number of components.
 * @param out_buf  Caller-allocated buffer of *out_len bytes (or NULL to query).
 * @param out_len  In: capacity; out: actual serialized length.
 * @return 0 on success, -1 if out_buf is too small (and *out_len is set).
 */
int qihse_btree_serialize_key(const qihse_btree_col_t* cols, size_t ncol,
                              void* out_buf, size_t* out_len);

/** Convenience: serialize into a freshly malloc'd buffer.
 *  @return 0 on success (*out_buf set, *out_len set), -1 on failure. */
int qihse_btree_serialize_key_alloc(const qihse_btree_col_t* cols, size_t ncol,
                                    void** out_buf, size_t* out_len);

#ifdef __cplusplus
}
#endif

#endif /* QIHSE_BTREE_H */
