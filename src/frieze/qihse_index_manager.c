#define _GNU_SOURCE
/* qihse_index_manager.c — Phase 3.4/3.6 index manager.
 *
 * Tracks all indexes on a table, supports synchronous insert-time updates,
 * bulk-load for B+ trees, and wrapper registration for HNSW/FTS.
 */
#include "qihse_index_manager.h"
#include "qihse_platform.h"

#include <stdlib.h>
#include <string.h>

struct qihse_index {
    char name[128];
    qihse_index_type_t type;
    qihse_idx_col_def_t* cols;
    size_t ncol;
    /* Native handles */
    qihse_btree_t* btree;
    qihse_hash_index_t* hash;
    /* Wrapped handle (HNSW/FTS) */
    void* wrapped_handle;
    qihse_index_wrapper_vtbl_t vtbl;
    struct qihse_index* next;
};

struct qihse_index_manager {
    qihse_index_t* head;
    size_t count;
    pthread_rwlock_t lock;
};

/* ------------------------------------------------------------------ */
/* Manager lifecycle                                                   */
/* ------------------------------------------------------------------ */

qihse_index_manager_t* qihse_index_manager_create(void) {
    qihse_index_manager_t* m = (qihse_index_manager_t*)calloc(1, sizeof(*m));
    if (!m) return NULL;
    m->head = NULL;
    m->count = 0;
    pthread_rwlock_init(&m->lock, NULL);
    return m;
}

void qihse_index_manager_destroy(qihse_index_manager_t* mgr) {
    if (!mgr) return;
    pthread_rwlock_wrlock(&mgr->lock);
    qihse_index_t* cur = mgr->head;
    while (cur) {
        qihse_index_t* next = cur->next;
        if (cur->btree) qihse_btree_destroy(cur->btree);
        if (cur->hash) qihse_hash_index_destroy(cur->hash);
        if (cur->wrapped_handle && cur->vtbl.destroy_fn)
            cur->vtbl.destroy_fn(cur->wrapped_handle);
        free(cur->cols);
        free(cur);
        cur = next;
    }
    pthread_rwlock_unlock(&mgr->lock);
    pthread_rwlock_destroy(&mgr->lock);
    free(mgr);
}

/* ------------------------------------------------------------------ */
/* Index registration                                                  */
/* ------------------------------------------------------------------ */

static qihse_index_t* index_alloc(const char* name,
                                  qihse_index_type_t type,
                                  const qihse_idx_col_def_t* cols,
                                  size_t ncol) {
    qihse_index_t* idx = (qihse_index_t*)calloc(1, sizeof(*idx));
    if (!idx) return NULL;
    strncpy(idx->name, name ? name : "", sizeof(idx->name) - 1);
    idx->type = type;
    idx->ncol = ncol;
    if (ncol > 0) {
        idx->cols = (qihse_idx_col_def_t*)calloc(ncol, sizeof(qihse_idx_col_def_t));
        if (!idx->cols) { free(idx); return NULL; }
        memcpy(idx->cols, cols, ncol * sizeof(qihse_idx_col_def_t));
    }
    idx->next = NULL;
    return idx;
}

static void manager_link(qihse_index_manager_t* mgr, qihse_index_t* idx) {
    idx->next = mgr->head;
    mgr->head = idx;
    mgr->count++;
}

qihse_index_t* qihse_index_manager_add_btree(qihse_index_manager_t* mgr,
                                             const char* name,
                                             const qihse_idx_col_def_t* cols,
                                             size_t ncol,
                                             uint32_t fanout) {
    if (!mgr) return NULL;
    qihse_index_t* idx = index_alloc(name, QIHSE_INDEX_BTREE, cols, ncol);
    if (!idx) return NULL;
    idx->btree = qihse_btree_create(fanout);
    if (!idx->btree) { free(idx->cols); free(idx); return NULL; }
    pthread_rwlock_wrlock(&mgr->lock);
    manager_link(mgr, idx);
    pthread_rwlock_unlock(&mgr->lock);
    return idx;
}

qihse_index_t* qihse_index_manager_add_hash(qihse_index_manager_t* mgr,
                                            const char* name,
                                            const qihse_idx_col_def_t* cols,
                                            size_t ncol,
                                            size_t initial_capacity) {
    if (!mgr) return NULL;
    qihse_index_t* idx = index_alloc(name, QIHSE_INDEX_HASH, cols, ncol);
    if (!idx) return NULL;
    /* Hash index key type: if single int64 column, use INT64; else STRING. */
    qihse_hash_key_type_t kt = QIHSE_HASH_KEY_STRING;
    if (ncol == 1 && cols[0].type == QIHSE_IDX_COL_INT64)
        kt = QIHSE_HASH_KEY_INT64;
    idx->hash = qihse_hash_index_create(kt, initial_capacity);
    if (!idx->hash) { free(idx->cols); free(idx); return NULL; }
    pthread_rwlock_wrlock(&mgr->lock);
    manager_link(mgr, idx);
    pthread_rwlock_unlock(&mgr->lock);
    return idx;
}

qihse_index_t* qihse_index_manager_add_wrapped(qihse_index_manager_t* mgr,
                                               const char* name,
                                               qihse_index_type_t type,
                                               const qihse_idx_col_def_t* cols,
                                               size_t ncol,
                                               const qihse_index_wrapper_vtbl_t* vtbl) {
    if (!mgr || !vtbl || !vtbl->create_fn) return NULL;
    if (type != QIHSE_INDEX_VECTOR_HNSW && type != QIHSE_INDEX_FTS_INVERTED)
        return NULL;
    qihse_index_t* idx = index_alloc(name, type, cols, ncol);
    if (!idx) return NULL;
    idx->vtbl = *vtbl;
    idx->wrapped_handle = vtbl->create_fn();
    if (!idx->wrapped_handle) { free(idx->cols); free(idx); return NULL; }
    pthread_rwlock_wrlock(&mgr->lock);
    manager_link(mgr, idx);
    pthread_rwlock_unlock(&mgr->lock);
    return idx;
}

/* ------------------------------------------------------------------ */
/* Index lookup                                                        */
/* ------------------------------------------------------------------ */

qihse_index_t* qihse_index_manager_find(const qihse_index_manager_t* mgr,
                                        const char* name) {
    if (!mgr || !name) return NULL;
    pthread_rwlock_rdlock(&((qihse_index_manager_t*)mgr)->lock);
    qihse_index_t* cur = mgr->head;
    while (cur) {
        if (strcmp(cur->name, name) == 0) break;
        cur = cur->next;
    }
    pthread_rwlock_unlock(&((qihse_index_manager_t*)mgr)->lock);
    return cur;
}

size_t qihse_index_manager_count(const qihse_index_manager_t* mgr) {
    if (!mgr) return 0;
    return mgr->count;
}

/* ------------------------------------------------------------------ */
/* Key serialization bridge                                            */
/* ------------------------------------------------------------------ */

static qihse_btree_col_type_t to_btree_col_type(qihse_idx_col_type_t t) {
    switch (t) {
        case QIHSE_IDX_COL_INT32:   return QIHSE_BTREE_COL_INT32;
        case QIHSE_IDX_COL_INT64:   return QIHSE_BTREE_COL_INT64;
        case QIHSE_IDX_COL_FLOAT64: return QIHSE_BTREE_COL_FLOAT64;
        case QIHSE_IDX_COL_STRING:  return QIHSE_BTREE_COL_STRING;
        default: return QIHSE_BTREE_COL_INT64;
    }
}

/* Serialize the index's columns from a row into a sort-preserving key. */
static bool serialize_index_key(qihse_index_t* idx,
                                const qihse_idx_col_type_t* col_types,
                                const void* const* col_values,
                                const size_t* col_lens,
                                size_t ncol,
                                void** out_key, size_t* out_len) {
    /* Build col array for the index's columns. We assume the caller passes
     * all table columns; we pick the ones matching our index definition. */
    /* For simplicity, we assume ncol == idx->ncol and the columns correspond
     * 1:1 (the caller passes exactly the indexed columns in order). */
    if (ncol != idx->ncol) return false;
    (void)col_types;
    qihse_btree_col_t* bcols = (qihse_btree_col_t*)calloc(ncol, sizeof(qihse_btree_col_t));
    if (!bcols) return false;
    for (size_t i = 0; i < ncol; i++) {
        bcols[i].type = to_btree_col_type(idx->cols[i].type);
        bcols[i].data = col_values[i];
        bcols[i].len = col_lens[i];
    }
    int rc = qihse_btree_serialize_key_alloc(bcols, ncol, out_key, out_len);
    free(bcols);
    return rc == 0;
}

/* ------------------------------------------------------------------ */
/* Index operations                                                    */
/* ------------------------------------------------------------------ */

bool qihse_index_insert(qihse_index_t* idx,
                        uint64_t row_id,
                        const qihse_idx_col_type_t* col_types,
                        const void* const* col_values,
                        const size_t* col_lens,
                        size_t ncol) {
    if (!idx || !col_values) return false;
    (void)col_types;

    switch (idx->type) {
        case QIHSE_INDEX_BTREE: {
            void* key; size_t klen;
            if (!serialize_index_key(idx, NULL, col_values, col_lens, ncol,
                                     &key, &klen))
                return false;
            bool ok = qihse_btree_insert(idx->btree, key, klen, row_id);
            free(key);
            return ok;
        }
        case QIHSE_INDEX_HASH: {
            const void* key; size_t klen;
            bool need_free;
            if (idx->ncol == 1 && idx->cols[0].type == QIHSE_IDX_COL_INT64) {
                key = col_values[0]; klen = 8; need_free = false;
            } else {
                void* k; size_t kl;
                if (!serialize_index_key(idx, NULL, col_values, col_lens,
                                         ncol, &k, &kl))
                    return false;
                key = k; klen = kl; need_free = true;
            }
            bool ok = qihse_hash_index_insert(idx->hash, key, klen, row_id);
            if (need_free) free((void*)key);
            return ok;
        }
        case QIHSE_INDEX_VECTOR_HNSW:
        case QIHSE_INDEX_FTS_INVERTED: {
            if (!idx->vtbl.insert_fn) return false;
            /* For wrapped indexes, we pass the first column's data as the
             * payload (vector floats for HNSW, text for FTS). */
            const void* data = ncol > 0 ? col_values[0] : NULL;
            size_t dlen = ncol > 0 ? col_lens[0] : 0;
            return idx->vtbl.insert_fn(idx->wrapped_handle, row_id, data, dlen);
        }
        default:
            return false;
    }
}

bool qihse_index_delete(qihse_index_t* idx,
                        uint64_t row_id,
                        const qihse_idx_col_type_t* col_types,
                        const void* const* col_values,
                        const size_t* col_lens,
                        size_t ncol) {
    if (!idx || !col_values) return false;

    (void)col_types;
    switch (idx->type) {
        case QIHSE_INDEX_BTREE: {
            void* key; size_t klen;
            if (!serialize_index_key(idx, NULL, col_values, col_lens, ncol,
                                     &key, &klen))
                return false;
            bool ok = qihse_btree_delete(idx->btree, key, klen, NULL);
            free(key);
            return ok;
        }
        case QIHSE_INDEX_HASH: {
            const void* key; size_t klen;
            bool need_free;
            if (idx->ncol == 1 && idx->cols[0].type == QIHSE_IDX_COL_INT64) {
                key = col_values[0]; klen = 8; need_free = false;
            } else {
                void* k; size_t kl;
                if (!serialize_index_key(idx, NULL, col_values, col_lens,
                                         ncol, &k, &kl))
                    return false;
                key = k; klen = kl; need_free = true;
            }
            bool ok = qihse_hash_index_delete(idx->hash, key, klen, NULL);
            if (need_free) free((void*)key);
            return ok;
        }
        case QIHSE_INDEX_VECTOR_HNSW:
        case QIHSE_INDEX_FTS_INVERTED: {
            if (!idx->vtbl.delete_fn) return false;
            return idx->vtbl.delete_fn(idx->wrapped_handle, row_id);
        }
        default:
            return false;
    }
}

bool qihse_index_manager_insert_row(qihse_index_manager_t* mgr,
                                    uint64_t row_id,
                                    const qihse_idx_col_type_t* col_types,
                                    const void* const* col_values,
                                    const size_t* col_lens,
                                    size_t ncol) {
    if (!mgr) return false;
    pthread_rwlock_rdlock(&mgr->lock);
    bool ok = true;
    for (qihse_index_t* cur = mgr->head; cur; cur = cur->next) {
        if (!qihse_index_insert(cur, row_id, col_types, col_values, col_lens, ncol))
            ok = false;
    }
    pthread_rwlock_unlock(&mgr->lock);
    return ok;
}

bool qihse_index_manager_delete_row(qihse_index_manager_t* mgr,
                                    uint64_t row_id,
                                    const qihse_idx_col_type_t* col_types,
                                    const void* const* col_values,
                                    const size_t* col_lens,
                                    size_t ncol) {
    if (!mgr) return false;
    pthread_rwlock_rdlock(&mgr->lock);
    bool ok = true;
    for (qihse_index_t* cur = mgr->head; cur; cur = cur->next) {
        if (!qihse_index_delete(cur, row_id, col_types, col_values, col_lens, ncol))
            ok = false;
    }
    pthread_rwlock_unlock(&mgr->lock);
    return ok;
}

/* ------------------------------------------------------------------ */
/* Bulk load                                                           */
/* ------------------------------------------------------------------ */

/* Simple qsort comparator for (row_id, key) pairs. */
typedef struct {
    uint64_t row_id;
    const void* key;
    size_t key_len;
} bulk_entry_t;

static int bulk_cmp(const void* a, const void* b) {
    const bulk_entry_t* ea = (const bulk_entry_t*)a;
    const bulk_entry_t* eb = (const bulk_entry_t*)b;
    size_t n = ea->key_len < eb->key_len ? ea->key_len : eb->key_len;
    int c = n ? memcmp(ea->key, eb->key, n) : 0;
    if (c != 0) return c;
    if (ea->key_len < eb->key_len) return -1;
    if (ea->key_len > eb->key_len) return 1;
    return 0;
}

bool qihse_index_bulk_load(qihse_index_t* idx,
                           const uint64_t* row_ids,
                           const void* const* keys,
                           const size_t* key_lens,
                           size_t nrows) {
    if (!idx || !row_ids || !keys || !key_lens) return false;
    if (idx->type != QIHSE_INDEX_BTREE) {
        /* For non-BTREE, fall back to per-row insert. */
        for (size_t i = 0; i < nrows; i++) {
            if (!qihse_btree_insert(idx->btree, keys[i], key_lens[i], row_ids[i]))
                return false;
        }
        return true;
    }

    /* Sort entries by key, then insert in order. */
    bulk_entry_t* entries = (bulk_entry_t*)malloc(nrows * sizeof(bulk_entry_t));
    if (!entries) return false;
    for (size_t i = 0; i < nrows; i++) {
        entries[i].row_id = row_ids[i];
        entries[i].key = keys[i];
        entries[i].key_len = key_lens[i];
    }
    qsort(entries, nrows, sizeof(bulk_entry_t), bulk_cmp);
    bool ok = true;
    for (size_t i = 0; i < nrows; i++) {
        if (!qihse_btree_insert(idx->btree, entries[i].key, entries[i].key_len,
                                entries[i].row_id)) {
            ok = false;
            break;
        }
    }
    free(entries);
    return ok;
}

/* ------------------------------------------------------------------ */
/* Accessors                                                           */
/* ------------------------------------------------------------------ */

qihse_index_type_t qihse_index_type(const qihse_index_t* idx) {
    return idx ? idx->type : QIHSE_INDEX_BTREE;
}
const char* qihse_index_name(const qihse_index_t* idx) {
    return idx ? idx->name : NULL;
}
size_t qihse_index_ncols(const qihse_index_t* idx) {
    return idx ? idx->ncol : 0;
}
const qihse_idx_col_def_t* qihse_index_cols(const qihse_index_t* idx) {
    return idx ? idx->cols : NULL;
}
qihse_btree_t* qihse_index_btree(const qihse_index_t* idx) {
    return idx ? idx->btree : NULL;
}
qihse_hash_index_t* qihse_index_hash(const qihse_index_t* idx) {
    return idx ? idx->hash : NULL;
}
void* qihse_index_wrapped_handle(const qihse_index_t* idx) {
    return idx ? idx->wrapped_handle : NULL;
}
