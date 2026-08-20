#define _GNU_SOURCE
/*
 * QIHSE MVCC Version Store
 *
 * Phase 2: ACID Transactions & MVCC
 *
 * Implements per-row version chains with xmin/xmax metadata, snapshot
 * visibility checks, garbage collection, and vacuum.
 */

#include "qihse_mvcc.h"
#include "qihse_arena.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* ── Internal structures ────────────────────────────────────────────────── */

struct qihse_mvcc_store {
    pthread_mutex_t   lock;
    qihse_arena_t*    arena;
    size_t            n_buckets;
    qihse_mvcc_row_t** buckets;
    int               total_versions;
    int               total_rows;
};

/* ── Hash function ──────────────────────────────────────────────────────── */

static size_t mvcc_hash(uint8_t engine_id, const void* key, size_t key_len,
                        size_t n_buckets)
{
    const uint8_t* p = (const uint8_t*)key;
    size_t h = (size_t)engine_id * 31;
    for (size_t i = 0; i < key_len; i++) {
        h = h * 31 + p[i];
    }
    return h % n_buckets;
}

/* ── Row lookup (must hold lock) ────────────────────────────────────────── */

static qihse_mvcc_row_t* row_lookup(qihse_mvcc_store_t* store,
                                    uint8_t engine_id,
                                    const void* key, size_t key_len)
{
    size_t b = mvcc_hash(engine_id, key, key_len, store->n_buckets);
    qihse_mvcc_row_t* row = store->buckets[b];
    while (row) {
        if (row->engine_id == engine_id &&
            row->key_len == key_len &&
            memcmp(row->key, key, key_len) == 0)
        {
            return row;
        }
        row = row->next;
    }
    return NULL;
}

/* ── Row creation (must hold lock) ──────────────────────────────────────── */

static qihse_mvcc_row_t* row_create(qihse_mvcc_store_t* store,
                                    uint8_t engine_id,
                                    const void* key, size_t key_len)
{
    if (key_len >= QIHSE_MVCC_MAX_KEY) return NULL;

    size_t b = mvcc_hash(engine_id, key, key_len, store->n_buckets);
    qihse_mvcc_row_t* row = qihse_arena_alloc(store->arena, sizeof(*row));
    if (!row) return NULL;
    memset(row, 0, sizeof(*row));
    row->engine_id = engine_id;
    row->key_len   = key_len;
    memcpy(row->key, key, key_len);
    row->key[key_len] = '\0';
    row->head = NULL;
    row->next = store->buckets[b];
    store->buckets[b] = row;
    store->total_rows++;
    return row;
}

/* ── Version creation (must hold lock) ──────────────────────────────────── */

static qihse_mvcc_version_t* version_create(qihse_mvcc_store_t* store,
                                            uint64_t txn_id,
                                            const void* value, size_t value_len)
{
    qihse_mvcc_version_t* v =
        qihse_arena_alloc(store->arena, sizeof(*v));
    if (!v) return NULL;
    v->xmin = txn_id;
    v->xmax = QIHSE_MVCC_INVALID_XMAX;
    v->value_len = value_len;
    v->next = NULL;

    if (value_len > 0 && value) {
        v->value = qihse_arena_alloc(store->arena, value_len);
        if (!v->value) return NULL;
        memcpy(v->value, value, value_len);
    } else {
        v->value = NULL;
        v->value_len = 0;
    }
    return v;
}

/* ── Lifecycle ──────────────────────────────────────────────────────────── */

qihse_mvcc_store_t* qihse_mvcc_store_create(size_t initial_buckets) {
    if (initial_buckets == 0) initial_buckets = 1024;

    qihse_mvcc_store_t* store = calloc(1, sizeof(*store));
    if (!store) return NULL;

    pthread_mutex_init(&store->lock, NULL);
    store->n_buckets = initial_buckets;
    store->total_versions = 0;
    store->total_rows = 0;

    store->arena = qihse_arena_create(256 * 1024);
    if (!store->arena) {
        pthread_mutex_destroy(&store->lock);
        free(store);
        return NULL;
    }

    store->buckets = qihse_arena_alloc(
        store->arena, store->n_buckets * sizeof(void*));
    if (!store->buckets) {
        qihse_arena_destroy(store->arena);
        pthread_mutex_destroy(&store->lock);
        free(store);
        return NULL;
    }
    memset(store->buckets, 0, store->n_buckets * sizeof(void*));

    return store;
}

void qihse_mvcc_store_destroy(qihse_mvcc_store_t* store) {
    if (!store) return;
    qihse_arena_destroy(store->arena);
    pthread_mutex_destroy(&store->lock);
    free(store);
}

/* ── Insert ─────────────────────────────────────────────────────────────── */

int qihse_mvcc_insert(qihse_mvcc_store_t* store,
                      uint8_t engine_id,
                      const void* key, size_t key_len,
                      const void* value, size_t value_len,
                      uint64_t txn_id)
{
    if (!store || !key) return -1;
    if (key_len >= QIHSE_MVCC_MAX_KEY) return -1;

    pthread_mutex_lock(&store->lock);

    qihse_mvcc_row_t* row = row_lookup(store, engine_id, key, key_len);
    if (!row) {
        row = row_create(store, engine_id, key, key_len);
        if (!row) {
            pthread_mutex_unlock(&store->lock);
            return -1;
        }
    }

    qihse_mvcc_version_t* v = version_create(store, txn_id, value, value_len);
    if (!v) {
        pthread_mutex_unlock(&store->lock);
        return -1;
    }

    /* Prepend to chain (newest version at head) */
    v->next = row->head;
    row->head = v;
    store->total_versions++;

    pthread_mutex_unlock(&store->lock);
    return 0;
}

/* ── Delete ─────────────────────────────────────────────────────────────── */

int qihse_mvcc_delete(qihse_mvcc_store_t* store,
                      uint8_t engine_id,
                      const void* key, size_t key_len,
                      uint64_t txn_id)
{
    if (!store || !key) return -1;

    pthread_mutex_lock(&store->lock);

    qihse_mvcc_row_t* row = row_lookup(store, engine_id, key, key_len);
    if (!row || !row->head) {
        pthread_mutex_unlock(&store->lock);
        return -1;
    }

    /* Set xmax on the head version (the latest live version) */
    if (row->head->xmax == QIHSE_MVCC_INVALID_XMAX) {
        row->head->xmax = txn_id;
    }

    pthread_mutex_unlock(&store->lock);
    return 0;
}

/* ── Update ─────────────────────────────────────────────────────────────── */

int qihse_mvcc_update(qihse_mvcc_store_t* store,
                      uint8_t engine_id,
                      const void* key, size_t key_len,
                      const void* value, size_t value_len,
                      uint64_t txn_id)
{
    if (!store || !key) return -1;
    if (key_len >= QIHSE_MVCC_MAX_KEY) return -1;

    pthread_mutex_lock(&store->lock);

    qihse_mvcc_row_t* row = row_lookup(store, engine_id, key, key_len);
    if (!row) {
        /* Row doesn't exist — treat as insert */
        pthread_mutex_unlock(&store->lock);
        return qihse_mvcc_insert(store, engine_id, key, key_len,
                                 value, value_len, txn_id);
    }

    /* Set xmax on the current head */
    if (row->head && row->head->xmax == QIHSE_MVCC_INVALID_XMAX) {
        row->head->xmax = txn_id;
    }

    /* Create new version and prepend */
    qihse_mvcc_version_t* v = version_create(store, txn_id, value, value_len);
    if (!v) {
        pthread_mutex_unlock(&store->lock);
        return -1;
    }

    v->next = row->head;
    row->head = v;
    store->total_versions++;

    pthread_mutex_unlock(&store->lock);
    return 0;
}

/* ── Visibility check ───────────────────────────────────────────────────── */

static bool version_visible(const qihse_mvcc_version_t* v,
                            uint64_t snapshot,
                            qihse_mvcc_committed_cb is_committed,
                            void* committed_ctx)
{
    /* A version is visible if:
     *   1. xmin <= snapshot AND xmin is committed (or xmin == current txn)
     *   2. xmax == 0 (not deleted) OR xmax > snapshot
     *      OR xmax is not committed (aborted/active) */
    if (v->xmin > snapshot) return false;

    /* xmin must be committed (or the transaction itself, handled by caller
     * passing snapshot >= own txn_id).  If is_committed callback is provided,
     * check it.  Otherwise assume visible. */
    if (is_committed && !is_committed(committed_ctx, v->xmin)) {
        /* xmin's transaction is not committed — not visible */
        return false;
    }

    if (v->xmax == QIHSE_MVCC_INVALID_XMAX) return true;

    /* xmax > snapshot means the delete happened after our snapshot */
    if (v->xmax > snapshot) return true;

    /* xmax <= snapshot: check if the deleting txn was committed */
    if (is_committed && !is_committed(committed_ctx, v->xmax)) {
        /* The delete was by an uncommitted/aborted txn — version still visible */
        return true;
    }

    return false;
}

/* ── Read ───────────────────────────────────────────────────────────────── */

bool qihse_mvcc_read(qihse_mvcc_store_t* store,
                     uint8_t engine_id,
                     const void* key, size_t key_len,
                     uint64_t snapshot,
                     qihse_mvcc_committed_cb is_committed,
                     void* committed_ctx,
                     const void** out_value, size_t* out_value_len)
{
    if (!store || !key) return false;

    pthread_mutex_lock(&store->lock);

    qihse_mvcc_row_t* row = row_lookup(store, engine_id, key, key_len);
    if (!row) {
        pthread_mutex_unlock(&store->lock);
        return false;
    }

    /* Walk the chain from newest to oldest, return first visible version */
    qihse_mvcc_version_t* v = row->head;
    while (v) {
        if (version_visible(v, snapshot, is_committed, committed_ctx)) {
            if (out_value)     *out_value = v->value;
            if (out_value_len) *out_value_len = v->value_len;
            pthread_mutex_unlock(&store->lock);
            return true;
        }
        v = v->next;
    }

    pthread_mutex_unlock(&store->lock);
    return false;
}

/* ── Exists ─────────────────────────────────────────────────────────────── */

bool qihse_mvcc_exists(qihse_mvcc_store_t* store,
                       uint8_t engine_id,
                       const void* key, size_t key_len,
                       uint64_t snapshot,
                       qihse_mvcc_committed_cb is_committed,
                       void* committed_ctx)
{
    return qihse_mvcc_read(store, engine_id, key, key_len, snapshot,
                           is_committed, committed_ctx, NULL, NULL);
}

/* ── Garbage collection / vacuum ────────────────────────────────────────── */

uint64_t qihse_mvcc_min_active_snapshot(qihse_mvcc_store_t* store) {
    (void)store;
    /* This is typically provided by the transaction manager.
     * Here we return 0 as a placeholder — the caller should pass the
     * actual min active snapshot from the txn manager. */
    return 0;
}

int qihse_mvcc_gc(qihse_mvcc_store_t* store, uint64_t min_snapshot) {
    if (!store) return 0;

    int reclaimed = 0;
    pthread_mutex_lock(&store->lock);

    for (size_t b = 0; b < store->n_buckets; b++) {
        qihse_mvcc_row_t* row = store->buckets[b];
        while (row) {
            /* Walk the chain and remove dead versions.
             * A version is dead if xmax is set AND xmax < min_snapshot
             * (i.e., the delete is visible to all active transactions). */
            qihse_mvcc_version_t** pp = &row->head;
            while (*pp) {
                qihse_mvcc_version_t* v = *pp;
                if (v->xmax != QIHSE_MVCC_INVALID_XMAX &&
                    v->xmax < min_snapshot)
                {
                    /* This version is dead — remove from chain */
                    *pp = v->next;
                    /* Note: arena-allocated, can't individually free.
                     * The memory will be reclaimed when the arena is
                     * destroyed or reset.  For a production system,
                     * we'd use malloc/free for version nodes. */
                    store->total_versions--;
                    reclaimed++;
                } else {
                    pp = &v->next;
                }
            }
            row = row->next;
        }
    }

    pthread_mutex_unlock(&store->lock);
    return reclaimed;
}

int qihse_mvcc_vacuum(qihse_mvcc_store_t* store, uint64_t min_snapshot) {
    /* Vacuum = GC + compact.  Since we use arena allocation, compaction
     * is limited to removing dead versions from chains. */
    return qihse_mvcc_gc(store, min_snapshot);
}

/* ── Debug / inspection ─────────────────────────────────────────────────── */

int qihse_mvcc_version_count(qihse_mvcc_store_t* store) {
    if (!store) return 0;
    pthread_mutex_lock(&store->lock);
    int count = store->total_versions;
    pthread_mutex_unlock(&store->lock);
    return count;
}

int qihse_mvcc_row_count(qihse_mvcc_store_t* store) {
    if (!store) return 0;
    pthread_mutex_lock(&store->lock);
    int count = store->total_rows;
    pthread_mutex_unlock(&store->lock);
    return count;
}
