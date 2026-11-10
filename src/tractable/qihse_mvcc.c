#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
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
#include <errno.h>
#include <limits.h>

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

/* ── Version creation (must hold lock) ──────────────────────────────────── */

static qihse_mvcc_version_t* version_create(qihse_mvcc_store_t* store,
                                            uint64_t txn_id,
                                            const void* value, size_t value_len,
                                            qihse_mvcc_row_t** new_row)
{
    /* One reservation covers the optional new row, version and payload.
     * No later allocation can strand a value-sized reservation. */
    size_t align = sizeof(void*) == 8 ? 16u : 8u;
    size_t row_bytes = new_row ? (sizeof(qihse_mvcc_row_t) + align - 1) & ~(align - 1) : 0;
    size_t version_bytes = (sizeof(qihse_mvcc_version_t) + align - 1) & ~(align - 1);
    if (value_len > SIZE_MAX - row_bytes - version_bytes) { errno = EOVERFLOW; return NULL; }
    unsigned char* block = qihse_arena_alloc(store->arena, row_bytes + version_bytes + value_len);
    if (!block) { errno = ENOMEM; return NULL; }
    if (new_row) { *new_row = (qihse_mvcc_row_t*)block; memset(*new_row, 0, sizeof(**new_row)); }
    qihse_mvcc_version_t* v = (qihse_mvcc_version_t*)(block + row_bytes);
    v->xmin = txn_id;
    v->xmax = QIHSE_MVCC_INVALID_XMAX;
    v->value_len = value_len;
    v->is_delete = false;
    v->delete_snapshot = 0;
    v->next = NULL;

    if (value_len > 0 && value) {
        v->value = block + row_bytes + version_bytes;
        memcpy(v->value, value, value_len);
    } else {
        v->value = NULL;
        v->value_len = 0;
    }
    return v;
}

/* Prepare every allocation before publishing either a row or an xmax.
 * An allocation failure must not hide the previous committed value. */
static int write_version_locked(qihse_mvcc_store_t* store, uint8_t engine_id,
                                const void* key, size_t key_len,
                                const void* value, size_t value_len,
                                uint64_t txn_id, bool supersede) {
    if (store->total_versions == INT_MAX) { errno = EOVERFLOW; return -1; }
    qihse_mvcc_row_t* row = row_lookup(store, engine_id, key, key_len);
    if (!row && store->total_rows == INT_MAX) { errno = EOVERFLOW; return -1; }
    qihse_mvcc_row_t* reserved_row = NULL;
    qihse_mvcc_version_t* v = version_create(store, txn_id, value, value_len,
                                             row ? NULL : &reserved_row);
    if (!v) return -1;
    if (!row) {
        row = reserved_row;
        row->engine_id = engine_id;
        row->key_len = key_len;
        memcpy(row->key, key, key_len);
        row->key[key_len] = '\0';
        size_t bucket = mvcc_hash(engine_id, key, key_len, store->n_buckets);
        row->next = store->buckets[bucket];
        store->buckets[bucket] = row;
        store->total_rows++;
    }
    if (supersede) {
        qihse_mvcc_version_t* prev = row->head;
        while (prev && prev->is_delete) prev = prev->next;
        if (prev && prev->xmax == QIHSE_MVCC_INVALID_XMAX) prev->xmax = txn_id;
    }
    v->next = row->head;
    row->head = v;
    store->total_versions++;
    return 0;
}

/* ── Lifecycle ──────────────────────────────────────────────────────────── */

qihse_mvcc_store_t* qihse_mvcc_store_create(size_t initial_buckets) {
    if (initial_buckets == 0) initial_buckets = 1024;
    if (initial_buckets > SIZE_MAX / sizeof(void*)) { errno = EOVERFLOW; return NULL; }

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
    if (!store || !key || key_len >= QIHSE_MVCC_MAX_KEY ||
        (!value && value_len) || !txn_id) { errno = EINVAL; return -1; }

    pthread_mutex_lock(&store->lock);

    int rc = write_version_locked(store, engine_id, key, key_len,
                                   value, value_len, txn_id, false);
    pthread_mutex_unlock(&store->lock);
    return rc;
}

/* ── Delete ─────────────────────────────────────────────────────────────── */

int qihse_mvcc_delete(qihse_mvcc_store_t* store,
                      uint8_t engine_id,
                      const void* key, size_t key_len,
                      uint64_t txn_id)
{
    if (!store || !key || key_len >= QIHSE_MVCC_MAX_KEY || !txn_id) {
        errno = EINVAL; return -1;
    }

    pthread_mutex_lock(&store->lock);

    qihse_mvcc_row_t* row = row_lookup(store, engine_id, key, key_len);
    if (!row || !row->head) {
        pthread_mutex_unlock(&store->lock);
        return -1;
    }
    if (store->total_versions == INT_MAX) {
        pthread_mutex_unlock(&store->lock); errno = EOVERFLOW; return -1;
    }

    /*
     * Record a delete intent at the head of the chain instead of marking xmax
     * on a version.
     *
     * The head is not necessarily the version a reader at this transaction's
     * snapshot sees: it may be a version whose writer aborted (or an earlier
     * delete intent), and this call has no commit context, so it cannot tell a
     * committed version from an aborted one.  Marking the wrong version leaves
     * a committed DELETE's row visible; marking every version hides versions
     * the delete never saw (and overwriting an older marker resurrects a row
     * an earlier committed DELETE hid).
     *
     * The intent records the deleting transaction and the snapshot the delete
     * is evaluated at (this transaction's id -- the snapshot a reader of this
     * delete uses).  qihse_mvcc_read() resolves it with commit context and
     * hides exactly the versions that were visible at that snapshot.
     */
    qihse_mvcc_version_t* v = version_create(store, txn_id, NULL, 0, NULL);
    if (!v) {
        pthread_mutex_unlock(&store->lock);
        return -1;
    }
    v->is_delete = true;
    v->delete_snapshot = txn_id;

    v->next = row->head;
    row->head = v;
    store->total_versions++;

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
    if (!store || !key || key_len >= QIHSE_MVCC_MAX_KEY ||
        (!value && value_len) || !txn_id) { errno = EINVAL; return -1; }

    pthread_mutex_lock(&store->lock);

    int rc = write_version_locked(store, engine_id, key, key_len,
                                   value, value_len, txn_id, true);
    pthread_mutex_unlock(&store->lock);
    return rc;
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

/* True when a delete intent above v in the chain deletes v.
 *
 * The intent deletes the versions that were visible at the snapshot it was
 * evaluated at, so it hides v only if v was itself visible at that snapshot.
 * That is what keeps the delete precise: a version written by a transaction
 * the deleter could not see (xmin above the deleting snapshot) stays visible,
 * and a version already superseded or hidden by an earlier committed delete
 * was not visible there either, so the intent never resurrects it.
 *
 * A delete that has not committed (or has aborted) hides nothing.
 */
static bool version_deleted_by_intent(const qihse_mvcc_version_t* head,
                                      const qihse_mvcc_version_t* v,
                                      uint64_t snapshot,
                                      qihse_mvcc_committed_cb is_committed,
                                      void* committed_ctx)
{
    for (const qihse_mvcc_version_t* p = head; p && p != v; p = p->next) {
        if (!p->is_delete) continue;
        /* The delete must be visible to this reader ... */
        if (p->xmin > snapshot) continue;
        if (is_committed && !is_committed(committed_ctx, p->xmin)) continue;
        /* ... and it deletes v only if v was visible where it was taken. */
        if (version_visible(v, p->delete_snapshot, is_committed, committed_ctx))
            return true;
    }
    return false;
}

/* ── Read ───────────────────────────────────────────────────────────────── */

typedef struct {
    uint64_t txn_id;
    bool committed;
} gc_txn_t;

static int gc_txn_compare(const void* a, const void* b) {
    uint64_t x = ((const gc_txn_t*)a)->txn_id, y = ((const gc_txn_t*)b)->txn_id;
    return (x > y) - (x < y);
}

typedef struct { gc_txn_t* states; size_t count; } read_commit_view_t;

static bool read_commit_cached(void* ctx, uint64_t id) {
    read_commit_view_t* view = ctx;
    gc_txn_t key = {.txn_id = id};
    const gc_txn_t* state = view->count ? bsearch(&key, view->states,
        view->count, sizeof(*view->states), gc_txn_compare) : NULL;
    return state && state->committed;
}

bool qihse_mvcc_read(qihse_mvcc_store_t* store,
                     uint8_t engine_id,
                     const void* key, size_t key_len,
                     uint64_t snapshot,
                     qihse_mvcc_committed_cb is_committed,
                     void* committed_ctx,
                     const void** out_value, size_t* out_value_len)
{
    if (out_value) *out_value = NULL;
    if (out_value_len) *out_value_len = 0;
    if (!store || !key || key_len >= QIHSE_MVCC_MAX_KEY) {
        errno = EINVAL; return false;
    }

    pthread_mutex_lock(&store->lock);

    qihse_mvcc_row_t* row = row_lookup(store, engine_id, key, key_len);
    if (!row) {
        pthread_mutex_unlock(&store->lock);
        return false;
    }

    /* Commit callbacks may acquire the transaction-manager lock. Commit's
     * engine callbacks can acquire this store lock in the opposite direction,
     * so resolve status against a private metadata snapshot without our lock.
     * Payloads remain arena-owned and stable until store destruction. */
    qihse_mvcc_version_t* copies = NULL;
    qihse_mvcc_version_t* head = row->head;
    read_commit_view_t commit_view = {0};
    if (is_committed) {
        size_t count = 0;
        for (qihse_mvcc_version_t* p = head; p; p = p->next) count++;
        if (count > SIZE_MAX / sizeof(*copies) ||
            (count && !(copies = malloc(count * sizeof(*copies))))) {
            pthread_mutex_unlock(&store->lock); errno = ENOMEM; return false;
        }
        size_t i = 0;
        for (qihse_mvcc_version_t* p = head; p; p = p->next, i++) {
            copies[i] = *p;
            copies[i].next = i + 1 < count ? &copies[i + 1] : NULL;
        }
        head = copies;
        pthread_mutex_unlock(&store->lock);
        /* Resolve each transaction once. A commit between two checks of the
         * same ID must not make both the new and old versions invisible. */
        if (count > SIZE_MAX / 2u / sizeof(*commit_view.states) ||
            (count && !(commit_view.states = malloc(2u * count * sizeof(*commit_view.states))))) {
            free(copies); errno = ENOMEM; return false;
        }
        size_t n = 0;
        for (size_t j = 0; j < count; j++) {
            commit_view.states[n++] = (gc_txn_t){.txn_id = copies[j].xmin};
            if (copies[j].xmax)
                commit_view.states[n++] = (gc_txn_t){.txn_id = copies[j].xmax};
        }
        if (n > 1) qsort(commit_view.states, n, sizeof(*commit_view.states), gc_txn_compare);
        for (size_t j = 0; j < n; j++)
            if (!commit_view.count || commit_view.states[j].txn_id !=
                commit_view.states[commit_view.count - 1].txn_id)
                commit_view.states[commit_view.count++] = commit_view.states[j];
        for (size_t j = 0; j < commit_view.count; j++)
            commit_view.states[j].committed = is_committed(committed_ctx,
                commit_view.states[j].txn_id);
        is_committed = read_commit_cached;
        committed_ctx = &commit_view;
    }

    /* Walk the chain from newest to oldest, return first visible version.
     * A delete intent is a marker rather than a version: it is never returned,
     * and it can hide the versions below it that were visible at the snapshot
     * it was evaluated at.  Chains with no delete intent (the common case) take
     * the same path as before -- no intent is ever consulted. */
    qihse_mvcc_version_t* v = head;
    int intents_above = 0;
    while (v) {
        if (v->is_delete) {
            intents_above++;
            v = v->next;
            continue;
        }
        if (version_visible(v, snapshot, is_committed, committed_ctx) &&
            (intents_above == 0 ||
             !version_deleted_by_intent(head, v, snapshot,
                                        is_committed, committed_ctx)))
        {
            if (out_value)     *out_value = v->value;
            if (out_value_len) *out_value_len = v->value_len;
            if (!is_committed) pthread_mutex_unlock(&store->lock);
            free(copies);
            free(commit_view.states);
            return true;
        }
        v = v->next;
    }

    if (!is_committed) pthread_mutex_unlock(&store->lock);
    free(copies);
    free(commit_view.states);
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

int qihse_mvcc_gc_committed(qihse_mvcc_store_t* store, uint64_t min_snapshot,
                            qihse_mvcc_committed_cb is_committed,
                            void* committed_ctx) {
    if (!store || !is_committed) { errno = EINVAL; return -1; }

    int reclaimed = 0;
    pthread_mutex_lock(&store->lock);
    size_t capacity = (size_t)store->total_versions;
    if (capacity > SIZE_MAX / sizeof(gc_txn_t)) {
        pthread_mutex_unlock(&store->lock); errno = EOVERFLOW; return -1;
    }
    gc_txn_t* states = capacity ? malloc(capacity * sizeof(*states)) : NULL;
    if (capacity && !states) {
        pthread_mutex_unlock(&store->lock); errno = ENOMEM; return -1;
    }
    size_t count = 0;
    for (size_t b = 0; b < store->n_buckets; b++)
        for (qihse_mvcc_row_t* row = store->buckets[b]; row; row = row->next)
            for (qihse_mvcc_version_t* v = row->head; v; v = v->next)
                if (!v->is_delete && v->xmax && v->xmax < min_snapshot)
                    states[count++] = (gc_txn_t){.txn_id = v->xmax};
    pthread_mutex_unlock(&store->lock);
    if (count > 1) qsort(states, count, sizeof(*states), gc_txn_compare);
    size_t unique = 0;
    for (size_t i = 0; i < count; i++)
        if (!unique || states[i].txn_id != states[unique - 1].txn_id)
            states[unique++] = states[i];
    for (size_t i = 0; i < unique; i++)
        states[i].committed = is_committed(committed_ctx, states[i].txn_id);
    pthread_mutex_lock(&store->lock);

    for (size_t b = 0; b < store->n_buckets; b++) {
        qihse_mvcc_row_t* row = store->buckets[b];
        while (row) {
            /* Walk the chain and remove dead versions.
             * A version is dead if xmax is set AND xmax < min_snapshot
             * AND its superseding transaction actually committed. An aborted
             * or active xmax does not make the old data dead. */
            qihse_mvcc_version_t** pp = &row->head;
            while (*pp) {
                qihse_mvcc_version_t* v = *pp;
                if (v->is_delete) {
                    /* A delete intent is a marker, not a version. Removing it
                     * can resurrect versions it hides; retain it until a
                     * collector also proves those versions can be removed. */
                    pp = &v->next;
                    continue;
                }
                gc_txn_t key = {.txn_id = v->xmax};
                const gc_txn_t* state = unique
                    ? bsearch(&key, states, unique, sizeof(*states), gc_txn_compare) : NULL;
                if (v->xmax != QIHSE_MVCC_INVALID_XMAX &&
                    v->xmax < min_snapshot && state && state->committed)
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
    free(states);
    return reclaimed;
}

int qihse_mvcc_gc(qihse_mvcc_store_t* store, uint64_t min_snapshot) {
    /* This legacy signature has no commit knowledge. It cannot distinguish
     * a dead version from a value preserved by an aborted update. */
    (void)store; (void)min_snapshot;
    return 0;
}

int qihse_mvcc_vacuum(qihse_mvcc_store_t* store, uint64_t min_snapshot) {
    /* Vacuum = GC + compact.  Since we use arena allocation, compaction
     * is limited to removing dead versions from chains. */
    return qihse_mvcc_gc(store, min_snapshot);
}

int qihse_mvcc_vacuum_committed(qihse_mvcc_store_t* store, uint64_t min_snapshot,
                                qihse_mvcc_committed_cb is_committed,
                                void* committed_ctx) {
    return qihse_mvcc_gc_committed(store, min_snapshot, is_committed, committed_ctx);
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
