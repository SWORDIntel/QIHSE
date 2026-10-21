#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
/*
 * QIHSE Transaction Manager
 *
 * Phase 2: ACID Transactions & MVCC
 *
 * Provides BEGIN/COMMIT/ROLLBACK/SAVEPOINT, per-transaction snapshots,
 * a transaction registry, isolation levels (READ COMMITTED, REPEATABLE READ,
 * SERIALIZABLE with OCC), and a 2PC coordinator interface.
 */

#include "qihse_txn.h"
#include "qihse_arena.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* ── Internal structures ────────────────────────────────────────────────── */

/* Registry entry for tracking committed / aborted transaction IDs. */
typedef struct qihse_txn_registry_entry_s {
    uint64_t txn_id;
    qihse_txn_state_t state;
    struct qihse_txn_registry_entry_s* next;
} qihse_txn_registry_entry_t;

/* Active transaction list node. */
typedef struct qihse_active_node_s {
    qihse_txn_t* txn;
    struct qihse_active_node_s* next;
} qihse_active_node_t;

/* A committed transaction's writes remain here while an active SERIALIZABLE
 * transaction has a snapshot older than the commit.  Validation needs only
 * writes from the committed side: they are compared with both reads and
 * writes of the transaction being validated. */
typedef struct qihse_committed_summary_s {
    uint64_t commit_seq;
    uint64_t txn_id;
    qihse_rw_entry_t* writes;
    int write_count;
    struct qihse_committed_summary_s* next;
} qihse_committed_summary_t;

struct qihse_txn_manager {
    pthread_mutex_t          lock;
    uint64_t                 next_txn_id;
    qihse_arena_t*           arena;
    /* Active transactions (linked list) */
    qihse_active_node_t*     active_head;
    /* Committed/aborted registry (hash table for quick lookup) */
    qihse_txn_registry_entry_t** registry_buckets;
    size_t                   registry_n_buckets;
    int                      active_count;
    uint64_t                 commit_seq;
    qihse_committed_summary_t* committed_head;
    qihse_committed_summary_t* committed_tail;
    size_t                   committed_count;
    /* 2PC participants */
    qihse_txn_participant_t  participants[QIHSE_TXN_MAX_PARTICIPANTS];
    int                      participant_count;
};

/* ── Registry hash ──────────────────────────────────────────────────────── */

static size_t registry_hash(uint64_t txn_id, size_t n_buckets) {
    /* Simple multiplicative hash */
    return (size_t)((txn_id * 2654435761u) % n_buckets);
}

static qihse_txn_registry_entry_t* registry_find(
    qihse_txn_manager_t* mgr, uint64_t txn_id)
{
    if (!mgr->registry_buckets) return NULL;
    size_t b = registry_hash(txn_id, mgr->registry_n_buckets);
    qihse_txn_registry_entry_t* e = mgr->registry_buckets[b];
    while (e) {
        if (e->txn_id == txn_id) return e;
        e = e->next;
    }
    return NULL;
}

static qihse_txn_registry_entry_t* registry_alloc(
    qihse_txn_manager_t* mgr, uint64_t txn_id, qihse_txn_state_t state)
{
    if (!mgr->registry_buckets) return NULL;
    qihse_txn_registry_entry_t* e =
        qihse_arena_alloc(mgr->arena, sizeof(*e));
    if (!e) return NULL;
    e->txn_id = txn_id;
    e->state  = state;
    e->next = NULL;
    return e;
}

static void registry_link(qihse_txn_manager_t* mgr,
                          qihse_txn_registry_entry_t* e) {
    size_t b = registry_hash(e->txn_id, mgr->registry_n_buckets);
    e->next   = mgr->registry_buckets[b];
    mgr->registry_buckets[b] = e;
}

static bool registry_insert(qihse_txn_manager_t* mgr,
                            uint64_t txn_id, qihse_txn_state_t state)
{
    qihse_txn_registry_entry_t* e = registry_alloc(mgr, txn_id, state);
    if (!e) return false;
    registry_link(mgr, e);
    return true;
}

/* ── Active list management ─────────────────────────────────────────────── */

static bool active_add(qihse_txn_manager_t* mgr, qihse_txn_t* txn) {
    qihse_active_node_t* node = qihse_arena_alloc(mgr->arena, sizeof(*node));
    if (!node) return false;
    node->txn  = txn;
    node->next = mgr->active_head;
    mgr->active_head = node;
    mgr->active_count++;
    return true;
}

static void active_remove(qihse_txn_manager_t* mgr, uint64_t txn_id) {
    qihse_active_node_t** pp = &mgr->active_head;
    while (*pp) {
        if ((*pp)->txn->id == txn_id) {
            qihse_active_node_t* dead = *pp;
            *pp = dead->next;
            /* Don't arena-free the node (arena is bump-allocated); just unlink */
            mgr->active_count--;
            return;
        }
        pp = &(*pp)->next;
    }
}

static void committed_summary_free(qihse_committed_summary_t* summary) {
    if (!summary) return;
    free(summary->writes);
    free(summary);
}

static uint64_t min_serializable_snapshot_locked(qihse_txn_manager_t* mgr,
                                                 bool* found) {
    uint64_t minimum = UINT64_MAX;
    *found = false;
    for (qihse_active_node_t* node = mgr->active_head; node; node = node->next) {
        qihse_txn_t* txn = node->txn;
        if (!txn || txn->isolation != QIHSE_ISO_SERIALIZABLE ||
            (txn->state != QIHSE_TXN_ACTIVE && txn->state != QIHSE_TXN_PREPARED))
            continue;
        if (!*found || txn->serialization_snapshot < minimum)
            minimum = txn->serialization_snapshot;
        *found = true;
    }
    return minimum;
}

static void prune_committed_history_locked(qihse_txn_manager_t* mgr) {
    bool found = false;
    uint64_t minimum = min_serializable_snapshot_locked(mgr, &found);
    while (mgr->committed_head &&
           (!found || mgr->committed_head->commit_seq <= minimum)) {
        qihse_committed_summary_t* dead = mgr->committed_head;
        mgr->committed_head = dead->next;
        if (!mgr->committed_head) mgr->committed_tail = NULL;
        mgr->committed_count--;
        committed_summary_free(dead);
    }
}

static bool summary_needed_locked(qihse_txn_manager_t* mgr,
                                  const qihse_txn_t* committing) {
    if (committing->write_count == 0) return false;
    for (qihse_active_node_t* node = mgr->active_head; node; node = node->next) {
        qihse_txn_t* txn = node->txn;
        if (txn && txn != committing && txn->isolation == QIHSE_ISO_SERIALIZABLE &&
            (txn->state == QIHSE_TXN_ACTIVE || txn->state == QIHSE_TXN_PREPARED))
            return true;
    }
    return false;
}

static qihse_committed_summary_t* committed_summary_create(
    const qihse_txn_t* txn, uint64_t commit_seq)
{
    qihse_committed_summary_t* summary = calloc(1, sizeof(*summary));
    if (!summary) return NULL;
    summary->commit_seq = commit_seq;
    summary->txn_id = txn->id;

    int writes = 0;
    for (int i = 0; i < txn->rw_count; i++)
        if (txn->rw_set[i].is_write) writes++;
    if (writes > 0) {
        summary->writes = calloc((size_t)writes, sizeof(*summary->writes));
        if (!summary->writes) {
            free(summary);
            return NULL;
        }
        for (int i = 0; i < txn->rw_count; i++) {
            if (txn->rw_set[i].is_write)
                summary->writes[summary->write_count++] = txn->rw_set[i];
        }
    }
    return summary;
}

static void committed_summary_append_locked(qihse_txn_manager_t* mgr,
                                            qihse_committed_summary_t* summary) {
    if (!summary) return;
    if (mgr->committed_tail) mgr->committed_tail->next = summary;
    else mgr->committed_head = summary;
    mgr->committed_tail = summary;
    mgr->committed_count++;
}

static bool rw_keys_equal(const qihse_rw_entry_t* a,
                          const qihse_rw_entry_t* b) {
    return a->engine_id == b->engine_id && a->key_len == b->key_len &&
           memcmp(a->key, b->key, a->key_len) == 0;
}

static void txn_resource_rollback(qihse_txn_t* txn) {
    if (!txn || !txn->resource_ctx) return;
    if (txn->resource_rollback)
        txn->resource_rollback(txn->resource_ctx);
    txn->resource_ctx = NULL;
    txn->resource_commit = NULL;
    txn->resource_rollback = NULL;
}

static int validate_occ_locked(qihse_txn_manager_t* mgr, qihse_txn_t* txn) {
    if (txn->isolation != QIHSE_ISO_SERIALIZABLE) return 0;
    for (qihse_committed_summary_t* summary = mgr->committed_head;
         summary; summary = summary->next) {
        if (summary->commit_seq <= txn->serialization_snapshot) continue;
        for (int i = 0; i < summary->write_count; i++) {
            for (int j = 0; j < txn->rw_count; j++) {
                if (rw_keys_equal(&summary->writes[i], &txn->rw_set[j]))
                    return -1;
            }
        }
    }
    return 0;
}

/* ── Lifecycle ──────────────────────────────────────────────────────────── */

qihse_txn_manager_t* qihse_txn_manager_create(void) {
    qihse_txn_manager_t* mgr = calloc(1, sizeof(*mgr));
    if (!mgr) return NULL;

    pthread_mutex_init(&mgr->lock, NULL);
    mgr->next_txn_id     = QIHSE_TXN_FIRST_ID;
    mgr->active_head     = NULL;
    mgr->active_count    = 0;
    mgr->commit_seq      = 0;
    mgr->participant_count = 0;

    mgr->arena = qihse_arena_create(64 * 1024);
    if (!mgr->arena) {
        pthread_mutex_destroy(&mgr->lock);
        free(mgr);
        return NULL;
    }

    mgr->registry_n_buckets = 1024;
    mgr->registry_buckets = qihse_arena_alloc(
        mgr->arena, mgr->registry_n_buckets * sizeof(void*));
    if (!mgr->registry_buckets) {
        qihse_arena_destroy(mgr->arena);
        pthread_mutex_destroy(&mgr->lock);
        free(mgr);
        return NULL;
    }
    memset(mgr->registry_buckets, 0,
           mgr->registry_n_buckets * sizeof(void*));

    return mgr;
}

void qihse_txn_manager_destroy(qihse_txn_manager_t* mgr) {
    if (!mgr) return;
    pthread_mutex_lock(&mgr->lock);
    /* Free any remaining txn handles (rw_set) */
    qihse_active_node_t* node = mgr->active_head;
    while (node) {
        txn_resource_rollback(node->txn);
        if (node->txn && node->txn->rw_set) {
            free(node->txn->rw_set);
            node->txn->rw_set = NULL;
        }
        node = node->next;
    }
    qihse_committed_summary_t* summary = mgr->committed_head;
    while (summary) {
        qihse_committed_summary_t* next = summary->next;
        committed_summary_free(summary);
        summary = next;
    }
    pthread_mutex_unlock(&mgr->lock);
    qihse_arena_destroy(mgr->arena);
    pthread_mutex_destroy(&mgr->lock);
    free(mgr);
}

/* ── BEGIN ──────────────────────────────────────────────────────────────── */

qihse_txn_t* qihse_txn_begin(qihse_txn_manager_t* mgr,
                             qihse_isolation_level_t isolation)
{
    if (!mgr) return NULL;

    qihse_txn_t* txn = calloc(1, sizeof(*txn));
    if (!txn) return NULL;

    pthread_mutex_lock(&mgr->lock);
    txn->id         = mgr->next_txn_id++;
    txn->state      = QIHSE_TXN_ACTIVE;
    txn->isolation  = isolation;
    txn->start_lsn  = 0;
    txn->savepoint_count = 0;
    txn->rw_set     = NULL;
    txn->rw_count   = 0;
    txn->rw_capacity = 0;
    txn->write_count = 0;
    txn->resource_ctx = NULL;
    txn->resource_commit = NULL;
    txn->resource_rollback = NULL;

    /* Snapshot: for REPEATABLE READ and SERIALIZABLE, snapshot = current
     * next_txn_id - 1 (i.e. all txns that have started so far).
     * For READ COMMITTED, snapshot will be refreshed per statement. */
    txn->snapshot = txn->id - 1;  /* see all transactions that started before us */
    txn->serialization_snapshot = mgr->commit_seq;

    if (!active_add(mgr, txn)) {
        pthread_mutex_unlock(&mgr->lock);
        free(txn);
        return NULL;
    }
    pthread_mutex_unlock(&mgr->lock);

    return txn;
}

/* ── COMMIT ─────────────────────────────────────────────────────────────── */

int qihse_txn_commit(qihse_txn_manager_t* mgr, qihse_txn_t* txn) {
    if (!mgr || !txn) return -1;

    pthread_mutex_lock(&mgr->lock);
    if (txn->state != QIHSE_TXN_ACTIVE) {
        pthread_mutex_unlock(&mgr->lock);
        return -1;
    }

    /* SERIALIZABLE: validate against every commit after our BEGIN snapshot. */
    if (txn->isolation == QIHSE_ISO_SERIALIZABLE) {
        if (validate_occ_locked(mgr, txn) != 0) {
            /* Conflict detected — abort */
            txn->state = QIHSE_TXN_ABORTED;
            registry_insert(mgr, txn->id, QIHSE_TXN_ABORTED);
            active_remove(mgr, txn->id);
            txn_resource_rollback(txn);
            prune_committed_history_locked(mgr);
            pthread_mutex_unlock(&mgr->lock);
            return -1;
        }
    }

    if (mgr->commit_seq == UINT64_MAX) {
        txn->state = QIHSE_TXN_ABORTED;
        (void)registry_insert(mgr, txn->id, QIHSE_TXN_ABORTED);
        active_remove(mgr, txn->id);
        txn_resource_rollback(txn);
        prune_committed_history_locked(mgr);
        pthread_mutex_unlock(&mgr->lock);
        return -1;
    }
    uint64_t commit_seq = mgr->commit_seq + 1;
    qihse_committed_summary_t* summary = NULL;
    if (summary_needed_locked(mgr, txn)) {
        summary = committed_summary_create(txn, commit_seq);
        if (!summary) {
            /* Losing the write set could admit a conflicting active
             * SERIALIZABLE transaction, so allocation failure aborts. */
            txn->state = QIHSE_TXN_ABORTED;
            (void)registry_insert(mgr, txn->id, QIHSE_TXN_ABORTED);
            active_remove(mgr, txn->id);
            txn_resource_rollback(txn);
            prune_committed_history_locked(mgr);
            pthread_mutex_unlock(&mgr->lock);
            return -1;
        }
    }

    qihse_txn_registry_entry_t* registry_entry =
        registry_alloc(mgr, txn->id, QIHSE_TXN_COMMITTED);
    if (!registry_entry) {
        committed_summary_free(summary);
        txn->state = QIHSE_TXN_ABORTED;
        active_remove(mgr, txn->id);
        txn_resource_rollback(txn);
        prune_committed_history_locked(mgr);
        pthread_mutex_unlock(&mgr->lock);
        return -1;
    }

    if (txn->resource_ctx &&
        (!txn->resource_commit || txn->resource_commit(txn->resource_ctx) != 0)) {
        committed_summary_free(summary);
        registry_entry->state = QIHSE_TXN_ABORTED;
        registry_link(mgr, registry_entry);
        txn->resource_ctx = NULL; /* commit callback consumes on both outcomes */
        txn->resource_commit = NULL;
        txn->resource_rollback = NULL;
        txn->state = QIHSE_TXN_ABORTED;
        active_remove(mgr, txn->id);
        prune_committed_history_locked(mgr);
        pthread_mutex_unlock(&mgr->lock);
        return -1;
    }

    registry_link(mgr, registry_entry);
    txn->resource_ctx = NULL;
    txn->resource_commit = NULL;
    txn->resource_rollback = NULL;
    txn->state = QIHSE_TXN_COMMITTED;
    mgr->commit_seq = commit_seq;
    committed_summary_append_locked(mgr, summary);
    active_remove(mgr, txn->id);
    prune_committed_history_locked(mgr);
    pthread_mutex_unlock(&mgr->lock);

    return 0;
}

/* ── ROLLBACK ───────────────────────────────────────────────────────────── */

int qihse_txn_rollback(qihse_txn_manager_t* mgr, qihse_txn_t* txn) {
    if (!mgr || !txn) return -1;

    pthread_mutex_lock(&mgr->lock);
    if (txn->state != QIHSE_TXN_ACTIVE) {
        pthread_mutex_unlock(&mgr->lock);
        return -1;
    }
    qihse_txn_registry_entry_t* registry_entry =
        registry_alloc(mgr, txn->id, QIHSE_TXN_ABORTED);
    txn_resource_rollback(txn);
    txn->state = QIHSE_TXN_ABORTED;
    if (registry_entry) registry_link(mgr, registry_entry);
    active_remove(mgr, txn->id);
    prune_committed_history_locked(mgr);
    pthread_mutex_unlock(&mgr->lock);

    return 0;
}

/* ── SAVEPOINT ──────────────────────────────────────────────────────────── */

int qihse_txn_savepoint(qihse_txn_manager_t* mgr, qihse_txn_t* txn,
                        const char* name)
{
    if (!mgr || !txn || !name) return -1;
    pthread_mutex_lock(&mgr->lock);
    if (txn->state != QIHSE_TXN_ACTIVE) {
        pthread_mutex_unlock(&mgr->lock);
        return -1;
    }
    /* A local resource needs its own snapshot callback before savepoints can
     * safely include it.  Refuse instead of recording a partial savepoint. */
    if (txn->resource_ctx) {
        pthread_mutex_unlock(&mgr->lock);
        return -1;
    }
    /* savepoint_count is always in [0, QIHSE_TXN_MAX_SAVEPOINTS]; compare as
     * int so the signed counter is not promoted to unsigned. */
    if (txn->savepoint_count >= (int)QIHSE_TXN_MAX_SAVEPOINTS) {
        pthread_mutex_unlock(&mgr->lock);
        return -1;
    }

    qihse_savepoint_t* sp = &txn->savepoints[txn->savepoint_count];
    strncpy(sp->name, name, sizeof(sp->name) - 1);
    sp->name[sizeof(sp->name) - 1] = '\0';
    sp->lsn = txn->start_lsn;
    sp->write_count = txn->write_count;
    txn->savepoint_count++;
    pthread_mutex_unlock(&mgr->lock);
    return 0;
}

int qihse_txn_rollback_to_savepoint(qihse_txn_manager_t* mgr,
                                    qihse_txn_t* txn, const char* name)
{
    if (!mgr || !txn || !name) return -1;
    pthread_mutex_lock(&mgr->lock);
    if (txn->state != QIHSE_TXN_ACTIVE || txn->resource_ctx) {
        pthread_mutex_unlock(&mgr->lock);
        return -1;
    }

    /* Find the savepoint (search from top of stack) */
    int found = -1;
    for (int i = txn->savepoint_count - 1; i >= 0; i--) {
        if (strcmp(txn->savepoints[i].name, name) == 0) {
            found = i;
            break;
        }
    }
    if (found < 0) {
        pthread_mutex_unlock(&mgr->lock);
        return -1;
    }

    /* Truncate the savepoint stack to the found savepoint.
     * The savepoint itself remains (like SQL ROLLBACK TO SAVEPOINT). */
    qihse_savepoint_t* sp = &txn->savepoints[found];
    txn->write_count = sp->write_count;

    /* Remove savepoints created after this one */
    txn->savepoint_count = found + 1;

    /* Truncate the rw_set to the write_count at savepoint time.
     * We keep read entries but remove write entries beyond the savepoint. */
    if (txn->rw_count > sp->write_count) {
        /* For simplicity, we just reduce the rw_count.
         * In a full implementation, we'd track which entries to remove. */
        /* Keep reads, remove writes after savepoint */
        int new_count = 0;
        int writes_seen = 0;
        for (int i = 0; i < txn->rw_count; i++) {
            if (txn->rw_set[i].is_write) {
                if (writes_seen < sp->write_count) {
                    txn->rw_set[new_count++] = txn->rw_set[i];
                    writes_seen++;
                }
            } else {
                txn->rw_set[new_count++] = txn->rw_set[i];
            }
        }
        txn->rw_count = new_count;
    }

    pthread_mutex_unlock(&mgr->lock);
    return 0;
}

/* ── Snapshot management ────────────────────────────────────────────────── */

void qihse_txn_refresh_snapshot(qihse_txn_manager_t* mgr, qihse_txn_t* txn) {
    if (!mgr || !txn) return;
    pthread_mutex_lock(&mgr->lock);
    /* For READ COMMITTED: snapshot = latest committed txn ID.
     * We use next_txn_id - 1 as a proxy (all txns that have started). */
    txn->snapshot = mgr->next_txn_id - 1;
    pthread_mutex_unlock(&mgr->lock);
}

uint64_t qihse_txn_get_snapshot(const qihse_txn_t* txn) {
    if (!txn) return 0;
    return txn->snapshot;
}

/* ── Read/Write set tracking ────────────────────────────────────────────── */

static int rw_set_ensure_capacity(qihse_txn_t* txn, int needed) {
    if (txn->rw_capacity >= needed) return 0;
    int new_cap = txn->rw_capacity == 0 ? 16 : txn->rw_capacity * 2;
    while (new_cap < needed) new_cap *= 2;
    qihse_rw_entry_t* new_set = realloc(txn->rw_set,
                                        new_cap * sizeof(qihse_rw_entry_t));
    if (!new_set) return -1;
    txn->rw_set = new_set;
    txn->rw_capacity = new_cap;
    return 0;
}

int qihse_txn_record_read(qihse_txn_t* txn, uint8_t engine_id,
                          const void* key, size_t key_len)
{
    if (!txn || !key) return -1;
    if (key_len >= 256) key_len = 255;  /* truncate to fit in entry */

    if (rw_set_ensure_capacity(txn, txn->rw_count + 1) != 0) return -1;

    qihse_rw_entry_t* e = &txn->rw_set[txn->rw_count++];
    e->engine_id = engine_id;
    e->key_len   = key_len;
    e->is_write  = false;
    memcpy(e->key, key, key_len);
    e->key[key_len] = '\0';
    return 0;
}

int qihse_txn_record_write(qihse_txn_t* txn, uint8_t engine_id,
                           const void* key, size_t key_len)
{
    if (!txn || !key) return -1;
    if (key_len >= 256) key_len = 255;

    if (rw_set_ensure_capacity(txn, txn->rw_count + 1) != 0) return -1;

    qihse_rw_entry_t* e = &txn->rw_set[txn->rw_count++];
    e->engine_id = engine_id;
    e->key_len   = key_len;
    e->is_write  = true;
    memcpy(e->key, key, key_len);
    e->key[key_len] = '\0';
    txn->write_count++;
    return 0;
}

/* ── OCC validation ─────────────────────────────────────────────────────── */

int qihse_txn_validate_occ(qihse_txn_manager_t* mgr, qihse_txn_t* txn) {
    if (!mgr || !txn) return -1;
    pthread_mutex_lock(&mgr->lock);
    int rc = validate_occ_locked(mgr, txn);
    pthread_mutex_unlock(&mgr->lock);
    return rc;
}

int qihse_txn_attach_resource(qihse_txn_t* txn, void* resource_ctx,
                              qihse_txn_resource_commit_fn commit_fn,
                              qihse_txn_resource_rollback_fn rollback_fn) {
    if (!txn || txn->state != QIHSE_TXN_ACTIVE || !resource_ctx ||
        !commit_fn || !rollback_fn || txn->resource_ctx)
        return -1;
    txn->resource_ctx = resource_ctx;
    txn->resource_commit = commit_fn;
    txn->resource_rollback = rollback_fn;
    return 0;
}

/* ── 2PC interface ──────────────────────────────────────────────────────── */

int qihse_txn_register_participant(qihse_txn_manager_t* mgr,
                                   qihse_txn_participant_t participant)
{
    if (!mgr) return -1;
    pthread_mutex_lock(&mgr->lock);
    /* participant_count is always in [0, QIHSE_TXN_MAX_PARTICIPANTS]. */
    if (mgr->participant_count >= (int)QIHSE_TXN_MAX_PARTICIPANTS) {
        pthread_mutex_unlock(&mgr->lock);
        return -1;
    }
    mgr->participants[mgr->participant_count++] = participant;
    pthread_mutex_unlock(&mgr->lock);
    return 0;
}

int qihse_txn_prepare(qihse_txn_manager_t* mgr, qihse_txn_t* txn) {
    if (!mgr || !txn) return -1;

    pthread_mutex_lock(&mgr->lock);
    if (txn->state != QIHSE_TXN_ACTIVE) {
        pthread_mutex_unlock(&mgr->lock);
        return -1;
    }
    /* Local resources have an atomic one-phase publish callback, not a durable
     * prepare record.  Mixing them with 2PC would allow COMMIT PREPARED to
     * report success without publishing the resource. */
    if (txn->resource_ctx) {
        pthread_mutex_unlock(&mgr->lock);
        return -1;
    }

    /* Call prepare() on all participants */
    for (int i = 0; i < mgr->participant_count; i++) {
        qihse_txn_participant_t* p = &mgr->participants[i];
        if (p->prepare) {
            int rc = p->prepare(p->engine_ctx, txn->id);
            if (rc != 0) {
                /* A participant failed to prepare — abort all */
                txn->state = QIHSE_TXN_ABORTED;
                registry_insert(mgr, txn->id, QIHSE_TXN_ABORTED);
                active_remove(mgr, txn->id);
                prune_committed_history_locked(mgr);
                pthread_mutex_unlock(&mgr->lock);
                return -1;
            }
        }
    }

    txn->state = QIHSE_TXN_PREPARED;
    pthread_mutex_unlock(&mgr->lock);
    return 0;
}

int qihse_txn_commit_prepared(qihse_txn_manager_t* mgr, qihse_txn_t* txn) {
    if (!mgr || !txn) return -1;

    pthread_mutex_lock(&mgr->lock);
    if (txn->state != QIHSE_TXN_PREPARED) {
        pthread_mutex_unlock(&mgr->lock);
        return -1;
    }

    if (validate_occ_locked(mgr, txn) != 0 || mgr->commit_seq == UINT64_MAX) {
        for (int i = 0; i < mgr->participant_count; i++) {
            qihse_txn_participant_t* p = &mgr->participants[i];
            if (p->abort) (void)p->abort(p->engine_ctx, txn->id);
        }
        txn->state = QIHSE_TXN_ABORTED;
        (void)registry_insert(mgr, txn->id, QIHSE_TXN_ABORTED);
        active_remove(mgr, txn->id);
        prune_committed_history_locked(mgr);
        pthread_mutex_unlock(&mgr->lock);
        return -1;
    }

    uint64_t commit_seq = mgr->commit_seq + 1;
    qihse_committed_summary_t* summary = NULL;
    if (summary_needed_locked(mgr, txn)) {
        summary = committed_summary_create(txn, commit_seq);
        if (!summary) {
            for (int i = 0; i < mgr->participant_count; i++) {
                qihse_txn_participant_t* p = &mgr->participants[i];
                if (p->abort) (void)p->abort(p->engine_ctx, txn->id);
            }
            txn->state = QIHSE_TXN_ABORTED;
            (void)registry_insert(mgr, txn->id, QIHSE_TXN_ABORTED);
            active_remove(mgr, txn->id);
            prune_committed_history_locked(mgr);
            pthread_mutex_unlock(&mgr->lock);
            return -1;
        }
    }

    if (!registry_insert(mgr, txn->id, QIHSE_TXN_COMMITTED)) {
        committed_summary_free(summary);
        for (int i = 0; i < mgr->participant_count; i++) {
            qihse_txn_participant_t* p = &mgr->participants[i];
            if (p->abort) (void)p->abort(p->engine_ctx, txn->id);
        }
        txn->state = QIHSE_TXN_ABORTED;
        active_remove(mgr, txn->id);
        prune_committed_history_locked(mgr);
        pthread_mutex_unlock(&mgr->lock);
        return -1;
    }

    /* Call commit() on all participants */
    for (int i = 0; i < mgr->participant_count; i++) {
        qihse_txn_participant_t* p = &mgr->participants[i];
        if (p->commit) {
            p->commit(p->engine_ctx, txn->id);
        }
    }

    txn->state = QIHSE_TXN_COMMITTED;
    mgr->commit_seq = commit_seq;
    committed_summary_append_locked(mgr, summary);
    active_remove(mgr, txn->id);
    prune_committed_history_locked(mgr);
    pthread_mutex_unlock(&mgr->lock);
    return 0;
}

int qihse_txn_abort_prepared(qihse_txn_manager_t* mgr, qihse_txn_t* txn) {
    if (!mgr || !txn) return -1;

    pthread_mutex_lock(&mgr->lock);
    if (txn->state != QIHSE_TXN_PREPARED) {
        pthread_mutex_unlock(&mgr->lock);
        return -1;
    }

    /* Call abort() on all participants */
    for (int i = 0; i < mgr->participant_count; i++) {
        qihse_txn_participant_t* p = &mgr->participants[i];
        if (p->abort) {
            p->abort(p->engine_ctx, txn->id);
        }
    }

    txn->state = QIHSE_TXN_ABORTED;
    registry_insert(mgr, txn->id, QIHSE_TXN_ABORTED);
    active_remove(mgr, txn->id);
    pthread_mutex_unlock(&mgr->lock);
    return 0;
}

/* ── Registry queries ───────────────────────────────────────────────────── */

bool qihse_txn_is_committed(qihse_txn_manager_t* mgr, uint64_t txn_id) {
    if (!mgr) return false;
    pthread_mutex_lock(&mgr->lock);
    qihse_txn_registry_entry_t* e = registry_find(mgr, txn_id);
    bool result = (e && e->state == QIHSE_TXN_COMMITTED);
    pthread_mutex_unlock(&mgr->lock);
    return result;
}

bool qihse_txn_is_aborted(qihse_txn_manager_t* mgr, uint64_t txn_id) {
    if (!mgr) return false;
    pthread_mutex_lock(&mgr->lock);
    qihse_txn_registry_entry_t* e = registry_find(mgr, txn_id);
    bool result = (e && e->state == QIHSE_TXN_ABORTED);
    pthread_mutex_unlock(&mgr->lock);
    return result;
}

int qihse_txn_active_list(qihse_txn_manager_t* mgr,
                          uint64_t** out_ids, int* out_count)
{
    if (!mgr || !out_ids || !out_count) return -1;
    pthread_mutex_lock(&mgr->lock);

    int count = mgr->active_count;
    uint64_t* ids = malloc(count * sizeof(uint64_t));
    if (!ids && count > 0) {
        pthread_mutex_unlock(&mgr->lock);
        return -1;
    }

    int i = 0;
    qihse_active_node_t* node = mgr->active_head;
    while (node && i < count) {
        ids[i++] = node->txn->id;
        node = node->next;
    }

    *out_ids = ids;
    *out_count = i;
    pthread_mutex_unlock(&mgr->lock);
    return 0;
}

int qihse_txn_active_count(qihse_txn_manager_t* mgr) {
    if (!mgr) return 0;
    pthread_mutex_lock(&mgr->lock);
    int count = mgr->active_count;
    pthread_mutex_unlock(&mgr->lock);
    return count;
}

size_t qihse_txn_committed_history_count(qihse_txn_manager_t* mgr) {
    if (!mgr) return 0;
    pthread_mutex_lock(&mgr->lock);
    size_t count = mgr->committed_count;
    pthread_mutex_unlock(&mgr->lock);
    return count;
}

/* ── LSN tracking ───────────────────────────────────────────────────────── */

void qihse_txn_set_start_lsn(qihse_txn_t* txn, uint64_t lsn) {
    if (!txn) return;
    txn->start_lsn = lsn;
}

uint64_t qihse_txn_get_start_lsn(const qihse_txn_t* txn) {
    if (!txn) return 0;
    return txn->start_lsn;
}

/* ── Recovery support ───────────────────────────────────────────────────── */

void qihse_txn_register_committed(qihse_txn_manager_t* mgr, uint64_t txn_id) {
    if (!mgr) return;
    pthread_mutex_lock(&mgr->lock);
    registry_insert(mgr, txn_id, QIHSE_TXN_COMMITTED);
    if (txn_id >= mgr->next_txn_id) {
        mgr->next_txn_id = txn_id + 1;
    }
    pthread_mutex_unlock(&mgr->lock);
}

void qihse_txn_register_aborted(qihse_txn_manager_t* mgr, uint64_t txn_id) {
    if (!mgr) return;
    pthread_mutex_lock(&mgr->lock);
    registry_insert(mgr, txn_id, QIHSE_TXN_ABORTED);
    if (txn_id >= mgr->next_txn_id) {
        mgr->next_txn_id = txn_id + 1;
    }
    pthread_mutex_unlock(&mgr->lock);
}

void qihse_txn_set_next_id(qihse_txn_manager_t* mgr, uint64_t next_id) {
    if (!mgr) return;
    pthread_mutex_lock(&mgr->lock);
    if (next_id > mgr->next_txn_id) {
        mgr->next_txn_id = next_id;
    }
    pthread_mutex_unlock(&mgr->lock);
}
