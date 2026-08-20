#define _GNU_SOURCE
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

static void registry_insert(qihse_txn_manager_t* mgr,
                            uint64_t txn_id, qihse_txn_state_t state)
{
    if (!mgr->registry_buckets) return;
    size_t b = registry_hash(txn_id, mgr->registry_n_buckets);
    qihse_txn_registry_entry_t* e =
        qihse_arena_alloc(mgr->arena, sizeof(*e));
    if (!e) return;
    e->txn_id = txn_id;
    e->state  = state;
    e->next   = mgr->registry_buckets[b];
    mgr->registry_buckets[b] = e;
}

/* ── Active list management ─────────────────────────────────────────────── */

static void active_add(qihse_txn_manager_t* mgr, qihse_txn_t* txn) {
    qihse_active_node_t* node = qihse_arena_alloc(mgr->arena, sizeof(*node));
    if (!node) return;
    node->txn  = txn;
    node->next = mgr->active_head;
    mgr->active_head = node;
    mgr->active_count++;
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

/* ── Lifecycle ──────────────────────────────────────────────────────────── */

qihse_txn_manager_t* qihse_txn_manager_create(void) {
    qihse_txn_manager_t* mgr = calloc(1, sizeof(*mgr));
    if (!mgr) return NULL;

    pthread_mutex_init(&mgr->lock, NULL);
    mgr->next_txn_id     = QIHSE_TXN_FIRST_ID;
    mgr->active_head     = NULL;
    mgr->active_count    = 0;
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
        if (node->txn && node->txn->rw_set) {
            free(node->txn->rw_set);
            node->txn->rw_set = NULL;
        }
        node = node->next;
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

    /* Snapshot: for REPEATABLE READ and SERIALIZABLE, snapshot = current
     * next_txn_id - 1 (i.e. all txns that have started so far).
     * For READ COMMITTED, snapshot will be refreshed per statement. */
    txn->snapshot = txn->id - 1;  /* see all transactions that started before us */

    active_add(mgr, txn);
    pthread_mutex_unlock(&mgr->lock);

    return txn;
}

/* ── COMMIT ─────────────────────────────────────────────────────────────── */

int qihse_txn_commit(qihse_txn_manager_t* mgr, qihse_txn_t* txn) {
    if (!mgr || !txn) return -1;
    if (txn->state != QIHSE_TXN_ACTIVE) return -1;

    pthread_mutex_lock(&mgr->lock);

    /* SERIALIZABLE: validate OCC before committing */
    if (txn->isolation == QIHSE_ISO_SERIALIZABLE) {
        if (qihse_txn_validate_occ(mgr, txn) != 0) {
            /* Conflict detected — abort */
            txn->state = QIHSE_TXN_ABORTED;
            registry_insert(mgr, txn->id, QIHSE_TXN_ABORTED);
            active_remove(mgr, txn->id);
            pthread_mutex_unlock(&mgr->lock);
            return -1;
        }
    }

    txn->state = QIHSE_TXN_COMMITTED;
    registry_insert(mgr, txn->id, QIHSE_TXN_COMMITTED);
    active_remove(mgr, txn->id);
    pthread_mutex_unlock(&mgr->lock);

    return 0;
}

/* ── ROLLBACK ───────────────────────────────────────────────────────────── */

int qihse_txn_rollback(qihse_txn_manager_t* mgr, qihse_txn_t* txn) {
    if (!mgr || !txn) return -1;
    if (txn->state != QIHSE_TXN_ACTIVE) return -1;

    pthread_mutex_lock(&mgr->lock);
    txn->state = QIHSE_TXN_ABORTED;
    registry_insert(mgr, txn->id, QIHSE_TXN_ABORTED);
    active_remove(mgr, txn->id);
    pthread_mutex_unlock(&mgr->lock);

    return 0;
}

/* ── SAVEPOINT ──────────────────────────────────────────────────────────── */

int qihse_txn_savepoint(qihse_txn_manager_t* mgr, qihse_txn_t* txn,
                        const char* name)
{
    (void)mgr;
    if (!txn || !name) return -1;
    if (txn->state != QIHSE_TXN_ACTIVE) return -1;
    if (txn->savepoint_count >= QIHSE_TXN_MAX_SAVEPOINTS) return -1;

    qihse_savepoint_t* sp = &txn->savepoints[txn->savepoint_count];
    strncpy(sp->name, name, sizeof(sp->name) - 1);
    sp->name[sizeof(sp->name) - 1] = '\0';
    sp->lsn = txn->start_lsn;
    sp->write_count = txn->write_count;
    txn->savepoint_count++;
    return 0;
}

int qihse_txn_rollback_to_savepoint(qihse_txn_manager_t* mgr,
                                    qihse_txn_t* txn, const char* name)
{
    (void)mgr;
    if (!txn || !name) return -1;
    if (txn->state != QIHSE_TXN_ACTIVE) return -1;

    /* Find the savepoint (search from top of stack) */
    int found = -1;
    for (int i = txn->savepoint_count - 1; i >= 0; i--) {
        if (strcmp(txn->savepoints[i].name, name) == 0) {
            found = i;
            break;
        }
    }
    if (found < 0) return -1;

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

    /* For each entry in our read set, check if any concurrent transaction
     * (that committed after our snapshot) wrote to the same key.
     * Also check write-write conflicts. */
    qihse_active_node_t* node = mgr->active_head;
    while (node) {
        qihse_txn_t* other = node->txn;
        if (other == txn) { node = node->next; continue; }
        if (other->id <= txn->snapshot) { node = node->next; continue; }

        /* other started after our snapshot — check its writes against our reads */
        for (int i = 0; i < other->rw_count; i++) {
            if (!other->rw_set[i].is_write) continue;
            /* other wrote to (engine, key) */
            for (int j = 0; j < txn->rw_count; j++) {
                if (txn->rw_set[j].engine_id != other->rw_set[i].engine_id)
                    continue;
                if (txn->rw_set[j].key_len != other->rw_set[i].key_len)
                    continue;
                if (memcmp(txn->rw_set[j].key, other->rw_set[i].key,
                           txn->rw_set[j].key_len) != 0)
                    continue;
                /* Conflict: we read what they wrote, or we both wrote */
                return -1;
            }
        }
        node = node->next;
    }

    /* Also check committed transactions that committed after our snapshot */
    /* The registry holds all committed/aborted txns. We scan for committed
     * txns with id > our snapshot.  For simplicity, we check if any committed
     * txn wrote to keys in our read set.  Since we don't store the rw_set
     * of committed txns in the registry, this check is limited to active
     * transactions above.  In a full implementation, we'd retain the rw_set
     * of recently committed transactions. */
    return 0;
}

/* ── 2PC interface ──────────────────────────────────────────────────────── */

int qihse_txn_register_participant(qihse_txn_manager_t* mgr,
                                   qihse_txn_participant_t participant)
{
    if (!mgr) return -1;
    pthread_mutex_lock(&mgr->lock);
    if (mgr->participant_count >= QIHSE_TXN_MAX_PARTICIPANTS) {
        pthread_mutex_unlock(&mgr->lock);
        return -1;
    }
    mgr->participants[mgr->participant_count++] = participant;
    pthread_mutex_unlock(&mgr->lock);
    return 0;
}

int qihse_txn_prepare(qihse_txn_manager_t* mgr, qihse_txn_t* txn) {
    if (!mgr || !txn) return -1;
    if (txn->state != QIHSE_TXN_ACTIVE) return -1;

    pthread_mutex_lock(&mgr->lock);

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
    if (txn->state != QIHSE_TXN_PREPARED) return -1;

    pthread_mutex_lock(&mgr->lock);

    /* Call commit() on all participants */
    for (int i = 0; i < mgr->participant_count; i++) {
        qihse_txn_participant_t* p = &mgr->participants[i];
        if (p->commit) {
            p->commit(p->engine_ctx, txn->id);
        }
    }

    txn->state = QIHSE_TXN_COMMITTED;
    registry_insert(mgr, txn->id, QIHSE_TXN_COMMITTED);
    active_remove(mgr, txn->id);
    pthread_mutex_unlock(&mgr->lock);
    return 0;
}

int qihse_txn_abort_prepared(qihse_txn_manager_t* mgr, qihse_txn_t* txn) {
    if (!mgr || !txn) return -1;
    if (txn->state != QIHSE_TXN_PREPARED) return -1;

    pthread_mutex_lock(&mgr->lock);

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
