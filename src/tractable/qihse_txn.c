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
#include "qihse_auth.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <unistd.h>

/* ── Internal structures ────────────────────────────────────────────────── */

#define TXN_JOURNAL_RECORD_SIZE 36u
#define TXN_JOURNAL_MAX_SIZE (64u * 1024u * 1024u)
#define TXN_JOURNAL_MEMBERS 1u
#define TXN_JOURNAL_COMMIT 2u
#define TXN_JOURNAL_ABORT 3u
static int journal_append(qihse_txn_manager_t* mgr, uint8_t kind,
                          uint64_t txn_id, const uint8_t* engines, uint8_t count);

/* Registry entry for tracking committed / aborted transaction IDs. */
typedef struct qihse_txn_registry_entry_s {
    uint64_t txn_id;
    qihse_txn_state_t state;
    struct qihse_txn_registry_entry_s* next;
} qihse_txn_registry_entry_t;

typedef struct qihse_committed_summary_s qihse_committed_summary_t;

typedef struct qihse_resource_binding_s {
    uint8_t engine_id;
    void* resource_ctx;
    qihse_txn_resource_rollback_fn rollback;
    struct qihse_resource_binding_s* next;
} qihse_resource_binding_t;

/* Active transaction list node. */
typedef struct qihse_active_node_s {
    qihse_txn_t* txn;
    /* 2PC participant membership is fixed at PREPARE. A COMMIT decision and
     * progress live here so an in-doubt caller can retry without replaying
     * participants that already acknowledged it. */
    qihse_txn_participant_t participants[QIHSE_TXN_MAX_PARTICIPANTS];
    int participant_count;
    qihse_resource_binding_t* resource_bindings;
    bool prepare_failed;
    uint32_t prepare_attempted_mask;
    uint32_t commit_pending_mask;
    uint32_t abort_pending_mask;
    uint64_t commit_seq;
    qihse_committed_summary_t* commit_summary;
    qihse_txn_registry_entry_t* commit_registry_entry;
    qihse_txn_registry_entry_t* abort_registry_entry;
    struct qihse_active_node_s* next;
    struct qihse_active_node_s* finished_next;
} qihse_active_node_t;

/* A committed transaction's writes remain here while an active SERIALIZABLE
 * transaction has a snapshot older than the commit.  Validation needs only
 * writes from the committed side: they are compared with both reads and
 * writes of the transaction being validated. */
struct qihse_committed_summary_s {
    uint64_t commit_seq;
    uint64_t txn_id;
    qihse_rw_entry_t* writes;
    int write_count;
    struct qihse_committed_summary_s* next;
};

struct qihse_txn_manager {
    pthread_mutex_t          lock;
    uint64_t                 next_txn_id;
    qihse_arena_t*           arena;
    /* Active transactions (linked list) */
    qihse_active_node_t*     active_head;
    /* Keep terminal handles valid until manager destruction, then release the
     * handle and its heap-backed read/write set. There is no public per-handle
     * destroy API, so unlinking a transaction must not orphan its allocation. */
    qihse_active_node_t*     finished_head;
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
    qihse_txn_resource_prepare_fn resource_prepare[QIHSE_TXN_MAX_PARTICIPANTS];
    int                      participant_count;
    int                      journal_fd;
    bool                     durable;
    bool                     recovered;
    bool                     poisoned;
    pid_t                    owner_pid;
    uint64_t                 backup_epoch;
    uint64_t                 journal_bytes; /* validated/appended prefix, never shrinks */
};

static void backup_changed_locked(qihse_txn_manager_t* mgr) {
    if (mgr->backup_epoch != UINT64_MAX) ++mgr->backup_epoch;
}

static bool manager_owned(const qihse_txn_manager_t* mgr) {
    return mgr && mgr->owner_pid == getpid();
}

/* Poison is irreversible on this handle. Only reopening and replaying the disk
 * journal may decide whether an uncertain append actually survived. */
static bool manager_fenced_locked(const qihse_txn_manager_t* mgr) {
    return mgr->poisoned || (mgr->durable && !mgr->recovered);
}

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
    memset(node->participants, 0, sizeof(node->participants));
    node->participant_count = 0;
    node->resource_bindings = NULL;
    node->prepare_failed = false;
    node->prepare_attempted_mask = 0;
    node->commit_pending_mask = 0;
    node->abort_pending_mask = 0;
    node->commit_seq = 0;
    node->commit_summary = NULL;
    node->commit_registry_entry = NULL;
    node->abort_registry_entry = NULL;
    node->finished_next = NULL;
    node->next = mgr->active_head;
    mgr->active_head = node;
    mgr->active_count++;
    return true;
}

static qihse_active_node_t* active_find(qihse_txn_manager_t* mgr,
                                        const qihse_txn_t* txn) {
    for (qihse_active_node_t* node = mgr->active_head; node; node = node->next)
        if (node->txn == txn) return node;
    return NULL;
}

static qihse_resource_binding_t** resource_binding_link(
    qihse_active_node_t* active, uint8_t engine_id) {
    qihse_resource_binding_t** link = &active->resource_bindings;
    while (*link && (*link)->engine_id != engine_id) link = &(*link)->next;
    return link;
}

static void resource_bindings_rollback(qihse_active_node_t* active) {
    qihse_resource_binding_t* binding = active ? active->resource_bindings : NULL;
    if (active) active->resource_bindings = NULL;
    while (binding) {
        qihse_resource_binding_t* next = binding->next;
        if (binding->resource_ctx && binding->rollback)
            binding->rollback(binding->resource_ctx);
        free(binding);
        binding = next;
    }
}

static bool commit_in_doubt_locked(qihse_txn_manager_t* mgr,
                                   const qihse_txn_t* except) {
    for (qihse_active_node_t* node = mgr->active_head; node; node = node->next)
        if (node->txn && node->txn != except &&
            node->txn->state == QIHSE_TXN_COMMITTING) return true;
    return false;
}

static void active_remove(qihse_txn_manager_t* mgr, uint64_t txn_id);
static void prune_committed_history_locked(qihse_txn_manager_t* mgr);

static int drive_abort_locked(qihse_txn_manager_t* mgr,
                              qihse_active_node_t* active) {
    if (!active->abort_registry_entry) {
        active->abort_registry_entry = registry_alloc(
            mgr, active->txn->id, QIHSE_TXN_ABORTED);
        if (!active->abort_registry_entry) {
            errno = ENOMEM;
            return -1;
        }
    }
    for (int i = 0; i < active->participant_count; ++i) {
        uint32_t bit = UINT32_C(1) << i;
        if (!(active->abort_pending_mask & bit)) continue;
        qihse_txn_participant_t* p = &active->participants[i];
        if (p->abort && p->abort(p->engine_ctx, active->txn->id) == 0)
            active->abort_pending_mask &= ~bit;
    }
    if (active->abort_pending_mask) {
        errno = EAGAIN;
        return -1;
    }
    active->abort_registry_entry->state = QIHSE_TXN_ABORTED;
    registry_link(mgr, active->abort_registry_entry);
    active->txn->state = QIHSE_TXN_ABORTED;
    active_remove(mgr, active->txn->id);
    prune_committed_history_locked(mgr);
    return 0;
}

static int decide_abort_prepared_locked(qihse_txn_manager_t* mgr,
                                        qihse_active_node_t* active,
                                        uint32_t participants) {
    if (mgr->durable && journal_append(mgr, TXN_JOURNAL_ABORT,
                                       active->txn->id, NULL, 0) != 0)
        return -1;
    active->abort_pending_mask = participants;
    active->txn->state = QIHSE_TXN_ABORTING;
    return drive_abort_locked(mgr, active);
}

static void active_remove(qihse_txn_manager_t* mgr, uint64_t txn_id) {
    qihse_active_node_t** pp = &mgr->active_head;
    while (*pp) {
        if ((*pp)->txn->id == txn_id) {
            qihse_active_node_t* dead = *pp;
            *pp = dead->next;
            /* Keep terminal handles usable by callers until manager destroy,
             * while retaining a route to their malloc-backed rw_set. */
            dead->next = NULL;
            dead->finished_next = mgr->finished_head;
            mgr->finished_head = dead;
            mgr->active_count--;
            backup_changed_locked(mgr);
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
            (txn->state != QIHSE_TXN_ACTIVE && txn->state != QIHSE_TXN_PREPARED &&
             txn->state != QIHSE_TXN_COMMITTING && txn->state != QIHSE_TXN_ABORTING))
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
            (txn->state == QIHSE_TXN_ACTIVE || txn->state == QIHSE_TXN_PREPARED ||
             txn->state == QIHSE_TXN_COMMITTING))
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

/* ── Durable 2PC journal ────────────────────────────────────────────────── */

typedef struct durable_record_s {
    uint64_t txn_id;
    uint8_t count;
    uint8_t engines[QIHSE_TXN_MAX_PARTICIPANTS];
    uint8_t decision;
    struct durable_record_s* next;
} durable_record_t;

static uint32_t journal_crc32(const uint8_t* p, size_t n) {
    uint32_t crc = UINT32_MAX;
    for (size_t i = 0; i < n; ++i) {
        crc ^= p[i];
        for (int b = 0; b < 8; ++b)
            crc = (crc >> 1) ^ (UINT32_C(0xedb88320) & (uint32_t)-(int32_t)(crc & 1));
    }
    return ~crc;
}

static void journal_put64(uint8_t* p, uint64_t v) {
    for (int i = 0; i < 8; ++i) p[i] = (uint8_t)(v >> (56 - 8 * i));
}

static uint64_t journal_get64(const uint8_t* p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v = (v << 8) | p[i];
    return v;
}

static int journal_append(qihse_txn_manager_t* mgr, uint8_t kind,
                          uint64_t txn_id, const uint8_t* engines, uint8_t count) {
    uint8_t r[TXN_JOURNAL_RECORD_SIZE] = { 'Q', 'T', '2', 'P', 1, kind, count, 0 };
    journal_put64(r + 8, txn_id);
    if (engines && count) memcpy(r + 16, engines, count);
    uint32_t crc = journal_crc32(r, 32);
    r[32] = (uint8_t)(crc >> 24); r[33] = (uint8_t)(crc >> 16);
    r[34] = (uint8_t)(crc >> 8); r[35] = (uint8_t)crc;
    if (mgr->poisoned) { errno = EIO; return -1; }
    off_t start = lseek(mgr->journal_fd, 0, SEEK_END);
    if (start < 0) return -1;
    if ((uint64_t)start != mgr->journal_bytes) {
        mgr->poisoned = true;
        mgr->recovered = false;
        backup_changed_locked(mgr);
        errno = EIO;
        return -1;
    }
    size_t done = 0;
    while (done < sizeof(r)) {
        ssize_t n = write(mgr->journal_fd, r + done, sizeof(r) - done);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { if (n == 0) errno = EIO; goto rollback; }
        done += (size_t)n;
    }
    if (fdatasync(mgr->journal_fd) != 0) goto rollback;
    mgr->journal_bytes += sizeof(r);
    backup_changed_locked(mgr);
    return 0;
rollback: {
        int saved = errno;
        /* A failed sync can leave a complete COMMIT record. Do not permit a
         * later ABORT unless removing that record has itself become durable. */
        if (ftruncate(mgr->journal_fd, start) != 0 ||
            fdatasync(mgr->journal_fd) != 0) {
            mgr->poisoned = true;
            mgr->recovered = false;
        }
        backup_changed_locked(mgr);
        errno = saved;
        return -1;
    }
}

static qihse_txn_participant_t* participant_by_id(qihse_txn_manager_t* mgr,
                                                  uint8_t id) {
    for (int i = 0; i < mgr->participant_count; ++i)
        if (mgr->participants[i].engine_id == id) return &mgr->participants[i];
    return NULL;
}

static int journal_parse(qihse_txn_manager_t* mgr, durable_record_t** out,
                         bool repair, uint8_t** captured, size_t* captured_size) {
    struct stat st;
    if (fstat(mgr->journal_fd, &st) != 0 || !S_ISREG(st.st_mode) ||
        st.st_uid != geteuid() || (st.st_mode & 077) != 0 ||
        st.st_size < 0 || (uint64_t)st.st_size > TXN_JOURNAL_MAX_SIZE) {
        errno = EACCES;
        return -1;
    }
    off_t complete = st.st_size - st.st_size % TXN_JOURNAL_RECORD_SIZE;
    /* Even a record-aligned truncation must not silently lose a known common
     * decision. First-open recovery may learn an existing prefix, never lose it. */
    if ((uint64_t)complete < mgr->journal_bytes ||
        (!repair && (uint64_t)st.st_size != mgr->journal_bytes)) {
        errno = EINVAL;
        return -1;
    }
    if (complete != st.st_size) {
        if (!repair) { errno = EINVAL; return -1; }
        backup_changed_locked(mgr);
        if (ftruncate(mgr->journal_fd, complete) != 0 ||
            fdatasync(mgr->journal_fd) != 0) {
            mgr->poisoned = true;
            mgr->recovered = false;
            return -1;
        }
    }
    durable_record_t *head = NULL, **tail = &head;
    uint8_t* bytes = malloc(complete ? (size_t)complete : 1);
    if (!bytes) return -1;
    size_t got = 0;
    while (got < (size_t)complete) {
        ssize_t n = pread(mgr->journal_fd, bytes + got, (size_t)complete - got,
                          (off_t)got);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) goto invalid;
        got += (size_t)n;
    }
    for (off_t pos = 0; pos < complete; pos += TXN_JOURNAL_RECORD_SIZE) {
        const uint8_t* r = bytes + pos;
        uint32_t expected = ((uint32_t)r[32] << 24) | ((uint32_t)r[33] << 16) |
                           ((uint32_t)r[34] << 8) | r[35];
        uint8_t kind = r[5], count = r[6];
        uint64_t id = journal_get64(r + 8);
        if (memcmp(r, "QT2P", 4) || r[4] != 1 || r[7] != 0 || !id ||
            expected != journal_crc32(r, 32) || count > QIHSE_TXN_MAX_PARTICIPANTS ||
            (kind != TXN_JOURNAL_MEMBERS && kind != TXN_JOURNAL_COMMIT && kind != TXN_JOURNAL_ABORT) ||
            (kind != TXN_JOURNAL_MEMBERS && count != 0)) goto invalid;
        for (size_t i = 16u + count; i < 32u; ++i)
            if (r[i]) goto invalid;
        durable_record_t* d = head;
        while (d && d->txn_id != id) d = d->next;
        if (kind == TXN_JOURNAL_MEMBERS) {
            if (d || count == 0) goto invalid;
            bool used[256] = { false };
            for (int i = 0; i < count; ++i) {
                if (used[r[16 + i]]) goto invalid;
                used[r[16 + i]] = true;
            }
            d = calloc(1, sizeof(*d));
            if (!d) goto invalid;
            d->txn_id = id; d->count = count;
            memcpy(d->engines, r + 16, count);
            *tail = d; tail = &d->next;
        } else {
            if (!d || d->decision) goto invalid;
            d->decision = kind;
        }
    }
    if (repair) mgr->journal_bytes = (uint64_t)complete;
    *out = head;
    if (captured) *captured = bytes;
    else free(bytes);
    if (captured_size) *captured_size = (size_t)complete;
    return 0;
invalid:
    free(bytes);
    while (head) { durable_record_t* n = head->next; free(head); head = n; }
    errno = EINVAL;
    return -1;
}

/* ── Authenticated local journal capture ────────────────────────────────── */

static bool backup_authorized(const qihse_user_t* user) {
    return user && qihse_auth_user_is_active(user) &&
        qihse_user_get_role(user) == QIHSE_ROLE_OPERATOR &&
        qihse_user_get_id(user) == 0 && qihse_user_get_tenant_id(user) == 0;
}

static bool checkpoint_equal(const qihse_txn_backup_checkpoint_t* a,
                             const qihse_txn_backup_checkpoint_t* b) {
    return a->epoch == b->epoch && a->next_txn_id == b->next_txn_id &&
        a->journal_bytes == b->journal_bytes;
}

/* Called under the manager lock. No repair, participant replay or callbacks. */
static bool backup_capture_locked(qihse_txn_manager_t* mgr,
    qihse_txn_backup_checkpoint_t* checkpoint, uint8_t** bytes) {
    if (!mgr->durable || manager_fenced_locked(mgr) || mgr->active_count ||
        mgr->active_head || mgr->backup_epoch == UINT64_MAX ||
        mgr->next_txn_id == UINT64_MAX) return false;
    durable_record_t* records = NULL;
    uint8_t* data = NULL;
    size_t size = 0;
    if (journal_parse(mgr, &records, false, &data, &size) != 0) return false;
    bool ok = true;
    for (durable_record_t* d = records; d; d = d->next) {
        qihse_txn_registry_entry_t* e = registry_find(mgr, d->txn_id);
        if (!d->decision || d->txn_id >= mgr->next_txn_id || !e ||
            e->state != (d->decision == TXN_JOURNAL_COMMIT ?
                         QIHSE_TXN_COMMITTED : QIHSE_TXN_ABORTED)) ok = false;
        for (int i = 0; i < d->count; ++i)
            if (!participant_by_id(mgr, d->engines[i])) ok = false;
    }
    while (records) { durable_record_t* n = records->next; free(records); records = n; }
    if (!ok) { free(data); return false; }
    checkpoint->epoch = mgr->backup_epoch;
    checkpoint->next_txn_id = mgr->next_txn_id;
    checkpoint->journal_bytes = size;
    if (bytes) *bytes = data;
    else free(data);
    return true;
}

static qihse_user_t* backup_borrow(const qihse_user_t* user, uint64_t* generation) {
    if (!backup_authorized(user)) return NULL;
    qihse_user_t* borrowed = qihse_auth_borrow_principal_scoped(0, generation);
    if (borrowed != user || !*generation || !backup_authorized(user) ||
        !qihse_auth_validate_handle_generation(user, *generation)) {
        qihse_auth_release_principal_scoped(borrowed);
        return NULL;
    }
    return borrowed;
}

bool qihse_txn_backup_checkpoint_user(qihse_txn_manager_t* mgr,
    const qihse_user_t* user, qihse_txn_backup_checkpoint_t* out) {
    if (!manager_owned(mgr) || !out) return false;
    uint64_t generation = 0;
    qihse_user_t* borrowed = backup_borrow(user, &generation);
    if (!borrowed) return false;
    qihse_txn_backup_checkpoint_t checkpoint;
    pthread_mutex_lock(&mgr->lock);
    bool ok = backup_capture_locked(mgr, &checkpoint, NULL) &&
        backup_authorized(user) &&
        qihse_auth_validate_handle_generation(user, generation);
    if (ok) *out = checkpoint;
    pthread_mutex_unlock(&mgr->lock);
    qihse_auth_release_principal_scoped(borrowed);
    return ok;
}

bool qihse_txn_backup_export_user(qihse_txn_manager_t* mgr,
    const qihse_user_t* user, const qihse_txn_backup_checkpoint_t* expected,
    qihse_txn_backup_write_fn write_fn, void* ctx,
    qihse_txn_backup_checkpoint_t* out) {
    if (!manager_owned(mgr) || !expected || !write_fn || !out) return false;
    /* The caller may reuse its checkpoint variable for the result. */
    qihse_txn_backup_checkpoint_t wanted = *expected, captured;
    uint64_t generation = 0;
    qihse_user_t* borrowed = backup_borrow(user, &generation);
    if (!borrowed) return false;
    uint8_t* bytes = NULL;
    pthread_mutex_lock(&mgr->lock);
    bool ok = backup_capture_locked(mgr, &captured, &bytes) &&
        checkpoint_equal(&wanted, &captured) && backup_authorized(user) &&
        qihse_auth_validate_handle_generation(user, generation);
    pthread_mutex_unlock(&mgr->lock);
    if (ok) {
        for (size_t pos = 0; pos < captured.journal_bytes;) {
            size_t n = (size_t)captured.journal_bytes - pos;
            if (n > 65536u) n = 65536u;
            if (!write_fn(ctx, bytes + pos, n)) { ok = false; break; }
            pos += n;
        }
    }
    if (ok) {
        qihse_txn_backup_checkpoint_t final;
        uint8_t* final_bytes = NULL;
        pthread_mutex_lock(&mgr->lock);
        ok = backup_capture_locked(mgr, &final, &final_bytes) &&
            checkpoint_equal(&captured, &final) &&
            memcmp(bytes, final_bytes, (size_t)captured.journal_bytes) == 0 &&
            backup_authorized(user) &&
            qihse_auth_validate_handle_generation(user, generation);
        if (ok) *out = captured;
        pthread_mutex_unlock(&mgr->lock);
        free(final_bytes);
    }
    free(bytes);
    qihse_auth_release_principal_scoped(borrowed);
    return ok;
}

/* ── Lifecycle ──────────────────────────────────────────────────────────── */

qihse_txn_manager_t* qihse_txn_manager_create(void) {
    qihse_txn_manager_t* mgr = calloc(1, sizeof(*mgr));
    if (!mgr) return NULL;

    pthread_mutex_init(&mgr->lock, NULL);
    mgr->next_txn_id     = QIHSE_TXN_FIRST_ID;
    mgr->active_head     = NULL;
    mgr->finished_head   = NULL;
    mgr->active_count    = 0;
    mgr->commit_seq      = 0;
    mgr->participant_count = 0;
    mgr->journal_fd = -1;
    mgr->durable = false;
    mgr->recovered = true;
    mgr->owner_pid = getpid();
    mgr->backup_epoch = 1;

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

static bool txn_journal_sync_parent(const char* path) {
    char* parent = strdup(path);
    if (!parent) return false;
    char* slash = strrchr(parent, '/');
    const char* directory = ".";
    if (slash) {
        if (slash == parent) slash[1] = '\0';
        else *slash = '\0';
        directory = parent;
    }
    int fd = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) { free(parent); return false; }
    bool ok = fsync(fd) == 0;
    int saved = errno;
    if (close(fd) != 0 && ok) { ok = false; saved = errno; }
    free(parent);
    if (!ok) errno = saved;
    return ok;
}

qihse_txn_manager_t* qihse_txn_manager_create_durable(const char* path) {
    if (!path || !*path) { errno = EINVAL; return NULL; }
    qihse_txn_manager_t* mgr = qihse_txn_manager_create();
    if (!mgr) return NULL;
    int fd = open(path, O_RDWR | O_CREAT | O_APPEND | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) { qihse_txn_manager_destroy(mgr); return NULL; }
    struct stat st;
    if (fstat(fd, &st) != 0) {
        int saved = errno;
        close(fd); qihse_txn_manager_destroy(mgr); errno = saved; return NULL;
    }
    if (!S_ISREG(st.st_mode) || st.st_uid != geteuid() ||
        (st.st_mode & 077) != 0) {
        close(fd); qihse_txn_manager_destroy(mgr); errno = EACCES; return NULL;
    }
    if (flock(fd, LOCK_EX | LOCK_NB) != 0) {
        int saved = errno;
        close(fd); qihse_txn_manager_destroy(mgr); errno = saved; return NULL;
    }
    if (!txn_journal_sync_parent(path)) {
        int saved = errno;
        close(fd); qihse_txn_manager_destroy(mgr); errno = saved; return NULL;
    }
    mgr->journal_fd = fd;
    mgr->durable = true;
    mgr->recovered = false;
    return mgr;
}

int qihse_txn_manager_recover(qihse_txn_manager_t* mgr) {
    if (!manager_owned(mgr) || !mgr->durable) { errno = EINVAL; return -1; }
    pthread_mutex_lock(&mgr->lock);
    if (mgr->poisoned) { pthread_mutex_unlock(&mgr->lock); errno = EIO; return -1; }
    if (mgr->active_count != 0) { pthread_mutex_unlock(&mgr->lock); errno = EBUSY; return -1; }
    backup_changed_locked(mgr);
    mgr->recovered = false;
    durable_record_t* records = NULL;
    if (journal_parse(mgr, &records, true, NULL, NULL) != 0) {
        pthread_mutex_unlock(&mgr->lock);
        return -1;
    }
    for (durable_record_t* d = records; d; d = d->next) {
        for (int i = 0; i < d->count; ++i) {
            if (!participant_by_id(mgr, d->engines[i])) goto recovery_fail;
        }
    }
    for (durable_record_t* d = records; d; d = d->next) {
        if (!d->decision) {
            if (journal_append(mgr, TXN_JOURNAL_ABORT, d->txn_id, NULL, 0) != 0)
                goto recovery_fail;
            d->decision = TXN_JOURNAL_ABORT;
        }
        for (int i = 0; i < d->count; ++i) {
            qihse_txn_participant_t* p = participant_by_id(mgr, d->engines[i]);
            int rc = d->decision == TXN_JOURNAL_COMMIT ?
                p->commit(p->engine_ctx, d->txn_id) : p->abort(p->engine_ctx, d->txn_id);
            if (rc != 0) goto recovery_fail;
        }
        if (!registry_find(mgr, d->txn_id) &&
            !registry_insert(mgr, d->txn_id, d->decision == TXN_JOURNAL_COMMIT ?
                             QIHSE_TXN_COMMITTED : QIHSE_TXN_ABORTED))
            goto recovery_fail;
        if (d->txn_id >= mgr->next_txn_id) {
            mgr->next_txn_id = d->txn_id == UINT64_MAX ? UINT64_MAX : d->txn_id + 1;
        }
    }
    mgr->recovered = true;
    while (records) { durable_record_t* n = records->next; free(records); records = n; }
    pthread_mutex_unlock(&mgr->lock);
    return 0;
recovery_fail:
    while (records) { durable_record_t* n = records->next; free(records); records = n; }
    mgr->recovered = false;
    errno = EAGAIN;
    pthread_mutex_unlock(&mgr->lock);
    return -1;
}

void qihse_txn_manager_destroy(qihse_txn_manager_t* mgr) {
    if (!manager_owned(mgr)) return;
    pthread_mutex_lock(&mgr->lock);
    /* Free any remaining txn handles (rw_set) */
    qihse_active_node_t* node = mgr->active_head;
    while (node) {
        txn_resource_rollback(node->txn);
        resource_bindings_rollback(node);
        committed_summary_free(node->commit_summary);
        node->commit_summary = NULL;
        if (node->txn && node->txn->rw_set) {
            free(node->txn->rw_set);
            node->txn->rw_set = NULL;
        }
        if (node->txn) {
            free(node->txn);
            node->txn = NULL;
        }
        node = node->next;
    }
    node = mgr->finished_head;
    while (node) {
        qihse_active_node_t* next = node->finished_next;
        if (node->txn) {
            if (node->txn->rw_set) free(node->txn->rw_set);
            free(node->txn);
            node->txn = NULL;
        }
        node = next;
    }
    qihse_committed_summary_t* summary = mgr->committed_head;
    while (summary) {
        qihse_committed_summary_t* next = summary->next;
        committed_summary_free(summary);
        summary = next;
    }
    pthread_mutex_unlock(&mgr->lock);
    if (mgr->journal_fd >= 0) close(mgr->journal_fd);
    qihse_arena_destroy(mgr->arena);
    pthread_mutex_destroy(&mgr->lock);
    free(mgr);
}

/* ── BEGIN ──────────────────────────────────────────────────────────────── */

qihse_txn_t* qihse_txn_begin(qihse_txn_manager_t* mgr,
                             qihse_isolation_level_t isolation)
{
    if (!manager_owned(mgr)) return NULL;

    qihse_txn_t* txn = calloc(1, sizeof(*txn));
    if (!txn) return NULL;

    pthread_mutex_lock(&mgr->lock);
    if (manager_fenced_locked(mgr) || mgr->next_txn_id == UINT64_MAX) {
        errno = mgr->next_txn_id == UINT64_MAX ? EOVERFLOW : EAGAIN;
        pthread_mutex_unlock(&mgr->lock);
        free(txn);
        return NULL;
    }
    backup_changed_locked(mgr);
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
    if (!manager_owned(mgr) || !txn) return -1;

    pthread_mutex_lock(&mgr->lock);
    if (manager_fenced_locked(mgr)) {
        pthread_mutex_unlock(&mgr->lock); errno = EIO; return -1;
    }
    if (txn->state != QIHSE_TXN_ACTIVE) {
        pthread_mutex_unlock(&mgr->lock);
        return -1;
    }
    qihse_active_node_t* active = active_find(mgr, txn);
    if (active && active->resource_bindings) {
        pthread_mutex_unlock(&mgr->lock);
        errno = EINVAL;
        return -1;
    }
    if (commit_in_doubt_locked(mgr, txn)) {
        errno = EAGAIN;
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
    if (!manager_owned(mgr) || !txn) return -1;

    pthread_mutex_lock(&mgr->lock);
    if (manager_fenced_locked(mgr)) {
        pthread_mutex_unlock(&mgr->lock); errno = EIO; return -1;
    }
    if (txn->state != QIHSE_TXN_ACTIVE) {
        pthread_mutex_unlock(&mgr->lock);
        return -1;
    }
    qihse_txn_registry_entry_t* registry_entry =
        registry_alloc(mgr, txn->id, QIHSE_TXN_ABORTED);
    txn_resource_rollback(txn);
    resource_bindings_rollback(active_find(mgr, txn));
    txn->state = QIHSE_TXN_ABORTED;
    if (registry_entry) registry_link(mgr, registry_entry);
    active_remove(mgr, txn->id);
    prune_committed_history_locked(mgr);
    pthread_mutex_unlock(&mgr->lock);

    return 0;
}

int qihse_txn_release(qihse_txn_manager_t* mgr, qihse_txn_t* txn) {
    if (!manager_owned(mgr) || !txn) return -1;
    pthread_mutex_lock(&mgr->lock);
    qihse_active_node_t** link = &mgr->finished_head;
    while (*link && (*link)->txn != txn) link = &(*link)->finished_next;
    if (!*link || (txn->state != QIHSE_TXN_COMMITTED &&
                   txn->state != QIHSE_TXN_ABORTED)) {
        pthread_mutex_unlock(&mgr->lock);
        return -1;
    }
    qihse_active_node_t* finished = *link;
    *link = finished->finished_next;
    finished->finished_next = NULL;
    free(txn->rw_set);
    txn->rw_set = NULL;
    txn->rw_count = 0;
    txn->rw_capacity = 0;
    free(txn);
    finished->txn = NULL;
    pthread_mutex_unlock(&mgr->lock);
    return 0;
}

/* ── SAVEPOINT ──────────────────────────────────────────────────────────── */

int qihse_txn_savepoint(qihse_txn_manager_t* mgr, qihse_txn_t* txn,
                        const char* name)
{
    if (!manager_owned(mgr) || !txn || !name) return -1;
    pthread_mutex_lock(&mgr->lock);
    if (txn->state != QIHSE_TXN_ACTIVE) {
        pthread_mutex_unlock(&mgr->lock);
        return -1;
    }
    /* A local resource needs its own snapshot callback before savepoints can
     * safely include it. Refuse any attached resource before recording only a
     * partial savepoint. */
    qihse_active_node_t* active = active_find(mgr, txn);
    if (txn->resource_ctx || (active && active->resource_bindings)) {
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
    if (!manager_owned(mgr) || !txn || !name) return -1;
    pthread_mutex_lock(&mgr->lock);
    qihse_active_node_t* active = active_find(mgr, txn);
    if (txn->state != QIHSE_TXN_ACTIVE || txn->resource_ctx ||
        (active && active->resource_bindings)) {
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
    if (!manager_owned(mgr) || !txn) return;
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
    if (!manager_owned(mgr) || !txn) return -1;
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

int qihse_txn_attach_participant_resource(qihse_txn_manager_t* mgr,
    qihse_txn_t* txn, uint8_t engine_id, void* resource_ctx,
    qihse_txn_resource_rollback_fn rollback_fn) {
    if (!manager_owned(mgr) || !txn || !resource_ctx || !rollback_fn) return -1;
    qihse_resource_binding_t* binding = calloc(1, sizeof(*binding));
    if (!binding) return -1;
    binding->engine_id = engine_id;
    binding->resource_ctx = resource_ctx;
    binding->rollback = rollback_fn;
    pthread_mutex_lock(&mgr->lock);
    qihse_active_node_t* active = active_find(mgr, txn);
    int index = -1;
    for (int i = 0; i < mgr->participant_count; ++i)
        if (mgr->participants[i].engine_id == engine_id &&
            mgr->resource_prepare[i]) { index = i; break; }
    if (!mgr->durable || !mgr->recovered || txn->state != QIHSE_TXN_ACTIVE ||
        !active || txn->resource_ctx || *resource_binding_link(active, engine_id) ||
        index < 0) {
        pthread_mutex_unlock(&mgr->lock);
        free(binding);
        return -1;
    }
    binding->next = active->resource_bindings;
    active->resource_bindings = binding;
    pthread_mutex_unlock(&mgr->lock);
    return 0;
}

/* ── 2PC interface ──────────────────────────────────────────────────────── */

int qihse_txn_enlist_attached_resource(qihse_txn_manager_t* mgr,
    qihse_txn_t* txn, uint8_t engine_id) {
    if (!manager_owned(mgr) || !txn) return -1;
    qihse_resource_binding_t* binding = calloc(1, sizeof(*binding));
    if (!binding) return -1;
    pthread_mutex_lock(&mgr->lock);
    qihse_active_node_t* active = active_find(mgr, txn);
    bool registered = false;
    for (int i = 0; i < mgr->participant_count; ++i)
        if (mgr->participants[i].engine_id == engine_id &&
            mgr->resource_prepare[i]) { registered = true; break; }
    if (!mgr->durable || !mgr->recovered || txn->state != QIHSE_TXN_ACTIVE ||
        !active || !txn->resource_ctx || !txn->resource_rollback ||
        *resource_binding_link(active, engine_id) || !registered) {
        pthread_mutex_unlock(&mgr->lock);
        free(binding);
        return -1;
    }
    binding->engine_id = engine_id;
    binding->resource_ctx = txn->resource_ctx;
    binding->rollback = txn->resource_rollback;
    binding->next = active->resource_bindings;
    active->resource_bindings = binding;
    txn->resource_ctx = NULL;
    txn->resource_commit = NULL;
    txn->resource_rollback = NULL;
    pthread_mutex_unlock(&mgr->lock);
    return 0;
}

static int register_participant(qihse_txn_manager_t* mgr,
    qihse_txn_participant_t participant,
    qihse_txn_resource_prepare_fn resource_prepare) {
    if (!manager_owned(mgr) || (!!participant.prepare != !!participant.commit) ||
        (!!participant.prepare != !!participant.abort) ||
        (resource_prepare && !participant.prepare)) return -1;
    pthread_mutex_lock(&mgr->lock);
    if (mgr->poisoned || mgr->participant_count >= (int)QIHSE_TXN_MAX_PARTICIPANTS ||
        (mgr->durable && (mgr->recovered || !participant.prepare ||
         participant_by_id(mgr, participant.engine_id))) ||
        (!mgr->durable && resource_prepare)) {
        pthread_mutex_unlock(&mgr->lock);
        return -1;
    }
    int index = mgr->participant_count++;
    mgr->participants[index] = participant;
    mgr->resource_prepare[index] = resource_prepare;
    backup_changed_locked(mgr);
    pthread_mutex_unlock(&mgr->lock);
    return 0;
}

int qihse_txn_register_participant(qihse_txn_manager_t* mgr,
                                   qihse_txn_participant_t participant) {
    return register_participant(mgr, participant, NULL);
}

int qihse_txn_register_resource_participant(qihse_txn_manager_t* mgr,
    qihse_txn_participant_t participant,
    qihse_txn_resource_prepare_fn resource_prepare) {
    if (!resource_prepare) return -1;
    return register_participant(mgr, participant, resource_prepare);
}

int qihse_txn_prepare(qihse_txn_manager_t* mgr, qihse_txn_t* txn) {
    if (!manager_owned(mgr) || !txn) return -1;

    pthread_mutex_lock(&mgr->lock);
    if (manager_fenced_locked(mgr)) {
        pthread_mutex_unlock(&mgr->lock); errno = EIO; return -1;
    }
    if (txn->state != QIHSE_TXN_ACTIVE) {
        pthread_mutex_unlock(&mgr->lock);
        return -1;
    }
    qihse_active_node_t* active = active_find(mgr, txn);
    if (!active || txn->resource_ctx) {
        pthread_mutex_unlock(&mgr->lock);
        return -1;
    }

    for (qihse_resource_binding_t* binding = active->resource_bindings;
         binding; binding = binding->next) {
        bool registered = false;
        for (int i = 0; i < mgr->participant_count; ++i)
            if (mgr->participants[i].engine_id == binding->engine_id &&
                mgr->resource_prepare[i]) { registered = true; break; }
        if (!registered || !mgr->durable) {
            pthread_mutex_unlock(&mgr->lock);
            return -1;
        }
    }

    /* Freeze and durably record membership before invoking prepare callbacks. */
    memcpy(active->participants, mgr->participants,
           (size_t)mgr->participant_count * sizeof(mgr->participants[0]));
    active->participant_count = mgr->participant_count;
    if (mgr->durable) {
        uint8_t engines[QIHSE_TXN_MAX_PARTICIPANTS];
        for (int i = 0; i < active->participant_count; ++i)
            engines[i] = active->participants[i].engine_id;
        if (active->participant_count == 0 || journal_append(mgr, TXN_JOURNAL_MEMBERS,
                txn->id, engines, (uint8_t)active->participant_count) != 0) {
            active->participant_count = 0;
            pthread_mutex_unlock(&mgr->lock);
            return -1;
        }
    }

    /* Call each participant's normal or resource-aware prepare callback. */
    uint32_t prepare_attempted = 0;
    for (int i = 0; i < active->participant_count; i++) {
        qihse_txn_participant_t* p = &active->participants[i];
        if (!p->prepare) continue;
        prepare_attempted |= UINT32_C(1) << i;
        int rc;
        qihse_resource_binding_t** binding_link =
            resource_binding_link(active, p->engine_id);
        qihse_resource_binding_t* binding = *binding_link;
        if (binding) {
            qihse_txn_resource_prepare_fn prepare_resource =
                mgr->resource_prepare[i];
            rc = prepare_resource ? prepare_resource(p->engine_ctx, txn->id,
                binding->resource_ctx) : -1;
            /* Resource-aware prepare consumes the volatile shadow on either
             * result; subsequent decisions use participant-owned durable state. */
            *binding_link = binding->next;
            binding->resource_ctx = NULL;
            free(binding);
        } else {
            rc = p->prepare(p->engine_ctx, txn->id);
        }
        if (rc != 0) {
            resource_bindings_rollback(active);
            /* The prepare callback may have changed durable state. Keep this
             * transaction abort-only if recording or delivering ABORT fails. */
            active->prepare_failed = true;
            active->prepare_attempted_mask = prepare_attempted;
            txn->state = QIHSE_TXN_PREPARED;
            (void)decide_abort_prepared_locked(mgr, active, prepare_attempted);
            pthread_mutex_unlock(&mgr->lock);
            return -1;
        }
    }

    txn->state = QIHSE_TXN_PREPARED;
    pthread_mutex_unlock(&mgr->lock);
    return 0;
}

int qihse_txn_commit_prepared(qihse_txn_manager_t* mgr, qihse_txn_t* txn) {
    if (!manager_owned(mgr) || !txn) return -1;

    pthread_mutex_lock(&mgr->lock);
    if (manager_fenced_locked(mgr)) {
        pthread_mutex_unlock(&mgr->lock); errno = EIO; return -1;
    }
    qihse_active_node_t* active = active_find(mgr, txn);
    if (!active || active->resource_bindings || active->prepare_failed ||
        (txn->state != QIHSE_TXN_PREPARED &&
         txn->state != QIHSE_TXN_COMMITTING)) {
        pthread_mutex_unlock(&mgr->lock);
        return -1;
    }
    if (txn->state == QIHSE_TXN_PREPARED &&
        commit_in_doubt_locked(mgr, txn)) {
        errno = EAGAIN;
        pthread_mutex_unlock(&mgr->lock);
        return -1;
    }

    if (txn->state == QIHSE_TXN_PREPARED &&
        (validate_occ_locked(mgr, txn) != 0 || mgr->commit_seq == UINT64_MAX)) {
        uint32_t participants = active->participant_count == 0 ? 0 :
            ((UINT32_C(1) << active->participant_count) - 1u);
        for (int i = 0; i < active->participant_count; i++)
            if (!active->participants[i].abort)
                participants &= ~(UINT32_C(1) << i);
        (void)decide_abort_prepared_locked(mgr, active, participants);
        pthread_mutex_unlock(&mgr->lock);
        return -1;
    }

    if (txn->state == QIHSE_TXN_PREPARED) {
        active->commit_seq = mgr->commit_seq + 1;
        /* Keep the write summary with the irrevocable decision even when no
         * SERIALIZABLE transaction exists yet. A transaction may BEGIN while
         * participant commit callbacks are in doubt; it snapshots the old
         * commit_seq and must see this write once the decision completes. */
        if (txn->write_count > 0) {
            active->commit_summary = committed_summary_create(txn, active->commit_seq);
            if (!active->commit_summary) {
                uint32_t participants = active->participant_count == 0 ? 0 :
                    ((UINT32_C(1) << active->participant_count) - 1u);
                for (int i = 0; i < active->participant_count; i++)
                    if (!active->participants[i].abort)
                        participants &= ~(UINT32_C(1) << i);
                (void)decide_abort_prepared_locked(mgr, active, participants);
                pthread_mutex_unlock(&mgr->lock);
                return -1;
            }
        }
        active->commit_registry_entry = registry_alloc(mgr, txn->id,
                                                        QIHSE_TXN_COMMITTED);
        if (!active->commit_registry_entry) {
            committed_summary_free(active->commit_summary);
            active->commit_summary = NULL;
            uint32_t participants = active->participant_count == 0 ? 0 :
                ((UINT32_C(1) << active->participant_count) - 1u);
            for (int i = 0; i < active->participant_count; i++)
                if (!active->participants[i].abort)
                    participants &= ~(UINT32_C(1) << i);
            (void)decide_abort_prepared_locked(mgr, active, participants);
            pthread_mutex_unlock(&mgr->lock);
            return -1;
        }
        active->commit_pending_mask = active->participant_count == 0 ? 0 :
            ((UINT32_C(1) << active->participant_count) - 1u);
        if (mgr->durable && journal_append(mgr, TXN_JOURNAL_COMMIT,
                                           txn->id, NULL, 0) != 0) {
            committed_summary_free(active->commit_summary);
            active->commit_summary = NULL;
            active->commit_registry_entry = NULL;
            pthread_mutex_unlock(&mgr->lock);
            return -1;
        }
        txn->state = QIHSE_TXN_COMMITTING; /* irrevocable decision from here */
    }

    /* The commit decision is irreversible. Continue attempting all pending
     * participants and retain failed bits for retry without duplicate commits. */
    for (int i = 0; i < active->participant_count; i++) {
        uint32_t bit = UINT32_C(1) << i;
        if (!(active->commit_pending_mask & bit)) continue;
        qihse_txn_participant_t* p = &active->participants[i];
        if (!p->commit || p->commit(p->engine_ctx, txn->id) == 0)
            active->commit_pending_mask &= ~bit;
    }
    if (active->commit_pending_mask) {
        errno = EAGAIN;
        pthread_mutex_unlock(&mgr->lock);
        return -1;
    }

    active->commit_registry_entry->state = QIHSE_TXN_COMMITTED;
    registry_link(mgr, active->commit_registry_entry);
    txn->state = QIHSE_TXN_COMMITTED;
    mgr->commit_seq = active->commit_seq;
    committed_summary_append_locked(mgr, active->commit_summary);
    active->commit_summary = NULL;
    active_remove(mgr, txn->id);
    prune_committed_history_locked(mgr);
    pthread_mutex_unlock(&mgr->lock);
    return 0;
}

int qihse_txn_abort_prepared(qihse_txn_manager_t* mgr, qihse_txn_t* txn) {
    if (!manager_owned(mgr) || !txn) return -1;

    pthread_mutex_lock(&mgr->lock);
    if (manager_fenced_locked(mgr)) {
        pthread_mutex_unlock(&mgr->lock); errno = EIO; return -1;
    }
    qihse_active_node_t* active = active_find(mgr, txn);
    if (!active || (txn->state != QIHSE_TXN_PREPARED &&
                    txn->state != QIHSE_TXN_ABORTING)) {
        pthread_mutex_unlock(&mgr->lock);
        return -1;
    }

    if (txn->state == QIHSE_TXN_PREPARED) {
        uint32_t participants = active->prepare_failed ?
            active->prepare_attempted_mask : 0;
        if (!active->prepare_failed) {
            for (int i = 0; i < active->participant_count; i++) {
                if (active->participants[i].abort)
                    participants |= UINT32_C(1) << i;
            }
        } else {
            for (int i = 0; i < active->participant_count; i++)
                if (!active->participants[i].abort)
                    participants &= ~(UINT32_C(1) << i);
        }
        int rc = decide_abort_prepared_locked(mgr, active, participants);
        pthread_mutex_unlock(&mgr->lock);
        return rc;
    }
    int rc = drive_abort_locked(mgr, active);
    pthread_mutex_unlock(&mgr->lock);
    return rc;
}

/* ── Registry queries ───────────────────────────────────────────────────── */

bool qihse_txn_is_committed(qihse_txn_manager_t* mgr, uint64_t txn_id) {
    if (!manager_owned(mgr)) return false;
    pthread_mutex_lock(&mgr->lock);
    qihse_txn_registry_entry_t* e = registry_find(mgr, txn_id);
    bool result = (e && e->state == QIHSE_TXN_COMMITTED);
    pthread_mutex_unlock(&mgr->lock);
    return result;
}

bool qihse_txn_is_aborted(qihse_txn_manager_t* mgr, uint64_t txn_id) {
    if (!manager_owned(mgr)) return false;
    pthread_mutex_lock(&mgr->lock);
    qihse_txn_registry_entry_t* e = registry_find(mgr, txn_id);
    bool result = (e && e->state == QIHSE_TXN_ABORTED);
    pthread_mutex_unlock(&mgr->lock);
    return result;
}

int qihse_txn_active_list(qihse_txn_manager_t* mgr,
                          uint64_t** out_ids, int* out_count)
{
    if (!manager_owned(mgr) || !out_ids || !out_count) return -1;
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
    if (!manager_owned(mgr)) return 0;
    pthread_mutex_lock(&mgr->lock);
    int count = mgr->active_count;
    pthread_mutex_unlock(&mgr->lock);
    return count;
}

size_t qihse_txn_committed_history_count(qihse_txn_manager_t* mgr) {
    if (!manager_owned(mgr)) return 0;
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
    if (!manager_owned(mgr) || !txn_id) return;
    pthread_mutex_lock(&mgr->lock);
    if (mgr->poisoned) { pthread_mutex_unlock(&mgr->lock); return; }
    if (registry_insert(mgr, txn_id, QIHSE_TXN_COMMITTED))
        backup_changed_locked(mgr);
    if (txn_id >= mgr->next_txn_id) {
        mgr->next_txn_id = txn_id == UINT64_MAX ? UINT64_MAX : txn_id + 1;
        backup_changed_locked(mgr);
    }
    pthread_mutex_unlock(&mgr->lock);
}

void qihse_txn_register_aborted(qihse_txn_manager_t* mgr, uint64_t txn_id) {
    if (!manager_owned(mgr) || !txn_id) return;
    pthread_mutex_lock(&mgr->lock);
    if (mgr->poisoned) { pthread_mutex_unlock(&mgr->lock); return; }
    if (registry_insert(mgr, txn_id, QIHSE_TXN_ABORTED))
        backup_changed_locked(mgr);
    if (txn_id >= mgr->next_txn_id) {
        mgr->next_txn_id = txn_id == UINT64_MAX ? UINT64_MAX : txn_id + 1;
        backup_changed_locked(mgr);
    }
    pthread_mutex_unlock(&mgr->lock);
}

void qihse_txn_set_next_id(qihse_txn_manager_t* mgr, uint64_t next_id) {
    if (!manager_owned(mgr)) return;
    pthread_mutex_lock(&mgr->lock);
    if (!mgr->poisoned && next_id > mgr->next_txn_id) {
        mgr->next_txn_id = next_id;
        backup_changed_locked(mgr);
    }
    pthread_mutex_unlock(&mgr->lock);
}

int qihse_txn_advance_next_id(qihse_txn_manager_t* mgr, uint64_t next_id) {
    if (!manager_owned(mgr) || !next_id) { errno = EINVAL; return -1; }
    pthread_mutex_lock(&mgr->lock);
    if (!mgr->durable || mgr->poisoned || mgr->recovered || mgr->active_count != 0) {
        pthread_mutex_unlock(&mgr->lock);
        errno = EBUSY;
        return -1;
    }
    if (next_id > mgr->next_txn_id) {
        mgr->next_txn_id = next_id;
        backup_changed_locked(mgr);
    }
    pthread_mutex_unlock(&mgr->lock);
    return 0;
}
