#define _GNU_SOURCE
/*
 * QIHSE Crash Recovery
 *
 * Phase 2: ACID Transactions & MVCC
 *
 * Implements WAL replay on startup with three phases:
 *   1. Analysis: scan WAL, build transaction commit/abort table
 *   2. Redo: re-apply all committed mutations to the MVCC store
 *   3. Undo: mark uncommitted transactions as aborted
 *
 * Also implements checkpoint: flush engine state, record checkpoint LSN,
 * truncate old WAL segments.
 */

#include "qihse_recovery.h"
#include "qihse_txn.h"
#include "qihse_mvcc.h"
#include "qihse_wal.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* ── Analysis phase data ────────────────────────────────────────────────── */

/* Track transaction status during analysis */
typedef struct qihse_rec_txn_status_s {
    uint64_t txn_id;
    int      status;  /* 0=active, 1=committed, 2=aborted */
} qihse_rec_txn_status_t;

typedef struct qihse_rec_analysis_s {
    qihse_rec_txn_status_t* txns;
    int                     txn_count;
    int                     txn_capacity;
    /* Pending mutations (redo log entries) */
    qihse_wal_record_t*     records;
    void**                  record_keys;
    void**                  record_values;
    int                     record_count;
    int                     record_capacity;
} qihse_rec_analysis_t;

/* ── Analysis helpers ───────────────────────────────────────────────────── */

static int analysis_find_txn(qihse_rec_analysis_t* a, uint64_t txn_id) {
    for (int i = 0; i < a->txn_count; i++) {
        if (a->txns[i].txn_id == txn_id) return i;
    }
    return -1;
}

static int analysis_add_txn(qihse_rec_analysis_t* a, uint64_t txn_id) {
    int idx = analysis_find_txn(a, txn_id);
    if (idx >= 0) return idx;
    if (a->txn_count >= a->txn_capacity) {
        int new_cap = a->txn_capacity == 0 ? 64 : a->txn_capacity * 2;
        a->txns = realloc(a->txns, new_cap * sizeof(qihse_rec_txn_status_t));
        if (!a->txns) return -1;
        a->txn_capacity = new_cap;
    }
    a->txns[a->txn_count].txn_id = txn_id;
    a->txns[a->txn_count].status = 0;  /* active */
    return a->txn_count++;
}

static int analysis_add_record(qihse_rec_analysis_t* a,
                               const qihse_wal_record_t* rec,
                               const void* key, uint32_t key_len,
                               const void* value, uint32_t value_len)
{
    if (a->record_count >= a->record_capacity) {
        int new_cap = a->record_capacity == 0 ? 128 : a->record_capacity * 2;
        a->records = realloc(a->records, new_cap * sizeof(qihse_wal_record_t));
        a->record_keys = realloc(a->record_keys, new_cap * sizeof(void*));
        a->record_values = realloc(a->record_values, new_cap * sizeof(void*));
        if (!a->records || !a->record_keys || !a->record_values) return -1;
        a->record_capacity = new_cap;
    }

    int idx = a->record_count;
    a->records[idx] = *rec;

    /* Copy key */
    if (key_len > 0) {
        a->record_keys[idx] = malloc(key_len);
        if (a->record_keys[idx]) memcpy(a->record_keys[idx], key, key_len);
    } else {
        a->record_keys[idx] = NULL;
    }

    /* Copy value */
    if (value_len > 0) {
        a->record_values[idx] = malloc(value_len);
        if (a->record_values[idx]) memcpy(a->record_values[idx], value, value_len);
    } else {
        a->record_values[idx] = NULL;
    }

    a->record_count++;
    return 0;
}

/* ── Replay callback (analysis phase) ───────────────────────────────────── */

typedef struct qihse_rec_replay_ctx_s {
    qihse_rec_analysis_t* analysis;
} qihse_rec_replay_ctx_t;

static bool recovery_replay_cb(const qihse_wal_record_t* rec,
                               const void* key, uint32_t key_len,
                               const void* value, uint32_t value_len,
                               void* user_data)
{
    qihse_rec_replay_ctx_t* ctx = (qihse_rec_replay_ctx_t*)user_data;
    qihse_rec_analysis_t* a = ctx->analysis;

    switch (rec->op_type) {
    case QIHSE_WAL_OP_BEGIN:
        analysis_add_txn(a, rec->txn_id);
        break;
    case QIHSE_WAL_OP_COMMIT: {
        int idx = analysis_find_txn(a, rec->txn_id);
        if (idx >= 0) a->txns[idx].status = 1;  /* committed */
        else { analysis_add_txn(a, rec->txn_id); a->txns[a->txn_count-1].status = 1; }
        break;
    }
    case QIHSE_WAL_OP_ABORT: {
        int idx = analysis_find_txn(a, rec->txn_id);
        if (idx >= 0) a->txns[idx].status = 2;  /* aborted */
        else { analysis_add_txn(a, rec->txn_id); a->txns[a->txn_count-1].status = 2; }
        break;
    }
    case QIHSE_WAL_OP_INSERT:
    case QIHSE_WAL_OP_UPDATE:
    case QIHSE_WAL_OP_DELETE:
        /* Store the mutation for the redo phase */
        if (rec->txn_id > 0) {
            analysis_add_txn(a, rec->txn_id);
        }
        analysis_add_record(a, rec, key, key_len, value, value_len);
        break;
    case QIHSE_WAL_OP_CHECKPOINT:
        /* Skip checkpoint records during replay */
        break;
    default:
        break;
    }

    return true;  /* continue replay */
}

/* ── Lifecycle ──────────────────────────────────────────────────────────── */

qihse_recovery_t* qihse_recovery_create(qihse_txn_manager_t* txn_mgr,
                                        qihse_mvcc_store_t* mvcc,
                                        qihse_wal_t* wal)
{
    if (!txn_mgr || !mvcc || !wal) return NULL;

    qihse_recovery_t* rec = calloc(1, sizeof(*rec));
    if (!rec) return NULL;

    rec->txn_mgr = txn_mgr;
    rec->mvcc    = mvcc;
    rec->wal     = wal;

    rec->committed_txns = NULL;
    rec->committed_count = 0;
    rec->committed_capacity = 0;
    rec->aborted_txns = NULL;
    rec->aborted_count = 0;
    rec->aborted_capacity = 0;

    return rec;
}

void qihse_recovery_destroy(qihse_recovery_t* rec) {
    if (!rec) return;
    free(rec->committed_txns);
    free(rec->aborted_txns);
    free(rec);
}

/* ── Helper: add to committed/aborted arrays ────────────────────────────── */

static void rec_add_committed(qihse_recovery_t* rec, uint64_t txn_id) {
    if (rec->committed_count >= rec->committed_capacity) {
        int new_cap = rec->committed_capacity == 0 ? 64 : rec->committed_capacity * 2;
        rec->committed_txns = realloc(rec->committed_txns,
                                      new_cap * sizeof(uint64_t));
        rec->committed_capacity = new_cap;
    }
    rec->committed_txns[rec->committed_count++] = txn_id;
}

static void rec_add_aborted(qihse_recovery_t* rec, uint64_t txn_id) {
    if (rec->aborted_count >= rec->aborted_capacity) {
        int new_cap = rec->aborted_capacity == 0 ? 64 : rec->aborted_capacity * 2;
        rec->aborted_txns = realloc(rec->aborted_txns,
                                    new_cap * sizeof(uint64_t));
        rec->aborted_capacity = new_cap;
    }
    rec->aborted_txns[rec->aborted_count++] = txn_id;
}

/* ── Crash recovery replay ──────────────────────────────────────────────── */

int qihse_recovery_replay(qihse_recovery_t* rec) {
    if (!rec) return -1;

    /* Initialize analysis data */
    qihse_rec_analysis_t analysis;
    memset(&analysis, 0, sizeof(analysis));

    /* Phase 1: Analysis — scan WAL and build transaction table */
    qihse_rec_replay_ctx_t ctx = { .analysis = &analysis };
    uint64_t start_lsn = qihse_wal_last_checkpoint(rec->wal);
    int n_replayed = qihse_wal_replay(rec->wal, start_lsn,
                                      recovery_replay_cb, &ctx);
    if (n_replayed < 0) {
        free(analysis.txns);
        for (int i = 0; i < analysis.record_count; i++) {
            free(analysis.record_keys[i]);
            free(analysis.record_values[i]);
        }
        free(analysis.records);
        free(analysis.record_keys);
        free(analysis.record_values);
        return -1;
    }

    /* Build committed/aborted lists and register in txn manager */
    for (int i = 0; i < analysis.txn_count; i++) {
        if (analysis.txns[i].status == 1) {
            rec_add_committed(rec, analysis.txns[i].txn_id);
            qihse_txn_register_committed(rec->txn_mgr, analysis.txns[i].txn_id);
        } else if (analysis.txns[i].status == 2) {
            rec_add_aborted(rec, analysis.txns[i].txn_id);
            qihse_txn_register_aborted(rec->txn_mgr, analysis.txns[i].txn_id);
        } else {
            /* Active (uncommitted) — treat as aborted (undo phase) */
            rec_add_aborted(rec, analysis.txns[i].txn_id);
            qihse_txn_register_aborted(rec->txn_mgr, analysis.txns[i].txn_id);
        }
    }

    /* Phase 2: Redo — re-apply all committed mutations to MVCC store */
    for (int i = 0; i < analysis.record_count; i++) {
        qihse_wal_record_t* r = &analysis.records[i];
        int idx = analysis_find_txn(&analysis, r->txn_id);
        if (idx < 0) continue;
        if (analysis.txns[idx].status != 1) continue;  /* skip uncommitted */

        void* key = analysis.record_keys[i];
        void* value = analysis.record_values[i];

        switch (r->op_type) {
        case QIHSE_WAL_OP_INSERT:
            qihse_mvcc_insert(rec->mvcc, r->engine_id,
                             key, r->key_length,
                             value, r->value_length,
                             r->txn_id);
            break;
        case QIHSE_WAL_OP_UPDATE:
            qihse_mvcc_update(rec->mvcc, r->engine_id,
                             key, r->key_length,
                             value, r->value_length,
                             r->txn_id);
            break;
        case QIHSE_WAL_OP_DELETE:
            qihse_mvcc_delete(rec->mvcc, r->engine_id,
                             key, r->key_length,
                             r->txn_id);
            break;
        default:
            break;
        }
    }

    /* Phase 3: Undo — mark uncommitted transactions as aborted in the
     * transaction manager registry.  The MVCC store will naturally hide
     * versions from uncommitted transactions (xmin not committed). */
    for (int i = 0; i < analysis.txn_count; i++) {
        if (analysis.txns[i].status == 0) {
            /* Uncommitted transaction — already added to aborted list above */
        }
    }

    /* Cleanup analysis data */
    free(analysis.txns);
    for (int i = 0; i < analysis.record_count; i++) {
        free(analysis.record_keys[i]);
        free(analysis.record_values[i]);
    }
    free(analysis.records);
    free(analysis.record_keys);
    free(analysis.record_values);

    return 0;
}

/* ── Checkpoint ─────────────────────────────────────────────────────────── */

int qihse_recovery_checkpoint(qihse_recovery_t* rec,
                              qihse_recovery_flush_cb flush_cb,
                              void* flush_ctx)
{
    if (!rec) return -1;

    /* 1. Flush all engine state via callback */
    if (flush_cb) {
        int rc = flush_cb(flush_ctx);
        if (rc != 0) return rc;
    }

    /* 2. Flush WAL to disk */
    qihse_wal_flush(rec->wal);

    /* 3. Record checkpoint LSN and truncate old segments */
    uint64_t lsn = qihse_wal_current_lsn(rec->wal);
    qihse_wal_append_checkpoint(rec->wal, lsn);
    qihse_wal_flush(rec->wal);
    qihse_wal_checkpoint(rec->wal, lsn);

    return 0;
}

/* ── Inspection ─────────────────────────────────────────────────────────── */

bool qihse_recovery_txn_committed(qihse_recovery_t* rec, uint64_t txn_id) {
    if (!rec) return false;
    for (int i = 0; i < rec->committed_count; i++) {
        if (rec->committed_txns[i] == txn_id) return true;
    }
    return false;
}

bool qihse_recovery_txn_aborted(qihse_recovery_t* rec, uint64_t txn_id) {
    if (!rec) return false;
    for (int i = 0; i < rec->aborted_count; i++) {
        if (rec->aborted_txns[i] == txn_id) return true;
    }
    return false;
}

int qihse_recovery_committed_count(qihse_recovery_t* rec) {
    return rec ? rec->committed_count : 0;
}

int qihse_recovery_aborted_count(qihse_recovery_t* rec) {
    return rec ? rec->aborted_count : 0;
}
