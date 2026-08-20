#ifndef QIHSE_RECOVERY_H
#define QIHSE_RECOVERY_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "qihse_platform.h"
#include "qihse_wal.h"
#include "qihse_txn.h"
#include "qihse_mvcc.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ── Recovery context ───────────────────────────────────────────────────── */

typedef struct qihse_recovery_s {
    qihse_txn_manager_t* txn_mgr;
    qihse_mvcc_store_t*  mvcc;
    qihse_wal_t*         wal;
    /* Track which transactions committed / aborted during replay */
    uint64_t* committed_txns;
    int       committed_count;
    int       committed_capacity;
    uint64_t* aborted_txns;
    int       aborted_count;
    int       aborted_capacity;
} qihse_recovery_t;

/* ── Lifecycle ──────────────────────────────────────────────────────────── */

qihse_recovery_t* qihse_recovery_create(qihse_txn_manager_t* txn_mgr,
                                        qihse_mvcc_store_t* mvcc,
                                        qihse_wal_t* wal);
void qihse_recovery_destroy(qihse_recovery_t* rec);

/* ── Crash recovery ─────────────────────────────────────────────────────── */

/* Replay the WAL from the last checkpoint and rebuild state.
 * Phase 1 (Analysis): scan WAL, build transaction commit/abort table.
 * Phase 2 (Redo): re-apply all committed mutations to the MVCC store.
 * Phase 3 (Undo): mark uncommitted transactions as aborted.
 * Returns 0 on success, -1 on error. */
int qihse_recovery_replay(qihse_recovery_t* rec);

/* ── Checkpoint ─────────────────────────────────────────────────────────── */

/* Perform a checkpoint:
 * 1. Flush all engine state (caller-provided flush callback)
 * 2. Record checkpoint LSN in WAL
 * 3. Truncate old WAL segments
 * Returns 0 on success. */
typedef int (*qihse_recovery_flush_cb)(void* ctx);

int qihse_recovery_checkpoint(qihse_recovery_t* rec,
                              qihse_recovery_flush_cb flush_cb,
                              void* flush_ctx);

/* ── Inspection ─────────────────────────────────────────────────────────── */

/* Check if a transaction was committed during recovery replay. */
bool qihse_recovery_txn_committed(qihse_recovery_t* rec, uint64_t txn_id);

/* Check if a transaction was aborted during recovery replay. */
bool qihse_recovery_txn_aborted(qihse_recovery_t* rec, uint64_t txn_id);

/* Get the number of committed transactions found during replay. */
int qihse_recovery_committed_count(qihse_recovery_t* rec);

/* Get the number of aborted transactions found during replay. */
int qihse_recovery_aborted_count(qihse_recovery_t* rec);

#ifdef __cplusplus
}
#endif

#endif /* QIHSE_RECOVERY_H */
