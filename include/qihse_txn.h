#ifndef QIHSE_TXN_H
#define QIHSE_TXN_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "qihse_platform.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ── Constants ──────────────────────────────────────────────────────────── */

#define QIHSE_TXN_INVALID_ID  0u
#define QIHSE_TXN_FIRST_ID    1u
#define QIHSE_TXN_MAX_SAVEPOINTS 64u
#define QIHSE_TXN_MAX_PARTICIPANTS 16u

/* ── Transaction state ──────────────────────────────────────────────────── */

typedef enum qihse_txn_state_e {
    QIHSE_TXN_ACTIVE     = 0,
    QIHSE_TXN_PREPARED   = 1,
    QIHSE_TXN_COMMITTED  = 2,
    QIHSE_TXN_ABORTED    = 3
} qihse_txn_state_t;

/* ── Isolation level ────────────────────────────────────────────────────── */

typedef enum qihse_isolation_level_e {
    QIHSE_ISO_READ_COMMITTED  = 0,
    QIHSE_ISO_REPEATABLE_READ = 1,
    QIHSE_ISO_SERIALIZABLE    = 2
} qihse_isolation_level_t;

/* ── Savepoint ──────────────────────────────────────────────────────────── */

typedef struct qihse_savepoint_s {
    char     name[64];
    uint64_t lsn;          /* WAL LSN at savepoint creation */
    int      write_count;  /* number of writes before this savepoint */
} qihse_savepoint_t;

/* ── Read/Write set entry for SERIALIZABLE OCC ──────────────────────────── */

typedef struct qihse_rw_entry_s {
    uint8_t  engine_id;
    char     key[256];
    size_t   key_len;
    bool     is_write;
} qihse_rw_entry_t;

/* ── 2PC participant interface ──────────────────────────────────────────── */

typedef struct qihse_txn_participant_s {
    uint8_t  engine_id;
    void*    engine_ctx;
    /* Returns 0 on success, non-zero on failure (abort) */
    int  (*prepare)(void* engine_ctx, uint64_t txn_id);
    int  (*commit)(void* engine_ctx, uint64_t txn_id);
    int  (*abort)(void* engine_ctx, uint64_t txn_id);
} qihse_txn_participant_t;

/* ── Transaction handle ─────────────────────────────────────────────────── */

typedef struct qihse_txn_s {
    uint64_t                id;
    qihse_txn_state_t       state;
    qihse_isolation_level_t isolation;
    uint64_t                snapshot;     /* txn ID at BEGIN for MVCC visibility */
    uint64_t                start_lsn;    /* WAL LSN at BEGIN */
    qihse_savepoint_t       savepoints[QIHSE_TXN_MAX_SAVEPOINTS];
    int                     savepoint_count;
    /* OCC read/write sets for SERIALIZABLE */
    qihse_rw_entry_t*       rw_set;
    int                     rw_count;
    int                     rw_capacity;
    int                     write_count;
} qihse_txn_t;

/* ── Transaction manager (opaque) ───────────────────────────────────────── */

typedef struct qihse_txn_manager qihse_txn_manager_t;

/* ── Lifecycle ──────────────────────────────────────────────────────────── */

qihse_txn_manager_t* qihse_txn_manager_create(void);
void qihse_txn_manager_destroy(qihse_txn_manager_t* mgr);

/* ── Transaction operations ─────────────────────────────────────────────── */

/* BEGIN a new transaction with the given isolation level.
 * Returns a pointer to the transaction handle, or NULL on failure. */
qihse_txn_t* qihse_txn_begin(qihse_txn_manager_t* mgr,
                             qihse_isolation_level_t isolation);

/* COMMIT a transaction.  Returns 0 on success.
 * For SERIALIZABLE, performs OCC validation before committing. */
int qihse_txn_commit(qihse_txn_manager_t* mgr, qihse_txn_t* txn);

/* ROLLBACK a transaction.  Returns 0 on success. */
int qihse_txn_rollback(qihse_txn_manager_t* mgr, qihse_txn_t* txn);

/* Create a SAVEPOINT with the given name.  Returns 0 on success. */
int qihse_txn_savepoint(qihse_txn_manager_t* mgr, qihse_txn_t* txn,
                        const char* name);

/* Rollback to a named SAVEPOINT.  Returns 0 on success, -1 if not found. */
int qihse_txn_rollback_to_savepoint(qihse_txn_manager_t* mgr,
                                    qihse_txn_t* txn, const char* name);

/* ── Snapshot management ────────────────────────────────────────────────── */

/* Refresh the snapshot (used by READ COMMITTED for per-statement snapshots). */
void qihse_txn_refresh_snapshot(qihse_txn_manager_t* mgr, qihse_txn_t* txn);

/* Get the current snapshot for a transaction. */
uint64_t qihse_txn_get_snapshot(const qihse_txn_t* txn);

/* ── Read/Write set tracking (SERIALIZABLE OCC) ─────────────────────────── */

/* Record a read in the transaction's read set. */
int qihse_txn_record_read(qihse_txn_t* txn, uint8_t engine_id,
                          const void* key, size_t key_len);

/* Record a write in the transaction's write set. */
int qihse_txn_record_write(qihse_txn_t* txn, uint8_t engine_id,
                           const void* key, size_t key_len);

/* Validate OCC at commit: check for read-write and write-write conflicts
 * against all concurrent committed transactions.
 * Returns 0 if validation passes, -1 on conflict. */
int qihse_txn_validate_occ(qihse_txn_manager_t* mgr, qihse_txn_t* txn);

/* ── 2PC interface ──────────────────────────────────────────────────────── */

/* Register a participant engine for 2PC. */
int qihse_txn_register_participant(qihse_txn_manager_t* mgr,
                                   qihse_txn_participant_t participant);

/* PREPARE phase: call prepare() on all registered participants.
 * Returns 0 if all participants prepared successfully, -1 otherwise. */
int qihse_txn_prepare(qihse_txn_manager_t* mgr, qihse_txn_t* txn);

/* After PREPARE succeeds, COMMIT phase calls commit() on all participants. */
int qihse_txn_commit_prepared(qihse_txn_manager_t* mgr, qihse_txn_t* txn);

/* After PREPARE fails (or coordinator decides to abort), call abort(). */
int qihse_txn_abort_prepared(qihse_txn_manager_t* mgr, qihse_txn_t* txn);

/* ── Registry queries ───────────────────────────────────────────────────── */

/* Check whether a transaction ID is committed. */
bool qihse_txn_is_committed(qihse_txn_manager_t* mgr, uint64_t txn_id);

/* Check whether a transaction ID is aborted. */
bool qihse_txn_is_aborted(qihse_txn_manager_t* mgr, uint64_t txn_id);

/* Get the list of currently active transaction IDs.
 * Caller must free *out_ids. */
int qihse_txn_active_list(qihse_txn_manager_t* mgr,
                          uint64_t** out_ids, int* out_count);

/* Get the number of active transactions. */
int qihse_txn_active_count(qihse_txn_manager_t* mgr);

/* ── LSN tracking ───────────────────────────────────────────────────────── */

/* Set the start LSN for a transaction (called by WAL layer). */
void qihse_txn_set_start_lsn(qihse_txn_t* txn, uint64_t lsn);

/* Get the start LSN. */
uint64_t qihse_txn_get_start_lsn(const qihse_txn_t* txn);

#ifdef __cplusplus
}
#endif

#endif /* QIHSE_TXN_H */

/* ── Recovery support ───────────────────────────────────────────────────── */

/* Register a transaction as committed (used by crash recovery to rebuild
 * the transaction registry from the WAL). */
void qihse_txn_register_committed(qihse_txn_manager_t* mgr, uint64_t txn_id);

/* Register a transaction as aborted (used by crash recovery). */
void qihse_txn_register_aborted(qihse_txn_manager_t* mgr, uint64_t txn_id);

/* Set the next transaction ID (used by crash recovery to continue
 * monotonic ID allocation after replay). */
void qihse_txn_set_next_id(qihse_txn_manager_t* mgr, uint64_t next_id);
