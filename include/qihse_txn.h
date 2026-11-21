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
    QIHSE_TXN_ABORTED    = 3,
    /* COMMIT is irrevocable and still being delivered to one or more 2PC
     * participants. Retry qihse_txn_commit_prepared() to finish it. */
    QIHSE_TXN_COMMITTING = 4,
    /* An ABORT decision is pending participant acknowledgements. Retry
     * qihse_txn_abort_prepared() until it reaches ABORTED. */
    QIHSE_TXN_ABORTING   = 5
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

/* Optional transaction-local resource.  The commit callback publishes the
 * resource atomically and consumes resource_ctx on either success or failure;
 * rollback consumes unpublished state.  Callbacks run under the manager lock
 * and must not call transaction-manager APIs.  Savepoints and PREPARE are
 * refused while a resource is attached.  A transaction may attach one
 * resource; a coordinator for multiple resources belongs in durable 2PC. */
typedef int  (*qihse_txn_resource_commit_fn)(void* resource_ctx);
typedef void (*qihse_txn_resource_rollback_fn)(void* resource_ctx);
/* Durable participant prepare may consume the transaction-local resource after
 * persisting its prepared state. It must consume resource_ctx on success or
 * failure; commit/abort replay then uses the participant's durable record. */
typedef int (*qihse_txn_resource_prepare_fn)(void* engine_ctx, uint64_t txn_id,
                                              void* resource_ctx);

/* ── 2PC participant interface ──────────────────────────────────────────── */

typedef struct qihse_txn_participant_s {
    uint8_t  engine_id;
    void*    engine_ctx;
    /* Participants must durably deduplicate decisions by txn_id: a non-zero
     * return can mean the effect happened but its acknowledgement was lost.
     * Failed callbacks are retried; COMMIT is never followed by ABORT. */
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
    uint64_t                serialization_snapshot; /* committed sequence at BEGIN */
    uint64_t                start_lsn;    /* WAL LSN at BEGIN */
    qihse_savepoint_t       savepoints[QIHSE_TXN_MAX_SAVEPOINTS];
    int                     savepoint_count;
    /* OCC read/write sets for SERIALIZABLE */
    qihse_rw_entry_t*       rw_set;
    int                     rw_count;
    int                     rw_capacity;
    int                     write_count;
    void*                   resource_ctx;
    qihse_txn_resource_commit_fn resource_commit;
    qihse_txn_resource_rollback_fn resource_rollback;
} qihse_txn_t;

/* ── Transaction manager (opaque) ───────────────────────────────────────── */

/* A manager handle belongs to its creating process. Every API receiving a
 * manager refuses inherited handles after fork, before locking, allocating or
 * invoking callbacks: NULL/false/0/-1, or a void no-op, as for a NULL manager.
 * Output parameters and transaction fields remain unchanged; inherited destroy
 * does not run the parent's resource callbacks or close inherited descriptors.
 * Transaction-only helpers cannot enforce this ownership rule.
 *
 * Children must exec/exit and discard inherited handles, not use or destroy
 * them. Arrange a proper fresh-owner journal handoff: the inherited journal FD
 * retains its flock until all copies close (O_CLOEXEC closes it on exec).
 * Discarding a handle alone does not close that FD, so it does not permit a
 * non-exec child to reopen the same journal while an old FD still exists. */
typedef struct qihse_txn_manager qihse_txn_manager_t;

/* ── Lifecycle ──────────────────────────────────────────────────────────── */

/* The default manager uses no durable 2PC decision journal. Callers must
 * resolve all COMMITTING/ABORTING transactions before destroying it or pending
 * participant work will require external recovery. Terminal handles are
 * retained so their state remains readable; call qihse_txn_release() promptly
 * in long-lived managers, or destruction releases all remaining handles. */
qihse_txn_manager_t* qihse_txn_manager_create(void);
/* Opt-in durable 2PC coordinator. The journal path must name a private,
 * owner-only regular file; opening the coordinator also syncs its parent
 * directory before transaction admission. Register each participant engine_id
 * exactly once, then call recover() before beginning transactions. Participant
 * callbacks must durably deduplicate by txn_id and be safe to retry. */
qihse_txn_manager_t* qihse_txn_manager_create_durable(const char* journal_path);
int qihse_txn_manager_recover(qihse_txn_manager_t* mgr);
void qihse_txn_manager_destroy(qihse_txn_manager_t* mgr);

/* Local shared-backup support. Checkpoints compare only on the SAME retained
 * live manager (never across close/reopen or fork). The private epoch covers
 * membership, decisions, recovery, configuration and ID-floor changes, including
 * unjournaled BEGIN/rollback ABA; it saturates and capture then fails closed.
 * Only an active System Operator (role Operator, user 0, tenant 0) may capture.
 * Volatile, unrecovered, poisoned, inherited, exhausted or non-idle managers
 * are refused. Validation never repairs/truncates the journal.
 *
 * Export requires the starting checkpoint, validates before any output, copies
 * immutable journal bytes, calls write_fn WITHOUT the manager lock, and checks
 * the checkpoint, health and principal generation again afterwards. Callbacks
 * may call manager APIs but must not destroy the manager or the user. A false
 * return leaves *out unchanged: discard ALL callback bytes, even if complete.
 * The caller must retain the handle/user and synchronize their destruction.
 *
 * Bytes are the portable CRC-protected replay journal, NOT an authenticated
 * bundle or full one-phase/MVCC registry snapshot. Record next_txn_id in the
 * authenticated manifest; restore that floor with advance_next_id BEFORE
 * recover(), alongside matching participant receipts. Journal length alone
 * cannot preserve unjournaled IDs. Obtain all sources' starting checkpoints
 * before any export and revalidate all sources after all exports. */

typedef struct qihse_user_s qihse_user_t;
typedef struct qihse_txn_backup_checkpoint_s {
    uint64_t epoch;
    uint64_t next_txn_id;
    uint64_t journal_bytes;
} qihse_txn_backup_checkpoint_t;
typedef bool (*qihse_txn_backup_write_fn)(void* ctx, const void* data, size_t len);

bool qihse_txn_backup_checkpoint_user(qihse_txn_manager_t* mgr,
    const qihse_user_t* user, qihse_txn_backup_checkpoint_t* out);
bool qihse_txn_backup_export_user(qihse_txn_manager_t* mgr,
    const qihse_user_t* user, const qihse_txn_backup_checkpoint_t* expected,
    qihse_txn_backup_write_fn write_fn, void* ctx,
    qihse_txn_backup_checkpoint_t* out);

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

/* Release a terminal transaction handle and its read/write set before manager
 * destruction. The handle remains valid after COMMIT/ROLLBACK until released
 * or until the manager is destroyed. Active, PREPARED, COMMITTING, and
 * ABORTING transactions cannot be released. */
int qihse_txn_release(qihse_txn_manager_t* mgr, qihse_txn_t* txn);

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

/* Attach one transaction-local resource.  Commit publishes it after OCC
 * validation and before the transaction becomes visible as committed;
 * rollback and failed commit discard it. */
int qihse_txn_attach_resource(qihse_txn_t* txn, void* resource_ctx,
                              qihse_txn_resource_commit_fn commit_fn,
                              qihse_txn_resource_rollback_fn rollback_fn);
/* Attach one resource to a registered durable participant. PREPARE routes the
 * resource to that participant's resource_prepare callback, which must persist
 * and consume it. Ordinary one-phase qihse_txn_commit refuses this binding. */
int qihse_txn_attach_participant_resource(qihse_txn_manager_t* mgr,
    qihse_txn_t* txn, uint8_t engine_id, void* resource_ctx,
    qihse_txn_resource_rollback_fn rollback_fn);
/* Move an existing one-phase transaction resource into a registered durable
 * participant binding. On success the participant's resource PREPARE callback
 * owns it; the original one-phase commit callback is not invoked. */
int qihse_txn_enlist_attached_resource(qihse_txn_manager_t* mgr,
    qihse_txn_t* txn, uint8_t engine_id);

/* ── 2PC interface ──────────────────────────────────────────────────────── */

/* Register a participant engine for 2PC. */
int qihse_txn_register_participant(qihse_txn_manager_t* mgr,
                                   qihse_txn_participant_t participant);
/* Register a participant whose prepare callback can persist a per-transaction
 * resource. Keeps qihse_txn_participant_t layout stable. */
int qihse_txn_register_resource_participant(qihse_txn_manager_t* mgr,
    qihse_txn_participant_t participant,
    qihse_txn_resource_prepare_fn resource_prepare);

/* PREPARE phase: call prepare() on all registered participants.
 * Returns 0 if all participants prepared successfully, -1 otherwise. */
int qihse_txn_prepare(qihse_txn_manager_t* mgr, qihse_txn_t* txn);

/* After PREPARE succeeds, COMMIT calls participants. If any callback fails,
 * returns -1 with txn->state == QIHSE_TXN_COMMITTING. The commit decision is
 * irrevocable; call this function again to retry only unfinished callbacks.
 * Durable managers persist and replay the decision; volatile managers retain
 * it only in memory. Participants must deduplicate retries by txn_id. */
int qihse_txn_commit_prepared(qihse_txn_manager_t* mgr, qihse_txn_t* txn);

/* After PREPARE fails (or coordinator decides to abort), call abort(). A
 * failed abort leaves state ABORTING; retry this function until acknowledged.
 * Durable managers persist the ABORT decision before callbacks and replay it
 * during recovery; volatile managers retain pending work only in memory.
 * Participants must durably deduplicate decisions by txn_id. */
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

/* Number of committed write-set summaries retained for active SERIALIZABLE
 * transactions.  Exposed for operational inspection and pruning tests. */
size_t qihse_txn_committed_history_count(qihse_txn_manager_t* mgr);

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
/* Raise the next ID before recovery on a durable, idle coordinator. */
int qihse_txn_advance_next_id(qihse_txn_manager_t* mgr, uint64_t next_id);
