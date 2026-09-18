#ifndef QIHSE_REPL_H
#define QIHSE_REPL_H

#include <stdint.h>
#include <stddef.h>
#include <pthread.h>
#include <time.h>

#include "qihse_kv_store.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    REPL_ROLE_PRIMARY = 0,
    REPL_ROLE_REPLICA = 1,
    REPL_ROLE_STANDBY = 2
} repl_role_t;

typedef enum {
    REPL_STATE_DISCONNECTED = 0,
    REPL_STATE_CONNECTING = 1,
    REPL_STATE_STREAMING = 2,
    REPL_STATE_SYNCING = 3,
    REPL_STATE_ERROR = 4
} repl_state_t;

typedef struct {
    char* name;
    uint64_t restart_lsn;
    uint64_t confirmed_flush_lsn;
    int active;
} qihse_repl_slot_t;

typedef struct {
    repl_role_t role;
    repl_state_t state;
    char* primary_host;
    uint16_t primary_port;
    char* replica_name;
    uint64_t last_lsn;
    uint64_t flush_lsn;
    uint64_t replay_lsn;
    int sync_mode;
    pthread_t stream_thread;
    int stream_fd;
    pthread_mutex_t lock;
    qihse_repl_slot_t* slots;
    size_t num_slots;
    size_t slots_cap;
    /* ── Replica-side apply (qihse_repl_apply_wal) ────────────────────────
     * store is the local store accepted records are replayed into.  It is
     * BORROWED: the caller owns it and must keep it alive until
     * qihse_repl_destroy().  A context with no bound store refuses every
     * record rather than advancing an LSN that reached no store.
     * stage_dir/stage_seg are the context's own one-record replay staging
     * area, created on first use and removed by qihse_repl_destroy(). */
    qihse_kv_store_t* store;
    char* stage_dir;
    char* stage_seg;
} qihse_repl_context_t;

qihse_repl_context_t* qihse_repl_create(repl_role_t role);
int qihse_repl_connect_primary(qihse_repl_context_t* ctx, const char* host, uint16_t port);
int qihse_repl_start_streaming(qihse_repl_context_t* ctx);
int qihse_repl_stop(qihse_repl_context_t* ctx);
void qihse_repl_destroy(qihse_repl_context_t* ctx);

int qihse_repl_ship_wal(qihse_repl_context_t* ctx, const uint8_t* wal_data, size_t len, uint64_t lsn);

/* Bind the local store that qihse_repl_apply_wal() replays accepted records
 * into.  The store is borrowed, never owned, and must outlive the context.
 * Passing NULL unbinds, after which apply refuses every record.  Returns 0, or
 * -1 for a NULL context. */
int qihse_repl_set_store(qihse_repl_context_t* ctx, qihse_kv_store_t* store);

/* The bound store, or NULL when none is bound. */
qihse_kv_store_t* qihse_repl_get_store(qihse_repl_context_t* ctx);

/* Apply one received WAL record (the [LSN][length][data] frame payload shipped
 * by qihse_repl_ship_wal) to the bound store.
 *
 * The record is NOT re-parsed here: the bytes are staged as the single record
 * of a private WAL segment and replayed through the WAL layer's own
 * qihse_wal_replay(), so the length rules and the CRC32 check that decide
 * whether a record is valid are the WAL layer's, not a second copy of them.
 * The store mutation happens in the replay callback, which the WAL layer
 * invokes only after it has accepted the record, so a refused record cannot
 * be partially applied.  INSERT/UPDATE write the key, DELETE removes it, and
 * BEGIN/COMMIT/ABORT/CHECKPOINT carry no store mutation and only advance the
 * position.  The applier writes through the KV layer's unclassified-only
 * entry points: a WAL record carries no classification or SCI, so it cannot
 * express a classified write, and a mutation that the store refuses (for
 * example an overwrite of a classified row) refuses the whole record.
 *
 * On success the mutation has reached the store and replay_lsn/flush_lsn
 * advance to the record's LSN.  On refusal (-1) nothing is applied and no LSN
 * advances.  Refused are: a NULL/empty record, a context with no bound store,
 * QIHSE_WAL_INVALID_LSN, a record whose own LSN is not the lsn argument,
 * declared field lengths that disagree with len, bytes the WAL layer rejects
 * (truncated tail, checksum mismatch, unknown op), and a mutation the store
 * refuses.
 *
 * Ordering and idempotency: apply is order-sensitive.  replay_lsn is a
 * monotonic watermark of the highest LSN that reached the store; a record at
 * or below the watermark has already been applied, is not applied twice, and
 * still reports success (0), so a retransmitted record is a no-op.  ctx->lock
 * serialises appliers, so concurrent callers cannot cross the watermark out
 * of order.  The watermark is in memory: it is not recovered after a restart,
 * which is safe for INSERT/UPDATE/DELETE because reaching the same key state
 * twice is idempotent, but a caller that needs durable exactly-once semantics
 * must persist the position itself. */
int qihse_repl_apply_wal(qihse_repl_context_t* ctx, const uint8_t* wal_data, size_t len, uint64_t lsn);
int qihse_repl_get_status(qihse_repl_context_t* ctx, uint64_t* last_lsn, uint64_t* flush_lsn, repl_state_t* state);

int qihse_repl_create_slot(qihse_repl_context_t* ctx, const char* name);
int qihse_repl_drop_slot(qihse_repl_context_t* ctx, const char* name);
int qihse_repl_advance_slot(qihse_repl_context_t* ctx, const char* name, uint64_t new_lsn);
size_t qihse_repl_slot_count(qihse_repl_context_t* ctx);

#ifdef __cplusplus
}
#endif
#endif
