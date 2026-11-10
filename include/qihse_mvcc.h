#ifndef QIHSE_MVCC_H
#define QIHSE_MVCC_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "qihse_platform.h"
#include "qihse_arena.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ── Constants ──────────────────────────────────────────────────────────── */

#define QIHSE_MVCC_INVALID_XMAX 0u
#define QIHSE_MVCC_MAX_KEY 256u

/* ── Engine IDs ─────────────────────────────────────────────────────────── */

typedef enum qihse_mvcc_engine_e {
    QIHSE_MVCC_ENGINE_KV       = 0,
    QIHSE_MVCC_ENGINE_DOCUMENT = 1,
    QIHSE_MVCC_ENGINE_COLUMN   = 2,
    QIHSE_MVCC_ENGINE_VECTOR   = 3,
    QIHSE_MVCC_ENGINE_EVENT    = 4
} qihse_mvcc_engine_t;

/* ── Version node ───────────────────────────────────────────────────────── */

typedef struct qihse_mvcc_version_s {
    uint64_t xmin;                    /* txn ID that created this version */
    uint64_t xmax;                    /* txn ID that deleted/superseded, 0 = live */
    size_t   value_len;
    void*    value;                   /* owned copy of the value data */
    bool     is_delete;               /* delete intent: a marker, not a version */
    uint64_t delete_snapshot;         /* snapshot a delete intent was taken at */
    struct qihse_mvcc_version_s* next; /* newer version in the chain */
} qihse_mvcc_version_t;

/* ── Row (version chain head) ───────────────────────────────────────────── */

typedef struct qihse_mvcc_row_s {
    uint8_t  engine_id;
    size_t   key_len;
    char     key[QIHSE_MVCC_MAX_KEY];
    qihse_mvcc_version_t* head;       /* newest version (front of chain) */
    struct qihse_mvcc_row_s* next;    /* hash chain */
} qihse_mvcc_row_t;

/* ── MVCC store (opaque) ────────────────────────────────────────────────── */

typedef struct qihse_mvcc_store qihse_mvcc_store_t;

/* ── Lifecycle ──────────────────────────────────────────────────────────── */

qihse_mvcc_store_t* qihse_mvcc_store_create(size_t initial_buckets);
void qihse_mvcc_store_destroy(qihse_mvcc_store_t* store);

/* ── Version chain operations ───────────────────────────────────────────── */

/* Insert a new version of a row (creates a new version node and prepends
 * to the chain).
 * Returns 0 on success, -1 on failure. */
int qihse_mvcc_insert(qihse_mvcc_store_t* store,
                      uint8_t engine_id,
                      const void* key, size_t key_len,
                      const void* value, size_t value_len,
                      uint64_t txn_id);

/* Delete a row for the given transaction.
 *
 * The delete is recorded as a delete intent at the head of the chain instead
 * of marking xmax on a version: the chain head is not necessarily the version
 * a reader at this transaction's snapshot sees (it may be a version whose
 * writer aborted), and the store has no commit context here, so it cannot tell
 * a committed version from an aborted one.  The intent carries the deleting
 * transaction and the snapshot the delete is evaluated at (the deleting
 * transaction's id, the snapshot a reader of this delete uses); the read path,
 * which does have commit context, then hides exactly the versions that were
 * visible at that snapshot.  Readers whose snapshot predates the delete still
 * see the row.
 * Returns 0 on success, -1 if row not found. */
int qihse_mvcc_delete(qihse_mvcc_store_t* store,
                      uint8_t engine_id,
                      const void* key, size_t key_len,
                      uint64_t txn_id);

/* Update a row = insert new version + mark old as superseded. */
int qihse_mvcc_update(qihse_mvcc_store_t* store,
                      uint8_t engine_id,
                      const void* key, size_t key_len,
                      const void* value, size_t value_len,
                      uint64_t txn_id);

/* ── Visibility / read ──────────────────────────────────────────────────── */

/* A version is visible to a transaction if:
 *   xmin <= snapshot AND (xmax == 0 OR xmax > snapshot)
 * and xmin belongs to a committed transaction or the current txn itself.
 *
 * A delete intent (qihse_mvcc_delete) hides the versions that were visible at
 * the snapshot it was evaluated at, once its deleting transaction is committed
 * and visible to the reader; a version written by a transaction the delete
 * could not see (xmin above that snapshot) is not hidden.
 *
 * is_committed_cb: callback to check if a txn_id is committed.
 *   (passed from the transaction manager). If read-your-own-writes is needed,
 *   the caller's callback must also recognize its current transaction ID;
 *   the snapshot alone does not identify the reader. Each ID is resolved once
 *   per read, without holding the version-store lock.
 */
typedef bool (*qihse_mvcc_committed_cb)(void* ctx, uint64_t txn_id);

/* Read the visible version of a row for a given snapshot.
 * Returns true if a visible version exists, false otherwise.
 * On success, out_value points to internal memory (do not free) and
 * out_value_len is set. Failure clears both outputs. Metadata-copy allocation
 * failure returns false with errno=ENOMEM; payloads are not copied. */
bool qihse_mvcc_read(qihse_mvcc_store_t* store,
                     uint8_t engine_id,
                     const void* key, size_t key_len,
                     uint64_t snapshot,
                     qihse_mvcc_committed_cb is_committed,
                     void* committed_ctx,
                     const void** out_value, size_t* out_value_len);

/* Check if a row exists (visible to the given snapshot). */
bool qihse_mvcc_exists(qihse_mvcc_store_t* store,
                       uint8_t engine_id,
                       const void* key, size_t key_len,
                       uint64_t snapshot,
                       qihse_mvcc_committed_cb is_committed,
                       void* committed_ctx);

/* ── Garbage collection / vacuum ────────────────────────────────────────── */

/* Determine the minimum active snapshot (oldest active txn ID).
 * Versions with xmax < min_snapshot AND not visible to any active txn
 * can be garbage collected. */
uint64_t qihse_mvcc_min_active_snapshot(qihse_mvcc_store_t* store);

/* Legacy cutoff-only entry points cannot determine whether xmax committed.
 * They conservatively reclaim nothing; use the committed-aware forms below
 * for a transactional store. Existing signatures remain available. */
int qihse_mvcc_gc(qihse_mvcc_store_t* store, uint64_t min_snapshot);

/* Legacy conservative vacuum; like cutoff-only GC it reclaims nothing. */
int qihse_mvcc_vacuum(qihse_mvcc_store_t* store, uint64_t min_snapshot);

/* Reclaim versions only when xmax is below the oldest active snapshot AND
 * the supplied transaction status confirms that xmax committed. The callback
 * runs without the store lock. A missing callback is an error. Delete intents
 * remain retained. Returns removed version count, or -1 on error.
 * Arena storage is retained until store destruction; these unlink versions. */
int qihse_mvcc_gc_committed(qihse_mvcc_store_t* store, uint64_t min_snapshot,
                            qihse_mvcc_committed_cb is_committed,
                            void* committed_ctx);
int qihse_mvcc_vacuum_committed(qihse_mvcc_store_t* store, uint64_t min_snapshot,
                                qihse_mvcc_committed_cb is_committed,
                                void* committed_ctx);

/* ── Debug / inspection ─────────────────────────────────────────────────── */

/* Count total version nodes in the store. */
int qihse_mvcc_version_count(qihse_mvcc_store_t* store);

/* Count rows (distinct keys) in the store. */
int qihse_mvcc_row_count(qihse_mvcc_store_t* store);

#ifdef __cplusplus
}
#endif

#endif /* QIHSE_MVCC_H */
