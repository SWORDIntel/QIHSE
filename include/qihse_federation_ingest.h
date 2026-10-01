#ifndef QIHSE_FEDERATION_INGEST_H
#define QIHSE_FEDERATION_INGEST_H

/*
 * QIHSE federation ingest — the KEYSTONE live-consumption contract
 * (CITADEL KEYSTONE_FEDERATION_INTELLIGENCE_UPGRADE_BRIEF §5.2, W7 item 3).
 *
 * A consumer (KEYSTONE, a mirror, a rejoin driver) applies journal events
 * to its own state under this module's guarantees:
 *
 *   - resumable cursor: a durable checkpoint holds the journal position;
 *     run() resumes exactly there after a crash;
 *   - at-least-once input, idempotent application: re-delivery (a crash
 *     between applying an event and persisting the checkpoint, or overlap
 *     with a snapshot bootstrap) is detected by event-id dedup and never
 *     reaches the apply callback twice;
 *   - event-id deduplication: request_ids are remembered in a bounded
 *     ring persisted with the checkpoint;
 *   - generation check: per-resource generations must strictly increase;
 *     stale events (old writers, reordered delivery) are skipped and
 *     counted, never applied;
 *   - tombstone support: object.delete events arrive as INGEST_APPLY_DELETE
 *     under the same generation gate, and reset the resource's lifecycle
 *     (a later create at a lower generation is a NEW object, not a
 *     regression);
 *   - checkpoint persistence: atomic (tmp+rename), after every run.
 *
 * ── The snapshot↔watch cursor handshake (§5.1) ─────────────────────────
 *
 * boot(snapshot_cursor C) encodes the exact-cursor meeting: it declares
 * "my materialized snapshot already reflects every event at offset <= C;
 *  run me live from C."  Events after C stream through the gates above.
 * If the snapshot was taken a moment LATER than its claimed cursor (the
 * practical case — snapshot materialization is not atomic with the
 * journal), the first live events overlap the snapshot's tail: dedup by
 * event id discards what the snapshot already applied and the generation
 * gate discards what it superseded.  Events are "neither lost nor
 * double-applied without detection" — detection is the dedup and
 * generation counters, surfaced via qihse_federation_ingest_stats().
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "qihse_federation.h"

#ifdef __cplusplus
extern "C" {
#endif

#define QIHSE_FEDERATION_INGEST_DEDUP_RING 64u
#define QIHSE_FEDERATION_INGEST_RESOURCES_MAX 4096u

typedef enum {
    QIHSE_INGEST_APPLY_UPSERT = 0,      /* create/replace at a newer generation */
    QIHSE_INGEST_APPLY_DELETE,          /* tombstone at a newer generation */
    QIHSE_INGEST_SKIPPED_DUPLICATE,     /* event id already applied (idempotent) */
    QIHSE_INGEST_SKIPPED_STALE          /* generation did not strictly increase */
} qihse_federation_ingest_op_t;

typedef struct {
    uint64_t applied_upserts;
    uint64_t applied_deletes;
    uint64_t skipped_duplicates;
    uint64_t skipped_stale;
} qihse_federation_ingest_stats_t;

/*
 * Apply callback.  Return false to stop this run early (the checkpoint is
 * still persisted; the event that was refused is re-delivered next run —
 * the caller's own write must be retryable, which is the at-least-once
 * contract).  DELETE events arrive with payload_len 0.
 */
typedef bool (*qihse_federation_ingest_apply_fn)(
    qihse_federation_ingest_op_t op,
    const qihse_federation_event_t* event,
    const uint8_t* payload, size_t payload_len,
    void* user_data);

typedef struct qihse_federation_ingest qihse_federation_ingest_t;

/* Open (or resume from) a checkpoint file.  NULL on error. */
qihse_federation_ingest_t* qihse_federation_ingest_open(const char* checkpoint_path);
void qihse_federation_ingest_destroy(qihse_federation_ingest_t* ingest);

/* The §5.1 handshake: declare that the caller's snapshot reflects every
 * event at offset <= snapshot_cursor and start live consumption there.
 * Refuses on a non-fresh consumer that already has progress (call
 * _reset() first if a re-bootstrap is genuinely intended). */
bool qihse_federation_ingest_boot(qihse_federation_ingest_t* ingest,
                                  uint64_t snapshot_cursor);

/* Seed a resource's generation gate from the SNAPSHOT state (part of the
 * §5.1 handshake): a bootstrapping consumer declares the generations its
 * snapshot already reflects, so live events that overlap the snapshot's
 * tail are refused by the generation gate instead of re-applying.  The
 * gate only ever rises (never lowered). */
bool qihse_federation_ingest_seed_generation(qihse_federation_ingest_t* ingest,
                                             const char* resource_id,
                                             uint64_t generation);

/* Wipe the checkpoint (fresh consumer). */
bool qihse_federation_ingest_reset(qihse_federation_ingest_t* ingest);

/*
 * Pull at most max_events (0 = unbounded) events from the checkpointed
 * cursor, run them through the gates, and persist the checkpoint.
 * Returns the number of events CONSUMED (including skips).  A callback
 * that returns false stops the run; its event is re-delivered next time.
 * out_cursor (optional) receives the new resume position.
 */
uint64_t qihse_federation_ingest_run(qihse_federation_ingest_t* ingest,
                                     qihse_federation_journal_t* journal,
                                     uint64_t max_events,
                                     qihse_federation_ingest_apply_fn apply,
                                     void* user_data,
                                     uint64_t* out_cursor);

/* Current resume position / stats. */
uint64_t qihse_federation_ingest_cursor(const qihse_federation_ingest_t* ingest);
void qihse_federation_ingest_stats(const qihse_federation_ingest_t* ingest,
                                   qihse_federation_ingest_stats_t* out);

#ifdef __cplusplus
}
#endif

#endif /* QIHSE_FEDERATION_INGEST_H */
