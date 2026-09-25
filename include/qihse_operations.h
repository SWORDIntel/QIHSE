#ifndef QIHSE_OPERATIONS_H
#define QIHSE_OPERATIONS_H

/*
 * QIHSE operational hardening — federation stage F8.
 * See docs/plans/qihse_federation_upgrade_plan.md §23 (snapshot and backup semantics), §24 (schema evolution),
 * §41 (observability) and §43 (reconciliation safety).
 *
 * Every persisted or wire object carries a schema header.  Snapshots carry a
 * manifest with checksums and a WAL continuation point.  Rejoin follows an
 * explicit ordered state machine.  Metrics are label-bounded.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "qihse_federation.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ────────────────────────────────────────────────────────────────────────
 * Schema evolution (plan §24)
 * ──────────────────────────────────────────────────────────────────────── */

#define QIHSE_SCHEMA_ID_FEDERATION 0x51484644u /* "QHFD" */

/* What THIS build understands.  A reader's capabilities come from its own
 * build, never from the object it is reading — deriving them from the object
 * would make every compatibility check vacuous. */
#define QIHSE_SCHEMA_MAX_VERSION 1u
#define QIHSE_SCHEMA_KNOWN_FEATURES 0ULL

typedef struct {
    uint32_t schema_id;
    uint32_t schema_version;
    /* Oldest reader version that can still interpret this object.  A reader
     * older than this must refuse rather than guess. */
    uint32_t minimum_reader_version;
    /* Features a reader MUST implement to interpret this object safely.  An
     * unknown bit here is a hard rejection. */
    uint64_t required_features;
    /* Features a reader MAY ignore.  An unknown bit here is silently dropped,
     * which is what allows a new writer to add fields without a flag day. */
    uint64_t optional_features;
} qihse_schema_header_t;

typedef enum {
    QIHSE_SCHEMA_OK = 0,
    QIHSE_SCHEMA_ERR_MALFORMED,
    QIHSE_SCHEMA_ERR_READER_TOO_OLD,
    QIHSE_SCHEMA_ERR_UNKNOWN_REQUIRED_FEATURE
} qihse_schema_result_t;

const char* qihse_schema_result_name(qihse_schema_result_t r);

/* A reader declares what it can handle. */
typedef struct {
    uint32_t max_schema_version;
    uint64_t known_features;
} qihse_schema_reader_t;

/* Decide whether this reader may interpret the object.  Fails closed: an
 * unknown required feature or a too-old reader is a rejection, never a
 * best-effort parse. */
qihse_schema_result_t qihse_schema_check(const qihse_schema_header_t* header,
                                         const qihse_schema_reader_t* reader);

void qihse_schema_header_init(qihse_schema_header_t* header, uint32_t schema_id,
                              uint32_t version);

/* ── Resumable migrations (plan §24) ──────────────────────────────────── */

typedef struct {
    uint32_t schema_id;
    uint32_t from_version;
    uint32_t to_version;
    char description[128];
    /* A resumable migration records progress, so a crash mid-migration
     * continues from where it stopped instead of restarting. */
    bool resumable;
} qihse_schema_migration_t;

#define QIHSE_SCHEMA_MIGRATION_PREFIX "schema/migration:"
#define QIHSE_SCHEMA_PROGRESS_PREFIX  "schema/progress:"

bool qihse_schema_migration_register(void* store_void, void* user_void,
                                     const qihse_schema_migration_t* migration);
bool qihse_schema_migration_lookup(void* store_void, void* user_void,
                                   uint32_t schema_id, uint32_t from_version,
                                   qihse_schema_migration_t* out);

/* Progress is tracked in units of work so a partially applied migration is
 * observable and resumable rather than being a coin flip. */
bool qihse_schema_progress_set(void* store_void, void* user_void,
                               uint32_t schema_id, uint32_t version,
                               uint64_t completed_units, uint64_t total_units);
bool qihse_schema_progress_get(void* store_void, void* user_void,
                               uint32_t schema_id, uint32_t version,
                               uint64_t* out_completed, uint64_t* out_total);
/* True when the migration reached its total. */
bool qihse_schema_progress_complete(void* store_void, void* user_void,
                                    uint32_t schema_id, uint32_t version);

/* ────────────────────────────────────────────────────────────────────────
 * Snapshot and backup semantics (plan §23)
 * ──────────────────────────────────────────────────────────────────────── */

typedef enum {
    /* Crash-consistent local snapshot with no federation coordination. */
    QIHSE_SNAPSHOT_LOCAL = 0,
    /* Captures selected replication groups at known committed indices. */
    QIHSE_SNAPSHOT_COORDINATED
} qihse_snapshot_kind_t;

const char* qihse_snapshot_kind_name(qihse_snapshot_kind_t kind);
bool qihse_snapshot_kind_parse(const char* name, qihse_snapshot_kind_t* out);

#define QIHSE_SNAPSHOT_MAX_GROUPS 8u

typedef struct {
    qihse_uuid_t snapshot_id;
    qihse_snapshot_kind_t kind;
    qihse_uuid_t cluster_id;
    qihse_uuid_t created_by;
    uint64_t created_hlc_physical;
    qihse_schema_header_t schema;
    /* Highest object generation captured, per the manifest. */
    uint64_t max_generation;
    /* Where the WAL resumes after this snapshot.  A backup without this is
     * not restorable to a consistent point. */
    uint64_t wal_continuation_offset;
    /* SHA-384 over the manifest body, so a truncated or edited manifest is
     * detectable before anyone tries to restore from it. */
    uint8_t checksum[48];
    /* Key id only — never key material (plan §20, §21). */
    char encryption_key_id[128];
    uint32_t group_count;
    char groups[QIHSE_SNAPSHOT_MAX_GROUPS][64];
    uint64_t object_count;
} qihse_snapshot_manifest_t;

#define QIHSE_SNAPSHOT_PREFIX "snapshot/manifest:"

/* Persist a snapshot manifest.  The checksum is computed over the manifest
 * body by this call, so a caller cannot record a manifest whose digest does
 * not match its contents. */
bool qihse_snapshot_record(void* store_void, void* user_void,
                           qihse_snapshot_manifest_t* manifest);
bool qihse_snapshot_lookup(void* store_void, void* user_void,
                           const qihse_uuid_t* snapshot_id,
                           qihse_snapshot_manifest_t* out);

/* Verify a stored manifest against its recorded checksum.  Returns false if
 * the record was altered or truncated. */
bool qihse_snapshot_verify(void* store_void, void* user_void,
                           const qihse_uuid_t* snapshot_id);

/* ────────────────────────────────────────────────────────────────────────
 * Reconciliation safety (plan §43)
 * ──────────────────────────────────────────────────────────────────────── */

/* The ordered rejoin sequence.  A rejoining node must not publish stale
 * exclusive ownership as authoritative, so the sequence deliberately ends
 * with the authority decision rather than starting with it. */
typedef enum {
    QIHSE_REJOIN_IDLE = 0,
    QIHSE_REJOIN_AUTHENTICATE_PEER,
    QIHSE_REJOIN_COMPARE_FEDERATION_UUID,
    QIHSE_REJOIN_COMPARE_BOOT_UUID,
    QIHSE_REJOIN_EXCHANGE_HLC,
    QIHSE_REJOIN_EXCHANGE_MANIFESTS,
    QIHSE_REJOIN_IDENTIFY_DIVERGENCE,
    QIHSE_REJOIN_TRANSFER_EVENTS,
    QIHSE_REJOIN_APPLY_CONFLICT_POLICY,
    QIHSE_REJOIN_RECONSTRUCT_STATE,
    QIHSE_REJOIN_VERIFY_CHECKSUMS,
    QIHSE_REJOIN_COMPLETE,
    QIHSE_REJOIN_ABORTED
} qihse_rejoin_step_t;

const char* qihse_rejoin_step_name(qihse_rejoin_step_t step);
bool qihse_rejoin_step_parse(const char* name, qihse_rejoin_step_t* out);

/* The next step in the sequence, or ABORTED when the current step is
 * terminal or the transition is illegal. */
qihse_rejoin_step_t qihse_rejoin_next_step(qihse_rejoin_step_t current);

/* May exclusive ownership be published at this point in the sequence?  Only
 * after the state has been reconstructed and checksums verified. */
bool qihse_rejoin_may_publish_ownership(qihse_rejoin_step_t current);

typedef struct {
    qihse_uuid_t node_id;
    qihse_uuid_t peer_node;
    qihse_rejoin_step_t step;
    uint64_t started_hlc_physical;
    uint64_t updated_hlc_physical;
    uint64_t events_transferred;
    uint64_t conflicts_applied;
    char last_error[128];
} qihse_rejoin_state_t;

#define QIHSE_REJOIN_PREFIX "rejoin/state:"

bool qihse_rejoin_state_put(void* store_void, void* user_void,
                            const qihse_rejoin_state_t* state);
bool qihse_rejoin_state_get(void* store_void, void* user_void,
                            const qihse_uuid_t* node_id,
                            qihse_rejoin_state_t* out);

/* ────────────────────────────────────────────────────────────────────────
 * Observability (plan §41)
 * ──────────────────────────────────────────────────────────────────────── */

/* Counters are plain monotonically-increasing integers.  Gauges are
 * point-in-time values.  Nothing here is labelled by node or namespace: the
 * brief requires label-bounded metrics to avoid cardinality explosions, so
 * per-node detail is read from the status APIs instead. */
typedef struct {
    uint64_t federation_peer_state_connected;
    uint64_t replication_lag_ms;
    uint64_t unreplicated_bytes;
    uint64_t anti_entropy_ranges_checked;
    uint64_t anti_entropy_bytes_repaired;
    uint64_t conflict_count;
    uint64_t watch_subscribers;
    uint64_t watch_backlog;
    uint64_t lease_count;
    uint64_t lease_expiry_failures;
    uint64_t cas_failures;
    uint64_t stale_epoch_rejections;
    uint64_t auth_failures;
    uint64_t audit_chain_status_ok;
    uint64_t runtime_trust_state;
    uint64_t runtime_profile_drift;
    uint64_t unexpected_listener_count;
    uint64_t unexpected_capability_count;
    uint64_t provenance_verification_state;
    uint64_t clock_sync_state;
    uint64_t peer_clock_skew_ms;
} qihse_federation_metrics_t;

void qihse_federation_metrics_init(qihse_federation_metrics_t* m);

/* Render the metric set as label-bounded Prometheus-style text.  A NULL or
 * empty prefix uses "qihse". */
bool qihse_federation_metrics_render(const qihse_federation_metrics_t* m,
                                     const char* prefix,
                                     char* out, size_t out_cap);

/* ────────────────────────────────────────────────────────────────────────
 * Performance budgets (plan §40)
 * ──────────────────────────────────────────────────────────────────────── */

/* Budgets are engineering targets, not benchmark claims.  A measurement is
 * only meaningful relative to the same machine's baseline, so the harness
 * records both and compares. */
typedef struct {
    double local_kv_overhead_p50_pct;
    double local_kv_overhead_p99_pct;
    double event_append_per_sec_min;
    double watch_delivery_p50_ms;
} qihse_perf_budget_t;

void qihse_perf_budget_init(qihse_perf_budget_t* b);

typedef struct {
    double local_kv_overhead_p50_pct;
    double local_kv_overhead_p99_pct;
    double event_append_per_sec;
    double watch_delivery_p50_ms;
} qihse_perf_measurement_t;

typedef struct {
    bool passed;
    char failures[4][128];
    uint32_t failure_count;
} qihse_perf_verdict_t;

/* Compare a measurement against a budget.  Each metric is checked only if the
 * measurement actually produced it (a non-positive value means "not
 * measured"), so a partial harness does not produce false failures. */
bool qihse_perf_evaluate(const qihse_perf_budget_t* budget,
                         const qihse_perf_measurement_t* measured,
                         qihse_perf_verdict_t* out);

#ifdef __cplusplus
}
#endif

#endif /* QIHSE_OPERATIONS_H */
