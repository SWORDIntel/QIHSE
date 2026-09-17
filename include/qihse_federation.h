#ifndef QIHSE_FEDERATION_H
#define QIHSE_FEDERATION_H

/* QIHSE federation — stage F0 primitives.
 *
 * The federation data plane (consistency classes, local-authority
 * namespaces, event journal, watches, leases, trust plane) builds on these
 * primitives. F0 deliberately changes no existing cluster behaviour: it adds
 * the identity, time, version, and fencing vocabulary the later stages need.
 * See docs/plans/qihse_federation_upgrade_plan.md.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "qihse_event_stream.h"

#ifdef __cplusplus
extern "C" {
#endif

#define QIHSE_UUID_BYTES 16u
#define QIHSE_UUID_STR_LEN 36u /* "8-4-4-4-12" without NUL */

typedef struct {
    uint8_t bytes[QIHSE_UUID_BYTES];
} qihse_uuid_t;

/* Identity. A federation node/object identity is a UUID — never an IP, a
 * hostname, or a topology index (plan §18). */
bool qihse_uuid_generate(qihse_uuid_t* out);
/* Deterministic identity for a seed (SHA-384 derived, version/variant bits
 * set): same seed, same UUID, on every node. */
bool qihse_uuid_from_seed(const void* seed, size_t seed_len, qihse_uuid_t* out);
bool qihse_uuid_parse(const char* text, qihse_uuid_t* out);
bool qihse_uuid_format(const qihse_uuid_t* id, char out[QIHSE_UUID_STR_LEN + 1u]);
bool qihse_uuid_is_nil(const qihse_uuid_t* id);
bool qihse_uuid_equal(const qihse_uuid_t* a, const qihse_uuid_t* b);

/* Hybrid logical clock (plan §7.1): physical milliseconds plus a logical
 * counter, monotonic on a node and causally ordered across nodes. */
typedef struct {
    uint64_t physical_ms;
    uint32_t logical;
} qihse_hlc_t;

void qihse_hlc_init(qihse_hlc_t* clock);
/* Local event: strictly greater than any previous tick and any observed
 * remote timestamp. */
void qihse_hlc_tick(qihse_hlc_t* clock, qihse_hlc_t* out);
/* Receive path: advance the local clock past a remote timestamp so the next
 * local tick is ordered after the remote event. */
void qihse_hlc_observe(qihse_hlc_t* clock, const qihse_hlc_t* remote);
/* Total order across nodes: -1, 0, +1. */
int qihse_hlc_compare(const qihse_hlc_t* a, const qihse_hlc_t* b);
/* Sortable 64-bit encoding (48-bit ms + 16-bit logical counter). */
uint64_t qihse_hlc_pack(const qihse_hlc_t* clock);
void qihse_hlc_unpack(uint64_t packed, qihse_hlc_t* out);

/* Object generation (plan §7.2): per-object version bumped on every mutation,
 * carrying the HLC stamp of the bump. */
typedef struct {
    qihse_uuid_t object;
    uint64_t generation;
    qihse_hlc_t stamp;
} qihse_object_version_t;

void qihse_object_version_init(qihse_object_version_t* version, const qihse_uuid_t* object);
/* Bump to the next generation and stamp it with the clock's next tick. */
void qihse_object_version_bump(qihse_object_version_t* version, qihse_hlc_t* clock);
/* Order by generation first, HLC stamp as the tie-break: -1, 0, +1. */
int qihse_object_version_compare(const qihse_object_version_t* a,
                                 const qihse_object_version_t* b);

/* Fencing epoch (plan §7.3): monotonic ownership epoch for exclusive state.
 * A holder may only act while its epoch is the highest it has observed. */
typedef struct {
    uint64_t epoch;
    qihse_uuid_t holder;
} qihse_fencing_token_t;

void qihse_fencing_token_init(qihse_fencing_token_t* token);
/* Acquire exclusive state: succeeds only when `observed_epoch` is strictly
 * older than the new epoch, and always advances the epoch. Fails closed. */
bool qihse_fencing_acquire(qihse_fencing_token_t* token, uint64_t observed_epoch,
                           const qihse_uuid_t* holder);
/* Is this token still the highest the caller has observed? */
bool qihse_fencing_valid(const qihse_fencing_token_t* token, uint64_t observed_epoch);

/* ────────────────────────────────────────────────────────────────────────
 * F1 — Sovereign local state (plan §4, §5).
 *
 * A consistency class tags how a namespace reaches agreement. LOCAL
 * namespaces are authoritative on one node and MUST remain read-write
 * during complete network isolation. QUORUM/LINEARIZABLE namespaces fail
 * closed when consensus is unavailable; they never force the whole node
 * read-only (plan §3.1, §3.2, acceptance criteria 1–2).
 * ──────────────────────────────────────────────────────────────────────── */

typedef enum {
    QIHSE_CONSISTENCY_LOCAL = 0,
    QIHSE_CONSISTENCY_EVENTUAL,
    QIHSE_CONSISTENCY_CAUSAL,
    QIHSE_CONSISTENCY_QUORUM,
    QIHSE_CONSISTENCY_LINEARIZABLE
} qihse_consistency_class_t;

/* Human-readable name ("LOCAL", "EVENTUAL", ...); NULL if invalid. */
const char* qihse_consistency_class_name(qihse_consistency_class_t c);
/* Parse a name into a class; false on unknown. */
bool qihse_consistency_class_parse(const char* name, qihse_consistency_class_t* out);
/* A class is "local-safe" if an isolated node may continue to serve
 * authorized reads and writes without peer agreement. LOCAL always;
 * EVENTUAL and CAUSAL are local-safe for non-exclusive state. */
bool qihse_consistency_class_is_local_safe(qihse_consistency_class_t c);
/* A class is "strong" if it requires peer agreement and must fail closed
 * when that agreement is unavailable (QUORUM, LINEARIZABLE). */
bool qihse_consistency_class_is_strong(qihse_consistency_class_t c);

/* Federation operating state of a node (plan §5). */
typedef enum {
    QIHSE_FEDERATION_STATE_CONNECTED = 0,
    QIHSE_FEDERATION_STATE_DEGRADED,
    QIHSE_FEDERATION_STATE_ISOLATED,
    QIHSE_FEDERATION_STATE_RECOVERING,
    QIHSE_FEDERATION_STATE_FENCED,
    QIHSE_FEDERATION_STATE_MAINTENANCE
} qihse_federation_state_t;

const char* qihse_federation_state_name(qihse_federation_state_t s);
bool qihse_federation_state_parse(const char* name, qihse_federation_state_t* out);

/* Local database usability, independent of federation state. A node in
 * ISOLATED state still reports local_database = READ_WRITE for LOCAL
 * namespaces (acceptance criterion 2). */
typedef enum {
    QIHSE_LOCAL_DB_READ_WRITE = 0,
    QIHSE_LOCAL_DB_READ_ONLY
} qihse_local_db_state_t;

const char* qihse_local_db_state_name(qihse_local_db_state_t s);

/* Namespace authority record (plan §5, §6). A namespace is either
 * local-authority (this node owns it) or federation-authority (peers must
 * agree). LOCAL namespaces are always local-authority. */
typedef struct {
    char name[64];
    qihse_consistency_class_t consistency;
    qihse_uuid_t authority_node;
    bool local_authority;
} qihse_federation_namespace_t;

/* A namespace is writable on this node right now if its consistency class
 * is local-safe OR the authority is the local node OR the federation is
 * CONNECTED/DEGRADED for strong namespaces. Strong namespaces fail closed
 * (not writable) when the node is ISOLATED/FENCED/RECOVERING without peers. */
bool qihse_federation_namespace_writable(const qihse_federation_namespace_t* ns,
                                         qihse_federation_state_t state,
                                         const qihse_uuid_t* local_node);

/* Federation status snapshot (plan §5 status object). */
typedef struct {
    qihse_uuid_t node_id;
    qihse_federation_state_t federation_state;
    qihse_local_db_state_t local_database;
    bool strong_namespaces_available;
    bool eventual_namespaces_available;
    uint64_t pending_replication_events;
    qihse_hlc_t last_peer_contact_hlc;
    bool reconciliation_required;
} qihse_federation_status_t;

void qihse_federation_status_init(qihse_federation_status_t* status,
                                 const qihse_uuid_t* node_id);
/* Recompute derived fields from the federation state: local_database stays
 * READ_WRITE for local-safe namespaces; strong_namespaces_available is true
 * only when the state allows consensus. */
void qihse_federation_status_recompute(qihse_federation_status_t* status);
/* Render the status as a single-line JSON-ish string into `out`. */
void qihse_federation_status_format(const qihse_federation_status_t* status,
                                    char* out, size_t out_cap);

/* ────────────────────────────────────────────────────────────────────────
 * Namespace registry. Backed by the caller-provided KV store under the
 * "fedns:" prefix. Every entry takes an explicit authenticated user so the
 * registry never becomes an authorization bypass (AGENTS.md invariant 1).
 * ──────────────────────────────────────────────────────────────────────── */

#define QIHSE_FEDERATION_NS_PREFIX "fedns:"
#define QIHSE_FEDERATION_NS_NAME_MAX 63u

/* Register or replace a namespace. `local_node` is the calling node's UUID;
 * local_authority is set when authority_node equals local_node OR when the
 * consistency class is LOCAL. Returns false on invalid name/class. */
bool qihse_federation_namespace_register(void* store_void, void* user_void,
                                         const char* name,
                                         qihse_consistency_class_t consistency,
                                         const qihse_uuid_t* authority_node,
                                         const qihse_uuid_t* local_node);
/* Look up a namespace by name. Returns false if not registered. */
bool qihse_federation_namespace_lookup(void* store_void, void* user_void,
                                        const char* name,
                                        qihse_federation_namespace_t* out);
/* Remove a namespace registration. Returns false if not found. */
bool qihse_federation_namespace_unregister(void* store_void, void* user_void,
                                            const char* name);
/* Iterate registered namespaces. cb returns false to stop. */
typedef bool (*qihse_federation_ns_iter_cb)(const qihse_federation_namespace_t* ns,
                                            void* user_data);
void qihse_federation_namespace_foreach(void* store_void, void* user_void,
                                        qihse_federation_ns_iter_cb cb,
                                        void* user_data);

/* ────────────────────────────────────────────────────────────────────────
 * F2 — Event journal + watches (plan §8, §9, §12, §13).
 *
 * Every cross-node mutation carries a federation mutation envelope so the
 * journal can deduplicate retries (idempotency), attribute changes, and
 * detect conflicts.  The journal itself is an append-only log backed by
 * qihse_event_stream under the "federation" topic; records form a hash
 * chain for tamper-evidence.  Watches are resumable cursors over the
 * journal with prefix filtering and at-least-once delivery.
 * ──────────────────────────────────────────────────────────────────────── */

/* Mutation envelope (plan §8). Every cross-node write path carries this. */
typedef struct {
    qihse_uuid_t request_id;      /* idempotency key — retries reuse it */
    qihse_uuid_t origin_node;     /* node that initiated the mutation */
    qihse_uuid_t principal_id;    /* authenticated principal */
    qihse_hlc_t  hlc;             /* causal timestamp */
    uint64_t     expected_generation; /* CAS guard; 0 = no CAS */
    uint64_t     fencing_epoch;   /* exclusive-state epoch; 0 = none */
    qihse_consistency_class_t consistency;
    uint32_t     flags;           /* reserved */
} qihse_federation_mutation_t;

/* Idempotency ledger (plan §9). Bounded, KV-backed under "fedreq:". Maps
 * request_id -> result digest + completion generation. Every entry takes
 * an explicit authenticated user (AGENTS.md invariant 1). */
typedef struct {
    qihse_uuid_t request_id;
    uint64_t     completed_generation;
    uint32_t     result_code;
    char         result_digest[64]; /* hex SHA-384 truncated, or empty */
} qihse_federation_request_result_t;

#define QIHSE_FEDERATION_REQ_PREFIX "fedreq:"

/* Record a completed request. Returns false if the request_id is already
 * present (caller should treat that as a replay and fetch the stored result
 * instead of re-executing). */
bool qihse_federation_request_record(void* store_void, void* user_void,
                                     const qihse_federation_request_result_t* result);
/* Look up a previously completed request. Returns false if not found. */
bool qihse_federation_request_lookup(void* store_void, void* user_void,
                                     const qihse_uuid_t* request_id,
                                     qihse_federation_request_result_t* out);
/* Is this request_id already completed? (idempotency check before execute) */
bool qihse_federation_request_seen(void* store_void, void* user_void,
                                   const qihse_uuid_t* request_id);

/* ── Event journal ──────────────────────────────────────────────────────── */

#define QIHSE_FEDERATION_JOURNAL_TOPIC "federation"
#define QIHSE_FEDERATION_EVENT_TYPE_MAX 63u

typedef struct {
    qihse_uuid_t event_id;        /* journal-assigned, monotonic-ish */
    qihse_federation_mutation_t mutation;
    char event_type[QIHSE_FEDERATION_EVENT_TYPE_MAX + 1u];
    char resource_id[64];
    uint64_t journal_offset;      /* assigned by the event stream */
    uint8_t  previous_hash[48];   /* SHA-384 chain */
    uint8_t  hash[48];            /* SHA-384 of (previous_hash || envelope || payload) */
} qihse_federation_event_t;

/* Opaque journal handle. Backed by qihse_event_stream. */
typedef struct qihse_federation_journal qihse_federation_journal_t;

qihse_federation_journal_t* qihse_federation_journal_open(const char* log_directory,
                                                         qihse_es_durability_t durability);
void qihse_federation_journal_destroy(qihse_federation_journal_t* journal);

/* Append a federation event. The envelope's hlc is ticked from the journal's
 * clock if it is zero; the event_id is generated if nil. The hash chain is
 * extended from the previous record. Returns the journal offset, or 0 on
 * failure. The payload is opaque bytes stored alongside the envelope. */
uint64_t qihse_federation_journal_append(qihse_federation_journal_t* journal,
                                        const qihse_federation_mutation_t* mutation,
                                        const char* event_type,
                                        const char* resource_id,
                                        const uint8_t* payload, size_t payload_len,
                                        qihse_federation_event_t* out_event);

/* Replay events from a cursor (0 = beginning). Returns the number of events
 * replayed. cb returns false to stop. */
typedef bool (*qihse_federation_journal_cb)(const qihse_federation_event_t* event,
                                           const uint8_t* payload, size_t payload_len,
                                           void* user_data);
uint64_t qihse_federation_journal_replay(qihse_federation_journal_t* journal,
                                        uint64_t from_cursor,
                                        qihse_federation_journal_cb cb,
                                        void* user_data);

/* Current journal length (offset of the next append). */
uint64_t qihse_federation_journal_length(qihse_federation_journal_t* journal);

/* ── Resumable watches (plan §13) ───────────────────────────────────────── */

typedef struct qihse_federation_watch qihse_federation_watch_t;

typedef struct {
    char prefix[64];        /* resource_id prefix filter; "" = all */
    uint64_t cursor;        /* resume point; 0 = from beginning */
    uint64_t last_ack;      /* highest acknowledged offset */
    size_t  backlog_limit;  /* max unacked events before backpressure */
} qihse_federation_watch_config_t;

qihse_federation_watch_t* qihse_federation_watch_open(qihse_federation_journal_t* journal,
                                                     const qihse_federation_watch_config_t* config);
void qihse_federation_watch_destroy(qihse_federation_watch_t* watch);

/* Fetch the next event matching the prefix filter. Returns false at
 * end-of-journal (caller may poll or sleep). Advances the internal cursor
 * but does NOT advance last_ack — call qihse_federation_watch_ack(). */
bool qihse_federation_watch_next(qihse_federation_watch_t* watch,
                                qihse_federation_event_t* out_event,
                                uint8_t** out_payload, size_t* out_payload_len);

/* Acknowledge events up to `offset`. At-least-once: unacked events are
 * re-delivered on resume. */
bool qihse_federation_watch_ack(qihse_federation_watch_t* watch, uint64_t offset);

/* Resume a watch from a previously saved cursor (e.g. after reconnect). */
bool qihse_federation_watch_resume(qihse_federation_watch_t* watch, uint64_t cursor);

/* Get the current cursor and last_ack for persistence. */
uint64_t qihse_federation_watch_cursor(const qihse_federation_watch_t* watch);
uint64_t qihse_federation_watch_last_ack(const qihse_federation_watch_t* watch);
/* Number of unacked events in the backlog. */
size_t qihse_federation_watch_backlog(const qihse_federation_watch_t* watch);

/* ────────────────────────────────────────────────────────────────────────
 * F3 — Replication correctness (plan §10, §11).
 *
 * Anti-entropy: each namespace produces a manifest of range digests over
 * sorted object IDs so peers can compare state without full dataset
 * transfer.  Divergent ranges are reconciled by exchanging missing events
 * from the F2 journal.
 *
 * Conflict handling: irreconcilable control-plane conflicts are never
 * silently overwritten.  Each namespace has a conflict policy; conflicts
 * are recorded as explicit conflict objects under "fedconf:" with both
 * versions, causal metadata, origin nodes, principal, reason, and
 * resolution status.
 * ──────────────────────────────────────────────────────────────────────── */

/* Conflict policies (plan §11). */
typedef enum {
    QIHSE_CONFLICT_LWW_HLC = 0,      /* last-writer-wins by HLC */
    QIHSE_CONFLICT_MERGE_SET,        /* set union merge */
    QIHSE_CONFLICT_COUNTER,          /* CRDT counter merge */
    QIHSE_CONFLICT_APPEND_ONLY,      /* append, never overwrite */
    QIHSE_CONFLICT_MANUAL,           /* require operator resolution */
    QIHSE_CONFLICT_REJECT,            /* reject the conflicting write */
    QIHSE_CONFLICT_CUSTOM             /* caller-defined merge function */
} qihse_conflict_policy_t;

const char* qihse_conflict_policy_name(qihse_conflict_policy_t policy);
bool qihse_conflict_policy_parse(const char* name, qihse_conflict_policy_t* out);

/* Conflict object (plan §11). Stored under "fedconf:<uuid>". */
typedef struct {
    qihse_uuid_t conflict_id;        /* assigned at creation */
    char namespace_name[QIHSE_FEDERATION_NS_NAME_MAX + 1u];
    char resource_id[64];
    qihse_conflict_policy_t policy;
    qihse_federation_mutation_t local_mutation;
    qihse_federation_mutation_t remote_mutation;
    uint8_t local_value[256];
    size_t local_value_len;
    uint8_t remote_value[256];
    size_t remote_value_len;
    char reason[128];
    bool resolved;
    qihse_uuid_t resolved_by;        /* nil if unresolved */
    uint64_t resolved_at_hlc_physical;
} qihse_federation_conflict_t;

#define QIHSE_FEDERATION_CONFLICT_PREFIX "fedconf:"

/* Record a conflict. Returns false if a conflict with the same id exists.
 * Every entry takes an explicit authenticated user (AGENTS.md invariant 1). */
bool qihse_federation_conflict_record(void* store_void, void* user_void,
                                     const qihse_federation_conflict_t* conflict);
/* Look up a conflict by id. */
bool qihse_federation_conflict_lookup(void* store_void, void* user_void,
                                      const qihse_uuid_t* conflict_id,
                                      qihse_federation_conflict_t* out);
/* Mark a conflict resolved. */
bool qihse_federation_conflict_resolve(void* store_void, void* user_void,
                                       const qihse_uuid_t* conflict_id,
                                       const qihse_uuid_t* resolver);
/* Iterate unresolved conflicts. cb returns false to stop. */
typedef bool (*qihse_federation_conflict_cb)(const qihse_federation_conflict_t* conflict,
                                            void* user_data);
void qihse_federation_conflict_foreach(void* store_void, void* user_void,
                                       qihse_federation_conflict_cb cb,
                                       void* user_data);

/* ── Namespace manifest (plan §10) ──────────────────────────────────────── */

/* A manifest entry covers a contiguous range of object IDs and carries a
 * SHA-384 digest of the sorted (id, generation, hlc) tuples in that range.
 * Peers compare manifests to identify divergent ranges without transferring
 * the full dataset. */
#define QIHSE_FEDERATION_MANIFEST_MAX_RANGES 64u

typedef struct {
    char range_start[64];   /* inclusive lower bound of object id range */
    char range_end[64];     /* exclusive upper bound; "" = end of keyspace */
    uint64_t object_count;
    uint8_t digest[48];     /* SHA-384 of sorted (id||generation||hlc) */
} qihse_federation_manifest_entry_t;

typedef struct {
    char namespace_name[QIHSE_FEDERATION_NS_NAME_MAX + 1u];
    uint64_t total_objects;
    uint64_t max_generation;
    qihse_hlc_t max_hlc;
    size_t entry_count;
    qihse_federation_manifest_entry_t entries[QIHSE_FEDERATION_MANIFEST_MAX_RANGES];
} qihse_federation_manifest_t;

/* Build a manifest for a namespace by scanning KV keys with the namespace
 * prefix. The scan takes an explicit authenticated user (AGENTS.md invariant 1). */
bool qihse_federation_manifest_build(void* store_void, void* user_void,
                                     const char* namespace_name,
                                     qihse_federation_manifest_t* out);

/* Compare two manifests. Returns the number of divergent ranges. Divergent
 * ranges are written to `out_divergent` (up to out_cap). A range is divergent
 * if the digests differ or the object counts differ. */
size_t qihse_federation_manifest_compare(const qihse_federation_manifest_t* local,
                                        const qihse_federation_manifest_t* remote,
                                        qihse_federation_manifest_entry_t* out_divergent,
                                        size_t out_cap);

/* ── Anti-entropy sync (plan §10) ───────────────────────────────────────── */

/* A sync plan identifies what a peer needs to send or receive. */
typedef enum {
    QIHSE_SYNC_NONE = 0,
    QIHSE_SYNC_FETCH,    /* local is missing objects remote has */
    QIHSE_SYNC_SEND,     /* remote is missing objects local has */
    QIHSE_SYNC_CONFLICT  /* both have objects but they diverge */
} qihse_sync_action_t;

typedef struct {
    char range_start[64];
    char range_end[64];
    qihse_sync_action_t action;
} qihse_federation_sync_range_t;

/* Produce a sync plan from a manifest comparison. Returns the number of
 * ranges needing action. */
size_t qihse_federation_sync_plan(const qihse_federation_manifest_t* local,
                                 const qihse_federation_manifest_t* remote,
                                 qihse_federation_sync_range_t* out_ranges,
                                 size_t out_cap);

/* ────────────────────────────────────────────────────────────────────────
 * F4 — Strong namespace (plan §7.2, §7.3, §14, §15, §16).
 *
 * Strong namespaces require:
 *   - native compare-and-swap (CAS) on generation-tagged objects;
 *   - monotonic, non-reusable fencing epochs;
 *   - a lease primitive with server-side expiry;
 *   - scoped replication groups (not a monolithic federation quorum).
 *
 * Consensus is NOT implemented as Raft in F4 — the plan explicitly forbids
 * labeling a component Raft without full Raft safety mechanics.  F4 provides
 * the data structures and local primitives; actual consensus is a future
 * stage.
 * ──────────────────────────────────────────────────────────────────────── */

/* ── Native CAS (plan §7.2) ─────────────────────────────────────────────── */

/* A CAS result tells the caller whether the swap succeeded, what the old
 * generation was, and what the new generation is. */
typedef struct {
    bool swapped;           /* true if the CAS succeeded */
    uint64_t old_generation;/* generation observed before the CAS */
    uint64_t new_generation;/* generation after the CAS (old+1 on success) */
} qihse_federation_cas_result_t;

/* Atomically compare-and-swap a generation-tagged object value.
 *
 * The object is stored under "fedobj:<namespace>:<resource_id>" and its
 * value format is "<generation>\t<value>".  If expected_generation matches
 * the stored generation, the value is replaced and the generation is
 * incremented.  Otherwise the swap fails and the current generation is
 * returned in old_generation.
 *
 * Every CAS takes an explicit authenticated user (AGENTS.md invariant 1).
 * The CAS is atomic under the federation CAS lock. */
bool qihse_federation_object_cas(void* store_void, void* user_void,
                                 const char* namespace_name,
                                 const char* resource_id,
                                 uint64_t expected_generation,
                                 const char* new_value,
                                 qihse_federation_cas_result_t* result);

/* Read a generation-tagged object. Returns false if not found. */
bool qihse_federation_object_get(void* store_void, void* user_void,
                                 const char* namespace_name,
                                 const char* resource_id,
                                 uint64_t* out_generation,
                                 char* out_value, size_t out_value_cap);

/* ── Fencing epochs (plan §7.3) ─────────────────────────────────────────── */

/* Fencing epochs are monotonic and non-reusable.  Each node maintains a
 * persistent counter under "fedepoch:<node_id>".  EPOCH.NEXT advances the
 * counter and returns the new value.  The counter never goes backwards. */
uint64_t qihse_federation_epoch_next(void* store_void, void* user_void,
                                      const qihse_uuid_t* node_id);
uint64_t qihse_federation_epoch_current(void* store_void, void* user_void,
                                        const qihse_uuid_t* node_id);

/* ── Lease primitive (plan §14) ─────────────────────────────────────────── */

typedef enum {
    QIHSE_LEASE_FREE = 0,
    QIHSE_LEASE_GRANTED,
    QIHSE_LEASE_EXPIRED,
    QIHSE_LEASE_RELEASED
} qihse_lease_state_t;

const char* qihse_lease_state_name(qihse_lease_state_t state);

typedef struct {
    qihse_uuid_t lease_id;
    qihse_uuid_t owner_node;
    char namespace_name[QIHSE_FEDERATION_NS_NAME_MAX + 1u];
    char resource_id[64];
    uint64_t fencing_epoch;
    uint64_t generation;
    qihse_lease_state_t state;
    uint64_t issued_hlc_physical;
    uint64_t expires_hlc_physical;  /* 0 = no expiry */
    qihse_uuid_t request_id;         /* for idempotency */
    qihse_uuid_t issuer;
} qihse_federation_lease_t;

#define QIHSE_FEDERATION_LEASE_PREFIX "fedlease:"
/* Request-id index for idempotent retries. */
#define QIHSE_FEDERATION_LEASE_REQUEST_PREFIX "fedleasereq:"
/* Resource index carrying the monotonic fencing high-water mark.  Persists
 * after release so a stale holder at a lower epoch can never re-acquire. */
#define QIHSE_FEDERATION_LEASE_RESOURCE_PREFIX "fedleaseres:"

/* Acquire a lease.  If a live lease exists for the resource, the acquire
 * fails unless the caller's fencing_epoch is strictly greater than the
 * existing lease's epoch.  Idempotent: a repeated request_id returns the
 * existing lease. */
bool qihse_federation_lease_acquire(void* store_void, void* user_void,
                                   const qihse_federation_lease_t* request,
                                   qihse_federation_lease_t* out);

/* Renew a lease.  The caller must hold the current lease. */
bool qihse_federation_lease_renew(void* store_void, void* user_void,
                                 const qihse_uuid_t* lease_id,
                                 uint64_t new_expires_hlc_physical,
                                 qihse_federation_lease_t* out);

/* Release a lease.  Idempotent: releasing an already-released lease succeeds. */
bool qihse_federation_lease_release(void* store_void, void* user_void,
                                   const qihse_uuid_t* lease_id);

/* Read a lease by id. */
bool qihse_federation_lease_read(void* store_void, void* user_void,
                                 const qihse_uuid_t* lease_id,
                                 qihse_federation_lease_t* out);

/* ── Replication groups (plan §15) ──────────────────────────────────────── */

#define QIHSE_FEDERATION_GROUP_MAX_MEMBERS 32u

typedef struct {
    qihse_uuid_t member_id;
    bool is_voter;
    bool is_witness;
} qihse_federation_group_member_t;

typedef struct {
    char group_id[64];
    size_t member_count;
    qihse_federation_group_member_t members[QIHSE_FEDERATION_GROUP_MAX_MEMBERS];
    uint64_t term;
    qihse_consistency_class_t consistency;
} qihse_federation_group_t;

#define QIHSE_FEDERATION_GROUP_PREFIX "fedgrp:"

/* Create a replication group. Returns false if the group already exists. */
bool qihse_federation_group_create(void* store_void, void* user_void,
                                   const qihse_federation_group_t* group);
/* Look up a group by id. */
bool qihse_federation_group_lookup(void* store_void, void* user_void,
                                   const char* group_id,
                                   qihse_federation_group_t* out);
/* Add or update a member. */
bool qihse_federation_group_add_member(void* store_void, void* user_void,
                                       const char* group_id,
                                       const qihse_federation_group_member_t* member);
/* Remove a member. */
bool qihse_federation_group_remove_member(void* store_void, void* user_void,
                                          const char* group_id,
                                          const qihse_uuid_t* member_id);
/* Advance the term. Returns the new term. */
uint64_t qihse_federation_group_advance_term(void* store_void, void* user_void,
                                              const char* group_id);
/* List all groups. cb returns false to stop. */
typedef bool (*qihse_federation_group_cb)(const qihse_federation_group_t* group,
                                         void* user_data);
void qihse_federation_group_foreach(void* store_void, void* user_void,
                                    qihse_federation_group_cb cb,
                                    void* user_data);

/* ────────────────────────────────────────────────────────────────────────
 * F5 — Trust plane (plan §17, §18, §19, §20).
 *
 * Node identity is a durable keypair, not an IP address, hostname, or
 * topology index.  Enrollment is an operator-approved flow:
 *
 *   generate node key -> operator approves -> federation CA signs
 *     -> node obtains scoped certificate -> QIHSE stores enrollment event
 *
 * Private keys are NEVER placed in QIHSE records.  Records carry a key
 * handle (a filesystem reference) and the public key only (plan §20).
 *
 * Gossip becomes a signed membership/health plane with a replay window.
 * A UDP datagram is never trusted merely because its source IP matches a
 * configured peer (plan §17).
 * ──────────────────────────────────────────────────────────────────────── */

/* ── Infrastructure authorization scopes (plan §19) ─────────────────────── */

typedef uint32_t qihse_infra_scope_t;

#define QIHSE_SCOPE_NONE              (0u)
#define QIHSE_SCOPE_FEDERATION_READ   (1u << 0)
#define QIHSE_SCOPE_FEDERATION_WRITE  (1u << 1)
#define QIHSE_SCOPE_NODE_ENROLL       (1u << 2)
#define QIHSE_SCOPE_NODE_REVOKE       (1u << 3)
#define QIHSE_SCOPE_POLICY_READ       (1u << 4)
#define QIHSE_SCOPE_POLICY_WRITE      (1u << 5)
#define QIHSE_SCOPE_LEASE_READ        (1u << 6)
#define QIHSE_SCOPE_LEASE_WRITE       (1u << 7)
#define QIHSE_SCOPE_SECURITY_ADMIN    (1u << 8)
#define QIHSE_SCOPE_AUDIT_READ        (1u << 9)
#define QIHSE_SCOPE_TELEMETRY_WRITE   (1u << 10)

/* Every scope that exists, for iteration/validation. */
#define QIHSE_SCOPE_ALL               (0x7FFu)

const char* qihse_infra_scope_name(qihse_infra_scope_t scope);
bool qihse_infra_scope_parse(const char* name, qihse_infra_scope_t* out);

/* Service identities are distinct from human principals.  KEYSTONE must
 * receive a read/index identity, never database-admin privileges. */
typedef enum {
    QIHSE_IDENTITY_OPERATOR = 0,
    QIHSE_IDENTITY_HYPERVISOR_CONTROLLER,
    QIHSE_IDENTITY_HOST_AGENT,
    QIHSE_IDENTITY_UI_API,
    QIHSE_IDENTITY_KEYSTONE_INDEXER,
    QIHSE_IDENTITY_BACKUP_AGENT
} qihse_service_identity_t;

const char* qihse_service_identity_name(qihse_service_identity_t kind);
bool qihse_service_identity_parse(const char* name, qihse_service_identity_t* out);

/* The default scope set granted to a service identity at enrollment.
 * KEYSTONE_INDEXER deliberately receives read/index scopes only. */
qihse_infra_scope_t qihse_service_identity_default_scopes(qihse_service_identity_t kind);

/* Check whether an authenticated principal holds the required scope.
 * The operator principal implicitly holds every scope. */
bool qihse_infra_scope_check(void* user_void, qihse_infra_scope_t required);

/* ── Node identity and trust (plan §18, §20) ────────────────────────────── */

typedef enum {
    QIHSE_TRUST_UNKNOWN = 0,
    QIHSE_TRUST_PENDING,    /* enrollment requested, awaiting operator approval */
    QIHSE_TRUST_APPROVED,   /* CA-signed and active */
    QIHSE_TRUST_REVOKED     /* permanently denied */
} qihse_trust_state_t;

const char* qihse_trust_state_name(qihse_trust_state_t state);
bool qihse_trust_state_parse(const char* name, qihse_trust_state_t* out);

#define QIHSE_FEDERATION_NODE_PUBKEY_BYTES 32u  /* Ed25519 raw public key */
#define QIHSE_FEDERATION_NODE_SIG_BYTES    64u  /* Ed25519 signature */
#define QIHSE_FEDERATION_NODE_FINGERPRINT_BYTES 48u /* SHA-384 */

typedef struct {
    qihse_uuid_t node_id;       /* durable, immutable identity */
    char hostname[128];         /* mutable attribute — display only */
    char boot_id[64];           /* boot/session identifier, changes per boot */
    char key_handle[160];       /* filesystem reference to the private key */
    uint8_t public_key[QIHSE_FEDERATION_NODE_PUBKEY_BYTES];
    uint8_t fingerprint[QIHSE_FEDERATION_NODE_FINGERPRINT_BYTES];
    qihse_trust_state_t trust;
    uint64_t enrollment_epoch;
    qihse_service_identity_t identity_kind;
    qihse_infra_scope_t scopes;
    uint32_t capabilities;
    uint64_t last_hlc_physical;
} qihse_federation_node_identity_t;

#define QIHSE_FEDERATION_NODE_PREFIX "fednode:"

/* Generate a durable node identity keypair.  The private key is written to
 * "<key_directory>/<node_id>.key" with 0600 permissions; only the public key
 * and a key handle are returned.  The private key never enters a QIHSE
 * record (plan §20).  key_directory must exist. */
bool qihse_federation_node_keygen(const char* key_directory,
                                  const qihse_uuid_t* node_id,
                                  uint8_t* out_public_key,
                                  char* out_key_handle, size_t out_key_handle_cap);

/* Compute the SHA-384 fingerprint of a raw public key. */
bool qihse_federation_node_fingerprint(const uint8_t* public_key,
                                       uint8_t* out_fingerprint);

/* Load a node private key from a handle.  Returns an opaque EVP_PKEY* which
 * the caller must release with qihse_federation_node_key_free(). */
void* qihse_federation_node_key_load(const char* key_handle);
void qihse_federation_node_key_free(void* pkey);

/* Enrollment: request records a PENDING identity; approve promotes it to
 * APPROVED and assigns the enrollment epoch; revoke marks it REVOKED and
 * makes it permanently unusable. */
bool qihse_federation_node_enroll_request(void* store_void, void* user_void,
                                         const qihse_federation_node_identity_t* identity);
bool qihse_federation_node_enroll_approve(void* store_void, void* user_void,
                                         const qihse_uuid_t* node_id,
                                         uint64_t enrollment_epoch);
bool qihse_federation_node_revoke(void* store_void, void* user_void,
                                  const qihse_uuid_t* node_id);
bool qihse_federation_node_lookup(void* store_void, void* user_void,
                                  const qihse_uuid_t* node_id,
                                  qihse_federation_node_identity_t* out);

typedef bool (*qihse_federation_node_cb)(const qihse_federation_node_identity_t* node,
                                        void* user_data);
void qihse_federation_node_foreach(void* store_void, void* user_void,
                                   qihse_federation_node_cb cb, void* user_data);

/* ── Signed gossip / membership plane (plan §17) ────────────────────────── */

#define QIHSE_FEDERATION_GOSSIP_MAGIC 0x51484753u /* "QHGS" */
#define QIHSE_FEDERATION_GOSSIP_VERSION 1u

typedef struct {
    uint32_t magic;
    uint16_t version;          /* protocol version */
    uint16_t feature_bitmap;   /* feature negotiation */
    qihse_uuid_t cluster_id;   /* cluster/federation UUID */
    qihse_uuid_t sender_node;  /* sender node UUID, not topology index */
    qihse_uuid_t boot_id;      /* boot/session UUID */
    uint64_t sequence;         /* monotonic per boot */
    qihse_hlc_t hlc;
    uint32_t capability_bitmap;
    uint32_t health_summary;
    uint8_t signature[QIHSE_FEDERATION_NODE_SIG_BYTES];
} qihse_federation_gossip_t;

/* The bytes covered by the signature: every field except the signature
 * itself.  Serialization is little-endian and length-prefixed so a peer
 * cannot reinterpret fields. */
bool qihse_federation_gossip_serialize(const qihse_federation_gossip_t* gossip,
                                       uint8_t* out, size_t out_cap, size_t* out_len);

/* Sign a gossip frame in place. pkey is an EVP_PKEY* from node_key_load(). */
bool qihse_federation_gossip_sign(void* pkey, qihse_federation_gossip_t* gossip);

/* Verify a gossip frame's signature against a raw Ed25519 public key. */
bool qihse_federation_gossip_verify(const uint8_t* public_key,
                                    const qihse_federation_gossip_t* gossip);

/* Replay-window state, one per (sender node, boot). */
typedef struct {
    qihse_uuid_t sender_node;
    qihse_uuid_t boot_id;
    uint64_t highest_sequence;
    uint64_t first_seen_hlc_physical;
} qihse_federation_replay_state_t;

#define QIHSE_FEDERATION_REPLAY_PREFIX "fedreplay:"

/* Accept a gossip frame: checks the magic/version, the sender's trust state,
 * the signature against the enrolled public key, and the replay window.
 * A frame is rejected if its sequence is not strictly greater than the
 * highest sequence already accepted from that (sender, boot).
 *
 * Replay state persists under "fedreplay:<node>:<boot>" so a restart does
 * not reopen the window.  Every call takes an explicit authenticated user
 * (AGENTS.md invariant 1). */
typedef enum {
    QIHSE_GOSSIP_ACCEPTED = 0,
    QIHSE_GOSSIP_REJECT_MALFORMED,
    QIHSE_GOSSIP_REJECT_VERSION,
    QIHSE_GOSSIP_REJECT_UNKNOWN_SENDER,
    QIHSE_GOSSIP_REJECT_UNTRUSTED_SENDER,
    QIHSE_GOSSIP_REJECT_BAD_SIGNATURE,
    QIHSE_GOSSIP_REJECT_REPLAY
} qihse_gossip_result_t;

const char* qihse_gossip_result_name(qihse_gossip_result_t result);

qihse_gossip_result_t qihse_federation_gossip_accept(void* store_void, void* user_void,
                                                    const qihse_federation_gossip_t* gossip);

/* Read the stored replay state for a (sender, boot). */
bool qihse_federation_replay_state_read(void* store_void, void* user_void,
                                        const qihse_uuid_t* sender_node,
                                        const qihse_uuid_t* boot_id,
                                        qihse_federation_replay_state_t* out);

#ifdef __cplusplus
}
#endif

#endif /* QIHSE_FEDERATION_H */
