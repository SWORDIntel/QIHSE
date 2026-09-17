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

#ifdef __cplusplus
}
#endif

#endif /* QIHSE_FEDERATION_H */
