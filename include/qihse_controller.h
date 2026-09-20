#ifndef QIHSE_CONTROLLER_H
#define QIHSE_CONTROLLER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * qihse_controller — the narrow, first-class controller client API.
 *
 * Design intent (CITADEL v3 §25): the hypervisor controller must not have to
 * pretend to be a Redis/PostgreSQL client.  This is a typed RESP client with
 * named wrappers for the federation surface a controller actually needs:
 * node inventory, object CAS, leases/epochs, event append + resumable
 * watches, conflict inspection, and status.
 *
 * Everything here is a thin wire mapping — the SERVER enforces every
 * invariant (authentication, system-domain gate, scopes, classification,
 * replay).  This client never bypasses authorization; it exists so callers
 * cannot smuggle semantics through a generic query language.  Watch ids are
 * session-scoped server state: a reconnect re-opens watches and resumes
 * from the last acked cursor.
 *
 * Wire bounds: replies are decoded with hard caps — bulk payloads up to
 * QIHSE_CTRL_MAX_BULK, arrays up to QIHSE_CTRL_MAX_ITEMS, nesting up to
 * QIHSE_CTRL_MAX_DEPTH — so a hostile or corrupt peer cannot turn the
 * client decoder into a memory sink.
 */

#define QIHSE_CTRL_MAX_BULK   (16u * 1024u * 1024u)
#define QIHSE_CTRL_MAX_ITEMS  (1u << 20)
#define QIHSE_CTRL_MAX_DEPTH  32u
#define QIHSE_CTRL_DEFAULT_TIMEOUT_MS 5000u

typedef struct qihse_controller qihse_controller_t;

typedef struct {
    const char* host;        /* required — e.g. "127.0.0.1" */
    uint16_t port;           /* required — the server's RESP port */
    const char* username;    /* NULL → connect unauthenticated */
    const char* password;    /* used only when username is set */
    uint32_t timeout_ms;     /* 0 → QIHSE_CTRL_DEFAULT_TIMEOUT_MS */
} qihse_controller_config_t;

typedef enum {
    QIHSE_CTRL_SIMPLE = 0,   /* +OK etc.         — text */
    QIHSE_CTRL_ERROR,        /* -ERR/-NOPERM…    — text */
    QIHSE_CTRL_INT,          /* :n               — integer */
    QIHSE_CTRL_BULK,         /* $len             — text/text_len */
    QIHSE_CTRL_NIL,          /* $-1 / *-1 */
    QIHSE_CTRL_ARRAY         /* *n               — items/count */
} qihse_ctrl_kind_t;

typedef struct qihse_ctrl_reply {
    qihse_ctrl_kind_t kind;
    char* text;                        /* SIMPLE/ERROR/BULK (owned; use text_len) */
    size_t text_len;
    int64_t integer;                   /* INT */
    struct qihse_ctrl_reply* items;    /* ARRAY (owned) */
    size_t count;
} qihse_ctrl_reply_t;

/* Connect and, when username is set, authenticate.  Returns NULL on failure
 * (no server, refused credentials) — the caller distinguishes "no reply"
 * from "-ERR" by inspecting the returned reply kind. */
qihse_controller_t* qihse_controller_connect(const qihse_controller_config_t* config);
void qihse_controller_destroy(qihse_controller_t* ctrl);
bool qihse_controller_connected(const qihse_controller_t* ctrl);

/* Generic escape hatch — sends an arbitrary command.  `lens` may be NULL
 * (args measured with strlen).  Returns NULL on transport failure, never
 * on a -ERR reply: check qihse_ctrl_reply_text() for the error text. */
qihse_ctrl_reply_t* qihse_ctrl_callv(qihse_controller_t* ctrl,
                                    size_t argc, const char* const argv[],
                                    const size_t* lens);
qihse_ctrl_reply_t* qihse_ctrl_call(qihse_controller_t* ctrl,
                                    size_t argc, const char* const argv[]);
void qihse_ctrl_reply_free(qihse_ctrl_reply_t* reply);

/* Reply helpers. */
bool qihse_ctrl_reply_ok(const qihse_ctrl_reply_t* reply);            /* +OK */
bool qihse_ctrl_reply_int(const qihse_ctrl_reply_t* reply, int64_t* out);
const char* qihse_ctrl_reply_text(const qihse_ctrl_reply_t* reply);   /* SIMPLE/BULK/ERROR, else NULL */

/* ── §25: Node ──────────────────────────────────────────────────────── */

/* Node.List → array of triples [node_uuid, trust_state, identity_kind]. */
qihse_ctrl_reply_t* qihse_ctrl_node_list(qihse_controller_t* ctrl);
/* Node.Get → array [hostname, trust, kind, scopes, enroll_epoch,
 * capabilities, fingerprint_hex, key_handle, sig_alg, pubkey_len]. */
qihse_ctrl_reply_t* qihse_ctrl_node_get(qihse_controller_t* ctrl, const char* node_uuid);
/* Node.Register → enroll a node: generates its keypair in the server's
 * configured key directory and returns the new node UUID (bulk). */
qihse_ctrl_reply_t* qihse_ctrl_node_enroll(qihse_controller_t* ctrl,
                                          const char* identity_kind,
                                          const char* hostname,
                                          const char* boot_id);
/* Node.Approve / Revoke → +OK; approve takes an optional enrollment epoch
 * (0 = server assigns). */
qihse_ctrl_reply_t* qihse_ctrl_node_approve(qihse_controller_t* ctrl,
                                            const char* node_uuid, uint64_t enrollment_epoch);
qihse_ctrl_reply_t* qihse_ctrl_node_revoke(qihse_controller_t* ctrl, const char* node_uuid);
/* Trust.Set → +OK; result is the verification verdict ("attested", …).
 * Trust.States → array of state names.  Trust.Admission → the admission
 * verdict array for a node. */
qihse_ctrl_reply_t* qihse_ctrl_trust_set(qihse_controller_t* ctrl,
                                         const char* node_uuid,
                                         const char* trust_state,
                                         const char* result);
qihse_ctrl_reply_t* qihse_ctrl_trust_states(qihse_controller_t* ctrl);
qihse_ctrl_reply_t* qihse_ctrl_trust_admission(qihse_controller_t* ctrl, const char* node_uuid);

/* ── §25: Object / desired-vs-observed ──────────────────────────────── */

/* Object.Get → array [generation, value].  Object.CAS → :1 on swap, :0 on
 * generation mismatch; expected_generation 0 = create-only.  The
 * desired/observed split is keyed by convention: <id>/desired and
 * <id>/observed/<node> inside a caller-chosen namespace. */
qihse_ctrl_reply_t* qihse_ctrl_object_get(qihse_controller_t* ctrl,
                                         const char* ns, const char* resource_id);
qihse_ctrl_reply_t* qihse_ctrl_object_cas(qihse_controller_t* ctrl,
                                         const char* ns, const char* resource_id,
                                         const char* value, uint64_t expected_generation);

/* ── §25: Lease / epoch ─────────────────────────────────────────────── */

/* Lease.Acquire → bulk lease UUID string.  fencing_epoch is the epoch the
 * caller already advanced to (EPOCH.NEXT); expires_ms 0 = server default.
 * Lease.Read → array [resource_id, state, fencing_epoch, generation,
 * expires_hlc_physical].  Renew/Release → +OK. */
qihse_ctrl_reply_t* qihse_ctrl_lease_acquire(qihse_controller_t* ctrl,
                                            const char* ns, const char* resource_id,
                                            uint64_t fencing_epoch, uint64_t expires_ms);
qihse_ctrl_reply_t* qihse_ctrl_lease_read(qihse_controller_t* ctrl, const char* lease_id);
qihse_ctrl_reply_t* qihse_ctrl_lease_renew(qihse_controller_t* ctrl,
                                          const char* lease_id, uint64_t expires_ms);
qihse_ctrl_reply_t* qihse_ctrl_lease_release(qihse_controller_t* ctrl, const char* lease_id);

/* Epoch.Next → :new fencing epoch.  Epoch.Current → :current. */
qihse_ctrl_reply_t* qihse_ctrl_epoch_next(qihse_controller_t* ctrl);
qihse_ctrl_reply_t* qihse_ctrl_epoch_current(qihse_controller_t* ctrl);

/* ── §25: Event journal + resumable watches ─────────────────────────── */

/* Event.Append → :journal offset (the resumable cursor).  payload may be
 * NULL/0 for an empty payload; it is transmitted byte-exact. */
qihse_ctrl_reply_t* qihse_ctrl_event_append(qihse_controller_t* ctrl,
                                            const char* event_type,
                                            const char* resource_id,
                                            const void* payload, size_t payload_len);
/* Event.Replay → flat array of triples [offset, event_type, resource_id]
 * starting at from_cursor (0 = journal start). */
qihse_ctrl_reply_t* qihse_ctrl_event_replay(qihse_controller_t* ctrl, uint64_t from_cursor);
/* Watch.Open → :watch id (session slot).  prefix is a RESOURCE_ID prefix
 * filter (e.g. "vm-" receives only events for resources under it);
 * NULL = all events. */
qihse_ctrl_reply_t* qihse_ctrl_watch_open(qihse_controller_t* ctrl, const char* prefix);
/* Watch.Next → :0 at journal end, or array [offset, event_type,
 * resource_id, payload]. */
qihse_ctrl_reply_t* qihse_ctrl_watch_next(qihse_controller_t* ctrl, uint32_t watch_id);
/* Watch.Ack → +OK (drops the backlog up to offset).  Watch.Resume → +OK
 * (rewind to a cursor; e.g. after reading, replay for a second pass). */
qihse_ctrl_reply_t* qihse_ctrl_watch_ack(qihse_controller_t* ctrl,
                                        uint32_t watch_id, uint64_t offset);
qihse_ctrl_reply_t* qihse_ctrl_watch_resume(qihse_controller_t* ctrl,
                                            uint32_t watch_id, uint64_t cursor);

/* ── §25: Conflicts, status, reconciliation ─────────────────────────── */

/* Conflict.List → flat array of pairs [conflict_uuid, namespace]. */
qihse_ctrl_reply_t* qihse_ctrl_conflict_list(qihse_controller_t* ctrl);
/* Conflict.Resolve → +OK; resolver_uuid is an enrolled node id. */
qihse_ctrl_reply_t* qihse_ctrl_conflict_resolve(qihse_controller_t* ctrl,
                                                 const char* conflict_uuid,
                                                 const char* resolver_uuid);
/* Federation.Status → bulk status object text (§5 status shape). */
qihse_ctrl_reply_t* qihse_ctrl_federation_status(qihse_controller_t* ctrl);
/* Rejoin.Status → array [step, events_transferred, conflicts_applied,
 * may_publish_ownership, last_error]. */
qihse_ctrl_reply_t* qihse_ctrl_rejoin_status(qihse_controller_t* ctrl, const char* node_uuid);
/* Metrics → bulk rendered metrics text; prefix NULL = all federation
 * metrics (label-bounded per §41). */
qihse_ctrl_reply_t* qihse_ctrl_metrics(qihse_controller_t* ctrl, const char* prefix);

/* ── Namespaces and replication groups (§15) ────────────────────────── */

/* NS.Register → +OK; class is a consistency class name ("LOCAL",
 * "EVENTUAL", "CAUSAL", "QUORUM", "LINEARIZABLE" — case-sensitive);
 * authority_node_uuid NULL = this node. */
qihse_ctrl_reply_t* qihse_ctrl_ns_register(qihse_controller_t* ctrl,
                                          const char* name, const char* consistency,
                                          const char* authority_node_uuid);
qihse_ctrl_reply_t* qihse_ctrl_ns_unregister(qihse_controller_t* ctrl, const char* name);
qihse_ctrl_reply_t* qihse_ctrl_ns_list(qihse_controller_t* ctrl);
/* NS.Writable → :1/:0 — can this principal write the namespace now? */
qihse_ctrl_reply_t* qihse_ctrl_ns_writable(qihse_controller_t* ctrl, const char* name);
/* Manifest → the namespace anti-entropy manifest (range digests). */
qihse_ctrl_reply_t* qihse_ctrl_manifest(qihse_controller_t* ctrl, const char* ns);

/* Group.Create → +OK; consistency NULL = "QUORUM" (names are the
 * case-sensitive class names above).
 * Group.Add → +OK; voter/witness are bools.  Group.Remove → +OK.
 * Group.Show → the group record; Group.List → group ids;
 * Group.Advance → :new term. */
qihse_ctrl_reply_t* qihse_ctrl_group_create(qihse_controller_t* ctrl,
                                            const char* group_id, const char* consistency);
qihse_ctrl_reply_t* qihse_ctrl_group_add(qihse_controller_t* ctrl,
                                        const char* group_id, const char* member_uuid,
                                        bool voter, bool witness);
qihse_ctrl_reply_t* qihse_ctrl_group_remove(qihse_controller_t* ctrl,
                                            const char* group_id, const char* member_uuid);
qihse_ctrl_reply_t* qihse_ctrl_group_show(qihse_controller_t* ctrl, const char* group_id);
qihse_ctrl_reply_t* qihse_ctrl_group_list(qihse_controller_t* ctrl);
qihse_ctrl_reply_t* qihse_ctrl_group_advance(qihse_controller_t* ctrl, const char* group_id);

/* ── Build coordination (§28–§30 — STATE ONLY; QIHSE never executes) ── */

/* Build.JobCreate → the new build id (bulk).  Transition → +OK;
 * request_id is the idempotency key. */
qihse_ctrl_reply_t* qihse_ctrl_build_job_create(qihse_controller_t* ctrl,
                                                 const char* package, const char* revision,
                                                 const char* profile, const char* toolchain);
qihse_ctrl_reply_t* qihse_ctrl_build_job_transition(qihse_controller_t* ctrl,
                                                     const char* build_id, const char* state,
                                                     const char* request_id, const char* reason);
qihse_ctrl_reply_t* qihse_ctrl_build_job_get(qihse_controller_t* ctrl, const char* build_id);
qihse_ctrl_reply_t* qihse_ctrl_build_job_list(qihse_controller_t* ctrl);
qihse_ctrl_reply_t* qihse_ctrl_build_states(qihse_controller_t* ctrl);
/* Build.WorkerPublish → +OK: the worker's capability snapshot. */
qihse_ctrl_reply_t* qihse_ctrl_build_worker_publish(qihse_controller_t* ctrl,
                                                    const char* node_uuid,
                                                    uint32_t cores_available,
                                                    uint32_t ram_available_gb,
                                                    uint32_t queue_depth);
qihse_ctrl_reply_t* qihse_ctrl_build_worker_get(qihse_controller_t* ctrl, const char* node_uuid);

/* ── Supply chain (§31–§34) ─────────────────────────────────────────── */

/* Package registry (§27): PKG.SET → +OK; mode is one of the registry
 * modes; PKG.GET → the package record; PKG.MODES → array of mode names. */
qihse_ctrl_reply_t* qihse_ctrl_pkg_set(qihse_controller_t* ctrl,
                                        const char* package, const char* mode,
                                        const char* reason);
qihse_ctrl_reply_t* qihse_ctrl_pkg_get(qihse_controller_t* ctrl, const char* package);
qihse_ctrl_reply_t* qihse_ctrl_pkg_modes(qihse_controller_t* ctrl);

/* SBOM/attestation records: SBOM → +OK; SBOM.GET → the record. */
qihse_ctrl_reply_t* qihse_ctrl_supply_sbom(qihse_controller_t* ctrl,
                                            const char* artifact_digest,
                                            const char* sbom_digest,
                                            const char* signing_identity,
                                            const char* format);
qihse_ctrl_reply_t* qihse_ctrl_supply_sbom_get(qihse_controller_t* ctrl, const char* sbom_digest);
/* Repository snapshots: SNAPSHOT → +OK; SNAPSHOT.LIST → array. */
qihse_ctrl_reply_t* qihse_ctrl_supply_snapshot(qihse_controller_t* ctrl,
                                                const char* repository, const char* digest,
                                                const char* release, uint64_t package_count);
qihse_ctrl_reply_t* qihse_ctrl_supply_snapshot_list(qihse_controller_t* ctrl,
                                                     const char* repository);
/* Vulnerability observations (§33): VULN → +OK; VULN.COUNT → :n. */
qihse_ctrl_reply_t* qihse_ctrl_supply_vuln(qihse_controller_t* ctrl,
                                            const char* component_digest,
                                            const char* advisory, const char* severity,
                                            const char* status);
qihse_ctrl_reply_t* qihse_ctrl_supply_vuln_count(qihse_controller_t* ctrl,
                                                  const char* component_digest);
/* Provenance graph (§31): PROV.NODE/EDGE → +OK; SHOW/TRACE/IMPACT →
 * records/arrays.  depth 0 = default bound. */
qihse_ctrl_reply_t* qihse_ctrl_prov_node(qihse_controller_t* ctrl,
                                          const char* entity, const char* id,
                                          const char* label);
qihse_ctrl_reply_t* qihse_ctrl_prov_edge(qihse_controller_t* ctrl,
                                          const char* from_ref, const char* edge,
                                          const char* to_ref);
qihse_ctrl_reply_t* qihse_ctrl_prov_show(qihse_controller_t* ctrl,
                                          const char* entity, const char* id);
qihse_ctrl_reply_t* qihse_ctrl_prov_trace(qihse_controller_t* ctrl,
                                           const char* entity, const char* id,
                                           bool forward, uint32_t depth);
qihse_ctrl_reply_t* qihse_ctrl_prov_impact(qihse_controller_t* ctrl,
                                            const char* entity, const char* id,
                                            const char* want_entity, uint32_t depth);

/* ── Operational admin (§23/§24/§36–§39) ────────────────────────────── */

/* Snapshot.Create → the snapshot id; kind is "local" or "coordinated".
 * key_id NULL = unencrypted manifest.  Show/Verify → the record/verdict. */
qihse_ctrl_reply_t* qihse_ctrl_snapshot_create(qihse_controller_t* ctrl,
                                                const char* kind, uint64_t max_generation,
                                                uint64_t wal_offset, const char* key_id);
qihse_ctrl_reply_t* qihse_ctrl_snapshot_show(qihse_controller_t* ctrl, const char* snapshot_id);
qihse_ctrl_reply_t* qihse_ctrl_snapshot_verify(qihse_controller_t* ctrl, const char* snapshot_id);

/* Schema evolution: status of a schema version, compat check, migrate
 * (resumable bool), and progress record. */
qihse_ctrl_reply_t* qihse_ctrl_schema_status(qihse_controller_t* ctrl,
                                              const char* schema_id, const char* version);
qihse_ctrl_reply_t* qihse_ctrl_schema_check(qihse_controller_t* ctrl,
                                             const char* writer_version, const char* min_reader,
                                             const char* required_hex, const char* optional_hex);
qihse_ctrl_reply_t* qihse_ctrl_schema_migrate(qihse_controller_t* ctrl,
                                               const char* schema_id,
                                               const char* from_version, const char* to_version,
                                               bool resumable);
qihse_ctrl_reply_t* qihse_ctrl_schema_progress(qihse_controller_t* ctrl,
                                                const char* schema_id, const char* version,
                                                uint64_t completed, uint64_t total);

/* Security posture (§39): AUDIT → the runtime self-audit report;
 * OBSERVE → the node's runtime observation (uid/gid/caps/core-dump/
 * seccomp/listeners); IFACES → the kernel-interface classification;
 * PROFILE.GET/SET and NET.GET → declared runtime/network profiles. */
qihse_ctrl_reply_t* qihse_ctrl_security_audit(qihse_controller_t* ctrl,
                                               const char* service, const char* version);
qihse_ctrl_reply_t* qihse_ctrl_security_observe(qihse_controller_t* ctrl);
qihse_ctrl_reply_t* qihse_ctrl_security_ifaces(qihse_controller_t* ctrl);
qihse_ctrl_reply_t* qihse_ctrl_security_profile_get(qihse_controller_t* ctrl,
                                                     const char* service, const char* version);
qihse_ctrl_reply_t* qihse_ctrl_security_net_get(qihse_controller_t* ctrl,
                                                 const char* service, const char* version);

#ifdef __cplusplus
}
#endif

#endif /* QIHSE_CONTROLLER_H */
