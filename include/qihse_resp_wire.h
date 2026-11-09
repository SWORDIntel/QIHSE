#ifndef QIHSE_RESP_WIRE_H
#define QIHSE_RESP_WIRE_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "qihse_kv_store.h"
#include "qihse_vector_db.h"
#include "qihse_timeseries.h"
#include "qihse_column.h"
#include "qihse_cluster_slot.h"
#include "qihse_qkp.h"
#include "qihse_resp_cluster.h"
#include "qihse_cluster_bus.h"
#include "qihse_cluster_failover.h"
#include "qihse_cluster_ownership.h"
#include "qihse_cluster_transfer.h"
#include "qihse_ct_target.h"
#include "qihse_cluster_scatter.h"
#include "qihse_system_guard.h"
#include "qihse_quota.h"
#include "qihse_blob.h"
#include "qihse_consensus_mesh.h"
#include "qihse_consensus_prefix_point_challenge.h"
#include "qihse_bundle.h"
#include "qihse_task_queue.h"
#include "qihse_task_worker.h"
#include "qihse_task_scheduler.h"
#include "qihse_cluster_maintenance.h"
#include "qihse_resp_fts_namespace.h"

typedef struct qihse_resp_server qihse_resp_server_t;
/* A receipt can only be produced by the pinned-QKP CT receipt verifier. The
 * type is opaque so callers cannot manufacture authenticated peer evidence. */
typedef struct qihse_cluster_ct_peer_receipt qihse_cluster_ct_peer_receipt_t;
typedef struct qihse_resp_ct_activation_request qihse_resp_ct_activation_request_t;
typedef struct qihse_resp_ct_begin_request qihse_resp_ct_begin_request_t;
typedef struct qihse_resp_ct_abort_request qihse_resp_ct_abort_request_t;
typedef struct qihse_cluster_ct_activation_receipt qihse_cluster_ct_activation_receipt_t;
typedef struct { const void* data; size_t len; } qihse_resp_ct_arg_t;
typedef struct { unsigned char* data; size_t len; } qihse_resp_ct_reply_t;
typedef bool (*qihse_resp_ct_activation_handler_fn)(void* context,
    const qihse_resp_ct_activation_request_t* request, char* err, size_t err_cap);
typedef bool (*qihse_resp_ct_begin_handler_fn)(void* context,
    const qihse_resp_ct_begin_request_t* request, uint64_t* out_target_cut,
    char* err, size_t err_cap);
typedef bool (*qihse_resp_ct_abort_handler_fn)(void* context,
    const qihse_resp_ct_abort_request_t* request, char* err, size_t err_cap);
bool qihse_resp_server_ct_activation_handler_set(qihse_resp_server_t* server,
    qihse_resp_ct_activation_handler_fn handler, void* context);
bool qihse_resp_server_ct_begin_handler_set(qihse_resp_server_t* server,
    qihse_resp_ct_begin_handler_fn handler, void* context);
bool qihse_resp_server_ct_abort_handler_set(qihse_resp_server_t* server,
    qihse_resp_ct_abort_handler_fn handler, void* context);
bool qihse_resp_ct_begin_request_fields(
    const qihse_resp_ct_begin_request_t* request,
    const char** transfer_id, const char** topology_source_id,
    const char** topology_target_id, const char** qkp_source_id,
    const char** qkp_target_id, const char** generation,
    uint16_t* first_slot, uint16_t* last_slot, uint64_t* source_lsn,
    uint64_t* config_epoch, unsigned char canonical_range_checksum[32],
    unsigned char image_sha256[32], uint64_t* total_bytes);
bool qihse_resp_ct_abort_request_fields(
    const qihse_resp_ct_abort_request_t* request,
    const char** transfer_id, const char** topology_source_id,
    const char** topology_target_id, const char** qkp_source_id,
    const char** qkp_target_id, const char** generation,
    uint16_t* first_slot, uint16_t* last_slot, uint64_t* source_lsn,
    uint64_t* config_epoch, unsigned char canonical_range_checksum[32]);
bool qihse_resp_ct_activation_request_fields(
    const qihse_resp_ct_activation_request_t* request,
    const char** transfer_id, const char** topology_source_id,
    const char** topology_target_id, const char** qkp_source_id,
    const char** qkp_target_id, const char** generation,
    uint16_t* first_slot, uint16_t* last_slot, uint64_t* source_lsn,
    uint64_t* config_epoch, uint64_t* target_lsn, unsigned char checksum[32]);
/* Principal pointers are set only by the QKP-authenticated request parser and
 * remain valid for the duration of the synchronous handler callback. */
qihse_user_t* qihse_resp_ct_begin_request_principal(
    const qihse_resp_ct_begin_request_t* request);
qihse_user_t* qihse_resp_ct_abort_request_principal(
    const qihse_resp_ct_abort_request_t* request);
qihse_user_t* qihse_resp_ct_activation_request_principal(
    const qihse_resp_ct_activation_request_t* request);

/* One authenticated command to the already configured replication peer. The
 * caller cannot supply a host, key, or identity. Reply is the exact RESP wire
 * value (without QKP framing) and must be freed with the paired function. */
bool qihse_resp_ct_peer_command(qihse_resp_server_t* server,
    const qihse_resp_ct_arg_t* args, size_t argc, qihse_resp_ct_reply_t* out);
bool qihse_resp_ct_peer_command_to(qihse_resp_server_t* server,
    uint16_t target_topology_index, const char* expected_qkp_node_id,
    const qihse_resp_ct_arg_t* args, size_t argc, qihse_resp_ct_reply_t* out);
void qihse_resp_ct_reply_free(qihse_resp_ct_reply_t* reply);
void qihse_resp_server_ct_control_only_set(qihse_resp_server_t* server,
                                           bool control_only);
bool qihse_resp_server_ct_ownership_set(qihse_resp_server_t* server,
    qihse_cluster_ownership_context_t* context);
bool qihse_resp_server_ct_target_set(qihse_resp_server_t* server,
    qihse_ct_target_t* target);
bool qihse_resp_server_ct_is_successor(qihse_resp_server_t* server);
/* Trusted ownership recovery and daemon lifecycle adapters, using the explicit
 * authenticated control principal already bound to the server. */
bool qihse_resp_server_ct_authorize_promotion(void* context,
    const char* source_id, const char* target_id, const char* generation, uint64_t cursor);
bool qihse_resp_server_ct_auto_resume(qihse_resp_server_t* server,
    qihse_user_t* principal);

/* Explicit fresh-spare bootstrap: accept a generation only from its already
 * pinned source; refuses replacing any persisted receiver generation. */
bool qihse_resp_server_ct_bind_generation(qihse_resp_server_t* server,
    qihse_user_t* principal, const char generation[33]);
bool qihse_resp_ct_peer_activation_receipt_query(qihse_resp_server_t* server,
    const char* transfer_id, const char* topology_source_id,
    const char* topology_target_id, const char* qkp_source_id,
    const char* qkp_target_id, const char* generation,
    uint16_t first_slot, uint16_t last_slot, uint64_t source_lsn,
    uint64_t config_epoch, uint64_t target_lsn, const unsigned char checksum[32],
    qihse_cluster_ct_activation_receipt_t** out_receipt);
bool qihse_resp_ct_peer_activation_receipt_query_to(qihse_resp_server_t* server,
    uint16_t target_topology_index, const char* target_qkp_id,
    const char* transfer_id, const char* topology_source_id,
    const char* topology_target_id, const char* qkp_source_id,
    const char* qkp_target_id, const char* generation,
    uint16_t first_slot, uint16_t last_slot, uint64_t source_lsn,
    uint64_t config_epoch, uint64_t target_lsn, const unsigned char checksum[32],
    qihse_cluster_ct_activation_receipt_t** out_receipt);
bool qihse_resp_ct_activation_receipt_query_to(qihse_resp_server_t* server,
    uint16_t target_topology_index, const char* target_qkp_id,
    const char* transfer_id, const char* topology_source_id,
    const char* topology_target_id, const char* qkp_source_id,
    const char* qkp_target_id, const char* generation,
    uint16_t first_slot, uint16_t last_slot, uint64_t source_lsn,
    uint64_t config_epoch, uint64_t target_lsn, const unsigned char checksum[32],
    qihse_cluster_ct_activation_receipt_t** out_receipt);
bool qihse_resp_ct_activation_receipt_validate(
    const qihse_cluster_ct_activation_receipt_t* receipt,
    const char* transfer_id, const char* topology_source_id,
    const char* topology_target_id, const char* qkp_source_id,
    const char* qkp_target_id, const char* generation,
    uint16_t first_slot, uint16_t last_slot, uint64_t source_lsn,
    uint64_t config_epoch, uint64_t* out_target_lsn, unsigned char out_checksum[32]);
void qihse_resp_ct_activation_receipt_free(
    qihse_cluster_ct_activation_receipt_t* receipt);
typedef struct qihse_resp_fts_namespace_registry qihse_resp_fts_namespace_registry_t;
typedef struct {
    uint32_t tenant_id;
    const char* canonical_name;
    const char* allowlisted_key_glob;
} qihse_resp_fts_namespace_config_t;
/* Forward-declared: the full FTS type lives in qihse_fts.h and is only
 * dereferenced by the fusion path in the engine. */
typedef struct qihse_fts_index qihse_fts_index_t;

/* Query the server's configured CT peer only; there is intentionally no host,
 * key, or fingerprint argument. Both topology IDs and QKP transport IDs are
 * explicit because the namespaces are distinct. */
bool qihse_resp_ct_peer_receipt_query(qihse_resp_server_t* server,
    const char* transfer_id, const char* topology_source_id,
    const char* topology_target_id, const char* qkp_source_id,
    const char* qkp_target_id, const char* generation,
    uint16_t first_slot, uint16_t last_slot, uint64_t source_lsn,
    uint64_t config_epoch, qihse_cluster_ct_peer_receipt_t** out_receipt);
bool qihse_resp_ct_peer_receipt_query_to(qihse_resp_server_t* server,
    uint16_t target_topology_index, const char* target_qkp_id,
    const char* transfer_id, const char* topology_source_id,
    const char* topology_target_id, const char* qkp_source_id,
    const char* qkp_target_id, const char* generation,
    uint16_t first_slot, uint16_t last_slot, uint64_t source_lsn,
    uint64_t config_epoch, qihse_cluster_ct_peer_receipt_t** out_receipt);
bool qihse_resp_ct_peer_prepared_receipt_query_to(qihse_resp_server_t* server,
    uint16_t source_topology_index, const char* source_qkp_id,
    const char* transfer_id, const char* topology_source_id,
    const char* topology_target_id, const char* qkp_source_id,
    const char* qkp_target_id, const char* generation,
    uint16_t first_slot, uint16_t last_slot, uint64_t source_lsn,
    uint64_t config_epoch, const unsigned char canonical_checksum[32],
    qihse_cluster_ct_peer_receipt_t** out_receipt);
bool qihse_resp_ct_peer_aborted_receipt_query_to(qihse_resp_server_t* server,
    uint16_t source_topology_index, const char* source_qkp_id,
    const char* transfer_id, const char* topology_source_id,
    const char* topology_target_id, const char* qkp_source_id,
    const char* qkp_target_id, const char* generation,
    uint16_t first_slot, uint16_t last_slot, uint64_t source_lsn,
    uint64_t config_epoch, const unsigned char canonical_checksum[32],
    qihse_cluster_ct_peer_receipt_t** out_receipt);
bool qihse_resp_ct_source_receipt_validate(
    const qihse_cluster_ct_peer_receipt_t* receipt, const char* phase,
    const char* transfer_id, const char* topology_source_id,
    const char* topology_target_id, const char* qkp_source_id,
    const char* qkp_target_id, const char* generation,
    uint16_t first_slot, uint16_t last_slot, uint64_t source_lsn,
    uint64_t config_epoch, const unsigned char canonical_checksum[32]);
bool qihse_resp_ct_peer_receipt_validate(
    const qihse_cluster_ct_peer_receipt_t* receipt,
    const char* transfer_id, const char* topology_source_id,
    const char* topology_target_id, const char* qkp_source_id,
    const char* qkp_target_id, const char* generation,
    uint16_t first_slot, uint16_t last_slot, uint64_t source_lsn,
    uint64_t config_epoch, uint64_t* out_target_lsn, unsigned char out_checksum[32]);
void qihse_resp_ct_peer_receipt_free(qihse_cluster_ct_peer_receipt_t* receipt);

typedef struct {
    qihse_kv_store_t* store;
    qihse_vector_db_t vdb;
    qihse_tsdb_t* tsdb;
    qihse_column_store_t* column_store;
    /* Optional system-domain full-text index for system-Operator FTS.BUILD,
     * FTS.SEARCH, SAVE/LOAD and VECHYBRID. Tenant-default indexes are created
     * independently by the server; registered APP scopes add another tenant-
     * bound subdivision. NULL disables only the system-domain projection. */
    qihse_fts_index_t* fts;
    /* Optional FTS artifact root. Legacy FTS.SAVE/LOAD use the system-domain
     * `fts-index.qfts` and `fts-index.keys`; APP artifacts use tenant/name-
     * derived paths under the same root. NULL or empty disables persistence
     * and autoload for both forms. Never taken from a request. */
    const char* fts_persist_directory;
    /* Principal the startup autoload runs as. NULL disables autoload even
     * when a directory is configured. It must be supplied explicitly: a
     * forgotten principal must not decay into a context-free read of a
     * classified projection (AGENTS.md invariant #1). */
    qihse_user_t* fts_autoload_principal;
    /* Explicit startup namespace mappings. Names/globs are copied and validated;
     * no namespace is inferred from a key prefix or application label. */
    const qihse_resp_fts_namespace_config_t* fts_namespaces;
    size_t fts_namespace_count;
    qihse_cluster_topology_t* topology;
    /* Optional borrowed cluster-wide maintenance admission gate. */
    qihse_cluster_maintenance_t* maintenance_gate;
    const char* bind_address;
    const char* advertise_address;
    const char* node_id;
    uint16_t port;
    uint16_t bus_port;
    uint16_t local_node_index;
    size_t max_clients;
    size_t max_request_bytes;
    bool auth_required;
    /* Optional least-privilege AIMEM service identity.  UINT32_MAX disables
     * the restriction.  Once this principal authenticates, the RESP
     * dispatcher admits AIMEM commands only (plus the pre-auth/control
     * AUTH/HELLO/PING/QUIT control commands). */
    uint32_t aimem_service_user_id;
    bool require_full_coverage;
    bool pin_workers;
    bool strict_hardware_affinity;
    int numa_node_id;
    /* Phase 3: cluster bus + failover + guard throttling */
    bool enable_bus;
    bool enable_failover;
    bool enable_guard_throttle;
    const char* xdp_interface;       /* NULL = standard UDP bus */
    /* Veiled bus framing key (cluster operator password). Non-NULL and
     * non-empty wraps every bus datagram as [nonce 8B][pad_len u8][padding]
     * [HMAC-SHA384-keystream-XORed frame] — transport obfuscation only; bus
     * auth is separate. NULL/empty = plain frames. */
    const char* veil_key;
    /* Signed ops frames (hybrid bus upgrade): signing key (borrowed) and
     * hardened receive policy — copied onto the cluster bus at create. */
    void* federation_sign_key;
    bool require_signed_ops;
    /* R4c QKP1 (CNSA 2.0 RESP handshake): zero-initialized = disabled
     * (opportunistic cleartext). Set by the daemon from --pqc-* flags. */
    qihse_qkp_config_t pqc;
    /* Locally authoritative identity used by the pinned QKP replication
     * peer. The caller owns this principal and must recreate the same user
     * and tenant ids on restart. It must be an active system-domain
     * non-Operator. A matching server-side QKP handshake maps directly to
     * this identity; no password AUTH is performed. NULL disables the
     * passwordless replication data plane. */
    qihse_user_t* replication_service_principal;
    /* CT1/CT2 certified writer protocol. A non-empty role requires an exact
     * QKP peer pin, an explicit generation token, bounded retained log, and
     * a finite ACK deadline. These fields are copied at create time; the
     * caller retains ownership of all strings and the principal. */
    const char* ct_role; /* "primary" or "successor"; NULL disables CT */
    const char* ct_auto_successor_id; /* opt-in spare topology ID; requires consensus mesh */
    const char* ct_peer_host;
    uint16_t ct_peer_port;
    const char* ct_generation_hex; /* exactly 32 lowercase hex characters */
    uint64_t ct_log_limit_bytes;
    uint32_t ct_ack_timeout_ms;
    const unsigned char* ct_owner_token; /* primary capability; never on RESP */
    qihse_user_t* ct_control_principal; /* active startup Operator, borrowed */
    qihse_cluster_topology_qkp_id_fn ct_topology_qkp_id;
    void* ct_topology_qkp_id_context;
    /* R4 replicated namespaces: keys matching one of these globs are
     * SOVEREIGN-LOCAL (never MOVED/CLUSTERDOWN-routed) and are expected to
     * exist on every node. Boot-time source of truth; REPL.MARK adds more
     * at runtime (in-memory only, lost on restart). */
    const char* const* replicate_globs;
    size_t replicate_glob_count;
    uint64_t guard_window_ms;        /* 0 = default 1000ms */
    double guard_saturation_fraction; /* 0 = default 0.8 */
    /* Phase 4: scatter-gather engine */
    bool enable_scatter;
    uint32_t scatter_timeout_ms;     /* 0 = default 2000ms */
    /* Task Queue Engine & Scheduler */
    bool enable_task_queue;
    bool enable_task_workers;
    uint32_t task_worker_count;
    const char* task_python_binary;
    bool enable_task_scheduler;
    qihse_task_queue_t* task_queue;
    qihse_task_worker_pool_t* task_workers;
    qihse_task_scheduler_t* task_scheduler;
    /* Pub/Sub: optional durable event-stream log directory for PUBLISH; when
     * NULL the broker is in-memory only. Channels are tagged with
     * (channel_classification, channel_sci) and require caller clearance. */
    const char* pubsub_log_directory;
    uint16_t channel_classification;
    uint16_t channel_sci;
    /* F2: federation event journal log directory. NULL = journal disabled. */
    const char* federation_journal_directory;
    qihse_es_durability_t federation_journal_durability;
    /* F5: directory holding node identity private keys. NULL = node
     * enrollment via RESP is disabled (fails closed).  Private keys are
     * written here with 0600 permissions and never enter a QIHSE record. */
    const char* federation_key_directory;
    /* UWP bridge: allow qihse_resp_server_execute() (QIHSE_UWP_TARGET_RESP)
     * to run commands through this server's dispatch path. Default true. */
    bool enable_uwp_bridge;
    /* Remote fabric job dispatch. When enabled, this server starts a dispatch
     * listener so peers can submit jobs to it. OFF by default: a listener is
     * network-facing and must be opted into. `fabric_dispatch_bind` is
     * REQUIRED when enabled (a wildcard bind is refused by the listener), and
     * port 0 means ephemeral — read the real port back with
     * qihse_resp_server_fabric_port(). */
    bool enable_fabric_dispatch;
    const char* fabric_dispatch_bind;
    uint16_t fabric_dispatch_port;
    const char* fabric_dispatch_ca_cert_path;
    const char* fabric_dispatch_node_cert_path;
    const char* fabric_dispatch_node_id;
    /* Per-tenant quota policies (QIHSE_QUOTA_*). Caller-owned; may be NULL
     * (no quotas). Tenant principals (tenant_id != 0) are enforced at
     * dispatch; system-domain principals are exempt. */
    qihse_quota_table_t* quotas;
    /* U3 session-bundle delivery. blobs is caller-owned (may be NULL =
     * BUNDLE.* disabled). keys_dir holds per-tenant client KEM public keys
     * ("tenant-<id>-kem_pub.pem"); dsa_private_key_path signs manifests
     * (NULL = unsigned manifests). */
    qihse_blob_store_t* blobs;
    /* Optional authenticated, bounded dump upload. Disabled by default.
     * Staging directory must be private (0700), owned by this daemon, and
     * on a volume with room for up to four concurrent 4 GiB uploads. */
    bool enable_artifact_uploads;
    const char* artifact_staging_dir;
    /* Isolated operator-only 1024-dim collection, never exposed by VEC*. */
    qihse_vector_db_t forensic_vdb;
    /* Optional committed transaction bridge. Commands fail closed unless
     * both are supplied; mesh proposals and reads use session->user. */
    qihse_consensus_mesh_t* consensus_mesh;
    qihse_consensus_blob_context_t* consensus_blob_context;
    /* Client proposals are separately gated per daemon. Keep false on the
     * Relay during normal operation; enabling it there requires an explicit
     * emergency configuration change after the primary nodes are fenced. */
    bool consensus_allow_client_proposals;
    /* Optional read-only exact-prefix challenge. RESP command:
     * QIHSE.CONSENSUS.PREFIX.POINT.CHALLENGE <index> <64-hex nonce>.
     * The 15-field response is version, group, history, writer epoch, index,
     * prefix digest, member UUID, QKP ID, observed commit index, signer UUID,
     * signer fingerprint, signature algorithm, prefix signature, challenge,
     * challenge signature. The verifier must pin identity and consume its own
     * fresh nonce once. No rejoin authority follows from this response.
     * The expected identity comes from trusted local mesh configuration, never
     * from a request. The signer must be enrolled and approved in the store.
     * Merge requires low-clearance/high-data negative adapter coverage in CI. */
    bool consensus_prefix_challenge_enabled;
    qihse_consensus_prefix_expected_t consensus_prefix_expected;
    const char* bundle_keys_dir;
    const char* bundle_dsa_private_key_path;
    /* U8: enable the fleet-wide "killswitch" channel — every authenticated
     * tenant may subscribe, only system-domain principals may publish
     * (burn-edge writes fan out through the engine bridge). */
    bool enable_killswitch_channel;
    /* U6: background KV expiry sweep cadence in seconds. 0 = disabled. */
    uint32_t kv_sweep_interval_seconds;
    /* Password used by CLUSTER MOVESLOTS when authenticating to the target
     * node (as GODMODE_OP). NULL/empty = migration auth disabled. */
    const char* cluster_migrate_password;
    /* Reserved legacy data-redundancy peer. Any non-NULL value is rejected
     * by server creation until authenticated, durable QKP write replication
     * replaces the label-dropping cleartext RESP replay path. */
    const char* redundancy_peer;
} qihse_resp_server_config_t;

void qihse_resp_server_config_init(qihse_resp_server_config_t* config);
qihse_resp_server_t* qihse_resp_server_create(const qihse_resp_server_config_t* config);
bool qihse_resp_server_start(qihse_resp_server_t* server);
bool qihse_resp_server_run(qihse_resp_server_t* server);
void qihse_resp_server_stop(qihse_resp_server_t* server);
void qihse_resp_server_destroy(qihse_resp_server_t* server);
uint16_t qihse_resp_server_port(const qihse_resp_server_t* server);
qihse_cluster_topology_t* qihse_resp_server_topology(qihse_resp_server_t* server);
qihse_kv_store_t* qihse_resp_server_store(qihse_resp_server_t* server);
bool qihse_resp_server_handle_client_fd(qihse_resp_server_t* server, int client_fd);

/* ── R4 replicated namespaces (REPL.*) — internal API for the daemon ─────
 * The registry lives in the engine so routing and REPL.STATUS share one
 * source of truth; the daemon's anti-entropy thread drives it. */
/* Add/remove a namespace glob. from_flag distinguishes boot-time
 * (--replicate, re-added on every restart) from runtime (REPL.MARK,
 * lost on restart). Fails on bad input or a full registry. */
bool qihse_resp_server_repl_add(qihse_resp_server_t* server, const char* glob, bool from_flag);
bool qihse_resp_server_repl_remove(qihse_resp_server_t* server, const char* glob);
/* Snapshot the current globs (out arrays are caller-provided, capped);
 * returns how many were written. from_flag_out[i] receives the source. */
size_t qihse_resp_server_repl_list(qihse_resp_server_t* server,
                                   char (*out_globs)[128], bool* from_flag_out, size_t cap);
/* Sovereign-routing predicate: does this key match any marked namespace? */
bool qihse_resp_server_repl_key_matched(qihse_resp_server_t* server, const char* key, size_t key_len);
/* In-process receiver seam for a daemon that has authenticated the source
 * server with QKP1. These validate the client-side session against this
 * server's configured upstream pin and require the exact configured active
 * replication service principal.
 * Apply also requires an exact marked glob/key match and persists the row
 * before advancing its durable per-peer cursor. Both methods take kv_lock. */
bool qihse_resp_server_repl_apply_local(qihse_resp_server_t* server,
                                        const qihse_qkp_session_t* source_session,
                                        const char* glob,
                                        const qihse_kv_replica_record_t* record,
                                        qihse_user_t* principal);
bool qihse_resp_server_repl_cursor_local(qihse_resp_server_t* server,
                                         const qihse_qkp_session_t* source_session,
                                         const char* glob,
                                         qihse_user_t* principal,
                                         uint64_t* out_seq);
bool qihse_resp_server_repl_snapshot_installed_local(qihse_resp_server_t* server,
                                                      const qihse_qkp_session_t* source_session,
                                                      const char* glob,
                                                      qihse_user_t* principal,
                                                      bool* out_installed);
bool qihse_resp_server_repl_snapshot_install_local(qihse_resp_server_t* server,
                                                    const qihse_qkp_session_t* source_session,
                                                    const char* glob,
                                                    const char* filepath,
                                                    uint64_t source_highwater,
                                                    qihse_user_t* principal);
/* QKP1 pinned-peer source data plane. REPL.DELTA returns flat bulk fields
 * [cursor,count,op,seq,class,sci,expire_ms,key,value,...]. Network peers may
 * call DELTA, SNAPSHOT.BEGIN/READ/END and ACK only. Receiver-side APPLY and
 * CURSOR remain available solely to local authenticated/in-process adapters.
 * REPL.SNAPSHOT.BEGIN registers the source's durable baseline for that
 * peer/namespace before releasing the snapshot view; REPL.ACK advances it
 * after receiver durability.
 * Streaming compaction retains matching tombstones until that acknowledgement.
 * Legacy sequence-zero rows still require a full snapshot baseline. */
/* Anti-entropy bookkeeping for REPL.STATUS. peer == NULL updates the
 * pattern-level counters (local_count/orphaned); otherwise the per-peer
 * record (pulled/divergent/ok/last_sync). UINT64_MAX leaves a counter
 * untouched. Best effort: unknown globs or a full peer table are no-ops. */
void qihse_resp_server_repl_note(qihse_resp_server_t* server, const char* glob, const char* peer,
                                 uint64_t pulled, uint64_t divergent,
                                 uint64_t local_count, uint64_t orphaned, bool ok);
/* Trigger a pull from a peer host:port for a given glob.
 * If missing_only is true, existing keys in store are skipped without GET.
 * Returns true if the connection and pull completed, with out_pulled set. */
bool qihse_resp_server_repl_pull(qihse_resp_server_t* server, const char* glob,
                                 const char* host, uint16_t port, bool missing_only,
                                 uint64_t* out_pulled, char* err, size_t err_cap);
qihse_cluster_bus_t* qihse_resp_server_bus(qihse_resp_server_t* server);

/* The dispatch listener's actual port, or 0 when dispatch is not running
 * (disabled, or the listener could not start). A caller that asked for an
 * ephemeral port needs this to build a dispatch endpoint. */
uint16_t qihse_resp_server_fabric_port(qihse_resp_server_t* server);
qihse_cluster_failover_t* qihse_resp_server_failover(qihse_resp_server_t* server);
qihse_system_guard_window_t* qihse_resp_server_guard_window(qihse_resp_server_t* server);
qihse_cluster_scatter_t* qihse_resp_server_scatter(qihse_resp_server_t* server);
qihse_task_queue_t* qihse_resp_server_task_queue(qihse_resp_server_t* server);
qihse_task_worker_pool_t* qihse_resp_server_task_workers(qihse_resp_server_t* server);
qihse_task_scheduler_t* qihse_resp_server_task_scheduler(qihse_resp_server_t* server);

/**
 * @brief Executes a single RESP command on behalf of an explicit authenticated
 * user, statelessly (no TCP session; MULTI/transaction state is not kept).
 * The reply bytes (a complete RESP reply) are returned in *out_reply and must
 * be freed by the caller. Used by the UWP RESP bridge
 * (QIHSE_UWP_TARGET_RESP); requires config.enable_uwp_bridge and a non-NULL
 * user — there is no context-free fallback.
 */
bool qihse_resp_server_execute(qihse_resp_server_t* server, qihse_user_t* user,
                               size_t argc, const qihse_resp_arg_t* argv,
                               uint8_t** out_reply, size_t* out_reply_len);

/**
 * @brief Starts a TCP server that listens for RESP (Redis Serialization Protocol) commands.
 * 
 * Supports standard Redis commands (PING, SET, GET, DEL) mapped to the QIHSE KV Store,
 * as well as custom commands (VECSET, VECGET, VECSEARCH) mapped to the QIHSE Vector DB.
 * 
 * @param store Pointer to the initialized QIHSE KV Store.
 * @param vdb Pointer to the initialized QIHSE Vector Database.
 * @param port TCP port to bind to (e.g., 6379).
 * @param bind_address IP address to bind to (e.g., "0.0.0.0" or "127.0.0.1").
 * @return true if the server started successfully, false otherwise.
 */
bool qihse_start_resp_server(qihse_kv_store_t* store, qihse_vector_db_t vdb, uint16_t port, const char* bind_address);

/**
 * Handles a RESP client connection synchronously on the given socket.
 * Useful for multiplexing connections.
 */
void qihse_resp_handle_client(int client_fd, qihse_kv_store_t* store, qihse_vector_db_t vdb);

#endif /* QIHSE_RESP_WIRE_H */
