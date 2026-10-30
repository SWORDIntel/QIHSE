#ifndef QIHSE_CONSENSUS_MESH_H
#define QIHSE_CONSENSUS_MESH_H

/* History-bound QIHSE consensus mesh. Each node dials its provisioned peers
 * over private IPv4 and accepts only pinned QKP identities. The durable
 * baseline member list stays fixed across restarts; logged config entries
 * determine the effective voters. Transport peers may be provisioned before
 * ADD or omitted after REMOVE. Gossip is never commit authority. */

#include "qihse_consensus_blob_channel.h"
#include "qihse_consensus_snapshot_stage.h"

#ifdef __cplusplus
extern "C" {
#endif

#define QIHSE_CONSENSUS_MESH_MAX_PEERS (QIHSE_CONSENSUS_MAX_MEMBERS - 1u)

typedef struct {
    qihse_uuid_t member_uuid;
    const char* qkp_node_id;
    const char* dsa_public_key_path;
    const char* wireguard_ipv4;
    uint16_t port;
    /* Explicitly provisioned QCS1 snapshot-chunk support. False is the
     * legacy-compatible default because old wire decoders reject type 7. */
    bool snapshot_chunks_supported;
} qihse_consensus_mesh_peer_t;

typedef struct {
    qihse_consensus_config_t consensus;
    qihse_qkp_config_t qkp;
    qihse_user_t* system_principal;
    qihse_consensus_blob_context_t* blob_context;
    /* Optional durable receiver staging path. Leave NULL to reject chunked
     * snapshots; legacy SNAPSHOT messages remain available. */
    const char* snapshot_stage_path;
    const char* listen_wireguard_ipv4;
    uint16_t listen_port;
    size_t peer_count;
    qihse_consensus_mesh_peer_t peers[QIHSE_CONSENSUS_MESH_MAX_PEERS];
    uint32_t tick_interval_ms; /* 0 = 10 ms */
} qihse_consensus_mesh_config_t;

typedef struct qihse_consensus_mesh qihse_consensus_mesh_t;

qihse_consensus_mesh_t* qihse_consensus_mesh_create(
    const qihse_consensus_mesh_config_t* config);
bool qihse_consensus_mesh_start(qihse_consensus_mesh_t* mesh);
void qihse_consensus_mesh_stop(qihse_consensus_mesh_t* mesh);
void qihse_consensus_mesh_destroy(qihse_consensus_mesh_t* mesh);
uint16_t qihse_consensus_mesh_port(const qihse_consensus_mesh_t* mesh);

/* Metadata-only, lock-consistent view. It never materializes log entries. */
typedef struct {
    qihse_consensus_role_t role;
    bool has_leader;
    qihse_uuid_t leader_id;
    uint64_t term;
    uint64_t commit_index;
    uint64_t last_log_index;
} qihse_consensus_mesh_status_t;

bool qihse_consensus_mesh_status(qihse_consensus_mesh_t* mesh,
                                 qihse_consensus_mesh_status_t* out);

/* Identity copied from the configuration with which the durable consensus
 * instance was opened. Metadata only; no log payload is materialized. The
 * state lock serializes this read with consensus mutation and rejoin. */
typedef struct {
    char group_id[QIHSE_CONSENSUS_GROUP_ID_MAX + 1u];
    uint8_t history_id[32];
    uint64_t writer_epoch_floor;
} qihse_consensus_mesh_identity_t;

bool qihse_consensus_mesh_history_identity(
    qihse_consensus_mesh_t* mesh, qihse_consensus_mesh_identity_t* out);

/* Fixed-size local recovery inventory. The SHA-256 digest covers the exact
 * committed prefix using the consensus-core v1 encoding; zero index has the
 * documented all-zero digest. The caller must be a live system Operator and
 * may bound work to at most QIHSE_MESH_EVIDENCE_MAX_ENTRIES. Refuse larger
 * prefixes rather than holding the mesh state lock for unbounded work.
 * This is local, unsigned evidence, not a peer attestation or rejoin grant. */
#define QIHSE_MESH_EVIDENCE_MAX_ENTRIES 4096u
typedef struct {
    char group_id[QIHSE_CONSENSUS_GROUP_ID_MAX + 1u];
    uint8_t history_id[32];
    uint64_t writer_epoch_floor;
    uint64_t commit_index;
    uint8_t committed_prefix_sha256[32];
    qihse_uuid_t member_uuid;
    char qkp_node_id[QIHSE_QKP_NODE_ID_LEN + 1u];
} qihse_consensus_mesh_prefix_evidence_t;

bool qihse_consensus_mesh_export_prefix_evidence_user(
    qihse_consensus_mesh_t* mesh, const qihse_user_t* requester,
    uint64_t max_entries, qihse_consensus_mesh_prefix_evidence_t* out);

/* A point on the committed history, including the source's committed
 * watermark captured under the same state lock. This lets a recovery caller
 * ask whether a source still has the exact prefix held by a lagging node.
 * The point is unsigned and is not a rejoin or writer-fence authorization.
 * Hashing is bounded by QIHSE_MESH_EVIDENCE_MAX_ENTRIES and requires a live
 * system Operator authorized for every included entry. */
typedef struct {
    qihse_consensus_mesh_prefix_evidence_t prefix;
    uint64_t observed_commit_index;
} qihse_consensus_mesh_prefix_point_t;

bool qihse_consensus_mesh_export_prefix_point_user(
    qihse_consensus_mesh_t* mesh, const qihse_user_t* requester,
    uint64_t through_index, qihse_consensus_mesh_prefix_point_t* out);

qihse_consensus_role_t qihse_consensus_mesh_role(qihse_consensus_mesh_t* mesh);
uint64_t qihse_consensus_mesh_term(qihse_consensus_mesh_t* mesh);
uint64_t qihse_consensus_mesh_commit_index(qihse_consensus_mesh_t* mesh);
bool qihse_consensus_mesh_leader_id(qihse_consensus_mesh_t* mesh,
                                    qihse_uuid_t* out);

/* Request one logged voter-set change through the live leader. The caller
 * must be an active system Operator. REMOVE is permitted only when at least
 * two voters remain; ADD requires an already provisioned, authenticated mesh
 * peer. A true result means this exact config entry committed. On timeout,
 * out_index identifies the locally appended entry, whose final state must
 * be inspected before retrying. The durable opening baseline is never edited. */
bool qihse_consensus_mesh_propose_membership(
    qihse_consensus_mesh_t* mesh, const qihse_user_t* principal,
    qihse_consensus_membership_op_t op, const qihse_uuid_t* member,
    uint32_t timeout_ms, uint64_t* out_index);

/* Propose locally and wait until the entry is committed or timeout expires.
 * On timeout, out_index still receives the locally durable index when the
 * proposal was appended; callers must use operation IDs for retry safety. */
bool qihse_consensus_mesh_propose(qihse_consensus_mesh_t* mesh,
                                  const qihse_user_t* principal,
                                  uint64_t journal_generation,
                                  qihse_hlc_t hlc,
                                  uint16_t classification, uint16_t sci,
                                  const void* payload, size_t payload_len,
                                  uint32_t timeout_ms, uint64_t* out_index);

/* Stage a transaction on this node and a voter quorum, then propose its QBR1
 * reference and wait for the normal consensus commit. principal is the
 * authenticated application context and must be authorized for class/SCI;
 * application tenant/compartment checks remain the caller's responsibility. */
bool qihse_consensus_mesh_propose_transaction(
    qihse_consensus_mesh_t* mesh,
    const qihse_user_t* principal,
    uint64_t journal_generation, qihse_hlc_t hlc,
    uint16_t classification, uint16_t sci,
    const void* transaction, size_t transaction_len,
    uint32_t stage_timeout_ms, uint32_t commit_timeout_ms,
    uint64_t* out_index);

/* Serialize a transaction proposal and allocate the next journal generation
 * from the durable consensus log. This is the entry point for concurrent
 * application writers; out_generation is assigned even when the call times
 * out after local append, matching out_index's unknown-commit semantics. */
bool qihse_consensus_mesh_propose_transaction_auto_generation(
    qihse_consensus_mesh_t* mesh,
    const qihse_user_t* principal, qihse_hlc_t hlc,
    uint16_t classification, uint16_t sci,
    const void* transaction, size_t transaction_len,
    uint32_t stage_timeout_ms, uint32_t commit_timeout_ms,
    uint64_t* out_generation, uint64_t* out_index);

/* Compare the caller's last applied journal generation under the same
 * proposal serialization lock used for allocation. A stale application
 * transaction is refused before staging or append, preventing a follower
 * that computed changes from an old snapshot from overwriting newer values. */
bool qihse_consensus_mesh_propose_transaction_if_generation(
    qihse_consensus_mesh_t* mesh,
    const qihse_user_t* principal, uint64_t expected_generation,
    qihse_hlc_t hlc, uint16_t classification, uint16_t sci,
    const void* transaction, size_t transaction_len,
    uint32_t stage_timeout_ms, uint32_t commit_timeout_ms,
    uint64_t* out_generation, uint64_t* out_index);

bool qihse_consensus_mesh_read_committed(qihse_consensus_mesh_t* mesh,
                                         const qihse_user_t* principal,
                                         uint64_t from_index,
                                         qihse_consensus_entry_t* out_entries,
                                         size_t out_cap, size_t* out_count);

/* Read a complete, authorized page and capture its committed watermark under
 * the same state lock. A denied or missing entry fails the entire read, so a
 * transaction cursor cannot advance past an unseen committed entry. */
bool qihse_consensus_mesh_read_committed_page(
    qihse_consensus_mesh_t* mesh, const qihse_user_t* principal,
    uint64_t from_index, qihse_consensus_entry_t* out_entries,
    size_t out_cap, size_t* out_count, uint64_t* out_commit_index);

#ifdef QIHSE_CONSENSUS_MESH_TESTING
/* Exercises the production per-peer dequeue selector with interleaved jobs. */
bool qihse_consensus_mesh_test_tx_priority(void);
/* Test-only deterministic fault injection. After a peer imports and
 * acknowledges a blob, the sender reports the first configured ACK as lost.
 * This exercises reconnect + QBR1 HAVE retry without production hooks. */
bool qihse_consensus_mesh_test_drop_next_stage_ack(
    qihse_consensus_mesh_t* mesh, size_t peer_index, unsigned int count);
unsigned int qihse_consensus_mesh_test_stage_ack_drops(
    qihse_consensus_mesh_t* mesh);
bool qihse_consensus_mesh_test_drop_next_snapshot_ack(
    qihse_consensus_mesh_t* mesh, size_t peer_index, unsigned int count);
bool qihse_consensus_mesh_test_set_snapshot_ack_drops(
    qihse_consensus_mesh_t* mesh, size_t peer_index, unsigned int count);
unsigned int qihse_consensus_mesh_test_snapshot_ack_drops(
    qihse_consensus_mesh_t* mesh);
bool qihse_consensus_mesh_test_set_snapshot_chunks_supported(
    qihse_consensus_mesh_t* mesh, size_t peer_index, bool supported);
bool qihse_consensus_mesh_test_snapshot_progress(
    qihse_consensus_mesh_t* mesh, const qihse_user_t* principal,
    qihse_consensus_snapshot_stage_progress_t* out);
#endif

#ifdef __cplusplus
}
#endif

#endif
