#ifndef QIHSE_CONSENSUS_MESH_H
#define QIHSE_CONSENSUS_MESH_H

/* Static three-or-more-member QIHSE consensus mesh. Every node dials every
 * configured peer over a private IPv4 mesh address and accepts the matching
 * inbound streams. The QKP channel is the only transport; topology gossip is
 * not used as commit authority. */

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

qihse_consensus_role_t qihse_consensus_mesh_role(qihse_consensus_mesh_t* mesh);
uint64_t qihse_consensus_mesh_term(qihse_consensus_mesh_t* mesh);
uint64_t qihse_consensus_mesh_commit_index(qihse_consensus_mesh_t* mesh);
bool qihse_consensus_mesh_leader_id(qihse_consensus_mesh_t* mesh,
                                    qihse_uuid_t* out);

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
