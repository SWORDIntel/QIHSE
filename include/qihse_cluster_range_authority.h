#ifndef QIHSE_CLUSTER_RANGE_AUTHORITY_H
#define QIHSE_CLUSTER_RANGE_AUTHORITY_H

#include "qihse_cluster_ownership.h"
#include "qihse_consensus_mesh.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    QIHSE_CLUSTER_RANGE_SOURCE_GROUP = 1,
    QIHSE_CLUSTER_RANGE_TARGET_GROUP = 2
} qihse_cluster_range_group_role_t;

/* Resolve the owning source group, or choose one eligible destination group.
 * A target group need not already own the incoming slots.
 * The callback must use configured/committed group membership, not gossip or
 * an inferred daemon-wide PRIMARY role. Outputs are NUL-terminated. */
typedef bool (*qihse_cluster_range_group_resolver_fn)(
    void* context, const qihse_user_t* principal, const char* topology_node_id,
    const uint8_t slots[QIHSE_CONSENSUS_RANGE_BITMAP_BYTES],
    qihse_cluster_range_group_role_t role,
    char group_id[65], char generation[33]);
typedef bool (*qihse_cluster_range_successor_resolver_fn)(
    void* context, const qihse_user_t* principal, const char* group_id,
    char topology_node_id[41], char qkp_node_id[65]);

typedef struct {
    qihse_consensus_mesh_t* mesh;
    qihse_cluster_range_group_resolver_fn resolve_group;
    qihse_cluster_range_successor_resolver_fn resolve_successor;
    void* group_context;
    /* Required for local ABORT evidence; the callback substitutes the actual
     * requesting principal before reading its authenticated journal/status. */
    qihse_cluster_ownership_context_t* local_ownership;
    uint32_t timeout_ms; /* per mesh phase; zero uses two seconds */
} qihse_cluster_range_authority_t;

/* Carries the actual authenticated control identity through KV verification. */
typedef struct {
    qihse_cluster_range_authority_t* authority;
    qihse_user_t* principal;
} qihse_cluster_range_verifier_t;

/* Bootstrap from the common operator-provisioned group/slot map. A second
 * different genesis is refused by the consensus state machine. */
bool qihse_cluster_range_authority_initialize(
    qihse_cluster_range_authority_t* authority, const qihse_user_t* principal,
    const qihse_consensus_range_slot_t slots[QIHSE_CONSENSUS_RANGE_SLOT_COUNT],
    char* error, size_t error_cap);

/* Reconcile routing from the committed common map. This never changes KV
 * admission or replication roles. Older local journal/event replay cannot
 * undo newer committed slot epochs. */
bool qihse_cluster_range_authority_refresh(
    void* authority, qihse_user_t* principal,
    const uint8_t slots[QIHSE_CONSENSUS_RANGE_BITMAP_BYTES],
    char* error, size_t error_cap);

/* Ownership adapter hooks. Reserve fills config_epoch before the local
 * INTENT/fence is created. An existing ID must resolve its original immutable
 * reservation rather than computing a new CAS input on retry. */
bool qihse_cluster_range_authority_reserve(
    void* authority, qihse_user_t* principal,
    qihse_cluster_ownership_txn_t* transaction, char* error, size_t error_cap);
bool qihse_cluster_range_authority_check_reserved(
    void* authority, qihse_user_t* principal,
    const qihse_cluster_ownership_txn_t* transaction,
    char* error, size_t error_cap);

/* Only an opaque, exact-tuple ACTIVATED receipt can finalize a transfer.
 * The metadata mesh never treats a caller-provided checksum as that proof. */
bool qihse_cluster_range_authority_finalize(
    void* authority, qihse_user_t* principal,
    const qihse_cluster_ownership_txn_t* transaction,
    const qihse_cluster_ct_activation_receipt_t* receipt,
    char* error, size_t error_cap);
bool qihse_cluster_range_authority_check_finalized(
    void* authority, qihse_user_t* principal,
    const qihse_cluster_ownership_txn_t* transaction,
    char* error, size_t error_cap);

/* Copy the committed immutable reservation into a store-bound proof claim.
 * Copy/image cuts may be filled as staging proceeds; final verification binds
 * those values to the operation-specific committed evidence. */
bool qihse_cluster_range_authority_claim(
    void* authority, qihse_user_t* principal,
    const qihse_cluster_ownership_txn_t* transaction,
    qihse_kv_ct_lane_authority_claim_t* out_claim);
bool qihse_cluster_range_authority_verify_claim_user(
    void* authority, qihse_user_t* principal,
    const qihse_kv_ct_lane_authority_claim_t* claim,
    bool require_final_decision);
bool qihse_cluster_range_authority_verify_claim(
    void* verifier, const qihse_kv_ct_lane_authority_claim_t* claim,
    bool require_final_decision);
bool qihse_cluster_range_authority_finalize_promotion(
    void* authority, qihse_user_t* principal,
    const qihse_cluster_ownership_txn_t* transaction,
    const qihse_kv_ct_proof_t* promoted_proof,
    const uint8_t promotion_event_digest[32],
    char* error, size_t error_cap);

/* Called after guarded durable local ABORTED, before releasing its fence.
 * The adapter verifies the local journal; caller booleans are not evidence. */
bool qihse_cluster_range_authority_abort(
    void* authority, qihse_user_t* principal,
    const qihse_cluster_ownership_txn_t* transaction,
    char* error, size_t error_cap);

#ifdef __cplusplus
}
#endif

#endif
