#include "qihse_consensus_replay_verify.h"

#include <string.h>

bool qihse_consensus_mesh_verify_replayed_prefix_user(
    qihse_consensus_mesh_t* mesh, const qihse_user_t* requester,
    void* store, void* store_user,
    const qihse_consensus_prefix_expected_t* local_expected,
    const qihse_consensus_prefix_expected_t* peer_expected,
    const qihse_consensus_prefix_attestation_t* peer_target,
    uint64_t target_index) {
    if (!mesh || !requester || !store || !store_user || !local_expected ||
        !peer_expected || !peer_target ||
        target_index > QIHSE_MESH_EVIDENCE_MAX_ENTRIES ||
        peer_target->evidence.commit_index != target_index ||
        qihse_uuid_equal(&local_expected->member_uuid,
                         &peer_expected->member_uuid) ||
        qihse_uuid_equal(&local_expected->signer_node,
                         &peer_expected->signer_node) ||
        !qihse_consensus_prefix_attestation_verify_user(
            store, store_user, peer_expected, peer_target)) return false;

    /* The local exporter checks a live system Operator and authorizes every
     * committed entry. It also refuses a prefix above the caller's bound. */
    qihse_consensus_mesh_prefix_evidence_t local;
    memset(&local, 0, sizeof(local));
    if (!qihse_consensus_mesh_export_prefix_evidence_user(
            mesh, requester, target_index, &local) ||
        local.commit_index != target_index ||
        strncmp(local.group_id, local_expected->group_id,
                sizeof(local.group_id)) != 0 ||
        memcmp(local.history_id, local_expected->history_id,
               sizeof(local.history_id)) != 0 ||
        local.writer_epoch_floor != local_expected->writer_epoch_floor ||
        !qihse_uuid_equal(&local.member_uuid,
                          &local_expected->member_uuid) ||
        strncmp(local.qkp_node_id, local_expected->qkp_node_id,
                sizeof(local.qkp_node_id)) != 0) return false;

    const qihse_consensus_prefix_evidence_t* peer = &peer_target->evidence;
    return strcmp(local.group_id, peer->group_id) == 0 &&
        memcmp(local.history_id, peer->history_id,
               sizeof(local.history_id)) == 0 &&
        local.writer_epoch_floor == peer->writer_epoch_floor &&
        memcmp(local.committed_prefix_sha256,
               peer->committed_prefix_sha256,
               sizeof(local.committed_prefix_sha256)) == 0;
}
