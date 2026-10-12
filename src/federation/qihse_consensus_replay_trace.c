#include "qihse_consensus_replay_trace.h"

#include <string.h>

/* Limit caller-controlled verification and lock-held prefix hashing work. */
#define QIHSE_REPLAY_TRACE_MAX_CHECKPOINTS 64u

static bool trace_inputs_valid(
    qihse_consensus_mesh_t* mesh, const qihse_user_t* requester,
    void* store, void* store_user,
    const qihse_consensus_prefix_expected_t* local_expected,
    const qihse_consensus_prefix_expected_t* peer_expected,
    const void* checkpoints, size_t checkpoint_count,
    uint64_t final_index) {
    return mesh && requester && store && store_user && local_expected &&
        peer_expected && checkpoints && checkpoint_count > 0u &&
        checkpoint_count <= QIHSE_REPLAY_TRACE_MAX_CHECKPOINTS &&
        final_index > 0u && final_index <= QIHSE_MESH_EVIDENCE_MAX_ENTRIES &&
        !qihse_uuid_equal(&local_expected->member_uuid,
                          &peer_expected->member_uuid) &&
        !qihse_uuid_equal(&local_expected->signer_node,
                          &peer_expected->signer_node) &&
        strncmp(local_expected->group_id, peer_expected->group_id,
                sizeof(local_expected->group_id)) == 0 &&
        memcmp(local_expected->history_id, peer_expected->history_id,
               sizeof(local_expected->history_id)) == 0 &&
        local_expected->writer_epoch_floor ==
            peer_expected->writer_epoch_floor;
}

static bool local_point_matches(
    qihse_consensus_mesh_t* mesh, const qihse_user_t* requester,
    const qihse_consensus_prefix_expected_t* expected,
    const qihse_consensus_prefix_evidence_t* peer,
    uint64_t previous_observed_commit,
    uint64_t* observed_commit) {
    qihse_consensus_mesh_prefix_point_t local;
    memset(&local, 0, sizeof(local));
    if (!qihse_consensus_mesh_export_prefix_point_user(
            mesh, requester, peer->commit_index, &local) ||
        local.prefix.commit_index != peer->commit_index ||
        local.observed_commit_index < peer->commit_index ||
        local.observed_commit_index < previous_observed_commit ||
        strncmp(local.prefix.group_id, expected->group_id,
                sizeof(local.prefix.group_id)) != 0 ||
        memcmp(local.prefix.history_id, expected->history_id,
               sizeof(local.prefix.history_id)) != 0 ||
        local.prefix.writer_epoch_floor != expected->writer_epoch_floor ||
        !qihse_uuid_equal(&local.prefix.member_uuid,
                          &expected->member_uuid) ||
        strncmp(local.prefix.qkp_node_id, expected->qkp_node_id,
                sizeof(local.prefix.qkp_node_id)) != 0 ||
        memcmp(local.prefix.committed_prefix_sha256,
               peer->committed_prefix_sha256,
               sizeof(local.prefix.committed_prefix_sha256)) != 0)
        return false;
    *observed_commit = local.observed_commit_index;
    return true;
}

bool qihse_consensus_mesh_verify_replay_trace_user(
    qihse_consensus_mesh_t* mesh, const qihse_user_t* requester,
    void* store, void* store_user,
    const qihse_consensus_prefix_expected_t* local_expected,
    const qihse_consensus_prefix_expected_t* peer_expected,
    const qihse_consensus_prefix_attestation_t* checkpoints,
    size_t checkpoint_count, uint64_t final_index) {
    if (!trace_inputs_valid(mesh, requester, store, store_user,
                            local_expected, peer_expected, checkpoints,
                            checkpoint_count, final_index)) return false;

    uint64_t previous_index = 0u;
    uint64_t previous_observed_commit = 0u;
    for (size_t i = 0u; i < checkpoint_count; ++i) {
        const qihse_consensus_prefix_attestation_t* peer = &checkpoints[i];
        const qihse_consensus_prefix_evidence_t* evidence = &peer->evidence;
        uint64_t index = evidence->commit_index;
        if (index <= previous_index || index > final_index ||
            !qihse_consensus_prefix_attestation_verify_user(
                store, store_user, peer_expected, peer)) return false;

        if (!local_point_matches(mesh, requester, local_expected, evidence,
                                 previous_observed_commit,
                                 &previous_observed_commit))
            return false;
        previous_index = index;
    }
    return previous_index == final_index;
}

bool qihse_consensus_mesh_verify_challenged_replay_trace_user(
    qihse_consensus_mesh_t* mesh, const qihse_user_t* requester,
    void* store, void* store_user,
    const qihse_consensus_prefix_expected_t* local_expected,
    const qihse_consensus_prefix_expected_t* peer_expected,
    const qihse_consensus_prefix_point_challenge_t* checkpoints,
    const uint8_t (*expected_challenges)
        [QIHSE_CONSENSUS_PREFIX_CHALLENGE_BYTES],
    size_t checkpoint_count, uint64_t final_index) {
    if (!trace_inputs_valid(mesh, requester, store, store_user,
                            local_expected, peer_expected, checkpoints,
                            checkpoint_count, final_index) ||
        !expected_challenges) return false;

    uint64_t previous_index = 0u;
    uint64_t previous_local_commit = 0u;
    uint64_t previous_peer_commit = 0u;
    for (size_t i = 0u; i < checkpoint_count; ++i) {
        const qihse_consensus_prefix_point_challenge_t* point =
            &checkpoints[i];
        const qihse_consensus_prefix_evidence_t* evidence =
            &point->prefix.evidence;
        uint64_t index = evidence->commit_index;
        if (index <= previous_index || index > final_index ||
            point->observed_commit_index < previous_peer_commit)
            return false;
        for (size_t j = 0u; j < i; ++j) {
            if (memcmp(expected_challenges[j], expected_challenges[i],
                       QIHSE_CONSENSUS_PREFIX_CHALLENGE_BYTES) == 0)
                return false;
        }
        if (!qihse_consensus_prefix_point_challenge_verify_user(
                store, store_user, peer_expected, index,
                expected_challenges[i], point) ||
            !local_point_matches(mesh, requester, local_expected, evidence,
                                 previous_local_commit,
                                 &previous_local_commit))
            return false;
        previous_index = index;
        previous_peer_commit = point->observed_commit_index;
    }
    return previous_index == final_index;
}
