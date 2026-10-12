#include "qihse_consensus_prefix_attestation_adapter.h"

#include <string.h>

static bool export_mesh_prefix_user(
    void* source, const qihse_user_t* requester, uint64_t max_entries,
    qihse_consensus_prefix_evidence_t* out) {
    if (out) memset(out, 0, sizeof(*out));
    if (!source || !requester || !out ||
        max_entries > QIHSE_MESH_EVIDENCE_MAX_ENTRIES) return false;

    qihse_consensus_mesh_prefix_evidence_t mesh_evidence;
    memset(&mesh_evidence, 0, sizeof(mesh_evidence));
    if (!qihse_consensus_mesh_export_prefix_evidence_user(
            (qihse_consensus_mesh_t*)source, requester, max_entries,
            &mesh_evidence)) return false;

    /* Keep the two public structures independent. A struct cast would couple
     * their ABI and could silently omit a new identity or digest field. */
    memcpy(out->group_id, mesh_evidence.group_id, sizeof(out->group_id));
    memcpy(out->history_id, mesh_evidence.history_id, sizeof(out->history_id));
    out->writer_epoch_floor = mesh_evidence.writer_epoch_floor;
    out->commit_index = mesh_evidence.commit_index;
    memcpy(out->committed_prefix_sha256,
           mesh_evidence.committed_prefix_sha256,
           sizeof(out->committed_prefix_sha256));
    out->member_uuid = mesh_evidence.member_uuid;
    memcpy(out->qkp_node_id, mesh_evidence.qkp_node_id,
           sizeof(out->qkp_node_id));
    return true;
}

bool qihse_consensus_mesh_attest_prefix_user(
    qihse_consensus_mesh_t* mesh, const qihse_user_t* requester,
    void* store, void* store_user, const qihse_uuid_t* signer_node,
    const qihse_consensus_prefix_expected_t* expected,
    uint64_t max_entries, qihse_consensus_prefix_attestation_t* out) {
    if (out) memset(out, 0, sizeof(*out));
    if (!mesh || !requester || !out ||
        max_entries > QIHSE_MESH_EVIDENCE_MAX_ENTRIES) return false;
    return qihse_consensus_prefix_attest_user(
        mesh, export_mesh_prefix_user, requester, store, store_user,
        signer_node, expected, max_entries, out);
}

static void attestation_anchor(
    const qihse_consensus_prefix_attestation_t* statement,
    qihse_consensus_history_anchor_t* anchor) {
    memset(anchor, 0, sizeof(*anchor));
    memcpy(anchor->group_id, statement->evidence.group_id,
           sizeof(anchor->group_id));
    memcpy(anchor->history_id, statement->evidence.history_id,
           sizeof(anchor->history_id));
    anchor->writer_epoch = statement->evidence.writer_epoch_floor;
    anchor->commit_index = statement->evidence.commit_index;
    memcpy(anchor->prefix_sha256,
           statement->evidence.committed_prefix_sha256,
           sizeof(anchor->prefix_sha256));
}

qihse_consensus_rejoin_result_t qihse_consensus_mesh_compare_attested_peer_user(
    qihse_consensus_mesh_t* mesh, const qihse_user_t* requester,
    void* store, void* store_user, const qihse_uuid_t* local_signer_node,
    const qihse_consensus_prefix_expected_t* local_expected,
    const qihse_consensus_prefix_expected_t* peer_expected,
    const qihse_consensus_prefix_attestation_t* peer,
    uint64_t max_entries) {
    if (!mesh || !requester || !store || !store_user ||
        !local_signer_node || !local_expected || !peer_expected || !peer ||
        max_entries > QIHSE_MESH_EVIDENCE_MAX_ENTRIES ||
        peer->evidence.commit_index > max_entries ||
        qihse_uuid_equal(&local_expected->member_uuid,
                         &peer_expected->member_uuid) ||
        qihse_uuid_equal(&local_expected->signer_node,
                         &peer_expected->signer_node) ||
        !qihse_uuid_equal(local_signer_node,
                          &local_expected->signer_node))
        return QIHSE_REJOIN_INVALID;

    /* Verify before comparing, including enrollment and revocation on each
     * call. Never accept a caller-supplied digest as authenticated evidence. */
    if (!qihse_consensus_prefix_attestation_verify_user(
            store, store_user, peer_expected, peer))
        return QIHSE_REJOIN_INVALID;

    qihse_consensus_prefix_attestation_t local;
    if (!qihse_consensus_mesh_attest_prefix_user(
            mesh, requester, store, store_user, local_signer_node,
            local_expected, max_entries, &local))
        return QIHSE_REJOIN_INVALID;

    qihse_consensus_history_anchor_t local_anchor, peer_anchor;
    attestation_anchor(&local, &local_anchor);
    attestation_anchor(peer, &peer_anchor);
    return qihse_consensus_rejoin_compare(&local_anchor, &peer_anchor);
}
