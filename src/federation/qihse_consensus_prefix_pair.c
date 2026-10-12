#include "qihse_consensus_prefix_pair.h"
#include "qihse_consensus_prefix_pair_nonce.h"
#include "qihse_consensus_prefix_pair_nonce_internal.h"

#include <string.h>

static bool nonzero(const uint8_t* bytes, size_t count) {
    uint8_t bits = 0u;
    for (size_t i = 0u; i < count; ++i) bits |= bytes[i];
    return bits != 0u;
}

static bool bounded_nonempty(const char* value, size_t capacity) {
    size_t length = strnlen(value, capacity);
    return length > 0u && length < capacity;
}

static bool bounded_equal(const char* first, const char* second,
                          size_t capacity) {
    size_t first_len = strnlen(first, capacity);
    size_t second_len = strnlen(second, capacity);
    return first_len > 0u && first_len < capacity &&
           first_len == second_len &&
           memcmp(first, second, first_len) == 0;
}

bool qihse_consensus_prefix_pair_verify_user(
    const char* nonce_directory, void* store, void* store_user,
    const qihse_consensus_prefix_pair_expected_t* expected,
    const qihse_consensus_prefix_point_challenge_t* first,
    const qihse_consensus_prefix_point_challenge_t* second,
    qihse_consensus_prefix_pair_evidence_t* out) {
    if (out) memset(out, 0, sizeof(*out));
    if (!nonce_directory || !store || !store_user || !expected || !first ||
        !second || !out ||
        expected->index > QIHSE_MESH_EVIDENCE_MAX_ENTRIES ||
        !nonzero(expected->trusted_recovery_anchor_sha256, 32u) ||
        (expected->index == 0u &&
         nonzero(expected->committed_prefix_sha256, 32u)) ||
        (expected->index != 0u &&
         !nonzero(expected->committed_prefix_sha256, 32u)) ||
        !bounded_equal(expected->first.group_id,
                       expected->second.group_id,
                       sizeof(expected->first.group_id)) ||
        memcmp(expected->first.history_id, expected->second.history_id,
               sizeof(expected->first.history_id)) != 0 ||
        expected->first.writer_epoch_floor == 0u ||
        expected->first.writer_epoch_floor !=
            expected->second.writer_epoch_floor ||
        qihse_uuid_equal(&expected->first.member_uuid,
                         &expected->second.member_uuid) ||
        qihse_uuid_equal(&expected->first.signer_node,
                         &expected->second.signer_node) ||
        !bounded_nonempty(expected->first.qkp_node_id,
                          sizeof(expected->first.qkp_node_id)) ||
        !bounded_nonempty(expected->second.qkp_node_id,
                          sizeof(expected->second.qkp_node_id)) ||
        bounded_equal(expected->first.qkp_node_id,
                      expected->second.qkp_node_id,
                      sizeof(expected->first.qkp_node_id)) ||
        memcmp(expected->first_challenge, expected->second_challenge,
               QIHSE_CONSENSUS_PREFIX_CHALLENGE_BYTES) == 0 ||
        !qihse_consensus_prefix_pair_nonce_claim(
            nonce_directory, expected)) return false;

    if (!qihse_consensus_prefix_pair_nonce_accept_verified(
            nonce_directory, store, store_user, expected, first, second,
            out->accepted_record_name)) return false;

    out->index = expected->index;
    out->first_observed_commit_index = first->observed_commit_index;
    out->second_observed_commit_index = second->observed_commit_index;
    memcpy(out->committed_prefix_sha256,
           expected->committed_prefix_sha256, 32u);
    return true;
}
