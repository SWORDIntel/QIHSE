#ifndef QIHSE_CONSENSUS_PREFIX_POINT_CHALLENGE_H
#define QIHSE_CONSENSUS_PREFIX_POINT_CHALLENGE_H

#include "qihse_consensus_mesh.h"
#include "qihse_consensus_prefix_challenge.h"

#ifdef __cplusplus
extern "C" {
#endif

/* A source's signed commitment to a requested committed prefix and the
 * source watermark observed under the same mesh lock. The verifier supplies
 * the requested index and a fresh, single-use challenge from local state.
 * This is diagnostic evidence only: it grants no replay, quorum, writer
 * fence, rejoin, or serving authority. */
typedef struct {
    qihse_consensus_prefix_attestation_t prefix;
    uint64_t observed_commit_index;
    uint8_t challenge[QIHSE_CONSENSUS_PREFIX_CHALLENGE_BYTES];
    size_t signature_len;
    uint8_t signature[QIHSE_FEDERATION_SIG_MAX_BYTES];
} qihse_consensus_prefix_point_challenge_t;

/* Requires a live, authenticated system Operator authorized for every entry
 * through requested_index. Federation identity lookup uses store_user. The
 * caller authenticates the transport separately. */
bool qihse_consensus_mesh_prefix_point_challenge_respond_user(
    qihse_consensus_mesh_t* mesh, const qihse_user_t* requester,
    void* store, void* store_user, const qihse_uuid_t* signer_node,
    const qihse_consensus_prefix_expected_t* expected,
    uint64_t requested_index,
    const uint8_t challenge[QIHSE_CONSENSUS_PREFIX_CHALLENGE_BYTES],
    qihse_consensus_prefix_point_challenge_t* out);

/* expected, requested_index and challenge are verifier-owned values, never
 * copied from the response. The caller expires and consumes the challenge
 * once. Current enrollment and revocation are checked during verification. */
bool qihse_consensus_prefix_point_challenge_verify_user(
    void* store, void* store_user,
    const qihse_consensus_prefix_expected_t* expected,
    uint64_t requested_index,
    const uint8_t challenge[QIHSE_CONSENSUS_PREFIX_CHALLENGE_BYTES],
    const qihse_consensus_prefix_point_challenge_t* response);

#ifdef __cplusplus
}
#endif

#endif
