#ifndef QIHSE_CONSENSUS_PREFIX_PAIR_H
#define QIHSE_CONSENSUS_PREFIX_PAIR_H

#include "qihse_consensus_prefix_point_challenge.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Two independently challenged, enrolled nodes' statements about the same
 * exact committed point. All expected values and nonces come from protected
 * verifier state, never from either response. The expected digest must come
 * from an independently trusted recovery record, not from the two peers.
 *
 * This is evidence comparison only. It does not prove a writer fence,
 * establish a quorum commit, or authorize replay or rejoin. */
typedef struct {
    qihse_consensus_prefix_expected_t first;
    qihse_consensus_prefix_expected_t second;
    uint64_t index;
    uint8_t committed_prefix_sha256[32];
    /* SHA-256 of a protected, independently trusted recovery anchor (for
     * example a retained signed fence record). Never derive this from either
     * peer response. Its contents and signature are checked elsewhere. */
    uint8_t trusted_recovery_anchor_sha256[32];
    uint8_t first_challenge[QIHSE_CONSENSUS_PREFIX_CHALLENGE_BYTES];
    uint8_t second_challenge[QIHSE_CONSENSUS_PREFIX_CHALLENGE_BYTES];
} qihse_consensus_prefix_pair_expected_t;

typedef struct {
    uint64_t index;
    uint64_t first_observed_commit_index;
    uint64_t second_observed_commit_index;
    uint8_t committed_prefix_sha256[32];
    /* Basename of the fsynced 0600 accepted record in nonce_directory.
     * The record is diagnostic evidence, never a rejoin grant. */
    char accepted_record_name[131];
} qihse_consensus_prefix_pair_evidence_t;

/* Both identity lookups use the authenticated federation-store context.
 * The caller must pin each QKP transport peer before either response. The
 * challenges must have been issued by nonce_issue in this protected local
 * directory. The pair is durably consumed BEFORE signature verification,
 * including when the responses are invalid. Success is returned only after
 * an owner-only accepted evidence record has been fsynced. */
bool qihse_consensus_prefix_pair_verify_user(
    const char* nonce_directory, void* store, void* store_user,
    const qihse_consensus_prefix_pair_expected_t* expected,
    const qihse_consensus_prefix_point_challenge_t* first,
    const qihse_consensus_prefix_point_challenge_t* second,
    qihse_consensus_prefix_pair_evidence_t* out);

#ifdef __cplusplus
}
#endif

#endif
