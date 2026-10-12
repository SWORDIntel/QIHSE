#ifndef QIHSE_CONSENSUS_PREFIX_CHALLENGE_H
#define QIHSE_CONSENSUS_PREFIX_CHALLENGE_H

#include "qihse_consensus_prefix_attestation.h"

#ifdef __cplusplus
extern "C" {
#endif

#define QIHSE_CONSENSUS_PREFIX_CHALLENGE_BYTES 32u

/* The verifier issues a fresh, unpredictable, single-use challenge and keeps
 * it in local state until the response is checked. The nonce is bound to an
 * independently signed prefix statement by an enrolled node key. This
 * proves possession of that key after challenge issuance, conditional on the
 * verifier's nonce lifecycle; it does not prove quorum, peer liveness after
 * verification, application state, writer fencing, or safe rejoin. */
typedef struct {
    qihse_consensus_prefix_attestation_t prefix;
    uint8_t challenge[QIHSE_CONSENSUS_PREFIX_CHALLENGE_BYTES];
    size_t response_signature_len;
    uint8_t response_signature[QIHSE_FEDERATION_SIG_MAX_BYTES];
} qihse_consensus_prefix_challenge_response_t;

/* The signer exports a fresh, authorized, bounded local prefix and signs it
 * before binding it to challenge. requester must be a live authorized QIHSE
 * principal; store_user must be an authenticated federation-store context.
 * The caller must authenticate the requester's peer transport separately. */
bool qihse_consensus_prefix_challenge_respond_user(
    void* source, qihse_consensus_prefix_export_user_fn export_user,
    const qihse_user_t* requester,
    void* store, void* store_user, const qihse_uuid_t* signer_node,
    const qihse_consensus_prefix_expected_t* expected,
    uint64_t max_entries,
    const uint8_t challenge[QIHSE_CONSENSUS_PREFIX_CHALLENGE_BYTES],
    qihse_consensus_prefix_challenge_response_t* out);

/* expected_challenge must come from the verifier's outstanding local request,
 * not the received response. The verifier must expire and consume it exactly
 * once. Verification re-reads current enrolled key/trust through store_user.
 * This function is diagnostic; it never grants replay or serving rights. */
bool qihse_consensus_prefix_challenge_verify_user(
    void* store, void* store_user,
    const qihse_consensus_prefix_expected_t* expected,
    const uint8_t expected_challenge[QIHSE_CONSENSUS_PREFIX_CHALLENGE_BYTES],
    const qihse_consensus_prefix_challenge_response_t* response);

#ifdef __cplusplus
}
#endif

#endif
