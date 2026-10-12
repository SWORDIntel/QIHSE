#include "qihse_consensus_prefix_challenge.h"

#include <string.h>

#define QPC_DOMAIN "QIHSE-CONSENSUS-PREFIX-CHALLENGE-v1"
#define QPC_FRAME_MAX (sizeof(QPC_DOMAIN) - 1u + \
    QIHSE_CONSENSUS_PREFIX_CHALLENGE_BYTES + QIHSE_UUID_BYTES + 1u + 2u + \
    QIHSE_FEDERATION_SIG_MAX_BYTES)

static bool nonzero(const uint8_t* p, size_t n) {
    uint8_t bits = 0u;
    for (size_t i = 0u; i < n; ++i) bits |= p[i];
    return bits != 0u;
}

/* Bind the challenge to the exact signed prefix statement. Its signature
 * authenticates all evidence and identity fields using the canonical QPA
 * encoding, so the response need only bind those signed bytes. */
static bool make_frame(
    const qihse_consensus_prefix_challenge_response_t* response,
    uint8_t out[QPC_FRAME_MAX], size_t* out_len) {
    if (!response || !out || !out_len ||
        !nonzero(response->challenge, sizeof(response->challenge)) ||
        response->prefix.signature_len == 0u ||
        response->prefix.signature_len > QIHSE_FEDERATION_SIG_MAX_BYTES ||
        response->prefix.signature_len > UINT16_MAX ||
        qihse_sig_alg_signature_bytes(response->prefix.sig_alg) !=
            response->prefix.signature_len) return false;

    size_t n = 0u;
    memcpy(out + n, QPC_DOMAIN, sizeof(QPC_DOMAIN) - 1u);
    n += sizeof(QPC_DOMAIN) - 1u;
    memcpy(out + n, response->challenge, sizeof(response->challenge));
    n += sizeof(response->challenge);
    memcpy(out + n, response->prefix.signer_node.bytes, QIHSE_UUID_BYTES);
    n += QIHSE_UUID_BYTES;
    out[n++] = (uint8_t)response->prefix.sig_alg;
    out[n++] = (uint8_t)(response->prefix.signature_len >> 8u);
    out[n++] = (uint8_t)response->prefix.signature_len;
    memcpy(out + n, response->prefix.signature,
           response->prefix.signature_len);
    n += response->prefix.signature_len;
    *out_len = n;
    return n <= QPC_FRAME_MAX;
}

bool qihse_consensus_prefix_challenge_respond_user(
    void* source, qihse_consensus_prefix_export_user_fn export_user,
    const qihse_user_t* requester,
    void* store, void* store_user, const qihse_uuid_t* signer_node,
    const qihse_consensus_prefix_expected_t* expected,
    uint64_t max_entries,
    const uint8_t challenge[QIHSE_CONSENSUS_PREFIX_CHALLENGE_BYTES],
    qihse_consensus_prefix_challenge_response_t* out) {
    if (out) memset(out, 0, sizeof(*out));
    if (!source || !export_user || !requester || !store || !store_user ||
        !signer_node || !expected || !challenge || !out ||
        !nonzero(challenge, QIHSE_CONSENSUS_PREFIX_CHALLENGE_BYTES))
        return false;
    if (!qihse_consensus_prefix_attest_user(
            source, export_user, requester, store, store_user, signer_node,
            expected, max_entries, &out->prefix)) goto fail;
    memcpy(out->challenge, challenge, sizeof(out->challenge));

    qihse_federation_node_identity_t identity;
    if (!qihse_federation_node_lookup(store, store_user, signer_node,
                                      &identity) ||
        identity.trust != QIHSE_TRUST_APPROVED ||
        identity.sig_alg != out->prefix.sig_alg ||
        !qihse_uuid_equal(&identity.node_id, signer_node) ||
        memcmp(identity.fingerprint, out->prefix.signer_fingerprint,
               sizeof(identity.fingerprint)) != 0) goto fail;

    uint8_t frame[QPC_FRAME_MAX];
    size_t frame_len = 0u;
    if (!make_frame(out, frame, &frame_len)) goto fail;
    void* key = qihse_federation_node_key_load(identity.key_handle);
    if (!key) goto fail;
    qihse_sig_alg_t key_alg;
    bool ok = qihse_federation_pkey_sig_alg(key, &key_alg) &&
        key_alg == out->prefix.sig_alg;
    if (ok) {
        out->response_signature_len = sizeof(out->response_signature);
        ok = qihse_federation_sign(key, frame, frame_len,
            out->response_signature, &out->response_signature_len);
    }
    qihse_federation_node_key_free(key);
    if (!ok) goto fail;
    return true;
fail:
    memset(out, 0, sizeof(*out));
    return false;
}

bool qihse_consensus_prefix_challenge_verify_user(
    void* store, void* store_user,
    const qihse_consensus_prefix_expected_t* expected,
    const uint8_t expected_challenge[QIHSE_CONSENSUS_PREFIX_CHALLENGE_BYTES],
    const qihse_consensus_prefix_challenge_response_t* response) {
    if (!store || !store_user || !expected || !expected_challenge ||
        !response ||
        !nonzero(expected_challenge, QIHSE_CONSENSUS_PREFIX_CHALLENGE_BYTES) ||
        memcmp(expected_challenge, response->challenge,
               QIHSE_CONSENSUS_PREFIX_CHALLENGE_BYTES) != 0 ||
        !qihse_consensus_prefix_attestation_verify_user(
            store, store_user, expected, &response->prefix) ||
        response->response_signature_len !=
            qihse_sig_alg_signature_bytes(response->prefix.sig_alg))
        return false;

    qihse_federation_node_identity_t identity;
    if (!qihse_federation_node_lookup(store, store_user,
                                      &response->prefix.signer_node,
                                      &identity) ||
        identity.trust != QIHSE_TRUST_APPROVED ||
        identity.sig_alg != response->prefix.sig_alg ||
        !qihse_uuid_equal(&identity.node_id,
                          &response->prefix.signer_node) ||
        identity.public_key_len !=
            qihse_sig_alg_public_key_bytes(identity.sig_alg) ||
        memcmp(identity.fingerprint,
               response->prefix.signer_fingerprint,
               sizeof(identity.fingerprint)) != 0) return false;

    uint8_t frame[QPC_FRAME_MAX];
    size_t frame_len = 0u;
    return make_frame(response, frame, &frame_len) &&
        qihse_federation_verify(identity.sig_alg, identity.public_key,
            identity.public_key_len, frame, frame_len,
            response->response_signature,
            response->response_signature_len);
}
