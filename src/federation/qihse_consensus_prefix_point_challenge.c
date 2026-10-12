#include "qihse_consensus_prefix_point_challenge.h"

#include <string.h>

#define POINT_DOMAIN "QIHSE-CONSENSUS-PREFIX-POINT-CHALLENGE-v1"
#define POINT_FRAME_MAX (sizeof(POINT_DOMAIN) - 1u + 8u + \
    QIHSE_CONSENSUS_PREFIX_CHALLENGE_BYTES + QIHSE_UUID_BYTES + 1u + 2u + \
    QIHSE_FEDERATION_SIG_MAX_BYTES)

typedef struct {
    qihse_consensus_mesh_t* mesh;
    uint64_t index;
    uint64_t observed;
} point_export_t;

static bool nonzero(const uint8_t* bytes, size_t length) {
    uint8_t bits = 0u;
    for (size_t i = 0u; i < length; ++i) bits |= bytes[i];
    return bits != 0u;
}

static void put_u64(uint8_t out[8], uint64_t value) {
    for (size_t i = 0u; i < 8u; ++i)
        out[i] = (uint8_t)(value >> (56u - 8u * i));
}

static bool export_point_user(
    void* source, const qihse_user_t* requester, uint64_t max_entries,
    qihse_consensus_prefix_evidence_t* out) {
    if (out) memset(out, 0, sizeof(*out));
    point_export_t* ctx = (point_export_t*)source;
    if (!ctx || !ctx->mesh || !requester || !out ||
        ctx->index > max_entries ||
        max_entries > QIHSE_MESH_EVIDENCE_MAX_ENTRIES) return false;
    qihse_consensus_mesh_prefix_point_t point;
    memset(&point, 0, sizeof(point));
    if (!qihse_consensus_mesh_export_prefix_point_user(
            ctx->mesh, requester, ctx->index, &point) ||
        point.prefix.commit_index != ctx->index ||
        point.observed_commit_index < ctx->index) return false;
    memcpy(out->group_id, point.prefix.group_id, sizeof(out->group_id));
    memcpy(out->history_id, point.prefix.history_id, sizeof(out->history_id));
    out->writer_epoch_floor = point.prefix.writer_epoch_floor;
    out->commit_index = point.prefix.commit_index;
    memcpy(out->committed_prefix_sha256,
           point.prefix.committed_prefix_sha256,
           sizeof(out->committed_prefix_sha256));
    out->member_uuid = point.prefix.member_uuid;
    memcpy(out->qkp_node_id, point.prefix.qkp_node_id,
           sizeof(out->qkp_node_id));
    ctx->observed = point.observed_commit_index;
    return true;
}

static bool frame(const qihse_consensus_prefix_point_challenge_t* response,
                  uint8_t out[POINT_FRAME_MAX], size_t* out_len) {
    if (!response || !out || !out_len ||
        !nonzero(response->challenge, sizeof(response->challenge)) ||
        response->observed_commit_index < response->prefix.evidence.commit_index ||
        response->prefix.signature_len == 0u ||
        response->prefix.signature_len > QIHSE_FEDERATION_SIG_MAX_BYTES ||
        response->prefix.signature_len > UINT16_MAX ||
        response->prefix.signature_len !=
            qihse_sig_alg_signature_bytes(response->prefix.sig_alg)) return false;
    size_t n = 0u;
    memcpy(out + n, POINT_DOMAIN, sizeof(POINT_DOMAIN) - 1u);
    n += sizeof(POINT_DOMAIN) - 1u;
    put_u64(out + n, response->observed_commit_index); n += 8u;
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
    return n <= POINT_FRAME_MAX;
}

bool qihse_consensus_mesh_prefix_point_challenge_respond_user(
    qihse_consensus_mesh_t* mesh, const qihse_user_t* requester,
    void* store, void* store_user, const qihse_uuid_t* signer_node,
    const qihse_consensus_prefix_expected_t* expected,
    uint64_t requested_index,
    const uint8_t challenge[QIHSE_CONSENSUS_PREFIX_CHALLENGE_BYTES],
    qihse_consensus_prefix_point_challenge_t* out) {
    if (out) memset(out, 0, sizeof(*out));
    if (!mesh || !requester || !store || !store_user || !signer_node ||
        !expected || !challenge || !out ||
        requested_index > QIHSE_MESH_EVIDENCE_MAX_ENTRIES ||
        !nonzero(challenge, QIHSE_CONSENSUS_PREFIX_CHALLENGE_BYTES)) return false;
    point_export_t source = {mesh, requested_index, 0u};
    if (!qihse_consensus_prefix_attest_user(
            &source, export_point_user, requester, store, store_user,
            signer_node, expected, requested_index, &out->prefix)) goto fail;
    out->observed_commit_index = source.observed;
    memcpy(out->challenge, challenge, sizeof(out->challenge));
    qihse_federation_node_identity_t identity;
    if (!qihse_federation_node_lookup(store, store_user, signer_node,
                                      &identity) ||
        identity.trust != QIHSE_TRUST_APPROVED ||
        identity.sig_alg != out->prefix.sig_alg ||
        !qihse_uuid_equal(&identity.node_id, signer_node) ||
        memcmp(identity.fingerprint, out->prefix.signer_fingerprint,
               sizeof(identity.fingerprint)) != 0) goto fail;
    uint8_t bytes[POINT_FRAME_MAX];
    size_t length = 0u;
    if (!frame(out, bytes, &length)) goto fail;
    void* key = qihse_federation_node_key_load(identity.key_handle);
    if (!key) goto fail;
    qihse_sig_alg_t key_alg;
    bool ok = qihse_federation_pkey_sig_alg(key, &key_alg) &&
        key_alg == out->prefix.sig_alg;
    if (ok) {
        out->signature_len = sizeof(out->signature);
        ok = qihse_federation_sign(key, bytes, length, out->signature,
                                   &out->signature_len);
    }
    qihse_federation_node_key_free(key);
    if (!ok) goto fail;
    return true;
fail:
    memset(out, 0, sizeof(*out));
    return false;
}

bool qihse_consensus_prefix_point_challenge_verify_user(
    void* store, void* store_user,
    const qihse_consensus_prefix_expected_t* expected,
    uint64_t requested_index,
    const uint8_t challenge[QIHSE_CONSENSUS_PREFIX_CHALLENGE_BYTES],
    const qihse_consensus_prefix_point_challenge_t* response) {
    if (!store || !store_user || !expected || !challenge || !response ||
        requested_index > QIHSE_MESH_EVIDENCE_MAX_ENTRIES ||
        !nonzero(challenge, QIHSE_CONSENSUS_PREFIX_CHALLENGE_BYTES) ||
        memcmp(challenge, response->challenge,
               QIHSE_CONSENSUS_PREFIX_CHALLENGE_BYTES) != 0 ||
        response->prefix.evidence.commit_index != requested_index ||
        !qihse_consensus_prefix_attestation_verify_user(
            store, store_user, expected, &response->prefix) ||
        response->signature_len !=
            qihse_sig_alg_signature_bytes(response->prefix.sig_alg)) return false;
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
    uint8_t bytes[POINT_FRAME_MAX];
    size_t length = 0u;
    return frame(response, bytes, &length) &&
        qihse_federation_verify(identity.sig_alg, identity.public_key,
            identity.public_key_len, bytes, length, response->signature,
            response->signature_len);
}
