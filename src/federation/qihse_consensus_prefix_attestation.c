#include "qihse_consensus_prefix_attestation.h"

#include <string.h>

/* Canonical signed region, with no native structs, padding, or byte order. */
#define QPA_DOMAIN "QIHSE-CONSENSUS-PREFIX-ATTESTATION-v1"
#define QPA_FRAME_MAX (sizeof(QPA_DOMAIN) - 1u + 1u + QIHSE_CONSENSUS_GROUP_ID_MAX + 32u + \
    8u + 8u + 32u + QIHSE_UUID_BYTES + 1u + QIHSE_QKP_NODE_ID_LEN + \
    QIHSE_UUID_BYTES + QIHSE_FEDERATION_NODE_FINGERPRINT_BYTES + 1u)

static void put_u64(uint8_t* p, uint64_t value) {
    for (size_t i = 0; i < 8u; ++i)
        p[i] = (uint8_t)(value >> (56u - 8u * i));
}

static bool nonzero(const uint8_t* p, size_t n) {
    uint8_t bits = 0;
    for (size_t i = 0; i < n; ++i) bits |= p[i];
    return bits != 0;
}

static bool frame(const qihse_consensus_prefix_attestation_t* s,
                  uint8_t out[QPA_FRAME_MAX], size_t* out_len) {
    static const uint8_t domain[] = QPA_DOMAIN;
    const qihse_consensus_prefix_evidence_t* e = &s->evidence;
    size_t group_len = strnlen(e->group_id, sizeof(e->group_id));
    size_t qkp_len = strnlen(e->qkp_node_id, sizeof(e->qkp_node_id));
    if (group_len == 0 || group_len > QIHSE_CONSENSUS_GROUP_ID_MAX ||
        qkp_len == 0 || qkp_len > QIHSE_QKP_NODE_ID_LEN ||
        e->writer_epoch_floor == 0 || !nonzero(e->history_id, 32u) ||
        qihse_uuid_is_nil(&e->member_uuid) ||
        qihse_uuid_is_nil(&s->signer_node) ||
        !nonzero(s->signer_fingerprint, sizeof(s->signer_fingerprint)) ||
        (e->commit_index == 0 && nonzero(e->committed_prefix_sha256, 32u)) ||
        (e->commit_index != 0 && !nonzero(e->committed_prefix_sha256, 32u)) ||
        qihse_sig_alg_signature_bytes(s->sig_alg) == 0) return false;

    size_t n = 0;
#define COPY(bytes, count) do { memcpy(out + n, (bytes), (count)); n += (count); } while (0)
    COPY(domain, sizeof(domain) - 1u);
    out[n++] = (uint8_t)group_len;
    COPY(e->group_id, group_len);
    COPY(e->history_id, 32u);
    put_u64(out + n, e->writer_epoch_floor); n += 8u;
    put_u64(out + n, e->commit_index); n += 8u;
    COPY(e->committed_prefix_sha256, 32u);
    COPY(e->member_uuid.bytes, QIHSE_UUID_BYTES);
    out[n++] = (uint8_t)qkp_len;
    COPY(e->qkp_node_id, qkp_len);
    COPY(s->signer_node.bytes, QIHSE_UUID_BYTES);
    COPY(s->signer_fingerprint, QIHSE_FEDERATION_NODE_FINGERPRINT_BYTES);
    out[n++] = (uint8_t)s->sig_alg;
#undef COPY
    *out_len = n;
    return n <= QPA_FRAME_MAX;
}

static bool identity_matches(void* store, void* store_user,
                             const qihse_uuid_t* signer,
                             const uint8_t fingerprint[QIHSE_FEDERATION_NODE_FINGERPRINT_BYTES],
                             qihse_sig_alg_t alg,
                             qihse_federation_node_identity_t* out) {
    uint8_t computed[QIHSE_FEDERATION_NODE_FINGERPRINT_BYTES];
    if (!store || !store_user || !signer || !out ||
        !qihse_federation_node_lookup(store, store_user, signer, out) ||
        out->trust != QIHSE_TRUST_APPROVED || out->sig_alg != alg ||
        !qihse_uuid_equal(&out->node_id, signer) ||
        out->public_key_len != qihse_sig_alg_public_key_bytes(alg) ||
        !qihse_federation_node_fingerprint(out->public_key,
            out->public_key_len, computed)) return false;
    return memcmp(computed, out->fingerprint, sizeof(computed)) == 0 &&
           memcmp(computed, fingerprint, sizeof(computed)) == 0;
}

static bool evidence_matches_expected(
    const qihse_consensus_prefix_expected_t* expected,
    const qihse_consensus_prefix_attestation_t* statement) {
    if (!expected || !statement) return false;
    const qihse_consensus_prefix_evidence_t* e = &statement->evidence;
    return strncmp(e->group_id, expected->group_id,
                   sizeof(e->group_id)) == 0 &&
           memcmp(e->history_id, expected->history_id, 32u) == 0 &&
           e->writer_epoch_floor == expected->writer_epoch_floor &&
           qihse_uuid_equal(&e->member_uuid, &expected->member_uuid) &&
           strncmp(e->qkp_node_id, expected->qkp_node_id,
                   sizeof(e->qkp_node_id)) == 0 &&
           qihse_uuid_equal(&statement->signer_node,
                            &expected->signer_node);
}

bool qihse_consensus_prefix_attestation_verify_user(
    void* store, void* store_user,
    const qihse_consensus_prefix_expected_t* expected,
    const qihse_consensus_prefix_attestation_t* statement) {
    if (!evidence_matches_expected(expected, statement) ||
        statement->signature_len != qihse_sig_alg_signature_bytes(statement->sig_alg))
        return false;
    uint8_t bytes[QPA_FRAME_MAX]; size_t n = 0;
    if (!frame(statement, bytes, &n)) return false;
    qihse_federation_node_identity_t identity;
    if (!identity_matches(store, store_user, &statement->signer_node,
                          statement->signer_fingerprint, statement->sig_alg,
                          &identity)) return false;
    return qihse_federation_verify(statement->sig_alg, identity.public_key,
        identity.public_key_len, bytes, n, statement->signature,
        statement->signature_len);
}

bool qihse_consensus_prefix_attest_user(
    void* source, qihse_consensus_prefix_export_user_fn export_user,
    const qihse_user_t* requester,
    void* store, void* store_user, const qihse_uuid_t* signer_node,
    const qihse_consensus_prefix_expected_t* expected,
    uint64_t max_entries, qihse_consensus_prefix_attestation_t* out) {
    if (out) memset(out, 0, sizeof(*out));
    if (!source || !export_user || !requester || !signer_node || !expected ||
        !out || !store || !store_user) return false;
    if (!export_user(source, requester, max_entries, &out->evidence) ||
        out->evidence.commit_index > max_entries) goto fail;
    out->signer_node = *signer_node;
    if (!evidence_matches_expected(expected, out)) goto fail;
    qihse_federation_node_identity_t identity;
    if (!qihse_federation_node_lookup(store, store_user, signer_node,
                                      &identity) ||
        identity.trust != QIHSE_TRUST_APPROVED ||
        !qihse_uuid_equal(&identity.node_id, signer_node)) goto fail;
    out->sig_alg = identity.sig_alg;
    memcpy(out->signer_fingerprint, identity.fingerprint,
           sizeof(out->signer_fingerprint));
    if (!identity_matches(store, store_user, signer_node,
                          out->signer_fingerprint, out->sig_alg,
                          &identity)) goto fail;
    void* key = qihse_federation_node_key_load(identity.key_handle);
    if (!key) goto fail;
    qihse_sig_alg_t key_alg;
    uint8_t bytes[QPA_FRAME_MAX]; size_t n = 0;
    bool ok = qihse_federation_pkey_sig_alg(key, &key_alg) &&
        key_alg == out->sig_alg && frame(out, bytes, &n);
    if (ok) {
        out->signature_len = sizeof(out->signature);
        ok = qihse_federation_sign(key, bytes, n, out->signature,
                                   &out->signature_len);
    }
    qihse_federation_node_key_free(key);
    if (!ok) goto fail;
    if (qihse_consensus_prefix_attestation_verify_user(
            store, store_user, expected, out)) return true;
fail:
    memset(out, 0, sizeof(*out));
    return false;
}
