#include "qihse_analysis_artifact.h"

#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <stdlib.h>
#include <string.h>

static bool text_valid(const char* text, size_t cap) {
    size_t end = 0;
    while (end < cap && text[end]) {
        unsigned char c = (unsigned char)text[end];
        if (c < 0x20u || c > 0x7eu) return false;
        end++;
    }
    if (end == 0 || end == cap) return false;
    for (size_t i = end + 1; i < cap; i++) {
        if (text[i]) return false; /* no hidden data or alternate encodings */
    }
    return true;
}

static bool nonzero_bytes(const uint8_t* bytes, size_t count) {
    uint8_t any = 0;
    for (size_t i = 0; i < count; i++) any |= bytes[i];
    return any != 0;
}

static bool fields_valid(const qihse_analysis_artifact_v1_t* m) {
    if (!m || m->version != QIHSE_ANALYSIS_ARTIFACT_VERSION ||
        m->kind < QIHSE_ANALYSIS_BINARY || m->kind > QIHSE_ANALYSIS_REPORT ||
        m->completion < QIHSE_ANALYSIS_PARTIAL || m->completion > QIHSE_ANALYSIS_COMPLETE ||
        m->fidelity < QIHSE_ANALYSIS_FIDELITY_UNASSESSED ||
        m->fidelity > QIHSE_ANALYSIS_FIDELITY_VALIDATED ||
        m->tenant_id == QIHSE_TENANT_SYSTEM || m->tenant_id == QIHSE_TENANT_INVALID ||
        m->generation == 0 || !nonzero_bytes(m->run_id, sizeof(m->run_id)) ||
        !nonzero_bytes(m->binary_sha384, sizeof(m->binary_sha384)) ||
        m->payload_size == 0 || m->payload_size > QIHSE_BLOB_MAX_SIZE ||
        m->input_count > QIHSE_ANALYSIS_ARTIFACT_MAX_INPUTS ||
        !text_valid(m->artifact_schema, sizeof(m->artifact_schema)) ||
        !text_valid(m->producer, sizeof(m->producer)) ||
        !text_valid(m->producer_version, sizeof(m->producer_version)) ||
        !text_valid(m->isa, sizeof(m->isa)) ||
        !text_valid(m->mode, sizeof(m->mode)) ||
        !nonzero_bytes(m->payload_sha384, sizeof(m->payload_sha384))) return false;
    if (m->fidelity == QIHSE_ANALYSIS_FIDELITY_VALIDATED &&
        m->completion != QIHSE_ANALYSIS_COMPLETE) return false;
    if (m->kind == QIHSE_ANALYSIS_BINARY) {
        if (m->input_count != 0 ||
            memcmp(m->binary_sha384, m->payload_sha384, QIHSE_BLOB_HASH_BYTES) != 0)
            return false;
    } else if (m->input_count == 0 || m->address_bits == 0)
        return false;
    if (m->address_bits > 128) return false;
    for (size_t i = 0; i < QIHSE_ANALYSIS_ARTIFACT_MAX_INPUTS; i++) {
        if (i < m->input_count) {
            if (!nonzero_bytes(m->input_ids[i], QIHSE_BLOB_HASH_BYTES)) return false;
            for (size_t j = 0; j < i; j++) {
                if (memcmp(m->input_ids[i], m->input_ids[j], QIHSE_BLOB_HASH_BYTES) == 0)
                    return false;
            }
        } else {
            uint8_t any = 0;
            for (size_t k = 0; k < QIHSE_BLOB_HASH_BYTES; k++) any |= m->input_ids[i][k];
            if (any) return false;
        }
    }
    return true;
}

static bool hash_bytes(EVP_MD_CTX* ctx, const void* data, size_t len) {
    return EVP_DigestUpdate(ctx, data, len) == 1;
}

static bool hash_u16(EVP_MD_CTX* ctx, uint16_t value) {
    uint8_t bytes[2] = { (uint8_t)(value >> 8), (uint8_t)value };
    return hash_bytes(ctx, bytes, sizeof(bytes));
}

static bool hash_u32(EVP_MD_CTX* ctx, uint32_t value) {
    uint8_t bytes[4];
    for (size_t i = 0; i < 4; i++) bytes[i] = (uint8_t)(value >> (24u - 8u * i));
    return hash_bytes(ctx, bytes, sizeof(bytes));
}

static bool hash_u64(EVP_MD_CTX* ctx, uint64_t value) {
    uint8_t bytes[8];
    for (size_t i = 0; i < 8; i++) bytes[i] = (uint8_t)(value >> (56u - 8u * i));
    return hash_bytes(ctx, bytes, sizeof(bytes));
}

bool qihse_analysis_artifact_compute_id(const qihse_analysis_artifact_v1_t* m,
                                        uint8_t out_id[QIHSE_BLOB_HASH_BYTES]) {
    static const uint8_t domain[] = "QIHSE/KP14/analysis-artifact/v1";
    if (!out_id || !fields_valid(m)) return false;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return false;
    bool ok = EVP_DigestInit_ex(ctx, EVP_sha384(), NULL) == 1 &&
              hash_bytes(ctx, domain, sizeof(domain)) &&
              hash_u16(ctx, m->version) && hash_u16(ctx, m->kind) &&
              hash_u16(ctx, m->completion) && hash_u16(ctx, m->fidelity) &&
              hash_u32(ctx, m->tenant_id) && hash_u16(ctx, m->classification) &&
              hash_u16(ctx, m->sci) &&
              hash_bytes(ctx, m->artifact_schema, sizeof(m->artifact_schema)) &&
              hash_bytes(ctx, m->producer, sizeof(m->producer)) &&
              hash_bytes(ctx, m->producer_version, sizeof(m->producer_version)) &&
              hash_bytes(ctx, m->run_id, sizeof(m->run_id)) &&
              hash_u64(ctx, m->generation) &&
              hash_bytes(ctx, m->binary_sha384, sizeof(m->binary_sha384)) &&
              hash_bytes(ctx, m->isa, sizeof(m->isa)) &&
              hash_bytes(ctx, m->mode, sizeof(m->mode)) &&
              hash_u16(ctx, m->address_bits) &&
              hash_bytes(ctx, m->isanity_catalogue_sha384,
                         sizeof(m->isanity_catalogue_sha384)) &&
              hash_bytes(ctx, m->vexel_pack_sha384, sizeof(m->vexel_pack_sha384)) &&
              hash_u64(ctx, m->payload_size) &&
              hash_bytes(ctx, m->payload_sha384, sizeof(m->payload_sha384)) &&
              hash_bytes(ctx, &m->input_count, 1);
    for (size_t i = 0; ok && i < m->input_count; i++)
        ok = hash_bytes(ctx, m->input_ids[i], QIHSE_BLOB_HASH_BYTES);
    unsigned int out_len = 0;
    uint8_t digest[QIHSE_BLOB_HASH_BYTES];
    if (ok) ok = EVP_DigestFinal_ex(ctx, digest, &out_len) == 1 &&
                 out_len == QIHSE_BLOB_HASH_BYTES;
    EVP_MD_CTX_free(ctx);
    if (ok) memcpy(out_id, digest, sizeof(digest));
    return ok;
}

bool qihse_analysis_artifact_validate(const qihse_analysis_artifact_v1_t* m) {
    uint8_t computed[QIHSE_BLOB_HASH_BYTES];
    return m && qihse_analysis_artifact_compute_id(m, computed) &&
           memcmp(computed, m->artifact_id, sizeof(computed)) == 0;
}

bool qihse_analysis_artifact_authorize_user(const qihse_analysis_artifact_v1_t* m,
                                            const qihse_user_t* user) {
    if (!user || !qihse_auth_user_is_active(user) ||
        !qihse_analysis_artifact_validate(m)) return false;
    uint32_t tenant = qihse_user_get_tenant_id(user);
    if (tenant == QIHSE_TENANT_SYSTEM) {
        if (qihse_user_get_role(user) != QIHSE_ROLE_OPERATOR) return false;
    } else if (tenant != m->tenant_id) return false;
    return qihse_auth_can_access(user, m->classification, m->sci);
}

bool qihse_analysis_artifact_authorize_publisher(const qihse_analysis_artifact_v1_t* m,
                                                 const qihse_user_t* publisher) {
    if (!publisher || !qihse_auth_user_is_active(publisher) ||
        !qihse_analysis_artifact_validate(m)) return false;
    uint16_t role = qihse_user_get_role(publisher);
    uint32_t tenant = qihse_user_get_tenant_id(publisher);
    if (role != QIHSE_ROLE_OPERATOR && role != QIHSE_ROLE_ANALYST) return false;
    if (tenant == QIHSE_TENANT_SYSTEM) {
        if (role != QIHSE_ROLE_OPERATOR) return false;
    } else if (tenant != m->tenant_id) return false;
    return qihse_auth_can_access(publisher, m->classification, m->sci) &&
           qihse_auth_can_access_object(publisher, QIHSE_ANALYSIS_PUBLISH_ACL_NAMESPACE,
                                        m->tenant_id, QIHSE_ACL_WRITE);
}

qihse_analysis_preflight_result_t qihse_analysis_artifact_preflight_user(
    const qihse_analysis_artifact_v1_t* m, qihse_user_t* publisher,
    qihse_blob_read_fn payload_reader, void* reader_opaque) {
    if (!publisher || !qihse_auth_user_is_active(publisher))
        return QIHSE_ANALYSIS_PREFLIGHT_DENIED;
    if (!qihse_analysis_artifact_validate(m) || !payload_reader)
        return QIHSE_ANALYSIS_PREFLIGHT_INVALID;
    if (!qihse_analysis_artifact_authorize_publisher(m, publisher))
        return QIHSE_ANALYSIS_PREFLIGHT_DENIED;

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return QIHSE_ANALYSIS_PREFLIGHT_READ_ERROR;
    qihse_analysis_preflight_result_t result = QIHSE_ANALYSIS_PREFLIGHT_READ_ERROR;
    uint8_t* chunk = malloc(QIHSE_BLOB_CHUNK_SIZE);
    uint8_t digest[QIHSE_BLOB_HASH_BYTES];
    unsigned int digest_size = 0;
    uint64_t total = 0;
    if (!chunk) goto done;
    if (EVP_DigestInit_ex(ctx, EVP_sha384(), NULL) != 1) goto done;
    for (;;) {
        int64_t n = payload_reader(reader_opaque, chunk, QIHSE_BLOB_CHUNK_SIZE);
        if (n < 0 || n > QIHSE_BLOB_CHUNK_SIZE) goto done;
        if (n == 0) break;
        if ((uint64_t)n > m->payload_size - total) {
            result = QIHSE_ANALYSIS_PREFLIGHT_PAYLOAD_MISMATCH;
            goto done;
        }
        if (EVP_DigestUpdate(ctx, chunk, (size_t)n) != 1) goto done;
        total += (uint64_t)n;
    }
    if (EVP_DigestFinal_ex(ctx, digest, &digest_size) != 1) goto done;
    if (total != m->payload_size || digest_size != QIHSE_BLOB_HASH_BYTES ||
        CRYPTO_memcmp(digest, m->payload_sha384, sizeof(digest)) != 0) {
        result = QIHSE_ANALYSIS_PREFLIGHT_PAYLOAD_MISMATCH;
        goto done;
    }
    /* Revocation or ACL changes during a long stream must not yield success. */
    if (!qihse_analysis_artifact_authorize_publisher(m, publisher)) {
        result = QIHSE_ANALYSIS_PREFLIGHT_DENIED;
        goto done;
    }
    result = m->kind == QIHSE_ANALYSIS_BINARY && m->input_count == 0
                 ? QIHSE_ANALYSIS_PREFLIGHT_BINARY_VERIFIED
                 : QIHSE_ANALYSIS_PREFLIGHT_LINEAGE_UNRESOLVED;
done:
    free(chunk);
    EVP_MD_CTX_free(ctx);
    return result;
}
