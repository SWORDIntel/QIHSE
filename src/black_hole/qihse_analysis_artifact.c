#include "qihse_analysis_artifact.h"
#include "qihse_audit.h"

#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

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

/* ═══════════════════════════════════════════════════════════════════════════
 * Durable Analysis Artifact Store & KEYSTONE Feed Projection
 * ═══════════════════════════════════════════════════════════════════════════ */

static void put_u16_be(uint8_t* p, uint16_t v) {
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

static uint16_t get_u16_be(const uint8_t* p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

static void put_u32_be(uint8_t* p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static uint32_t get_u32_be(const uint8_t* p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void put_u64_be(uint8_t* p, uint64_t v) {
    for (size_t i = 0; i < 8; i++) {
        p[i] = (uint8_t)(v >> (56u - 8u * i));
    }
}

static uint64_t get_u64_be(const uint8_t* p) {
    uint64_t v = 0;
    for (size_t i = 0; i < 8; i++) {
        v = (v << 8) | (uint64_t)p[i];
    }
    return v;
}

#define QIHSE_ANALYSIS_PROJ_MAGIC 0x4B505052u /* "KPPR" */
#define QIHSE_ANALYSIS_PROJ_VERSION 1u
#define QIHSE_ANALYSIS_PROJ_HEADER_BYTES 520u

bool qihse_analysis_projection_encode(const qihse_analysis_projection_t* proj,
                                     uint8_t* out, size_t out_cap, size_t* out_len) {
    if (!proj || !out || out_cap < QIHSE_ANALYSIS_PROJ_HEADER_BYTES) return false;
    if (proj->input_count > QIHSE_ANALYSIS_ARTIFACT_MAX_INPUTS) return false;
    size_t needed = QIHSE_ANALYSIS_PROJ_HEADER_BYTES + (size_t)proj->input_count * QIHSE_BLOB_HASH_BYTES;
    if (out_cap < needed) return false;

    uint8_t* p = out;
    put_u32_be(p, QIHSE_ANALYSIS_PROJ_MAGIC); p += 4;
    put_u16_be(p, QIHSE_ANALYSIS_PROJ_VERSION); p += 2;
    put_u64_be(p, proj->payload_size); p += 8;
    put_u64_be(p, proj->generation); p += 8;
    put_u32_be(p, proj->tenant_id); p += 4;
    put_u16_be(p, proj->classification); p += 2;
    put_u16_be(p, proj->sci); p += 2;
    put_u16_be(p, proj->kind); p += 2;
    put_u16_be(p, proj->completion); p += 2;
    put_u16_be(p, proj->fidelity); p += 2;
    put_u16_be(p, proj->address_bits); p += 2;
    *p++ = proj->is_tombstone ? 1u : 0u;
    *p++ = proj->input_count;

    memcpy(p, proj->artifact_id, QIHSE_BLOB_HASH_BYTES); p += QIHSE_BLOB_HASH_BYTES;
    memcpy(p, proj->binary_sha384, QIHSE_BLOB_HASH_BYTES); p += QIHSE_BLOB_HASH_BYTES;
    memcpy(p, proj->payload_sha384, QIHSE_BLOB_HASH_BYTES); p += QIHSE_BLOB_HASH_BYTES;
    memcpy(p, proj->artifact_schema, QIHSE_ANALYSIS_ARTIFACT_TEXT_BYTES); p += QIHSE_ANALYSIS_ARTIFACT_TEXT_BYTES;
    memcpy(p, proj->producer, QIHSE_ANALYSIS_ARTIFACT_TEXT_BYTES); p += QIHSE_ANALYSIS_ARTIFACT_TEXT_BYTES;
    memcpy(p, proj->producer_version, QIHSE_ANALYSIS_ARTIFACT_TEXT_BYTES); p += QIHSE_ANALYSIS_ARTIFACT_TEXT_BYTES;
    memcpy(p, proj->isa, QIHSE_ANALYSIS_ARTIFACT_CONTEXT_BYTES); p += QIHSE_ANALYSIS_ARTIFACT_CONTEXT_BYTES;
    memcpy(p, proj->mode, QIHSE_ANALYSIS_ARTIFACT_CONTEXT_BYTES); p += QIHSE_ANALYSIS_ARTIFACT_CONTEXT_BYTES;
    memcpy(p, proj->tombstone_reason, QIHSE_ANALYSIS_ARTIFACT_TEXT_BYTES); p += QIHSE_ANALYSIS_ARTIFACT_TEXT_BYTES;

    for (size_t i = 0; i < proj->input_count; i++) {
        memcpy(p, proj->input_ids[i], QIHSE_BLOB_HASH_BYTES);
        p += QIHSE_BLOB_HASH_BYTES;
    }
    if (out_len) *out_len = needed;
    return true;
}

bool qihse_analysis_projection_decode(const uint8_t* in, size_t in_len,
                                     qihse_analysis_projection_t* out_proj) {
    if (!in || in_len < QIHSE_ANALYSIS_PROJ_HEADER_BYTES || !out_proj) return false;
    memset(out_proj, 0, sizeof(*out_proj));
    const uint8_t* p = in;

    if (get_u32_be(p) != QIHSE_ANALYSIS_PROJ_MAGIC) {
        return false;
    }
    p += 4;
    if (get_u16_be(p) != QIHSE_ANALYSIS_PROJ_VERSION) {
        return false;
    }
    p += 2;
    out_proj->payload_size = get_u64_be(p); p += 8;
    out_proj->generation = get_u64_be(p); p += 8;
    out_proj->tenant_id = get_u32_be(p); p += 4;
    out_proj->classification = get_u16_be(p); p += 2;
    out_proj->sci = get_u16_be(p); p += 2;
    out_proj->kind = get_u16_be(p); p += 2;
    out_proj->completion = get_u16_be(p); p += 2;
    out_proj->fidelity = get_u16_be(p); p += 2;
    out_proj->address_bits = get_u16_be(p); p += 2;
    out_proj->is_tombstone = (*p++ != 0);
    out_proj->input_count = *p++;

    if (out_proj->input_count > QIHSE_ANALYSIS_ARTIFACT_MAX_INPUTS) return false;
    size_t expected_len = QIHSE_ANALYSIS_PROJ_HEADER_BYTES + (size_t)out_proj->input_count * QIHSE_BLOB_HASH_BYTES;
    if (in_len != expected_len) return false;

    memcpy(out_proj->artifact_id, p, QIHSE_BLOB_HASH_BYTES); p += QIHSE_BLOB_HASH_BYTES;
    memcpy(out_proj->binary_sha384, p, QIHSE_BLOB_HASH_BYTES); p += QIHSE_BLOB_HASH_BYTES;
    memcpy(out_proj->payload_sha384, p, QIHSE_BLOB_HASH_BYTES); p += QIHSE_BLOB_HASH_BYTES;
    memcpy(out_proj->artifact_schema, p, QIHSE_ANALYSIS_ARTIFACT_TEXT_BYTES); p += QIHSE_ANALYSIS_ARTIFACT_TEXT_BYTES;
    memcpy(out_proj->producer, p, QIHSE_ANALYSIS_ARTIFACT_TEXT_BYTES); p += QIHSE_ANALYSIS_ARTIFACT_TEXT_BYTES;
    memcpy(out_proj->producer_version, p, QIHSE_ANALYSIS_ARTIFACT_TEXT_BYTES); p += QIHSE_ANALYSIS_ARTIFACT_TEXT_BYTES;
    memcpy(out_proj->isa, p, QIHSE_ANALYSIS_ARTIFACT_CONTEXT_BYTES); p += QIHSE_ANALYSIS_ARTIFACT_CONTEXT_BYTES;
    memcpy(out_proj->mode, p, QIHSE_ANALYSIS_ARTIFACT_CONTEXT_BYTES); p += QIHSE_ANALYSIS_ARTIFACT_CONTEXT_BYTES;
    memcpy(out_proj->tombstone_reason, p, QIHSE_ANALYSIS_ARTIFACT_TEXT_BYTES); p += QIHSE_ANALYSIS_ARTIFACT_TEXT_BYTES;

    for (size_t i = 0; i < out_proj->input_count; i++) {
        memcpy(out_proj->input_ids[i], p, QIHSE_BLOB_HASH_BYTES);
        p += QIHSE_BLOB_HASH_BYTES;
    }
    return true;
}

#define MANIFEST_LOG_MAGIC 0x4B504D31u /* "KPM1" */
#define MANIFEST_LOG_VERSION 1u
#define MANIFEST_RECORD_BODY_BYTES 931u

static bool manifest_serialize(const qihse_analysis_artifact_v1_t* m, uint8_t* out, size_t cap) {
    if (!m || !out || cap < MANIFEST_RECORD_BODY_BYTES) return false;
    uint8_t* p = out;
    put_u16_be(p, m->version); p += 2;
    put_u16_be(p, m->kind); p += 2;
    put_u16_be(p, m->completion); p += 2;
    put_u16_be(p, m->fidelity); p += 2;
    put_u32_be(p, m->tenant_id); p += 4;
    put_u16_be(p, m->classification); p += 2;
    put_u16_be(p, m->sci); p += 2;
    memcpy(p, m->artifact_schema, sizeof(m->artifact_schema)); p += sizeof(m->artifact_schema);
    memcpy(p, m->producer, sizeof(m->producer)); p += sizeof(m->producer);
    memcpy(p, m->producer_version, sizeof(m->producer_version)); p += sizeof(m->producer_version);
    memcpy(p, m->run_id, sizeof(m->run_id)); p += sizeof(m->run_id);
    put_u64_be(p, m->generation); p += 8;
    memcpy(p, m->binary_sha384, sizeof(m->binary_sha384)); p += sizeof(m->binary_sha384);
    memcpy(p, m->isa, sizeof(m->isa)); p += sizeof(m->isa);
    memcpy(p, m->mode, sizeof(m->mode)); p += sizeof(m->mode);
    put_u16_be(p, m->address_bits); p += 2;
    memcpy(p, m->isanity_catalogue_sha384, sizeof(m->isanity_catalogue_sha384)); p += sizeof(m->isanity_catalogue_sha384);
    memcpy(p, m->vexel_pack_sha384, sizeof(m->vexel_pack_sha384)); p += sizeof(m->vexel_pack_sha384);
    put_u64_be(p, m->payload_size); p += 8;
    memcpy(p, m->payload_sha384, sizeof(m->payload_sha384)); p += sizeof(m->payload_sha384);
    *p++ = m->input_count;
    memcpy(p, m->input_ids, sizeof(m->input_ids)); p += sizeof(m->input_ids);
    memcpy(p, m->artifact_id, sizeof(m->artifact_id)); p += sizeof(m->artifact_id);
    return true;
}

static bool manifest_deserialize(const uint8_t* in, size_t len, qihse_analysis_artifact_v1_t* m) {
    if (!in || len != MANIFEST_RECORD_BODY_BYTES || !m) return false;
    memset(m, 0, sizeof(*m));
    const uint8_t* p = in;
    m->version = get_u16_be(p); p += 2;
    m->kind = get_u16_be(p); p += 2;
    m->completion = get_u16_be(p); p += 2;
    m->fidelity = get_u16_be(p); p += 2;
    m->tenant_id = get_u32_be(p); p += 4;
    m->classification = get_u16_be(p); p += 2;
    m->sci = get_u16_be(p); p += 2;
    memcpy(m->artifact_schema, p, sizeof(m->artifact_schema)); p += sizeof(m->artifact_schema);
    memcpy(m->producer, p, sizeof(m->producer)); p += sizeof(m->producer);
    memcpy(m->producer_version, p, sizeof(m->producer_version)); p += sizeof(m->producer_version);
    memcpy(m->run_id, p, sizeof(m->run_id)); p += sizeof(m->run_id);
    m->generation = get_u64_be(p); p += 8;
    memcpy(m->binary_sha384, p, sizeof(m->binary_sha384)); p += sizeof(m->binary_sha384);
    memcpy(m->isa, p, sizeof(m->isa)); p += sizeof(m->isa);
    memcpy(m->mode, p, sizeof(m->mode)); p += sizeof(m->mode);
    m->address_bits = get_u16_be(p); p += 2;
    memcpy(m->isanity_catalogue_sha384, p, sizeof(m->isanity_catalogue_sha384)); p += sizeof(m->isanity_catalogue_sha384);
    memcpy(m->vexel_pack_sha384, p, sizeof(m->vexel_pack_sha384)); p += sizeof(m->vexel_pack_sha384);
    m->payload_size = get_u64_be(p); p += 8;
    memcpy(m->payload_sha384, p, sizeof(m->payload_sha384)); p += sizeof(m->payload_sha384);
    m->input_count = *p++;
    memcpy(m->input_ids, p, sizeof(m->input_ids)); p += sizeof(m->input_ids);
    memcpy(m->artifact_id, p, sizeof(m->artifact_id)); p += sizeof(m->artifact_id);
    return true;
}

typedef struct manifest_node {
    qihse_analysis_artifact_v1_t manifest;
    bool is_tombstone;
    char tombstone_reason[QIHSE_ANALYSIS_ARTIFACT_TEXT_BYTES];
    struct manifest_node* next;
} manifest_node_t;

#define MANIFEST_BUCKETS 1024u

struct qihse_analysis_artifact_store {
    char base_dir[512];
    char log_path[576];
    int log_fd;
    pthread_rwlock_t lock;
    manifest_node_t* buckets[MANIFEST_BUCKETS];
    size_t count;
    qihse_blob_store_t* blob_store;
    bool owns_blob_store;
    qihse_federation_journal_t* journal;
    qihse_uuid_t origin_node;
    bool has_origin_node;
};

static size_t manifest_bucket(const uint8_t* id) {
    uint64_t h = 1469598103934665603ull;
    for (size_t i = 0; i < QIHSE_BLOB_HASH_BYTES; i++) {
        h ^= id[i];
        h *= 1099511628211ull;
    }
    return (size_t)(h % MANIFEST_BUCKETS);
}

static manifest_node_t* store_find_node_locked(qihse_analysis_artifact_store_t* store,
                                               const uint8_t* id) {
    if (!store || !id) return NULL;
    size_t b = manifest_bucket(id);
    for (manifest_node_t* cur = store->buckets[b]; cur; cur = cur->next) {
        if (CRYPTO_memcmp(cur->manifest.artifact_id, id, QIHSE_BLOB_HASH_BYTES) == 0)
            return cur;
    }
    return NULL;
}

static manifest_node_t* store_insert_or_update_node_locked(
    qihse_analysis_artifact_store_t* store,
    const qihse_analysis_artifact_v1_t* m,
    bool is_tombstone,
    const char* reason) {
    manifest_node_t* node = store_find_node_locked(store, m->artifact_id);
    if (!node) {
        node = calloc(1, sizeof(*node));
        if (!node) return NULL;
        size_t b = manifest_bucket(m->artifact_id);
        node->next = store->buckets[b];
        store->buckets[b] = node;
        store->count++;
    }
    node->manifest = *m;
    node->is_tombstone = is_tombstone;
    if (reason) snprintf(node->tombstone_reason, sizeof(node->tombstone_reason), "%s", reason);
    else node->tombstone_reason[0] = '\0';
    return node;
}

static bool store_fsync_dir(const char* dir) {
    int fd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0) return false;
    bool ok = (fsync(fd) == 0);
    close(fd);
    return ok;
}

static bool store_log_append(qihse_analysis_artifact_store_t* store, char op,
                             const void* body, size_t body_len) {
    if (store->log_fd < 0 || !body || body_len > 65535u) return false;
    uint8_t header[8];
    put_u32_be(header, MANIFEST_LOG_MAGIC);
    header[4] = MANIFEST_LOG_VERSION;
    header[5] = (uint8_t)op;
    put_u16_be(header + 6, (uint16_t)body_len);

    off_t start = lseek(store->log_fd, 0, SEEK_END);
    if (start < 0) return false;

    if (write(store->log_fd, header, sizeof(header)) != (ssize_t)sizeof(header) ||
        write(store->log_fd, body, body_len) != (ssize_t)body_len) {
        (void)ftruncate(store->log_fd, start);
        return false;
    }
    if (fsync(store->log_fd) != 0) {
        (void)ftruncate(store->log_fd, start);
        return false;
    }
    return true;
}

static bool store_log_replay(qihse_analysis_artifact_store_t* store) {
    FILE* f = fopen(store->log_path, "rb+");
    if (!f) return errno == ENOENT;
    uint8_t header[8];
    off_t valid_end = 0;
    bool torn = false, ok = true;
    for (;;) {
        size_t got = fread(header, 1, sizeof(header), f);
        if (got == 0 && feof(f)) break;
        if (got != sizeof(header)) { torn = true; break; }
        if (get_u32_be(header) != MANIFEST_LOG_MAGIC || header[4] != MANIFEST_LOG_VERSION) {
            ok = false; break;
        }
        char op = (char)header[5];
        uint16_t body_len = get_u16_be(header + 6);
        uint8_t body[1024];
        if (body_len > sizeof(body) || fread(body, 1, body_len, f) != body_len) {
            torn = true; break;
        }
        if (op == 'I') {
            qihse_analysis_artifact_v1_t m;
            if (!manifest_deserialize(body, body_len, &m) || !qihse_analysis_artifact_validate(&m)) {
                ok = false; break;
            }
            if (!store_insert_or_update_node_locked(store, &m, false, NULL)) {
                ok = false; break;
            }
        } else if (op == 'T') {
            if (body_len < QIHSE_BLOB_HASH_BYTES + QIHSE_ANALYSIS_ARTIFACT_TEXT_BYTES) {
                ok = false; break;
            }
            manifest_node_t* node = store_find_node_locked(store, body);
            if (node) {
                node->is_tombstone = true;
                memcpy(node->tombstone_reason, body + QIHSE_BLOB_HASH_BYTES, QIHSE_ANALYSIS_ARTIFACT_TEXT_BYTES);
                node->tombstone_reason[QIHSE_ANALYSIS_ARTIFACT_TEXT_BYTES - 1] = '\0';
            }
        } else {
            ok = false; break;
        }
        valid_end = ftello(f);
        if (valid_end < 0) { ok = false; break; }
    }
    if (ferror(f)) ok = false;
    if (ok && torn) {
        clearerr(f);
        if (valid_end >= 0) {
            (void)ftruncate(fileno(f), valid_end);
            (void)fsync(fileno(f));
        }
    }
    fclose(f);
    return ok;
}

qihse_analysis_artifact_store_t* qihse_analysis_artifact_store_open(
    const char* base_dir,
    qihse_blob_store_t* blob_store,
    qihse_federation_journal_t* journal,
    const qihse_uuid_t* origin_node) {
    if (!base_dir || !*base_dir || strlen(base_dir) >= 500u) return NULL;
    if (mkdir(base_dir, 0700) != 0 && errno != EEXIST) return NULL;

    qihse_analysis_artifact_store_t* store = calloc(1, sizeof(*store));
    if (!store) return NULL;
    store->log_fd = -1;
    snprintf(store->base_dir, sizeof(store->base_dir), "%s", base_dir);
    snprintf(store->log_path, sizeof(store->log_path), "%s/manifests.log", base_dir);

    if (pthread_rwlock_init(&store->lock, NULL) != 0) {
        free(store);
        return NULL;
    }

    if (blob_store) {
        store->blob_store = blob_store;
        store->owns_blob_store = false;
    } else {
        char blob_dir[576];
        snprintf(blob_dir, sizeof(blob_dir), "%s/blobs", base_dir);
        store->blob_store = qihse_blob_store_create(blob_dir);
        if (!store->blob_store) {
            pthread_rwlock_destroy(&store->lock);
            free(store);
            return NULL;
        }
        store->owns_blob_store = true;
    }

    store->journal = journal;
    if (origin_node) {
        store->origin_node = *origin_node;
        store->has_origin_node = true;
    } else {
        (void)qihse_uuid_from_seed("qihse-analysis-origin", 21, &store->origin_node);
        store->has_origin_node = true;
    }

    if (!store_log_replay(store)) {
        qihse_analysis_artifact_store_close(store);
        return NULL;
    }

    store->log_fd = open(store->log_path, O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC, 0600);
    if (store->log_fd < 0 || !store_fsync_dir(store->base_dir)) {
        qihse_analysis_artifact_store_close(store);
        return NULL;
    }
    return store;
}

void qihse_analysis_artifact_store_close(qihse_analysis_artifact_store_t* store) {
    if (!store) return;
    pthread_rwlock_wrlock(&store->lock);
    for (size_t i = 0; i < MANIFEST_BUCKETS; i++) {
        manifest_node_t* cur = store->buckets[i];
        while (cur) {
            manifest_node_t* next = cur->next;
            free(cur);
            cur = next;
        }
        store->buckets[i] = NULL;
    }
    store->count = 0;
    if (store->log_fd >= 0) {
        close(store->log_fd);
        store->log_fd = -1;
    }
    pthread_rwlock_unlock(&store->lock);
    pthread_rwlock_destroy(&store->lock);

    if (store->owns_blob_store && store->blob_store) {
        qihse_blob_store_destroy(store->blob_store);
        store->blob_store = NULL;
    }
    free(store);
}

qihse_analysis_store_result_t qihse_analysis_artifact_ingest_user(
    qihse_analysis_artifact_store_t* store,
    const qihse_analysis_artifact_v1_t* manifest,
    qihse_blob_read_fn payload_reader,
    void* reader_opaque,
    qihse_user_t* publisher,
    uint8_t out_artifact_id[QIHSE_BLOB_HASH_BYTES]) {
    if (!store || !manifest || !payload_reader || !publisher)
        return QIHSE_ANALYSIS_STORE_INVALID;
    if (!qihse_auth_user_is_active(publisher))
        return QIHSE_ANALYSIS_STORE_DENIED;
    if (!qihse_analysis_artifact_validate(manifest))
        return QIHSE_ANALYSIS_STORE_INVALID;
    if (!qihse_analysis_artifact_authorize_publisher(manifest, publisher))
        return QIHSE_ANALYSIS_STORE_DENIED;

    /* Lineage verification */
    if (manifest->kind == QIHSE_ANALYSIS_BINARY) {
        if (manifest->input_count != 0) return QIHSE_ANALYSIS_STORE_INVALID;
        if (CRYPTO_memcmp(manifest->binary_sha384, manifest->payload_sha384, QIHSE_BLOB_HASH_BYTES) != 0)
            return QIHSE_ANALYSIS_STORE_INVALID;
    } else {
        if (manifest->input_count == 0 || manifest->address_bits == 0)
            return QIHSE_ANALYSIS_STORE_INVALID;
        pthread_rwlock_rdlock(&store->lock);
        for (size_t i = 0; i < manifest->input_count; i++) {
            manifest_node_t* inp = store_find_node_locked(store, manifest->input_ids[i]);
            if (!inp || inp->is_tombstone) {
                pthread_rwlock_unlock(&store->lock);
                return QIHSE_ANALYSIS_STORE_LINEAGE_ERROR;
            }
            if (manifest->tenant_id != QIHSE_TENANT_SYSTEM &&
                inp->manifest.tenant_id != manifest->tenant_id) {
                pthread_rwlock_unlock(&store->lock);
                return QIHSE_ANALYSIS_STORE_LINEAGE_ERROR;
            }
            if (CRYPTO_memcmp(inp->manifest.binary_sha384, manifest->binary_sha384, QIHSE_BLOB_HASH_BYTES) != 0) {
                pthread_rwlock_unlock(&store->lock);
                return QIHSE_ANALYSIS_STORE_LINEAGE_ERROR;
            }
            if (!qihse_analysis_artifact_authorize_user(&inp->manifest, publisher)) {
                pthread_rwlock_unlock(&store->lock);
                return QIHSE_ANALYSIS_STORE_DENIED;
            }
        }
        pthread_rwlock_unlock(&store->lock);
    }

    /* Check existing entry */
    pthread_rwlock_rdlock(&store->lock);
    manifest_node_t* existing = store_find_node_locked(store, manifest->artifact_id);
    if (existing && !existing->is_tombstone) {
        if (CRYPTO_memcmp(&existing->manifest, manifest, sizeof(qihse_analysis_artifact_v1_t)) == 0) {
            pthread_rwlock_unlock(&store->lock);
            if (out_artifact_id) memcpy(out_artifact_id, manifest->artifact_id, QIHSE_BLOB_HASH_BYTES);
            return QIHSE_ANALYSIS_STORE_OK;
        }
        pthread_rwlock_unlock(&store->lock);
        return QIHSE_ANALYSIS_STORE_CONFLICT;
    }
    pthread_rwlock_unlock(&store->lock);

    /* Stream payload into QIHSE blob store */
    bool put_ok = qihse_blob_put_expected_user(
        store->blob_store, manifest->tenant_id, QIHSE_BLOB_TAG_ANALYSIS_ARTIFACT,
        manifest->classification, manifest->sci, publisher,
        payload_reader, reader_opaque,
        manifest->payload_sha384, manifest->payload_size);
    if (!put_ok) return QIHSE_ANALYSIS_STORE_PAYLOAD_MISMATCH;

    /* Pin referenced blob from deletion */
    if (!qihse_blob_pin_user(store->blob_store, manifest->payload_sha384, publisher)) {
        return QIHSE_ANALYSIS_STORE_IO_ERROR;
    }

    /* Atomically log manifest */
    uint8_t body[MANIFEST_RECORD_BODY_BYTES];
    if (!manifest_serialize(manifest, body, sizeof(body))) {
        qihse_blob_unpin_user(store->blob_store, manifest->payload_sha384, publisher);
        return QIHSE_ANALYSIS_STORE_INVALID;
    }

    pthread_rwlock_wrlock(&store->lock);
    if (!qihse_analysis_artifact_authorize_publisher(manifest, publisher)) {
        pthread_rwlock_unlock(&store->lock);
        qihse_blob_unpin_user(store->blob_store, manifest->payload_sha384, publisher);
        return QIHSE_ANALYSIS_STORE_DENIED;
    }

    if (!store_log_append(store, 'I', body, sizeof(body))) {
        pthread_rwlock_unlock(&store->lock);
        qihse_blob_unpin_user(store->blob_store, manifest->payload_sha384, publisher);
        return QIHSE_ANALYSIS_STORE_IO_ERROR;
    }

    store_insert_or_update_node_locked(store, manifest, false, NULL);
    pthread_rwlock_unlock(&store->lock);

    /* Publish bounded KEYSTONE feed projection */
    if (store->journal) {
        qihse_analysis_projection_t proj;
        memset(&proj, 0, sizeof(proj));
        memcpy(proj.artifact_id, manifest->artifact_id, QIHSE_BLOB_HASH_BYTES);
        memcpy(proj.binary_sha384, manifest->binary_sha384, QIHSE_BLOB_HASH_BYTES);
        memcpy(proj.payload_sha384, manifest->payload_sha384, QIHSE_BLOB_HASH_BYTES);
        proj.payload_size = manifest->payload_size;
        proj.tenant_id = manifest->tenant_id;
        proj.classification = manifest->classification;
        proj.sci = manifest->sci;
        proj.kind = manifest->kind;
        proj.completion = manifest->completion;
        proj.fidelity = manifest->fidelity;
        memcpy(proj.artifact_schema, manifest->artifact_schema, sizeof(proj.artifact_schema));
        memcpy(proj.producer, manifest->producer, sizeof(proj.producer));
        memcpy(proj.producer_version, manifest->producer_version, sizeof(proj.producer_version));
        proj.generation = manifest->generation;
        memcpy(proj.isa, manifest->isa, sizeof(proj.isa));
        memcpy(proj.mode, manifest->mode, sizeof(proj.mode));
        proj.address_bits = manifest->address_bits;
        proj.input_count = manifest->input_count;
        memcpy(proj.input_ids, manifest->input_ids, sizeof(proj.input_ids));
        proj.is_tombstone = false;

        uint8_t proj_buf[1024];
        size_t proj_len = 0;
        if (qihse_analysis_projection_encode(&proj, proj_buf, sizeof(proj_buf), &proj_len)) {
            char hex_id[QIHSE_BLOB_HASH_HEX];
            qihse_blob_hash_to_hex(manifest->artifact_id, hex_id);
            qihse_keystone_feed_record_t rec;
            memset(&rec, 0, sizeof(rec));
            (void)qihse_uuid_from_seed(hex_id, strlen(hex_id), &rec.object_id);
            rec.generation = manifest->generation;
            rec.tenant_id = manifest->tenant_id;
            rec.object_type = manifest->kind;
            rec.classification = manifest->classification;
            rec.sci = manifest->sci;
            rec.flags = QIHSE_KEYSTONE_FEED_FLAG_EVENT |
                        (manifest->kind > QIHSE_ANALYSIS_BINARY ? QIHSE_KEYSTONE_FEED_FLAG_DERIVED : 0);

            const qihse_uuid_t* node = store->has_origin_node ? &store->origin_node : NULL;
            qihse_federation_event_t out_ev;
            (void)qihse_keystone_feed_publish(store->journal, publisher, node,
                                              "kp14.analysis.artifact", hex_id,
                                              &rec, proj_buf, proj_len, &out_ev);
        }
    }

    if (out_artifact_id) memcpy(out_artifact_id, manifest->artifact_id, QIHSE_BLOB_HASH_BYTES);
    return QIHSE_ANALYSIS_STORE_OK;
}

typedef struct {
    const uint8_t* data;
    size_t len;
    size_t pos;
} artifact_buffer_reader_t;

static int64_t artifact_buffer_reader_fn(void* opaque, uint8_t* buffer, size_t capacity) {
    artifact_buffer_reader_t* st = opaque;
    if (!st || st->pos >= st->len) return 0;
    size_t n = st->len - st->pos;
    if (n > capacity) n = capacity;
    memcpy(buffer, st->data + st->pos, n);
    st->pos += n;
    return (int64_t)n;
}

qihse_analysis_store_result_t qihse_analysis_artifact_ingest_buffer_user(
    qihse_analysis_artifact_store_t* store,
    const qihse_analysis_artifact_v1_t* manifest,
    const uint8_t* payload_data,
    size_t payload_len,
    qihse_user_t* publisher,
    uint8_t out_artifact_id[QIHSE_BLOB_HASH_BYTES]) {
    if (!payload_data && payload_len > 0) return QIHSE_ANALYSIS_STORE_INVALID;
    artifact_buffer_reader_t reader = { payload_data, payload_len, 0 };
    return qihse_analysis_artifact_ingest_user(
        store, manifest, artifact_buffer_reader_fn, &reader, publisher, out_artifact_id);
}

qihse_analysis_store_result_t qihse_analysis_artifact_get_manifest_user(
    qihse_analysis_artifact_store_t* store,
    const uint8_t artifact_id[QIHSE_BLOB_HASH_BYTES],
    const qihse_user_t* user,
    qihse_analysis_artifact_v1_t* out_manifest) {
    if (!store || !artifact_id || !user) return QIHSE_ANALYSIS_STORE_DENIED;
    if (!qihse_auth_user_is_active(user)) return QIHSE_ANALYSIS_STORE_DENIED;

    pthread_rwlock_rdlock(&store->lock);
    manifest_node_t* node = store_find_node_locked(store, artifact_id);
    if (!node) {
        pthread_rwlock_unlock(&store->lock);
        return QIHSE_ANALYSIS_STORE_NOT_FOUND;
    }
    if (!qihse_analysis_artifact_authorize_user(&node->manifest, user)) {
        pthread_rwlock_unlock(&store->lock);
        return QIHSE_ANALYSIS_STORE_DENIED;
    }
    if (node->is_tombstone) {
        pthread_rwlock_unlock(&store->lock);
        return QIHSE_ANALYSIS_STORE_TOMBSTONED;
    }
    if (out_manifest) *out_manifest = node->manifest;
    pthread_rwlock_unlock(&store->lock);
    return QIHSE_ANALYSIS_STORE_OK;
}

qihse_analysis_store_result_t qihse_analysis_artifact_get_payload_user(
    qihse_analysis_artifact_store_t* store,
    const uint8_t artifact_id[QIHSE_BLOB_HASH_BYTES],
    uint64_t offset,
    uint8_t* buffer,
    size_t buffer_len,
    size_t* out_read,
    qihse_user_t* user) {
    if (!store || !artifact_id || !buffer || buffer_len == 0 || !out_read || !user)
        return QIHSE_ANALYSIS_STORE_DENIED;
    if (!qihse_auth_user_is_active(user)) return QIHSE_ANALYSIS_STORE_DENIED;

    pthread_rwlock_rdlock(&store->lock);
    manifest_node_t* node = store_find_node_locked(store, artifact_id);
    if (!node) {
        pthread_rwlock_unlock(&store->lock);
        return QIHSE_ANALYSIS_STORE_NOT_FOUND;
    }
    if (!qihse_analysis_artifact_authorize_user(&node->manifest, user)) {
        pthread_rwlock_unlock(&store->lock);
        return QIHSE_ANALYSIS_STORE_DENIED;
    }
    if (node->is_tombstone) {
        pthread_rwlock_unlock(&store->lock);
        return QIHSE_ANALYSIS_STORE_TOMBSTONED;
    }
    uint8_t payload_hash[QIHSE_BLOB_HASH_BYTES];
    memcpy(payload_hash, node->manifest.payload_sha384, QIHSE_BLOB_HASH_BYTES);
    pthread_rwlock_unlock(&store->lock);

    if (!qihse_blob_get_user(store->blob_store, payload_hash, offset, buffer, buffer_len, out_read, user)) {
        return QIHSE_ANALYSIS_STORE_IO_ERROR;
    }
    return QIHSE_ANALYSIS_STORE_OK;
}

qihse_analysis_store_result_t qihse_analysis_artifact_tombstone_user(
    qihse_analysis_artifact_store_t* store,
    const uint8_t artifact_id[QIHSE_BLOB_HASH_BYTES],
    const char* reason,
    qihse_user_t* publisher) {
    if (!store || !artifact_id || !publisher) return QIHSE_ANALYSIS_STORE_INVALID;
    if (!qihse_auth_user_is_active(publisher)) return QIHSE_ANALYSIS_STORE_DENIED;

    pthread_rwlock_wrlock(&store->lock);
    manifest_node_t* node = store_find_node_locked(store, artifact_id);
    if (!node) {
        pthread_rwlock_unlock(&store->lock);
        return QIHSE_ANALYSIS_STORE_NOT_FOUND;
    }
    if (!qihse_analysis_artifact_authorize_publisher(&node->manifest, publisher)) {
        pthread_rwlock_unlock(&store->lock);
        return QIHSE_ANALYSIS_STORE_DENIED;
    }
    if (node->is_tombstone) {
        pthread_rwlock_unlock(&store->lock);
        return QIHSE_ANALYSIS_STORE_OK;
    }

    /* Unpin blob */
    (void)qihse_blob_unpin_user(store->blob_store, node->manifest.payload_sha384, publisher);

    uint8_t body[QIHSE_BLOB_HASH_BYTES + QIHSE_ANALYSIS_ARTIFACT_TEXT_BYTES];
    memcpy(body, artifact_id, QIHSE_BLOB_HASH_BYTES);
    memset(body + QIHSE_BLOB_HASH_BYTES, 0, QIHSE_ANALYSIS_ARTIFACT_TEXT_BYTES);
    if (reason) snprintf((char*)body + QIHSE_BLOB_HASH_BYTES, QIHSE_ANALYSIS_ARTIFACT_TEXT_BYTES, "%s", reason);

    if (!store_log_append(store, 'T', body, sizeof(body))) {
        pthread_rwlock_unlock(&store->lock);
        return QIHSE_ANALYSIS_STORE_IO_ERROR;
    }

    node->is_tombstone = true;
    snprintf(node->tombstone_reason, sizeof(node->tombstone_reason), "%s", reason ? reason : "tombstone");
    qihse_analysis_artifact_v1_t m = node->manifest;
    pthread_rwlock_unlock(&store->lock);

    /* Publish tombstone feed event */
    if (store->journal) {
        qihse_analysis_projection_t proj;
        memset(&proj, 0, sizeof(proj));
        memcpy(proj.artifact_id, m.artifact_id, QIHSE_BLOB_HASH_BYTES);
        memcpy(proj.binary_sha384, m.binary_sha384, QIHSE_BLOB_HASH_BYTES);
        memcpy(proj.payload_sha384, m.payload_sha384, QIHSE_BLOB_HASH_BYTES);
        proj.payload_size = m.payload_size;
        proj.tenant_id = m.tenant_id;
        proj.classification = m.classification;
        proj.sci = m.sci;
        proj.kind = m.kind;
        proj.completion = m.completion;
        proj.fidelity = m.fidelity;
        memcpy(proj.artifact_schema, m.artifact_schema, sizeof(proj.artifact_schema));
        memcpy(proj.producer, m.producer, sizeof(proj.producer));
        memcpy(proj.producer_version, m.producer_version, sizeof(proj.producer_version));
        proj.generation = m.generation;
        memcpy(proj.isa, m.isa, sizeof(proj.isa));
        memcpy(proj.mode, m.mode, sizeof(proj.mode));
        proj.address_bits = m.address_bits;
        proj.input_count = m.input_count;
        memcpy(proj.input_ids, m.input_ids, sizeof(proj.input_ids));
        proj.is_tombstone = true;
        if (reason) snprintf(proj.tombstone_reason, sizeof(proj.tombstone_reason), "%s", reason);

        uint8_t proj_buf[1024];
        size_t proj_len = 0;
        if (qihse_analysis_projection_encode(&proj, proj_buf, sizeof(proj_buf), &proj_len)) {
            char hex_id[QIHSE_BLOB_HASH_HEX];
            qihse_blob_hash_to_hex(m.artifact_id, hex_id);
            qihse_keystone_feed_record_t rec;
            memset(&rec, 0, sizeof(rec));
            (void)qihse_uuid_from_seed(hex_id, strlen(hex_id), &rec.object_id);
            rec.generation = m.generation;
            rec.tenant_id = m.tenant_id;
            rec.object_type = m.kind;
            rec.classification = m.classification;
            rec.sci = m.sci;
            rec.flags = QIHSE_KEYSTONE_FEED_FLAG_EVENT | QIHSE_KEYSTONE_FEED_FLAG_TOMBSTONE;

            const qihse_uuid_t* node = store->has_origin_node ? &store->origin_node : NULL;
            qihse_federation_event_t out_ev;
            (void)qihse_keystone_feed_publish(store->journal, publisher, node,
                                              "kp14.analysis.tombstone", hex_id,
                                              &rec, proj_buf, proj_len, &out_ev);
        }
    }
    return QIHSE_ANALYSIS_STORE_OK;
}

static qihse_analysis_store_result_t verify_lineage_rec(
    qihse_analysis_artifact_store_t* store,
    const uint8_t id[QIHSE_BLOB_HASH_BYTES],
    const qihse_user_t* user,
    int depth) {
    if (depth > 64) return QIHSE_ANALYSIS_STORE_LINEAGE_ERROR;
    manifest_node_t* node = store_find_node_locked(store, id);
    if (!node) return QIHSE_ANALYSIS_STORE_NOT_FOUND;
    if (!qihse_analysis_artifact_authorize_user(&node->manifest, user))
        return QIHSE_ANALYSIS_STORE_DENIED;
    if (node->is_tombstone) return QIHSE_ANALYSIS_STORE_TOMBSTONED;

    for (size_t i = 0; i < node->manifest.input_count; i++) {
        qihse_analysis_store_result_t rc = verify_lineage_rec(
            store, node->manifest.input_ids[i], user, depth + 1);
        if (rc != QIHSE_ANALYSIS_STORE_OK) return QIHSE_ANALYSIS_STORE_LINEAGE_ERROR;
    }
    return QIHSE_ANALYSIS_STORE_OK;
}

qihse_analysis_store_result_t qihse_analysis_artifact_verify_lineage_user(
    qihse_analysis_artifact_store_t* store,
    const uint8_t artifact_id[QIHSE_BLOB_HASH_BYTES],
    const qihse_user_t* user) {
    if (!store || !artifact_id || !user) return QIHSE_ANALYSIS_STORE_DENIED;
    if (!qihse_auth_user_is_active(user)) return QIHSE_ANALYSIS_STORE_DENIED;

    pthread_rwlock_rdlock(&store->lock);
    qihse_analysis_store_result_t rc = verify_lineage_rec(store, artifact_id, user, 0);
    pthread_rwlock_unlock(&store->lock);
    return rc;
}

qihse_analysis_store_result_t qihse_analysis_artifact_list_user(
    qihse_analysis_artifact_store_t* store,
    const qihse_user_t* user,
    qihse_analysis_artifact_list_fn callback,
    void* callback_opaque) {
    if (!store || !user || !callback) return QIHSE_ANALYSIS_STORE_DENIED;
    if (!qihse_auth_user_is_active(user)) return QIHSE_ANALYSIS_STORE_DENIED;

    pthread_rwlock_rdlock(&store->lock);
    bool keep_going = true;
    for (size_t i = 0; i < MANIFEST_BUCKETS && keep_going; i++) {
        for (manifest_node_t* cur = store->buckets[i]; cur && keep_going; cur = cur->next) {
            if (!qihse_analysis_artifact_authorize_user(&cur->manifest, user)) continue;
            keep_going = callback(&cur->manifest, cur->is_tombstone, callback_opaque);
        }
    }
    pthread_rwlock_unlock(&store->lock);
    return QIHSE_ANALYSIS_STORE_OK;
}

qihse_analysis_store_result_t qihse_analysis_artifact_search_user(
    qihse_analysis_artifact_store_t* store,
    const qihse_analysis_search_filter_t* filter,
    const qihse_user_t* user,
    uint8_t out_artifact_ids[][QIHSE_BLOB_HASH_BYTES],
    size_t max_results,
    size_t* out_count) {
    if (out_count) *out_count = 0;
    if (!store || !user) return QIHSE_ANALYSIS_STORE_DENIED;
    if (!qihse_auth_user_is_active(user)) return QIHSE_ANALYSIS_STORE_DENIED;
    if (max_results > 0 && !out_artifact_ids) return QIHSE_ANALYSIS_STORE_INVALID;

    size_t found = 0;
    pthread_rwlock_rdlock(&store->lock);
    for (size_t i = 0; i < MANIFEST_BUCKETS && found < max_results; i++) {
        for (manifest_node_t* cur = store->buckets[i]; cur && found < max_results; cur = cur->next) {
            if (!qihse_analysis_artifact_authorize_user(&cur->manifest, user)) continue;
            if (cur->is_tombstone && (!filter || !filter->include_tombstones)) continue;
            if (filter) {
                if (filter->tenant_id != 0 && cur->manifest.tenant_id != filter->tenant_id) continue;
                if (filter->kind != 0 && cur->manifest.kind != filter->kind) continue;
                if (filter->artifact_schema[0] && strcmp(cur->manifest.artifact_schema, filter->artifact_schema) != 0) continue;
                if (filter->producer[0] && strcmp(cur->manifest.producer, filter->producer) != 0) continue;
                if (filter->match_binary && CRYPTO_memcmp(cur->manifest.binary_sha384, filter->binary_sha384, QIHSE_BLOB_HASH_BYTES) != 0) continue;
            }
            if (out_artifact_ids) memcpy(out_artifact_ids[found], cur->manifest.artifact_id, QIHSE_BLOB_HASH_BYTES);
            found++;
        }
    }
    pthread_rwlock_unlock(&store->lock);
    if (out_count) *out_count = found;
    return QIHSE_ANALYSIS_STORE_OK;
}

#define QIHSE_ANALYSIS_EXPORT_MAGIC 0x4B504558u /* "KPEX" */
#ifndef QIHSE_ANALYSIS_EXPORT_FRAME_BYTES
#define QIHSE_ANALYSIS_EXPORT_FRAME_BYTES (6u + MANIFEST_RECORD_BODY_BYTES)
#endif

qihse_analysis_store_result_t qihse_analysis_artifact_export_user(
    qihse_analysis_artifact_store_t* store,
    const uint8_t artifact_id[QIHSE_BLOB_HASH_BYTES],
    const qihse_user_t* user,
    uint8_t* out_buf,
    size_t buf_cap,
    size_t* out_len) {
    if (out_len) *out_len = 0;
    if (!store || !artifact_id || !user) return QIHSE_ANALYSIS_STORE_DENIED;
    if (!qihse_auth_user_is_active(user)) return QIHSE_ANALYSIS_STORE_DENIED;
    if (!out_buf || buf_cap < QIHSE_ANALYSIS_EXPORT_FRAME_BYTES) return QIHSE_ANALYSIS_STORE_INVALID;

    pthread_rwlock_rdlock(&store->lock);
    manifest_node_t* node = store_find_node_locked(store, artifact_id);
    if (!node) {
        pthread_rwlock_unlock(&store->lock);
        return QIHSE_ANALYSIS_STORE_NOT_FOUND;
    }
    if (!qihse_analysis_artifact_authorize_user(&node->manifest, user)) {
        pthread_rwlock_unlock(&store->lock);
        return QIHSE_ANALYSIS_STORE_DENIED;
    }
    if (node->is_tombstone) {
        pthread_rwlock_unlock(&store->lock);
        return QIHSE_ANALYSIS_STORE_TOMBSTONED;
    }
    qihse_analysis_artifact_v1_t m = node->manifest;
    pthread_rwlock_unlock(&store->lock);

    put_u32_be(out_buf, QIHSE_ANALYSIS_EXPORT_MAGIC);
    put_u16_be(out_buf + 4, 1u);
    if (!manifest_serialize(&m, out_buf + 6, buf_cap - 6)) {
        return QIHSE_ANALYSIS_STORE_IO_ERROR;
    }
    if (out_len) *out_len = QIHSE_ANALYSIS_EXPORT_FRAME_BYTES;
    return QIHSE_ANALYSIS_STORE_OK;
}

bool qihse_analysis_artifact_feed_freshness(
    qihse_analysis_artifact_store_t* store,
    uint64_t consumer_cursor,
    uint64_t* out_latest_offset,
    uint64_t* out_lag_bytes) {
    if (!store || !store->journal) return false;
    uint64_t len = qihse_federation_journal_length(store->journal);
    if (out_latest_offset) *out_latest_offset = len;
    if (out_lag_bytes) *out_lag_bytes = (consumer_cursor < len) ? (len - consumer_cursor) : 0u;
    return true;
}

qihse_blob_store_t* qihse_analysis_artifact_store_get_blob_store(
    const qihse_analysis_artifact_store_t* store) {
    return store ? store->blob_store : NULL;
}
