#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "qihse_ct_codec.h"
#include <errno.h>
#include <limits.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <stdlib.h>
#include <string.h>

/* QKV6CT01: fixed 96-byte header, source/generation bytes, 48-byte public
 * record descriptors, then key/value bytes. The descriptors contain every
 * security label and tenant field, so read authorizes the whole group before
 * reading or allocating its protected body. The SHA-256 covers the entire
 * frame with its checksum slot zeroed. It is an integrity check, not a MAC. */
enum {
    CT_HEADER = 96,
    CT_ROW = 48,
    CT_KEY_MAX = 65535,
    CT_VALUE_MAX = 16 * 1024 * 1024
};
static const unsigned char ct_magic[8] = {'Q','K','V','6','C','T','0','1'};

typedef struct {
    uint32_t actor_id, actor_tenant, resource_tenant;
    uint16_t classification, sci;
    uint8_t actor_kind, tombstone;
    uint64_t seq, expiry;
    uint32_t key_len, value_len;
} ct_row;

static uint16_t rd16(const unsigned char* p) {
    return ((uint16_t)p[0] << 8) | p[1];
}
static uint32_t rd32(const unsigned char* p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | p[3];
}
static uint64_t rd64(const unsigned char* p) {
    uint64_t v = 0;
    for (unsigned i = 0; i < 8; i++) v = (v << 8) | p[i];
    return v;
}
static void wr16(unsigned char* p, uint16_t v) {
    p[0] = (unsigned char)(v >> 8); p[1] = (unsigned char)v;
}
static void wr32(unsigned char* p, uint32_t v) {
    for (unsigned i = 0; i < 4; i++) p[i] = (unsigned char)(v >> (24u - 8u * i));
}
static void wr64(unsigned char* p, uint64_t v) {
    for (unsigned i = 0; i < 8; i++) p[i] = (unsigned char)(v >> (56u - 8u * i));
}
static bool id_valid(const char* id, size_t* length) {
    if (!id) return false;
    size_t n = strnlen(id, QIHSE_KV_CT_ID_MAX + 1u);
    if (!n || n > QIHSE_KV_CT_ID_MAX) return false;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)id[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '-' || c == '_' ||
              c == '.' || c == ':')) return false;
    }
    if (length) *length = n;
    return true;
}
static bool principal_policy(qihse_user_t* principal,
                             qihse_kv_ct_tenant_policy_t policy, uint32_t tenant) {
    if (!principal || !qihse_auth_user_is_active(principal)) return false;
    bool system_principal = qihse_user_get_tenant_id(principal) == QIHSE_TENANT_SYSTEM;
    if (policy == QIHSE_KV_CT_TENANT_SYSTEM_ALL)
        return tenant == 0u && system_principal;
    return policy == QIHSE_KV_CT_TENANT_EXACT &&
           (system_principal || tenant == 0u ||
            qihse_user_get_tenant_id(principal) == tenant);
}
static bool row_authorized(qihse_user_t* principal,
                           qihse_kv_ct_tenant_policy_t policy, uint32_t tenant,
                           const ct_row* row) {
    if (!principal_policy(principal, policy, tenant) ||
        !qihse_auth_can_access(principal, row->classification, row->sci)) return false;
    if (row->actor_tenant == QIHSE_TENANT_INVALID ||
        row->resource_tenant == QIHSE_TENANT_INVALID) return false;
    if (policy == QIHSE_KV_CT_TENANT_EXACT && row->resource_tenant != tenant)
        return false;
    /* A tenant principal may only act on its own tenant rows or its own
     * commons/ writes. System principals may carry other actors' history. */
    uint32_t principal_tenant = qihse_user_get_tenant_id(principal);
    if (principal_tenant != 0u && row->actor_tenant != principal_tenant)
        return false;
    if (row->actor_tenant != 0u && row->resource_tenant != 0u &&
        row->actor_tenant != row->resource_tenant) return false;
    return true;
}
static bool row_shape(const ct_row* row) {
    return row->actor_kind >= QIHSE_KV_CT_ACTOR_USER &&
           row->actor_kind <= QIHSE_KV_CT_ACTOR_REPLICA &&
           row->tombstone <= 1u && row->seq != 0u &&
           row->key_len > 0u && row->key_len <= CT_KEY_MAX &&
           row->value_len <= CT_VALUE_MAX &&
           (!row->tombstone || (row->value_len == 0u && row->expiry == 0u));
}
static bool key_tenant(const char* key, size_t len, uint32_t actor_tenant,
                       uint32_t resource_tenant) {
    if (!len) return false;
    if (len >= 2u && key[0] == 't' && key[1] == ':') {
        size_t i = 2u;
        uint64_t value = 0u;
        if (i >= len || key[i] < '1' || key[i] > '9') return false;
        for (; i < len && key[i] >= '0' && key[i] <= '9'; i++) {
            value = value * 10u + (unsigned)(key[i] - '0');
            if (value > UINT32_MAX) return false;
        }
        return i < len && key[i] == '/' && value == resource_tenant &&
               (actor_tenant == 0u || actor_tenant == value);
    }
    if (resource_tenant != 0u) return false;
    return actor_tenant == 0u ||
           (len >= 8u && memcmp(key, "commons/", 8u) == 0);
}
static bool mode_valid(uint8_t mode) {
    return mode == QIHSE_CT_CODEC_MODE_SOURCE || mode == QIHSE_CT_CODEC_MODE_RECEIVER;
}
static size_t ceiling(size_t max_bytes) {
    return max_bytes < QIHSE_CT_CODEC_MAX_FRAME ? max_bytes : QIHSE_CT_CODEC_MAX_FRAME;
}
static void row_write(unsigned char* p, const ct_row* r) {
    wr32(p, r->actor_id); wr32(p + 4, r->actor_tenant);
    wr32(p + 8, r->resource_tenant); wr16(p + 12, r->classification);
    wr16(p + 14, r->sci); p[16] = r->actor_kind; p[17] = r->tombstone;
    p[18] = p[19] = 0u; wr64(p + 20, r->seq); wr64(p + 28, r->expiry);
    wr32(p + 36, r->key_len); wr32(p + 40, r->value_len);
    memset(p + 44, 0, 4u);
}
static bool row_read(const unsigned char* p, ct_row* r) {
    if (p[18] || p[19] || rd32(p + 44)) return false;
    *r = (ct_row){.actor_id = rd32(p), .actor_tenant = rd32(p + 4),
        .resource_tenant = rd32(p + 8), .classification = rd16(p + 12),
        .sci = rd16(p + 14), .actor_kind = p[16], .tombstone = p[17],
        .seq = rd64(p + 20), .expiry = rd64(p + 28),
        .key_len = rd32(p + 36), .value_len = rd32(p + 40)};
    return row_shape(r);
}

/* Validation is two-pass: all public labels before any key/value access. */
static bool measure(qihse_user_t* principal, qihse_kv_ct_tenant_policy_t policy,
                    uint32_t tenant, uint8_t mode, const qihse_kv_ct_group_t* group,
                    size_t max_bytes, size_t* out, size_t* source_len,
                    size_t* generation_len) {
    if (out) *out = 0u;
    if (!out || !group || !mode_valid(mode) || !max_bytes ||
        !principal_policy(principal, policy, tenant) ||
        !id_valid(group->source_id, source_len) ||
        !id_valid(group->generation, generation_len) ||
        !group->stream_position || !group->records ||
        !group->count || group->count > QIHSE_KV_CT_MAX_GROUP_RECORDS ||
        !group->first_seq || group->first_seq > group->last_seq) return false;
    uint64_t prior = 0u;
    for (size_t i = 0; i < group->count; i++) {
        const qihse_kv_ct_record_t* r = &group->records[i];
        ct_row row = {.actor_id = r->actor_id, .actor_tenant = r->actor_tenant_id,
            .resource_tenant = r->resource_tenant_id,
            .classification = r->classification, .sci = r->sci_compartment,
            .actor_kind = (uint8_t)r->actor_kind, .tombstone = r->tombstone ? 1u : 0u,
            .seq = r->change_seq, .expiry = r->expire_time_ms,
            .key_len = 1u, .value_len = 0u};
        if ((unsigned)r->actor_kind > QIHSE_KV_CT_ACTOR_REPLICA ||
            !row_shape(&row) || !row_authorized(principal, policy, tenant, &row) ||
            row.seq <= prior || (i == 0u && row.seq != group->first_seq)) return false;
        prior = row.seq;
    }
    if (prior != group->last_seq) return false;
    size_t limit = ceiling(max_bytes);
    size_t total = CT_HEADER + *source_len + *generation_len + group->count * CT_ROW;
    if (total > limit) return false;
    for (size_t i = 0; i < group->count; i++) {
        const qihse_kv_ct_record_t* r = &group->records[i];
        if (!r->key || (!r->tombstone && !r->value) ||
            (r->tombstone && r->value)) return false;
        size_t key_len = strnlen(r->key, CT_KEY_MAX + 1u);
        size_t value_len = r->tombstone ? 0u : strnlen(r->value, CT_VALUE_MAX + 1u);
        if (!key_len || key_len > CT_KEY_MAX || value_len > CT_VALUE_MAX ||
            !key_tenant(r->key, key_len, r->actor_tenant_id,
                        r->resource_tenant_id) ||
            key_len > limit - total) return false;
        total += key_len;
        if (value_len > limit - total) return false;
        total += value_len;
    }
    *out = total;
    return true;
}

bool qihse_ct_codec_encoded_size(qihse_user_t* principal,
    qihse_kv_ct_tenant_policy_t policy, uint32_t exact_tenant_id,
    uint8_t mode, const qihse_kv_ct_group_t* group, size_t max_bytes,
    size_t* out_bytes) {
    size_t s = 0u, g = 0u;
    return measure(principal, policy, exact_tenant_id, mode, group,
                   max_bytes, out_bytes, &s, &g);
}

bool qihse_ct_codec_group_digest(qihse_user_t* principal,
    qihse_kv_ct_tenant_policy_t policy, uint32_t exact_tenant_id,
    const qihse_kv_ct_group_t* group, unsigned char out_sha256[32]) {
    if (!out_sha256) return false;
    memset(out_sha256, 0, 32u);
    size_t size = 0u, source_len = 0u, generation_len = 0u;
    if (!measure(principal, policy, exact_tenant_id, QIHSE_CT_CODEC_MODE_SOURCE,
                 group, QIHSE_CT_CODEC_MAX_FRAME, &size, &source_len,
                 &generation_len)) return false;
    EVP_MD_CTX* md = EVP_MD_CTX_new();
    if (!md) return false;
    static const unsigned char domain[] = "QKV6-group-digest-v1";
    unsigned char fields[36];
    fields[0] = (unsigned char)policy;
    wr32(fields + 1, exact_tenant_id);
    fields[5] = (unsigned char)source_len;
    fields[6] = (unsigned char)generation_len;
    wr64(fields + 7, group->stream_position);
    wr64(fields + 15, group->first_seq);
    wr64(fields + 23, group->last_seq);
    wr32(fields + 31, (uint32_t)group->count);
    bool ok = EVP_DigestInit_ex(md, EVP_sha256(), NULL) == 1 &&
              EVP_DigestUpdate(md, domain, sizeof domain - 1u) == 1 &&
              EVP_DigestUpdate(md, fields, 35u) == 1 &&
              EVP_DigestUpdate(md, group->source_id, source_len) == 1 &&
              EVP_DigestUpdate(md, group->generation, generation_len) == 1;
    for (size_t i = 0; ok && i < group->count; i++) {
        const qihse_kv_ct_record_t* r = &group->records[i];
        ct_row row = {.actor_id = r->actor_id, .actor_tenant = r->actor_tenant_id,
            .resource_tenant = r->resource_tenant_id,
            .classification = r->classification, .sci = r->sci_compartment,
            .actor_kind = (uint8_t)r->actor_kind, .tombstone = r->tombstone ? 1u : 0u,
            .seq = r->change_seq, .expiry = r->expire_time_ms,
            .key_len = (uint32_t)strlen(r->key),
            .value_len = r->tombstone ? 0u : (uint32_t)strlen(r->value)};
        unsigned char encoded[CT_ROW];
        row_write(encoded, &row);
        ok = EVP_DigestUpdate(md, encoded, sizeof encoded) == 1 &&
             EVP_DigestUpdate(md, r->key, row.key_len) == 1 &&
             (r->tombstone || EVP_DigestUpdate(md, r->value, row.value_len) == 1);
    }
    unsigned int digest_len = 0u;
    if (ok) ok = qihse_auth_user_is_active(principal) &&
                 EVP_DigestFinal_ex(md, out_sha256, &digest_len) == 1 &&
                 digest_len == 32u;
    EVP_MD_CTX_free(md);
    if (!ok) memset(out_sha256, 0, 32u);
    return ok;
}

bool qihse_ct_codec_write(FILE* out, qihse_user_t* principal,
    qihse_kv_ct_tenant_policy_t policy, uint32_t exact_tenant_id,
    uint8_t mode, const qihse_kv_ct_group_t* group, size_t max_bytes,
    size_t* out_written) {
    if (out_written) *out_written = 0u;
    if (!out || !out_written) return false;
    size_t size = 0u, source_len = 0u, generation_len = 0u;
    if (!measure(principal, policy, exact_tenant_id, mode, group, max_bytes,
                 &size, &source_len, &generation_len) || size > UINT32_MAX)
        return false;
    unsigned char* frame = calloc(size, 1u);
    if (!frame) return false;
    memcpy(frame, ct_magic, sizeof ct_magic);
    frame[8] = mode; frame[9] = (unsigned char)policy;
    wr32(frame + 12, (uint32_t)size);
    wr32(frame + 16, (uint32_t)(group->count * CT_ROW));
    wr32(frame + 20, (uint32_t)(size - CT_HEADER - source_len - generation_len -
                                group->count * CT_ROW));
    wr32(frame + 24, (uint32_t)group->count);
    wr32(frame + 28, exact_tenant_id);
    wr64(frame + 32, group->stream_position);
    wr64(frame + 40, group->first_seq);
    wr64(frame + 48, group->last_seq);
    frame[56] = (unsigned char)source_len;
    frame[57] = (unsigned char)generation_len;
    size_t ids_at = CT_HEADER;
    memcpy(frame + ids_at, group->source_id, source_len);
    memcpy(frame + ids_at + source_len, group->generation, generation_len);
    size_t table_at = ids_at + source_len + generation_len;
    size_t body_at = table_at + group->count * CT_ROW;
    for (size_t i = 0; i < group->count; i++) {
        const qihse_kv_ct_record_t* r = &group->records[i];
        ct_row row = {.actor_id = r->actor_id, .actor_tenant = r->actor_tenant_id,
            .resource_tenant = r->resource_tenant_id,
            .classification = r->classification, .sci = r->sci_compartment,
            .actor_kind = (uint8_t)r->actor_kind, .tombstone = r->tombstone ? 1u : 0u,
            .seq = r->change_seq, .expiry = r->expire_time_ms,
            .key_len = (uint32_t)strlen(r->key),
            .value_len = r->tombstone ? 0u : (uint32_t)strlen(r->value)};
        row_write(frame + table_at + i * CT_ROW, &row);
        memcpy(frame + body_at, r->key, row.key_len); body_at += row.key_len;
        if (row.value_len) {
            memcpy(frame + body_at, r->value, row.value_len); body_at += row.value_len;
        }
    }
    unsigned char digest[32];
    unsigned int digest_len = 0u;
    bool ok = EVP_Digest(frame, size, digest, &digest_len, EVP_sha256(), NULL) == 1 &&
              digest_len == 32u && qihse_auth_user_is_active(principal);
    if (ok) memcpy(frame + 64, digest, 32u);
    ok = ok &&
              fwrite(frame, 1u, size, out) == size;
    OPENSSL_cleanse(frame, size);
    free(frame);
    if (ok) *out_written = size;
    return ok;
}

void qihse_ct_codec_clear(qihse_kv_ct_group_t* group) {
    if (!group) return;
    if (group->records) {
        for (size_t i = 0; i < group->count; i++) {
            if (group->records[i].key) {
                OPENSSL_cleanse(group->records[i].key,
                                strlen(group->records[i].key));
                free(group->records[i].key);
            }
            if (group->records[i].value) {
                OPENSSL_cleanse(group->records[i].value, strlen(group->records[i].value));
                free(group->records[i].value);
            }
        }
        free(group->records);
    }
    memset(group, 0, sizeof *group);
}

int qihse_ct_codec_read(FILE* in, qihse_user_t* principal,
    qihse_kv_ct_tenant_policy_t policy, uint32_t exact_tenant_id,
    size_t max_bytes, qihse_kv_ct_group_t* out_group, uint8_t* out_mode,
    size_t* out_read) {
    if (out_group) memset(out_group, 0, sizeof *out_group);
    if (out_mode) *out_mode = 0u;
    if (out_read) *out_read = 0u;
    if (!in || !out_group || !out_mode || !out_read || !max_bytes) return -1;
    if (!principal_policy(principal, policy, exact_tenant_id)) return -2;
    unsigned char header[CT_HEADER];
    int first = fgetc(in);
    if (first == EOF) return ferror(in) ? -1 : 0;
    header[0] = (unsigned char)first;
    if (fread(header + 1u, 1u, CT_HEADER - 1u, in) != CT_HEADER - 1u) return -1;
    uint8_t mode = header[8], frame_policy = header[9];
    size_t total = rd32(header + 12), table_size = rd32(header + 16);
    size_t body_size = rd32(header + 20), count = rd32(header + 24);
    uint32_t frame_tenant = rd32(header + 28);
    size_t source_len = header[56], generation_len = header[57];
    if (memcmp(header, ct_magic, 8u) || !mode_valid(mode) ||
        header[10] || header[11] ||
        (frame_policy != QIHSE_KV_CT_TENANT_EXACT &&
         frame_policy != QIHSE_KV_CT_TENANT_SYSTEM_ALL) ||
        !source_len || source_len > QIHSE_KV_CT_ID_MAX ||
        !generation_len || generation_len > QIHSE_KV_CT_ID_MAX ||
        !count || count > QIHSE_KV_CT_MAX_GROUP_RECORDS ||
        table_size != count * CT_ROW ||
        total > ceiling(max_bytes) ||
        total < CT_HEADER + source_len + generation_len + table_size ||
        body_size != total - CT_HEADER - source_len - generation_len - table_size ||
        !rd64(header + 32) || !rd64(header + 40) ||
        rd64(header + 40) > rd64(header + 48)) return -1;
    for (size_t i = 58u; i < 64u; i++) if (header[i]) return -1;
    if (frame_policy != (uint8_t)policy || frame_tenant != exact_tenant_id)
        return -2;
    size_t meta_size = source_len + generation_len + table_size;
    unsigned char* meta = malloc(meta_size);
    if (!meta) return -1;
    ct_row* rows = calloc(count, sizeof *rows);
    if (!rows) { free(meta); return -1; }
    int result = -1;
    unsigned char* body = NULL;
    if (fread(meta, 1u, meta_size, in) != meta_size) goto done;
    char source[QIHSE_KV_CT_ID_MAX + 1u] = {0};
    char generation[QIHSE_KV_CT_ID_MAX + 1u] = {0};
    memcpy(source, meta, source_len);
    memcpy(generation, meta + source_len, generation_len);
    size_t id_len = 0u;
    if (!id_valid(source, &id_len) || id_len != source_len ||
        !id_valid(generation, &id_len) || id_len != generation_len) goto done;
    size_t expected_body = 0u;
    uint64_t prior = 0u;
    for (size_t i = 0; i < count; i++) {
        if (!row_read(meta + source_len + generation_len + i * CT_ROW, &rows[i]) ||
            rows[i].seq <= prior || (i == 0u && rows[i].seq != rd64(header + 40)) ||
            rows[i].key_len > body_size - expected_body) goto done;
        expected_body += rows[i].key_len;
        if (rows[i].value_len > body_size - expected_body) goto done;
        expected_body += rows[i].value_len;
        prior = rows[i].seq;
    }
    if (prior != rd64(header + 48) || expected_body != body_size) goto done;
    for (size_t i = 0; i < count; i++) {
        if (!row_authorized(principal, policy, exact_tenant_id, &rows[i])) {
            result = -2;
            goto done;
        }
    }
    body = malloc(body_size ? body_size : 1u);
    if (!body || fread(body, 1u, body_size, in) != body_size) goto done;
    unsigned char saved_digest[32];
    memcpy(saved_digest, header + 64u, 32u);
    memset(header + 64u, 0, 32u);
    EVP_MD_CTX* md = EVP_MD_CTX_new();
    unsigned char calculated[32];
    unsigned int calculated_len = 0u;
    bool hash_ok = md && EVP_DigestInit_ex(md, EVP_sha256(), NULL) == 1 &&
        EVP_DigestUpdate(md, header, CT_HEADER) == 1 &&
        EVP_DigestUpdate(md, meta, meta_size) == 1 &&
        EVP_DigestUpdate(md, body, body_size) == 1 &&
        EVP_DigestFinal_ex(md, calculated, &calculated_len) == 1 &&
        calculated_len == 32u && CRYPTO_memcmp(saved_digest, calculated, 32u) == 0;
    EVP_MD_CTX_free(md);
    if (!hash_ok) goto done;
    if (!qihse_auth_user_is_active(principal)) { result = -2; goto done; }
    qihse_kv_ct_group_t group = {0};
    memcpy(group.source_id, source, source_len + 1u);
    memcpy(group.generation, generation, generation_len + 1u);
    group.stream_position = rd64(header + 32);
    group.first_seq = rd64(header + 40);
    group.last_seq = rd64(header + 48);
    group.records = calloc(count, sizeof *group.records);
    if (!group.records) goto done;
    group.count = count;
    size_t offset = 0u;
    for (size_t i = 0; i < count; i++) {
        ct_row* r = &rows[i];
        if (memchr(body + offset, 0, r->key_len) ||
            !key_tenant((const char*)body + offset, r->key_len,
                        r->actor_tenant, r->resource_tenant)) {
            qihse_ct_codec_clear(&group); goto done;
        }
        group.records[i].key = malloc((size_t)r->key_len + 1u);
        if (!group.records[i].key) { qihse_ct_codec_clear(&group); goto done; }
        memcpy(group.records[i].key, body + offset, r->key_len);
        group.records[i].key[r->key_len] = '\0';
        offset += r->key_len;
        if (!r->tombstone) {
            if (memchr(body + offset, 0, r->value_len)) {
                qihse_ct_codec_clear(&group); goto done;
            }
            group.records[i].value = malloc((size_t)r->value_len + 1u);
            if (!group.records[i].value) { qihse_ct_codec_clear(&group); goto done; }
            memcpy(group.records[i].value, body + offset, r->value_len);
            group.records[i].value[r->value_len] = '\0';
        }
        offset += r->value_len;
        group.records[i].change_seq = r->seq;
        group.records[i].expire_time_ms = r->expiry;
        group.records[i].actor_id = r->actor_id;
        group.records[i].actor_tenant_id = r->actor_tenant;
        group.records[i].resource_tenant_id = r->resource_tenant;
        group.records[i].classification = r->classification;
        group.records[i].sci_compartment = r->sci;
        group.records[i].actor_kind = (qihse_kv_ct_actor_t)r->actor_kind;
        group.records[i].tombstone = r->tombstone != 0u;
    }
    *out_group = group;
    *out_mode = mode;
    *out_read = total;
    result = 1;
done:
    if (body) { OPENSSL_cleanse(body, body_size); free(body); }
    free(meta);
    free(rows);
    return result;
}
