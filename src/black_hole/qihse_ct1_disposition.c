#include "qihse_ct1_disposition.h"
#include "qihse_ct_codec.h"
#include <openssl/crypto.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <string.h>

/* Fixed offsets, network byte order; length is redundant to make framing
 * explicit. The complete canonical manifest binds identity, position,
 * tombstone, cursor and high-water, not just the original frame digest. */
enum { HEADER = 16, MANIFEST = HEADER,
    FRAME = MANIFEST + QIHSE_CT1_RECOVERY_WIRE_SIZE,
    CHECKSUM = FRAME + QIHSE_CT1_RECOVERY_FRAME_BYTES };
static const unsigned char magic[8] = {'Q','C','T','1','S','O','0','1'};
static const unsigned char source_magic[8] = {'Q','K','V','6','C','T','0','1'};
typedef char disposition_size_check[
    CHECKSUM + 32 == QIHSE_CT1_DISPOSITION_SIZE ? 1 : -1];

static void put32(unsigned char *p, uint32_t v) {
    p[0] = (unsigned char)(v >> 24);
    p[1] = (unsigned char)(v >> 16);
    p[2] = (unsigned char)(v >> 8);
    p[3] = (unsigned char)v;
}
static uint32_t get32(const unsigned char *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
        ((uint32_t)p[2] << 8) | p[3];
}
static uint64_t get64(const unsigned char *p) {
    uint64_t v = 0;
    for (unsigned i = 0; i < 8; ++i) v = (v << 8) | p[i];
    return v;
}
static bool source_authorized(const unsigned char *frame,
    const qihse_user_t *principal,
    const qihse_ct1_recovery_manifest_t *expected);
/* Reject mismatched framing before the authorized CT read. */
static bool source_envelope(const unsigned char *frame,
    const qihse_ct1_recovery_manifest_t *expected) {
    return !memcmp(frame, source_magic, sizeof(source_magic)) &&
        frame[8] == 1 && get32(frame + 12) == QIHSE_CT1_RECOVERY_FRAME_BYTES &&
        get64(frame + 32) == expected->frame_position;
}

static bool manifest_for_principal(const qihse_user_t *principal,
    const qihse_ct1_recovery_manifest_t *expected,
    unsigned char wire[QIHSE_CT1_RECOVERY_WIRE_SIZE]) {
    if (!principal || !expected || !qihse_auth_user_is_active(principal) ||
        qihse_user_get_tenant_id(principal) != expected->principal_tenant_id ||
        !qihse_auth_can_access(principal, expected->classification, expected->sci) ||
        (expected->row_tenant_id != 0 &&
         qihse_user_get_tenant_id(principal) != QIHSE_TENANT_SYSTEM &&
         qihse_user_get_tenant_id(principal) != expected->row_tenant_id))
        return false;
    return qihse_ct1_recovery_encode(expected, false, false, wire);
}

bool qihse_ct1_disposition_encode(const qihse_user_t *principal,
    const qihse_ct1_recovery_manifest_t *expected,
    const unsigned char *original_frame, size_t original_length,
    unsigned char out[QIHSE_CT1_DISPOSITION_SIZE]) {
    unsigned char wire[QIHSE_CT1_RECOVERY_WIRE_SIZE], digest[32];
    unsigned char candidate[QIHSE_CT1_DISPOSITION_SIZE];
    if (!out || !original_frame || original_length != QIHSE_CT1_RECOVERY_FRAME_BYTES ||
        !manifest_for_principal(principal, expected, wire) ||
        !source_envelope(original_frame, expected) ||
        !source_authorized(original_frame, principal, expected) ||
        !SHA256(original_frame, original_length, digest) ||
        memcmp(digest, expected->frame_sha256, sizeof(digest))) return false;
    memcpy(candidate, magic, sizeof(magic));
    put32(candidate + 8, QIHSE_CT1_DISPOSITION_SIZE);
    put32(candidate + 12, (uint32_t)original_length);
    memcpy(candidate + MANIFEST, wire, sizeof(wire));
    memcpy(candidate + FRAME, original_frame, original_length);
    bool ok = SHA256(candidate, CHECKSUM, candidate + CHECKSUM) != NULL;
    if (ok) memcpy(out, candidate, sizeof(candidate));
    OPENSSL_cleanse(candidate, sizeof(candidate));
    return ok;
}

bool qihse_ct1_disposition_decode(const qihse_user_t *principal,
    const qihse_ct1_recovery_manifest_t *expected,
    const unsigned char *data, size_t length,
    qihse_ct1_disposition_view_t *out) {
    unsigned char wire[QIHSE_CT1_RECOVERY_WIRE_SIZE], digest[32];
    if (!out) return false;
    *out = (qihse_ct1_disposition_view_t){0};
    if (!data || length != QIHSE_CT1_DISPOSITION_SIZE ||
        memcmp(data, magic, sizeof(magic)) ||
        get32(data + 8) != QIHSE_CT1_DISPOSITION_SIZE ||
        get32(data + 12) != QIHSE_CT1_RECOVERY_FRAME_BYTES ||
        !manifest_for_principal(principal, expected, wire) ||
        memcmp(data + MANIFEST, wire, sizeof(wire)) ||
        !source_envelope(data + FRAME, expected) ||
        !source_authorized(data + FRAME, principal, expected) ||
        !SHA256(data, CHECKSUM, digest) ||
        memcmp(data + CHECKSUM, digest, sizeof(digest)) ||
        !SHA256(data + FRAME, QIHSE_CT1_RECOVERY_FRAME_BYTES, digest) ||
        memcmp(digest, expected->frame_sha256, sizeof(digest))) return false;
    out->original_frame = data + FRAME;
    out->original_length = QIHSE_CT1_RECOVERY_FRAME_BYTES;
    return true;
}

/* Reuse native all-row authorization before exposing any frame bytes. */
static bool source_authorized(const unsigned char *frame,
    const qihse_user_t *principal,
    const qihse_ct1_recovery_manifest_t *expected) {
    qihse_kv_ct_group_t group = {0};
    uint8_t mode = 0;
    size_t consumed = 0;
    bool ok = false;
    char key[QIHSE_CT1_RECOVERY_ID_MAX + 32u];
    FILE *in = fmemopen((void *)frame, QIHSE_CT1_RECOVERY_FRAME_BYTES, "rb");
    if (!in) goto done;
    /* Native source stores may encode system-wide groups; their selected row
     * still has to match the manifest's exact system-tenant key and label. */
    qihse_kv_ct_tenant_policy_t policy = expected->row_tenant_id == 0 &&
        frame[9] == QIHSE_KV_CT_TENANT_SYSTEM_ALL ?
        QIHSE_KV_CT_TENANT_SYSTEM_ALL : QIHSE_KV_CT_TENANT_EXACT;
    int result = qihse_ct_codec_read(in, (qihse_user_t *)principal,
        policy, expected->row_tenant_id,
        QIHSE_CT1_RECOVERY_FRAME_BYTES, &group, &mode, &consumed);
    if (result != 1 || mode != QIHSE_CT_CODEC_MODE_SOURCE ||
        consumed != QIHSE_CT1_RECOVERY_FRAME_BYTES || fgetc(in) != EOF ||
        ferror(in) || group.count != 1 ||
        strcmp(group.source_id, expected->source_store_id) ||
        strcmp(group.generation, expected->generation) ||
        group.stream_position != expected->frame_position) goto done;
    const qihse_kv_ct_record_t *row = &group.records[0];
    int n = expected->row_tenant_id ?
        snprintf(key, sizeof(key), "t:%u/%s", expected->row_tenant_id,
            expected->row_key) :
        snprintf(key, sizeof(key), "commons/%s", expected->row_key);
    /* Tenant-zero system-authored keys can also be unprefixed. */
    ok = n > 0 && (size_t)n < sizeof(key) &&
        (!strcmp(row->key, key) ||
         (expected->row_tenant_id == 0 && !strcmp(row->key, expected->row_key))) &&
        row->change_seq == expected->row_change_seq &&
        row->classification == expected->classification &&
        row->sci_compartment == expected->sci &&
        row->resource_tenant_id == expected->row_tenant_id;
done:
    qihse_ct_codec_clear(&group);
    if (in) fclose(in);
    return ok;
}
