#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "qihse_ct_codec.h"
#include <assert.h>
#include <openssl/evp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Hermetic principals exercise the codec's lowest-layer authorization. */
struct qihse_user_s {
    uint32_t tenant;
    uint16_t role, clearance, sci;
    bool active;
};
bool qihse_auth_user_is_active(const qihse_user_t* u) { return u && u->active; }
uint32_t qihse_user_get_tenant_id(const qihse_user_t* u) { return u->tenant; }
uint16_t qihse_user_get_role(const qihse_user_t* u) { return u->role; }
bool qihse_auth_can_access(const qihse_user_t* u, uint16_t label, uint16_t sci) {
    return u && u->active && (u->role == QIHSE_ROLE_OPERATOR ||
           (u->clearance >= label && (u->sci & sci) == sci));
}

static qihse_user_t operator_user = {0, QIHSE_ROLE_OPERATOR, 65535, 65535, true};
static qihse_user_t low_user = {7, QIHSE_ROLE_ANALYST, 0, 0, true};
static qihse_user_t no_sci = {7, QIHSE_ROLE_ANALYST, 4, 0, true};
static qihse_user_t high_user = {7, QIHSE_ROLE_ANALYST, 4, 2, true};
static qihse_user_t other_tenant = {8, QIHSE_ROLE_ANALYST, 4, 2, true};
static qihse_user_t revoked = {7, QIHSE_ROLE_ANALYST, 4, 2, false};
static qihse_user_t system_service = {0, QIHSE_ROLE_ANALYST, 4, 2, true};
static qihse_user_t system_low = {0, QIHSE_ROLE_ANALYST, 0, 0, true};

static qihse_kv_ct_record_t rows[2] = {
    {.key = "t:7/item", .value = "sensitive", .change_seq = 10,
     .expire_time_ms = 123456, .actor_id = 71, .actor_tenant_id = 7,
     .resource_tenant_id = 7, .classification = 4, .sci_compartment = 2,
     .actor_kind = QIHSE_KV_CT_ACTOR_USER},
    {.key = "t:7/item", .value = NULL, .change_seq = 12,
     .actor_id = 71, .actor_tenant_id = 7, .resource_tenant_id = 7,
     .classification = 4, .sci_compartment = 2,
     .actor_kind = QIHSE_KV_CT_ACTOR_USER, .tombstone = true}
};
static qihse_kv_ct_group_t group = {
    .source_id = "source_A", .generation = "generation_1",
    .stream_position = 3, .first_seq = 10, .last_seq = 12,
    .records = rows, .count = 2
};

static FILE* encoded(uint8_t mode, size_t* size) {
    FILE* f = tmpfile(); assert(f);
    assert(qihse_ct_codec_write(f, &operator_user, QIHSE_KV_CT_TENANT_EXACT,
                                7, mode, &group, QIHSE_CT_CODEC_MAX_FRAME, size));
    assert(*size > 0 && ftell(f) == (long)*size);
    rewind(f);
    return f;
}
static void empty(const qihse_kv_ct_group_t* g) {
    assert(g->records == NULL && g->count == 0 && g->stream_position == 0);
}
static void round_trip(uint8_t mode) {
    size_t measured = 0, written = 0, read_bytes = 0;
    assert(qihse_ct_codec_encoded_size(&operator_user, QIHSE_KV_CT_TENANT_EXACT,
                                       7, mode, &group, QIHSE_CT_CODEC_MAX_FRAME,
                                       &measured));
    FILE* f = encoded(mode, &written);
    assert(measured == written);
    qihse_kv_ct_group_t got = {0}; uint8_t got_mode = 0;
    assert(qihse_ct_codec_read(f, &high_user, QIHSE_KV_CT_TENANT_EXACT, 7,
                               QIHSE_CT_CODEC_MAX_FRAME, &got, &got_mode,
                               &read_bytes) == 1);
    assert(read_bytes == written && got_mode == mode && got.count == 2);
    assert(!strcmp(got.source_id, group.source_id) &&
           !strcmp(got.generation, group.generation) &&
           got.stream_position == 3 && got.first_seq == 10 && got.last_seq == 12);
    assert(!strcmp(got.records[0].key, "t:7/item") &&
           !strcmp(got.records[0].value, "sensitive") &&
           got.records[0].expire_time_ms == 123456 &&
           got.records[0].classification == 4 && got.records[0].sci_compartment == 2);
    assert(!strcmp(got.records[1].key, got.records[0].key) &&
           got.records[1].tombstone && !got.records[1].value);
    qihse_ct_codec_clear(&got); empty(&got);
    assert(qihse_ct_codec_read(f, &operator_user, QIHSE_KV_CT_TENANT_EXACT,
                               7, QIHSE_CT_CODEC_MAX_FRAME, &got, &got_mode,
                               &read_bytes) == 0);
    empty(&got);
    fclose(f);
}
static void authorization(void) {
    size_t bytes = 123;
    qihse_kv_ct_group_t fake = group;
    qihse_kv_ct_record_t inaccessible = rows[0];
    inaccessible.key = (char*)(uintptr_t)1;
    inaccessible.value = (char*)(uintptr_t)1;
    fake.records = &inaccessible; fake.count = 1; fake.last_seq = 10;
    assert(!qihse_ct_codec_encoded_size(&low_user, QIHSE_KV_CT_TENANT_EXACT,
                                        7, 1, &fake, 4096, &bytes) && bytes == 0);
    FILE* denied_write = tmpfile(); assert(denied_write);
    assert(!qihse_ct_codec_write(denied_write, &low_user, QIHSE_KV_CT_TENANT_EXACT,
                                 7, 1, &fake, 4096, &bytes) && bytes == 0);
    assert(ftell(denied_write) == 0); fclose(denied_write);
    size_t size = 0; FILE* f = encoded(1, &size);
    qihse_user_t* denied[] = {&low_user, &no_sci, &other_tenant, &revoked, NULL};
    for (size_t i = 0; i < sizeof denied / sizeof denied[0]; i++) {
        rewind(f);
        qihse_kv_ct_group_t out = {0}; uint8_t mode = 99; size_t read_bytes = 99;
        int rc = qihse_ct_codec_read(f, denied[i], QIHSE_KV_CT_TENANT_EXACT,
                                     7, size, &out, &mode, &read_bytes);
        assert(rc == -2 && mode == 0 && read_bytes == 0);
        empty(&out);
        if (denied[i] == &low_user || denied[i] == &no_sci)
            assert(ftell(f) < (long)size); /* body never read */
    }
    rewind(f);
    qihse_kv_ct_group_t out = {0}; uint8_t mode = 99; size_t read_bytes = 99;
    assert(qihse_ct_codec_read(f, &operator_user, QIHSE_KV_CT_TENANT_EXACT,
                               8, size, &out, &mode, &read_bytes) == -2);
    empty(&out); fclose(f);
}
static void bounds_and_digest(void) {
    size_t size = 0;
    assert(qihse_ct_codec_encoded_size(&operator_user, QIHSE_KV_CT_TENANT_EXACT,
                                       7, 1, &group, QIHSE_CT_CODEC_MAX_FRAME, &size));
    assert(!qihse_ct_codec_encoded_size(&operator_user, QIHSE_KV_CT_TENANT_EXACT,
                                        7, 1, &group, size - 1, &size));
    qihse_kv_ct_group_t altered = group;
    altered.last_seq = altered.first_seq;
    assert(!qihse_ct_codec_encoded_size(&operator_user, QIHSE_KV_CT_TENANT_EXACT,
                                        7, 1, &altered, 4096, &size));
    altered = group; altered.count = QIHSE_KV_CT_MAX_GROUP_RECORDS + 1u;
    assert(!qihse_ct_codec_encoded_size(&operator_user, QIHSE_KV_CT_TENANT_EXACT,
                                        7, 1, &altered, 4096, &size));
    altered = group; altered.source_id[0] = '/';
    assert(!qihse_ct_codec_encoded_size(&operator_user, QIHSE_KV_CT_TENANT_EXACT,
                                        7, 1, &altered, 4096, &size));
    altered = group;
    strcpy(altered.source_id, "192.168.1.90:6379");
    assert(qihse_ct_codec_encoded_size(&operator_user, QIHSE_KV_CT_TENANT_EXACT,
                                       7, 1, &altered, 4096, &size));
    assert(!qihse_ct_codec_encoded_size(&operator_user, QIHSE_KV_CT_TENANT_EXACT,
                                        7, 0, &group, 4096, &size));
    qihse_kv_ct_record_t saved = rows[1];
    rows[1].change_seq = 10; /* duplicate local sequence forbidden */
    assert(!qihse_ct_codec_encoded_size(&operator_user, QIHSE_KV_CT_TENANT_EXACT,
                                        7, 1, &group, 4096, &size));
    rows[1] = saved;
    unsigned char digest_a[32], digest_b[32], digest_c[32];
    assert(qihse_ct_codec_group_digest(&operator_user, QIHSE_KV_CT_TENANT_EXACT,
                                       7, &group, digest_a));
    assert(qihse_ct_codec_group_digest(&high_user, QIHSE_KV_CT_TENANT_EXACT,
                                       7, &group, digest_b));
    assert(!memcmp(digest_a, digest_b, 32));
    rows[0].value = "changed";
    assert(qihse_ct_codec_group_digest(&operator_user, QIHSE_KV_CT_TENANT_EXACT,
                                       7, &group, digest_c));
    assert(memcmp(digest_a, digest_c, 32));
    rows[0].value = "sensitive";
    assert(!qihse_ct_codec_group_digest(&low_user, QIHSE_KV_CT_TENANT_EXACT,
                                        7, &group, digest_c));
    for (size_t i = 0; i < 32; i++) assert(digest_c[i] == 0);
    rows[0].key = "t:07/item";
    assert(!qihse_ct_codec_encoded_size(&operator_user, QIHSE_KV_CT_TENANT_EXACT,
                                        7, 1, &group, 4096, &size));
    rows[0].key = "t:7/item";
    rows[0].actor_tenant_id = 8;
    assert(!qihse_ct_codec_encoded_size(&operator_user, QIHSE_KV_CT_TENANT_EXACT,
                                        7, 1, &group, 4096, &size));
    rows[0].actor_tenant_id = 7;
    rows[0].actor_tenant_id = QIHSE_TENANT_INVALID;
    assert(!qihse_ct_codec_encoded_size(&operator_user, QIHSE_KV_CT_TENANT_EXACT,
                                        7, 1, &group, 4096, &size));
    rows[0].actor_tenant_id = 7;
    rows[0].resource_tenant_id = QIHSE_TENANT_INVALID;
    assert(!qihse_ct_codec_encoded_size(&operator_user, QIHSE_KV_CT_TENANT_EXACT,
                                        7, 1, &group, 4096, &size));
    rows[0].resource_tenant_id = 7;
    rows[1].expire_time_ms = 1;
    assert(!qihse_ct_codec_encoded_size(&operator_user, QIHSE_KV_CT_TENANT_EXACT,
                                        7, 1, &group, 4096, &size));
    rows[1].expire_time_ms = 0;
}
static void system_all_and_commons(void) {
    qihse_kv_ct_record_t mixed[2] = {rows[0], rows[1]};
    mixed[0].actor_tenant_id = 0;
    mixed[1].actor_tenant_id = 0;
    mixed[1].key = "t:8/item";
    mixed[1].resource_tenant_id = 8;
    qihse_kv_ct_group_t batch = group;
    batch.records = mixed;
    size_t n = 0;
    assert(qihse_ct_codec_encoded_size(&system_service, QIHSE_KV_CT_TENANT_SYSTEM_ALL,
                                       0, 1, &batch, 4096, &n));
    assert(!qihse_ct_codec_encoded_size(&system_service, QIHSE_KV_CT_TENANT_EXACT,
                                        7, 1, &batch, 4096, &n));
    assert(!qihse_ct_codec_encoded_size(&system_low, QIHSE_KV_CT_TENANT_SYSTEM_ALL,
                                        0, 1, &batch, 4096, &n));
    FILE* f = tmpfile(); assert(f);
    assert(qihse_ct_codec_write(f, &system_service, QIHSE_KV_CT_TENANT_SYSTEM_ALL,
                                0, 2, &batch, 4096, &n));
    rewind(f);
    qihse_kv_ct_group_t out = {0}; uint8_t mode = 0; size_t read_bytes = 0;
    assert(qihse_ct_codec_read(f, &system_service, QIHSE_KV_CT_TENANT_SYSTEM_ALL,
                               0, 4096, &out, &mode, &read_bytes) == 1);
    assert(mode == 2 && read_bytes == n && out.records[1].resource_tenant_id == 8);
    qihse_ct_codec_clear(&out); fclose(f);
    mixed[1] = rows[1];
    mixed[1].key = "commons/shared";
    mixed[1].resource_tenant_id = 0;
    mixed[1].actor_tenant_id = 7;
    batch.records = &mixed[1]; batch.count = 1; batch.first_seq = batch.last_seq = 12;
    assert(qihse_ct_codec_encoded_size(&operator_user, QIHSE_KV_CT_TENANT_EXACT,
                                       0, 1, &batch, 4096, &n));
    assert(qihse_ct_codec_encoded_size(&high_user, QIHSE_KV_CT_TENANT_EXACT,
                                       0, 1, &batch, 4096, &n));
    mixed[1].key = "system/private";
    assert(!qihse_ct_codec_encoded_size(&high_user, QIHSE_KV_CT_TENANT_EXACT,
                                        0, 1, &batch, 4096, &n));
}
static uint32_t get32(const unsigned char* p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | p[3];
}
static void put64(unsigned char* p, uint64_t value) {
    for (unsigned i = 0; i < 8; i++) p[i] = (unsigned char)(value >> (56u - 8u * i));
}
static void checksum(unsigned char* data, size_t size) {
    unsigned char digest[32]; unsigned int n = 0;
    memset(data + 64, 0, 32);
    assert(EVP_Digest(data, size, digest, &n, EVP_sha256(), NULL) && n == 32);
    memcpy(data + 64, digest, 32);
}
static void check_bad(const unsigned char* data, size_t size, int expected) {
    FILE* f = tmpfile(); assert(f);
    assert(fwrite(data, 1, size, f) == size); rewind(f);
    qihse_kv_ct_group_t out = {0}; uint8_t mode = 99; size_t read_bytes = 99;
    int rc = qihse_ct_codec_read(f, &operator_user, QIHSE_KV_CT_TENANT_EXACT,
                                  7, QIHSE_CT_CODEC_MAX_FRAME, &out, &mode,
                                  &read_bytes);
    assert((rc == expected || (expected == -1 && rc == -2)) &&
           mode == 0 && read_bytes == 0);
    empty(&out);
    fclose(f);
}
static void corruption(void) {
    size_t size = 0; FILE* f = encoded(1, &size);
    qihse_kv_ct_group_t bounded = {0}; uint8_t mode = 99; size_t read_bytes = 99;
    assert(qihse_ct_codec_read(f, &operator_user, QIHSE_KV_CT_TENANT_EXACT,
                               7, size - 1u, &bounded, &mode, &read_bytes) == -1);
    assert(mode == 0 && read_bytes == 0); empty(&bounded);
    rewind(f);
    unsigned char* bytes = malloc(size); assert(bytes);
    assert(fread(bytes, 1, size, f) == size); fclose(f);
    check_bad(bytes, size - 1u, -1); /* truncated protected body */
    unsigned char saved = bytes[0]; bytes[0] ^= 1u;
    check_bad(bytes, size, -1); bytes[0] = saved;
    size_t body_at = 96u + bytes[56] + bytes[57] + get32(bytes + 16);
    for (size_t i = 0; i < size; i += 7u) {
        saved = bytes[i]; bytes[i] ^= 1u;
        check_bad(bytes, size, -1);
        bytes[i] = saved;
    }
    /* Recompute the checksum so validation must independently reject an
     * embedded NUL in the key or value after complete frame integrity. */
    saved = bytes[body_at]; bytes[body_at] = 0;
    checksum(bytes, size);
    check_bad(bytes, size, -1);
    bytes[body_at] = saved;
    size_t second_row = 96u + bytes[56] + bytes[57] + 48u;
    put64(bytes + second_row + 20u, 10u); /* duplicate sequence, valid checksum */
    checksum(bytes, size);
    check_bad(bytes, size, -1);
    free(bytes);
}
int main(void) {
    round_trip(QIHSE_CT_CODEC_MODE_SOURCE);
    round_trip(QIHSE_CT_CODEC_MODE_RECEIVER);
    authorization();
    bounds_and_digest();
    system_all_and_commons();
    corruption();
    puts("CT codec tests passed");
    return 0;
}
