#define _GNU_SOURCE
#include "qihse_codegraph_packed.h"
#include "qihse_audit.h"
#include <assert.h>
#include <ftw.h>
#include <openssl/evp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define PASSWORD "CodegraphPackedPrototype1!"
static int clean_test(const char *path, const struct stat *st, int type,
                      struct FTW *walk) {
    (void)st; (void)type; (void)walk; return remove(path);
}
static void reseal(unsigned char *frame, size_t length) {
    unsigned int count = 0;
    assert(EVP_Digest(frame, length - 32, frame + length - 32, &count,
                      EVP_sha256(), NULL) == 1 && count == 32);
}
static void same(const cg_packed_record *left, const cg_packed_record *right) {
    assert(left->key_len == right->key_len);
    assert(!memcmp(left->key, right->key, left->key_len));
    assert(left->value_len == right->value_len);
    if (left->value_len)
        assert(!memcmp(left->value, right->value, left->value_len));
    assert(left->meta.classification == right->meta.classification);
    assert(left->meta.sci_compartment == right->meta.sci_compartment);
    assert(left->meta.flags == right->meta.flags);
    assert(left->meta.expire_time_ms == right->meta.expire_time_ms);
    assert(left->meta.change_seq == right->meta.change_seq);
}
int main(void) {
    char root[] = "./qihse-codegraph-packed-test-XXXXXX";
    assert(mkdtemp(root));
    assert(setenv("QIHSE_DATA_DIR", root, 1) == 0);
    assert(setenv("QIHSE_FIPS_MODE", "disabled", 1) == 0);
    assert(qihse_auth_init() && qihse_auth_bootstrap_operator(PASSWORD));
    qihse_user_t *op = qihse_auth_authenticate_id(0, PASSWORD);
    assert(op);
    assert(qihse_auth_create_user(op, 321, QIHSE_ROLE_ANALYST, 0, 0,
                                  PASSWORD, false));
    qihse_user_t *low = qihse_auth_authenticate_id(321, PASSWORD);
    assert(low);

    char node[67] = "n:";
    char edge[67] = "e:";
    memset(node + 2, 'a', 64); node[66] = 0;
    memset(edge + 2, 'b', 64); edge[66] = 0;
    unsigned char unknown[] = "{\"extra\":{\"future\":\"preserve bytes\"}}";
    unsigned char classified[] = "protected evidence";
    unsigned char literal[] = {'x', 0, 'y', 0xff};
    cg_packed_record source[] = {
        {.key = node, .key_len = 66, .value = unknown,
         .value_len = sizeof(unknown) - 1,
         .meta = {.change_seq = 101}},
        {.key = edge, .key_len = 66, .value = classified,
         .value_len = sizeof(classified) - 1,
         .meta = {.classification = 4, .sci_compartment = 2,
                  .expire_time_ms = 42, .change_seq = 102}},
        {.key = "_meta", .key_len = 5, .value = literal,
         .value_len = sizeof(literal), .meta = {.change_seq = 103}},
        {.key = "_deleted", .key_len = 8,
         .meta = {.flags = 1, .change_seq = 104}},
    };
    unsigned char *frame = NULL;
    size_t frame_len = 0;
    assert(!cg_packed_encode(source, 4, NULL, &frame, &frame_len));
    assert(!frame && !frame_len);
    assert(!cg_packed_encode(source, 4, low, &frame, &frame_len));
    assert(!frame && !frame_len);
    size_t saved_length = source[0].value_len;
    source[0].value_len = CG_PACKED_MAX_VALUE + 1u;
    assert(!cg_packed_encode(source, 4, op, &frame, &frame_len));
    assert(!frame && !frame_len);
    source[0].value_len = saved_length;
    assert(cg_packed_encode(source, 4, op, &frame, &frame_len));
    assert(frame_len > 100);
    assert(frame[24] == 1); /* n:<64hex> encoded as 32 digest bytes */
    cg_packed_record *decoded = NULL; size_t count = 0;
    assert(!cg_packed_decode(frame, frame_len, NULL, &decoded, &count));
    assert(!decoded && !count);
    assert(!cg_packed_decode(frame, frame_len, low, &decoded, &count));
    assert(!decoded && !count);
    assert(cg_packed_decode(frame, frame_len, op, &decoded, &count));
    assert(count == 4);
    for (size_t i = 0; i < count; i++) same(source + i, decoded + i);
    cg_packed_records_free(decoded, count);
    decoded = NULL; count = 0;

    assert(!cg_packed_decode(frame, frame_len - 1, op, &decoded, &count));
    unsigned char *bad = malloc(frame_len + 1);
    assert(bad);
    memcpy(bad, frame, frame_len); bad[frame_len] = 0;
    assert(!cg_packed_decode(bad, frame_len + 1, op, &decoded, &count));
    bad[24] ^= 1;
    assert(!cg_packed_decode(bad, frame_len, op, &decoded, &count));
    memcpy(bad, frame, frame_len);
    bad[24] = 9; reseal(bad, frame_len);
    assert(!cg_packed_decode(bad, frame_len, op, &decoded, &count));
    memcpy(bad, frame, frame_len);
    size_t value_length_offset = 24 + 1 + 32 + 2 + 2 + 1 + 8 + 8;
    memset(bad + value_length_offset, 0xff, 4); reseal(bad, frame_len);
    assert(!cg_packed_decode(bad, frame_len, op, &decoded, &count));
    memcpy(bad, frame, frame_len);
    memset(bad + 8, 0xff, 4); reseal(bad, frame_len);
    assert(!cg_packed_decode(bad, frame_len, op, &decoded, &count));
    memcpy(bad, frame, frame_len);
    bad[20] = 1; reseal(bad, frame_len);
    assert(!cg_packed_decode(bad, frame_len, op, &decoded, &count));
    memcpy(bad, frame, frame_len);
    size_t second_class_offset = 24 + 1 + 32 + 2 + 2 + 1 + 8 + 8 + 4 +
                                 source[0].value_len + 1 + 32;
    memset(bad + second_class_offset, 0, 4); reseal(bad, frame_len);
    assert(!cg_packed_decode(bad, frame_len, low, &decoded, &count));
    assert(!decoded && !count); /* even a re-sealed label cannot grant a low user */
    /* Recheck structurally changed, valid-checksum frames under sanitizers. */
    uint32_t seed = 0x825d2143u;
    for (size_t i = 0; i < 512; i++) {
        memcpy(bad, frame, frame_len);
        seed ^= seed << 13; seed ^= seed >> 17; seed ^= seed << 5;
        size_t position = 8 + seed % (frame_len - 8 - 32);
        bad[position] ^= (unsigned char)(1u << (i % 8));
        reseal(bad, frame_len);
        if (cg_packed_decode(bad, frame_len, op, &decoded, &count)) {
            cg_packed_records_free(decoded, count);
            decoded = NULL; count = 0;
        } else assert(!decoded && !count);
    }
    free(bad);
    unsigned char *extra = frame; size_t extra_len = 1;
    assert(!cg_packed_encode(source, CG_PACKED_MAX_RECORDS + 1u,
                             op, &extra, &extra_len));
    assert(!extra && !extra_len);
    assert(qihse_auth_destroy_user(op, 321));
    assert(!cg_packed_decode(frame, frame_len, low, &decoded, &count));
    free(frame);
    qihse_audit_shutdown();
    assert(nftw(root, clean_test, 16, FTW_DEPTH | FTW_PHYS) == 0);
    puts("CodeGraph packed prototype: exact records, labels, bounds and corruption PASS");
    return 0;
}
