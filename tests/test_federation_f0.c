/*
 * test_federation_f0.c — Federation stage F0 primitives.
 *
 * Identity (UUID), hybrid logical time, object generations, and fencing
 * epochs: the vocabulary the federation stages build on. No cluster
 * behaviour is touched by this stage.
 */
#include "qihse_federation.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static void test_uuid(void) {
    qihse_uuid_t a, b, c;
    assert(qihse_uuid_generate(&a));
    assert(qihse_uuid_generate(&b));
    assert(!qihse_uuid_equal(&a, &b)); /* random: collisions are not expected */

    char text[QIHSE_UUID_STR_LEN + 1u];
    assert(qihse_uuid_format(&a, text));
    assert(strlen(text) == QIHSE_UUID_STR_LEN);
    assert(text[8] == '-' && text[13] == '-' && text[18] == '-' && text[23] == '-');
    assert(text[14] == '4'); /* version 4 */
    assert(strchr("89ab", text[19]) != NULL); /* RFC 4122 variant */

    assert(qihse_uuid_parse(text, &c));
    assert(qihse_uuid_equal(&a, &c));
    assert(!qihse_uuid_parse("not-a-uuid", &c));
    assert(!qihse_uuid_parse("12345678-1234-1234-1234-12345678901", &c));

    /* Name-based identity is stable across calls and distinct per seed. */
    qihse_uuid_t s1, s2, s3;
    assert(qihse_uuid_from_seed("node-alpha", 10u, &s1));
    assert(qihse_uuid_from_seed("node-alpha", 10u, &s2));
    assert(qihse_uuid_from_seed("node-beta", 9u, &s3));
    assert(qihse_uuid_equal(&s1, &s2));
    assert(!qihse_uuid_equal(&s1, &s3));
    assert(s1.bytes[6] >> 4 == 5u); /* version 5 */

    qihse_uuid_t nil;
    memset(&nil, 0, sizeof nil);
    assert(qihse_uuid_is_nil(&nil));
    assert(!qihse_uuid_is_nil(&s1));
    printf("PASS uuid: generate/format/parse/seed round-trips\n");
}

static void test_hlc(void) {
    qihse_hlc_t clock, t1, t2, t3;
    qihse_hlc_init(&clock);
    qihse_hlc_tick(&clock, &t1);
    qihse_hlc_tick(&clock, &t2);
    qihse_hlc_tick(&clock, &t3);
    /* Monotonic even inside the same millisecond. */
    assert(qihse_hlc_compare(&t1, &t2) < 0);
    assert(qihse_hlc_compare(&t2, &t3) < 0);

    /* Observing a remote timestamp that is ahead pushes the next tick past it. */
    qihse_hlc_t remote = {t3.physical_ms + 5000u, 7u};
    qihse_hlc_observe(&clock, &remote);
    qihse_hlc_t next;
    qihse_hlc_tick(&clock, &next);
    assert(qihse_hlc_compare(&next, &remote) > 0);

    /* Packing preserves order. */
    assert(qihse_hlc_pack(&t1) < qihse_hlc_pack(&t2));
    qihse_hlc_t round;
    qihse_hlc_unpack(qihse_hlc_pack(&t2), &round);
    assert(qihse_hlc_compare(&round, &t2) == 0);
    assert(qihse_hlc_compare(&t2, &t2) == 0);
    printf("PASS hlc: monotonic ticks, causal observe, sortable packing\n");
}

static void test_object_version(void) {
    qihse_uuid_t object;
    assert(qihse_uuid_from_seed("object-1", 8u, &object));
    qihse_object_version_t v1, v2;
    qihse_hlc_t clock;
    qihse_hlc_init(&clock);
    qihse_object_version_init(&v1, &object);
    qihse_object_version_init(&v2, &object);
    assert(v1.generation == 1u);
    assert(qihse_object_version_compare(&v1, &v2) == 0);

    qihse_object_version_bump(&v1, &clock);
    assert(v1.generation == 2u);
    assert(qihse_object_version_compare(&v1, &v2) > 0); /* newer generation wins */
    assert(qihse_object_version_compare(&v2, &v1) < 0);

    /* Equal generations fall back to the HLC stamp. */
    qihse_object_version_bump(&v2, &clock);
    assert(v1.generation == v2.generation);
    assert(qihse_object_version_compare(&v1, &v2) < 0);
    printf("PASS object version: generation ordering with HLC tie-break\n");
}

static void test_fencing(void) {
    qihse_uuid_t holder_a, holder_b;
    assert(qihse_uuid_from_seed("holder-a", 8u, &holder_a));
    assert(qihse_uuid_from_seed("holder-b", 8u, &holder_b));

    qihse_fencing_token_t token;
    qihse_fencing_token_init(&token);
    assert(token.epoch == 0u);

    /* The holder must have observed the epoch it is replacing. */
    assert(!qihse_fencing_acquire(&token, 5u, &holder_a)); /* stale view: refused */
    assert(qihse_fencing_acquire(&token, 0u, &holder_a));
    assert(token.epoch == 1u);
    assert(qihse_uuid_equal(&token.holder, &holder_a));

    /* A second acquirer with a stale observation is refused (fail closed). */
    assert(!qihse_fencing_acquire(&token, 0u, &holder_b));
    assert(qihse_fencing_acquire(&token, 1u, &holder_b));
    assert(token.epoch == 2u);
    assert(qihse_uuid_equal(&token.holder, &holder_b));

    assert(qihse_fencing_valid(&token, 0u));
    assert(qihse_fencing_valid(&token, 1u));
    assert(!qihse_fencing_valid(&token, 2u));
    printf("PASS fencing: monotonic epochs, stale holders fail closed\n");
}

int main(void) {
    test_uuid();
    test_hlc();
    test_object_version();
    test_fencing();
    printf("federation F0 tests passed\n");
    return 0;
}
