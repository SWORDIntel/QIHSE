/*
 * test_bolt.c — Neo4j Bolt adapter: PackStream codec, message framing and
 * the version handshake.
 *
 * Exercises src/spinnaker/qihse_bolt.c.
 *
 * Asserted (works):
 *   1.  PackStream round trip: null, bool, int (positive tiny / negative tiny / int8 / int16 /
 *       int32 / int64), float64, string (tiny / empty / 8-bit / 16-bit lengths), list
 *       (tiny / 8-bit), map (tiny / 8-bit / 16-bit / 32-bit), tiny struct
 *       with the Node/Relationship/Path signatures
 *   2.  Truncated input is refused rather than mis-decoded
 *   3.  Message framing: single-chunk encode/decode round trip, two messages
 *       back to back, multi-chunk reassembly, partial input returns "need
 *       more data", and an empty message is an error
 *   4.  Handshake over a socketpair: magic + version proposals select 4.0,
 *       a wrong magic byte is refused, and an unknown version is refused
 *   5.  Client message loop over a socketpair: RESET is answered with a
 *       SUCCESS frame and GOODBYE ends the session
 *   6.  Bolt 4.x spec compliance: client->server message signatures (HELLO, GOODBYE,
 *       RESET 0x0F, RUN 0x10, BEGIN 0x11, COMMIT 0x12, ROLLBACK 0x13, DISCARD 0x2F, PULL 0x3F)
 *       and PackStream tiny map/int/string/list encoding and decoding.
 */
#include "qihse_bolt.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>

/* ── 1. PackStream round trip ───────────────────────────────────────────── */

static qihse_bolt_value_t* round_trip(const qihse_bolt_buf_t* b) {
    qihse_bolt_decoder_t d;
    qihse_bolt_decoder_init(&d, b->buf, b->len);
    return qihse_bolt_decode(&d);
}

static void test_packstream_primitives(void) {
    qihse_bolt_buf_t b;
    qihse_bolt_value_t* v;

    qihse_bolt_buf_init(&b, 64);
    qihse_bolt_encode_null(&b);
    v = round_trip(&b);
    assert(v && v->type == QIHSE_BOLT_NULL);
    qihse_bolt_value_free(v);
    qihse_bolt_buf_free(&b);

    qihse_bolt_buf_init(&b, 64);
    qihse_bolt_encode_bool(&b, true);
    qihse_bolt_encode_bool(&b, false);
    qihse_bolt_decoder_t d;
    qihse_bolt_decoder_init(&d, b.buf, b.len);
    v = qihse_bolt_decode(&d);
    assert(v && v->type == QIHSE_BOLT_BOOL && v->v.b == true);
    qihse_bolt_value_free(v);
    v = qihse_bolt_decode(&d);
    assert(v && v->type == QIHSE_BOLT_BOOL && v->v.b == false);
    qihse_bolt_value_free(v);
    qihse_bolt_buf_free(&b);

    /* Integers in the ranges the codec handles. */
    int64_t cases[] = {
        0, 1, 42, 127,             /* tiny positive */
        -1, -5, -16,               /* tiny negative (-16..-1) */
        128, 32767,                /* int16 */
        32768, 2147483647LL,       /* int32 */
        2147483648LL, 1234567890123LL, INT64_MIN, INT64_MAX,
        -17, -128, -32768, -2147483648LL, INT64_MIN + 1
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        qihse_bolt_buf_init(&b, 16);
        qihse_bolt_encode_int(&b, cases[i]);
        v = round_trip(&b);
        assert(v && v->type == QIHSE_BOLT_INT);
        assert(v->v.i == cases[i]);
        qihse_bolt_value_free(v);
        qihse_bolt_buf_free(&b);
    }

    /* Float64. */
    double floats[] = {0.0, -0.0, 1.5, -273.15, 3.14159265358979};
    for (size_t i = 0; i < sizeof(floats) / sizeof(floats[0]); i++) {
        qihse_bolt_buf_init(&b, 16);
        qihse_bolt_encode_float(&b, floats[i]);
        v = round_trip(&b);
        assert(v && v->type == QIHSE_BOLT_FLOAT);
        assert(v->v.f == floats[i]);
        qihse_bolt_value_free(v);
        qihse_bolt_buf_free(&b);
    }

    /* Strings: empty, 8-bit and 16-bit length prefixes. */
    qihse_bolt_buf_init(&b, 64);
    qihse_bolt_encode_string(&b, "");
    char big[400];
    memset(big, 'x', sizeof(big) - 1);
    big[sizeof(big) - 1] = '\0';
    qihse_bolt_encode_string(&b, "hello");
    qihse_bolt_encode_string(&b, big);
    qihse_bolt_decoder_init(&d, b.buf, b.len);
    v = qihse_bolt_decode(&d);
    assert(v && v->type == QIHSE_BOLT_STRING && v->v.s.len == 0);
    qihse_bolt_value_free(v);
    v = qihse_bolt_decode(&d);
    assert(v && v->type == QIHSE_BOLT_STRING);
    assert(strcmp(v->v.s.data, "hello") == 0 && v->v.s.len == 5);
    qihse_bolt_value_free(v);
    v = qihse_bolt_decode(&d);
    assert(v && v->type == QIHSE_BOLT_STRING);
    assert(v->v.s.len == 399 && strcmp(v->v.s.data, big) == 0);
    qihse_bolt_value_free(v);
    qihse_bolt_buf_free(&b);

    printf("PASS packstream primitives: null, bool, int ranges, float64, strings\n");
}

static void test_packstream_containers(void) {
    qihse_bolt_buf_t b;
    qihse_bolt_value_t* v;

    /* List of mixed values. */
    qihse_bolt_buf_init(&b, 64);
    qihse_bolt_encode_list_begin(&b, 3);
    qihse_bolt_encode_int(&b, 1);
    qihse_bolt_encode_string(&b, "two");
    qihse_bolt_encode_bool(&b, true);
    v = round_trip(&b);
    assert(v && v->type == QIHSE_BOLT_LIST && v->v.list.count == 3);
    assert(v->v.list.items[0]->type == QIHSE_BOLT_INT);
    assert(v->v.list.items[0]->v.i == 1);
    assert(v->v.list.items[1]->type == QIHSE_BOLT_STRING);
    assert(strcmp(v->v.list.items[1]->v.s.data, "two") == 0);
    assert(v->v.list.items[2]->type == QIHSE_BOLT_BOOL);
    qihse_bolt_value_free(v);
    qihse_bolt_buf_free(&b);

    /* Empty list. */
    qihse_bolt_buf_init(&b, 16);
    qihse_bolt_encode_list_begin(&b, 0);
    v = round_trip(&b);
    assert(v && v->type == QIHSE_BOLT_LIST && v->v.list.count == 0);
    qihse_bolt_value_free(v);
    qihse_bolt_buf_free(&b);

    /* Tiny map: 0 entries (0xA0) and 3 entries (0xA3). */
    qihse_bolt_buf_init(&b, 16);
    qihse_bolt_encode_map_begin(&b, 0);
    assert(b.buf[0] == 0xA0);
    v = round_trip(&b);
    assert(v && v->type == QIHSE_BOLT_MAP && v->v.map.count == 0);
    qihse_bolt_value_free(v);
    qihse_bolt_buf_free(&b);

    qihse_bolt_buf_init(&b, 64);
    qihse_bolt_encode_map_begin(&b, 3);
    assert(b.buf[0] == 0xA3);
    char tkey[16];
    for (int i = 0; i < 3; i++) {
        snprintf(tkey, sizeof(tkey), "tk%d", i);
        qihse_bolt_encode_string(&b, tkey);
        qihse_bolt_encode_int(&b, i);
    }
    v = round_trip(&b);
    assert(v && v->type == QIHSE_BOLT_MAP && v->v.map.count == 3);
    for (int i = 0; i < 3; i++) {
        snprintf(tkey, sizeof(tkey), "tk%d", i);
        assert(v->v.map.keys[i]->type == QIHSE_BOLT_STRING && strcmp(v->v.map.keys[i]->v.s.data, tkey) == 0);
        assert(v->v.map.vals[i]->type == QIHSE_BOLT_INT && v->v.map.vals[i]->v.i == i);
    }
    qihse_bolt_value_free(v);
    qihse_bolt_buf_free(&b);

    /* Map with 16 entries: the smallest size that uses the 0xD8 prefix. */
    qihse_bolt_buf_init(&b, 256);
    qihse_bolt_encode_map_begin(&b, 16);
    assert(b.buf[0] == 0xD8);
    char key[16];
    for (int i = 0; i < 16; i++) {
        snprintf(key, sizeof(key), "k%02d", i);
        qihse_bolt_encode_string(&b, key);
        qihse_bolt_encode_int(&b, i);
    }
    v = round_trip(&b);
    assert(v && v->type == QIHSE_BOLT_MAP && v->v.map.count == 16);
    for (int i = 0; i < 16; i++) {
        assert(v->v.map.keys[i]->type == QIHSE_BOLT_STRING);
        assert(v->v.map.vals[i]->type == QIHSE_BOLT_INT);
        assert(v->v.map.vals[i]->v.i == i);
    }
    qihse_bolt_value_free(v);
    qihse_bolt_buf_free(&b);

    /* Tiny struct carrying the Node signature (id, labels, properties). */
    qihse_bolt_buf_init(&b, 128);
    qihse_bolt_encode_struct_begin(&b, QIHSE_BOLT_STRUCT_NODE, 3);
    qihse_bolt_encode_int(&b, 7);
    qihse_bolt_encode_list_begin(&b, 1);
    qihse_bolt_encode_string(&b, "Person");
    qihse_bolt_encode_map_begin(&b, 16);   /* 0xD8 form, see the gap notes */
    for (int i = 0; i < 16; i++) {
        snprintf(key, sizeof(key), "p%02d", i);
        qihse_bolt_encode_string(&b, key);
        qihse_bolt_encode_int(&b, i);
    }
    v = round_trip(&b);
    assert(v && v->type == QIHSE_BOLT_STRUCT);
    assert(v->v.strct.signature == QIHSE_BOLT_STRUCT_NODE);
    assert(v->v.strct.nfields == 3);
    assert(v->v.strct.fields[0]->v.i == 7);
    assert(v->v.strct.fields[1]->type == QIHSE_BOLT_LIST);
    assert(strcmp(v->v.strct.fields[1]->v.list.items[0]->v.s.data, "Person") == 0);
    assert(v->v.strct.fields[2]->type == QIHSE_BOLT_MAP);
    assert(v->v.strct.fields[2]->v.map.count == 16);
    qihse_bolt_value_free(v);
    qihse_bolt_buf_free(&b);

    /* Relationship and Path signatures are just struct type bytes here. */
    qihse_bolt_buf_init(&b, 64);
    qihse_bolt_encode_struct_begin(&b, QIHSE_BOLT_STRUCT_RELATION, 5);
    for (int i = 0; i < 5; i++) qihse_bolt_encode_int(&b, i);
    qihse_bolt_encode_struct_begin(&b, QIHSE_BOLT_STRUCT_PATH, 3);
    for (int i = 0; i < 3; i++) qihse_bolt_encode_int(&b, i);
    qihse_bolt_decoder_t d;
    qihse_bolt_decoder_init(&d, b.buf, b.len);
    v = qihse_bolt_decode(&d);
    assert(v && v->type == QIHSE_BOLT_STRUCT);
    assert(v->v.strct.signature == QIHSE_BOLT_STRUCT_RELATION);
    assert(v->v.strct.nfields == 5);
    qihse_bolt_value_free(v);
    v = qihse_bolt_decode(&d);
    assert(v && v->type == QIHSE_BOLT_STRUCT);
    assert(v->v.strct.signature == QIHSE_BOLT_STRUCT_PATH);
    assert(v->v.strct.nfields == 3);
    qihse_bolt_value_free(v);
    qihse_bolt_buf_free(&b);

    printf("PASS packstream containers: lists, 16-entry maps, Node/Relationship/Path structs\n");
}

static void test_truncated_input_refused(void) {
    /* A string header promising 8 bytes with only 3 present. */
    const uint8_t bad[] = {0xD0, 0x08, 'a', 'b', 'c'};
    qihse_bolt_decoder_t d;
    qihse_bolt_decoder_init(&d, bad, sizeof(bad));
    assert(qihse_bolt_decode(&d) == NULL);

    /* A list promising 2 items with 1 present. */
    const uint8_t bad2[] = {0xD4, 0x02, 0x01};
    qihse_bolt_decoder_init(&d, bad2, sizeof(bad2));
    assert(qihse_bolt_decode(&d) == NULL);

    /* An unknown marker is refused. */
    const uint8_t bad3[] = {0xDF};
    qihse_bolt_decoder_init(&d, bad3, sizeof(bad3));
    assert(qihse_bolt_decode(&d) == NULL);

    /* Empty input. */
    qihse_bolt_decoder_init(&d, NULL, 0);
    assert(qihse_bolt_decode(&d) == NULL);

    printf("PASS packstream decoder: truncated and unknown input refused\n");
}

/* ── 3. Message framing ─────────────────────────────────────────────────── */

static void test_message_framing(void) {
    /* One message with a payload. */
    qihse_bolt_buf_t body, msg;
    qihse_bolt_buf_init(&body, 32);
    qihse_bolt_encode_string(&body, "RETURN 1");
    qihse_bolt_buf_init(&msg, body.len + 8);
    qihse_bolt_encode_message(&msg, QIHSE_BOLT_MSG_RUN, body.buf, body.len);

    uint8_t sig = 0;
    uint8_t* payload = NULL;
    size_t plen = 0, consumed = 0;
    assert(qihse_bolt_decode_message(msg.buf, msg.len, &sig, &payload, &plen,
                                     &consumed) == 0);
    assert(sig == QIHSE_BOLT_MSG_RUN);
    assert(consumed == msg.len);
    assert(plen == body.len);
    assert(memcmp(payload, body.buf, plen) == 0);
    free(payload);

    /* Partial input: only the first chunk header is present. */
    assert(qihse_bolt_decode_message(msg.buf, 2, &sig, &payload, &plen,
                                     &consumed) == 1);
    assert(consumed == 0);
    /* Partial input: chunk header plus part of the body. */
    assert(qihse_bolt_decode_message(msg.buf, msg.len - 1, &sig, &payload,
                                     &plen, &consumed) == 1);

    /* An empty message (a bare end-of-message marker) is an error. */
    const uint8_t empty[] = {0x00, 0x00};
    assert(qihse_bolt_decode_message(empty, sizeof(empty), &sig, &payload,
                                     &plen, &consumed) == -1);

    qihse_bolt_buf_free(&body);
    qihse_bolt_buf_free(&msg);

    /* Two messages back to back: consumed must only cover the first. */
    qihse_bolt_buf_t b;
    qihse_bolt_buf_init(&b, 64);
    const uint8_t p1[] = {0xC0};
    const uint8_t p2[] = {0xC3};
    qihse_bolt_encode_message(&b, QIHSE_BOLT_MSG_RESET, p1, sizeof(p1));
    size_t first_len = b.len;
    qihse_bolt_encode_message(&b, QIHSE_BOLT_MSG_GOODBYE, p2, sizeof(p2));
    assert(qihse_bolt_decode_message(b.buf, b.len, &sig, &payload, &plen,
                                     &consumed) == 0);
    assert(sig == QIHSE_BOLT_MSG_RESET && consumed == first_len);
    free(payload);
    assert(qihse_bolt_decode_message(b.buf + consumed, b.len - consumed, &sig,
                                     &payload, &plen, &consumed) == 0);
    assert(sig == QIHSE_BOLT_MSG_GOODBYE && plen == 1);
    assert(payload[0] == 0xC3);
    free(payload);
    qihse_bolt_buf_free(&b);

    /* A message split over two chunks must be reassembled: the first chunk
     * carries only the signature, the second the whole payload. */
    const uint8_t chunked[] = {
        0x00, 0x01, QIHSE_BOLT_MSG_RUN,          /* first chunk: signature only */
        0x00, 0x03, 0x02, 'a', 'b',              /* second chunk: 3 payload bytes */
        0x00, 0x00                               /* end of message */
    };
    assert(qihse_bolt_decode_message(chunked, sizeof(chunked), &sig, &payload,
                                     &plen, &consumed) == 0);
    assert(sig == QIHSE_BOLT_MSG_RUN);
    assert(consumed == sizeof(chunked));
    assert(plen == 3);
    assert(payload[0] == 0x02 && payload[1] == 'a' && payload[2] == 'b');
    free(payload);

    printf("PASS message framing: single chunk, back-to-back, multi-chunk, partial, empty\n");
}

/* ── 4. Handshake ───────────────────────────────────────────────────────── */

static void test_handshake(void) {
    int sv[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);

    uint8_t req[20];
    req[0] = 0x60; req[1] = 0x60; req[2] = 0xB0; req[3] = 0x17;
    uint32_t versions[4] = {0x00000300, QIHSE_BOLT_VERSION_4, 0x00000001, 0};
    for (int i = 0; i < 4; i++) {
        req[4 + i * 4] = (uint8_t)(versions[i] >> 24);
        req[5 + i * 4] = (uint8_t)(versions[i] >> 16);
        req[6 + i * 4] = (uint8_t)(versions[i] >> 8);
        req[7 + i * 4] = (uint8_t)versions[i];
    }
    assert(write(sv[0], req, sizeof(req)) == (ssize_t)sizeof(req));

    uint32_t chosen = 0;
    assert(qihse_bolt_handshake(sv[1], &chosen));
    assert(chosen == QIHSE_BOLT_VERSION_4);
    uint8_t resp[4];
    assert(read(sv[0], resp, 4) == 4);
    uint32_t echoed = ((uint32_t)resp[0] << 24) | ((uint32_t)resp[1] << 16) |
                      ((uint32_t)resp[2] << 8) | resp[3];
    assert(echoed == QIHSE_BOLT_VERSION_4);

    /* No 4.x proposal: the server answers 0 and reports failure. */
    uint32_t only3[4] = {0x00000300, 0x00000301, 0x00000000, 0x00000000};
    for (int i = 0; i < 4; i++) {
        req[4 + i * 4] = (uint8_t)(only3[i] >> 24);
        req[5 + i * 4] = (uint8_t)(only3[i] >> 16);
        req[6 + i * 4] = (uint8_t)(only3[i] >> 8);
        req[7 + i * 4] = (uint8_t)only3[i];
    }
    assert(write(sv[0], req, sizeof(req)) == (ssize_t)sizeof(req));
    chosen = 0xFFFFFFFFu;
    assert(!qihse_bolt_handshake(sv[1], &chosen));
    assert(chosen == 0);
    assert(read(sv[0], resp, 4) == 4);
    assert(resp[0] == 0 && resp[1] == 0 && resp[2] == 0 && resp[3] == 0);

    /* Wrong magic byte is refused. */
    uint8_t badmagic[20];
    memcpy(badmagic, req, sizeof(badmagic));
    badmagic[3] = 0x18;
    assert(write(sv[0], badmagic, sizeof(badmagic)) == (ssize_t)sizeof(badmagic));
    assert(!qihse_bolt_handshake(sv[1], &chosen));

    /* Truncated handshake is refused. */
    assert(write(sv[0], badmagic, 10) == 10);
    close(sv[0]);
    assert(!qihse_bolt_handshake(sv[1], &chosen));

    close(sv[1]);
    printf("PASS bolt handshake: magic check, 4.0 selection, version-0 refusal, truncation\n");
}

/* ── 5. Client message loop ─────────────────────────────────────────────── */

/* Read one framed message from fd; returns the signature or -1. */
static int read_frame(int fd, uint8_t* out_sig, uint8_t** out_payload,
                      size_t* out_len) {
    uint8_t buf[512];
    size_t have = 0;
    for (int attempt = 0; attempt < 8; attempt++) {
        ssize_t r = read(fd, buf + have, sizeof(buf) - have);
        if (r <= 0) return -1;
        have += (size_t)r;
        size_t consumed = 0;
        int rc = qihse_bolt_decode_message(buf, have, out_sig, out_payload,
                                           out_len, &consumed);
        if (rc == 0) return 0;
        if (rc < 0) return -1;
    }
    return -1;
}

static void test_client_message_loop(void) {
    int sv[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);

    uint8_t req[20];
    req[0] = 0x60; req[1] = 0x60; req[2] = 0xB0; req[3] = 0x17;
    for (int i = 0; i < 4; i++) {
        uint32_t v = (i == 0) ? QIHSE_BOLT_VERSION_4 : 0;
        req[4 + i * 4] = (uint8_t)(v >> 24);
        req[5 + i * 4] = (uint8_t)(v >> 16);
        req[6 + i * 4] = (uint8_t)(v >> 8);
        req[7 + i * 4] = (uint8_t)v;
    }
    assert(write(sv[0], req, sizeof(req)) == (ssize_t)sizeof(req));

    /* The handler runs in this process; ctx is NULL because these messages
     * do not reach the UWP dispatch path. */
    pid_t pid = fork();
    assert(pid >= 0);
    if (pid == 0) {
        close(sv[0]);
        qihse_bolt_handle_client(sv[1], NULL);
        _exit(0);
    }
    close(sv[1]);

    /* Handshake response first. */
    uint8_t vresp[4];
    assert(read(sv[0], vresp, 4) == 4);

    /* RESET must be answered with SUCCESS. */
    qihse_bolt_buf_t msg;
    qihse_bolt_buf_init(&msg, 16);
    qihse_bolt_encode_message(&msg, QIHSE_BOLT_MSG_RESET, NULL, 0);
    assert(write(sv[0], msg.buf, msg.len) == (ssize_t)msg.len);
    qihse_bolt_buf_free(&msg);

    uint8_t sig = 0;
    uint8_t* payload = NULL;
    size_t plen = 0;
    assert(read_frame(sv[0], &sig, &payload, &plen) == 0);
    assert(sig == QIHSE_BOLT_MSG_SUCCESS);
    free(payload);

    /* An unknown signature is answered with IGNORED. */
    qihse_bolt_buf_init(&msg, 16);
    qihse_bolt_encode_message(&msg, 0x42, NULL, 0);
    assert(write(sv[0], msg.buf, msg.len) == (ssize_t)msg.len);
    qihse_bolt_buf_free(&msg);
    assert(read_frame(sv[0], &sig, &payload, &plen) == 0);
    assert(sig == QIHSE_BOLT_MSG_IGNORED);
    free(payload);

    /* GOODBYE ends the session: the child must exit and close the socket. */
    qihse_bolt_buf_init(&msg, 16);
    qihse_bolt_encode_message(&msg, QIHSE_BOLT_MSG_GOODBYE, NULL, 0);
    assert(write(sv[0], msg.buf, msg.len) == (ssize_t)msg.len);
    qihse_bolt_buf_free(&msg);

    uint8_t sink[8];
    assert(read(sv[0], sink, sizeof(sink)) == 0);   /* EOF: handler returned */
    close(sv[0]);
    int status = 0;
    assert(waitpid(pid, &status, 0) == pid);

    printf("PASS bolt message loop: RESET answered with SUCCESS, unknown IGNORED, GOODBYE closes\n");
}

/* ── 7. Bolt 4.x spec compliance (asserted) ─────────────────────────────── */

static void test_bolt_spec_compliance(void) {
    /* Tiny map: verify 0xA0..0xAF encoding and round-trip decoding. */
    qihse_bolt_buf_t b;
    qihse_bolt_buf_init(&b, 32);
    qihse_bolt_encode_map_begin(&b, 1);
    qihse_bolt_encode_string(&b, "server");
    qihse_bolt_encode_string(&b, "QIHSE/1.0");
    uint8_t marker = b.buf[0];
    assert(marker == 0xA1);
    qihse_bolt_value_t* v = round_trip(&b);
    assert(v && v->type == QIHSE_BOLT_MAP);
    assert(v->v.map.count == 1);
    assert(v->v.map.keys[0]->type == QIHSE_BOLT_STRING && strcmp(v->v.map.keys[0]->v.s.data, "server") == 0);
    assert(v->v.map.vals[0]->type == QIHSE_BOLT_STRING && strcmp(v->v.map.vals[0]->v.s.data, "QIHSE/1.0") == 0);
    qihse_bolt_value_free(v);
    qihse_bolt_buf_free(&b);

    /* Negative tiny ints: -16..-1 encode as 0xF0..0xFF and decode with sign extension. */
    int64_t tiny_neg_cases[] = { -1, -5, -16 };
    uint8_t tiny_neg_expected[] = { 0xFF, 0xFB, 0xF0 };
    for (size_t i = 0; i < sizeof(tiny_neg_cases) / sizeof(tiny_neg_cases[0]); i++) {
        qihse_bolt_buf_init(&b, 8);
        qihse_bolt_encode_int(&b, tiny_neg_cases[i]);
        assert(b.buf[0] == tiny_neg_expected[i]);
        v = round_trip(&b);
        assert(v && v->type == QIHSE_BOLT_INT);
        assert(v->v.i == tiny_neg_cases[i]);
        qihse_bolt_value_free(v);
        qihse_bolt_buf_free(&b);
    }

    /* Tiny string / tiny list / tiny map markers decode correctly. */
    const uint8_t tiny_string[] = {0x83, 'a', 'b', 'c'};   /* PackStream: "abc" */
    const uint8_t tiny_list[] = {0x92, 0x01, 0x02};        /* PackStream: [1,2] */
    const uint8_t tiny_map[] = {0xA1, 0x81, 'k', 0x01};    /* PackStream: {"k":1} */
    qihse_bolt_decoder_t d;

    qihse_bolt_decoder_init(&d, tiny_string, sizeof(tiny_string));
    v = qihse_bolt_decode(&d);
    assert(v && v->type == QIHSE_BOLT_STRING);
    assert(v->v.s.len == 3 && strcmp(v->v.s.data, "abc") == 0);
    qihse_bolt_value_free(v);

    qihse_bolt_decoder_init(&d, tiny_list, sizeof(tiny_list));
    v = qihse_bolt_decode(&d);
    assert(v && v->type == QIHSE_BOLT_LIST && v->v.list.count == 2);
    assert(v->v.list.items[0]->type == QIHSE_BOLT_INT && v->v.list.items[0]->v.i == 1);
    assert(v->v.list.items[1]->type == QIHSE_BOLT_INT && v->v.list.items[1]->v.i == 2);
    qihse_bolt_value_free(v);

    qihse_bolt_decoder_init(&d, tiny_map, sizeof(tiny_map));
    v = qihse_bolt_decode(&d);
    assert(v && v->type == QIHSE_BOLT_MAP && v->v.map.count == 1);
    assert(v->v.map.keys[0]->type == QIHSE_BOLT_STRING && strcmp(v->v.map.keys[0]->v.s.data, "k") == 0);
    assert(v->v.map.vals[0]->type == QIHSE_BOLT_INT && v->v.map.vals[0]->v.i == 1);
    qihse_bolt_value_free(v);

    /* Message signature constants match Bolt 4.x spec. */
    assert(QIHSE_BOLT_MSG_HELLO == 0x01);
    assert(QIHSE_BOLT_MSG_GOODBYE == 0x02);
    assert(QIHSE_BOLT_MSG_RESET == 0x0F);
    assert(QIHSE_BOLT_MSG_RUN == 0x10);
    assert(QIHSE_BOLT_MSG_BEGIN == 0x11);
    assert(QIHSE_BOLT_MSG_COMMIT == 0x12);
    assert(QIHSE_BOLT_MSG_ROLLBACK == 0x13);
    assert(QIHSE_BOLT_MSG_DISCARD == 0x2F);
    assert(QIHSE_BOLT_MSG_PULL == 0x3F);
    assert(QIHSE_BOLT_MSG_SUCCESS == 0x70);
    assert(QIHSE_BOLT_MSG_RECORD == 0x71);
    assert(QIHSE_BOLT_MSG_IGNORED == 0x7E);
    assert(QIHSE_BOLT_MSG_FAILURE == 0x7F);

    printf("PASS bolt 4.x spec compliance: signatures and packstream tiny containers\n");
}

int main(void) {
    test_packstream_primitives();
    test_packstream_containers();
    test_truncated_input_refused();
    test_message_framing();
    test_handshake();
    test_client_message_loop();
    test_bolt_spec_compliance();
    printf("test_bolt: all asserted Bolt behaviours passed\n");
    return 0;
}
