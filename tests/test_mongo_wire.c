/*
 * test_mongo_wire.c — MongoDB wire protocol adapter: framing, catalog,
 * command dispatch and the TCP server.
 *
 * Exercises src/spinnaker/qihse_mongo_wire.c (include/qihse_mongo_wire.h).
 *
 * Asserted:
 *   1.  Nested BSON encoding is spec-conformant: a nested document declares
 *       the number of bytes it occupies and ends with the 0x00 terminator,
 *       including the case where its last element is an int32 (the case the
 *       previous encoder got wrong).
 *   2.  mongo_msg_parse() accepts well-formed frames and REFUSES a declared
 *       length larger than the bytes present, a length below the header, an
 *       unknown opcode, OP_COMPRESSED, a checksummed OP_MSG, a document-
 *       sequence section, a document that is not NUL-terminated and a
 *       document whose inner length overruns the frame.
 *   3.  mongo_msg_get_document() materialises the command document, advances
 *       the offset and refuses a truncated document.
 *   4.  Catalog: create/get/drop, and the user-less accessors fail closed
 *       (NULL) until a principal is bound.
 *   5.  Dispatch: ping, hello, insert, find, count, distinct, update, delete,
 *       aggregate, listCollections, listDatabases, drop; an unknown command is
 *       refused; getMore and createIndexes are refused loudly rather than
 *       silently accepted.
 *   6.  A NULL principal is refused with code 13 and no payload.
 *   7.  The TCP server: start on an ephemeral port, authenticate, insert and
 *       find over the wire, a real OP_MSG reply frame, stop and destroy.
 *
 * The negative authorization test required by AGENTS.md invariant 3 lives in
 * tests/test_mongo_wire_security.c (target test-mongo-wire-security).
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "qihse_auth.h"
#include "qihse_mongo_wire.h"

#include <assert.h>
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define OPERATOR_PASSWORD "OperatorMongoPass1!"

/* ── helpers ─────────────────────────────────────────────────────────────── */

static void put_i32(uint8_t* p, int32_t v) { memcpy(p, &v, 4); }

/* Build an OP_MSG request: header(16) + flags(4) + kind(1) + command. */
static uint8_t* build_op_msg(int32_t request_id, const bson_t* cmd, size_t* out_len) {
    size_t dlen = bson_size(cmd);
    size_t total = 16 + 5 + dlen;
    uint8_t* frame = (uint8_t*)malloc(total);
    assert(frame != NULL);
    put_i32(frame, (int32_t)total);
    put_i32(frame + 4, request_id);
    put_i32(frame + 8, 0);
    put_i32(frame + 12, MONGO_OP_MSG);
    put_i32(frame + 16, 0);
    frame[20] = 0;
    memcpy(frame + 21, bson_data(cmd), dlen);
    *out_len = total;
    return frame;
}

/* Build a legacy OP_QUERY request: header(16) + flags(4) + ns + skip(4) +
 * return(4) + query document. */
static uint8_t* build_op_query(int32_t request_id, const char* ns, const bson_t* query,
                               size_t* out_len) {
    size_t nslen = strlen(ns) + 1;
    size_t dlen = bson_size(query);
    size_t total = 16 + 4 + nslen + 8 + dlen;
    uint8_t* frame = (uint8_t*)malloc(total);
    assert(frame != NULL);
    put_i32(frame, (int32_t)total);
    put_i32(frame + 4, request_id);
    put_i32(frame + 8, 0);
    put_i32(frame + 12, MONGO_OP_QUERY);
    put_i32(frame + 16, 0);
    memcpy(frame + 20, ns, nslen);
    size_t off = 20 + nslen;
    put_i32(frame + off, 0);
    put_i32(frame + off + 4, 0);
    memcpy(frame + off + 8, bson_data(query), dlen);
    *out_len = total;
    return frame;
}

/* Build a legacy OP_INSERT request: header(16) + flags(4) + ns + document.
 * Legacy write ops are fire-and-forget: there is no reply frame. */
static uint8_t* build_op_insert(int32_t request_id, const char* ns, const bson_t* doc,
                                size_t* out_len) {
    size_t nslen = strlen(ns) + 1;
    size_t dlen = bson_size(doc);
    size_t total = 16 + 4 + nslen + dlen;
    uint8_t* frame = (uint8_t*)malloc(total);
    assert(frame != NULL);
    put_i32(frame, (int32_t)total);
    put_i32(frame + 4, request_id);
    put_i32(frame + 8, 0);
    put_i32(frame + 12, MONGO_OP_INSERT);
    put_i32(frame + 16, 0);
    memcpy(frame + 20, ns, nslen);
    memcpy(frame + 20 + nslen, bson_data(doc), dlen);
    *out_len = total;
    return frame;
}

static bson_t* cmd_ping(void) {
    bson_t* c = bson_create();
    bson_append_int32(c, "ping", 1);
    return c;
}

static bson_t* cmd_find(const char* coll) {
    bson_t* c = bson_create();
    bson_append_string(c, "find", coll);
    return c;
}

/* ── 1. nested BSON encoding ─────────────────────────────────────────────── */

static void test_nested_encoding(void) {
    /* A nested document whose LAST element is an int32: with the previous
     * encoder the declared length excluded the terminator and the terminator
     * was absent, so a stock BSON parser read the int32's high byte as the
     * document terminator and rejected the document. */
    bson_t* sub = bson_create();
    assert(bson_append_int32(sub, "n", 5) == 0);
    bson_t* doc = bson_create();
    assert(bson_append_string(doc, "name", "alice") == 0);
    assert(bson_append_document(doc, "sub", sub) == 0);

    size_t size = bson_size(doc);
    const uint8_t* data = bson_data(doc);
    int32_t declared;
    memcpy(&declared, data, 4);
    assert(declared == (int32_t)size);
    assert(data[size - 1] == 0x00);

    /* Walk to the nested document and check its own prefix and terminator. */
    size_t off = 4;
    bson_element_t e;
    int saw_sub = 0;
    while (bson_iter(doc, &off, &e) == 0) {
        if (strcmp(e.key, "sub") != 0) continue;
        saw_sub = 1;
        int32_t inner;
        memcpy(&inner, e.v.doc.data, 4);
        assert(inner == e.v.doc.len);
        assert(e.v.doc.data[e.v.doc.len - 1] == 0x00);
        /* the nested document must parse on its own */
        bson_t view = { (uint8_t*)e.v.doc.data, (size_t)e.v.doc.len, (size_t)e.v.doc.len };
        bson_element_t inner_e;
        size_t ioff = 0;
        assert(bson_iter(&view, &ioff, &inner_e) == 0);
        assert(strcmp(inner_e.key, "n") == 0 && inner_e.v.i32 == 5);
    }
    assert(saw_sub);

    /* The same for an array, and the round trip through bson_copy. */
    bson_t* arr = bson_create();
    assert(bson_append_int32(arr, "0", 7) == 0);
    bson_t* doc2 = bson_create();
    assert(bson_append_array(doc2, "a", arr) == 0);
    bson_t* copy = bson_copy(doc2);
    assert(copy != NULL);
    bson_t* doc3 = bson_create();
    assert(bson_append_document(doc3, "d", copy) == 0);
    char* json = bson_to_json(doc3);
    assert(json != NULL && strstr(json, "7") != NULL);
    free(json);

    bson_destroy(doc3);
    bson_destroy(copy);
    bson_destroy(doc2);
    bson_destroy(arr);
    bson_destroy(doc);
    bson_destroy(sub);
    printf("PASS mongo framing: nested documents are spec-conformant\n");
}

/* ── 2/3. message parsing ────────────────────────────────────────────────── */

static void test_msg_parse(void) {
    bson_t* cmd = cmd_ping();
    size_t len = 0;
    uint8_t* frame = build_op_msg(42, cmd, &len);

    mongo_msg_t msg;
    assert(mongo_msg_parse(frame, len, &msg) == 0);
    assert(msg.message_length == (int32_t)len);
    assert(msg.request_id == 42);
    assert(msg.opcode == MONGO_OP_MSG);
    assert(msg.body_len == len - 16);

    size_t off = 0;
    bson_t* got = mongo_msg_get_document(&msg, &off);
    assert(got != NULL);
    bson_element_t e;
    assert(bson_find_element(got, "ping", &e) == 0 && e.v.i32 == 1);
    assert(off == msg.body_len);
    /* End of body: no further document. */
    assert(mongo_msg_get_document(&msg, &off) == NULL);
    bson_destroy(got);

    /* Declared length larger than the bytes present. */
    assert(mongo_msg_parse(frame, len - 1, &msg) != 0);
    /* Declared length below the header. */
    uint8_t small[16];
    memset(small, 0, sizeof(small));
    put_i32(small, 15);
    put_i32(small + 12, MONGO_OP_MSG);
    assert(mongo_msg_parse(small, sizeof(small), &msg) != 0);
    /* Unknown opcode. */
    uint8_t unknown[16];
    memcpy(unknown, frame, 16);
    put_i32(unknown + 12, 1234);
    assert(mongo_msg_parse(unknown, sizeof(unknown), &msg) != 0);
    /* OP_COMPRESSED is refused rather than guessed at. */
    memcpy(unknown, frame, 16);
    put_i32(unknown + 12, MONGO_OP_COMPRESSED);
    assert(mongo_msg_parse(unknown, sizeof(unknown), &msg) != 0);
    /* Truncated header. */
    assert(mongo_msg_parse(frame, 8, &msg) != 0);

    /* checksumPresent is refused (no CRC32C implementation). */
    uint8_t* bad = (uint8_t*)malloc(len);
    assert(bad != NULL);
    memcpy(bad, frame, len);
    put_i32(bad + 16, 0x1);
    assert(mongo_msg_parse(bad, len, &msg) != 0);
    /* A document-sequence section (kind 1) is refused. */
    memcpy(bad, frame, len);
    bad[20] = 1;
    assert(mongo_msg_parse(bad, len, &msg) != 0);
    /* A document that is not NUL-terminated. */
    memcpy(bad, frame, len);
    bad[len - 1] = 0x7F;
    assert(mongo_msg_parse(bad, len, &msg) != 0);
    /* A document whose declared inner length overruns the frame. */
    memcpy(bad, frame, len);
    put_i32(bad + 21, (int32_t)len);
    assert(mongo_msg_parse(bad, len, &msg) != 0);
    /* A string element whose declared length overruns the document. */
    bson_t* big = bson_create();
    bson_append_string(big, "s", "hello");
    size_t blen = 0;
    uint8_t* bframe = build_op_msg(1, big, &blen);
    /* find the string's length field: type(1)+key("s\0"=2)+len(4) after the
     * 21-byte OP_MSG head */
    put_i32(bframe + 21 + 4 + 1 + 2, 1000);
    assert(mongo_msg_parse(bframe, blen, &msg) != 0);
    free(bframe);
    bson_destroy(big);
    free(bad);

    /* mongo_msg_get_document on a truncated body. */
    mongo_msg_t fake;
    memset(&fake, 0, sizeof(fake));
    uint8_t body[10];
    memset(body, 0, sizeof(body));
    put_i32(body, 9);   /* declares 9 bytes, only 10 present, no terminator */
    fake.body = body;
    fake.body_len = sizeof(body);
    fake.opcode = MONGO_OP_MSG;
    size_t foff = 5;
    assert(mongo_msg_get_document(&fake, &foff) == NULL);

    /* Legacy OP_QUERY framing. */
    bson_t* q = cmd_find("coll");
    size_t qlen = 0;
    uint8_t* qframe = build_op_query(7, "db.coll", q, &qlen);
    assert(mongo_msg_parse(qframe, qlen, &msg) == 0);
    assert(msg.opcode == MONGO_OP_QUERY);
    off = 0;
    bson_t* qdoc = mongo_msg_get_document(&msg, &off);
    assert(qdoc != NULL);
    assert(bson_find_element(qdoc, "find", &e) == 0 && strcmp(e.v.str, "coll") == 0);
    bson_destroy(qdoc);
    free(qframe);
    bson_destroy(q);

    free(frame);
    bson_destroy(cmd);
    printf("PASS mongo framing: OP_MSG/OP_QUERY framing and malformed frames refused\n");
}

/* ── 5b. aggregation stages ──────────────────────────────────────────────── */

static bson_t* make_doc(const char* name, int32_t age, const char* tag) {
    bson_t* d = bson_create();
    bson_append_string(d, "name", name);
    bson_append_int32(d, "age", age);
    bson_t* tags = bson_create();
    bson_append_string(tags, "0", tag);
    bson_append_string(tags, "1", "shared");
    bson_append_array(d, "tags", tags);
    bson_destroy(tags);
    return d;
}

/* Append a stage to a pipeline array under its index key. */
static void pipe_add(bson_t* pipe, size_t* idx, bson_t* stage) {
    char key[16];
    snprintf(key, sizeof(key), "%zu", (*idx)++);
    bson_append_document(pipe, key, stage);
}

/* {$<name>: <document argument>} */
static bson_t* stage_with_doc(const char* name, const bson_t* arg) {
    bson_t* s = bson_create();
    bson_append_document(s, name, arg);
    return s;
}

static void test_aggregation(void) {
    bson_t* a = make_doc("alice", 41, "x");
    bson_t* b = make_doc("bob", 22, "y");
    bson_t* c = make_doc("carol", 35, "x");
    const bson_t* input[3] = { a, b, c };
    size_t n = 0, idx = 0;

    /* {$sort: {age: -1}}, {$limit: 2} */
    bson_t* sort_arg = bson_create();
    bson_append_int32(sort_arg, "age", -1);
    bson_t* sort = stage_with_doc("$sort", sort_arg);
    bson_t* limit = bson_create();
    bson_append_int32(limit, "$limit", 2);   /* $limit takes a scalar */
    bson_t* pipe = bson_create();
    pipe_add(pipe, &idx, sort);
    pipe_add(pipe, &idx, limit);
    bson_t** out = bson_aggregate(input, 3, pipe, 0, &n);
    assert(out != NULL && n == 2);
    {
        char* j0 = bson_to_json(out[0]);
        char* j1 = bson_to_json(out[1]);
        assert(strstr(j0, "alice") != NULL && strstr(j1, "carol") != NULL);
        free(j0);
        free(j1);
    }
    for (size_t i = 0; i < n; i++) bson_destroy(out[i]);
    free(out);
    bson_destroy(pipe);
    bson_destroy(limit);
    bson_destroy(sort);
    bson_destroy(sort_arg);

    /* {$skip: 1}, {$count: "n"} */
    idx = 0;
    bson_t* skip = bson_create();
    bson_append_int32(skip, "$skip", 1);
    bson_t* count = bson_create();
    bson_append_string(count, "$count", "n");
    pipe = bson_create();
    pipe_add(pipe, &idx, skip);
    pipe_add(pipe, &idx, count);
    out = bson_aggregate(input, 3, pipe, 0, &n);
    assert(out != NULL && n == 1);
    {
        char* j = bson_to_json(out[0]);
        assert(strstr(j, "\"n\":2") != NULL);
        free(j);
    }
    for (size_t i = 0; i < n; i++) bson_destroy(out[i]);
    free(out);
    bson_destroy(pipe);
    bson_destroy(count);
    bson_destroy(skip);

    /* {$unwind: "$tags"}, {$group: {_id: "$tags", avgAge: {$avg: "$age"}}} */
    idx = 0;
    bson_t* unwind = bson_create();
    bson_append_string(unwind, "$unwind", "$tags");
    bson_t* gspec = bson_create();
    bson_append_string(gspec, "_id", "$tags");
    bson_t* gavg = bson_create();
    bson_append_string(gavg, "$avg", "$age");
    bson_append_document(gspec, "avgAge", gavg);
    bson_t* group = stage_with_doc("$group", gspec);
    pipe = bson_create();
    pipe_add(pipe, &idx, unwind);
    pipe_add(pipe, &idx, group);
    out = bson_aggregate(input, 3, pipe, 0, &n);
    assert(out != NULL && n == 3);   /* x, shared, y */
    {
        int saw_x = 0, saw_shared = 0;
        for (size_t i = 0; i < n; i++) {
            char* j = bson_to_json(out[i]);
            if (strstr(j, "\"x\"") && strstr(j, "\"avgAge\":38")) saw_x = 1;
            if (strstr(j, "\"shared\"") && strstr(j, "\"avgAge\":32.6667")) saw_shared = 1;
            free(j);
        }
        assert(saw_x && saw_shared);
    }
    for (size_t i = 0; i < n; i++) bson_destroy(out[i]);
    free(out);
    bson_destroy(pipe);
    bson_destroy(group);
    bson_destroy(gavg);
    bson_destroy(gspec);
    bson_destroy(unwind);

    /* {$project: {age: 0, tags: 0}} */
    idx = 0;
    bson_t* proj = bson_create();
    bson_append_int32(proj, "age", 0);
    bson_append_int32(proj, "tags", 0);
    bson_t* pstage = stage_with_doc("$project", proj);
    pipe = bson_create();
    pipe_add(pipe, &idx, pstage);
    out = bson_aggregate(input, 1, pipe, 0, &n);
    assert(out != NULL && n == 1);
    {
        char* j = bson_to_json(out[0]);
        assert(strstr(j, "alice") != NULL && strstr(j, "age") == NULL && strstr(j, "tags") == NULL);
        free(j);
    }
    for (size_t i = 0; i < n; i++) bson_destroy(out[i]);
    free(out);

    /* an unimplemented stage fails the whole pipeline rather than being
     * silently skipped */
    bson_t* lookup_arg = bson_create();
    bson_append_string(lookup_arg, "from", "other");
    bson_t* lookup = stage_with_doc("$lookup", lookup_arg);
    bson_t* pipe2 = bson_create();
    idx = 0;
    pipe_add(pipe2, &idx, lookup);
    n = 0;
    out = bson_aggregate(input, 3, pipe2, 0, &n);
    assert(out == NULL && n == 0);
    bson_destroy(pipe2);
    bson_destroy(lookup);
    bson_destroy(lookup_arg);
    bson_destroy(pipe);
    bson_destroy(pstage);
    bson_destroy(proj);

    bson_destroy(a);
    bson_destroy(b);
    bson_destroy(c);
    printf("PASS mongo aggregation: $sort/$limit/$skip/$count/$unwind/$group/$project, "
           "unimplemented stages refused\n");
}

/* ── 4. catalog ──────────────────────────────────────────────────────────── */

static void test_catalog(void) {
    /* No bound principal: every accessor fails closed. */
    mongo_catalog_t* cat = mongo_catalog_create(NULL);
    assert(cat != NULL);
    assert(mongo_catalog_get_user(cat) == NULL);
    assert(mongo_catalog_get_db(cat, "db") == NULL);
    assert(mongo_catalog_get_collection(cat, "db", "coll") == NULL);
    assert(mongo_catalog_drop_collection(cat, "db", "coll") != 0);

    /* The user-less dispatch refuses with code 13 and no payload. */
    bson_t* cmd = cmd_find("coll");
    bson_t* reply = mongo_dispatch_command(cat, "db", cmd);
    assert(reply != NULL);
    bson_element_t e;
    assert(bson_find_element(reply, "ok", &e) == 0 && e.v.i32 == 0);
    assert(bson_find_element(reply, "code", &e) == 0 && e.v.i32 == 13);
    bson_destroy(reply);

    /* The same for an explicit NULL principal. */
    reply = mongo_dispatch_command_as(cat, NULL, "db", cmd);
    assert(bson_find_element(reply, "ok", &e) == 0 && e.v.i32 == 0);
    assert(bson_find_element(reply, "code", &e) == 0 && e.v.i32 == 13);
    bson_destroy(reply);

    bson_destroy(cmd);
    mongo_catalog_destroy(cat);
    printf("PASS mongo catalog: user-less accessors and dispatch fail closed\n");
}

/* ── 5. dispatch ─────────────────────────────────────────────────────────── */

static qihse_user_t* bootstrap_users(void) {
    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator(OPERATOR_PASSWORD));
    qihse_user_t* op = qihse_auth_get_user(0);
    assert(op != NULL);
    assert(qihse_auth_create_user(op, 71, QIHSE_ROLE_ANALYST, 90, 0, "AnalystMongoPass1!", false) != NULL);
    return op;
}

static void expect_ok(const bson_t* reply, int32_t want_ok) {
    bson_element_t e;
    assert(bson_find_element(reply, "ok", &e) == 0);
    if (e.v.i32 != want_ok) {
        char* json = bson_to_json(reply);
        fprintf(stderr, "expected ok=%d, got: %s\n", want_ok, json ? json : "(null)");
        free(json);
        assert(0);
    }
}

static void test_dispatch(qihse_user_t* op) {
    mongo_catalog_t* cat = mongo_catalog_create_auth(NULL, op);
    assert(cat != NULL);
    bson_t* reply;
    bson_element_t e;

    /* ping / hello */
    bson_t* ping = cmd_ping();
    reply = mongo_dispatch_command(cat, "db", ping);
    expect_ok(reply, 1);
    bson_destroy(reply);
    bson_destroy(ping);

    bson_t* hello = bson_create();
    bson_append_int32(hello, "hello", 1);
    bson_append_string(hello, "$db", "db");
    reply = mongo_dispatch_command(cat, "db", hello);
    expect_ok(reply, 1);
    assert(bson_find_element(reply, "maxWireVersion", &e) == 0);
    bson_destroy(reply);
    bson_destroy(hello);

    /* insert */
    bson_t* doc = bson_create();
    bson_append_string(doc, "_id", "one");
    bson_append_string(doc, "name", "alice");
    bson_append_int32(doc, "age", 41);
    bson_t* docs = bson_create();
    bson_append_document(docs, "0", doc);
    bson_t* ins = bson_create();
    bson_append_string(ins, "insert", "people");
    bson_append_array(ins, "documents", docs);
    reply = mongo_dispatch_command(cat, "db", ins);
    expect_ok(reply, 1);
    assert(bson_find_element(reply, "n", &e) == 0 && e.v.i32 == 1);
    bson_destroy(reply);
    bson_destroy(ins);
    bson_destroy(docs);
    bson_destroy(doc);

    /* find by _id: the reply is a cursor with one document */
    bson_t* filter = bson_create();
    bson_append_string(filter, "_id", "one");
    bson_t* find = bson_create();
    bson_append_string(find, "find", "people");
    bson_append_document(find, "filter", filter);
    reply = mongo_dispatch_command(cat, "db", find);
    expect_ok(reply, 1);
    char* json = bson_to_json(reply);
    assert(json != NULL && strstr(json, "alice") != NULL && strstr(json, "\"db.people\"") != NULL);
    free(json);
    bson_destroy(reply);
    bson_destroy(find);
    bson_destroy(filter);

    /* count */
    bson_t* count = bson_create();
    bson_append_string(count, "count", "people");
    reply = mongo_dispatch_command(cat, "db", count);
    expect_ok(reply, 1);
    assert(bson_find_element(reply, "n", &e) == 0 && e.v.i32 == 1);
    bson_destroy(reply);
    bson_destroy(count);

    /* distinct */
    bson_t* distinct = bson_create();
    bson_append_string(distinct, "distinct", "people");
    bson_append_string(distinct, "key", "name");
    reply = mongo_dispatch_command(cat, "db", distinct);
    expect_ok(reply, 1);
    json = bson_to_json(reply);
    assert(json != NULL && strstr(json, "alice") != NULL);
    free(json);
    bson_destroy(reply);
    bson_destroy(distinct);

    /* update */
    bson_t* q = bson_create();
    bson_append_string(q, "_id", "one");
    bson_t* setdoc = bson_create();
    bson_append_int32(setdoc, "age", 42);
    bson_t* u = bson_create();
    bson_append_document(u, "$set", setdoc);
    bson_t* upd = bson_create();
    bson_append_string(upd, "update", "people");
    bson_t* uarr = bson_create();
    bson_t* uspec = bson_create();
    bson_append_document(uspec, "q", q);
    bson_append_document(uspec, "u", u);
    bson_append_document(uarr, "0", uspec);
    bson_append_array(upd, "updates", uarr);
    reply = mongo_dispatch_command(cat, "db", upd);
    expect_ok(reply, 1);
    assert(bson_find_element(reply, "nModified", &e) == 0 && e.v.i32 == 1);
    bson_destroy(reply);
    bson_destroy(upd);
    bson_destroy(uarr);
    bson_destroy(uspec);
    bson_destroy(setdoc);
    bson_destroy(u);
    bson_destroy(q);

    /* aggregate: $match + $group */
    bson_t* match = bson_create();
    bson_t* mf = bson_create();
    bson_append_string(mf, "name", "alice");
    bson_append_document(match, "$match", mf);
    bson_t* group = bson_create();
    bson_t* gspec = bson_create();
    bson_append_int32(gspec, "_id", 0);
    bson_t* gsum = bson_create();
    bson_append_int32(gsum, "$sum", 1);
    bson_append_document(gspec, "count", gsum);
    bson_append_document(group, "$group", gspec);
    bson_t* pipeline = bson_create();
    bson_append_document(pipeline, "0", match);
    bson_append_document(pipeline, "1", group);
    bson_t* agg = bson_create();
    bson_append_string(agg, "aggregate", "people");
    bson_append_array(agg, "pipeline", pipeline);
    reply = mongo_dispatch_command(cat, "db", agg);
    expect_ok(reply, 1);
    json = bson_to_json(reply);
    if (!json || strstr(json, "\"count\":1") == NULL) {
        fprintf(stderr, "aggregate reply: %s\n", json ? json : "(null)");
    }
    assert(json != NULL && strstr(json, "\"count\":1") != NULL);
    free(json);
    bson_destroy(reply);
    bson_destroy(agg);
    bson_destroy(pipeline);
    bson_destroy(group);
    bson_destroy(gsum);
    bson_destroy(gspec);
    bson_destroy(match);
    bson_destroy(mf);

    /* an unimplemented aggregation stage is refused, not silently dropped */
    bson_t* lookup = bson_create();
    bson_t* lspec = bson_create();
    bson_append_string(lspec, "from", "other");
    bson_append_document(lookup, "$lookup", lspec);
    bson_t* pipe2 = bson_create();
    bson_append_document(pipe2, "0", lookup);
    bson_t* agg2 = bson_create();
    bson_append_string(agg2, "aggregate", "people");
    bson_append_array(agg2, "pipeline", pipe2);
    reply = mongo_dispatch_command(cat, "db", agg2);
    expect_ok(reply, 0);
    bson_destroy(reply);
    bson_destroy(agg2);
    bson_destroy(pipe2);
    bson_destroy(lookup);
    bson_destroy(lspec);

    /* listCollections / listDatabases */
    bson_t* lc = bson_create();
    bson_append_int32(lc, "listCollections", 1);
    reply = mongo_dispatch_command(cat, "db", lc);
    expect_ok(reply, 1);
    json = bson_to_json(reply);
    assert(json != NULL && strstr(json, "people") != NULL);
    free(json);
    bson_destroy(reply);
    bson_destroy(lc);

    bson_t* ld = bson_create();
    bson_append_int32(ld, "listDatabases", 1);
    reply = mongo_dispatch_command(cat, "admin", ld);
    expect_ok(reply, 1);
    json = bson_to_json(reply);
    assert(json != NULL && strstr(json, "\"db\"") != NULL);
    free(json);
    bson_destroy(reply);
    bson_destroy(ld);

    /* getMore / createIndexes are refused loudly */
    bson_t* gm = bson_create();
    bson_append_int64(gm, "getMore", 0);
    reply = mongo_dispatch_command(cat, "db", gm);
    expect_ok(reply, 0);
    assert(bson_find_element(reply, "code", &e) == 0 && e.v.i32 == 303);
    bson_destroy(reply);
    bson_destroy(gm);

    bson_t* ci = bson_create();
    bson_append_string(ci, "createIndexes", "people");
    reply = mongo_dispatch_command(cat, "db", ci);
    expect_ok(reply, 0);
    assert(bson_find_element(reply, "code", &e) == 0 && e.v.i32 == 303);
    bson_destroy(reply);
    bson_destroy(ci);

    /* unknown command */
    bson_t* bogus = bson_create();
    bson_append_int32(bogus, "notACommand", 1);
    reply = mongo_dispatch_command(cat, "db", bogus);
    expect_ok(reply, 0);
    assert(bson_find_element(reply, "code", &e) == 0 && e.v.i32 == 59);
    bson_destroy(reply);
    bson_destroy(bogus);

    /* an option that would change the answer is refused, not ignored */
    bson_t* collation = bson_create();
    bson_t* locale = bson_create();
    bson_append_string(locale, "locale", "en_US");
    bson_append_string(collation, "find", "people");
    bson_append_document(collation, "collation", locale);
    reply = mongo_dispatch_command(cat, "db", collation);
    expect_ok(reply, 0);
    assert(bson_find_element(reply, "code", &e) == 0 && e.v.i32 == 303);
    bson_destroy(reply);
    bson_destroy(collation);
    bson_destroy(locale);

    /* delete then drop */
    bson_t* dq = bson_create();
    bson_append_string(dq, "_id", "one");
    bson_t* dspec = bson_create();
    bson_append_document(dspec, "q", dq);
    bson_append_int32(dspec, "limit", 0);
    bson_t* darr = bson_create();
    bson_append_document(darr, "0", dspec);
    bson_t* del = bson_create();
    bson_append_string(del, "delete", "people");
    bson_append_array(del, "deletes", darr);
    reply = mongo_dispatch_command(cat, "db", del);
    expect_ok(reply, 1);
    assert(bson_find_element(reply, "n", &e) == 0 && e.v.i32 == 1);
    bson_destroy(reply);
    bson_destroy(del);
    bson_destroy(darr);
    bson_destroy(dspec);
    bson_destroy(dq);

    bson_t* drop = bson_create();
    bson_append_string(drop, "drop", "people");
    reply = mongo_dispatch_command(cat, "db", drop);
    expect_ok(reply, 1);
    bson_destroy(reply);
    bson_destroy(drop);

    mongo_catalog_destroy(cat);
    printf("PASS mongo dispatch: ping/hello/insert/find/count/distinct/update/"
           "delete/aggregate/catalog commands\n");
}

/* ── 7. the TCP server ───────────────────────────────────────────────────── */

static int connect_to(uint16_t port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    assert(fd >= 0);
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    assert(connect(fd, (struct sockaddr*)&addr, sizeof(addr)) == 0);
    return fd;
}

static int send_frame(int fd, const uint8_t* frame, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        ssize_t w = write(fd, frame + sent, len - sent);
        if (w <= 0) return -1;
        sent += (size_t)w;
    }
    return 0;
}

/* Read one full reply frame; returns a heap buffer the caller frees. */
static uint8_t* read_frame(int fd, size_t* out_len) {
    uint8_t head[4];
    size_t have = 0;
    while (have < 4) {
        struct pollfd pfd = { fd, POLLIN, 0 };
        assert(poll(&pfd, 1, 5000) > 0);
        ssize_t r = read(fd, head + have, 4 - have);
        assert(r > 0);
        have += (size_t)r;
    }
    int32_t declared;
    memcpy(&declared, head, 4);
    assert(declared >= 16 && declared <= (int32_t)(17 * 1024 * 1024));
    uint8_t* buf = (uint8_t*)malloc((size_t)declared);
    assert(buf != NULL);
    memcpy(buf, head, 4);
    have = 4;
    while (have < (size_t)declared) {
        struct pollfd pfd = { fd, POLLIN, 0 };
        assert(poll(&pfd, 1, 5000) > 0);
        ssize_t r = read(fd, buf + have, (size_t)declared - have);
        assert(r > 0);
        have += (size_t)r;
    }
    *out_len = (size_t)declared;
    return buf;
}

/* Extract the reply document from an OP_MSG or OP_REPLY frame. */
static bson_t* reply_document(const uint8_t* frame, size_t len) {
    mongo_msg_t msg;
    assert(mongo_msg_parse(frame, len, &msg) == 0);
    size_t off = 0;
    bson_t* doc = mongo_msg_get_document(&msg, &off);
    assert(doc != NULL);
    return doc;
}

static void test_server(void) {
    qihse_mongo_server_t* srv = qihse_mongo_server_create(0, NULL);
    assert(srv != NULL);
    assert(qihse_mongo_server_start(srv) == 0);
    assert(srv->port != 0);
    uint16_t port = srv->port;

    int fd = connect_to(port);
    bson_element_t e;
    bson_t* reply;
    size_t len = 0;

    /* Before authenticating, every command is refused with code 13. */
    bson_t* ping = cmd_ping();
    uint8_t* frame = build_op_msg(1, ping, &len);
    assert(send_frame(fd, frame, len) == 0);
    free(frame);
    uint8_t* resp = read_frame(fd, &len);
    reply = reply_document(resp, len);
    assert(bson_find_element(reply, "ok", &e) == 0 && e.v.i32 == 0);
    assert(bson_find_element(reply, "code", &e) == 0 && e.v.i32 == 13);
    bson_destroy(reply);
    free(resp);
    bson_destroy(ping);

    /* authenticate */
    bson_t* auth = bson_create();
    bson_append_int32(auth, "authenticate", 1);
    bson_append_string(auth, "user", "GODMODE_OP");
    bson_append_string(auth, "pwd", OPERATOR_PASSWORD);
    bson_append_string(auth, "$db", "admin");
    frame = build_op_msg(2, auth, &len);
    assert(send_frame(fd, frame, len) == 0);
    free(frame);
    resp = read_frame(fd, &len);
    reply = reply_document(resp, len);
    expect_ok(reply, 1);
    bson_destroy(reply);
    free(resp);
    bson_destroy(auth);

    /* insert + find over the wire */
    bson_t* doc = bson_create();
    bson_append_string(doc, "_id", "wire-1");
    bson_append_string(doc, "name", "over-the-wire");
    bson_t* docs = bson_create();
    bson_append_document(docs, "0", doc);
    bson_t* ins = bson_create();
    bson_append_string(ins, "insert", "wire");
    bson_append_array(ins, "documents", docs);
    bson_append_string(ins, "$db", "wiredb");
    frame = build_op_msg(3, ins, &len);
    assert(send_frame(fd, frame, len) == 0);
    free(frame);
    resp = read_frame(fd, &len);
    reply = reply_document(resp, len);
    expect_ok(reply, 1);
    bson_destroy(reply);
    free(resp);
    bson_destroy(ins);
    bson_destroy(docs);
    bson_destroy(doc);

    bson_t* find = cmd_find("wire");
    bson_append_string(find, "$db", "wiredb");
    frame = build_op_msg(4, find, &len);
    assert(send_frame(fd, frame, len) == 0);
    free(frame);
    resp = read_frame(fd, &len);
    reply = reply_document(resp, len);
    expect_ok(reply, 1);
    char* json = bson_to_json(reply);
    assert(json != NULL && strstr(json, "over-the-wire") != NULL);
    free(json);
    bson_destroy(reply);
    free(resp);
    bson_destroy(find);

    /* a malformed frame ends the connection instead of being guessed at */
    uint8_t junk[16];
    memset(junk, 0, sizeof(junk));
    put_i32(junk, 8);   /* a message cannot be shorter than its header */
    assert(send_frame(fd, junk, sizeof(junk)) == 0);
    struct pollfd pfd = { fd, POLLIN, 0 };
    assert(poll(&pfd, 1, 2000) > 0);
    uint8_t sink[64];
    assert(read(fd, sink, sizeof(sink)) == 0);   /* EOF: server closed */
    close(fd);

    /* legacy OP_QUERY on a collection is the pre-OP_MSG find form */
    int fd2 = connect_to(port);
    bson_t* auth2 = bson_create();
    bson_append_int32(auth2, "authenticate", 1);
    bson_append_string(auth2, "user", "GODMODE_OP");
    bson_append_string(auth2, "pwd", OPERATOR_PASSWORD);
    frame = build_op_query(5, "admin.$cmd", auth2, &len);
    assert(send_frame(fd2, frame, len) == 0);
    free(frame);
    resp = read_frame(fd2, &len);
    reply = reply_document(resp, len);
    expect_ok(reply, 1);
    bson_destroy(reply);
    free(resp);
    bson_destroy(auth2);

    bson_t* empty = bson_create();
    frame = build_op_query(6, "wiredb.wire", empty, &len);
    assert(send_frame(fd2, frame, len) == 0);
    free(frame);
    resp = read_frame(fd2, &len);
    {
        int32_t opcode;
        memcpy(&opcode, resp + 12, 4);
        assert(opcode == MONGO_OP_REPLY);
    }
    reply = reply_document(resp, len);
    expect_ok(reply, 1);
    json = bson_to_json(reply);
    assert(json != NULL && strstr(json, "over-the-wire") != NULL);
    free(json);
    bson_destroy(reply);
    free(resp);
    bson_destroy(empty);

    /* legacy OP_INSERT is applied and answered with no frame at all */
    bson_t* legacy = bson_create();
    bson_append_string(legacy, "_id", "legacy-1");
    bson_append_string(legacy, "name", "inserted-by-op-insert");
    frame = build_op_insert(7, "wiredb.wire", legacy, &len);
    assert(send_frame(fd2, frame, len) == 0);
    free(frame);
    bson_destroy(legacy);

    bson_t* find2 = cmd_find("wire");
    bson_append_string(find2, "$db", "wiredb");
    frame = build_op_msg(8, find2, &len);
    assert(send_frame(fd2, frame, len) == 0);
    free(frame);
    resp = read_frame(fd2, &len);
    reply = reply_document(resp, len);
    expect_ok(reply, 1);
    json = bson_to_json(reply);
    assert(json != NULL && strstr(json, "inserted-by-op-insert") != NULL);
    free(json);
    bson_destroy(reply);
    free(resp);
    bson_destroy(find2);
    close(fd2);

    assert(qihse_mongo_server_stop(srv) == 0);
    qihse_mongo_server_destroy(srv);
    printf("PASS mongo server: start/authenticate/insert/find over a socket, malformed frame closes\n");
}

int main(void) {
    char data_dir[] = "/tmp/qihse-mongo-wire-XXXXXX";
    assert(mkdtemp(data_dir) != NULL);
    assert(setenv("QIHSE_DATA_DIR", data_dir, 1) == 0);
    assert(setenv("QIHSE_FIPS_MODE", "disabled", 1) == 0);

    test_nested_encoding();
    test_msg_parse();
    test_aggregation();
    test_catalog();
    qihse_user_t* op = bootstrap_users();
    test_dispatch(op);
    test_server();

    printf("test_mongo_wire: all asserted MongoDB wire behaviours passed\n");
    return 0;
}
