/*
 * test_mongo_wire_security.c — MongoDB wire adapter negative authorization
 * test (AGENTS.md invariant 3).
 *
 * A low-clearance GUEST principal (classification 91, no SCI compartments)
 * authenticates against ONE catalog that holds data above its clearance and
 * outside its compartments, and every access attempt through the adapter is
 * asserted to be denied WITH NO PROTECTED PAYLOAD DISCLOSURE.  The assertions
 * are on BYTES: the serialized reply document, its JSON rendering and the raw
 * wire frame must not contain the protected payload — not merely "the call
 * returned an error".
 *
 * Covered access forms:
 *   1.  normal query path (find with no filter, find with a filter, count,
 *       distinct, aggregate)
 *   2.  direct-ID lookup (find {_id: "vault-1"})
 *   3.  enumeration (listCollections, listDatabases, dbStats, collStats)
 *   4.  write/destructive forms (update, delete, drop, dropDatabase,
 *       mongo_catalog_drop_collection)
 *   5.  handle materialisation (mongo_catalog_get_collection,
 *       mongo_catalog_get_db, mongo_db_get_collection)
 *   6.  a NULL security context over the SAME catalog that holds the protected
 *       data (invariant 1: must fail closed, never inherit a principal)
 *   7.  client-side label forgery (a client must not be able to label its own
 *       data as unclassified)
 *   8.  the same negative checks over a real socket (OP_MSG + authenticate)
 *
 * Positive controls prove the test is not vacuous: the operator DOES read the
 * protected payload in-process and over the wire, and the guest DOES read the
 * document it wrote itself at its own clearance.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "qihse_auth.h"
#include "qihse_mongo_wire.h"

#include <assert.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define OPERATOR_PASSWORD "OperatorMongoSec1!"
#define GUEST_PASSWORD    "GuestMongoSec1!"
#define SCI_PASSWORD      "SciMongoSec1!"
#define LOW_PASSWORD      "LowMongoSec1!"

#define GUEST_UID 81
#define SCI_UID   82
#define LOW_UID   83
#define GUEST_CLEARANCE 91
#define LOW_CLEARANCE   40

/* The protected payload: a byte sequence that must never reach the guest. */
#define PROTECTED_PAYLOAD "MONGO-TOPSECRET-PAYLOAD-4f2b9c"
#define PROTECTED_ID      "vault-1"
#define PUBLIC_ID         "public-1"
#define SCI_PAYLOAD       "MONGO-SCI-PAYLOAD-7d1e5a"
#define SCI_ID            "sci-1"

static int failures = 0;

#define CHECK(cond, what) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, (what)); \
        failures++; \
    } \
} while (0)

/* ── byte-level non-disclosure assertions ────────────────────────────────── */

static int bytes_contain(const uint8_t* hay, size_t n, const char* needle) {
    size_t nl = strlen(needle);
    if (nl == 0 || n < nl) return 0;
    return memmem(hay, n, needle, nl) != NULL;
}

/* Assert the needle appears in NO byte of the reply document or of its JSON
 * rendering. */
static void check_no_payload(const bson_t* reply, const char* needle, const char* what) {
    size_t len = bson_size(reply);
    const uint8_t* data = bson_data(reply);
    if (bytes_contain(data, len, needle)) {
        fprintf(stderr, "FAIL %s: reply bytes contain the protected payload\n", what);
        failures++;
    }
    char* json = bson_to_json(reply);
    if (json && strstr(json, needle) != NULL) {
        fprintf(stderr, "FAIL %s: reply JSON contains the protected payload: %s\n", what, json);
        failures++;
    }
    free(json);
}

static void check_frame_no_payload(const uint8_t* frame, size_t len, const char* needle,
                                   const char* what) {
    if (bytes_contain(frame, len, needle)) {
        fprintf(stderr, "FAIL %s: wire frame contains the protected payload\n", what);
        failures++;
    }
}

static int reply_ok(const bson_t* reply) {
    bson_element_t e;
    if (bson_find_element(reply, "ok", &e) != 0) return -1;
    return e.v.i32;
}

static int reply_code(const bson_t* reply) {
    bson_element_t e;
    if (bson_find_element(reply, "code", &e) != 0) return -1;
    return e.v.i32;
}

/* Number of documents in a cursor reply's firstBatch, or -1 when the reply is
 * not a cursor reply (e.g. an error). */
static int first_batch_count(const bson_t* reply) {
    bson_element_t c, b;
    if (bson_find_element(reply, "cursor", &c) != 0) return -1;
    if (c.type != BSON_DOCUMENT) return -1;
    bson_t cursor = { (uint8_t*)c.v.doc.data, (size_t)c.v.doc.len, (size_t)c.v.doc.len };
    if (bson_find_element(&cursor, "firstBatch", &b) != 0) return -1;
    if (b.type != BSON_ARRAY) return -1;
    bson_t arr = { (uint8_t*)b.v.doc.data, (size_t)b.v.doc.len, (size_t)b.v.doc.len };
    int n = 0;
    size_t off = 0;
    bson_element_t e;
    while (bson_iter(&arr, &off, &e) == 0) n++;
    return n;
}

/* ── command builders ────────────────────────────────────────────────────── */

static bson_t* cmd(const char* name, const char* coll) {
    bson_t* c = bson_create();
    if (coll) bson_append_string(c, name, coll);
    else bson_append_int32(c, name, 1);
    return c;
}

static bson_t* cmd_find_id(const char* coll, const char* id) {
    bson_t* f = bson_create();
    bson_append_string(f, "_id", id);
    bson_t* c = bson_create();
    bson_append_string(c, "find", coll);
    bson_append_document(c, "filter", f);
    bson_destroy(f);
    return c;
}

static bson_t* cmd_insert_one(const char* coll, const bson_t* doc) {
    bson_t* docs = bson_create();
    bson_append_document(docs, "0", doc);
    bson_t* c = bson_create();
    bson_append_string(c, "insert", coll);
    bson_append_array(c, "documents", docs);
    bson_destroy(docs);
    return c;
}

static bson_t* doc_public(void) {
    bson_t* d = bson_create();
    bson_append_string(d, "_id", PUBLIC_ID);
    bson_append_string(d, "name", "unclassified");
    return d;
}

static bson_t* doc_protected(void) {
    bson_t* d = bson_create();
    bson_append_string(d, "_id", PROTECTED_ID);
    bson_append_string(d, "secret", PROTECTED_PAYLOAD);
    bson_append_string(d, "name", "above-the-guests-clearance");
    return d;
}

static bson_t* doc_sci(void) {
    bson_t* d = bson_create();
    bson_append_string(d, "_id", SCI_ID);
    bson_append_string(d, "secret", SCI_PAYLOAD);
    return d;
}

/* ── the in-process negative test ────────────────────────────────────────── */

static void run_in_process(qihse_user_t* op, qihse_user_t* guest, qihse_user_t* sci_principal) {
    /* ONE catalog holding the protected data.  Every principal is bound to it
     * in turn, so "denied" cannot be an artefact of looking at an empty
     * catalog. */
    mongo_catalog_t* cat = mongo_catalog_create_auth(NULL, op);
    assert(cat != NULL);
    bson_t* r;

    /* the operator writes data above the guest's clearance */
    bson_t* prot = doc_protected();
    bson_t* c = cmd_insert_one("vault", prot);
    r = mongo_dispatch_command(cat, "db", c);
    CHECK(reply_ok(r) == 1, "operator could not insert the protected document");
    bson_destroy(r);
    bson_destroy(c);
    bson_destroy(prot);

    /* a principal with SCI compartments the guest does not hold writes an
     * unclassified document that is still outside the guest's compartments */
    CHECK(mongo_catalog_bind_user(cat, sci_principal) == 0, "could not bind the SCI principal");
    bson_t* sci = doc_sci();
    c = cmd_insert_one("compartments", sci);
    r = mongo_dispatch_command(cat, "db", c);
    CHECK(reply_ok(r) == 1, "SCI principal could not insert its document");
    bson_destroy(r);
    bson_destroy(c);
    bson_destroy(sci);

    /* ── positive control: the operator DOES get the payload ─────────────── */
    CHECK(mongo_catalog_bind_user(cat, op) == 0, "could not bind the operator");
    c = cmd_find_id("vault", PROTECTED_ID);
    r = mongo_dispatch_command(cat, "db", c);
    CHECK(reply_ok(r) == 1, "operator find failed");
    CHECK(first_batch_count(r) == 1, "operator find did not return the protected document");
    CHECK(bytes_contain(bson_data(r), bson_size(r), PROTECTED_PAYLOAD),
          "positive control: the operator's reply does not contain the payload, so this "
          "test cannot detect a disclosure");
    bson_destroy(r);
    bson_destroy(c);

    /* ── the guest, on the same catalog ──────────────────────────────────── */
    CHECK(mongo_catalog_bind_user(cat, guest) == 0, "could not bind the guest");

    /* positive control: the guest writes and reads back its own document,
     * which is labelled at the guest's own clearance */
    bson_t* pub = doc_public();
    c = cmd_insert_one("public", pub);
    r = mongo_dispatch_command(cat, "db", c);
    CHECK(reply_ok(r) == 1, "guest could not insert its own document");
    bson_destroy(r);
    bson_destroy(c);
    bson_destroy(pub);

    c = cmd_find_id("public", PUBLIC_ID);
    r = mongo_dispatch_command(cat, "db", c);
    CHECK(reply_ok(r) == 1 && first_batch_count(r) == 1,
          "guest could not read the document it wrote at its own clearance");
    bson_destroy(r);
    bson_destroy(c);

    /* 1. normal query path */
    c = cmd("find", "vault");
    r = mongo_dispatch_command(cat, "db", c);
    CHECK(reply_ok(r) == 1, "guest unfiltered find should be an empty result, not an error");
    CHECK(first_batch_count(r) == 0, "guest unfiltered find returned documents above its clearance");
    check_no_payload(r, PROTECTED_PAYLOAD, "guest unfiltered find");
    check_no_payload(r, PROTECTED_ID, "guest unfiltered find (_id)");
    bson_destroy(r);
    bson_destroy(c);

    /* 2. direct-ID lookup */
    c = cmd_find_id("vault", PROTECTED_ID);
    r = mongo_dispatch_command(cat, "db", c);
    CHECK(reply_ok(r) == 1, "guest direct-ID find should be an empty result, not an error");
    CHECK(first_batch_count(r) == 0, "guest direct-ID lookup returned the protected document");
    check_no_payload(r, PROTECTED_PAYLOAD, "guest direct-ID lookup");
    bson_destroy(r);
    bson_destroy(c);

    /* 2b. filter probe: using the payload as a filter value must not confirm
     * anything (the clearance check runs before the filter) */
    {
        bson_t* f = bson_create();
        bson_append_string(f, "secret", PROTECTED_PAYLOAD);
        c = cmd("find", "vault");
        bson_append_document(c, "filter", f);
        bson_destroy(f);
        r = mongo_dispatch_command(cat, "db", c);
        CHECK(first_batch_count(r) == 0, "guest probe by payload value matched the protected document");
        check_no_payload(r, PROTECTED_PAYLOAD, "guest payload-value probe");
        bson_destroy(r);
        bson_destroy(c);
    }

    /* count / distinct / aggregate */
    c = cmd("count", "vault");
    r = mongo_dispatch_command(cat, "db", c);
    {
        bson_element_t e;
        CHECK(bson_find_element(r, "n", &e) == 0 && e.v.i32 == 0,
              "guest count included a document above its clearance");
    }
    check_no_payload(r, PROTECTED_PAYLOAD, "guest count");
    bson_destroy(r);
    bson_destroy(c);

    c = cmd("distinct", "vault");
    bson_append_string(c, "key", "secret");
    r = mongo_dispatch_command(cat, "db", c);
    check_no_payload(r, PROTECTED_PAYLOAD, "guest distinct");
    bson_destroy(r);
    bson_destroy(c);

    {
        bson_t* stage = bson_create();
        bson_t* empty = bson_create();
        bson_append_document(stage, "$match", empty);
        bson_t* pipe = bson_create();
        bson_append_document(pipe, "0", stage);
        c = cmd("aggregate", "vault");
        bson_append_array(c, "pipeline", pipe);
        r = mongo_dispatch_command(cat, "db", c);
        CHECK(reply_ok(r) == 1, "guest aggregate on a collection it cannot read failed");
        CHECK(first_batch_count(r) == 0, "guest aggregate returned documents above its clearance");
        check_no_payload(r, PROTECTED_PAYLOAD, "guest aggregate");
        bson_destroy(r);
        bson_destroy(c);
        bson_destroy(pipe);
        bson_destroy(stage);
        bson_destroy(empty);
    }

    /* SCI compartments: unclassified but outside the guest's compartments */
    c = cmd_find_id("compartments", SCI_ID);
    r = mongo_dispatch_command(cat, "db", c);
    CHECK(first_batch_count(r) == 0, "guest read a document outside its SCI compartments");
    check_no_payload(r, SCI_PAYLOAD, "guest SCI-compartment find");
    bson_destroy(r);
    bson_destroy(c);

    /* 3. enumeration */
    c = cmd("listCollections", NULL);
    r = mongo_dispatch_command(cat, "db", c);
    {
        char* json = bson_to_json(r);
        CHECK(json && strstr(json, "vault") == NULL,
              "guest listCollections enumerated a collection above its clearance");
        CHECK(json && strstr(json, "compartments") == NULL,
              "guest listCollections enumerated a collection outside its compartments");
        CHECK(json && strstr(json, "public") != NULL,
              "guest listCollections did not enumerate the collection it may read");
        free(json);
    }
    check_no_payload(r, PROTECTED_PAYLOAD, "guest listCollections");
    bson_destroy(r);
    bson_destroy(c);

    c = cmd("listDatabases", NULL);
    r = mongo_dispatch_command(cat, "admin", c);
    {
        char* json = bson_to_json(r);
        CHECK(json && strstr(json, "\"db\"") == NULL,
              "guest listDatabases enumerated a database holding data above its clearance");
        free(json);
    }
    check_no_payload(r, PROTECTED_PAYLOAD, "guest listDatabases");
    bson_destroy(r);
    bson_destroy(c);

    c = cmd("collStats", "vault");
    r = mongo_dispatch_command(cat, "db", c);
    {
        bson_element_t e;
        CHECK(bson_find_element(r, "objects", &e) == 0 && e.v.i32 == 0,
              "guest collStats counted a document above its clearance");
    }
    check_no_payload(r, PROTECTED_PAYLOAD, "guest collStats");
    bson_destroy(r);
    bson_destroy(c);

    c = cmd("dbStats", NULL);
    r = mongo_dispatch_command(cat, "db", c);
    {
        /* Exactly one document in this database is within the guest's
         * clearance (public-1, which the guest itself wrote); the protected
         * document and the SCI document must not be counted. */
        bson_element_t e;
        CHECK(bson_find_element(r, "objects", &e) == 0 && e.v.i32 == 1,
              "guest dbStats counted documents above its clearance");
    }
    check_no_payload(r, PROTECTED_PAYLOAD, "guest dbStats");
    bson_destroy(r);
    bson_destroy(c);

    /* 4. destructive forms */
    {
        bson_t* q = bson_create();
        bson_append_string(q, "_id", PROTECTED_ID);
        bson_t* setdoc = bson_create();
        bson_append_string(setdoc, "secret", "overwritten");
        bson_t* u = bson_create();
        bson_append_document(u, "$set", setdoc);
        bson_t* spec = bson_create();
        bson_append_document(spec, "q", q);
        bson_append_document(spec, "u", u);
        bson_t* arr = bson_create();
        bson_append_document(arr, "0", spec);
        c = cmd("update", "vault");
        bson_append_array(c, "updates", arr);
        r = mongo_dispatch_command(cat, "db", c);
        {
            bson_element_t e;
            CHECK(bson_find_element(r, "nModified", &e) == 0 && e.v.i32 == 0,
                  "guest modified a document above its clearance");
        }
        check_no_payload(r, PROTECTED_PAYLOAD, "guest update");
        bson_destroy(r);
        bson_destroy(c);
        bson_destroy(arr); bson_destroy(spec); bson_destroy(u);
        bson_destroy(setdoc); bson_destroy(q);
    }
    {
        bson_t* q = bson_create();
        bson_append_string(q, "_id", PROTECTED_ID);
        bson_t* spec = bson_create();
        bson_append_document(spec, "q", q);
        bson_t* arr = bson_create();
        bson_append_document(arr, "0", spec);
        c = cmd("delete", "vault");
        bson_append_array(c, "deletes", arr);
        r = mongo_dispatch_command(cat, "db", c);
        {
            bson_element_t e;
            CHECK(bson_find_element(r, "n", &e) == 0 && e.v.i32 == 0,
                  "guest deleted a document above its clearance");
        }
        check_no_payload(r, PROTECTED_PAYLOAD, "guest delete");
        bson_destroy(r);
        bson_destroy(c);
        bson_destroy(arr); bson_destroy(spec); bson_destroy(q);
    }
    c = cmd("drop", "vault");
    r = mongo_dispatch_command(cat, "db", c);
    CHECK(reply_ok(r) == 0 && reply_code(r) == 13,
          "guest drop of a collection above its clearance was not refused with code 13");
    check_no_payload(r, PROTECTED_PAYLOAD, "guest drop");
    bson_destroy(r);
    bson_destroy(c);

    c = cmd("dropDatabase", NULL);
    r = mongo_dispatch_command(cat, "db", c);
    CHECK(reply_ok(r) == 0 && reply_code(r) == 13,
          "guest dropDatabase holding protected data was not refused with code 13");
    check_no_payload(r, PROTECTED_PAYLOAD, "guest dropDatabase");
    bson_destroy(r);
    bson_destroy(c);

    /* the protected document survived every destructive attempt */
    CHECK(mongo_catalog_bind_user(cat, op) == 0, "could not re-bind the operator");
    c = cmd_find_id("vault", PROTECTED_ID);
    r = mongo_dispatch_command(cat, "db", c);
    CHECK(first_batch_count(r) == 1,
          "the protected document no longer exists: a denied guest action was applied");
    bson_destroy(r);
    bson_destroy(c);

    /* 5. handle materialisation */
    CHECK(mongo_catalog_bind_user(cat, guest) == 0, "could not re-bind the guest");
    CHECK(mongo_catalog_get_collection(cat, "db", "vault") == NULL,
          "guest obtained a collection handle for a collection above its clearance");
    CHECK(mongo_catalog_get_db(cat, "db") == NULL,
          "guest obtained a database handle for a database holding protected data");
    {
        mongo_collection_t* pub_coll = mongo_catalog_get_collection(cat, "db", "public");
        CHECK(pub_coll != NULL, "guest could not obtain a handle for a collection it may read");
        CHECK(pub_coll == NULL || pub_coll->count == 1,
              "guest handle for its own collection has unexpected contents");
    }
    CHECK(mongo_catalog_drop_collection(cat, "db", "vault") != 0,
          "mongo_catalog_drop_collection dropped a collection above the guest's clearance");

    /* the same accessors for the operator, so the NULLs above are the
     * authorization decision and not a broken accessor */
    CHECK(mongo_catalog_bind_user(cat, op) == 0, "could not re-bind the operator");
    {
        mongo_database_t* db = mongo_catalog_get_db(cat, "db");
        CHECK(db != NULL, "operator could not obtain its own database handle");
        CHECK(db && mongo_db_get_collection(db, "vault") != NULL,
              "operator could not obtain a handle for the protected collection");
    }
    CHECK(mongo_catalog_get_collection(cat, "db", "vault") != NULL,
          "the protected collection is missing");

    /* 6. NULL security context over the SAME catalog.  Note that
     * qihse_auth_can_access(NULL, 0, 0) is TRUE by design, so this must be
     * refused by the adapter itself. */
    CHECK(mongo_catalog_bind_user(cat, NULL) == 0, "could not unbind the principal");
    c = cmd_find_id("vault", PROTECTED_ID);
    r = mongo_dispatch_command(cat, "db", c);
    CHECK(reply_ok(r) == 0 && reply_code(r) == 13,
          "a user-less dispatch was not refused with code 13");
    check_no_payload(r, PROTECTED_PAYLOAD, "NULL context dispatch");
    bson_destroy(r);
    bson_destroy(c);
    /* and an UNCLASSIFIED document is refused too: "no context" must not be
     * treated as "unclassified access" */
    c = cmd_find_id("public", PUBLIC_ID);
    r = mongo_dispatch_command(cat, "db", c);
    CHECK(reply_ok(r) == 0 && reply_code(r) == 13,
          "a user-less dispatch reached an unclassified document (NULL must fail closed)");
    bson_destroy(r);
    bson_destroy(c);
    c = cmd("find", "public");
    r = mongo_dispatch_command_as(cat, NULL, "db", c);
    CHECK(reply_ok(r) == 0 && reply_code(r) == 13,
          "mongo_dispatch_command_as(cat, NULL, ...) was not refused");
    bson_destroy(r);
    bson_destroy(c);
    CHECK(mongo_catalog_get_db(cat, "db") == NULL, "unbound catalog handed out a database handle");
    CHECK(mongo_catalog_get_collection(cat, "db", "public") == NULL,
          "unbound catalog handed out a collection handle");
    CHECK(mongo_catalog_drop_collection(cat, "db", "public") != 0,
          "unbound catalog dropped a collection");

    /* a never-bound catalog (the constructor path) must behave identically */
    {
        mongo_catalog_t* anon = mongo_catalog_create(NULL);
        assert(anon != NULL);
        CHECK(mongo_catalog_get_user(anon) == NULL, "an unbound catalog reported a principal");
        c = cmd_find_id("vault", PROTECTED_ID);
        r = mongo_dispatch_command(anon, "db", c);
        CHECK(reply_ok(r) == 0 && reply_code(r) == 13,
              "a user-less dispatch through a fresh catalog was not refused");
        check_no_payload(r, PROTECTED_PAYLOAD, "never-bound catalog dispatch");
        bson_destroy(r);
        bson_destroy(c);
        mongo_catalog_destroy(anon);
    }

    /* 7. client-side label forgery: the guest inserts a document claiming to be
     * unclassified.  The label must come from the guest's authenticated
     * clearance, so a lower-clearance principal still cannot read it. */
    CHECK(mongo_catalog_bind_user(cat, guest) == 0, "could not re-bind the guest");
    {
        bson_t* forged = bson_create();
        bson_append_string(forged, "_id", "forged-1");
        bson_append_string(forged, "secret", "forged-label-payload");
        bson_append_int32(forged, "__qihse_classif", 0);
        bson_append_int32(forged, "__qihse_sci", 0);
        c = cmd_insert_one("public", forged);
        r = mongo_dispatch_command(cat, "db", c);
        CHECK(reply_ok(r) == 1, "guest could not insert its own document");
        bson_destroy(r);
        bson_destroy(c);
        bson_destroy(forged);

        /* white-box: the stored label is the guest's clearance, not the
         * client-supplied 0 */
        mongo_collection_t* coll = mongo_catalog_get_collection(cat, "db", "public");
        CHECK(coll != NULL, "guest lost access to its own collection");
        if (coll) {
            int saw_label = 0;
            for (size_t i = 0; i < coll->count; i++) {
                bson_element_t id, cl, sc;
                if (bson_find_element(coll->docs[i], "_id", &id) != 0) continue;
                if (id.type != BSON_STRING || strcmp(id.v.str, "forged-1") != 0) continue;
                saw_label = 1;
                CHECK(bson_find_element(coll->docs[i], "__qihse_classif", &cl) == 0 &&
                      cl.v.i32 == GUEST_CLEARANCE,
                      "a client-supplied classification was accepted as the document label");
                CHECK(bson_find_element(coll->docs[i], "__qihse_sci", &sc) == 0 && sc.v.i32 == 0,
                      "a client-supplied SCI value was accepted as the document label");
            }
            CHECK(saw_label, "the forged document was not stored");
        }

        /* black-box: a principal below the guest's clearance must not see it */
        qihse_user_t* low = qihse_auth_authenticate("User_83", LOW_PASSWORD);
        CHECK(low != NULL, "could not authenticate the lower-clearance principal");
        if (low) {
            CHECK(mongo_catalog_bind_user(cat, low) == 0, "could not bind the low principal");
            c = cmd_find_id("public", "forged-1");
            r = mongo_dispatch_command(cat, "db", c);
            CHECK(first_batch_count(r) == 0,
                  "a client-forged label made a document readable below its writer's clearance");
            check_no_payload(r, "forged-label-payload", "forged-label read");
            bson_destroy(r);
            bson_destroy(c);
        }
    }

    /* the internal label fields must never appear in a reply */
    CHECK(mongo_catalog_bind_user(cat, guest) == 0, "could not re-bind the guest");
    c = cmd_find_id("public", PUBLIC_ID);
    r = mongo_dispatch_command(cat, "db", c);
    check_no_payload(r, "__qihse_classif", "guest find (internal label leak)");
    check_no_payload(r, "__qihse_sci", "guest find (internal label leak)");
    bson_destroy(r);
    bson_destroy(c);

    mongo_catalog_destroy(cat);
}

/* ── the same checks over a socket ───────────────────────────────────────── */

static void put_i32(uint8_t* p, int32_t v) { memcpy(p, &v, 4); }

static uint8_t* build_op_msg(int32_t request_id, const bson_t* cmd_doc, size_t* out_len) {
    size_t dlen = bson_size(cmd_doc);
    size_t total = 16 + 5 + dlen;
    uint8_t* frame = (uint8_t*)malloc(total);
    assert(frame != NULL);
    put_i32(frame, (int32_t)total);
    put_i32(frame + 4, request_id);
    put_i32(frame + 8, 0);
    put_i32(frame + 12, MONGO_OP_MSG);
    put_i32(frame + 16, 0);
    frame[20] = 0;
    memcpy(frame + 21, bson_data(cmd_doc), dlen);
    *out_len = total;
    return frame;
}

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

static uint8_t* read_frame(int fd, size_t* out_len) {
    uint8_t head[4];
    size_t have = 0;
    while (have < 4) {
        struct pollfd pfd = { fd, POLLIN, 0 };
        assert(poll(&pfd, 1, 5000) > 0);
        ssize_t n = read(fd, head + have, 4 - have);
        assert(n > 0);
        have += (size_t)n;
    }
    int32_t declared;
    memcpy(&declared, head, 4);
    assert(declared >= 16);
    uint8_t* buf = (uint8_t*)malloc((size_t)declared);
    assert(buf != NULL);
    memcpy(buf, head, 4);
    have = 4;
    while (have < (size_t)declared) {
        struct pollfd pfd = { fd, POLLIN, 0 };
        assert(poll(&pfd, 1, 5000) > 0);
        ssize_t n = read(fd, buf + have, (size_t)declared - have);
        assert(n > 0);
        have += (size_t)n;
    }
    *out_len = (size_t)declared;
    return buf;
}

static bson_t* frame_document(const uint8_t* frame, size_t len) {
    mongo_msg_t msg;
    assert(mongo_msg_parse(frame, len, &msg) == 0);
    size_t off = 0;
    bson_t* doc = mongo_msg_get_document(&msg, &off);
    assert(doc != NULL);
    return doc;
}

/* Send a command and return both the reply document and the raw frame. */
static bson_t* round_trip(int fd, int32_t id, const bson_t* c, uint8_t** raw, size_t* raw_len) {
    size_t len = 0;
    uint8_t* frame = build_op_msg(id, c, &len);
    size_t sent = 0;
    while (sent < len) {
        ssize_t w = write(fd, frame + sent, len - sent);
        assert(w > 0);
        sent += (size_t)w;
    }
    free(frame);
    *raw = read_frame(fd, &len);
    *raw_len = len;
    return frame_document(*raw, len);
}

static void authenticate(int fd, int32_t id, const char* user, const char* password, int want_ok) {
    bson_t* a = bson_create();
    bson_append_int32(a, "authenticate", 1);
    bson_append_string(a, "user", user);
    bson_append_string(a, "pwd", password);
    bson_append_string(a, "$db", "admin");
    uint8_t* raw = NULL;
    size_t raw_len = 0;
    bson_t* r = round_trip(fd, id, a, &raw, &raw_len);
    CHECK(reply_ok(r) == want_ok, "authenticate did not return the expected status");
    check_frame_no_payload(raw, raw_len, password, "authenticate reply echoes the password");
    bson_destroy(r);
    free(raw);
    bson_destroy(a);
}

static void run_over_the_wire(void) {
    qihse_mongo_server_t* srv = qihse_mongo_server_create(0, NULL);
    assert(srv != NULL);
    assert(qihse_mongo_server_start(srv) == 0);
    uint16_t port = srv->port;
    uint8_t* raw = NULL;
    size_t raw_len = 0;

    /* connection 1: the operator plants the protected document over the wire */
    int op_fd = connect_to(port);
    authenticate(op_fd, 1, "GODMODE_OP", OPERATOR_PASSWORD, 1);
    bson_t* prot = doc_protected();
    bson_t* c = cmd_insert_one("vault", prot);
    bson_t* r = round_trip(op_fd, 2, c, &raw, &raw_len);
    CHECK(reply_ok(r) == 1, "operator could not insert the protected document over the wire");
    bson_destroy(r);
    free(raw);
    bson_destroy(c);
    bson_destroy(prot);

    /* connection 2: no principal at all */
    int anon = connect_to(port);
    c = cmd_find_id("vault", PROTECTED_ID);
    r = round_trip(anon, 3, c, &raw, &raw_len);
    CHECK(reply_ok(r) == 0 && reply_code(r) == 13,
          "an unauthenticated connection was not refused with code 13");
    check_frame_no_payload(raw, raw_len, PROTECTED_PAYLOAD, "unauthenticated wire find");
    bson_destroy(r);
    free(raw);
    bson_destroy(c);
    close(anon);

    /* connection 3: the low-clearance guest */
    int guest_fd = connect_to(port);
    authenticate(guest_fd, 4, "User_81", GUEST_PASSWORD, 1);

    c = cmd_find_id("vault", PROTECTED_ID);
    r = round_trip(guest_fd, 5, c, &raw, &raw_len);
    CHECK(first_batch_count(r) == 0, "guest received the protected document over the wire");
    check_frame_no_payload(raw, raw_len, PROTECTED_PAYLOAD, "guest wire find");
    check_frame_no_payload(raw, raw_len, PROTECTED_ID, "guest wire find (_id)");
    bson_destroy(r);
    free(raw);
    bson_destroy(c);

    c = cmd("find", "vault");
    r = round_trip(guest_fd, 6, c, &raw, &raw_len);
    CHECK(first_batch_count(r) == 0, "guest unfiltered wire find returned protected documents");
    check_frame_no_payload(raw, raw_len, PROTECTED_PAYLOAD, "guest wire unfiltered find");
    bson_destroy(r);
    free(raw);
    bson_destroy(c);

    c = cmd("drop", "vault");
    r = round_trip(guest_fd, 7, c, &raw, &raw_len);
    CHECK(reply_ok(r) == 0 && reply_code(r) == 13, "guest wire drop was not refused");
    check_frame_no_payload(raw, raw_len, PROTECTED_PAYLOAD, "guest wire drop");
    bson_destroy(r);
    free(raw);
    bson_destroy(c);
    close(guest_fd);

    /* connection 1 again: the operator DOES get the payload over the wire */
    c = cmd_find_id("vault", PROTECTED_ID);
    r = round_trip(op_fd, 8, c, &raw, &raw_len);
    CHECK(first_batch_count(r) == 1, "the operator did not receive the protected document");
    if (!bytes_contain(raw, raw_len, PROTECTED_PAYLOAD)) {
        fprintf(stderr, "FAIL operator wire control: the payload is absent, so this test "
                        "cannot detect a disclosure\n");
        failures++;
    }
    bson_destroy(r);
    free(raw);
    bson_destroy(c);
    close(op_fd);

    assert(qihse_mongo_server_stop(srv) == 0);
    qihse_mongo_server_destroy(srv);
}

int main(void) {
    char data_dir[] = "/tmp/qihse-mongo-sec-XXXXXX";
    assert(mkdtemp(data_dir) != NULL);
    assert(setenv("QIHSE_DATA_DIR", data_dir, 1) == 0);
    assert(setenv("QIHSE_FIPS_MODE", "disabled", 1) == 0);

    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator(OPERATOR_PASSWORD));
    qihse_user_t* op = qihse_auth_get_user(0);
    assert(op != NULL);

    /* The low-clearance principal: GUEST role, classification 91, no SCI. */
    assert(qihse_auth_create_user(op, GUEST_UID, QIHSE_ROLE_GUEST, GUEST_CLEARANCE, 0,
                                  GUEST_PASSWORD, false) != NULL);
    /* A principal whose compartments are outside the guest's. */
    assert(qihse_auth_create_user(op, SCI_UID, QIHSE_ROLE_ANALYST, 0, 0xFFFF,
                                  SCI_PASSWORD, false) != NULL);
    /* A principal below the guest's clearance. */
    assert(qihse_auth_create_user(op, LOW_UID, QIHSE_ROLE_GUEST, LOW_CLEARANCE, 0,
                                  LOW_PASSWORD, false) != NULL);

    qihse_user_t* guest = qihse_auth_authenticate("User_81", GUEST_PASSWORD);
    assert(guest != NULL);
    qihse_user_t* sci_principal = qihse_auth_authenticate("User_82", SCI_PASSWORD);
    assert(sci_principal != NULL);

    run_in_process(op, guest, sci_principal);
    run_over_the_wire();

    if (failures != 0) {
        fprintf(stderr, "test_mongo_wire_security: %d assertion(s) FAILED\n", failures);
        return 1;
    }
    printf("test_mongo_wire_security: all assertions passed — the low-clearance principal "
           "is denied every access form with no protected payload disclosure\n");
    return 0;
}
