/* Blob tier security regression test (AGENTS.md invariants #1, U1).
 *
 * Positive coverage: streaming/buffer puts, content-addressed dedup, range
 * reads, refcounting. Negative coverage (asserted with payload-absence
 * checks): NULL/denied user contexts, cross-tenant reads/deletes/lists,
 * above-clearance blobs, tenant writes to commons or foreign tenants, hash
 * binding-clash dedup abuse, and revoked principals.
 */
#define _GNU_SOURCE

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "qihse_auth.h"
#include "qihse_blob.h"

#define TENANT7_PW "BlobTenant7Pass1!"
#define TENANT8_PW "BlobTenant8Pass1!"
#define OPERATOR_PASSWORD "OperatorBlobPass1!"

typedef struct {
    int seen;
    int foreign_seen;
} list_counter_t;

static bool count_cb(const qihse_blob_info_t* info, void* opaque) {
    list_counter_t* c = opaque;
    c->seen++;
    if (info->tenant_id == 7 && info->tag != QIHSE_BLOB_TAG_COMMONS_SNAPSHOT) c->foreign_seen++;
    return true;
}

int main(void) {
    char data_dir[] = "/tmp/qihse-blob-sec-XXXXXX";
    assert(mkdtemp(data_dir) != NULL);
    assert(setenv("QIHSE_DATA_DIR", data_dir, 1) == 0);
    assert(setenv("QIHSE_FIPS_MODE", "disabled", 1) == 0);

    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator(OPERATOR_PASSWORD));
    qihse_user_t* operator_user = qihse_auth_get_user(0);
    assert(operator_user != NULL);
    qihse_user_t* tenant7 = qihse_auth_create_tenant_user(operator_user, 7, 71,
                                                          QIHSE_ROLE_GUEST, 91, 0,
                                                          TENANT7_PW, false);
    assert(tenant7 != NULL);
    qihse_user_t* tenant8 = qihse_auth_create_tenant_user(operator_user, 8, 72,
                                                          QIHSE_ROLE_GUEST, 91, 0,
                                                          TENANT8_PW, false);
    assert(tenant8 != NULL);

    char blob_dir[512];
    snprintf(blob_dir, sizeof(blob_dir), "%s/blobs", data_dir);
    qihse_blob_store_t* blobs = qihse_blob_store_create(blob_dir);
    assert(blobs != NULL);

    /* --- Positive: operator writes tenant 7's pattern bundle ------------- */
    uint8_t pattern[70000]; /* spans several 64KB-ish streaming chunks */
    for (size_t i = 0; i < sizeof(pattern); i++) pattern[i] = (uint8_t)(i * 7u);
    uint8_t hash7[QIHSE_BLOB_HASH_BYTES];
    uint64_t size7 = 0;
    assert(qihse_blob_put_buffer_user(blobs, 7, QIHSE_BLOB_TAG_PATTERN_BUNDLE, 91, 0,
                                      operator_user, pattern, sizeof(pattern),
                                      hash7));
    assert(qihse_blob_size_user(blobs, hash7, &size7, operator_user));
    assert(size7 == sizeof(pattern));

    /* Full read + range read. */
    uint8_t out[sizeof(pattern)];
    size_t nread = 0;
    assert(qihse_blob_get_user(blobs, hash7, 0, out, sizeof(out), &nread, operator_user));
    assert(nread == sizeof(pattern));
    assert(memcmp(out, pattern, sizeof(pattern)) == 0);
    uint8_t window[100];
    assert(qihse_blob_get_user(blobs, hash7, 4096, window, sizeof(window), &nread, tenant7));
    assert(nread == sizeof(window));
    assert(memcmp(window, pattern + 4096, sizeof(window)) == 0);

    /* Dedup: same content + same binding → same hash, no error. */
    uint8_t hash7b[QIHSE_BLOB_HASH_BYTES];
    assert(qihse_blob_put_buffer_user(blobs, 7, QIHSE_BLOB_TAG_PATTERN_BUNDLE, 91, 0,
                                      operator_user, pattern, sizeof(pattern), hash7b));
    assert(memcmp(hash7b, hash7, QIHSE_BLOB_HASH_BYTES) == 0);

    /* --- Negative: hash binding-clash (cross-tenant dedup claim) -------- */
    uint8_t clash[QIHSE_BLOB_HASH_BYTES];
    assert(!qihse_blob_put_buffer_user(blobs, 8, QIHSE_BLOB_TAG_PATTERN_BUNDLE, 91, 0,
                                       operator_user, pattern, sizeof(pattern), clash));

    /* --- Negative: NULL user is unconditionally denied (invariant #1) ---- */
    assert(!qihse_blob_put_buffer_user(blobs, 7, QIHSE_BLOB_TAG_SCRIPT_SET, 0, 0,
                                       NULL, pattern, 128, clash));
    assert(!qihse_blob_get_user(blobs, hash7, 0, out, sizeof(out), &nread, NULL));
    assert(!qihse_blob_size_user(blobs, hash7, &size7, NULL));
    assert(!qihse_blob_delete_user(blobs, hash7, NULL));

    /* --- Tenant writes --------------------------------------------------- */
    uint8_t script[4096];
    memset(script, 0xAB, sizeof(script));
    uint8_t hash_script[QIHSE_BLOB_HASH_BYTES];
    assert(qihse_blob_put_buffer_user(blobs, 7, QIHSE_BLOB_TAG_SCRIPT_SET, 0, 0,
                                      tenant7, script, sizeof(script), hash_script));
    /* Commons is operator-curated: tenant writes denied. */
    assert(!qihse_blob_put_buffer_user(blobs, 7, QIHSE_BLOB_TAG_COMMONS_SNAPSHOT, 0, 0,
                                       tenant7, script, sizeof(script), clash));
    /* Foreign tenant binding denied. */
    assert(!qihse_blob_put_buffer_user(blobs, 8, QIHSE_BLOB_TAG_SCRIPT_SET, 0, 0,
                                       tenant7, script, sizeof(script), clash));

    /* --- Negative: cross-tenant reads / enumeration / deletion ----------- */
    memset(out, 0, sizeof(out));
    assert(!qihse_blob_get_user(blobs, hash7, 0, out, sizeof(out), &nread, tenant8));
    for (size_t i = 0; i < sizeof(out); i++) assert(out[i] == 0); /* no payload disclosure */
    assert(!qihse_blob_get_user(blobs, hash_script, 0, out, sizeof(out), &nread, tenant8));
    assert(!qihse_blob_size_user(blobs, hash7, &size7, tenant8));
    assert(!qihse_blob_delete_user(blobs, hash7, tenant8));
    assert(!qihse_blob_ref_user(blobs, hash7, tenant8));

    list_counter_t counts = { 0, 0 };
    assert(qihse_blob_list_user(blobs, tenant8, count_cb, &counts));
    assert(counts.foreign_seen == 0); /* tenant 8 sees no tenant 7 blobs */

    /* Tenant 7 lists its own blob. */
    counts.seen = 0; counts.foreign_seen = 0;
    assert(qihse_blob_list_user(blobs, tenant7, count_cb, &counts));
    assert(counts.seen >= 1);

    /* --- Negative: above-clearance blob ---------------------------------- */
    uint8_t secret[2048];
    memset(secret, 0x11, sizeof(secret));
    uint8_t hash_secret[QIHSE_BLOB_HASH_BYTES];
    assert(qihse_blob_put_buffer_user(blobs, 7, QIHSE_BLOB_TAG_SCRIPT_SET, 95, 0,
                                      operator_user, secret, sizeof(secret), hash_secret));
    memset(out, 0, sizeof(out));
    assert(!qihse_blob_get_user(blobs, hash_secret, 0, out, sizeof(out), &nread, tenant7));
    for (size_t i = 0; i < sizeof(out); i++) assert(out[i] == 0);

    /* --- Commons: readable by all authenticated tenants ------------------ */
    uint8_t commons[1024];
    memset(commons, 0x33, sizeof(commons));
    uint8_t hash_commons[QIHSE_BLOB_HASH_BYTES];
    assert(qihse_blob_put_buffer_user(blobs, 0, QIHSE_BLOB_TAG_COMMONS_SNAPSHOT, 0, 0,
                                      operator_user, commons, sizeof(commons), hash_commons));
    assert(qihse_blob_get_user(blobs, hash_commons, 0, out, sizeof(out), &nread, tenant7));
    assert(nread == sizeof(commons));
    assert(qihse_blob_get_user(blobs, hash_commons, 0, out, sizeof(out), &nread, tenant8));
    /* ...but not by the unauthenticated: handled by NULL denial above. */

    /* --- Refcount lifecycle ---------------------------------------------- */
    assert(qihse_blob_ref_user(blobs, hash_script, tenant7));     /* refs = 2 */
    assert(qihse_blob_delete_user(blobs, hash_script, tenant7));  /* refs = 1 */
    assert(qihse_blob_get_user(blobs, hash_script, 0, out, sizeof(out), &nread, tenant7));
    assert(nread == sizeof(script));
    assert(qihse_blob_delete_user(blobs, hash_script, tenant7));  /* refs = 0 → gone */
    assert(!qihse_blob_get_user(blobs, hash_script, 0, out, sizeof(out), &nread, tenant7));

    /* --- Revocation: destroyed principal loses access immediately -------- */
    qihse_user_t* ephemeral = qihse_auth_create_tenant_user(operator_user, 7, 73,
                                                            QIHSE_ROLE_GUEST, 91, 0,
                                                            "EphemeralPass12!", false);
    assert(ephemeral != NULL);
    assert(qihse_auth_destroy_user(operator_user, 73));
    assert(!qihse_blob_get_user(blobs, hash7, 0, out, sizeof(out), &nread, ephemeral));
    assert(!qihse_blob_put_buffer_user(blobs, 7, QIHSE_BLOB_TAG_SCRIPT_SET, 0, 0,
                                       ephemeral, script, sizeof(script), clash));

    qihse_blob_store_destroy(blobs);
    printf("test_blob_security_regression: all assertions passed\n");
    return 0;
}
