/* SCI compartmentalization regression test.
 *
 * Exercises the actual enforcement of Need-to-Know compartments at access
 * time — the gap this suite closes: until now every test fixture used
 * sci=0, so the subset rule (data SCI must be a subset of the principal's
 * compartments) was only covered on the creation/forgery side.
 *
 * Compartment conventions here: SI=0x1, TK=0x2 (so SI|TK = 0x3).
 *
 * Covered surfaces: qihse_auth_can_access directly, KV records
 * (qihse_kv_set_user/get_user carry per-record SCI), and the blob tier
 * (write-side possession and read-side enforcement, with no payload
 * disclosure on denial). Also: NULL user against nonzero-SCI data is denied.
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
#include "qihse_kv_store.h"

#define SCI_SI 0x1u
#define SCI_TK 0x2u
#define SCI_SI_TK (SCI_SI | SCI_TK)

#define PW_A "SciHolderSIpa1!"
#define PW_B "SciHolderSITKp1!"
#define PW_C "SciHolderNone1!"
#define OPERATOR_PASSWORD "OperatorSciPass1!"

int main(void) {
    char data_dir[] = "/tmp/qihse-sci-sec-XXXXXX";
    assert(mkdtemp(data_dir) != NULL);
    assert(setenv("QIHSE_DATA_DIR", data_dir, 1) == 0);
    assert(setenv("QIHSE_FIPS_MODE", "disabled", 1) == 0);

    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator(OPERATOR_PASSWORD));
    qihse_user_t* op = qihse_auth_get_user(0);
    assert(op != NULL);

    /* Tenant 7 principals with different compartment holdings (operator
     * creation sets explicit SCI — verified by accessors). */
    qihse_user_t* a_si = qihse_auth_create_tenant_user(op, 7, 71, QIHSE_ROLE_GUEST, 91, SCI_SI, PW_A, false);
    qihse_user_t* b_sitk = qihse_auth_create_tenant_user(op, 7, 72, QIHSE_ROLE_GUEST, 91, SCI_SI_TK, PW_B, false);
    qihse_user_t* c_none = qihse_auth_create_tenant_user(op, 7, 73, QIHSE_ROLE_GUEST, 91, 0, PW_C, false);
    assert(a_si && b_sitk && c_none);
    assert(qihse_user_get_sci(a_si) == SCI_SI);
    assert(qihse_user_get_sci(b_sitk) == SCI_SI_TK);
    assert(qihse_user_get_sci(c_none) == 0);

    /* ---- can_access: the subset rule directly --------------------------- */
    assert(qihse_auth_can_access(a_si, 0, SCI_SI));        /* holds SI, data SI */
    assert(qihse_auth_can_access(b_sitk, 0, SCI_SI));      /* SI ⊆ SI|TK */
    assert(!qihse_auth_can_access(c_none, 0, SCI_SI));     /* no compartments */
    assert(!qihse_auth_can_access(a_si, 0, SCI_SI_TK));    /* SI|TK ⊄ SI — denied */
    assert(qihse_auth_can_access(b_sitk, 0, SCI_SI_TK));   /* SI|TK ⊆ SI|TK */
    assert(qihse_auth_can_access(op, 0, 0xFFFF));          /* operator full */
    assert(!qihse_auth_can_access(NULL, 0, SCI_SI));       /* NULL never bypasses */

    /* ---- KV records: per-record SCI enforcement ------------------------- */
    qihse_kv_store_t* store = qihse_kv_store_create();
    assert(store != NULL);
    /* SI-only record inside tenant 7's namespace. */
    assert(qihse_kv_set_user(store, "t:7/asset/si", "si-payload", 0, SCI_SI, op));
    /* SI|TK record. */
    assert(qihse_kv_set_user(store, "t:7/asset/sitk", "sitk-payload", 0, SCI_SI_TK, op));

    char* v = qihse_kv_get_user(store, "t:7/asset/si", a_si);
    assert(v && strcmp(v, "si-payload") == 0);
    free(v);
    v = qihse_kv_get_user(store, "t:7/asset/si", b_sitk);
    assert(v && strcmp(v, "si-payload") == 0);
    free(v);
    v = qihse_kv_get_user(store, "t:7/asset/si", c_none);
    assert(v == NULL); /* no SI: denied, nothing disclosed */
    v = qihse_kv_get_user(store, "t:7/asset/sitk", a_si);
    assert(v == NULL); /* needs TK: denied */
    v = qihse_kv_get_user(store, "t:7/asset/sitk", b_sitk);
    assert(v && strcmp(v, "sitk-payload") == 0);
    free(v);
    v = qihse_kv_get_user(store, "t:7/asset/sitk", NULL);
    assert(v == NULL); /* NULL user + nonzero SCI: denied */

    /* ---- Blob tier: read-side enforcement -------------------------------- */
    char blob_dir[512];
    snprintf(blob_dir, sizeof(blob_dir), "%s/blobs", data_dir);
    qihse_blob_store_t* blobs = qihse_blob_store_create(blob_dir);
    assert(blobs != NULL);

    uint8_t hash_si[QIHSE_BLOB_HASH_BYTES], hash_sitk[QIHSE_BLOB_HASH_BYTES];
    const uint8_t si_body[] = "si-blob-body";
    const uint8_t sitk_body[] = "sitk-blob-body";
    assert(qihse_blob_put_buffer_user(blobs, 7, QIHSE_BLOB_TAG_SCRIPT_SET, 0, SCI_SI,
                                      op, si_body, sizeof(si_body) - 1u, hash_si));
    assert(qihse_blob_put_buffer_user(blobs, 7, QIHSE_BLOB_TAG_SCRIPT_SET, 0, SCI_SI_TK,
                                      op, sitk_body, sizeof(sitk_body) - 1u, hash_sitk));

    uint8_t out[256];
    size_t nread = 0;
    /* Holders read the SI blob; a compartment-less tenant does not. */
    assert(qihse_blob_get_user(blobs, hash_si, 0, out, sizeof(out), &nread, a_si));
    assert(nread == sizeof(si_body) - 1u && memcmp(out, si_body, nread) == 0);
    assert(qihse_blob_get_user(blobs, hash_si, 0, out, sizeof(out), &nread, b_sitk));
    memset(out, 0, sizeof(out));
    assert(!qihse_blob_get_user(blobs, hash_si, 0, out, sizeof(out), &nread, c_none));
    for (size_t i = 0; i < sizeof(out); i++) assert(out[i] == 0); /* no payload leak */
    assert(!qihse_blob_get_user(blobs, hash_si, 0, out, sizeof(out), &nread, NULL));
    /* The SI|TK blob needs TK: SI-only denied, holder allowed. */
    memset(out, 0, sizeof(out));
    assert(!qihse_blob_get_user(blobs, hash_sitk, 0, out, sizeof(out), &nread, a_si));
    for (size_t i = 0; i < sizeof(out); i++) assert(out[i] == 0);
    assert(qihse_blob_get_user(blobs, hash_sitk, 0, out, sizeof(out), &nread, b_sitk));
    assert(nread == sizeof(sitk_body) - 1u);
    assert(!qihse_blob_size_user(blobs, hash_sitk, &(uint64_t){0}, c_none));
    assert(!qihse_blob_delete_user(blobs, hash_sitk, a_si));

    /* ---- Blob tier: write-side possession -------------------------------- */
    /* A tenant may only tag a blob with compartments it actually holds.
     * Distinct content per case: identical bytes under a different binding
     * would (correctly) trip the hash-binding-clash dedup refusal instead. */
    const uint8_t body_si[] = "tenant-written-si";
    const uint8_t body_tk[] = "tenant-written-tk";
    const uint8_t body_sitk[] = "tenant-written-sitk";
    uint8_t hash_w[QIHSE_BLOB_HASH_BYTES];
    assert(qihse_blob_put_buffer_user(blobs, 7, QIHSE_BLOB_TAG_SCRIPT_SET, 0, SCI_SI,
                                      a_si, body_si, sizeof(body_si) - 1u, hash_w)); /* holds SI */
    assert(!qihse_blob_put_buffer_user(blobs, 7, QIHSE_BLOB_TAG_SCRIPT_SET, 0, SCI_TK,
                                       a_si, body_tk, sizeof(body_tk) - 1u, hash_w)); /* lacks TK */
    assert(qihse_blob_put_buffer_user(blobs, 7, QIHSE_BLOB_TAG_SCRIPT_SET, 0, SCI_SI_TK,
                                      b_sitk, body_sitk, sizeof(body_sitk) - 1u, hash_w)); /* holds both */
    assert(!qihse_blob_put_buffer_user(blobs, 7, QIHSE_BLOB_TAG_SCRIPT_SET, 0, SCI_SI,
                                       c_none, body_si, sizeof(body_si) - 1u, hash_w)); /* holds none */

    qihse_blob_store_destroy(blobs);
    qihse_kv_store_destroy(store);
    printf("test_sci_compartment_regression: all assertions passed\n");
    return 0;
}
