/* Object-storage durability and correctness regression (U1).
 *
 * Closes the persistence-side gaps the authorization suite does not cover:
 *   - SHA-384 known-answer correctness (the switch from SHA-256 is pinned to
 *     the NIST vector for "abc"),
 *   - index.log replay: blobs, refcounts, and dedup survive a full
 *     destroy/reopen cycle,
 *   - torn-tail recovery: a partially appended record is ignored and the
 *     store keeps working,
 *   - range-read edges (offset == size, offset > size, last byte),
 *   - empty payloads and unknown hashes.
 */
#define _GNU_SOURCE

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "qihse_auth.h"
#include "qihse_blob.h"

#define OPERATOR_PASSWORD "OperatorPersist1!"

static qihse_blob_store_t* open_store(const char* data_dir, char* dir, size_t dir_cap) {
    snprintf(dir, dir_cap, "%s/blobs", data_dir);
    return qihse_blob_store_create(dir);
}

int main(void) {
    char data_dir[] = "/tmp/qihse-blob-persist-XXXXXX";
    assert(mkdtemp(data_dir) != NULL);
    assert(setenv("QIHSE_DATA_DIR", data_dir, 1) == 0);
    assert(setenv("QIHSE_FIPS_MODE", "disabled", 1) == 0);

    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator(OPERATOR_PASSWORD));
    qihse_user_t* op = qihse_auth_get_user(0);
    assert(op != NULL);

    char blob_dir[512];
    qihse_blob_store_t* blobs = open_store(data_dir, blob_dir, sizeof(blob_dir));
    assert(blobs != NULL);

    /* ---- SHA-384 known-answer: NIST vector for "abc" --------------------- */
    uint8_t hash_abc[QIHSE_BLOB_HASH_BYTES];
    assert(qihse_blob_put_buffer_user(blobs, 0, QIHSE_BLOB_TAG_COMMONS_SNAPSHOT, 0, 0,
                                      op, (const uint8_t*)"abc", 3, hash_abc));
    char hex[QIHSE_BLOB_HASH_HEX];
    qihse_blob_hash_to_hex(hash_abc, hex);
    const char* expected =
        "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded163"
        "1a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7";
    assert(strcmp(hex, expected) == 0); /* pins the CNSA 2.0 SHA-384 switch */

    /* ---- Seed state that must survive reopen ----------------------------- */
    uint8_t keep[5000], shared[2000];
    memset(keep, 0x42, sizeof(keep));
    memset(shared, 0x77, sizeof(shared));
    uint8_t hash_keep[QIHSE_BLOB_HASH_BYTES], hash_shared[QIHSE_BLOB_HASH_BYTES];
    assert(qihse_blob_put_buffer_user(blobs, 7, QIHSE_BLOB_TAG_SCRIPT_SET, 0, 0,
                                      op, keep, sizeof(keep), hash_keep));
    assert(qihse_blob_put_buffer_user(blobs, 7, QIHSE_BLOB_TAG_SCRIPT_SET, 0, 0,
                                      op, shared, sizeof(shared), hash_shared));
    assert(qihse_blob_ref_user(blobs, hash_shared, op)); /* refcount 2 */
    uint64_t keep_size = 0;
    assert(qihse_blob_size_user(blobs, hash_keep, &keep_size, op));
    assert(keep_size == sizeof(keep));

    qihse_blob_store_destroy(blobs);

    /* ---- Reopen: full replay --------------------------------------------- */
    blobs = open_store(data_dir, blob_dir, sizeof(blob_dir));
    assert(blobs != NULL);
    uint8_t out[8192];
    size_t nread = 0;
    assert(qihse_blob_get_user(blobs, hash_keep, 0, out, sizeof(out), &nread, op));
    assert(nread == sizeof(keep) && memcmp(out, keep, sizeof(keep)) == 0);
    assert(qihse_blob_get_user(blobs, hash_shared, 0, out, sizeof(out), &nread, op));
    /* Dedup still dedups after replay: identical bytes bump the refcount. */
    uint8_t hash_dup[QIHSE_BLOB_HASH_BYTES];
    assert(qihse_blob_put_buffer_user(blobs, 7, QIHSE_BLOB_TAG_SCRIPT_SET, 0, 0,
                                      op, shared, sizeof(shared), hash_dup));
    assert(memcmp(hash_dup, hash_shared, QIHSE_BLOB_HASH_BYTES) == 0);
    /* Refcount survived replay: 2 at close, +1 from the dedup put above = 3.
     * The object disappears only after the third delete. */
    assert(qihse_blob_delete_user(blobs, hash_shared, op));
    assert(qihse_blob_get_user(blobs, hash_shared, 0, out, sizeof(out), &nread, op));
    assert(qihse_blob_delete_user(blobs, hash_shared, op));
    assert(qihse_blob_get_user(blobs, hash_shared, 0, out, sizeof(out), &nread, op));
    assert(qihse_blob_delete_user(blobs, hash_shared, op));
    assert(!qihse_blob_get_user(blobs, hash_shared, 0, out, sizeof(out), &nread, op));

    /* ---- Torn tail: a half-written record is ignored --------------------- */
    qihse_blob_store_destroy(blobs);
    {
        char log_path[600];
        snprintf(log_path, sizeof(log_path), "%s/index.log", blob_dir);
        FILE* f = fopen(log_path, "ab");
        assert(f != NULL);
        /* Simulate a crash mid-append: header + a fraction of a record. */
        const unsigned char torn[] = { 'Q', 2, 'P', 0x11, 0x22, 0x33, 0x44 };
        fwrite(torn, 1, sizeof(torn), f);
        fclose(f);
    }
    blobs = open_store(data_dir, blob_dir, sizeof(blob_dir));
    assert(blobs != NULL);
    /* Everything appended before the torn record still resolves... */
    assert(qihse_blob_get_user(blobs, hash_keep, 0, out, sizeof(out), &nread, op));
    assert(nread == sizeof(keep));
    /* ...and the store keeps accepting new blobs across the torn tail. */
    uint8_t hash_post[QIHSE_BLOB_HASH_BYTES];
    assert(qihse_blob_put_buffer_user(blobs, 7, QIHSE_BLOB_TAG_SCRIPT_SET, 0, 0,
                                      op, "post-torn", 9, hash_post));
    assert(qihse_blob_get_user(blobs, hash_post, 0, out, sizeof(out), &nread, op));
    assert(nread == 9 && memcmp(out, "post-torn", 9) == 0);

    /* ---- Range-read edges ------------------------------------------------ */
    /* offset == size: defined as a clean empty read. */
    assert(qihse_blob_get_user(blobs, hash_post, 9, out, sizeof(out), &nread, op));
    assert(nread == 0);
    /* offset > size: same. */
    assert(qihse_blob_get_user(blobs, hash_post, 100, out, sizeof(out), &nread, op));
    assert(nread == 0);
    /* Last byte exactly. */
    assert(qihse_blob_get_user(blobs, hash_post, 8, out, sizeof(out), &nread, op));
    assert(nread == 1 && out[0] == 'n');

    /* ---- Empty payload and unknown hash ---------------------------------- */
    uint8_t hash_empty[QIHSE_BLOB_HASH_BYTES];
    assert(qihse_blob_put_buffer_user(blobs, 7, QIHSE_BLOB_TAG_SCRIPT_SET, 0, 0,
                                      op, NULL, 0, hash_empty));
    assert(qihse_blob_get_user(blobs, hash_empty, 0, out, sizeof(out), &nread, op));
    assert(nread == 0);
    uint8_t ghost[QIHSE_BLOB_HASH_BYTES] = {0};
    assert(!qihse_blob_get_user(blobs, ghost, 0, out, sizeof(out), &nread, op));
    assert(!qihse_blob_size_user(blobs, ghost, &(uint64_t){0}, op));

    qihse_blob_store_destroy(blobs);
    printf("test_blob_persistence_regression: all assertions passed\n");
    return 0;
}
