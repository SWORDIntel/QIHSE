/* Diagnostic, not an artifact-ingest regression test: proves that the current
 * public blob ref API cannot serve as a protected manifest lineage pin. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "qihse_audit.h"
#include "qihse_auth.h"
#include "qihse_blob.h"

static void remove_fixture_file(const char* dir, const char* name) {
    char path[512];
    int n = snprintf(path, sizeof(path), "%s/%s", dir, name);
    assert(n > 0 && (size_t)n < sizeof(path));
    assert(unlink(path) == 0 || errno == ENOENT);
}

int main(void) {
    assert(mkdir("./build", 0700) == 0 || errno == EEXIST);
    char dir[] = "./build/test_analysis_artifact_gap_XXXXXX";
    assert(mkdtemp(dir));
    assert(setenv("QIHSE_DATA_DIR", dir, 1) == 0);
    assert(setenv("QIHSE_FIPS_MODE", "disabled", 1) == 0);
    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator("OperatorGapPass1!"));
    qihse_user_t* op = qihse_auth_get_user(0);
    assert(op);
    qihse_user_t* tenant = qihse_auth_create_tenant_user(
        op, 77, 778, QIHSE_ROLE_ANALYST, 2, 1, "TenantGapPass1!", false);
    assert(tenant);

    char blobdir[512];
    int n = snprintf(blobdir, sizeof(blobdir), "%s/blobs", dir);
    assert(n > 0 && (size_t)n < sizeof(blobdir));
    qihse_blob_store_t* store = qihse_blob_store_create(blobdir);
    assert(store);
    uint8_t hash[QIHSE_BLOB_HASH_BYTES];
    const uint8_t payload[] = {0x48, 0x8b, 0x04, 0x24};
    assert(qihse_blob_put_buffer_user(store, 77, QIHSE_BLOB_TAG_SCRIPT_SET,
                                      2, 1, tenant, payload, sizeof(payload), hash));
    assert(qihse_blob_ref_user(store, hash, tenant));
    qihse_blob_info_t info;
    assert(qihse_blob_info_user(store, hash, &info, tenant));
    assert(info.refcount == 2);

    /* The same tenant principal can consume both the ordinary ownership
     * reference and the supposed manifest pin via the public delete API. */
    assert(qihse_blob_delete_user(store, hash, tenant));
    assert(qihse_blob_info_user(store, hash, &info, tenant));
    assert(info.refcount == 1);
    assert(qihse_blob_delete_user(store, hash, tenant));
    assert(!qihse_blob_info_user(store, hash, &info, tenant));
    size_t out_read = 0;
    uint8_t out[sizeof(payload)] = {0};
    assert(!qihse_blob_get_user(store, hash, 0, out, sizeof(out), &out_read, tenant));
    qihse_blob_store_destroy(store);

    char hex[QIHSE_BLOB_HASH_HEX];
    qihse_blob_hash_to_hex(hash, hex);
    char path[512];
    n = snprintf(path, sizeof(path), "%s/objects/%.2s", blobdir, hex);
    assert(n > 0 && (size_t)n < sizeof(path));
    assert(rmdir(path) == 0);
    remove_fixture_file(blobdir, "index.log");
    n = snprintf(path, sizeof(path), "%s/objects", blobdir);
    assert(n > 0 && (size_t)n < sizeof(path));
    assert(rmdir(path) == 0);
    assert(rmdir(blobdir) == 0);
    qihse_audit_shutdown();
    remove_fixture_file(dir, "qihse_audit.log");
    remove_fixture_file(dir, "qihse_integrity.chain");
    remove_fixture_file(dir, "qihse_audit.writer.lock");
    assert(rmdir(dir) == 0);
    puts("diagnostic: public blob deletion can consume a hypothetical manifest pin");
    return 0;
}
