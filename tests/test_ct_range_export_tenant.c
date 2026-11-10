#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "qihse_auth.h"
#include "qihse_kv_store.h"
#include "aimem_fixture_cleanup.h"
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>

int main(void) {
    assert(mkdir("build", 0700) == 0 || errno == EEXIST);
    char directory[] = "build/ct-export-tenant-XXXXXX";
    assert(mkdtemp(directory));
    assert(setenv("QIHSE_DATA_DIR", directory, 1) == 0);
    assert(setenv("QIHSE_AUTH_STATE_DIR", directory, 1) == 0);
    assert(setenv("QIHSE_AUDIT_DIR", directory, 1) == 0);
    assert(qihse_auth_init());
    qihse_user_t* op = qihse_auth_get_user(0);
    qihse_user_t* tenant = qihse_auth_create_tenant_user(op, 7, 63992,
        QIHSE_ROLE_ANALYST, 0, 0, "TenantRangeExport1!", false);
    qihse_user_t* peer = qihse_auth_create_user(op, 63993,
        QIHSE_ROLE_ANALYST, 0, 0, "RangeReplication1!", false);
    assert(op && tenant && peer);
    qihse_kv_store_t* store = qihse_kv_store_create_user(op);
    assert(store);
    assert(qihse_kv_set_user(store, "t:8/protected", "other-tenant", 0, 0, op));
    assert(qihse_kv_ct_source_enable(store, op, "source:tenant", "peer:tenant",
        "generation:tenant", NULL, 128u << 20));
    qihse_kv_store_set_replication_principal_id(store, 63993);
    unsigned char token[QIHSE_KV_CT_TOKEN_BYTES], digest[32];
    assert(qihse_kv_ct_owner_token_get(store, op, token));
    qihse_kv_replica_snapshot_t* baseline = NULL;
    uint64_t sequence = 0;
    assert(qihse_kv_ct_source_baseline_snapshot_create(store, op, &baseline,
        &sequence, digest) == 0);
    assert(qihse_kv_ct_source_reconcile_peer(store, op, peer, "peer:tenant",
        "generation:tenant", digest, 0));
    qihse_kv_replica_snapshot_destroy(baseline);
    uint64_t cut = 0;
    assert(qihse_kv_ct_fence_range(store, op, "transfer:tenant", 0, 16383,
        token, &cut));
    qihse_kv_ct_range_snapshot_t* image = NULL;
    uint64_t exported_cut = 999;
    /* Both principals can read class/SCI zero. Tenant identity is the only
     * denial condition; no protected bytes or image handle may be returned. */
    assert(qihse_kv_ct_range_export(store, op, tenant, "transfer:tenant",
        "target:tenant", "generation:tenant", 0, 16383, token, &image,
        &exported_cut, digest) == -2);
    assert(!image && exported_cut == 0);
    assert(qihse_kv_ct_range_export(store, op, op, "transfer:tenant",
        "target:tenant", "generation:tenant", 0, 16383, token, &image,
        &exported_cut, digest) == 0 && image);
    qihse_kv_ct_range_snapshot_destroy(image);
    qihse_kv_store_destroy(store);
    aimem_fixture_cleanup(directory);
    puts("PASS CT range export: foreign tenant denied independently of class and SCI");
    return 0;
}
