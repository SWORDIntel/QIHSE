/* Tenant-subset export regression test (U7).
 *
 * A tenant can export ITS OWN data (namespace-scoped KV records + blob
 * manifest) as a portable artifact; records above the caller's clearance are
 * excluded; foreign-tenant export is denied; NULL user is denied (invariant
 * #1); the system domain may export on behalf of any tenant.
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
#include "qihse_export.h"
#include "qihse_kv_store.h"

#define TENANT7_PW "ExportTenant7Pa1!"
#define TENANT8_PW "ExportTenant8Pa1!"
#define OPERATOR_PASSWORD "OperatorExportP1!"

int main(void) {
    char data_dir[] = "/tmp/qihse-export-XXXXXX";
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

    qihse_kv_store_t* store = qihse_kv_store_create();
    assert(store != NULL);
    char blob_dir[512];
    snprintf(blob_dir, sizeof(blob_dir), "%s/blobs", data_dir);
    qihse_blob_store_t* blobs = qihse_blob_store_create(blob_dir);
    assert(blobs != NULL);

    /* Tenant 7 data: one readable, one above clearance; tenant 8 + commons. */
    assert(qihse_kv_set_user(store, "t:7/script/main", "print hello", 0, 0, operator_user));
    assert(qihse_kv_set_user(store, "t:7/secret/core", "classified-payload", 95, 0, operator_user));
    assert(qihse_kv_set_user(store, "t:8/script/main", "tenant8 data", 0, 0, operator_user));
    assert(qihse_kv_set_user(store, "commons/notice", "shared banner", 0, 0, operator_user));
    uint8_t blob_hash[QIHSE_BLOB_HASH_BYTES];
    assert(qihse_blob_put_buffer_user(blobs, 7, QIHSE_BLOB_TAG_PATTERN_BUNDLE, 0, 0,
                                      operator_user, (const uint8_t*)"PATTERNBYTES", 12, blob_hash));

    /* Tenant 7 exports its own tenant. */
    char out7[600];
    snprintf(out7, sizeof(out7), "%s/tenant-7.export", data_dir);
    char err[192] = {0};
    assert(qihse_export_tenant_user(store, blobs, 7, tenant7, out7, err, sizeof(err)));
    FILE* f = fopen(out7, "rb");
    assert(f != NULL);
    char body[16384];
    size_t n = fread(body, 1, sizeof(body) - 1u, f);
    body[n] = '\0';
    fclose(f);
    assert(strstr(body, "QIHSE-TENANT-EXPORT 1") == body);
    assert(strstr(body, "tenant:7") != NULL);
    assert(strstr(body, "t:7/script/main") != NULL);
    assert(strstr(body, "print hello") != NULL);
    assert(strstr(body, "commons/notice") != NULL);
    assert(strstr(body, "B ") != NULL);            /* blob manifest present */
    assert(strstr(body, "classified-payload") == NULL); /* above clearance */
    assert(strstr(body, "tenant8 data") == NULL);  /* foreign tenant */

    /* Foreign-tenant export denied, no artifact written. */
    char out_cross[600];
    snprintf(out_cross, sizeof(out_cross), "%s/cross.export", data_dir);
    assert(!qihse_export_tenant_user(store, blobs, 7, tenant8, out_cross, err, sizeof(err)));
    assert(strstr(err, "foreign tenant") != NULL);
    assert(access(out_cross, F_OK) != 0);

    /* NULL user denied (invariant #1). */
    assert(!qihse_export_tenant_user(store, blobs, 7, NULL, out_cross, err, sizeof(err)));

    /* System domain may export on behalf of a tenant. */
    char out_op[600];
    snprintf(out_op, sizeof(out_op), "%s/operator-8.export", data_dir);
    assert(qihse_export_tenant_user(store, blobs, 8, operator_user, out_op, err, sizeof(err)));
    f = fopen(out_op, "rb");
    assert(f != NULL);
    n = fread(body, 1, sizeof(body) - 1u, f);
    body[n] = '\0';
    fclose(f);
    assert(strstr(body, "tenant:8") != NULL);
    assert(strstr(body, "tenant8 data") != NULL);
    assert(strstr(body, "t:7/script/main") == NULL);

    qihse_blob_store_destroy(blobs);
    qihse_kv_store_destroy(store);
    printf("test_export_regression: all assertions passed\n");
    return 0;
}
