/*
 * Fabric index authorization regression (AGENTS.md invariant 3).
 *
 * The KEYSTONE fabric index is an externally reachable data-access surface:
 * it indexes artifacts that may carry classification and answers content
 * queries over them. This regression asserts:
 *   1. NULL/unauthenticated contexts are denied (never a bypass).
 *   2. A low-clearance principal querying artifacts classified above its
 *      clearance and outside its SCI compartments gets denial with zero
 *      records and no key disclosure (trigram lookup and class listing).
 *   3. The soft dependency holds: without libkeystone.so nothing is indexed
 *      and every surface fails closed (EUNAVAILABLE, empty results).
 *   4. Candidate-only indexing: the persisted index never contains artifact
 *      content (KEYSTONE must not create a second classified-data copy).
 *
 * When KEYSTONE is not installed (CI), tests 1-3 still run; the positive
 * half of test 4 prints SKIP and exits 0.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "qihse_auth.h"
#include "qihse_fabric_index.h"

static int g_failures = 0;

#define CHECK(cond, msg)                                                   \
    do {                                                                   \
        if (!(cond)) {                                                     \
            printf("[FAIL] %s (line %d)\n", msg, __LINE__);                \
            g_failures++;                                                  \
        } else {                                                           \
            printf("[PASS] %s\n", msg);                                    \
        }                                                                  \
    } while (0)

static const char* SECRET_SNIPPET = "quarterly-revenue-swift";

static void rmtree(const char* path) {
    char cmd[768];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", path);
    if (system(cmd) != 0) {
        /* best effort cleanup */
    }
}

/* Loads the whole file and searches for needle in the raw bytes. */
static int file_contains(const char* path, const char* needle) {
    FILE* fp = fopen(path, "rb");
    if (!fp) return 0;
    if (fseek(fp, 0, SEEK_END) != 0) { fclose(fp); return 0; }
    long size = ftell(fp);
    if (size < 0) { fclose(fp); return 0; }
    rewind(fp);
    char* buf = (char*)malloc((size_t)size + 1u);
    if (!buf) { fclose(fp); return 0; }
    size_t got = fread(buf, 1, (size_t)size, fp);
    fclose(fp);
    int found = got > 0u && memmem(buf, got, needle, strlen(needle)) != NULL;
    free(buf);
    return found;
}

int main(void) {
    const char* tmp_base = getenv("TMPDIR");
    if (!tmp_base || !*tmp_base) tmp_base = "/tmp";

    char dir_unavail[512];
    char dir_live[512];
    snprintf(dir_unavail, sizeof(dir_unavail), "%s/qihse_fabric_test_unavail", tmp_base);
    snprintf(dir_live, sizeof(dir_live), "%s/qihse_fabric_test_live", tmp_base);
    rmtree(dir_unavail);
    rmtree(dir_live);

    /* Auth state first: the fabric index authorization-gates every surface. */
    CHECK(qihse_auth_init(), "auth init");
    qihse_user_t* operator_user = qihse_auth_get_user(0);
    CHECK(operator_user != NULL, "bootstrap operator present");
    CHECK(qihse_auth_bootstrap_operator("SecureOpPass1!"), "operator bootstrap");

    /* Low-clearance principal: classification 1, no SCI compartments. */
    qihse_user_t* guest = qihse_auth_create_user(operator_user, 4211u,
                                                 QIHSE_ROLE_GUEST, 1u, 0x0u,
                                                 "GuestAccount123!", false);
    CHECK(guest != NULL, "low-clearance guest created");

    /* --- 1. Unauthenticated denial (stateless; runs with or without KEYSTONE) */
    qihse_fabric_index_record_t recs[8];
    size_t count = 12345u;
    CHECK(qihse_fabric_index_lookup_user("fabric", NULL, recs, 8u, &count) ==
              QIHSE_FABRIC_INDEX_EDENIED && count == 0u,
          "NULL user content lookup denied with no disclosure");
    count = 12345u;
    CHECK(qihse_fabric_index_by_class_user(QIHSE_FABRIC_CLASS_GOVERNMENT, NULL,
                                           recs, 8u, &count) ==
              QIHSE_FABRIC_INDEX_EDENIED && count == 0u,
          "NULL user class listing denied with no disclosure");

    /* --- 2. Soft dependency: explicit missing library fails closed */
    CHECK(qihse_fabric_index_init(dir_unavail, "/nonexistent/libkeystone.so") ==
              QIHSE_FABRIC_INDEX_EUNAVAILABLE,
          "explicit missing KEYSTONE library leaves index unavailable");
    CHECK(!qihse_fabric_index_is_available(),
          "is_available false without KEYSTONE");
    CHECK(qihse_fabric_index_artifact_user(
              "fabric:softdep", "hello world", 11u, 0u, 0u, operator_user) ==
              QIHSE_FABRIC_INDEX_EUNAVAILABLE,
          "artifact indexing without KEYSTONE fails closed");
    CHECK(qihse_fabric_index_record_count() == 0u,
          "no records indexed without KEYSTONE");
    count = 7u;
    CHECK(qihse_fabric_index_lookup_user("hello", operator_user, recs, 8u,
                                         &count) ==
              QIHSE_FABRIC_INDEX_EUNAVAILABLE && count == 0u,
          "lookup without KEYSTONE fails closed with no records");
    CHECK(qihse_fabric_index_keystone_version() == NULL,
          "keystone_version NULL without KEYSTONE");
    uint8_t cap_buf[50];
    CHECK(qihse_fabric_index_export_node_cap("node1", cap_buf, sizeof(cap_buf)) ==
              QIHSE_FABRIC_INDEX_EUNAVAILABLE,
          "export_node_cap without KEYSTONE fails closed");
    qihse_fabric_index_shutdown();

    /* --- 3. Authenticated scenarios against live KEYSTONE (if present) */
    int live = qihse_fabric_index_init(dir_live, NULL) == QIHSE_FABRIC_INDEX_OK;
    if (!live) {
        printf("[SKIP] KEYSTONE library not present; positive-path assertions skipped\n");
    } else {
        CHECK(qihse_fabric_index_init(dir_live, NULL) == QIHSE_FABRIC_INDEX_OK,
              "fabric index init is idempotent");
        CHECK(qihse_fabric_index_keystone_version() != NULL,
              "keystone version exposed when available");
        CHECK(qihse_fabric_index_export_node_cap("node1", cap_buf, sizeof(cap_buf)) == 50,
              "export_node_cap with live KEYSTONE returns 50 bytes");
        CHECK(qihse_fabric_index_export_node_cap("node1", cap_buf, 40) == QIHSE_FABRIC_INDEX_EINVAL,
              "export_node_cap rejects undersized buffer with EINVAL");

        char value[512];
        snprintf(value, sizeof(value),
                 "CONFIDENTIAL treasury %s settlement ledger reconciliation",
                 SECRET_SNIPPET);

        /* Data above guest clearance (classif 2 > 1, SCI 0x1 not in 0x0),
         * indexed by the operator. */
        CHECK(qihse_fabric_index_artifact_user(
                  "fabric:clearing/ledger-2026", value, strlen(value), 2u,
                  0x1u, operator_user) == QIHSE_FABRIC_INDEX_OK,
              "operator indexes classified fabric artifact");
        CHECK(qihse_fabric_index_record_count() == 1u, "one record indexed");

        /* Low-clearance content lookup: denial with zero disclosure. */
        count = 999u;
        int rc = qihse_fabric_index_lookup_user("revenue", guest, recs, 8u, &count);
        CHECK(rc == QIHSE_FABRIC_INDEX_OK && count == 0u,
              "guest content lookup returns zero records");
        count = 999u;
        rc = qihse_fabric_index_by_class_user(QIHSE_FABRIC_CLASS_FINANCIAL,
                                              guest, recs, 8u, &count);
        CHECK(rc == QIHSE_FABRIC_INDEX_OK && count == 0u,
              "guest class listing returns zero records");

        /* NULL user stays denied even with data present. */
        count = 999u;
        CHECK(qihse_fabric_index_lookup_user("revenue", NULL, recs, 8u, &count) ==
                  QIHSE_FABRIC_INDEX_EDENIED && count == 0u,
              "NULL user still denied with data present");

        /* Authorized principal gets the candidate back. */
        count = 0u;
        rc = qihse_fabric_index_lookup_user("revenue", operator_user, recs, 8u,
                                            &count);
        CHECK(rc == QIHSE_FABRIC_INDEX_OK && count == 1u &&
                  strcmp(recs[0].key, "fabric:clearing/ledger-2026") == 0,
              "authorized lookup returns indexed fabric key");
        int indexed_class = (int)recs[0].semantic_class;
        CHECK(indexed_class >= 0 && indexed_class <= 5,
              "micro-model returned a defined semantic class");

        count = 0u;
        rc = qihse_fabric_index_by_class_user((qihse_fabric_index_class_t)indexed_class,
                                              operator_user, recs, 8u, &count);
        CHECK(rc == QIHSE_FABRIC_INDEX_OK && count >= 1u,
              "authorized class listing returns the record");

        /* Candidate-only indexing: artifact content must NOT be persisted in
         * the KEYSTONE segment or the manifest (no second classified copy). */
        char seg_path[640];
        snprintf(seg_path, sizeof(seg_path), "%s/seg_%016llu.kt3", dir_live,
                 (unsigned long long)recs[0].seq);
        CHECK(!file_contains(seg_path, SECRET_SNIPPET),
              "segment file contains no artifact content");
        CHECK(!file_contains(seg_path, "treasury"),
              "segment file contains no artifact vocabulary");
        char manifest_path[640];
        snprintf(manifest_path, sizeof(manifest_path), "%s/manifest.tsv",
                 dir_live);
        CHECK(!file_contains(manifest_path, SECRET_SNIPPET),
              "manifest contains no artifact content");
    }

    qihse_fabric_index_shutdown();
    qihse_fabric_index_shutdown(); /* idempotent teardown */

    rmtree(dir_unavail);
    rmtree(dir_live);

    if (g_failures) {
        printf("fabric index regression: %d failure(s)\n", g_failures);
        return 1;
    }
    printf("fabric index regression: all checks passed\n");
    return 0;
}
