#define _GNU_SOURCE
#include <assert.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "qihse_auth.h"
#include "qihse_fts.h"
#include "core/qihse_auth_internal.h"

#define QFTS_MAGIC 0x53544651u
#define QFTS_VERSION 1u

static void cleanup(void) {
    unlink("/tmp/test_fts_classified.qfts");
    unlink("/tmp/test_fts_classified_guest.qfts");
    unlink("/tmp/test_fts_unclassified.qfts");
    unlink("/tmp/test_fts_roundtrip.qfts");
    unlink("/tmp/test_fts_mixed.qfts");
    unlink("/tmp/test_fts_mixed_null.qfts");
    unlink("/tmp/test_fts_bad_counts.qfts");
    unlink("/tmp/test_fts_bad_docidx.qfts");
}

static void write_bad_counts_fixture(void) {
    FILE* f = fopen("/tmp/test_fts_bad_counts.qfts", "wb");
    assert(f != NULL);
    uint32_t magic = QFTS_MAGIC, version = QFTS_VERSION;
    uint32_t doc_count = UINT32_MAX, doc_capacity = UINT32_MAX;
    uint64_t total = 0;
    assert(fwrite(&magic, sizeof(magic), 1, f) == 1);
    assert(fwrite(&version, sizeof(version), 1, f) == 1);
    assert(fwrite(&doc_count, sizeof(doc_count), 1, f) == 1);
    assert(fwrite(&total, sizeof(total), 1, f) == 1);
    assert(fwrite(&doc_capacity, sizeof(doc_capacity), 1, f) == 1);
    fclose(f);
}

static void test_ranking_isolation(qihse_user_t* guest, qihse_user_t* operator_user) {
    qihse_fts_index_t* public_only = qihse_fts_create();
    qihse_fts_index_t* mixed = qihse_fts_create();
    assert(public_only && mixed);

    const char* pub = "alpha bravo public";
    const char* secret = "alpha alpha classified material";
    assert(qihse_fts_add_document(public_only, 100, pub, strlen(pub),
                                  0, 0, QIHSE_KEYSTONE_CLASS_UNKNOWN));
    assert(qihse_fts_add_document(mixed, 100, pub, strlen(pub),
                                  0, 0, QIHSE_KEYSTONE_CLASS_UNKNOWN));
    assert(qihse_fts_add_document_user(mixed, 101, secret, strlen(secret),
                                       5, 0, QIHSE_KEYSTONE_CLASS_GOVERNMENT,
                                       operator_user));

    qihse_fts_result_t a[4], b[4];
    int na = qihse_fts_search_user(public_only, "alpha", guest, a, 4);
    int nb = qihse_fts_search_user(mixed, "alpha", guest, b, 4);
    assert(na == 1 && nb == 1);
    assert(a[0].doc_id == b[0].doc_id);
    assert(fabsf(a[0].bm25_score - b[0].bm25_score) < 0.000001f);

    /* Hidden semantic metadata is not an independent disclosure surface. */
    assert(qihse_fts_get_doc_semantic_class_user(mixed, 101, guest) ==
           QIHSE_KEYSTONE_CLASS_UNKNOWN);
    assert(qihse_fts_get_doc_semantic_class_user(mixed, 101, operator_user) ==
           QIHSE_KEYSTONE_CLASS_GOVERNMENT);
    assert(qihse_fts_get_doc_semantic_class(mixed, 101) ==
           QIHSE_KEYSTONE_CLASS_UNKNOWN);

    qihse_fts_destroy(public_only);
    qihse_fts_destroy(mixed);
    printf("[PASS] Hidden documents do not influence guest BM25 scores or metadata\n");
}

int main(void) {
    cleanup();
    setenv("QIHSE_FIPS_MODE", "disabled", 1);
    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator("SecureOpPass1!"));
    qihse_user_t* operator_user = qihse_auth_get_user(0);
    assert(operator_user != NULL);

    qihse_user_t* guest = qihse_auth_create_user(
        operator_user, 10, QIHSE_ROLE_GUEST, 0, 0,
        "GuestPass123!", false);
    assert(guest != NULL);
    qihse_user_t* analyst = qihse_auth_create_user(
        operator_user, 11, QIHSE_ROLE_ANALYST, 5, 0,
        "AnalystPass123!", false);
    assert(analyst != NULL);

    /* Context-free classified indexing is now fail-closed. */
    qihse_fts_index_t* deny_idx = qihse_fts_create();
    assert(deny_idx);
    assert(!qihse_fts_add_document(deny_idx, 99, "secret", 6,
                                   5, 0, QIHSE_KEYSTONE_CLASS_GOVERNMENT));
    assert(!qihse_fts_add_document_user(deny_idx, 99, "secret", 6,
                                        5, 0, QIHSE_KEYSTONE_CLASS_GOVERNMENT,
                                        guest));
    assert(qihse_fts_add_document_user(deny_idx, 99, "secret", 6,
                                       5, 0, QIHSE_KEYSTONE_CLASS_GOVERNMENT,
                                       operator_user));
    qihse_fts_destroy(deny_idx);
    printf("[PASS] Classified insertion requires an authorized principal\n");

    qihse_fts_index_t* idx_classified = qihse_fts_create();
    assert(idx_classified != NULL);
    const char* t1 = "secret kernel exploit driver analysis";
    const char* t2 = "classified vulnerability refcount race";
    assert(qihse_fts_add_document_user(idx_classified, 1, t1, strlen(t1),
                                       5, 0, QIHSE_KEYSTONE_CLASS_GOVERNMENT,
                                       operator_user));
    assert(qihse_fts_add_document_user(idx_classified, 2, t2, strlen(t2),
                                       5, 0, QIHSE_KEYSTONE_CLASS_GOVERNMENT,
                                       operator_user));

    assert(qihse_fts_save(idx_classified, "/tmp/test_fts_classified.qfts", operator_user));
    assert(!qihse_fts_save(idx_classified, "/tmp/test_fts_classified_guest.qfts", guest));
    assert(access("/tmp/test_fts_classified_guest.qfts", F_OK) != 0);

    qihse_fts_index_t* loaded_op = qihse_fts_load("/tmp/test_fts_classified.qfts", operator_user);
    assert(loaded_op != NULL);
    qihse_fts_result_t results[10];
    assert(qihse_fts_search_user(loaded_op, "exploit", operator_user, results, 10) > 0);
    qihse_fts_destroy(loaded_op);
    assert(qihse_fts_load("/tmp/test_fts_classified.qfts", guest) == NULL);
    qihse_fts_index_t* loaded_analyst = qihse_fts_load("/tmp/test_fts_classified.qfts", analyst);
    assert(loaded_analyst != NULL);
    qihse_fts_destroy(loaded_analyst);
    qihse_fts_destroy(idx_classified);
    printf("[PASS] FTS save/load is all-or-nothing RBAC protected\n");

    qihse_fts_index_t* idx_unclassified = qihse_fts_create();
    assert(idx_unclassified != NULL);
    const char* t10 = "public driver analysis documentation";
    const char* t11 = "open source kernel module reference";
    assert(qihse_fts_add_document(idx_unclassified, 10, t10, strlen(t10),
                                  0, 0, QIHSE_KEYSTONE_CLASS_UNKNOWN));
    assert(qihse_fts_add_document(idx_unclassified, 11, t11, strlen(t11),
                                  0, 0, QIHSE_KEYSTONE_CLASS_UNKNOWN));
    assert(qihse_fts_save(idx_unclassified, "/tmp/test_fts_unclassified.qfts", NULL));
    qihse_fts_index_t* loaded_null = qihse_fts_load("/tmp/test_fts_unclassified.qfts", NULL);
    assert(loaded_null != NULL);
    qihse_fts_destroy(loaded_null);
    qihse_fts_destroy(idx_unclassified);
    printf("[PASS] Unclassified legacy FTS path remains compatible\n");

    qihse_fts_index_t* idx_rt = qihse_fts_create();
    assert(idx_rt);
    for (int i = 0; i < 50; i++) {
        char text[128];
        snprintf(text, sizeof(text),
                 "function_%d ExAllocatePoolWithTag kernel driver test %d", i, i);
        assert(qihse_fts_add_document(idx_rt, 100 + (uint64_t)i, text, strlen(text),
                                      0, 0, QIHSE_KEYSTONE_CLASS_UNKNOWN));
    }
    qihse_fts_result_t before[5], after[5];
    int n_before = qihse_fts_search_user(idx_rt, "ExAllocatePool", NULL, before, 5);
    assert(n_before > 0);
    assert(qihse_fts_save(idx_rt, "/tmp/test_fts_roundtrip.qfts", NULL));
    qihse_fts_index_t* idx_loaded = qihse_fts_load("/tmp/test_fts_roundtrip.qfts", NULL);
    assert(idx_loaded != NULL);
    int n_after = qihse_fts_search_user(idx_loaded, "ExAllocatePool", NULL, after, 5);
    assert(n_after == n_before);
    for (int i = 0; i < n_before; i++) {
        assert(before[i].doc_id == after[i].doc_id);
        assert(before[i].bm25_score == after[i].bm25_score);
    }
    qihse_fts_destroy(idx_loaded);
    qihse_fts_destroy(idx_rt);
    printf("[PASS] Hardened persistence preserves exact search round-trip\n");

    qihse_fts_index_t* idx_mixed = qihse_fts_create();
    assert(idx_mixed);
    assert(qihse_fts_add_document(idx_mixed, 1, "unclassified doc", 16,
                                  0, 0, QIHSE_KEYSTONE_CLASS_UNKNOWN));
    assert(qihse_fts_add_document_user(idx_mixed, 2, "secret doc", 10,
                                       3, 0, QIHSE_KEYSTONE_CLASS_GOVERNMENT,
                                       operator_user));
    assert(!qihse_fts_save(idx_mixed, "/tmp/test_fts_mixed_null.qfts", NULL));
    assert(qihse_fts_save(idx_mixed, "/tmp/test_fts_mixed.qfts", operator_user));
    assert(qihse_fts_load("/tmp/test_fts_mixed.qfts", guest) == NULL);
    qihse_fts_destroy(idx_mixed);

    test_ranking_isolation(guest, operator_user);

    /* Malicious serialized cardinalities must be rejected before allocation. */
    write_bad_counts_fixture();
    assert(qihse_fts_load("/tmp/test_fts_bad_counts.qfts", operator_user) == NULL);
    printf("[PASS] Malformed FTS cardinalities are rejected before allocation\n");

    cleanup();
    printf("\n[ALL PASS] FTS persistence/RBAC/inference regression suite\n");
    return 0;
}
