#define _GNU_SOURCE
/*
 * test_fts_persistence_auth.c — Negative authorization test for FTS save/load.
 *
 * Per QIHSE AGENTS.md invariant 3: every new protocol adapter / persistence
 * layer requires a low-clearance/high-data negative test.
 *
 * This test:
 *   1. Creates an FTS index with classified documents (classification=5)
 *   2. Verifies an operator can save and load the classified index
 *   3. Verifies a guest (classification=0) CANNOT save the classified index
 *   4. Verifies a guest CANNOT load the classified index file
 *   5. Verifies unclassified indexes work with NULL user
 *   6. Verifies round-trip fidelity (search results identical after save/load)
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "qihse_auth.h"
#include "qihse_fts.h"
#include "core/qihse_auth_internal.h"

int main(void) {
    /* Initialize auth */
    setenv("QIHSE_FIPS_MODE", "disabled", 1);
    assert(qihse_auth_init());

    /* Bootstrap operator */
    assert(qihse_auth_bootstrap_operator("SecureOpPass1!"));
    qihse_user_t* operator_user = qihse_auth_get_user(0);
    assert(operator_user != NULL);

    /* Create a guest with classification=0 (unclassified only) */
    qihse_user_t* guest = qihse_auth_create_user(
        operator_user, 10, QIHSE_ROLE_GUEST, 0, 0,
        "GuestPass123!", false);
    assert(guest != NULL);

    /* Create an analyst with classification=5 */
    qihse_user_t* analyst = qihse_auth_create_user(
        operator_user, 11, QIHSE_ROLE_ANALYST, 5, 0,
        "AnalystPass123!", false);
    assert(analyst != NULL);

    /* ---- Test 1: Classified index — operator can save ---- */
    qihse_fts_index_t* idx_classified = qihse_fts_create();
    assert(idx_classified != NULL);

    /* Add classified documents */
    const char* t1 = "secret kernel exploit driver analysis";
    assert(qihse_fts_add_document(idx_classified, 1, t1, strlen(t1),
        5, 0, QIHSE_KEYSTONE_CLASS_GOVERNMENT));
    const char* t2 = "classified vulnerability refcount race";
    assert(qihse_fts_add_document(idx_classified, 2, t2, strlen(t2),
        5, 0, QIHSE_KEYSTONE_CLASS_GOVERNMENT));

    /* Operator can save (has classification >= 5) */
    bool op_save = qihse_fts_save(idx_classified, "/tmp/test_fts_classified.qfts", operator_user);
    assert(op_save);
    printf("[PASS] Operator can save classified FTS index\n");

    /* ---- Test 2: Guest CANNOT save classified index ---- */
    bool guest_save = qihse_fts_save(idx_classified, "/tmp/test_fts_classified_guest.qfts", guest);
    assert(!guest_save);
    printf("[PASS] Guest denied saving classified FTS index (no partial export)\n");

    /* Verify the guest's save file was NOT created */
    FILE* check = fopen("/tmp/test_fts_classified_guest.qfts", "rb");
    assert(check == NULL);
    printf("[PASS] No file leaked from denied save\n");

    /* ---- Test 3: Operator can load classified index ---- */
    qihse_fts_index_t* loaded_op = qihse_fts_load("/tmp/test_fts_classified.qfts", operator_user);
    assert(loaded_op != NULL);

    /* Verify search works and returns classified results */
    qihse_fts_result_t results[10];
    int n = qihse_fts_search_user(loaded_op, "exploit", operator_user, results, 10);
    assert(n > 0);
    printf("[PASS] Operator can load and search classified FTS index (%d results)\n", n);
    qihse_fts_destroy(loaded_op);

    /* ---- Test 4: Guest CANNOT load classified index ---- */
    qihse_fts_index_t* loaded_guest = qihse_fts_load("/tmp/test_fts_classified.qfts", guest);
    assert(loaded_guest == NULL);
    printf("[PASS] Guest denied loading classified FTS index (no partial import)\n");

    /* ---- Test 5: Analyst (classification=5) CAN load classified index ---- */
    qihse_fts_index_t* loaded_analyst = qihse_fts_load("/tmp/test_fts_classified.qfts", analyst);
    assert(loaded_analyst != NULL);
    printf("[PASS] Analyst (classification=5) can load classified FTS index\n");
    qihse_fts_destroy(loaded_analyst);

    qihse_fts_destroy(idx_classified);

    /* ---- Test 6: Unclassified index — NULL user works ---- */
    qihse_fts_index_t* idx_unclassified = qihse_fts_create();
    assert(idx_unclassified != NULL);

    const char* t10 = "public driver analysis documentation";
    assert(qihse_fts_add_document(idx_unclassified, 10, t10, strlen(t10),
        0, 0, QIHSE_KEYSTONE_CLASS_UNKNOWN));
    const char* t11 = "open source kernel module reference";
    assert(qihse_fts_add_document(idx_unclassified, 11, t11, strlen(t11),
        0, 0, QIHSE_KEYSTONE_CLASS_UNKNOWN));

    /* NULL user can save unclassified index */
    bool null_save = qihse_fts_save(idx_unclassified, "/tmp/test_fts_unclassified.qfts", NULL);
    assert(null_save);
    printf("[PASS] NULL user can save unclassified FTS index\n");

    /* NULL user can load unclassified index */
    qihse_fts_index_t* loaded_null = qihse_fts_load("/tmp/test_fts_unclassified.qfts", NULL);
    assert(loaded_null != NULL);
    printf("[PASS] NULL user can load unclassified FTS index\n");

    /* Guest can also load unclassified index */
    qihse_fts_index_t* loaded_guest_unc = qihse_fts_load("/tmp/test_fts_unclassified.qfts", guest);
    assert(loaded_guest_unc != NULL);
    printf("[PASS] Guest can load unclassified FTS index\n");
    qihse_fts_destroy(loaded_guest_unc);

    qihse_fts_destroy(loaded_null);
    qihse_fts_destroy(idx_unclassified);

    /* ---- Test 7: Round-trip fidelity ---- */
    qihse_fts_index_t* idx_rt = qihse_fts_create();
    for (int i = 0; i < 50; i++) {
        char text[128];
        snprintf(text, sizeof(text), "function_%d ExAllocatePoolWithTag kernel driver test %d", i, i);
        qihse_fts_add_document(idx_rt, 100 + i, text, strlen(text), 0, 0, QIHSE_KEYSTONE_CLASS_UNKNOWN);
    }

    /* Search before save */
    qihse_fts_result_t before[5];
    int n_before = qihse_fts_search_user(idx_rt, "ExAllocatePool", NULL, before, 5);
    assert(n_before > 0);

    /* Save and reload */
    assert(qihse_fts_save(idx_rt, "/tmp/test_fts_roundtrip.qfts", NULL));
    qihse_fts_index_t* idx_loaded = qihse_fts_load("/tmp/test_fts_roundtrip.qfts", NULL);
    assert(idx_loaded != NULL);

    /* Search after load — results must match */
    qihse_fts_result_t after[5];
    int n_after = qihse_fts_search_user(idx_loaded, "ExAllocatePool", NULL, after, 5);
    assert(n_after == n_before);

    for (int i = 0; i < n_before; i++) {
        assert(before[i].doc_id == after[i].doc_id);
        /* BM25 scores should be identical (same index structure) */
        assert(before[i].bm25_score == after[i].bm25_score);
    }
    printf("[PASS] Round-trip fidelity: %d results match exactly\n", n_before);

    qihse_fts_destroy(idx_loaded);
    qihse_fts_destroy(idx_rt);

    /* ---- Test 8: NULL user CANNOT save classified index ---- */
    qihse_fts_index_t* idx_mixed = qihse_fts_create();
    qihse_fts_add_document(idx_mixed, 1, "unclassified doc", 16, 0, 0, QIHSE_KEYSTONE_CLASS_UNKNOWN);
    qihse_fts_add_document(idx_mixed, 2, "secret doc", 10, 3, 0, QIHSE_KEYSTONE_CLASS_GOVERNMENT);

    bool null_save_classified = qihse_fts_save(idx_mixed, "/tmp/test_fts_mixed_null.qfts", NULL);
    assert(!null_save_classified);
    printf("[PASS] NULL user denied saving mixed-classification index\n");

    /* Operator can save the mixed index */
    bool op_save_mixed = qihse_fts_save(idx_mixed, "/tmp/test_fts_mixed.qfts", operator_user);
    assert(op_save_mixed);
    printf("[PASS] Operator can save mixed-classification index\n");

    /* Guest cannot load mixed index (has classified docs) */
    qihse_fts_index_t* guest_mixed = qihse_fts_load("/tmp/test_fts_mixed.qfts", guest);
    assert(guest_mixed == NULL);
    printf("[PASS] Guest denied loading mixed-classification index\n");

    qihse_fts_destroy(idx_mixed);

    /* Cleanup */
    unlink("/tmp/test_fts_classified.qfts");
    unlink("/tmp/test_fts_unclassified.qfts");
    unlink("/tmp/test_fts_roundtrip.qfts");
    unlink("/tmp/test_fts_mixed.qfts");

    printf("\n[ALL PASS] FTS persistence authorization tests — %s:%d\n", __FILE__, __LINE__);
    return 0;
}
