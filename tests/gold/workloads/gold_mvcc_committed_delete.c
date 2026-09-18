/*
 * gold_mvcc_committed_delete.c — gold workload (area: relational).
 *
 * A KNOWN-DEFECT probe for the MVCC delete path:
 *
 *   GOLD: KNOWN-BUG <workload-id> <check>: <detail>
 *   GOLD: OK        <workload-id> <check>: <detail>
 *
 * qihse_mvcc_delete() marks xmax on the chain HEAD.  If the head is a version
 * written by a transaction that later aborted, the delete marks a version no
 * reader can see while the version readers DO see stays live — so a committed
 * DELETE leaves the row visible.  The sequence below is the one recorded in
 * tests/test_txn.c:218-247 and docs/architecture/transactions_mvcc.md.
 *
 * Control: the same insert/delete/commit sequence on a key with no aborted
 * writer must hide the row.  If the control fails, the probe itself is broken
 * and exits non-zero rather than reporting a defect.
 *
 * Exit status: 0 when the probe ran and reported; non-zero when the control
 * failed.
 */
#include "qihse_mvcc.h"
#include "qihse_txn.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define GOLD_ID "gold_mvcc_committed_delete"

static bool committed_cb(void* ctx, uint64_t txn_id) {
    return qihse_txn_is_committed((qihse_txn_manager_t*)ctx, txn_id);
}

static bool row_visible(qihse_mvcc_store_t* store, qihse_txn_manager_t* mgr,
                        const char* key, uint64_t snapshot) {
    return qihse_mvcc_read(store, QIHSE_MVCC_ENGINE_KV, key, strlen(key),
                           snapshot, committed_cb, mgr, NULL, NULL);
}

static int report(const char* check, const char* detail, int broken) {
    if (broken) {
        printf("GOLD: KNOWN-BUG %s %s: %s\n", GOLD_ID, check, detail);
    } else {
        printf("GOLD: OK %s %s: %s\n", GOLD_ID, check, detail);
    }
    return 0;
}

int main(void) {
    qihse_txn_manager_t* mgr = qihse_txn_manager_create();
    qihse_mvcc_store_t* store = qihse_mvcc_store_create(64);
    if (!mgr || !store) {
        fprintf(stderr, "%s: probe control failed: could not create the txn "
                "manager or MVCC store\n", GOLD_ID);
        return 1;
    }

    /* ── Control: delete after a plain committed insert must hide the row ── */
    const char* control_key = "gold:mvcc:control";
    qihse_txn_t* c1 = qihse_txn_begin(mgr, QIHSE_ISO_READ_COMMITTED);
    if (!c1 || qihse_mvcc_insert(store, QIHSE_MVCC_ENGINE_KV, control_key,
                                 strlen(control_key), "keep", 4, c1->id) != 0 ||
        qihse_txn_commit(mgr, c1) != 0) {
        fprintf(stderr, "%s: probe control failed: insert+commit\n", GOLD_ID);
        return 1;
    }
    qihse_txn_t* c2 = qihse_txn_begin(mgr, QIHSE_ISO_READ_COMMITTED);
    if (!c2 || qihse_mvcc_delete(store, QIHSE_MVCC_ENGINE_KV, control_key,
                                 strlen(control_key), c2->id) != 0 ||
        qihse_txn_commit(mgr, c2) != 0) {
        fprintf(stderr, "%s: probe control failed: delete+commit\n", GOLD_ID);
        return 1;
    }
    if (row_visible(store, mgr, control_key, c2->id)) {
        fprintf(stderr,
                "%s: probe control failed: a plain committed DELETE left the "
                "row visible, so the defect check below cannot be interpreted\n",
                GOLD_ID);
        return 1;
    }

    /* ── Defect sequence: committed delete after an aborted writer ───────── */
    const char* key = "gold:mvcc:aborted-writer";
    qihse_txn_t* t1 = qihse_txn_begin(mgr, QIHSE_ISO_READ_COMMITTED);
    if (!t1 || qihse_mvcc_insert(store, QIHSE_MVCC_ENGINE_KV, key, strlen(key),
                                 "base", 4, t1->id) != 0 ||
        qihse_txn_commit(mgr, t1) != 0) {
        fprintf(stderr, "%s: probe control failed: base insert+commit\n", GOLD_ID);
        return 1;
    }

    qihse_txn_t* t2 = qihse_txn_begin(mgr, QIHSE_ISO_READ_COMMITTED);
    if (!t2 || qihse_mvcc_update(store, QIHSE_MVCC_ENGINE_KV, key, strlen(key),
                                 "aborted", 7, t2->id) != 0 ||
        qihse_txn_rollback(mgr, t2) != 0) {
        fprintf(stderr, "%s: probe control failed: update+rollback\n", GOLD_ID);
        return 1;
    }

    qihse_txn_t* t3 = qihse_txn_begin(mgr, QIHSE_ISO_READ_COMMITTED);
    if (!t3 || qihse_mvcc_delete(store, QIHSE_MVCC_ENGINE_KV, key, strlen(key),
                                 t3->id) != 0 ||
        qihse_txn_commit(mgr, t3) != 0) {
        fprintf(stderr, "%s: probe control failed: delete+commit\n", GOLD_ID);
        return 1;
    }

    bool visible = row_visible(store, mgr, key, t3->id);
    if (visible) {
        char detail[512];
        snprintf(detail, sizeof(detail),
                 "after (insert+commit, update+rollback, delete+commit) the row "
                 "is STILL VISIBLE at the deleting snapshot; qihse_mvcc_delete "
                 "marks the chain head (the aborted version) instead of the "
                 "version readers see (src/tractable/qihse_mvcc.c:204-207, "
                 "tests/test_txn.c:218-247, "
                 "docs/architecture/transactions_mvcc.md)");
        report("mvcc-committed-delete-hides-row", detail, 1);
    } else {
        report("mvcc-committed-delete-hides-row",
               "a committed DELETE hid the row even after an aborted writer "
               "(the delete now marks a version readers can see)", 0);
    }

    qihse_mvcc_store_destroy(store);
    qihse_txn_manager_destroy(mgr);
    return 0;
}
