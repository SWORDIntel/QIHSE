/*
 * test_mvcc_delete.c — MVCC DELETE semantics, tested in both directions.
 *
 * qihse_mvcc_delete() used to mark the chain head, which may be a version
 * written by a transaction that later aborted, so a committed DELETE could
 * leave the row visible.  A fix has to be correct in BOTH directions:
 *
 *   (a) a committed DELETE must hide the row for readers whose snapshot is at
 *       or after the deleting transaction, whatever aborted writers preceded
 *       it (aborted UPDATE, aborted DELETE, several aborted writers, a hole
 *       under a committed version);
 *   (b) it must NOT hide anything a reader of an older snapshot is entitled
 *       to see, must NOT hide a version written by a transaction the deleter
 *       could not see (that would be silent data loss), and must NOT resurrect
 *       a row that an earlier committed DELETE hid.
 *
 * Cases 4, 5 and 6 are the over-correction guards: they fail against a fix
 * that marks xmax on every version of the chain.
 *
 * No on-disk state; every case runs against a fresh store and manager.
 */
#include "qihse_txn.h"
#include "qihse_mvcc.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static bool committed_cb(void* ctx, uint64_t txn_id) {
    return qihse_txn_is_committed((qihse_txn_manager_t*)ctx, txn_id);
}

static bool row_visible(qihse_mvcc_store_t* store, qihse_txn_manager_t* mgr,
                        const char* key, uint64_t snapshot) {
    return qihse_mvcc_read(store, QIHSE_MVCC_ENGINE_KV, key, strlen(key),
                           snapshot, committed_cb, mgr, NULL, NULL);
}

static void expect_value(qihse_mvcc_store_t* store, qihse_txn_manager_t* mgr,
                         const char* key, uint64_t snapshot, const char* want) {
    const void* val = NULL;
    size_t len = 0;
    bool found = qihse_mvcc_read(store, QIHSE_MVCC_ENGINE_KV, key, strlen(key),
                                 snapshot, committed_cb, mgr, &val, &len);
    assert(found);
    assert(len == strlen(want));
    assert(memcmp(val, want, len) == 0);
}

/* Hidden for the reader AND for the existence check, which shares the path. */
static void expect_hidden(qihse_mvcc_store_t* store, qihse_txn_manager_t* mgr,
                          const char* key, uint64_t snapshot) {
    assert(!row_visible(store, mgr, key, snapshot));
    assert(!qihse_mvcc_exists(store, QIHSE_MVCC_ENGINE_KV, key, strlen(key),
                              snapshot, committed_cb, mgr));
}

/* ── 1. Plain insert + delete: the control the gold probe uses ──────────── */

static void test_plain_delete(void) {
    qihse_txn_manager_t* mgr = qihse_txn_manager_create();
    qihse_mvcc_store_t* store = qihse_mvcc_store_create(64);
    assert(mgr && store);

    const char* key = "plain";
    qihse_txn_t* t1 = qihse_txn_begin(mgr, QIHSE_ISO_READ_COMMITTED);
    assert(t1 && qihse_mvcc_insert(store, QIHSE_MVCC_ENGINE_KV, key,
                                   strlen(key), "keep", 4, t1->id) == 0);
    assert(qihse_txn_commit(mgr, t1) == 0);
    expect_value(store, mgr, key, t1->id, "keep");

    qihse_txn_t* t2 = qihse_txn_begin(mgr, QIHSE_ISO_READ_COMMITTED);
    assert(t2 && qihse_mvcc_delete(store, QIHSE_MVCC_ENGINE_KV, key,
                                   strlen(key), t2->id) == 0);
    assert(qihse_txn_commit(mgr, t2) == 0);

    /* At and after the delete: hidden.  Before it: still visible. */
    expect_hidden(store, mgr, key, t2->id);
    expect_hidden(store, mgr, key, t2->id + 100);
    expect_value(store, mgr, key, t1->id, "keep");

    qihse_mvcc_store_destroy(store);
    qihse_txn_manager_destroy(mgr);
    printf("PASS mvcc delete: plain committed DELETE hides the row, older "
           "snapshot keeps it\n");
}

/* ── 2. Aborted writer before the delete (the gold probe's sequence) ────── */

static void test_delete_after_aborted_update(void) {
    qihse_txn_manager_t* mgr = qihse_txn_manager_create();
    qihse_mvcc_store_t* store = qihse_mvcc_store_create(64);
    assert(mgr && store);

    const char* key = "aborted-update";
    qihse_txn_t* t1 = qihse_txn_begin(mgr, QIHSE_ISO_READ_COMMITTED);
    assert(t1 && qihse_mvcc_insert(store, QIHSE_MVCC_ENGINE_KV, key,
                                   strlen(key), "base", 4, t1->id) == 0);
    assert(qihse_txn_commit(mgr, t1) == 0);

    qihse_txn_t* t2 = qihse_txn_begin(mgr, QIHSE_ISO_READ_COMMITTED);
    assert(t2 && qihse_mvcc_update(store, QIHSE_MVCC_ENGINE_KV, key,
                                   strlen(key), "aborted", 7, t2->id) == 0);
    assert(qihse_txn_rollback(mgr, t2) == 0);

    /* The aborted version is invisible; the base version is what readers see. */
    expect_value(store, mgr, key, t1->id, "base");
    expect_value(store, mgr, key, t2->id, "base");

    qihse_txn_t* t3 = qihse_txn_begin(mgr, QIHSE_ISO_READ_COMMITTED);
    assert(t3 && qihse_mvcc_delete(store, QIHSE_MVCC_ENGINE_KV, key,
                                   strlen(key), t3->id) == 0);
    assert(qihse_txn_commit(mgr, t3) == 0);

    /* The delete hides the row: the aborted head was not what it marked. */
    expect_hidden(store, mgr, key, t3->id);
    expect_hidden(store, mgr, key, t3->id + 100);
    /* Snapshots that predate the delete still see the committed base value. */
    expect_value(store, mgr, key, t1->id, "base");
    expect_value(store, mgr, key, t2->id, "base");

    /* No snapshot ever returns the aborted writer's value. */
    for (uint64_t snap = t1->id; snap <= t3->id + 4; snap++) {
        const void* val = NULL;
        size_t len = 0;
        if (qihse_mvcc_read(store, QIHSE_MVCC_ENGINE_KV, key, strlen(key),
                            snap, committed_cb, mgr, &val, &len)) {
            assert(len == 4 && memcmp(val, "base", 4) == 0);
        }
    }

    qihse_mvcc_store_destroy(store);
    qihse_txn_manager_destroy(mgr);
    printf("PASS mvcc delete: committed DELETE hides the row after an aborted "
           "UPDATE, aborted version never resurfaces\n");
}

/* ── 3. Aborted DELETE before the committed DELETE ──────────────────────── */

static void test_delete_after_aborted_delete(void) {
    qihse_txn_manager_t* mgr = qihse_txn_manager_create();
    qihse_mvcc_store_t* store = qihse_mvcc_store_create(64);
    assert(mgr && store);

    const char* key = "aborted-delete";
    qihse_txn_t* t1 = qihse_txn_begin(mgr, QIHSE_ISO_READ_COMMITTED);
    assert(t1 && qihse_mvcc_insert(store, QIHSE_MVCC_ENGINE_KV, key,
                                   strlen(key), "base", 4, t1->id) == 0);
    assert(qihse_txn_commit(mgr, t1) == 0);

    /* A rolled-back DELETE must hide nothing. */
    qihse_txn_t* t2 = qihse_txn_begin(mgr, QIHSE_ISO_READ_COMMITTED);
    assert(t2 && qihse_mvcc_delete(store, QIHSE_MVCC_ENGINE_KV, key,
                                   strlen(key), t2->id) == 0);
    assert(qihse_txn_rollback(mgr, t2) == 0);
    expect_value(store, mgr, key, t1->id, "base");
    expect_value(store, mgr, key, t2->id, "base");

    qihse_txn_t* t3 = qihse_txn_begin(mgr, QIHSE_ISO_READ_COMMITTED);
    assert(t3 && qihse_mvcc_delete(store, QIHSE_MVCC_ENGINE_KV, key,
                                   strlen(key), t3->id) == 0);
    assert(qihse_txn_commit(mgr, t3) == 0);

    expect_hidden(store, mgr, key, t3->id);
    expect_hidden(store, mgr, key, t3->id + 100);
    expect_value(store, mgr, key, t1->id, "base");
    expect_value(store, mgr, key, t2->id, "base");

    qihse_mvcc_store_destroy(store);
    qihse_txn_manager_destroy(mgr);
    printf("PASS mvcc delete: committed DELETE hides the row after an aborted "
           "DELETE\n");
}

/* ── 4. Over-correction guard: no resurrection of a deleted row ─────────── */

static void test_repeat_delete_does_not_resurrect(void) {
    qihse_txn_manager_t* mgr = qihse_txn_manager_create();
    qihse_mvcc_store_t* store = qihse_mvcc_store_create(64);
    assert(mgr && store);

    const char* key = "repeat-delete";
    qihse_txn_t* t1 = qihse_txn_begin(mgr, QIHSE_ISO_READ_COMMITTED);
    assert(t1 && qihse_mvcc_insert(store, QIHSE_MVCC_ENGINE_KV, key,
                                   strlen(key), "keep", 4, t1->id) == 0);
    assert(qihse_txn_commit(mgr, t1) == 0);

    qihse_txn_t* t2 = qihse_txn_begin(mgr, QIHSE_ISO_READ_COMMITTED);
    assert(t2 && qihse_mvcc_delete(store, QIHSE_MVCC_ENGINE_KV, key,
                                   strlen(key), t2->id) == 0);
    assert(qihse_txn_commit(mgr, t2) == 0);
    expect_hidden(store, mgr, key, t2->id);

    /* A second DELETE must not un-delete the row for snapshots taken between
     * the two deletes, and must not un-delete it for later ones either. */
    qihse_txn_t* t3 = qihse_txn_begin(mgr, QIHSE_ISO_READ_COMMITTED);
    assert(t3 && qihse_mvcc_delete(store, QIHSE_MVCC_ENGINE_KV, key,
                                   strlen(key), t3->id) == 0);
    assert(qihse_txn_commit(mgr, t3) == 0);
    expect_hidden(store, mgr, key, t2->id);
    expect_hidden(store, mgr, key, t3->id);
    expect_hidden(store, mgr, key, t3->id + 100);
    /* The snapshot before the first delete still sees the original row. */
    expect_value(store, mgr, key, t1->id, "keep");

    qihse_mvcc_store_destroy(store);
    qihse_txn_manager_destroy(mgr);
    printf("PASS mvcc delete: a second DELETE neither resurrects the row nor "
           "hides an older snapshot's view\n");
}

/* ── 5. Over-correction guard: a version the deleter could not see ──────── */

static void test_delete_does_not_hide_unseen_version(void) {
    qihse_txn_manager_t* mgr = qihse_txn_manager_create();
    qihse_mvcc_store_t* store = qihse_mvcc_store_create(64);
    assert(mgr && store);

    const char* key = "concurrent-writer";
    qihse_txn_t* t1 = qihse_txn_begin(mgr, QIHSE_ISO_READ_COMMITTED);
    assert(t1 && qihse_mvcc_insert(store, QIHSE_MVCC_ENGINE_KV, key,
                                   strlen(key), "base", 4, t1->id) == 0);
    assert(qihse_txn_commit(mgr, t1) == 0);

    /* t2 starts first (lower id) but writes last; t3 writes "new" before t2's
     * DELETE.  t2's snapshot is below t3's version, so t2 never saw it. */
    qihse_txn_t* t2 = qihse_txn_begin(mgr, QIHSE_ISO_READ_COMMITTED);
    assert(t2);
    qihse_txn_t* t3 = qihse_txn_begin(mgr, QIHSE_ISO_READ_COMMITTED);
    assert(t3 && qihse_mvcc_update(store, QIHSE_MVCC_ENGINE_KV, key,
                                   strlen(key), "new", 3, t3->id) == 0);
    assert(qihse_txn_commit(mgr, t3) == 0);
    expect_value(store, mgr, key, t3->id, "new");

    assert(qihse_mvcc_delete(store, QIHSE_MVCC_ENGINE_KV, key, strlen(key),
                             t2->id) == 0);
    assert(qihse_txn_commit(mgr, t2) == 0);

    /* The DELETE hides the row at its own snapshot ... */
    expect_hidden(store, mgr, key, t2->id);
    /* ... but must not hide the version written by t3, which t2 could not
     * see: a reader at t3's snapshot still sees "new". */
    expect_value(store, mgr, key, t3->id, "new");
    /* The snapshot before t3's write still sees the original row. */
    expect_value(store, mgr, key, t1->id, "base");

    qihse_mvcc_store_destroy(store);
    qihse_txn_manager_destroy(mgr);
    printf("PASS mvcc delete: a DELETE does not hide a version its transaction "
           "could not see\n");
}

/* ── 6. Over-correction guard: no resurrection through a delete chain ───── */

static void test_delete_chain(void) {
    qihse_txn_manager_t* mgr = qihse_txn_manager_create();
    qihse_mvcc_store_t* store = qihse_mvcc_store_create(64);
    assert(mgr && store);

    const char* key = "chain";
    qihse_txn_t* t1 = qihse_txn_begin(mgr, QIHSE_ISO_READ_COMMITTED);
    assert(t1 && qihse_mvcc_insert(store, QIHSE_MVCC_ENGINE_KV, key,
                                   strlen(key), "base", 4, t1->id) == 0);
    assert(qihse_txn_commit(mgr, t1) == 0);

    /* delete, re-insert, delete again: every delete must stay effective for
     * the snapshots at or after it, and none may reveal an older version. */
    qihse_txn_t* t2 = qihse_txn_begin(mgr, QIHSE_ISO_READ_COMMITTED);
    assert(t2 && qihse_mvcc_delete(store, QIHSE_MVCC_ENGINE_KV, key,
                                   strlen(key), t2->id) == 0);
    assert(qihse_txn_commit(mgr, t2) == 0);

    qihse_txn_t* t3 = qihse_txn_begin(mgr, QIHSE_ISO_READ_COMMITTED);
    assert(t3 && qihse_mvcc_insert(store, QIHSE_MVCC_ENGINE_KV, key,
                                   strlen(key), "second", 6, t3->id) == 0);
    assert(qihse_txn_commit(mgr, t3) == 0);
    expect_hidden(store, mgr, key, t2->id);
    expect_value(store, mgr, key, t3->id, "second");
    expect_value(store, mgr, key, t1->id, "base");

    qihse_txn_t* t4 = qihse_txn_begin(mgr, QIHSE_ISO_READ_COMMITTED);
    assert(t4 && qihse_mvcc_delete(store, QIHSE_MVCC_ENGINE_KV, key,
                                   strlen(key), t4->id) == 0);
    assert(qihse_txn_commit(mgr, t4) == 0);
    expect_hidden(store, mgr, key, t4->id);
    expect_hidden(store, mgr, key, t4->id + 100);
    /* The re-inserted row stays visible to snapshots that saw it, and the
     * first delete stays effective for snapshots that saw it. */
    expect_value(store, mgr, key, t3->id, "second");
    expect_hidden(store, mgr, key, t2->id);
    expect_value(store, mgr, key, t1->id, "base");

    qihse_mvcc_store_destroy(store);
    qihse_txn_manager_destroy(mgr);
    printf("PASS mvcc delete: delete / re-insert / delete keeps every snapshot's "
           "view\n");
}

/* ── 7. Holes under a committed version: several aborted writers ────────── */

static void test_delete_after_aborted_writers(void) {
    qihse_txn_manager_t* mgr = qihse_txn_manager_create();
    qihse_mvcc_store_t* store = qihse_mvcc_store_create(64);
    assert(mgr && store);

    const char* key = "holes";
    qihse_txn_t* t1 = qihse_txn_begin(mgr, QIHSE_ISO_READ_COMMITTED);
    assert(t1 && qihse_mvcc_insert(store, QIHSE_MVCC_ENGINE_KV, key,
                                   strlen(key), "v1", 2, t1->id) == 0);
    assert(qihse_txn_commit(mgr, t1) == 0);

    qihse_txn_t* t2 = qihse_txn_begin(mgr, QIHSE_ISO_READ_COMMITTED);
    assert(t2 && qihse_mvcc_update(store, QIHSE_MVCC_ENGINE_KV, key,
                                   strlen(key), "v2", 2, t2->id) == 0);
    assert(qihse_txn_commit(mgr, t2) == 0);

    qihse_txn_t* t3 = qihse_txn_begin(mgr, QIHSE_ISO_READ_COMMITTED);
    assert(t3 && qihse_mvcc_update(store, QIHSE_MVCC_ENGINE_KV, key,
                                   strlen(key), "v3", 2, t3->id) == 0);
    assert(qihse_txn_rollback(mgr, t3) == 0);

    qihse_txn_t* t4 = qihse_txn_begin(mgr, QIHSE_ISO_READ_COMMITTED);
    assert(t4 && qihse_mvcc_update(store, QIHSE_MVCC_ENGINE_KV, key,
                                   strlen(key), "v4", 2, t4->id) == 0);
    assert(qihse_txn_commit(mgr, t4) == 0);
    expect_value(store, mgr, key, t4->id, "v4");
    expect_value(store, mgr, key, t3->id, "v2");

    qihse_txn_t* t5 = qihse_txn_begin(mgr, QIHSE_ISO_READ_COMMITTED);
    assert(t5 && qihse_mvcc_delete(store, QIHSE_MVCC_ENGINE_KV, key,
                                   strlen(key), t5->id) == 0);
    assert(qihse_txn_commit(mgr, t5) == 0);

    /* The delete must not expose the version under the aborted hole. */
    expect_hidden(store, mgr, key, t5->id);
    expect_hidden(store, mgr, key, t5->id + 100);
    expect_value(store, mgr, key, t4->id, "v4");
    expect_value(store, mgr, key, t3->id, "v2");
    expect_value(store, mgr, key, t1->id, "v1");

    qihse_mvcc_store_destroy(store);
    qihse_txn_manager_destroy(mgr);
    printf("PASS mvcc delete: DELETE hides a row sitting above an aborted "
           "writer's hole\n");
}

/* ── 8. UPDATE after a DELETE behaves like a re-insert ──────────────────── */

static void test_update_after_delete(void) {
    qihse_txn_manager_t* mgr = qihse_txn_manager_create();
    qihse_mvcc_store_t* store = qihse_mvcc_store_create(64);
    assert(mgr && store);

    const char* key = "reinsert";
    qihse_txn_t* t1 = qihse_txn_begin(mgr, QIHSE_ISO_READ_COMMITTED);
    assert(t1 && qihse_mvcc_insert(store, QIHSE_MVCC_ENGINE_KV, key,
                                   strlen(key), "base", 4, t1->id) == 0);
    assert(qihse_txn_commit(mgr, t1) == 0);

    qihse_txn_t* t2 = qihse_txn_begin(mgr, QIHSE_ISO_READ_COMMITTED);
    assert(t2 && qihse_mvcc_delete(store, QIHSE_MVCC_ENGINE_KV, key,
                                   strlen(key), t2->id) == 0);
    assert(qihse_txn_commit(mgr, t2) == 0);

    qihse_txn_t* t3 = qihse_txn_begin(mgr, QIHSE_ISO_READ_COMMITTED);
    assert(t3 && qihse_mvcc_update(store, QIHSE_MVCC_ENGINE_KV, key,
                                   strlen(key), "revived", 7, t3->id) == 0);
    assert(qihse_txn_commit(mgr, t3) == 0);

    expect_value(store, mgr, key, t3->id, "revived");
    expect_hidden(store, mgr, key, t2->id);
    expect_value(store, mgr, key, t1->id, "base");

    qihse_mvcc_store_destroy(store);
    qihse_txn_manager_destroy(mgr);
    printf("PASS mvcc delete: UPDATE after DELETE revives the row only for "
           "snapshots at or after the update\n");
}

int main(void) {
    test_plain_delete();
    test_delete_after_aborted_update();
    test_delete_after_aborted_delete();
    test_repeat_delete_does_not_resurrect();
    test_delete_does_not_hide_unseen_version();
    test_delete_chain();
    test_delete_after_aborted_writers();
    test_update_after_delete();
    printf("test_mvcc_delete: all MVCC delete semantics tests passed\n");
    return 0;
}
