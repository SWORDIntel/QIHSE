/*
 * test_txn.c — ACID transactions, MVCC visibility, WAL replay and crash recovery.
 *
 * Exercises the sources the transactions document describes:
 *   src/tractable/qihse_txn.c       — transaction manager, savepoints, OCC, 2PC
 *   src/tractable/qihse_mvcc.c      — version chains, snapshot visibility, vacuum
 *   src/tractable/qihse_wal.c       — append, CRC-checked replay, checkpoint
 *   src/tractable/qihse_recovery.c  — analysis / redo / undo replay
 *
 *   1. BEGIN/COMMIT/ROLLBACK lifecycle, registry and active set
 *   2. MVCC visibility: an older snapshot still sees the superseded version,
 *      and a version written by an uncommitted transaction is invisible
 *   3. SAVEPOINT and partial rollback (savepoint stack and write-set trim)
 *   4. WAL append and replay (payloads and LSN ordering survive a round trip)
 *   5. Crash recovery: committed transaction redo is applied, the transaction
 *      that never committed is marked aborted and its data stays invisible
 *   6. SERIALIZABLE OCC: read-write and write-write conflicts abort at commit
 *   7. Two-phase commit: prepare / commit_prepared / abort_prepared callbacks
 *
 * All on-disk state lives under a mkdtemp() directory in build/ (relative),
 * per the repository path policy.
 *
 * Not covered here, and not claimed by the document: the OCC validator only
 * compares against transactions that are still *active* at commit time, so a
 * write by a transaction that already committed is not detected (see
 * qihse_txn_validate_occ in src/tractable/qihse_txn.c).
 */
#include "qihse_txn.h"
#include "qihse_mvcc.h"
#include "qihse_wal.h"
#include "qihse_recovery.h"

#include <assert.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* Remove a mkdtemp() directory and the WAL segments inside it, so repeated
 * runs do not accumulate artefacts under build/. */
static void remove_wal_dir(const char* dir) {
    DIR* d = opendir(dir);
    if (d) {
        struct dirent* ent;
        while ((ent = readdir(d)) != NULL) {
            if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
                continue;
            char path[512];
            snprintf(path, sizeof(path), "%s/%s", dir, ent->d_name);
            unlink(path);
        }
        closedir(d);
    }
    rmdir(dir);
}

/* ── 1. Transaction lifecycle ───────────────────────────────────────────── */

static void test_lifecycle(void) {
    qihse_txn_manager_t* mgr = qihse_txn_manager_create();
    assert(mgr);
    assert(qihse_txn_active_count(mgr) == 0);

    qihse_txn_t* t1 = qihse_txn_begin(mgr, QIHSE_ISO_READ_COMMITTED);
    assert(t1);
    assert(t1->state == QIHSE_TXN_ACTIVE);
    assert(t1->id == QIHSE_TXN_FIRST_ID);
    uint64_t id1 = t1->id;

    qihse_txn_t* t2 = qihse_txn_begin(mgr, QIHSE_ISO_REPEATABLE_READ);
    assert(t2);
    assert(t2->id != id1);
    assert(qihse_txn_active_count(mgr) == 2);

    uint64_t* ids = NULL;
    int n_ids = 0;
    assert(qihse_txn_active_list(mgr, &ids, &n_ids) == 0);
    assert(n_ids == 2);
    bool saw1 = false, saw2 = false;
    for (int i = 0; i < n_ids; i++) {
        if (ids[i] == id1) saw1 = true;
        if (ids[i] == t2->id) saw2 = true;
    }
    assert(saw1 && saw2);
    free(ids);

    assert(qihse_txn_commit(mgr, t1) == 0);
    assert(t1->state == QIHSE_TXN_COMMITTED);
    assert(qihse_txn_is_committed(mgr, id1));
    assert(!qihse_txn_is_aborted(mgr, id1));
    assert(qihse_txn_active_count(mgr) == 1);
    /* A second commit of the same handle must be refused. */
    assert(qihse_txn_commit(mgr, t1) == -1);

    assert(qihse_txn_rollback(mgr, t2) == 0);
    assert(t2->state == QIHSE_TXN_ABORTED);
    assert(qihse_txn_is_aborted(mgr, t2->id));
    assert(!qihse_txn_is_committed(mgr, t2->id));
    assert(qihse_txn_active_count(mgr) == 0);
    assert(qihse_txn_rollback(mgr, t2) == -1);

    /* Unknown ids are in neither registry. */
    assert(!qihse_txn_is_committed(mgr, 99999));
    assert(!qihse_txn_is_aborted(mgr, 99999));

    /* LSN plumbing. */
    qihse_txn_set_start_lsn(t1, 4242);
    assert(qihse_txn_get_start_lsn(t1) == 4242);
    assert(qihse_txn_get_snapshot(t2) == t2->id - 1);

    qihse_txn_manager_destroy(mgr);
    printf("PASS txn lifecycle: BEGIN/COMMIT/ROLLBACK, registry, active set, LSN\n");
}

/* ── 2. MVCC visibility ─────────────────────────────────────────────────── */

static bool committed_cb(void* ctx, uint64_t txn_id) {
    return qihse_txn_is_committed((qihse_txn_manager_t*)ctx, txn_id);
}

static void expect_value(qihse_mvcc_store_t* store, qihse_txn_manager_t* mgr,
                         const char* key, uint64_t snapshot, const char* want) {
    const void* val = NULL;
    size_t len = 0;
    bool found = qihse_mvcc_read(store, QIHSE_MVCC_ENGINE_KV,
                                 key, strlen(key), snapshot,
                                 committed_cb, mgr, &val, &len);
    assert(found);
    assert(len == strlen(want));
    assert(memcmp(val, want, len) == 0);
}

static void test_mvcc_visibility(void) {
    qihse_txn_manager_t* mgr = qihse_txn_manager_create();
    qihse_mvcc_store_t* store = qihse_mvcc_store_create(64);
    assert(mgr && store);

    const char* key = "user:1";

    /* t1 writes v1 and commits. */
    qihse_txn_t* t1 = qihse_txn_begin(mgr, QIHSE_ISO_REPEATABLE_READ);
    assert(t1);
    assert(qihse_mvcc_insert(store, QIHSE_MVCC_ENGINE_KV, key, strlen(key),
                             "v1", 2, t1->id) == 0);
    assert(qihse_txn_commit(mgr, t1) == 0);
    uint64_t snap_after_t1 = t1->id;   /* snapshot that sees t1's version */

    expect_value(store, mgr, key, snap_after_t1, "v1");
    assert(qihse_mvcc_exists(store, QIHSE_MVCC_ENGINE_KV, key, strlen(key),
                             snap_after_t1, committed_cb, mgr));
    assert(qihse_mvcc_row_count(store) == 1);
    assert(qihse_mvcc_version_count(store) == 1);

    /* t2 supersedes v1 with v2. */
    qihse_txn_t* t2 = qihse_txn_begin(mgr, QIHSE_ISO_REPEATABLE_READ);
    assert(t2);
    assert(qihse_mvcc_update(store, QIHSE_MVCC_ENGINE_KV, key, strlen(key),
                             "v2", 2, t2->id) == 0);
    assert(qihse_mvcc_version_count(store) == 2);
    /* Not yet committed: the new version is invisible even to a snapshot at
     * or above its xmin, and the superseded version stays visible because
     * its xmax belongs to a transaction that has not committed. */
    expect_value(store, mgr, key, t2->id, "v1");
    assert(qihse_txn_commit(mgr, t2) == 0);

    /* The older snapshot must still see v1; the newer one sees v2. */
    expect_value(store, mgr, key, snap_after_t1, "v1");
    expect_value(store, mgr, key, t2->id, "v2");

    /* A rollback leaves the previous committed version in place: t3 writes,
     * then aborts, and readers still see v2. */
    qihse_txn_t* t3 = qihse_txn_begin(mgr, QIHSE_ISO_READ_COMMITTED);
    assert(t3);
    assert(qihse_mvcc_update(store, QIHSE_MVCC_ENGINE_KV, key, strlen(key),
                             "v3", 2, t3->id) == 0);
    assert(qihse_txn_rollback(mgr, t3) == 0);
    expect_value(store, mgr, key, t3->id, "v2");
    expect_value(store, mgr, key, t3->id + 100, "v2");

    /* Vacuum reclaims versions whose xmax is below the cutoff.  v1 (xmax=2)
     * and v2 (xmax=3) are dead at cutoff 4; the aborted v3 has no xmax and
     * survives, but it is invisible because its xmin never committed. */
    int before = qihse_mvcc_version_count(store);
    assert(before == 3);
    assert(qihse_mvcc_vacuum(store, 4) == 2);
    assert(qihse_mvcc_version_count(store) == 1);
    assert(!qihse_mvcc_read(store, QIHSE_MVCC_ENGINE_KV, key, strlen(key),
                            4, committed_cb, mgr, NULL, NULL));

    /* A committed DELETE on a key with no aborted writer hides the row. */
    const char* key2 = "user:2";
    qihse_txn_t* t5 = qihse_txn_begin(mgr, QIHSE_ISO_READ_COMMITTED);
    assert(t5);
    assert(qihse_mvcc_insert(store, QIHSE_MVCC_ENGINE_KV, key2, strlen(key2),
                             "keep", 4, t5->id) == 0);
    assert(qihse_txn_commit(mgr, t5) == 0);
    expect_value(store, mgr, key2, t5->id, "keep");

    qihse_txn_t* t6 = qihse_txn_begin(mgr, QIHSE_ISO_READ_COMMITTED);
    assert(t6);
    assert(qihse_mvcc_delete(store, QIHSE_MVCC_ENGINE_KV, key2, strlen(key2),
                             t6->id) == 0);
    assert(qihse_txn_commit(mgr, t6) == 0);
    assert(!qihse_mvcc_read(store, QIHSE_MVCC_ENGINE_KV, key2, strlen(key2),
                            t6->id, committed_cb, mgr, NULL, NULL));
    expect_value(store, mgr, key2, t5->id, "keep");
    /* Deleting a missing key is an error, not a silent success. */
    assert(qihse_mvcc_delete(store, QIHSE_MVCC_ENGINE_KV, "no-such-key", 11,
                             t6->id) == -1);

    /* Missing keys and the placeholder min-active helper. */
    assert(!qihse_mvcc_read(store, QIHSE_MVCC_ENGINE_KV, "absent", 6,
                            t6->id, committed_cb, mgr, NULL, NULL));
    assert(qihse_mvcc_min_active_snapshot(store) == 0);

    /*
     * KNOWN DEFECT (reported, not asserted): qihse_mvcc_delete() marks the
     * chain head, which may be a version written by a transaction that later
     * aborted.  It therefore does not necessarily delete the version readers
     * can actually see.  The block below runs the sequence and prints what
     * happens so the defect is visible in CI output; it asserts nothing so
     * that fixing the defect does not break this test.
     */
    const char* key3 = "user:3";
    qihse_txn_t* t7 = qihse_txn_begin(mgr, QIHSE_ISO_READ_COMMITTED);
    assert(t7 && qihse_mvcc_insert(store, QIHSE_MVCC_ENGINE_KV, key3,
                                   strlen(key3), "base", 4, t7->id) == 0);
    assert(qihse_txn_commit(mgr, t7) == 0);
    qihse_txn_t* t8 = qihse_txn_begin(mgr, QIHSE_ISO_READ_COMMITTED);
    assert(t8 && qihse_mvcc_update(store, QIHSE_MVCC_ENGINE_KV, key3,
                                   strlen(key3), "aborted", 7, t8->id) == 0);
    assert(qihse_txn_rollback(mgr, t8) == 0);
    qihse_txn_t* t9 = qihse_txn_begin(mgr, QIHSE_ISO_READ_COMMITTED);
    assert(t9 && qihse_mvcc_delete(store, QIHSE_MVCC_ENGINE_KV, key3,
                                   strlen(key3), t9->id) == 0);
    assert(qihse_txn_commit(mgr, t9) == 0);
    const void* kd_val = NULL;
    size_t kd_len = 0;
    bool kd_visible = qihse_mvcc_read(store, QIHSE_MVCC_ENGINE_KV, key3,
                                      strlen(key3), t9->id, committed_cb, mgr,
                                      &kd_val, &kd_len);
    printf("NOTE mvcc delete-after-aborted-write: row %s after a committed "
           "DELETE (expected: hidden) -- see the defect note in "
           "docs/architecture/transactions_mvcc.md\n",
           kd_visible ? "STILL VISIBLE (defect reproduced)" : "hidden");

    qihse_mvcc_store_destroy(store);
    qihse_txn_manager_destroy(mgr);
    printf("PASS mvcc visibility: snapshot isolation, uncommitted/aborted versions, delete, vacuum\n");
}

/* ── 3. SAVEPOINT ───────────────────────────────────────────────────────── */

static void test_savepoints(void) {
    qihse_txn_manager_t* mgr = qihse_txn_manager_create();
    assert(mgr);
    qihse_txn_t* t = qihse_txn_begin(mgr, QIHSE_ISO_READ_COMMITTED);
    assert(t);

    assert(qihse_txn_savepoint(mgr, t, "sp1") == 0);
    assert(qihse_txn_record_write(t, 0, "a", 1) == 0);
    assert(t->write_count == 1);
    assert(qihse_txn_savepoint(mgr, t, "sp2") == 0);
    assert(qihse_txn_record_write(t, 0, "b", 1) == 0);
    assert(qihse_txn_record_read(t, 0, "c", 1) == 0);
    assert(t->write_count == 2);
    assert(t->rw_count == 3);

    assert(qihse_txn_rollback_to_savepoint(mgr, t, "sp2") == 0);
    assert(t->write_count == 1);
    /* The read survives; the write issued after sp2 does not. */
    assert(t->rw_count == 2);

    assert(qihse_txn_rollback_to_savepoint(mgr, t, "sp1") == 0);
    assert(t->write_count == 0);
    assert(t->rw_count == 1);

    assert(qihse_txn_rollback_to_savepoint(mgr, t, "never_created") == -1);
    assert(qihse_txn_savepoint(mgr, t, NULL) == -1);

    /* A savepoint may not be created on a finished transaction. */
    assert(qihse_txn_commit(mgr, t) == 0);
    assert(qihse_txn_savepoint(mgr, t, "after_commit") == -1);

    qihse_txn_manager_destroy(mgr);
    printf("PASS savepoints: create, rollback-to-savepoint, write-set trim\n");
}

/* ── 4. WAL append and replay ───────────────────────────────────────────── */

typedef struct {
    int count;
    uint64_t last_lsn;
    bool lsn_monotonic;
    int inserts;
    int begins;
    int commits;
    char last_key[64];
    char last_value[64];
} wal_scan_t;

static bool wal_scan_cb(const qihse_wal_record_t* rec,
                        const void* key, uint32_t key_len,
                        const void* value, uint32_t value_len,
                        void* user_data) {
    wal_scan_t* s = (wal_scan_t*)user_data;
    if (s->count > 0 && rec->lsn <= s->last_lsn) s->lsn_monotonic = false;
    s->last_lsn = rec->lsn;
    s->count++;
    if (rec->op_type == QIHSE_WAL_OP_INSERT ||
        rec->op_type == QIHSE_WAL_OP_UPDATE) {
        if (rec->op_type == QIHSE_WAL_OP_INSERT) s->inserts++;
        if (key_len < sizeof(s->last_key) && value_len < sizeof(s->last_value)) {
            memcpy(s->last_key, key, key_len);
            s->last_key[key_len] = '\0';
            memcpy(s->last_value, value, value_len);
            s->last_value[value_len] = '\0';
        }
    } else if (rec->op_type == QIHSE_WAL_OP_BEGIN) {
        s->begins++;
    } else if (rec->op_type == QIHSE_WAL_OP_COMMIT) {
        s->commits++;
    }
    return true;
}

static void test_wal_append_replay(void) {
    char dir[] = "build/test_txn_wal_XXXXXX";
    assert(mkdtemp(dir));

    qihse_wal_t* wal = qihse_wal_create(dir, 64 * 1024,
                                        QIHSE_WAL_DURABILITY_FDATASYNC);
    assert(wal);

    uint64_t lsn_begin = qihse_wal_append_begin(wal, 7);
    uint64_t lsn_ins = qihse_wal_append(wal, 7, QIHSE_MVCC_ENGINE_KV,
                                        QIHSE_WAL_OP_INSERT,
                                        "key/one", 7, "value-one", 9);
    uint64_t lsn_upd = qihse_wal_append(wal, 7, QIHSE_MVCC_ENGINE_KV,
                                        QIHSE_WAL_OP_UPDATE,
                                        "key/one", 7, "value-two", 9);
    uint64_t lsn_commit = qihse_wal_append_commit(wal, 7);
    assert(lsn_begin && lsn_ins && lsn_upd && lsn_commit);
    assert(lsn_begin < lsn_ins && lsn_ins < lsn_upd && lsn_upd < lsn_commit);
    assert(qihse_wal_current_lsn(wal) == lsn_commit + 1);

    wal_scan_t scan;
    memset(&scan, 0, sizeof(scan));
    scan.lsn_monotonic = true;
    assert(qihse_wal_replay(wal, 0, wal_scan_cb, &scan) == 4);
    assert(scan.count == 4 && scan.lsn_monotonic);
    assert(scan.begins == 1 && scan.inserts == 1 && scan.commits == 1);
    assert(strcmp(scan.last_key, "key/one") == 0);
    assert(strcmp(scan.last_value, "value-two") == 0);
    assert(scan.last_lsn == lsn_commit);

    /* start_lsn filters earlier records. */
    wal_scan_t tail;
    memset(&tail, 0, sizeof(tail));
    tail.lsn_monotonic = true;
    assert(qihse_wal_replay(wal, lsn_upd, wal_scan_cb, &tail) == 2);
    assert(tail.count == 2 && tail.last_lsn == lsn_commit);

    /* A CRC mismatch stops replay instead of returning corrupt data.
     * Corrupt the checksum field (offset 26 in the 30-byte record header) of
     * the first record; replay must stop there and report nothing. */
    qihse_wal_destroy(wal);
    char path[512];
    snprintf(path, sizeof(path), "%s/wal_%020lu.log", dir, 0UL);
    FILE* f = fopen(path, "r+b");
    assert(f);
    assert(fseek(f, 26, SEEK_SET) == 0);
    unsigned char bad = 0xFF;
    assert(fwrite(&bad, 1, 1, f) == 1);
    assert(fclose(f) == 0);

    qihse_wal_t* reopened = qihse_wal_create(dir, 64 * 1024,
                                             QIHSE_WAL_DURABILITY_NONE);
    assert(reopened);
    wal_scan_t corrupt;
    memset(&corrupt, 0, sizeof(corrupt));
    corrupt.lsn_monotonic = true;
    int n = qihse_wal_replay(reopened, 0, wal_scan_cb, &corrupt);
    assert(n == 0);
    assert(corrupt.count == 0);

    /* Checkpoint bookkeeping. */
    assert(qihse_wal_checkpoint(reopened, lsn_commit) == 0);
    assert(qihse_wal_last_checkpoint(reopened) == lsn_commit);

    qihse_wal_destroy(reopened);
    remove_wal_dir(dir);
    printf("PASS WAL: append ordering, CRC-checked replay, start-LSN filter, checkpoint\n");
}

/* ── 5. Crash recovery ──────────────────────────────────────────────────── */

static void test_crash_recovery(void) {
    char dir[] = "build/test_txn_rec_XXXXXX";
    assert(mkdtemp(dir));

    /* Transaction 10 commits; transaction 11 never does. */
    qihse_wal_t* wal = qihse_wal_create(dir, 64 * 1024,
                                        QIHSE_WAL_DURABILITY_FDATASYNC);
    assert(wal);
    assert(qihse_wal_append_begin(wal, 10) != 0);
    assert(qihse_wal_append(wal, 10, QIHSE_MVCC_ENGINE_KV, QIHSE_WAL_OP_INSERT,
                            "committed", 9, "durable", 7) != 0);
    assert(qihse_wal_append_commit(wal, 10) != 0);
    assert(qihse_wal_append_begin(wal, 11) != 0);
    assert(qihse_wal_append(wal, 11, QIHSE_MVCC_ENGINE_KV, QIHSE_WAL_OP_INSERT,
                            "uncommitted", 11, "lost", 4) != 0);
    qihse_wal_destroy(wal);

    qihse_txn_manager_t* mgr = qihse_txn_manager_create();
    qihse_mvcc_store_t* store = qihse_mvcc_store_create(64);
    qihse_wal_t* wal2 = qihse_wal_create(dir, 64 * 1024,
                                         QIHSE_WAL_DURABILITY_NONE);
    assert(mgr && store && wal2);

    qihse_recovery_t* rec = qihse_recovery_create(mgr, store, wal2);
    assert(rec);
    assert(qihse_recovery_replay(rec) == 0);

    assert(qihse_recovery_committed_count(rec) == 1);
    assert(qihse_recovery_aborted_count(rec) == 1);
    assert(qihse_recovery_txn_committed(rec, 10));
    assert(!qihse_recovery_txn_committed(rec, 11));
    assert(qihse_recovery_txn_aborted(rec, 11));
    assert(!qihse_recovery_txn_aborted(rec, 10));
    assert(qihse_txn_is_committed(mgr, 10));
    assert(qihse_txn_is_aborted(mgr, 11));

    /* Redo applied the committed insert to the MVCC store. */
    const void* val = NULL;
    size_t len = 0;
    assert(qihse_mvcc_read(store, QIHSE_MVCC_ENGINE_KV, "committed", 9, 10,
                           committed_cb, mgr, &val, &len));
    assert(len == 7 && memcmp(val, "durable", 7) == 0);

    /* The uncommitted insert is invisible even to a snapshot that includes it. */
    assert(!qihse_mvcc_read(store, QIHSE_MVCC_ENGINE_KV, "uncommitted", 11, 11,
                            committed_cb, mgr, NULL, NULL));

    /* Recovery keeps transaction IDs monotonic. */
    qihse_txn_t* next = qihse_txn_begin(mgr, QIHSE_ISO_READ_COMMITTED);
    assert(next && next->id > 11);
    assert(qihse_txn_commit(mgr, next) == 0);

    /* Checkpoint runs the flush callback and records an LSN. */
    assert(qihse_recovery_checkpoint(rec, NULL, NULL) == 0);
    assert(qihse_wal_last_checkpoint(wal2) > 0);

    qihse_recovery_destroy(rec);
    qihse_wal_destroy(wal2);
    qihse_mvcc_store_destroy(store);
    qihse_txn_manager_destroy(mgr);
    remove_wal_dir(dir);
    printf("PASS crash recovery: analysis/redo/undo, committed visible, uncommitted aborted\n");
}

/* ── 6. SERIALIZABLE OCC ────────────────────────────────────────────────── */

static void test_serializable_occ(void) {
    qihse_txn_manager_t* mgr = qihse_txn_manager_create();
    assert(mgr);

    /* Write-write conflict: both transactions write key "x". */
    qihse_txn_t* a = qihse_txn_begin(mgr, QIHSE_ISO_SERIALIZABLE);
    assert(a && qihse_txn_record_write(a, 0, "x", 1) == 0);
    qihse_txn_t* b = qihse_txn_begin(mgr, QIHSE_ISO_SERIALIZABLE);
    assert(b && qihse_txn_record_write(b, 0, "x", 1) == 0);
    assert(qihse_txn_commit(mgr, a) == -1);
    assert(a->state == QIHSE_TXN_ABORTED);
    assert(qihse_txn_is_aborted(mgr, a->id));
    assert(qihse_txn_commit(mgr, b) == 0);

    /* Read-write conflict: one reads what the other writes. */
    qihse_txn_t* c = qihse_txn_begin(mgr, QIHSE_ISO_SERIALIZABLE);
    assert(c && qihse_txn_record_read(c, 0, "y", 1) == 0);
    qihse_txn_t* d = qihse_txn_begin(mgr, QIHSE_ISO_SERIALIZABLE);
    assert(d && qihse_txn_record_write(d, 0, "y", 1) == 0);
    assert(qihse_txn_commit(mgr, c) == -1);
    assert(qihse_txn_is_aborted(mgr, c->id));
    assert(qihse_txn_commit(mgr, d) == 0);

    /* Disjoint keys commit cleanly. */
    qihse_txn_t* e = qihse_txn_begin(mgr, QIHSE_ISO_SERIALIZABLE);
    qihse_txn_t* f = qihse_txn_begin(mgr, QIHSE_ISO_SERIALIZABLE);
    assert(e && f);
    assert(qihse_txn_record_write(e, 0, "e-key", 5) == 0);
    assert(qihse_txn_record_write(f, 1, "f-key", 5) == 0);
    assert(qihse_txn_validate_occ(mgr, e) == 0);
    assert(qihse_txn_commit(mgr, e) == 0);
    assert(qihse_txn_commit(mgr, f) == 0);

    /* Non-serializable levels skip validation entirely. */
    qihse_txn_t* g = qihse_txn_begin(mgr, QIHSE_ISO_READ_COMMITTED);
    qihse_txn_t* h = qihse_txn_begin(mgr, QIHSE_ISO_READ_COMMITTED);
    assert(g && h);
    assert(qihse_txn_record_write(g, 0, "same", 4) == 0);
    assert(qihse_txn_record_write(h, 0, "same", 4) == 0);
    assert(qihse_txn_commit(mgr, g) == 0);
    assert(qihse_txn_commit(mgr, h) == 0);

    qihse_txn_manager_destroy(mgr);
    printf("PASS SERIALIZABLE OCC: read-write and write-write conflicts abort, disjoint commits\n");
}

/* ── 7. Two-phase commit ────────────────────────────────────────────────── */

typedef struct {
    int prepares;
    int commits;
    int aborts;
    int fail_prepare;
} participant_state_t;

static int part_prepare(void* ctx, uint64_t txn_id) {
    (void)txn_id;
    participant_state_t* s = (participant_state_t*)ctx;
    s->prepares++;
    return s->fail_prepare;
}
static int part_commit(void* ctx, uint64_t txn_id) {
    (void)txn_id;
    ((participant_state_t*)ctx)->commits++;
    return 0;
}
static int part_abort(void* ctx, uint64_t txn_id) {
    (void)txn_id;
    ((participant_state_t*)ctx)->aborts++;
    return 0;
}

static void test_two_phase_commit(void) {
    qihse_txn_manager_t* mgr = qihse_txn_manager_create();
    assert(mgr);

    participant_state_t p1 = {0}, p2 = {0};
    qihse_txn_participant_t e1 = {0};
    e1.engine_id = QIHSE_MVCC_ENGINE_KV;
    e1.engine_ctx = &p1;
    e1.prepare = part_prepare;
    e1.commit = part_commit;
    e1.abort = part_abort;
    qihse_txn_participant_t e2 = e1;
    e2.engine_id = QIHSE_MVCC_ENGINE_DOCUMENT;
    e2.engine_ctx = &p2;
    assert(qihse_txn_register_participant(mgr, e1) == 0);
    assert(qihse_txn_register_participant(mgr, e2) == 0);

    qihse_txn_t* t = qihse_txn_begin(mgr, QIHSE_ISO_READ_COMMITTED);
    assert(t);
    assert(qihse_txn_prepare(mgr, t) == 0);
    assert(t->state == QIHSE_TXN_PREPARED);
    assert(p1.prepares == 1 && p2.prepares == 1);
    assert(qihse_txn_commit_prepared(mgr, t) == 0);
    assert(t->state == QIHSE_TXN_COMMITTED);
    assert(p1.commits == 1 && p2.commits == 1);
    assert(qihse_txn_is_committed(mgr, t->id));

    /* A participant that refuses to prepare aborts the transaction. */
    p1.fail_prepare = 1;
    qihse_txn_t* u = qihse_txn_begin(mgr, QIHSE_ISO_READ_COMMITTED);
    assert(u);
    assert(qihse_txn_prepare(mgr, u) == -1);
    assert(u->state == QIHSE_TXN_ABORTED);
    assert(qihse_txn_is_aborted(mgr, u->id));

    /* Explicit abort of a prepared transaction calls every participant. */
    p1.fail_prepare = 0;
    int aborts_before = p1.aborts;
    qihse_txn_t* v = qihse_txn_begin(mgr, QIHSE_ISO_READ_COMMITTED);
    assert(v);
    assert(qihse_txn_prepare(mgr, v) == 0);
    assert(qihse_txn_abort_prepared(mgr, v) == 0);
    assert(v->state == QIHSE_TXN_ABORTED);
    assert(p1.aborts == aborts_before + 1);
    /* commit_prepared on a non-prepared transaction is refused. */
    assert(qihse_txn_commit_prepared(mgr, v) == -1);

    qihse_txn_manager_destroy(mgr);
    printf("PASS 2PC: prepare/commit_prepared/abort_prepared, failing prepare aborts\n");
}

int main(void) {
    test_lifecycle();
    test_mvcc_visibility();
    test_savepoints();
    test_wal_append_replay();
    test_crash_recovery();
    test_serializable_occ();
    test_two_phase_commit();
    printf("test_txn: all transaction tests passed\n");
    return 0;
}
