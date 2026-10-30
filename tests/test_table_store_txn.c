#include "qihse_table_store.h"
#include "qihse_schema.h"
#include "qihse_sql_row_index.h"
#include "qihse_auth.h"
#include "qihse_audit.h"

#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <math.h>
#include <sys/syscall.h>

/* Test-only fsync fault: fail exactly once after rename, on the directory. */
static __thread int fail_directory_fsync;
static __thread const char* verify_directory_fsync_target;
static void arm_directory_fsync_failure(void) {
    fail_directory_fsync = 1;
}
int fsync(int fd) {
    struct stat st;
    if (verify_directory_fsync_target && fstat(fd, &st) == 0 && S_ISDIR(st.st_mode)) {
        struct stat published;
        assert(stat(verify_directory_fsync_target, &published) == 0);
        assert(published.st_nlink == 1);
        verify_directory_fsync_target = NULL;
    }
    if (fail_directory_fsync && fstat(fd, &st) == 0 && S_ISDIR(st.st_mode)) {
        fail_directory_fsync = 0;
        errno = EIO;
        return -1;
    }
    return (int)syscall(SYS_fsync, fd);
}

typedef struct {
    int id;
    int found;
    const char* expected_name;
    int expected_score;
} row_expect_t;

static int id_matches(const qihse_col_value_t* values, size_t num_cols,
                      void* ctx) {
    assert(num_cols == 3);
    return values[0].type == QIHSE_TS_INT32 &&
           values[0].v.i32 == *(const int*)ctx;
}

static int match_any_row(const qihse_col_value_t* values, size_t num_cols,
                         void* ctx) {
    (void)values;
    (void)num_cols;
    (void)ctx;
    return 1;
}

static bool expect_row(const qihse_col_value_t* values, size_t num_cols,
                       void* ctx) {
    row_expect_t* expect = (row_expect_t*)ctx;
    assert(num_cols == 3);
    if (values[0].v.i32 != expect->id) return true;
    assert(values[0].type == QIHSE_TS_INT32);
    assert(values[1].type == QIHSE_TS_STRING);
    assert(values[1].v.str != NULL);
    assert(strcmp(values[1].v.str, expect->expected_name) == 0);
    assert(values[2].type == QIHSE_TS_INT32);
    assert(values[2].v.i32 == expect->expected_score);
    expect->found++;
    return true;
}

static void assert_live_row(qihse_table_t* table, int id, const char* name,
                            int score) {
    row_expect_t expect = { id, 0, name, score };
    qihse_table_scan(table, expect_row, &expect);
    assert(expect.found == 1);
}

static void assert_txn_row(qihse_table_txn_t* txn, int id, const char* name,
                           int score) {
    row_expect_t expect = { id, 0, name, score };
    qihse_table_txn_scan(txn, expect_row, &expect);
    assert(expect.found == 1);
}

static void assert_live_absent(qihse_table_t* table, int id) {
    row_expect_t expect = { id, 0, "", 0 };
    qihse_table_scan(table, expect_row, &expect);
    assert(expect.found == 0);
}

static void insert_live(qihse_table_t* table, int id, const char* name,
                        int score) {
    qihse_col_value_t row[3] = {
        { .type = QIHSE_TS_INT32, .v.i32 = id },
        { .type = QIHSE_TS_STRING, .v.str = (char*)name },
        { .type = QIHSE_TS_INT32, .v.i32 = score },
    };
    assert(qihse_table_insert(table, row, 3) >= 0);
}

static void test_rollback_and_read_your_writes(qihse_table_t* table) {
    qihse_table_txn_t* txn = qihse_table_txn_begin(table);
    assert(txn != NULL);

    char name[] = "carol";
    qihse_col_value_t inserted[3] = {
        { .type = QIHSE_TS_INT32, .v.i32 = 3 },
        { .type = QIHSE_TS_STRING, .v.str = name },
        { .type = QIHSE_TS_INT32, .v.i32 = 30 },
    };
    assert(qihse_table_txn_insert(txn, inserted, 3) >= 0);
    name[0] = 'X';

    int id = 1;
    int score_col = 2;
    qihse_col_value_t score = { .type = QIHSE_TS_INT32, .v.i32 = 11 };
    assert(qihse_table_txn_update(txn, id_matches, &id, &score_col, &score, 1));
    id = 2;
    assert(qihse_table_txn_delete(txn, id_matches, &id));

    assert(qihse_table_txn_row_count(txn) == 2);
    assert_txn_row(txn, 1, "alice", 11);
    assert_txn_row(txn, 3, "carol", 30);

    /* The live table cannot see the insert, update, or delete. */
    assert(qihse_table_row_count(table) == 2);
    assert_live_row(table, 1, "alice", 10);
    assert_live_row(table, 2, "bob", 20);
    assert_live_absent(table, 3);

    qihse_table_txn_rollback(txn);
    assert(qihse_table_row_count(table) == 2);
    assert_live_row(table, 1, "alice", 10);
    assert_live_row(table, 2, "bob", 20);
    assert_live_absent(table, 3);
}

static void test_commit_and_string_copy(qihse_table_t* table) {
    qihse_table_txn_t* txn = qihse_table_txn_begin(table);
    assert(txn != NULL);

    int id = 1;
    int name_col = 1;
    char renamed[] = "alicia";
    qihse_col_value_t name = { .type = QIHSE_TS_STRING, .v.str = renamed };
    assert(qihse_table_txn_update(txn, id_matches, &id, &name_col, &name, 1));
    renamed[0] = 'X';

    char inserted_name[] = "dave";
    qihse_col_value_t inserted[3] = {
        { .type = QIHSE_TS_INT32, .v.i32 = 4 },
        { .type = QIHSE_TS_STRING, .v.str = inserted_name },
        { .type = QIHSE_TS_INT32, .v.i32 = 40 },
    };
    assert(qihse_table_txn_insert(txn, inserted, 3) >= 0);
    inserted_name[0] = 'X';

    /* Still invisible before the atomic generation-checked swap. */
    assert_live_row(table, 1, "alice", 10);
    assert_live_absent(table, 4);

    assert(qihse_table_txn_commit(txn));
    assert(qihse_table_row_count(table) == 3);
    assert_live_row(table, 1, "alicia", 10);
    assert_live_row(table, 4, "dave", 40);
}

static void test_conflict_preserves_live_mutation(qihse_table_t* table) {
    qihse_table_txn_t* txn = qihse_table_txn_begin(table);
    assert(txn != NULL);

    qihse_col_value_t shadow_row[3] = {
        { .type = QIHSE_TS_INT32, .v.i32 = 5 },
        { .type = QIHSE_TS_STRING, .v.str = "shadow" },
        { .type = QIHSE_TS_INT32, .v.i32 = 50 },
    };
    assert(qihse_table_txn_insert(txn, shadow_row, 3) >= 0);

    /* This advances the live generation after begin. */
    insert_live(table, 6, "live", 60);
    assert(!qihse_table_txn_commit(txn));

    assert_live_absent(table, 5);
    assert_live_row(table, 6, "live", 60);
}

static void test_failed_update_is_atomic(qihse_table_t* table) {
    int id = 1;
    int name_col = 1;
    qihse_col_value_t invalid = { .type = (qihse_ts_type_t)255 };
    assert(qihse_table_update(table, id_matches, &id, &name_col, &invalid, 1) ==
           -1);
    assert_live_row(table, 1, "alicia", 10);

    qihse_table_txn_t* txn = qihse_table_txn_begin(table);
    assert(txn != NULL);
    assert(qihse_table_txn_update(txn, id_matches, &id, &name_col, &invalid,
                                  1) == -1);
    assert_txn_row(txn, 1, "alicia", 10);
    qihse_table_txn_rollback(txn);
}

static void test_group_commit_is_all_or_nothing(qihse_table_t* first,
                                                 qihse_table_t* second) {
    qihse_table_txn_t* a = qihse_table_txn_begin(first);
    qihse_table_txn_t* b = qihse_table_txn_begin(second);
    assert(a && b);
    qihse_col_value_t ra[3] = {
        { .type = QIHSE_TS_INT32, .v.i32 = 10 },
        { .type = QIHSE_TS_STRING, .v.str = "first-commit" },
        { .type = QIHSE_TS_INT32, .v.i32 = 100 },
    };
    qihse_col_value_t rb[3] = {
        { .type = QIHSE_TS_INT32, .v.i32 = 20 },
        { .type = QIHSE_TS_STRING, .v.str = "second-commit" },
        { .type = QIHSE_TS_INT32, .v.i32 = 200 },
    };
    assert(qihse_table_txn_insert(a, ra, 3) >= 0);
    assert(qihse_table_txn_insert(b, rb, 3) >= 0);
    qihse_table_txn_t* group[] = {a, b};
    assert(qihse_table_txn_commit_group(group, 2));
    assert_live_row(first, 10, "first-commit", 100);
    assert_live_row(second, 20, "second-commit", 200);

    a = qihse_table_txn_begin(first);
    b = qihse_table_txn_begin(second);
    assert(a && b);
    ra[0].v.i32 = 11;
    ra[1].v.str = "must-not-publish";
    rb[0].v.i32 = 21;
    rb[1].v.str = "stale-shadow";
    assert(qihse_table_txn_insert(a, ra, 3) >= 0);
    assert(qihse_table_txn_insert(b, rb, 3) >= 0);
    insert_live(second, 22, "concurrent-live", 220);
    qihse_table_txn_t* conflict_group[] = {a, b};
    assert(!qihse_table_txn_commit_group(conflict_group, 2));
    assert_live_absent(first, 11);
    assert_live_absent(second, 21);
    assert_live_row(second, 22, "concurrent-live", 220);
}

typedef struct {
    pthread_barrier_t* barrier;
    qihse_table_txn_t* txns[2];
    bool committed;
} concurrent_group_t;

static void* commit_group_at_barrier(void* opaque) {
    concurrent_group_t* group = (concurrent_group_t*)opaque;
    (void)pthread_barrier_wait(group->barrier);
    group->committed = qihse_table_txn_commit_group(group->txns, 2);
    return NULL;
}

typedef struct { int id; bool found; } row_find_t;

static bool find_row_id(const qihse_col_value_t* values, size_t num_cols,
                        void* ctx) {
    row_find_t* find = (row_find_t*)ctx;
    assert(num_cols == 3);
    if (values[0].type == QIHSE_TS_INT32 && values[0].v.i32 == find->id) {
        find->found = true;
        return false;
    }
    return true;
}

static bool table_has_id(qihse_table_t* table, int id) {
    row_find_t find = { .id = id, .found = false };
    qihse_table_scan(table, find_row_id, &find);
    return find.found;
}

static void test_concurrent_group_commits(qihse_table_t* first,
                                          qihse_table_t* second) {
    concurrent_group_t a = {0}, b = {0};
    a.txns[0] = qihse_table_txn_begin(first);
    a.txns[1] = qihse_table_txn_begin(second);
    b.txns[0] = qihse_table_txn_begin(first);
    b.txns[1] = qihse_table_txn_begin(second);
    assert(a.txns[0] && a.txns[1] && b.txns[0] && b.txns[1]);
    qihse_col_value_t row_a1[3] = {
        { .type = QIHSE_TS_INT32, .v.i32 = 31 },
        { .type = QIHSE_TS_STRING, .v.str = "group-a" },
        { .type = QIHSE_TS_INT32, .v.i32 = 310 },
    };
    qihse_col_value_t row_a2[3] = {
        { .type = QIHSE_TS_INT32, .v.i32 = 131 },
        { .type = QIHSE_TS_STRING, .v.str = "group-a" },
        { .type = QIHSE_TS_INT32, .v.i32 = 1310 },
    };
    qihse_col_value_t row_b1[3] = {
        { .type = QIHSE_TS_INT32, .v.i32 = 32 },
        { .type = QIHSE_TS_STRING, .v.str = "group-b" },
        { .type = QIHSE_TS_INT32, .v.i32 = 320 },
    };
    qihse_col_value_t row_b2[3] = {
        { .type = QIHSE_TS_INT32, .v.i32 = 132 },
        { .type = QIHSE_TS_STRING, .v.str = "group-b" },
        { .type = QIHSE_TS_INT32, .v.i32 = 1320 },
    };
    assert(qihse_table_txn_insert(a.txns[0], row_a1, 3) >= 0);
    assert(qihse_table_txn_insert(a.txns[1], row_a2, 3) >= 0);
    assert(qihse_table_txn_insert(b.txns[0], row_b1, 3) >= 0);
    assert(qihse_table_txn_insert(b.txns[1], row_b2, 3) >= 0);

    pthread_barrier_t barrier;
    assert(pthread_barrier_init(&barrier, NULL, 3) == 0);
    a.barrier = &barrier;
    b.barrier = &barrier;
    pthread_t ta, tb;
    assert(pthread_create(&ta, NULL, commit_group_at_barrier, &a) == 0);
    assert(pthread_create(&tb, NULL, commit_group_at_barrier, &b) == 0);
    (void)pthread_barrier_wait(&barrier);
    assert(pthread_join(ta, NULL) == 0);
    assert(pthread_join(tb, NULL) == 0);
    pthread_barrier_destroy(&barrier);
    assert(a.committed != b.committed);

    int a1 = 31, a2 = 131, b1 = 32, b2 = 132;
    if (a.committed) {
        assert(table_has_id(first, a1) && table_has_id(second, a2));
        assert(!table_has_id(first, b1) && !table_has_id(second, b2));
    } else {
        assert(table_has_id(first, b1) && table_has_id(second, b2));
        assert(!table_has_id(first, a1) && !table_has_id(second, a2));
    }
}

static void test_durable_snapshot(const qihse_col_def_t* defs) {
    char dir[] = "/tmp/qihse-table-txn-XXXXXX";
    assert(mkdtemp(dir));
    char path[256], tmp[260], lock[261];
    assert(snprintf(path, sizeof path, "%s/store", dir) < (int)sizeof path);
    assert(snprintf(tmp, sizeof tmp, "%s.tmp", path) < (int)sizeof tmp);
    assert(snprintf(lock, sizeof lock, "%s.lock", path) < (int)sizeof lock);
    qihse_table_store_t* s = qihse_table_store_open_durable(path);
    assert(s);
    qihse_table_t* a = qihse_table_store_create_table(s, "a", defs, 3);
    qihse_table_t* b = qihse_table_store_create_table(s, "b", defs, 3);
    assert(a && b);
    qihse_col_value_t ra[3] = {
        { .type = QIHSE_TS_INT32, .v.i32 = 1 },
        { .type = QIHSE_TS_STRING, .v.str = "persistent" },
        { .type = QIHSE_TS_INT32, .v.i32 = 17 },
    };
    assert(qihse_table_insert(a, ra, 3) == -1);
    assert(qihse_table_update(a, id_matches, &ra[0].v.i32,
                              (int[]){2}, &ra[2], 1) == -1);
    assert(!qihse_table_delete(a, id_matches, &ra[0].v.i32));
    qihse_table_txn_t* x = qihse_table_txn_begin(a);
    qihse_table_txn_t* y = qihse_table_txn_begin(b);
    assert(x && y);
    assert(qihse_table_txn_insert(x, ra, 3) >= 0);
    ra[0].v.i32 = 2;
    assert(qihse_table_txn_insert(y, ra, 3) >= 0);
    qihse_table_txn_t* group[] = {x, y};
    assert(qihse_table_txn_commit_group(group, 2));
    pid_t pid = fork();
    assert(pid >= 0);
    if (pid == 0) {
        qihse_table_store_t* locked = qihse_table_store_open_durable(path);
        if (locked) qihse_table_store_destroy(locked);
        qihse_table_txn_t* inherited = qihse_table_txn_begin(a);
        bool rejected = inherited && !qihse_table_txn_commit(inherited);
        _exit(locked || !rejected ? 1 : 0);
    }
    int status;
    assert(waitpid(pid, &status, 0) == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    /* An uncommitted temporary image never supersedes the committed image. */
    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    assert(fd >= 0);
    assert(write(fd, "partial", 7) == 7);
    assert(close(fd) == 0);
    qihse_table_store_destroy(s);
    s = qihse_table_store_open_durable(path);
    assert(s);
    a = qihse_table_store_find_table(s, "a");
    b = qihse_table_store_find_table(s, "b");
    assert(a && b);
    assert_live_row(a, 1, "persistent", 17);
    assert_live_row(b, 2, "persistent", 17);
    x = qihse_table_txn_begin(a);
    y = qihse_table_txn_begin(b);
    assert(x && y);
    ra[0].v.i32 = 3;
    assert(qihse_table_txn_insert(x, ra, 3) >= 0);
    ra[0].v.i32 = 4;
    assert(qihse_table_txn_insert(y, ra, 3) >= 0);
    qihse_table_txn_t* conflict = qihse_table_txn_begin(a);
    assert(conflict);
    char victim[280];
    assert(snprintf(victim, sizeof victim, "%s/victim", dir) < (int)sizeof victim);
    fd = open(victim, O_WRONLY | O_CREAT | O_EXCL, 0600);
    assert(fd >= 0 && write(fd, "untouched", 9) == 9 && close(fd) == 0);
    assert(unlink(tmp) == 0);
    assert(symlink(victim, tmp) == 0);
    assert(qihse_table_txn_commit(conflict));
    char sentinel[9];
    fd = open(victim, O_RDONLY);
    assert(fd >= 0 && read(fd, sentinel, sizeof sentinel) == 9 && close(fd) == 0);
    assert(memcmp(sentinel, "untouched", 9) == 0);
    qihse_table_txn_t* stale[] = {x, y};
    assert(!qihse_table_txn_commit_group(stale, 2));
    qihse_table_store_destroy(s);
    s = qihse_table_store_open_durable(path);
    assert(s);
    assert_live_absent(qihse_table_store_find_table(s, "a"), 3);
    assert_live_absent(qihse_table_store_find_table(s, "b"), 4);
    qihse_table_store_destroy(s);
    /* A successful child commit must survive abrupt process exit. */
    pid = fork();
    assert(pid >= 0);
    if (pid == 0) {
        qihse_table_store_t* child = qihse_table_store_open_durable(path);
        if (!child) _exit(1);
        qihse_table_t* ca = qihse_table_store_find_table(child, "a");
        qihse_table_t* cb = qihse_table_store_find_table(child, "b");
        qihse_table_txn_t* cx = qihse_table_txn_begin(ca);
        qihse_table_txn_t* cy = qihse_table_txn_begin(cb);
        if (!cx || !cy) _exit(2);
        ra[0].v.i32 = 5;
        if (qihse_table_txn_insert(cx, ra, 3) < 0) _exit(3);
        ra[0].v.i32 = 6;
        if (qihse_table_txn_insert(cy, ra, 3) < 0) _exit(4);
        qihse_table_txn_t* pair[] = {cx, cy};
        _exit(qihse_table_txn_commit_group(pair, 2) ? 0 : 5);
    }
    assert(waitpid(pid, &status, 0) == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    s = qihse_table_store_open_durable(path);
    assert(s);
    assert_live_row(qihse_table_store_find_table(s, "a"), 5, "persistent", 17);
    assert_live_row(qihse_table_store_find_table(s, "b"), 6, "persistent", 17);
    qihse_table_store_destroy(s);
    assert(chmod(dir, 0750) == 0);
    assert(qihse_table_store_open_durable(path) == NULL);
    assert(chmod(dir, 0700) == 0);
    assert(chmod(path, 0644) == 0);
    assert(qihse_table_store_open_durable(path) == NULL);
    assert(chmod(path, 0600) == 0);
    assert(chmod(lock, 0644) == 0);
    assert(qihse_table_store_open_durable(path) == NULL);
    assert(chmod(lock, 0600) == 0);
    char real_path[270];
    assert(snprintf(real_path, sizeof real_path, "%s.real", path) < (int)sizeof real_path);
    assert(rename(path, real_path) == 0);
    assert(symlink(real_path, path) == 0);
    assert(qihse_table_store_open_durable(path) == NULL);
    assert(unlink(path) == 0 && rename(real_path, path) == 0);
    /* Corrupt committed images must fail closed, not be treated as empty. */
    fd = open(path, O_RDWR);
    assert(fd >= 0);
    unsigned char byte;
    assert(pread(fd, &byte, 1, 32) == 1);
    byte ^= 1;
    assert(pwrite(fd, &byte, 1, 32) == 1);
    assert(close(fd) == 0);
    assert(qihse_table_store_open_durable(path) == NULL);
    if (unlink(tmp) != 0) assert(errno == ENOENT);
    assert(unlink(victim) == 0);
    assert(unlink(path) == 0);
    assert(unlink(lock) == 0);
    assert(rmdir(dir) == 0);
}

static void test_reject_nonfinite_snapshot(void) {
    char dir[] = "./qihse-float-store-XXXXXX";
    assert(mkdtemp(dir));
    char path[sizeof dir + 16], lock[sizeof dir + 24];
    assert(snprintf(path, sizeof path, "%s/store", dir) < (int)sizeof path);
    assert(snprintf(lock, sizeof lock, "%s.lock", path) < (int)sizeof lock);
    qihse_table_store_t* store = qihse_table_store_open_durable(path);
    assert(store);
    qihse_col_def_t col = {.name="value", .type=QIHSE_TS_FLOAT};
    qihse_table_t* table = qihse_table_store_create_table(store, "floats", &col, 1);
    assert(table);
    qihse_col_value_t row = {.type=QIHSE_TS_FLOAT, .v.f32=1.25f};
    qihse_table_txn_t* txn = qihse_table_txn_begin(table);
    assert(txn && qihse_table_txn_insert(txn, &row, 1) >= 0);
    row.v.f32 = INFINITY;
    assert(qihse_table_txn_insert(txn, &row, 1) < 0);
    assert(qihse_table_txn_commit(txn));
    qihse_table_store_destroy(store);
    int fd = open(path, O_RDWR);
    assert(fd >= 0);
    struct stat st;
    assert(fstat(fd, &st) == 0 && st.st_size > 64);
    size_t size = (size_t)st.st_size;
    unsigned char* bytes = malloc(size);
    assert(bytes && read(fd, bytes, size) == (ssize_t)size);
    size_t offset = 0;
    for (size_t i = 24; i + 24 <= size; ++i) {
        if (bytes[i] == QIHSE_TS_FLOAT &&
            !memcmp(bytes + i + 1, (unsigned char[15]){0}, 15) &&
            bytes[i + 16] == 0 && bytes[i + 17] == 0 &&
            bytes[i + 18] == 0xa0 && bytes[i + 19] == 0x3f &&
            !memcmp(bytes + i + 20, (unsigned char[4]){0}, 4)) {
            assert(!offset);
            offset = i + 16;
        }
    }
    assert(offset);
    const uint32_t bits[] = {UINT32_C(0x7f800000), UINT32_C(0xff800000),
                             UINT32_C(0x7fc00000), UINT32_C(0x3fa00000)};
    for (size_t trial = 0; trial < sizeof bits / sizeof *bits; ++trial) {
        for (size_t j = 0; j < 4; ++j)
            bytes[offset + j] = (unsigned char)(bits[trial] >> (8 * j));
        uint64_t hash = UINT64_C(14695981039346656037);
        for (size_t j = 24; j < size; ++j) {
            hash ^= bytes[j];
            hash *= UINT64_C(1099511628211);
        }
        for (int j = 0; j < 8; ++j)
            bytes[16 + j] = (unsigned char)(hash >> (8 * j));
        assert(pwrite(fd, bytes, size, 0) == (ssize_t)size);
        store = qihse_table_store_open_durable(path);
        if (trial + 1 == sizeof bits / sizeof *bits) {
            assert(store && qihse_table_row_count(qihse_table_store_find_table(store, "floats")) == 1);
            qihse_table_store_destroy(store);
        } else assert(!store);
    }
    free(bytes);
    assert(close(fd) == 0);
    assert(unlink(path) == 0 && unlink(lock) == 0 && rmdir(dir) == 0);
}

static void downgrade_empty_snapshot(const char* path, unsigned char version) {
    int fd = open(path, O_RDWR);
    assert(fd >= 0);
    struct stat st;
    assert(fstat(fd, &st) == 0 && st.st_size > 40);
    size_t size = (size_t)st.st_size;
    unsigned char* bytes = malloc(size);
    assert(bytes && read(fd, bytes, size) == (ssize_t)size);
    assert(bytes[6] == (version == 4 ? 5 : version == 2 ? 4 : version + 1));
    if (version != 4) size -= 8; /* empty v4/v3 ledger, or empty v2 catalog */
    bytes[6] = version;
    uint64_t payload = size - 24;
    uint64_t hash = UINT64_C(14695981039346656037);
    for (size_t i = 24; i < size; ++i) {
        hash ^= bytes[i];
        hash *= UINT64_C(1099511628211);
    }
    for (int i = 0; i < 8; ++i) {
        bytes[8 + i] = (unsigned char)(payload >> (8 * i));
        bytes[16 + i] = (unsigned char)(hash >> (8 * i));
    }
    assert(pwrite(fd, bytes, size, 0) == (ssize_t)size);
    assert(ftruncate(fd, (off_t)size) == 0);
    free(bytes);
    assert(close(fd) == 0);
}

static void test_durable_retry(const qihse_col_def_t* defs) {
    char dir[] = "/tmp/qihse-retry-XXXXXX";
    assert(mkdtemp(dir));
    char path[256], lock[262];
    assert(snprintf(path, sizeof path, "%s/store", dir) < (int)sizeof path);
    assert(snprintf(lock, sizeof lock, "%s.lock", path) < (int)sizeof lock);
    qihse_table_store_t* s = qihse_table_store_open_durable(path);
    assert(s);
    qihse_table_t* t = qihse_table_store_create_table(s, "items", defs, 3);
    assert(t);
    qihse_table_store_destroy(s);
    downgrade_empty_snapshot(path, 4);
    s = qihse_table_store_open_durable(path);
    assert(s && qihse_table_store_find_table(s, "items"));
    qihse_table_store_destroy(s);
    downgrade_empty_snapshot(path, 2);
    s = qihse_table_store_open_durable(path);
    assert(s && qihse_table_store_find_table(s, "items"));
    qihse_table_store_destroy(s);
    downgrade_empty_snapshot(path, 1);
    s = qihse_table_store_open_durable(path);
    assert(s);
    t = qihse_table_store_find_table(s, "items");
    assert(t);
    qihse_ts_retry_identity_t id = {.key = "request-1", .principal = "user-1",
                                    .tenant = "tenant-1", .digest = {17}};
    qihse_ts_retry_outcome_t result = { .affected_rows = 1, .command_count = 1 };
    qihse_ts_retry_outcome_t looked = {0};
    assert(qihse_table_store_retry_lookup(s, &id, &looked) == QIHSE_TS_RETRY_ABSENT);
    char oversized[QIHSE_TS_RETRY_MAX_TEXT + 2];
    memset(oversized, 'x', sizeof oversized - 1);
    oversized[sizeof oversized - 1] = 0;
    qihse_ts_retry_identity_t invalid = id;
    invalid.key = oversized;
    assert(qihse_table_store_retry_lookup(s, &invalid, &looked) == QIHSE_TS_RETRY_ERROR);
    qihse_col_value_t row[3] = {
        { .type = QIHSE_TS_INT32, .v.i32 = 99 },
        { .type = QIHSE_TS_STRING, .v.str = "once" },
        { .type = QIHSE_TS_INT32, .v.i32 = 7 },
    };
    qihse_table_txn_t* tx = qihse_table_txn_begin(t);
    assert(tx && qihse_table_txn_insert(tx, row, 3) >= 0);
    qihse_table_txn_t* group[] = {tx};
    assert(qihse_table_txn_commit_group_retry(group, 1, &id, &result) ==
           QIHSE_TS_RETRY_COMMITTED);
    assert(qihse_table_store_retry_lookup(s, &id, &looked) == QIHSE_TS_RETRY_COMMITTED);
    assert(looked.affected_rows == 1 && looked.command_count == 1);
    qihse_ts_retry_identity_t fenced = id;
    fenced.key = "fenced-request";
    qihse_table_txn_t* stale_tx = qihse_table_txn_begin(t);
    assert(stale_tx && qihse_table_txn_commit(qihse_table_txn_begin(t)));
    qihse_table_txn_t* stale_group[] = {stale_tx};
    assert(qihse_table_txn_commit_group_retry(stale_group, 1, &fenced, &result) ==
           QIHSE_TS_RETRY_ABSENT);
    assert(qihse_table_store_retry_lookup(s, &fenced, &looked) == QIHSE_TS_RETRY_ABSENT);
    tx = qihse_table_txn_begin(t);
    assert(tx && qihse_table_txn_insert(tx, row, 3) >= 0);
    group[0] = tx;
    result.affected_rows = 42;
    assert(qihse_table_txn_commit_group_retry(group, 1, &id, &result) ==
           QIHSE_TS_RETRY_COMMITTED);
    assert(result.affected_rows == 1 && qihse_table_row_count(t) == 1);
    qihse_ts_retry_identity_t wrong = id;
    wrong.principal = "user-2";
    assert(qihse_table_store_retry_lookup(s, &wrong, &looked) == QIHSE_TS_RETRY_MISMATCH);
    wrong = id;
    wrong.tenant = "tenant-2";
    assert(qihse_table_store_retry_lookup(s, &wrong, &looked) == QIHSE_TS_RETRY_MISMATCH);
    wrong = id;
    wrong.digest[0]++;
    tx = qihse_table_txn_begin(t);
    assert(tx && qihse_table_txn_insert(tx, row, 3) >= 0);
    group[0] = tx;
    assert(qihse_table_txn_commit_group_retry(group, 1, &wrong, &result) ==
           QIHSE_TS_RETRY_MISMATCH);
    assert(qihse_table_row_count(t) == 1);
    qihse_table_store_destroy(s);
    s = qihse_table_store_open_durable(path);
    assert(s);
    t = qihse_table_store_find_table(s, "items");
    assert(t && qihse_table_row_count(t) == 1);
    assert(qihse_table_store_retry_lookup(s, &id, &looked) == QIHSE_TS_RETRY_COMMITTED);
    assert(looked.affected_rows == 1);
    id.key = "ambiguous";
    row[0].v.i32 = 100;
    tx = qihse_table_txn_begin(t);
    assert(tx && qihse_table_txn_insert(tx, row, 3) >= 0);
    group[0] = tx;
    result.affected_rows = 1;
    arm_directory_fsync_failure();
    assert(qihse_table_txn_commit_group_retry(group, 1, &id, &result) ==
           QIHSE_TS_RETRY_ERROR);
    assert(!fail_directory_fsync);
    assert(qihse_table_store_retry_lookup(s, &id, &looked) == QIHSE_TS_RETRY_ERROR);
    qihse_table_store_destroy(s);
    s = qihse_table_store_open_durable(path);
    assert(s);
    t = qihse_table_store_find_table(s, "items");
    assert(t && qihse_table_row_count(t) == 2);
    assert(qihse_table_store_retry_lookup(s, &id, &looked) == QIHSE_TS_RETRY_COMMITTED);
    assert(looked.affected_rows == 1);
    tx = qihse_table_txn_begin(t);
    assert(tx && qihse_table_txn_insert(tx, row, 3) >= 0);
    group[0] = tx;
    assert(qihse_table_txn_commit_group_retry(group, 1, &id, &result) ==
           QIHSE_TS_RETRY_COMMITTED);
    assert(qihse_table_row_count(t) == 2);
    qihse_table_store_destroy(s);
    /* Valid outer checksum must not make a malformed ledger acceptable. */
    int fd = open(path, O_RDWR);
    assert(fd >= 0);
    struct stat st;
    assert(fstat(fd, &st) == 0 && st.st_size > 24);
    unsigned char* bytes = malloc((size_t)st.st_size);
    assert(bytes && read(fd, bytes, (size_t)st.st_size) == st.st_size);
    size_t offset = 0;
    for (size_t i = 32; i + 9 <= (size_t)st.st_size; ++i)
        if (!memcmp(bytes + i, "request-1", 9)) { offset = i; break; }
    assert(offset >= 8);
    memset(bytes + offset - 8, 0xff, 8); /* impossible string length */
    uint64_t hash = UINT64_C(14695981039346656037);
    for (size_t i = 24; i < (size_t)st.st_size; ++i) {
        hash ^= bytes[i];
        hash *= UINT64_C(1099511628211);
    }
    for (int i = 0; i < 8; ++i) bytes[16 + i] = (unsigned char)(hash >> (8 * i));
    assert(pwrite(fd, bytes, (size_t)st.st_size, 0) == st.st_size);
    free(bytes);
    assert(close(fd) == 0);
    assert(qihse_table_store_open_durable(path) == NULL);
    assert(unlink(path) == 0 && unlink(lock) == 0 && rmdir(dir) == 0);
}

typedef struct { int seen; int fail_on; } transform_probe_t;

static bool update_numeric_row(const qihse_col_value_t* old, size_t n,
                               qihse_col_value_t* output, void* arg) {
    transform_probe_t* probe = arg;
    assert(n == 3 && old[1].type == QIHSE_TS_NUMERIC);
    if (++probe->seen == probe->fail_on) return false;
    output[1].v.str = "0.2000";
    return true;
}

static bool expect_numeric_row(const qihse_col_value_t* row, size_t n, void* arg) {
    const char* expected = arg;
    assert(n == 3 && row[1].type == QIHSE_TS_NUMERIC);
    assert(strcmp(row[1].v.str, expected) == 0);
    return true;
}

static void test_exact_typed_transform(qihse_user_t* user) {
    assert(qihse_ts_numeric_valid("0", 10, 0));
    assert(qihse_ts_numeric_valid("-0", 10, 0));
    assert(qihse_ts_numeric_valid("+000", 10, 0));
    assert(qihse_ts_numeric_valid(".0", 4, 4));
    assert(!qihse_ts_numeric_valid(".", 10, 0));
    assert(!qihse_ts_numeric_valid("+", 10, 0));
    assert(qihse_ts_numeric_valid("123456.7890", 10, 4));
    assert(!qihse_ts_numeric_valid("1234567.0000", 10, 4));
    assert(!qihse_ts_numeric_valid("1.23456", 10, 4));
    assert(qihse_ts_numeric_valid("0.1000", 4, 4));
    assert(qihse_ts_numeric_valid("0001", 3, 0));
    assert(qihse_ts_numeric_valid("-000.0001", 4, 4));
    assert(!qihse_ts_numeric_valid("0001.0001", 4, 4));
    assert(!qihse_ts_numeric_valid("0001000", 3, 0));
    assert(!qihse_ts_numeric_valid("0.10000", 4, 4));
    qihse_col_def_t defs[] = {{.name = "id", .type = QIHSE_TS_INT32},
        {.name = "cost", .type = QIHSE_TS_NUMERIC},
        {.name = "search_vector", .type = QIHSE_TS_TSVECTOR}};
    qihse_table_store_t* store = qihse_table_store_create();
    assert(store);
    qihse_table_t* table = qihse_table_store_create_table(store, "typed_transform", defs, 3);
    assert(table);
    qihse_col_value_t row[] = {{.type = QIHSE_TS_INT32, .v.i32 = 1},
        {.type = QIHSE_TS_NUMERIC, .v.str = "0.1000"},
        {.type = QIHSE_TS_TSVECTOR, .v.str = "'alpha':1"}};
    assert(qihse_table_insert(table, row, 3) >= 0);
    row[0].v.i32 = 2;
    assert(qihse_table_insert(table, row, 3) >= 0);
    row[1].v.str = "NaN";
    assert(qihse_table_insert(table, row, 3) < 0);
    row[1].v.str = "0.1000";
    row[2].v.str = "alpha:0";
    assert(qihse_table_insert(table, row, 3) < 0);
    assert(qihse_table_row_count(table) == 2);
    qihse_table_txn_t* txn = qihse_table_txn_begin(table);
    assert(txn);
    transform_probe_t probe = {.fail_on = 2};
    assert(qihse_table_txn_transform(txn, NULL, match_any_row, NULL,
                                     update_numeric_row, &probe) == -1);
    assert(probe.seen == 0);
    assert(qihse_table_txn_transform(txn, user, match_any_row, NULL,
                                     update_numeric_row, &probe) == -1);
    assert(probe.seen == 2);
    assert(qihse_table_txn_scan_user(txn, user, expect_numeric_row, "0.1000"));
    probe.seen = 0;
    probe.fail_on = 0;
    assert(qihse_table_txn_transform(txn, user, match_any_row, NULL,
                                     update_numeric_row, &probe) == 1);
    assert(qihse_table_txn_commit(txn));
    assert(qihse_table_scan_user(table, user, expect_numeric_row, "0.2000"));
    qihse_table_store_destroy(store);
}

static bool transform_low_row_only(const qihse_col_value_t* old, size_t n,
                                   qihse_col_value_t* output, void* arg) {
    int* seen = arg;
    assert(n == 5 && old[3].type == QIHSE_TS_INT32);
    assert(old[3].v.i32 == 0); /* Never disclose the high row to the callback. */
    ++*seen;
    output[1].v.str = "0.2000";
    return true;
}

static bool verify_labeled_scan(const qihse_col_value_t* row, size_t n,
                                void* arg) {
    int* seen = arg;
    assert(n == 5 && row[1].type == QIHSE_TS_NUMERIC);
    assert(strcmp(row[1].v.str, row[3].v.i32 ? "0.1000" : "0.2000") == 0);
    ++*seen;
    return true;
}

static bool verify_low_scan(const qihse_col_value_t* row, size_t n, void* arg) {
    int* seen = arg;
    assert(n == 5 && row[3].v.i32 == 0 &&
           strcmp(row[1].v.str, "0.2000") == 0);
    ++*seen;
    return true;
}

static void test_transform_protected_rows(qihse_user_t* operator,
                                          qihse_user_t* low) {
    const char* name = "typed_labeled_transform";
    qihse_col_def_t defs[] = {
        {.name = "id", .type = QIHSE_TS_INT32},
        {.name = "cost", .type = QIHSE_TS_NUMERIC},
        {.name = "__qihse_tenant_id", .type = QIHSE_TS_INT32},
        {.name = "__qihse_classification", .type = QIHSE_TS_INT32},
        {.name = "__qihse_sci", .type = QIHSE_TS_INT32}
    };
    qihse_table_store_t* store = qihse_table_store_create();
    assert(store);
    qihse_table_t* table = qihse_table_store_create_table(store, name, defs, 5);
    assert(table);
    qihse_col_value_t row[] = {
        {.type = QIHSE_TS_INT32, .v.i32 = 1},
        {.type = QIHSE_TS_NUMERIC, .v.str = "0.1000"},
        {.type = QIHSE_TS_INT32, .v.i32 = 0},
        {.type = QIHSE_TS_INT32, .v.i32 = 3},
        {.type = QIHSE_TS_INT32, .v.i32 = 0}
    };
    assert(qihse_table_insert(table, row, 5) >= 0);
    row[0].v.i32 = 2;
    row[3].v.i32 = 0;
    assert(qihse_table_insert(table, row, 5) >= 0);
    uint32_t resource = 2166136261u;
    for (const unsigned char* p = (const unsigned char*)name; *p; ++p)
        resource = (resource ^ *p) * 16777619u;
    assert(qihse_auth_grant_object(operator, low, 0, resource, QIHSE_ACL_WRITE));
    qihse_table_txn_t* txn = qihse_table_txn_begin(table);
    assert(txn);
    int seen = 0;
    assert(!qihse_table_txn_scan_user(txn, low, verify_low_scan, &seen));
    assert(qihse_table_txn_transform(txn, low, match_any_row, NULL,
                                     transform_low_row_only, &seen) == -1);
    assert(seen == 0);
    qihse_table_txn_rollback(txn);
    assert(qihse_auth_grant_object(operator, low, 0, resource,
                                   QIHSE_ACL_WRITE | QIHSE_ACL_READ));
    txn = qihse_table_txn_begin(table);
    assert(txn);
    assert(qihse_table_txn_transform(txn, low, match_any_row, NULL,
                                     transform_low_row_only, &seen) == 1);
    assert(seen == 1);
    assert(qihse_table_txn_commit(txn));
    assert(qihse_table_row_count(table) == 2);
    seen = 0;
    assert(!qihse_table_scan_user(table, NULL, verify_low_scan, &seen));
    assert(seen == 0);
    assert(qihse_table_scan_user(table, low, verify_low_scan, &seen));
    assert(seen == 1);
    uint64_t generation = 0;
    assert(qihse_table_generation_user(table, low, &generation));
    seen = 0;
    assert(!qihse_table_row_get_user(table, low, generation, 0, verify_low_scan, &seen));
    assert(seen == 0); /* High row ID is not a bypass of the filtered scan. */
    assert(qihse_table_row_get_user(table, low, generation, 1, verify_low_scan, &seen));
    assert(seen == 1);
    assert(!qihse_table_row_get_user(table, low, generation + 1, 1,
                                     verify_low_scan, &seen));
    assert(seen == 1);
    seen = 0;
    assert(qihse_table_scan_user(table, operator, verify_labeled_scan, &seen));
    assert(seen == 2);
    qihse_table_store_destroy(store);
}

static void test_numeric_float_index(qihse_user_t* user) {
    qihse_col_def_t defs[] = {{.name="amount", .type=QIHSE_TS_NUMERIC},
                              {.name="ratio", .type=QIHSE_TS_FLOAT}};
    char dir[] = "./qihse-numeric-zero-XXXXXX";
    assert(mkdtemp(dir));
    char path[sizeof(dir) + 16], lock[sizeof(dir) + 24];
    snprintf(path, sizeof(path), "%s/rows.snap", dir);
    snprintf(lock, sizeof(lock), "%s.lock", path);
    qihse_table_store_t* store = qihse_table_store_open_durable(path);
    assert(store);
    qihse_table_t* table = qihse_table_store_create_table(store, "numeric_keys", defs, 2);
    assert(table);
    qihse_col_value_t row[] = {{.type=QIHSE_TS_NUMERIC, .v.str="+01.00"},
                               {.type=QIHSE_TS_FLOAT, .v.f32=-0.0f}};
    qihse_table_txn_t* txn = qihse_table_txn_begin(table);
    assert(txn && qihse_table_txn_insert(txn, row, 2) >= 0);
    row[0].v.str = "1.0";
    row[1].v.f32 = 0.0f;
    assert(qihse_table_txn_insert(txn, row, 2) >= 0);
    row[0].v.str = "-000.000";
    assert(qihse_table_txn_insert(txn, row, 2) >= 0);
    row[0].v.str = "0";
    assert(qihse_table_txn_insert(txn, row, 2) >= 0);
    assert(qihse_table_txn_commit(txn));
    qihse_table_store_destroy(store);
    store = qihse_table_store_open_durable(path);
    assert(store);
    table = qihse_table_store_find_table(store, "numeric_keys");
    assert(table);
    char* expressions[] = {"amount", "ratio"};
    qihse_schema_index_t definition = {.table_name="numeric_keys",
        .expressions=expressions, .num_expressions=2, .using_method="btree"};
    qihse_sql_row_index_t* index = NULL;
    assert(qihse_sql_row_index_build(&definition, table, NULL, user, &index));
    qihse_col_value_t keys[] = {{.type=QIHSE_TS_NUMERIC, .v.str="1"},
                                {.type=QIHSE_TS_FLOAT, .v.f32=0.0f}};
    size_t* ids = NULL; size_t count = 0;
    assert(qihse_sql_row_index_equal(index, table, NULL, user, keys, 2, &ids, &count));
    assert(count == 2 && ids[0] == 0 && ids[1] == 1);
    free(ids);
    keys[0].v.str = "+0.000";
    keys[1].v.f32 = -0.0f;
    assert(qihse_sql_row_index_equal(index, table, NULL, user, keys, 2, &ids, &count));
    assert(count == 2 && ids[0] == 2 && ids[1] == 3);
    free(ids);
    keys[0].v.str = "not-a-number";
    assert(!qihse_sql_row_index_equal(index, table, NULL, user, keys, 2, &ids, &count));
    qihse_sql_row_index_destroy(index);
    qihse_table_store_destroy(store);
    assert(unlink(path) == 0 && unlink(lock) == 0 && rmdir(dir) == 0);
}

static int indexed_id_matches(const qihse_col_value_t* row, size_t n, void* ctx) {
    assert(n == 5);
    return row[0].v.i32 == *(int*)ctx;
}

static bool indexed_row_seen(const qihse_col_value_t* row, size_t n, void* ctx) {
    int* seen = ctx;
    assert(n == 5 && row[0].type == QIHSE_TS_INT32);
    ++*seen;
    return true;
}

static void test_indexed_txn_shadow(qihse_user_t* operator, qihse_user_t* low) {
    char dir[] = "./qihse-indexed-txn-XXXXXX";
    assert(mkdtemp(dir));
    char path[sizeof dir + 16], lock[sizeof dir + 24];
    assert(snprintf(path, sizeof path, "%s/rows.snap", dir) < (int)sizeof path);
    assert(snprintf(lock, sizeof lock, "%s.lock", path) < (int)sizeof lock);
    const char* name = "indexed_txn_shadow";
    qihse_col_def_t defs[] = {
        {.name="id", .type=QIHSE_TS_INT32},
        {.name="identifier", .type=QIHSE_TS_STRING},
        {.name="__qihse_tenant_id", .type=QIHSE_TS_INT32},
        {.name="__qihse_classification", .type=QIHSE_TS_INT32},
        {.name="__qihse_sci", .type=QIHSE_TS_INT32}
    };
    char* expressions[] = {"identifier"};
    qihse_schema_index_t def = {.table_name="indexed_txn_shadow",
        .expressions=expressions, .num_expressions=1, .using_method="btree"};
    qihse_table_store_t* store = qihse_table_store_open_durable(path);
    assert(store);
    qihse_table_t* table = qihse_table_store_create_table(store, name, defs, 5);
    assert(table);
    uint32_t resource = 2166136261u;
    for (const unsigned char* p = (const unsigned char*)name; *p; ++p)
        resource = (resource ^ *p) * 16777619u;
    assert(qihse_auth_grant_object(operator, low, 0, resource, QIHSE_ACL_READ));
    qihse_table_txn_t* txn = qihse_table_txn_begin_user(table, operator);
    assert(txn);
    qihse_col_value_t row[] = {
        {.type=QIHSE_TS_INT32, .v.i32=1},
        {.type=QIHSE_TS_STRING, .v.str="indexed-person-1"},
        {.type=QIHSE_TS_INT32, .v.i32=0},
        {.type=QIHSE_TS_INT32, .v.i32=0},
        {.type=QIHSE_TS_INT32, .v.i32=0}
    };
    assert(qihse_table_txn_insert(txn, row, 5) == 0);
    row[0].v.i32 = 2;
    row[1].v.str = "indexed-person-2";
    assert(qihse_table_txn_insert(txn, row, 5) == 1);
    qihse_sql_row_index_t* index = NULL;
    assert(qihse_sql_row_index_build(&def, table, txn, operator, &index));
    qihse_col_value_t key = {.type=QIHSE_TS_STRING, .v.str="indexed-person-2"};
    size_t* ids = NULL; size_t count = 0;
    assert(qihse_sql_row_index_equal(index, table, txn, operator, &key, 1, &ids, &count));
    assert(count == 1 && ids[0] == 1);
    uint64_t generation;
    assert(qihse_table_txn_generation_user(txn, operator, &generation));
    int seen = 0;
    assert(qihse_table_txn_row_get_user(txn, operator, generation, ids[0], indexed_row_seen, &seen));
    assert(seen == 1);
    free(ids);
    assert(!qihse_sql_row_index_equal(index, table, txn, NULL, &key, 1, &ids, &count));
    assert(!qihse_sql_row_index_equal(index, table, NULL, operator, &key, 1, &ids, &count));
    assert(!qihse_sql_row_index_equal(index, table, txn, low, &key, 1, &ids, &count));
    row[0].v.i32 = 3;
    assert(qihse_table_txn_insert(txn, row, 5) == 2);
    assert(!qihse_sql_row_index_equal(index, table, txn, operator, &key, 1, &ids, &count));
    assert(!qihse_table_txn_row_get_user(txn, operator, generation, 1, indexed_row_seen, &seen));
    qihse_sql_row_index_destroy(index);
    assert(qihse_sql_row_index_build(&def, table, txn, operator, &index));
    assert(qihse_sql_row_index_equal(index, table, txn, operator, &key, 1, &ids, &count));
    assert(count == 2 && ids[0] == 1 && ids[1] == 2);
    free(ids);
    int col = 1, id = 2;
    qihse_col_value_t updated = {.type=QIHSE_TS_STRING, .v.str="updated-person"};
    assert(qihse_table_txn_update(txn, indexed_id_matches, &id, &col, &updated, 1) == 1);
    assert(!qihse_sql_row_index_equal(index, table, txn, operator, &key, 1, &ids, &count));
    qihse_sql_row_index_destroy(index);
    assert(qihse_sql_row_index_build(&def, table, txn, operator, &index));
    assert(qihse_sql_row_index_equal(index, table, txn, operator, &key, 1, &ids, &count));
    assert(count == 1 && ids[0] == 2);
    free(ids);
    id = 3;
    assert(qihse_table_txn_delete(txn, indexed_id_matches, &id));
    assert(!qihse_sql_row_index_equal(index, table, txn, operator, &key, 1, &ids, &count));
    qihse_sql_row_index_destroy(index);
    row[0].v.i32 = 4;
    row[1].v.str = "restricted-person";
    row[3].v.i32 = 3;
    assert(qihse_table_txn_insert(txn, row, 5) >= 0);
    assert(qihse_sql_row_index_build(&def, table, txn, low, &index));
    key.v.str = "restricted-person";
    assert(qihse_sql_row_index_equal(index, table, txn, low, &key, 1, &ids, &count));
    assert(count == 0 && ids == NULL);
    key.v.str = "indexed-person-1";
    assert(qihse_sql_row_index_equal(index, table, txn, low, &key, 1, &ids, &count));
    assert(count == 1 && ids[0] == 0);
    assert(qihse_table_txn_generation_user(txn, low, &generation));
    seen = 0;
    assert(qihse_table_txn_row_get_user(txn, low, generation, ids[0], indexed_row_seen, &seen));
    assert(seen == 1);
    free(ids);
    assert(!qihse_table_txn_row_get_user(txn, low, generation, 2, indexed_row_seen, &seen));
    assert(seen == 1);
    qihse_sql_row_index_destroy(index);
    assert(qihse_table_txn_commit(txn));
    qihse_table_store_destroy(store);
    store = qihse_table_store_open_durable(path);
    assert(store);
    table = qihse_table_store_find_table(store, name);
    assert(table);
    key.v.str = "indexed-person-2";
    assert(qihse_sql_row_index_build(&def, table, NULL, operator, &index));
    assert(qihse_sql_row_index_equal(index, table, NULL, operator, &key, 1, &ids, &count));
    assert(count == 0);
    free(ids);
    key.v.str = "updated-person";
    assert(qihse_sql_row_index_equal(index, table, NULL, operator, &key, 1, &ids, &count));
    assert(count == 1);
    assert(qihse_table_generation_user(table, operator, &generation));
    seen = 0;
    assert(qihse_table_row_get_user(table, operator, generation, ids[0], indexed_row_seen, &seen));
    assert(seen == 1);
    free(ids);
    qihse_sql_row_index_destroy(index);
    assert(!qihse_table_txn_begin_user(table, low)); /* High row blocks partial snapshot. */
    qihse_table_store_destroy(store);
    assert(unlink(path) == 0 && unlink(lock) == 0 && rmdir(dir) == 0);
}

static uint32_t table_resource(const char* name) {
    uint32_t resource = 2166136261u;
    for (const unsigned char* p = (const unsigned char*)name; *p; ++p)
        resource = (resource ^ *p) * 16777619u;
    return resource;
}

static void test_seeded_publication(const char* auth_dir, qihse_user_t* operator) {
    qihse_user_t* low = qihse_auth_create_tenant_user(operator, 7, 39174,
        QIHSE_ROLE_GUEST, 0, 0, "SeededLowPrincipal1!", false);
    qihse_user_t* other = qihse_auth_create_tenant_user(operator, 8, 39175,
        QIHSE_ROLE_GUEST, 0, 0, "SeededOtherPrincipal1!", false);
    assert(low && other);
    char path[256], lock[264];
    assert(snprintf(path, sizeof path, "%s/seeded", auth_dir) < (int)sizeof path);
    assert(snprintf(lock, sizeof lock, "%s.lock", path) < (int)sizeof lock);
    qihse_schema_registry_t* schema = qihse_schema_registry_create();
    assert(schema);
    uint8_t *expected = NULL, *image = NULL;
    size_t expected_len = 0, image_len = 0;
    assert(qihse_schema_serialize(schema, &expected, &expected_len) == 0);
    qihse_schema_column_t columns[] = {
        {.name="id", .type=QIHSE_TYPE_INT},
        {.name="__qihse_tenant_id", .type=QIHSE_TYPE_INT},
        {.name="__qihse_classification", .type=QIHSE_TYPE_INT},
        {.name="__qihse_sci", .type=QIHSE_TYPE_INT}
    };
    qihse_col_def_t defs[] = {
        {.name="id", .type=QIHSE_TS_INT32},
        {.name="__qihse_tenant_id", .type=QIHSE_TS_INT32},
        {.name="__qihse_classification", .type=QIHSE_TS_INT32},
        {.name="__qihse_sci", .type=QIHSE_TS_INT32}
    };
    assert(qihse_schema_create_materialized_view(schema, "seeded", "SELECT 1",
        columns, 4) == 0);
    assert(qihse_schema_serialize(schema, &image, &image_len) == 0);
    qihse_table_store_t* store = qihse_table_store_open_durable(path);
    assert(store && qihse_table_store_set_schema_image(store, expected, expected_len));
    qihse_col_value_t allowed[] = {
        {.type=QIHSE_TS_INT32, .v.i32=1}, {.type=QIHSE_TS_INT32, .v.i32=7},
        {.type=QIHSE_TS_INT32, .v.i32=0}, {.type=QIHSE_TS_INT32, .v.i32=0}
    };
    qihse_col_value_t forbidden[] = {
        {.type=QIHSE_TS_INT32, .v.i32=2}, {.type=QIHSE_TS_INT32, .v.i32=7},
        {.type=QIHSE_TS_INT32, .v.i32=3}, {.type=QIHSE_TS_INT32, .v.i32=1}
    };
    const qihse_col_value_t* rows[] = {allowed, forbidden};
    qihse_ts_new_table_t table = {.name="seeded", .cols=defs, .num_cols=4,
        .initial_rows=rows, .num_initial_rows=2};
    assert(qihse_auth_grant_object(operator, low, 0, table_resource("seeded"), QIHSE_ACL_WRITE));
    assert(qihse_auth_grant_object(operator, other, 0, table_resource("seeded"), QIHSE_ACL_WRITE));
    assert(!qihse_table_store_create_tables_with_schema(store, &table, 1,
        expected, expected_len, image, image_len));
    assert(!qihse_table_store_create_tables_seeded_with_schema(store, &table, 1,
        NULL, 0, low, expected, expected_len, image, image_len));
    assert(qihse_table_store_table_count(store) == 0);
    table.num_initial_rows = 1;
    rows[0] = forbidden;
    forbidden[3].v.i32 = 0;
    assert(!qihse_table_store_create_tables_seeded_with_schema(store, &table, 1,
        NULL, 0, low, expected, expected_len, image, image_len));
    forbidden[2].v.i32 = 0;
    forbidden[3].v.i32 = 1;
    assert(!qihse_table_store_create_tables_seeded_with_schema(store, &table, 1,
        NULL, 0, low, expected, expected_len, image, image_len));
    rows[0] = allowed;
    assert(!qihse_table_store_create_tables_seeded_with_schema(store, &table, 1,
        NULL, 0, other, expected, expected_len, image, image_len));
    assert(qihse_auth_grant_object(operator, low, 0, table_resource("seeded"), QIHSE_ACL_READ));
    assert(!qihse_table_store_create_tables_seeded_with_schema(store, &table, 1,
        NULL, 0, low, expected, expected_len, image, image_len));
    assert(qihse_auth_grant_object(operator, low, 0, table_resource("seeded"), QIHSE_ACL_WRITE));
    const uint8_t* current = NULL;
    size_t current_len = 0;
    assert(qihse_table_store_table_count(store) == 0 &&
        !qihse_table_store_find_table(store, "seeded") &&
        qihse_table_store_schema_image(store, &current, &current_len) &&
        current_len == expected_len && memcmp(current, expected, current_len) == 0);
    assert(qihse_table_store_create_tables_seeded_with_schema(store, &table, 1,
        NULL, 0, low, expected, expected_len, image, image_len));
    qihse_table_store_destroy(store);
    store = qihse_table_store_open_durable(path);
    assert(store && qihse_table_row_count(qihse_table_store_find_table(store, "seeded")) == 1);
    qihse_table_store_destroy(store);
    free(expected); free(image);
    qihse_schema_registry_destroy(schema);
    assert(unlink(path) == 0 && unlink(lock) == 0);

    assert(snprintf(path, sizeof path, "%s/partial_labels", auth_dir) < (int)sizeof path);
    assert(snprintf(lock, sizeof lock, "%s.lock", path) < (int)sizeof lock);
    schema = qihse_schema_registry_create();
    expected = image = NULL;
    assert(schema && qihse_schema_serialize(schema, &expected, &expected_len) == 0);
    qihse_schema_column_t partial_columns[] = {
        {.name="id", .type=QIHSE_TYPE_INT},
        {.name="__qihse_tenant_id", .type=QIHSE_TYPE_INT}
    };
    qihse_col_def_t partial_defs[] = {
        {.name="id", .type=QIHSE_TS_INT32},
        {.name="__qihse_tenant_id", .type=QIHSE_TS_INT32}
    };
    assert(qihse_schema_create_materialized_view(schema, "partial_labels", "SELECT 1",
        partial_columns, 2) == 0);
    assert(qihse_schema_serialize(schema, &image, &image_len) == 0);
    store = qihse_table_store_open_durable(path);
    assert(store && qihse_table_store_set_schema_image(store, expected, expected_len));
    qihse_col_value_t partial_row[] = {
        {.type=QIHSE_TS_INT32, .v.i32=1},
        {.type=QIHSE_TS_INT32, .v.i32=7}
    };
    const qihse_col_value_t* partial_rows[] = {partial_row};
    qihse_ts_new_table_t partial = {.name="partial_labels", .cols=partial_defs,
        .num_cols=2, .initial_rows=partial_rows, .num_initial_rows=1};
    assert(!qihse_table_store_create_tables_seeded_with_schema(store, &partial, 1,
        NULL, 0, operator, expected, expected_len, image, image_len));
    assert(qihse_table_store_table_count(store) == 0);
    partial.num_initial_rows = 0;
    assert(qihse_table_store_create_tables_with_schema(store, &partial, 1,
        expected, expected_len, image, image_len));
    qihse_table_store_destroy(store);
    store = qihse_table_store_open_durable(path);
    assert(store && qihse_table_store_table_count(store) == 1);
    qihse_table_store_destroy(store);
    free(expected); free(image);
    qihse_schema_registry_destroy(schema);
    assert(unlink(path) == 0 && unlink(lock) == 0);
}

static void test_catalog_name_bijection(void) {
    char dir[] = "./qihse-catalog-bijection-XXXXXX";
    assert(mkdtemp(dir));
    char path[256], lock[264];
    assert(snprintf(path, sizeof path, "%s/store", dir) < (int)sizeof path);
    assert(snprintf(lock, sizeof lock, "%s.lock", path) < (int)sizeof lock);
    qihse_schema_registry_t* schema = qihse_schema_registry_create();
    uint8_t *expected = NULL, *image = NULL;
    size_t expected_len = 0, image_len = 0;
    assert(schema && qihse_schema_serialize(schema, &expected, &expected_len) == 0);
    qihse_schema_column_t column = {.name="id", .type=QIHSE_TYPE_INT};
    assert(qihse_schema_create_materialized_view(schema, "foo", "SELECT 1", &column, 1) == 0);
    assert(qihse_schema_create_materialized_view(schema, "bar", "SELECT 2", &column, 1) == 0);
    assert(qihse_schema_serialize(schema, &image, &image_len) == 0);
    qihse_table_store_t* store = qihse_table_store_open_durable(path);
    assert(store && qihse_table_store_set_schema_image(store, expected, expected_len));
    qihse_col_def_t col = {.name="id", .type=QIHSE_TS_INT32};
    qihse_ts_new_table_t tables[] = {
        {.name="foo", .cols=&col, .num_cols=1},
        {.name="bar", .cols=&col, .num_cols=1}
    };
    assert(qihse_table_store_create_tables_with_schema(store, tables, 2,
        expected, expected_len, image, image_len));
    qihse_table_store_destroy(store);
    int fd = open(path, O_RDWR);
    struct stat st;
    assert(fd >= 0 && fstat(fd, &st) == 0 && st.st_size > 64);
    unsigned char* bytes = malloc((size_t)st.st_size);
    assert(bytes && pread(fd, bytes, (size_t)st.st_size, 0) == st.st_size);
    const unsigned char encoded_bar[] = {3, 0, 0, 0, 0, 0, 0, 0, 'b', 'a', 'r'};
    size_t at = 0;
    for (size_t i = 24; i + sizeof encoded_bar <= (size_t)st.st_size; ++i)
        if (memcmp(bytes + i, encoded_bar, sizeof encoded_bar) == 0) {
            at = i + 8; break;
        }
    assert(at != 0);
    memcpy(bytes + at, "FOO", 3);
    uint64_t hash = UINT64_C(14695981039346656037);
    for (size_t i = 24; i < (size_t)st.st_size; ++i) {
        hash ^= bytes[i];
        hash *= UINT64_C(1099511628211);
    }
    for (int i = 0; i < 8; ++i) bytes[16 + i] = (unsigned char)(hash >> (8 * i));
    assert(pwrite(fd, bytes, (size_t)st.st_size, 0) == st.st_size);
    free(bytes);
    assert(close(fd) == 0);
    assert(qihse_table_store_open_durable(path) == NULL);
    free(expected); free(image);
    qihse_schema_registry_destroy(schema);
    assert(unlink(path) == 0 && unlink(lock) == 0 && rmdir(dir) == 0);
}

static void test_backup_restore(const qihse_col_def_t* defs) {
    char dir[] = "./qihse-backup-txn-XXXXXX";
    assert(mkdtemp(dir));
    assert(setenv("QIHSE_DATA_DIR", dir, 1) == 0);
    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator("TableStoreBackupOperator1!"));
    qihse_user_t* operator = qihse_auth_get_user(0);
    assert(operator);
    qihse_user_t* guest = qihse_auth_create_user(operator, 39172,
        QIHSE_ROLE_GUEST, 0, 0, "TableStoreBackupGuest1!", false);
    assert(guest);
    qihse_user_t* delegated = qihse_auth_create_user(operator, 39173,
        QIHSE_ROLE_OPERATOR, 0, 0, "TableStoreBackupDelegate1!", false);
    assert(delegated);
    test_seeded_publication(dir, operator);
    test_exact_typed_transform(operator);
    test_numeric_float_index(operator);
    test_transform_protected_rows(operator, guest);
    test_indexed_txn_shadow(operator, guest);
    char original[sizeof dir + 16], backup[sizeof dir + 16], target[sizeof dir + 16];
    char after[sizeof dir + 16];
    assert(snprintf(after, sizeof after, "%s/after", dir) < (int)sizeof after);
    char original_lock[sizeof dir + 24], backup_lock[sizeof dir + 24], target_lock[sizeof dir + 24];
    assert(snprintf(original, sizeof original, "%s/original", dir) < (int)sizeof original);
    assert(snprintf(backup, sizeof backup, "%s/backup", dir) < (int)sizeof backup);
    assert(snprintf(target, sizeof target, "%s/restore", dir) < (int)sizeof target);
    snprintf(original_lock, sizeof original_lock, "%s.lock", original);
    snprintf(backup_lock, sizeof backup_lock, "%s.lock", backup);
    snprintf(target_lock, sizeof target_lock, "%s.lock", target);
    qihse_table_store_t* s = qihse_table_store_open_durable(original);
    assert(s);
    const uint8_t catalog[] = {1, 2, 3, 4};
    assert(qihse_table_store_set_schema_image(s, catalog, sizeof catalog));
    qihse_table_t* t = qihse_table_store_create_table(s, "items", defs, 3);
    assert(t);
    qihse_col_value_t row[] = {{.type=QIHSE_TS_INT32, .v.i32=17},
        {.type=QIHSE_TS_STRING, .v.str="recovered"},
        {.type=QIHSE_TS_INT32, .v.i32=19}};
    qihse_ts_retry_identity_t id = {.key="backup-key", .principal="op", .tenant="system"};
    id.digest[0] = 42;
    qihse_ts_retry_outcome_t outcome = {.affected_rows=1, .command_count=1};
    qihse_table_txn_t* tx = qihse_table_txn_begin(t);
    assert(tx && qihse_table_txn_insert(tx, row, 3) >= 0);
    qihse_table_txn_t* group[] = {tx};
    assert(qihse_table_txn_commit_group_retry(group, 1, &id, &outcome) ==
           QIHSE_TS_RETRY_COMMITTED);
    assert(!qihse_table_store_backup(s, NULL, backup));
    assert(!qihse_table_store_backup(s, guest, backup));
    assert(!qihse_table_store_backup(s, delegated, backup));
    verify_directory_fsync_target = backup;
    assert(qihse_table_store_backup(s, operator, backup));
    assert(!verify_directory_fsync_target);
    assert(!qihse_table_store_backup(s, operator, backup));
    assert(!qihse_table_store_restore(guest, backup, target));
    assert(!qihse_table_store_restore(operator, original, target)); /* writer lock */
    verify_directory_fsync_target = target;
    assert(qihse_table_store_restore(operator, backup, target));
    assert(!verify_directory_fsync_target);
    assert(!qihse_table_store_restore(operator, backup, target));
    char failed_backup[sizeof dir + 32], failed_restore[sizeof dir + 32];
    char failed_backup_lock[sizeof dir + 40], failed_restore_lock[sizeof dir + 40];
    assert(snprintf(failed_backup, sizeof failed_backup, "%s/failed_backup", dir) < (int)sizeof failed_backup);
    assert(snprintf(failed_restore, sizeof failed_restore, "%s/failed_restore", dir) < (int)sizeof failed_restore);
    assert(snprintf(failed_backup_lock, sizeof failed_backup_lock, "%s.lock", failed_backup) < (int)sizeof failed_backup_lock);
    assert(snprintf(failed_restore_lock, sizeof failed_restore_lock, "%s.lock", failed_restore) < (int)sizeof failed_restore_lock);
    arm_directory_fsync_failure();
    assert(!qihse_table_store_backup(s, operator, failed_backup));
    assert(!fail_directory_fsync);
    qihse_table_store_t* uncertain = qihse_table_store_open_durable(failed_backup);
    assert(uncertain && qihse_table_row_count(qihse_table_store_find_table(uncertain, "items")) == 1);
    qihse_table_store_destroy(uncertain);
    arm_directory_fsync_failure();
    assert(!qihse_table_store_restore(operator, backup, failed_restore));
    assert(!fail_directory_fsync);
    uncertain = qihse_table_store_open_durable(failed_restore);
    assert(uncertain && qihse_table_row_count(qihse_table_store_find_table(uncertain, "items")) == 1);
    qihse_table_store_destroy(uncertain);
    assert(unlink(failed_backup) == 0 && unlink(failed_backup_lock) == 0);
    assert(unlink(failed_restore) == 0 && unlink(failed_restore_lock) == 0);
    qihse_table_store_t* recovered = qihse_table_store_open_durable(target);
    assert(recovered);
    assert_live_row(qihse_table_store_find_table(recovered, "items"), 17, "recovered", 19);
    const uint8_t* image = NULL;
    size_t image_len = 0;
    assert(qihse_table_store_schema_image(recovered, &image, &image_len));
    assert(image_len == sizeof catalog && !memcmp(image, catalog, image_len));
    qihse_ts_retry_outcome_t looked = {0};
    assert(qihse_table_store_retry_lookup(recovered, &id, &looked) == QIHSE_TS_RETRY_COMMITTED);
    assert(looked.affected_rows == 1 && looked.command_count == 1);
    assert(!qihse_table_store_restore(operator, backup, target));
    qihse_table_store_destroy(recovered);
    id.key = "uncertain-key";
    row[0].v.i32 = 18;
    tx = qihse_table_txn_begin(t);
    assert(tx && qihse_table_txn_insert(tx, row, 3) >= 0);
    group[0] = tx;
    arm_directory_fsync_failure();
    assert(qihse_table_txn_commit_group_retry(group, 1, &id, &outcome) ==
           QIHSE_TS_RETRY_ERROR);
    assert(!fail_directory_fsync);
    assert(!qihse_table_store_backup(s, operator, after));
    assert(access(after, F_OK) == -1);
    qihse_table_store_destroy(s);
    s = qihse_table_store_open_durable(original);
    assert(s && qihse_table_store_retry_lookup(s, &id, &looked) ==
           QIHSE_TS_RETRY_COMMITTED);
    assert(qihse_table_row_count(qihse_table_store_find_table(s, "items")) == 2);
    qihse_table_store_t* frozen = qihse_table_store_open_durable(backup);
    assert(frozen && qihse_table_row_count(qihse_table_store_find_table(frozen, "items")) == 1);
    assert(qihse_table_store_retry_lookup(frozen, &id, &looked) == QIHSE_TS_RETRY_ABSENT);
    qihse_table_store_destroy(frozen);
    int fd = open(backup, O_RDWR);
    assert(fd >= 0);
    struct stat backup_st;
    assert(fstat(fd, &backup_st) == 0 && backup_st.st_size >= 24);
    unsigned char* corrupted = malloc((size_t)backup_st.st_size);
    assert(corrupted && pread(fd, corrupted, (size_t)backup_st.st_size, 0) == backup_st.st_size);
    corrupted[24] = 0; /* malformed payload with a valid outer checksum */
    uint64_t hash = UINT64_C(14695981039346656037);
    for (size_t i = 24; i < (size_t)backup_st.st_size; ++i) {
        hash ^= corrupted[i];
        hash *= UINT64_C(1099511628211);
    }
    for (int i = 0; i < 8; ++i) corrupted[16 + i] = (unsigned char)(hash >> (8 * i));
    assert(pwrite(fd, corrupted, (size_t)backup_st.st_size, 0) == backup_st.st_size);
    free(corrupted);
    assert(close(fd) == 0);
    assert(!qihse_table_store_restore(operator, backup, target));
    assert(unlink(target) == 0);
    assert(!qihse_table_store_restore(operator, backup, target));
    assert(access(target, F_OK) == -1);
    qihse_table_store_destroy(s);
    assert(unlink(original) == 0 && unlink(original_lock) == 0);
    assert(unlink(backup) == 0 && unlink(backup_lock) == 0);
    assert(unlink(target_lock) == 0);
    /* Drain and stop the asynchronous signer before removing its files; an
     * in-flight append would otherwise recreate the chain beside a stale lock. */
    qihse_audit_shutdown();
    const char* auth_files[] = {"qihse_audit.log", "qihse_audit.writer.lock",
                                "qihse_integrity.chain"};
    for (size_t i = 0; i < sizeof auth_files / sizeof *auth_files; ++i) {
        char file[sizeof dir + 40];
        assert(snprintf(file, sizeof file, "%s/%s", dir, auth_files[i]) < (int)sizeof file);
        int rc = unlink(file);
        assert(rc == 0 || errno == ENOENT);
    }
    assert(rmdir(dir) == 0);
}

static void test_atomic_multi_table_schema(void) {
    char dir[] = "./qihse-multi-ddl-XXXXXX";
    assert(mkdtemp(dir));
    char path[sizeof dir + 16], lock[sizeof dir + 24];
    assert(snprintf(path, sizeof path, "%s/rows.snap", dir) < (int)sizeof path);
    assert(snprintf(lock, sizeof lock, "%s.lock", path) < (int)sizeof lock);
    qihse_table_store_t* store = qihse_table_store_open_durable(path);
    assert(store);
    const uint8_t original[] = {1, 4, 9};
    const uint8_t committed[] = {2, 5, 10};
    const uint8_t uncertain[] = {3, 6, 11};
    assert(qihse_table_store_set_schema_image(store, original, sizeof original));
    qihse_col_def_t col = {.name="id", .type=QIHSE_TS_INT32};
    qihse_ts_new_table_t group[] = {
        {.name="first", .cols=&col, .num_cols=1},
        {.name="second", .cols=&col, .num_cols=1}
    };
    qihse_col_def_t invalid = {.name="id", .type=(qihse_ts_type_t)-1};
    qihse_ts_new_table_t bad = {.name="bad", .cols=&invalid, .num_cols=1};
    assert(!qihse_table_store_create_tables_with_schema(store, &bad, 1,
        original, sizeof original, committed, sizeof committed));
    assert(!qihse_table_store_find_table(store, "bad"));
    uint8_t stale[] = {0};
    assert(!qihse_table_store_create_tables_with_schema(store, group, 2,
        stale, sizeof stale, committed, sizeof committed));
    assert(!qihse_table_store_find_table(store, "first"));
    assert(!qihse_table_store_create_tables_with_schema(store, group, 2,
        original, sizeof original - 1, committed, sizeof committed));
    assert(qihse_table_store_create_tables_with_schema(store, group, 2,
        original, sizeof original, committed, sizeof committed));
    assert(qihse_table_store_table_count(store) == 2);
    assert(!qihse_table_store_create_tables_with_schema(store, group, 2,
        committed, sizeof committed, uncertain, sizeof uncertain));
    assert(qihse_table_store_open_durable(path) == NULL);
    qihse_table_store_destroy(store);
    store = qihse_table_store_open_durable(path);
    assert(store && qihse_table_store_table_count(store) == 2);
    const uint8_t* recovered = NULL;
    size_t size = 0;
    assert(qihse_table_store_schema_image(store, &recovered, &size));
    assert(size == sizeof committed && !memcmp(recovered, committed, size));
    qihse_ts_new_table_t third = {.name="third", .cols=&col, .num_cols=1};
    arm_directory_fsync_failure();
    assert(!qihse_table_store_create_tables_with_schema(store, &third, 1,
        committed, sizeof committed, uncertain, sizeof uncertain));
    assert(!fail_directory_fsync);
    assert(!qihse_table_store_is_durable(store));
    qihse_table_store_destroy(store);
    store = qihse_table_store_open_durable(path);
    assert(store && qihse_table_store_table_count(store) == 3);
    assert(qihse_table_store_find_table(store, "third"));
    assert(qihse_table_store_schema_image(store, &recovered, &size));
    assert(size == sizeof uncertain && !memcmp(recovered, uncertain, size));
    qihse_table_store_destroy(store);
    assert(unlink(path) == 0 && unlink(lock) == 0 && rmdir(dir) == 0);
}

static bool check_typed_rows(const qihse_col_value_t* values, size_t n, void* ctx) {
    size_t* seen = ctx;
    assert(n == 5);
    if ((*seen)++ == 0) {
        assert(!values[0].is_null && !strcmp(values[0].v.str, "01234567-89ab-cdef-0123-456789abcdef"));
        assert(!values[1].is_null && !strcmp(values[1].v.str, "null"));
        assert(!values[2].is_null && values[2].v.boolean);
        assert(!values[3].is_null && values[3].v.timestamptz_us == -1234567);
        assert(!values[4].is_null && values[4].v.str && !*values[4].v.str);
    } else {
        for (size_t i = 0; i < n; ++i) assert(values[i].is_null);
    }
    return true;
}

static void test_typed_nullable_snapshot(void) {
    char dir[] = "/tmp/qihse-typed-store-XXXXXX";
    assert(mkdtemp(dir));
    char path[256], lock[261];
    assert(snprintf(path, sizeof path, "%s/store", dir) < (int)sizeof path);
    assert(snprintf(lock, sizeof lock, "%s.lock", path) < (int)sizeof lock);
    qihse_col_def_t cols[] = {
        {.name="uuid", .type=QIHSE_TS_UUID}, {.name="doc", .type=QIHSE_TS_JSONB},
        {.name="enabled", .type=QIHSE_TS_BOOLEAN},
        {.name="stamp", .type=QIHSE_TS_TIMESTAMPTZ}, {.name="text", .type=QIHSE_TS_STRING}
    };
    qihse_table_store_t* store = qihse_table_store_open_durable(path);
    assert(store);
    qihse_table_t* table = qihse_table_store_create_table(store, "typed", cols, 5);
    assert(table);
    qihse_col_value_t row[5] = {
        {.type=QIHSE_TS_UUID, .v.str="01234567-89ab-cdef-0123-456789abcdef"},
        {.type=QIHSE_TS_JSONB, .v.str="null"},
        {.type=QIHSE_TS_BOOLEAN, .v.boolean=true},
        {.type=QIHSE_TS_TIMESTAMPTZ, .v.timestamptz_us=-1234567},
        {.type=QIHSE_TS_STRING, .v.str=""}
    };
    qihse_table_txn_t* txn = qihse_table_txn_begin(table);
    assert(txn && qihse_table_txn_insert(txn, row, 5) >= 0);

    qihse_col_value_t wrong_row[5];
    memcpy(wrong_row, row, sizeof wrong_row);
    wrong_row[0].type = QIHSE_TS_STRING; /* valid type, wrong schema type */
    wrong_row[0].v.str = "not-a-uuid-column";
    assert(qihse_table_txn_insert(txn, wrong_row, 5) == -1);
    assert(qihse_table_txn_row_count(txn) == 1);

    int uuid_col = 0;
    qihse_col_value_t wrong_null = {.type=QIHSE_TS_STRING, .is_null=true};
    assert(qihse_table_txn_update(txn, match_any_row, NULL, &uuid_col,
                                  &wrong_null, 1) == -1);
    size_t before_valid_update = 0;
    qihse_table_txn_scan(txn, check_typed_rows, &before_valid_update);
    assert(before_valid_update == 1);

    int enabled_col = 2;
    qihse_col_value_t enabled = {.type=QIHSE_TS_BOOLEAN, .v.boolean=true};
    assert(qihse_table_txn_update(txn, match_any_row, NULL, &enabled_col,
                                  &enabled, 1) == 1);
    for (size_t i = 0; i < 5; ++i) { row[i].is_null = true; row[i].v.str = NULL; }
    assert(qihse_table_txn_insert(txn, row, 5) >= 0 && qihse_table_txn_commit(txn));
    qihse_table_store_destroy(store);
    store = qihse_table_store_open_durable(path);
    assert(store);
    table = qihse_table_store_find_table(store, "typed");
    size_t seen = 0;
    assert(table && qihse_table_row_count(table) == 2);
    qihse_table_scan(table, check_typed_rows, &seen);
    assert(seen == 2);
    qihse_table_store_destroy(store);
    assert(unlink(path) == 0 && unlink(lock) == 0 && rmdir(dir) == 0);
}

static void test_read_only_group_validation(void) {
    qihse_table_store_t* store = qihse_table_store_create();
    assert(store);
    qihse_col_def_t col = {.name="value", .type=QIHSE_TS_INT32};
    qihse_col_def_t unsupported = {.name="unsupported", .type=(qihse_ts_type_t)255};
    assert(!qihse_table_store_create_table(store, "unsupported", &unsupported, 1));
    assert(!qihse_table_store_create_table(store, "unnamed", &(qihse_col_def_t){
        .name=NULL, .type=QIHSE_TS_INT32}, 1));
    qihse_table_t* table = qihse_table_store_create_table(store, "read_only", &col, 1);
    assert(table);
    qihse_table_txn_t* writer = qihse_table_txn_begin(table);
    qihse_table_txn_t* reader = qihse_table_txn_begin(table);
    assert(writer && reader);
    qihse_table_txn_t* group[] = {reader};
    assert(qihse_table_txn_validate_group(group, 1));
    qihse_col_value_t row = {.type=QIHSE_TS_INT32, .v.i32=9};
    assert(qihse_table_txn_insert(writer, &row, 1) >= 0);
    assert(qihse_table_txn_commit(writer));
    assert(qihse_table_row_count(table) == 1);
    writer = qihse_table_txn_begin(table);
    reader = qihse_table_txn_begin(table);
    assert(writer && reader);
    row.v.i32 = 10;
    assert(qihse_table_txn_insert(writer, &row, 1) >= 0);
    assert(qihse_table_txn_commit(writer));
    group[0] = reader;
    assert(!qihse_table_txn_validate_group(group, 1));
    assert(qihse_table_row_count(table) == 2);
    qihse_table_store_destroy(store);
}

int main(void) {
    test_atomic_multi_table_schema();
    test_catalog_name_bijection();
    test_typed_nullable_snapshot();
    test_reject_nonfinite_snapshot();
    test_read_only_group_validation();
    qihse_col_def_t defs[3] = {
        { .name = "id", .type = QIHSE_TS_INT32 },
        { .name = "name", .type = QIHSE_TS_STRING },
        { .name = "score", .type = QIHSE_TS_INT32 },
    };
    qihse_table_store_t* store = qihse_table_store_create();
    assert(store != NULL);
    qihse_table_t* table =
        qihse_table_store_create_table(store, "items", defs, 3);
    qihse_table_t* second =
        qihse_table_store_create_table(store, "items_secondary", defs, 3);
    assert(table != NULL);
    assert(second != NULL);
    insert_live(table, 1, "alice", 10);
    insert_live(table, 2, "bob", 20);

    test_rollback_and_read_your_writes(table);
    test_commit_and_string_copy(table);
    test_conflict_preserves_live_mutation(table);
    test_failed_update_is_atomic(table);
    test_group_commit_is_all_or_nothing(table, second);
    test_concurrent_group_commits(table, second);

    qihse_table_store_destroy(store);
    test_durable_snapshot(defs);
    test_durable_retry(defs);
    test_backup_restore(defs);
    puts("PASS table store optimistic transaction commit, rollback, isolation, group conflict atomicity, and string ownership");
    return 0;
}
