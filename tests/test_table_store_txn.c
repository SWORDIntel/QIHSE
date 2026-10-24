#include "qihse_table_store.h"

#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>

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

int main(void) {
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
    puts("PASS table store optimistic transaction commit, rollback, isolation, group conflict atomicity, and string ownership");
    return 0;
}
