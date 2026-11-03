/* Durable SQL table store: ACK / SIGKILL crash-recovery regression.
 *
 * The roadmap durability gate for the PostgreSQL-replacement path requires
 * acknowledged operation IDs to survive kill/restart: a commit_group_retry
 * that returned COMMITTED (or a plain durable commit_group) must leave rows
 * and retry receipts recoverable after SIGKILL with no orderly destroy, and
 * an unacknowledged (uncommitted) shadow must leave no partial state.
 *
 * The parent never opens the store; each writer child is SIGKILLed
 * immediately after the ACK path returns, before any destructor or flush.
 * Verifier children reopen the snapshot independently. */
#include "qihse_table_store.h"

#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static char crash_dir[64];
static char crash_path[80];

static const qihse_col_def_t* item_defs(void) {
    static qihse_col_def_t defs[3];
    defs[0].name = "id";
    defs[0].type = QIHSE_TS_INT32;
    defs[1].name = "name";
    defs[1].type = QIHSE_TS_STRING;
    defs[2].name = "score";
    defs[2].type = QIHSE_TS_INT32;
    return defs;
}

typedef struct {
    int id;
    const char* name;
    int found;
} row_expect_t;

static bool expect_row(const qihse_col_value_t* values, size_t num_cols,
                       void* ctx) {
    row_expect_t* expect = (row_expect_t*)ctx;
    assert(num_cols == 3);
    if (values[0].v.i32 != expect->id) return true;
    assert(values[1].type == QIHSE_TS_STRING && values[1].v.str);
    assert(strcmp(values[1].v.str, expect->name) == 0);
    assert(values[2].type == QIHSE_TS_INT32 && values[2].v.i32 == 17);
    expect->found++;
    return true;
}

static void assert_row(qihse_table_t* table, int id, const char* name) {
    row_expect_t expect = {.id = id, .name = name, .found = 0};
    qihse_table_scan(table, expect_row, &expect);
    assert(expect.found == 1);
}

/* Seed one committed table so later children have a known base state. */
static void seed_store(void) {
    qihse_table_store_t* s = qihse_table_store_open_durable(crash_path);
    assert(s);
    qihse_table_t* t = qihse_table_store_create_table(s, "items",
                                                      item_defs(), 3);
    assert(t);
    qihse_table_t* u = qihse_table_store_create_table(s, "audit",
                                                      item_defs(), 3);
    assert(u);
    qihse_table_store_destroy(s); /* orderly publish of the empty catalog */
}

static qihse_ts_retry_identity_t retry_id(const char* key) {
    qihse_ts_retry_identity_t id = {.key = key, .principal = "crash-user",
                                    .tenant = "crash-tenant"};
    for (size_t i = 0; i < QIHSE_TS_RETRY_DIGEST_SIZE; ++i) id.digest[i] = 7;
    return id;
}

static void insert_row(qihse_table_txn_t* txn, int id, const char* name) {
    qihse_col_value_t row[3] = {
        {.type = QIHSE_TS_INT32, .v.i32 = id},
        {.type = QIHSE_TS_STRING, .v.str = (char*)name},
        {.type = QIHSE_TS_INT32, .v.i32 = 17},
    };
    assert(qihse_table_txn_insert(txn, row, 3) >= 0);
}

/* Case 1: retry commit ACK, then SIGKILL before any reply or destroy. */
static void ack_then_kill(void) {
    qihse_table_store_t* s = qihse_table_store_open_durable(crash_path);
    if (!s) _exit(60);
    qihse_table_t* t = qihse_table_store_find_table(s, "items");
    if (!t) _exit(61);
    qihse_table_txn_t* tx = qihse_table_txn_begin(t);
    if (!tx) _exit(62);
    insert_row(tx, 1, "acked");
    qihse_table_txn_t* group[] = {tx};
    qihse_ts_retry_identity_t id = retry_id("crash-ack-1");
    qihse_ts_retry_outcome_t outcome = {.affected_rows = 1,
                                        .command_count = 1};
    if (qihse_table_txn_commit_group_retry(group, 1, &id, &outcome) !=
        QIHSE_TS_RETRY_COMMITTED)
        _exit(63); /* the ACK itself failed: not a crash subject */
    kill(getpid(), SIGKILL); /* durable fence already crossed at ACK */
    _exit(100);
}

/* Case 2: shadow staged, SIGKILLed BEFORE any commit acknowledgement. */
static void uncommitted_then_kill(void) {
    qihse_table_store_t* s = qihse_table_store_open_durable(crash_path);
    if (!s) _exit(60);
    qihse_table_t* t = qihse_table_store_find_table(s, "items");
    if (!t) _exit(61);
    qihse_table_txn_t* tx = qihse_table_txn_begin(t);
    if (!tx) _exit(62);
    insert_row(tx, 2, "ghost");
    if (qihse_table_txn_row_count(tx) != 2) _exit(64); /* shadow visible */
    kill(getpid(), SIGKILL); /* never acknowledged */
    _exit(100);
}

/* Case 3: multi-table retry group ACK, then SIGKILL. */
static void multi_table_ack_then_kill(void) {
    qihse_table_store_t* s = qihse_table_store_open_durable(crash_path);
    if (!s) _exit(60);
    qihse_table_t* t = qihse_table_store_find_table(s, "items");
    qihse_table_t* u = qihse_table_store_find_table(s, "audit");
    if (!t || !u) _exit(61);
    qihse_table_txn_t* tx = qihse_table_txn_begin(t);
    qihse_table_txn_t* ux = qihse_table_txn_begin(u);
    if (!tx || !ux) _exit(62);
    insert_row(tx, 3, "paired");
    insert_row(ux, 9, "paired-audit");
    qihse_table_txn_t* group[] = {tx, ux};
    qihse_ts_retry_identity_t id = retry_id("crash-ack-multi");
    qihse_ts_retry_outcome_t outcome = {.affected_rows = 2,
                                        .command_count = 2};
    if (qihse_table_txn_commit_group_retry(group, 2, &id, &outcome) !=
        QIHSE_TS_RETRY_COMMITTED)
        _exit(63);
    kill(getpid(), SIGKILL);
    _exit(100);
}

/* Case 4: after the crash, a fresh retry of the same identity must be
 * idempotent — COMMITTED with the original outcome and no reapplication. */
static void verify_and_retry_idempotent(void) {
    qihse_table_store_t* s = qihse_table_store_open_durable(crash_path);
    if (!s) _exit(70);
    qihse_table_t* t = qihse_table_store_find_table(s, "items");
    qihse_table_t* u = qihse_table_store_find_table(s, "audit");
    if (!t || !u) _exit(71);

    /* Case 1 state: acknowledged row + receipt survived the kill. */
    assert_row(t, 1, "acked");
    qihse_ts_retry_identity_t id = retry_id("crash-ack-1");
    qihse_ts_retry_outcome_t looked = {0};
    if (qihse_table_store_retry_lookup(s, &id, &looked) !=
        QIHSE_TS_RETRY_COMMITTED)
        _exit(72);
    if (looked.affected_rows != 1 || looked.command_count != 1) _exit(73);

    /* Case 2 state: the unacknowledged shadow left nothing behind. */
    if (qihse_table_row_count(t) != 2) _exit(74); /* acked row + group row */
    qihse_ts_retry_identity_t ghost = retry_id("crash-ghost");
    if (qihse_table_store_retry_lookup(s, &ghost, &looked) !=
        QIHSE_TS_RETRY_ABSENT)
        _exit(75);

    /* Case 3 state: both tables of the group survived together. */
    assert_row(t, 3, "paired");
    assert_row(u, 9, "paired-audit");
    qihse_ts_retry_identity_t multi = retry_id("crash-ack-multi");
    if (qihse_table_store_retry_lookup(s, &multi, &looked) !=
        QIHSE_TS_RETRY_COMMITTED)
        _exit(76);
    if (looked.affected_rows != 2 || looked.command_count != 2) _exit(77);

    /* Lost-reply recovery: reissuing the identical acknowledged request
     * returns COMMITTED without publishing a second copy. */
    qihse_table_txn_t* tx = qihse_table_txn_begin(t);
    if (!tx) _exit(78);
    insert_row(tx, 1, "acked"); /* same logical write */
    qihse_table_txn_t* group[] = {tx};
    qihse_ts_retry_outcome_t retry_outcome = {.affected_rows = 1,
                                              .command_count = 1};
    if (qihse_table_txn_commit_group_retry(group, 1, &id, &retry_outcome) !=
        QIHSE_TS_RETRY_COMMITTED)
        _exit(79);
    if (qihse_table_row_count(t) != 2) _exit(80); /* not reapplied */
    qihse_table_store_destroy(s);
    _exit(0);
}

static void expect_killed(pid_t pid) {
    int status = 0;
    assert(waitpid(pid, &status, 0) == pid);
    assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
}

static void expect_ok(pid_t pid) {
    int status = 0;
    assert(waitpid(pid, &status, 0) == pid);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fprintf(stderr, "verifier child failed: status=%d exit=%d sig=%d\n",
                status, WIFEXITED(status) ? WEXITSTATUS(status) : -1,
                WIFSIGNALED(status) ? WTERMSIG(status) : -1);
        assert(0);
    }
}

int main(void) {
    assert(mkdir("./build", 0700) == 0 || errno == EEXIST);
    strcpy(crash_dir, "./build/table-crash-XXXXXX");
    assert(mkdtemp(crash_dir));
    assert(snprintf(crash_path, sizeof crash_path, "%s/store", crash_dir) <
           (int)sizeof crash_path);

    seed_store();

    pid_t pid = fork();
    assert(pid >= 0);
    if (pid == 0) ack_then_kill();
    expect_killed(pid);

    pid = fork();
    assert(pid >= 0);
    if (pid == 0) uncommitted_then_kill();
    expect_killed(pid);

    pid = fork();
    assert(pid >= 0);
    if (pid == 0) multi_table_ack_then_kill();
    expect_killed(pid);

    pid = fork();
    assert(pid >= 0);
    if (pid == 0) verify_and_retry_idempotent();
    expect_ok(pid);

    assert(unlink(crash_path) == 0);
    char lock_path[96];
    assert(snprintf(lock_path, sizeof lock_path, "%s.lock", crash_path) <
           (int)sizeof lock_path);
    assert(unlink(lock_path) == 0);
    assert(rmdir(crash_dir) == 0);
    puts("PASS durable table store ACK/SIGKILL: rows, receipts and group "
         "atomicity survive kill; unacknowledged shadows leave no state");
    return 0;
}
