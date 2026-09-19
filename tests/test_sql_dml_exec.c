/*
 * test_sql_dml_exec.c — SQL UPDATE / DELETE execution against the mutable
 * table store.
 *
 * This is the execution half of the UPDATE/DELETE gap.  Parsing UPDATE SET
 * assignments and DELETE WHERE conditions was already covered by
 * tests/test_sql_completeness.c; nothing consumed them.  These tests drive the
 * UWP SQL EXECUTE path with SQL text, so the statement is parsed, the
 * structured AST (ast->set_columns / set_values / num_set and
 * ast->where_conditions) is executed against src/tractable/qihse_table_store.c,
 * and the reply reports the number of rows actually changed.
 *
 * Covered:
 *   - UPDATE executes and honours =, <>, <, >, <=, >=, LIKE, ILIKE, AND chains,
 *     a qualified target alias (x.id), update-all with no WHERE, and a WHERE
 *     keyword inside a string literal in the SET clause;
 *   - DELETE executes, honours the WHERE conditions, and reports truthful
 *     counts (a second identical DELETE reports rows=0);
 *   - THE ZERO-CONDITION DELETE GUARD: a DELETE whose WHERE clause parsed to
 *     zero conditions (aliased/lost filter, NOT, parentheses) REFUSES and
 *     changes nothing, and an unqualified DELETE refuses rather than becoming
 *     a match-all.  This is asserted directly, because the executor used to
 *     treat zero conditions as match-all and that was nearly a data-loss bug;
 *   - A ZERO-ASSIGNMENT UPDATE refuses at the executor as well as at the
 *     parser;
 *   - refusals for anything the row-store predicate cannot represent safely:
 *     OR, parentheses, NOT, NOT LIKE, IN, BETWEEN, IS NULL, malformed tails,
 *     unknown columns, expression SET values, and non-literal values;
 *   - write-permission enforcement: a non-operator without a grant is refused
 *     and nothing changes; a grant on the table's resource id allows it.
 *
 * The row store is process-wide and lazily created (see
 * qihse_uwp_sql_table_store()); this test populates it directly because the
 * INSERT path still targets the append-only column store.
 */
#include "qihse_uwp.h"
#include "qihse_uwp_sql_txn_schema.h"
#include "qihse_sql_parser.h"
#include "qihse_table_store.h"
#include "qihse_auth.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

/* ── Reply capture ──────────────────────────────────────────────────────── */

typedef struct {
    char   data[2048];
    size_t len;
} uwp_reply_buf_t;

static ssize_t test_write(void* ctx, const void* data, size_t len) {
    uwp_reply_buf_t* out = (uwp_reply_buf_t*)ctx;
    size_t room = sizeof(out->data) - 1 - out->len;
    size_t copy = len < room ? len : room;
    memcpy(out->data + out->len, data, copy);
    out->len += copy;
    out->data[out->len] = '\0';
    return (ssize_t)len;
}

/* Execute one SQL statement through the UWP SQL EXECUTE opcode.  Returns the
 * dispatch result; the reply (OK text or ERR_*) is captured in out. */
static uwp_sts_result_t run_sql(qihse_uwp_context_t* ctx, qihse_user_t* user,
                                const char* sql, uwp_reply_buf_t* out) {
    qihse_txn_t* txn = NULL;
    memset(out, 0, sizeof(*out));
    return uwp_dispatch_sql(ctx, 0x02, (const uint8_t*)sql, strlen(sql) + 1,
                            &txn, user, -1, test_write, out);
}

static void expect_reply(const uwp_reply_buf_t* out, const char* needle) {
    if (!strstr(out->data, needle)) {
        fprintf(stderr, "FAIL: expected reply containing '%s', got: %s\n",
                needle, out->data);
        assert(0);
    }
}

/* ── Table fixtures ─────────────────────────────────────────────────────── */

static void insert_row(qihse_table_t* table, int32_t id, const char* name,
                       int32_t n) {
    qihse_col_value_t values[3];
    memset(values, 0, sizeof(values));
    values[0].type = QIHSE_TS_INT32;
    values[0].v.i32 = id;
    values[1].type = QIHSE_TS_STRING;
    values[1].v.str = (char*)name;
    values[2].type = QIHSE_TS_INT32;
    values[2].v.i32 = n;
    assert(qihse_table_insert(table, values, 3) >= 0);
}

static qihse_table_t* make_table(const char* name) {
    qihse_col_def_t cols[3] = {
        {(char*)"id",   QIHSE_TS_INT32},
        {(char*)"name", QIHSE_TS_STRING},
        {(char*)"n",    QIHSE_TS_INT32},
    };
    qihse_table_store_t* store = qihse_uwp_sql_table_store();
    assert(store != NULL);
    qihse_table_t* table = qihse_table_store_create_table(store, name, cols, 3);
    assert(table != NULL);
    return table;
}

typedef struct {
    int32_t     id;
    int         found;
    const char* name;
    int32_t     n;
} row_probe_t;

static bool probe_row(const qihse_col_value_t* values, size_t num_cols,
                      void* ctx) {
    row_probe_t* probe = (row_probe_t*)ctx;
    if (num_cols < 3) return false;
    if (values[0].type != QIHSE_TS_INT32 || values[0].v.i32 != probe->id)
        return true;
    probe->found = 1;
    probe->name = values[1].type == QIHSE_TS_STRING ? values[1].v.str : NULL;
    probe->n = values[2].type == QIHSE_TS_INT32 ? values[2].v.i32 : -999999;
    return false;
}

static void expect_row(qihse_table_t* table, int32_t id, const char* name,
                       int32_t n) {
    row_probe_t probe;
    memset(&probe, 0, sizeof(probe));
    probe.id = id;
    qihse_table_scan(table, probe_row, &probe);
    assert(probe.found);
    if (name) assert(probe.name && strcmp(probe.name, name) == 0);
    assert(probe.n == n);
}

static void expect_row_absent(qihse_table_t* table, int32_t id) {
    row_probe_t probe;
    memset(&probe, 0, sizeof(probe));
    probe.id = id;
    qihse_table_scan(table, probe_row, &probe);
    assert(!probe.found);
}

/* FNV-1a 32-bit, the same derivation the executor uses for the ACL resource
 * id of a table name (namespace 0), matching the KV / column / document
 * targets. */
static uint64_t table_resource_id(const char* name) {
    uint32_t h = 2166136261u;
    for (const char* p = name; *p; p++) {
        h ^= (unsigned char)*p;
        h *= 16777619u;
    }
    return (uint64_t)h;
}

/* ── UPDATE execution ───────────────────────────────────────────────────── */

static void test_update_executes(qihse_uwp_context_t* ctx, qihse_user_t* user) {
    qihse_table_t* table = make_table("t_up");
    insert_row(table, 1, "alice", 10);
    insert_row(table, 2, "bob", 20);
    insert_row(table, 3, "carol", 30);

    uwp_reply_buf_t reply;
    assert(run_sql(ctx, user, "UPDATE t_up SET n = 42 WHERE id = 2", &reply) == UWP_STS_OK);
    expect_reply(&reply, "OK stmt_type=UPDATE rows=1");
    /* The count is the rows actually changed, not a matched-document count. */
    assert(strstr(reply.data, "matched=") == NULL);
    expect_row(table, 1, "alice", 10);
    expect_row(table, 2, "bob", 42);
    expect_row(table, 3, "carol", 30);
    assert(qihse_table_row_count(table) == 3);

    assert(run_sql(ctx, user, "UPDATE t_up SET name = 'robert' WHERE id = 2", &reply) == UWP_STS_OK);
    expect_reply(&reply, "OK stmt_type=UPDATE rows=1");
    expect_row(table, 2, "robert", 42);

    /* Range operators and an AND chain. */
    assert(run_sql(ctx, user, "UPDATE t_up SET n = 99 WHERE id >= 2", &reply) == UWP_STS_OK);
    expect_reply(&reply, "OK stmt_type=UPDATE rows=2");
    expect_row(table, 1, "alice", 10);
    expect_row(table, 2, "robert", 99);
    expect_row(table, 3, "carol", 99);

    assert(run_sql(ctx, user,
                   "UPDATE t_up SET n = 1 WHERE name LIKE 'a%' AND id <= 1",
                   &reply) == UWP_STS_OK);
    expect_reply(&reply, "OK stmt_type=UPDATE rows=1");
    expect_row(table, 1, "alice", 1);

    assert(run_sql(ctx, user, "UPDATE t_up SET n = 5 WHERE n <> 1", &reply) == UWP_STS_OK);
    expect_reply(&reply, "OK stmt_type=UPDATE rows=2");

    /* No WHERE at all: a legitimate update-all. */
    assert(run_sql(ctx, user, "UPDATE t_up SET n = 7", &reply) == UWP_STS_OK);
    expect_reply(&reply, "OK stmt_type=UPDATE rows=3");
    expect_row(table, 1, "alice", 7);
    expect_row(table, 2, "robert", 7);
    expect_row(table, 3, "carol", 7);

    printf("PASS sql dml: UPDATE executes against the row store with truthful "
           "row counts\n");
}

static void test_update_qualified_and_quoted(qihse_uwp_context_t* ctx,
                                             qihse_user_t* user) {
    qihse_table_t* table = make_table("t_qq");
    insert_row(table, 1, "alice", 10);
    insert_row(table, 2, "bob", 20);

    uwp_reply_buf_t reply;

    /* An aliased target: the parser drops the alias and keeps x.id, which the
     * row store resolves on the column's last component. */
    assert(run_sql(ctx, user, "UPDATE t_qq AS x SET n = 8 WHERE x.id = 1", &reply) == UWP_STS_OK);
    expect_reply(&reply, "OK stmt_type=UPDATE rows=1");
    expect_row(table, 1, "alice", 8);

    /* A WHERE keyword inside a SET string literal must not be mistaken for the
     * clause boundary. */
    assert(run_sql(ctx, user, "UPDATE t_qq SET name = 'where x' WHERE id = 2", &reply) == UWP_STS_OK);
    expect_reply(&reply, "OK stmt_type=UPDATE rows=1");
    expect_row(table, 2, "where x", 20);

    printf("PASS sql dml: qualified target alias and quoted WHERE text in SET\n");
}

static void test_update_refusals(qihse_uwp_context_t* ctx, qihse_user_t* user) {
    qihse_table_t* table = make_table("t_ref");
    insert_row(table, 1, "alice", 10);
    insert_row(table, 2, "bob", 20);
    insert_row(table, 3, "carol", 30);

    uwp_reply_buf_t reply;
    const char* refusals[] = {
        /* expression right-hand side: the store applies constants, so an
         * expression must refuse rather than store "n + 1" as text */
        "UPDATE t_ref SET n = n + 1 WHERE id = 1",
        /* unknown SET column */
        "UPDATE t_ref SET nosuch = 1 WHERE id = 1",
        /* a SET value that names a column is an expression, not a literal; the
         * AST cannot record quoting, so it refuses rather than storing the
         * column name as text.  A quoted literal that happens to equal a
         * column name is refused too (conservative direction). */
        "UPDATE t_ref SET name = id WHERE id = 1",
        "UPDATE t_ref SET name = 'id' WHERE id = 1",
        /* unknown WHERE column */
        "UPDATE t_ref SET n = 1 WHERE nosuch = 1",
        /* OR: the AST has no connector, so the parser's two conditions would
         * otherwise be ANDed into a different match set */
        "UPDATE t_ref SET n = 1 WHERE id = 1 OR id = 2",
        /* parentheses: the parser stops at '(' and drops the rest */
        "UPDATE t_ref SET n = 1 WHERE (id = 1)",
        "UPDATE t_ref SET n = 1 WHERE id = 1 AND (id = 2)",
        /* NOT: the parser drops the condition entirely */
        "UPDATE t_ref SET n = 1 WHERE NOT id = 1",
        /* NOT LIKE loses its negation in the parser (operator comes back as
         * LIKE), so the raw clause cannot verify */
        "UPDATE t_ref SET n = 1 WHERE id NOT LIKE 'a%'",
        /* malformed tail the parser silently stopped at */
        "UPDATE t_ref SET n = 1 WHERE id = 1 b = 2",
        "UPDATE t_ref SET n = 1 WHERE id = 1 AND b =",
        /* operators the predicate cannot evaluate faithfully */
        "UPDATE t_ref SET n = 1 WHERE id IS NULL",
        "UPDATE t_ref SET n = 1 WHERE id BETWEEN 1 AND 2",
        "UPDATE t_ref SET n = 1 WHERE id IN (1,2)",
    };
    for (size_t i = 0; i < sizeof(refusals) / sizeof(refusals[0]); i++) {
        uwp_sts_result_t rc = run_sql(ctx, user, refusals[i], &reply);
        if (rc != UWP_STS_OK) {
            fprintf(stderr, "FAIL: '%s' was rejected before execution: %s\n",
                    refusals[i], reply.data);
            assert(0);
        }
        expect_reply(&reply, "refused:");
        expect_reply(&reply, "no rows changed");
        expect_reply(&reply, "OK stmt_type=UPDATE");
    }
    /* Nothing was mutated by any refusal. */
    assert(qihse_table_row_count(table) == 3);
    expect_row(table, 1, "alice", 10);
    expect_row(table, 2, "bob", 20);
    expect_row(table, 3, "carol", 30);

    /* A zero-assignment UPDATE is refused by the parser ... */
    uwp_sts_result_t rc = run_sql(ctx, user, "UPDATE t_ref SET", &reply);
    assert(rc != UWP_STS_OK);
    expect_reply(&reply, "ERR_PARSE");
    assert(qihse_table_row_count(table) == 3);

    /* ... and the executor refuses one too, for any caller that builds an AST
     * without going through the parser. */
    qihse_sql_ast_t zero_set;
    memset(&zero_set, 0, sizeof(zero_set));
    zero_set.stmt_type = QIHSE_SQL_UPDATE;
    zero_set.table_name = (char*)"t_ref";
    zero_set.limit = -1;
    zero_set.offset = -1;
    char* dml_reply = qihse_uwp_sql_execute_dml(&zero_set, user);
    assert(dml_reply != NULL);
    assert(strstr(dml_reply, "refused: zero SET assignments") != NULL);
    assert(strstr(dml_reply, "no rows changed") != NULL);
    free(dml_reply);
    assert(qihse_table_row_count(table) == 3);
    expect_row(table, 1, "alice", 10);

    printf("PASS sql dml: UPDATE refusals (expression, unknown column, OR, "
           "parentheses, NOT, malformed tail, IS/BETWEEN/IN, zero assignments) "
           "change nothing\n");
}

/* ── DELETE execution ───────────────────────────────────────────────────── */

static void test_delete_executes(qihse_uwp_context_t* ctx, qihse_user_t* user) {
    qihse_table_t* table = make_table("t_del");
    insert_row(table, 1, "alice", 10);
    insert_row(table, 2, "bob", 20);
    insert_row(table, 3, "carol", 30);

    uwp_reply_buf_t reply;
    assert(run_sql(ctx, user, "DELETE FROM t_del WHERE id = 2", &reply) == UWP_STS_OK);
    expect_reply(&reply, "OK stmt_type=DELETE rows=1");
    assert(strstr(reply.data, "matched=") == NULL);
    assert(qihse_table_row_count(table) == 2);
    expect_row_absent(table, 2);
    expect_row(table, 1, "alice", 10);
    expect_row(table, 3, "carol", 30);

    assert(run_sql(ctx, user, "DELETE FROM t_del WHERE name = 'carol'", &reply) == UWP_STS_OK);
    expect_reply(&reply, "OK stmt_type=DELETE rows=1");
    assert(qihse_table_row_count(table) == 1);
    expect_row_absent(table, 3);

    /* A predicate that matches nothing reports zero. */
    assert(run_sql(ctx, user, "DELETE FROM t_del WHERE id <> 1", &reply) == UWP_STS_OK);
    expect_reply(&reply, "OK stmt_type=DELETE rows=0");
    assert(qihse_table_row_count(table) == 1);

    /* RETURNING is not part of the WHERE clause. */
    assert(run_sql(ctx, user, "DELETE FROM t_del WHERE id = 1 RETURNING *", &reply) == UWP_STS_OK);
    expect_reply(&reply, "OK stmt_type=DELETE rows=1");
    assert(qihse_table_row_count(table) == 0);

    /* Re-running the same DELETE is idempotent: it now reports zero. */
    assert(run_sql(ctx, user, "DELETE FROM t_del WHERE id = 1", &reply) == UWP_STS_OK);
    expect_reply(&reply, "OK stmt_type=DELETE rows=0");

    printf("PASS sql dml: DELETE executes against the row store with truthful "
           "row counts and is idempotent\n");
}

/* THE critical guard: a DELETE with zero parsed conditions must refuse, never
 * match-all. */
static void test_delete_zero_condition_guard(qihse_uwp_context_t* ctx,
                                             qihse_user_t* user) {
    qihse_table_t* table = make_table("t_guard");
    insert_row(table, 1, "alice", 10);
    insert_row(table, 2, "bob", 20);
    insert_row(table, 3, "carol", 30);

    uwp_reply_buf_t reply;

    /* (a) unqualified DELETE: refused, not a match-all. */
    assert(run_sql(ctx, user, "DELETE FROM t_guard", &reply) == UWP_STS_OK);
    expect_reply(&reply, "OK stmt_type=DELETE");
    expect_reply(&reply, "refused: zero WHERE conditions");
    expect_reply(&reply, "no rows changed");
    assert(qihse_table_row_count(table) == 3);

    /* (b) a WHERE clause that parsed to zero conditions -- the aliased-DELETE
     * class of lost filter -- refuses and changes nothing. */
    const char* lost_filters[] = {
        "DELETE FROM t_guard WHERE NOT id = 1",
        "DELETE FROM t_guard WHERE (id = 1)",
    };
    for (size_t i = 0; i < sizeof(lost_filters) / sizeof(lost_filters[0]); i++) {
        assert(run_sql(ctx, user, lost_filters[i], &reply) == UWP_STS_OK);
        expect_reply(&reply, "OK stmt_type=DELETE");
        expect_reply(&reply, "refused:");
        expect_reply(&reply, "no rows changed");
        assert(qihse_table_row_count(table) == 3);
    }

    /* (c) conditions that parsed but do not match the raw clause refuse. */
    const char* unverifiable[] = {
        "DELETE FROM t_guard WHERE id = 1 OR id = 2",
        "DELETE FROM t_guard WHERE id = 1 b = 2",
        "DELETE FROM t_guard WHERE id = 1 AND (id = 2)",
        "DELETE FROM t_guard WHERE id IN (1,2)",
    };
    for (size_t i = 0; i < sizeof(unverifiable) / sizeof(unverifiable[0]); i++) {
        assert(run_sql(ctx, user, unverifiable[i], &reply) == UWP_STS_OK);
        expect_reply(&reply, "refused:");
        expect_reply(&reply, "no rows changed");
        assert(qihse_table_row_count(table) == 3);
    }

    /* (d) a hand-built AST with zero conditions and no raw SQL refuses. */
    qihse_sql_ast_t zero_cond;
    memset(&zero_cond, 0, sizeof(zero_cond));
    zero_cond.stmt_type = QIHSE_SQL_DELETE;
    zero_cond.table_name = (char*)"t_guard";
    zero_cond.limit = -1;
    zero_cond.offset = -1;
    char* dml_reply = qihse_uwp_sql_execute_dml(&zero_cond, user);
    assert(dml_reply != NULL);
    assert(strstr(dml_reply, "refused: zero WHERE conditions") != NULL);
    free(dml_reply);
    assert(qihse_table_row_count(table) == 3);

    /* (e) a hand-built AST whose raw text has a WHERE but no parsed conditions
     * (a lost filter) refuses with the lost-filter reason. */
    qihse_sql_ast_t lost;
    memset(&lost, 0, sizeof(lost));
    lost.stmt_type = QIHSE_SQL_DELETE;
    lost.table_name = (char*)"t_guard";
    lost.raw_sql = (char*)"DELETE FROM t_guard WHERE id = 1";
    lost.limit = -1;
    lost.offset = -1;
    dml_reply = qihse_uwp_sql_execute_dml(&lost, user);
    assert(dml_reply != NULL);
    assert(strstr(dml_reply, "WHERE clause present but no conditions were "
                             "parsed") != NULL);
    free(dml_reply);
    assert(qihse_table_row_count(table) == 3);

    /* Every row survived the guard; a real filtered DELETE still works. */
    expect_row(table, 1, "alice", 10);
    expect_row(table, 2, "bob", 20);
    expect_row(table, 3, "carol", 30);
    assert(run_sql(ctx, user, "DELETE FROM t_guard WHERE id = 1", &reply) == UWP_STS_OK);
    expect_reply(&reply, "OK stmt_type=DELETE rows=1");
    assert(qihse_table_row_count(table) == 2);

    printf("PASS sql dml: zero-condition DELETE refuses (no match-all, no lost "
           "filter) and changes nothing\n");
}

/* ── Permission enforcement ─────────────────────────────────────────────── */

static void test_write_permission(qihse_uwp_context_t* ctx,
                                  qihse_user_t* operator_user) {
    qihse_table_t* table = make_table("t_acl");
    insert_row(table, 1, "alice", 10);
    insert_row(table, 2, "bob", 20);

    qihse_user_t* analyst = qihse_auth_create_user(
        operator_user, 100, QIHSE_ROLE_ANALYST, 0, 0, "dml-acl-password", false);
    assert(analyst != NULL);

    uwp_reply_buf_t reply;

    /* Without a grant the analyst is refused and nothing changes. */
    assert(run_sql(ctx, analyst, "DELETE FROM t_acl WHERE id = 1", &reply) == UWP_STS_OK);
    expect_reply(&reply, "refused: no write access to table t_acl");
    assert(qihse_table_row_count(table) == 2);

    assert(run_sql(ctx, analyst, "UPDATE t_acl SET n = 5 WHERE id = 1", &reply) == UWP_STS_OK);
    expect_reply(&reply, "refused: no write access to table t_acl");
    expect_row(table, 1, "alice", 10);

    /* A WRITE grant on the table's resource id allows both. */
    assert(qihse_auth_grant_object(operator_user, analyst, 0,
                                   table_resource_id("t_acl"), QIHSE_ACL_WRITE));
    assert(run_sql(ctx, analyst, "UPDATE t_acl SET n = 5 WHERE id = 1", &reply) == UWP_STS_OK);
    expect_reply(&reply, "OK stmt_type=UPDATE rows=1");
    expect_row(table, 1, "alice", 5);

    assert(run_sql(ctx, analyst, "DELETE FROM t_acl WHERE id = 2", &reply) == UWP_STS_OK);
    expect_reply(&reply, "OK stmt_type=DELETE rows=1");
    assert(qihse_table_row_count(table) == 1);

    printf("PASS sql dml: non-operator without a WRITE grant is refused; a "
           "grant allows it\n");
}

static void test_missing_table(qihse_uwp_context_t* ctx, qihse_user_t* user) {
    uwp_reply_buf_t reply;
    assert(run_sql(ctx, user, "UPDATE t_absent SET n = 1 WHERE id = 1", &reply) == UWP_STS_OK);
    expect_reply(&reply, "not found in the SQL row store");
    assert(run_sql(ctx, user, "DELETE FROM t_absent WHERE id = 1", &reply) == UWP_STS_OK);
    expect_reply(&reply, "not found in the SQL row store");
    printf("PASS sql dml: statements against a table not in the row store are "
           "refused without changing anything\n");
}

int main(void) {
    qihse_auth_init();
    qihse_user_t* operator_user = qihse_auth_get_user(0);
    assert(operator_user != NULL);

    /* The SQL dispatcher only requires ctx->sql_engine to be non-NULL; the
     * executor does not dereference it (the row store is process-wide). */
    qihse_uwp_context_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    static int sql_engine_placeholder;
    ctx.sql_engine = &sql_engine_placeholder;

    test_update_executes(&ctx, operator_user);
    test_update_qualified_and_quoted(&ctx, operator_user);
    test_update_refusals(&ctx, operator_user);
    test_delete_executes(&ctx, operator_user);
    test_delete_zero_condition_guard(&ctx, operator_user);
    test_write_permission(&ctx, operator_user);
    test_missing_table(&ctx, operator_user);

    printf("test_sql_dml_exec: all SQL UPDATE/DELETE execution tests passed\n");
    return 0;
}
