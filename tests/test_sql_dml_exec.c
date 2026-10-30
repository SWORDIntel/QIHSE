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
 * qihse_uwp_sql_table_store()); most fixtures populate it directly, and
 * test_insert_populates_row_store verifies the INSERT statement path
 * reaches it.
 */
#include "qihse_uwp.h"
#include "qihse_uwp_sql_txn_schema.h"
#include "qihse_schema.h"
#include "qihse_sql_parser.h"
#include "qihse_table_store.h"
#include "qihse_auth.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

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

static uwp_sts_result_t run_sql_txn(qihse_uwp_context_t* ctx,
                                    qihse_user_t* user, const char* sql,
                                    qihse_txn_t** txn, uwp_reply_buf_t* out) {
    memset(out, 0, sizeof(*out));
    return uwp_dispatch_sql(ctx, 0x02, (const uint8_t*)sql, strlen(sql) + 1,
                            txn, user, -1, test_write, out);
}

static uwp_sts_result_t run_txn_command(qihse_uwp_context_t* ctx,
                                        qihse_user_t* user, uint8_t opcode,
                                        const char* arg, qihse_txn_t** txn,
                                        uwp_reply_buf_t* out) {
    memset(out, 0, sizeof(*out));
    return uwp_dispatch_txn(ctx, opcode, (const uint8_t*)arg,
                            arg ? strlen(arg) + 1 : 0, txn, user, -1,
                            test_write, out);
}

static uwp_sts_result_t run_schema(qihse_uwp_context_t* ctx,
                                   qihse_user_t* user, uint8_t opcode,
                                   const char* arg, uwp_reply_buf_t* out) {
    memset(out, 0, sizeof(*out));
    return uwp_dispatch_schema(ctx, opcode, (const uint8_t*)arg,
                               arg ? strlen(arg) + 1 : 0, user, -1,
                               test_write, out);
}

static void expect_reply(const uwp_reply_buf_t* out, const char* needle) {
    if (!strstr(out->data, needle)) {
        fprintf(stderr, "FAIL: expected reply containing '%s', got: %s\n",
                needle, out->data);
        assert(0);
    }
}

static void expect_reply_absent(const uwp_reply_buf_t* out, const char* needle) {
    if (strstr(out->data, needle)) {
        fprintf(stderr, "FAIL: reply disclosed forbidden marker '%s': %s\n",
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
    assert(run_sql(ctx, user, "UPDATE t_up SET n = 8 WHERE (id = 1)", &reply) == UWP_STS_OK);
    expect_reply(&reply, "OK stmt_type=UPDATE rows=1");
    expect_row(table, 1, "alice", 8);
    assert(run_sql(ctx, user,
                   "UPDATE t_up SET n = 9 WHERE id = 1 AND (id = 2)", &reply) == UWP_STS_OK);
    expect_reply(&reply, "OK stmt_type=UPDATE rows=0");
    expect_row(table, 1, "alice", 8);

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
    assert(run_sql(ctx, user, "UPDATE t_qq SET name = 'id' WHERE id = 2", &reply) == UWP_STS_OK);
    expect_reply(&reply, "OK stmt_type=UPDATE rows=1");
    expect_row(table, 2, "id", 20);

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
        /* An unquoted column reference is still an unsupported expression. */
        "UPDATE t_ref SET name = id WHERE id = 1",
        /* unknown WHERE column */
        "UPDATE t_ref SET n = 1 WHERE nosuch = 1",
        /* OR: the AST has no connector, so the parser's two conditions would
         * otherwise be ANDed into a different match set */
        "UPDATE t_ref SET n = 1 WHERE id = 1 OR id = 2",
        /* Unsupported negation must not drop the condition. */
        "UPDATE t_ref SET n = 1 WHERE NOT id = 1",
        /* NOT LIKE must not be executed as positive LIKE. */
        "UPDATE t_ref SET n = 1 WHERE id NOT LIKE 'a%'",
        /* Malformed tails must not be silently discarded. */
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
            /* Strict parsing may reject an unrepresentable predicate before
             * execution, instead of returning an executable refusal. */
            expect_reply(&reply, "ERR_PARSE");
        } else {
            expect_reply(&reply, "refused:");
            expect_reply(&reply, "no rows changed");
            expect_reply(&reply, "OK stmt_type=UPDATE");
        }
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
           "NOT, malformed tail, IS/BETWEEN/IN, zero assignments) "
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

    /* (b) unsupported negation cannot drop the WHERE condition. */
    uwp_sts_result_t rejected = run_sql(ctx, user,
        "DELETE FROM t_guard WHERE NOT id = 1", &reply);
    if (rejected != UWP_STS_OK) expect_reply(&reply, "ERR_PARSE");
    else {
        expect_reply(&reply, "refused:");
        expect_reply(&reply, "no rows changed");
    }
    assert(qihse_table_row_count(table) == 3);

    /* (c) conditions that parsed but do not match the raw clause refuse. */
    const char* unverifiable[] = {
        "DELETE FROM t_guard WHERE id = 1 OR id = 2",
        "DELETE FROM t_guard WHERE id = 1 b = 2",
        "DELETE FROM t_guard WHERE id IN (1,2)",
    };
    for (size_t i = 0; i < sizeof(unverifiable) / sizeof(unverifiable[0]); i++) {
        rejected = run_sql(ctx, user, unverifiable[i], &reply);
        if (rejected != UWP_STS_OK) expect_reply(&reply, "ERR_PARSE");
        else {
            expect_reply(&reply, "refused:");
            expect_reply(&reply, "no rows changed");
        }
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
    assert(run_sql(ctx, user, "DELETE FROM t_guard WHERE (id = 1)", &reply) == UWP_STS_OK);
    expect_reply(&reply, "OK stmt_type=DELETE rows=1");
    assert(qihse_table_row_count(table) == 2);
    assert(run_sql(ctx, user, "DELETE FROM t_guard WHERE id = 2 AND (id = 3)", &reply) == UWP_STS_OK);
    expect_reply(&reply, "OK stmt_type=DELETE rows=0");
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
    assert(run_sql(ctx, analyst, "DELETE FROM t_acl WHERE id = 1", &reply) == UWP_STS_ERR_PERM);
    expect_reply(&reply, "ERR_PERM");
    assert(qihse_table_row_count(table) == 2);

    assert(run_sql(ctx, analyst, "UPDATE t_acl SET n = 5 WHERE id = 1", &reply) == UWP_STS_ERR_PERM);
    expect_reply(&reply, "ERR_PERM");
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

static void test_statement_authorization(qihse_uwp_context_t* ctx,
                                         qihse_user_t* operator_user) {
    static const char protected_marker[] = "SQL-PROTECTED-MARKER-71e3";
    uwp_reply_buf_t reply;

    qihse_user_t* low = qihse_auth_create_user(
        operator_user, 101, QIHSE_ROLE_GUEST, 0, 0,
        "sql-low-principal-password", false);
    assert(low != NULL);

    assert(run_sql(ctx, operator_user,
                   "CREATE TABLE t_stmt_auth (id INT, name TEXT, n INT)",
                   &reply) == UWP_STS_OK);
    expect_reply(&reply, "OK stmt_type=CREATE");

    assert(run_sql(ctx, operator_user,
                   "INSERT INTO t_stmt_auth VALUES (9, 'SQL-PROTECTED-MARKER-71e3', 99)",
                   &reply) == UWP_STS_OK);
    assert(run_sql(ctx, low,
                   "SELECT name FROM t_stmt_auth WHERE id = 9", &reply) ==
           UWP_STS_ERR_PERM);
    expect_reply(&reply, "ERR_PERM");
    expect_reply_absent(&reply, protected_marker);
    assert(run_sql(ctx, operator_user,
                   "DELETE FROM t_stmt_auth WHERE id = 9", &reply) ==
           UWP_STS_OK);

    /* A live low principal cannot mutate the table or execute DDL before an
     * explicit table WRITE grant.  Denials are protocol errors and never echo
     * the protected value. */
    assert(run_sql(ctx, low,
                   "INSERT INTO t_stmt_auth VALUES (1, 'SQL-PROTECTED-MARKER-71e3', 10)",
                   &reply) == UWP_STS_ERR_PERM);
    expect_reply(&reply, "ERR_PERM");
    expect_reply_absent(&reply, protected_marker);

    assert(run_sql(ctx, low,
                   "UPDATE t_stmt_auth SET name = 'SQL-PROTECTED-MARKER-71e3' WHERE id = 1",
                   &reply) == UWP_STS_ERR_PERM);
    expect_reply_absent(&reply, protected_marker);
    assert(run_sql(ctx, low, "DELETE FROM t_stmt_auth WHERE id = 1", &reply) ==
           UWP_STS_ERR_PERM);

    assert(run_sql(ctx, low,
                   "CREATE TABLE SQL_PROTECTED_MARKER_71e3 (id INT)", &reply) ==
           UWP_STS_ERR_PERM);
    expect_reply_absent(&reply, "SQL_PROTECTED_MARKER_71e3");
    assert(run_sql(ctx, low, "ALTER TABLE t_stmt_auth ADD COLUMN extra INT", &reply) ==
           UWP_STS_ERR_PERM);
    assert(run_sql(ctx, low, "DROP TABLE t_stmt_auth", &reply) == UWP_STS_ERR_PERM);

    qihse_table_t* table =
        qihse_table_store_find_table(qihse_uwp_sql_table_store(), "t_stmt_auth");
    assert(table == NULL || qihse_table_row_count(table) == 0);

    /* A table WRITE grant covers INSERT, UPDATE and DELETE. */
    assert(qihse_auth_grant_object(operator_user, low, 0,
                                   table_resource_id("t_stmt_auth"),
                                   QIHSE_ACL_WRITE));
    assert(run_sql(ctx, low,
                   "INSERT INTO t_stmt_auth VALUES (1, 'allowed', 10)", &reply) ==
           UWP_STS_OK);
    expect_reply(&reply, "OK stmt_type=INSERT rows=1");
    table = qihse_table_store_find_table(qihse_uwp_sql_table_store(),
                                         "t_stmt_auth");
    assert(table != NULL);
    expect_row(table, 1, "allowed", 10);

    assert(run_sql(ctx, low, "SELECT name FROM t_stmt_auth WHERE id = 1",
                   &reply) == UWP_STS_ERR_PERM);
    expect_reply_absent(&reply, "allowed");
    assert(qihse_auth_grant_object(operator_user, low, 0,
                                   table_resource_id("t_stmt_auth"),
                                   QIHSE_ACL_READ | QIHSE_ACL_WRITE));
    assert(run_sql(ctx, low, "SELECT name FROM t_stmt_auth WHERE id = 1",
                   &reply) == UWP_STS_OK);
    expect_reply(&reply, "name\nallowed\nOK stmt_type=SELECT rows=1");

    assert(run_sql(ctx, low, "UPDATE t_stmt_auth SET n = 11 WHERE id = 1", &reply) ==
           UWP_STS_OK);
    expect_row(table, 1, "allowed", 11);
    assert(run_sql(ctx, low, "DELETE FROM t_stmt_auth WHERE id = 1", &reply) ==
           UWP_STS_OK);
    expect_row_absent(table, 1);

    /* NULL and revoked handles fail at the command boundary for every
     * mutation family, even if the revoked principal used to hold WRITE. */
    const char* denied_sql[] = {
        "INSERT INTO t_stmt_auth VALUES (2, 'denied', 20)",
        "UPDATE t_stmt_auth SET n = 20 WHERE id = 2",
        "DELETE FROM t_stmt_auth WHERE id = 2",
        "CREATE TABLE t_null_ddl (id INT)",
        "ALTER TABLE t_stmt_auth ADD COLUMN denied_col INT",
        "DROP TABLE t_stmt_auth",
    };
    for (size_t i = 0; i < sizeof(denied_sql) / sizeof(denied_sql[0]); i++) {
        assert(run_sql(ctx, NULL, denied_sql[i], &reply) == UWP_STS_ERR_PERM);
        expect_reply(&reply, "ERR_PERM");
    }

    assert(qihse_auth_destroy_user(operator_user, 101));
    for (size_t i = 0; i < sizeof(denied_sql) / sizeof(denied_sql[0]); i++) {
        assert(run_sql(ctx, low, denied_sql[i], &reply) == UWP_STS_ERR_PERM);
        expect_reply(&reply, "ERR_PERM");
    }

    /* Operator DDL remains available through the same execution path. */
    assert(run_sql(ctx, operator_user,
                   "ALTER TABLE t_stmt_auth ADD COLUMN operator_col INT", &reply) ==
           UWP_STS_OK);
    expect_reply(&reply, "OK stmt_type=ALTER");
    assert(run_sql(ctx, operator_user, "DROP TABLE t_stmt_auth", &reply) ==
           UWP_STS_OK);
    expect_reply(&reply, "OK stmt_type=DROP");

    printf("PASS sql authorization: active principal revalidation, WRITE-gated "
           "DML, Operator-only DDL, and non-disclosing denials\n");
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

/* ── INSERT populates the row store end to end ────────────────────────────
 * INSERT previously went to the append-only column store only, so a row a
 * client inserted could never be UPDATEd or DELETEd.  The row store is now
 * the insert's authoritative destination — the column-store append remains
 * as the analytic copy. */
static void test_insert_populates_row_store(qihse_uwp_context_t* ctx,
                                            qihse_user_t* user) {
    uwp_reply_buf_t out;

    run_sql(ctx, user,
            "CREATE TABLE t_ins (id INT, name TEXT, n INT)", &out);
    expect_reply(&out, "OK");

    run_sql(ctx, user,
            "INSERT INTO t_ins (id, name, n) VALUES (1, 'alice', 7), "
            "(2, 'bob', 8)", &out);
    expect_reply(&out, "stmt_type=INSERT rows=2");

    /* The rows are in the mutable row store, not only the column store. */
    qihse_table_store_t* store = qihse_uwp_sql_table_store();
    qihse_table_t* table = qihse_table_store_find_table(store, "t_ins");
    assert(table != NULL);
    expect_row(table, 1, "alice", 7);
    expect_row(table, 2, "bob", 8);
    assert(qihse_table_row_count(table) == 2);

    /* ...so UPDATE and DELETE reach them end to end. */
    run_sql(ctx, user, "UPDATE t_ins SET n = 9 WHERE id = 1", &out);
    expect_reply(&out, "rows=1");
    expect_row(table, 1, "alice", 9);

    run_sql(ctx, user, "DELETE FROM t_ins WHERE id = 2", &out);
    expect_reply(&out, "rows=1");
    expect_row_absent(table, 2);
    assert(qihse_table_row_count(table) == 1);

    /* A column subset lands the named columns and type-zero defaults. */
    run_sql(ctx, user,
            "INSERT INTO t_ins (id, name) VALUES (3, 'carol')", &out);
    expect_reply(&out, "rows=1");
    expect_row(table, 3, "carol", 0);

    /* A parsed but unimplemented conflict action must not insert a row or
     * claim success before uniqueness and UPSERT execution are implemented. */
    assert(run_sql(ctx, user,
        "INSERT INTO t_ins (id, name, n) VALUES (4, 'unsupported', 4) "
        "ON CONFLICT (id) DO NOTHING", &out) != UWP_STS_OK);
    expect_reply(&out, "ERR_EXEC");
    expect_row_absent(table, 4);

    assert(run_sql(ctx, user,
                   "SELECT id, name, n FROM t_ins WHERE id = 1 LIMIT 1",
                   &out) == UWP_STS_OK);
    expect_reply(&out, "id\tname\tn\n1\talice\t9\nOK stmt_type=SELECT rows=1");
    assert(run_sql(ctx, user,
                   "SELECT id, name FROM t_ins WHERE id >= 1 OFFSET 1",
                   &out) == UWP_STS_OK);
    expect_reply(&out, "id\tname\n3\tcarol\nOK stmt_type=SELECT rows=1");

    assert(run_sql(ctx, user,
        "CREATE TABLE t_typed (id INT, uid UUID, doc JSONB, enabled BOOLEAN, "
        "created TIMESTAMPTZ, note TEXT)", &out) == UWP_STS_OK);
    assert(run_sql(ctx, user,
        "INSERT INTO t_typed VALUES (7, '01234567-89ab-cdef-0123-456789abcdef', "
        "'true', true, '2024-01-02T03:04:05.123456Z', '')", &out) == UWP_STS_OK);
    assert(run_sql(ctx, user, "SELECT * FROM t_typed", &out) == UWP_STS_OK);
    expect_reply(&out, "id\tuid\tdoc\tenabled\tcreated\tnote\n"
        "7\t01234567-89ab-cdef-0123-456789abcdef\ttrue\ttrue\t"
        "2024-01-02 03:04:05.123456+00\t\nOK stmt_type=SELECT rows=1");
    assert(run_sql(ctx, user,
        "UPDATE t_typed SET uid = NULL, doc = NULL, enabled = NULL, "
        "created = NULL WHERE id = 7", &out) == UWP_STS_OK);
    assert(run_sql(ctx, user, "SELECT * FROM t_typed", &out) == UWP_STS_OK);
    expect_reply(&out, "id\tuid\tdoc\tenabled\tcreated\tnote\n"
        "7\t\\N\t\\N\t\\N\t\\N\t\nOK stmt_type=SELECT rows=1");

    assert(run_sql(ctx, user,
        "CREATE TABLE t_literal_null (id INT, note TEXT DEFAULT 'fallback')",
        &out) == UWP_STS_OK);
    assert(run_sql(ctx, user,
        "INSERT INTO t_literal_null (id, note) VALUES (1, 'NULL'), (2, NULL)",
        &out) == UWP_STS_OK);
    assert(run_sql(ctx, user,
        "INSERT INTO t_literal_null (id) VALUES (3)", &out) == UWP_STS_OK);
    assert(run_sql(ctx, user,
        "SELECT id, note FROM t_literal_null WHERE id = 1", &out) == UWP_STS_OK);
    expect_reply(&out, "id\tnote\n1\tNULL\nOK stmt_type=SELECT rows=1");
    assert(run_sql(ctx, user,
        "SELECT id, note FROM t_literal_null WHERE id = 2", &out) == UWP_STS_OK);
    expect_reply(&out, "id\tnote\n2\t\\N\nOK stmt_type=SELECT rows=1");
    assert(run_sql(ctx, user,
        "SELECT id, note FROM t_literal_null WHERE id = 3", &out) == UWP_STS_OK);
    expect_reply(&out, "id\tnote\n3\tfallback\nOK stmt_type=SELECT rows=1");
    assert(run_sql(ctx, user,
        "UPDATE t_literal_null SET note = 'NULL' WHERE id = 3", &out) == UWP_STS_OK);
    assert(run_sql(ctx, user,
        "UPDATE t_literal_null SET note = 'O''Brien' WHERE id = 1", &out) == UWP_STS_OK);
    assert(run_sql(ctx, user,
        "SELECT note FROM t_literal_null WHERE id = 1", &out) == UWP_STS_OK);
    expect_reply(&out, "note\nO'Brien\nOK stmt_type=SELECT rows=1");
    assert(run_sql(ctx, user,
        "UPDATE t_literal_null SET note = '' WHERE id = 2", &out) == UWP_STS_OK);
    assert(run_sql(ctx, user,
        "SELECT note FROM t_literal_null WHERE id = 2", &out) == UWP_STS_OK);
    expect_reply(&out, "note\n\nOK stmt_type=SELECT rows=1");
    assert(run_sql(ctx, user,
        "UPDATE t_literal_null SET note = DEFAULT WHERE id = 1", &out) == UWP_STS_OK);
    assert(run_sql(ctx, user,
        "SELECT note FROM t_literal_null WHERE id = 1", &out) == UWP_STS_OK);
    expect_reply(&out, "note\nfallback\nOK stmt_type=SELECT rows=1");
    assert(run_sql(ctx, user,
        "CREATE INDEX t_literal_null_note ON t_literal_null(note)", &out) == UWP_STS_OK);
    assert(run_sql(ctx, user,
        "SELECT id FROM t_literal_null WHERE note = 'NULL'", &out) == UWP_STS_OK);
    expect_reply(&out, "id\n3\nOK stmt_type=SELECT rows=1");
    assert(run_sql(ctx, user,
        "SELECT id FROM t_literal_null WHERE note = NULL", &out) == UWP_STS_OK);
    expect_reply(&out, "id\nOK stmt_type=SELECT rows=0");

    printf("PASS insert: rows land in the mutable row store and are "
           "UPDATE/DELETE-able end to end\n");
}

static void test_durable_keys(qihse_user_t* user) {
    char dir[] = "./qihse-sql-keys-XXXXXX";
    assert(mkdtemp(dir));
    char path[sizeof(dir) + 16], lock[sizeof(dir) + 24];
    assert(snprintf(path, sizeof(path), "%s/rows", dir) < (int)sizeof(path));
    assert(snprintf(lock, sizeof(lock), "%s.lock", path) < (int)sizeof(lock));
    qihse_uwp_context_t ctx = {0};
    static int engine;
    ctx.sql_engine = &engine;
    ctx.schema = qihse_schema_registry_create();
    ctx.txn_manager = qihse_txn_manager_create();
    assert(ctx.schema && ctx.txn_manager);
    assert(qihse_uwp_sql_open_durable(&ctx, path) == 0);
    uwp_reply_buf_t out;
    assert(run_sql(&ctx, user,
        "CREATE TABLE t_describe_width (a INT,b INT,c INT,d INT,e INT,f INT,g INT,h INT,i INT)",
        &out) == UWP_STS_OK);
    uint32_t declared = 23;
    qihse_uwp_sql_metadata_t metadata;
    assert(qihse_uwp_sql_describe(&ctx, "INSERT INTO t_describe_width VALUES ($1)",
        user, &declared, 1, &metadata) == UWP_STS_ERR_ARGS);
    qihse_uwp_sql_param_t short_row = {.oid=23,
        .data=(const uint8_t*)"1", .len=1, .format=0};
    qihse_txn_t* short_txn = NULL;
    assert(qihse_uwp_sql_execute_params(&ctx,
        "INSERT INTO t_describe_width VALUES ($1)", &short_row, 1,
        &short_txn, user, NULL, NULL) == UWP_STS_ERR_ARGS);
    assert(short_txn == NULL);
    assert(run_sql(&ctx, user, "CREATE EXTENSION IF NOT EXISTS \"uuid-ossp\"", &out) == UWP_STS_OK);
    assert(qihse_schema_has_extension(ctx.schema, "uuid-ossp"));
    assert(run_sql(&ctx, user, "CREATE EXTENSION IF NOT EXISTS pgcrypto", &out) != UWP_STS_OK);
    assert(run_sql(&ctx, user, "CREATE FUNCTION durable_fn() RETURNS INT AS $$ SELECT 1 $$ LANGUAGE SQL", &out) != UWP_STS_OK);
    qihse_txn_t* txn = NULL;
    assert(run_sql_txn(&ctx, user, "BEGIN", &txn, &out) == UWP_STS_OK);
    assert(run_sql_txn(&ctx, user, "CREATE EXTENSION pgcrypto", &txn, &out) != UWP_STS_OK);
    if (txn) assert(run_sql_txn(&ctx, user, "ROLLBACK", &txn, &out) == UWP_STS_OK);
    assert(qihse_schema_get_table(ctx.schema, "durable_fn") == NULL);
    assert(run_sql_txn(&ctx, user, "BEGIN", &txn, &out) == UWP_STS_OK);
    assert(run_sql_txn(&ctx, user, "CREATE TABLE rolled_back_ddl (id INT)", &txn, &out) == UWP_STS_OK);
    assert(qihse_schema_get_table(ctx.schema, "rolled_back_ddl") == NULL);
    assert(run_sql_txn(&ctx, user, "ROLLBACK", &txn, &out) == UWP_STS_OK);
    assert(txn == NULL);
    assert(qihse_schema_get_table(ctx.schema, "rolled_back_ddl") == NULL);
    assert(run_sql(&ctx, user, "CREATE TABLE dkeys (id INT PRIMARY KEY, code TEXT NOT NULL UNIQUE)", &out) == UWP_STS_OK);
    assert(run_sql(&ctx, user, "CREATE TABLE dpeer (id INT, UNIQUE (id))", &out) != UWP_STS_OK);
    assert(run_sql(&ctx, user, "CREATE TABLE dcheck (id INT CHECK (id > 0))", &out) != UWP_STS_OK);
    assert(run_sql(&ctx, user, "CREATE TABLE dfk (id INT REFERENCES dkeys(id))", &out) != UWP_STS_OK);
    assert(run_sql(&ctx, user, "CREATE TABLE dcomposite (id INT, code INT, PRIMARY KEY (id, code))", &out) != UWP_STS_OK);
    assert(run_sql(&ctx, user, "CREATE TABLE dnamed (id INT, CONSTRAINT p PRIMARY KEY (id))", &out) != UWP_STS_OK);
    assert(run_sql(&ctx, user, "CREATE TABLE dlabel (id INT PRIMARY KEY, __qihse_tenant_id INT, __qihse_classification INT, __qihse_sci INT)", &out) != UWP_STS_OK);
    assert(run_sql(&ctx, user, "CREATE TABLE dpeer (PRIMARY KEY (id), id INT)", &out) == UWP_STS_OK);
    assert(run_sql(&ctx, user, "CREATE TABLE dtable_unique (id INT NOT NULL, UNIQUE (id))", &out) == UWP_STS_OK);
    assert(run_sql_txn(&ctx, user, "BEGIN", &txn, &out) == UWP_STS_OK);
    assert(run_sql_txn(&ctx, user, "INSERT INTO dkeys VALUES (1, 'a'), (2, 'b')", &txn, &out) == UWP_STS_OK);
    assert(run_sql_txn(&ctx, user, "COMMIT", &txn, &out) == UWP_STS_OK);
    qihse_table_t* table = qihse_table_store_find_table(qihse_uwp_sql_table_store(), "dkeys");
    assert(table && qihse_table_row_count(table) == 2);
    assert(run_sql_txn(&ctx, user, "BEGIN", &txn, &out) == UWP_STS_OK);
    assert(run_sql_txn(&ctx, user, "INSERT INTO dkeys VALUES (3, 'c'), (3, 'd')", &txn, &out) == UWP_STS_OK);
    assert(run_sql_txn(&ctx, user, "COMMIT", &txn, &out) != UWP_STS_OK);
    assert(qihse_table_row_count(table) == 2);
    assert(run_sql_txn(&ctx, user, "BEGIN", &txn, &out) == UWP_STS_OK);
    assert(run_sql_txn(&ctx, user, "INSERT INTO dkeys VALUES (3, 'a')", &txn, &out) == UWP_STS_OK);
    assert(run_sql_txn(&ctx, user, "INSERT INTO dpeer VALUES (8)", &txn, &out) == UWP_STS_OK);
    assert(run_sql_txn(&ctx, user, "COMMIT", &txn, &out) != UWP_STS_OK);
    assert(qihse_table_row_count(table) == 2);
    assert(qihse_table_row_count(qihse_table_store_find_table(qihse_uwp_sql_table_store(), "dpeer")) == 0);
    assert(run_sql_txn(&ctx, user, "BEGIN", &txn, &out) == UWP_STS_OK);
    assert(run_sql_txn(&ctx, user, "UPDATE dkeys SET id = 1 WHERE id = 2", &txn, &out) == UWP_STS_OK);
    assert(run_sql_txn(&ctx, user, "COMMIT", &txn, &out) != UWP_STS_OK);
    assert(qihse_table_row_count(table) == 2);
    assert(run_sql_txn(&ctx, user, "BEGIN", &txn, &out) == UWP_STS_OK);
    assert(run_sql_txn(&ctx, user, "INSERT INTO dtable_unique VALUES (7), (7)", &txn, &out) == UWP_STS_OK);
    assert(run_sql_txn(&ctx, user, "COMMIT", &txn, &out) != UWP_STS_OK);
    assert(qihse_table_row_count(qihse_table_store_find_table(qihse_uwp_sql_table_store(), "dtable_unique")) == 0);
    assert(run_sql(&ctx, user, "CREATE TABLE ddefault (id UUID DEFAULT gen_random_uuid() PRIMARY KEY, note TEXT)", &out) == UWP_STS_OK);
    assert(run_sql_txn(&ctx, user, "BEGIN", &txn, &out) == UWP_STS_OK);
    assert(run_sql_txn(&ctx, user, "INSERT INTO ddefault (note) VALUES ('one'), ('two')", &txn, &out) == UWP_STS_OK);
    assert(run_sql_txn(&ctx, user, "COMMIT", &txn, &out) == UWP_STS_OK);
    assert(qihse_table_row_count(qihse_table_store_find_table(qihse_uwp_sql_table_store(), "ddefault")) == 2);
    assert(run_sql_txn(&ctx, user, "BEGIN", &txn, &out) == UWP_STS_OK);
    assert(run_sql_txn(&ctx, user, "INSERT INTO ddefault (id, note) VALUES (NULL, 'invalid')", &txn, &out) != UWP_STS_OK);
    if (txn) assert(run_sql_txn(&ctx, user, "ROLLBACK", &txn, &out) == UWP_STS_OK);
    assert(qihse_table_row_count(qihse_table_store_find_table(qihse_uwp_sql_table_store(), "ddefault")) == 2);
    qihse_uwp_sql_close_durable(&ctx);
    qihse_schema_registry_destroy(ctx.schema);
    ctx.schema = NULL;
    assert(qihse_uwp_sql_open_durable(&ctx, path) == 0);
    assert(qihse_table_row_count(qihse_table_store_find_table(qihse_uwp_sql_table_store(), "dkeys")) == 2);
    assert(qihse_schema_has_extension(ctx.schema, "uuid-ossp"));
    assert(qihse_table_row_count(qihse_table_store_find_table(qihse_uwp_sql_table_store(), "ddefault")) == 2);
    assert(qihse_schema_get_table(ctx.schema, "dkeys")->columns[0].is_primary_key);
    assert(qihse_schema_get_table(ctx.schema, "dkeys")->columns[1].is_unique);
    assert(run_sql_txn(&ctx, user, "BEGIN", &txn, &out) == UWP_STS_OK);
    assert(run_sql_txn(&ctx, user, "INSERT INTO dkeys VALUES (4, 'b')", &txn, &out) == UWP_STS_OK);
    assert(run_sql_txn(&ctx, user, "COMMIT", &txn, &out) != UWP_STS_OK);
    assert(qihse_table_row_count(qihse_table_store_find_table(qihse_uwp_sql_table_store(), "dkeys")) == 2);
    qihse_uwp_sql_close_durable(&ctx);
    qihse_schema_registry_destroy(ctx.schema);
    qihse_txn_manager_destroy(ctx.txn_manager);
    assert(unlink(path) == 0 && unlink(lock) == 0 && rmdir(dir) == 0);
}

static void test_create_constraint_boundary(qihse_uwp_context_t* ctx,
                                            qihse_user_t* user) {
    uwp_reply_buf_t out;
    /* Extension installation is a durable-catalog operation. Its successful
     * execution and recovery are covered by the durable fixture above. */
    assert(run_sql(ctx, user, "CREATE EXTENSION IF NOT EXISTS \"uuid-ossp\"", &out) != UWP_STS_OK);
    assert(!qihse_schema_has_extension(ctx->schema, "uuid-ossp"));
    assert(run_sql(ctx, user, "CREATE TABLE supported_default (id UUID DEFAULT gen_random_uuid())", &out) == UWP_STS_OK);
    assert(qihse_schema_get_table(ctx->schema, "supported_default") != NULL);
    const char* unsupported[] = {
        "CREATE EXTENSION pgcrypto",
        "CREATE FUNCTION rejected_fn() RETURNS uuid AS $$ SELECT gen_random_uuid() $$ LANGUAGE SQL",
        "CREATE TRIGGER rejected_trigger BEFORE INSERT ON t_required FOR EACH ROW EXECUTE FUNCTION rejected_fn()",
        "CREATE TABLE rejected_pk (id INT PRIMARY KEY)",
        "CREATE TABLE rejected_unique (id INT UNIQUE)",
        "CREATE TABLE rejected_table_pk (id INT, PRIMARY KEY (id))",
        "CREATE TABLE rejected_check (id INT CHECK (id > 0))",
        "CREATE TABLE rejected_fk (id INT REFERENCES other(id))",
        "CREATE TABLE rejected_cascade (id INT, FOREIGN KEY (id) "
            "REFERENCES other(id) ON DELETE CASCADE)",
        "CREATE TABLE rejected_table_check (id INT, CHECK (id > 0))",
        "CREATE TABLE rejected_table_fk (id INT, FOREIGN KEY (id) REFERENCES other(id))",
        "CREATE TABLE rejected_fake_check (id INT, CHECK (id > 0) NOT VALID)",
        "CREATE TABLE rejected_fake_fk (id INT, FOREIGN KEY (id) REFERENCES other(id) NOT VALID)",
    };
    for (size_t i = 0; i < sizeof(unsupported) / sizeof(*unsupported); ++i) {
        assert(run_sql(ctx, user, unsupported[i], &out) != UWP_STS_OK);
    }
    /* Unsupported extension/function/trigger syntax must fail rather
     * than report a successful no-op or persist a partial catalog entry. */
    assert(qihse_schema_get_table(ctx->schema, "rejected_pk") == NULL);
    assert(qihse_schema_get_table(ctx->schema, "rejected_unique") == NULL);
    assert(qihse_schema_get_table(ctx->schema, "rejected_table_pk") == NULL);
    assert(qihse_schema_get_table(ctx->schema, "rejected_check") == NULL);
    assert(qihse_schema_get_table(ctx->schema, "rejected_fk") == NULL);
    assert(qihse_schema_get_table(ctx->schema, "rejected_cascade") == NULL);
    assert(qihse_schema_get_table(ctx->schema, "rejected_table_check") == NULL);
    assert(qihse_schema_get_table(ctx->schema, "rejected_table_fk") == NULL);
    assert(qihse_schema_get_table(ctx->schema, "rejected_fake_check") == NULL);
    assert(qihse_schema_get_table(ctx->schema, "rejected_fake_fk") == NULL);

    assert(run_sql(ctx, user,
        "CREATE TABLE t_required (id INT NOT NULL, name TEXT)", &out) == UWP_STS_OK);
    qihse_table_t* table = qihse_table_store_find_table(
        qihse_uwp_sql_table_store(), "t_required");
    /* Lazily instantiated when first inserted. */
    assert(table == NULL);
    assert(run_sql(ctx, user,
        "INSERT INTO t_required (id, name) VALUES (1, 'a')", &out) == UWP_STS_OK);
    table = qihse_table_store_find_table(qihse_uwp_sql_table_store(), "t_required");
    assert(table && qihse_table_row_count(table) == 1);
    assert(run_sql(ctx, user,
        "INSERT INTO t_required (id, name) VALUES (2, 'b'), (NULL, 'c')",
        &out) != UWP_STS_OK);
    assert(qihse_table_row_count(table) == 1);
    assert(run_sql(ctx, user,
        "INSERT INTO t_required (name) VALUES ('missing')", &out) != UWP_STS_OK);
    assert(qihse_table_row_count(table) == 1);
    assert(run_sql(ctx, user,
        "INSERT INTO t_required (id, id) VALUES (3, 4)", &out) != UWP_STS_OK);
    assert(qihse_table_row_count(table) == 1);
    assert(run_sql(ctx, user,
        "UPDATE t_required SET id = NULL WHERE id = 1", &out) == UWP_STS_OK);
    expect_reply(&out, "refused");
    assert(qihse_table_row_count(table) == 1);

    qihse_txn_t* txn = NULL;
    assert(run_sql_txn(ctx, user, "BEGIN", &txn, &out) == UWP_STS_OK);
    assert(run_sql_txn(ctx, user,
        "INSERT INTO t_required (id, name) VALUES (5, 'ok')",
        &txn, &out) == UWP_STS_OK);
    assert(run_sql_txn(ctx, user,
        "INSERT INTO t_required (name) VALUES ('bad')",
        &txn, &out) != UWP_STS_OK);
    assert(txn == NULL);
    assert(qihse_table_row_count(table) == 1);
}

static void test_transactional_dml_commit_rollback(
    qihse_uwp_context_t* ctx, qihse_user_t* user) {
    uwp_reply_buf_t out;
    qihse_txn_t* txn = NULL;

    assert(run_sql(ctx, user,
                   "CREATE TABLE t_txn_dml (id INT, name TEXT, n INT)",
                   &out) == UWP_STS_OK);
    assert(run_sql(ctx, user,
                   "INSERT INTO t_txn_dml VALUES (1, 'base', 10)",
                   &out) == UWP_STS_OK);
    assert(run_sql(ctx, user,
                   "CREATE TABLE t_txn_dml_peer (id INT, name TEXT, n INT)",
                   &out) == UWP_STS_OK);
    assert(run_sql(ctx, user,
                   "INSERT INTO t_txn_dml_peer VALUES (1, 'peer', 100)",
                   &out) == UWP_STS_OK);
    qihse_table_t* table = qihse_table_store_find_table(
        qihse_uwp_sql_table_store(), "t_txn_dml");
    qihse_table_t* peer = qihse_table_store_find_table(
        qihse_uwp_sql_table_store(), "t_txn_dml_peer");
    assert(table != NULL && peer != NULL);

    assert(run_sql_txn(ctx, user, "BEGIN SERIALIZABLE", &txn, &out) == UWP_STS_OK);
    assert(txn != NULL);
    assert(run_sql_txn(ctx, user,
                       "UPDATE t_txn_dml SET n = 20 WHERE id = 1",
                       &txn, &out) == UWP_STS_OK);
    expect_reply(&out, "rows=1");
    expect_row(table, 1, "base", 10); /* uncommitted shadow is private */
    assert(run_sql_txn(ctx, user, "ROLLBACK", &txn, &out) == UWP_STS_OK);
    assert(txn == NULL);
    expect_row(table, 1, "base", 10);

    assert(run_sql_txn(ctx, user, "BEGIN SERIALIZABLE", &txn, &out) == UWP_STS_OK);
    assert(run_sql_txn(ctx, user,
                       "UPDATE t_txn_dml SET n = 30 WHERE id = 1",
                       &txn, &out) == UWP_STS_OK);
    assert(run_sql_txn(ctx, user,
                       "UPDATE t_txn_dml_peer SET n = 130 WHERE id = 1",
                       &txn, &out) == UWP_STS_OK);
    expect_row(table, 1, "base", 10);
    expect_row(peer, 1, "peer", 100);
    assert(run_sql_txn(ctx, user, "COMMIT", &txn, &out) == UWP_STS_OK);
    assert(txn == NULL);
    expect_row(table, 1, "base", 30);
    expect_row(peer, 1, "peer", 130);

    assert(run_sql_txn(ctx, user, "BEGIN", &txn, &out) == UWP_STS_OK);
    assert(run_sql_txn(ctx, user,
                       "INSERT INTO t_txn_dml VALUES (2, 'rolled-back', 40)",
                       &txn, &out) == UWP_STS_OK);
    expect_row_absent(table, 2);
    assert(run_sql_txn(ctx, user, "ROLLBACK", &txn, &out) == UWP_STS_OK);
    expect_row_absent(table, 2);

    assert(run_sql_txn(ctx, user, "BEGIN", &txn, &out) == UWP_STS_OK);
    assert(run_sql_txn(ctx, user,
                       "INSERT INTO t_txn_dml VALUES (2, 'committed', 50)",
                       &txn, &out) == UWP_STS_OK);
    assert(run_sql_txn(ctx, user, "COMMIT", &txn, &out) == UWP_STS_OK);
    expect_row(table, 2, "committed", 50);

    /* Optimistic conflict: a live autocommit write after the transaction's
     * snapshot makes COMMIT abort without overwriting the live change. */
    assert(run_sql_txn(ctx, user, "BEGIN SERIALIZABLE", &txn, &out) == UWP_STS_OK);
    assert(run_sql_txn(ctx, user,
                       "UPDATE t_txn_dml SET n = 60 WHERE id = 1",
                       &txn, &out) == UWP_STS_OK);
    assert(run_sql(ctx, user,
                   "UPDATE t_txn_dml SET n = 70 WHERE id = 1",
                   &out) == UWP_STS_OK);
    assert(run_sql_txn(ctx, user, "COMMIT", &txn, &out) == UWP_STS_ERR_FAILED);
    assert(txn == NULL);
    expect_row(table, 1, "base", 70);
    expect_row(peer, 1, "peer", 130);

    /* SQL savepoints and transactional DDL are refused until the row/schema
     * resources can snapshot and restore those operations. */
    assert(run_sql_txn(ctx, user, "BEGIN", &txn, &out) == UWP_STS_OK);
    assert(run_sql_txn(ctx, user, "SAVEPOINT s1", &txn, &out) ==
           UWP_STS_ERR_FAILED);
    assert(run_sql_txn(ctx, user, "CREATE TABLE t_txn_ddl (id INT)",
                       &txn, &out) == UWP_STS_ERR_FAILED);
    assert(qihse_schema_get_table((qihse_schema_registry_t*)ctx->schema,
                                  "t_txn_ddl") == NULL);
    assert(run_sql_txn(ctx, user, "ROLLBACK", &txn, &out) == UWP_STS_OK);

    printf("PASS sql transactions: private multi-table DML shadows commit "
           "together, rollback, and abort on concurrent live mutation\n");
}

static void test_txn_revocation_and_schema_authorization(
    qihse_uwp_context_t* ctx, qihse_user_t* operator_user) {
    uwp_reply_buf_t out;
    qihse_txn_t* txn = NULL;
    qihse_user_t* low = qihse_auth_create_user(
        operator_user, 102, QIHSE_ROLE_GUEST, 0, 0,
        "schema-low-principal-password", false);
    assert(low != NULL);

    assert(run_schema(ctx, operator_user, 0x01,
                      "CREATE TABLE t_schema_auth (id INT)", &out) == UWP_STS_OK);
    assert(run_schema(ctx, low, 0x04, "t_schema_auth", &out) ==
           UWP_STS_ERR_PERM);
    expect_reply(&out, "ERR_PERM");
    assert(run_schema(ctx, low, 0x02, "t_schema_auth", &out) ==
           UWP_STS_ERR_PERM);
    assert(qihse_auth_grant_object(operator_user, low, 0,
                                   table_resource_id("t_schema_auth"),
                                   QIHSE_ACL_READ));
    assert(run_schema(ctx, low, 0x04, "t_schema_auth", &out) == UWP_STS_OK);
    expect_reply(&out, "OK table=t_schema_auth");

    assert(run_sql(ctx, operator_user,
                   "CREATE TABLE t_revoked_commit (id INT, name TEXT, n INT)",
                   &out) == UWP_STS_OK);
    assert(qihse_auth_grant_object(operator_user, low, 0,
                                   table_resource_id("t_revoked_commit"),
                                   QIHSE_ACL_WRITE));

    uint8_t isolation = (uint8_t)QIHSE_ISO_SERIALIZABLE;
    memset(&out, 0, sizeof(out));
    assert(uwp_dispatch_txn(ctx, 0x01, &isolation, 1, &txn, low, -1,
                            test_write, &out) == UWP_STS_OK);
    assert(txn != NULL);
    assert(run_sql_txn(ctx, low,
                       "INSERT INTO t_revoked_commit VALUES (1, 'private', 9)",
                       &txn, &out) == UWP_STS_OK);
    qihse_table_t* revoke_table = qihse_table_store_find_table(
        qihse_uwp_sql_table_store(), "t_revoked_commit");
    assert(revoke_table != NULL && qihse_table_row_count(revoke_table) == 0);
    assert(qihse_auth_destroy_user(operator_user, 102));
    assert(run_txn_command(ctx, low, 0x02, NULL, &txn, &out) ==
           UWP_STS_ERR_PERM);
    expect_reply(&out, "ERR_PERM");
    assert(txn != NULL && txn->state == QIHSE_TXN_ACTIVE);
    assert(qihse_txn_rollback((qihse_txn_manager_t*)ctx->txn_manager, txn) == 0);
    txn = NULL;
    assert(qihse_table_row_count(revoke_table) == 0);
    assert(run_schema(ctx, low, 0x04, "t_schema_auth", &out) ==
           UWP_STS_ERR_PERM);
    assert(run_schema(ctx, operator_user, 0x02, "t_schema_auth", &out) ==
           UWP_STS_OK);
    assert(run_sql(ctx, operator_user, "DROP TABLE t_revoked_commit", &out) ==
           UWP_STS_OK);

    printf("PASS SQL adapters: SCHEMA enforces active READ/Operator boundaries "
           "and TXN revalidates revocation before commit\n");
}

static void test_tenant_row_boundaries(qihse_uwp_context_t* ctx,
                                       qihse_user_t* op) {
    uwp_reply_buf_t reply;
    qihse_user_t* tenant7 = qihse_auth_create_tenant_user(
        op, 7, 107, QIHSE_ROLE_ANALYST, 2, 0, "sql-tenant-seven-pw", false);
    qihse_user_t* tenant8 = qihse_auth_create_tenant_user(
        op, 8, 108, QIHSE_ROLE_ANALYST, 2, 0, "sql-tenant-eight-pw", false);
    assert(tenant7 && tenant8);
    assert(run_sql(ctx, op,
                   "CREATE TABLE t_row_acl (id INT, name TEXT, n INT, "
                   "__qihse_tenant_id INT, __qihse_classification INT, __qihse_sci INT)",
                   &reply) == UWP_STS_OK);
    for (size_t i = 0; i < 2; ++i) {
        qihse_user_t* principal = i ? tenant8 : tenant7;
        assert(qihse_auth_grant_object(op, principal, 0,
                                       table_resource_id("t_row_acl"),
                                       QIHSE_ACL_READ | QIHSE_ACL_WRITE));
    }
    assert(run_sql(ctx, tenant7,
                   "INSERT INTO t_row_acl VALUES (1, 'tenant-seven', 1, 7, 1, 0)",
                   &reply) == UWP_STS_OK);
    expect_reply(&reply, "rows=1");
    assert(run_sql(ctx, tenant8,
                   "INSERT INTO t_row_acl VALUES (2, 'tenant-eight', 2, 8, 1, 0)",
                   &reply) == UWP_STS_OK);
    assert(run_sql(ctx, op,
                   "INSERT INTO t_row_acl VALUES (3, 'classified', 3, 7, 3, 0)",
                   &reply) == UWP_STS_OK);
    assert(run_sql(ctx, tenant7, "SELECT name FROM t_row_acl", &reply) == UWP_STS_OK);
    expect_reply(&reply, "tenant-seven");
    expect_reply_absent(&reply, "tenant-eight");
    expect_reply_absent(&reply, "classified");
    assert(run_sql(ctx, tenant8, "UPDATE t_row_acl SET n = 99", &reply) == UWP_STS_OK);
    expect_reply(&reply, "rows=1");
    assert(run_sql(ctx, tenant7,
                   "UPDATE t_row_acl SET __qihse_tenant_id = 8 WHERE id = 1",
                   &reply) == UWP_STS_OK);
    expect_reply(&reply, "immutable");
    assert(run_sql(ctx, tenant7,
                   "INSERT INTO t_row_acl VALUES (4, 'forged', 4, 8, 1, 0)",
                   &reply) == UWP_STS_ERR_PERM);
    assert(run_sql(ctx, tenant7,
                   "INSERT INTO t_row_acl VALUES (5, 'above-clearance', 5, 7, 3, 0)",
                   &reply) == UWP_STS_ERR_PERM);
    assert(run_sql(ctx, tenant7, "DELETE FROM t_row_acl WHERE id = 3",
                   &reply) == UWP_STS_OK);
    expect_reply(&reply, "rows=0");
    assert(run_sql(ctx, tenant7, "SELECT name FROM t_row_acl", &reply) == UWP_STS_OK);
    expect_reply_absent(&reply, "classified");
    assert(run_sql(ctx, NULL, "SELECT name FROM t_row_acl", &reply) == UWP_STS_ERR_PERM);
    assert(qihse_auth_grant_object(op, tenant7, 0,
                                   table_resource_id("t_stmt_auth"), QIHSE_ACL_READ));
    assert(run_sql(ctx, tenant7, "SELECT name FROM t_stmt_auth", &reply) == UWP_STS_ERR_FAILED);
    printf("PASS SQL tenant row labels: read/write isolation, clearance and unauthenticated denial\n");
}

static void test_transactional_select(qihse_uwp_context_t* ctx,
                                      qihse_user_t* op) {
    uwp_reply_buf_t out;
    qihse_txn_t* txn = NULL;
    assert(run_sql(ctx, op,
                   "CREATE TABLE t_txn_select (id INT, name TEXT, n INT)",
                   &out) == UWP_STS_OK);
    assert(run_sql(ctx, op,
                   "INSERT INTO t_txn_select VALUES (1, 'initial', 10)",
                   &out) == UWP_STS_OK);
    assert(run_sql_txn(ctx, op, "BEGIN SERIALIZABLE", &txn, &out) == UWP_STS_OK);
    assert(run_sql_txn(ctx, op, "SELECT name FROM t_txn_select WHERE id = 1",
                       &txn, &out) == UWP_STS_OK);
    expect_reply(&out, "name\ninitial\nOK stmt_type=SELECT rows=1");
    assert(run_sql(ctx, op, "UPDATE t_txn_select SET name = 'outside' WHERE id = 1",
                   &out) == UWP_STS_OK);
    assert(run_sql_txn(ctx, op, "SELECT name FROM t_txn_select WHERE id = 1",
                       &txn, &out) == UWP_STS_OK);
    expect_reply(&out, "name\ninitial\nOK stmt_type=SELECT rows=1");
    assert(run_sql_txn(ctx, op, "COMMIT", &txn, &out) == UWP_STS_ERR_FAILED);
    assert(txn == NULL);
    assert(run_sql(ctx, op, "SELECT name FROM t_txn_select", &out) == UWP_STS_OK);
    expect_reply(&out, "outside");

    assert(run_sql_txn(ctx, op, "BEGIN", &txn, &out) == UWP_STS_OK);
    assert(run_sql_txn(ctx, op,
                       "INSERT INTO t_txn_select VALUES (2, 'private', 20)",
                       &txn, &out) == UWP_STS_OK);
    assert(run_sql_txn(ctx, op, "SELECT name FROM t_txn_select WHERE id = 2",
                       &txn, &out) == UWP_STS_OK);
    expect_reply(&out, "name\nprivate\nOK stmt_type=SELECT rows=1");
    assert(run_sql(ctx, op, "SELECT name FROM t_txn_select WHERE id = 2",
                   &out) == UWP_STS_OK);
    expect_reply(&out, "OK stmt_type=SELECT rows=0");
    assert(run_sql_txn(ctx, op,
                       "UPDATE t_txn_select SET name = 'changed' WHERE id = 2",
                       &txn, &out) == UWP_STS_OK);
    assert(run_sql_txn(ctx, op, "SELECT name FROM t_txn_select WHERE id = 2",
                       &txn, &out) == UWP_STS_OK);
    expect_reply(&out, "name\nchanged\nOK stmt_type=SELECT rows=1");
    assert(run_sql_txn(ctx, op, "DELETE FROM t_txn_select WHERE id = 2",
                       &txn, &out) == UWP_STS_OK);
    assert(run_sql_txn(ctx, op, "SELECT name FROM t_txn_select WHERE id = 2",
                       &txn, &out) == UWP_STS_OK);
    expect_reply(&out, "OK stmt_type=SELECT rows=0");
    assert(run_sql_txn(ctx, op, "SELECT name FROM t_txn_select a JOIN t_txn_select b ON a.id = b.id",
                       &txn, &out) == UWP_STS_ERR_FAILED);
    assert(run_sql_txn(ctx, op, "SELECT COUNT(*) FROM t_txn_select",
                       &txn, &out) == UWP_STS_ERR_FAILED);
    assert(run_sql_txn(ctx, op, "ROLLBACK", &txn, &out) == UWP_STS_OK);
    qihse_table_t* read_table = qihse_table_store_find_table(
        qihse_uwp_sql_table_store(), "t_txn_select");
    assert(read_table);
    qihse_table_txn_t* untouched = qihse_table_txn_begin(read_table);
    assert(untouched);
    assert(run_sql_txn(ctx, op, "BEGIN", &txn, &out) == UWP_STS_OK);
    assert(run_sql_txn(ctx, op, "SELECT name FROM t_txn_select LIMIT 1",
                       &txn, &out) == UWP_STS_OK);
    expect_reply(&out, "OK stmt_type=SELECT rows=1");
    assert(run_sql_txn(ctx, op, "COMMIT", &txn, &out) == UWP_STS_OK);
    assert(txn == NULL);
    qihse_table_txn_t* read_group[] = {untouched};
    assert(qihse_table_txn_validate_group(read_group, 1));

    qihse_user_t* low = qihse_auth_create_tenant_user(
        op, 7, 109, QIHSE_ROLE_ANALYST, 1, 0, "txn-select-low-password", false);
    assert(low);
    assert(run_sql(ctx, op,
                   "CREATE TABLE t_txn_select_acl (name TEXT, __qihse_tenant_id INT, "
                   "__qihse_classification INT, __qihse_sci INT)",
                   &out) == UWP_STS_OK);
    assert(run_sql(ctx, op,
                   "INSERT INTO t_txn_select_acl VALUES ('allowed', 7, 1, 0)",
                   &out) == UWP_STS_OK);
    assert(run_sql(ctx, op,
                   "INSERT INTO t_txn_select_acl VALUES ('high-secret', 7, 3, 0)",
                   &out) == UWP_STS_OK);
    assert(run_sql(ctx, op,
                   "INSERT INTO t_txn_select_acl VALUES ('other-tenant', 8, 1, 0)",
                   &out) == UWP_STS_OK);
    assert(qihse_auth_grant_object(op, low, 0,
                                   table_resource_id("t_txn_select_acl"),
                                   QIHSE_ACL_READ));
    assert(run_sql_txn(ctx, low, "BEGIN", &txn, &out) == UWP_STS_OK);
    assert(run_sql_txn(ctx, low, "SELECT name FROM t_txn_select_acl",
                       &txn, &out) == UWP_STS_OK);
    expect_reply(&out, "name\nallowed\nOK stmt_type=SELECT rows=1");
    expect_reply_absent(&out, "high-secret");
    expect_reply_absent(&out, "other-tenant");
    assert(qihse_auth_revoke_object(op, low, 0,
                                    table_resource_id("t_txn_select_acl")));
    assert(run_sql_txn(ctx, low, "SELECT name FROM t_txn_select_acl",
                       &txn, &out) != UWP_STS_OK);
    expect_reply_absent(&out, "high-secret");
    assert(run_sql_txn(ctx, low, "COMMIT", &txn, &out) == UWP_STS_ERR_PERM);
    expect_reply(&out, "ERR_PERM");
    assert(run_txn_command(ctx, low, 0x02, NULL, &txn, &out) == UWP_STS_ERR_PERM);
    expect_reply(&out, "ERR_PERM");
    assert(txn != NULL);
    assert(run_txn_command(ctx, low, 0x03, NULL, &txn, &out) == UWP_STS_OK);
    assert(txn == NULL);
    printf("PASS transactional SELECT: snapshot, private mutations, conflict, unsupported shapes and commit-time ACL\n");
}

static void test_directeye_ordered_lookup(qihse_uwp_context_t* ctx,
                                          qihse_user_t* op) {
    uwp_reply_buf_t out;
    qihse_txn_t* txn = NULL;
    qihse_user_t* low = qihse_auth_create_tenant_user(
        op, 17, 117, QIHSE_ROLE_ANALYST, 1, 0,
        "directeye-ordered-lookup-pw", false);
    assert(low);
    assert(run_sql(ctx, op,
        "CREATE TABLE osint_records (identifier TEXT, created_at BIGINT, "
        "payload TEXT, __qihse_tenant_id INT, __qihse_classification INT, "
        "__qihse_sci INT)", &out) == UWP_STS_OK);
    assert(qihse_auth_grant_object(op, low, 0,
        table_resource_id("osint_records"), QIHSE_ACL_READ));
    assert(run_sql(ctx, op,
        "INSERT INTO osint_records VALUES ('target', 20, 'allowed-new', 17, 1, 0)",
        &out) == UWP_STS_OK);
    assert(run_sql(ctx, op,
        "INSERT INTO osint_records VALUES ('target', 99, 'high-secret', 17, 3, 0)",
        &out) == UWP_STS_OK);
    assert(run_sql(ctx, op,
        "INSERT INTO osint_records VALUES ('target', 100, 'other-tenant', 18, 1, 0)",
        &out) == UWP_STS_OK);
    assert(run_sql(ctx, op,
        "INSERT INTO osint_records VALUES ('target', 10, 'allowed-old', 17, 1, 0)",
        &out) == UWP_STS_OK);
    assert(run_sql(ctx, op,
        "INSERT INTO osint_records VALUES ('different', 150, 'wrong-id', 17, 1, 0)",
        &out) == UWP_STS_OK);
    const char* query = "SELECT * FROM osint_records WHERE identifier = 'target' "
                        "ORDER BY created_at DESC LIMIT 1";
    assert(run_sql(ctx, low, query, &out) == UWP_STS_OK);
    expect_reply(&out, "target\t20\tallowed-new\t17\t1\t0\nOK stmt_type=SELECT rows=1");
    expect_reply_absent(&out, "high-secret");
    expect_reply_absent(&out, "other-tenant");
    expect_reply_absent(&out, "wrong-id");
    assert(run_sql(ctx, low,
        "SELECT payload FROM osint_records WHERE identifier = 'target' "
        "ORDER BY created_at DESC LIMIT 1;", &out) == UWP_STS_OK);
    expect_reply(&out, "payload\nallowed-new\nOK stmt_type=SELECT rows=1");
    assert(run_sql(ctx, low,
        "SELECT payload FROM osint_records WHERE identifier = 'target' "
        "ORDER BY created_at ASC LIMIT 1", &out) == UWP_STS_OK);
    expect_reply(&out, "payload\nallowed-old\nOK stmt_type=SELECT rows=1");
    assert(run_sql(ctx, low,
        "SELECT payload FROM osint_records WHERE identifier = 'target' "
        "ORDER BY payload desc LIMIT 1", &out) == UWP_STS_OK);
    expect_reply(&out, "payload\nallowed-old\nOK stmt_type=SELECT rows=1");
    expect_reply_absent(&out, "high-secret");
    assert(run_sql(ctx, op, query, &out) == UWP_STS_OK);
    expect_reply(&out, "other-tenant");
    assert(run_sql(ctx, low,
        "SELECT payload FROM osint_records WHERE identifier = 'absent' "
        "ORDER BY created_at DESC LIMIT 1", &out) == UWP_STS_OK);
    expect_reply(&out, "payload\nOK stmt_type=SELECT rows=0");
    const char* refused[] = {
        "SELECT payload FROM osint_records ORDER BY created_at DESC",
        "SELECT payload FROM osint_records ORDER BY created_at DESC LIMIT 2",
        "SELECT payload FROM osint_records ORDER BY created_at DESC LIMIT 1 OFFSET 1",
        "SELECT payload FROM osint_records ORDER BY created_at DESC LIMIT 1 GARBAGE",
        "SELECT payload FROM osint_records ORDER BY missing DESC LIMIT 1",
        "SELECT COUNT(*), SUM(CASE WHEN payload = 'high-secret' THEN 1 ELSE 0 END) "
        "FROM osint_records WHERE created_at > 0"
    };
    for (size_t i = 0; i < sizeof(refused) / sizeof(*refused); ++i) {
        assert(run_sql(ctx, low, refused[i], &out) != UWP_STS_OK);
        expect_reply_absent(&out, "high-secret");
        expect_reply_absent(&out, "other-tenant");
    }
    assert(run_sql_txn(ctx, op, "BEGIN SERIALIZABLE", &txn, &out) == UWP_STS_OK);
    assert(run_sql_txn(ctx, op, query, &txn, &out) == UWP_STS_OK);
    expect_reply(&out, "other-tenant");
    assert(run_sql(ctx, op,
        "INSERT INTO osint_records VALUES ('target', 200, 'outside', 17, 1, 0)",
        &out) == UWP_STS_OK);
    assert(run_sql_txn(ctx, op, query, &txn, &out) == UWP_STS_OK);
    expect_reply(&out, "other-tenant");
    expect_reply_absent(&out, "outside");
    assert(run_sql_txn(ctx, op, "COMMIT", &txn, &out) == UWP_STS_ERR_FAILED);
    assert(txn == NULL);
    assert(run_sql(ctx, op, query, &out) == UWP_STS_OK);
    expect_reply(&out, "outside");

    /* A single projected row must not allocate proportional to arbitrary
     * table payload size in the ordered top-1 path. */
    qihse_table_t* table = qihse_table_store_find_table(
        qihse_uwp_sql_table_store(), "osint_records");
    assert(table);
    char* huge = (char*)malloc(20001);
    assert(huge);
    memset(huge, 'x', 20000);
    huge[20000] = '\0';
    qihse_col_value_t row[6] = {0};
    row[0].type = QIHSE_TS_STRING; row[0].v.str = (char*)"large";
    row[1].type = QIHSE_TS_INT64; row[1].v.i64 = 300;
    row[2].type = QIHSE_TS_STRING; row[2].v.str = huge;
    for (size_t i = 3; i < 6; ++i) row[i].type = QIHSE_TS_INT32;
    row[3].v.i32 = 17; row[4].v.i32 = 1;
    assert(qihse_table_insert(table, row, 6) >= 0);
    free(huge);
    assert(run_sql(ctx, low,
        "SELECT * FROM osint_records WHERE identifier = 'large' "
        "ORDER BY created_at DESC LIMIT 1", &out) == UWP_STS_ERR_FAILED);
    expect_reply_absent(&out, "xxxxxxxx");

    assert(run_sql_txn(ctx, low, "BEGIN", &txn, &out) == UWP_STS_OK);
    assert(run_sql_txn(ctx, low, query, &txn, &out) == UWP_STS_OK);
    expect_reply(&out, "outside");
    assert(qihse_auth_revoke_object(op, low, 0,
        table_resource_id("osint_records")));
    assert(run_txn_command(ctx, low, 0x02, NULL, &txn, &out) == UWP_STS_ERR_PERM);
    expect_reply(&out, "ERR_PERM");
    assert(txn != NULL);
    assert(run_txn_command(ctx, low, 0x03, NULL, &txn, &out) == UWP_STS_OK);
    printf("PASS DIRECTEYE ordered top-1: filter, labels, bounded row, snapshot, commit ACL\n");
}

static void test_exact_numeric_predicates(qihse_uwp_context_t* ctx,
                                          qihse_user_t* op) {
    uwp_reply_buf_t out;
    char sql[512];
    for (int indexed = 0; indexed < 2; ++indexed) {
        snprintf(sql, sizeof(sql),
            "CREATE TABLE t_decimal_%d (id INT, amount NUMERIC(38,2))", indexed);
        assert(run_sql(ctx, op, sql, &out) == UWP_STS_OK);
        snprintf(sql, sizeof(sql),
            "INSERT INTO t_decimal_%d VALUES (1, '1.00'), (2, '-2.50'), "
            "(3, '90071992547409931234567890.12'), "
            "(4, '90071992547409931234567890.13'), (5, NULL)", indexed);
        assert(run_sql(ctx, op, sql, &out) == UWP_STS_OK);
        if (indexed) {
            assert(run_sql(ctx, op,
                "CREATE INDEX t_decimal_amount ON t_decimal_1(amount)", &out) == UWP_STS_OK);
        }
        const char* predicates[] = {
            "amount = '+0001.0'", "amount > '90071992547409931234567890.12'",
            "amount >= '90071992547409931234567890.13'", "amount < '-2.49'",
            "amount <= '-2.50'", "amount != '1.00'", "amount <> '1.00'",
            "amount = NULL", "amount = '1.001'",
            "amount = '9999999999999999999999999999999999999999'"
        };
        const int counts[] = {1, 1, 1, 1, 1, 3, 3, 0, 0, 0};
        for (size_t i = 0; i < sizeof(counts) / sizeof(*counts); ++i) {
            snprintf(sql, sizeof(sql), "SELECT id FROM t_decimal_%d WHERE %s",
                     indexed, predicates[i]);
            uwp_sts_result_t status = run_sql(ctx, op, sql, &out);
            if (status != UWP_STS_OK) fprintf(stderr, "%s: %s\n", sql, out.data);
            assert(status == UWP_STS_OK);
            char expected[64];
            snprintf(expected, sizeof(expected), "OK stmt_type=SELECT rows=%d", counts[i]);
            expect_reply(&out, expected);
        }
        snprintf(sql, sizeof(sql),
            "SELECT id FROM t_decimal_%d WHERE amount = 'not-a-number'", indexed);
        if (run_sql(ctx, op, sql, &out) == UWP_STS_OK)
            expect_reply(&out, "OK stmt_type=SELECT rows=0");
        snprintf(sql, sizeof(sql),
            "UPDATE t_decimal_%d SET amount = '3.25' WHERE amount = '+01.000'", indexed);
        assert(run_sql(ctx, op, sql, &out) == UWP_STS_OK);
        expect_reply(&out, "rows=1");
        snprintf(sql, sizeof(sql),
            "DELETE FROM t_decimal_%d WHERE amount < '0'", indexed);
        assert(run_sql(ctx, op, sql, &out) == UWP_STS_OK);
        expect_reply(&out, "rows=1");
    }
    printf("PASS exact NUMERIC predicates: indexed/unindexed equality, ranges, mutations and NULL\n");
}

int main(void) {
{
    /* Per-test audit/chain isolation (parallel aggregates). */
    char qdd[] = "build/test_sql_dml_exec_XXXXXX";
    if (mkdtemp(qdd)) setenv("QIHSE_DATA_DIR", qdd, 1);
}
    qihse_auth_init();
    qihse_user_t* operator_user = qihse_auth_get_user(0);
    assert(operator_user != NULL);

    /* The SQL dispatcher only requires ctx->sql_engine to be non-NULL; the
     * executor does not dereference it (the row store is process-wide). */
    qihse_uwp_context_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    static int sql_engine_placeholder;
    ctx.sql_engine = &sql_engine_placeholder;
    /* INSERT resolves its table through the schema registry. */
    ctx.schema = qihse_schema_registry_create();
    assert(ctx.schema != NULL);
    ctx.txn_manager = qihse_txn_manager_create();
    assert(ctx.txn_manager != NULL);

    /* A pgwire-style descriptor must not inherit the test-only in-memory SQL
     * store, even if every other context pointer is populated. */
    uwp_reply_buf_t refused = {0};
    qihse_txn_t* no_txn = NULL;
    const char* insert = "INSERT INTO missing VALUES (1)";
    assert(uwp_dispatch_sql(&ctx, 0x02, (const uint8_t*)insert,
                              strlen(insert) + 1, &no_txn, operator_user, 3,
                              test_write, &refused) == UWP_STS_ERR_NO_CTX);
    expect_reply(&refused, "ERR_NO_CTX");
    uint8_t isolation = 0;
    assert(uwp_dispatch_txn(&ctx, 0x01, &isolation, 1, &no_txn,
                              operator_user, 3, test_write, &refused) ==
           UWP_STS_ERR_NO_CTX);
    assert(no_txn == NULL);

    test_durable_keys(operator_user);
    test_update_executes(&ctx, operator_user);
    test_update_qualified_and_quoted(&ctx, operator_user);
    test_update_refusals(&ctx, operator_user);
    test_delete_executes(&ctx, operator_user);
    test_delete_zero_condition_guard(&ctx, operator_user);
    test_write_permission(&ctx, operator_user);
    test_statement_authorization(&ctx, operator_user);
    test_missing_table(&ctx, operator_user);
    test_insert_populates_row_store(&ctx, operator_user);
    test_create_constraint_boundary(&ctx, operator_user);
    test_transactional_dml_commit_rollback(&ctx, operator_user);
    test_txn_revocation_and_schema_authorization(&ctx, operator_user);
    test_tenant_row_boundaries(&ctx, operator_user);
    test_transactional_select(&ctx, operator_user);
    test_directeye_ordered_lookup(&ctx, operator_user);
    test_exact_numeric_predicates(&ctx, operator_user);

    qihse_txn_manager_destroy((qihse_txn_manager_t*)ctx.txn_manager);
    qihse_schema_registry_destroy((qihse_schema_registry_t*)ctx.schema);
    printf("test_sql_dml_exec: all SQL UPDATE/DELETE/INSERT execution tests passed\n");
    return 0;
}
