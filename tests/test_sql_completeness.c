/*
 * test_sql_completeness.c — SQL engine: parser, join / aggregate / sort
 * executors, schema registry and cost-based optimizer.
 *
 * Exercises the sources the SQL-engine document describes:
 *   src/tractable/qihse_sql_parser.c        — statement parsing to an AST
 *   src/tractable/qihse_join_executor.c     — hash and nested-loop joins
 *   src/tractable/qihse_aggregate_executor.c— hash grouping and aggregates
 *   src/tractable/qihse_sort_executor.c     — multi-key in-memory sort
 *   src/tractable/qihse_schema.c            — in-memory catalog
 *   src/tractable/qihse_optimizer.c         — plan building
 *
 * Covered: SELECT shape (columns, FROM, WHERE, GROUP BY, HAVING, ORDER BY,
 * LIMIT, OFFSET, DISTINCT), aggregate detection, all five JOIN spellings,
 * IN / EXISTS subqueries, UNION / INTERSECT / EXCEPT, multi-row INSERT,
 * CREATE TABLE across every documented column type, ALTER TABLE
 * add/drop/rename column and rename table, CREATE/DROP INDEX, DROP TABLE,
 * join execution (hash + nested loop, including LEFT and CROSS), GROUP BY
 * with SUM/COUNT/AVG/MIN/MAX/COUNT(*), multi-key sort, schema registry and
 * optimizer plan shape.
 *
 * Known gaps versus the document, printed at the end of this run and stated
 * in docs/architecture/sql_engine.md:
 *   - UPDATE captures the table name only: the SET list is never parsed
 *     (ast->set_columns/set_values/num_set stay empty).
 *   - DELETE captures its WHERE clause as raw text in
 *     ast->insert_select_query, not as structured ast->where_conditions.
 *   - A scalar subquery in the SELECT list is not extracted into
 *     ast->select_items[i].scalar_subquery.
 * These are reported, not asserted, so that fixing them cannot break this
 * test.
 */
#include "qihse_sql_parser.h"
#include "qihse_join_executor.h"
#include "qihse_aggregate_executor.h"
#include "qihse_sort_executor.h"
#include "qihse_schema.h"
#include "qihse_optimizer.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── Parser ─────────────────────────────────────────────────────────────── */

static void test_select_shape(void) {
    qihse_sql_ast_t* ast = qihse_parse_sql_to_ast(
        "SELECT a, b FROM t WHERE x = 5 ORDER BY a ASC, b DESC LIMIT 10 OFFSET 2");
    assert(ast);
    assert(ast->stmt_type == QIHSE_SQL_SELECT);
    assert(ast->num_select_items == 2);
    assert(strcmp(ast->select_items[0].expr, "a") == 0);
    assert(strcmp(ast->select_items[1].expr, "b") == 0);
    assert(ast->num_from_tables == 1);
    assert(strcmp(ast->from_tables[0].table_name, "t") == 0);
    assert(ast->num_where_conditions == 1);
    assert(strcmp(ast->where_conditions[0].column_name, "x") == 0);
    assert(strcmp(ast->where_conditions[0].operator, "=") == 0);
    assert(strcmp(ast->where_conditions[0].value, "5") == 0);
    assert(ast->where_conditions[0].value_is_string == 0);
    assert(ast->num_order_items == 2);
    assert(strcmp(ast->order_items[0].column_name, "a") == 0);
    assert(ast->order_items[0].ascending == 1);
    assert(strcmp(ast->order_items[1].column_name, "b") == 0);
    assert(ast->order_items[1].ascending == 0);
    assert(ast->limit == 10);
    assert(ast->offset == 2);
    assert(ast->select_distinct == 0);
    qihse_sql_ast_free(ast);

    /* String literal filter and DISTINCT. */
    ast = qihse_parse_sql_to_ast("SELECT DISTINCT name FROM users WHERE name = 'bob'");
    assert(ast);
    assert(ast->select_distinct == 1);
    assert(ast->num_where_conditions == 1);
    assert(ast->where_conditions[0].value_is_string == 1);
    assert(strcmp(ast->where_conditions[0].value, "bob") == 0);
    qihse_sql_ast_free(ast);

    /* A statement the parser cannot classify is reported as UNKNOWN. */
    ast = qihse_parse_sql_to_ast("FROBNICATE THE DATABASE");
    assert(ast);
    assert(ast->stmt_type == QIHSE_SQL_UNKNOWN);
    qihse_sql_ast_free(ast);

    printf("PASS sql parser: SELECT shape, WHERE, ORDER BY, LIMIT/OFFSET, DISTINCT\n");
}

static void test_aggregates_and_grouping(void) {
    qihse_sql_ast_t* ast = qihse_parse_sql_to_ast(
        "SELECT COUNT(*), SUM(x), AVG(y), MIN(z), MAX(w) FROM t "
        "GROUP BY g HAVING COUNT(*) > 1");
    assert(ast);
    assert(ast->num_select_items == 5);
    assert(ast->select_items[0].agg_kind == QIHSE_AGG_COUNT_STAR);
    assert(strcmp(ast->select_items[0].agg_arg, "*") == 0);
    assert(ast->select_items[1].agg_kind == QIHSE_AGG_SUM);
    assert(strcmp(ast->select_items[1].agg_arg, "x") == 0);
    assert(ast->select_items[2].agg_kind == QIHSE_AGG_AVG);
    assert(ast->select_items[3].agg_kind == QIHSE_AGG_MIN);
    assert(ast->select_items[4].agg_kind == QIHSE_AGG_MAX);
    assert(ast->group_by);
    assert(ast->group_by->num_group_columns == 1);
    assert(strcmp(ast->group_by->group_columns[0], "g") == 0);
    assert(ast->group_by->having_expr);
    assert(strstr(ast->group_by->having_expr, "COUNT(*) > 1") != NULL);
    qihse_sql_ast_free(ast);

    /* Multi-column GROUP BY. */
    ast = qihse_parse_sql_to_ast("SELECT SUM(v) FROM t GROUP BY a, b");
    assert(ast && ast->group_by && ast->group_by->num_group_columns == 2);
    assert(strcmp(ast->group_by->group_columns[0], "a") == 0);
    assert(strcmp(ast->group_by->group_columns[1], "b") == 0);
    qihse_sql_ast_free(ast);
    printf("PASS sql parser: SUM/COUNT/COUNT(*)/AVG/MIN/MAX, GROUP BY, HAVING\n");
}

static void test_join_parsing(void) {
    struct { const char* sql; qihse_sql_join_type_t want; } cases[] = {
        {"SELECT a FROM t1 INNER JOIN t2 ON t1.id = t2.id", QIHSE_JOIN_INNER},
        {"SELECT a FROM t1 JOIN t2 ON t1.id = t2.id",       QIHSE_JOIN_INNER},
        {"SELECT a FROM t1 LEFT JOIN t2 ON t1.id = t2.id",  QIHSE_JOIN_LEFT},
        {"SELECT a FROM t1 LEFT OUTER JOIN t2 ON t1.id = t2.id", QIHSE_JOIN_LEFT},
        {"SELECT a FROM t1 RIGHT JOIN t2 ON t1.id = t2.id", QIHSE_JOIN_RIGHT},
        {"SELECT a FROM t1 FULL OUTER JOIN t2 ON t1.id = t2.id", QIHSE_JOIN_FULL},
        {"SELECT a FROM t1 CROSS JOIN t2",                  QIHSE_JOIN_CROSS},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        qihse_sql_ast_t* ast = qihse_parse_sql_to_ast(cases[i].sql);
        assert(ast);
        assert(ast->num_joins == 1);
        assert(ast->joins[0].join_type == cases[i].want);
        assert(ast->joins[0].table.table_name);
        assert(strcmp(ast->joins[0].table.table_name, "t2") == 0);
        if (cases[i].want != QIHSE_JOIN_CROSS) {
            /* The ON equality is decomposed into left/right keys. */
            assert(ast->joins[0].left_key && ast->joins[0].right_key);
            assert(strcmp(ast->joins[0].left_key, "t1.id") == 0);
            assert(strcmp(ast->joins[0].right_key, "t2.id") == 0);
        }
        qihse_sql_ast_free(ast);
    }
    printf("PASS sql parser: INNER/LEFT/RIGHT/FULL/CROSS joins with ON keys\n");
}

static void test_subqueries_and_set_ops(void) {
    /* IN (SELECT ...) */
    qihse_sql_ast_t* ast = qihse_parse_sql_to_ast(
        "SELECT a FROM t WHERE a IN (SELECT b FROM s)");
    assert(ast);
    assert(ast->num_where_conditions == 1);
    assert(strcmp(ast->where_conditions[0].operator, "IN") == 0);
    assert(ast->where_conditions[0].subquery != NULL);
    assert(ast->where_conditions[0].subquery->stmt_type == QIHSE_SQL_SELECT);
    assert(strcmp(ast->where_conditions[0].subquery->from_tables[0].table_name, "s") == 0);
    qihse_sql_ast_free(ast);

    /* EXISTS (SELECT ...) with a correlated inner predicate. */
    ast = qihse_parse_sql_to_ast(
        "SELECT a FROM t WHERE EXISTS (SELECT 1 FROM s WHERE s.id = t.id)");
    assert(ast);
    assert(ast->num_where_conditions == 1);
    assert(ast->where_conditions[0].subquery != NULL);
    qihse_sql_ast_t* inner = ast->where_conditions[0].subquery;
    assert(strcmp(inner->from_tables[0].table_name, "s") == 0);
    /* The inner predicate names an outer column, i.e. it is correlated. */
    assert(inner->num_where_conditions >= 1);
    qihse_sql_ast_free(ast);

    /* Set operations. */
    struct { const char* sql; qihse_sql_set_op_t want; } ops[] = {
        {"SELECT a FROM t1 UNION SELECT b FROM t2",     QIHSE_SET_UNION},
        {"SELECT a FROM t1 INTERSECT SELECT b FROM t2", QIHSE_SET_INTERSECT},
        {"SELECT a FROM t1 EXCEPT SELECT b FROM t2",    QIHSE_SET_EXCEPT},
    };
    for (size_t i = 0; i < sizeof(ops) / sizeof(ops[0]); i++) {
        ast = qihse_parse_sql_to_ast(ops[i].sql);
        assert(ast);
        assert(ast->set_op == ops[i].want);
        assert(ast->set_left && ast->set_right);
        assert(ast->set_left->stmt_type == QIHSE_SQL_SELECT);
        assert(ast->set_right->stmt_type == QIHSE_SQL_SELECT);
        qihse_sql_ast_free(ast);
    }
    printf("PASS sql parser: IN and EXISTS subqueries, UNION/INTERSECT/EXCEPT\n");
}

static void test_dml_and_ddl_parsing(void) {
    /* Multi-row INSERT with a column list. */
    qihse_sql_ast_t* ast = qihse_parse_sql_to_ast(
        "INSERT INTO t (a, b) VALUES (1, 'x'), (2, 'y')");
    assert(ast);
    assert(ast->stmt_type == QIHSE_SQL_INSERT);
    assert(strcmp(ast->table_name, "t") == 0);
    assert(ast->num_insert_columns == 2);
    assert(strcmp(ast->insert_columns[0], "a") == 0);
    assert(strcmp(ast->insert_columns[1], "b") == 0);
    assert(ast->num_insert_rows == 2);
    assert(strcmp(ast->insert_rows[0][0], "1") == 0);
    assert(strcmp(ast->insert_rows[0][1], "x") == 0);
    assert(strcmp(ast->insert_rows[1][0], "2") == 0);
    assert(strcmp(ast->insert_rows[1][1], "y") == 0);
    qihse_sql_ast_free(ast);

    /* UPDATE and DELETE are recognised; see the gap note below. */
    ast = qihse_parse_sql_to_ast("UPDATE t SET a = 1 WHERE id = 3");
    assert(ast);
    assert(ast->stmt_type == QIHSE_SQL_UPDATE);
    assert(strcmp(ast->table_name, "t") == 0);
    qihse_sql_ast_free(ast);

    ast = qihse_parse_sql_to_ast("DELETE FROM t WHERE id = 4");
    assert(ast);
    assert(ast->stmt_type == QIHSE_SQL_DELETE);
    assert(strcmp(ast->table_name, "t") == 0);
    qihse_sql_ast_free(ast);

    /* CREATE TABLE with every documented column type. */
    ast = qihse_parse_sql_to_ast(
        "CREATE TABLE t (a INT, b BIGINT, c FLOAT, d DOUBLE, e VARCHAR(32), "
        "f TEXT, g BOOL, h TIMESTAMP, v VECTOR(128))");
    assert(ast);
    assert(ast->stmt_type == QIHSE_SQL_CREATE);
    assert(strcmp(ast->table_name, "t") == 0);
    assert(ast->num_columns == 9);
    qihse_sql_type_t want_types[9] = {
        QIHSE_TYPE_INT, QIHSE_TYPE_BIGINT, QIHSE_TYPE_FLOAT, QIHSE_TYPE_DOUBLE,
        QIHSE_TYPE_VARCHAR, QIHSE_TYPE_TEXT, QIHSE_TYPE_BOOL,
        QIHSE_TYPE_TIMESTAMP, QIHSE_TYPE_VECTOR
    };
    const char* want_names[9] = {"a","b","c","d","e","f","g","h","v"};
    for (int i = 0; i < 9; i++) {
        assert(ast->columns[i].type == want_types[i]);
        assert(strcmp(ast->columns[i].name, want_names[i]) == 0);
    }
    assert(ast->columns[4].type_len == 32);
    assert(ast->columns[8].type_len == 128);
    qihse_sql_ast_free(ast);

    /* ALTER TABLE: add / drop / rename column, rename table. */
    struct { const char* sql; qihse_sql_alter_action_t want; } alters[] = {
        {"ALTER TABLE t ADD COLUMN x INT",      QIHSE_ALTER_ADD_COLUMN},
        {"ALTER TABLE t DROP COLUMN x",         QIHSE_ALTER_DROP_COLUMN},
        {"ALTER TABLE t RENAME COLUMN x TO y",  QIHSE_ALTER_RENAME_COLUMN},
        {"ALTER TABLE t RENAME TO t2",          QIHSE_ALTER_RENAME_TABLE},
    };
    for (size_t i = 0; i < sizeof(alters) / sizeof(alters[0]); i++) {
        ast = qihse_parse_sql_to_ast(alters[i].sql);
        assert(ast);
        assert(ast->stmt_type == QIHSE_SQL_ALTER);
        assert(ast->alter_clause);
        assert(ast->alter_clause->action == alters[i].want);
        assert(strcmp(ast->table_name, "t") == 0);
        qihse_sql_ast_free(ast);
    }

    /* CREATE INDEX / DROP INDEX / DROP TABLE. */
    ast = qihse_parse_sql_to_ast("CREATE INDEX idx ON t (a)");
    assert(ast);
    assert(ast->stmt_type == QIHSE_SQL_CREATE);
    assert(ast->index_def);
    assert(strcmp(ast->index_def->name, "idx") == 0);
    assert(strcmp(ast->index_def->table_name, "t") == 0);
    assert(strcmp(ast->index_def->column_name, "a") == 0);
    qihse_sql_ast_free(ast);

    ast = qihse_parse_sql_to_ast("DROP INDEX idx");
    assert(ast);
    assert(ast->stmt_type == QIHSE_SQL_DROP);
    assert(ast->drop_is_index == 1);
    assert(strcmp(ast->drop_name, "idx") == 0);
    qihse_sql_ast_free(ast);

    ast = qihse_parse_sql_to_ast("DROP TABLE t");
    assert(ast);
    assert(ast->stmt_type == QIHSE_SQL_DROP);
    assert(ast->drop_is_index == 0);
    assert(strcmp(ast->drop_name, "t") == 0);
    qihse_sql_ast_free(ast);

    printf("PASS sql parser: INSERT rows, UPDATE/DELETE recognition, CREATE TABLE types, "
           "ALTER, CREATE/DROP INDEX, DROP TABLE\n");
}

/* ── Row-stream helpers for the executor tests ──────────────────────────── */

static qihse_exec_row_t* row_of(qihse_exec_schema_t* schema, const char* v0,
                                const char* v1, const char* v2) {
    qihse_exec_row_t* r = (qihse_exec_row_t*)calloc(1, sizeof(*r));
    r->num_values = schema->num_cols;
    r->values = (char**)calloc(schema->num_cols, sizeof(char*));
    const char* src[3] = {v0, v1, v2};
    for (size_t i = 0; i < schema->num_cols; i++)
        r->values[i] = src[i] ? strdup(src[i]) : NULL;
    return r;
}

/* Consume a stream into a caller-owned array; caller frees each row. */
static size_t drain(qihse_row_stream_t* s, qihse_exec_row_t* out, size_t cap) {
    size_t n = 0;
    qihse_exec_row_t* r;
    while (n < cap && (r = qihse_row_stream_next(s)) != NULL) {
        out[n++] = *r;
        free(r);
    }
    return n;
}

static void free_rows(qihse_exec_row_t* rows, size_t n) {
    for (size_t i = 0; i < n; i++) qihse_exec_row_free(&rows[i]);
}

/* ── Join execution ─────────────────────────────────────────────────────── */

static void test_join_execution(void) {
    qihse_exec_schema_t left_schema = {(char*[]){"id", "name"}, 2};
    qihse_exec_schema_t right_schema = {(char*[]){"id", "dept"}, 2};

    qihse_exec_row_t left_rows[3];
    left_rows[0] = *row_of(&left_schema, "1", "alice", NULL);
    left_rows[1] = *row_of(&left_schema, "2", "bob", NULL);
    left_rows[2] = *row_of(&left_schema, "3", "carol", NULL);
    qihse_exec_row_t right_rows[2];
    right_rows[0] = *row_of(&right_schema, "1", "eng", NULL);
    right_rows[1] = *row_of(&right_schema, "2", "ops", NULL);

    qihse_exec_row_t out[16];

    /* Hash join, inner: ids 1 and 2 match; 4 output columns. */
    qihse_row_stream_t* build = qihse_row_array_stream_create(&left_schema, left_rows, 3);
    qihse_row_stream_t* probe = qihse_row_array_stream_create(&right_schema, right_rows, 2);
    qihse_row_stream_t* join = qihse_hash_join_create(build, probe, "id", "id",
                                                      QIHSE_JOIN_INNER);
    assert(join);
    assert(join->schema && join->schema->num_cols == 4);
    size_t n = drain(join, out, 16);
    assert(n == 2);
    int seen1 = 0, seen2 = 0;
    for (size_t i = 0; i < n; i++) {
        assert(out[i].num_values == 4);
        if (strcmp(out[i].values[0], "1") == 0) {
            assert(strcmp(out[i].values[1], "alice") == 0);
            assert(strcmp(out[i].values[3], "eng") == 0);
            seen1++;
        }
        if (strcmp(out[i].values[0], "2") == 0) {
            assert(strcmp(out[i].values[3], "ops") == 0);
            seen2++;
        }
    }
    assert(seen1 == 1 && seen2 == 1);
    free_rows(out, n);
    qihse_row_stream_close(join);

    /* Nested-loop LEFT join: carol is preserved with NULL right columns. */
    build = qihse_row_array_stream_create(&left_schema, left_rows, 3);
    probe = qihse_row_array_stream_create(&right_schema, right_rows, 2);
    join = qihse_nested_loop_join_create(build, probe, "id", "id", QIHSE_JOIN_LEFT);
    assert(join);
    n = drain(join, out, 16);
    assert(n == 3);
    int unmatched = 0;
    for (size_t i = 0; i < n; i++) {
        if (strcmp(out[i].values[0], "3") == 0) {
            assert(strcmp(out[i].values[1], "carol") == 0);
            assert(out[i].values[2] == NULL);
            assert(out[i].values[3] == NULL);
            unmatched++;
        }
    }
    assert(unmatched == 1);
    free_rows(out, n);
    qihse_row_stream_close(join);

    /* Nested-loop CROSS join: 3 x 2 = 6 rows. */
    build = qihse_row_array_stream_create(&left_schema, left_rows, 3);
    probe = qihse_row_array_stream_create(&right_schema, right_rows, 2);
    join = qihse_nested_loop_join_create(build, probe, NULL, NULL, QIHSE_JOIN_CROSS);
    assert(join);
    n = drain(join, out, 16);
    assert(n == 6);
    free_rows(out, n);
    qihse_row_stream_close(join);

    /* Column lookup is case-insensitive. */
    assert(qihse_schema_find_col(&left_schema, "NAME") == 1);
    assert(qihse_schema_find_col(&left_schema, "absent") == -1);

    free_rows(left_rows, 3);
    free_rows(right_rows, 2);
    printf("PASS join executor: hash inner, nested-loop LEFT, CROSS, schema lookup\n");
}

/* ── Aggregate execution ────────────────────────────────────────────────── */

static void test_aggregate_execution(void) {
    qihse_exec_schema_t schema = {(char*[]){"dept", "amount"}, 2};
    qihse_exec_row_t rows[5];
    rows[0] = *row_of(&schema, "eng", "10", NULL);
    rows[1] = *row_of(&schema, "eng", "20", NULL);
    rows[2] = *row_of(&schema, "ops", "5", NULL);
    rows[3] = *row_of(&schema, "ops", "15", NULL);
    rows[4] = *row_of(&schema, "ops", "25", NULL);

    int group_cols[1] = {0};
    qihse_aggop_t aggs[6] = {
        {QIHSE_AGGOP_SUM, 1, 0},
        {QIHSE_AGGOP_COUNT, 1, 0},
        {QIHSE_AGGOP_COUNT_STAR, -1, 0},
        {QIHSE_AGGOP_AVG, 1, 0},
        {QIHSE_AGGOP_MIN, 1, 0},
        {QIHSE_AGGOP_MAX, 1, 0},
    };
    qihse_row_stream_t* input = qihse_row_array_stream_create(&schema, rows, 5);
    qihse_row_stream_t* agg = qihse_aggregate_create(input, group_cols, 1, aggs, 6);
    assert(agg);
    assert(agg->schema && agg->schema->num_cols == 7);  /* 1 group + 6 aggregates */

    qihse_exec_row_t out[8];
    size_t n = drain(agg, out, 8);
    assert(n == 2);
    int eng = 0, ops = 0;
    for (size_t i = 0; i < n; i++) {
        const char* dept = out[i].values[0];
        if (strcmp(dept, "eng") == 0) {
            eng++;
            assert(atof(out[i].values[1]) == 30.0);   /* SUM   */
            assert(atof(out[i].values[2]) == 2.0);    /* COUNT */
            assert(atof(out[i].values[3]) == 2.0);    /* COUNT(*) */
            assert(atof(out[i].values[4]) == 15.0);   /* AVG   */
            assert(atof(out[i].values[5]) == 10.0);   /* MIN   */
            assert(atof(out[i].values[6]) == 20.0);   /* MAX   */
        } else if (strcmp(dept, "ops") == 0) {
            ops++;
            assert(atof(out[i].values[1]) == 45.0);
            assert(atof(out[i].values[2]) == 3.0);
            assert(atof(out[i].values[3]) == 3.0);
            assert(atof(out[i].values[4]) == 15.0);
            assert(atof(out[i].values[5]) == 5.0);
            assert(atof(out[i].values[6]) == 25.0);
        } else {
            assert(0 && "unexpected group key");
        }
    }
    assert(eng == 1 && ops == 1);
    free_rows(out, n);
    qihse_row_stream_close(agg);

    /* Global aggregate (no GROUP BY): one row for the whole input. */
    qihse_aggop_t count_star[1] = {{QIHSE_AGGOP_COUNT_STAR, -1, 0}};
    input = qihse_row_array_stream_create(&schema, rows, 5);
    agg = qihse_aggregate_create(input, NULL, 0, count_star, 1);
    assert(agg);
    n = drain(agg, out, 8);
    assert(n == 1);
    assert(atof(out[0].values[0]) == 5.0);
    free_rows(out, n);
    qihse_row_stream_close(agg);

    free_rows(rows, 5);
    printf("PASS aggregate executor: GROUP BY with SUM/COUNT/COUNT(*)/AVG/MIN/MAX, global agg\n");
}

/* ── Sort execution ─────────────────────────────────────────────────────── */

static void test_sort_execution(void) {
    qihse_exec_schema_t schema = {(char*[]){"dept", "amount"}, 2};
    qihse_exec_row_t rows[5];
    rows[0] = *row_of(&schema, "ops", "5", NULL);
    rows[1] = *row_of(&schema, "eng", "20", NULL);
    rows[2] = *row_of(&schema, "ops", "25", NULL);
    rows[3] = *row_of(&schema, "eng", "10", NULL);
    rows[4] = *row_of(&schema, "ops", "15", NULL);

    /* dept ASC, amount DESC. */
    qihse_sort_key_t keys[2] = {{0, 1}, {1, 0}};
    qihse_row_stream_t* input = qihse_row_array_stream_create(&schema, rows, 5);
    qihse_row_stream_t* sorted = qihse_sort_create(input, keys, 2, 0);
    assert(sorted);
    qihse_exec_row_t out[8];
    size_t n = drain(sorted, out, 8);
    assert(n == 5);
    const char* want[5][2] = {
        {"eng", "20"}, {"eng", "10"},
        {"ops", "25"}, {"ops", "15"}, {"ops", "5"}
    };
    for (size_t i = 0; i < n; i++) {
        assert(strcmp(out[i].values[0], want[i][0]) == 0);
        assert(strcmp(out[i].values[1], want[i][1]) == 0);
    }
    free_rows(out, n);
    qihse_row_stream_close(sorted);

    /* A single key ASC. */
    qihse_sort_key_t one[1] = {{1, 1}};
    input = qihse_row_array_stream_create(&schema, rows, 5);
    sorted = qihse_sort_create(input, one, 1, 0);
    assert(sorted);
    n = drain(sorted, out, 8);
    assert(n == 5);
    const char* want_asc[5] = {"5", "10", "15", "20", "25"};
    for (size_t i = 0; i < n; i++)
        assert(strcmp(out[i].values[1], want_asc[i]) == 0);
    free_rows(out, n);
    qihse_row_stream_close(sorted);

    /* Spill-to-disk: a threshold small enough that the input must be written
     * to temporary runs and merged back. */
    qihse_exec_row_t many[20];
    for (int i = 0; i < 20; i++) {
        char v[16];
        snprintf(v, sizeof(v), "%d", 100 - i * 3);
        many[i] = *row_of(&schema, (i % 2) ? "ops" : "eng", v, NULL);
    }
    input = qihse_row_array_stream_create(&schema, many, 20);
    sorted = qihse_sort_create(input, one, 1, 32);   /* 32-byte buffer => spills */
    assert(sorted);
    n = drain(sorted, out, 8);
    assert(n == 8);   /* out[] only has room for 8; the first 8 must be ordered */
    for (size_t i = 1; i < n; i++) {
        int prev = atoi(out[i - 1].values[1]);
        int cur = atoi(out[i].values[1]);
        assert(cur >= prev);
    }
    assert(atoi(out[0].values[1]) == 43);   /* 100 - 19*3, the smallest key */
    free_rows(out, n);
    qihse_row_stream_close(sorted);
    free_rows(many, 20);

    free_rows(rows, 5);
    printf("PASS sort executor: multi-key ASC/DESC, single-key and spill-to-disk runs\n");
}

/* ── Schema registry ────────────────────────────────────────────────────── */

static void test_schema_registry(void) {
    qihse_schema_registry_t* reg = qihse_schema_registry_create();
    assert(reg);
    assert(qihse_schema_table_count(reg) == 0);

    qihse_sql_ast_t* ast = qihse_parse_sql_to_ast(
        "CREATE TABLE users (id INT PRIMARY KEY, name TEXT NOT NULL, age INT)");
    assert(ast);
    assert(qihse_schema_create_table(reg, ast) == 0);
    qihse_sql_ast_free(ast);

    assert(qihse_schema_table_count(reg) == 1);
    const qihse_schema_table_t* t = qihse_schema_get_table(reg, "users");
    assert(t);
    assert(strcmp(t->name, "users") == 0);
    assert(t->num_columns == 3);
    assert(strcmp(t->columns[0].name, "id") == 0);
    assert(t->columns[0].is_primary_key == 1);
    assert(strcmp(t->columns[1].name, "name") == 0);
    assert(t->columns[1].not_null == 1);
    assert(t->columns[1].type == QIHSE_TYPE_TEXT);
    assert(qihse_schema_table_at(reg, 0) == t);
    assert(qihse_schema_get_table(reg, "absent") == NULL);

    /* Index registration and lookup by table+column. */
    ast = qihse_parse_sql_to_ast("CREATE INDEX idx_age ON users (age)");
    assert(ast);
    assert(qihse_schema_create_index(reg, ast) == 0);
    qihse_sql_ast_free(ast);
    const qihse_schema_index_t* idx = qihse_schema_get_index(reg, "idx_age");
    assert(idx);
    assert(strcmp(idx->table_name, "users") == 0);
    assert(strcmp(idx->column_name, "age") == 0);
    assert(qihse_schema_has_index(reg, "users", "age"));
    assert(!qihse_schema_has_index(reg, "users", "name"));
    assert(t->num_indexes == 1);

    /* ALTER TABLE ADD COLUMN goes through the same registry. */
    ast = qihse_parse_sql_to_ast("ALTER TABLE users ADD COLUMN email VARCHAR(64)");
    assert(ast);
    assert(qihse_schema_alter_table(reg, ast) == 0);
    qihse_sql_ast_free(ast);
    assert(t->num_columns == 4);
    assert(strcmp(t->columns[3].name, "email") == 0);
    assert(t->columns[3].type == QIHSE_TYPE_VARCHAR);
    assert(t->columns[3].type_len == 64);

    /* Drop index then table. */
    assert(qihse_schema_drop_index(reg, "idx_age") == 0);
    assert(qihse_schema_get_index(reg, "idx_age") == NULL);
    assert(!qihse_schema_has_index(reg, "users", "age"));
    assert(qihse_schema_drop_table(reg, "users") == 0);
    assert(qihse_schema_get_table(reg, "users") == NULL);
    assert(qihse_schema_table_count(reg) == 0);
    /* Dropping what is not there is an error. */
    assert(qihse_schema_drop_table(reg, "users") == -1);

    qihse_schema_registry_destroy(reg);
    printf("PASS schema registry: create table/index, alter add column, drop, lookup\n");
}

/* ── Cost-based optimizer ───────────────────────────────────────────────── */

static qihse_plan_node_type_t plan_type_for(qihse_optimizer_t* opt, const char* sql) {
    qihse_sql_ast_t* ast = qihse_parse_sql_to_ast(sql);
    assert(ast);
    qihse_plan_node_t* plan = qihse_optimizer_build_plan(opt, ast);
    assert(plan);
    qihse_plan_node_type_t type = plan->type;
    qihse_plan_node_free(plan);
    qihse_sql_ast_free(ast);
    return type;
}

static void test_optimizer_plans(void) {
    qihse_schema_registry_t* reg = qihse_schema_registry_create();
    assert(reg);
    qihse_sql_ast_t* ddl = qihse_parse_sql_to_ast(
        "CREATE TABLE users (id INT PRIMARY KEY, dept TEXT, age INT)");
    assert(ddl && qihse_schema_create_table(reg, ddl) == 0);
    qihse_sql_ast_free(ddl);

    qihse_optimizer_t* opt = qihse_optimizer_create(reg);
    assert(opt);
    qihse_optimizer_set_table_stats(opt, "users", 100000);
    qihse_optimizer_set_column_stats(opt, "users", "age", 50000, 0.0, "18", "95");
    const qihse_table_stat_t* st = qihse_optimizer_get_table_stats(opt, "users");
    assert(st && st->row_count == 100000);

    /* Selectivity estimate for an equality filter is 1/distinct. */
    qihse_sql_ast_t* ast = qihse_parse_sql_to_ast(
        "SELECT id FROM users WHERE age = 30");
    assert(ast);
    assert(ast->num_where_conditions == 1);
    double sel = qihse_optimizer_estimate_selectivity(opt, "users",
                                                      &ast->where_conditions[0]);
    assert(sel > 0.0 && sel <= 1.0);
    assert(sel < 0.001);   /* 1/50000 */
    qihse_sql_ast_free(ast);

    /* No index on age -> sequential scan. */
    assert(plan_type_for(opt, "SELECT id FROM users WHERE age = 30") == QIHSE_PLAN_SEQ_SCAN);
    /* A LIMIT wraps the plan. */
    assert(plan_type_for(opt, "SELECT id FROM users LIMIT 5") == QIHSE_PLAN_LIMIT);
    /* ORDER BY adds a sort under the limit. */
    assert(plan_type_for(opt, "SELECT id FROM users ORDER BY age LIMIT 5") == QIHSE_PLAN_LIMIT);
    assert(plan_type_for(opt, "SELECT id FROM users ORDER BY age") == QIHSE_PLAN_SORT);
    /* GROUP BY adds an aggregate. */
    assert(plan_type_for(opt, "SELECT COUNT(*) FROM users GROUP BY dept") == QIHSE_PLAN_AGGREGATE);
    /* A join becomes a join node. */
    qihse_plan_node_type_t jt = plan_type_for(opt,
        "SELECT u.id FROM users u INNER JOIN orders o ON u.id = o.id");
    assert(jt == QIHSE_PLAN_HASH_JOIN || jt == QIHSE_PLAN_NESTED_LOOP);
    /* A UNION of two selects is planned. */
    assert(plan_type_for(opt, "SELECT id FROM users UNION SELECT id FROM users") != 0);
    /* Non-SELECT statements have no query plan. */
    ast = qihse_parse_sql_to_ast("INSERT INTO users (id) VALUES (1)");
    assert(ast);
    assert(qihse_optimizer_build_plan(opt, ast) == NULL);
    qihse_sql_ast_free(ast);

    /* Adding an index on the filtered column switches the scan choice. */
    ddl = qihse_parse_sql_to_ast("CREATE INDEX users_age ON users (age)");
    assert(ddl && qihse_schema_create_index(reg, ddl) == 0);
    qihse_sql_ast_free(ddl);
    assert(plan_type_for(opt, "SELECT id FROM users WHERE age = 30") == QIHSE_PLAN_INDEX_SCAN);

    qihse_optimizer_destroy(opt);
    qihse_schema_registry_destroy(reg);
    printf("PASS optimizer: selectivity, seq/index scan choice, sort/limit/aggregate/join nodes\n");
}

/* ── Documented gaps (reported, not asserted) ───────────────────────────── */

static void report_known_gaps(void) {
    qihse_sql_ast_t* ast = qihse_parse_sql_to_ast("UPDATE t SET a = 1 WHERE id = 3");
    assert(ast);
    printf("NOTE sql parser: UPDATE ... SET captures %zu set columns "
           "(document claims SET support) -- see docs/architecture/sql_engine.md\n",
           ast->num_set);
    qihse_sql_ast_free(ast);

    ast = qihse_parse_sql_to_ast("DELETE FROM t WHERE id = 4");
    assert(ast);
    printf("NOTE sql parser: DELETE WHERE yields %zu structured conditions; raw text is "
           "kept in insert_select_query (%s) -- see docs/architecture/sql_engine.md\n",
           ast->num_where_conditions,
           ast->insert_select_query ? "present" : "absent");
    qihse_sql_ast_free(ast);

    ast = qihse_parse_sql_to_ast("SELECT (SELECT MAX(x) FROM s) AS m FROM t");
    assert(ast);
    printf("NOTE sql parser: select-list scalar subquery extracted: %s "
           "-- see docs/architecture/sql_engine.md\n",
           ast->select_items[0].scalar_subquery ? "yes" : "no");
    qihse_sql_ast_free(ast);
}

int main(void) {
    test_select_shape();
    test_aggregates_and_grouping();
    test_join_parsing();
    test_subqueries_and_set_ops();
    test_dml_and_ddl_parsing();
    test_join_execution();
    test_aggregate_execution();
    test_sort_execution();
    test_schema_registry();
    test_optimizer_plans();
    report_known_gaps();
    printf("test_sql_completeness: all SQL engine tests passed\n");
    return 0;
}
