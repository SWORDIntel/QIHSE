#ifndef QIHSE_SQL_PARSER_H
#define QIHSE_SQL_PARSER_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* -------------------------------------------------------------------------
 * Statement types
 * ------------------------------------------------------------------------- */
typedef enum {
    QIHSE_SQL_SELECT          = 1,
    QIHSE_SQL_INSERT          = 2,
    QIHSE_SQL_UPDATE          = 3,
    QIHSE_SQL_DELETE          = 4,
    QIHSE_SQL_CREATE          = 5,
    QIHSE_SQL_DROP            = 6,
    QIHSE_SQL_ALTER           = 7,
    QIHSE_SQL_UNION           = 8,
    QIHSE_SQL_INTERSECT       = 9,
    QIHSE_SQL_EXCEPT          = 10,
    QIHSE_SQL_WITH            = 11,  /* CTE wrapper */
    QIHSE_SQL_CREATE_VIEW     = 12,
    QIHSE_SQL_DROP_VIEW       = 13,
    QIHSE_SQL_CREATE_MATVIEW  = 14,
    QIHSE_SQL_REFRESH         = 15,
    QIHSE_SQL_CREATE_SEQ      = 16,
    QIHSE_SQL_DROP_SEQ        = 17,
    QIHSE_SQL_EXPLAIN         = 18,
    QIHSE_SQL_VACUUM          = 19,
    QIHSE_SQL_ANALYZE         = 20,
    QIHSE_SQL_LISTEN          = 21,
    QIHSE_SQL_NOTIFY          = 22,
    QIHSE_SQL_DECLARE         = 23,
    QIHSE_SQL_FETCH           = 24,
    QIHSE_SQL_CLOSE           = 25,
    /* Transaction control (TCL) */
    QIHSE_SQL_BEGIN           = 26,
    QIHSE_SQL_COMMIT          = 27,
    QIHSE_SQL_ROLLBACK        = 28,
    QIHSE_SQL_SAVEPOINT       = 29,
    QIHSE_SQL_RELEASE         = 30,
    QIHSE_SQL_SET_TXN         = 31,
    /* Data Control Language (DCL) */
    QIHSE_SQL_GRANT           = 32,
    QIHSE_SQL_REVOKE          = 33,
    QIHSE_SQL_CREATE_ROLE     = 34,
    QIHSE_SQL_DROP_ROLE       = 35,
    QIHSE_SQL_ALTER_ROLE      = 36,
    /* Utility commands */
    QIHSE_SQL_TRUNCATE        = 37,
    QIHSE_SQL_COPY            = 38,
    QIHSE_SQL_DISCARD         = 39,
    QIHSE_SQL_RESET           = 40,
    QIHSE_SQL_SET_PARAM       = 41,
    QIHSE_SQL_SHOW            = 42,
    QIHSE_SQL_DEALLOCATE      = 43,
    QIHSE_SQL_PREPARE         = 44,
    QIHSE_SQL_EXECUTE         = 45,
    QIHSE_SQL_REINDEX         = 46,
    QIHSE_SQL_CLUSTER         = 47,
    QIHSE_SQL_UNKNOWN         = 0
} qihse_sql_stmt_type_t;

/* -------------------------------------------------------------------------
 * Column / data types for DDL
 * ------------------------------------------------------------------------- */
typedef enum {
    QIHSE_TYPE_UNKNOWN    = 0,
    QIHSE_TYPE_INT        = 1,
    QIHSE_TYPE_BIGINT     = 2,
    QIHSE_TYPE_FLOAT      = 3,
    QIHSE_TYPE_DOUBLE     = 4,
    QIHSE_TYPE_VARCHAR    = 5,
    QIHSE_TYPE_TEXT       = 6,
    QIHSE_TYPE_BOOL       = 7,
    QIHSE_TYPE_TIMESTAMP  = 8,
    QIHSE_TYPE_VECTOR     = 9,
    QIHSE_TYPE_SERIAL     = 10,
    QIHSE_TYPE_BIGSERIAL  = 11,
    QIHSE_TYPE_INT_ARRAY  = 12,
    QIHSE_TYPE_FLOAT_ARRAY= 13,
    QIHSE_TYPE_TEXT_ARRAY = 14,
    QIHSE_TYPE_BOOL_ARRAY = 15,
    QIHSE_TYPE_JSONB      = 16
} qihse_sql_type_t;

/* -------------------------------------------------------------------------
 * Join types
 * ------------------------------------------------------------------------- */
typedef enum {
    QIHSE_JOIN_INNER  = 1,
    QIHSE_JOIN_LEFT   = 2,
    QIHSE_JOIN_RIGHT  = 3,
    QIHSE_JOIN_CROSS  = 4,
    QIHSE_JOIN_FULL   = 5
} qihse_sql_join_type_t;

/* -------------------------------------------------------------------------
 * Aggregate function kinds
 * ------------------------------------------------------------------------- */
typedef enum {
    QIHSE_AGG_NONE       = 0,
    QIHSE_AGG_SUM        = 1,
    QIHSE_AGG_COUNT      = 2,
    QIHSE_AGG_AVG        = 3,
    QIHSE_AGG_MIN        = 4,
    QIHSE_AGG_MAX        = 5,
    QIHSE_AGG_COUNT_STAR = 6,
    QIHSE_AGG_STRING_AGG = 7,
    QIHSE_AGG_ARRAY_AGG  = 8,
    QIHSE_AGG_BOOL_OR    = 9,
    QIHSE_AGG_BOOL_AND   = 10,
    QIHSE_AGG_VARIANCE   = 11,
    QIHSE_AGG_STDDEV     = 12,
    QIHSE_AGG_CORR       = 13,
    QIHSE_AGG_COVAR_SAMP = 14,
    QIHSE_AGG_COVAR_POP  = 15,
    QIHSE_AGG_EVERY      = 16  /* alias for bool_and */
} qihse_sql_agg_kind_t;

/* -------------------------------------------------------------------------
 * Window function kinds
 * ------------------------------------------------------------------------- */
typedef enum {
    QIHSE_WIN_NONE       = 0,
    QIHSE_WIN_ROW_NUMBER = 1,
    QIHSE_WIN_RANK       = 2,
    QIHSE_WIN_DENSE_RANK = 3,
    QIHSE_WIN_LAG        = 4,
    QIHSE_WIN_LEAD       = 5,
    QIHSE_WIN_SUM        = 6,
    QIHSE_WIN_AVG        = 7,
    QIHSE_WIN_COUNT      = 8,
    QIHSE_WIN_MIN        = 9,
    QIHSE_WIN_MAX        = 10,
    QIHSE_WIN_FIRST_VALUE= 11,
    QIHSE_WIN_LAST_VALUE = 12,
    QIHSE_WIN_NTH_VALUE  = 13,
    QIHSE_WIN_NTILE      = 14,
    QIHSE_WIN_PERCENT_RANK = 15,
    QIHSE_WIN_CUME_DIST  = 16
} qihse_sql_win_kind_t;

/* -------------------------------------------------------------------------
 * Window frame modes
 * ------------------------------------------------------------------------- */
typedef enum {
    QIHSE_FRAME_NONE     = 0,
    QIHSE_FRAME_ROWS     = 1,
    QIHSE_FRAME_RANGE    = 2
} qihse_sql_frame_mode_t;

/* -------------------------------------------------------------------------
 * Set operation kinds (UNION / INTERSECT / EXCEPT)
 * ------------------------------------------------------------------------- */
typedef enum {
    QIHSE_SET_NONE     = 0,
    QIHSE_SET_UNION    = 1,
    QIHSE_SET_UNION_ALL= 2,
    QIHSE_SET_INTERSECT= 3,
    QIHSE_SET_EXCEPT   = 4
} qihse_sql_set_op_t;

/* -------------------------------------------------------------------------
 * Subquery kinds
 * ------------------------------------------------------------------------- */
typedef enum {
    QIHSE_SUBQ_SCALAR  = 1,  /* scalar subquery in SELECT list */
    QIHSE_SUBQ_IN      = 2,  /* IN (subquery) in WHERE */
    QIHSE_SUBQ_NOT_IN  = 3,  /* NOT IN (subquery) in WHERE */
    QIHSE_SUBQ_EXISTS  = 4,  /* EXISTS (subquery) */
    QIHSE_SUBQ_NOT_EXISTS = 5
} qihse_sql_subq_kind_t;

/* -------------------------------------------------------------------------
 * ON CONFLICT action kinds
 * ------------------------------------------------------------------------- */
typedef enum {
    QIHSE_CONFLICT_NONE    = 0,
    QIHSE_CONFLICT_NOTHING = 1,
    QIHSE_CONFLICT_UPDATE  = 2
} qihse_sql_conflict_action_t;

/* -------------------------------------------------------------------------
 * Basic structures
 * ------------------------------------------------------------------------- */
typedef struct {
    char* column_name;
    char* table_name;
} qihse_sql_column_ref_t;

typedef struct {
    char* table_name;
    char* alias;
} qihse_sql_table_ref_t;

typedef struct {
    char* column_name;
    char* operator;     /* "=", "<>", "<", ">", "<=", ">=", "LIKE", "IN" */
    char* value;
    int   value_is_string;
    /* Subquery support for IN / EXISTS */
    qihse_sql_subq_kind_t subq_kind;
    struct qihse_sql_ast_s* subquery;  /* owned; freed with AST */
} qihse_sql_condition_t;

/* -------------------------------------------------------------------------
 * JOIN definition
 * ------------------------------------------------------------------------- */
typedef struct {
    qihse_sql_join_type_t join_type;
    qihse_sql_table_ref_t table;       /* joined table */
    char* left_key;                    /* join key column on the left side */
    char* right_key;                   /* join key column on the right side */
    char* on_condition;                /* raw ON expression (optional) */
} qihse_sql_join_t;

/* -------------------------------------------------------------------------
 * Window specification (OVER clause)
 * ------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------
 * ORDER BY item
 * ------------------------------------------------------------------------- */
typedef struct {
    char* column_name;
    int   ascending;   /* 1 = ASC, 0 = DESC */
} qihse_sql_order_item_t;

typedef struct {
    char** partition_by;          /* PARTITION BY column names */
    size_t num_partition_by;
    qihse_sql_order_item_t* order_by;  /* ORDER BY within OVER */
    size_t num_order_by;
    qihse_sql_frame_mode_t frame_mode;
    int frame_preceding;          /* N PRECEDING, -1 = UNBOUNDED */
    int frame_following;          /* N FOLLOWING, -1 = UNBOUNDED */
} qihse_sql_window_spec_t;

/* -------------------------------------------------------------------------
 * SELECT-list item (supports aggregates, aliases, window functions)
 * ------------------------------------------------------------------------- */
typedef struct {
    char*  expr;            /* raw expression text (e.g. "a.x", "COUNT(*)") */
    char*  alias;           /* optional output alias */
    qihse_sql_agg_kind_t agg_kind;
    char*  agg_arg;         /* argument column for aggregate, or "*" for COUNT(*) */
    int    is_distinct;     /* DISTINCT applied to this item */
    struct qihse_sql_ast_s* scalar_subquery; /* scalar subquery in select list */
    /* Window function support */
    qihse_sql_win_kind_t win_kind;
    char*  win_arg;         /* argument for LAG/LEAD/SUM/etc. */
    int    win_offset;      /* LAG/LEAD offset (default 1) */
    char*  win_default;     /* LAG/LEAD default value */
    qihse_sql_window_spec_t* window;  /* OVER(...) spec; NULL if not window */
} qihse_sql_select_item_t;

/* -------------------------------------------------------------------------
 * GROUP BY / HAVING
 * ------------------------------------------------------------------------- */
typedef struct {
    char** group_columns;
    size_t num_group_columns;
    char*  having_expr;   /* raw HAVING expression text (optional) */
} qihse_sql_group_by_t;

/* -------------------------------------------------------------------------
 * Foreign key constraint
 * ------------------------------------------------------------------------- */
typedef enum {
    QIHSE_FK_NO_ACTION = 0,
    QIHSE_FK_CASCADE   = 1,
    QIHSE_FK_SET_NULL  = 2,
    QIHSE_FK_RESTRICT  = 3
} qihse_sql_fk_action_t;

typedef struct {
    char** columns;              /* local columns */
    size_t num_columns;
    char*  ref_table;
    char** ref_columns;
    size_t num_ref_columns;
    qihse_sql_fk_action_t on_delete;
    qihse_sql_fk_action_t on_update;
} qihse_sql_fk_t;

/* -------------------------------------------------------------------------
 * CHECK and UNIQUE table-level constraints
 * ------------------------------------------------------------------------- */
typedef struct {
    char*  expr;                 /* CHECK expression text */
    char*  name;                 /* optional constraint name */
} qihse_sql_check_t;

typedef struct {
    char** columns;
    size_t num_columns;
    char*  name;                 /* optional constraint name */
} qihse_sql_unique_t;

/* -------------------------------------------------------------------------
 * DDL: column definition (extended with FK / CHECK / SERIAL)
 * ------------------------------------------------------------------------- */
typedef struct {
    char*             name;
    qihse_sql_type_t  type;
    int               type_len;     /* length for VARCHAR / VECTOR dim */
    int               not_null;
    int               is_primary_key;
    char*             default_expr; /* raw default expression (optional) */
    int               is_unique;    /* column-level UNIQUE */
    int               is_serial;    /* SERIAL / BIGSERIAL */
    qihse_sql_fk_t*   fk;           /* column-level REFERENCES (optional) */
    char*             check_expr;   /* column-level CHECK (optional) */
} qihse_sql_column_def_t;

typedef struct {
    char* name;
    char* table_name;
    char* column_name;   /* single-column index; NULL if multi-column */
    int   unique;
} qihse_sql_index_def_t;

/* -------------------------------------------------------------------------
 * ALTER TABLE actions
 * ------------------------------------------------------------------------- */
typedef enum {
    QIHSE_ALTER_ADD_COLUMN   = 1,
    QIHSE_ALTER_DROP_COLUMN  = 2,
    QIHSE_ALTER_RENAME_TABLE = 3,
    QIHSE_ALTER_RENAME_COLUMN= 4
} qihse_sql_alter_action_t;

typedef struct {
    qihse_sql_alter_action_t action;
    char*  column_name;     /* for ADD/DROP/RENAME COLUMN */
    char*  new_name;        /* new name for RENAME */
    qihse_sql_column_def_t* add_column; /* for ADD COLUMN (owned) */
} qihse_sql_alter_clause_t;

/* -------------------------------------------------------------------------
 * ON CONFLICT (UPSERT) clause
 * ------------------------------------------------------------------------- */
typedef struct {
    qihse_sql_conflict_action_t action;
    char** conflict_columns;     /* conflict target columns */
    size_t num_conflict_columns;
    /* DO UPDATE SET col = expr, ... [WHERE expr] */
    char** set_columns;
    char** set_values;
    size_t num_set;
    char*  where_expr;           /* optional WHERE on the UPDATE */
} qihse_sql_on_conflict_t;

/* -------------------------------------------------------------------------
 * RETURNING clause
 * ------------------------------------------------------------------------- */
typedef struct {
    char** columns;     /* column names; NULL entry means "*" */
    size_t num_columns;
    int    is_star;     /* RETURNING * */
} qihse_sql_returning_t;

/* -------------------------------------------------------------------------
 * CTE definition (WITH clause)
 * ------------------------------------------------------------------------- */
typedef struct {
    char* name;                  /* CTE name */
    int   recursive;             /* WITH RECURSIVE */
    struct qihse_sql_ast_s* query; /* owned subquery AST */
} qihse_sql_cte_def_t;

typedef struct {
    qihse_sql_cte_def_t* ctes;
    size_t num_ctes;
    struct qihse_sql_ast_s* body; /* main query (owned) */
} qihse_sql_with_t;

/* -------------------------------------------------------------------------
 * Sequence definition (CREATE SEQUENCE)
 * ------------------------------------------------------------------------- */
typedef struct {
    char* name;
    int64_t start;
    int64_t increment;
    int64_t minvalue;
    int64_t maxvalue;
    int   cycle;          /* CYCLE / NO CYCLE */
} qihse_sql_sequence_def_t;

/* -------------------------------------------------------------------------
 * Cursor definition (DECLARE)
 * ------------------------------------------------------------------------- */
typedef struct {
    char* name;
    struct qihse_sql_ast_s* query; /* owned */
    int   scroll;          /* SCROLL / NO SCROLL */
} qihse_sql_cursor_def_t;

/* -------------------------------------------------------------------------
 * Generic utility command descriptor
 *
 * Used by transaction control (BEGIN/COMMIT/ROLLBACK/SAVEPOINT/RELEASE),
 * data control language (GRANT/REVOKE/CREATE ROLE/DROP ROLE/ALTER ROLE),
 * and utility commands (TRUNCATE/COPY/DISCARD/RESET/SET/SHOW/DEALLOCATE/
 * PREPARE/EXECUTE/REINDEX/CLUSTER).  These commands are mostly recognised
 * and acknowledged; the fields below carry the parsed details.
 * ------------------------------------------------------------------------- */
typedef struct qihse_sql_util_s {
    char*  name;        /* primary name: role, savepoint, param, cursor, table */
    char*  value;       /* secondary value: password, param value, file path */
    char*  name2;       /* secondary name: referenced table, target type */
    char** list;        /* list of names/privileges (truncate tables, grant privs) */
    size_t num_list;
    char** list2;       /* second list (e.g. COPY column list, EXECUTE args) */
    size_t num_list2;
    int    flags;       /* command-specific flags (read-only, with-grant, cascade...) */
    int    flags2;      /* additional flags (isolation level, direction...) */
    struct qihse_sql_ast_s* subquery; /* COPY (SELECT...), PREPARE AS, DECLARE FOR */
} qihse_sql_util_t;

/* utility flag constants */
#define QIHSE_UTIL_READ_ONLY      0x01
#define QIHSE_UTIL_WITH_GRANT     0x02
#define QIHSE_UTIL_CASCADE        0x04
#define QIHSE_UTIL_RESTRICT       0x08
#define QIHSE_UTIL_RESTART_ID     0x10
#define QIHSE_UTIL_CONTINUE_ID    0x20
#define QIHSE_UTIL_HOLD           0x40
#define QIHSE_UTIL_ALL            0x80
#define QIHSE_UTIL_VERBOSE        0x100
#define QIHSE_UTIL_ANALYZE_FLAG   0x200
#define QIHSE_UTIL_FROM           0x400  /* COPY FROM (import) vs TO (export) */

/* -------------------------------------------------------------------------
 * AST node
 * ------------------------------------------------------------------------- */
typedef struct qihse_sql_ast_s {
    qihse_sql_stmt_type_t stmt_type;

    /* SELECT */
    qihse_sql_select_item_t* select_items;
    size_t num_select_items;
    qihse_sql_table_ref_t* from_tables;
    size_t num_from_tables;
    qihse_sql_join_t* joins;
    size_t num_joins;
    qihse_sql_condition_t* where_conditions;
    size_t num_where_conditions;
    qihse_sql_group_by_t* group_by;     /* NULL if no GROUP BY */
    qihse_sql_order_item_t* order_items;
    size_t num_order_items;
    int limit;
    int offset;
    int select_distinct;                /* SELECT DISTINCT */

    /* Set operations (UNION/INTERSECT/EXCEPT) */
    qihse_sql_set_op_t set_op;
    struct qihse_sql_ast_s* set_left;   /* left operand (owned) */
    struct qihse_sql_ast_s* set_right;  /* right operand (owned) */

    /* DDL: CREATE TABLE / CREATE INDEX / DROP */
    char* table_name;                   /* target table for DDL/DML */
    qihse_sql_column_def_t* columns;    /* CREATE TABLE columns (owned) */
    size_t num_columns;
    qihse_sql_index_def_t* index_def;   /* CREATE INDEX (owned) */
    int   drop_is_index;                /* DROP INDEX vs DROP TABLE */
    char* drop_name;                    /* name of object to drop */

    /* ALTER TABLE */
    qihse_sql_alter_clause_t* alter_clause; /* owned */

    /* CTE (WITH) */
    qihse_sql_with_t* with_clause;      /* owned */

    /* ON CONFLICT (UPSERT) */
    qihse_sql_on_conflict_t* on_conflict; /* owned */

    /* RETURNING */
    qihse_sql_returning_t* returning;   /* owned */

    /* Table-level constraints (CREATE TABLE) */
    qihse_sql_fk_t*       fks;          /* array of FK constraints */
    size_t num_fks;
    qihse_sql_check_t*    checks;       /* array of CHECK constraints */
    size_t num_checks;
    qihse_sql_unique_t*   uniques;      /* array of UNIQUE constraints */
    size_t num_uniques;

    /* CREATE SEQUENCE */
    qihse_sql_sequence_def_t* seq_def;  /* owned */

    /* CREATE VIEW / MATERIALIZED VIEW */
    char* view_name;                    /* view name */
    struct qihse_sql_ast_s* view_query; /* owned SELECT AST for the view */

    /* EXPLAIN / EXPLAIN ANALYZE */
    int   explain_analyze;              /* 1 = EXPLAIN ANALYZE */
    struct qihse_sql_ast_s* explain_query; /* owned query to explain */

    /* VACUUM / ANALYZE target (NULL = all tables) */
    char* vacuum_table;

    /* LISTEN / NOTIFY */
    char* notify_channel;
    char* notify_payload;               /* NOTIFY payload (optional) */

    /* DECLARE CURSOR */
    qihse_sql_cursor_def_t* cursor_def; /* owned */

    /* FETCH cursor */
    char* fetch_cursor;
    int   fetch_count;                  /* FETCH n; 0 = FETCH 1, -1 = FETCH ALL */

    /* CLOSE cursor */
    char* close_cursor;

    /* Generic utility command (TCL / DCL / utility) */
    qihse_sql_util_t* util;            /* owned */

    /* INSERT specifics */
    char** insert_columns;              /* column names for INSERT */
    size_t num_insert_columns;
    char*** insert_rows;                /* each row is array of value strings */
    size_t num_insert_rows;
    char*  insert_select_query;         /* raw INSERT ... SELECT text */

    /* UPDATE specifics */
    char** set_columns;
    char** set_values;
    size_t num_set;

    /* raw */
    char* raw_sql;
} qihse_sql_ast_t;

/* -------------------------------------------------------------------------
 * Public API
 * ------------------------------------------------------------------------- */
qihse_sql_ast_t* qihse_parse_sql_to_ast(const char* sql);

void qihse_sql_ast_free(qihse_sql_ast_t* ast);

/* Helper: convert type enum to string name */
const char* qihse_sql_type_name(qihse_sql_type_t t);

/* Helper: convert join type enum to string name */
const char* qihse_sql_join_type_name(qihse_sql_join_type_t j);

/* Helper: convert aggregate kind to string name */
const char* qihse_sql_agg_name(qihse_sql_agg_kind_t a);

/* Helper: convert window kind to string name */
const char* qihse_sql_win_name(qihse_sql_win_kind_t w);

/* Helper: convert statement type to string name */
const char* qihse_sql_stmt_name(qihse_sql_stmt_type_t s);

#ifdef __cplusplus
}
#endif

#endif
