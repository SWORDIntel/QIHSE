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
    QIHSE_SQL_SELECT   = 1,
    QIHSE_SQL_INSERT   = 2,
    QIHSE_SQL_UPDATE   = 3,
    QIHSE_SQL_DELETE   = 4,
    QIHSE_SQL_CREATE   = 5,
    QIHSE_SQL_DROP     = 6,
    QIHSE_SQL_ALTER    = 7,
    QIHSE_SQL_UNION    = 8,
    QIHSE_SQL_INTERSECT= 9,
    QIHSE_SQL_EXCEPT   = 10,
    QIHSE_SQL_UNKNOWN  = 0
} qihse_sql_stmt_type_t;

/* -------------------------------------------------------------------------
 * Column / data types for DDL
 * ------------------------------------------------------------------------- */
typedef enum {
    QIHSE_TYPE_UNKNOWN = 0,
    QIHSE_TYPE_INT     = 1,
    QIHSE_TYPE_BIGINT  = 2,
    QIHSE_TYPE_FLOAT   = 3,
    QIHSE_TYPE_DOUBLE  = 4,
    QIHSE_TYPE_VARCHAR = 5,
    QIHSE_TYPE_TEXT    = 6,
    QIHSE_TYPE_BOOL    = 7,
    QIHSE_TYPE_TIMESTAMP = 8,
    QIHSE_TYPE_VECTOR  = 9
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
    QIHSE_AGG_NONE   = 0,
    QIHSE_AGG_SUM    = 1,
    QIHSE_AGG_COUNT  = 2,
    QIHSE_AGG_AVG    = 3,
    QIHSE_AGG_MIN    = 4,
    QIHSE_AGG_MAX    = 5,
    QIHSE_AGG_COUNT_STAR = 6
} qihse_sql_agg_kind_t;

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
 * SELECT-list item (supports aggregates and aliases)
 * ------------------------------------------------------------------------- */
typedef struct {
    char*  expr;            /* raw expression text (e.g. "a.x", "COUNT(*)") */
    char*  alias;           /* optional output alias */
    qihse_sql_agg_kind_t agg_kind;
    char*  agg_arg;         /* argument column for aggregate, or "*" for COUNT(*) */
    int    is_distinct;     /* DISTINCT applied to this item */
    struct qihse_sql_ast_s* scalar_subquery; /* scalar subquery in select list */
} qihse_sql_select_item_t;

/* -------------------------------------------------------------------------
 * ORDER BY item
 * ------------------------------------------------------------------------- */
typedef struct {
    char* column_name;
    int   ascending;   /* 1 = ASC, 0 = DESC */
} qihse_sql_order_item_t;

/* -------------------------------------------------------------------------
 * GROUP BY / HAVING
 * ------------------------------------------------------------------------- */
typedef struct {
    char** group_columns;
    size_t num_group_columns;
    char*  having_expr;   /* raw HAVING expression text (optional) */
} qihse_sql_group_by_t;

/* -------------------------------------------------------------------------
 * DDL: column definition
 * ------------------------------------------------------------------------- */
typedef struct {
    char*             name;
    qihse_sql_type_t  type;
    int               type_len;     /* length for VARCHAR / VECTOR dim */
    int               not_null;
    int               is_primary_key;
    char*             default_expr; /* raw default expression (optional) */
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

#ifdef __cplusplus
}
#endif

#endif
