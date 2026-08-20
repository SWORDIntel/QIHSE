#ifndef QIHSE_CYPHER_PARSER_H
#define QIHSE_CYPHER_PARSER_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * QIHSE Cypher Parser — recursive-descent parser producing an AST.
 * ============================================================================ */

typedef enum {
    CYPHER_MATCH,
    CYPHER_CREATE,
    CYPHER_MERGE,
    CYPHER_DELETE,
    CYPHER_SET,
    CYPHER_REMOVE,
    CYPHER_RETURN,
    CYPHER_WITH,
    CYPHER_WHERE,
    CYPHER_ORDER_BY,
    CYPHER_LIMIT,
    CYPHER_SKIP,
    CYPHER_UNWIND,
    CYPHER_UNION,
    CYPHER_LOAD_CSV,
    CYPHER_CALL,
    CYPHER_FOREACH,
    CYPHER_CREATE_INDEX,
    CYPHER_DROP_INDEX,
    CYPHER_SHOW_INDEXES,
    CYPHER_CREATE_CONSTRAINT,
    CYPHER_DROP_CONSTRAINT,
    CYPHER_SHOW_CONSTRAINTS,
    CYPHER_CREATE_DATABASE,
    CYPHER_DROP_DATABASE,
    CYPHER_SHOW_DATABASES,
    CYPHER_SHOW,
    CYPHER_EXPLAIN,
    CYPHER_PROFILE,
    CYPHER_USE,
    CYPHER_PERIODIC_COMMIT,
    CYPHER_START_DATABASE,
    CYPHER_STOP_DATABASE,
    CYPHER_ALTER_DATABASE
} qihse_cypher_clause_type_t;

/* --- expression types --- */
typedef enum {
    CEXPR_LITERAL_INT,
    CEXPR_LITERAL_DBL,
    CEXPR_LITERAL_STR,
    CEXPR_LITERAL_BOOL,
    CEXPR_LITERAL_NULL,
    CEXPR_PARAM,        /* $name */
    CEXPR_VAR,          /* identifier */
    CEXPR_PROP_ACCESS,  /* var.prop */
    CEXPR_FUNC_CALL,
    CEXPR_AGG_CALL,
    CEXPR_LIST,         /* [a, b, c] */
    CEXPR_MAP,          /* {k: v, ...} */
    CEXPR_CASE,
    CEXPR_BINOP,
    CEXPR_UNARYOP,
    CEXPR_STAR,         /* * (for count(*)) */
    CEXPR_LIST_COMP,    /* [x IN list WHERE pred | expr] */
    CEXPR_PATTERN_COMP, /* [(n)-[:R]->(m) | m.name] */
    CEXPR_INDEX_ACCESS, /* list[i] */
    CEXPR_SLICE,        /* list[i..j] */
    CEXPR_SUBQUERY      /* CALL { ... } / EXISTS { ... } */
} cypher_expr_type_t;

typedef enum {
    COP_AND, COP_OR, COP_NOT,
    COP_EQ, COP_NE, COP_LT, COP_GT, COP_LE, COP_GE,
    COP_IN, COP_STARTS_WITH, COP_ENDS_WITH, COP_CONTAINS,
    COP_IS_NULL, COP_IS_NOT_NULL, COP_EXISTS,
    COP_ADD, COP_SUB, COP_MUL, COP_DIV, COP_MOD
} cypher_op_t;

typedef struct cypher_expr_s cypher_expr_t;
typedef struct qihse_cypher_query_s qihse_cypher_query_t;
typedef struct cypher_path_s cypher_path_t;
typedef struct qihse_cypher_clause_s qihse_cypher_clause_t;

struct cypher_expr_s {
    cypher_expr_type_t type;
    /* literal values */
    int64_t i_val;
    double d_val;
    char* s_val;       /* string literal, var name, param name, func name */
    bool b_val;
    /* children */
    cypher_expr_t* left;
    cypher_expr_t* right;
    cypher_op_t op;
    /* list/map */
    cypher_expr_t** items;
    char** keys;        /* for map */
    size_t count;
    /* function call args */
    cypher_expr_t** args;
    size_t nargs;
    bool distinct;      /* for aggregates / collect */
    /* case */
    cypher_expr_t** when_exprs;
    cypher_expr_t** then_exprs;
    size_t ncase;
    cypher_expr_t* else_expr;
    /* list comprehension: [var IN list_expr WHERE where_expr | proj_expr] */
    char* comp_var;          /* loop variable name */
    cypher_expr_t* comp_list; /* list to iterate */
    cypher_expr_t* comp_where;/* optional WHERE predicate */
    cypher_expr_t* comp_proj; /* optional projection expression */
    /* pattern comprehension */
    cypher_path_t* comp_path; /* pattern to match */
    /* index access / slice: list[index] or list[start..end] */
    cypher_expr_t* idx_start; /* index (for INDEX_ACCESS) or start (for SLICE) */
    cypher_expr_t* idx_end;   /* end for SLICE, NULL for open-ended */
    /* subquery: stores a query AST */
    struct qihse_cypher_query_s* subquery;
    int subquery_kind;  /* 0=CALL, 1=EXISTS, 2=COUNT, 3=COLLECT */
};

/* --- patterns --- */
typedef struct {
    char* var;          /* variable name, may be NULL */
    char* label;        /* label, may be NULL */
    cypher_expr_t** prop_keys;   /* property map keys (as string literals) */
    cypher_expr_t** prop_vals;
    size_t num_props;
} cypher_node_pattern_t;

typedef enum {
    CREL_DIR_NONE,      /* -[r]- */
    CREL_DIR_LEFT,      /* <-[r]- */
    CREL_DIR_RIGHT,     /* -[r]-> */
    CREL_DIR_BOTH       /* -[r]- (undirected, treated as both) */
} cypher_rel_dir_t;

typedef struct {
    char* var;
    char* rel_type;
    cypher_rel_dir_t direction;
    int var_len_min;    /* variable-length, -1 if not variable-length */
    int var_len_max;
    cypher_expr_t** prop_keys;
    cypher_expr_t** prop_vals;
    size_t num_props;
} cypher_rel_pattern_t;

struct cypher_path_s {
    cypher_node_pattern_t** nodes;
    size_t num_nodes;
    cypher_rel_pattern_t** rels;
    size_t num_rels;
};

/* --- return items --- */
typedef struct {
    cypher_expr_t* expr;
    char* alias;        /* AS alias, may be NULL */
} cypher_return_item_t;

/* --- set/remove items --- */
typedef struct {
    char* var;
    char* prop;         /* NULL for label ops */
    char* label;        /* for SET n:Label / REMOVE n:Label */
    cypher_expr_t* value; /* for SET n.prop = value */
} cypher_set_item_t;

/* --- order by --- */
typedef struct {
    cypher_expr_t* expr;
    bool descending;
    bool nulls_first;  /* NULLS FIRST */
    bool nulls_last;   /* NULLS LAST */
} cypher_order_item_t;

/* --- clause --- */
struct qihse_cypher_clause_s {
    qihse_cypher_clause_type_t type;
    /* MATCH / CREATE / MERGE */
    cypher_path_t** paths;
    size_t num_paths;
    /* WHERE */
    cypher_expr_t* where;
    /* RETURN / WITH */
    cypher_return_item_t** items;
    size_t num_items;
    bool distinct;
    bool return_star;  /* RETURN * */
    /* SET / REMOVE */
    cypher_set_item_t** set_items;
    size_t num_set_items;
    /* DELETE */
    char** del_vars;
    size_t num_del_vars;
    bool detach;
    /* ORDER BY */
    cypher_order_item_t** order_items;
    size_t num_order_items;
    /* SKIP / LIMIT */
    int64_t skip;
    int64_t limit;
    /* UNWIND */
    cypher_expr_t* unwind_expr;
    char* unwind_var;
    /* UNION */
    bool union_all;
    /* LOAD CSV */
    char* csv_uri;         /* file path or URL */
    char* csv_var;         /* row variable name */
    bool csv_with_headers; /* WITH HEADERS */
    char csv_field_term;   /* FIELDTERMINATOR char, 0 = comma */
    int periodic_commit;   /* PERIODIC COMMIT n, 0 = none */
    /* CALL procedure */
    char* proc_namespace;  /* e.g. "db", "dbms", "apoc" */
    char* proc_name;       /* e.g. "labels", "security.createUser" */
    cypher_expr_t** proc_args;
    size_t num_proc_args;
    char** yield_vars;     /* YIELD var1, var2 */
    size_t num_yield_vars;
    qihse_cypher_query_t* call_subquery; /* CALL { ... } subquery */
    int call_in_transactions; /* IN TRANSACTIONS OF n ROWS, 0 = none */
    /* FOREACH */
    char* foreach_var;     /* loop variable */
    cypher_expr_t* foreach_list; /* list expression */
    qihse_cypher_clause_t* foreach_body; /* body clause chain */
    /* Schema: index/constraint/database name and details */
    char* schema_name;     /* index/constraint/database name */
    char* schema_label;    /* label for index/constraint */
    char** schema_props;   /* property names */
    size_t num_schema_props;
    int schema_kind;       /* constraint kind: 0=unique,1=node key,2=exists,3=not null */
    bool schema_if_exists; /* IF EXISTS / IF NOT EXISTS */
    bool schema_rel;       /* relationship constraint */
    char* schema_rel_type; /* relationship type */
    int db_access;         /* 0=read only, 1=read write */
    /* SHOW */
    int show_kind;         /* 0=all, 1=built in, 2=procedures, 3=functions */
    char* show_user;       /* EXECUTABLE BY user */
    bool show_yield;       /* YIELD ... */
    char** show_yield_vars;
    size_t num_show_yield_vars;
    /* USE */
    char* use_database;    /* database name for USE clause */
    struct qihse_cypher_clause_s* next; /* clause chain */
};

struct qihse_cypher_query_s {
    qihse_cypher_clause_t* first;
    qihse_cypher_clause_t* last;
};

typedef struct {
    qihse_cypher_query_t** queries;
    size_t num_queries;
} qihse_cypher_ast_t;

/* --- API --- */
qihse_cypher_ast_t* qihse_cypher_parse(const char* text);
void qihse_cypher_ast_free(qihse_cypher_ast_t* ast);

/* diagnostics */
const char* qihse_cypher_error(void);

#ifdef __cplusplus
}
#endif

#endif /* QIHSE_CYPHER_PARSER_H */
