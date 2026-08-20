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
    CYPHER_UNION
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
    CEXPR_STAR          /* * (for count(*)) */
} cypher_expr_type_t;

typedef enum {
    COP_AND, COP_OR, COP_NOT,
    COP_EQ, COP_NE, COP_LT, COP_GT, COP_LE, COP_GE,
    COP_IN, COP_STARTS_WITH, COP_ENDS_WITH, COP_CONTAINS,
    COP_IS_NULL, COP_IS_NOT_NULL, COP_EXISTS,
    COP_ADD, COP_SUB, COP_MUL, COP_DIV, COP_MOD
} cypher_op_t;

typedef struct cypher_expr_s cypher_expr_t;

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

typedef struct {
    cypher_node_pattern_t** nodes;
    size_t num_nodes;
    cypher_rel_pattern_t** rels;
    size_t num_rels;
} cypher_path_t;

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
} cypher_order_item_t;

/* --- clause --- */
typedef struct qihse_cypher_clause_s {
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
    struct qihse_cypher_clause_s* next; /* clause chain */
} qihse_cypher_clause_t;

typedef struct {
    qihse_cypher_clause_t* first;
    qihse_cypher_clause_t* last;
} qihse_cypher_query_t;

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
