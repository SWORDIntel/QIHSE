#ifndef QIHSE_CYPHER_EXECUTOR_H
#define QIHSE_CYPHER_EXECUTOR_H

#include "qihse_graph_store.h"
#include "qihse_cypher_parser.h"
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* A result value mirrors graph_prop_t but adds a NULL variant for Cypher. */
typedef enum {
    CRES_INT64, CRES_DOUBLE, CRES_STRING, CRES_BOOL, CRES_NULL, CRES_VERTEX, CRES_EDGE, CRES_LIST
} cypher_res_type_t;

typedef struct cypher_res_s {
    cypher_res_type_t type;
    union {
        int64_t i;
        double d;
        char* s;
        bool b;
        uint64_t id;          /* vertex/edge id */
        struct { struct cypher_res_s* items; size_t count; } list;
    } val;
} cypher_res_t;

typedef struct {
    char** names;          /* column names */
    cypher_res_t* values;  /* flat: num_cols per row */
    size_t num_cols;
    size_t num_rows;
} cypher_result_set_t;

/* Execute a parsed Cypher AST against the graph. Returns a result set (may be
 * NULL on error). Caller must free with qihse_cypher_result_free(). */
cypher_result_set_t* qihse_cypher_execute(qihse_graph_t* g, qihse_cypher_ast_t* ast);

/* Convenience: parse + execute. */
cypher_result_set_t* qihse_cypher_run(qihse_graph_t* g, const char* cypher);

void qihse_cypher_result_free(cypher_result_set_t* rs);

void cypher_res_free(cypher_res_t* r);
cypher_res_t cypher_res_int64(int64_t v);
cypher_res_t cypher_res_double(double v);
cypher_res_t cypher_res_string(const char* s);
cypher_res_t cypher_res_bool(bool b);
cypher_res_t cypher_res_null(void);

#ifdef __cplusplus
}
#endif

#endif /* QIHSE_CYPHER_EXECUTOR_H */
