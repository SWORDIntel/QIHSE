#ifndef QIHSE_JOIN_EXECUTOR_H
#define QIHSE_JOIN_EXECUTOR_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "qihse_sql_parser.h"

#ifdef __cplusplus
extern "C" {
#endif

/* -------------------------------------------------------------------------
 * Generic row representation for executor operators.
 * A row is a set of named column values (string-encoded for simplicity).
 * ------------------------------------------------------------------------- */
typedef struct {
    char**  values;     /* array of string values, one per column */
    size_t  num_values;
} qihse_exec_row_t;

typedef struct {
    char** names;       /* column names */
    size_t num_cols;
} qihse_exec_schema_t;

/* A row stream is a simple iterator producing rows one at a time. */
typedef struct qihse_row_stream_s {
    const qihse_exec_schema_t* schema;
    qihse_exec_row_t* (*next)(struct qihse_row_stream_s* self);
    void              (*close)(struct qihse_row_stream_s* self);
    void*              state;   /* operator-specific state */
} qihse_row_stream_t;

qihse_exec_row_t* qihse_row_stream_next(qihse_row_stream_t* s);
void qihse_row_stream_close(qihse_row_stream_t* s);

/* In-memory row array stream (helper for tests / materialization). */
qihse_row_stream_t* qihse_row_array_stream_create(const qihse_exec_schema_t* schema,
                                                   qihse_exec_row_t* rows, size_t num_rows);

/* -------------------------------------------------------------------------
 * Join operators
 * ------------------------------------------------------------------------- */

/* Hash join: builds a hash table on the build stream's join key,
 * probes with the probe stream's join key. */
qihse_row_stream_t* qihse_hash_join_create(qihse_row_stream_t* build,
                                            qihse_row_stream_t* probe,
                                            const char* build_key_col,
                                            const char* probe_key_col,
                                            qihse_sql_join_type_t join_type);

/* Nested-loop join: for each build row, scans all probe rows and
 * tests the equi-condition.  Works for any join type including CROSS. */
qihse_row_stream_t* qihse_nested_loop_join_create(qihse_row_stream_t* outer,
                                                   qihse_row_stream_t* inner,
                                                   const char* outer_key_col,
                                                   const char* inner_key_col,
                                                   qihse_sql_join_type_t join_type);

/* Helper: find column index in a schema by name (case-insensitive). */
int qihse_schema_find_col(const qihse_exec_schema_t* schema, const char* name);

/* Helper: free a row's values (but not the row struct itself). */
void qihse_exec_row_free(qihse_exec_row_t* row);

#ifdef __cplusplus
}
#endif

#endif
