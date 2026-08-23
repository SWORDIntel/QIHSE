#ifndef QIHSE_WINDOW_EXECUTOR_H
#define QIHSE_WINDOW_EXECUTOR_H

#include <stddef.h>
#include <stdint.h>
#include "qihse_join_executor.h"
#include "qihse_sql_parser.h"

#ifdef __cplusplus
extern "C" {
#endif

/* -------------------------------------------------------------------------
 * Window function executor
 *
 * Computes SQL window functions (ROW_NUMBER, RANK, DENSE_RANK, SUM, COUNT,
 * AVG, MIN, MAX) over partitions of an input row stream.  The stream
 * buffers all input rows, sorts them by PARTITION BY then ORDER BY columns,
 * computes the window function values per partition, and emits rows with
 * the original columns followed by one appended result column per spec.
 * ------------------------------------------------------------------------- */

typedef enum {
    QIHSE_WIN_FUNC_ROW_NUMBER = 0,
    QIHSE_WIN_FUNC_RANK,
    QIHSE_WIN_FUNC_DENSE_RANK,
    QIHSE_WIN_FUNC_SUM,
    QIHSE_WIN_FUNC_COUNT,
    QIHSE_WIN_FUNC_AVG,
    QIHSE_WIN_FUNC_MIN,
    QIHSE_WIN_FUNC_MAX
} qihse_window_func_t;

typedef struct {
    qihse_window_func_t func;
    int*   partition_by_cols;   /* column indices for PARTITION BY */
    size_t num_partition_cols;
    int*   order_by_cols;       /* column indices for ORDER BY */
    size_t num_order_cols;
    int    arg_col;             /* column index for the function argument
                                 * (-1 for ROW_NUMBER / RANK / DENSE_RANK) */
} qihse_window_spec_t;

/* Create a window-function row stream.
 *
 *   input          — upstream row stream
 *   input_schema   — schema of the upstream rows
 *   specs          — array of window specifications (one per output column)
 *   num_specs      — number of window specifications
 *   out_schema     — on success, *out_schema is allocated and filled with the
 *                    output schema (input columns + appended window columns).
 *                    The caller must free it with qihse_window_schema_free()
 *                    (or manually) after the stream is closed.
 *
 * Returns a row stream producing rows with (input_schema->num_cols + num_specs)
 * columns, or NULL on error.
 */
qihse_row_stream_t* qihse_window_create(qihse_row_stream_t* input,
                                        const qihse_exec_schema_t* input_schema,
                                        const qihse_window_spec_t* specs,
                                        size_t num_specs,
                                        qihse_exec_schema_t** out_schema);

/* Convenience: free an output schema allocated by qihse_window_create. */
void qihse_window_schema_free(qihse_exec_schema_t* schema);

#ifdef __cplusplus
}
#endif

#endif
