#ifndef QIHSE_AGGREGATE_EXECUTOR_H
#define QIHSE_AGGREGATE_EXECUTOR_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "qihse_join_executor.h"
#include "qihse_sql_parser.h"

#ifdef __cplusplus
extern "C" {
#endif

/* -------------------------------------------------------------------------
 * Aggregate executor — hash-based grouping with SUM/COUNT/AVG/MIN/MAX.
 *
 * Consumes an input row stream, groups rows by the specified group-key
 * columns, and computes the requested aggregates per group.
 * ------------------------------------------------------------------------- */

typedef enum {
    QIHSE_AGGOP_SUM   = 1,
    QIHSE_AGGOP_COUNT = 2,
    QIHSE_AGGOP_AVG   = 3,
    QIHSE_AGGOP_MIN   = 4,
    QIHSE_AGGOP_MAX   = 5,
    QIHSE_AGGOP_COUNT_STAR = 6
} qihse_aggop_kind_t;

typedef struct {
    qihse_aggop_kind_t kind;
    int   input_col_idx;   /* column index in input stream (-1 for COUNT(*)) */
    int   is_distinct;
} qihse_aggop_t;

/* Create an aggregation stream.
 *   input        — upstream row stream
 *   group_cols   — array of column indices to group by (may be empty for global agg)
 *   num_groups   — number of group-by columns
 *   aggs         — aggregate operations to compute
 *   num_aggs     — number of aggregates
 * The output schema is: [group_cols...] [agg results...]
 */
qihse_row_stream_t* qihse_aggregate_create(qihse_row_stream_t* input,
                                            const int* group_cols, size_t num_groups,
                                            const qihse_aggop_t* aggs, size_t num_aggs);

#ifdef __cplusplus
}
#endif

#endif
