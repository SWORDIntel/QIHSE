#ifndef QIHSE_SORT_EXECUTOR_H
#define QIHSE_SORT_EXECUTOR_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "qihse_join_executor.h"

#ifdef __cplusplus
extern "C" {
#endif

/* -------------------------------------------------------------------------
 * Sort executor — in-memory sort-merge with optional spill-to-disk.
 *
 * Sort key is a list of (column index, ascending) pairs.
 * When the in-memory buffer exceeds spill_threshold_bytes, rows are
 * sorted and spilled to a temporary file; a final merge pass combines
 * all runs.
 * ------------------------------------------------------------------------- */

typedef struct {
    int col_idx;
    int ascending;
} qihse_sort_key_t;

/* Create a sort stream.
 *   input              — upstream row stream
 *   keys               — sort keys (column indices + direction)
 *   num_keys           — number of sort keys
 *   spill_threshold    — max in-memory bytes before spilling (0 = no spill)
 */
qihse_row_stream_t* qihse_sort_create(qihse_row_stream_t* input,
                                       const qihse_sort_key_t* keys, size_t num_keys,
                                       size_t spill_threshold);

#ifdef __cplusplus
}
#endif

#endif
