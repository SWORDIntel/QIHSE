#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
/*
 * QIHSE Window Function Executor (Streaming)
 *
 * Sorts the input by PARTITION BY then ORDER BY columns (using the sort
 * executor, which may spill to disk for large inputs), then streams through
 * the sorted output computing window function values per partition on the
 * fly.  Only the previous row is retained for partition-boundary and tie
 * detection, reducing window-computation memory from O(n) to O(1).
 *
 * Note: the sort step may still buffer the entire input in memory when the
 * input is small enough to fit below the spill threshold.  For very large
 * inputs the sort executor spills to disk, so the overall memory footprint
 * is bounded by the spill threshold rather than the full input size.  The
 * window computation itself is fully streaming — it never buffers more
 * than one row beyond the current one.
 *
 * Window functions implemented:
 *   ROW_NUMBER  — sequential 1-based counter within each partition
 *   RANK        — 1-based; ties share the same rank; next non-tie skips
 *   DENSE_RANK  — 1-based; ties share the same rank; next non-tie +1
 *   SUM/COUNT/AVG/MIN/MAX — running aggregate over the entire partition
 *                           up to and including the current row
 */
#include "qihse_window_executor.h"
#include "qihse_sort_executor.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <math.h>

/* Spill threshold for the sort step: 64 MB.  When the in-memory sort buffer
 * exceeds this, the sort executor spills to a temporary file and merges. */
#define WIN_SORT_SPILL_THRESHOLD (64 * 1024 * 1024)

/* ------------------------------------------------------------------------- */
/* Helpers                                                                    */
/* ------------------------------------------------------------------------- */

/* compare two values: tries numeric first, falls back to string */
static int win_compare_values(const char* a, const char* b) {
    if (a == NULL && b == NULL) return 0;
    if (a == NULL) return -1;
    if (b == NULL) return 1;
    char* ea; char* eb;
    double da = strtod(a, &ea);
    double db = strtod(b, &eb);
    if (ea != a && eb != b && *ea == '\0' && *eb == '\0') {
        if (da < db) return -1;
        if (da > db) return 1;
        return 0;
    }
    return strcmp(a, b);
}

static char* win_strdup_or_null(const char* s) {
    return s ? strdup(s) : NULL;
}

static char* win_double_to_str(double v) {
    /* enough for ~20 digits + sign + decimal + null */
    char buf[64];
    if (v == (double)((long long)v) &&
        v >= -9.2233720368547758e18 && v <= 9.2233720368547758e18) {
        snprintf(buf, sizeof(buf), "%lld", (long long)v);
    } else {
        snprintf(buf, sizeof(buf), "%.17g", v);
    }
    return strdup(buf);
}

static char* win_longlong_to_str(long long v) {
    char buf[32];
    snprintf(buf, sizeof(buf), "%lld", v);
    return strdup(buf);
}

/* ------------------------------------------------------------------------- */
/* Partition / order comparison helpers                                       */
/* ------------------------------------------------------------------------- */

static int same_partition(const qihse_exec_row_t* a, const qihse_exec_row_t* b,
                          const qihse_window_spec_t* sp) {
    for (size_t i = 0; i < sp->num_partition_cols; i++) {
        int idx = sp->partition_by_cols[i];
        const char* va = (idx >= 0 && (size_t)idx < a->num_values) ? a->values[idx] : NULL;
        const char* vb = (idx >= 0 && (size_t)idx < b->num_values) ? b->values[idx] : NULL;
        if (win_compare_values(va, vb) != 0) return 0;
    }
    return 1;
}

static int same_order_key(const qihse_exec_row_t* a, const qihse_exec_row_t* b,
                          const qihse_window_spec_t* sp) {
    for (size_t i = 0; i < sp->num_order_cols; i++) {
        int idx = sp->order_by_cols[i];
        const char* va = (idx >= 0 && (size_t)idx < a->num_values) ? a->values[idx] : NULL;
        const char* vb = (idx >= 0 && (size_t)idx < b->num_values) ? b->values[idx] : NULL;
        if (win_compare_values(va, vb) != 0) return 0;
    }
    return 1;
}

/* ------------------------------------------------------------------------- */
/* Aggregate accumulators                                                     */
/* ------------------------------------------------------------------------- */

typedef struct {
    long long   count;     /* number of non-null values seen */
    double      sum;
    double      min;
    double      max;
    int         have_value; /* any non-null value seen yet */
} win_agg_t;

static void win_agg_reset(win_agg_t* agg) {
    agg->count = 0;
    agg->sum = 0.0;
    agg->min = 0.0;
    agg->max = 0.0;
    agg->have_value = 0;
}

static void win_agg_accum(win_agg_t* agg, const char* val) {
    if (!val) return;  /* NULL values are skipped */
    char* end;
    double d = strtod(val, &end);
    if (end == val) return;  /* non-numeric, skip */
    agg->count++;
    agg->sum += d;
    if (!agg->have_value) {
        agg->min = d;
        agg->max = d;
        agg->have_value = 1;
    } else {
        if (d < agg->min) agg->min = d;
        if (d > agg->max) agg->max = d;
    }
}

static char* win_agg_result(qihse_window_func_t func, const win_agg_t* agg) {
    switch (func) {
        case QIHSE_WIN_FUNC_SUM:
            if (!agg->have_value) return strdup("0");
            return win_double_to_str(agg->sum);
        case QIHSE_WIN_FUNC_COUNT:
            return win_longlong_to_str(agg->count);
        case QIHSE_WIN_FUNC_AVG:
            if (agg->count == 0) return strdup("0");
            return win_double_to_str(agg->sum / (double)agg->count);
        case QIHSE_WIN_FUNC_MIN:
            if (!agg->have_value) return NULL;
            return win_double_to_str(agg->min);
        case QIHSE_WIN_FUNC_MAX:
            if (!agg->have_value) return NULL;
            return win_double_to_str(agg->max);
        default:
            return NULL;
    }
}

/* ------------------------------------------------------------------------- */
/* Stream state                                                               */
/* ------------------------------------------------------------------------- */

typedef struct {
    qihse_row_stream_t* sorted_input;  /* sorted stream (or original input) */
    const qihse_exec_schema_t* input_schema;
    qihse_window_spec_t* specs;
    size_t num_specs;

    /* previous row for partition/tie detection (owned) */
    qihse_exec_row_t* prev_row;
    int has_prev;

    /* per-spec running state (allocated once, reused for all rows) */
    win_agg_t* aggs;
    long long* row_number;
    long long* rank_val;
    long long* dense_val;

    /* output schema (owned by this state) */
    qihse_exec_schema_t out_schema;
    char** out_schema_names;
} window_state_t;

/* ------------------------------------------------------------------------- */
/* Stream operations                                                          */
/* ------------------------------------------------------------------------- */

static qihse_exec_row_t* window_next(qihse_row_stream_t* self) {
    window_state_t* st = (window_state_t*)self->state;

    qihse_exec_row_t* cur = qihse_row_stream_next(st->sorted_input);
    if (!cur) return NULL;

    size_t in_cols = st->input_schema ? st->input_schema->num_cols : 0;
    size_t out_cols = in_cols + st->num_specs;

    /* Build the output row: input columns + one per spec. */
    qihse_exec_row_t* out = (qihse_exec_row_t*)malloc(sizeof(qihse_exec_row_t));
    if (!out) {
        qihse_exec_row_free(cur);
        free(cur);
        return NULL;
    }
    out->num_values = out_cols;
    out->values = (char**)calloc(out_cols ? out_cols : 1, sizeof(char*));
    if (!out->values) {
        free(out);
        qihse_exec_row_free(cur);
        free(cur);
        return NULL;
    }
    for (size_t c = 0; c < in_cols; c++)
        out->values[c] = win_strdup_or_null(cur->values[c]);

    for (size_t s = 0; s < st->num_specs; s++) {
        qihse_window_spec_t* sp = &st->specs[s];
        char* result = NULL;

        /* Detect new partition (relative to previous row). */
        int new_part = 0;
        if (!st->has_prev) {
            new_part = 1;
        } else if (!same_partition(st->prev_row, cur, sp)) {
            new_part = 1;
        }

        if (new_part) {
            win_agg_reset(&st->aggs[s]);
            st->row_number[s] = 0;
            st->rank_val[s] = 0;
            st->dense_val[s] = 0;
        }

        /* Detect whether the ORDER BY key ties with the previous row
         * within this partition (for RANK / DENSE_RANK). */
        int tie = 0;
        if (sp->num_order_cols > 0 && st->has_prev &&
            same_partition(st->prev_row, cur, sp) &&
            same_order_key(st->prev_row, cur, sp)) {
            tie = 1;
        }

        switch (sp->func) {
            case QIHSE_WIN_FUNC_ROW_NUMBER:
                st->row_number[s]++;
                result = win_longlong_to_str(st->row_number[s]);
                break;

            case QIHSE_WIN_FUNC_RANK:
                if (new_part) {
                    st->rank_val[s] = 1;
                } else if (!tie) {
                    /* rank jumps to current 1-based position = row_number + 1 */
                    st->rank_val[s] = st->row_number[s] + 1;
                }
                /* if tie, rank stays the same */
                result = win_longlong_to_str(st->rank_val[s]);
                break;

            case QIHSE_WIN_FUNC_DENSE_RANK:
                if (new_part) {
                    st->dense_val[s] = 1;
                } else if (!tie) {
                    st->dense_val[s]++;
                }
                /* if tie, dense rank stays the same */
                result = win_longlong_to_str(st->dense_val[s]);
                break;

            case QIHSE_WIN_FUNC_SUM:
            case QIHSE_WIN_FUNC_COUNT:
            case QIHSE_WIN_FUNC_AVG:
            case QIHSE_WIN_FUNC_MIN:
            case QIHSE_WIN_FUNC_MAX: {
                const char* v = (sp->arg_col >= 0 &&
                                 (size_t)sp->arg_col < cur->num_values)
                                ? cur->values[sp->arg_col] : NULL;
                win_agg_accum(&st->aggs[s], v);
                result = win_agg_result(sp->func, &st->aggs[s]);
                break;
            }

            default:
                result = strdup("0");
                break;
        }

        /* ROW_NUMBER must always advance regardless of function type,
         * because RANK uses it to compute skip positions. */
        if (sp->func != QIHSE_WIN_FUNC_ROW_NUMBER) {
            if (new_part) {
                st->row_number[s] = 1;
            } else {
                st->row_number[s]++;
            }
        }

        out->values[in_cols + s] = result;
    }

    /* Save current row as prev_row for the next call; free old prev_row. */
    if (st->prev_row) {
        qihse_exec_row_free(st->prev_row);
        free(st->prev_row);
    }
    st->prev_row = cur;
    st->has_prev = 1;

    return out;
}

static void window_close(qihse_row_stream_t* self) {
    window_state_t* st = (window_state_t*)self->state;
    if (!st) return;
    /* free previous row */
    if (st->prev_row) {
        qihse_exec_row_free(st->prev_row);
        free(st->prev_row);
    }
    /* free per-spec running state */
    free(st->aggs);
    free(st->row_number);
    free(st->rank_val);
    free(st->dense_val);
    /* free specs (deep) */
    for (size_t s = 0; s < st->num_specs; s++) {
        free(st->specs[s].partition_by_cols);
        free(st->specs[s].order_by_cols);
    }
    free(st->specs);
    /* close the sorted input stream (which closes the original input) */
    if (st->sorted_input)
        qihse_row_stream_close(st->sorted_input);
    /* free output schema names */
    for (size_t i = 0; i < st->out_schema.num_cols; i++)
        free(st->out_schema_names[i]);
    free(st->out_schema_names);
    free(st);
}

/* ------------------------------------------------------------------------- */
/* Public API                                                                 */
/* ------------------------------------------------------------------------- */

void qihse_window_schema_free(qihse_exec_schema_t* schema) {
    if (!schema) return;
    for (size_t i = 0; i < schema->num_cols; i++)
        free(schema->names[i]);
    free(schema->names);
    free(schema);
}

qihse_row_stream_t* qihse_window_create(qihse_row_stream_t* input,
                                        const qihse_exec_schema_t* input_schema,
                                        const qihse_window_spec_t* specs,
                                        size_t num_specs,
                                        qihse_exec_schema_t** out_schema) {
    if (!input || !input_schema) return NULL;

    qihse_row_stream_t* s = (qihse_row_stream_t*)calloc(1, sizeof(*s));
    window_state_t* st = (window_state_t*)calloc(1, sizeof(*st));
    if (!s || !st) {
        free(s);
        free(st);
        return NULL;
    }
    st->input_schema = input_schema;
    st->num_specs = num_specs;

    /* deep-copy specs */
    st->specs = (qihse_window_spec_t*)calloc(num_specs ? num_specs : 1,
                                             sizeof(qihse_window_spec_t));
    if (!st->specs) {
        free(st);
        free(s);
        return NULL;
    }
    for (size_t i = 0; i < num_specs; i++) {
        st->specs[i].func = specs[i].func;
        st->specs[i].arg_col = specs[i].arg_col;
        st->specs[i].num_partition_cols = specs[i].num_partition_cols;
        if (specs[i].num_partition_cols > 0) {
            st->specs[i].partition_by_cols = (int*)malloc(
                specs[i].num_partition_cols * sizeof(int));
            if (!st->specs[i].partition_by_cols) {
                for (size_t j = 0; j < i; j++) {
                    free(st->specs[j].partition_by_cols);
                    free(st->specs[j].order_by_cols);
                }
                free(st->specs);
                free(st);
                free(s);
                return NULL;
            }
            memcpy(st->specs[i].partition_by_cols, specs[i].partition_by_cols,
                   specs[i].num_partition_cols * sizeof(int));
        }
        st->specs[i].num_order_cols = specs[i].num_order_cols;
        if (specs[i].num_order_cols > 0) {
            st->specs[i].order_by_cols = (int*)malloc(
                specs[i].num_order_cols * sizeof(int));
            if (!st->specs[i].order_by_cols) {
                free(st->specs[i].partition_by_cols);
                for (size_t j = 0; j < i; j++) {
                    free(st->specs[j].partition_by_cols);
                    free(st->specs[j].order_by_cols);
                }
                free(st->specs);
                free(st);
                free(s);
                return NULL;
            }
            memcpy(st->specs[i].order_by_cols, specs[i].order_by_cols,
                   specs[i].num_order_cols * sizeof(int));
        }
    }

    /* allocate per-spec running state */
    st->aggs = (win_agg_t*)calloc(num_specs ? num_specs : 1, sizeof(win_agg_t));
    st->row_number = (long long*)calloc(num_specs ? num_specs : 1, sizeof(long long));
    st->rank_val   = (long long*)calloc(num_specs ? num_specs : 1, sizeof(long long));
    st->dense_val  = (long long*)calloc(num_specs ? num_specs : 1, sizeof(long long));
    if (!st->aggs || !st->row_number || !st->rank_val || !st->dense_val) {
        free(st->aggs);
        free(st->row_number);
        free(st->rank_val);
        free(st->dense_val);
        for (size_t i = 0; i < num_specs; i++) {
            free(st->specs[i].partition_by_cols);
            free(st->specs[i].order_by_cols);
        }
        free(st->specs);
        free(st);
        free(s);
        return NULL;
    }

    /* Build the sorted input stream.  We sort by spec 0's PARTITION BY then
     * ORDER BY columns (all ascending).  All specs share the same row
     * ordering for partition detection.  If there are no partition or order
     * columns, no sort is needed and we stream directly from the input. */
    st->sorted_input = input;
    if (num_specs > 0) {
        const qihse_window_spec_t* sp0 = &st->specs[0];
        size_t num_sort_keys = sp0->num_partition_cols + sp0->num_order_cols;
        if (num_sort_keys > 0) {
            qihse_sort_key_t* keys =
                (qihse_sort_key_t*)malloc(num_sort_keys * sizeof(qihse_sort_key_t));
            if (keys) {
                size_t k = 0;
                for (size_t i = 0; i < sp0->num_partition_cols; i++)
                    keys[k].col_idx = sp0->partition_by_cols[i],
                    keys[k].ascending = 1, k++;
                for (size_t i = 0; i < sp0->num_order_cols; i++)
                    keys[k].col_idx = sp0->order_by_cols[i],
                    keys[k].ascending = 1, k++;
                qihse_row_stream_t* sorted =
                    qihse_sort_create(input, keys, num_sort_keys,
                                      WIN_SORT_SPILL_THRESHOLD);
                free(keys);
                if (sorted)
                    st->sorted_input = sorted;
                /* if sort creation failed, fall back to unsorted input */
            }
        }
    }

    /* build output schema = input cols + window cols */
    size_t in_cols = input_schema->num_cols;
    size_t total = in_cols + num_specs;
    st->out_schema_names = (char**)calloc(total ? total : 1, sizeof(char*));
    st->out_schema.num_cols = total;
    for (size_t i = 0; i < in_cols; i++)
        st->out_schema_names[i] = strdup(input_schema->names[i]);
    for (size_t i = 0; i < num_specs; i++) {
        char nm[32];
        snprintf(nm, sizeof(nm), "win_%zu", i);
        st->out_schema_names[in_cols + i] = strdup(nm);
    }
    st->out_schema.names = st->out_schema_names;

    s->schema = &st->out_schema;
    s->next = window_next;
    s->close = window_close;
    s->state = st;

    if (out_schema) {
        /* allocate a separate schema struct for the caller; the stream
         * retains its own copy internally. */
        qihse_exec_schema_t* os = (qihse_exec_schema_t*)calloc(1, sizeof(*os));
        os->num_cols = total;
        os->names = (char**)calloc(total ? total : 1, sizeof(char*));
        for (size_t i = 0; i < total; i++)
            os->names[i] = strdup(st->out_schema_names[i]);
        *out_schema = os;
    }

    return s;
}
