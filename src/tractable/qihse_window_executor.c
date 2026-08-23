#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
/*
 * QIHSE Window Function Executor
 *
 * Buffers all input rows, sorts them by PARTITION BY then ORDER BY columns,
 * and computes window function values per partition.  The output schema is
 * the input schema plus one appended column per window specification.
 *
 * Window functions implemented:
 *   ROW_NUMBER  — sequential 1-based counter within each partition
 *   RANK        — 1-based; ties share the same rank; next non-tie skips
 *   DENSE_RANK  — 1-based; ties share the same rank; next non-tie +1
 *   SUM/COUNT/AVG/MIN/MAX — running aggregate over the entire partition
 *                           up to and including the current row
 */
#include "qihse_window_executor.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <math.h>

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
/* Stream state                                                               */
/* ------------------------------------------------------------------------- */

typedef struct {
    qihse_row_stream_t* input;
    const qihse_exec_schema_t* input_schema;
    qihse_window_spec_t* specs;
    size_t num_specs;

    /* buffered input rows (owned until computed) */
    qihse_exec_row_t* buf;
    size_t buf_count;
    size_t buf_cap;

    /* computed output rows (owned) */
    qihse_exec_row_t* out_rows;
    size_t out_count;
    size_t out_pos;

    /* output schema (owned by this state) */
    qihse_exec_schema_t out_schema;
    char** out_schema_names;

    int built;   /* 1 once output has been computed */
} window_state_t;

/* ------------------------------------------------------------------------- */
/* Sort: PARTITION BY then ORDER BY                                          */
/* ------------------------------------------------------------------------- */

static window_state_t* g_win_cmp_state;
static int g_win_cmp_spec;

static int win_row_cmp(const void* pa, const void* pb) {
    const qihse_exec_row_t* a = (const qihse_exec_row_t*)pa;
    const qihse_exec_row_t* b = (const qihse_exec_row_t*)pb;
    const qihse_window_spec_t* sp = &g_win_cmp_state->specs[g_win_cmp_spec];

    /* PARTITION BY columns (ascending) */
    for (size_t i = 0; i < sp->num_partition_cols; i++) {
        int idx = sp->partition_by_cols[i];
        const char* va = (idx >= 0 && (size_t)idx < a->num_values) ? a->values[idx] : NULL;
        const char* vb = (idx >= 0 && (size_t)idx < b->num_values) ? b->values[idx] : NULL;
        int c = win_compare_values(va, vb);
        if (c != 0) return c;
    }
    /* ORDER BY columns (ascending) */
    for (size_t i = 0; i < sp->num_order_cols; i++) {
        int idx = sp->order_by_cols[i];
        const char* va = (idx >= 0 && (size_t)idx < a->num_values) ? a->values[idx] : NULL;
        const char* vb = (idx >= 0 && (size_t)idx < b->num_values) ? b->values[idx] : NULL;
        int c = win_compare_values(va, vb);
        if (c != 0) return c;
    }
    return 0;
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
/* Build: drain input, sort, compute window values                            */
/* ------------------------------------------------------------------------- */

static void window_build(window_state_t* st) {
    if (st->built) return;
    st->built = 1;

    /* 1. Drain the entire input into buf. */
    qihse_exec_row_t* r;
    while ((r = qihse_row_stream_next(st->input)) != NULL) {
        if (st->buf_count >= st->buf_cap) {
            st->buf_cap = st->buf_cap ? st->buf_cap * 2 : 64;
            st->buf = (qihse_exec_row_t*)realloc(st->buf,
                                                st->buf_cap * sizeof(qihse_exec_row_t));
        }
        st->buf[st->buf_count] = *r;   /* take ownership of the row contents */
        free(r);
        st->buf_count++;
    }

    size_t n = st->buf_count;
    size_t in_cols = st->input_schema ? st->input_schema->num_cols : 0;
    size_t out_cols = in_cols + st->num_specs;

    /* 2. Sort rows by PARTITION BY then ORDER BY (using spec 0 as the
     *    representative ordering; all specs share the same row ordering
     *    for partition detection). If there are no specs, skip. */
    if (st->num_specs > 0 && n > 1) {
        g_win_cmp_state = st;
        g_win_cmp_spec = 0;
        qsort(st->buf, n, sizeof(qihse_exec_row_t), win_row_cmp);
    }

    /* 3. Allocate output rows. */
    st->out_rows = (qihse_exec_row_t*)calloc(n ? n : 1, sizeof(qihse_exec_row_t));
    st->out_count = n;

    /* Per-spec running state. */
    win_agg_t* aggs = (win_agg_t*)calloc(st->num_specs ? st->num_specs : 1,
                                         sizeof(win_agg_t));
    long long* row_number = (long long*)calloc(st->num_specs ? st->num_specs : 1,
                                               sizeof(long long));
    long long* rank_val   = (long long*)calloc(st->num_specs ? st->num_specs : 1,
                                               sizeof(long long));
    long long* dense_val  = (long long*)calloc(st->num_specs ? st->num_specs : 1,
                                               sizeof(long long));
    for (size_t i = 0; i < n; i++) {
        qihse_exec_row_t* src = &st->buf[i];

        /* Build the output row: input columns + one per spec. */
        qihse_exec_row_t* out = &st->out_rows[i];
        out->num_values = out_cols;
        out->values = (char**)calloc(out_cols ? out_cols : 1, sizeof(char*));
        for (size_t c = 0; c < in_cols; c++)
            out->values[c] = win_strdup_or_null(src->values[c]);

        for (size_t s = 0; s < st->num_specs; s++) {
            qihse_window_spec_t* sp = &st->specs[s];
            char* result = NULL;

            /* Detect new partition (relative to previous row). */
            int new_part = 0;
            if (i == 0) {
                new_part = 1;
            } else if (!same_partition(&st->buf[i - 1], src, sp)) {
                new_part = 1;
            }

            if (new_part) {
                win_agg_reset(&aggs[s]);
                row_number[s] = 0;
                rank_val[s] = 0;
                dense_val[s] = 0;
            }

            /* Detect whether the ORDER BY key ties with the previous row
             * within this partition (for RANK / DENSE_RANK). */
            int tie = 0;
            if (sp->num_order_cols > 0 && i > 0 &&
                same_partition(&st->buf[i - 1], src, sp) &&
                same_order_key(&st->buf[i - 1], src, sp)) {
                tie = 1;
            }

            switch (sp->func) {
                case QIHSE_WIN_FUNC_ROW_NUMBER:
                    row_number[s]++;
                    result = win_longlong_to_str(row_number[s]);
                    break;

                case QIHSE_WIN_FUNC_RANK:
                    if (new_part) {
                        rank_val[s] = 1;
                    } else if (!tie) {
                        /* rank jumps to current 1-based position = row_number */
                        rank_val[s] = row_number[s] + 1;
                    }
                    /* if tie, rank stays the same */
                    result = win_longlong_to_str(rank_val[s]);
                    break;

                case QIHSE_WIN_FUNC_DENSE_RANK:
                    if (new_part) {
                        dense_val[s] = 1;
                    } else if (!tie) {
                        dense_val[s]++;
                    }
                    /* if tie, dense rank stays the same */
                    result = win_longlong_to_str(dense_val[s]);
                    break;

                case QIHSE_WIN_FUNC_SUM:
                case QIHSE_WIN_FUNC_COUNT:
                case QIHSE_WIN_FUNC_AVG:
                case QIHSE_WIN_FUNC_MIN:
                case QIHSE_WIN_FUNC_MAX: {
                    const char* v = (sp->arg_col >= 0 &&
                                     (size_t)sp->arg_col < src->num_values)
                                    ? src->values[sp->arg_col] : NULL;
                    win_agg_accum(&aggs[s], v);
                    result = win_agg_result(sp->func, &aggs[s]);
                    break;
                }

                default:
                    result = strdup("0");
                    break;
            }

            /* ROW_NUMBER must always advance regardless of function type,
             * because RANK uses it to compute skip positions. */
            if (sp->func != QIHSE_WIN_FUNC_ROW_NUMBER) {
                /* maintain an implicit row counter for rank computation */
                if (new_part) {
                    row_number[s] = 1;
                } else {
                    row_number[s]++;
                }
            }

            out->values[in_cols + s] = result;
        }
    }

    free(aggs);
    free(row_number);
    free(rank_val);
    free(dense_val);

    /* 4. Free the buffered input rows now that output is computed. */
    for (size_t i = 0; i < st->buf_count; i++)
        qihse_exec_row_free(&st->buf[i]);
    free(st->buf);
    st->buf = NULL;
    st->buf_count = 0;
    st->buf_cap = 0;
}

/* ------------------------------------------------------------------------- */
/* Stream operations                                                          */
/* ------------------------------------------------------------------------- */

static qihse_exec_row_t* window_next(qihse_row_stream_t* self) {
    window_state_t* st = (window_state_t*)self->state;
    if (!st->built) window_build(st);
    if (st->out_pos >= st->out_count) return NULL;
    qihse_exec_row_t* src = &st->out_rows[st->out_pos++];
    qihse_exec_row_t* out = (qihse_exec_row_t*)malloc(sizeof(qihse_exec_row_t));
    out->num_values = src->num_values;
    out->values = (char**)calloc(src->num_values ? src->num_values : 1,
                                 sizeof(char*));
    for (size_t i = 0; i < src->num_values; i++)
        out->values[i] = win_strdup_or_null(src->values[i]);
    return out;
}

static void window_close(qihse_row_stream_t* self) {
    window_state_t* st = (window_state_t*)self->state;
    if (!st) return;
    /* free any remaining buffered input rows */
    for (size_t i = 0; i < st->buf_count; i++)
        qihse_exec_row_free(&st->buf[i]);
    free(st->buf);
    /* free computed output rows */
    for (size_t i = 0; i < st->out_count; i++)
        qihse_exec_row_free(&st->out_rows[i]);
    free(st->out_rows);
    /* free specs (deep) */
    for (size_t s = 0; s < st->num_specs; s++) {
        free(st->specs[s].partition_by_cols);
        free(st->specs[s].order_by_cols);
    }
    free(st->specs);
    /* close input */
    qihse_row_stream_close(st->input);
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
    st->input = input;
    st->input_schema = input_schema;
    st->num_specs = num_specs;

    /* deep-copy specs */
    st->specs = (qihse_window_spec_t*)calloc(num_specs ? num_specs : 1,
                                             sizeof(qihse_window_spec_t));
    for (size_t i = 0; i < num_specs; i++) {
        st->specs[i].func = specs[i].func;
        st->specs[i].arg_col = specs[i].arg_col;
        st->specs[i].num_partition_cols = specs[i].num_partition_cols;
        if (specs[i].num_partition_cols > 0) {
            st->specs[i].partition_by_cols = (int*)malloc(
                specs[i].num_partition_cols * sizeof(int));
            memcpy(st->specs[i].partition_by_cols, specs[i].partition_by_cols,
                   specs[i].num_partition_cols * sizeof(int));
        }
        st->specs[i].num_order_cols = specs[i].num_order_cols;
        if (specs[i].num_order_cols > 0) {
            st->specs[i].order_by_cols = (int*)malloc(
                specs[i].num_order_cols * sizeof(int));
            memcpy(st->specs[i].order_by_cols, specs[i].order_by_cols,
                   specs[i].num_order_cols * sizeof(int));
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
