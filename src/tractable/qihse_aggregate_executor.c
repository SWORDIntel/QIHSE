#define _GNU_SOURCE
/*
 * QIHSE Aggregate Executor — Phase 1 Relational Completeness
 *
 * Hash-based aggregation: builds groups in a hash table keyed by the
 * concatenation of group-by column values, then applies aggregates.
 */
#include "qihse_aggregate_executor.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <math.h>
#include <float.h>

static bool ieq(const char* a, const char* b) {
    if (!a || !b) return a == b;
    while (*a && *b) {
        if (tolower((unsigned char)*a) != tolower((unsigned char)*b)) return false;
        a++; b++;
    }
    return *a == *b;
}

static unsigned long hash_str(const char* s) {
    unsigned long h = 5381;
    if (!s) return 0;
    while (*s) { h = ((h << 5) + h) + (unsigned char)*s; s++; }
    return h;
}

typedef struct agg_group {
    char** key_parts;       /* group key values */
    size_t num_keys;
    /* aggregate accumulators */
    double*   sum;
    int64_t*  count;
    double*   min;
    double*   max;
    /* distinct tracking (simple: store seen values per agg) */
    char***   distinct_vals;
    size_t*   distinct_count;
    size_t*   distinct_cap;
    struct agg_group* next;
} agg_group_t;

typedef struct {
    qihse_row_stream_t* input;
    int* group_cols;
    size_t num_groups;
    qihse_aggop_t* aggs;
    size_t num_aggs;
    /* hash table */
    agg_group_t** buckets;
    size_t num_buckets;
    size_t num_groups_total;
    /* output */
    agg_group_t** group_list;
    size_t group_pos;
    qihse_exec_schema_t out_schema;
    char** out_schema_names;
} agg_state_t;

static char* make_group_key(qihse_exec_row_t* row, const int* group_cols, size_t num_groups) {
    /* build a concatenated key string */
    size_t total = 1;
    for (size_t i = 0; i < num_groups; i++) {
        int idx = group_cols[i];
        const char* v = (idx >= 0 && (size_t)idx < row->num_values) ? row->values[idx] : NULL;
        total += (v ? strlen(v) : 0) + 1;
    }
    char* key = (char*)malloc(total);
    char* p = key;
    for (size_t i = 0; i < num_groups; i++) {
        int idx = group_cols[i];
        const char* v = (idx >= 0 && (size_t)idx < row->num_values) ? row->values[idx] : NULL;
        if (v) { strcpy(p, v); p += strlen(v); }
        *p++ = '\x1f'; /* unit separator */
    }
    *p = '\0';
    return key;
}

static int distinct_seen(char** vals, size_t count, const char* v) {
    for (size_t i = 0; i < count; i++) {
        if (ieq(vals[i], v)) return 1;
    }
    return 0;
}

static void update_group(agg_group_t* g, const qihse_aggop_t* aggs, size_t num_aggs,
                         qihse_exec_row_t* row) {
    for (size_t i = 0; i < num_aggs; i++) {
        const qihse_aggop_t* a = &aggs[i];
        const char* v = NULL;
        if (a->kind != QIHSE_AGGOP_COUNT_STAR && a->input_col_idx >= 0 &&
            (size_t)a->input_col_idx < row->num_values) {
            v = row->values[a->input_col_idx];
        }
        if (a->kind == QIHSE_AGGOP_COUNT_STAR) {
            g->count[i]++;
        } else if (a->kind == QIHSE_AGGOP_COUNT) {
            if (v) {
                if (a->is_distinct) {
                    if (!distinct_seen(g->distinct_vals[i], g->distinct_count[i], v)) {
                        if (g->distinct_count[i] >= g->distinct_cap[i]) {
                            g->distinct_cap[i] = g->distinct_cap[i] ? g->distinct_cap[i] * 2 : 8;
                            g->distinct_vals[i] = (char**)realloc(g->distinct_vals[i], g->distinct_cap[i] * sizeof(char*));
                        }
                        g->distinct_vals[i][g->distinct_count[i]++] = strdup(v);
                        g->count[i]++;
                    }
                } else {
                    g->count[i]++;
                }
            }
        } else if (v) {
            double dv = strtod(v, NULL);
            if (a->is_distinct && distinct_seen(g->distinct_vals[i], g->distinct_count[i], v))
                continue;
            if (a->is_distinct) {
                if (g->distinct_count[i] >= g->distinct_cap[i]) {
                    g->distinct_cap[i] = g->distinct_cap[i] ? g->distinct_cap[i] * 2 : 8;
                    g->distinct_vals[i] = (char**)realloc(g->distinct_vals[i], g->distinct_cap[i] * sizeof(char*));
                }
                g->distinct_vals[i][g->distinct_count[i]++] = strdup(v);
            }
            switch (a->kind) {
                case QIHSE_AGGOP_SUM: g->sum[i] += dv; break;
                case QIHSE_AGGOP_AVG:  g->sum[i] += dv; g->count[i]++; break;
                case QIHSE_AGGOP_MIN:  if (g->count[i] == 0 || dv < g->min[i]) g->min[i] = dv; break;
                case QIHSE_AGGOP_MAX:  if (g->count[i] == 0 || dv > g->max[i]) g->max[i] = dv; break;
                default: break;
            }
            if (a->kind != QIHSE_AGGOP_AVG && a->kind != QIHSE_AGGOP_COUNT) g->count[i]++;
        }
    }
}

static agg_group_t* find_or_create_group(agg_state_t* st, const char* key,
                                          qihse_exec_row_t* row) {
    unsigned long h = hash_str(key) % st->num_buckets;
    agg_group_t* g = st->buckets[h];
    for (; g; g = g->next) {
        /* compare keys */
        int match = 1;
        for (size_t i = 0; i < st->num_groups && match; i++) {
            const char* gv = g->key_parts[i];
            int idx = st->group_cols[i];
            const char* rv = (idx >= 0 && (size_t)idx < row->num_values) ? row->values[idx] : NULL;
            if ((gv == NULL && rv != NULL) || (gv != NULL && rv == NULL) ||
                (gv && rv && !ieq(gv, rv))) match = 0;
        }
        if (match) return g;
    }
    /* create new group */
    g = (agg_group_t*)calloc(1, sizeof(*g));
    g->num_keys = st->num_groups;
    g->key_parts = (char**)calloc(st->num_groups ? st->num_groups : 1, sizeof(char*));
    for (size_t i = 0; i < st->num_groups; i++) {
        int idx = st->group_cols[i];
        g->key_parts[i] = (idx >= 0 && (size_t)idx < row->num_values && row->values[idx])
                          ? strdup(row->values[idx]) : NULL;
    }
    g->sum = (double*)calloc(st->num_aggs ? st->num_aggs : 1, sizeof(double));
    g->count = (int64_t*)calloc(st->num_aggs ? st->num_aggs : 1, sizeof(int64_t));
    g->min = (double*)calloc(st->num_aggs ? st->num_aggs : 1, sizeof(double));
    g->max = (double*)calloc(st->num_aggs ? st->num_aggs : 1, sizeof(double));
    g->distinct_vals = (char***)calloc(st->num_aggs ? st->num_aggs : 1, sizeof(char**));
    g->distinct_count = (size_t*)calloc(st->num_aggs ? st->num_aggs : 1, sizeof(size_t));
    g->distinct_cap = (size_t*)calloc(st->num_aggs ? st->num_aggs : 1, sizeof(size_t));
    for (size_t i = 0; i < st->num_aggs; i++) { g->min[i] = DBL_MAX; g->max[i] = -DBL_MAX; }
    g->next = st->buckets[h];
    st->buckets[h] = g;
    /* add to group list */
    st->group_list = (agg_group_t**)realloc(st->group_list, (st->num_groups_total + 1) * sizeof(agg_group_t*));
    st->group_list[st->num_groups_total++] = g;
    return g;
}

static void agg_build(agg_state_t* st) {
    st->num_buckets = 256;
    st->buckets = (agg_group_t**)calloc(st->num_buckets, sizeof(agg_group_t*));
    qihse_exec_row_t* r;
    while ((r = qihse_row_stream_next(st->input)) != NULL) {
        char* key = make_group_key(r, st->group_cols, st->num_groups);
        agg_group_t* g = find_or_create_group(st, key, r);
        update_group(g, st->aggs, st->num_aggs, r);
        free(key);
        qihse_exec_row_free(r);
        free(r);
    }
}

static char* fmt_double(double v) {
    char* buf = (char*)malloc(32);
    if (v == (double)(int64_t)v && fabs(v) < 1e15) {
        snprintf(buf, 32, "%lld", (long long)v);
    } else {
        snprintf(buf, 32, "%.6g", v);
    }
    return buf;
}

static qihse_exec_row_t* agg_next(qihse_row_stream_t* self) {
    agg_state_t* st = (agg_state_t*)self->state;
    if (st->group_pos >= st->num_groups_total) return NULL;
    agg_group_t* g = st->group_list[st->group_pos++];
    qihse_exec_row_t* out = (qihse_exec_row_t*)malloc(sizeof(qihse_exec_row_t));
    out->num_values = st->num_groups + st->num_aggs;
    out->values = (char**)calloc(out->num_values ? out->num_values : 1, sizeof(char*));
    for (size_t i = 0; i < st->num_groups; i++)
        out->values[i] = g->key_parts[i] ? strdup(g->key_parts[i]) : NULL;
    for (size_t i = 0; i < st->num_aggs; i++) {
        double val = 0;
        switch (st->aggs[i].kind) {
            case QIHSE_AGGOP_SUM:   val = g->sum[i]; break;
            case QIHSE_AGGOP_COUNT:
            case QIHSE_AGGOP_COUNT_STAR: val = (double)g->count[i]; break;
            case QIHSE_AGGOP_AVG:   val = g->count[i] > 0 ? g->sum[i] / (double)g->count[i] : 0; break;
            case QIHSE_AGGOP_MIN:   val = g->min[i]; break;
            case QIHSE_AGGOP_MAX:   val = g->max[i]; break;
            default: break;
        }
        out->values[st->num_groups + i] = fmt_double(val);
    }
    return out;
}

static void agg_close(qihse_row_stream_t* self) {
    agg_state_t* st = (agg_state_t*)self->state;
    if (!st) return;
    for (size_t i = 0; i < st->num_buckets; i++) {
        agg_group_t* g = st->buckets[i];
        while (g) {
            agg_group_t* next = g->next;
            for (size_t j = 0; j < g->num_keys; j++) free(g->key_parts[j]);
            free(g->key_parts);
            free(g->sum); free(g->count); free(g->min); free(g->max);
            for (size_t j = 0; j < st->num_aggs; j++) {
                if (g->distinct_vals[j]) {
                    for (size_t k = 0; k < g->distinct_count[j]; k++) free(g->distinct_vals[j][k]);
                    free(g->distinct_vals[j]);
                }
            }
            free(g->distinct_vals); free(g->distinct_count); free(g->distinct_cap);
            free(g);
            g = next;
        }
    }
    free(st->buckets);
    free(st->group_list);
    free(st->group_cols);
    free(st->aggs);
    qihse_row_stream_close(st->input);
    for (size_t i = 0; i < st->out_schema.num_cols; i++) free(st->out_schema_names[i]);
    free(st->out_schema_names);
    free(st);
}

qihse_row_stream_t* qihse_aggregate_create(qihse_row_stream_t* input,
                                            const int* group_cols, size_t num_groups,
                                            const qihse_aggop_t* aggs, size_t num_aggs) {
    if (!input) return NULL;
    qihse_row_stream_t* s = (qihse_row_stream_t*)calloc(1, sizeof(*s));
    agg_state_t* st = (agg_state_t*)calloc(1, sizeof(*st));
    st->input = input;
    st->num_groups = num_groups;
    st->group_cols = (int*)calloc(num_groups ? num_groups : 1, sizeof(int));
    memcpy(st->group_cols, group_cols, num_groups * sizeof(int));
    st->num_aggs = num_aggs;
    st->aggs = (qihse_aggop_t*)calloc(num_aggs ? num_aggs : 1, sizeof(qihse_aggop_t));
    memcpy(st->aggs, aggs, num_aggs * sizeof(qihse_aggop_t));

    /* output schema: group cols + agg result cols */
    size_t total = num_groups + num_aggs;
    st->out_schema_names = (char**)calloc(total ? total : 1, sizeof(char*));
    st->out_schema.num_cols = total;
    for (size_t i = 0; i < num_groups; i++) {
        int idx = group_cols[i];
        st->out_schema_names[i] = strdup(idx >= 0 ? input->schema->names[idx] : "?");
    }
    for (size_t i = 0; i < num_aggs; i++) {
        char buf[64];
        const char* nm = "?";
        switch (aggs[i].kind) {
            case QIHSE_AGGOP_SUM: nm = "sum"; break;
            case QIHSE_AGGOP_COUNT: nm = "count"; break;
            case QIHSE_AGGOP_COUNT_STAR: nm = "count"; break;
            case QIHSE_AGGOP_AVG: nm = "avg"; break;
            case QIHSE_AGGOP_MIN: nm = "min"; break;
            case QIHSE_AGGOP_MAX: nm = "max"; break;
            default: break;
        }
        snprintf(buf, sizeof(buf), "%s_%zu", nm, i);
        st->out_schema_names[num_groups + i] = strdup(buf);
    }
    st->out_schema.names = st->out_schema_names;

    s->schema = &st->out_schema;
    s->next = agg_next;
    s->close = agg_close;
    s->state = st;

    agg_build(st);
    return s;
}
