#define _GNU_SOURCE
/*
 * QIHSE Aggregate Executor — Phase 1 Relational Completeness
 * Hardened against unbounded memory amplification and allocation failures.
 */
#include "qihse_aggregate_executor.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <math.h>
#include <float.h>

#define QIHSE_AGG_MAX_GROUPS 65536
#define QIHSE_AGG_MAX_DISTINCT_PER_GROUP 4096
#define QIHSE_AGG_MAX_KEY_LEN 32768
#define QIHSE_AGG_MAX_MEMORY_BYTES (64 * 1024 * 1024) /* 64 MB budget */

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
    unsigned long hash;     /* precomputed key hash for fast rejection */
    char** key_parts;       /* group key values */
    size_t num_keys;
    /* aggregate accumulators */
    double*   sum;
    int64_t*  count;
    double*   min;
    double*   max;
    /* distinct tracking */
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
    size_t group_list_cap;
    size_t group_pos;
    qihse_exec_schema_t out_schema;
    char** out_schema_names;
    /* memory accounting */
    size_t memory_used_bytes;
    bool memory_limit_exceeded;
} agg_state_t;

static char* make_group_key(qihse_exec_row_t* row, const int* group_cols, size_t num_groups) {
    size_t total = 1;
    for (size_t i = 0; i < num_groups; i++) {
        int idx = group_cols[i];
        const char* v = (idx >= 0 && (size_t)idx < row->num_values) ? row->values[idx] : NULL;
        size_t vlen = v ? strlen(v) : 0;
        if (vlen > QIHSE_AGG_MAX_KEY_LEN || total > QIHSE_AGG_MAX_KEY_LEN - vlen - 1) {
            return NULL;
        }
        total += vlen + 1;
    }
    char* key = (char*)malloc(total);
    if (!key) return NULL;
    char* p = key;
    for (size_t i = 0; i < num_groups; i++) {
        int idx = group_cols[i];
        const char* v = (idx >= 0 && (size_t)idx < row->num_values) ? row->values[idx] : NULL;
        if (v) {
            size_t vlen = strlen(v);
            memcpy(p, v, vlen);
            p += vlen;
        }
        *p++ = '\x1f'; /* unit separator */
    }
    *p = '\0';
    return key;
}

static int distinct_seen(char** vals, size_t count, const char* v) {
    if (!vals || !v) return 0;
    for (size_t i = 0; i < count; i++) {
        if (ieq(vals[i], v)) return 1;
    }
    return 0;
}

static void update_group(agg_state_t* st, agg_group_t* g, const qihse_aggop_t* aggs, size_t num_aggs,
                         qihse_exec_row_t* row) {
    if (!st || !g || !aggs || !row) return;

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
                    if (g->distinct_count[i] >= QIHSE_AGG_MAX_DISTINCT_PER_GROUP) {
                        continue;
                    }
                    if (!distinct_seen(g->distinct_vals[i], g->distinct_count[i], v)) {
                        if (g->distinct_count[i] >= g->distinct_cap[i]) {
                            size_t new_cap = g->distinct_cap[i] ? g->distinct_cap[i] * 2 : 8;
                            if (new_cap > QIHSE_AGG_MAX_DISTINCT_PER_GROUP) new_cap = QIHSE_AGG_MAX_DISTINCT_PER_GROUP;
                            char** new_arr = (char**)realloc(g->distinct_vals[i], new_cap * sizeof(char*));
                            if (!new_arr) continue;
                            g->distinct_vals[i] = new_arr;
                            g->distinct_cap[i] = new_cap;
                        }
                        size_t vlen = strlen(v) + 1;
                        if (st->memory_used_bytes + vlen > QIHSE_AGG_MAX_MEMORY_BYTES) {
                            st->memory_limit_exceeded = true;
                            continue;
                        }
                        char* copy = strdup(v);
                        if (copy) {
                            g->distinct_vals[i][g->distinct_count[i]++] = copy;
                            st->memory_used_bytes += vlen;
                            g->count[i]++;
                        }
                    }
                } else {
                    g->count[i]++;
                }
            }
        } else if (v) {
            double dv = strtod(v, NULL);
            if (a->is_distinct) {
                if (g->distinct_count[i] >= QIHSE_AGG_MAX_DISTINCT_PER_GROUP ||
                    distinct_seen(g->distinct_vals[i], g->distinct_count[i], v))
                    continue;

                if (g->distinct_count[i] >= g->distinct_cap[i]) {
                    size_t new_cap = g->distinct_cap[i] ? g->distinct_cap[i] * 2 : 8;
                    if (new_cap > QIHSE_AGG_MAX_DISTINCT_PER_GROUP) new_cap = QIHSE_AGG_MAX_DISTINCT_PER_GROUP;
                    char** new_arr = (char**)realloc(g->distinct_vals[i], new_cap * sizeof(char*));
                    if (!new_arr) continue;
                    g->distinct_vals[i] = new_arr;
                    g->distinct_cap[i] = new_cap;
                }
                size_t vlen = strlen(v) + 1;
                if (st->memory_used_bytes + vlen > QIHSE_AGG_MAX_MEMORY_BYTES) {
                    st->memory_limit_exceeded = true;
                    continue;
                }
                char* copy = strdup(v);
                if (copy) {
                    g->distinct_vals[i][g->distinct_count[i]++] = copy;
                    st->memory_used_bytes += vlen;
                }
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

static void agg_rehash(agg_state_t* st) {
    if (!st || !st->buckets || st->num_buckets == 0) return;
    size_t new_num_buckets = st->num_buckets * 2;
    agg_group_t** new_buckets = (agg_group_t**)calloc(new_num_buckets, sizeof(agg_group_t*));
    if (!new_buckets) return; /* Allocation failure: keep existing buckets */

    for (size_t i = 0; i < st->num_buckets; i++) {
        agg_group_t* g = st->buckets[i];
        while (g) {
            agg_group_t* next = g->next;
            unsigned long h = g->hash % new_num_buckets;
            g->next = new_buckets[h];
            new_buckets[h] = g;
            g = next;
        }
    }
    free(st->buckets);
    st->buckets = new_buckets;
    st->num_buckets = new_num_buckets;
}

static agg_group_t* find_or_create_group(agg_state_t* st, const char* key,
                                          qihse_exec_row_t* row) {
    if (!st || !key || !row || !st->buckets) return NULL;

    unsigned long raw_hash = hash_str(key);
    unsigned long h = raw_hash % st->num_buckets;
    agg_group_t* g = st->buckets[h];
    for (; g; g = g->next) {
        if (g->hash != raw_hash) continue;
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

    /* Check group limits and memory budget */
    if (st->memory_limit_exceeded || st->num_groups_total >= QIHSE_AGG_MAX_GROUPS) {
        return NULL;
    }

    size_t est_bytes = sizeof(agg_group_t) + (st->num_groups * sizeof(char*)) +
                       (st->num_aggs * (sizeof(double) * 3 + sizeof(int64_t) + sizeof(char**) + sizeof(size_t) * 2));
    if (st->memory_used_bytes + est_bytes > QIHSE_AGG_MAX_MEMORY_BYTES) {
        st->memory_limit_exceeded = true;
        return NULL;
    }

    g = (agg_group_t*)calloc(1, sizeof(*g));
    if (!g) return NULL;

    g->hash = raw_hash;
    g->num_keys = st->num_groups;
    g->key_parts = (char**)calloc(st->num_groups ? st->num_groups : 1, sizeof(char*));
    if (!g->key_parts) { free(g); return NULL; }

    for (size_t i = 0; i < st->num_groups; i++) {
        int idx = st->group_cols[i];
        if (idx >= 0 && (size_t)idx < row->num_values && row->values[idx]) {
            g->key_parts[i] = strdup(row->values[idx]);
            if (g->key_parts[i]) {
                st->memory_used_bytes += strlen(row->values[idx]) + 1;
            }
        }
    }

    g->sum = (double*)calloc(st->num_aggs ? st->num_aggs : 1, sizeof(double));
    g->count = (int64_t*)calloc(st->num_aggs ? st->num_aggs : 1, sizeof(int64_t));
    g->min = (double*)calloc(st->num_aggs ? st->num_aggs : 1, sizeof(double));
    g->max = (double*)calloc(st->num_aggs ? st->num_aggs : 1, sizeof(double));
    g->distinct_vals = (char***)calloc(st->num_aggs ? st->num_aggs : 1, sizeof(char**));
    g->distinct_count = (size_t*)calloc(st->num_aggs ? st->num_aggs : 1, sizeof(size_t));
    g->distinct_cap = (size_t*)calloc(st->num_aggs ? st->num_aggs : 1, sizeof(size_t));

    if (!g->sum || !g->count || !g->min || !g->max || !g->distinct_vals || !g->distinct_count || !g->distinct_cap) {
        for (size_t i = 0; i < st->num_groups; i++) free(g->key_parts[i]);
        free(g->key_parts); free(g->sum); free(g->count); free(g->min); free(g->max);
        free(g->distinct_vals); free(g->distinct_count); free(g->distinct_cap);
        free(g);
        return NULL;
    }

    for (size_t i = 0; i < st->num_aggs; i++) { g->min[i] = DBL_MAX; g->max[i] = -DBL_MAX; }
    g->next = st->buckets[h];
    st->buckets[h] = g;

    if (st->num_groups_total >= st->group_list_cap) {
        size_t new_cap = st->group_list_cap ? st->group_list_cap * 2 : 64;
        if (new_cap > QIHSE_AGG_MAX_GROUPS) new_cap = QIHSE_AGG_MAX_GROUPS;
        agg_group_t** new_list = (agg_group_t**)realloc(st->group_list, new_cap * sizeof(agg_group_t*));
        if (!new_list) {
            return g; /* bucket already has g, but group_list won't include it */
        }
        st->group_list = new_list;
        st->group_list_cap = new_cap;
    }
    st->group_list[st->num_groups_total++] = g;
    st->memory_used_bytes += est_bytes;

    /* Rehash when load factor exceeds 0.75 */
    if (st->num_groups_total > (st->num_buckets * 3 / 4) && st->num_buckets * 2 <= QIHSE_AGG_MAX_GROUPS * 2) {
        agg_rehash(st);
    }

    return g;
}

static void agg_build(agg_state_t* st) {
    st->num_buckets = 1024;
    st->buckets = (agg_group_t**)calloc(st->num_buckets, sizeof(agg_group_t*));
    if (!st->buckets) return;

    st->group_list_cap = 64;
    st->group_list = (agg_group_t**)malloc(st->group_list_cap * sizeof(agg_group_t*));
    if (!st->group_list) {
        free(st->buckets);
        st->buckets = NULL;
        return;
    }

    qihse_exec_row_t* r;
    while ((r = qihse_row_stream_next(st->input)) != NULL) {
        char* key = make_group_key(r, st->group_cols, st->num_groups);
        if (key) {
            agg_group_t* g = find_or_create_group(st, key, r);
            if (g) {
                update_group(st, g, st->aggs, st->num_aggs, r);
            }
            free(key);
        }
        qihse_exec_row_free(r);
        free(r);
    }
}

static char* fmt_double(double v) {
    char* buf = (char*)malloc(32);
    if (!buf) return NULL;
    if (v == (double)(int64_t)v && fabs(v) < 1e15) {
        snprintf(buf, 32, "%lld", (long long)v);
    } else {
        snprintf(buf, 32, "%.6g", v);
    }
    return buf;
}

static qihse_exec_row_t* agg_next(qihse_row_stream_t* self) {
    agg_state_t* st = (agg_state_t*)self->state;
    if (!st || st->group_pos >= st->num_groups_total) return NULL;
    agg_group_t* g = st->group_list[st->group_pos++];
    if (!g) return NULL;

    qihse_exec_row_t* out = (qihse_exec_row_t*)malloc(sizeof(qihse_exec_row_t));
    if (!out) return NULL;
    out->num_values = st->num_groups + st->num_aggs;
    out->values = (char**)calloc(out->num_values ? out->num_values : 1, sizeof(char*));
    if (!out->values) { free(out); return NULL; }

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
    if (!self) return;
    agg_state_t* st = (agg_state_t*)self->state;
    if (!st) return;

    if (st->buckets) {
        for (size_t i = 0; i < st->num_buckets; i++) {
            agg_group_t* g = st->buckets[i];
            while (g) {
                agg_group_t* next = g->next;
                if (g->key_parts) {
                    for (size_t j = 0; j < g->num_keys; j++) free(g->key_parts[j]);
                    free(g->key_parts);
                }
                free(g->sum); free(g->count); free(g->min); free(g->max);
                if (g->distinct_vals) {
                    for (size_t j = 0; j < st->num_aggs; j++) {
                        if (g->distinct_vals[j]) {
                            for (size_t k = 0; k < g->distinct_count[j]; k++) free(g->distinct_vals[j][k]);
                            free(g->distinct_vals[j]);
                        }
                    }
                    free(g->distinct_vals);
                }
                free(g->distinct_count); free(g->distinct_cap);
                free(g);
                g = next;
            }
        }
        free(st->buckets);
    }
    free(st->group_list);
    free(st->group_cols);
    free(st->aggs);
    if (st->input) qihse_row_stream_close(st->input);
    if (st->out_schema_names) {
        for (size_t i = 0; i < st->out_schema.num_cols; i++) free(st->out_schema_names[i]);
        free(st->out_schema_names);
    }
    free(st);
}

qihse_row_stream_t* qihse_aggregate_create(qihse_row_stream_t* input,
                                            const int* group_cols, size_t num_groups,
                                            const qihse_aggop_t* aggs, size_t num_aggs) {
    if (!input) return NULL;
    qihse_row_stream_t* s = (qihse_row_stream_t*)calloc(1, sizeof(*s));
    if (!s) return NULL;
    agg_state_t* st = (agg_state_t*)calloc(1, sizeof(*st));
    if (!st) { free(s); return NULL; }

    st->input = input;
    st->num_groups = num_groups;
    st->group_cols = (int*)calloc(num_groups ? num_groups : 1, sizeof(int));
    if (group_cols && st->group_cols) {
        memcpy(st->group_cols, group_cols, num_groups * sizeof(int));
    }
    st->num_aggs = num_aggs;
    st->aggs = (qihse_aggop_t*)calloc(num_aggs ? num_aggs : 1, sizeof(qihse_aggop_t));
    if (aggs && st->aggs) {
        memcpy(st->aggs, aggs, num_aggs * sizeof(qihse_aggop_t));
    }

    /* output schema: group cols + agg result cols */
    size_t total = num_groups + num_aggs;
    st->out_schema_names = (char**)calloc(total ? total : 1, sizeof(char*));
    st->out_schema.num_cols = total;
    for (size_t i = 0; i < num_groups; i++) {
        int idx = group_cols[i];
        st->out_schema_names[i] = strdup((idx >= 0 && input->schema && input->schema->names) ? input->schema->names[idx] : "?");
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
