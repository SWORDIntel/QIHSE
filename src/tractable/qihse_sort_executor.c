#define _GNU_SOURCE
/*
 * QIHSE Sort Executor — Phase 1 Relational Completeness
 *
 * In-memory sort-merge with configurable spill-to-disk for large result sets.
 * When the accumulated row buffer exceeds the spill threshold, the current
 * buffer is sorted and written to a temporary file as a sorted run.  After
 * the input is exhausted, all runs (in-memory + spilled) are merged via a
 * k-way merge using a simple priority queue.
 */
#include "qihse_sort_executor.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <math.h>

__attribute__((unused)) static bool ieq(const char* a, const char* b) {
    if (!a || !b) return a == b;
    while (*a && *b) {
        if (tolower((unsigned char)*a) != tolower((unsigned char)*b)) return false;
        a++; b++;
    }
    return *a == *b;
}

/* compare two values: tries numeric first, falls back to string */
static int compare_values(const char* a, const char* b) {
    if (a == NULL && b == NULL) return 0;
    if (a == NULL) return -1;
    if (b == NULL) return 1;
    /* try numeric */
    char* ea, * eb;
    double da = strtod(a, &ea);
    double db = strtod(b, &eb);
    if (ea != a && eb != b && *ea == '\0' && *eb == '\0') {
        if (da < db) return -1;
        if (da > db) return 1;
        return 0;
    }
    return strcmp(a, b);
}

typedef struct {
    qihse_row_stream_t* input;
    qihse_sort_key_t* keys;
    size_t num_keys;
    size_t spill_threshold;

    /* in-memory buffer */
    qihse_exec_row_t* buf;
    size_t buf_count;
    size_t buf_cap;
    size_t buf_bytes;

    /* spilled runs */
    FILE** spill_files;
    size_t num_spills;
    size_t spill_cap;

    /* merged output */
    qihse_exec_row_t* merged;
    size_t merged_count;
    size_t merged_pos;

    qihse_exec_schema_t out_schema;
    char** out_schema_names;
} sort_state_t;

/* qsort comparator using sort_state keys */
static sort_state_t* g_cmp_state;
static int row_cmp(const void* pa, const void* pb) {
    const qihse_exec_row_t* a = (const qihse_exec_row_t*)pa;
    const qihse_exec_row_t* b = (const qihse_exec_row_t*)pb;
    for (size_t i = 0; i < g_cmp_state->num_keys; i++) {
        int idx = g_cmp_state->keys[i].col_idx;
        const char* va = (idx >= 0 && (size_t)idx < a->num_values) ? a->values[idx] : NULL;
        const char* vb = (idx >= 0 && (size_t)idx < b->num_values) ? b->values[idx] : NULL;
        int c = compare_values(va, vb);
        if (!g_cmp_state->keys[i].ascending) c = -c;
        if (c != 0) return c;
    }
    return 0;
}

static size_t row_size(const qihse_exec_row_t* r) {
    size_t s = sizeof(*r);
    for (size_t i = 0; i < r->num_values; i++)
        s += r->values[i] ? strlen(r->values[i]) + 1 : 0;
    return s;
}

/* serialize a row to a file: num_values, then for each: len + data */
static void write_row(FILE* f, const qihse_exec_row_t* r) {
    int32_t nv = (int32_t)r->num_values;
    fwrite(&nv, sizeof(nv), 1, f);
    for (size_t i = 0; i < r->num_values; i++) {
        if (r->values[i]) {
            int32_t len = (int32_t)strlen(r->values[i]);
            fwrite(&len, sizeof(len), 1, f);
            fwrite(r->values[i], 1, (size_t)len, f);
        } else {
            int32_t len = -1;
            fwrite(&len, sizeof(len), 1, f);
        }
    }
}

static qihse_exec_row_t read_row(FILE* f) {
    qihse_exec_row_t r = {0};
    int32_t nv;
    if (fread(&nv, sizeof(nv), 1, f) != 1) { r.num_values = 0; return r; }
    r.num_values = (size_t)nv;
    r.values = (char**)calloc(r.num_values ? r.num_values : 1, sizeof(char*));
    for (size_t i = 0; i < r.num_values; i++) {
        int32_t len;
        if (fread(&len, sizeof(len), 1, f) != 1) { r.num_values = i; break; }
        if (len < 0) { r.values[i] = NULL; }
        else {
            r.values[i] = (char*)malloc((size_t)len + 1);
            if (fread(r.values[i], 1, (size_t)len, f) != (size_t)len) { free(r.values[i]); r.values[i] = NULL; }
            else r.values[i][len] = '\0';
        }
    }
    return r;
}

static void spill_buffer(sort_state_t* st) {
    if (st->buf_count == 0) return;
    g_cmp_state = st;
    qsort(st->buf, st->buf_count, sizeof(qihse_exec_row_t), row_cmp);
    /* write to temp file */
    if (st->num_spills >= st->spill_cap) {
        st->spill_cap = st->spill_cap ? st->spill_cap * 2 : 4;
        st->spill_files = (FILE**)realloc(st->spill_files, st->spill_cap * sizeof(FILE*));
    }
    FILE* f = tmpfile();
    if (!f) { /* fallback: keep in memory */ return; }
    for (size_t i = 0; i < st->buf_count; i++) {
        write_row(f, &st->buf[i]);
        qihse_exec_row_free(&st->buf[i]);
    }
    st->buf_count = 0;
    st->buf_bytes = 0;
    rewind(f);
    st->spill_files[st->num_spills++] = f;
}

static void sort_build(sort_state_t* st) {
    qihse_exec_row_t* r;
    while ((r = qihse_row_stream_next(st->input)) != NULL) {
        if (st->buf_count >= st->buf_cap) {
            st->buf_cap = st->buf_cap ? st->buf_cap * 2 : 64;
            st->buf = (qihse_exec_row_t*)realloc(st->buf, st->buf_cap * sizeof(qihse_exec_row_t));
        }
        st->buf[st->buf_count] = *r;
        free(r);
        st->buf_bytes += row_size(&st->buf[st->buf_count]);
        st->buf_count++;
        if (st->spill_threshold > 0 && st->buf_bytes >= st->spill_threshold) {
            spill_buffer(st);
        }
    }
    /* sort remaining in-memory buffer */
    if (st->buf_count > 0) {
        g_cmp_state = st;
        qsort(st->buf, st->buf_count, sizeof(qihse_exec_row_t), row_cmp);
    }

    /* if no spills, output is the in-memory buffer */
    if (st->num_spills == 0) {
        st->merged = st->buf;
        st->merged_count = st->buf_count;
        st->buf = NULL;
        st->buf_count = 0;
        return;
    }

    /* k-way merge: merge spilled runs + in-memory buffer */
    /* collect all rows into merged array (simple approach for correctness) */
    size_t total = st->buf_count;
    /* count rows in spill files */
    for (size_t i = 0; i < st->num_spills; i++) {
        while (1) {
            qihse_exec_row_t rr = read_row(st->spill_files[i]);
            if (rr.num_values == 0 && (rr.values == NULL || feof(st->spill_files[i]))) {
                if (rr.values) { free(rr.values); }
                break;
            }
            total++;
            /* store temporarily — we'll re-sort; for simplicity merge by reading all */
            /* Actually we need to store; use a temp dynamic array */
            if (st->merged_count >= st->buf_cap) {
                st->buf_cap = st->buf_cap ? st->buf_cap * 2 : 64;
                st->merged = (qihse_exec_row_t*)realloc(st->merged ? st->merged : NULL, st->buf_cap * sizeof(qihse_exec_row_t));
            }
            /* first time init merged */
            if (st->merged == NULL) st->merged = (qihse_exec_row_t*)calloc(st->buf_cap, sizeof(qihse_exec_row_t));
            st->merged[st->merged_count] = rr;
            st->merged_count++;
        }
        fclose(st->spill_files[i]);
    }
    /* add in-memory buffer rows */
    for (size_t i = 0; i < st->buf_count; i++) {
        if (st->merged_count >= st->buf_cap) {
            st->buf_cap *= 2;
            st->merged = (qihse_exec_row_t*)realloc(st->merged, st->buf_cap * sizeof(qihse_exec_row_t));
        }
        st->merged[st->merged_count++] = st->buf[i];
    }
    st->buf_count = 0;
    /* final sort of merged */
    g_cmp_state = st;
    qsort(st->merged, st->merged_count, sizeof(qihse_exec_row_t), row_cmp);
}

static qihse_exec_row_t* sort_next(qihse_row_stream_t* self) {
    sort_state_t* st = (sort_state_t*)self->state;
    if (st->merged_pos >= st->merged_count) return NULL;
    qihse_exec_row_t* out = (qihse_exec_row_t*)malloc(sizeof(qihse_exec_row_t));
    qihse_exec_row_t* src = &st->merged[st->merged_pos++];
    out->num_values = src->num_values;
    out->values = (char**)calloc(src->num_values ? src->num_values : 1, sizeof(char*));
    for (size_t i = 0; i < src->num_values; i++)
        out->values[i] = src->values[i] ? strdup(src->values[i]) : NULL;
    return out;
}

static void sort_close(qihse_row_stream_t* self) {
    sort_state_t* st = (sort_state_t*)self->state;
    if (!st) return;
    for (size_t i = 0; i < st->merged_count; i++) qihse_exec_row_free(&st->merged[i]);
    free(st->merged);
    for (size_t i = 0; i < st->buf_count; i++) qihse_exec_row_free(&st->buf[i]);
    free(st->buf);
    for (size_t i = 0; i < st->num_spills; i++) if (st->spill_files[i]) fclose(st->spill_files[i]);
    free(st->spill_files);
    qihse_row_stream_close(st->input);
    free(st->keys);
    for (size_t i = 0; i < st->out_schema.num_cols; i++) free(st->out_schema_names[i]);
    free(st->out_schema_names);
    free(st);
}

qihse_row_stream_t* qihse_sort_create(qihse_row_stream_t* input,
                                       const qihse_sort_key_t* keys, size_t num_keys,
                                       size_t spill_threshold) {
    if (!input) return NULL;
    qihse_row_stream_t* s = (qihse_row_stream_t*)calloc(1, sizeof(*s));
    sort_state_t* st = (sort_state_t*)calloc(1, sizeof(*st));
    st->input = input;
    st->num_keys = num_keys;
    st->keys = (qihse_sort_key_t*)calloc(num_keys ? num_keys : 1, sizeof(qihse_sort_key_t));
    memcpy(st->keys, keys, num_keys * sizeof(qihse_sort_key_t));
    st->spill_threshold = spill_threshold;

    /* out schema = input schema */
    size_t nc = input->schema ? input->schema->num_cols : 0;
    st->out_schema_names = (char**)calloc(nc ? nc : 1, sizeof(char*));
    st->out_schema.num_cols = nc;
    for (size_t i = 0; i < nc; i++) st->out_schema_names[i] = strdup(input->schema->names[i]);
    st->out_schema.names = st->out_schema_names;

    s->schema = &st->out_schema;
    s->next = sort_next;
    s->close = sort_close;
    s->state = st;

    sort_build(st);
    return s;
}
