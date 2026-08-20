#define _GNU_SOURCE
/*
 * QIHSE Join Executor — Phase 1 Relational Completeness
 *
 * Implements hash-join (build/probe) and nested-loop join operators over
 * generic row streams.  Output schema is the concatenation of build+probe
 * (or outer+inner) columns.
 */
#include "qihse_join_executor.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

/* ------------------------------------------------------------------------- */
/* Helpers                                                                    */
/* ------------------------------------------------------------------------- */

static bool ieq(const char* a, const char* b) {
    if (!a || !b) return a == b;
    while (*a && *b) {
        if (tolower((unsigned char)*a) != tolower((unsigned char)*b)) return false;
        a++; b++;
    }
    return *a == *b;
}

int qihse_schema_find_col(const qihse_exec_schema_t* schema, const char* name) {
    if (!schema || !name) return -1;
    for (size_t i = 0; i < schema->num_cols; i++) {
        if (ieq(schema->names[i], name)) return (int)i;
    }
    return -1;
}

void qihse_exec_row_free(qihse_exec_row_t* row) {
    if (!row) return;
    for (size_t i = 0; i < row->num_values; i++) free(row->values[i]);
    free(row->values);
    row->values = NULL;
    row->num_values = 0;
}

static qihse_exec_row_t dup_row(const qihse_exec_row_t* src) {
    qihse_exec_row_t r = {0};
    r.num_values = src->num_values;
    r.values = (char**)calloc(src->num_values, sizeof(char*));
    for (size_t i = 0; i < src->num_values; i++)
        r.values[i] = src->values[i] ? strdup(src->values[i]) : NULL;
    return r;
}

static qihse_exec_row_t concat_rows(const qihse_exec_row_t* a, const qihse_exec_row_t* b) {
    size_t na = a ? a->num_values : 0;
    size_t nb = b ? b->num_values : 0;
    qihse_exec_row_t r = {0};
    r.num_values = na + nb;
    r.values = (char**)calloc(r.num_values ? r.num_values : 1, sizeof(char*));
    for (size_t i = 0; i < na; i++)
        r.values[i] = a->values[i] ? strdup(a->values[i]) : NULL;
    for (size_t i = 0; i < nb; i++)
        r.values[na + i] = b->values[i] ? strdup(b->values[i]) : NULL;
    return r;
}

qihse_exec_row_t* qihse_row_stream_next(qihse_row_stream_t* s) {
    if (!s || !s->next) return NULL;
    return s->next(s);
}

void qihse_row_stream_close(qihse_row_stream_t* s) {
    if (!s) return;
    if (s->close) s->close(s);
    free(s);
}

/* ------------------------------------------------------------------------- */
/* Row array stream (materialized rows)                                       */
/* ------------------------------------------------------------------------- */

typedef struct {
    const qihse_exec_schema_t* schema;
    qihse_exec_row_t* rows;
    size_t num_rows;
    size_t pos;
    int owns_rows;
} array_stream_state_t;

static qihse_exec_row_t* array_next(qihse_row_stream_t* self) {
    array_stream_state_t* st = (array_stream_state_t*)self->state;
    if (st->pos >= st->num_rows) return NULL;
    qihse_exec_row_t* out = (qihse_exec_row_t*)malloc(sizeof(qihse_exec_row_t));
    *out = dup_row(&st->rows[st->pos]);
    st->pos++;
    return out;
}

static void array_close(qihse_row_stream_t* self) {
    array_stream_state_t* st = (array_stream_state_t*)self->state;
    if (st && st->owns_rows) {
        for (size_t i = 0; i < st->num_rows; i++) qihse_exec_row_free(&st->rows[i]);
        free(st->rows);
    }
    free(st);
}

qihse_row_stream_t* qihse_row_array_stream_create(const qihse_exec_schema_t* schema,
                                                   qihse_exec_row_t* rows, size_t num_rows) {
    qihse_row_stream_t* s = (qihse_row_stream_t*)calloc(1, sizeof(*s));
    array_stream_state_t* st = (array_stream_state_t*)calloc(1, sizeof(*st));
    st->schema = schema;
    st->rows = rows;
    st->num_rows = num_rows;
    st->pos = 0;
    st->owns_rows = 0;
    s->schema = schema;
    s->next = array_next;
    s->close = array_close;
    s->state = st;
    return s;
}

/* ------------------------------------------------------------------------- */
/* Hash join                                                                  */
/* ------------------------------------------------------------------------- */

typedef struct hash_bucket {
    char* key;
    qihse_exec_row_t* rows;   /* chain of build rows with this key */
    size_t num_rows;
    struct hash_bucket* next;
} hash_bucket_t;

typedef struct {
    qihse_row_stream_t* build;
    qihse_row_stream_t* probe;
    qihse_sql_join_type_t join_type;
    int build_key_idx;
    int probe_key_idx;
    /* hash table */
    hash_bucket_t** buckets;
    size_t num_buckets;
    /* output schema */
    qihse_exec_schema_t out_schema;
    char** out_schema_names;
    /* probe state */
    qihse_exec_row_t* current_probe;   /* current probe row */
    hash_bucket_t* current_bucket;     /* bucket matching current probe */
    size_t bucket_pos;                 /* position within current bucket */
    /* for LEFT join: track unmatched build rows */
    int* build_matched;
    size_t num_build_rows;
    qihse_exec_row_t* build_rows;      /* materialized build rows */
    size_t build_row_pos;              /* for emitting unmatched left rows */
    int emitting_unmatched;
} hash_join_state_t;

static unsigned long hash_str(const char* s) {
    unsigned long h = 5381;
    if (!s) return 0;
    while (*s) { h = ((h << 5) + h) + (unsigned char)*s; s++; }
    return h;
}

static void hash_join_build(hash_join_state_t* st) {
    /* materialize build side into hash table + array */
    size_t cap = 16;
    st->build_rows = (qihse_exec_row_t*)calloc(cap, sizeof(qihse_exec_row_t));
    st->num_build_rows = 0;
    st->num_buckets = 256;
    st->buckets = (hash_bucket_t**)calloc(st->num_buckets, sizeof(hash_bucket_t*));

    qihse_exec_row_t* r;
    while ((r = qihse_row_stream_next(st->build)) != NULL) {
        if (st->num_build_rows >= cap) {
            cap *= 2;
            st->build_rows = (qihse_exec_row_t*)realloc(st->build_rows, cap * sizeof(qihse_exec_row_t));
        }
        st->build_rows[st->num_build_rows] = *r;
        free(r);
        const char* key = st->build_key_idx >= 0 && (size_t)st->build_key_idx < st->build_rows[st->num_build_rows].num_values
                          ? st->build_rows[st->num_build_rows].values[st->build_key_idx] : NULL;
        unsigned long h = hash_str(key) % st->num_buckets;
        hash_bucket_t* b = st->buckets[h];
        hash_bucket_t* found = NULL;
        for (; b; b = b->next) {
            if ((b->key == NULL && key == NULL) || (b->key && key && ieq(b->key, key))) { found = b; break; }
        }
        if (!found) {
            found = (hash_bucket_t*)calloc(1, sizeof(*found));
            found->key = key ? strdup(key) : NULL;
            found->rows = (qihse_exec_row_t*)calloc(4, sizeof(qihse_exec_row_t));
            found->num_rows = 0;
            found->next = st->buckets[h];
            st->buckets[h] = found;
        }
        if (found->num_rows && (found->num_rows % 4 == 0)) {
            found->rows = (qihse_exec_row_t*)realloc(found->rows, (found->num_rows + 4) * sizeof(qihse_exec_row_t));
        }
        found->rows[found->num_rows++] = dup_row(&st->build_rows[st->num_build_rows]);
        st->num_build_rows++;
    }
    st->build_matched = (int*)calloc(st->num_build_rows, sizeof(int));
}

static qihse_exec_row_t* hash_join_next(qihse_row_stream_t* self) {
    hash_join_state_t* st = (hash_join_state_t*)self->state;

    /* phase: emit unmatched build rows for LEFT/FULL join */
    if (st->emitting_unmatched) {
        while (st->build_row_pos < st->num_build_rows) {
            if (!st->build_matched[st->build_row_pos]) {
                qihse_exec_row_t* out = (qihse_exec_row_t*)malloc(sizeof(qihse_exec_row_t));
                *out = dup_row(&st->build_rows[st->build_row_pos]);
                st->build_row_pos++;
                return out;
            }
            st->build_row_pos++;
        }
        return NULL;
    }

    for (;;) {
        /* if we have a current probe row and bucket, continue emitting matches */
        if (st->current_probe && st->current_bucket) {
            while (st->bucket_pos < st->current_bucket->num_rows) {
                qihse_exec_row_t* out = (qihse_exec_row_t*)malloc(sizeof(qihse_exec_row_t));
                *out = concat_rows(&st->current_bucket->rows[st->bucket_pos], st->current_probe);
                st->bucket_pos++;
                return out;
            }
            st->current_bucket = NULL;
        }

        /* get next probe row */
        if (st->current_probe) { qihse_exec_row_free(st->current_probe); free(st->current_probe); st->current_probe = NULL; }
        st->current_probe = qihse_row_stream_next(st->probe);
        if (!st->current_probe) {
            /* switch to emitting unmatched build rows for LEFT/FULL */
            if (st->join_type == QIHSE_JOIN_LEFT || st->join_type == QIHSE_JOIN_FULL) {
                st->emitting_unmatched = 1;
                st->build_row_pos = 0;
                continue;
            }
            return NULL;
        }
        const char* key = st->probe_key_idx >= 0 && (size_t)st->probe_key_idx < st->current_probe->num_values
                          ? st->current_probe->values[st->probe_key_idx] : NULL;
        unsigned long h = hash_str(key) % st->num_buckets;
        st->current_bucket = st->buckets[h];
        /* find matching bucket */
        hash_bucket_t* b = st->current_bucket;
        st->current_bucket = NULL;
        for (; b; b = b->next) {
            if ((b->key == NULL && key == NULL) || (b->key && key && ieq(b->key, key))) { st->current_bucket = b; break; }
        }
        st->bucket_pos = 0;
        if (!st->current_bucket) {
            /* no match — for RIGHT join emit probe with nulls; for INNER skip */
            if (st->join_type == QIHSE_JOIN_RIGHT || st->join_type == QIHSE_JOIN_FULL) {
                qihse_exec_row_t* out = (qihse_exec_row_t*)malloc(sizeof(qihse_exec_row_t));
                /* build side nulls + probe row */
                
                /* determine build width from schema */
                size_t build_width = 0;
                /* out_schema names = build_names + probe_names; build portion is first half */
                size_t total = st->out_schema.num_cols;
                size_t probe_width = st->current_probe->num_values;
                build_width = total >= probe_width ? total - probe_width : 0;
                out->num_values = total;
                out->values = (char**)calloc(total ? total : 1, sizeof(char*));
                for (size_t i = 0; i < build_width; i++) out->values[i] = NULL;
                for (size_t i = 0; i < probe_width; i++)
                    out->values[build_width + i] = st->current_probe->values[i] ? strdup(st->current_probe->values[i]) : NULL;
                return out;
            }
            /* INNER/LEFT: just continue to next probe */
            continue;
        }
        /* mark build rows as matched */
        for (size_t i = 0; i < st->num_build_rows; i++) {
            const char* bk = st->build_key_idx >= 0 && (size_t)st->build_key_idx < st->build_rows[i].num_values
                             ? st->build_rows[i].values[st->build_key_idx] : NULL;
            if ((bk == NULL && key == NULL) || (bk && key && ieq(bk, key))) st->build_matched[i] = 1;
        }
    }
}

static void hash_join_close(qihse_row_stream_t* self) {
    hash_join_state_t* st = (hash_join_state_t*)self->state;
    if (!st) return;
    /* free hash table */
    for (size_t i = 0; i < st->num_buckets; i++) {
        hash_bucket_t* b = st->buckets[i];
        while (b) {
            hash_bucket_t* next = b->next;
            free(b->key);
            for (size_t j = 0; j < b->num_rows; j++) qihse_exec_row_free(&b->rows[j]);
            free(b->rows);
            free(b);
            b = next;
        }
    }
    free(st->buckets);
    /* free materialized build rows */
    for (size_t i = 0; i < st->num_build_rows; i++) qihse_exec_row_free(&st->build_rows[i]);
    free(st->build_rows);
    free(st->build_matched);
    if (st->current_probe) { qihse_exec_row_free(st->current_probe); free(st->current_probe); }
    /* close input streams */
    qihse_row_stream_close(st->build);
    qihse_row_stream_close(st->probe);
    /* free out schema names */
    for (size_t i = 0; i < st->out_schema.num_cols; i++) free(st->out_schema_names[i]);
    free(st->out_schema_names);
    free(st);
}

qihse_row_stream_t* qihse_hash_join_create(qihse_row_stream_t* build,
                                            qihse_row_stream_t* probe,
                                            const char* build_key_col,
                                            const char* probe_key_col,
                                            qihse_sql_join_type_t join_type) {
    if (!build || !probe) return NULL;
    qihse_row_stream_t* s = (qihse_row_stream_t*)calloc(1, sizeof(*s));
    hash_join_state_t* st = (hash_join_state_t*)calloc(1, sizeof(*st));
    st->build = build;
    st->probe = probe;
    st->join_type = join_type;
    st->build_key_idx = build_key_col ? qihse_schema_find_col(build->schema, build_key_col) : -1;
    st->probe_key_idx = probe_key_col ? qihse_schema_find_col(probe->schema, probe_key_col) : -1;

    /* build out schema = build cols + probe cols */
    size_t nb = build->schema ? build->schema->num_cols : 0;
    size_t np = probe->schema ? probe->schema->num_cols : 0;
    st->out_schema_names = (char**)calloc(nb + np ? nb + np : 1, sizeof(char*));
    st->out_schema.num_cols = nb + np;
    for (size_t i = 0; i < nb; i++)
        st->out_schema_names[i] = strdup(build->schema->names[i]);
    for (size_t i = 0; i < np; i++)
        st->out_schema_names[nb + i] = strdup(probe->schema->names[i]);
    st->out_schema.names = st->out_schema_names;

    s->schema = &st->out_schema;
    s->next = hash_join_next;
    s->close = hash_join_close;
    s->state = st;

    /* build phase */
    hash_join_build(st);
    return s;
}

/* ------------------------------------------------------------------------- */
/* Nested-loop join                                                           */
/* ------------------------------------------------------------------------- */

typedef struct {
    qihse_row_stream_t* outer;
    qihse_row_stream_t* inner;
    qihse_sql_join_type_t join_type;
    int outer_key_idx;
    int inner_key_idx;
    qihse_exec_row_t* current_outer;
    qihse_exec_row_t* inner_rows;     /* materialized inner */
    size_t num_inner;
    size_t inner_pos;
    int outer_matched;
    qihse_exec_schema_t out_schema;
    char** out_schema_names;
} nl_join_state_t;

static qihse_exec_row_t* nl_join_next(qihse_row_stream_t* self) {
    nl_join_state_t* st = (nl_join_state_t*)self->state;
    for (;;) {
        if (st->current_outer) {
            while (st->inner_pos < st->num_inner) {
                qihse_exec_row_t* ir = &st->inner_rows[st->inner_pos];
                st->inner_pos++;
                /* test equi-condition (or CROSS = always match) */
                int match = 1;
                if (st->outer_key_idx >= 0 && st->inner_key_idx >= 0) {
                    const char* ov = st->current_outer->values[st->outer_key_idx];
                    const char* iv = ir->values[st->inner_key_idx];
                    match = (ov == NULL && iv == NULL) || (ov && iv && ieq(ov, iv));
                }
                if (match) {
                    st->outer_matched = 1;
                    qihse_exec_row_t* out = (qihse_exec_row_t*)malloc(sizeof(qihse_exec_row_t));
                    *out = concat_rows(st->current_outer, ir);
                    return out;
                }
            }
            /* inner exhausted for this outer row */
            if (!st->outer_matched && (st->join_type == QIHSE_JOIN_LEFT || st->join_type == QIHSE_JOIN_FULL)) {
                qihse_exec_row_t* out = (qihse_exec_row_t*)malloc(sizeof(qihse_exec_row_t));
                size_t no = st->current_outer->num_values;
                size_t ni = st->num_inner > 0 ? st->inner_rows[0].num_values : 0;
                out->num_values = no + ni;
                out->values = (char**)calloc(out->num_values ? out->num_values : 1, sizeof(char*));
                for (size_t i = 0; i < no; i++)
                    out->values[i] = st->current_outer->values[i] ? strdup(st->current_outer->values[i]) : NULL;
                for (size_t i = 0; i < ni; i++) out->values[no + i] = NULL;
                qihse_exec_row_free(st->current_outer);
                free(st->current_outer);
                st->current_outer = NULL;
                return out;
            }
            qihse_exec_row_free(st->current_outer);
            free(st->current_outer);
            st->current_outer = NULL;
        }
        st->current_outer = qihse_row_stream_next(st->outer);
        if (!st->current_outer) return NULL;
        st->inner_pos = 0;
        st->outer_matched = 0;
    }
}

static void nl_join_close(qihse_row_stream_t* self) {
    nl_join_state_t* st = (nl_join_state_t*)self->state;
    if (!st) return;
    if (st->current_outer) { qihse_exec_row_free(st->current_outer); free(st->current_outer); }
    for (size_t i = 0; i < st->num_inner; i++) qihse_exec_row_free(&st->inner_rows[i]);
    free(st->inner_rows);
    qihse_row_stream_close(st->outer);
    qihse_row_stream_close(st->inner);
    for (size_t i = 0; i < st->out_schema.num_cols; i++) free(st->out_schema_names[i]);
    free(st->out_schema_names);
    free(st);
}

qihse_row_stream_t* qihse_nested_loop_join_create(qihse_row_stream_t* outer,
                                                   qihse_row_stream_t* inner,
                                                   const char* outer_key_col,
                                                   const char* inner_key_col,
                                                   qihse_sql_join_type_t join_type) {
    if (!outer || !inner) return NULL;
    qihse_row_stream_t* s = (qihse_row_stream_t*)calloc(1, sizeof(*s));
    nl_join_state_t* st = (nl_join_state_t*)calloc(1, sizeof(*st));
    st->outer = outer;
    st->inner = inner;
    st->join_type = join_type;
    st->outer_key_idx = outer_key_col ? qihse_schema_find_col(outer->schema, outer_key_col) : -1;
    st->inner_key_idx = inner_key_col ? qihse_schema_find_col(inner->schema, inner_key_col) : -1;

    /* materialize inner */
    size_t cap = 16;
    st->inner_rows = (qihse_exec_row_t*)calloc(cap, sizeof(qihse_exec_row_t));
    qihse_exec_row_t* r;
    while ((r = qihse_row_stream_next(inner)) != NULL) {
        if (st->num_inner >= cap) {
            cap *= 2;
            st->inner_rows = (qihse_exec_row_t*)realloc(st->inner_rows, cap * sizeof(qihse_exec_row_t));
        }
        st->inner_rows[st->num_inner] = *r;
        free(r);
        st->num_inner++;
    }

    /* out schema */
    size_t no = outer->schema ? outer->schema->num_cols : 0;
    size_t ni = inner->schema ? inner->schema->num_cols : 0;
    st->out_schema_names = (char**)calloc(no + ni ? no + ni : 1, sizeof(char*));
    st->out_schema.num_cols = no + ni;
    for (size_t i = 0; i < no; i++) st->out_schema_names[i] = strdup(outer->schema->names[i]);
    for (size_t i = 0; i < ni; i++) st->out_schema_names[no + i] = strdup(inner->schema->names[i]);
    st->out_schema.names = st->out_schema_names;

    s->schema = &st->out_schema;
    s->next = nl_join_next;
    s->close = nl_join_close;
    s->state = st;
    return s;
}
