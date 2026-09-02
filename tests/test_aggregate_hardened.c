#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "qihse_aggregate_executor.h"
#include "qihse_join_executor.h"

/* Helper stream that emits N rows */
typedef struct {
    size_t count;
    size_t max_rows;
    bool high_cardinality_distinct;
    qihse_exec_schema_t schema;
    char* schema_names[2];
} mock_stream_state_t;

static qihse_exec_row_t* mock_stream_next(qihse_row_stream_t* self) {
    mock_stream_state_t* st = (mock_stream_state_t*)self->state;
    if (st->count >= st->max_rows) return NULL;

    qihse_exec_row_t* row = (qihse_exec_row_t*)malloc(sizeof(qihse_exec_row_t));
    row->num_values = 2;
    row->values = (char**)calloc(2, sizeof(char*));

    char buf[64];
    if (st->high_cardinality_distinct) {
        /* Single group, many distinct values */
        row->values[0] = strdup("same_group");
        snprintf(buf, sizeof(buf), "val_%zu", st->count);
        row->values[1] = strdup(buf);
    } else {
        /* Many groups */
        snprintf(buf, sizeof(buf), "grp_%zu", st->count);
        row->values[0] = strdup(buf);
        row->values[1] = strdup("10.5");
    }

    st->count++;
    return row;
}

static void mock_stream_close(qihse_row_stream_t* self) {
    if (!self) return;
    free(self->state);
}

static qihse_row_stream_t* create_mock_stream(size_t max_rows, bool high_cardinality_distinct) {
    qihse_row_stream_t* s = (qihse_row_stream_t*)calloc(1, sizeof(*s));
    mock_stream_state_t* st = (mock_stream_state_t*)calloc(1, sizeof(*st));
    st->max_rows = max_rows;
    st->high_cardinality_distinct = high_cardinality_distinct;
    st->schema_names[0] = "grp";
    st->schema_names[1] = "val";
    st->schema.names = st->schema_names;
    st->schema.num_cols = 2;

    s->schema = &st->schema;
    s->next = mock_stream_next;
    s->close = mock_stream_close;
    s->state = st;
    return s;
}

static void test_group_cardinality_cap(void) {
    printf("[RUN] Aggregate executor group cardinality limit test (100,000 unique groups)...\n");
    qihse_row_stream_t* mock = create_mock_stream(100000, false);

    int group_cols[1] = {0};
    qihse_aggop_t aggs[1] = {
        { .kind = QIHSE_AGGOP_SUM, .input_col_idx = 1, .is_distinct = 0 }
    };

    /* Build aggregate over 100,000 distinct keys */
    qihse_row_stream_t* agg = qihse_aggregate_create(mock, group_cols, 1, aggs, 1);
    assert(agg != NULL);

    size_t out_rows = 0;
    qihse_exec_row_t* r;
    while ((r = qihse_row_stream_next(agg)) != NULL) {
        out_rows++;
        qihse_exec_row_free(r);
        free(r);
    }
    qihse_row_stream_close(agg);

    /* Must have capped at QIHSE_AGG_MAX_GROUPS (65,536) and not crashed */
    printf("   Emitted groups: %zu (budget cap: 65536)\n", out_rows);
    assert(out_rows <= 65536);
    assert(out_rows > 0);
    printf("[PASS] Group cardinality cap successfully enforced without memory exhaustion\n");
}

static void test_distinct_cardinality_cap(void) {
    printf("[RUN] Aggregate executor COUNT(DISTINCT) cardinality limit test (10,000 distinct values)...\n");
    qihse_row_stream_t* mock = create_mock_stream(10000, true);

    int group_cols[1] = {0};
    qihse_aggop_t aggs[1] = {
        { .kind = QIHSE_AGGOP_COUNT, .input_col_idx = 1, .is_distinct = 1 }
    };

    qihse_row_stream_t* agg = qihse_aggregate_create(mock, group_cols, 1, aggs, 1);
    assert(agg != NULL);

    qihse_exec_row_t* r = qihse_row_stream_next(agg);
    assert(r != NULL);
    assert(r->num_values == 2);
    printf("   Group: %s, COUNT(DISTINCT): %s\n", r->values[0], r->values[1]);

    long distinct_val = strtol(r->values[1], NULL, 10);
    /* Should be capped at QIHSE_AGG_MAX_DISTINCT_PER_GROUP (4,096) */
    assert(distinct_val <= 4096);
    assert(distinct_val > 0);

    qihse_exec_row_free(r);
    free(r);

    assert(qihse_row_stream_next(agg) == NULL);
    qihse_row_stream_close(agg);
    printf("[PASS] COUNT(DISTINCT) cardinality cap successfully enforced\n");
}

int main(void) {
    test_group_cardinality_cap();
    test_distinct_cardinality_cap();
    printf("\nALL aggregate hardening tests PASSED!\n");
    return 0;
}
