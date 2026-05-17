#include "codecs/qihse_trinary_tryte_codec.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define QIHSE_BENCH_ROWS 2048u
#define QIHSE_BENCH_DIMS 64u
#define QIHSE_BENCH_TOPK 8u
#define QIHSE_BENCH_ITERS 64u

static double qihse_bench_seconds(void) {
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0.0;
    }
    return (double)ts.tv_sec + ((double)ts.tv_nsec / 1000000000.0);
}

static uint32_t qihse_bench_mix32(uint32_t value) {
    value ^= value >> 16;
    value *= 0x7feb352du;
    value ^= value >> 15;
    value *= 0x846ca68bu;
    value ^= value >> 16;
    return value;
}

static float qihse_bench_query_value(size_t dim) {
    return (dim % 3u == 0u) ? 1.0f : -1.0f;
}

static int32_t qihse_bench_signed_from_float(float value) {
    if (value < 0.0f) {
        return -1;
    }
    if (value > 0.0f) {
        return 1;
    }
    return 0;
}

static void qihse_bench_fill_data(float* rows, float* query) {
    size_t row;
    size_t dim;

    for (dim = 0u; dim < QIHSE_BENCH_DIMS; dim++) {
        query[dim] = qihse_bench_query_value(dim);
    }

    for (row = 0u; row < QIHSE_BENCH_ROWS; row++) {
        for (dim = 0u; dim < QIHSE_BENCH_DIMS; dim++) {
            uint32_t mixed = qihse_bench_mix32((uint32_t)((row + 17u) * 131u +
                                                          (dim + 5u) * 977u));
            uint32_t bucket = mixed % 5u;
            float value = 0.0f;

            if (bucket == 0u || bucket == 1u) {
                value = query[dim];
            } else if (bucket == 2u || bucket == 3u) {
                value = -query[dim];
            }
            rows[(row * QIHSE_BENCH_DIMS) + dim] = value;
        }
    }

    for (dim = 0u; dim < QIHSE_BENCH_DIMS; dim++) {
        rows[dim] = query[dim];
        rows[QIHSE_BENCH_DIMS + dim] = dim == 7u ? 0.0f : query[dim];
        rows[(2u * QIHSE_BENCH_DIMS) + dim] = dim == 11u ? -query[dim] : query[dim];
        rows[(3u * QIHSE_BENCH_DIMS) + dim] =
            (dim == 13u || dim == 17u) ? -query[dim] : query[dim];
    }
}

static int32_t qihse_bench_reference_score(const float* row, const float* query) {
    int32_t score = 0;
    size_t dim;

    for (dim = 0u; dim < QIHSE_BENCH_DIMS; dim++) {
        score += qihse_bench_signed_from_float(row[dim]) *
                 qihse_bench_signed_from_float(query[dim]);
    }
    return score;
}

static int qihse_bench_is_better(int32_t lhs_score,
                                 size_t lhs_row,
                                 int32_t rhs_score,
                                 size_t rhs_row) {
    return lhs_score > rhs_score ||
           (lhs_score == rhs_score && lhs_row < rhs_row);
}

static void qihse_bench_reference_topk(const float* rows,
                                       const float* query,
                                       size_t* out_indexes,
                                       int32_t* out_scores) {
    size_t count = 0u;
    size_t row;

    for (row = 0u; row < QIHSE_BENCH_ROWS; row++) {
        int32_t score = qihse_bench_reference_score(rows + (row * QIHSE_BENCH_DIMS),
                                                    query);
        size_t insert_at = count;

        while (insert_at > 0u &&
               qihse_bench_is_better(score,
                                     row,
                                     out_scores[insert_at - 1u],
                                     out_indexes[insert_at - 1u])) {
            insert_at--;
        }
        if (insert_at >= QIHSE_BENCH_TOPK) {
            continue;
        }
        if (count < QIHSE_BENCH_TOPK) {
            count++;
        }
        if (count > insert_at + 1u) {
            size_t move;
            for (move = count - 1u; move > insert_at; move--) {
                out_indexes[move] = out_indexes[move - 1u];
                out_scores[move] = out_scores[move - 1u];
            }
        }
        out_indexes[insert_at] = row;
        out_scores[insert_at] = score;
    }
}

static int qihse_bench_verify_results(const size_t* actual_indexes,
                                      const int32_t* actual_scores,
                                      size_t actual_count,
                                      const size_t* expected_indexes,
                                      const int32_t* expected_scores) {
    size_t i;

    if (actual_count != QIHSE_BENCH_TOPK) {
        fprintf(stderr, "expected %u results, got %zu\n",
                (unsigned)QIHSE_BENCH_TOPK, actual_count);
        return 0;
    }
    for (i = 0u; i < QIHSE_BENCH_TOPK; i++) {
        if (actual_indexes[i] != expected_indexes[i] ||
            actual_scores[i] != expected_scores[i]) {
            fprintf(stderr,
                    "top-k mismatch at %zu: got row=%zu score=%d, "
                    "expected row=%zu score=%d\n",
                    i,
                    actual_indexes[i],
                    actual_scores[i],
                    expected_indexes[i],
                    expected_scores[i]);
            return 0;
        }
    }
    return 1;
}

int main(void) {
    float* rows = NULL;
    float query[QIHSE_BENCH_DIMS];
    uint8_t* encoded_rows = NULL;
    uint8_t* encoded_query = NULL;
    size_t expected_indexes[QIHSE_BENCH_TOPK] = {0u};
    int32_t expected_scores[QIHSE_BENCH_TOPK] = {0};
    size_t actual_indexes[QIHSE_BENCH_TOPK] = {0u};
    int32_t actual_scores[QIHSE_BENCH_TOPK] = {0};
    size_t actual_count = 0u;
    size_t row_bytes = 0u;
    size_t payload_bytes = 0u;
    double encode_start;
    double encode_seconds;
    double select_start;
    double select_seconds;
    volatile int64_t checksum = 0;
    size_t iter;
    size_t i;
    int exit_code = 1;

    rows = (float*)calloc(QIHSE_BENCH_ROWS * QIHSE_BENCH_DIMS, sizeof(float));
    if (!rows) {
        perror("calloc rows");
        goto cleanup;
    }
    qihse_bench_fill_data(rows, query);
    qihse_bench_reference_topk(rows, query, expected_indexes, expected_scores);

    if (!qihse_trinary_tryte_row_bytes(QIHSE_BENCH_DIMS, &row_bytes) ||
        !qihse_trinary_tryte_payload_bytes(QIHSE_BENCH_ROWS,
                                           QIHSE_BENCH_DIMS,
                                           &payload_bytes)) {
        perror("size calculation");
        goto cleanup;
    }

    encoded_rows = (uint8_t*)malloc(payload_bytes);
    encoded_query = (uint8_t*)malloc(row_bytes);
    if (!encoded_rows || !encoded_query) {
        perror("malloc encoded payloads");
        goto cleanup;
    }

    encode_start = qihse_bench_seconds();
    if (!qihse_trinary_tryte_encode_matrix(rows,
                                           QIHSE_BENCH_ROWS,
                                           QIHSE_BENCH_DIMS,
                                           encoded_rows,
                                           payload_bytes) ||
        !qihse_trinary_tryte_encode_row(query,
                                        QIHSE_BENCH_DIMS,
                                        encoded_query,
                                        row_bytes)) {
        perror("encode");
        goto cleanup;
    }
    encode_seconds = qihse_bench_seconds() - encode_start;

    if (!qihse_trinary_tryte_select_topk(encoded_rows,
                                         encoded_query,
                                         QIHSE_BENCH_ROWS,
                                         QIHSE_BENCH_DIMS,
                                         actual_indexes,
                                         actual_scores,
                                         QIHSE_BENCH_TOPK,
                                         &actual_count)) {
        perror("select_topk");
        goto cleanup;
    }
    if (!qihse_bench_verify_results(actual_indexes,
                                    actual_scores,
                                    actual_count,
                                    expected_indexes,
                                    expected_scores)) {
        goto cleanup;
    }

    select_start = qihse_bench_seconds();
    for (iter = 0u; iter < QIHSE_BENCH_ITERS; iter++) {
        if (!qihse_trinary_tryte_select_topk(encoded_rows,
                                             encoded_query,
                                             QIHSE_BENCH_ROWS,
                                             QIHSE_BENCH_DIMS,
                                             actual_indexes,
                                             actual_scores,
                                             QIHSE_BENCH_TOPK,
                                             &actual_count)) {
            perror("select_topk benchmark");
            goto cleanup;
        }
        checksum += (int64_t)actual_indexes[0] + (int64_t)actual_scores[0];
    }
    select_seconds = qihse_bench_seconds() - select_start;

    printf("trinary_candidate_bench rows=%u dims=%u row_bytes=%zu topk=%u iterations=%u\n",
           (unsigned)QIHSE_BENCH_ROWS,
           (unsigned)QIHSE_BENCH_DIMS,
           row_bytes,
           (unsigned)QIHSE_BENCH_TOPK,
           (unsigned)QIHSE_BENCH_ITERS);
    printf("encoding_ms=%.3f selection_total_ms=%.3f selection_avg_us=%.3f checksum=%lld\n",
           encode_seconds * 1000.0,
           select_seconds * 1000.0,
           (select_seconds * 1000000.0) / (double)QIHSE_BENCH_ITERS,
           (long long)checksum);
    for (i = 0u; i < actual_count; i++) {
        printf("result[%zu] row=%zu score=%d\n",
               i,
               actual_indexes[i],
               actual_scores[i]);
    }

    exit_code = 0;

cleanup:
    free(encoded_query);
    free(encoded_rows);
    free(rows);
    return exit_code;
}
