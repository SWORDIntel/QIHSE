#ifndef QIHSE_W12_FP32_BENCHMARK_H
#define QIHSE_W12_FP32_BENCHMARK_H

#include <stddef.h>
#include <stdint.h>

/* Benchmark-only generated-fixture interface; NOT a classified data primitive.
 * metric: 0 cosine, 1 dot, 2 Euclidean similarity. dispatched: 0 scalar, 1 auto.
 * Buffers: rows*dims vectors, rows mask bytes, dims query, top_k result slots.
 * Mask is mandatory and only represents synthetic fixture membership.
 * Return 0 on success, otherwise an errno value. Never consume results on error.
 */
int qihse_w12_synthetic_search(const float *vectors, const uint8_t *selected,
                              size_t rows, size_t dims, const float *query,
                              size_t top_k, int metric, int dispatched,
                              size_t *result_rows, float *result_scores,
                              size_t *result_count, size_t *rows_scored);
const char *qihse_w12_dispatch_name(void);

#endif
