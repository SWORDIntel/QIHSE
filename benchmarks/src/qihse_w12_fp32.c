/* W12.0 synthetic-only kernel harness, NOT a VectorDB/read API.
 * No files, stored records, user data, sidecars, or network inputs are opened.
 * The mask describes generated fixture membership, not authorization.
 */
#include "../include/qihse_w12_fp32.h"
#include "qihse_cpu_distance.h"

#include <errno.h>
#include <float.h>
typedef char w12_requires_ieee_binary32[(sizeof(float) == 4 && FLT_RADIX == 2 && FLT_MANT_DIG == 24 && FLT_MAX_EXP == 128) ? 1 : -1];
#include <math.h>
#include <stddef.h>
#include <stdint.h>

/* Higher score first; ties retain physical fixture row order, like the native
 * exhaustive VectorDB path. Workspace is caller-owned and reused per query. */
int qihse_w12_synthetic_search(const float *vectors, const uint8_t *selected,
                              size_t rows, size_t dims, const float *query,
                              size_t top_k, int metric, int dispatched,
                              size_t *result_rows, float *result_scores,
                              size_t *result_count, size_t *rows_scored) {
    if (result_count) *result_count = 0;
    if (rows_scored) *rows_scored = 0;
    if (!vectors || !selected || !query || !result_rows || !result_scores ||
        !result_count || !rows_scored || !rows || !dims || !top_k ||
        top_k > rows || metric < 0 || metric > 2 ||
        (dispatched != 0 && dispatched != 1) ||
        rows > SIZE_MAX / dims || rows * dims > SIZE_MAX / sizeof(float)) {
        return EINVAL;
    }
    for (size_t j = 0; j < dims; ++j) {
        if (!isfinite(query[j])) return EDOM;
    }
    qihse_distance_functions_t fns;
    if (dispatched) {
        fns = qihse_distance_resolve();
    } else {
        fns.cosine = qihse_distance_cosine_scalar;
        fns.dot = qihse_distance_dot_scalar;
        fns.euclidean = qihse_distance_euclidean_scalar;
    }
    qihse_distance_fn_t fn = metric == 1 ? fns.dot :
                             metric == 2 ? fns.euclidean : fns.cosine;
    size_t count = 0;
    for (size_t row = 0; row < rows; ++row) {
        /* Selection precedes validation, scoring and top-K: excluded fixture
         * values cannot influence the result or the reported scored count. */
        if (!selected[row]) continue;
        const float *vector = vectors + row * dims;
        for (size_t j = 0; j < dims; ++j) {
            if (!isfinite(vector[j])) return EDOM;
        }
        float score = fn(query, vector, dims);
        if (!isfinite(score)) return ERANGE;
        if (metric == 2) score = 1.0f / (1.0f + score);
        if (!isfinite(score)) return ERANGE;
        ++*rows_scored;
        if (count == top_k && score <= result_scores[top_k - 1]) continue;
        size_t pos = count < top_k ? count : top_k - 1;
        while (pos && result_scores[pos - 1] < score) {
            result_scores[pos] = result_scores[pos - 1];
            result_rows[pos] = result_rows[pos - 1];
            --pos;
        }
        result_scores[pos] = score;
        result_rows[pos] = row;
        if (count < top_k) ++count;
    }
    *result_count = count;
    return 0;
}

const char *qihse_w12_dispatch_name(void) {
    qihse_distance_fn_t fn = qihse_distance_resolve().dot;
    if (fn == qihse_distance_dot_avx512) return "avx512";
    if (fn == qihse_distance_dot_avx2) return "avx2_fma";
    if (fn == qihse_distance_dot_avx1) return "avx1";
    return "scalar";
}
