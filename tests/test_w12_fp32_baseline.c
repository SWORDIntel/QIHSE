#include "../benchmarks/include/qihse_w12_fp32.h"
#include "qihse_vector_db.h"
#include <assert.h>
#include <errno.h>
#include <math.h>
#include <stdio.h>

/* Pin the existing public selector values without altering the production ABI. */
#define ABI_CHECK(name, value) typedef char abi_##name[(name == value) ? 1 : -1]
ABI_CHECK(QIHSE_VDB_QUERY_FLOAT32, 0);
ABI_CHECK(QIHSE_VDB_QUERY_TRINARY_SCALAR, 1);
ABI_CHECK(QIHSE_VDB_QUERY_TRINARY_MAGNITUDE, 2);
ABI_CHECK(QIHSE_VDB_QUERY_TRINARY_MAGNITUDE_BYPASS, 3);
ABI_CHECK(QIHSE_VDB_QUERY_GRAPH, 4);
ABI_CHECK(QIHSE_VDB_QUERY_INT8, 5);
ABI_CHECK(QIHSE_VDB_QUERY_SPARSE, 6);
ABI_CHECK(QIHSE_VDB_QUERY_FP16, 7);
ABI_CHECK(QIHSE_VDB_QUERY_FP32, 8);
ABI_CHECK(QIHSE_VDB_QUERY_FP8, 9);
ABI_CHECK(QIHSE_VDB_QUERY_FP4, 10);
ABI_CHECK(QIHSE_VDB_QUERY_INT4, 11);
ABI_CHECK(QIHSE_VDB_QUERY_BINARY, 12);
ABI_CHECK(QIHSE_DISTANCE_COSINE, 0);
ABI_CHECK(QIHSE_DISTANCE_DOT_PRODUCT, 1);
ABI_CHECK(QIHSE_DISTANCE_EUCLIDEAN, 2);

int main(void) {
    float vectors[] = {1, 0, 1, 0, -1, 0, NAN, INFINITY};
    float query[] = {1, 0};
    uint8_t mask[] = {1, 1, 1, 0};
    size_t ids[4], count, scored;
    float scores[4];
    for (int dispatch = 0; dispatch <= 1; ++dispatch) {
        for (int metric = 0; metric < 3; ++metric) {
            int rc = qihse_w12_synthetic_search(vectors, mask, 4, 2, query,
                                               4, metric, dispatch, ids, scores,
                                               &count, &scored);
            assert(rc == 0 && count == 3 && scored == 3);
            assert(ids[0] == 0 && ids[1] == 1 && ids[2] == 2);
            assert(scores[0] == 1 && scores[1] == 1);
            assert(metric == 2 ? fabsf(scores[2] - 1.0f/3.0f) < 1e-6f : scores[2] == -1);
        }
    }
    /* Invalid/nonfinite selected inputs fail; excluded values have no effect. */
    mask[3] = 1;
    assert(qihse_w12_synthetic_search(vectors, mask, 4, 2, query, 4, 0, 0,
                                     ids, scores, &count, &scored) == EDOM);
    assert(count == 0);
    assert(qihse_w12_synthetic_search(vectors, NULL, 4, 2, query, 4, 0, 0,
                                     ids, scores, &count, &scored) == EINVAL);
    assert(qihse_w12_synthetic_search(vectors, mask, SIZE_MAX, 2, query, 4, 0, 0,
                                     ids, scores, &count, &scored) == EINVAL);
    assert(qihse_w12_synthetic_search(vectors, mask, 4, 2, query, 0, 0, 0,
                                     ids, scores, &count, &scored) == EINVAL);
    assert(qihse_w12_synthetic_search(vectors, mask, 4, 2, query, 4, 3, 0,
                                     ids, scores, &count, &scored) == EINVAL);
    assert(qihse_w12_synthetic_search(vectors, mask, 4, 2, query, 4, 0, 2,
                                     ids, scores, &count, &scored) == EINVAL);
    /* A raw infinite L2 must not become a seemingly valid zero similarity. */
    float huge[] = {2e20f, 0, 1e20f, 0};
    float zero[] = {0, 0};
    uint8_t visible[] = {1, 1};
    for (int dispatch = 0; dispatch <= 1; ++dispatch) {
        assert(qihse_w12_synthetic_search(huge, visible, 2, 2, zero, 1, 2,
                                         dispatch, ids, scores, &count, &scored) == ERANGE);
        assert(count == 0);
    }
    puts("W12 synthetic FP32 C/ABI checks passed");
    return 0;
}
