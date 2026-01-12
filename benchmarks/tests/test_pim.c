/* ============================================================================
 * QIHSE PIM (PROCESSING-IN-MEMORY) OPERATIONS TEST SUITE
 * ============================================================================
 *
 * Comprehensive tests for PIM operations using NPU tensor cores and AMX tiles.
 * Validates in-situ matrix operations and memory-compute co-location.
 * ============================================================================ */

#include "../include/qihse_benchmark.h"
#include "../../backends/npu/qihse_npu_openvino.h"
#include "../../backends/cpu/qihse_cpu_avx512.h"
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <math.h>

/* Test NPU PIM matrix-vector multiplication */
static void test_npu_pim_mv(void) {
    printf("Testing NPU PIM matrix-vector multiplication...\n");

    /* Create test matrix and vector */
    const size_t M = 64;  /* Matrix rows */
    const size_t N = 32;  /* Matrix columns / vector size */

    float* matrix = malloc(M * N * sizeof(float));
    float* vector = malloc(N * sizeof(float));
    float* result = malloc(M * sizeof(float));
    float* expected = malloc(M * sizeof(float));

    assert(matrix && vector && result && expected);

    /* Initialize test data */
    for (size_t i = 0; i < M * N; i++) {
        matrix[i] = (float)i * 0.01f;
    }

    for (size_t i = 0; i < N; i++) {
        vector[i] = (float)i * 0.1f;
    }

    /* Compute expected result */
    memset(expected, 0, M * sizeof(float));
    for (size_t i = 0; i < M; i++) {
        for (size_t j = 0; j < N; j++) {
            expected[i] += matrix[i * N + j] * vector[j];
        }
    }

    /* Test PIM operation */
    qihse_npu_pim_mv_t mv;
    int ret = qihse_npu_pim_mv_init(&mv, M, N, matrix, 16);
    assert(ret == 0);

    ret = qihse_npu_pim_mv_execute(&mv, vector, result);
    assert(ret == 0);

    /* Verify results */
    const float tolerance = 1e-6f;
    for (size_t i = 0; i < M; i++) {
        assert(fabsf(result[i] - expected[i]) < tolerance);
    }

    /* Cleanup */
    qihse_npu_pim_mv_destroy(&mv);
    free(matrix);
    free(vector);
    free(result);
    free(expected);

    printf("  NPU PIM matrix-vector test passed!\n");
}

/* Test NPU PIM GEMM operation */
static void test_npu_pim_gemm(void) {
    printf("Testing NPU PIM GEMM operation...\n");

    /* Create test matrices */
    const size_t M = 32;  /* Matrix A rows, Matrix C rows */
    const size_t N = 24;  /* Matrix B columns, Matrix C columns */
    const size_t K = 16;  /* Matrix A columns, Matrix B rows */

    float* matrix_a = malloc(M * K * sizeof(float));
    float* matrix_b = malloc(K * N * sizeof(float));
    float* result = malloc(M * N * sizeof(float));
    float* expected = calloc(M * N, sizeof(float));

    assert(matrix_a && matrix_b && result && expected);

    /* Initialize test data */
    for (size_t i = 0; i < M * K; i++) {
        matrix_a[i] = (float)i * 0.01f;
    }

    for (size_t i = 0; i < K * N; i++) {
        matrix_b[i] = (float)i * 0.005f;
    }

    /* Compute expected result */
    for (size_t i = 0; i < M; i++) {
        for (size_t j = 0; j < N; j++) {
            for (size_t k = 0; k < K; k++) {
                expected[i * N + j] += matrix_a[i * K + k] * matrix_b[k * N + j];
            }
        }
    }

    /* Test PIM GEMM operation */
    qihse_npu_pim_gemm_t gemm;
    int ret = qihse_npu_pim_gemm_init(&gemm, M, N, K, matrix_a, matrix_b, 8);
    assert(ret == 0);

    ret = qihse_npu_pim_gemm_execute(&gemm, result);
    assert(ret == 0);

    /* Verify results */
    const float tolerance = 1e-5f;
    for (size_t i = 0; i < M * N; i++) {
        assert(fabsf(result[i] - expected[i]) < tolerance);
    }

    /* Cleanup */
    qihse_npu_pim_gemm_destroy(&gemm);
    free(matrix_a);
    free(matrix_b);
    free(result);
    free(expected);

    printf("  NPU PIM GEMM test passed!\n");
}

/* Test AMX PIM matrix-vector multiplication */
static void test_amx_pim_mv(void) {
    printf("Testing AMX PIM matrix-vector multiplication...\n");

    /* Check if AMX is supported */
    if (!qihse_amx_pim_supported()) {
        printf("  AMX PIM not supported, skipping test\n");
        return;
    }

    /* Create test matrix and vector */
    const size_t M = 48;  /* Matrix rows */
    const size_t N = 32;  /* Matrix columns / vector size */

    float* matrix = malloc(M * N * sizeof(float));
    float* vector = malloc(N * sizeof(float));
    float* result = malloc(M * sizeof(float));
    float* expected = malloc(M * sizeof(float));

    assert(matrix && vector && result && expected);

    /* Initialize test data */
    for (size_t i = 0; i < M * N; i++) {
        matrix[i] = (float)i * 0.01f;
    }

    for (size_t i = 0; i < N; i++) {
        vector[i] = (float)i * 0.1f;
    }

    /* Compute expected result */
    memset(expected, 0, M * sizeof(float));
    for (size_t i = 0; i < M; i++) {
        for (size_t j = 0; j < N; j++) {
            expected[i] += matrix[i * N + j] * vector[j];
        }
    }

    /* Test AMX PIM operation */
    qihse_amx_pim_mv_t mv;
    int ret = qihse_amx_pim_mv_init(&mv, M, N, matrix, 16);
    assert(ret == 0);

    ret = qihse_amx_pim_mv_execute(&mv, vector, result);
    assert(ret == 0);

    /* Verify results */
    const float tolerance = 1e-6f;
    for (size_t i = 0; i < M; i++) {
        assert(fabsf(result[i] - expected[i]) < tolerance);
    }

    /* Cleanup */
    qihse_amx_pim_mv_destroy(&mv);
    free(matrix);
    free(vector);
    free(result);
    free(expected);

    printf("  AMX PIM matrix-vector test passed!\n");
}

/* Test AMX PIM GEMM operation */
static void test_amx_pim_gemm(void) {
    printf("Testing AMX PIM GEMM operation...\n");

    /* Check if AMX is supported */
    if (!qihse_amx_pim_supported()) {
        printf("  AMX PIM not supported, skipping test\n");
        return;
    }

    /* Create test matrices */
    const size_t M = 24;  /* Matrix A rows, Matrix C rows */
    const size_t N = 20;  /* Matrix B columns, Matrix C columns */
    const size_t K = 16;  /* Matrix A columns, Matrix B rows */

    float* matrix_a = malloc(M * K * sizeof(float));
    float* matrix_b = malloc(K * N * sizeof(float));
    float* result = malloc(M * N * sizeof(float));
    float* expected = calloc(M * N, sizeof(float));

    assert(matrix_a && matrix_b && result && expected);

    /* Initialize test data */
    for (size_t i = 0; i < M * K; i++) {
        matrix_a[i] = (float)i * 0.01f;
    }

    for (size_t i = 0; i < K * N; i++) {
        matrix_b[i] = (float)i * 0.005f;
    }

    /* Compute expected result */
    for (size_t i = 0; i < M; i++) {
        for (size_t j = 0; j < N; j++) {
            for (size_t k = 0; k < K; k++) {
                expected[i * N + j] += matrix_a[i * K + k] * matrix_b[k * N + j];
            }
        }
    }

    /* Test AMX PIM GEMM operation */
    qihse_amx_pim_gemm_t gemm;
    int ret = qihse_amx_pim_gemm_init(&gemm, M, N, K, matrix_a, matrix_b, 8);
    assert(ret == 0);

    ret = qihse_amx_pim_gemm_execute(&gemm, result);
    assert(ret == 0);

    /* Verify results */
    const float tolerance = 1e-5f;
    for (size_t i = 0; i < M * N; i++) {
        assert(fabsf(result[i] - expected[i]) < tolerance);
    }

    /* Cleanup */
    qihse_amx_pim_gemm_destroy(&gemm);
    free(matrix_a);
    free(matrix_b);
    free(result);
    free(expected);

    printf("  AMX PIM GEMM test passed!\n");
}

/* Test PIM memory allocation */
static void test_pim_memory(void) {
    printf("Testing PIM memory allocation...\n");

    const size_t size = 1024;
    const size_t alignment = 64;

    /* Test PIM allocation */
    void* ptr = qihse_npu_pim_alloc(size, alignment);
    assert(ptr != NULL);

    /* Verify alignment */
    assert(((uintptr_t)ptr % alignment) == 0);

    /* Test PIM free */
    qihse_npu_pim_free(ptr);

    printf("  PIM memory allocation test passed!\n");
}

/* Test AMX tile information */
static void test_amx_tile_info(void) {
    printf("Testing AMX tile information...\n");

    size_t tile_count, max_rows, max_cols;
    qihse_amx_get_tile_info(&tile_count, &max_rows, &max_cols);

    assert(tile_count == 8);  /* AMX has 8 tiles */
    assert(max_rows == 16);   /* Maximum 16 rows */
    assert(max_cols == 16);   /* Maximum 16 columns */

    printf("  AMX tile information test passed!\n");
}

/* Main test runner */
int main(int argc, char** argv) {
    printf("Running QIHSE PIM Operations Test Suite...\n\n");

    test_npu_pim_mv();
    printf("\n");

    test_npu_pim_gemm();
    printf("\n");

    test_amx_pim_mv();
    printf("\n");

    test_amx_pim_gemm();
    printf("\n");

    test_pim_memory();
    printf("\n");

    test_amx_tile_info();
    printf("\n");

    printf("All QIHSE PIM Operations tests passed!\n");
    return 0;
}
