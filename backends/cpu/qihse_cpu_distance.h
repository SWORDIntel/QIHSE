/*
 * QIHSE - CPU SIMD Distance Functions
 *
 * Runtime-dispatched SIMD-accelerated vector distance computations.
 * Auto-selects AVX-512, AVX2, AVX1, or scalar fallback based on CPU features.
 */

#ifndef QIHSE_CPU_DISTANCE_H
#define QIHSE_CPU_DISTANCE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Distance function signatures */
typedef float (*qihse_distance_fn_t)(const float* a, const float* b, size_t dims);

typedef struct {
    qihse_distance_fn_t cosine;
    qihse_distance_fn_t dot;
    qihse_distance_fn_t euclidean;
} qihse_distance_functions_t;

qihse_distance_functions_t qihse_distance_resolve(void);

/* Runtime-dispatched distance functions.
 * These auto-select the best implementation (AVX-512 > AVX2 > AVX1 > scalar)
 * on first call. */
float qihse_distance_cosine(const float* a, const float* b, size_t dims);
float qihse_distance_dot(const float* a, const float* b, size_t dims);
float qihse_distance_euclidean(const float* a, const float* b, size_t dims);

/* AVX1 implementations — 8 floats per instruction, no FMA (Sandy Bridge / Ivy Bridge) */
float qihse_distance_cosine_avx1(const float* a, const float* b, size_t dims);
float qihse_distance_dot_avx1(const float* a, const float* b, size_t dims);
float qihse_distance_euclidean_avx1(const float* a, const float* b, size_t dims);

/* 4-way ILP unrolled AVX 1.0 distance kernels (Ivy Bridge 3-cycle vaddps saturation) */
float qihse_l2_sq_distance_avx(const float *a, const float *b, size_t dim);
float qihse_dot_product_avx(const float *a, const float *b, size_t dim);
float qihse_cosine_distance_avx(const float *a, const float *b, size_t dim, float norm_a, float norm_b);

/* F16C half-precision distance kernels (dynamic precision tiering) */
float qihse_l2_sq_distance_f16c(const uint16_t *a, const uint16_t *b, size_t dim);
float qihse_dot_product_f16c(const uint16_t *a, const uint16_t *b, size_t dim);

/* Explicit SIMD implementations (for benchmarking/comparison) */
float qihse_distance_cosine_avx2(const float* a, const float* b, size_t dims);
float qihse_distance_dot_avx2(const float* a, const float* b, size_t dims);
float qihse_distance_euclidean_avx2(const float* a, const float* b, size_t dims);

/* AVX-512 implementations — 16 floats per instruction, 2x unrolled for ILP */
float qihse_distance_cosine_avx512(const float* a, const float* b, size_t dims);
float qihse_distance_dot_avx512(const float* a, const float* b, size_t dims);
float qihse_distance_euclidean_avx512(const float* a, const float* b, size_t dims);

/* Scalar implementations for benchmarking */
float qihse_distance_cosine_scalar(const float* a, const float* b, size_t dims);
float qihse_distance_dot_scalar(const float* a, const float* b, size_t dims);
float qihse_distance_euclidean_scalar(const float* a, const float* b, size_t dims);

#ifdef __cplusplus
}
#endif

#endif /* QIHSE_CPU_DISTANCE_H */
