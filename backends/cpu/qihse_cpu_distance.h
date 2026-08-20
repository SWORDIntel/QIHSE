/*
 * QIHSE - CPU SIMD Distance Functions
 *
 * Runtime-dispatched SIMD-accelerated vector distance computations.
 * Auto-selects AVX-512, AVX2, AVX1, or scalar fallback based on CPU features.
 */

#ifndef QIHSE_CPU_DISTANCE_H
#define QIHSE_CPU_DISTANCE_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Distance function signatures */
typedef float (*qihse_distance_fn_t)(const float* a, const float* b, size_t dims);

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
