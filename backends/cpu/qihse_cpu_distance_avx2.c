/*
 * QIHSE - AVX2 Distance Functions
 *
 * AVX2-accelerated cosine similarity, dot product, and euclidean distance.
 * Processes 8 floats per instruction. Falls back to scalar for tail elements.
 */

#include "qihse_cpu_distance.h"
#include <immintrin.h>
#include <math.h>

/* Helper: horizontal sum of 8 floats in __m256 */
static inline float qihse_avx2_hsum(__m256 v) {
    __m128 vlow  = _mm256_castps256_ps128(v);
    __m128 vhigh = _mm256_extractf128_ps(v, 1);
    vlow  = _mm_add_ps(vlow, vhigh);
    vlow  = _mm_hadd_ps(vlow, vlow);
    vlow  = _mm_hadd_ps(vlow, vlow);
    return _mm_cvtss_f32(vlow);
}

float qihse_distance_dot_avx2(const float* a, const float* b, size_t dims) {
    __m256 sum = _mm256_setzero_ps();
    size_t i = 0;

    /* Main loop: 8 floats at a time */
    for (; i + 8 <= dims; i += 8) {
        __m256 va = _mm256_loadu_ps(a + i);
        __m256 vb = _mm256_loadu_ps(b + i);
        sum = _mm256_fmadd_ps(va, vb, sum);
    }

    float result = qihse_avx2_hsum(sum);

    /* Tail: scalar fallback */
    for (; i < dims; i++) {
        result += a[i] * b[i];
    }

    return result;
}

float qihse_distance_cosine_avx2(const float* a, const float* b, size_t dims) {
    __m256 dot_acc = _mm256_setzero_ps();
    __m256 na_acc  = _mm256_setzero_ps();
    __m256 nb_acc  = _mm256_setzero_ps();
    size_t i = 0;

    for (; i + 8 <= dims; i += 8) {
        __m256 va = _mm256_loadu_ps(a + i);
        __m256 vb = _mm256_loadu_ps(b + i);
        dot_acc = _mm256_fmadd_ps(va, vb, dot_acc);
        na_acc  = _mm256_fmadd_ps(va, va, na_acc);
        nb_acc  = _mm256_fmadd_ps(vb, vb, nb_acc);
    }

    float dot = qihse_avx2_hsum(dot_acc);
    float na  = qihse_avx2_hsum(na_acc);
    float nb  = qihse_avx2_hsum(nb_acc);

    for (; i < dims; i++) {
        dot += a[i] * b[i];
        na  += a[i] * a[i];
        nb  += b[i] * b[i];
    }

    if (na <= 0.0f || nb <= 0.0f) {
        return 0.0f;
    }
    return dot / (sqrtf(na) * sqrtf(nb));
}

float qihse_distance_euclidean_avx2(const float* a, const float* b, size_t dims) {
    __m256 sum = _mm256_setzero_ps();
    size_t i = 0;

    for (; i + 8 <= dims; i += 8) {
        __m256 va = _mm256_loadu_ps(a + i);
        __m256 vb = _mm256_loadu_ps(b + i);
        __m256 diff = _mm256_sub_ps(va, vb);
        sum = _mm256_fmadd_ps(diff, diff, sum);
    }

    float result = qihse_avx2_hsum(sum);

    for (; i < dims; i++) {
        float diff = a[i] - b[i];
        result += diff * diff;
    }

    return sqrtf(result);
}
