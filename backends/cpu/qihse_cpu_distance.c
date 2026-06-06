/*
 * QIHSE - CPU Distance Function Dispatch
 *
 * Runtime selection of the best distance function implementation
 * based on CPU feature detection. Supports AVX2+FMA and scalar fallback.
 * AVX-512 is intentionally excluded — we target AVX2 as the high-water mark.
 */

#include "qihse_cpu_distance.h"
#include "qihse_cpu_detect.h"
#include <pthread.h>
#include <math.h>

#ifdef __x86_64__
#include <immintrin.h>
#endif

/* -------------------------------------------------------------------------- */
/* Scalar fallback implementations */
/* -------------------------------------------------------------------------- */
static float qihse_distance_dot_scalar(const float* a, const float* b, size_t dims) {
    float sum = 0.0f;
    for (size_t i = 0; i < dims; i++) {
        sum += a[i] * b[i];
    }
    return sum;
}

static float qihse_distance_cosine_scalar(const float* a, const float* b, size_t dims) {
    float dot = 0.0f, na = 0.0f, nb = 0.0f;
    for (size_t i = 0; i < dims; i++) {
        dot += a[i] * b[i];
        na  += a[i] * a[i];
        nb  += b[i] * b[i];
    }
    if (na <= 0.0f || nb <= 0.0f) return 0.0f;
    return dot / (sqrtf(na) * sqrtf(nb));
}

static float qihse_distance_euclidean_scalar(const float* a, const float* b, size_t dims) {
    float sum = 0.0f;
    for (size_t i = 0; i < dims; i++) {
        float d = a[i] - b[i];
        sum += d * d;
    }
    return sqrtf(sum);
}

/* -------------------------------------------------------------------------- */
/* Horizontal sum helper for __m256 — AVX2+FMA target, pure SSE reduce       */
/* -------------------------------------------------------------------------- */
#ifdef __x86_64__
__attribute__((target("avx2,fma")))
static float hsum256(__m256 v) {
    /* Fold 8 lanes to 4 */
    __m128 lo  = _mm256_castps256_ps128(v);
    __m128 hi  = _mm256_extractf128_ps(v, 1);
    __m128 s4  = _mm_add_ps(lo, hi);
    /* Fold 4 lanes to 2 using shuffle (SSE, no SSSE3 needed) */
    __m128 t1  = _mm_movehl_ps(s4, s4);   /* high 2 -> low 2 */
    __m128 s2  = _mm_add_ps(s4, t1);
    /* Fold 2 lanes to 1 */
    __m128 t2  = _mm_shuffle_ps(s2, s2, 0x1);
    __m128 s1  = _mm_add_ss(s2, t2);
    return _mm_cvtss_f32(s1);
}
#endif

/* -------------------------------------------------------------------------- */
/* AVX2 + FMA implementations                                                 */
/* Compiled with per-function target attribute — no global -mavx2 needed.    */
/* -------------------------------------------------------------------------- */
#ifdef __x86_64__

__attribute__((target("avx2,fma")))
float qihse_distance_dot_avx2(const float* a, const float* b, size_t dims) {
    __m256 acc = _mm256_setzero_ps();
    size_t i = 0;
    for (; i + 8 <= dims; i += 8) {
        __m256 va = _mm256_loadu_ps(a + i);
        __m256 vb = _mm256_loadu_ps(b + i);
        acc = _mm256_fmadd_ps(va, vb, acc);
    }
    float result = hsum256(acc);
    for (; i < dims; i++) result += a[i] * b[i];
    return result;
}

__attribute__((target("avx2,fma")))
float qihse_distance_cosine_avx2(const float* a, const float* b, size_t dims) {
    __m256 acc_dot = _mm256_setzero_ps();
    __m256 acc_na  = _mm256_setzero_ps();
    __m256 acc_nb  = _mm256_setzero_ps();
    size_t i = 0;
    for (; i + 8 <= dims; i += 8) {
        __m256 va = _mm256_loadu_ps(a + i);
        __m256 vb = _mm256_loadu_ps(b + i);
        acc_dot = _mm256_fmadd_ps(va, vb, acc_dot);
        acc_na  = _mm256_fmadd_ps(va, va, acc_na);
        acc_nb  = _mm256_fmadd_ps(vb, vb, acc_nb);
    }
    float dot = hsum256(acc_dot), na = hsum256(acc_na), nb = hsum256(acc_nb);
    for (; i < dims; i++) {
        dot += a[i] * b[i];
        na  += a[i] * a[i];
        nb  += b[i] * b[i];
    }
    if (na <= 0.0f || nb <= 0.0f) return 0.0f;
    return dot / (sqrtf(na) * sqrtf(nb));
}

__attribute__((target("avx2,fma")))
float qihse_distance_euclidean_avx2(const float* a, const float* b, size_t dims) {
    __m256 acc = _mm256_setzero_ps();
    size_t i = 0;
    for (; i + 8 <= dims; i += 8) {
        __m256 va   = _mm256_loadu_ps(a + i);
        __m256 vb   = _mm256_loadu_ps(b + i);
        __m256 diff = _mm256_sub_ps(va, vb);
        acc = _mm256_fmadd_ps(diff, diff, acc);
    }
    float result = hsum256(acc);
    for (; i < dims; i++) {
        float d = a[i] - b[i];
        result += d * d;
    }
    return sqrtf(result);
}

#else /* !__x86_64__ — portable fallbacks exported as symbols */

float qihse_distance_dot_avx2(const float* a, const float* b, size_t dims) {
    return qihse_distance_dot_scalar(a, b, dims);
}
float qihse_distance_cosine_avx2(const float* a, const float* b, size_t dims) {
    return qihse_distance_cosine_scalar(a, b, dims);
}
float qihse_distance_euclidean_avx2(const float* a, const float* b, size_t dims) {
    return qihse_distance_euclidean_scalar(a, b, dims);
}

#endif /* __x86_64__ */

/* -------------------------------------------------------------------------- */
/* Dispatch table — populated once at first call via pthread_once             */
/* -------------------------------------------------------------------------- */
static qihse_distance_fn_t g_cosine_fn    = NULL;
static qihse_distance_fn_t g_dot_fn       = NULL;
static qihse_distance_fn_t g_euclidean_fn = NULL;
static pthread_once_t g_init_once = PTHREAD_ONCE_INIT;

static void qihse_distance_init_once(void) {
    qihse_cpu_info_t info = qihse_cpu_detect();

    if (qihse_cpu_has_feature(&info, QIHSE_CPU_FEATURE_AVX2) &&
        qihse_cpu_has_feature(&info, QIHSE_CPU_FEATURE_AVX)) {
        /* AVX2 + FMA path — fastest available without AVX-512 */
        g_cosine_fn    = qihse_distance_cosine_avx2;
        g_dot_fn       = qihse_distance_dot_avx2;
        g_euclidean_fn = qihse_distance_euclidean_avx2;
    } else {
        /* Scalar fallback — safe on any architecture */
        g_cosine_fn    = qihse_distance_cosine_scalar;
        g_dot_fn       = qihse_distance_dot_scalar;
        g_euclidean_fn = qihse_distance_euclidean_scalar;
    }
}

/* -------------------------------------------------------------------------- */
/* Public API */
/* -------------------------------------------------------------------------- */
float qihse_distance_cosine(const float* a, const float* b, size_t dims) {
    pthread_once(&g_init_once, qihse_distance_init_once);
    return g_cosine_fn(a, b, dims);
}

float qihse_distance_dot(const float* a, const float* b, size_t dims) {
    pthread_once(&g_init_once, qihse_distance_init_once);
    return g_dot_fn(a, b, dims);
}

float qihse_distance_euclidean(const float* a, const float* b, size_t dims) {
    pthread_once(&g_init_once, qihse_distance_init_once);
    return g_euclidean_fn(a, b, dims);
}
