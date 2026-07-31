/*
 * QIHSE - CPU Distance Function Dispatch
 *
 * Runtime selection of the best distance function implementation
 * based on CPU feature detection. Supports AVX-512+FMA, AVX2+FMA, and scalar.
 * AVX-512 path processes 16 floats per instruction with 2x unrolling for ILP.
 */

#include "qihse_cpu_distance.h"
#include "qihse_cpu_detect.h"
#include <pthread.h>
#include <math.h>

#ifdef __x86_64__
#include <immintrin.h>
#endif

/* -------------------------------------------------------------------------- */
/* Scalar fallback implementations (exported for benchmarking) */
/* -------------------------------------------------------------------------- */
float qihse_distance_dot_scalar(const float* a, const float* b, size_t dims) {
    float sum = 0.0f;
    for (size_t i = 0; i < dims; i++) {
        sum += a[i] * b[i];
    }
    return sum;
}

float qihse_distance_cosine_scalar(const float* a, const float* b, size_t dims) {
    float dot = 0.0f, na = 0.0f, nb = 0.0f;
    for (size_t i = 0; i < dims; i++) {
        dot += a[i] * b[i];
        na  += a[i] * a[i];
        nb  += b[i] * b[i];
    }
    if (na <= 0.0f || nb <= 0.0f) return 0.0f;
    return dot / (sqrtf(na) * sqrtf(nb));
}

float qihse_distance_euclidean_scalar(const float* a, const float* b, size_t dims) {
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

/* -------------------------------------------------------------------------- */
/* Horizontal sum helper for __m512 — AVX-512 reduce                          */
/* -------------------------------------------------------------------------- */
__attribute__((target("avx512f,avx512dq")))
static float hsum512(__m512 v) {
    /* Reduce 512→256 using extract + add */
    __m256 lo = _mm512_castps512_ps256(v);
    __m256 hi = _mm512_extractf32x8_ps(v, 1);
    __m256 s256 = _mm256_add_ps(lo, hi);
    /* Reuse AVX2 hsum for the 256-bit remainder */
    return hsum256(s256);
}

/* -------------------------------------------------------------------------- */
/* AVX-512 + FMA implementations                                              */
/* 16 floats per iteration, 2x unrolled for independent accumulator chains.   */
/* Compiled with per-function target attribute — no global -mavx512f needed.  */
/* -------------------------------------------------------------------------- */

__attribute__((target("avx512f,fma")))
float qihse_distance_dot_avx512(const float* a, const float* b, size_t dims) {
    /* Two independent accumulators for better pipeline utilization */
    __m512 acc0 = _mm512_setzero_ps();
    __m512 acc1 = _mm512_setzero_ps();
    size_t i = 0;
    /* Main loop: 32 floats per iteration (2x unrolled, 16 each) */
    for (; i + 32 <= dims; i += 32) {
        __m512 va0 = _mm512_loadu_ps(a + i);
        __m512 vb0 = _mm512_loadu_ps(b + i);
        __m512 va1 = _mm512_loadu_ps(a + i + 16);
        __m512 vb1 = _mm512_loadu_ps(b + i + 16);
        acc0 = _mm512_fmadd_ps(va0, vb0, acc0);
        acc1 = _mm512_fmadd_ps(va1, vb1, acc1);
    }
    /* Handle remaining 16-float chunk */
    for (; i + 16 <= dims; i += 16) {
        __m512 va = _mm512_loadu_ps(a + i);
        __m512 vb = _mm512_loadu_ps(b + i);
        acc0 = _mm512_fmadd_ps(va, vb, acc0);
    }
    /* Merge accumulators */
    __m512 acc = _mm512_add_ps(acc0, acc1);
    float result = hsum512(acc);
    /* Tail: scalar fallback */
    for (; i < dims; i++) result += a[i] * b[i];
    return result;
}

__attribute__((target("avx512f,fma")))
float qihse_distance_cosine_avx512(const float* a, const float* b, size_t dims) {
    __m512 dot0 = _mm512_setzero_ps(), dot1 = _mm512_setzero_ps();
    __m512 na0  = _mm512_setzero_ps(), na1  = _mm512_setzero_ps();
    __m512 nb0  = _mm512_setzero_ps(), nb1  = _mm512_setzero_ps();
    size_t i = 0;
    for (; i + 32 <= dims; i += 32) {
        __m512 va0 = _mm512_loadu_ps(a + i);
        __m512 vb0 = _mm512_loadu_ps(b + i);
        __m512 va1 = _mm512_loadu_ps(a + i + 16);
        __m512 vb1 = _mm512_loadu_ps(b + i + 16);
        dot0 = _mm512_fmadd_ps(va0, vb0, dot0);
        na0  = _mm512_fmadd_ps(va0, va0, na0);
        nb0  = _mm512_fmadd_ps(vb0, vb0, nb0);
        dot1 = _mm512_fmadd_ps(va1, vb1, dot1);
        na1  = _mm512_fmadd_ps(va1, va1, na1);
        nb1  = _mm512_fmadd_ps(vb1, vb1, nb1);
    }
    for (; i + 16 <= dims; i += 16) {
        __m512 va = _mm512_loadu_ps(a + i);
        __m512 vb = _mm512_loadu_ps(b + i);
        dot0 = _mm512_fmadd_ps(va, vb, dot0);
        na0  = _mm512_fmadd_ps(va, va, na0);
        nb0  = _mm512_fmadd_ps(vb, vb, nb0);
    }
    __m512 dot = _mm512_add_ps(dot0, dot1);
    __m512 na  = _mm512_add_ps(na0, na1);
    __m512 nb  = _mm512_add_ps(nb0, nb1);
    float d = hsum512(dot), na_v = hsum512(na), nb_v = hsum512(nb);
    for (; i < dims; i++) {
        d    += a[i] * b[i];
        na_v += a[i] * a[i];
        nb_v += b[i] * b[i];
    }
    if (na_v <= 0.0f || nb_v <= 0.0f) return 0.0f;
    return d / (sqrtf(na_v) * sqrtf(nb_v));
}

__attribute__((target("avx512f,fma")))
float qihse_distance_euclidean_avx512(const float* a, const float* b, size_t dims) {
    __m512 acc0 = _mm512_setzero_ps();
    __m512 acc1 = _mm512_setzero_ps();
    size_t i = 0;
    for (; i + 32 <= dims; i += 32) {
        __m512 va0 = _mm512_loadu_ps(a + i);
        __m512 vb0 = _mm512_loadu_ps(b + i);
        __m512 va1 = _mm512_loadu_ps(a + i + 16);
        __m512 vb1 = _mm512_loadu_ps(b + i + 16);
        __m512 diff0 = _mm512_sub_ps(va0, vb0);
        __m512 diff1 = _mm512_sub_ps(va1, vb1);
        acc0 = _mm512_fmadd_ps(diff0, diff0, acc0);
        acc1 = _mm512_fmadd_ps(diff1, diff1, acc1);
    }
    for (; i + 16 <= dims; i += 16) {
        __m512 va = _mm512_loadu_ps(a + i);
        __m512 vb = _mm512_loadu_ps(b + i);
        __m512 diff = _mm512_sub_ps(va, vb);
        acc0 = _mm512_fmadd_ps(diff, diff, acc0);
    }
    __m512 acc = _mm512_add_ps(acc0, acc1);
    float result = hsum512(acc);
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

/* AVX-512 stubs for non-x86 platforms */
float qihse_distance_cosine_avx512(const float* a, const float* b, size_t dims) {
    return qihse_distance_cosine_scalar(a, b, dims);
}
float qihse_distance_dot_avx512(const float* a, const float* b, size_t dims) {
    return qihse_distance_dot_scalar(a, b, dims);
}
float qihse_distance_euclidean_avx512(const float* a, const float* b, size_t dims) {
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

    if (qihse_cpu_has_feature(&info, QIHSE_CPU_FEATURE_AVX512F)) {
        /* AVX-512 + FMA path — 16 floats per instruction, 2x unrolled.
         * FMA is implied on all AVX-512 capable CPUs (Skylake-X+). */
        g_cosine_fn    = qihse_distance_cosine_avx512;
        g_dot_fn       = qihse_distance_dot_avx512;
        g_euclidean_fn = qihse_distance_euclidean_avx512;
    } else if (qihse_cpu_has_feature(&info, QIHSE_CPU_FEATURE_AVX2) &&
               qihse_cpu_has_feature(&info, QIHSE_CPU_FEATURE_AVX)) {
        /* AVX2 + FMA path — 8 floats per instruction */
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
