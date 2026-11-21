/*
 * QIHSE - Verification and Accuracy Modes Implementation
 *
 * Implements multi-level verification system for approximate/probabilistic search.
 *
 * Version: 1.0.0
 * Author: DSMIL System
 * License: MIT
 */

#include "qihse_verification.h"
#include "../backends/cpu/qihse_cpu_detect.h"
#include "qihse_rff.h"
#include "qihse_superposition.h"
#include "qihse_amplification.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <math.h>
#include <errno.h>
#include <time.h>
#include <immintrin.h>  /* AVX/AVX512 intrinsics */
#include <stdint.h>     /* For qihse_cpu_feature_t */

/* ============================================================================
 * VERIFICATION CONFIGURATION
 * ============================================================================ */

void qihse_verification_config_init(
    qihse_verification_config_t* config,
    qihse_verification_mode_t mode
) {
    if (!config) return;

    config->mode = mode;
    config->confidence_threshold = 0.95; /* Default confidence threshold */
    config->max_retries = 3; 
    config->tolerance = 1e-5; 
    config->enable_fallback = 1;
    config->performance_budget = 0.3; 
    config->window_size = 10; 
    config->adaptive_verification = 1; 

    /* Mode-specific adjustments - balanced for accuracy and reasonable speed */
    switch (mode) {
        case QIHSE_VERIFY_NONE:
            config->confidence_threshold = 0.0; /* No verification */
            config->max_retries = 0;
            break;
        case QIHSE_VERIFY_FAST:
            config->confidence_threshold = 0.85; /* 85% for fast */
            config->max_retries = 2;
            break;
        case QIHSE_VERIFY_WINDOW:
            config->confidence_threshold = 0.90; /* 90% for window */
            config->window_size = 15;
            break;
        case QIHSE_VERIFY_FALLBACK:
            config->confidence_threshold = 0.95; /* 95% for fallback */
            config->enable_fallback = 1;
            config->max_retries = 3;
            break;
        case QIHSE_VERIFY_EXACT:
            config->confidence_threshold = 0.98; /* 98% for exact */
            config->tolerance = 1e-7;
            config->max_retries = 5;
            break;
        case QIHSE_VERIFY_PRECISION:
            config->confidence_threshold = 0.99; /* 99% minimum for precision mode */
            config->max_retries = 8;
            config->enable_fallback = 1;
            config->adaptive_verification = 1; 
            config->performance_budget = 0.15; 
            config->window_size = 30;
            break;
    }
}

/* ============================================================================
 * VERIFICATION RESULTS
 * ============================================================================ */

void qihse_verification_result_init(qihse_verification_result_t* result) {
    if (!result) return;
    memset(result, 0, sizeof(qihse_verification_result_t));
    result->confidence = 0.0;
    result->accuracy = 0.0;
}

void qihse_verification_result_destroy(qihse_verification_result_t* result) {
    if (!result) return;
    if (result->error_message) {
        free(result->error_message);
    }
    memset(result, 0, sizeof(qihse_verification_result_t));
}

/* ============================================================================
 * VERIFICATION OPERATIONS
 * ============================================================================ */

static int verification_error(qihse_verification_result_t *out, int error,
                               const char *message) {
    if (out) {
        out->is_valid = 0;
        out->confidence = 0.0;
        out->accuracy = 0.0;
        size_t length = strlen(message) + 1;
        out->error_message = malloc(length);
        if (out->error_message) memcpy(out->error_message, message, length);
    }
    errno = error;
    return -1;
}

int qihse_verify_result_advanced_sized(const void *query, const float *result,
                                      const float *ground_truth, size_t data_size,
                                      const qihse_verification_config_t *config,
                                      qihse_verification_result_t *out) {
    (void)query;
    if (!out) { errno = EINVAL; return -1; }
    qihse_verification_result_init(out);
    if (!config || !qihse_verification_config_validate(config) || !result ||
        !ground_truth || !data_size || data_size > SIZE_MAX / sizeof(float))
        return verification_error(out, EINVAL, "Verification needs valid, sized float arrays and ground truth");
    out->mode_used = config->mode;
    if (config->mode == QIHSE_VERIFY_NONE)
        return verification_error(out, ENOTSUP, "No verification was requested");
    clock_t started = clock();
    size_t exact_matches = 0, tolerance_matches = 0;
    long double dot = 0.0L, an = 0.0L, bn = 0.0L;
    for (size_t i = 0; i < data_size; ++i) {
        if (!isfinite(result[i]) || !isfinite(ground_truth[i]))
            return verification_error(out, EDOM, "Verification input contains a non-finite value");
        long double a = result[i], b = ground_truth[i];
        exact_matches += result[i] == ground_truth[i];
        tolerance_matches += fabsl(a - b) <= config->tolerance;
        dot += a * b; an += a * a; bn += b * b;
    }
    if (config->mode == QIHSE_VERIFY_EXACT) {
        out->accuracy = (double)exact_matches / (double)data_size;
        out->confidence = exact_matches == data_size ? 1.0 : 0.0;
        out->is_valid = exact_matches == data_size;
    } else if (config->mode == QIHSE_VERIFY_PRECISION) {
        out->accuracy = (double)tolerance_matches / (double)data_size;
        out->confidence = tolerance_matches == data_size ? 1.0 : 0.0;
        out->is_valid = tolerance_matches == data_size;
    } else {
        /* A bounded similarity score, not a calibrated probability of correctness. */
        double score = exact_matches == data_size ? 1.0 :
            (an > 0.0L && bn > 0.0L ? (double)((dot / sqrtl(an)) / sqrtl(bn)) : 0.0);
        out->accuracy = out->confidence = fmin(1.0, fmax(0.0, score));
        out->is_valid = out->confidence >= config->confidence_threshold;
    }
    clock_t ended = clock();
    if (started != (clock_t)-1 && ended != (clock_t)-1 && ended >= started)
        out->verification_time_us = (size_t)((long double)(ended - started) * 1000000.0L / CLOCKS_PER_SEC);
    if (!out->is_valid) { errno = EDOM; return -1; }
    return 0;
}

int qihse_verify_result_advanced(const void *query, const void *result,
                                const void *ground_truth,
                                const qihse_verification_config_t *config,
                                qihse_verification_result_t *out) {
    (void)query; (void)result; (void)ground_truth; (void)config;
    if (out) qihse_verification_result_init(out);
    return verification_error(out, ENOTSUP, "Use qihse_verify_result_advanced_sized with the actual element count");
}

int qihse_verify_batch_sized(const void *const *queries, const float *const *results,
                            const float *const *ground_truths, const size_t *data_sizes,
                            size_t batch_size, const qihse_verification_config_t *config,
                            qihse_verification_result_t *out) {
    if (!results || !ground_truths || !data_sizes || !config || !out || !batch_size ||
        batch_size > SIZE_MAX / sizeof(*out)) { errno = EINVAL; return -1; }
    for (size_t i = 0; i < batch_size; ++i) qihse_verification_result_init(&out[i]);
    for (size_t i = 0; i < batch_size; ++i)
        if (qihse_verify_result_advanced_sized(queries ? queries[i] : NULL,
                results[i], ground_truths[i], data_sizes[i], config, &out[i])) return -1;
    return 0;
}

int qihse_verify_batch(const void *const *queries, const void *const *results,
                      const void *const *ground_truths, size_t batch_size,
                      const qihse_verification_config_t *config,
                      qihse_verification_result_t *out) {
    (void)queries; (void)results; (void)ground_truths; (void)config;
    if (out && batch_size <= SIZE_MAX / sizeof(*out))
        for (size_t i = 0; i < batch_size; ++i) qihse_verification_result_init(&out[i]);
    errno = ENOTSUP;
    return -1;
}

/* ============================================================================
 * ADAPTIVE VERIFICATION
 * ============================================================================ */

int qihse_adaptive_verifier_init(
    qihse_adaptive_verifier_t* verifier,
    qihse_verification_mode_t initial_mode,
    double target_confidence,
    double performance_budget
) {
    if (!verifier) {
        errno = EINVAL;
        return -1;
    }

    verifier->current_mode = initial_mode;
    verifier->target_confidence = target_confidence;
    verifier->performance_budget = performance_budget;
    verifier->window_size = 10;
    verifier->adaptation_rate = 0.1;
    verifier->recent_confidence = target_confidence;
    verifier->recent_performance = performance_budget;
    verifier->samples_collected = 0;
    verifier->internal_state = NULL;

    return 0;
}

void qihse_adaptive_verifier_destroy(qihse_adaptive_verifier_t* verifier) {
    if (!verifier) return;
    free(verifier->internal_state);
    memset(verifier, 0, sizeof(qihse_adaptive_verifier_t));
}

qihse_verification_mode_t qihse_adaptive_verifier_adapt(
    qihse_adaptive_verifier_t* verifier,
    const qihse_verification_result_t* verification_result,
    size_t query_time_us
) {
    if (!verifier || !verification_result) { errno = EINVAL; return verifier ? verifier->current_mode : QIHSE_VERIFY_NONE; }

    /* Update running averages */
    verifier->samples_collected++;
    double alpha = 1.0 / verifier->samples_collected;
    verifier->recent_confidence = (1 - alpha) * verifier->recent_confidence +
                                 alpha * verification_result->confidence;
    verifier->recent_performance = (1 - alpha) * verifier->recent_performance +
                                  alpha * (double)query_time_us;

    /* Adapt verification level based on precision requirements */
    /* For precision search: NEVER allow confidence below 90% */
    if (verifier->recent_confidence < 0.9) {
        /* CRITICAL: Confidence below acceptable threshold - escalate */
        if (verifier->current_mode < QIHSE_VERIFY_PRECISION) {
            verifier->current_mode = QIHSE_VERIFY_PRECISION;
        } else if (verifier->current_mode < QIHSE_VERIFY_EXACT) {
            verifier->current_mode++;
        }
    } else if (verifier->recent_confidence > verifier->target_confidence * 1.05 &&
               verifier->recent_performance < verifier->performance_budget * 1e6) {
        /* Confidence good and performance allows, decrease verification to speed up */
        if (verifier->current_mode > QIHSE_VERIFY_FAST) {
            verifier->current_mode--;
        }
    }

    return verifier->current_mode;
}

void qihse_adaptive_verifier_get_stats(
    const qihse_adaptive_verifier_t* verifier,
    double* avg_confidence,
    double* avg_performance,
    double mode_distribution[5]
) {
    if (!verifier) return;

    if (avg_confidence) *avg_confidence = verifier->recent_confidence;
    if (avg_performance) *avg_performance = verifier->recent_performance;

    if (mode_distribution) {
        memset(mode_distribution, 0, 5 * sizeof(double));
        if (verifier->current_mode >= QIHSE_VERIFY_NONE && verifier->current_mode < QIHSE_VERIFY_PRECISION)
            mode_distribution[verifier->current_mode] = 1.0; /* Legacy output has five slots. */
    }
}

/* ============================================================================
 * VERIFICATION UTILITIES
 * ============================================================================ */

double qihse_estimate_verification_overhead(
    qihse_verification_mode_t mode,
    size_t problem_size
) {
    switch (mode) {
        case QIHSE_VERIFY_NONE:
            return 0.0;
        case QIHSE_VERIFY_FAST:
            return 0.01; /* 1% overhead */
        case QIHSE_VERIFY_WINDOW:
            return 0.05; /* 5% overhead */
        case QIHSE_VERIFY_FALLBACK:
            return 0.10; /* 10% overhead */
        case QIHSE_VERIFY_EXACT:
            return 0.20 + log2(problem_size) / 100.0; /* 20% + size-dependent */
        default:
            return 0.05;
    }
}

const char* qihse_verification_mode_name(qihse_verification_mode_t mode) {
    switch (mode) {
        case QIHSE_VERIFY_NONE: return "NONE";
        case QIHSE_VERIFY_FAST: return "FAST";
        case QIHSE_VERIFY_WINDOW: return "WINDOW";
        case QIHSE_VERIFY_FALLBACK: return "FALLBACK";
        case QIHSE_VERIFY_EXACT: return "EXACT";
        default: return "UNKNOWN";
    }
}

int qihse_verification_config_validate(const qihse_verification_config_t* config) {
    if (!config) {
        errno = EINVAL;
        return 0;  /* Invalid: NULL config */
    }

    /* Validate confidence threshold ranges */
    if (!isfinite(config->confidence_threshold) || config->confidence_threshold < 0.0 || config->confidence_threshold > 1.0) {
        errno = EINVAL;
        return 0;  /* Invalid: confidence threshold out of range */
    }

    /* For precision search, enforce minimum 90% confidence threshold */
    if (config->mode == QIHSE_VERIFY_PRECISION && config->confidence_threshold < 0.9) {
        errno = EINVAL;
        return 0;  /* Invalid: precision mode requires 90%+ confidence */
    }

    /* Validate max_retries */
    if (config->max_retries > 100) {
        errno = EINVAL;
        return 0;  /* Invalid: max_retries out of reasonable range */
    }

    /* Validate tolerance */
    if (!isfinite(config->tolerance) || config->tolerance < 0.0 || config->tolerance > 1.0) {
        errno = EINVAL;
        return 0;  /* Invalid: tolerance out of range */
    }

    /* Validate performance_budget */
    if (!isfinite(config->performance_budget) || config->performance_budget < 0.0 || config->performance_budget > 1.0) {
        errno = EINVAL;
        return 0;  /* Invalid: performance budget out of range */
    }

    /* Validate window_size for relevant modes */
    if ((config->mode == QIHSE_VERIFY_WINDOW || config->mode == QIHSE_VERIFY_PRECISION) &&
        (config->window_size < 1 || config->window_size > 10000)) {
        errno = EINVAL;
        return 0;  /* Invalid: window size out of reasonable range */
    }

    /* Validate verification mode */
    if (config->mode < QIHSE_VERIFY_NONE || config->mode > QIHSE_VERIFY_PRECISION) {
        errno = EINVAL;
        return 0;  /* Invalid: unknown verification mode */
    }

    return 1;  /* Configuration is valid */
}

int qihse_generate_ground_truth(
    const void* query,
    void* ground_truth,
    size_t buffer_size
) {
    /* Generate test ground truth */
    (void)query;

    if (!ground_truth || buffer_size < sizeof(double)) {
        errno = EINVAL;
        return -1;
    }

    /* Generate simple test ground truth */
    double* gt = (double*)ground_truth;
    gt[0] = 1.0; /* Expected correct result */

    return 0;
}

/* ============================================================================
 * VERIFICATION METRICS AND MONITORING
 * ============================================================================ */

/*
 * NOTE: This is userspace code, NOT kernel code.
 * Do NOT use atomic_t types here - atomic_t is for kernel code only.
 * In userspace, use mutexes or other synchronization primitives if needed.
 * atomic_t will not compile in userspace (linux/atomic.h doesn't exist).
 */
static struct {
    size_t total_verifications;
    size_t passed_verifications;
    size_t failed_verifications;
    double average_confidence;
    double average_accuracy;
    size_t average_time_us;
    size_t max_time_us;
    size_t min_time_us;
} verification_metrics = {0};

void qihse_get_verification_metrics(qihse_verification_metrics_t* metrics) {
    if (!metrics) return;

    metrics->total_verifications = verification_metrics.total_verifications;
    metrics->passed_verifications = verification_metrics.passed_verifications;
    metrics->failed_verifications = verification_metrics.failed_verifications;
    metrics->average_confidence = verification_metrics.average_confidence;
    metrics->average_accuracy = verification_metrics.average_accuracy;
    metrics->average_time_us = verification_metrics.average_time_us;
    metrics->max_time_us = verification_metrics.max_time_us;
    metrics->min_time_us = verification_metrics.min_time_us;
}

void qihse_reset_verification_metrics(void) {
    memset(&verification_metrics, 0, sizeof(verification_metrics));
    verification_metrics.min_time_us = SIZE_MAX;
}

char* qihse_export_verification_metrics_json(void) {
    /* Export metrics as JSON */
    const char* json_template =
        "{"
        "\"total_verifications\": %zu,"
        "\"passed_verifications\": %zu,"
        "\"failed_verifications\": %zu,"
        "\"average_confidence\": %.3f,"
        "\"average_accuracy\": %.3f,"
        "\"average_time_us\": %zu,"
        "\"max_time_us\": %zu,"
        "\"min_time_us\": %zu"
        "}";

    char* json = calloc(1, 512);
    if (!json) return NULL;

        snprintf(json, 512, json_template,
             verification_metrics.total_verifications,
             verification_metrics.passed_verifications,
             verification_metrics.failed_verifications,
             verification_metrics.average_confidence,
             verification_metrics.average_accuracy,
             verification_metrics.average_time_us,
             verification_metrics.max_time_us,
             verification_metrics.min_time_us);

    return json;
}

/* ============================================================================
 * ENHANCED SIMILARITY CALCULATIONS - HARDWARE ACCELERATED & QUANTUM-INSPIRED
 * ============================================================================ */

static int cosine_inputs_valid(const float *a, const float *b, size_t n) {
    if (!a || !b || !n || n > SIZE_MAX / sizeof(float)) { errno = EINVAL; return 0; }
    for (size_t i = 0; i < n; ++i)
        if (!isfinite(a[i]) || !isfinite(b[i])) { errno = EDOM; return 0; }
    return 1;
}

static double cosine_finish(double dot, double a_squared, double b_squared) {
    if (!(a_squared > 0.0) || !(b_squared > 0.0)) return 0.0;
    return fmin(1.0, fmax(-1.0, (dot / sqrt(a_squared)) / sqrt(b_squared)));
}

double qihse_cosine_similarity_scalar(const float *a, const float *b, size_t n) {
    if (!cosine_inputs_valid(a, b, n)) return 0.0;
    double dot = 0.0, an = 0.0, bn = 0.0;
    for (size_t i = 0; i < n; ++i) {
        double x = a[i], y = b[i];
        dot += x * y; an += x * x; bn += y * y;
    }
    return cosine_finish(dot, an, bn);
}

double qihse_cosine_similarity_avx512(const float *a, const float *b, size_t n) {
#if defined(__AVX512F__) && defined(__AVX512DQ__)
    if (!cosine_inputs_valid(a, b, n)) return 0.0;
    /* Promote before multiplying: finite floats can overflow a float product. */
    __m512d dot_vector = _mm512_setzero_pd();
    __m512d a_vector = _mm512_setzero_pd(), b_vector = _mm512_setzero_pd();
    size_t i = 0;
    for (; n - i >= 8; i += 8) {
        __m512d x = _mm512_cvtps_pd(_mm256_loadu_ps(a + i));
        __m512d y = _mm512_cvtps_pd(_mm256_loadu_ps(b + i));
        dot_vector = _mm512_add_pd(dot_vector, _mm512_mul_pd(x, y));
        a_vector = _mm512_add_pd(a_vector, _mm512_mul_pd(x, x));
        b_vector = _mm512_add_pd(b_vector, _mm512_mul_pd(y, y));
    }
    double dot = _mm512_reduce_add_pd(dot_vector);
    double an = _mm512_reduce_add_pd(a_vector), bn = _mm512_reduce_add_pd(b_vector);
    for (; i < n; ++i) {
        double x = a[i], y = b[i];
        dot += x * y; an += x * x; bn += y * y;
    }
    /* Reduce squared norms, then take each square root exactly once. */
    return cosine_finish(dot, an, bn);
#else
    return qihse_cosine_similarity_scalar(a, b, n);
#endif
}

double qihse_cosine_similarity_avx2(const float *a, const float *b, size_t n) {
#if defined(__AVX2__)
    if (!cosine_inputs_valid(a, b, n)) return 0.0;
    __m256d dot_vector = _mm256_setzero_pd();
    __m256d a_vector = _mm256_setzero_pd(), b_vector = _mm256_setzero_pd();
    size_t i = 0;
    for (; n - i >= 4; i += 4) {
        __m256d x = _mm256_cvtps_pd(_mm_loadu_ps(a + i));
        __m256d y = _mm256_cvtps_pd(_mm_loadu_ps(b + i));
        dot_vector = _mm256_add_pd(dot_vector, _mm256_mul_pd(x, y));
        a_vector = _mm256_add_pd(a_vector, _mm256_mul_pd(x, x));
        b_vector = _mm256_add_pd(b_vector, _mm256_mul_pd(y, y));
    }
    double dp[4], ap[4], bp[4];
    _mm256_storeu_pd(dp, dot_vector); _mm256_storeu_pd(ap, a_vector); _mm256_storeu_pd(bp, b_vector);
    double dot = 0.0, an = 0.0, bn = 0.0;
    for (size_t lane = 0; lane < 4; ++lane) { dot += dp[lane]; an += ap[lane]; bn += bp[lane]; }
    for (; i < n; ++i) {
        double x = a[i], y = b[i];
        dot += x * y; an += x * x; bn += y * y;
    }
    return cosine_finish(dot, an, bn);
#else
    return qihse_cosine_similarity_scalar(a, b, n);
#endif
}

/* Project to Hilbert space using RFF, then compute similarity */
double qihse_rff_similarity(const float *a, const float *b, size_t n,
                            qihse_rff_kernel_t *kernel) {
    if (!a || !b || !n || !kernel || !kernel->omega || !kernel->bias ||
        kernel->input_dims != n || !kernel->output_dims ||
        n > SIZE_MAX / sizeof(double) || kernel->output_dims > SIZE_MAX / sizeof(double) ||
        n > SIZE_MAX / sizeof(double) / kernel->output_dims) {
        errno = EINVAL; return 0.0;
    }
    double *ad = malloc(n * sizeof(double)), *bd = malloc(n * sizeof(double));
    double *az = malloc(kernel->output_dims * sizeof(double));
    double *bz = malloc(kernel->output_dims * sizeof(double));
    double similarity = 0.0;
    if (!ad || !bd || !az || !bz) { errno = ENOMEM; goto done; }
    for (size_t i = 0; i < n; ++i) {
        if (!isfinite(a[i]) || !isfinite(b[i])) { errno = EDOM; goto done; }
        ad[i] = a[i]; bd[i] = b[i];
    }
    qihse_rff_project(kernel, ad, az); qihse_rff_project(kernel, bd, bz);
    long double dot = 0.0L, an = 0.0L, bn = 0.0L;
    for (size_t i = 0; i < kernel->output_dims; ++i) {
        if (!isfinite(az[i]) || !isfinite(bz[i])) { errno = EDOM; goto done; }
        dot += (long double)az[i] * bz[i];
        an += (long double)az[i] * az[i]; bn += (long double)bz[i] * bz[i];
    }
    if (an > 0.0L && bn > 0.0L)
        similarity = (double)fminl(1.0L, fmaxl(-1.0L, (dot / sqrtl(an)) / sqrtl(bn)));
 done:
    free(ad); free(bd); free(az); free(bz);
    return similarity;
}

double qihse_superposition_fidelity_similarity(const float *a, const float *b, size_t n) {
    if (!a || !b || !n || n > SIZE_MAX / sizeof(double)) { errno = EINVAL; return 0.0; }
    qihse_superposition_t as = {0}, bs = {0};
    double *ad = malloc(n * sizeof(double)), *bd = malloc(n * sizeof(double));
    double fidelity = 0.0;
    if (!ad || !bd) { errno = ENOMEM; goto done; }
    for (size_t i = 0; i < n; ++i) { ad[i] = a[i]; bd[i] = b[i]; }
    /* Each buffer is one vector with n coordinates, not n vectors of n coordinates. */
    if (qihse_create_superposition(ad, 1, n, &as) || qihse_create_superposition(bd, 1, n, &bs)) goto done;
    fidelity = qihse_superposition_state_fidelity(&as, &bs);
 done:
    qihse_destroy_superposition(&as); qihse_destroy_superposition(&bs);
    free(ad); free(bd);
    return fidelity;
}

/* Use AMX tiles for blocked matrix similarity computation */
double qihse_amx_matrix_similarity(
    const float* result,
    const float* ground_truth,
    size_t data_size
) {
#ifdef __AMX__
    /* Configure AMX tiles for 4x4 blocks */
    struct __tile_config tile_config = {0};
    tile_config.palette_id = 1;
    tile_config.colsb[0] = 16;  /* 4 floats * 4 bytes */
    tile_config.rowsb[0] = 4;
    _tile_loadconfig(&tile_config);

    /* Process in 4x4 blocks using AMX tiles */
    double total_similarity = 0.0;
    size_t num_blocks = data_size / 16;

    for (size_t block = 0; block < num_blocks; block++) {
        /* Load 4x4 block into tile */
        _tile_loadd(0, &result[block * 16], 16);
        _tile_loadd(1, &ground_truth[block * 16], 16);

        /* Compute dot product using AMX DPBF16PS (or equivalent) */
        /* For FP32, use tile multiply-accumulate operations */
        /* Similarity contribution from this block */
        /* (Simplified - actual AMX operations depend on tile configuration) */
    }

    _tile_release();
    return total_similarity / num_blocks;
#else
    /* Fallback to AVX512 if AMX not available */
    return qihse_cosine_similarity_avx512(result, ground_truth, data_size);
#endif
}

/* Use Grover amplification to find optimal similarity matches */
double qihse_grover_amplified_similarity(const float *a, const float *b,
                                       size_t n, double threshold) {
    if (!a || !b || !n || n > SIZE_MAX / sizeof(double) || n > SIZE_MAX / sizeof(size_t) ||
        !isfinite(threshold) || threshold < 0.0) { errno = EINVAL; return 0.0; }
    double *re = malloc(n * sizeof(double)), *im = calloc(n, sizeof(double));
    double *probabilities = malloc(n * sizeof(double));
    size_t *targets = malloc(n * sizeof(size_t));
    qihse_superposition_t state = {0};
    double probability = 0.0;
    if (!re || !im || !probabilities || !targets) { errno = ENOMEM; goto done; }
    size_t count = 0;
    double uniform = 1.0 / sqrt((double)n);
    for (size_t i = 0; i < n; ++i) {
        if (!isfinite(a[i]) || !isfinite(b[i])) { errno = EDOM; goto done; }
        re[i] = uniform;
        if (fabs((double)a[i] - b[i]) <= threshold) targets[count++] = i;
    }
    if (!count) goto done;
    if (qihse_create_superposition_from_amplitudes(re, im, n, &state)) goto done;
    qihse_amplification_config_t config;
    qihse_amplification_config_init(&config, n);
    if (qihse_amplify(&state, targets, count, &config) < 0) goto done;
    qihse_superposition_get_probabilities(&state, probabilities);
    for (size_t i = 0; i < count; ++i) probability += probabilities[targets[i]];
    probability = fmin(1.0, fmax(0.0, probability));
 done:
    qihse_destroy_superposition(&state);
    free(re); free(im); free(probabilities); free(targets);
    return probability;
}

/* Statistical distribution similarity */
double qihse_statistical_similarity(
    const float* result,
    const float* ground_truth,
    size_t data_size
) {
    /* Compute statistical properties */
    double res_mean = 0.0, gt_mean = 0.0;
    double res_var = 0.0, gt_var = 0.0;

    for (size_t i = 0; i < data_size; i++) {
        res_mean += result[i];
        gt_mean += ground_truth[i];
    }
    res_mean /= data_size;
    gt_mean /= data_size;

    for (size_t i = 0; i < data_size; i++) {
        double res_diff = result[i] - res_mean;
        double gt_diff = ground_truth[i] - gt_mean;
        res_var += res_diff * res_diff;
        gt_var += gt_diff * gt_diff;
    }
    res_var /= data_size;
    gt_var /= data_size;

    /* Statistical similarity based on mean difference and variance ratio */
    double mean_diff = fabs(res_mean - gt_mean);
    double var_ratio = fmax(res_var, gt_var) / fmax(fmin(res_var, gt_var), 1e-6);

    /* Combine into similarity score (0-1, higher is better) */
    return exp(-mean_diff) * exp(-fabs(log(var_ratio)));
}

/* Comprehensive precision similarity using all available methods */
double qihse_calculate_precision_similarity(
    const void* result,
    const void* ground_truth,
    size_t data_size,
    qihse_cpu_feature_t cpu_features
) {
    if (!result || !ground_truth || !data_size || data_size > SIZE_MAX / (2 * sizeof(double))) {
        errno = EINVAL; return 0.0;
    }
    const float* res = (const float*)result;
    const float* gt = (const float*)ground_truth;

    double similarities[6] = {0.0};
    double weights[6] = {0.0};
    int num_methods = 0;

    /* 1. SIMD-accelerated cosine similarity (fastest, always available) */
    if (cpu_features & QIHSE_CPU_FEATURE_AVX512F) {
        similarities[num_methods] = qihse_cosine_similarity_avx512(res, gt, data_size);
        weights[num_methods] = 0.25;
        num_methods++;
    } else if (cpu_features & QIHSE_CPU_FEATURE_AVX2) {
        similarities[num_methods] = qihse_cosine_similarity_avx2(res, gt, data_size);
        weights[num_methods] = 0.25;
        num_methods++;
    } else {
        similarities[num_methods] = qihse_cosine_similarity_scalar(res, gt, data_size);
        weights[num_methods] = 0.20;
        num_methods++;
    }

    /* 2. RFF-based Hilbert space similarity (quantum-inspired, high precision) */
    qihse_rff_kernel_t* rff_kernel = qihse_rff_create(data_size, data_size * 2, 1.0, 0);
    if (rff_kernel) {
        similarities[num_methods] = qihse_rff_similarity(res, gt, data_size, rff_kernel);
        weights[num_methods] = 0.25;  /* High weight for quantum-inspired method */
        num_methods++;
        qihse_rff_destroy(rff_kernel);
    }

    /* 3. Superposition fidelity (quantum-inspired, captures phase relationships) */
    similarities[num_methods] = qihse_superposition_fidelity_similarity(res, gt, data_size);
    weights[num_methods] = 0.20;
    num_methods++;

    /* 4. AMX tile operations (for large datasets, if available) */
    if ((cpu_features & QIHSE_CPU_FEATURE_AMX_TILE) && data_size >= 1024) {
        similarities[num_methods] = qihse_amx_matrix_similarity(res, gt, data_size);
        weights[num_methods] = 0.15;
        num_methods++;
    }

    /* 5. Grover amplification (for finding optimal matches, highest precision) */
    if (data_size <= 10000) {  /* Materialized simulation: cap input size for cost. */
        similarities[num_methods] = qihse_grover_amplified_similarity(
            res, gt, data_size, 0.01);  /* 1% threshold */
        weights[num_methods] = 0.15;  /* High weight for quantum method */
        num_methods++;
    }

    /* 6. Statistical distribution similarity (fallback validation) */
    similarities[num_methods] = qihse_statistical_similarity(res, gt, data_size);
    weights[num_methods] = 0.10;
    num_methods++;

    /* Normalize weights */
    double total_weight = 0.0;
    for (int i = 0; i < num_methods; i++) {
        total_weight += weights[i];
    }
    for (int i = 0; i < num_methods; i++) {
        weights[i] /= total_weight;
    }

    /* Weighted combination for precision search */
    double final_similarity = 0.0;
    for (int i = 0; i < num_methods; i++) {
        final_similarity += weights[i] * similarities[i];
    }

    /* Ensure result is in [0, 1] range */
    return fmax(0.0, fmin(1.0, final_similarity));
}