#ifndef QIHSE_MATH_TYPES_H
#define QIHSE_MATH_TYPES_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Shared by installed APIs and algorithm translation units. Preserve these
 * public layouts; algorithm-specific state must not extend them privately. */
typedef struct qihse_rff_kernel_s {
    double *omega;
    double *bias;
    size_t input_dims;
    size_t output_dims;
    double gamma;
    uint64_t seed;
} qihse_rff_kernel_t;

typedef struct qihse_superposition_s {
    double *real;
    double *imag;
    double *phase;
    size_t num_states;
    size_t dims_per_state;
    double global_phase;
    double measurement_confidence; /* Maximum normalized row mass, not retrieval accuracy */
} qihse_superposition_t;

typedef struct qihse_amplification_config_s {
    int min_rounds;
    int max_rounds;
    double convergence_threshold;
    double oracle_selectivity;
    bool adaptive_rounds;
    int fixed_rounds;
} qihse_amplification_config_t;

typedef enum qihse_verification_mode_e {
    QIHSE_VERIFY_NONE = 0,      /* Scalar: candidate equality only; sized float API: unsupported */
    QIHSE_VERIFY_FAST = 1,      /* Bounded approximate verification */
    QIHSE_VERIFY_WINDOW = 2,    /* Window policy in the search verifier */
    QIHSE_VERIFY_FALLBACK = 3,  /* Fallback policy in the search verifier */
    QIHSE_VERIFY_EXACT = 4,     /* Exact numeric comparison */
    QIHSE_VERIFY_PRECISION = 5  /* Sized vector comparison with absolute tolerance */
} qihse_verify_mode_t;
typedef qihse_verify_mode_t qihse_verification_mode_t;

typedef struct qihse_verification_config_s {
    qihse_verification_mode_t mode;      /* Verification mode */
    double confidence_threshold;         /* Minimum confidence required (0.0-1.0) */
    size_t max_retries;                  /* Reserved policy metadata; sized verifier does not retry */
    double tolerance;                    /* Numerical tolerance for comparisons */
    int enable_fallback;                 /* Reserved policy metadata */
    double performance_budget;           /* Performance budget for verification (%) */
    size_t window_size;                  /* Window size for rolling verification */
    int adaptive_verification;           /* Enable adaptive verification level */
} qihse_verification_config_t;

typedef struct qihse_verification_result_s {
    int is_valid;               /* 1 if verification passed, 0 if failed */
    double confidence;          /* Confidence score (0.0-1.0) */
    double accuracy;            /* Measured accuracy (0.0-1.0) */
    size_t verification_time_us; /* Measured CPU time spent on sized verification */
    size_t retries_used;        /* Number of retries performed */
    qihse_verification_mode_t mode_used; /* Verification mode actually used */
    char* error_message;        /* Error message if verification failed */
    void* detailed_metrics;     /* Backend-specific metrics */
} qihse_verification_result_t;

#endif
