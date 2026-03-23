#ifndef QIHSE_MATH_H
#define QIHSE_MATH_H

#include "qihse.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * RANDOM FOURIER FEATURES KERNEL EMBEDDING
 * ============================================================================ */

typedef struct {
    double* omega;              /* Random frequency matrix [dims x input_dims] */
    double* bias;               /* Random phase offsets [dims] */
    size_t input_dims;          /* Input dimension count */
    size_t output_dims;         /* Output dimension count (Hilbert space) */
    double gamma;               /* RBF kernel bandwidth parameter */
    uint64_t seed;              /* Random seed for reproducibility */
} qihse_rff_kernel_t;

qihse_rff_kernel_t* qihse_rff_create(size_t input_dims, size_t output_dims,
                                    double gamma, uint64_t seed);
void qihse_rff_destroy(qihse_rff_kernel_t* kernel);
void qihse_rff_project(const qihse_rff_kernel_t* kernel, const double* input,
                      double* output);

/* ============================================================================
 * SUPERPOSITION STATE ENCODING
 * ============================================================================ */

typedef struct qihse_superposition_s {
    double* real;               /* Real amplitude components */
    double* imag;               /* Imaginary amplitude components */
    double* phase;              /* Per-element phase angles */
    size_t num_states;          /* Number of superposition states */
    size_t dims_per_state;      /* Dimensions per quantum state */
    double global_phase;        /* Global quantum phase */
    double measurement_confidence; /* Confidence in quantum measurement */
} qihse_superposition_t;

int qihse_create_superposition(const double* rff_data, size_t n, size_t rff_dims,
                              qihse_superposition_t* superposition);
void qihse_destroy_superposition(qihse_superposition_t* superposition);

/* ============================================================================
 * INTEL ONEAPI ENHANCEMENT
 * ============================================================================ */

typedef enum {
    QIHSE_INTEL_BACKEND_NONE = 0,    /* No Intel acceleration */
    QIHSE_INTEL_BACKEND_MKL = 1,     /* Intel MKL for BLAS operations */
    QIHSE_INTEL_BACKEND_IPP = 2,     /* Intel IPP for signal processing */
    QIHSE_INTEL_BACKEND_TBB = 3,     /* Intel TBB for threading */
    QIHSE_INTEL_BACKEND_DPCPP = 4,   /* Intel oneAPI DPC++ */
    QIHSE_INTEL_BACKEND_FORTRAN = 5  /* FORTRAN kernels */
} qihse_intel_backend_t;

typedef struct {
    qihse_intel_backend_t backend;
    int mkl_threads;                 /* MKL thread count */
    int tbb_threads;                 /* TBB thread count */
    bool enable_amx;                 /* Use AMX instructions */
    bool enable_avx512;              /* Use AVX-512 */
    bool enable_vnni;                /* Use VNNI instructions */
    size_t mkl_block_size;           /* MKL block size for GEMM */
    int fortran_precision;           /* FORTRAN precision mode */
    void* backend_context;           /* Backend-specific context */
} qihse_intel_config_t;

typedef struct {
    double mkl_gemm_time;            /* MKL GEMM operation time */
    double ipp_fft_time;             /* IPP FFT time */
    double tbb_parallel_time;        /* TBB parallel execution time */
    double fortran_compute_time;     /* FORTRAN computation time */
    size_t amx_tiles_used;           /* AMX tiles utilized */
    size_t avx512_vectors;           /* AVX-512 vector operations */
    double frequency_mhz;            /* CPU frequency during execution */
    double power_watts;              /* Power consumption estimate */
} qihse_intel_performance_t;

int qihse_intel_init(const qihse_intel_config_t* config);
void qihse_intel_shutdown(void);
bool qihse_intel_backend_available(qihse_intel_backend_t backend);
int qihse_intel_get_performance_stats(qihse_intel_performance_t* stats);
int qihse_intel_set_frequency_scaling(double target_frequency_mhz);
void* qihse_intel_optimize_memory_layout(const void* data, size_t size, size_t alignment);

/* ============================================================================
 * FORTRAN INTEGRATION
 * ============================================================================ */

typedef enum {
    QIHSE_FORTRAN_PRECISION_SINGLE = 1,   /* Single precision (float32) */
    QIHSE_FORTRAN_PRECISION_DOUBLE = 2,   /* Double precision (float64) */
    QIHSE_FORTRAN_PRECISION_QUAD = 3      /* Quad precision */
} qihse_fortran_precision_t;

typedef struct {
    qihse_fortran_precision_t precision;
    bool enable_openmp;               /* Use OpenMP in FORTRAN code */
    int openmp_threads;               /* OpenMP thread count */
    bool enable_simd;                 /* Enable SIMD directives */
    bool enable_vectorization;        /* Enable vectorization */
    char* library_path;               /* Path to FORTRAN libraries */
    void* fortran_context;            /* FORTRAN runtime context */
} qihse_fortran_config_t;

typedef struct {
    double matrix_multiply_time;      /* BLAS-like operations */
    double eigenvalue_time;           /* Eigenvalue computations */
    double svd_time;                  /* SVD decompositions */
    double fft_time;                  /* FFT operations */
    size_t flops_performed;           /* Floating point operations */
    double gflops_achieved;           /* GFLOPS achieved */
} qihse_fortran_performance_t;

int qihse_fortran_init(const qihse_fortran_config_t* config);
void qihse_fortran_shutdown(void);
bool qihse_fortran_available(void);
int qihse_fortran_gemm(const double* a, const double* b, double* c,
                      size_t m, size_t n, size_t k);
int qihse_fortran_eigenvalues(const double* matrix, double* eigenvalues,
                             double* eigenvectors, size_t n);
int qihse_fortran_fft(const double* input, double* output,
                     size_t size, int direction);
int qihse_fortran_get_performance_stats(qihse_fortran_performance_t* stats);

/* ============================================================================
 * ADVANCED MATHEMATICAL OPTIMIZATIONS
 * ============================================================================ */

typedef enum {
    QIHSE_MATH_PRECISION_FULL = 0,    /* Full IEEE 754 precision */
    QIHSE_MATH_PRECISION_HIGH = 1,    /* High precision (1e-12 relative) */
    QIHSE_MATH_PRECISION_MEDIUM = 2,  /* Medium precision (1e-8 relative) */
    QIHSE_MATH_PRECISION_LOW = 3,     /* Low precision (1e-4 relative) */
    QIHSE_MATH_PRECISION_FAST = 4     /* Fast approximations */
} qihse_math_precision_t;

typedef struct {
    qihse_math_precision_t precision;
    bool enable_fma;                  /* Use fused multiply-add */
    bool enable_fast_math;            /* Use fast math approximations */
    bool enable_vectorization;        /* Enable SIMD vectorization */
    size_t cache_line_size;           /* Cache line size for alignment */
    bool enable_prefetching;          /* Enable software prefetching */
} qihse_math_config_t;

typedef struct {
    double exp_approximation_error;    /* Max error in exp() approximation */
    double log_approximation_error;    /* Max error in log() approximation */
    double sqrt_approximation_error;   /* Max error in sqrt() approximation */
    double trig_approximation_error;   /* Max error in trig approximations */
    size_t vector_operations;          /* SIMD vector operations performed */
    size_t cache_misses;               /* Estimated cache misses */
    double computation_time;           /* Total computation time */
} qihse_math_performance_t;

int qihse_math_init(const qihse_math_config_t* config);
double qihse_math_fast_exp(double x, qihse_math_precision_t precision);
double qihse_math_fast_log(double x, qihse_math_precision_t precision);
double qihse_math_fast_sqrt(double x, qihse_math_precision_t precision);
void qihse_math_fast_sincos(double x, double* sin_out, double* cos_out,
                           qihse_math_precision_t precision);
double qihse_math_vector_dot(const double* a, const double* b, size_t n);
int32_t qihse_math_int8_dot(const int8_t* a, const int8_t* b, size_t n);
void qihse_math_matrix_vector_mul(const double* matrix, const double* vector,
                                 double* result, size_t m, size_t n);
double qihse_math_fast_random(uint64_t* seed);
void qihse_math_cache_efficient_transpose(const double* input, double* output,
                                        size_t rows, size_t cols);
int qihse_math_get_performance_stats(qihse_math_performance_t* stats);

#ifdef __cplusplus
}
#endif

#endif /* QIHSE_MATH_H */
int qihse_superposition_fidelity(const void* a, const void* b, size_t n, double* fidelity);
int qihse_superposition_fidelity(const void* a, const void* b, size_t n, double* fidelity);
int qihse_superposition_fidelity(const void* a, const void* b, size_t n, double* fidelity);
