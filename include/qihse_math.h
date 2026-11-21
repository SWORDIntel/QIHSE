#ifndef QIHSE_MATH_H
#define QIHSE_MATH_H

#include "qihse.h"
#include "qihse_math_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * RANDOM FOURIER FEATURES KERNEL EMBEDDING
 * ============================================================================ */


qihse_rff_kernel_t* qihse_rff_create(size_t input_dims, size_t output_dims,
                                    double gamma, uint64_t seed);
void qihse_rff_destroy(qihse_rff_kernel_t* kernel);
void qihse_rff_project(const qihse_rff_kernel_t* kernel, const double* input,
                      double* output);

/* Additive, immutable feature maps own their method. The legacy kernel APIs
 * above retain random-phase cosine semantics and their existing layout.
 * PAIRED_SINCOS requires even output_dims D: m=D/2 frequencies produce
 * [cos(w0.x), sin(w0.x), ...] / sqrt(m), with no random phase offsets.
 * Gamma must be finite and positive, and dimensions nonzero. Creation returns
 * NULL with errno EINVAL, EOVERFLOW, or ENOMEM on failure. Seed zero is valid. */
qihse_rff_map_t* qihse_rff_map_create(size_t input_dims, size_t output_dims,
                                     double gamma, uint64_t seed,
                                     qihse_rff_method_t method);
void qihse_rff_map_destroy(qihse_rff_map_t* map);
/* Input/output hold input_dims/output_dims doubles and must not overlap.
 * Returns 0 on success, -1 with errno on failure. Null pointers or overlap fail
 * EINVAL without writing output. Nonfinite input fails EDOM; finite input whose
 * projection overflows fails ERANGE. Both numeric failures fill output with NaN.
 * Concurrent projections of an immutable map into separate buffers are safe. */
int qihse_rff_map_project(const qihse_rff_map_t* map, const double* input,
                          double* output);
size_t qihse_rff_map_input_dims(const qihse_rff_map_t* map);
size_t qihse_rff_map_output_dims(const qihse_rff_map_t* map);
/* Requested owned allocation bytes, including metadata and kernel arrays;
 * excludes allocator overhead and the caller's projected-vector buffers. */
size_t qihse_rff_map_storage_bytes(const qihse_rff_map_t* map);
/* descriptor_bytes must be >= sizeof(qihse_rff_map_descriptor_t). Cache
 * identity includes every descriptor field. Serialize fields explicitly,
 * never the raw struct/padding. Reproduction is within a compatible libm/build. */
int qihse_rff_map_get_descriptor(const qihse_rff_map_t* map,
                                 qihse_rff_map_descriptor_t* descriptor,
                                 size_t descriptor_bytes);

/* ============================================================================
 * SUPERPOSITION STATE ENCODING
 * ============================================================================ */


int qihse_create_superposition(const double* rff_data, size_t n, size_t rff_dims,
                              qihse_superposition_t* superposition);
void qihse_destroy_superposition(qihse_superposition_t* superposition);
int qihse_create_superposition_from_amplitudes(const double* real, const double* imag,
                                              size_t n, qihse_superposition_t* state);
int qihse_superposition_normalize(qihse_superposition_t* state);
int qihse_superposition_is_normalized(const qihse_superposition_t* state);
double qihse_superposition_state_fidelity(const qihse_superposition_t* a,
                                         const qihse_superposition_t* b);
/* Legacy raw-float ABI: normalized squared overlap, not an unbounded dot product. */
int qihse_superposition_fidelity(const void* a, const void* b, size_t n,
                                 double* fidelity);
size_t qihse_superposition_measure(const qihse_superposition_t* state, uint64_t seed);
double qihse_superposition_get_measurement_confidence(const qihse_superposition_t* state);


void qihse_verification_config_init(qihse_verification_config_t* config,
                                     qihse_verification_mode_t mode);
void qihse_verification_result_init(qihse_verification_result_t* result);
void qihse_verification_result_destroy(qihse_verification_result_t* result);

/* Sized APIs consume exactly data_size float elements. EXACT checks equality;
 * PRECISION checks every element against absolute config->tolerance. Other
 * modes report bounded cosine similarity, not a calibrated probability. */
int qihse_verify_result_advanced_sized(const void* query, const float* result,
                                      const float* ground_truth, size_t data_size,
                                      const qihse_verification_config_t* config,
                                      qihse_verification_result_t* verification_result);
int qihse_verify_batch_sized(const void* const* queries, const float* const* results,
                            const float* const* ground_truths, const size_t* data_sizes,
                            size_t batch_size, const qihse_verification_config_t* config,
                            qihse_verification_result_t* verification_results);

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

/* Compatibility selectors: all five currently use the libm implementation.
 * These names do not promise distinct error bounds or approximate fast paths. */
typedef enum {
    QIHSE_MATH_PRECISION_FULL = 0,
    QIHSE_MATH_PRECISION_HIGH = 1,
    QIHSE_MATH_PRECISION_MEDIUM = 2,
    QIHSE_MATH_PRECISION_LOW = 3,
    QIHSE_MATH_PRECISION_FAST = 4
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
