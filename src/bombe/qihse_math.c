/* #define _GNU_SOURCE */
#include "qihse_math.h"
#include "qihse_instr.h"
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include <stdio.h>
#include <errno.h>

#ifndef M_PI
#define M_PI acos(-1.0)
#endif

static inline uint64_t ns_now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

/* ============================================================================
 * RANDOM FOURIER FEATURES KERNEL EMBEDDING
 * ============================================================================ */

qihse_rff_kernel_t* qihse_rff_create(
    size_t input_dims,
    size_t output_dims,
    double gamma,
    uint64_t seed
) {
    if (input_dims == 0 || output_dims == 0) return NULL;

    qihse_rff_kernel_t* kernel = calloc(1, sizeof(qihse_rff_kernel_t));
    if (!kernel) return NULL;

    kernel->input_dims = input_dims;
    kernel->output_dims = output_dims;
    kernel->gamma = gamma;
    kernel->seed = seed;

    /* Allocate matrices */
    kernel->omega = malloc(output_dims * input_dims * sizeof(double));
    kernel->bias = malloc(output_dims * sizeof(double));

    if (!kernel->omega || !kernel->bias) {
        qihse_rff_destroy(kernel);
        return NULL;
    }

    /* Initialize random number generator */
    srand(seed);

    /* Generate random frequencies from Gaussian distribution */
    double sigma = sqrt(2.0 * gamma);  /* RBF kernel bandwidth */

    for (size_t i = 0; i < output_dims * input_dims; i++) {
        /* Box-Muller transform for Gaussian random variables */
        double u1 = (double)rand() / RAND_MAX;
        double u2 = (double)rand() / RAND_MAX;

        double z0 = sqrt(-2.0 * log(u1)) * cos(2.0 * M_PI * u2);
        kernel->omega[i] = z0 * sigma;
    }

    /* Generate random biases */
    for (size_t i = 0; i < output_dims; i++) {
        kernel->bias[i] = 2.0 * M_PI * ((double)rand() / RAND_MAX);
    }

    return kernel;
}

void qihse_rff_destroy(qihse_rff_kernel_t* kernel) {
    if (!kernel) return;

    free(kernel->omega);
    free(kernel->bias);
    free(kernel);
}

void qihse_rff_project(
    const qihse_rff_kernel_t* kernel,
    const double* input,
    double* output
) {
    if (!kernel || !input || !output) return;

    const double scale = sqrt(2.0 / kernel->output_dims);

    for (size_t d = 0; d < kernel->output_dims; d++) {
        double dot_product = 0.0;

        /* Compute ω·x + b */
        for (size_t i = 0; i < kernel->input_dims; i++) {
            dot_product += kernel->omega[d * kernel->input_dims + i] * input[i];
        }
        dot_product += kernel->bias[d];

        /* Apply cos transform: z(x) = sqrt(2/D) * cos(ω·x + b) */
        output[d] = scale * cos(dot_product);
    }
}

/* ============================================================================
 * SUPERPOSITION STATE ENCODING
 * ============================================================================ */

int qihse_create_superposition(
    const double* rff_data,
    size_t n,
    size_t rff_dims,
    qihse_superposition_t* superposition
) {
    if (!rff_data || n == 0 || rff_dims == 0 || !superposition) return -1;

    superposition->num_states = n;
    superposition->dims_per_state = rff_dims;
    superposition->global_phase = 0.0;
    superposition->measurement_confidence = 0.0;

    /* Allocate superposition arrays */
    superposition->real = malloc(n * rff_dims * sizeof(double));
    superposition->imag = malloc(n * rff_dims * sizeof(double));
    superposition->phase = malloc(n * sizeof(double));

    if (!superposition->real || !superposition->imag || !superposition->phase) {
        qihse_destroy_superposition(superposition);
        return -1;
    }

    /* Encode RFF data into quantum superposition states */
    for (size_t state = 0; state < n; state++) {
        const double* rff_vector = &rff_data[state * rff_dims];
        superposition->phase[state] = 0.0;

        /* Phase encoding: amplitude becomes complex exponential */
        for (size_t dim = 0; dim < rff_dims; dim++) {
            size_t idx = state * rff_dims + dim;
            double amplitude = rff_vector[dim];

            /* Encode amplitude as |ψ⟩ = α|0⟩ + β|1⟩ in higher-dimensional space */
            /* For simplicity, we use phase encoding with correlation strength */
            double phase_offset = 2.0 * M_PI * (double)state / n;
            double dim_phase = 2.0 * M_PI * (double)dim / rff_dims;

            superposition->real[idx] = amplitude * cos(phase_offset + dim_phase);
            superposition->imag[idx] = amplitude * sin(phase_offset + dim_phase);
        }
    }

    return 0;
}

void qihse_destroy_superposition(qihse_superposition_t* superposition) {
    if (!superposition) return;

    free(superposition->real);
    free(superposition->imag);
    free(superposition->phase);

    memset(superposition, 0, sizeof(qihse_superposition_t));
}

/* ============================================================================
 * INTEL ONEAPI INTEGRATION IMPLEMENTATION
 * ============================================================================ */

static qihse_intel_config_t g_intel_config = {0};
static bool g_intel_initialized = false;
static qihse_intel_performance_t g_intel_perf = {0};

int qihse_intel_init(const qihse_intel_config_t* config) {
    if (!config) return -EINVAL;

    /* Copy configuration */
    memcpy(&g_intel_config, config, sizeof(qihse_intel_config_t));
    g_intel_initialized = false;

    /* Initialize MKL if requested */
    if (config->backend == QIHSE_INTEL_BACKEND_MKL && QIHSE_MKL_AVAILABLE) {
        /* Set MKL thread count */
        if (config->mkl_threads > 0) {
            setenv("MKL_NUM_THREADS", "4", 1);  /* Default to 4 threads */
            setenv("MKL_DYNAMIC", "FALSE", 1);
        }
        /* MKL is typically initialized on first use */
        g_intel_initialized = true;
    }

    /* Initialize IPP if requested */
    if (config->backend == QIHSE_INTEL_BACKEND_IPP && QIHSE_IPP_AVAILABLE) {
        /* IPP initialization */
        g_intel_initialized = true;
    }

    /* Initialize TBB if requested */
    if (config->backend == QIHSE_INTEL_BACKEND_TBB && QIHSE_TBB_AVAILABLE) {
        g_intel_initialized = true;
    }

    /* Initialize DPC++ if requested */
    if (config->backend == QIHSE_INTEL_BACKEND_DPCPP && QIHSE_ONEAPI_AVAILABLE) {
        g_intel_initialized = true;
    }

    return g_intel_initialized ? 0 : -ENOTSUP;
}

void qihse_intel_shutdown(void) {
    if (!g_intel_initialized) return;

    memset(&g_intel_config, 0, sizeof(g_intel_config));
    g_intel_initialized = false;
}

bool qihse_intel_backend_available(qihse_intel_backend_t backend) {
    switch (backend) {
        case QIHSE_INTEL_BACKEND_MKL:
            return QIHSE_MKL_AVAILABLE;
        case QIHSE_INTEL_BACKEND_IPP:
            return QIHSE_IPP_AVAILABLE;
        case QIHSE_INTEL_BACKEND_TBB:
            return QIHSE_TBB_AVAILABLE;
        case QIHSE_INTEL_BACKEND_DPCPP:
            return QIHSE_ONEAPI_AVAILABLE;
        case QIHSE_INTEL_BACKEND_FORTRAN:
            return QIHSE_FORTRAN_AVAILABLE;
        default:
            return false;
    }
}

int qihse_intel_get_performance_stats(qihse_intel_performance_t* stats) {
    if (!stats) return -EINVAL;
    memcpy(stats, &g_intel_perf, sizeof(qihse_intel_performance_t));
    return 0;
}

int qihse_intel_set_frequency_scaling(double target_frequency_mhz) {
    if (target_frequency_mhz == 0.0) {
        system("cpupower frequency-set -g performance 2>/dev/null || true");
    } else {
        char cmd[256];
        snprintf(cmd, sizeof(cmd),
                "cpupower frequency-set -f %.0fMHz 2>/dev/null || true",
                target_frequency_mhz);
        system(cmd);
    }
    return 0;
}

void* qihse_intel_optimize_memory_layout(const void* data, size_t size, size_t alignment) {
    if (!data || size == 0) return NULL;

    void* aligned_data = NULL;
    if (posix_memalign(&aligned_data, alignment, size) == 0) {
        memcpy(aligned_data, data, size);
        return aligned_data;
    }

    return NULL;
}

/* ============================================================================
 * FORTRAN INTEGRATION IMPLEMENTATION
 * ============================================================================ */

static qihse_fortran_config_t g_fortran_config = {0};
static bool g_fortran_initialized = false;
static qihse_fortran_performance_t g_fortran_perf = {0};

#ifdef QIHSE_ENABLE_FORTRAN
extern void fortran_gemm_(const double* a, const double* b, double* c,
                         const int* m, const int* n, const int* k);
extern void fortran_eigenvalues_(const double* matrix, double* eigenvalues,
                               double* eigenvectors, const int* n);
extern void fortran_fft_(const double* input, double* output,
                        const int* size, const int* direction);
#endif

int qihse_fortran_init(const qihse_fortran_config_t* config) {
    if (!config) return -EINVAL;
    if (!QIHSE_FORTRAN_AVAILABLE) return -ENOTSUP;

    memcpy(&g_fortran_config, config, sizeof(qihse_fortran_config_t));

    if (config->enable_openmp && config->openmp_threads > 0) {
        char env_var[64];
        snprintf(env_var, sizeof(env_var), "%d", config->openmp_threads);
        setenv("OMP_NUM_THREADS", env_var, 1);
    }

    g_fortran_initialized = true;
    return 0;
}

void qihse_fortran_shutdown(void) {
    if (!g_fortran_initialized) return;
    memset(&g_fortran_config, 0, sizeof(g_fortran_config));
    g_fortran_initialized = false;
}

bool qihse_fortran_available(void) {
    return QIHSE_FORTRAN_AVAILABLE && g_fortran_initialized;
}

int qihse_fortran_gemm(const double* a, const double* b, double* c,
                      size_t m, size_t n, size_t k) {
    if (!g_fortran_initialized || !QIHSE_FORTRAN_AVAILABLE) return -ENOTSUP;
    if (!a || !b || !c) return -EINVAL;

#ifdef QIHSE_ENABLE_FORTRAN
    uint64_t start_time = ns_now();
    int m_int = (int)m, n_int = (int)n, k_int = (int)k;
    fortran_gemm_(a, b, c, &m_int, &n_int, &k_int);
    uint64_t end_time = ns_now();
    g_fortran_perf.matrix_multiply_time = (double)(end_time - start_time) / 1e9;
    g_fortran_perf.flops_performed += (size_t)m * n * k * 2;
    return 0;
#else
    for (size_t i = 0; i < m; i++) {
        for (size_t j = 0; j < n; j++) {
            c[i * n + j] = 0.0;
        }
        for (size_t l = 0; l < k; l++) {
            double a_il = a[i * k + l];
            for (size_t j = 0; j < n; j++) {
                c[i * n + j] += a_il * b[l * n + j];
            }
        }
    }
    return 0;
#endif
}

int qihse_fortran_eigenvalues(const double* matrix, double* eigenvalues,
                             double* eigenvectors, size_t n) {
    if (!g_fortran_initialized || !QIHSE_FORTRAN_AVAILABLE) {
        /* Fallback: Power Iteration for dominant eigenvalue */
        if (!matrix || !eigenvalues || !eigenvectors || n == 0) return -EINVAL;
        
        /* Initialize eigenvector guess */
        for (size_t i = 0; i < n; i++) {
            eigenvectors[i] = 1.0 / sqrt((double)n);
        }
        
        double prev_lambda = 0.0;
        double lambda = 0.0;
        double* temp = (double*)malloc(n * sizeof(double));
        
        if (!temp) return -ENOMEM;
        
        for (int iter = 0; iter < 1000; iter++) {
            /* temp = matrix * eigenvectors */
            for (size_t i = 0; i < n; i++) {
                temp[i] = 0.0;
                for (size_t j = 0; j < n; j++) {
                    temp[i] += matrix[i * n + j] * eigenvectors[j];
                }
            }
            
            /* lambda = eigenvectors^T * temp */
            lambda = 0.0;
            for (size_t i = 0; i < n; i++) {
                lambda += eigenvectors[i] * temp[i];
            }
            
            /* Normalize new eigenvector */
            double norm = 0.0;
            for (size_t i = 0; i < n; i++) {
                norm += temp[i] * temp[i];
            }
            norm = sqrt(norm);
            
            if (norm > 0.0) {
                for (size_t i = 0; i < n; i++) {
                    eigenvectors[i] = temp[i] / norm;
                }
            }
            
            if (fabs(lambda - prev_lambda) < 1e-9) break;
            prev_lambda = lambda;
        }
        
        eigenvalues[0] = lambda;
        for (size_t i = 1; i < n; i++) eigenvalues[i] = 0.0; /* Only dominant calculated in fallback */
        
        free(temp);
        return 0;
    }

#ifdef QIHSE_ENABLE_FORTRAN
    uint64_t start_time = ns_now();
    int n_int = (int)n;
    fortran_eigenvalues_(matrix, eigenvalues, eigenvectors, &n_int);
    uint64_t end_time = ns_now();
    g_fortran_perf.eigenvalue_time = (double)(end_time - start_time) / 1e9;
    return 0;
#else
    return -ENOTSUP; /* Should not reach here due to the if check above */
#endif
}

int qihse_fortran_fft(const double* input, double* output,
                     size_t size, int direction) {
    if (!g_fortran_initialized || !QIHSE_FORTRAN_AVAILABLE) return -ENOTSUP;

#ifdef QIHSE_ENABLE_FORTRAN
    uint64_t start_time = ns_now();
    int size_int = (int)size, dir_int = direction;
    fortran_fft_(input, output, &size_int, &dir_int);
    uint64_t end_time = ns_now();
    g_fortran_perf.fft_time = (double)(end_time - start_time) / 1e9;
    return 0;
#else
    for (size_t k = 0; k < size; k++) {
        output[k] = 0.0;
        for (size_t n = 0; n < size; n++) {
            double angle = -2.0 * M_PI * (double)k * (double)n / (double)size;
            if (direction < 0) angle = -angle;
            output[k] += input[n] * cos(angle); // Simplified
        }
    }
    return 0;
#endif
}

int qihse_fortran_get_performance_stats(qihse_fortran_performance_t* stats) {
    if (!stats) return -EINVAL;
    memcpy(stats, &g_fortran_perf, sizeof(qihse_fortran_performance_t));
    double total_time = stats->matrix_multiply_time + stats->eigenvalue_time +
                       stats->svd_time + stats->fft_time;
    if (total_time > 0.0) {
        stats->gflops_achieved = (double)stats->flops_performed / (total_time * 1e9);
    }
    return 0;
}

/* ============================================================================
 * ADVANCED MATHEMATICAL OPTIMIZATIONS
 * ============================================================================ */

static qihse_math_config_t g_math_config = {0};
static qihse_math_performance_t g_math_perf = {0};

int qihse_math_init(const qihse_math_config_t* config) {
    if (!config) return -EINVAL;
    memcpy(&g_math_config, config, sizeof(qihse_math_config_t));
    if (g_math_config.cache_line_size == 0) g_math_config.cache_line_size = 64;
    return 0;
}

double qihse_math_fast_exp(double x, qihse_math_precision_t precision) {
    if (x < -700.0) return 0.0;
    if (x > 700.0) return 1e300;
    double result;
    switch (precision) {
        case QIHSE_MATH_PRECISION_FAST: {
            const double c1 = 1.0 / (1 << 12);
            const double c2 = 1.0 / (1 << 6);
            double y = 1.0 + x * c1;
            y *= y; y *= y; y *= y; y *= y;
            y *= y; y *= y; y *= y; y *= y;
            result = y * c2;
            break;
        }
        case QIHSE_MATH_PRECISION_LOW: {
            double x2 = x * x;
            double x3 = x2 * x;
            double x4 = x2 * x2;
            result = 1.0 + x + x2 * 0.5 + x3 * 0.16666666666666666 + x4 * 0.041666666666666664;
            break;
        }
        case QIHSE_MATH_PRECISION_MEDIUM: {
            double x2 = x * x;
            double x4 = x2 * x2;
            double x6 = x4 * x2;
            double x8 = x4 * x4;
            result = 1.0 + x + x2 * 0.5 + x2 * x * 0.16666666666666666 +
                    x4 * 0.041666666666666664 + x4 * x * 0.008333333333333333 +
                    x6 * 0.001388888888888889 + x6 * x * 0.0001984126984126984 +
                    x8 * 0.0000248015873015873;
            break;
        }
        default: result = exp(x); break;
    }
    g_math_perf.exp_approximation_error = fabs(result - exp(x)) / fabs(exp(x));
    return result;
}

double qihse_math_fast_log(double x, qihse_math_precision_t precision) {
    if (x <= 0.0) return -1e300;
    double result;
    switch (precision) {
        case QIHSE_MATH_PRECISION_FAST: {
            union { double d; uint64_t i; } u = {x};
            u.i = (u.i - 0x3FE6A09E667F3BCD) & 0x7FFFFFFFFFFFFFFF;
            result = u.d - 1.0;
            break;
        }
        case QIHSE_MATH_PRECISION_LOW: {
            double y = (x - 1.0) / (x + 1.0);
            double y2 = y * y;
            double y4 = y2 * y2;
            result = 2.0 * y * (1.0 + y2 * 0.3333333333333333 + y4 * 0.2);
            break;
        }
        case QIHSE_MATH_PRECISION_MEDIUM: {
            double ln2 = 0.6931471805599453;
            int exponent;
            double mantissa = frexp(x, &exponent);
            double y = (mantissa - 1.0) / (mantissa + 1.0);
            double y2 = y * y;
            double y4 = y2 * y2;
            double log_mantissa = 2.0 * y * (1.0 + y2 * (0.3333333333333333 +
                                y2 * 0.2 + y4 * 0.1714285714285714));
            result = log_mantissa + (double)exponent * ln2;
            break;
        }
        default: result = log(x); break;
    }
    g_math_perf.log_approximation_error = fabs(result - log(x)) / fabs(log(x));
    return result;
}

double qihse_math_fast_sqrt(double x, qihse_math_precision_t precision) {
    if (x < 0.0) return 0.0;
    if (x == 0.0) return 0.0;
    double result;
    switch (precision) {
        case QIHSE_MATH_PRECISION_FAST: {
            union { double d; uint64_t i; } u = {x};
            u.i = (0x5FE6EB50C7B537A9 - (u.i >> 1));
            result = u.d;
            result = 0.5 * (result + x / result);
            break;
        }
        case QIHSE_MATH_PRECISION_LOW:
            result = x * 0.5;
            result = 0.5 * (result + x / result);
            result = 0.5 * (result + x / result);
            break;
        case QIHSE_MATH_PRECISION_MEDIUM:
            result = x * 0.5;
            for (int i = 0; i < 4; i++) result = 0.5 * (result + x / result);
            break;
        default: result = sqrt(x); break;
    }
    g_math_perf.sqrt_approximation_error = fabs(result - sqrt(x)) / sqrt(x);
    return result;
}

void qihse_math_fast_sincos(double x, double* sin_out, double* cos_out,
                           qihse_math_precision_t precision) {
    double pi = 3.141592653589793;
    double pi2 = pi * 2.0;
    double x_reduced = fmod(x, pi2);
    if (x_reduced > pi) x_reduced -= pi2;
    if (x_reduced < -pi) x_reduced += pi2;
    double sin_val, cos_val;
    switch (precision) {
        case QIHSE_MATH_PRECISION_FAST:
            sin_val = x_reduced - x_reduced * x_reduced * x_reduced / 6.0;
            cos_val = 1.0 - x_reduced * x_reduced / 2.0;
            break;
        case QIHSE_MATH_PRECISION_LOW: {
            double x2 = x_reduced * x_reduced;
            double x4 = x2 * x2;
            sin_val = x_reduced - x2 * x_reduced / 6.0 + x4 * x_reduced / 120.0;
            cos_val = 1.0 - x2 / 2.0 + x4 / 24.0;
            break;
        }
        case QIHSE_MATH_PRECISION_MEDIUM: {
            double x2 = x_reduced * x_reduced;
            double x4 = x2 * x2;
            double x6 = x4 * x2;
            sin_val = x_reduced - x2 * x_reduced / 6.0 +
                     x4 * x_reduced / 120.0 - x6 * x_reduced / 5040.0;
            cos_val = 1.0 - x2 / 2.0 + x4 / 24.0 - x6 / 720.0;
            break;
        }
        default:
            if (sin_out) *sin_out = sin(x);
            if (cos_out) *cos_out = cos(x);
            return;
    }
    if (sin_out) *sin_out = sin_val;
    if (cos_out) *cos_out = cos_val;
}

double qihse_math_vector_dot(const double* a, const double* b, size_t n) {
    double sum0 = 0.0, sum1 = 0.0, sum2 = 0.0, sum3 = 0.0;
    size_t i = 0;
    for (; i + 3 < n; i += 4) {
        sum0 += a[i] * b[i];
        sum1 += a[i+1] * b[i+1];
        sum2 += a[i+2] * b[i+2];
        sum3 += a[i+3] * b[i+3];
    }
    double sum = sum0 + sum1 + sum2 + sum3;
    for (; i < n; i++) sum += a[i] * b[i];
    g_math_perf.vector_operations += n;
    return sum;
}

int32_t qihse_math_int8_dot(const int8_t* a, const int8_t* b, size_t n) {
    int32_t result = 0;
    // Attempt to use VNNI acceleration via qihse_instr
    if (qihse_intel_vnni_dot_product(a, b, &result, n) == 0) {
        return result;
    }
    
    // Fallback to scalar dot product
    for (size_t i = 0; i < n; i++) {
        result += (int32_t)a[i] * (int32_t)b[i];
    }
    return result;
}

void qihse_math_matrix_vector_mul(const double* matrix, const double* vector,
                                 double* result, size_t m, size_t n) {
    for (size_t i = 0; i < m; i++) {
        result[i] = qihse_math_vector_dot(&matrix[i * n], vector, n);
    }
}

double qihse_math_fast_random(uint64_t* seed) {
    static uint64_t default_seed = 42;
    uint64_t* s = seed ? seed : &default_seed;
    *s = *s * 1103515245ULL + 12345ULL;
    return (double)(*s & 0x7FFFFFFFULL) / (double)0x80000000ULL;
}

void qihse_math_cache_efficient_transpose(const double* input, double* output,
                                        size_t rows, size_t cols) {
    const size_t block_size = 8;
    for (size_t i = 0; i < rows; i += block_size) {
        for (size_t j = 0; j < cols; j += block_size) {
            size_t i_end = (i + block_size < rows) ? i + block_size : rows;
            size_t j_end = (j + block_size < cols) ? j + block_size : cols;
            for (size_t bi = i; bi < i_end; bi++) {
                for (size_t bj = j; bj < j_end; bj++) {
                    output[bj * rows + bi] = input[bi * cols + bj];
                }
            }
        }
    }
}

int qihse_math_get_performance_stats(qihse_math_performance_t* stats) {
    if (!stats) return -EINVAL;
    memcpy(stats, &g_math_perf, sizeof(qihse_math_performance_t));
    return 0;
}
