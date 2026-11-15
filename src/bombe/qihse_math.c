
#ifdef _WIN32
#include <malloc.h>
#include <stdlib.h>
#include <stdio.h>
static inline int setenv(const char *name, const char *value, int overwrite) {
    (void)overwrite;
    char buf[256];
    snprintf(buf, sizeof(buf), "%s=%s", name, value);
    return _putenv(buf);
}
static inline int posix_memalign(void **memptr, size_t alignment, size_t size) {
    *memptr = _aligned_malloc(size, alignment);
    return (*memptr != NULL) ? 0 : 12; // ENOMEM
}
#endif

/* #define _GNU_SOURCE */
#include "qihse_math.h"
#include "qihse_instr.h"
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/mman.h>

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

/* A kernel owns its random stream: constructing a basis must neither depend on
 * nor reseed the process-global rand() state.  SplitMix64 also accepts seed 0. */
static uint64_t qihse_rff_random_u64(uint64_t* state) {
    uint64_t z = (*state += UINT64_C(0x9e3779b97f4a7c15));
    z = (z ^ (z >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
    z = (z ^ (z >> 27)) * UINT64_C(0x94d049bb133111eb);
    return z ^ (z >> 31);
}

static double qihse_rff_uniform(uint64_t* state) {
    return (double)(qihse_rff_random_u64(state) >> 11) * 0x1.0p-53;
}

/* Basis version 1 uses the same draw order as the legacy cosine constructor. */
static void qihse_rff_fill_frequencies(double* omega, size_t count, double gamma,
                                      uint64_t* random_state) {
    double sigma = sqrt(gamma) * sqrt(2.0);
    for (size_t i = 0; i < count; ++i) {
        double u1 = 1.0 - qihse_rff_uniform(random_state);
        double u2 = qihse_rff_uniform(random_state);
        double z0 = sqrt(-2.0 * log(u1)) * cos(2.0 * M_PI * u2);
        omega[i] = z0 * sigma;
    }
}

qihse_rff_kernel_t* qihse_rff_create(
    size_t input_dims,
    size_t output_dims,
    double gamma,
    uint64_t seed
) {
    if (input_dims == 0 || output_dims == 0 || !isfinite(gamma) || gamma <= 0.0) {
        errno = EINVAL;
        return NULL;
    }
    if (output_dims > SIZE_MAX / sizeof(double) ||
        input_dims > SIZE_MAX / sizeof(double) / output_dims) {
        errno = EOVERFLOW;
        return NULL;
    }
    const size_t frequency_count = output_dims * input_dims;

    qihse_rff_kernel_t* kernel = calloc(1, sizeof(qihse_rff_kernel_t));
    if (!kernel) return NULL;

    kernel->input_dims = input_dims;
    kernel->output_dims = output_dims;
    kernel->gamma = gamma;
    kernel->seed = seed;

    /* Allocate matrices */
    kernel->omega = malloc(frequency_count * sizeof(double));
    kernel->bias = malloc(output_dims * sizeof(double));

    if (!kernel->omega || !kernel->bias) {
        qihse_rff_destroy(kernel);
        return NULL;
    }

    uint64_t random_state = seed;

    qihse_rff_fill_frequencies(kernel->omega, frequency_count, gamma, &random_state);

    /* Generate random biases */
    for (size_t i = 0; i < output_dims; i++) {
        kernel->bias[i] = 2.0 * M_PI * qihse_rff_uniform(&random_state);
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
    if (!kernel || !input || !output || !kernel->omega || !kernel->bias ||
        kernel->input_dims == 0 || kernel->output_dims == 0 ||
        kernel->output_dims > SIZE_MAX / sizeof(double) ||
        kernel->input_dims > SIZE_MAX / sizeof(double) / kernel->output_dims) return;

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

/* The method belongs to the map, so a caller cannot accidentally project a
 * paired basis through the legacy cosine ABI. No legacy struct is extended. */
struct qihse_rff_map_s {
    qihse_rff_map_descriptor_t descriptor;
    qihse_rff_kernel_t* kernel;
    size_t storage_bytes;
};

qihse_rff_map_t* qihse_rff_map_create(size_t input_dims, size_t output_dims,
                                     double gamma, uint64_t seed,
                                     qihse_rff_method_t method) {
    if (!input_dims || !output_dims || !isfinite(gamma) || gamma <= 0.0 ||
        (method != QIHSE_RFF_COSINE_PHASE && method != QIHSE_RFF_PAIRED_SINCOS) ||
        (method == QIHSE_RFF_PAIRED_SINCOS && output_dims % 2 != 0)) {
        errno = EINVAL;
        return NULL;
    }
    size_t frequencies = method == QIHSE_RFF_PAIRED_SINCOS ? output_dims / 2 : output_dims;
    if (output_dims > SIZE_MAX / sizeof(double) ||
        input_dims > SIZE_MAX / sizeof(double) / frequencies) {
        errno = EOVERFLOW;
        return NULL;
    }
    size_t omega_bytes = frequencies * input_dims * sizeof(double);
    size_t bias_bytes = method == QIHSE_RFF_COSINE_PHASE ? frequencies * sizeof(double) : 0;
    size_t metadata_bytes = sizeof(qihse_rff_map_t) + sizeof(qihse_rff_kernel_t);
    if (omega_bytes > SIZE_MAX - bias_bytes || omega_bytes + bias_bytes > SIZE_MAX - metadata_bytes) {
        errno = EOVERFLOW;
        return NULL;
    }
    qihse_rff_map_t* map = calloc(1, sizeof(*map));
    if (!map) { errno = ENOMEM; return NULL; }
    map->descriptor.basis_version = QIHSE_RFF_BASIS_VERSION;
    map->descriptor.method = method;
    map->descriptor.input_dims = input_dims;
    map->descriptor.output_dims = output_dims;
    map->descriptor.gamma = gamma;
    map->descriptor.seed = seed;
    map->storage_bytes = metadata_bytes + omega_bytes + bias_bytes;
    if (method == QIHSE_RFF_COSINE_PHASE) {
        /* The phase method shares the exact legacy basis and projection. */
        map->kernel = qihse_rff_create(input_dims, output_dims, gamma, seed);
    } else {
        map->kernel = calloc(1, sizeof(*map->kernel));
        if (map->kernel) {
            map->kernel->input_dims = input_dims;
            /* This private kernel contains m frequencies, not D output slots. */
            map->kernel->output_dims = frequencies;
            map->kernel->gamma = gamma;
            map->kernel->seed = seed;
            map->kernel->omega = malloc(omega_bytes);
            if (map->kernel->omega) {
                uint64_t random_state = seed;
                qihse_rff_fill_frequencies(map->kernel->omega,
                    frequencies * input_dims, gamma, &random_state);
            }
        }
    }
    if (!map->kernel || !map->kernel->omega) {
        int error = errno ? errno : ENOMEM;
        qihse_rff_map_destroy(map);
        errno = error;
        return NULL;
    }
    return map;
}

void qihse_rff_map_destroy(qihse_rff_map_t* map) {
    if (!map) return;
    qihse_rff_destroy(map->kernel);
    free(map);
}

static int qihse_rff_map_projection_error(const qihse_rff_map_t* map, double* output,
                                          int error) {
    for (size_t i = 0; i < map->descriptor.output_dims; ++i) output[i] = NAN;
    errno = error;
    return -1;
}

int qihse_rff_map_project(const qihse_rff_map_t* map, const double* input, double* output) {
    if (!map || !input || !output) { errno = EINVAL; return -1; }
    size_t input_bytes = map->descriptor.input_dims * sizeof(double);
    size_t output_bytes = map->descriptor.output_dims * sizeof(double);
    uintptr_t input_start = (uintptr_t)input, output_start = (uintptr_t)output;
    if ((input_start <= output_start && output_start - input_start < input_bytes) ||
        (output_start < input_start && input_start - output_start < output_bytes)) {
        errno = EINVAL;
        return -1;
    }
    for (size_t i = 0; i < map->descriptor.input_dims; ++i)
        if (!isfinite(input[i])) return qihse_rff_map_projection_error(map, output, EDOM);
    if (map->descriptor.method == QIHSE_RFF_COSINE_PHASE) {
        qihse_rff_project(map->kernel, input, output);
        for (size_t i = 0; i < map->descriptor.output_dims; ++i)
            if (!isfinite(output[i])) return qihse_rff_map_projection_error(map, output, ERANGE);
    } else {
        size_t frequencies = map->descriptor.output_dims / 2;
        double scale = 1.0 / sqrt((double)frequencies);
        for (size_t row = 0; row < frequencies; ++row) {
            double phase = 0.0;
            for (size_t i = 0; i < map->descriptor.input_dims; ++i)
                phase += map->kernel->omega[row * map->descriptor.input_dims + i] * input[i];
            if (!isfinite(phase)) return qihse_rff_map_projection_error(map, output, ERANGE);
            output[2 * row] = scale * cos(phase);
            output[2 * row + 1] = scale * sin(phase);
        }
    }
    return 0;
}

size_t qihse_rff_map_input_dims(const qihse_rff_map_t* map) {
    return map ? map->descriptor.input_dims : 0;
}
size_t qihse_rff_map_output_dims(const qihse_rff_map_t* map) {
    return map ? map->descriptor.output_dims : 0;
}
size_t qihse_rff_map_storage_bytes(const qihse_rff_map_t* map) {
    return map ? map->storage_bytes : 0;
}
int qihse_rff_map_get_descriptor(const qihse_rff_map_t* map,
                                 qihse_rff_map_descriptor_t* descriptor,
                                 size_t descriptor_bytes) {
    if (!map || !descriptor || descriptor_bytes < sizeof(*descriptor)) {
        errno = EINVAL;
        return -1;
    }
    memcpy(descriptor, &map->descriptor, sizeof(*descriptor));
    return 0;
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
        pid_t pid = fork();
        if (pid == 0) {
            execlp("cpupower", "cpupower", "frequency-set", "-g", "performance", (char*)NULL);
            _exit(1);
        } else if (pid > 0) {
            int status; waitpid(pid, &status, 0);
        }
    } else {
        char freq_str[32];
        snprintf(freq_str, sizeof(freq_str), "%.0fMHz", target_frequency_mhz);
        pid_t pid = fork();
        if (pid == 0) {
            execlp("cpupower", "cpupower", "frequency-set", "-f", freq_str, (char*)NULL);
            _exit(1);
        } else if (pid > 0) {
            int status; waitpid(pid, &status, 0);
        }
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
    /* Iterative radix-2 Cooley-Tukey FFT (O(n log n)) */
    if (size == 0) return -EINVAL;

    /* Check if size is power of 2 */
    size_t sz = size;
    bool is_pow2 = (sz & (sz - 1)) == 0;
    if (!is_pow2) {
        /* Fall back to DFT for non-power-of-2 sizes */
        for (size_t k = 0; k < size; k++) {
            output[k] = 0.0;
            for (size_t n = 0; n < size; n++) {
                double angle = -2.0 * M_PI * (double)k * (double)n / (double)size;
                if (direction < 0) angle = -angle;
                output[k] += input[n] * cos(angle);
            }
        }
        return 0;
    }

    /* Bit-reversal permutation */
    size_t n = size;
    size_t bits = 0;
    while ((1u << bits) < n) bits++;

    /* Use separate real/imag arrays for the FFT computation */
    double* re = (double*)malloc(n * sizeof(double));
    double* im = (double*)malloc(n * sizeof(double));
    if (!re || !im) {
        free(re); free(im);
        return -ENOMEM;
    }

    for (size_t i = 0; i < n; i++) {
        size_t j = 0;
        size_t x = i;
        for (size_t b = 0; b < bits; b++) {
            j = (j << 1) | (x & 1);
            x >>= 1;
        }
        re[j] = input[i];
        im[j] = 0.0;
    }

    /* Butterfly operations */
    for (size_t len = 2; len <= n; len <<= 1) {
        double angle_step = -2.0 * M_PI / (double)len;
        if (direction < 0) angle_step = -angle_step;
        size_t half_len = len >> 1;
        for (size_t i = 0; i < n; i += len) {
            for (size_t j = 0; j < half_len; j++) {
                double angle = angle_step * (double)j;
                double wr = cos(angle);
                double wi = sin(angle);
                double tr = re[i + j + half_len] * wr - im[i + j + half_len] * wi;
                double ti = re[i + j + half_len] * wi + im[i + j + half_len] * wr;
                re[i + j + half_len] = re[i + j] - tr;
                im[i + j + half_len] = im[i + j] - ti;
                re[i + j] += tr;
                im[i + j] += ti;
            }
        }
    }

    /* Output magnitude (real part for real-valued input) */
    for (size_t k = 0; k < n; k++) {
        output[k] = re[k];
    }

    free(re);
    free(im);
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

/* The precision selector is retained for ABI compatibility.  Until an
 * approximation has a verified domain and error bound, all modes use libm.
 * This preserves IEEE-754 domain/range behavior and avoids evaluating an
 * expensive reference function merely to instrument an incorrect shortcut. */
double qihse_math_fast_exp(double x, qihse_math_precision_t precision) {
    (void)precision;
    return exp(x);
}

double qihse_math_fast_log(double x, qihse_math_precision_t precision) {
    (void)precision;
    return log(x);
}

double qihse_math_fast_sqrt(double x, qihse_math_precision_t precision) {
    (void)precision;
    return sqrt(x);
}

void qihse_math_fast_sincos(double x, double* sin_out, double* cos_out,
                           qihse_math_precision_t precision) {
    (void)precision;
    if (sin_out) *sin_out = sin(x);
    if (cos_out) *cos_out = cos(x);
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
