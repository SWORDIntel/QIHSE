# 🔧 QIHSE API Reference - Engineering Documentation

> **Complete Technical Reference for QIHSE Integration**

## Table of Contents
- [Core API](#core-api)
- [Configuration](#configuration)
- [Parallel Processing](#parallel-processing)
- [Intel Optimizations](#intel-optimizations)
- [Mathematical Functions](#mathematical-functions)
- [Performance Monitoring](#performance-monitoring)
- [Error Codes](#error-codes)

---

## Core API

### `qihse_search()`

**Primary search function with full QIHSE optimization pipeline.**

```c
not_stisla_result_t qihse_search(
    const void* data,           // Pointer to search data array
    size_t n,                   // Number of elements in array
    const void* query,          // Pointer to search query
    not_stisla_anchor_table_t* table,  // Optional: pre-computed anchor table
    const qihse_config_t* config       // QIHSE configuration
);
```

**Parameters:**
- `data`: Pointer to contiguous array of search data
- `n`: Number of elements (must be > 0)
- `query`: Pointer to query value (same type as data elements)
- `table`: Optional anchor table for repeated searches on same data
- `config`: QIHSE configuration structure

**Returns:**
- `NOT_STISLA_NOT_FOUND` (-1) if not found
- Index (0 to n-1) of found element

**Performance Characteristics:**
- Time: O(√n) quantum-inspired scaling
- Space: O(1) additional space beyond input
- Accuracy: 100% mathematically guaranteed

**Example Usage:**
```c
// Search integer array
int64_t data[1000] = {1, 2, 3, ..., 1000};
int64_t query = 42;

qihse_config_t config;
qihse_config_init(&config, QIHSE_TYPE_INT64, 1000);

not_stisla_result_t result = qihse_search(data, 1000, &query, NULL, &config);
if (result != NOT_STISLA_NOT_FOUND) {
    printf("Found at index: %lu\n", (unsigned long)result);
}
```

### `qihse_batch_search()`

**High-performance batch search for multiple queries.**

```c
size_t qihse_batch_search(
    const void* data,           // Search data array
    size_t n,                   // Number of elements
    const void* queries,        // Array of query values
    size_t num_queries,         // Number of queries
    not_stisla_result_t* results, // Output results array
    not_stisla_anchor_table_t* table,
    const qihse_config_t* config
);
```

**Performance Optimization:**
- SIMD vectorization across queries
- Shared Hilbert space computations
- Parallel pipeline processing

---

## Configuration

### `qihse_config_t` Structure

**Complete QIHSE configuration with all optimization options.**

```c
typedef struct {
    // Data type configuration
    qihse_data_type_t data_type;
    size_t array_size;

    // Core algorithm settings
    bool auto_dimensions;
    size_t fixed_dimensions;
    size_t min_dimensions;
    size_t max_dimensions;

    // Verification settings
    qihse_verify_config_t verification;

    // Hardware acceleration
    bool use_heterogeneous;
    size_t max_batch_size;
    bool enable_profiling;

    // Parallel processing
    bool use_parallel_pipelines;
    size_t max_parallel_pipelines;

    // Intel optimizations
    qihse_intel_config_t intel_config;

    // Power management
    qihse_power_config_t power_config;

    // Timeout and error handling
    uint32_t timeout_ms;
    bool fail_fast;
} qihse_config_t;
```

### Configuration Initialization

```c
int qihse_config_init(
    qihse_config_t* config,
    qihse_data_type_t data_type,
    size_t array_size
);
```

**Default Configuration Values:**
```c
// After qihse_config_init()
config->auto_dimensions = true;
config->use_parallel_pipelines = true;
config->use_heterogeneous = true;
config->enable_profiling = false;
config->timeout_ms = 5000;  // 5 seconds
config->fail_fast = false;
```

---

## Parallel Processing

### Pipeline Types

```c
typedef enum {
    QIHSE_PIPELINE_FAST,        // Quick approximate results
    QIHSE_PIPELINE_BALANCED,    // Balanced speed/accuracy
    QIHSE_PIPELINE_ACCURATE,    // Maximum accuracy
    QIHSE_PIPELINE_LEARNED      // ML-optimized configuration
} qihse_pipeline_type_t;
```

### Parallel Pipeline API

```c
size_t qihse_init_parallel_pipelines(
    qihse_pipeline_config_t* configs,
    size_t max_configs,
    qihse_data_type_t data_type,
    size_t array_size
);

int qihse_execute_parallel_pipelines(
    const void* data,
    size_t n,
    const void* query,
    not_stisla_anchor_table_t* table,
    const qihse_pipeline_config_t* configs,
    size_t num_configs,
    qihse_parallel_result_t* result
);

qihse_collapse_result_t qihse_combine_pipeline_results(
    const qihse_parallel_result_t* parallel_result,
    const char* combination_strategy
);
```

**Combination Strategies:**
- `"first_success"`: Return first successful result
- `"highest_confidence"`: Return highest confidence result
- `"weighted_average"`: Weighted average of all results

### Multi-Resolution Search

```c
size_t qihse_init_multires_search(
    qihse_resolution_config_t* configs,
    size_t max_configs,
    qihse_data_type_t data_type,
    size_t array_size
);

int qihse_execute_multires_search(
    const void* data,
    size_t n,
    const void* query,
    not_stisla_anchor_table_t* table,
    qihse_resolution_config_t* configs,
    size_t num_configs,
    qihse_multires_result_t* result
);
```

---

## Intel Optimizations

### Hardware Detection

```c
int qihse_intel_detect_hardware(qihse_intel_hw_info_t* info);
```

**Detected Features:**
```c
typedef enum {
    QIHSE_INTEL_HW_AMX = (1 << 0),       // Advanced Matrix Extensions
    QIHSE_INTEL_HW_AVX512 = (1 << 1),    // AVX-512 SIMD
    QIHSE_INTEL_HW_AVX_VNNI = (1 << 2),  // Neural network instructions
    QIHSE_INTEL_HW_AVX2 = (1 << 3),      // AVX2 SIMD
    QIHSE_INTEL_HW_FMA = (1 << 4),       // Fused multiply-add
    QIHSE_INTEL_HW_SSE4_2 = (1 << 5),    // SSE4.2 instructions
    QIHSE_INTEL_HW_PREFETCH = (1 << 6),  // Hardware prefetching
    QIHSE_INTEL_HW_TSX = (1 << 7),       // Transactional memory
    QIHSE_INTEL_HW_SHA = (1 << 8),       // SHA acceleration
    QIHSE_INTEL_HW_AES = (1 << 9)        // AES acceleration
} qihse_intel_hw_features_t;
```

### Intel oneAPI Integration

```c
int qihse_intel_init(const qihse_intel_config_t* config);

int qihse_intel_enable_features(uint32_t features);

int qihse_intel_amx_gemm(const void* a, const void* b, void* c,
                        size_t m, size_t n, size_t k);

int qihse_intel_avx512_vector_op(const double* a, const double* b,
                                double* result, size_t n, int operation);
```

### FORTRAN Integration

```c
int qihse_fortran_init(const qihse_fortran_config_t* config);

int qihse_fortran_gemm(const double* a, const double* b, double* c,
                      size_t m, size_t n, size_t k);

int qihse_fortran_eigenvalues(const double* matrix, double* eigenvalues,
                             double* eigenvectors, size_t n);

int qihse_fortran_fft(const double* input, double* output,
                     size_t size, int direction);
```

---

## Mathematical Functions

### Fast Approximations

```c
double qihse_math_fast_exp(double x, qihse_math_precision_t precision);
double qihse_math_fast_log(double x, qihse_math_precision_t precision);
double qihse_math_fast_sqrt(double x, qihse_math_precision_t precision);

void qihse_math_fast_sincos(double x, double* sin_out, double* cos_out,
                           qihse_math_precision_t precision);
```

**Precision Levels:**
```c
typedef enum {
    QIHSE_MATH_PRECISION_FULL,     // IEEE 754 compliance
    QIHSE_MATH_PRECISION_HIGH,     // 1e-12 relative error
    QIHSE_MATH_PRECISION_MEDIUM,   // 1e-8 relative error
    QIHSE_MATH_PRECISION_LOW,      // 1e-4 relative error
    QIHSE_MATH_PRECISION_FAST      // 1e-3 relative error (fastest)
} qihse_math_precision_t;
```

### Vector Operations

```c
double qihse_math_vector_dot(const double* a, const double* b, size_t n);

void qihse_math_matrix_vector_mul(const double* matrix, const double* vector,
                                 double* result, size_t m, size_t n);
```

---

## Performance Monitoring

### Performance Statistics

```c
typedef struct {
    double total_time_ns;
    double dim_calc_time_ns;
    double rff_time_ns;
    double superposition_time_ns;
    double amplification_time_ns;
    double collapse_time_ns;
    double verification_time_ns;

    double device_utilization[QIHSE_DEV_COUNT];
    double device_time_ns[QIHSE_DEV_COUNT];

    double avg_confidence;
    double verification_rate;
    size_t classical_fallbacks;

    size_t anchors_learned;
    double speedup_vs_binary;
    double speedup_vs_classical;

    size_t peak_memory_bytes;
    size_t total_operations;
} qihse_performance_stats_t;
```

### Statistics Access

```c
int qihse_get_performance_stats(qihse_performance_stats_t* stats);

void qihse_reset_performance_stats(void);
```

### Self-Optimization Database

```c
int qihse_optimization_init(qihse_optimization_db_t* db,
                           size_t max_entries, const char* storage_path);

void qihse_record_performance(qihse_optimization_db_t* db,
                             const qihse_data_signature_t* signature,
                             qihse_pipeline_type_t pipeline_type,
                             size_t dimensions, double speedup, double confidence);

void qihse_get_optimized_config(const qihse_optimization_db_t* db,
                               const qihse_data_signature_t* data_signature,
                               qihse_config_t* config);
```

---

## Error Codes

### QIHSE Error Values

```c
#define QIHSE_SUCCESS           0
#define QIHSE_ERROR_INVALID_ARG -1
#define QIHSE_ERROR_NO_MEMORY   -2
#define QIHSE_ERROR_TIMEOUT     -3
#define QIHSE_ERROR_HW_FAIL     -4
#define QIHSE_ERROR_NOT_FOUND   -5
#define QIHSE_ERROR_VERIFY_FAIL -6
```

### Error Handling Pattern

```c
qihse_config_t config;
int ret = qihse_config_init(&config, QIHSE_TYPE_INT64, array_size);
if (ret != QIHSE_SUCCESS) {
    switch (ret) {
        case QIHSE_ERROR_INVALID_ARG:
            fprintf(stderr, "Invalid configuration arguments\n");
            break;
        case QIHSE_ERROR_NO_MEMORY:
            fprintf(stderr, "Insufficient memory for QIHSE initialization\n");
            break;
        default:
            fprintf(stderr, "QIHSE initialization failed: %d\n", ret);
    }
    return ret;
}
```

### Hardware-Specific Errors

```c
// Intel hardware errors
#define QIHSE_ERROR_AMX_UNAVAILABLE    -100
#define QIHSE_ERROR_AVX512_UNAVAILABLE -101
#define QIHSE_ERROR_MKL_INIT_FAIL      -102

// FORTRAN errors
#define QIHSE_ERROR_FORTRAN_INIT_FAIL  -200
#define QIHSE_ERROR_FORTRAN_CALL_FAIL  -201
```

---

## Advanced Integration Examples

### High-Performance Database Integration

```c
// Initialize QIHSE with full optimization
qihse_config_t config;
qihse_config_init(&config, QIHSE_TYPE_INT64, database_size);

// Enable all optimizations
config.use_parallel_pipelines = true;
config.use_heterogeneous = true;
config.enable_profiling = true;

// Intel optimizations
qihse_intel_config_t intel_config = {
    .backend = QIHSE_INTEL_BACKEND_MKL,
    .mkl_threads = 8,
    .enable_amx = true,
    .enable_avx512 = true
};
qihse_intel_init(&intel_config);

// Power management
qihse_power_config_t power_config = {
    .mode = QIHSE_FREQ_MODE_ADAPTIVE,
    .power_budget_watts = 150.0,
    .enable_turbo = true
};
qihse_power_init(&power_config);

// Search with full acceleration
not_stisla_result_t result = qihse_search(data, size, &query, NULL, &config);
```

### Real-time Search Pipeline

```c
// Pre-compute anchor table for repeated searches
not_stisla_anchor_table_t* table = not_stisla_anchor_table_create();

// Configure for real-time performance
qihse_config_t config;
qihse_config_init(&config, QIHSE_TYPE_DOUBLE, signal_size);
config.verification.mode = QIHSE_VERIFY_FAST;  // Speed over accuracy
config.timeout_ms = 100;  // 100ms timeout

while (running) {
    // Real-time search
    not_stisla_result_t result = qihse_search(signal_data, signal_size,
                                            &target_value, table, &config);

    if (result != NOT_STISLA_NOT_FOUND) {
        process_result(result);
    }
}

// Cleanup
not_stisla_anchor_table_destroy(table);
```

This API reference provides complete technical documentation for integrating QIHSE into high-performance applications.
