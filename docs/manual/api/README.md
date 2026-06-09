# QIHSE API Reference

This document provides comprehensive API documentation for the QIHSE (Quantum-Inspired Hilbert Space Expansion) search ecosystem.

## Table of Contents

1. [Core API](#core-api)
2. [Configuration API](#configuration-api)
3. [Search Operations](#search-operations)
4. [Backend Management](#backend-management)
5. [Memory Management](#memory-management)
6. [ML Engine API](#ml-engine-api)
7. [Benchmarking API](#benchmarking-api)
8. [Distributed Systems API](#distributed-systems-api)
9. [Error Codes](#error-codes)
10. [Data Types](#data-types)
11. [Native Vector DB API](#native-vector-db-api)

## Core API

### Initialization and Cleanup

```c
#include <qihse/qihse.h>

// Initialize QIHSE search context
qihse_search_context_t* qihse_search_init(void);

// Destroy search context
void qihse_search_destroy(qihse_search_context_t* ctx);

// Get library version
const char* qihse_version(void);

// Get build information
const qihse_build_info_t* qihse_build_info(void);
```

### Configuration Structures

```c
typedef struct qihse_config_s {
    // Hardware backends
    bool enable_cpu_avx2;          // Enable AVX2 SIMD
    bool enable_cpu_avx512;        // Enable AVX-512 SIMD
    bool enable_cpu_amx;           // Enable AMX tiles
    bool enable_npu;               // Enable Neural Processing Unit
    bool enable_gpu_intel;         // Enable Intel Arc GPU
    bool enable_gpu_nvidia;        // Enable NVIDIA GPU

    // Quantum-inspired settings
    uint32_t rff_dimension;        // RFF Hilbert space dimension
    double rff_gamma;             // RFF kernel parameter
    qihse_quantum_mode_t quantum_mode; // Quantum algorithm mode

    // Verification settings
    qihse_verify_mode_t verification_mode; // Verification level
    double confidence_threshold;   // Minimum confidence threshold
    uint32_t max_verification_time_ms; // Max verification time

    // Memory settings
    size_t max_memory_mb;         // Maximum memory usage
    bool enable_uma;              // Enable Unified Memory Architecture
    qihse_memory_policy_t memory_policy; // Memory management policy

    // ML settings
    bool enable_self_optimization; // Enable self-optimizing runtime
    uint32_t ml_batch_size;       // ML training batch size
    double ml_learning_rate;      // ML learning rate

    // Energy settings
    bool enable_energy_aware;     // Enable energy-aware optimization
    uint32_t max_power_watts;     // Maximum power budget
    double thermal_limit_celsius; // Thermal throttling limit

    // Distributed settings
    bool enable_distributed;      // Enable distributed execution
    const char* cluster_name;     // Cluster name for discovery
    uint16_t cluster_port;        // Cluster communication port

    // Security settings
    qihse_security_level_t security_level; // CNSA 2.0 compliance level
    const char* key_store_path;   // Path to secure key store
} qihse_config_t;
```

## Configuration API

### Configuration Management

```c
// Create default configuration
qihse_config_t* qihse_config_default(void);

// Load configuration from file
qihse_config_t* qihse_config_load(const char* config_file);

// Save configuration to file
int qihse_config_save(const qihse_config_t* config, const char* config_file);

// Validate configuration
int qihse_config_validate(const qihse_config_t* config, qihse_error_info_t* error);

// Free configuration
void qihse_config_free(qihse_config_t* config);

// Get configuration description
const char* qihse_config_describe(const qihse_config_t* config);
```

### Runtime Configuration Updates

```c
// Update configuration at runtime
int qihse_config_update(qihse_search_context_t* ctx, const qihse_config_t* new_config);

// Get current configuration
const qihse_config_t* qihse_config_get(const qihse_search_context_t* ctx);

// Check if configuration change requires restart
bool qihse_config_requires_restart(const qihse_config_t* current, const qihse_config_t* new_config);
```

## Search Operations

### Dataset Management

```c
// Load vector dataset
int qihse_search_load_vectors(qihse_search_context_t* ctx,
                              const char* dataset_path,
                              qihse_vector_format_t format,
                              const qihse_config_t* config);

// Load graph dataset
int qihse_search_load_graph(qihse_search_context_t* ctx,
                            const char* dataset_path,
                            qihse_graph_format_t format,
                            const qihse_config_t* config);

// Unload dataset
void qihse_search_unload(qihse_search_context_t* ctx);

// Get dataset statistics
int qihse_search_get_stats(const qihse_search_context_t* ctx,
                           qihse_dataset_stats_t* stats);
```

### Vector Search Operations

```c
// Single vector search
int qihse_search_vector(qihse_search_context_t* ctx,
                        const float* query_vector,
                        uint32_t k,
                        uint32_t* result_ids,
                        float* result_distances);

// Batch vector search
int qihse_search_vector_batch(qihse_search_context_t* ctx,
                              const float* query_vectors,
                              uint32_t num_queries,
                              uint32_t k,
                              uint32_t* result_ids,
                              float* result_distances,
                              uint32_t* result_counts);

// Approximate nearest neighbor search
int qihse_search_ann(qihse_search_context_t* ctx,
                     const float* query_vector,
                     uint32_t k,
                     float epsilon,
                     uint32_t* result_ids,
                     float* result_distances);

// Range search
int qihse_search_range(qihse_search_context_t* ctx,
                       const float* query_vector,
                       float radius,
                       uint32_t max_results,
                       uint32_t* result_ids,
                       float* result_distances,
                       uint32_t* num_results);
```

### Native Vector DB API

The native QIHSE vector DB API provides trinary/qmag candidate modes and file-backed persistence.

```c
#include "qihse_vector_db.h"

typedef enum qihse_vector_db_query_mode_e {
    QIHSE_VDB_QUERY_FLOAT32 = 0,
    QIHSE_VDB_QUERY_TRINARY_SCALAR = 1,
    QIHSE_VDB_QUERY_TRINARY_MAGNITUDE_BYPASS = 3,
    QIHSE_VDB_QUERY_GRAPH = 4,
    QIHSE_VDB_QUERY_INT8 = 5,
    QIHSE_VDB_QUERY_SPARSE = 6,
    QIHSE_VDB_QUERY_FP16 = 7,
    QIHSE_VDB_QUERY_FP32 = 8,
    QIHSE_VDB_QUERY_FP8 = 9,
    QIHSE_VDB_QUERY_FP4 = 10,
    QIHSE_VDB_QUERY_INT4 = 11,
} qihse_vector_db_query_mode_t;

qihse_vector_db_t qihse_vector_db_open(
    qihse_vector_db_backend_t backend,
    qihse_uma_manager_t uma,
    const char* db_path,
    uint32_t flags);

int qihse_vector_db_search(
    qihse_vector_db_t vdb,
    const qihse_vector_query_t* query,
    qihse_vector_result_t* results,
    size_t max_results);

// Build optional low-precision and explicit sidecars
bool qihse_vector_db_build_fp16(qihse_vector_db_t vdb);
bool qihse_vector_db_build_fp32(qihse_vector_db_t vdb);
bool qihse_vector_db_build_fp8(qihse_vector_db_t vdb);
bool qihse_vector_db_build_fp4(qihse_vector_db_t vdb);
bool qihse_vector_db_build_int4(qihse_vector_db_t vdb);
```

- `QIHSE_VDB_QUERY_FLOAT32` uses authoritative exact float32 search and ignores
  sidecar failures.
- `QIHSE_VDB_QUERY_TRINARY_SCALAR` and
  `QIHSE_VDB_QUERY_TRINARY_MAGNITUDE` use sidecars for candidate reduction and
  exact float32 rerank.
- `QIHSE_VDB_QUERY_TRINARY_MAGNITUDE_BYPASS` uses qmag-only ordering for fast
  approximate results; scores are qmag scores, not cosine.
- Explicit trinary modes fail when sidecars are absent/corrupt/stale rather than
  silently falling back.
- **Security Note:** All native memory quantization builders (`FP8`, `FP4`, `INT4`, `INT8`, `FP16`) perform fully resilient `size_t` overflow assertions on payload allocation boundaries and have been thoroughly redteamed against `SIZE_MAX` memory and sub-byte array boundary corruption exploits.
- `candidate_pool_size = 0` enables the safe default policy for qmag; qmag default
  may still fall back to exact float32 when policy gates deny it.
- `QIHSE_VDB_QUERY_TRINARY_MAGNITUDE_BYPASS` never falls back to exact float32.

### Graph Search Operations

```c
// Graph traversal search
int qihse_search_graph(qihse_search_context_t* ctx,
                       uint32_t start_node,
                       qihse_graph_search_mode_t mode,
                       uint32_t max_depth,
                       uint32_t* result_nodes,
                       uint32_t* result_distances,
                       uint32_t* num_results);

// Shortest path search
int qihse_search_shortest_path(qihse_search_context_t* ctx,
                               uint32_t start_node,
                               uint32_t end_node,
                               uint32_t* path_nodes,
                               uint32_t* path_length,
                               uint32_t max_path_length);
```

### Constraint Search Operations

```c
// Traveling salesman problem
int qihse_search_tsp(qihse_search_context_t* ctx,
                     const qihse_tsp_config_t* tsp_config,
                     qihse_tsp_solution_t* solution);

// Job shop scheduling
int qihse_search_jobshop(qihse_search_context_t* ctx,
                         const qihse_jobshop_config_t* js_config,
                         qihse_jobshop_solution_t* solution);

// Knapsack optimization
int qihse_search_knapsack(qihse_search_context_t* ctx,
                          const qihse_knapsack_config_t* ks_config,
                          qihse_knapsack_solution_t* solution);
```

## Backend Management

### Backend Discovery and Selection

```c
// Discover available backends
int qihse_backend_discover(qihse_search_context_t* ctx);

// Get backend capabilities
int qihse_backend_get_capabilities(qihse_search_context_t* ctx,
                                   qihse_backend_type_t backend_type,
                                   qihse_backend_caps_t* capabilities);

// Select backend for operation
int qihse_backend_select(qihse_search_context_t* ctx,
                         qihse_operation_type_t operation,
                         qihse_backend_type_t* selected_backend);

// Get backend performance metrics
int qihse_backend_get_metrics(qihse_search_context_t* ctx,
                              qihse_backend_type_t backend_type,
                              qihse_backend_metrics_t* metrics);
```

### Backend-Specific Operations

```c
// CPU backend operations
int qihse_cpu_avx2_execute(qihse_search_context_t* ctx, qihse_operation_t* op);
int qihse_cpu_avx512_execute(qihse_search_context_t* ctx, qihse_operation_t* op);
int qihse_cpu_amx_execute(qihse_search_context_t* ctx, qihse_operation_t* op);

// NPU backend operations
int qihse_npu_openvino_execute(qihse_search_context_t* ctx, qihse_operation_t* op);
int qihse_npu_pim_execute(qihse_search_context_t* ctx, qihse_operation_t* op);

// GPU backend operations
int qihse_gpu_cuda_execute(qihse_search_context_t* ctx, qihse_operation_t* op);
int qihse_gpu_sycl_execute(qihse_search_context_t* ctx, qihse_operation_t* op);
```

## Memory Management

### UMA Memory Operations

```c
// Allocate unified memory
void* qihse_uma_alloc(qihse_search_context_t* ctx, size_t size, qihse_memory_flags_t flags);

// Free unified memory
void qihse_uma_free(qihse_search_context_t* ctx, void* ptr);

// Migrate memory between devices
int qihse_uma_migrate(qihse_search_context_t* ctx,
                      void* ptr,
                      qihse_device_type_t source_device,
                      qihse_device_type_t target_device);

// Prefetch memory to device
int qihse_uma_prefetch(qihse_search_context_t* ctx,
                       void* ptr,
                       size_t size,
                       qihse_device_type_t device);
```

### HMA Memory Operations

```c
// Allocate holographic memory
void* qihse_hma_alloc(qihse_search_context_t* ctx,
                      qihse_memory_tier_t tier,
                      size_t size);

// Free holographic memory
void qihse_hma_free(qihse_search_context_t* ctx, void* ptr);

// Get memory tier information
int qihse_hma_get_tier_info(qihse_search_context_t* ctx,
                            qihse_memory_tier_t tier,
                            qihse_tier_info_t* info);

// Optimize memory layout
int qihse_hma_optimize_layout(qihse_search_context_t* ctx);
```

## ML Engine API

### ML Engine Management

```c
// Initialize ML engine
int qihse_ml_init(qihse_search_context_t* ctx, const qihse_ml_config_t* config);

// Destroy ML engine
void qihse_ml_destroy(qihse_search_context_t* ctx);

// Process query with ML optimization
int qihse_ml_process_query(qihse_search_context_t* ctx,
                           qihse_query_t* query,
                           qihse_ml_decision_t* decision);

// Train ML models
int qihse_ml_train(qihse_search_context_t* ctx,
                   const qihse_training_data_t* training_data,
                   uint32_t epochs);

// Get ML engine statistics
int qihse_ml_get_stats(const qihse_search_context_t* ctx,
                       qihse_ml_stats_t* stats);
```

### Contextual Bandits

```c
// Initialize contextual bandit
qihse_contextual_bandit_t* qihse_cb_init(const qihse_cb_config_t* config);

// Destroy contextual bandit
void qihse_cb_destroy(qihse_contextual_bandit_t* cb);

// Select action based on context
int qihse_cb_select_arm(qihse_contextual_bandit_t* cb,
                        const qihse_context_t* context,
                        uint32_t* selected_arm);

// Update bandit with reward
int qihse_cb_update(qihse_contextual_bandit_t* cb,
                    uint32_t arm,
                    double reward,
                    const qihse_context_t* context);

// Get bandit statistics
int qihse_cb_get_stats(const qihse_contextual_bandit_t* cb,
                       qihse_cb_stats_t* stats);
```

### Meta-Learning

```c
// Initialize meta-optimizer
qihse_meta_optimizer_t* qihse_meta_init(const qihse_meta_config_t* config);

// Train on new task
int qihse_meta_train(qihse_meta_optimizer_t* meta,
                     const qihse_task_data_t* task_data,
                     uint32_t num_steps);

// Adapt to new task
int qihse_meta_adapt(qihse_meta_optimizer_t* meta,
                     const qihse_task_data_t* task_data,
                     uint32_t adaptation_steps);

// Get adaptation performance
double qihse_meta_get_performance(const qihse_meta_optimizer_t* meta);
```

## Benchmarking API

### Benchmark Execution

```c
// Initialize benchmark runner
qihse_benchmark_runner_t* qihse_benchmark_init(const qihse_benchmark_config_t* config);

// Run benchmark
int qihse_benchmark_run(qihse_benchmark_runner_t* runner,
                        qihse_workload_type_t workload_type,
                        qihse_benchmark_results_t* results);

// Run comparative benchmark
int qihse_benchmark_compare(qihse_benchmark_runner_t* runner,
                            const qihse_baseline_results_t* baseline,
                            qihse_comparison_report_t* report);

// Destroy benchmark runner
void qihse_benchmark_destroy(qihse_benchmark_runner_t* runner);
```

### Regression Detection

```c
// Initialize regression detector
qihse_regression_detector_t* qihse_regression_init(const qihse_regression_config_t* config);

// Add performance measurement
int qihse_regression_add_measurement(qihse_regression_detector_t* detector,
                                     const qihse_performance_metrics_t* metrics);

// Detect regression
qihse_regression_status_t qihse_regression_detect(qihse_regression_detector_t* detector);

// Get regression statistics
int qihse_regression_get_stats(const qihse_regression_detector_t* detector,
                               qihse_regression_stats_t* stats);
```

## Distributed Systems API

### Distributed Management

```c
// Initialize distributed manager
qihse_distributed_manager_t* qihse_distributed_init(uint32_t local_node_id,
                                                    const char* hostname,
                                                    uint16_t port);

// Join cluster
int qihse_distributed_join_cluster(qihse_distributed_manager_t* manager,
                                   const char* seed_hostname,
                                   uint16_t seed_port);

// Leave cluster
int qihse_distributed_leave_cluster(qihse_distributed_manager_t* manager);

// Get cluster statistics
int qihse_distributed_get_stats(const qihse_distributed_manager_t* manager,
                                uint32_t* num_nodes,
                                uint32_t* leader_id,
                                double* avg_latency);
```

### Message Passing

```c
// Send message
int qihse_distributed_send_message(qihse_distributed_manager_t* manager,
                                   uint32_t target_node_id,
                                   const qihse_distributed_message_t* message);

// Broadcast message
int qihse_distributed_broadcast_message(qihse_distributed_manager_t* manager,
                                        const qihse_distributed_message_t* message);

// Synchronize state
int qihse_distributed_sync_state(qihse_distributed_manager_t* manager,
                                 uint32_t timeout_ms);
```

## Error Codes

```c
typedef enum qihse_error_e {
    QIHSE_SUCCESS = 0,              // Operation successful
    QIHSE_ERROR_INVALID_ARGUMENT,   // Invalid argument provided
    QIHSE_ERROR_OUT_OF_MEMORY,      // Memory allocation failed
    QIHSE_ERROR_IO,                 // I/O operation failed
    QIHSE_ERROR_TIMEOUT,            // Operation timed out
    QIHSE_ERROR_NOT_SUPPORTED,      // Operation not supported
    QIHSE_ERROR_HARDWARE,           // Hardware error occurred
    QIHSE_ERROR_SECURITY,           // Security violation
    QIHSE_ERROR_NETWORK,            // Network communication error
    QIHSE_ERROR_CONSISTENCY,        // Data consistency error
    QIHSE_ERROR_VERIFICATION,       // Verification failed
    QIHSE_ERROR_REGRESSION,         // Performance regression detected
    QIHSE_ERROR_DISTRIBUTED,        // Distributed system error
    QIHSE_ERROR_ML,                 // Machine learning error
    QIHSE_ERROR_QUANTUM,            // Quantum algorithm error
} qihse_error_t;
```

## Data Types

### Core Types

```c
typedef struct qihse_search_context_s qihse_search_context_t;  // Opaque search context
typedef struct qihse_distributed_manager_s qihse_distributed_manager_t; // Distributed manager
typedef struct qihse_benchmark_runner_s qihse_benchmark_runner_t; // Benchmark runner
typedef struct qihse_ml_engine_s qihse_ml_engine_t; // ML engine

typedef uint32_t qihse_id_t;           // Identifier type
typedef double qihse_score_t;          // Score/confidence type
typedef uint64_t qihse_timestamp_t;    // Timestamp type
```

### Enumeration Types

```c
typedef enum qihse_backend_type_e {
    QIHSE_BACKEND_CPU_AVX2,
    QIHSE_BACKEND_CPU_AVX512,
    QIHSE_BACKEND_CPU_AMX,
    QIHSE_BACKEND_NPU_OPENVINO,
    QIHSE_BACKEND_GPU_CUDA,
    QIHSE_BACKEND_GPU_SYCL
} qihse_backend_type_t;

typedef enum qihse_verify_mode_e {
    QIHSE_VERIFY_NONE,      // No verification
    QIHSE_VERIFY_FAST,      // Fast probabilistic verification
    QIHSE_VERIFY_WINDOW,    // Sliding window verification
    QIHSE_VERIFY_FALLBACK,  // Fallback verification
    QIHSE_VERIFY_EXACT,     // Exact deterministic verification
    QIHSE_VERIFY_PRECISION  // High-precision verification
} qihse_verify_mode_t;

typedef enum qihse_quantum_mode_e {
    QIHSE_QUANTUM_CLASSICAL,     // Classical algorithms only
    QIHSE_QUANTUM_HYBRID,        // Classical + quantum-inspired
    QIHSE_QUANTUM_PREFERRED,     // Prefer quantum when available
    QIHSE_QUANTUM_REQUIRED       // Require quantum hardware
} qihse_quantum_mode_t;
```

### Complex Structures

```c
typedef struct qihse_vector_s {
    uint32_t dimension;           // Vector dimension
    float* data;                  // Vector data
} qihse_vector_t;

typedef struct qihse_query_s {
    qihse_operation_type_t type;  // Query type
    union {
        qihse_vector_t vector;     // Vector query data
        qihse_graph_query_t graph; // Graph query data
        qihse_constraint_query_t constraint; // Constraint query data
    } data;
    qihse_verify_mode_t verification; // Verification level
    uint32_t timeout_ms;          // Query timeout
} qihse_query_t;

typedef struct qihse_result_s {
    qihse_id_t id;                // Result identifier
    qihse_score_t score;          // Result score/confidence
    qihse_timestamp_t timestamp;  // Result timestamp
    void* data;                   // Result-specific data
} qihse_result_t;
```

## Authorization API

The cell-level authorization system is embedded natively across all 8 storage engines, enforcing US/Five Eyes/SCI style compartmentation. By default, if no user context is provided (`NULL` passed to `_user` functions), the system grants **full access**.

### User Management and Initialization

```c
#include <qihse/qihse_auth.h>

// Initialize the authorization sub-system
void qihse_auth_init(void);

// Create a new user with specific clearance and compartment bitmask
qihse_user_t* qihse_auth_create_user(qihse_user_t* creator, uint32_t user_id, uint16_t role, uint16_t classif, uint16_t sci, const char* plaintext_password, bool requires_hw_token);

// Modify an existing user's internal settings natively (Requires Operator privileges)
bool qihse_auth_modify_user(qihse_user_t* operator_user, uint32_t target_user_id, const char* new_username, const char* new_password, int new_requires_hw_token, int new_can_create_users);

// Retrieve an existing user
qihse_user_t* qihse_auth_get_user(uint32_t user_id);

// Cleanup and destroy user
void qihse_auth_destroy_user(uint32_t user_id);

// Check if a user can access a specific classification and SCI compartment
bool qihse_auth_can_access(qihse_user_t* user, uint16_t data_classif, uint16_t data_sci);
```

### Authorization-Aware Data Operations
Engine-specific operations use the `_user` suffix or accept `classification` / `sci_compartment` to propagate boundaries.

```c
// KV Store 
bool qihse_kv_set(qihse_kv_store_t* store, const char* key, const char* value, uint64_t expire_time_ms, uint16_t classification, uint16_t sci_compartment);
char* qihse_kv_get_user(qihse_kv_store_t* store, const char* key, qihse_user_t* user);

// Time-Series Database
bool qihse_tsdb_insert(qihse_tsdb_t* tsdb, uint32_t series_id, uint64_t timestamp, double value, uint16_t classification, uint16_t sci_compartment);
double qihse_tsdb_average_range_user(qihse_tsdb_t* tsdb, uint64_t start_ts, uint64_t end_ts, qihse_user_t* user);

// Document Store
qihse_doc_result_t* qihse_doc_query_user(qihse_doc_store_t* store, const char* query_str, qihse_user_t* user);
```

For complete API documentation including all function signatures, parameter descriptions, return values, and usage examples, see the individual header files in the `include/` directories of each component.
