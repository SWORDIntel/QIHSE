/*
 * QIHSE - Parallel Execution Orchestrator
 *
 * Orchestrates parallel execution across heterogeneous devices.
 *
 * Version: 1.0.0
 * Author: DSMIL System
 * License: MIT
 */

#ifndef QIHSE_ORCHESTRATOR_H
#define QIHSE_ORCHESTRATOR_H

#include "qihse_hetero.h"
#include "qihse_partition.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * EXECUTION ORCHESTRATOR
 * ============================================================================ */

/**
 * Execution orchestrator for parallel heterogeneous computing.
 */
typedef struct qihse_orchestrator_s* qihse_orchestrator_t;

/**
 * Create execution orchestrator.
 *
 * @param pool Heterogeneous compute pool
 * @param strategy Default partitioning strategy
 * @return Orchestrator handle, or NULL on failure
 */
qihse_orchestrator_t qihse_orchestrator_create(
    qihse_hetero_pool_t pool,
    qihse_partition_strategy_t strategy
);

/**
 * Destroy execution orchestrator.
 *
 * @param orchestrator Orchestrator to destroy
 */
void qihse_orchestrator_destroy(qihse_orchestrator_t orchestrator);

/**
 * Execute work batch with automatic partitioning and orchestration.
 *
 * @param orchestrator Execution orchestrator
 * @param batch Work batch to execute
 * @param strategy Partitioning strategy (use QIHSE_PARTITION_GREEDY for default)
 * @return 0 on success, negative error code on failure
 */
int qihse_orchestrator_execute(
    qihse_orchestrator_t orchestrator,
    qihse_work_batch_t* batch,
    qihse_partition_strategy_t strategy
);

/**
 * Execute work batch with explicit partitioning.
 *
 * @param orchestrator Execution orchestrator
 * @param batch Work batch to execute
 * @param partitions Pre-computed device assignments
 * @return 0 on success, negative error code on failure
 */
int qihse_orchestrator_execute_partitioned(
    qihse_orchestrator_t orchestrator,
    qihse_work_batch_t* batch,
    const qihse_device_type_t* partitions
);

/* ============================================================================
 * ASYNC EXECUTION
 * ============================================================================ */

/**
 * Asynchronous execution handle.
 */
typedef struct qihse_async_handle_s* qihse_async_handle_t;

/* ============================================================================
 * PARALLEL EXECUTION CONFIGURATION
 * ============================================================================ */


/* ============================================================================
 * EXECUTION ORCHESTRATOR
 * ============================================================================ */
typedef enum qihse_aggregation_method_e {
    QIHSE_AGGREGATION_WEIGHTED_VOTING = 0,    /* Weighted voting based on device confidence */
    QIHSE_AGGREGATION_PHASE_INTERFERENCE = 1, /* Quantum-inspired phase interference */
    QIHSE_AGGREGATION_BAYESIAN_FUSION = 2,    /* Bayesian probability fusion */
    QIHSE_AGGREGATION_NEURAL_COMBINATION = 3, /* Neural network combination */
    QIHSE_AGGREGATION_ADAPTIVE = 4            /* Adaptive method selection */
} qihse_aggregation_method_t;

/**
 * Parallel execution configuration.
 */
typedef struct qihse_parallel_config_s {
    qihse_aggregation_method_t aggregation_method; /* Aggregation method to use */
    size_t max_parallel_devices;               /* Maximum devices to use simultaneously */
    int hardware_accelerated;                  /* Use hardware acceleration for aggregation */
    int adaptive_rebalancing;                  /* Enable adaptive load rebalancing */
    double rebalance_threshold;                /* Load imbalance threshold for rebalancing */
} qihse_parallel_config_t;

/**
 * Execute work batch with parallel execution and advanced aggregation.
 *
 * @param orchestrator Execution orchestrator
 * @param batch Work batch to execute
 * @param strategy Partitioning strategy
 * @param parallel_config Parallel execution configuration
 * @param results Output buffer for results
 * @param max_results Maximum number of results to return
 * @param num_results Output: actual number of results returned
 * @return 0 on success, negative error code on failure
 */
int qihse_orchestrator_execute_parallel(
    qihse_orchestrator_t orchestrator,
    qihse_work_batch_t* batch,
    qihse_partition_strategy_t strategy,
    const qihse_parallel_config_t* parallel_config,
    qihse_search_result_t* results,
    size_t max_results,
    size_t* num_results
);

/**
 * Start asynchronous execution.
 *
 * @param orchestrator Execution orchestrator
 * @param batch Work batch to execute asynchronously
 * @param strategy Partitioning strategy
 * @return Async handle, or NULL on failure
 */
qihse_async_handle_t qihse_orchestrator_execute_async(
    qihse_orchestrator_t orchestrator,
    qihse_work_batch_t* batch,
    qihse_partition_strategy_t strategy
);

/**
 * Wait for asynchronous execution to complete.
 *
 * @param handle Async execution handle
 * @return 0 on success, negative error code on failure
 */
int qihse_orchestrator_wait_async(qihse_async_handle_t handle);

/**
 * Cancel asynchronous execution.
 *
 * @param handle Async execution handle
 * @return 0 on success, negative error code on failure
 */
int qihse_orchestrator_cancel_async(qihse_async_handle_t handle);

/**
 * Get status of asynchronous execution.
 *
 * @param handle Async execution handle
 * @param completed Output: true if completed
 * @param progress Output: completion progress (0.0 to 1.0)
 * @return 0 on success, negative error code on failure
 */
int qihse_orchestrator_get_async_status(
    qihse_async_handle_t handle,
    bool* completed,
    double* progress
);

/* ============================================================================
 * PERFORMANCE TUNING
 * ============================================================================ */

/**
 * Performance tuning hints for execution.
 */
typedef struct qihse_tuning_hints_s {
    bool prefer_low_latency;         /* Prefer low latency over high throughput */
    bool prefer_energy_efficiency;   /* Prefer energy-efficient devices */
    bool allow_approximate;          /* Allow approximate computing for speed */
    double max_memory_usage_mb;      /* Maximum memory usage per device */
    size_t max_concurrent_ops;       /* Maximum concurrent operations */
} qihse_tuning_hints_t;

/**
 * Set performance tuning hints.
 *
 * @param orchestrator Execution orchestrator
 * @param hints Tuning hints
 * @return 0 on success, negative error code on failure
 */
int qihse_orchestrator_set_tuning_hints(
    qihse_orchestrator_t orchestrator,
    const qihse_tuning_hints_t* hints
);

/**
 * Get current performance tuning hints.
 *
 * @param orchestrator Execution orchestrator
 * @param hints Output tuning hints
 * @return 0 on success, negative error code on failure
 */
int qihse_orchestrator_get_tuning_hints(
    qihse_orchestrator_t orchestrator,
    qihse_tuning_hints_t* hints
);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* QIHSE_ORCHESTRATOR_H */
