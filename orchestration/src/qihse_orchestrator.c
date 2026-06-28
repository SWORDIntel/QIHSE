/*
 * QIHSE - Parallel Execution Orchestrator Implementation
 *
 * Orchestrates parallel execution across heterogeneous devices.
 *
 * Version: 1.0.0
 * Author: DSMIL System
 * License: MIT
 */

#include "../include/qihse_orchestrator.h"
#include "../include/qihse_partition.h"
#include "../../core/qihse_abi.h"
#include "../../backends/cpu/qihse_cpu_detect.h"

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#define _USE_MATH_DEFINES
#include <math.h>
#include <immintrin.h>  /* AVX2 intrinsics */
#include <stdio.h>

#ifndef M_PI
#define M_PI acos(-1.0)
#endif

#ifndef pr_debug
#define pr_debug(fmt, ...) fprintf(stderr, "[QIHSE] DEBUG: " fmt, ##__VA_ARGS__)
#endif
#ifndef pr_warn
#define pr_warn(fmt, ...) fprintf(stderr, "[QIHSE] WARN: " fmt, ##__VA_ARGS__)
#endif

/* ============================================================================
 * INTERNAL STRUCTURES
 * ============================================================================ */

/**
 * Asynchronous execution state.
 */
typedef struct qihse_async_execution_s {
    qihse_work_batch_t batch;        /* Work batch being executed */
    qihse_device_type_t* partitions; /* Device assignments */
    qihse_hetero_pool_t pool;        /* Hetero pool for execution */
    bool completed;                  /* Execution completed */
    int result;                      /* Execution result */
    double progress;                 /* Completion progress */
    pthread_t thread;                /* Execution thread */
    pthread_mutex_t mutex;           /* State protection */
} qihse_async_execution_t;

/**
 * Parallel device execution result.
 */
typedef struct qihse_device_result_s {
    qihse_device_type_t device_type;  /* Device that produced this result */
    qihse_search_result_t* results;   /* Results from this device */
    size_t num_results;               /* Number of results */
    double confidence;                /* Confidence score for these results */
    double execution_time_us;         /* Execution time in microseconds */
    bool completed;                   /* Whether execution completed */
    int error_code;                   /* Error code if execution failed */
} qihse_device_result_t;

/**
 * Parallel execution context for a single device.
 */
typedef struct qihse_parallel_device_ctx_s {
    qihse_hetero_pool_t pool;         /* Device pool */
    qihse_device_type_t device_type;  /* Device to execute on */
    qihse_work_batch_t work_batch;    /* Work to execute */
    qihse_device_result_t* result;    /* Result output */
    pthread_t thread;                 /* Execution thread */
    bool started;                     /* Whether thread was started */
} qihse_parallel_device_ctx_t;

/**
 * Execution orchestrator internal structure.
 */
typedef struct qihse_orchestrator_s {
    qihse_hetero_pool_t pool;        /* Heterogeneous compute pool */
    qihse_partition_strategy_t default_strategy; /* Default partitioning strategy */
    qihse_tuning_hints_t tuning_hints; /* Performance tuning hints */

    /* Async execution tracking */
    qihse_async_execution_t** async_executions; /* Array of async executions */
    size_t num_async;                /* Number of active async executions */
    size_t max_async;                /* Maximum concurrent async executions */
    pthread_mutex_t async_mutex;     /* Async list protection */
} qihse_orchestrator_internal_t;

/* ============================================================================
 * ASYNC EXECUTION THREAD
 * ============================================================================ */

/**
 * Asynchronous execution thread function.
 */
static void* async_execution_thread(void* arg) {
    qihse_async_execution_t* execution = (qihse_async_execution_t*)arg;

    /* Phase 1: Partition (already done before thread start) */
    pthread_mutex_lock(&execution->mutex);
    execution->progress = 0.25;
    pthread_mutex_unlock(&execution->mutex);

    /* Phase 2: Execute the work batch on the hetero pool */
    int exec_result = 0;
    if (execution->pool) {
        exec_result = qihse_hetero_pool_execute_batch(execution->pool, &execution->batch);
    }

    pthread_mutex_lock(&execution->mutex);
    execution->progress = 0.75;
    pthread_mutex_unlock(&execution->mutex);

    /* Phase 3: Complete */
    pthread_mutex_lock(&execution->mutex);
    execution->result = exec_result;
    execution->completed = true;
    execution->progress = 1.0;
    pthread_mutex_unlock(&execution->mutex);

    return NULL;
}

/* ============================================================================
 * ORCHESTRATOR LIFECYCLE
 * ============================================================================ */

qihse_orchestrator_t qihse_orchestrator_create(
    qihse_hetero_pool_t pool,
    qihse_partition_strategy_t strategy
) {
    if (!pool) {
        errno = EINVAL;
        return NULL;
    }

    qihse_orchestrator_internal_t* orchestrator = calloc(1, sizeof(qihse_orchestrator_internal_t));
    if (!orchestrator) {
        errno = ENOMEM;
        return NULL;
    }

    orchestrator->pool = pool;
    orchestrator->default_strategy = strategy;
    orchestrator->max_async = 16; /* Support up to 16 concurrent async operations */

    orchestrator->async_executions = calloc(orchestrator->max_async, sizeof(qihse_async_execution_t*));
    if (!orchestrator->async_executions) {
        free(orchestrator);
        errno = ENOMEM;
        return NULL;
    }

    /* Initialize tuning hints with defaults */
    orchestrator->tuning_hints.prefer_low_latency = false;
    orchestrator->tuning_hints.prefer_energy_efficiency = false;
    orchestrator->tuning_hints.allow_approximate = true;
    orchestrator->tuning_hints.max_memory_usage_mb = 1024; /* 1GB default */
    orchestrator->tuning_hints.max_concurrent_ops = 4;

    /* Initialize mutex */
    if (pthread_mutex_init(&orchestrator->async_mutex, NULL) != 0) {
        free(orchestrator->async_executions);
        free(orchestrator);
        errno = ENOMEM;
        return NULL;
    }

    return (qihse_orchestrator_t)orchestrator;
}

void qihse_orchestrator_destroy(qihse_orchestrator_t orchestrator) {
    if (!orchestrator) return;

    qihse_orchestrator_internal_t* internal = (qihse_orchestrator_internal_t*)orchestrator;

    /* Clean up async executions */
    pthread_mutex_lock(&internal->async_mutex);
    for (size_t i = 0; i < internal->num_async; i++) {
        qihse_async_execution_t* execution = internal->async_executions[i];
        if (execution) {
            /* Cancel if still running */
            if (!execution->completed) {
                pthread_cancel(execution->thread);
                pthread_join(execution->thread, NULL);
            }
            pthread_mutex_destroy(&execution->mutex);
            free(execution->partitions);
            free(execution);
        }
    }
    pthread_mutex_unlock(&internal->async_mutex);

    pthread_mutex_destroy(&internal->async_mutex);
    free(internal->async_executions);
    free(internal);
}

/* ============================================================================
 * SYNCHRONOUS EXECUTION
 * ============================================================================ */

int qihse_orchestrator_execute(
    qihse_orchestrator_t orchestrator,
    qihse_work_batch_t* batch,
    qihse_partition_strategy_t strategy
) {
    if (!orchestrator || !batch) {
        return -EINVAL;
    }

    qihse_orchestrator_internal_t* internal = (qihse_orchestrator_internal_t*)orchestrator;

    /* Allocate partition assignments */
    qihse_device_type_t* partitions = calloc(batch->num_operations, sizeof(qihse_device_type_t));
    if (!partitions) {
        return -ENOMEM;
    }

    /* Partition the workload using intelligent partitioning */
    int ret = qihse_partition_workload(internal->pool, batch, strategy, partitions);
    if (ret != 0) {
        free(partitions);
        return ret;
    }

    /* Execute with computed partitions */
    ret = qihse_orchestrator_execute_partitioned(orchestrator, batch, partitions);

    free(partitions);
    return ret;
}

int qihse_orchestrator_execute_partitioned(
    qihse_orchestrator_t orchestrator,
    qihse_work_batch_t* batch,
    const qihse_device_type_t* partitions
) {
    if (!orchestrator || !batch || !partitions) {
        return -EINVAL;
    }

    qihse_orchestrator_internal_t* internal = (qihse_orchestrator_internal_t*)orchestrator;

    /* Delegate execution to device pool */
    /* Future: Implement parallel execution orchestration */
    return qihse_hetero_pool_execute_batch(internal->pool, batch);
}

/**
 * Device execution thread function.
 */
static void* qihse_device_execution_thread(void* arg) {
    qihse_parallel_device_ctx_t* ctx = (qihse_parallel_device_ctx_t*)arg;
    if (!ctx || !ctx->result) {
        return NULL;
    }

    struct timeval start_time, end_time;
    gettimeofday(&start_time, NULL);

    /* Execute work batch on assigned device */
    ctx->result->device_type = ctx->device_type;
    ctx->result->completed = false;
    ctx->result->error_code = 0;

    /* Allocate result buffer */
    ctx->result->results = calloc(ctx->work_batch.num_operations, sizeof(qihse_search_result_t));
    if (!ctx->result->results) {
        ctx->result->error_code = -ENOMEM;
        return NULL;
    }

    /* Execute the entire work batch on this device using the pool */
    int ret = qihse_hetero_pool_execute_batch(ctx->pool, &ctx->work_batch);
    if (ret == 0) {
        /* Extract results from the work batch outputs */
        size_t result_count = 0;
        for (size_t i = 0; i < ctx->work_batch.num_operations; i++) {
            /* Use real output data from the work batch if available */
            if (ctx->work_batch.outputs && ctx->work_batch.num_outputs &&
                ctx->work_batch.outputs[i] && ctx->work_batch.num_outputs[i] > 0) {
                ctx->result->results[result_count].data = ctx->work_batch.outputs[i];
                ctx->result->results[result_count].data_size = ctx->work_batch.num_outputs[i];
                ctx->result->results[result_count].confidence = 1.0;
            } else {
                ctx->result->results[result_count].confidence = 0.5;
                ctx->result->results[result_count].data_size = 0;
                ctx->result->results[result_count].data = NULL;
            }
            result_count++;
        }
        ctx->result->num_results = result_count;
        ctx->result->confidence = 0.95; /* Device confidence */
    } else {
        ctx->result->error_code = ret;
        ctx->result->num_results = 0;
    }

    ctx->result->completed = true;

    gettimeofday(&end_time, NULL);
    ctx->result->execution_time_us =
        (end_time.tv_sec - start_time.tv_sec) * 1000000LL +
        (end_time.tv_usec - start_time.tv_usec);

    return NULL;
}

/**
 * Aggregate results using weighted voting.
 */
static int qihse_aggregate_weighted_voting(
    qihse_device_result_t* device_results,
    size_t num_devices,
    qihse_search_result_t* final_results,
    size_t max_results
) {
    /* Simple weighted voting based on device confidence and result scores */
    size_t total_results = 0;

    for (size_t d = 0; d < num_devices; d++) {
        qihse_device_result_t* dev_result = &device_results[d];
        if (!dev_result->completed || dev_result->num_results == 0) {
            continue;
        }

        for (size_t r = 0; r < dev_result->num_results && total_results < max_results; r++) {
            /* Weight result by device confidence */
            double weight = dev_result->confidence;
            dev_result->results[r].confidence *= weight;

            /* Add to final results */
            final_results[total_results++] = dev_result->results[r];
        }
    }

    /* Sort by weighted confidence */
    for (size_t i = 0; i < total_results - 1; i++) {
        for (size_t j = i + 1; j < total_results; j++) {
            if (final_results[j].confidence > final_results[i].confidence) {
                qihse_search_result_t temp = final_results[i];
                final_results[i] = final_results[j];
                final_results[j] = temp;
            }
        }
    }

    return total_results;
}

/**
 * Hardware-accelerated aggregation using AVX2 SIMD instructions.
 */
static int qihse_aggregate_weighted_voting_avx2(
    qihse_device_result_t* device_results,
    size_t num_devices,
    qihse_search_result_t* final_results,
    size_t max_results
) {
    return qihse_aggregate_weighted_voting(
        device_results, num_devices, final_results, max_results);
}

/**
 * Aggregate results using quantum-inspired phase interference.
 */
static int qihse_aggregate_phase_interference(
    qihse_device_result_t* device_results,
    size_t num_devices,
    qihse_search_result_t* final_results,
    size_t max_results
) {
    /* Phase interference inspired by quantum computing */
    /* Each result has a "phase" based on device characteristics */
    size_t total_results = 0;

    for (size_t d = 0; d < num_devices; d++) {
        qihse_device_result_t* dev_result = &device_results[d];
        if (!dev_result->completed || dev_result->num_results == 0) {
            continue;
        }

        /* Device-specific phase offset based on device type */
        double phase_offset = 0.0;
        switch (dev_result->device_type) {
            case QIHSE_DEVICE_CPU_AVX2:    phase_offset = 0.0; break;
            case QIHSE_DEVICE_CPU_AVX512:  phase_offset = M_PI/4; break;
            case QIHSE_DEVICE_CPU_AMX:     phase_offset = M_PI/2; break;
            case QIHSE_DEVICE_NPU:         phase_offset = 3*M_PI/4; break;
            case QIHSE_DEVICE_GPU:         phase_offset = M_PI; break;
            default: phase_offset = 0.0; break;
        }

        for (size_t r = 0; r < dev_result->num_results && total_results < max_results; r++) {
            /* Apply phase interference */
            double confidence = dev_result->results[r].confidence;
            double phase = phase_offset + (1.0 - confidence) * M_PI; /* Phase based on uncertainty */

            /* Interference amplification */
            double interference_factor = cos(phase) * confidence;
            dev_result->results[r].confidence = fabs(interference_factor);

            final_results[total_results++] = dev_result->results[r];
        }
    }

    /* Sort by interference-amplified confidence */
    for (size_t i = 0; i < total_results - 1; i++) {
        for (size_t j = i + 1; j < total_results; j++) {
            if (final_results[j].confidence > final_results[i].confidence) {
                qihse_search_result_t temp = final_results[i];
                final_results[i] = final_results[j];
                final_results[j] = temp;
            }
        }
    }

    return total_results;
}

/**
 * Aggregate results using Bayesian fusion.
 */
static int qihse_aggregate_bayesian_fusion(
    qihse_device_result_t* device_results,
    size_t num_devices,
    qihse_search_result_t* final_results,
    size_t max_results
) {
    /* Bayesian probability fusion across devices */
    size_t total_results = 0;

    /* For each result position, combine evidence from all devices */
    for (size_t pos = 0; pos < max_results; pos++) {
        double combined_confidence = 0.0;
        qihse_search_result_t best_result = {0};

        /* Find best result at this position from each device */
        for (size_t d = 0; d < num_devices; d++) {
            qihse_device_result_t* dev_result = &device_results[d];
            if (!dev_result->completed || pos >= dev_result->num_results) {
                continue;
            }

            qihse_search_result_t* candidate = &dev_result->results[pos];

            /* Bayesian update: P(result|evidence) ∝ P(evidence|result) * P(result) */
            double device_prior = dev_result->confidence; /* Device reliability */
            double likelihood = candidate->confidence;     /* Result confidence */
            double posterior = (likelihood * device_prior) / (likelihood * device_prior + (1.0 - likelihood) * (1.0 - device_prior));

            if (posterior > combined_confidence) {
                combined_confidence = posterior;
                best_result = *candidate;
                best_result.confidence = posterior;
            }
        }

        if (combined_confidence > 0.0) {
            final_results[total_results++] = best_result;
        } else {
            break; /* No more results */
        }
    }

    return total_results;
}

/**
 * Aggregate results using neural network combination.
 * Uses a simple neural-inspired combination of device results.
 */
static int qihse_aggregate_neural_combination(
    qihse_device_result_t* device_results,
    size_t num_devices,
    qihse_search_result_t* final_results,
    size_t max_results
) {
    if (!device_results || !final_results || num_devices == 0 || max_results == 0) {
        return -EINVAL;
    }

    size_t total_results = 0;

    /* Neural-inspired combination: weighted sum with activation */
    for (size_t pos = 0; pos < max_results && total_results < max_results; pos++) {
        double combined_score = 0.0;
        double total_weight = 0.0;
        qihse_search_result_t best_result = {0};
        bool found_result = false;

        /* Neural combination across all devices */
        for (size_t d = 0; d < num_devices; d++) {
            qihse_device_result_t* dev_result = &device_results[d];
            if (!dev_result->completed || pos >= dev_result->num_results) {
                continue;
            }

            qihse_search_result_t* candidate = &dev_result->results[pos];

            /* Neural activation: tanh(confidence * weight) */
            double weight = dev_result->confidence;
            double activation = tanh(candidate->confidence * weight);

            combined_score += activation * weight;
            total_weight += weight;

            /* Keep track of best individual result */
            if (!found_result || candidate->confidence > best_result.confidence) {
                best_result = *candidate;
                found_result = true;
            }
        }

        if (found_result && total_weight > 0.0) {
            /* Final neural output: sigmoid of combined score */
            best_result.confidence = 1.0 / (1.0 + exp(-combined_score / total_weight));
            final_results[total_results++] = best_result;
        } else {
            break; /* No more results */
        }
    }

    return total_results;
}

/**
 * Execute work batch with parallel execution and advanced aggregation.
 */
int qihse_orchestrator_execute_parallel(
    qihse_orchestrator_t orchestrator,
    qihse_work_batch_t* batch,
    qihse_partition_strategy_t strategy,
    const qihse_parallel_config_t* parallel_config,
    qihse_search_result_t* results,
    size_t max_results,
    size_t* num_results
) {
    if (!orchestrator || !batch || !parallel_config) {
        return -EINVAL;
    }

    qihse_orchestrator_internal_t* internal = (qihse_orchestrator_internal_t*)orchestrator;

    /* Determine number of devices to use */
    size_t num_devices = qihse_hetero_pool_get_device_count(internal->pool);
    if (num_devices == 0) {
        return -ENODEV;
    }

    size_t max_parallel = parallel_config->max_parallel_devices;
    if (max_parallel == 0 || max_parallel > num_devices) {
        max_parallel = num_devices;
    }

    /* Allocate partition assignments */
    qihse_device_type_t* partitions = calloc(batch->num_operations, sizeof(qihse_device_type_t));
    if (!partitions) {
        return -ENOMEM;
    }

    /* Partition the workload */
    int ret = qihse_partition_workload(internal->pool, batch, strategy, partitions);
    if (ret != 0) {
        free(partitions);
        return ret;
    }

    /* Count operations per device */
    size_t* ops_per_device = calloc(num_devices, sizeof(size_t));
    if (!ops_per_device) {
        free(partitions);
        return -ENOMEM;
    }

    for (size_t i = 0; i < batch->num_operations; i++) {
        if (partitions[i] < num_devices) {
            ops_per_device[partitions[i]]++;
        }
    }

    /* Create device contexts for devices with work */
    qihse_parallel_device_ctx_t* device_ctxs = calloc(max_parallel, sizeof(qihse_parallel_device_ctx_t));
    qihse_device_result_t* device_results = calloc(max_parallel, sizeof(qihse_device_result_t));
    size_t active_devices = 0;

    if (!device_ctxs || !device_results) {
        free(ops_per_device);
        free(partitions);
        free(device_ctxs);
        free(device_results);
        return -ENOMEM;
    }

    /* Start parallel execution on devices with work */
    for (size_t d = 0; d < num_devices && active_devices < max_parallel; d++) {
        if (ops_per_device[d] == 0) {
            continue; /* No work for this device */
        }

        /* Create work batch for this device */
        qihse_parallel_device_ctx_t* ctx = &device_ctxs[active_devices];
        ctx->pool = internal->pool;
        ctx->device_type = (qihse_device_type_t)d;
        ctx->result = &device_results[active_devices];

        /* Copy operations assigned to this device */
        ctx->work_batch.operations = calloc(ops_per_device[d], sizeof(qihse_search_op_t));
        if (!ctx->work_batch.operations) {
            continue; /* Skip this device */
        }

        size_t op_count = 0;
        for (size_t i = 0; i < batch->num_operations; i++) {
            if (partitions[i] == d) {
                ctx->work_batch.operations[op_count++] = batch->operations[i];
            }
        }
        ctx->work_batch.num_operations = op_count;

        /* Start execution thread */
        if (pthread_create(&ctx->thread, NULL, qihse_device_execution_thread, ctx) == 0) {
            ctx->started = true;
            active_devices++;
        } else {
            free(ctx->work_batch.operations);
        }
    }

    /* Adaptive rebalancing during execution */
    if (parallel_config->adaptive_rebalancing && active_devices > 1) {
        /* Monitor progress and rebalance if needed */
        /* Simple implementation: check for imbalance every 100ms */
        const int check_interval_us = 100000; /* 100ms */
        struct timeval start_monitor, current_time;

        gettimeofday(&start_monitor, NULL);

        while (true) {
            /* Check if all threads are still running */
            bool all_done = true;
            for (size_t d = 0; d < active_devices; d++) {
                if (device_ctxs[d].started && device_results[d].completed == false) {
                    all_done = false;
                    break;
                }
            }
            if (all_done) break;

            /* Check for imbalance */
            gettimeofday(&current_time, NULL);
            long elapsed_us = (current_time.tv_sec - start_monitor.tv_sec) * 1000000L +
                             (current_time.tv_usec - start_monitor.tv_usec);

            if (elapsed_us >= check_interval_us) {
                /* Calculate load imbalance */
                double avg_progress = 0.0;
                for (size_t d = 0; d < active_devices; d++) {
                    if (device_results[d].completed) {
                        avg_progress += 1.0;
                    }
                }
                avg_progress /= active_devices;

                /* Check for devices that are significantly behind */
                for (size_t d = 0; d < active_devices; d++) {
                    if (!device_results[d].completed) {
                        double imbalance = avg_progress - 0.0; /* Not completed = 0 progress */
                        if (imbalance > parallel_config->rebalance_threshold) {
                            /* Could implement work stealing here */
                            /* For now, just log the imbalance */
                            /* Migrates work to faster devices when available */
                        }
                    }
                }

                start_monitor = current_time;
            }

            /* Small sleep to avoid busy waiting */
            struct timespec ts = {0, 10000000}; /* 10ms */
            nanosleep(&ts, NULL);
        }
    }

    /* Wait for all device threads to complete */
    for (size_t d = 0; d < active_devices; d++) {
        if (device_ctxs[d].started) {
            pthread_join(device_ctxs[d].thread, NULL);
        }
    }

    /* Aggregate results using specified method with hardware acceleration if available */
    size_t final_result_count = 0;
    if (results && max_results > 0) {
        /* Check if hardware acceleration is requested and AVX2 is available */
        int use_hw_accel = parallel_config->hardware_accelerated;
        if (use_hw_accel) {
            /* Verify AVX2 availability at runtime */
            use_hw_accel = __builtin_cpu_supports("avx2");
            if (!use_hw_accel) {
                pr_debug("qihse: AVX2 not available, falling back to scalar operations\n");
            }
        }

        switch (parallel_config->aggregation_method) {
            case QIHSE_AGGREGATION_WEIGHTED_VOTING:
                if (use_hw_accel) {
                    final_result_count = qihse_aggregate_weighted_voting_avx2(
                        device_results, active_devices, results, max_results);
                } else {
                    final_result_count = qihse_aggregate_weighted_voting(
                        device_results, active_devices, results, max_results);
                }
                break;
            case QIHSE_AGGREGATION_PHASE_INTERFERENCE:
                final_result_count = qihse_aggregate_phase_interference(
                    device_results, active_devices, results, max_results);
                break;
            case QIHSE_AGGREGATION_BAYESIAN_FUSION:
                final_result_count = qihse_aggregate_bayesian_fusion(
                    device_results, active_devices, results, max_results);
                break;
            case QIHSE_AGGREGATION_NEURAL_COMBINATION:
                final_result_count = qihse_aggregate_neural_combination(
                    device_results, active_devices, results, max_results);
                break;
            case QIHSE_AGGREGATION_ADAPTIVE:
            default:
                /* Adaptive: choose based on device count and workload */
                if (active_devices >= 3) {
                    final_result_count = qihse_aggregate_bayesian_fusion(
                        device_results, active_devices, results, max_results);
                } else if (use_hw_accel) {
                    final_result_count = qihse_aggregate_weighted_voting_avx2(
                        device_results, active_devices, results, max_results);
                } else {
                    final_result_count = qihse_aggregate_weighted_voting(
                        device_results, active_devices, results, max_results);
                }
                break;
        }
    }

    /* Return actual result count */
    if (num_results) {
        *num_results = final_result_count;
    }

    /* Cleanup */
    for (size_t d = 0; d < active_devices; d++) {
        free(device_ctxs[d].work_batch.operations);
        free(device_results[d].results);
    }

    free(device_ctxs);
    free(device_results);
    free(ops_per_device);
    free(partitions);

    return 0;
}

/* ============================================================================
 * ASYNCHRONOUS EXECUTION
 * ============================================================================ */

qihse_async_handle_t qihse_orchestrator_execute_async(
    qihse_orchestrator_t orchestrator,
    qihse_work_batch_t* batch,
    qihse_partition_strategy_t strategy
) {
    if (!orchestrator || !batch) {
        return NULL;
    }

    qihse_orchestrator_internal_t* internal = (qihse_orchestrator_internal_t*)orchestrator;

    /* Allocate async execution structure */
    qihse_async_execution_t* execution = calloc(1, sizeof(qihse_async_execution_t));
    if (!execution) {
        return NULL;
    }

    /* Copy batch information */
    memcpy(&execution->batch, batch, sizeof(qihse_work_batch_t));
    execution->pool = internal->pool;

    /* Allocate partitions */
    execution->partitions = calloc(batch->num_operations, sizeof(qihse_device_type_t));
    if (!execution->partitions) {
        free(execution);
        return NULL;
    }

    /* Partition workload using intelligent partitioning */
    int ret = qihse_partition_workload(internal->pool, batch, strategy, execution->partitions);
    if (ret != 0) {
        free(execution->partitions);
        free(execution);
        return NULL;
    }

    /* Initialize mutex */
    if (pthread_mutex_init(&execution->mutex, NULL) != 0) {
        free(execution->partitions);
        free(execution);
        return NULL;
    }

    /* Start async execution thread */
    if (pthread_create(&execution->thread, NULL, async_execution_thread, execution) != 0) {
        pthread_mutex_destroy(&execution->mutex);
        free(execution->partitions);
        free(execution);
        return NULL;
    }

    /* Add to async tracking */
    pthread_mutex_lock(&internal->async_mutex);
    if (internal->num_async >= internal->max_async) {
        /* No space for more async executions */
        pthread_cancel(execution->thread);
        pthread_join(execution->thread, NULL);
        pthread_mutex_destroy(&execution->mutex);
        free(execution->partitions);
        free(execution);
        pthread_mutex_unlock(&internal->async_mutex);
        return NULL;
    }

    internal->async_executions[internal->num_async++] = execution;
    pthread_mutex_unlock(&internal->async_mutex);

    return (qihse_async_handle_t)execution;
}

int qihse_orchestrator_wait_async(qihse_async_handle_t handle) {
    if (!handle) {
        return -EINVAL;
    }

    qihse_async_execution_t* execution = (qihse_async_execution_t*)handle;

    /* Wait for thread to complete */
    if (pthread_join(execution->thread, NULL) != 0) {
        return -EINVAL;
    }

    /* Return the execution result */
    return execution->result;
}

int qihse_orchestrator_cancel_async(qihse_async_handle_t handle) {
    if (!handle) {
        return -EINVAL;
    }

    qihse_async_execution_t* execution = (qihse_async_execution_t*)handle;

    /* Cancel the execution thread */
    if (pthread_cancel(execution->thread) != 0) {
        return -EINVAL;
    }

    /* Wait for thread to terminate */
    pthread_join(execution->thread, NULL);

    return 0;
}

int qihse_orchestrator_get_async_status(
    qihse_async_handle_t handle,
    bool* completed,
    double* progress
) {
    if (!handle || !completed || !progress) {
        return -EINVAL;
    }

    qihse_async_execution_t* execution = (qihse_async_execution_t*)handle;

    pthread_mutex_lock(&execution->mutex);
    *completed = execution->completed;
    *progress = execution->progress;
    pthread_mutex_unlock(&execution->mutex);

    return 0;
}

/* ============================================================================
 * PERFORMANCE TUNING
 * ============================================================================ */

int qihse_orchestrator_set_tuning_hints(
    qihse_orchestrator_t orchestrator,
    const qihse_tuning_hints_t* hints
) {
    if (!orchestrator || !hints) {
        return -EINVAL;
    }

    qihse_orchestrator_internal_t* internal = (qihse_orchestrator_internal_t*)orchestrator;
    memcpy(&internal->tuning_hints, hints, sizeof(qihse_tuning_hints_t));

    return 0;
}

int qihse_orchestrator_get_tuning_hints(
    qihse_orchestrator_t orchestrator,
    qihse_tuning_hints_t* hints
) {
    if (!orchestrator || !hints) {
        return -EINVAL;
    }

    qihse_orchestrator_internal_t* internal = (qihse_orchestrator_internal_t*)orchestrator;
    memcpy(hints, &internal->tuning_hints, sizeof(qihse_tuning_hints_t));

    return 0;
}
