/*
 * QIHSE - Work Partitioning Logic
 *
 * Intelligent partitioning of search workloads across heterogeneous devices.
 *
 * Version: 1.0.0
 * Author: DSMIL System
 * License: MIT
 */

#include "../include/qihse_partition.h"
#include "../include/qihse_hetero.h"
#include "../../core/qihse_abi.h"

#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <errno.h>
#include <unistd.h>

/* ============================================================================
 * FORWARD DECLARATIONS AND TYPE DEFINITIONS
 * ============================================================================ */

/* Simple result structure for partitioning (will be defined properly in ABI) */
typedef struct qihse_result_s {
    uint32_t id;
    float score;
    uint32_t data[4]; /* Operation result data */
} qihse_result_t;

/* ============================================================================
 * WORKLOAD CHARACTERIZATION
 * ============================================================================ */

/**
 * Workload characteristics for partitioning decisions.
 */
typedef struct qihse_workload_char_s {
    size_t input_size;               /* Size of input data */
    size_t output_size;              /* Expected output size */
    double compute_intensity;        /* FLOPs per byte */
    qihse_search_op_type_t op_type;  /* Type of search operation */
    bool requires_precision;         /* Requires high precision */
    bool memory_bound;               /* Memory bandwidth bound */
    bool compute_bound;              /* Compute bound */
} qihse_workload_char_t;

/**
 * Characterize a search operation for partitioning.
 *
 * @param op Search operation
 * @param config Search configuration
 * @param char_out Output workload characteristics
 * @return 0 on success, negative error code on failure
 */
static int characterize_operation(
    qihse_search_op_t op,
    const qihse_search_config_t* config,
    qihse_workload_char_t* char_out
) {
    if (!config || !char_out) {
        return -EINVAL;
    }
    (void)op;  /* Reserved for future operation-specific characterization */

    /* Characterize operation for partitioning */
    /* Future: Access operation type from search operation structure */
    memset(char_out, 0, sizeof(qihse_workload_char_t));

    /* Characterize as vector search operation */
    char_out->input_size = 128 * sizeof(float); /* Assume 128-dim vectors */
    char_out->output_size = 10 * sizeof(qihse_result_t); /* Top-k results */
    char_out->compute_intensity = 128.0; /* Dot product operations */
    char_out->memory_bound = true; /* Vector loads are memory bound */
    char_out->compute_bound = false;
    char_out->requires_precision = false; /* KNN can use lower precision */
    char_out->op_type = QIHSE_SEARCH_OP_VECTOR_KNN; /* Assume vector search */

    return 0;
}

/* ============================================================================
 * DEVICE SUITABILITY SCORING
 * ============================================================================ */

/**
 * Score how suitable a device is for a given workload.
 *
 * @param device_info Device information
 * @param device_metrics Device performance metrics
 * @param workload Workload characteristics
 * @return Suitability score (higher is better)
 */
static double score_device_suitability(
    const qihse_device_info_t* device_info,
    const qihse_device_metrics_t* device_metrics,
    const qihse_workload_char_t* workload
) {
    double score = 0.0;

    /* Base score from performance */
    score += device_metrics->throughput_gops * 0.1;

    /* Capability matching */
    if (workload->requires_precision) {
        /* Prefer devices with high precision support */
        if (device_info->capabilities & QIHSE_CAPS_FP16) {
            score += 10.0;
        }
    } else {
        /* Prefer devices with quantization support */
        if (device_info->capabilities & QIHSE_CAPS_INT8) {
            score += 10.0;
        }
    }

    /* Workload type preferences */
    if (workload->op_type == QIHSE_SEARCH_OP_VECTOR_KNN) {
        /* Vector search prefers SIMD and tensor devices */
        if (device_info->capabilities & (QIHSE_CAPS_SIMD_AVX2 | QIHSE_CAPS_SIMD_AVX512 | QIHSE_CAPS_TENSOR)) {
            score += 20.0;
        }
    } else if (workload->op_type == QIHSE_SEARCH_OP_GRAPH_BFS) {
        /* Graph search prefers devices with good memory bandwidth */
        if (device_metrics->memory_bandwidth_gbps > 50.0) {
            score += 15.0;
        }
    } else if (workload->op_type == QIHSE_SEARCH_OP_CONSTRAINT_OPTIMIZE) {
        /* Constraint search prefers compute-bound devices */
        if (device_info->capabilities & QIHSE_CAPS_AMX) {
            score += 25.0; /* AMX is great for constraint solving */
        }
    }

    /* Workload characteristics */
    if (workload->memory_bound && device_metrics->memory_bandwidth_gbps > 0) {
        score += device_metrics->memory_bandwidth_gbps * 0.5;
    }

    if (workload->compute_bound && device_metrics->throughput_gops > 0) {
        score += device_metrics->throughput_gops * 0.2;
    }

    /* Penalize overloaded devices */
    if (device_metrics->utilization_percent > 80.0) {
        score *= 0.5;
    }

    return score;
}

/* ============================================================================
 * PARTITIONING ALGORITHMS
 * ============================================================================ */

/**
 * Simple greedy partitioning - assign each operation to best device.
 */
static int partition_greedy(
    qihse_hetero_pool_t pool,
    const qihse_workload_char_t* workloads,
    size_t num_operations,
    qihse_device_type_t* partitions
) {
    size_t num_devices = qihse_hetero_pool_get_device_count(pool);

    for (size_t i = 0; i < num_operations; i++) {
        double best_score = -1.0;
        qihse_device_type_t best_device = QIHSE_DEVICE_CPU_AVX2; /* Fallback */

        for (size_t d = 0; d < num_devices; d++) {
            qihse_device_info_t device_info;
            qihse_device_metrics_t device_metrics;

            if (qihse_hetero_pool_get_device_info(pool, d, &device_info) == 0 &&
                qihse_hetero_pool_get_device_metrics(pool, device_info.type, &device_metrics) == 0) {

                double score = score_device_suitability(&device_info, &device_metrics, &workloads[i]);
                if (score > best_score) {
                    best_score = score;
                    best_device = device_info.type;
                }
            }
        }

        partitions[i] = best_device;
    }

    return 0;
}

/**
 * Load-balanced partitioning - distribute across devices by load.
 */
static int partition_load_balanced(
    qihse_hetero_pool_t pool,
    const qihse_workload_char_t* workloads,
    size_t num_operations,
    qihse_device_type_t* partitions
) {
    size_t num_devices = qihse_hetero_pool_get_device_count(pool);

    /* Track load per device */
    double* device_load = calloc(num_devices, sizeof(double));
    if (!device_load) {
        return -ENOMEM;
    }

    for (size_t i = 0; i < num_operations; i++) {
        size_t best_device_idx = 0;

        qihse_device_info_t best_device_info;
        qihse_device_metrics_t best_device_metrics;

        if (qihse_hetero_pool_get_device_info(pool, 0, &best_device_info) == 0 &&
            qihse_hetero_pool_get_device_metrics(pool, best_device_info.type, &best_device_metrics) == 0) {

            double best_score = score_device_suitability(&best_device_info, &best_device_metrics, &workloads[i]);

            /* Find device with best score and lowest load */
            for (size_t d = 1; d < num_devices; d++) {
                qihse_device_info_t device_info;
                qihse_device_metrics_t device_metrics;

                if (qihse_hetero_pool_get_device_info(pool, d, &device_info) == 0 &&
                    qihse_hetero_pool_get_device_metrics(pool, device_info.type, &device_metrics) == 0) {

                    double score = score_device_suitability(&device_info, &device_metrics, &workloads[i]);
                    double load = device_load[d];

                    /* Prefer lower load, but allow higher load if score is much better */
                    double adjusted_score = score - load * 0.1;

                    if (adjusted_score > best_score) {
                        best_score = adjusted_score;
                        best_device_idx = d;
                        best_device_info = device_info;
                    }
                }
            }
        }

        partitions[i] = best_device_info.type;
        device_load[best_device_idx] += workloads[i].compute_intensity;
    }

    free(device_load);
    return 0;
}

/* ============================================================================
 * PUBLIC API
 * ============================================================================ */

int qihse_partition_workload(
    qihse_hetero_pool_t pool,
    const qihse_work_batch_t* batch,
    qihse_partition_strategy_t strategy,
    qihse_device_type_t* partitions
) {
    if (!pool || !batch || !partitions) {
        return -EINVAL;
    }

    size_t num_devices = qihse_hetero_pool_get_device_count(pool);
    if (num_devices == 0) {
        return -ENODEV;
    }

    /* Characterize each operation */
    qihse_workload_char_t* workloads = calloc(batch->num_operations, sizeof(qihse_workload_char_t));
    if (!workloads) {
        return -ENOMEM;
    }

    for (size_t i = 0; i < batch->num_operations; i++) {
        int ret = characterize_operation(batch->operations[i], batch->config, &workloads[i]);
        if (ret != 0) {
            free(workloads);
            return ret;
        }
    }

    /* Apply partitioning strategy */
    int ret;
    switch (strategy) {
        case QIHSE_PARTITION_GREEDY:
            ret = partition_greedy(pool, workloads, batch->num_operations, partitions);
            break;

        case QIHSE_PARTITION_LOAD_BALANCED:
            ret = partition_load_balanced(pool, workloads, batch->num_operations, partitions);
            break;

        default:
            ret = -EINVAL;
            break;
    }

    free(workloads);
    return ret;
}
