/*
 * QIHSE - Device-Specific Memory Placement Helpers
 *
 * Deterministic host-safe placement policy helpers for Phase 2 memory planning.
 */

#ifndef QIHSE_MEMORY_DEVICE_PLACEMENT_H
#define QIHSE_MEMORY_DEVICE_PLACEMENT_H

#include <stdbool.h>

#include "qihse_memory.h"
#include "../../orchestration/include/qihse_hetero.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Memory placement policy used by the device placement scorer.
 */
typedef enum qihse_memory_device_policy_e {
    QIHSE_MEMORY_DEVICE_POLICY_HOST_SAFE = 0,
    QIHSE_MEMORY_DEVICE_POLICY_BALANCED = 1,
    QIHSE_MEMORY_DEVICE_POLICY_CPU_PREFERRED = 2,
    QIHSE_MEMORY_DEVICE_POLICY_DEVICE_PREFERRED = 3,
    QIHSE_MEMORY_DEVICE_POLICY_LOW_LATENCY = 4,
    QIHSE_MEMORY_DEVICE_POLICY_HIGH_BANDWIDTH = 5,
    QIHSE_MEMORY_DEVICE_POLICY_COHERENT = 6
} qihse_memory_device_policy_t;

/**
 * Coarse placement class selected by the helper.
 */
typedef enum qihse_memory_device_placement_e {
    QIHSE_MEMORY_DEVICE_PLACEMENT_HOST = 0,
    QIHSE_MEMORY_DEVICE_PLACEMENT_CPU = 1,
    QIHSE_MEMORY_DEVICE_PLACEMENT_DEVICE = 2
} qihse_memory_device_placement_t;

/**
 * Score bundle. Higher scores are better; selection uses HOST > CPU > DEVICE
 * tie-breaking by only moving on a strict score improvement.
 */
typedef struct qihse_memory_device_placement_scores_s {
    double host_score;
    double cpu_score;
    double device_score;
    qihse_memory_device_placement_t selected;
} qihse_memory_device_placement_scores_t;

bool qihse_memory_device_placement_is_cpu_target(qihse_device_type_t target_device);

bool qihse_memory_device_placement_is_accelerator_target(qihse_device_type_t target_device);

const char* qihse_memory_device_placement_string(qihse_memory_device_placement_t placement);

qihse_memory_type_t qihse_memory_device_placement_memory_type(
    qihse_memory_device_placement_t placement
);

double qihse_memory_device_placement_score_host(
    const qihse_memory_workload_analysis_t* workload,
    const qihse_memory_topology_t* topology,
    qihse_device_type_t target_device,
    qihse_memory_device_policy_t policy,
    qihse_memory_access_t access_pattern
);

double qihse_memory_device_placement_score_cpu(
    const qihse_memory_workload_analysis_t* workload,
    const qihse_memory_topology_t* topology,
    qihse_device_type_t target_device,
    qihse_memory_device_policy_t policy,
    qihse_memory_access_t access_pattern
);

double qihse_memory_device_placement_score_device(
    const qihse_memory_workload_analysis_t* workload,
    const qihse_memory_topology_t* topology,
    qihse_device_type_t target_device,
    qihse_memory_device_policy_t policy,
    qihse_memory_access_t access_pattern
);

qihse_memory_device_placement_scores_t qihse_memory_device_placement_score_all(
    const qihse_memory_workload_analysis_t* workload,
    const qihse_memory_topology_t* topology,
    qihse_device_type_t target_device,
    qihse_memory_device_policy_t policy,
    qihse_memory_access_t access_pattern
);

qihse_memory_device_placement_t qihse_memory_device_placement_select(
    const qihse_memory_workload_analysis_t* workload,
    const qihse_memory_topology_t* topology,
    qihse_device_type_t target_device,
    qihse_memory_device_policy_t policy,
    qihse_memory_access_t access_pattern
);

#ifdef __cplusplus
}
#endif

#endif /* QIHSE_MEMORY_DEVICE_PLACEMENT_H */
