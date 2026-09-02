/*
 * QIHSE - Unified Memory Management Implementation
 *
 * Core memory management for quantum-inspired search operations.
 *
 * Version: 1.0.0
 * Author: DSMIL System
 * License: MIT
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include "../include/qihse_memory.h"
#include "../include/qihse_memory_allocation_policy.h"
#include "../include/qihse_memory_coherence.h"
#include "../include/qihse_memory_migration_backend.h"
#include "../include/qihse_memory_migration_policy.h"
#include "../include/qihse_memory_migration_scheduler.h"
#include "../include/qihse_memory_planner_trace.h"
#include "../include/qihse_memory_device_placement.h"
#include "../include/qihse_memory_topology_probe.h"
#include "../../orchestration/include/qihse_hetero.h"
#include "qihse_anchor_search.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdatomic.h>
#include <stdio.h>
#include <pthread.h>

/* ============================================================================
 * INTERNAL STRUCTURES
 * ============================================================================ */

/**
 * Memory manager internal structure.
 */
typedef struct qihse_memory_manager_s {
    qihse_context_t ctx;             /* Phase 0 ABI context */
    const char* backend_type;        /* Backend type string */

    /* Statistics (atomically updated for thread safety) */
    atomic_size_t total_allocated;
    atomic_size_t total_used;
    atomic_size_t peak_usage;
    atomic_size_t num_buffers;

    /* Per-type statistics */
    atomic_size_t host_memory;
    atomic_size_t device_memory;
    atomic_size_t unified_memory;

    /* Performance tracking */
    atomic_uint_fast64_t total_allocations;
    atomic_uint_fast64_t total_frees;
    atomic_uint_fast64_t total_migrations;
    double avg_allocation_time;      /* Microseconds */

    /* Policy and configuration */
    qihse_memory_policy_t policy;
    pthread_mutex_t policy_mutex;

    /* Buffer tracking */
    qihse_memory_buffer_t** buffers;
    size_t max_buffers;
    size_t num_tracked_buffers;
    pthread_mutex_t buffer_mutex;
} qihse_memory_manager_internal_t;

typedef struct qihse_memory_migration_decision_config_s {
    double residency_weight;
    double access_weight;
    double coherence_weight;
    double target_weight;
    double policy_weight;
    uint64_t hot_access_threshold;
    double minimum_score;
} qihse_memory_migration_decision_config_t;

static double qihse_memory_clamp_score(double value, double min_value, double max_value)
{
    if (value != value) {
        return min_value;
    }
    if (value < min_value) {
        return min_value;
    }
    if (value > max_value) {
        return max_value;
    }
    return value;
}

static qihse_memory_migration_backend_t
qihse_memory_migration_backend_for_migration(
    qihse_memory_type_t source_type,
    qihse_memory_type_t target_type
)
{
    if (source_type == QIHSE_MEM_DEVICE || target_type == QIHSE_MEM_DEVICE) {
        return QIHSE_MEMORY_MIGRATION_BACKEND_DEVICE_COPY;
    }

    if (source_type == QIHSE_MEM_PINNED || target_type == QIHSE_MEM_PINNED) {
        return QIHSE_MEMORY_MIGRATION_BACKEND_HARDWARE_DMA;
    }

    return QIHSE_MEMORY_MIGRATION_BACKEND_HOST_MEMCPY;
}

static bool qihse_memory_migration_backend_execute_with_fallback(
    qihse_memory_migration_backend_request_t* request,
    qihse_memory_migration_backend_t preferred_backend
)
{
    size_t attempt;
    qihse_memory_migration_backend_t attempt_backends[2];
    qihse_memory_migration_backend_status_t status;

    attempt_backends[0] = preferred_backend;
    attempt_backends[1] = QIHSE_MEMORY_MIGRATION_BACKEND_HOST_MEMCPY;

    for (attempt = 0u; attempt < 2u; ++attempt) {
        request->backend = attempt_backends[attempt];
        status = qihse_memory_migration_backend_execute(request);

        if (status == QIHSE_MEMORY_MIGRATION_BACKEND_OK) {
            return true;
        }

        if (status != QIHSE_MEMORY_MIGRATION_BACKEND_UNSUPPORTED_DMA &&
            status != QIHSE_MEMORY_MIGRATION_BACKEND_UNSUPPORTED_DEVICE) {
            return false;
        }

        if (attempt_backends[attempt] == QIHSE_MEMORY_MIGRATION_BACKEND_HOST_MEMCPY) {
            break;
        }
    }

    return false;
}

static qihse_memory_migration_decision_config_t qihse_memory_migration_decision_default_config(void)
{
    qihse_memory_migration_decision_config_t config;

    config.residency_weight = 40.0;
    config.access_weight = 25.0;
    config.coherence_weight = 15.0;
    config.target_weight = 10.0;
    config.policy_weight = 10.0;
    config.hot_access_threshold = QIHSE_MEMORY_MIGRATION_SCHEDULER_DEFAULT_HOT_ACCESS_THRESHOLD;
    config.minimum_score = 1.0;

    return config;
}

static double qihse_memory_decision_access_score(uint64_t access_count, uint64_t hot_threshold)
{
    if (hot_threshold == 0u) {
        return access_count > 0u ? 1.0 : 0.0;
    }
    if (access_count >= hot_threshold) {
        return 1.0;
    }
    return (double)access_count / (double)hot_threshold;
}

static double qihse_memory_decision_coherence_score(
    const qihse_memory_buffer_t* buffer,
    const qihse_memory_migration_plan_t* plan
)
{
    uint64_t observed_version;
    uint64_t lag;
    double score;

    observed_version = buffer->coherence_last_read_version;
    if (buffer->coherence_last_write_version > observed_version) {
        observed_version = buffer->coherence_last_write_version;
    }

    lag = buffer->coherence_version > observed_version
        ? buffer->coherence_version - observed_version
        : 0u;

    score = 0.0;

    if (buffer->coherence_shared) {
        score += 0.20;
    }

    if (buffer->coherence_last_write_version > buffer->coherence_last_read_version) {
        score -= 0.25;
    }

    if (lag > 0u) {
        score -= qihse_memory_clamp_score((double)lag / 16.0, 0.0, 0.35);
    }

    switch (buffer->coherence_state) {
        case 0u:
            score += 0.00;
            break;
        case 1u:
            score += 0.10;
            break;
        case 2u:
            score -= 0.15;
            break;
        default:
            score -= 0.05;
            break;
    }

    if (plan->preserves_coherence) {
        score += 0.35;
    } else {
        score -= 0.35;
    }

    return qihse_memory_clamp_score(score, -1.0, 1.0);
}

static double qihse_memory_decision_target_score(qihse_memory_type_t target_type)
{
    switch (target_type) {
        case QIHSE_MEM_HOST:
            return 0.10;
        case QIHSE_MEM_PINNED:
            return 0.45;
        case QIHSE_MEM_DEVICE:
            return 0.80;
        case QIHSE_MEM_UNIFIED:
            return 0.65;
        case QIHSE_MEM_HMA_SUPERPOSITION:
            return 0.90;
        case QIHSE_MEM_HMA_INTERACTION:
            return 0.75;
        case QIHSE_MEM_HMA_ENTANGLEMENT:
            return 0.85;
        case QIHSE_MEM_ANCHOR_TABLE:
            return 0.40;
        case QIHSE_MEM_ANCHOR_WORKSPACE:
            return 0.50;
        default:
            return 0.0;
    }
}

static double qihse_memory_decision_policy_score(const qihse_memory_migration_plan_t* plan)
{
    double score;

    switch (plan->kind) {
        case QIHSE_MEMORY_MIGRATION_ZERO_COPY:
            score = 1.0;
            break;
        case QIHSE_MEMORY_MIGRATION_COPY_REQUIRED:
            score = 0.55;
            break;
        case QIHSE_MEMORY_MIGRATION_REJECT:
        default:
            return -1.0;
    }

    if (plan->preserves_coherence) {
        score += 0.20;
    } else {
        score -= 0.30;
    }

    return qihse_memory_clamp_score(score, -1.0, 1.0);
}

static bool qihse_memory_decision_reason_starts_with(
    const char* value,
    const char* prefix
) {
    if (!value || !prefix) {
        return false;
    }
    if (strlen(prefix) == 0u) {
        return *value == '\0';
    }
    return strncmp(value, prefix, strlen(prefix)) == 0;
}

static qihse_memory_migration_decision_reason_t qihse_memory_migration_plan_reject_reason(
    const qihse_memory_migration_plan_t* plan
) {
    if (!plan) {
        return QIHSE_MEMORY_MIGRATION_DECISION_REASON_UNKNOWN;
    }
    if (qihse_memory_decision_reason_starts_with(plan->reason, "rejected-not-migratable")) {
        return QIHSE_MEMORY_MIGRATION_DECISION_REASON_NOT_MIGRATABLE;
    }
    if (qihse_memory_decision_reason_starts_with(plan->reason, "rejected-invalid-source")) {
        return QIHSE_MEMORY_MIGRATION_DECISION_REASON_INVALID_ARGUMENTS;
    }
    return QIHSE_MEMORY_MIGRATION_DECISION_REASON_POLICY_REJECT;
}

/* ============================================================================
 * UTILITY FUNCTIONS
 * ============================================================================ */

size_t qihse_memory_get_alignment(qihse_memory_type_t mem_type) {
    switch (mem_type) {
        case QIHSE_MEM_HOST:
            return 64;  /* Cache line alignment */
        case QIHSE_MEM_PINNED:
            return 4096; /* Page alignment */
        case QIHSE_MEM_DEVICE:
            return 256; /* SIMD alignment */
        case QIHSE_MEM_UNIFIED:
            return 64;  /* Cache line alignment */
        case QIHSE_MEM_HMA_SUPERPOSITION:
            return 64;  /* SIMD alignment */
        case QIHSE_MEM_HMA_INTERACTION:
            return 64;  /* Cache alignment */
        case QIHSE_MEM_HMA_ENTANGLEMENT:
            return 4096; /* Page alignment */
        case QIHSE_MEM_ANCHOR_TABLE:
            return 4096; /* Large table aligned to page size */
        case QIHSE_MEM_ANCHOR_WORKSPACE:
            return 64;   /* Workspace benefits from cache alignment */
        default:
            return 64;
    }
}

bool qihse_memory_is_accessible(qihse_memory_type_t mem_type, qihse_device_type_t device) {
    bool device_is_cpu = (device == QIHSE_DEVICE_CPU_AVX2 ||
                          device == QIHSE_DEVICE_CPU_AVX512 ||
                          device == QIHSE_DEVICE_CPU_AMX);
    switch (mem_type) {
        case QIHSE_MEM_HOST:
            return true; /* Host memory always accessible */
        case QIHSE_MEM_PINNED:
            return true; /* Pinned host memory accessible */
        case QIHSE_MEM_DEVICE:
            return !device_is_cpu;
        case QIHSE_MEM_UNIFIED:
            return true; /* Unified memory accessible by all */
        case QIHSE_MEM_HMA_SUPERPOSITION:
        case QIHSE_MEM_HMA_INTERACTION:
        case QIHSE_MEM_HMA_ENTANGLEMENT:
            return true; /* HMA memory accessible by all */
        case QIHSE_MEM_ANCHOR_TABLE:
        case QIHSE_MEM_ANCHOR_WORKSPACE:
            return true; /* Anchor data accessible system-wide */
        default:
            return false;
    }
}

const char* qihse_memory_type_string(qihse_memory_type_t mem_type) {
    switch (mem_type) {
        case QIHSE_MEM_HOST: return "HOST";
        case QIHSE_MEM_PINNED: return "PINNED";
        case QIHSE_MEM_DEVICE: return "DEVICE";
        case QIHSE_MEM_UNIFIED: return "UNIFIED";
        case QIHSE_MEM_HMA_SUPERPOSITION: return "HMA_SUPERPOSITION";
        case QIHSE_MEM_HMA_INTERACTION: return "HMA_INTERACTION";
        case QIHSE_MEM_HMA_ENTANGLEMENT: return "HMA_ENTANGLEMENT";
        case QIHSE_MEM_ANCHOR_TABLE: return "ANCHOR_TABLE";
        case QIHSE_MEM_ANCHOR_WORKSPACE: return "ANCHOR_WORKSPACE";
        default: return "UNKNOWN";
    }
}

static bool qihse_memory_static_default_topology(qihse_memory_topology_t* topology) {
    if (!topology) {
        errno = EINVAL;
        return false;
    }

    memset(topology, 0, sizeof(*topology));
    topology->superposition_buffer.capacity = 128u * 1024u * 1024u;
    topology->superposition_buffer.bandwidth_gbps = 1000.0;
    topology->superposition_buffer.latency_ns = 10.0;
    topology->superposition_buffer.coherent = true;

    topology->interaction_cache.capacity = 64u * 1024u * 1024u;
    topology->interaction_cache.bandwidth_gbps = 500.0;
    topology->interaction_cache.latency_ns = 20.0;
    topology->interaction_cache.coherent = true;

    topology->entanglement_fabric.capacity = (size_t)1024u * 1024u * 1024u * 1024u;
    topology->entanglement_fabric.bandwidth_gbps = 100.0;
    topology->entanglement_fabric.latency_ns = 100.0;
    topology->entanglement_fabric.coherent = true;

    topology->inter_tier_bandwidth_gbps = 64.0;
    topology->numa_nodes = 1u;
    return true;
}

bool qihse_memory_default_topology(qihse_memory_topology_t* topology) {
    if (!topology) {
        errno = EINVAL;
        return false;
    }

    if (qihse_memory_topology_probe(topology)) {
        return true;
    }

    return qihse_memory_static_default_topology(topology);
}

static double qihse_memory_clamp_unit(double value) {
    if (value < 0.0) {
        return 0.0;
    }
    if (value > 1.0) {
        return 1.0;
    }
    return value;
}

static double qihse_memory_maintenance_clamp_unit(double value) {
    if (value < 0.0) {
        return 0.0;
    }
    if (value > 1.0) {
        return 1.0;
    }
    return value;
}

static qihse_memory_device_policy_t qihse_memory_maintenance_to_device_policy(
    qihse_memory_policy_t policy
) {
    switch (policy) {
        case QIHSE_POLICY_DEVICE_LOCAL:
            return QIHSE_MEMORY_DEVICE_POLICY_DEVICE_PREFERRED;
        case QIHSE_POLICY_LOW_LATENCY:
            return QIHSE_MEMORY_DEVICE_POLICY_LOW_LATENCY;
        case QIHSE_POLICY_HIGH_BANDWIDTH:
            return QIHSE_MEMORY_DEVICE_POLICY_HIGH_BANDWIDTH;
        case QIHSE_POLICY_ENERGY_EFFICIENT:
            return QIHSE_MEMORY_DEVICE_POLICY_COHERENT;
        case QIHSE_POLICY_BEST_FIT:
            return QIHSE_MEMORY_DEVICE_POLICY_BALANCED;
        case QIHSE_POLICY_FIRST_FIT:
        default:
            return QIHSE_MEMORY_DEVICE_POLICY_HOST_SAFE;
    }
}

#if 0
static double qihse_memory_maintenance_type_rank(qihse_memory_type_t mem_type) {
    switch (mem_type) {
        case QIHSE_MEM_HOST:
            return 0.10;
        case QIHSE_MEM_PINNED:
            return 0.20;
        case QIHSE_MEM_UNIFIED:
            return 0.35;
        case QIHSE_MEM_ANCHOR_WORKSPACE:
        case QIHSE_MEM_ANCHOR_TABLE:
            return 0.15;
        case QIHSE_MEM_HMA_INTERACTION:
            return 0.50;
        case QIHSE_MEM_HMA_ENTANGLEMENT:
            return 0.65;
        case QIHSE_MEM_DEVICE:
            return 0.80;
        case QIHSE_MEM_HMA_SUPERPOSITION:
        default:
            return 0.60;
    }
}
#endif

static qihse_memory_type_t qihse_memory_maintenance_derive_target_type(
    qihse_memory_buffer_t* buffer,
    qihse_memory_policy_t policy,
    int target_device
) {
    qihse_memory_workload_analysis_t analysis;
    qihse_memory_type_t recommended_type = QIHSE_MEM_HMA_ENTANGLEMENT;
    qihse_memory_device_placement_t placement;
    qihse_memory_device_policy_t device_policy;

    memset(&analysis, 0, sizeof(analysis));
    analysis.access_pattern = buffer->access_pattern;
    analysis.read_write_ratio = 1.0;
    analysis.working_set_size = buffer->logical_size;
    analysis.temporal_locality = qihse_memory_maintenance_clamp_unit(buffer->residency_score);
    analysis.spatial_locality = qihse_memory_maintenance_clamp_unit(
        1.0 - analysis.temporal_locality);
    analysis.superposition_dims = buffer->logical_size < 32u ? 1u : 32u;
    analysis.entanglement_density = qihse_memory_maintenance_clamp_unit(
        1.0 - (analysis.working_set_size / (1024.0 * 1024.0 * 1024.0 + 1.0)));
    analysis.phase = QIHSE_MEMORY_PHASE_INIT;

    if (buffer->access_pattern == QIHSE_ACCESS_SIMD ||
        buffer->access_pattern == QIHSE_ACCESS_BLOCKED) {
        analysis.phase = QIHSE_MEMORY_PHASE_AMPLIFICATION;
    } else if (buffer->mem_type == QIHSE_MEM_HMA_INTERACTION) {
        analysis.phase = QIHSE_MEMORY_PHASE_INTERACTION;
    } else if (buffer->mem_type == QIHSE_MEM_HMA_SUPERPOSITION) {
        analysis.phase = QIHSE_MEMORY_PHASE_SUPERPOSITION;
    } else if (buffer->mem_type == QIHSE_MEM_HMA_ENTANGLEMENT) {
        analysis.phase = QIHSE_MEMORY_PHASE_MEASUREMENT;
    } else if (buffer->access_count > 1024u) {
        analysis.phase = QIHSE_MEMORY_PHASE_INTERACTION;
    }

    if (!qihse_memory_recommend_type(&analysis, NULL, &recommended_type)) {
        recommended_type = QIHSE_MEM_HMA_ENTANGLEMENT;
    }

    device_policy = qihse_memory_maintenance_to_device_policy(policy);
    placement = qihse_memory_device_placement_select(
        &analysis,
        NULL,
        target_device,
        device_policy,
        buffer->access_pattern);

    switch (placement) {
        case QIHSE_MEMORY_DEVICE_PLACEMENT_DEVICE:
            return QIHSE_MEM_DEVICE;
        case QIHSE_MEMORY_DEVICE_PLACEMENT_CPU:
        case QIHSE_MEMORY_DEVICE_PLACEMENT_HOST:
        default:
            return recommended_type;
    }
}

#if 0
static double qihse_memory_maintenance_pressure(
    const qihse_memory_buffer_t* buffer,
    qihse_memory_type_t target_type
) {
    double access_pressure;
    double residency_pressure;
    double type_pressure;

    access_pressure = (buffer->access_count >= 2048u)
        ? 1.0
        : ((double)buffer->access_count / 2048.0);

    residency_pressure = qihse_memory_maintenance_clamp_unit(1.0 - buffer->residency_score);
    type_pressure = qihse_memory_maintenance_clamp_unit(
        qihse_memory_maintenance_clamp_unit(qihse_memory_maintenance_type_rank(target_type) -
            qihse_memory_maintenance_type_rank(buffer->mem_type) + 1.0) / 1.5);

    return 0.55 * access_pressure + 0.25 * residency_pressure + 0.20 * type_pressure;
}
#endif

static bool qihse_memory_recommend_type_internal(
    const qihse_memory_workload_analysis_t* analysis,
    const qihse_memory_topology_t* topology,
    qihse_memory_type_t* out_type,
    qihse_memory_planner_reason_t* out_reason
) {
    qihse_memory_topology_t default_topology;
    const qihse_memory_topology_t* topo = topology;
    double temporal;
    double spatial;
    double entanglement;

    if (!analysis || !out_type) {
        errno = EINVAL;
        return false;
    }
    if (!topo) {
        if (!qihse_memory_default_topology(&default_topology)) {
            return false;
        }
        topo = &default_topology;
    }

    temporal = qihse_memory_clamp_unit(analysis->temporal_locality);
    spatial = qihse_memory_clamp_unit(analysis->spatial_locality);
    entanglement = qihse_memory_clamp_unit(analysis->entanglement_density);

    if (analysis->phase == QIHSE_MEMORY_PHASE_SUPERPOSITION &&
        analysis->working_set_size <= topo->superposition_buffer.capacity) {
        *out_type = QIHSE_MEM_HMA_SUPERPOSITION;
        if (out_reason) {
            *out_reason = QIHSE_MEMORY_PLANNER_REASON_SUPERPOSITION_PHASE;
        }
        return true;
    }

    if (analysis->phase == QIHSE_MEMORY_PHASE_INTERACTION &&
        analysis->working_set_size <= topo->interaction_cache.capacity) {
        *out_type = QIHSE_MEM_HMA_INTERACTION;
        if (out_reason) {
            *out_reason = QIHSE_MEMORY_PLANNER_REASON_INTERACTION_PHASE;
        }
        return true;
    }

    if (analysis->working_set_size > topo->interaction_cache.capacity ||
        entanglement >= 0.50) {
        *out_type = QIHSE_MEM_HMA_ENTANGLEMENT;
        if (out_reason) {
            *out_reason = QIHSE_MEMORY_PLANNER_REASON_ENTANGLEMENT_DENSE;
        }
        return true;
    }

    if (analysis->working_set_size <= topo->superposition_buffer.capacity &&
        temporal >= 0.75 &&
        analysis->superposition_dims != 0u) {
        *out_type = QIHSE_MEM_HMA_SUPERPOSITION;
        if (out_reason) {
            *out_reason = QIHSE_MEMORY_PLANNER_REASON_LOCALITY_PREFERRED;
        }
        return true;
    }

    if (analysis->working_set_size <= topo->interaction_cache.capacity &&
        (analysis->access_pattern == QIHSE_ACCESS_SIMD ||
         analysis->access_pattern == QIHSE_ACCESS_BLOCKED ||
         analysis->access_pattern == QIHSE_ACCESS_STRIDED ||
         spatial >= 0.60 ||
         analysis->read_write_ratio >= 2.0)) {
        *out_type = QIHSE_MEM_HMA_INTERACTION;
        if (out_reason) {
            *out_reason = QIHSE_MEMORY_PLANNER_REASON_LOCALITY_PREFERRED;
        }
        return true;
    }

    *out_type = QIHSE_MEM_HMA_ENTANGLEMENT;
    if (out_reason) {
        *out_reason = QIHSE_MEMORY_PLANNER_REASON_FALLBACK;
    }
    return true;
}

bool qihse_memory_recommend_type(const qihse_memory_workload_analysis_t* analysis,
                                 const qihse_memory_topology_t* topology,
                                 qihse_memory_type_t* out_type) {
    return qihse_memory_recommend_type_internal(analysis, topology, out_type, NULL);
}

bool qihse_memory_recommend_type_with_trace(
    const qihse_memory_workload_analysis_t* analysis,
    const qihse_memory_topology_t* topology,
    qihse_memory_type_t* out_type,
    qihse_memory_planner_trace_t* trace
) {
    qihse_memory_planner_reason_t reason = QIHSE_MEMORY_PLANNER_REASON_UNKNOWN;
    bool ok;

    ok = qihse_memory_recommend_type_internal(analysis, topology, out_type, &reason);
    if (trace) {
        if (ok && out_type) {
            (void)qihse_memory_planner_trace_record(trace, *out_type, reason, analysis);
        } else {
            qihse_memory_planner_trace_clear(trace);
        }
    }
    return ok;
}

qihse_memory_buffer_t* qihse_memory_allocate_for_workload_traced(
    qihse_memory_manager_t manager,
    const qihse_memory_workload_analysis_t* analysis,
    const qihse_memory_topology_t* topology,
    uint32_t flags,
    qihse_memory_planner_trace_t* trace
) {
    qihse_memory_type_t mem_type;
    qihse_memory_type_t fallback_types[QIHSE_MEMORY_ALLOCATION_POLICY_TYPE_COUNT];
    size_t fallback_count;
    size_t i;

    if (!manager || !analysis || analysis->working_set_size == 0u) {
        errno = EINVAL;
        return NULL;
    }
    if (!qihse_memory_recommend_type_with_trace(analysis, topology, &mem_type, trace)) {
        return NULL;
    }

    fallback_count = qihse_memory_allocation_policy_fallback_order(
        mem_type,
        fallback_types,
        sizeof(fallback_types) / sizeof(fallback_types[0]));
    if (fallback_count == 0u) {
        fallback_types[0] = QIHSE_MEM_HOST;
        fallback_count = 1u;
    }

    for (i = 0u; i < fallback_count; i++) {
        qihse_memory_buffer_t* buffer = qihse_memory_allocate(
            manager,
            analysis->working_set_size,
            fallback_types[i],
            analysis->access_pattern,
            flags);
        if (buffer) {
            if (trace && fallback_types[i] != mem_type) {
                (void)qihse_memory_planner_trace_record(
                    trace,
                    fallback_types[i],
                    QIHSE_MEMORY_PLANNER_REASON_FALLBACK,
                    analysis);
            }
            return buffer;
        }
    }

    return NULL;
}

qihse_memory_buffer_t* qihse_memory_allocate_for_workload(
    qihse_memory_manager_t manager,
    const qihse_memory_workload_analysis_t* analysis,
    const qihse_memory_topology_t* topology,
    uint32_t flags
) {
    return qihse_memory_allocate_for_workload_traced(
        manager,
        analysis,
        topology,
        flags,
        NULL);
}

/* ============================================================================
 * MEMORY MANAGER LIFECYCLE
 * ============================================================================ */

qihse_memory_manager_t qihse_memory_manager_create(qihse_context_t ctx, const char* backend_type) {
    if (!ctx || !backend_type) {
        errno = EINVAL;
        return NULL;
    }

    qihse_memory_manager_internal_t* manager = calloc(1, sizeof(qihse_memory_manager_internal_t));
    if (!manager) {
        errno = ENOMEM;
        return NULL;
    }

    manager->ctx = ctx;
    manager->backend_type = strdup(backend_type);
    if (!manager->backend_type) {
        free(manager);
        errno = ENOMEM;
        return NULL;
    }

    /* Initialize atomics */
    atomic_init(&manager->total_allocated, 0);
    atomic_init(&manager->total_used, 0);
    atomic_init(&manager->peak_usage, 0);
    atomic_init(&manager->num_buffers, 0);
    atomic_init(&manager->host_memory, 0);
    atomic_init(&manager->device_memory, 0);
    atomic_init(&manager->unified_memory, 0);
    atomic_init(&manager->total_allocations, 0);
    atomic_init(&manager->total_frees, 0);
    atomic_init(&manager->total_migrations, 0);

    manager->avg_allocation_time = 0.0;
    manager->policy = QIHSE_POLICY_FIRST_FIT;

    /* Initialize mutexes */
    if (pthread_mutex_init(&manager->policy_mutex, NULL) != 0) {
        free((void*)manager->backend_type);
        free(manager);
        errno = ENOMEM;
        return NULL;
    }

    /* Buffer tracking */
    manager->max_buffers = 1024;
    manager->buffers = calloc(manager->max_buffers, sizeof(qihse_memory_buffer_t*));
    if (!manager->buffers) {
        pthread_mutex_destroy(&manager->policy_mutex);
        free((void*)manager->backend_type);
        free(manager);
        errno = ENOMEM;
        return NULL;
    }

    if (pthread_mutex_init(&manager->buffer_mutex, NULL) != 0) {
        free(manager->buffers);
        pthread_mutex_destroy(&manager->policy_mutex);
        free((void*)manager->backend_type);
        free(manager);
        errno = ENOMEM;
        return NULL;
    }

    (void)qihse_memory_migration_backend_register_platform_backends();

    return (qihse_memory_manager_t)manager;
}

void qihse_memory_manager_destroy(qihse_memory_manager_t manager) {
    if (!manager) return;

    qihse_memory_manager_internal_t* internal = (qihse_memory_manager_internal_t*)manager;

    /* Clean up tracked buffers */
    pthread_mutex_lock(&internal->buffer_mutex);
    for (size_t i = 0; i < internal->num_tracked_buffers; i++) {
        if (internal->buffers[i]) {
            qihse_memory_free(manager, internal->buffers[i]);
        }
    }
    pthread_mutex_unlock(&internal->buffer_mutex);

    /* Clean up resources */
    pthread_mutex_destroy(&internal->buffer_mutex);
    pthread_mutex_destroy(&internal->policy_mutex);
    free(internal->buffers);
    free((void*)internal->backend_type);
    free(internal);
}

/* ============================================================================
 * BUFFER ALLOCATION AND MANAGEMENT
 * ============================================================================ */

qihse_memory_buffer_t* qihse_memory_allocate(
    qihse_memory_manager_t manager,
    size_t size,
    qihse_memory_type_t mem_type,
    qihse_memory_access_t access_pattern,
    uint32_t flags
) {
    if (!manager || size == 0) {
        return NULL;
    }

    qihse_memory_manager_internal_t* internal = (qihse_memory_manager_internal_t*)manager;

    /* Allocate buffer structure */
    qihse_memory_buffer_t* buffer = calloc(1, sizeof(qihse_memory_buffer_t));
    if (!buffer) {
        return NULL;
    }

    /* Determine allocation size with alignment */
    size_t alignment = qihse_memory_get_alignment(mem_type);
    buffer->allocated_size = ((size + alignment - 1) / alignment) * alignment;
    buffer->logical_size = size;
    buffer->mem_type = mem_type;
    buffer->access_pattern = access_pattern;
    buffer->flags = flags;
    buffer->preferred_device = 0; /* Default CPU device */
    buffer->is_migratable = true;
    (void)qihse_memory_coherence_init_buffer(buffer);

    /* Allocate actual memory */
    void* data = NULL;
#ifdef _WIN32
    data = _aligned_malloc(buffer->allocated_size, alignment);
    int alloc_result = (data != NULL) ? 0 : ENOMEM;
#else
    int alloc_result = posix_memalign(&data, alignment, buffer->allocated_size);
#endif

    if (alloc_result != 0) {
        free(buffer);
        return NULL;
    }

    /* Initialize ABI buffer */
    buffer->abi_buffer.data = data;
    buffer->abi_buffer.size = buffer->allocated_size;
    buffer->abi_buffer.flags = 0; /* ABI flags */

    /* Apply zero initialization if requested */
    if (flags & QIHSE_MEM_ZERO) {
        memset(data, 0, buffer->allocated_size);
    }

    /* Update statistics atomically */
    atomic_fetch_add(&internal->total_allocated, buffer->allocated_size);
    atomic_fetch_add(&internal->total_used, size);
    atomic_fetch_add(&internal->num_buffers, 1);

    /* Update per-type statistics */
    switch (mem_type) {
        case QIHSE_MEM_HOST:
        case QIHSE_MEM_PINNED:
            atomic_fetch_add(&internal->host_memory, buffer->allocated_size);
            break;
        case QIHSE_MEM_DEVICE:
            atomic_fetch_add(&internal->device_memory, buffer->allocated_size);
            break;
        case QIHSE_MEM_UNIFIED:
        case QIHSE_MEM_HMA_SUPERPOSITION:
        case QIHSE_MEM_HMA_INTERACTION:
        case QIHSE_MEM_HMA_ENTANGLEMENT:
            atomic_fetch_add(&internal->unified_memory, buffer->allocated_size);
            break;
        case QIHSE_MEM_ANCHOR_TABLE:
        case QIHSE_MEM_ANCHOR_WORKSPACE:
            atomic_fetch_add(&internal->host_memory, buffer->allocated_size);
            break;
    }

    atomic_fetch_add(&internal->total_allocations, 1);

    /* Update peak usage */
    size_t current_used = atomic_load(&internal->total_used);
    size_t current_peak = atomic_load(&internal->peak_usage);
    while (current_used > current_peak) {
        if (atomic_compare_exchange_weak(&internal->peak_usage, &current_peak, current_used)) {
            break;
        }
    }

    /* Track buffer if requested */
    if (flags & QIHSE_MEM_TRACKED) {
        pthread_mutex_lock(&internal->buffer_mutex);
        if (internal->num_tracked_buffers < internal->max_buffers) {
            internal->buffers[internal->num_tracked_buffers++] = buffer;
        }
        pthread_mutex_unlock(&internal->buffer_mutex);
    }

    return buffer;
}

void qihse_memory_free(qihse_memory_manager_t manager, qihse_memory_buffer_t* buffer) {
    if (!manager || !buffer) return;

    qihse_memory_manager_internal_t* internal = (qihse_memory_manager_internal_t*)manager;

    /* Update statistics */
    atomic_fetch_sub(&internal->total_allocated, buffer->allocated_size);
    atomic_fetch_sub(&internal->total_used, buffer->logical_size);
    atomic_fetch_sub(&internal->num_buffers, 1);

    /* Update per-type statistics */
    switch (buffer->mem_type) {
        case QIHSE_MEM_HOST:
        case QIHSE_MEM_PINNED:
            atomic_fetch_sub(&internal->host_memory, buffer->allocated_size);
            break;
        case QIHSE_MEM_DEVICE:
            atomic_fetch_sub(&internal->device_memory, buffer->allocated_size);
            break;
        case QIHSE_MEM_UNIFIED:
        case QIHSE_MEM_HMA_SUPERPOSITION:
        case QIHSE_MEM_HMA_INTERACTION:
        case QIHSE_MEM_HMA_ENTANGLEMENT:
            atomic_fetch_sub(&internal->unified_memory, buffer->allocated_size);
            break;
        case QIHSE_MEM_ANCHOR_TABLE:
        case QIHSE_MEM_ANCHOR_WORKSPACE:
            atomic_fetch_sub(&internal->host_memory, buffer->allocated_size);
            break;
    }

    atomic_fetch_add(&internal->total_frees, 1);

    /* Free actual memory */
#ifdef _WIN32
    _aligned_free(buffer->abi_buffer.data);
#else
    free(buffer->abi_buffer.data);
#endif

    /* Remove from tracking if present */
    pthread_mutex_lock(&internal->buffer_mutex);
    for (size_t i = 0; i < internal->num_tracked_buffers; i++) {
        if (internal->buffers[i] == buffer) {
            internal->buffers[i] = internal->buffers[--internal->num_tracked_buffers];
            break;
        }
    }
    pthread_mutex_unlock(&internal->buffer_mutex);

    /* Free buffer structure */
    free(buffer);
}

bool qihse_memory_resize(qihse_memory_manager_t manager, qihse_memory_buffer_t* buffer, size_t new_size) {
    if (!manager || !buffer || new_size == 0) {
        return false;
    }

    qihse_memory_manager_internal_t* internal = (qihse_memory_manager_internal_t*)manager;

    /* Implement basic reallocation */
    /* Future optimization: in-place resize when possible */

    size_t old_logical_size = buffer->logical_size;
    size_t alignment = qihse_memory_get_alignment(buffer->mem_type);
    size_t new_allocated_size = ((new_size + alignment - 1) / alignment) * alignment;

    void* new_data = NULL;
#ifdef _WIN32
    new_data = _aligned_malloc(new_allocated_size, alignment);
    int alloc_result = (new_data != NULL) ? 0 : ENOMEM;
#else
    int alloc_result = posix_memalign(&new_data, alignment, new_allocated_size);
#endif

    if (alloc_result != 0) {
        return false;
    }

    /* Copy existing data */
    size_t copy_size = (new_size < old_logical_size) ? new_size : old_logical_size;
    memcpy(new_data, buffer->abi_buffer.data, copy_size);

    /* Zero new space if expanding and zero flag set */
    if (new_size > old_logical_size && (buffer->flags & QIHSE_MEM_ZERO)) {
        memset((char*)new_data + old_logical_size, 0, new_size - old_logical_size);
    }

    /* Free old memory */
#ifdef _WIN32
    _aligned_free(buffer->abi_buffer.data);
#else
    free(buffer->abi_buffer.data);
#endif

    size_t old_allocated_size = buffer->allocated_size;

    /* Update buffer */
    buffer->abi_buffer.data = new_data;
    buffer->abi_buffer.size = new_allocated_size;
    buffer->allocated_size = new_allocated_size;
    buffer->logical_size = new_size;

    /* Update statistics */
    atomic_fetch_sub(&internal->total_used, old_logical_size);
    atomic_fetch_add(&internal->total_used, new_size);

    /* Update per-type statistics */
    size_t size_diff = new_allocated_size - old_allocated_size;
    switch (buffer->mem_type) {
        case QIHSE_MEM_HOST:
        case QIHSE_MEM_PINNED:
            atomic_fetch_add(&internal->host_memory, size_diff);
            break;
        case QIHSE_MEM_DEVICE:
            atomic_fetch_add(&internal->device_memory, size_diff);
            break;
        case QIHSE_MEM_UNIFIED:
        case QIHSE_MEM_HMA_SUPERPOSITION:
        case QIHSE_MEM_HMA_INTERACTION:
        case QIHSE_MEM_HMA_ENTANGLEMENT:
            atomic_fetch_add(&internal->unified_memory, size_diff);
            break;
        case QIHSE_MEM_ANCHOR_TABLE:
        case QIHSE_MEM_ANCHOR_WORKSPACE:
            atomic_fetch_add(&internal->host_memory, size_diff);
            break;
    }

    return true;
}

/* ============================================================================
 * DATA TRANSFER AND MIGRATION
 * ============================================================================ */

bool qihse_memory_copy(
    qihse_memory_manager_t manager,
    qihse_memory_buffer_t* dst,
    size_t dst_offset,
    const qihse_memory_buffer_t* src,
    size_t src_offset,
    size_t size
) {
    if (!manager || !dst || !src || !dst->abi_buffer.data || !src->abi_buffer.data) {
        return false;
    }

    if (dst_offset + size > dst->allocated_size || src_offset + size > src->allocated_size) {
        return false;
    }

    /* Perform copy */
    memcpy((char*)dst->abi_buffer.data + dst_offset,
           (char*)src->abi_buffer.data + src_offset, size);

    /* Update access tracking */
    atomic_fetch_add(&dst->access_count, 1);
    atomic_fetch_add(&((qihse_memory_buffer_t*)src)->access_count, 1); /* Cast away const for statistics */

    qihse_memory_coherence_record_t src_coherence;
    qihse_memory_coherence_record_t dst_coherence;
    qihse_memory_buffer_t* mutable_src = (qihse_memory_buffer_t*)src;

    if (qihse_memory_coherence_load_buffer(mutable_src, &src_coherence) &&
        qihse_memory_coherence_mark_read(&src_coherence)) {
        (void)qihse_memory_coherence_apply_buffer(mutable_src, &src_coherence);
    }
    if (qihse_memory_coherence_load_buffer(dst, &dst_coherence) &&
        qihse_memory_coherence_mark_write(&dst_coherence)) {
        (void)qihse_memory_coherence_apply_buffer(dst, &dst_coherence);
    }

    return true;
}

bool qihse_memory_migrate(
    qihse_memory_manager_t manager,
    qihse_memory_buffer_t* buffer,
    int target_device,
    qihse_memory_type_t target_type
) {
    qihse_memory_type_t old_type;
    size_t old_allocated_size;
    size_t new_alignment;
    size_t new_allocated_size;
    void* new_data = NULL;
    bool copy_required;

    if (!manager || !buffer) {
        return false;
    }

    qihse_memory_manager_internal_t* internal = (qihse_memory_manager_internal_t*)manager;
    qihse_memory_migration_plan_t plan;
    qihse_memory_coherence_record_t coherence;

    if (!qihse_memory_migration_plan(buffer, target_device, target_type, &plan) ||
        plan.kind == QIHSE_MEMORY_MIGRATION_REJECT) {
        return false;
    }

    if (!qihse_memory_coherence_load_buffer(buffer, &coherence) ||
        !qihse_memory_coherence_begin_migration(&coherence)) {
        return false;
    }

    old_type = buffer->mem_type;
    old_allocated_size = buffer->allocated_size;
    copy_required = (plan.kind == QIHSE_MEMORY_MIGRATION_COPY_REQUIRED);

    if (copy_required) {
        qihse_memory_migration_backend_request_t request;
        qihse_memory_migration_backend_t preferred_backend;

        new_alignment = qihse_memory_get_alignment(target_type);
        new_allocated_size = ((buffer->logical_size + new_alignment - 1u) / new_alignment) * new_alignment;

#ifdef _WIN32
        new_data = _aligned_malloc(new_allocated_size, new_alignment);
        if (!new_data) {
#else
        if (posix_memalign(&new_data, new_alignment, new_allocated_size) != 0) {
#endif
            return false;
        }

        request = qihse_memory_migration_backend_request(
            new_data,
            buffer->abi_buffer.data,
            buffer->logical_size,
            QIHSE_MEMORY_MIGRATION_BACKEND_HOST_MEMCPY);
        request.source_type = buffer->mem_type;
        request.target_type = target_type;
        request.source_device = buffer->preferred_device;
        request.target_device = target_device;

        preferred_backend = qihse_memory_migration_backend_for_migration(
            request.source_type,
            request.target_type
        );
        if (!qihse_memory_migration_backend_execute_with_fallback(
                &request,
                preferred_backend)) {
            free(new_data);
            return false;
        }

        if (new_allocated_size > buffer->logical_size) {
            memset((char*)new_data + buffer->logical_size, 0, new_allocated_size - buffer->logical_size);
        }
    }

    if (!qihse_memory_coherence_complete_migration(&coherence, target_type, target_device)) {
        free(new_data);
        return false;
    }

    if (copy_required) {
        free(buffer->abi_buffer.data);
        buffer->abi_buffer.data = new_data;
        buffer->abi_buffer.size = new_allocated_size;
        buffer->allocated_size = new_allocated_size;
        buffer->alignment = new_alignment;

        switch (old_type) {
            case QIHSE_MEM_HOST:
            case QIHSE_MEM_PINNED:
            case QIHSE_MEM_ANCHOR_TABLE:
            case QIHSE_MEM_ANCHOR_WORKSPACE:
                atomic_fetch_sub(&internal->host_memory, old_allocated_size);
                break;
            case QIHSE_MEM_DEVICE:
                atomic_fetch_sub(&internal->device_memory, old_allocated_size);
                break;
            case QIHSE_MEM_UNIFIED:
            case QIHSE_MEM_HMA_SUPERPOSITION:
            case QIHSE_MEM_HMA_INTERACTION:
            case QIHSE_MEM_HMA_ENTANGLEMENT:
                atomic_fetch_sub(&internal->unified_memory, old_allocated_size);
                break;
        }

        switch (target_type) {
            case QIHSE_MEM_HOST:
            case QIHSE_MEM_PINNED:
            case QIHSE_MEM_ANCHOR_TABLE:
            case QIHSE_MEM_ANCHOR_WORKSPACE:
                atomic_fetch_add(&internal->host_memory, buffer->allocated_size);
                break;
            case QIHSE_MEM_DEVICE:
                atomic_fetch_add(&internal->device_memory, buffer->allocated_size);
                break;
            case QIHSE_MEM_UNIFIED:
            case QIHSE_MEM_HMA_SUPERPOSITION:
            case QIHSE_MEM_HMA_INTERACTION:
            case QIHSE_MEM_HMA_ENTANGLEMENT:
                atomic_fetch_add(&internal->unified_memory, buffer->allocated_size);
                break;
        }
    }

    if (!qihse_memory_coherence_apply_buffer(buffer, &coherence)) {
        return false;
    }

    atomic_fetch_add(&internal->total_migrations, 1);

    return true;
}

bool qihse_memory_prefetch(
    qihse_memory_manager_t manager,
    qihse_memory_buffer_t* buffer,
    int device
) {
    if (!manager || !buffer) {
        return false;
    }

    /* Prefetch not implemented in this version */
    /* Future: Implement prefetching for device-specific memory */

    buffer->preferred_device = device;
    return true;
}

bool qihse_memory_maintenance_start(
    qihse_memory_manager_t manager,
    struct qihse_memory_migration_scheduler_s* scheduler
) {
    if (!manager || !scheduler) {
        return false;
    }

    qihse_memory_migration_scheduler_reset(scheduler);
    return true;
}

size_t qihse_memory_maintenance_snapshot(
    qihse_memory_manager_t manager,
    struct qihse_memory_migration_scheduler_s* scheduler,
    int target_device,
    size_t max_candidates
) {
    qihse_memory_manager_internal_t* internal = (qihse_memory_manager_internal_t*)manager;
    size_t enqueued;
    size_t index;
    qihse_memory_buffer_t* buffer;
    qihse_memory_type_t target_type;
    qihse_memory_policy_t manager_policy;
    qihse_memory_migration_candidate_t candidate;
    qihse_memory_migration_task_t task;
    size_t candidate_limit;

    if (!manager || !scheduler) {
        return 0u;
    }

    pthread_mutex_lock(&internal->policy_mutex);
    manager_policy = internal->policy;
    pthread_mutex_unlock(&internal->policy_mutex);

    candidate_limit = max_candidates;

    enqueued = 0u;
    pthread_mutex_lock(&internal->buffer_mutex);
    for (index = 0u; index < internal->num_tracked_buffers; ++index) {
        if (candidate_limit != 0u && enqueued >= candidate_limit) {
            break;
        }

        buffer = internal->buffers[index];
        if (!buffer || !buffer->is_migratable) {
            continue;
        }

        target_type = qihse_memory_maintenance_derive_target_type(buffer, manager_policy, target_device);
        if (!qihse_memory_migration_scheduler_score(
                buffer,
                target_device,
                target_type,
                &scheduler->config,
                &task)) {
            continue;
        }

        candidate.buffer = buffer;
        candidate.target_device = target_device;
        candidate.target_type = target_type;

        if (qihse_memory_migration_scheduler_enqueue(scheduler, &candidate)) {
            enqueued++;
        }
    }
    pthread_mutex_unlock(&internal->buffer_mutex);

    return enqueued;
}

size_t qihse_memory_maintenance_step(
    qihse_memory_manager_t manager,
    struct qihse_memory_migration_scheduler_s* scheduler,
    size_t max_tasks
) {
    if (!manager || !scheduler) {
        return 0u;
    }

    return qihse_memory_migration_scheduler_run(manager, scheduler, max_tasks);
}

const char* qihse_memory_migration_decision_reason_name(
    qihse_memory_migration_decision_reason_t reason
) {
    switch (reason) {
        case QIHSE_MEMORY_MIGRATION_DECISION_REASON_ACCEPTED:
            return "accepted";
        case QIHSE_MEMORY_MIGRATION_DECISION_REASON_INVALID_ARGUMENTS:
            return "invalid-arguments";
        case QIHSE_MEMORY_MIGRATION_DECISION_REASON_NOT_MIGRATABLE:
            return "not-migratable";
        case QIHSE_MEMORY_MIGRATION_DECISION_REASON_ALREADY_PLACED:
            return "already-placed";
        case QIHSE_MEMORY_MIGRATION_DECISION_REASON_POLICY_REJECT:
            return "policy-reject";
        case QIHSE_MEMORY_MIGRATION_DECISION_REASON_BELOW_SCORE_THRESHOLD:
            return "below-score-threshold";
        case QIHSE_MEMORY_MIGRATION_DECISION_REASON_UNKNOWN:
        default:
            return "unknown";
    }
}

bool qihse_memory_migration_decision_inspect(
    const qihse_memory_buffer_t* buffer,
    int target_device,
    qihse_memory_type_t target_type,
    qihse_memory_migration_decision_t* out_decision
) {
    qihse_memory_migration_decision_config_t config;
    qihse_memory_migration_plan_t plan;
    double residency_component;
    double access_component;
    double coherence_component;
    double target_component;
    double policy_component;

    if (!buffer || !out_decision) {
        return false;
    }

    memset(out_decision, 0, sizeof(*out_decision));
    out_decision->buffer = (qihse_memory_buffer_t*)buffer;
    out_decision->target_device = target_device;
    out_decision->source_type = buffer->mem_type;
    out_decision->target_type = target_type;
    out_decision->reason = QIHSE_MEMORY_MIGRATION_DECISION_REASON_UNKNOWN;

    if (!qihse_memory_migration_plan(buffer, target_device, target_type, &plan)) {
        out_decision->reason = QIHSE_MEMORY_MIGRATION_DECISION_REASON_INVALID_ARGUMENTS;
        snprintf(out_decision->plan_reason, sizeof(out_decision->plan_reason), "%s", "invalid target/type or null input");
        return true;
    }

    (void)strncpy(
        out_decision->plan_reason,
        plan.reason,
        sizeof(out_decision->plan_reason) - 1);
    out_decision->plan_reason[sizeof(out_decision->plan_reason) - 1] = '\0';
    out_decision->plan_reason[sizeof(out_decision->plan_reason) - 1u] = '\0';

    out_decision->source_type = plan.source_type;
    out_decision->preserves_coherence = plan.preserves_coherence;
    out_decision->zero_copy = (plan.kind == QIHSE_MEMORY_MIGRATION_ZERO_COPY);
    out_decision->copy_required = (plan.kind == QIHSE_MEMORY_MIGRATION_COPY_REQUIRED);

    if (plan.kind == QIHSE_MEMORY_MIGRATION_REJECT) {
        out_decision->reason = qihse_memory_migration_plan_reject_reason(&plan);
        return true;
    }

    if (buffer->is_migratable == false) {
        out_decision->reason = QIHSE_MEMORY_MIGRATION_DECISION_REASON_NOT_MIGRATABLE;
        return true;
    }

    if (buffer->mem_type == target_type && buffer->preferred_device == target_device) {
        out_decision->reason = QIHSE_MEMORY_MIGRATION_DECISION_REASON_ALREADY_PLACED;
        return true;
    }

    config = qihse_memory_migration_decision_default_config();

    residency_component = config.residency_weight *
        qihse_memory_clamp_score(buffer->residency_score, 0.0, 1.0);
    access_component = config.access_weight *
        qihse_memory_decision_access_score(buffer->access_count, config.hot_access_threshold);
    coherence_component = config.coherence_weight *
        qihse_memory_decision_coherence_score(buffer, &plan);
    target_component = config.target_weight *
        qihse_memory_decision_target_score(target_type);
    policy_component = config.policy_weight *
        qihse_memory_decision_policy_score(&plan);

    out_decision->scoring.residency_component = residency_component;
    out_decision->scoring.access_component = access_component;
    out_decision->scoring.coherence_component = coherence_component;
    out_decision->scoring.target_component = target_component;
    out_decision->scoring.policy_component = policy_component;
    out_decision->scoring.minimum_score = config.minimum_score;
    out_decision->scoring.hot_access_threshold = config.hot_access_threshold;

    out_decision->score = residency_component + access_component + coherence_component +
        target_component + policy_component;

    if (out_decision->score < config.minimum_score) {
        out_decision->reason = QIHSE_MEMORY_MIGRATION_DECISION_REASON_BELOW_SCORE_THRESHOLD;
        return true;
    }

    out_decision->accepted = true;
    out_decision->reason = QIHSE_MEMORY_MIGRATION_DECISION_REASON_ACCEPTED;

    return true;
}

size_t qihse_memory_migration_decision_format(
    char* buffer,
    size_t buffer_size,
    const qihse_memory_migration_decision_t* decision
) {
    int written;

    if (!buffer || buffer_size == 0u || !decision) {
        return 0u;
    }

    written = (int)snprintf(
        buffer,
        buffer_size,
        "target=%s source=%s score=%.6f min=%.6f residency=%.3f access=%.3f coherence=%.3f target=%.3f policy=%.3f decision=%s reason=%s zero_copy=%u copy=%u coherence_ok=%u",
        qihse_memory_type_string(decision->target_type),
        qihse_memory_type_string(decision->source_type),
        decision->score,
        decision->scoring.minimum_score,
        decision->scoring.residency_component,
        decision->scoring.access_component,
        decision->scoring.coherence_component,
        decision->scoring.target_component,
        decision->scoring.policy_component,
        qihse_memory_migration_decision_reason_name(decision->reason),
        decision->plan_reason,
        (unsigned)(decision->zero_copy ? 1 : 0),
        (unsigned)(decision->copy_required ? 1 : 0),
        (unsigned)(decision->preserves_coherence ? 1 : 0)
    );

    if (written < 0) {
        return 0u;
    }

    return (size_t)written;
}

/* ============================================================================
 * STATISTICS AND MONITORING
 * ============================================================================ */

bool qihse_memory_get_stats(qihse_memory_manager_t manager, qihse_memory_stats_t* stats) {
    if (!manager || !stats) {
        return false;
    }

    qihse_memory_manager_internal_t* internal = (qihse_memory_manager_internal_t*)manager;

    /* Atomically read all statistics */
    stats->total_allocated = atomic_load(&internal->total_allocated);
    stats->total_used = atomic_load(&internal->total_used);
    stats->peak_usage = atomic_load(&internal->peak_usage);
    stats->num_buffers = atomic_load(&internal->num_buffers);
    stats->host_memory = atomic_load(&internal->host_memory);
    stats->device_memory = atomic_load(&internal->device_memory);
    stats->unified_memory = atomic_load(&internal->unified_memory);
    stats->total_allocations = atomic_load(&internal->total_allocations);
    stats->total_frees = atomic_load(&internal->total_frees);
    stats->total_migrations = atomic_load(&internal->total_migrations);
    stats->avg_allocation_time = internal->avg_allocation_time;

    return true;
}

void qihse_memory_reset_stats(qihse_memory_manager_t manager) {
    if (!manager) return;

    qihse_memory_manager_internal_t* internal = (qihse_memory_manager_internal_t*)manager;

    /* Reset atomic counters */
    atomic_store(&internal->total_allocations, 0);
    atomic_store(&internal->total_frees, 0);
    atomic_store(&internal->total_migrations, 0);
    internal->avg_allocation_time = 0.0;
}

/* ============================================================================
 * POLICY MANAGEMENT
 * ============================================================================ */

void qihse_memory_set_policy(qihse_memory_manager_t manager, qihse_memory_policy_t policy) {
    if (!manager) return;

    qihse_memory_manager_internal_t* internal = (qihse_memory_manager_internal_t*)manager;

    pthread_mutex_lock(&internal->policy_mutex);
    internal->policy = policy;
    pthread_mutex_unlock(&internal->policy_mutex);
}

qihse_memory_policy_t qihse_memory_get_policy(qihse_memory_manager_t manager) {
    if (!manager) return QIHSE_POLICY_FIRST_FIT;

    qihse_memory_manager_internal_t* internal = (qihse_memory_manager_internal_t*)manager;

    pthread_mutex_lock(&internal->policy_mutex);
    qihse_memory_policy_t policy = internal->policy;
    pthread_mutex_unlock(&internal->policy_mutex);

    return policy;
}

/* ============================================================================
 * QIHSE-NOT_STISLA INTEGRATION: ANCHOR MEMORY MANAGEMENT
 * ============================================================================ */

/**
 * Anchor table entry for LRU tracking.
 */
typedef struct qihse_anchor_table_entry_s {
    qihse_memory_buffer_t* buffer;    /* The anchor table buffer */
    int workload_type;                /* Associated workload type */
    size_t memory_used;               /* Memory usage of this table */
    uint64_t last_access_time;        /* Last access timestamp */
    uint64_t creation_time;           /* Creation timestamp */
    struct qihse_anchor_table_entry_s* next; /* LRU list next pointer */
    struct qihse_anchor_table_entry_s* prev; /* LRU list prev pointer */
} qihse_anchor_table_entry_t;

/**
 * Anchor memory manager internal structure.
 */
typedef struct qihse_anchor_memory_manager_s {
    qihse_memory_manager_t parent_manager; /* Parent memory manager */

    /* Memory limits */
    size_t max_memory_bytes;          /* Maximum memory budget */
    bool enable_lru;                  /* Enable LRU pruning */

    /* Current state */
    size_t current_memory_used;       /* Current memory usage */
    size_t num_active_tables;         /* Number of active anchor tables */
    size_t total_pruned_count;        /* Total anchors pruned */

    /* LRU tracking */
    qihse_anchor_table_entry_t* lru_head; /* Most recently used */
    qihse_anchor_table_entry_t* lru_tail; /* Least recently used */

    /* Statistics */
    uint64_t total_allocations;       /* Total anchor table allocations */
    uint64_t total_prunings;          /* Total LRU pruning operations */

    /* Thread safety */
    pthread_mutex_t mutex;            /* Protect all operations */
} qihse_anchor_memory_manager_internal_t;

qihse_anchor_memory_manager_t qihse_anchor_memory_manager_create(
    qihse_memory_manager_t manager,
    size_t max_memory_mb,
    bool enable_lru
) {
    if (!manager || max_memory_mb == 0) {
        return NULL;
    }

    qihse_anchor_memory_manager_internal_t* anchor_manager =
        calloc(1, sizeof(qihse_anchor_memory_manager_internal_t));

    if (!anchor_manager) {
        return NULL;
    }

    anchor_manager->parent_manager = manager;
    anchor_manager->max_memory_bytes = max_memory_mb * 1024 * 1024; /* Convert MB to bytes */
    anchor_manager->enable_lru = enable_lru;
    anchor_manager->current_memory_used = 0;
    anchor_manager->num_active_tables = 0;
    anchor_manager->total_pruned_count = 0;
    anchor_manager->total_allocations = 0;
    anchor_manager->total_prunings = 0;
    anchor_manager->lru_head = NULL;
    anchor_manager->lru_tail = NULL;

    /* Initialize mutex */
    if (pthread_mutex_init(&anchor_manager->mutex, NULL) != 0) {
        free(anchor_manager);
        return NULL;
    }

    return (qihse_anchor_memory_manager_t)anchor_manager;
}

void qihse_anchor_memory_manager_destroy(qihse_anchor_memory_manager_t anchor_manager) {
    if (!anchor_manager) return;

    qihse_anchor_memory_manager_internal_t* internal =
        (qihse_anchor_memory_manager_internal_t*)anchor_manager;

    pthread_mutex_lock(&internal->mutex);

    /* Free all anchor table entries */
    qihse_anchor_table_entry_t* entry = internal->lru_head;
    while (entry) {
        qihse_anchor_table_entry_t* next = entry->next;

        /* Free the buffer */
        if (entry->buffer) {
            qihse_memory_free(internal->parent_manager, entry->buffer);
        }

        free(entry);
        entry = next;
    }

    pthread_mutex_unlock(&internal->mutex);
    pthread_mutex_destroy(&internal->mutex);
    free(internal);
}

qihse_memory_buffer_t* qihse_anchor_memory_allocate_table(
    qihse_anchor_memory_manager_t anchor_manager,
    size_t max_anchors,
    int workload_type
) {
    if (!anchor_manager || max_anchors == 0) {
        return NULL;
    }

    qihse_anchor_memory_manager_internal_t* internal =
        (qihse_anchor_memory_manager_internal_t*)anchor_manager;

    /* Calculate required memory for anchor table */
    size_t anchor_size = sizeof(not_stisla_anchor_t);
    size_t table_overhead = sizeof(not_stisla_anchor_table_t);
    size_t required_memory = (max_anchors * anchor_size) + table_overhead;

    pthread_mutex_lock(&internal->mutex);

    /* Check if allocation exceeds memory limits */
    if (!qihse_anchor_memory_check_limits(anchor_manager, required_memory)) {
        /* Try LRU pruning if enabled */
        if (internal->enable_lru) {
            size_t pruned = qihse_anchor_memory_prune_lru(anchor_manager, required_memory);
            if (pruned == 0 || !qihse_anchor_memory_check_limits(anchor_manager, required_memory)) {
                pthread_mutex_unlock(&internal->mutex);
                return NULL; /* Still can't allocate */
            }
        } else {
            pthread_mutex_unlock(&internal->mutex);
            return NULL; /* LRU disabled and over limit */
        }
    }

    /* Allocate the anchor table buffer */
    qihse_memory_buffer_t* buffer = qihse_memory_allocate(
        internal->parent_manager,
        required_memory,
        QIHSE_MEM_ANCHOR_TABLE,
        QIHSE_ACCESS_RANDOM, /* Anchor tables have random access patterns */
        0 /* No special flags */
    );

    if (!buffer) {
        pthread_mutex_unlock(&internal->mutex);
        return NULL;
    }

    /* Create anchor table entry for tracking */
    qihse_anchor_table_entry_t* entry = calloc(1, sizeof(qihse_anchor_table_entry_t));
    if (!entry) {
        qihse_memory_free(internal->parent_manager, buffer);
        pthread_mutex_unlock(&internal->mutex);
        return NULL;
    }

    entry->buffer = buffer;
    entry->workload_type = workload_type;
    entry->memory_used = required_memory;
    entry->creation_time = time(NULL);
    entry->last_access_time = entry->creation_time;

    /* Add to LRU list (as most recently used) */
    if (internal->lru_head) {
        internal->lru_head->prev = entry;
        entry->next = internal->lru_head;
    } else {
        internal->lru_tail = entry;
    }
    internal->lru_head = entry;

    /* Update statistics */
    internal->current_memory_used += required_memory;
    internal->num_active_tables++;
    internal->total_allocations++;

    pthread_mutex_unlock(&internal->mutex);
    return buffer;
}

qihse_memory_buffer_t* qihse_anchor_memory_allocate_workspace(
    qihse_anchor_memory_manager_t anchor_manager,
    size_t workspace_size
) {
    if (!anchor_manager || workspace_size == 0) {
        return NULL;
    }

    qihse_anchor_memory_manager_internal_t* internal =
        (qihse_anchor_memory_manager_internal_t*)anchor_manager;

    /* Allocate workspace buffer */
    return qihse_memory_allocate(
        internal->parent_manager,
        workspace_size,
        QIHSE_MEM_ANCHOR_WORKSPACE,
        QIHSE_ACCESS_SEQUENTIAL, /* Workspace typically sequential access */
        0 /* No special flags */
    );
}

bool qihse_anchor_memory_check_limits(
    qihse_anchor_memory_manager_t anchor_manager,
    size_t requested_size
) {
    if (!anchor_manager) return false;

    qihse_anchor_memory_manager_internal_t* internal =
        (qihse_anchor_memory_manager_internal_t*)anchor_manager;

    return (internal->current_memory_used + requested_size) <= internal->max_memory_bytes;
}

size_t qihse_anchor_memory_prune_lru(
    qihse_anchor_memory_manager_t anchor_manager,
    size_t target_free_bytes
) {
    if (!anchor_manager) return 0;

    qihse_anchor_memory_manager_internal_t* internal =
        (qihse_anchor_memory_manager_internal_t*)anchor_manager;

    size_t freed_bytes = 0;
    size_t pruned_count = 0;

    /* Remove least recently used entries until we free enough memory */
    while (internal->lru_tail && freed_bytes < target_free_bytes) {
        qihse_anchor_table_entry_t* victim = internal->lru_tail;

        /* Remove from LRU list */
        if (victim->prev) {
            victim->prev->next = NULL;
        } else {
            internal->lru_head = NULL;
        }
        internal->lru_tail = victim->prev;

        /* Free the buffer */
        if (victim->buffer) {
            qihse_memory_free(internal->parent_manager, victim->buffer);
        }

        /* Update statistics */
        freed_bytes += victim->memory_used;
        internal->current_memory_used -= victim->memory_used;
        internal->num_active_tables--;
        pruned_count++;

        free(victim);
    }

    if (pruned_count > 0) {
        internal->total_prunings++;
        internal->total_pruned_count += pruned_count;
    }

    return pruned_count;
}

void qihse_anchor_memory_get_stats(
    qihse_anchor_memory_manager_t anchor_manager,
    size_t* current_usage_bytes,
    size_t* max_usage_bytes,
    size_t* num_tables,
    size_t* pruned_count
) {
    if (!anchor_manager) return;

    qihse_anchor_memory_manager_internal_t* internal =
        (qihse_anchor_memory_manager_internal_t*)anchor_manager;

    if (current_usage_bytes) *current_usage_bytes = internal->current_memory_used;
    if (max_usage_bytes) *max_usage_bytes = internal->max_memory_bytes;
    if (num_tables) *num_tables = internal->num_active_tables;
    if (pruned_count) *pruned_count = internal->total_pruned_count;
}

bool qihse_anchor_memory_optimize_for_workload(
    qihse_anchor_memory_manager_t anchor_manager,
    qihse_memory_buffer_t* table,
    int workload_type
) {
    if (!anchor_manager || !table) return false;

    qihse_anchor_memory_manager_internal_t* internal =
        (qihse_anchor_memory_manager_internal_t*)anchor_manager;

    /* Find the table entry and update its workload type */
    pthread_mutex_lock(&internal->mutex);

    qihse_anchor_table_entry_t* entry = internal->lru_head;
    while (entry) {
        if (entry->buffer == table) {
            entry->workload_type = workload_type;
            entry->last_access_time = time(NULL);
            pthread_mutex_unlock(&internal->mutex);
            return true;
        }
        entry = entry->next;
    }

    pthread_mutex_unlock(&internal->mutex);
    return false; /* Table not found */
}
