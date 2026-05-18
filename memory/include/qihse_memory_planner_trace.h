/*
 * QIHSE - Memory Planner Decision Telemetry
 *
 * Lightweight helpers for capturing why the UMA/HMA planner selected a memory
 * type for a workload. This module is intentionally independent from the
 * planner implementation so qihse_memory_recommend_type can adopt it later
 * without changing allocation behavior.
 */

#ifndef QIHSE_MEMORY_PLANNER_TRACE_H
#define QIHSE_MEMORY_PLANNER_TRACE_H

#include <stdbool.h>
#include <stddef.h>

#include "qihse_memory.h"

#ifdef __cplusplus
extern "C" {
#endif

#define QIHSE_MEMORY_PLANNER_TRACE_REASON_SIZE 128u

typedef enum qihse_memory_planner_reason_e {
    QIHSE_MEMORY_PLANNER_REASON_UNKNOWN = 0,
    QIHSE_MEMORY_PLANNER_REASON_FALLBACK = 1,
    QIHSE_MEMORY_PLANNER_REASON_SMALL_WORKING_SET = 2,
    QIHSE_MEMORY_PLANNER_REASON_SEQUENTIAL_TRANSFER = 3,
    QIHSE_MEMORY_PLANNER_REASON_SUPERPOSITION_PHASE = 4,
    QIHSE_MEMORY_PLANNER_REASON_INTERACTION_PHASE = 5,
    QIHSE_MEMORY_PLANNER_REASON_ENTANGLEMENT_DENSE = 6,
    QIHSE_MEMORY_PLANNER_REASON_MEASUREMENT_READBACK = 7,
    QIHSE_MEMORY_PLANNER_REASON_LOCALITY_PREFERRED = 8
} qihse_memory_planner_reason_t;

typedef struct qihse_memory_planner_trace_facts_s {
    bool has_workload;
    qihse_memory_access_t access_pattern;
    double read_write_ratio;
    size_t working_set_size;
    double temporal_locality;
    double spatial_locality;
    size_t superposition_dims;
    double entanglement_density;
    qihse_memory_phase_t phase;
} qihse_memory_planner_trace_facts_t;

typedef struct qihse_memory_planner_trace_s {
    qihse_memory_type_t selected_type;
    qihse_memory_planner_reason_t reason_code;
    qihse_memory_planner_trace_facts_t facts;
    char reason[QIHSE_MEMORY_PLANNER_TRACE_REASON_SIZE];
} qihse_memory_planner_trace_t;

const char* qihse_memory_planner_trace_memory_type_name(qihse_memory_type_t mem_type);
const char* qihse_memory_planner_reason_name(qihse_memory_planner_reason_t reason);

void qihse_memory_planner_trace_clear(qihse_memory_planner_trace_t* trace);

bool qihse_memory_planner_trace_record(
    qihse_memory_planner_trace_t* trace,
    qihse_memory_type_t selected_type,
    qihse_memory_planner_reason_t reason_code,
    const qihse_memory_workload_analysis_t* workload
);

bool qihse_memory_recommend_type_with_trace(
    const qihse_memory_workload_analysis_t* analysis,
    const qihse_memory_topology_t* topology,
    qihse_memory_type_t* out_type,
    qihse_memory_planner_trace_t* trace
);

qihse_memory_buffer_t* qihse_memory_allocate_for_workload_traced(
    qihse_memory_manager_t manager,
    const qihse_memory_workload_analysis_t* analysis,
    const qihse_memory_topology_t* topology,
    uint32_t flags,
    qihse_memory_planner_trace_t* trace
);

size_t qihse_memory_planner_trace_format_reason(
    char* buffer,
    size_t buffer_size,
    qihse_memory_type_t selected_type,
    qihse_memory_planner_reason_t reason_code,
    const qihse_memory_planner_trace_facts_t* facts
);

#ifdef __cplusplus
}
#endif

#endif /* QIHSE_MEMORY_PLANNER_TRACE_H */
