/*
 * QIHSE - Memory Planner Decision Telemetry Tests
 */

#include "../memory/include/qihse_memory_planner_trace.h"

#include <assert.h>
#include <stdbool.h>
#include <string.h>

static void test_record_captures_selection_and_workload(void)
{
    qihse_memory_workload_analysis_t workload;
    qihse_memory_planner_trace_t trace;

    memset(&workload, 0, sizeof(workload));
    workload.access_pattern = QIHSE_ACCESS_SEQUENTIAL;
    workload.read_write_ratio = 8.0;
    workload.working_set_size = 4096u;
    workload.temporal_locality = 0.75;
    workload.spatial_locality = 0.90;
    workload.superposition_dims = 128u;
    workload.entanglement_density = 0.25;
    workload.phase = QIHSE_MEMORY_PHASE_SUPERPOSITION;

    qihse_memory_planner_trace_clear(&trace);

    assert(qihse_memory_planner_trace_record(
        &trace,
        QIHSE_MEM_HMA_SUPERPOSITION,
        QIHSE_MEMORY_PLANNER_REASON_SUPERPOSITION_PHASE,
        &workload
    ));

    assert(trace.selected_type == QIHSE_MEM_HMA_SUPERPOSITION);
    assert(trace.reason_code == QIHSE_MEMORY_PLANNER_REASON_SUPERPOSITION_PHASE);
    assert(trace.facts.has_workload);
    assert(trace.facts.access_pattern == QIHSE_ACCESS_SEQUENTIAL);
    assert(trace.facts.working_set_size == 4096u);
    assert(trace.facts.phase == QIHSE_MEMORY_PHASE_SUPERPOSITION);
    assert(strstr(trace.reason, "selected=hma-superposition") != NULL);
    assert(strstr(trace.reason, "reason=superposition-phase") != NULL);
    assert(strstr(trace.reason, "phase=superposition") != NULL);
    assert(strstr(trace.reason, "access=sequential") != NULL);
}

static void test_record_handles_missing_workload(void)
{
    qihse_memory_planner_trace_t trace;

    qihse_memory_planner_trace_clear(&trace);

    assert(qihse_memory_planner_trace_record(
        &trace,
        QIHSE_MEM_HOST,
        QIHSE_MEMORY_PLANNER_REASON_FALLBACK,
        NULL
    ));

    assert(trace.selected_type == QIHSE_MEM_HOST);
    assert(trace.reason_code == QIHSE_MEMORY_PLANNER_REASON_FALLBACK);
    assert(!trace.facts.has_workload);
    assert(strcmp(trace.reason, "selected=host reason=fallback workload=none") == 0);
}

static void test_format_reason_respects_buffer_size(void)
{
    qihse_memory_planner_trace_facts_t facts;
    char buffer[16];
    size_t written;

    memset(&facts, 0, sizeof(facts));
    facts.has_workload = true;
    facts.access_pattern = QIHSE_ACCESS_RANDOM;
    facts.phase = QIHSE_MEMORY_PHASE_INIT;

    written = qihse_memory_planner_trace_format_reason(
        buffer,
        sizeof(buffer),
        QIHSE_MEM_UNIFIED,
        QIHSE_MEMORY_PLANNER_REASON_LOCALITY_PREFERRED,
        &facts
    );

    assert(written == sizeof(buffer) - 1u);
    assert(buffer[sizeof(buffer) - 1u] == '\0');
}

static void test_null_trace_is_rejected(void)
{
    assert(!qihse_memory_planner_trace_record(
        NULL,
        QIHSE_MEM_HOST,
        QIHSE_MEMORY_PLANNER_REASON_UNKNOWN,
        NULL
    ));
}

int main(void)
{
    test_record_captures_selection_and_workload();
    test_record_handles_missing_workload();
    test_format_reason_respects_buffer_size();
    test_null_trace_is_rejected();

    return 0;
}
