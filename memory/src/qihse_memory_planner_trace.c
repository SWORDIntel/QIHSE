/*
 * QIHSE - Memory Planner Decision Telemetry
 */

#include "../include/qihse_memory_planner_trace.h"

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>

static const char* qihse_memory_access_name(qihse_memory_access_t access_pattern)
{
    switch (access_pattern) {
        case QIHSE_ACCESS_RANDOM:
            return "random";
        case QIHSE_ACCESS_SEQUENTIAL:
            return "sequential";
        case QIHSE_ACCESS_STRIDED:
            return "strided";
        case QIHSE_ACCESS_BLOCKED:
            return "blocked";
        case QIHSE_ACCESS_SIMD:
            return "simd";
        default:
            return "unknown-access";
    }
}

static const char* qihse_memory_phase_name(qihse_memory_phase_t phase)
{
    switch (phase) {
        case QIHSE_MEMORY_PHASE_INIT:
            return "init";
        case QIHSE_MEMORY_PHASE_SUPERPOSITION:
            return "superposition";
        case QIHSE_MEMORY_PHASE_INTERACTION:
            return "interaction";
        case QIHSE_MEMORY_PHASE_AMPLIFICATION:
            return "amplification";
        case QIHSE_MEMORY_PHASE_MEASUREMENT:
            return "measurement";
        default:
            return "unknown-phase";
    }
}

const char* qihse_memory_planner_trace_memory_type_name(qihse_memory_type_t mem_type)
{
    switch (mem_type) {
        case QIHSE_MEM_HOST:
            return "host";
        case QIHSE_MEM_PINNED:
            return "pinned";
        case QIHSE_MEM_DEVICE:
            return "device";
        case QIHSE_MEM_UNIFIED:
            return "unified";
        case QIHSE_MEM_HMA_SUPERPOSITION:
            return "hma-superposition";
        case QIHSE_MEM_HMA_INTERACTION:
            return "hma-interaction";
        case QIHSE_MEM_HMA_ENTANGLEMENT:
            return "hma-entanglement";
        case QIHSE_MEM_ANCHOR_TABLE:
            return "anchor-table";
        case QIHSE_MEM_ANCHOR_WORKSPACE:
            return "anchor-workspace";
        default:
            return "unknown-memory";
    }
}

const char* qihse_memory_planner_reason_name(qihse_memory_planner_reason_t reason)
{
    switch (reason) {
        case QIHSE_MEMORY_PLANNER_REASON_UNKNOWN:
            return "unknown";
        case QIHSE_MEMORY_PLANNER_REASON_FALLBACK:
            return "fallback";
        case QIHSE_MEMORY_PLANNER_REASON_SMALL_WORKING_SET:
            return "small-working-set";
        case QIHSE_MEMORY_PLANNER_REASON_SEQUENTIAL_TRANSFER:
            return "sequential-transfer";
        case QIHSE_MEMORY_PLANNER_REASON_SUPERPOSITION_PHASE:
            return "superposition-phase";
        case QIHSE_MEMORY_PLANNER_REASON_INTERACTION_PHASE:
            return "interaction-phase";
        case QIHSE_MEMORY_PLANNER_REASON_ENTANGLEMENT_DENSE:
            return "entanglement-dense";
        case QIHSE_MEMORY_PLANNER_REASON_MEASUREMENT_READBACK:
            return "measurement-readback";
        case QIHSE_MEMORY_PLANNER_REASON_LOCALITY_PREFERRED:
            return "locality-preferred";
        default:
            return "unknown";
    }
}

static qihse_memory_planner_trace_facts_t qihse_memory_planner_trace_make_facts(
    const qihse_memory_workload_analysis_t* workload
)
{
    qihse_memory_planner_trace_facts_t facts;

    memset(&facts, 0, sizeof(facts));
    if (workload == NULL) {
        facts.has_workload = false;
        return facts;
    }

    facts.has_workload = true;
    facts.access_pattern = workload->access_pattern;
    facts.read_write_ratio = workload->read_write_ratio;
    facts.working_set_size = workload->working_set_size;
    facts.temporal_locality = workload->temporal_locality;
    facts.spatial_locality = workload->spatial_locality;
    facts.superposition_dims = workload->superposition_dims;
    facts.entanglement_density = workload->entanglement_density;
    facts.phase = workload->phase;

    return facts;
}

void qihse_memory_planner_trace_clear(qihse_memory_planner_trace_t* trace)
{
    if (trace == NULL) {
        return;
    }

    memset(trace, 0, sizeof(*trace));
    trace->selected_type = QIHSE_MEM_HOST;
    trace->reason_code = QIHSE_MEMORY_PLANNER_REASON_UNKNOWN;
    (void)qihse_memory_planner_trace_format_reason(
        trace->reason,
        sizeof(trace->reason),
        trace->selected_type,
        trace->reason_code,
        &trace->facts
    );
}

size_t qihse_memory_planner_trace_format_reason(
    char* buffer,
    size_t buffer_size,
    qihse_memory_type_t selected_type,
    qihse_memory_planner_reason_t reason_code,
    const qihse_memory_planner_trace_facts_t* facts
)
{
    int written;

    if (buffer == NULL || buffer_size == 0u) {
        return 0u;
    }

    if (facts == NULL || !facts->has_workload) {
        written = snprintf(
            buffer,
            buffer_size,
            "selected=%s reason=%s workload=none",
            qihse_memory_planner_trace_memory_type_name(selected_type),
            qihse_memory_planner_reason_name(reason_code)
        );
    } else {
        written = snprintf(
            buffer,
            buffer_size,
            "selected=%s reason=%s phase=%s access=%s ws=%lu rw=%.2f tl=%.2f sl=%.2f dims=%lu ent=%.2f",
            qihse_memory_planner_trace_memory_type_name(selected_type),
            qihse_memory_planner_reason_name(reason_code),
            qihse_memory_phase_name(facts->phase),
            qihse_memory_access_name(facts->access_pattern),
            (unsigned long)facts->working_set_size,
            facts->read_write_ratio,
            facts->temporal_locality,
            facts->spatial_locality,
            (unsigned long)facts->superposition_dims,
            facts->entanglement_density
        );
    }

    if (written < 0) {
        buffer[0] = '\0';
        return 0u;
    }

    if ((size_t)written >= buffer_size) {
        buffer[buffer_size - 1u] = '\0';
        return buffer_size - 1u;
    }

    return (size_t)written;
}

bool qihse_memory_planner_trace_record(
    qihse_memory_planner_trace_t* trace,
    qihse_memory_type_t selected_type,
    qihse_memory_planner_reason_t reason_code,
    const qihse_memory_workload_analysis_t* workload
)
{
    if (trace == NULL) {
        return false;
    }

    trace->selected_type = selected_type;
    trace->reason_code = reason_code;
    trace->facts = qihse_memory_planner_trace_make_facts(workload);
    (void)qihse_memory_planner_trace_format_reason(
        trace->reason,
        sizeof(trace->reason),
        trace->selected_type,
        trace->reason_code,
        &trace->facts
    );

    /* TICKET #3: QMAG Telemetry Attachment. Persist planner metrics to log securely. */
    {
        int fd = open("./qihse_qmag_telemetry.log", O_WRONLY | O_CREAT | O_APPEND | O_NOFOLLOW, 0600);
        if (fd != -1) {
            char log_buffer[512];
            int len = snprintf(log_buffer, sizeof(log_buffer), 
                "{\"timestamp\": %ld, \"trace\": \"%s\"}\n", 
                (long)time(NULL), trace->reason);
            if (len > 0 && len < (int)sizeof(log_buffer)) {
                ssize_t ret = write(fd, log_buffer, len);
                (void)ret; // Ignore error
            }
            close(fd);
        }
    }

    return true;
}
