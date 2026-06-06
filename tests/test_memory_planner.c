#include "../core/qihse_abi.h"
#include "../memory/include/qihse_memory.h"
#include "../memory/include/qihse_memory_topology_probe.h"
#include "../memory/include/qihse_memory_allocation_policy.h"
#include "../memory/include/qihse_memory_migration_scheduler.h"
#include "../memory/include/qihse_memory_planner_trace.h"
#include "../memory/include/qihse_memory_coherence.h"

#include <stdio.h>
#include <string.h>

#define TEST_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL: %s (%s:%d)\n", msg, __FILE__, __LINE__); \
        return false; \
    } \
} while (0)

static bool test_probed_topology(void) {
    qihse_memory_topology_probe_result_t result;
    memset(&result, 0, sizeof(result));
    
    TEST_ASSERT(qihse_memory_topology_probe_host(&result), "Topology probe should succeed");
    TEST_ASSERT(result.numa_nodes_detected >= 1u, "Should map at least 1 NUMA node");
    TEST_ASSERT(result.topology.numa_nodes >= 1u, "Topology should map NUMA nodes");
    TEST_ASSERT(result.topology.superposition_buffer.capacity > 0u, "Should have superposition capacity");
    return true;
}

static bool test_recommendation_and_qmag_workload(void) {
    qihse_memory_workload_analysis_t analysis;
    qihse_memory_type_t type = QIHSE_MEM_HOST;
    
    memset(&analysis, 0, sizeof(analysis));
    analysis.phase = QIHSE_MEMORY_PHASE_SUPERPOSITION;
    analysis.access_pattern = QIHSE_ACCESS_SIMD;
    analysis.working_set_size = 1024u * 1024u;
    analysis.temporal_locality = 0.95;
    analysis.superposition_dims = 1024u;
    
    TEST_ASSERT(qihse_memory_recommend_type(&analysis, NULL, &type), "Should classify qmag superposition workload");
    TEST_ASSERT(type == QIHSE_MEM_HMA_SUPERPOSITION, "qmag superposition workload should route to HMA superposition");
    return true;
}

static bool test_allocation_fallback(void) {
    qihse_memory_type_t order[4];
    size_t count = qihse_memory_allocation_policy_fallback_order(
        QIHSE_MEM_DEVICE,
        order,
        4u
    );
    TEST_ASSERT(count > 0, "Fallback order should return entries");
    TEST_ASSERT(order[0] == QIHSE_MEM_DEVICE, "Fallback first is target");
    return true;
}

static bool test_migration_decision_traces(void) {
    qihse_memory_planner_trace_t trace;
    qihse_memory_workload_analysis_t workload;
    
    memset(&workload, 0, sizeof(workload));
    workload.phase = QIHSE_MEMORY_PHASE_SUPERPOSITION;
    
    qihse_memory_planner_trace_clear(&trace);
    TEST_ASSERT(qihse_memory_planner_trace_record(
        &trace,
        QIHSE_MEM_HMA_SUPERPOSITION,
        QIHSE_MEMORY_PLANNER_REASON_SUPERPOSITION_PHASE,
        &workload
    ), "Should trace decision");
    
    TEST_ASSERT(trace.selected_type == QIHSE_MEM_HMA_SUPERPOSITION, "Trace type matched");
    TEST_ASSERT(strstr(trace.reason, "hma-superposition") != NULL, "Trace reason formatted");
    return true;
}

static bool test_mocked_migration_scheduler(void) {
    qihse_context_t ctx = NULL;
    qihse_memory_manager_t manager = NULL;
    qihse_memory_buffer_t* buffer = NULL;
    qihse_memory_migration_scheduler_t scheduler;
    qihse_memory_migration_task_t storage[4];
    qihse_memory_migration_candidate_t candidate;
    size_t executed = 0;
    
    TEST_ASSERT(qihse_context_create(NULL, &ctx) == QIHSE_OK, "Context created");
    manager = qihse_memory_manager_create(ctx, "uma");
    TEST_ASSERT(manager != NULL, "Manager created");
    
    /* Allocate buffer */
    buffer = qihse_memory_allocate(manager, 64u, QIHSE_MEM_DEVICE, QIHSE_ACCESS_SEQUENTIAL, QIHSE_MEM_ZERO);
    TEST_ASSERT(buffer != NULL, "Buffer allocated");
    
    buffer->is_migratable = true;
    buffer->residency_score = 0.9;
    buffer->access_count = 1000;
    
    TEST_ASSERT(qihse_memory_migration_scheduler_init(&scheduler, storage, 4, NULL), "Scheduler init");
    
    candidate.buffer = buffer;
    candidate.target_device = 0;
    candidate.target_type = QIHSE_MEM_HOST;
    
    TEST_ASSERT(qihse_memory_migration_scheduler_enqueue(&scheduler, &candidate), "Enqueue to scheduler");
    
    executed = qihse_memory_migration_scheduler_run(manager, &scheduler, 1);
    TEST_ASSERT(executed == 1, "Scheduler triggered mocked migration event");
    TEST_ASSERT(buffer->mem_type == QIHSE_MEM_HOST, "Buffer migrated via mocked event");
    
    qihse_memory_free(manager, buffer);
    qihse_memory_manager_destroy(manager);
    qihse_context_destroy(ctx);
    
    return true;
}

int main(void) {
    struct {
        const char* name;
        bool (*fn)(void);
    } tests[] = {
        {"probed topology", test_probed_topology},
        {"recommendation & qmag workload", test_recommendation_and_qmag_workload},
        {"allocation fallback", test_allocation_fallback},
        {"migration decision traces", test_migration_decision_traces},
        {"mocked migration scheduler", test_mocked_migration_scheduler},
    };

    for (size_t i = 0u; i < sizeof(tests) / sizeof(tests[0]); i++) {
        printf("RUN  %s\n", tests[i].name);
        if (!tests[i].fn()) {
            printf("FAIL %s\n", tests[i].name);
            return 1;
        }
        printf("PASS %s\n", tests[i].name);
    }
    printf("PASS all new e2e memory planner tests\n");
    return 0;
}
