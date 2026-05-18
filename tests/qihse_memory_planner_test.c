#include "../core/qihse_abi.h"
#include "../memory/include/qihse_memory.h"

#include <stdio.h>
#include <string.h>

#define TEST_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL: %s (%s:%d)\n", msg, __FILE__, __LINE__); \
        return false; \
    } \
} while (0)

static bool test_default_topology(void) {
    qihse_memory_topology_t topology;

    memset(&topology, 0, sizeof(topology));
    TEST_ASSERT(qihse_memory_default_topology(&topology),
                "default topology should initialize");
    TEST_ASSERT(topology.superposition_buffer.capacity > 0u,
                "default superposition capacity should be usable");
    TEST_ASSERT(topology.interaction_cache.capacity > 0u,
                "default interaction cache capacity should be usable");
    TEST_ASSERT(topology.entanglement_fabric.capacity > topology.interaction_cache.capacity,
                "entanglement fabric should be the largest default tier");
    return true;
}

static bool test_recommendation_rules(void) {
    qihse_memory_type_t type = QIHSE_MEM_HOST;
    qihse_memory_workload_analysis_t analysis;

    memset(&analysis, 0, sizeof(analysis));
    analysis.phase = QIHSE_MEMORY_PHASE_SUPERPOSITION;
    analysis.access_pattern = QIHSE_ACCESS_SIMD;
    analysis.working_set_size = 1024u * 1024u;
    analysis.temporal_locality = 0.95;
    analysis.superposition_dims = 1024u;
    TEST_ASSERT(qihse_memory_recommend_type(&analysis, NULL, &type),
                "superposition workload should be classified");
    TEST_ASSERT(type == QIHSE_MEM_HMA_SUPERPOSITION,
                "superposition workload should use superposition tier");

    memset(&analysis, 0, sizeof(analysis));
    analysis.phase = QIHSE_MEMORY_PHASE_INTERACTION;
    analysis.access_pattern = QIHSE_ACCESS_BLOCKED;
    analysis.working_set_size = 2u * 1024u * 1024u;
    analysis.spatial_locality = 0.80;
    TEST_ASSERT(qihse_memory_recommend_type(&analysis, NULL, &type),
                "interaction workload should be classified");
    TEST_ASSERT(type == QIHSE_MEM_HMA_INTERACTION,
                "interaction workload should use interaction cache tier");

    memset(&analysis, 0, sizeof(analysis));
    analysis.phase = QIHSE_MEMORY_PHASE_AMPLIFICATION;
    analysis.access_pattern = QIHSE_ACCESS_RANDOM;
    analysis.working_set_size = 512u * 1024u * 1024u;
    analysis.entanglement_density = 0.75;
    TEST_ASSERT(qihse_memory_recommend_type(&analysis, NULL, &type),
                "large entangled workload should be classified");
    TEST_ASSERT(type == QIHSE_MEM_HMA_ENTANGLEMENT,
                "large entangled workload should use entanglement fabric tier");

    return true;
}

static bool test_allocate_for_workload(void) {
    qihse_context_t ctx = NULL;
    qihse_memory_manager_t manager = NULL;
    qihse_memory_buffer_t* buffer = NULL;
    qihse_memory_workload_analysis_t analysis;

    TEST_ASSERT(qihse_context_create(NULL, &ctx) == QIHSE_OK,
                "context should be created");
    manager = qihse_memory_manager_create(ctx, "uma");
    TEST_ASSERT(manager != NULL, "memory manager should be created");

    memset(&analysis, 0, sizeof(analysis));
    analysis.phase = QIHSE_MEMORY_PHASE_SUPERPOSITION;
    analysis.access_pattern = QIHSE_ACCESS_SIMD;
    analysis.working_set_size = 4096u;
    analysis.temporal_locality = 1.0;
    analysis.superposition_dims = 128u;

    buffer = qihse_memory_allocate_for_workload(manager, &analysis, NULL, QIHSE_MEM_ZERO);
    TEST_ASSERT(buffer != NULL, "workload-routed allocation should succeed");
    TEST_ASSERT(buffer->mem_type == QIHSE_MEM_HMA_SUPERPOSITION,
                "workload-routed allocation should use recommended tier");
    TEST_ASSERT(buffer->logical_size == analysis.working_set_size,
                "workload-routed allocation should preserve logical size");
    TEST_ASSERT(buffer->access_pattern == analysis.access_pattern,
                "workload-routed allocation should preserve access hint");

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
        {"default topology", test_default_topology},
        {"recommendation rules", test_recommendation_rules},
        {"allocate for workload", test_allocate_for_workload},
    };

    for (size_t i = 0u; i < sizeof(tests) / sizeof(tests[0]); i++) {
        printf("RUN  %s\n", tests[i].name);
        if (!tests[i].fn()) {
            printf("FAIL %s\n", tests[i].name);
            return 1;
        }
        printf("PASS %s\n", tests[i].name);
    }
    printf("PASS all qihse memory planner tests\n");
    return 0;
}
