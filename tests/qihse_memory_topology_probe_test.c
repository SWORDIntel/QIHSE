#include "../memory/include/qihse_memory_topology_probe.h"

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#define TEST_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL: %s (%s:%d)\n", msg, __FILE__, __LINE__); \
        return false; \
    } \
} while (0)

static bool test_probe_host_result(void) {
    qihse_memory_topology_probe_result_t result;

    memset(&result, 0, sizeof(result));
    TEST_ASSERT(qihse_memory_topology_probe_host(&result),
                "host topology probe should succeed");
    TEST_ASSERT(result.total_bytes > 0u,
                "host probe should report total memory");
    TEST_ASSERT(result.available_bytes > 0u,
                "host probe should report available memory");
    TEST_ASSERT(result.page_size > 0u,
                "host probe should report page size");
    TEST_ASSERT(result.online_cpus >= 1u,
                "host probe should report at least one CPU");
    TEST_ASSERT(result.numa_nodes_detected >= 1u,
                "host probe should report at least one NUMA node");
    TEST_ASSERT(result.topology.numa_nodes == result.numa_nodes_detected,
                "result topology should preserve probed NUMA count");
    return true;
}

static bool test_probe_topology_wrapper(void) {
    qihse_memory_topology_t topology;

    memset(&topology, 0, sizeof(topology));
    TEST_ASSERT(qihse_memory_topology_probe(&topology),
                "topology wrapper should succeed");
    TEST_ASSERT(topology.numa_nodes >= 1u,
                "topology should have at least one NUMA node");
    TEST_ASSERT(topology.superposition_buffer.capacity > 0u,
                "superposition tier should have capacity");
    TEST_ASSERT(topology.interaction_cache.capacity > 0u,
                "interaction tier should have capacity");
    TEST_ASSERT(topology.entanglement_fabric.capacity >= topology.interaction_cache.capacity,
                "entanglement tier should be at least as large as interaction tier");
    TEST_ASSERT(topology.superposition_buffer.coherent,
                "host superposition tier should be coherent");
    TEST_ASSERT(topology.interaction_cache.coherent,
                "host interaction tier should be coherent");
    TEST_ASSERT(topology.entanglement_fabric.coherent,
                "host entanglement tier should be coherent");
    return true;
}

static bool test_probe_nodes(void) {
    qihse_memory_host_node_t node;
    size_t node_count = 0u;

    memset(&node, 0, sizeof(node));
    TEST_ASSERT(qihse_memory_topology_probe_nodes(&node, 1u, &node_count),
                "node probe should succeed with capacity one");
    TEST_ASSERT(node_count >= 1u,
                "node probe should report at least one node");
    TEST_ASSERT(node.online,
                "first probed node should be online");
    return true;
}

int main(void) {
    struct {
        const char* name;
        bool (*fn)(void);
    } tests[] = {
        {"host result", test_probe_host_result},
        {"topology wrapper", test_probe_topology_wrapper},
        {"node probe", test_probe_nodes},
    };

    for (size_t i = 0u; i < sizeof(tests) / sizeof(tests[0]); i++) {
        printf("RUN  %s\n", tests[i].name);
        if (!tests[i].fn()) {
            printf("FAIL %s\n", tests[i].name);
            return 1;
        }
        printf("PASS %s\n", tests[i].name);
    }

    printf("PASS all qihse memory topology probe tests\n");
    return 0;
}
