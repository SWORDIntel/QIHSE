#include "qihse_cluster_numa.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

int main(void) {
    int cpus[256];
    size_t cpu_count = qihse_cluster_available_cpus(cpus, sizeof(cpus) / sizeof(cpus[0]));
    assert(cpu_count > 0);

    qihse_cluster_binding_result_t binding;
    assert(qihse_cluster_bind_current_thread(cpus[0], -1, false, &binding));
    assert(binding.cpu_core_id == cpus[0]);
    assert(binding.cpu_affinity_applied || binding.cpu_affinity_error != 0);

    qihse_cluster_memory_t memory;
    assert(qihse_cluster_memory_alloc(&memory, 3u * 1024u * 1024u, -1, QIHSE_HUGEPAGES_TRANSPARENT, true));
    assert(memory.address != NULL);
    assert(memory.mapped_size >= memory.requested_size);
    unsigned char* bytes = (unsigned char*)memory.address;
    assert(bytes[0] == 0 && bytes[memory.requested_size - 1u] == 0);
    memset(bytes, 0xa5, memory.requested_size);
    qihse_cluster_memory_free(&memory);
    assert(memory.address == NULL);

    assert(qihse_cluster_memory_alloc(&memory, 4096u, -1, QIHSE_HUGEPAGES_PREFER_EXPLICIT, false));
    assert(memory.address != NULL);
    assert(memory.explicit_hugepages || memory.mapped_size >= 4096u);
    qihse_cluster_memory_free(&memory);

    bool explicit_ok = qihse_cluster_memory_alloc(&memory, QIHSE_CLUSTER_HUGEPAGE_SIZE, -1, QIHSE_HUGEPAGES_REQUIRE_EXPLICIT, false);
    if (explicit_ok) {
        assert(memory.explicit_hugepages);
        qihse_cluster_memory_free(&memory);
    } else {
        assert(memory.address == NULL);
        assert(memory.allocation_error != 0);
    }

    printf("cluster NUMA tests passed (%zu CPUs)\n", cpu_count);
    return 0;
}
