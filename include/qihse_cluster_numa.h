#ifndef QIHSE_CLUSTER_NUMA_H
#define QIHSE_CLUSTER_NUMA_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define QIHSE_CLUSTER_HUGEPAGE_SIZE (2u * 1024u * 1024u)

typedef enum {
    QIHSE_HUGEPAGES_DISABLED = 0,
    QIHSE_HUGEPAGES_TRANSPARENT = 1,
    QIHSE_HUGEPAGES_PREFER_EXPLICIT = 2,
    QIHSE_HUGEPAGES_REQUIRE_EXPLICIT = 3
} qihse_hugepage_policy_t;

typedef struct {
    bool cpu_affinity_applied;
    bool numa_policy_applied;
    int cpu_affinity_error;
    int numa_policy_error;
    int cpu_core_id;
    int numa_node_id;
} qihse_cluster_binding_result_t;

typedef struct {
    void* address;
    size_t requested_size;
    size_t mapped_size;
    int numa_node_id;
    qihse_hugepage_policy_t policy;
    bool explicit_hugepages;
    bool transparent_hugepages;
    bool numa_bound;
    int allocation_error;
    int hugepage_error;
    int numa_error;
} qihse_cluster_memory_t;

size_t qihse_cluster_available_cpus(int* out_cpu_ids, size_t capacity);
bool qihse_cluster_bind_current_thread(int cpu_core_id, int numa_node_id, bool strict, qihse_cluster_binding_result_t* out_result);
bool qihse_cluster_memory_alloc(qihse_cluster_memory_t* memory, size_t size, int numa_node_id, qihse_hugepage_policy_t policy, bool zero_memory);
void qihse_cluster_memory_free(qihse_cluster_memory_t* memory);
bool qihse_cluster_advise_hugepages(void* address, size_t size);

#ifdef __cplusplus
}
#endif

#endif
