/*
 * QIHSE - Host Memory Topology Probe
 *
 * Lightweight Linux sysfs/procfs probing helpers for Phase 2 memory planner
 * integration. The API is intentionally small and C99-compatible.
 */

#ifndef QIHSE_MEMORY_TOPOLOGY_PROBE_H
#define QIHSE_MEMORY_TOPOLOGY_PROBE_H

#include "qihse_memory.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct qihse_memory_host_node_s {
    size_t node_id;
    uint64_t total_bytes;
    uint64_t free_bytes;
    uint64_t available_bytes;
    bool online;
} qihse_memory_host_node_t;

typedef struct qihse_memory_topology_probe_result_s {
    qihse_memory_topology_t topology;
    uint64_t total_bytes;
    uint64_t available_bytes;
    uint64_t page_size;
    size_t online_cpus;
    size_t numa_nodes_detected;
    bool used_sysfs;
    bool used_procfs;
    bool used_fallbacks;
} qihse_memory_topology_probe_result_t;

void qihse_memory_topology_probe_init_result(
    qihse_memory_topology_probe_result_t* result
);

bool qihse_memory_topology_probe_host(
    qihse_memory_topology_probe_result_t* result
);

bool qihse_memory_topology_probe(
    qihse_memory_topology_t* topology
);

bool qihse_memory_topology_probe_nodes(
    qihse_memory_host_node_t* nodes,
    size_t node_capacity,
    size_t* out_node_count
);

#ifdef __cplusplus
}
#endif

#endif /* QIHSE_MEMORY_TOPOLOGY_PROBE_H */
