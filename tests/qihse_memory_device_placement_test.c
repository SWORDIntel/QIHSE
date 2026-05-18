#include <assert.h>
#include <stdio.h>

#include "qihse_memory_device_placement.h"

static qihse_memory_topology_t test_topology(void)
{
    qihse_memory_topology_t topology;

    topology.superposition_buffer.capacity = (size_t)512u << 20;
    topology.superposition_buffer.bandwidth_gbps = 64.0;
    topology.superposition_buffer.latency_ns = 90.0;
    topology.superposition_buffer.coherent = true;

    topology.interaction_cache.capacity = (size_t)256u << 20;
    topology.interaction_cache.bandwidth_gbps = 160.0;
    topology.interaction_cache.latency_ns = 45.0;
    topology.interaction_cache.coherent = true;

    topology.entanglement_fabric.capacity = (size_t)2u << 30;
    topology.entanglement_fabric.bandwidth_gbps = 900.0;
    topology.entanglement_fabric.latency_ns = 250.0;
    topology.entanglement_fabric.coherent = false;

    topology.inter_tier_bandwidth_gbps = 80.0;
    topology.numa_nodes = 2u;

    return topology;
}

static qihse_memory_workload_analysis_t random_host_workload(void)
{
    qihse_memory_workload_analysis_t workload;

    workload.access_pattern = QIHSE_ACCESS_RANDOM;
    workload.read_write_ratio = 1.0;
    workload.working_set_size = (size_t)4u << 20;
    workload.temporal_locality = 0.20;
    workload.spatial_locality = 0.10;
    workload.superposition_dims = 16u;
    workload.entanglement_density = 0.05;
    workload.phase = QIHSE_MEMORY_PHASE_MEASUREMENT;

    return workload;
}

static qihse_memory_workload_analysis_t gpu_workload(void)
{
    qihse_memory_workload_analysis_t workload;

    workload.access_pattern = QIHSE_ACCESS_SEQUENTIAL;
    workload.read_write_ratio = 12.0;
    workload.working_set_size = (size_t)512u << 20;
    workload.temporal_locality = 0.70;
    workload.spatial_locality = 0.95;
    workload.superposition_dims = 4096u;
    workload.entanglement_density = 0.90;
    workload.phase = QIHSE_MEMORY_PHASE_INTERACTION;

    return workload;
}

static qihse_memory_workload_analysis_t cpu_workload(void)
{
    qihse_memory_workload_analysis_t workload;

    workload.access_pattern = QIHSE_ACCESS_SIMD;
    workload.read_write_ratio = 3.0;
    workload.working_set_size = (size_t)32u << 20;
    workload.temporal_locality = 0.95;
    workload.spatial_locality = 0.60;
    workload.superposition_dims = 256u;
    workload.entanglement_density = 0.20;
    workload.phase = QIHSE_MEMORY_PHASE_AMPLIFICATION;

    return workload;
}

int main(void)
{
    qihse_memory_topology_t topology = test_topology();
    qihse_memory_workload_analysis_t host_work = random_host_workload();
    qihse_memory_workload_analysis_t gpu_work = gpu_workload();
    qihse_memory_workload_analysis_t cpu_work = cpu_workload();
    qihse_memory_device_placement_scores_t scores;

    assert(qihse_memory_device_placement_is_cpu_target(QIHSE_DEVICE_CPU_AVX2));
    assert(qihse_memory_device_placement_is_cpu_target(QIHSE_DEVICE_CPU_AVX512));
    assert(qihse_memory_device_placement_is_cpu_target(QIHSE_DEVICE_CPU_AMX));
    assert(!qihse_memory_device_placement_is_cpu_target(QIHSE_DEVICE_GPU));
    assert(qihse_memory_device_placement_is_accelerator_target(QIHSE_DEVICE_GPU));
    assert(qihse_memory_device_placement_is_accelerator_target(QIHSE_DEVICE_NPU));
    assert(!qihse_memory_device_placement_is_accelerator_target(QIHSE_DEVICE_CPU_AVX2));

    scores = qihse_memory_device_placement_score_all(
        &host_work,
        &topology,
        QIHSE_DEVICE_GPU,
        QIHSE_MEMORY_DEVICE_POLICY_HOST_SAFE,
        QIHSE_ACCESS_RANDOM);
    assert(scores.selected == QIHSE_MEMORY_DEVICE_PLACEMENT_HOST);
    assert(scores.cpu_score == 0.0);
    assert(scores.device_score == 0.0);

    scores = qihse_memory_device_placement_score_all(
        &gpu_work,
        &topology,
        QIHSE_DEVICE_GPU,
        QIHSE_MEMORY_DEVICE_POLICY_DEVICE_PREFERRED,
        QIHSE_ACCESS_SEQUENTIAL);
    assert(scores.selected == QIHSE_MEMORY_DEVICE_PLACEMENT_DEVICE);
    assert(qihse_memory_device_placement_memory_type(scores.selected) == QIHSE_MEM_DEVICE);

    scores = qihse_memory_device_placement_score_all(
        &cpu_work,
        &topology,
        QIHSE_DEVICE_CPU_AVX512,
        QIHSE_MEMORY_DEVICE_POLICY_CPU_PREFERRED,
        QIHSE_ACCESS_SIMD);
    assert(scores.selected == QIHSE_MEMORY_DEVICE_PLACEMENT_CPU);
    assert(qihse_memory_device_placement_memory_type(scores.selected) == QIHSE_MEM_HOST);

    assert(qihse_memory_device_placement_select(
        0,
        0,
        (qihse_device_type_t)0,
        (qihse_memory_device_policy_t)999,
        (qihse_memory_access_t)999) == QIHSE_MEMORY_DEVICE_PLACEMENT_HOST);

    assert(qihse_memory_device_placement_string(QIHSE_MEMORY_DEVICE_PLACEMENT_HOST) != 0);
    assert(qihse_memory_device_placement_string(QIHSE_MEMORY_DEVICE_PLACEMENT_CPU) != 0);
    assert(qihse_memory_device_placement_string(QIHSE_MEMORY_DEVICE_PLACEMENT_DEVICE) != 0);

    puts("qihse_memory_device_placement_test passed");
    return 0;
}
