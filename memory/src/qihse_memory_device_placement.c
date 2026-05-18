/*
 * QIHSE - Device-Specific Memory Placement Helpers
 */

#include "qihse_memory_device_placement.h"

#define QIHSE_PLACEMENT_EPSILON 0.000001
#define QIHSE_PLACEMENT_DEFAULT_LATENCY_NS 250.0
#define QIHSE_PLACEMENT_DEFAULT_BANDWIDTH_GBPS 16.0
#define QIHSE_PLACEMENT_BANDWIDTH_SCALE_GBPS 512.0
#define QIHSE_PLACEMENT_SMALL_WORKING_SET ((size_t)(1u << 20))
#define QIHSE_PLACEMENT_LARGE_WORKING_SET ((size_t)(64u << 20))

static double qihse_clamp01(double value)
{
    if (value < 0.0) {
        return 0.0;
    }
    if (value > 1.0) {
        return 1.0;
    }
    return value;
}

static qihse_memory_device_policy_t qihse_normalize_policy(qihse_memory_device_policy_t policy)
{
    switch (policy) {
    case QIHSE_MEMORY_DEVICE_POLICY_HOST_SAFE:
    case QIHSE_MEMORY_DEVICE_POLICY_BALANCED:
    case QIHSE_MEMORY_DEVICE_POLICY_CPU_PREFERRED:
    case QIHSE_MEMORY_DEVICE_POLICY_DEVICE_PREFERRED:
    case QIHSE_MEMORY_DEVICE_POLICY_LOW_LATENCY:
    case QIHSE_MEMORY_DEVICE_POLICY_HIGH_BANDWIDTH:
    case QIHSE_MEMORY_DEVICE_POLICY_COHERENT:
        return policy;
    default:
        return QIHSE_MEMORY_DEVICE_POLICY_HOST_SAFE;
    }
}

static qihse_memory_access_t qihse_effective_access(
    const qihse_memory_workload_analysis_t* workload,
    qihse_memory_access_t access_pattern)
{
    switch (access_pattern) {
    case QIHSE_ACCESS_RANDOM:
    case QIHSE_ACCESS_SEQUENTIAL:
    case QIHSE_ACCESS_STRIDED:
    case QIHSE_ACCESS_BLOCKED:
    case QIHSE_ACCESS_SIMD:
        return access_pattern;
    default:
        break;
    }

    if (workload != 0) {
        switch (workload->access_pattern) {
        case QIHSE_ACCESS_RANDOM:
        case QIHSE_ACCESS_SEQUENTIAL:
        case QIHSE_ACCESS_STRIDED:
        case QIHSE_ACCESS_BLOCKED:
        case QIHSE_ACCESS_SIMD:
            return workload->access_pattern;
        default:
            break;
        }
    }

    return QIHSE_ACCESS_RANDOM;
}

static const qihse_memory_tier_topology_t* qihse_host_tier(
    const qihse_memory_topology_t* topology)
{
    return topology != 0 ? &topology->superposition_buffer : 0;
}

static const qihse_memory_tier_topology_t* qihse_cpu_tier(
    const qihse_memory_topology_t* topology)
{
    return topology != 0 ? &topology->interaction_cache : 0;
}

static const qihse_memory_tier_topology_t* qihse_device_tier(
    const qihse_memory_topology_t* topology)
{
    return topology != 0 ? &topology->entanglement_fabric : 0;
}

static double qihse_capacity_score(const qihse_memory_tier_topology_t* tier, size_t working_set)
{
    if (working_set == 0u) {
        return 0.50;
    }
    if (tier == 0 || tier->capacity == 0u) {
        return 0.20;
    }
    if (tier->capacity >= working_set) {
        return 1.0;
    }
    return 0.15 + (0.75 * ((double)tier->capacity / (double)working_set));
}

static double qihse_bandwidth_score(const qihse_memory_tier_topology_t* tier)
{
    double bandwidth = QIHSE_PLACEMENT_DEFAULT_BANDWIDTH_GBPS;
    if (tier != 0 && tier->bandwidth_gbps > 0.0) {
        bandwidth = tier->bandwidth_gbps;
    }
    return qihse_clamp01(bandwidth / QIHSE_PLACEMENT_BANDWIDTH_SCALE_GBPS);
}

static double qihse_latency_score(const qihse_memory_tier_topology_t* tier)
{
    double latency = QIHSE_PLACEMENT_DEFAULT_LATENCY_NS;
    if (tier != 0 && tier->latency_ns > 0.0) {
        latency = tier->latency_ns;
    }
    return qihse_clamp01(100.0 / (latency + 100.0));
}

static double qihse_coherence_score(const qihse_memory_tier_topology_t* tier)
{
    if (tier == 0) {
        return 0.40;
    }
    return tier->coherent ? 1.0 : 0.0;
}

static double qihse_working_set_large_score(size_t working_set)
{
    if (working_set >= QIHSE_PLACEMENT_LARGE_WORKING_SET) {
        return 1.0;
    }
    if (working_set <= QIHSE_PLACEMENT_SMALL_WORKING_SET) {
        return 0.0;
    }
    return (double)(working_set - QIHSE_PLACEMENT_SMALL_WORKING_SET) /
        (double)(QIHSE_PLACEMENT_LARGE_WORKING_SET - QIHSE_PLACEMENT_SMALL_WORKING_SET);
}

static double qihse_read_heavy_score(const qihse_memory_workload_analysis_t* workload)
{
    if (workload == 0 || workload->read_write_ratio <= 0.0) {
        return 0.40;
    }
    return qihse_clamp01(workload->read_write_ratio / 8.0);
}

static double qihse_access_host_affinity(qihse_memory_access_t access_pattern)
{
    switch (access_pattern) {
    case QIHSE_ACCESS_RANDOM:
        return 0.75;
    case QIHSE_ACCESS_STRIDED:
        return 0.45;
    case QIHSE_ACCESS_SEQUENTIAL:
        return 0.30;
    case QIHSE_ACCESS_BLOCKED:
        return 0.25;
    case QIHSE_ACCESS_SIMD:
        return 0.20;
    default:
        return 0.60;
    }
}

static double qihse_access_cpu_affinity(qihse_memory_access_t access_pattern)
{
    switch (access_pattern) {
    case QIHSE_ACCESS_SIMD:
        return 1.00;
    case QIHSE_ACCESS_BLOCKED:
        return 0.85;
    case QIHSE_ACCESS_SEQUENTIAL:
        return 0.65;
    case QIHSE_ACCESS_STRIDED:
        return 0.55;
    case QIHSE_ACCESS_RANDOM:
        return 0.35;
    default:
        return 0.40;
    }
}

static double qihse_access_device_affinity(qihse_memory_access_t access_pattern)
{
    switch (access_pattern) {
    case QIHSE_ACCESS_BLOCKED:
        return 0.95;
    case QIHSE_ACCESS_SEQUENTIAL:
        return 0.85;
    case QIHSE_ACCESS_SIMD:
        return 0.75;
    case QIHSE_ACCESS_STRIDED:
        return 0.55;
    case QIHSE_ACCESS_RANDOM:
        return 0.15;
    default:
        return 0.20;
    }
}

static double qihse_phase_host_affinity(const qihse_memory_workload_analysis_t* workload)
{
    if (workload == 0) {
        return 0.55;
    }
    switch (workload->phase) {
    case QIHSE_MEMORY_PHASE_INIT:
        return 0.65;
    case QIHSE_MEMORY_PHASE_MEASUREMENT:
        return 0.90;
    case QIHSE_MEMORY_PHASE_SUPERPOSITION:
        return 0.35;
    case QIHSE_MEMORY_PHASE_INTERACTION:
        return 0.25;
    case QIHSE_MEMORY_PHASE_AMPLIFICATION:
        return 0.30;
    default:
        return 0.55;
    }
}

static double qihse_phase_cpu_affinity(const qihse_memory_workload_analysis_t* workload)
{
    if (workload == 0) {
        return 0.45;
    }
    switch (workload->phase) {
    case QIHSE_MEMORY_PHASE_INIT:
        return 0.65;
    case QIHSE_MEMORY_PHASE_AMPLIFICATION:
        return 0.70;
    case QIHSE_MEMORY_PHASE_MEASUREMENT:
        return 0.70;
    case QIHSE_MEMORY_PHASE_SUPERPOSITION:
        return 0.55;
    case QIHSE_MEMORY_PHASE_INTERACTION:
        return 0.50;
    default:
        return 0.45;
    }
}

static double qihse_phase_device_affinity(const qihse_memory_workload_analysis_t* workload)
{
    if (workload == 0) {
        return 0.20;
    }
    switch (workload->phase) {
    case QIHSE_MEMORY_PHASE_SUPERPOSITION:
        return 0.85;
    case QIHSE_MEMORY_PHASE_INTERACTION:
        return 0.95;
    case QIHSE_MEMORY_PHASE_AMPLIFICATION:
        return 0.80;
    case QIHSE_MEMORY_PHASE_INIT:
        return 0.45;
    case QIHSE_MEMORY_PHASE_MEASUREMENT:
        return 0.20;
    default:
        return 0.20;
    }
}

static double qihse_quantum_density_score(const qihse_memory_workload_analysis_t* workload)
{
    double density;
    double dims;

    if (workload == 0) {
        return 0.0;
    }

    density = qihse_clamp01(workload->entanglement_density);
    dims = workload->superposition_dims == 0u ? 0.0 : 1.0;
    if (workload->superposition_dims >= 1024u) {
        dims = 1.0;
    } else if (workload->superposition_dims > 0u) {
        dims = (double)workload->superposition_dims / 1024.0;
    }

    return qihse_clamp01((0.65 * density) + (0.35 * dims));
}

bool qihse_memory_device_placement_is_cpu_target(qihse_device_type_t target_device)
{
    return target_device == QIHSE_DEVICE_CPU_AVX2 ||
        target_device == QIHSE_DEVICE_CPU_AVX512 ||
        target_device == QIHSE_DEVICE_CPU_AMX;
}

bool qihse_memory_device_placement_is_accelerator_target(qihse_device_type_t target_device)
{
    return target_device == QIHSE_DEVICE_NPU || target_device == QIHSE_DEVICE_GPU;
}

const char* qihse_memory_device_placement_string(qihse_memory_device_placement_t placement)
{
    switch (placement) {
    case QIHSE_MEMORY_DEVICE_PLACEMENT_HOST:
        return "host";
    case QIHSE_MEMORY_DEVICE_PLACEMENT_CPU:
        return "cpu";
    case QIHSE_MEMORY_DEVICE_PLACEMENT_DEVICE:
        return "device";
    default:
        return "host";
    }
}

qihse_memory_type_t qihse_memory_device_placement_memory_type(
    qihse_memory_device_placement_t placement)
{
    switch (placement) {
    case QIHSE_MEMORY_DEVICE_PLACEMENT_DEVICE:
        return QIHSE_MEM_DEVICE;
    case QIHSE_MEMORY_DEVICE_PLACEMENT_CPU:
    case QIHSE_MEMORY_DEVICE_PLACEMENT_HOST:
    default:
        return QIHSE_MEM_HOST;
    }
}

double qihse_memory_device_placement_score_host(
    const qihse_memory_workload_analysis_t* workload,
    const qihse_memory_topology_t* topology,
    qihse_device_type_t target_device,
    qihse_memory_device_policy_t policy,
    qihse_memory_access_t access_pattern)
{
    const qihse_memory_tier_topology_t* tier = qihse_host_tier(topology);
    const qihse_memory_access_t access = qihse_effective_access(workload, access_pattern);
    const qihse_memory_device_policy_t normalized_policy = qihse_normalize_policy(policy);
    const size_t working_set = workload != 0 ? workload->working_set_size : 0u;
    double score;

    (void)target_device;

    score = 34.0;
    score += 16.0 * qihse_capacity_score(tier, working_set);
    score += 12.0 * qihse_latency_score(tier);
    score += 9.0 * qihse_coherence_score(tier);
    score += 10.0 * qihse_access_host_affinity(access);
    score += 9.0 * qihse_phase_host_affinity(workload);
    score += 4.0 * (1.0 - qihse_working_set_large_score(working_set));

    switch (normalized_policy) {
    case QIHSE_MEMORY_DEVICE_POLICY_HOST_SAFE:
        score += 35.0;
        break;
    case QIHSE_MEMORY_DEVICE_POLICY_LOW_LATENCY:
        score += 8.0;
        break;
    case QIHSE_MEMORY_DEVICE_POLICY_COHERENT:
        score += 7.0 * qihse_coherence_score(tier);
        break;
    case QIHSE_MEMORY_DEVICE_POLICY_DEVICE_PREFERRED:
        score -= 12.0;
        break;
    case QIHSE_MEMORY_DEVICE_POLICY_HIGH_BANDWIDTH:
        score -= 6.0;
        break;
    case QIHSE_MEMORY_DEVICE_POLICY_CPU_PREFERRED:
    case QIHSE_MEMORY_DEVICE_POLICY_BALANCED:
    default:
        break;
    }

    return score < 0.0 ? 0.0 : score;
}

double qihse_memory_device_placement_score_cpu(
    const qihse_memory_workload_analysis_t* workload,
    const qihse_memory_topology_t* topology,
    qihse_device_type_t target_device,
    qihse_memory_device_policy_t policy,
    qihse_memory_access_t access_pattern)
{
    const qihse_memory_tier_topology_t* tier = qihse_cpu_tier(topology);
    const qihse_memory_access_t access = qihse_effective_access(workload, access_pattern);
    const qihse_memory_device_policy_t normalized_policy = qihse_normalize_policy(policy);
    const size_t working_set = workload != 0 ? workload->working_set_size : 0u;
    double score;

    if (normalized_policy == QIHSE_MEMORY_DEVICE_POLICY_HOST_SAFE) {
        return 0.0;
    }

    score = 22.0;
    score += 14.0 * qihse_capacity_score(tier, working_set);
    score += 12.0 * qihse_bandwidth_score(tier);
    score += 12.0 * qihse_latency_score(tier);
    score += 11.0 * qihse_access_cpu_affinity(access);
    score += 8.0 * qihse_phase_cpu_affinity(workload);
    score += 8.0 * qihse_clamp01(workload != 0 ? workload->temporal_locality : 0.0);
    score += qihse_memory_device_placement_is_cpu_target(target_device) ? 16.0 : 0.0;

    switch (normalized_policy) {
    case QIHSE_MEMORY_DEVICE_POLICY_CPU_PREFERRED:
        score += 24.0;
        break;
    case QIHSE_MEMORY_DEVICE_POLICY_LOW_LATENCY:
        score += 8.0 * qihse_latency_score(tier);
        break;
    case QIHSE_MEMORY_DEVICE_POLICY_COHERENT:
        score += 8.0 * qihse_coherence_score(tier);
        break;
    case QIHSE_MEMORY_DEVICE_POLICY_DEVICE_PREFERRED:
        score -= 5.0;
        break;
    case QIHSE_MEMORY_DEVICE_POLICY_HIGH_BANDWIDTH:
        score += 3.0 * qihse_bandwidth_score(tier);
        break;
    case QIHSE_MEMORY_DEVICE_POLICY_BALANCED:
    case QIHSE_MEMORY_DEVICE_POLICY_HOST_SAFE:
    default:
        break;
    }

    if (qihse_memory_device_placement_is_accelerator_target(target_device)) {
        score -= 8.0;
    }

    return score < 0.0 ? 0.0 : score;
}

double qihse_memory_device_placement_score_device(
    const qihse_memory_workload_analysis_t* workload,
    const qihse_memory_topology_t* topology,
    qihse_device_type_t target_device,
    qihse_memory_device_policy_t policy,
    qihse_memory_access_t access_pattern)
{
    const qihse_memory_tier_topology_t* tier = qihse_device_tier(topology);
    const qihse_memory_access_t access = qihse_effective_access(workload, access_pattern);
    const qihse_memory_device_policy_t normalized_policy = qihse_normalize_policy(policy);
    const size_t working_set = workload != 0 ? workload->working_set_size : 0u;
    double score;

    if (normalized_policy == QIHSE_MEMORY_DEVICE_POLICY_HOST_SAFE) {
        return 0.0;
    }
    if (!qihse_memory_device_placement_is_accelerator_target(target_device)) {
        return 0.0;
    }

    score = 18.0;
    score += 16.0 * qihse_capacity_score(tier, working_set);
    score += 20.0 * qihse_bandwidth_score(tier);
    score += 13.0 * qihse_access_device_affinity(access);
    score += 10.0 * qihse_phase_device_affinity(workload);
    score += 9.0 * qihse_working_set_large_score(working_set);
    score += 9.0 * qihse_read_heavy_score(workload);
    score += 13.0 * qihse_quantum_density_score(workload);
    score += 7.0 * qihse_clamp01(workload != 0 ? workload->spatial_locality : 0.0);

    if (access == QIHSE_ACCESS_RANDOM && qihse_read_heavy_score(workload) < 0.65) {
        score -= 16.0;
    }

    switch (normalized_policy) {
    case QIHSE_MEMORY_DEVICE_POLICY_DEVICE_PREFERRED:
        score += 24.0;
        break;
    case QIHSE_MEMORY_DEVICE_POLICY_HIGH_BANDWIDTH:
        score += 12.0 * qihse_bandwidth_score(tier);
        break;
    case QIHSE_MEMORY_DEVICE_POLICY_COHERENT:
        score += 8.0 * qihse_coherence_score(tier);
        score -= qihse_coherence_score(tier) < 0.5 ? 10.0 : 0.0;
        break;
    case QIHSE_MEMORY_DEVICE_POLICY_LOW_LATENCY:
        score -= 7.0;
        break;
    case QIHSE_MEMORY_DEVICE_POLICY_CPU_PREFERRED:
        score -= 10.0;
        break;
    case QIHSE_MEMORY_DEVICE_POLICY_BALANCED:
    case QIHSE_MEMORY_DEVICE_POLICY_HOST_SAFE:
    default:
        break;
    }

    return score < 0.0 ? 0.0 : score;
}

qihse_memory_device_placement_scores_t qihse_memory_device_placement_score_all(
    const qihse_memory_workload_analysis_t* workload,
    const qihse_memory_topology_t* topology,
    qihse_device_type_t target_device,
    qihse_memory_device_policy_t policy,
    qihse_memory_access_t access_pattern)
{
    qihse_memory_device_placement_scores_t scores;
    double best;

    scores.host_score = qihse_memory_device_placement_score_host(
        workload, topology, target_device, policy, access_pattern);
    scores.cpu_score = qihse_memory_device_placement_score_cpu(
        workload, topology, target_device, policy, access_pattern);
    scores.device_score = qihse_memory_device_placement_score_device(
        workload, topology, target_device, policy, access_pattern);

    scores.selected = QIHSE_MEMORY_DEVICE_PLACEMENT_HOST;
    best = scores.host_score;

    if (scores.cpu_score > best + QIHSE_PLACEMENT_EPSILON) {
        scores.selected = QIHSE_MEMORY_DEVICE_PLACEMENT_CPU;
        best = scores.cpu_score;
    }
    if (scores.device_score > best + QIHSE_PLACEMENT_EPSILON) {
        scores.selected = QIHSE_MEMORY_DEVICE_PLACEMENT_DEVICE;
    }

    return scores;
}

qihse_memory_device_placement_t qihse_memory_device_placement_select(
    const qihse_memory_workload_analysis_t* workload,
    const qihse_memory_topology_t* topology,
    qihse_device_type_t target_device,
    qihse_memory_device_policy_t policy,
    qihse_memory_access_t access_pattern)
{
    return qihse_memory_device_placement_score_all(
        workload, topology, target_device, policy, access_pattern).selected;
}
