#include "qihse.h"
#include "qihse_hetero.h"

#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <errno.h>
#include <pthread.h>

static void qihse_init_device(
    qihse_compute_device_t* dev,
    qihse_device_type_t type,
    const char* name,
    double tops,
    size_t opt_batch,
    int numa
) {
    dev->type = type;
    dev->available = true;
    dev->theoretical_tops = tops;
    dev->measured_tops = tops;
    dev->optimal_batch_size = opt_batch;
    dev->min_batch_size = opt_batch / 4;
    if (dev->min_batch_size == 0) dev->min_batch_size = 1;
    dev->numa_node = numa;
    dev->device_context = NULL;
    dev->device_id = 0;
    strncpy(dev->device_name, name, sizeof(dev->device_name));
}

qihse_compute_pool_t* qihse_compute_pool_init(void) {
    qihse_compute_pool_t* pool = calloc(1, sizeof(*pool));
    if (!pool) return NULL;

    pthread_mutex_init(&pool->pool_mutex, NULL);
    pool->heterogeneous_enabled = true;

    qihse_init_device(&pool->devices[QIHSE_DEV_CPU_AVX2], QIHSE_DEV_CPU_AVX2,
                      "AVX2+FMA x86", 1.0, 2048, 0);
    pool->active_device_count++;
    pool->total_tops += pool->devices[QIHSE_DEV_CPU_AVX2].measured_tops;

    qihse_init_device(&pool->devices[QIHSE_DEV_CPU_AVX512], QIHSE_DEV_CPU_AVX512,
                      "AVX-512 x86", 2.0, 4096, 0);
    pool->active_device_count++;
    pool->total_tops += pool->devices[QIHSE_DEV_CPU_AVX512].measured_tops;

    qihse_init_device(&pool->devices[QIHSE_DEV_CPU_VNNI], QIHSE_DEV_CPU_VNNI,
                      "AVX512-VNNI INT8", 4.0, 4096, 0);
    pool->active_device_count++;
    pool->total_tops += pool->devices[QIHSE_DEV_CPU_VNNI].measured_tops;

    return pool;
}

int qihse_compute_pool_calibrate(qihse_compute_pool_t* pool) {
    if (!pool) return -EINVAL;
    for (size_t i = 0; i < QIHSE_DEV_COUNT; ++i) {
        if (pool->devices[i].available) {
            pool->devices[i].measured_tops = pool->devices[i].theoretical_tops;
        }
    }
    return 0;
}

qihse_work_schedule_t* qihse_create_work_schedule(
    const qihse_compute_pool_t* pool,
    size_t total_candidates,
    size_t dims
) {
    (void)dims;
    if (!pool || total_candidates == 0) return NULL;

    size_t partitions = pool->active_device_count;
    if (partitions == 0) partitions = 1;

    qihse_work_schedule_t* schedule = calloc(1, sizeof(*schedule));
    if (!schedule) return NULL;

    schedule->partitions = calloc(partitions, sizeof(qihse_work_partition_t));
    if (!schedule->partitions) {
        free(schedule);
        return NULL;
    }

    schedule->partition_count = partitions;
    schedule->total_candidates = total_candidates;

    size_t base = total_candidates / partitions;
    size_t remainder = total_candidates % partitions;
    size_t idx = 0;

    for (size_t i = 0; i < partitions; ++i) {
        size_t count = base + (i < remainder ? 1 : 0);
        schedule->partitions[i].device = (qihse_device_type_t)(i % QIHSE_DEV_COUNT);
        schedule->partitions[i].start_idx = idx;
        schedule->partitions[i].count = count;
        schedule->partitions[i].input_buffer = NULL;
        schedule->partitions[i].output_buffer = NULL;
        idx += count;
    }

    return schedule;
}

void qihse_work_schedule_destroy(qihse_work_schedule_t* schedule) {
    if (!schedule) return;
    free(schedule->partitions);
    free(schedule);
}

int qihse_compute_optimal_dimensions(
    const void* data,
    size_t n,
    size_t element_size,
    qihse_data_type_t type,
    const qihse_compute_pool_t* pool,
    qihse_dimension_params_t* params
) {
    (void)data;
    if (!params || n == 0 || !pool) return -EINVAL;

    double entropy = log2((double)n + 1.0);
    size_t dims = (size_t)(entropy * 4.0);
    if (dims < 64) dims = 64;
    if (dims > 2048) dims = 2048;

    params->optimal_dims = dims;
    params->expansion_factor = dims / (double)element_size;
    params->data_entropy = entropy;
    params->gap_coefficient = entropy * 0.1;
    params->effective_rank = dims / 2;
    params->array_size = n;
    params->data_type = type;

    return 0;
}

int qihse_config_init(
    qihse_config_t* config,
    qihse_data_type_t data_type,
    size_t array_size
) {
    if (!config) return -EINVAL;

    memset(config, 0, sizeof(*config));
    config->data_type = data_type;
    config->max_dimensions = 2048;
    config->min_dimensions = 64;
    config->fixed_dimensions = 256;
    config->auto_dimensions = true;
    config->enable_acceleration = false;
    config->use_heterogeneous = true;
    config->enable_profiling = false;
    config->max_batch_size = 4096;
    config->timeout_ms = 5000;
    config->backend_priority[0].type = QIHSE_BACKEND_CPU_C;
    config->backend_priority[0].priority_weight = 1.0f;
    config->num_backends = 1;
    config->adaptive_backend = false;
    config->anchor_config.max_anchors = 16;
    config->anchor_config.min_anchors = 2;
    config->anchor_config.anchor_prune_threshold = 0.8;
    config->anchor_config.memory_budget_mb = 8;
    config->anchor_config.enable_anchor_learning = true;
    config->anchor_config.chunk_size = 4;
    config->anchor_config.enable_anchor_simd = true;
    config->anchor_config.workload_type = array_size > 10000 ? 0 : 1;

    return 0;
}

int qihse_adaptive_amplify(
    qihse_superposition_t* superposition,
    const void* query,
    qihse_data_type_t type,
    const qihse_amplification_config_t* config
) {
    (void)query;
    (void)type;
    if (!superposition || !config) return -EINVAL;
    size_t rounds = config->adaptive_rounds ? config->fixed_rounds : config->fixed_rounds;
    return (int)rounds;
}

qihse_collapse_result_t qihse_dimensional_collapse_l2_norm(
    const qihse_superposition_t* superposition
) {
    qihse_collapse_result_t result = {0};
    if (!superposition || superposition->num_states == 0) return result;

    size_t best_idx = 0;
    double best_mag = 0.0;

    for (size_t i = 0; i < superposition->num_states; ++i) {
        double mag = 0.0;
        for (size_t d = 0; d < superposition->dims_per_state; ++d) {
            size_t idx = i * superposition->dims_per_state + d;
            mag += superposition->real[idx] * superposition->real[idx] +
                   superposition->imag[idx] * superposition->imag[idx];
        }
        if (mag > best_mag) {
            best_mag = mag;
            best_idx = i;
        }
    }

    result.predicted_index = best_idx;
    result.confidence = best_mag / superposition->dims_per_state;
    return result;
}
