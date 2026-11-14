#include "qihse.h"
#include "qihse_hetero.h"

#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <errno.h>
#include <pthread.h>

int qihse_compute_optimal_dimensions(
    const void* data,
    size_t n,
    size_t element_size,
    qihse_data_type_t type,
    const qihse_compute_pool_t* pool,
    qihse_dimension_params_t* params
) {
    (void)data;
    (void)pool;
    if (!data || !params || n == 0 || element_size == 0) return -EINVAL;

    double entropy = log2((double)n + 1.0);
    size_t dims = (size_t)(entropy * 4.0);
    if (dims < 64) dims = 64;
    if (dims > 2048) dims = 2048;

    params->optimal_dims = dims;
    params->expansion_factor = dims;
    params->data_entropy = NAN;
    params->gap_coefficient = NAN;
    params->effective_rank = 0;
    params->array_size = n;
    params->data_type = type;

    return 0;
}

int qihse_config_init(
    qihse_config_t* config,
    qihse_data_type_t data_type,
    size_t array_size
) {
    if (!config || data_type < QIHSE_TYPE_INT64 || data_type > QIHSE_TYPE_CUSTOM) return -EINVAL;

    memset(config, 0, sizeof(*config));
    config->data_type = data_type;
    config->type_descriptor.type = data_type;
    switch (data_type) {
        case QIHSE_TYPE_INT64: config->type_descriptor.element_size = sizeof(int64_t); break;
        case QIHSE_TYPE_UINT64: config->type_descriptor.element_size = sizeof(uint64_t); break;
        case QIHSE_TYPE_DOUBLE: config->type_descriptor.element_size = sizeof(double); break;
        default: break; /* The caller supplies the fixed record width. */
    }
    config->rff_gamma = 1.0;
    config->random_seed = 42;
    qihse_amplification_config_init(&config->amplification, array_size);
    qihse_verify_config_init(&config->verification, 1.0);
    config->max_dimensions = 2048;
    config->min_dimensions = 64;
    config->fixed_dimensions = 256;
    config->auto_dimensions = true;
    config->enable_acceleration = false;
    config->use_heterogeneous = false;
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

size_t qihse_init_parallel_pipelines(
    qihse_pipeline_config_t* configs,
    size_t max_configs,
    qihse_data_type_t data_type __attribute__((unused)),
    size_t array_size __attribute__((unused))
) {
    if (!configs || max_configs == 0) return 0;
    
    size_t count = 0;
    
    /* Config 1: Fast search (low dimensions) */
    if (count < max_configs) {
        configs[count].type = QIHSE_PIPELINE_FAST;
        configs[count].dimensions = 64;
        configs[count].confidence_threshold = 0.6;
        configs[count].early_exit = true;
        configs[count].priority = 10;
        configs[count].timeout_ms = 1000;
        configs[count].pipeline_data = NULL;
        count++;
    }

    /* Config 2: Balanced search */
    if (count < max_configs) {
        configs[count].type = QIHSE_PIPELINE_BALANCED;
        configs[count].dimensions = 256;
        configs[count].confidence_threshold = 0.85;
        configs[count].early_exit = true;
        configs[count].priority = 20;
        configs[count].timeout_ms = 2000;
        configs[count].pipeline_data = NULL;
        count++;
    }

    return count;
}
