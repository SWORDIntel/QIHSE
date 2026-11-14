/* Scalar RFF candidate scoring followed by equality against original records.
 * Keep projection scratch O(D): no per-record complex state or N*D allocation.
 * Experimental amplification and device kernels remain separate public APIs.
 */
#include "qihse.h"
#include "qihse_search_internal.h"

#include <errno.h>
#include <float.h>
#include <math.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static qihse_performance_stats_t g_performance_stats;
static pthread_mutex_t g_performance_mutex = PTHREAD_MUTEX_INITIALIZER;

static double qihse_search_now_ns(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return 0.0;
    return (double)ts.tv_sec * 1e9 + (double)ts.tv_nsec;
}

static bool qihse_scalar_value(const void* element, qihse_data_type_t type,
                               double* value) {
    /* Record strides need not preserve scalar alignment. */
    if (type == QIHSE_TYPE_INT64) {
        int64_t x;
        memcpy(&x, element, sizeof(x));
        *value = (double)x;
    } else if (type == QIHSE_TYPE_UINT64) {
        uint64_t x;
        memcpy(&x, element, sizeof(x));
        *value = (double)x;
    } else if (type == QIHSE_TYPE_DOUBLE) {
        memcpy(value, element, sizeof(*value));
    } else {
        return false;
    }
    return isfinite(*value);
}

static bool qihse_search_config_valid(const qihse_config_t* config, size_t n) {
    size_t width = config->type_descriptor.element_size;
    if (config->data_type < QIHSE_TYPE_INT64 || config->data_type > QIHSE_TYPE_CUSTOM ||
        width == 0 || config->min_dimensions == 0 ||
        config->max_dimensions < config->min_dimensions ||
        config->max_dimensions > QIHSE_MAX_DIMENSIONS ||
        (!config->auto_dimensions && config->fixed_dimensions == 0) ||
        !isfinite(config->rff_gamma) || config->rff_gamma <= 0.0 ||
        config->verification.mode < QIHSE_VERIFY_NONE ||
        config->verification.mode > QIHSE_VERIFY_EXACT) {
        errno = EINVAL;
        return false;
    }
    if (n > SIZE_MAX / width) {
        errno = EOVERFLOW;
        return false;
    }
    if (config->data_type <= QIHSE_TYPE_DOUBLE && width < sizeof(uint64_t)) {
        errno = EINVAL;
        return false;
    }
    if (config->data_type == QIHSE_TYPE_CUSTOM && !config->type_descriptor.compare_fn) {
        errno = ENOTSUP;
        return false;
    }
    return true;
}

not_stisla_result_t qihse_search(
    const void* data, size_t n, const void* query,
    not_stisla_anchor_table_t* table, const qihse_config_t* config) {
    (void)table;
    if (!data || !query || !config || n == 0) {
        errno = EINVAL;
        return NOT_STISLA_NOT_FOUND;
    }
    if (!qihse_search_config_valid(config, n)) return NOT_STISLA_NOT_FOUND;

    qihse_performance_stats_t stats = {0};
    bool profile = config->enable_profiling;
    double started = profile ? qihse_search_now_ns() : 0.0;
    qihse_collapse_result_t candidate = {0};
    candidate.predicted_index = NOT_STISLA_NOT_FOUND;
    qihse_rff_kernel_t* kernel = NULL;
    double* scratch = NULL;
    double query_value;

    /* RFF is only a candidate hint. Non-numeric and nonfinite scalar records
     * still have well-defined equality through the original typed data. */
    if (qihse_scalar_value(query, config->data_type, &query_value)) {
        qihse_dimension_params_t params;
        double phase_started = profile ? qihse_search_now_ns() : 0.0;
        if (qihse_compute_optimal_dimensions(data, n,
                config->type_descriptor.element_size, config->data_type, NULL, &params) != 0)
            return NOT_STISLA_NOT_FOUND;
        size_t dims = config->auto_dimensions ? params.optimal_dims : config->fixed_dimensions;
        if (dims > config->max_dimensions) dims = config->max_dimensions;
        if (dims < config->min_dimensions) dims = config->min_dimensions;
        if (dims > SIZE_MAX / (2 * sizeof(double))) {
            errno = EOVERFLOW;
            return NOT_STISLA_NOT_FOUND;
        }
        if (profile) stats.dim_calc_time_ns = qihse_search_now_ns() - phase_started;

        phase_started = profile ? qihse_search_now_ns() : 0.0;
        kernel = qihse_rff_create(1, dims, config->rff_gamma, config->random_seed);
        if (!kernel) return NOT_STISLA_NOT_FOUND;
        scratch = malloc(2 * dims * sizeof(double));
        if (!scratch) {
            qihse_rff_destroy(kernel);
            errno = ENOMEM;
            return NOT_STISLA_NOT_FOUND;
        }
        double* query_features = scratch;
        double* row_features = scratch + dims;
        qihse_rff_project(kernel, &query_value, query_features);
        double best_score = -DBL_MAX;
        const unsigned char* rows = data;
        for (size_t i = 0; i < n; ++i) {
            double value;
            if (!qihse_scalar_value(rows + i * config->type_descriptor.element_size,
                                    config->data_type, &value)) continue;
            qihse_rff_project(kernel, &value, row_features);
            double score = 0.0;
            for (size_t d = 0; d < dims; ++d)
                score += row_features[d] * query_features[d];
            /* Signed RFF inner product; no absolute value or row-index phase. */
            if (isfinite(score) && score > best_score) {
                best_score = score;
                candidate.predicted_index = i;
            }
        }
        if (profile) {
            stats.rff_time_ns = qihse_search_now_ns() - phase_started;
            /* Two feature buffers plus the one-dimensional kernel's omega/bias.
             * Excludes caller-owned records and allocator bookkeeping. */
            stats.peak_memory_bytes = 4 * dims * sizeof(double) + sizeof(*kernel);
        }
        qihse_rff_destroy(kernel);
        free(scratch);
    }

    /* A feature score is not a calibrated correctness probability. */
    candidate.confidence = 0.0;
    double verify_started = profile ? qihse_search_now_ns() : 0.0;
    not_stisla_result_t result = qihse_verify_result_with_descriptor(
        data, n, query, config->data_type, &config->type_descriptor,
        &candidate, &config->verification);
    if (profile) {
        stats.verification_time_ns = qihse_search_now_ns() - verify_started;
        stats.total_time_ns = qihse_search_now_ns() - started;
        stats.verification_rate = 1.0;
        stats.avg_confidence = result == NOT_STISLA_NOT_FOUND ? 0.0 : 1.0;
        pthread_mutex_lock(&g_performance_mutex);
        g_performance_stats = stats;
        pthread_mutex_unlock(&g_performance_mutex);
    }
    return result;
}

size_t qihse_batch_search(
    const void* data, size_t n, const void* queries, size_t num_queries,
    not_stisla_result_t* results, not_stisla_anchor_table_t* table,
    const qihse_config_t* config) {
    if (!data || !queries || !results || !config || n == 0) {
        errno = EINVAL;
        return 0;
    }
    if (!qihse_search_config_valid(config, n)) return 0;
    if (num_queries > SIZE_MAX / config->type_descriptor.element_size ||
        num_queries > SIZE_MAX / sizeof(*results)) {
        errno = EOVERFLOW;
        return 0;
    }
    size_t found = 0;
    const unsigned char* query_rows = queries;
    for (size_t i = 0; i < num_queries; ++i) {
        results[i] = qihse_search(data, n,
            query_rows + i * config->type_descriptor.element_size, table, config);
        if (results[i] != NOT_STISLA_NOT_FOUND) ++found;
    }
    return found;
}

int qihse_get_performance_stats(qihse_performance_stats_t* stats) {
    if (!stats) return -EINVAL;
    pthread_mutex_lock(&g_performance_mutex);
    *stats = g_performance_stats;
    pthread_mutex_unlock(&g_performance_mutex);
    return 0;
}

void qihse_reset_performance_stats(void) {
    pthread_mutex_lock(&g_performance_mutex);
    memset(&g_performance_stats, 0, sizeof(g_performance_stats));
    pthread_mutex_unlock(&g_performance_mutex);
}
