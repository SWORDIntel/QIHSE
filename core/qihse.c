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

static double qihse_elapsed_ns(double start, double end) {
    return start > 0.0 && end >= start ? end - start : 0.0;
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

int qihse_search_options_init(qihse_search_options_t* options, size_t bytes) {
    if (!options || bytes < sizeof(*options)) { errno = EINVAL; return -1; }
    memset(options, 0, sizeof(*options));
    options->struct_size = bytes;
    options->version = QIHSE_SEARCH_OPTIONS_VERSION;
    options->method = QIHSE_SEARCH_RFF_COSINE;
    options->tile_size = 16;
    return 0;
}

int qihse_search_metrics_init(qihse_search_metrics_t* metrics, size_t bytes) {
    if (!metrics || bytes < sizeof(*metrics)) { errno = EINVAL; return -1; }
    memset(metrics, 0, sizeof(*metrics));
    metrics->struct_size = bytes;
    metrics->version = QIHSE_SEARCH_OPTIONS_VERSION;
    return 0;
}

static bool qihse_search_config_valid(const qihse_config_t* config, size_t n,
                                      bool project) {
    size_t width = config->type_descriptor.element_size;
    if (config->data_type < QIHSE_TYPE_INT64 || config->data_type > QIHSE_TYPE_CUSTOM ||
        width == 0 || (project && (config->min_dimensions == 0 ||
        config->max_dimensions < config->min_dimensions ||
        config->max_dimensions > QIHSE_MAX_DIMENSIONS ||
        (!config->auto_dimensions && config->fixed_dimensions == 0) ||
        !isfinite(config->rff_gamma) || config->rff_gamma <= 0.0 ||
        config->verification.mode < QIHSE_VERIFY_NONE ||
        config->verification.mode > QIHSE_VERIFY_EXACT))) {
        errno = EINVAL;
        return false;
    }
    if (n > SIZE_MAX / width) { errno = EOVERFLOW; return false; }
    if (config->data_type <= QIHSE_TYPE_DOUBLE && width < sizeof(uint64_t)) {
        errno = EINVAL; return false;
    }
    if (config->data_type == QIHSE_TYPE_CUSTOM && !config->type_descriptor.compare_fn) {
        errno = ENOTSUP; return false;
    }
    return true;
}

static void qihse_count_add(size_t* counter, size_t amount) {
    *counter = amount > SIZE_MAX - *counter ? SIZE_MAX : *counter + amount;
}

static not_stisla_result_t qihse_verify_candidate(const void* data, size_t n,
    const void* query, const qihse_config_t* config, size_t index,
    bool exact, qihse_search_metrics_t* metrics) {
    qihse_collapse_result_t candidate = {0};
    candidate.predicted_index = index;
    qihse_verify_config_t verification = config->verification;
    if (exact) verification.mode = QIHSE_VERIFY_EXACT;
    qihse_verification_work_t work;
    not_stisla_result_t result = qihse_verify_result_with_work(data, n, query,
        config->data_type, &config->type_descriptor, &candidate, &verification, &work);
    qihse_count_add(&metrics->comparisons, work.comparisons);
    if (result != NOT_STISLA_NOT_FOUND) ++metrics->matches;
    if (exact) ++metrics->direct_queries;
    else {
        if (work.candidate_matched) ++metrics->candidate_hits;
        if (work.scanned) {
            ++metrics->fallback_queries;
            if (result != NOT_STISLA_NOT_FOUND) ++metrics->fallback_hits;
        }
    }
    return result;
}

static void qihse_publish_stats(const qihse_search_metrics_t* metrics) {
    qihse_performance_stats_t stats = {0};
    stats.total_time_ns = metrics->total_time_ns;
    stats.dim_calc_time_ns = metrics->setup_time_ns;
    stats.rff_time_ns = metrics->scoring_time_ns;
    stats.verification_time_ns = metrics->verification_time_ns;
    stats.peak_memory_bytes = metrics->peak_scratch_bytes;
    stats.classical_fallbacks = metrics->fallback_queries;
    stats.verification_rate = metrics->queries ? 1.0 : 0.0;
    stats.avg_confidence = metrics->queries ? (double)metrics->matches / metrics->queries : 0.0;
    pthread_mutex_lock(&g_performance_mutex);
    g_performance_stats = stats;
    pthread_mutex_unlock(&g_performance_mutex);
}

int qihse_batch_search_ex(const void* data, size_t n, const void* queries,
    size_t num_queries, not_stisla_result_t* results,
    not_stisla_anchor_table_t* table, const qihse_config_t* config,
    const qihse_search_options_t* options, qihse_search_metrics_t* metrics) {
    (void)table;
    qihse_search_options_t defaults;
    qihse_search_options_init(&defaults, sizeof(defaults));
    if (!options) options = &defaults;
    if (options->struct_size < sizeof(*options) ||
        options->version != QIHSE_SEARCH_OPTIONS_VERSION ||
        options->method < QIHSE_SEARCH_EXACT || options->method > QIHSE_SEARCH_RFF_PAIRED ||
        options->tile_size == 0 || options->tile_size > QIHSE_SEARCH_MAX_TILE_SIZE ||
        (metrics && (metrics->struct_size < sizeof(*metrics) ||
                     metrics->version != QIHSE_SEARCH_OPTIONS_VERSION)) ||
        !data || !config || !n || (num_queries && (!queries || !results))) {
        errno = EINVAL;
        return -1;
    }
    bool exact = options->method == QIHSE_SEARCH_EXACT;
    if (!qihse_search_config_valid(config, n, !exact)) return -1;
    const size_t width = config->type_descriptor.element_size;
    if (num_queries > SIZE_MAX / width || num_queries > SIZE_MAX / sizeof(*results)) {
        errno = EOVERFLOW;
        return -1;
    }
    qihse_search_metrics_t measured;
    qihse_search_metrics_init(&measured, sizeof(measured));
    measured.method = options->method;
    measured.queries = num_queries;
    measured.tile_size = num_queries < options->tile_size ? num_queries : options->tile_size;
    if (exact && num_queries) measured.tile_size = 1;
    const bool timed = metrics != NULL || config->enable_profiling;
    double started = timed ? qihse_search_now_ns() : 0.0;
    double stage_started = started;
    qihse_rff_map_t* map = NULL;
    double* scratch = NULL;
    const unsigned char* query_rows = queries;
    const unsigned char* rows = data;
    size_t dims = 0;
    int status = 0;
    for (size_t q = 0; q < num_queries; ++q) results[q] = NOT_STISLA_NOT_FOUND;
    if (!num_queries) goto complete;

    if (!exact) {
        qihse_dimension_params_t params;
        if (qihse_compute_optimal_dimensions(data, n, width, config->data_type,
                                              NULL, &params) != 0) {
            errno = EINVAL; status = -1; goto complete;
        }
        dims = config->auto_dimensions ? params.optimal_dims : config->fixed_dimensions;
        if (dims > config->max_dimensions) dims = config->max_dimensions;
        if (dims < config->min_dimensions) dims = config->min_dimensions;
        if (options->method == QIHSE_SEARCH_RFF_PAIRED && dims % 2 != 0) {
            errno = EINVAL; status = -1; goto complete;
        }
        measured.dimensions = dims;
        bool needs_map = false;
        if (config->data_type <= QIHSE_TYPE_DOUBLE) {
            for (size_t q = 0; q < num_queries; ++q) {
                double value;
                if (qihse_scalar_value(query_rows + q * width, config->data_type, &value)) {
                    needs_map = true; break;
                }
            }
        }
        if (needs_map) {
            size_t buffers = measured.tile_size + 1;
            if (dims > SIZE_MAX / sizeof(double) / buffers) {
                errno = EOVERFLOW; status = -1; goto complete;
            }
            size_t scratch_bytes = buffers * dims * sizeof(double);
            qihse_rff_method_t method = options->method == QIHSE_SEARCH_RFF_PAIRED
                ? QIHSE_RFF_PAIRED_SINCOS : QIHSE_RFF_COSINE_PHASE;
            map = qihse_rff_map_create(1, dims, config->rff_gamma, config->random_seed, method);
            if (!map) { status = -1; goto complete; }
            measured.kernel_builds = 1;
            size_t map_bytes = qihse_rff_map_storage_bytes(map);
            measured.peak_scratch_bytes = map_bytes;
            if (map_bytes > SIZE_MAX - scratch_bytes) {
                errno = EOVERFLOW; status = -1; goto complete;
            }
            scratch = malloc(scratch_bytes);
            if (!scratch) { errno = ENOMEM; status = -1; goto complete; }
            measured.peak_scratch_bytes = map_bytes + scratch_bytes;
        }
    }
    if (timed) measured.setup_time_ns = qihse_elapsed_ns(stage_started, qihse_search_now_ns());

    for (size_t start = 0; start < num_queries; ) {
        size_t count = num_queries - start < measured.tile_size
                     ? num_queries - start : measured.tile_size;
        size_t candidates[QIHSE_SEARCH_MAX_TILE_SIZE];
        double best_scores[QIHSE_SEARCH_MAX_TILE_SIZE];
        bool active[QIHSE_SEARCH_MAX_TILE_SIZE];
        bool any_active = false;
        if (timed) stage_started = qihse_search_now_ns();
        for (size_t q = 0; q < count; ++q) {
            candidates[q] = NOT_STISLA_NOT_FOUND;
            best_scores[q] = -DBL_MAX;
            active[q] = false;
            double value;
            if (map && qihse_scalar_value(query_rows + (start + q) * width,
                                           config->data_type, &value)) {
                if (qihse_rff_map_project(map, &value, scratch + q * dims) == 0) {
                    active[q] = any_active = true;
                    ++measured.query_projections;
                } else qihse_count_add(&measured.projection_failures, 1);
            }
            if (!exact && !active[q]) ++measured.unprojected_queries;
        }
        if (any_active) {
            ++measured.tiles;
            double* row_features = scratch + measured.tile_size * dims;
            for (size_t i = 0; i < n; ++i) {
                double value;
                if (!qihse_scalar_value(rows + i * width, config->data_type, &value)) continue;
                if (qihse_rff_map_project(map, &value, row_features) != 0) {
                    qihse_count_add(&measured.projection_failures, 1);
                    continue;
                }
                qihse_count_add(&measured.row_projections, 1);
                for (size_t q = 0; q < count; ++q) {
                    if (!active[q]) continue;
                    const double* query_features = scratch + q * dims;
                    double score = 0.0;
                    for (size_t d = 0; d < dims; ++d)
                        score += row_features[d] * query_features[d];
                    if (isfinite(score) && score > best_scores[q]) {
                        best_scores[q] = score;
                        candidates[q] = i;
                    }
                }
            }
        }
        if (timed) {
            double now = qihse_search_now_ns();
            measured.scoring_time_ns += qihse_elapsed_ns(stage_started, now);
            stage_started = now;
        }
        for (size_t q = 0; q < count; ++q)
            results[start + q] = qihse_verify_candidate(data, n,
                query_rows + (start + q) * width, config, candidates[q], exact, &measured);
        if (timed) measured.verification_time_ns += qihse_elapsed_ns(stage_started, qihse_search_now_ns());
        start += count;
    }
complete:
    {
        int saved_errno = errno;
        free(scratch);
        qihse_rff_map_destroy(map);
        if (timed) measured.total_time_ns = qihse_elapsed_ns(started, qihse_search_now_ns());
        if (metrics) {
            measured.struct_size = metrics->struct_size;
            *metrics = measured;
        }
        if (config->enable_profiling) qihse_publish_stats(&measured);
        if (status != 0) errno = saved_errno;
    }
    return status;
}

int qihse_search_ex(const void* data, size_t n, const void* query,
    not_stisla_anchor_table_t* table, const qihse_config_t* config,
    const qihse_search_options_t* options, not_stisla_result_t* result,
    qihse_search_metrics_t* metrics) {
    return qihse_batch_search_ex(data, n, query, 1, result, table, config, options, metrics);
}

not_stisla_result_t qihse_search(const void* data, size_t n, const void* query,
    not_stisla_anchor_table_t* table, const qihse_config_t* config) {
    not_stisla_result_t result = NOT_STISLA_NOT_FOUND;
    (void)qihse_search_ex(data, n, query, table, config, NULL, &result, NULL);
    return result;
}

size_t qihse_batch_search(const void* data, size_t n, const void* queries,
    size_t num_queries, not_stisla_result_t* results,
    not_stisla_anchor_table_t* table, const qihse_config_t* config) {
    if (qihse_batch_search_ex(data, n, queries, num_queries, results, table,
                               config, NULL, NULL) != 0) return 0;
    size_t found = 0;
    for (size_t i = 0; i < num_queries; ++i)
        if (results[i] != NOT_STISLA_NOT_FOUND) ++found;
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
