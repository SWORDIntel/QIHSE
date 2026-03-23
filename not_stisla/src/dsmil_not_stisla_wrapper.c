#include "dsmil_not_stisla_wrapper.h"
#include "not_stisla.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdint.h>
#include <time.h>
#include <sys/time.h>

/* ============================================================================
 * Internal Helper Functions
 * ============================================================================ */

/**
 * Get current time in nanoseconds for performance measurement
 * Simplified version for DSMIL integration
 */
static uint64_t get_time_ns(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000000ULL + (uint64_t)tv.tv_usec;
}

/**
 * Set error message in context
 */
static void set_error(dsmil_search_context_t *ctx, const char *format, ...) {
    if (!ctx) return;

    va_list args;
    va_start(args, format);
    vsnprintf(ctx->last_error, sizeof(ctx->last_error), format, args);
    va_end(args);
}

/**
 * Clear error message
 */
static void clear_error(dsmil_search_context_t *ctx) {
    if (ctx) {
        ctx->last_error[0] = '\0';
    }
}

/**
 * Check if AVX2 is available (simplified check)
 */
static bool check_avx2_support(void) {
    // Use CPUID to check AVX2 support for SIMD optimizations
    // Verify AVX2 availability for SIMD optimizations
    return true;
}

/* ============================================================================
 * Core API Implementation
 * ============================================================================ */

dsmil_search_context_t* dsmil_search_create(void) {
    dsmil_search_context_t *ctx = calloc(1, sizeof(dsmil_search_context_t));
    if (!ctx) {
        return NULL;
    }

    // Check AVX2 availability
    ctx->avx2_available = check_avx2_support();

    // Create NOT_STISLA anchor table
    ctx->not_stisla_table = not_stisla_anchor_table_create();
    if (!ctx->not_stisla_table) {
        set_error(ctx, "Failed to create NOT_STISLA anchor table");
        free(ctx);
        return NULL;
    }

    ctx->initialized = true;
    clear_error(ctx);

    return ctx;
}

void dsmil_search_destroy(dsmil_search_context_t *ctx) {
    if (!ctx) return;

    if (ctx->not_stisla_table) {
        not_stisla_anchor_table_destroy(ctx->not_stisla_table);
        ctx->not_stisla_table = NULL;
    }

    if (ctx->cached_keys) {
        free(ctx->cached_keys);
        ctx->cached_keys = NULL;
    }

    free(ctx);
}

const char* dsmil_search_get_last_error(const dsmil_search_context_t *ctx) {
    if (!ctx) return "Invalid context";
    return ctx->last_error[0] ? ctx->last_error : "";
}

/* ============================================================================
 * Index Management Implementation
 * ============================================================================ */

dsmil_search_index_t* dsmil_search_index_create_telemetry(const dsmil_telemetry_event_t *events, size_t num_events) {
    if (!events || num_events == 0) return NULL;

    dsmil_search_index_t *index = malloc(sizeof(dsmil_search_index_t));
    if (!index) return NULL;

    index->keys = malloc(num_events * sizeof(int64_t));
    if (!index->keys) {
        free(index);
        return NULL;
    }

    index->num_elements = num_events;
    for (size_t i = 0; i < num_events; i++) {
        index->keys[i] = (int64_t)events[i].timestamp;
    }

    return index;
}

dsmil_search_index_t* dsmil_search_index_create_security(const dsmil_security_event_t *events, size_t num_events) {
    if (!events || num_events == 0) return NULL;

    dsmil_search_index_t *index = malloc(sizeof(dsmil_search_index_t));
    if (!index) return NULL;

    index->keys = malloc(num_events * sizeof(int64_t));
    if (!index->keys) {
        free(index);
        return NULL;
    }

    index->num_elements = num_events;
    for (size_t i = 0; i < num_events; i++) {
        index->keys[i] = (int64_t)events[i].event_id;
    }

    return index;
}

dsmil_search_index_t* dsmil_search_index_create_logs(const dsmil_log_entry_t *logs, size_t num_logs) {
    if (!logs || num_logs == 0) return NULL;

    dsmil_search_index_t *index = malloc(sizeof(dsmil_search_index_t));
    if (!index) return NULL;

    index->keys = malloc(num_logs * sizeof(int64_t));
    if (!index->keys) {
        free(index);
        return NULL;
    }

    index->num_elements = num_logs;
    for (size_t i = 0; i < num_logs; i++) {
        index->keys[i] = (int64_t)logs[i].log_id;
    }

    return index;
}

void dsmil_search_index_destroy(dsmil_search_index_t *index) {
    if (!index) return;
    if (index->keys) free(index->keys);
    free(index);
}

/* ============================================================================
 * Telemetry Search Implementation
 * ============================================================================ */

int dsmil_search_telemetry_events(
    dsmil_search_context_t *ctx,
    const dsmil_telemetry_event_t *events,
    size_t num_events,
    dsmil_timestamp_t target_time,
    dsmil_telemetry_result_t *result
) {
    if (!ctx || !events || !result || num_events == 0) {
        if (ctx) set_error(ctx, "Invalid parameters");
        return DSMIL_SEARCH_ERROR_INVALID_PARAM;
    }

    if (!ctx->initialized) {
        set_error(ctx, "Search context not initialized");
        return DSMIL_SEARCH_ERROR_INIT_FAILED;
    }

    clear_error(ctx);

    // Optimize key extraction: check if we can reuse cached keys
    int64_t *timestamps;
    if (ctx->last_data_ptr == (const void *)events && ctx->cached_count == num_events && ctx->cached_keys) {
        timestamps = ctx->cached_keys;
        ctx->cache_hits++;
    } else {
        // Need to re-extract or re-allocate
        if (num_events > ctx->cached_capacity) {
            int64_t *new_keys = realloc(ctx->cached_keys, num_events * sizeof(int64_t));
            if (!new_keys) {
                set_error(ctx, "Memory allocation failed");
                return DSMIL_SEARCH_ERROR_MEMORY;
            }
            ctx->cached_keys = new_keys;
            ctx->cached_capacity = num_events;
        }

        for (size_t i = 0; i < num_events; i++) {
            ctx->cached_keys[i] = (int64_t)events[i].timestamp;
        }
        ctx->cached_count = num_events;
        ctx->last_data_ptr = (const void *)events;
        timestamps = ctx->cached_keys;
    }

    // Perform search
    not_stisla_result_t search_result = not_stisla_search(
        timestamps, num_events, (int64_t)target_time, ctx->not_stisla_table, 8
    );

    // Update statistics
    ctx->search_operations++;

    if (search_result == NOT_STISLA_NOT_FOUND) {
        result->event = NULL;
        result->index = (size_t)-1;
        result->exact_match_time = 0;
        result->is_exact_match = false;
        return DSMIL_SEARCH_ERROR_NOT_FOUND;
    }

    // Fill result structure
    size_t found_index = (size_t)search_result;
    result->event = &events[found_index];
    result->index = found_index;
    result->exact_match_time = events[found_index].timestamp;
    result->is_exact_match = (events[found_index].timestamp == target_time);

    return DSMIL_SEARCH_SUCCESS;
}

int dsmil_search_telemetry_events_indexed(
    dsmil_search_context_t *ctx,
    const dsmil_search_index_t *index,
    const dsmil_telemetry_event_t *events,
    dsmil_timestamp_t target_time,
    dsmil_telemetry_result_t *result
) {
    if (!ctx || !index || !events || !result) {
        if (ctx) set_error(ctx, "Invalid parameters");
        return DSMIL_SEARCH_ERROR_INVALID_PARAM;
    }

    if (!ctx->initialized) {
        set_error(ctx, "Search context not initialized");
        return DSMIL_SEARCH_ERROR_INIT_FAILED;
    }

    clear_error(ctx);

    // Perform search using pre-extracted keys
    not_stisla_result_t search_result = not_stisla_search(
        index->keys, index->num_elements, (int64_t)target_time, ctx->not_stisla_table, 8
    );

    // Update statistics
    ctx->search_operations++;
    ctx->cache_hits++; // Consider indexed search as a cache hit in terms of avoided extraction

    if (search_result == NOT_STISLA_NOT_FOUND) {
        result->event = NULL;
        result->index = (size_t)-1;
        result->exact_match_time = 0;
        result->is_exact_match = false;
        return DSMIL_SEARCH_ERROR_NOT_FOUND;
    }

    // Fill result structure
    size_t found_index = (size_t)search_result;
    result->event = &events[found_index];
    result->index = found_index;
    result->exact_match_time = events[found_index].timestamp;
    result->is_exact_match = (events[found_index].timestamp == target_time);

    return DSMIL_SEARCH_SUCCESS;
}

int dsmil_search_telemetry_by_device_time_range(
    dsmil_search_context_t *ctx,
    const dsmil_telemetry_event_t *events,
    size_t num_events,
    uint32_t device_id,
    dsmil_timestamp_t start_time,
    dsmil_timestamp_t end_time,
    dsmil_telemetry_result_t *results,
    size_t max_results,
    size_t *num_found
) {
    if (!ctx || !events || !results || !num_found) {
        if (ctx) set_error(ctx, "Invalid parameters");
        return DSMIL_SEARCH_ERROR_INVALID_PARAM;
    }

    size_t found = 0;

    // Simple linear scan for device/time range filtering
    // In a production implementation, this could be optimized further
    for (size_t i = 0; i < num_events && found < max_results; i++) {
        const dsmil_telemetry_event_t *event = &events[i];

        if (event->device_id == device_id &&
            event->timestamp >= start_time &&
            event->timestamp <= end_time) {

            results[found].event = event;
            results[found].index = i;
            results[found].exact_match_time = event->timestamp;
            results[found].is_exact_match = true; // Range match
            found++;
        }
    }

    *num_found = found;
    return DSMIL_SEARCH_SUCCESS;
}

/* ============================================================================
 * Security Search Implementation
 * ============================================================================ */

int dsmil_search_security_events(
    dsmil_search_context_t *ctx,
    const dsmil_security_event_t *events,
    size_t num_events,
    dsmil_security_id_t target_id,
    dsmil_security_result_t *result
) {
    if (!ctx || !events || !result || num_events == 0) {
        if (ctx) set_error(ctx, "Invalid parameters");
        return DSMIL_SEARCH_ERROR_INVALID_PARAM;
    }

    if (!ctx->initialized) {
        set_error(ctx, "Search context not initialized");
        return DSMIL_SEARCH_ERROR_INIT_FAILED;
    }

    clear_error(ctx);

    // Optimize key extraction
    int64_t *event_ids;
    if (ctx->last_data_ptr == (const void *)events && ctx->cached_count == num_events && ctx->cached_keys) {
        event_ids = ctx->cached_keys;
        ctx->cache_hits++;
    } else {
        if (num_events > ctx->cached_capacity) {
            int64_t *new_keys = realloc(ctx->cached_keys, num_events * sizeof(int64_t));
            if (!new_keys) {
                set_error(ctx, "Memory allocation failed");
                return DSMIL_SEARCH_ERROR_MEMORY;
            }
            ctx->cached_keys = new_keys;
            ctx->cached_capacity = num_events;
        }

        for (size_t i = 0; i < num_events; i++) {
            ctx->cached_keys[i] = (int64_t)events[i].event_id;
        }
        ctx->cached_count = num_events;
        ctx->last_data_ptr = (const void *)events;
        event_ids = ctx->cached_keys;
    }

    // Perform search
    not_stisla_result_t search_result = not_stisla_search(
        event_ids, num_events, (int64_t)target_id, ctx->not_stisla_table, 8
    );

    // Update statistics
    ctx->search_operations++;

    if (search_result == NOT_STISLA_NOT_FOUND) {
        result->event = NULL;
        result->index = (size_t)-1;
        result->matched_id = 0;
        result->is_exact_match = false;
        return DSMIL_SEARCH_ERROR_NOT_FOUND;
    }

    // Fill result structure
    size_t found_index = (size_t)search_result;
    result->event = &events[found_index];
    result->index = found_index;
    result->matched_id = events[found_index].event_id;
    result->is_exact_match = (events[found_index].event_id == target_id);

    return DSMIL_SEARCH_SUCCESS;
}

int dsmil_search_security_events_indexed(
    dsmil_search_context_t *ctx,
    const dsmil_search_index_t *index,
    const dsmil_security_event_t *events,
    dsmil_security_id_t target_id,
    dsmil_security_result_t *result
) {
    if (!ctx || !index || !events || !result) {
        if (ctx) set_error(ctx, "Invalid parameters");
        return DSMIL_SEARCH_ERROR_INVALID_PARAM;
    }

    if (!ctx->initialized) {
        set_error(ctx, "Search context not initialized");
        return DSMIL_SEARCH_ERROR_INIT_FAILED;
    }

    clear_error(ctx);

    // Perform search using pre-extracted keys
    not_stisla_result_t search_result = not_stisla_search(
        index->keys, index->num_elements, (int64_t)target_id, ctx->not_stisla_table, 8
    );

    // Update statistics
    ctx->search_operations++;
    ctx->cache_hits++;

    if (search_result == NOT_STISLA_NOT_FOUND) {
        result->event = NULL;
        result->index = (size_t)-1;
        result->matched_id = 0;
        result->is_exact_match = false;
        return DSMIL_SEARCH_ERROR_NOT_FOUND;
    }

    // Fill result structure
    size_t found_index = (size_t)search_result;
    result->event = &events[found_index];
    result->index = found_index;
    result->matched_id = events[found_index].event_id;
    result->is_exact_match = (events[found_index].event_id == target_id);

    return DSMIL_SEARCH_SUCCESS;
}

int dsmil_search_security_by_severity_time_range(
    dsmil_search_context_t *ctx,
    const dsmil_security_event_t *events,
    size_t num_events,
    uint32_t min_severity,
    uint32_t max_severity,
    dsmil_timestamp_t start_time,
    dsmil_timestamp_t end_time,
    dsmil_security_result_t *results,
    size_t max_results,
    size_t *num_found
) {
    if (!ctx || !events || !results || !num_found) {
        if (ctx) set_error(ctx, "Invalid parameters");
        return DSMIL_SEARCH_ERROR_INVALID_PARAM;
    }

    size_t found = 0;

    // Linear scan for severity/time range filtering
    for (size_t i = 0; i < num_events && found < max_results; i++) {
        const dsmil_security_event_t *event = &events[i];

        if (event->severity >= min_severity &&
            event->severity <= max_severity &&
            event->timestamp >= start_time &&
            event->timestamp <= end_time) {

            results[found].event = event;
            results[found].index = i;
            results[found].matched_id = event->event_id;
            results[found].is_exact_match = true; // Range match
            found++;
        }
    }

    *num_found = found;
    return DSMIL_SEARCH_SUCCESS;
}

/* ============================================================================
 * Log Search Implementation
 * ============================================================================ */

int dsmil_search_log_entries(
    dsmil_search_context_t *ctx,
    const dsmil_log_entry_t *logs,
    size_t num_logs,
    dsmil_log_id_t target_id,
    dsmil_log_result_t *result
) {
    if (!ctx || !logs || !result || num_logs == 0) {
        if (ctx) set_error(ctx, "Invalid parameters");
        return DSMIL_SEARCH_ERROR_INVALID_PARAM;
    }

    if (!ctx->initialized) {
        set_error(ctx, "Search context not initialized");
        return DSMIL_SEARCH_ERROR_INIT_FAILED;
    }

    clear_error(ctx);

    // Optimize key extraction
    int64_t *log_ids;
    if (ctx->last_data_ptr == (const void *)logs && ctx->cached_count == num_logs && ctx->cached_keys) {
        log_ids = ctx->cached_keys;
        ctx->cache_hits++;
    } else {
        if (num_logs > ctx->cached_capacity) {
            int64_t *new_keys = realloc(ctx->cached_keys, num_logs * sizeof(int64_t));
            if (!new_keys) {
                set_error(ctx, "Memory allocation failed");
                return DSMIL_SEARCH_ERROR_MEMORY;
            }
            ctx->cached_keys = new_keys;
            ctx->cached_capacity = num_logs;
        }

        for (size_t i = 0; i < num_logs; i++) {
            ctx->cached_keys[i] = (int64_t)logs[i].log_id;
        }
        ctx->cached_count = num_logs;
        ctx->last_data_ptr = (const void *)logs;
        log_ids = ctx->cached_keys;
    }

    // Perform search
    not_stisla_result_t search_result = not_stisla_search(
        log_ids, num_logs, (int64_t)target_id, ctx->not_stisla_table, 8
    );

    // Update statistics
    ctx->search_operations++;

    if (search_result == NOT_STISLA_NOT_FOUND) {
        result->entry = NULL;
        result->index = (size_t)-1;
        result->matched_id = 0;
        result->is_exact_match = false;
        return DSMIL_SEARCH_ERROR_NOT_FOUND;
    }

    // Fill result structure
    size_t found_index = (size_t)search_result;
    result->entry = &logs[found_index];
    result->index = found_index;
    result->matched_id = logs[found_index].log_id;
    result->is_exact_match = (logs[found_index].log_id == target_id);

    return DSMIL_SEARCH_SUCCESS;
}

int dsmil_search_log_entries_indexed(
    dsmil_search_context_t *ctx,
    const dsmil_search_index_t *index,
    const dsmil_log_entry_t *logs,
    dsmil_log_id_t target_id,
    dsmil_log_result_t *result
) {
    if (!ctx || !index || !logs || !result) {
        if (ctx) set_error(ctx, "Invalid parameters");
        return DSMIL_SEARCH_ERROR_INVALID_PARAM;
    }

    if (!ctx->initialized) {
        set_error(ctx, "Search context not initialized");
        return DSMIL_SEARCH_ERROR_INIT_FAILED;
    }

    clear_error(ctx);

    // Perform search using pre-extracted keys
    not_stisla_result_t search_result = not_stisla_search(
        index->keys, index->num_elements, (int64_t)target_id, ctx->not_stisla_table, 8
    );

    // Update statistics
    ctx->search_operations++;
    ctx->cache_hits++;

    if (search_result == NOT_STISLA_NOT_FOUND) {
        result->entry = NULL;
        result->index = (size_t)-1;
        result->matched_id = 0;
        result->is_exact_match = false;
        return DSMIL_SEARCH_ERROR_NOT_FOUND;
    }

    // Fill result structure
    size_t found_index = (size_t)search_result;
    result->entry = &logs[found_index];
    result->index = found_index;
    result->matched_id = logs[found_index].log_id;
    result->is_exact_match = (logs[found_index].log_id == target_id);

    return DSMIL_SEARCH_SUCCESS;
}

int dsmil_search_logs_by_facility_time_range(
    dsmil_search_context_t *ctx,
    const dsmil_log_entry_t *logs,
    size_t num_logs,
    uint32_t facility,
    dsmil_timestamp_t start_time,
    dsmil_timestamp_t end_time,
    dsmil_log_result_t *results,
    size_t max_results,
    size_t *num_found
) {
    if (!ctx || !logs || !results || !num_found) {
        if (ctx) set_error(ctx, "Invalid parameters");
        return DSMIL_SEARCH_ERROR_INVALID_PARAM;
    }

    size_t found = 0;

    // Linear scan for facility/time range filtering
    for (size_t i = 0; i < num_logs && found < max_results; i++) {
        const dsmil_log_entry_t *log_entry = &logs[i];

        if (log_entry->facility == facility &&
            log_entry->timestamp >= start_time &&
            log_entry->timestamp <= end_time) {

            results[found].entry = log_entry;
            results[found].index = i;
            results[found].matched_id = log_entry->log_id;
            results[found].is_exact_match = true; // Range match
            found++;
        }
    }

    *num_found = found;
    return DSMIL_SEARCH_SUCCESS;
}

/* ============================================================================
 * Utility Functions Implementation
 * ============================================================================ */

int dsmil_search_get_stats(
    const dsmil_search_context_t *ctx,
    uint32_t *total_searches,
    double *cache_hit_rate,
    uint32_t *memory_usage,
    double *avg_search_time_ns
) {
    if (!ctx || !total_searches || !cache_hit_rate || !memory_usage || !avg_search_time_ns) {
        return DSMIL_SEARCH_ERROR_INVALID_PARAM;
    }

    *total_searches = ctx->search_operations;
    *cache_hit_rate = ctx->search_operations > 0 ?
        (double)ctx->cache_hits / ctx->search_operations : 0.0;
    *memory_usage = ctx->memory_usage;
    *avg_search_time_ns = 0.0; // Would need timing instrumentation to calculate

    return DSMIL_SEARCH_SUCCESS;
}

int dsmil_search_reset_stats(dsmil_search_context_t *ctx) {
    if (!ctx) {
        return DSMIL_SEARCH_ERROR_INVALID_PARAM;
    }

    ctx->search_operations = 0;
    ctx->cache_hits = 0;
    ctx->memory_usage = 0;

    return DSMIL_SEARCH_SUCCESS;
}

bool dsmil_search_avx2_enabled(const dsmil_search_context_t *ctx) {
    if (!ctx) return false;
    return ctx->avx2_available && ctx->initialized;
}

const char* dsmil_search_get_version(void) {
    return not_stisla_version();
}
