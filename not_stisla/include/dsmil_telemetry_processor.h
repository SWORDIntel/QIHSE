#ifndef DSMIL_TELEMETRY_PROCESSOR_H
#define DSMIL_TELEMETRY_PROCESSOR_H

#include "dsmil_not_stisla_wrapper.h"

/**
 * @file dsmil_telemetry_processor.h
 * @brief High-performance telemetry processing with NOT_STISLA acceleration
 *
 * Provides telemetry event storage, timestamp-based lookups, and pattern analysis
 * using NOT_STISLA for 22.28× speedup over traditional search methods.
 */

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Telemetry Processor Context
 * ============================================================================ */

/**
 * Opaque telemetry processor context
 */
typedef struct dsmil_telemetry_processor dsmil_telemetry_processor_t;

/* ============================================================================
 * Core Telemetry Processor API
 * ============================================================================ */

/**
 * @brief Create a new telemetry processor with NOT_STISLA acceleration
 *
 * @param max_events Maximum number of telemetry events to store
 * @return Pointer to telemetry processor, or NULL on failure
 */
dsmil_telemetry_processor_t* dsmil_telemetry_processor_create(size_t max_events);

/**
 * @brief Destroy telemetry processor and free resources
 *
 * @param processor Telemetry processor to destroy (can be NULL)
 */
void dsmil_telemetry_processor_destroy(dsmil_telemetry_processor_t *processor);

/**
 * @brief Add telemetry event to processor
 *
 * @param processor Telemetry processor
 * @param event Telemetry event to add
 * @return DSMIL_SEARCH_SUCCESS on success, error code otherwise
 */
int dsmil_telemetry_processor_add_event(dsmil_telemetry_processor_t *processor,
                                      const dsmil_telemetry_event_t *event);

/**
 * @brief Find telemetry event by exact timestamp (NOT_STISLA accelerated)
 *
 * Uses NOT_STISLA interpolation search for 22.28× speedup over binary search.
 *
 * @param processor Telemetry processor
 * @param target_time Target timestamp to search for
 * @param result Pointer to store search result
 * @return DSMIL_SEARCH_SUCCESS on success, error code otherwise
 */
int dsmil_telemetry_processor_find_by_timestamp(
    dsmil_telemetry_processor_t *processor,
    dsmil_timestamp_t target_time,
    dsmil_telemetry_result_t *result
);

/**
 * @brief Find telemetry events within timestamp range
 *
 * @param processor Telemetry processor
 * @param start_time Start of timestamp range (inclusive)
 * @param end_time End of timestamp range (inclusive)
 * @param results Array to store matching events (caller allocated)
 * @param max_results Maximum number of results to return
 * @param num_found Pointer to store actual number of results found
 * @return DSMIL_SEARCH_SUCCESS on success, error code otherwise
 */
int dsmil_telemetry_processor_find_in_time_range(
    dsmil_telemetry_processor_t *processor,
    dsmil_timestamp_t start_time,
    dsmil_timestamp_t end_time,
    dsmil_telemetry_result_t *results,
    size_t max_results,
    size_t *num_found
);

/**
 * @brief Find telemetry events for specific device within time range
 *
 * @param processor Telemetry processor
 * @param device_id Device ID to filter by
 * @param start_time Start of timestamp range (inclusive)
 * @param end_time End of timestamp range (inclusive)
 * @param results Array to store matching events (caller allocated)
 * @param max_results Maximum number of results to return
 * @param num_found Pointer to store actual number of results found
 * @return DSMIL_SEARCH_SUCCESS on success, error code otherwise
 */
int dsmil_telemetry_processor_find_by_device_time_range(
    dsmil_telemetry_processor_t *processor,
    uint32_t device_id,
    dsmil_timestamp_t start_time,
    dsmil_timestamp_t end_time,
    dsmil_telemetry_result_t *results,
    size_t max_results,
    size_t *num_found
);

/* ============================================================================
 * Analysis and Statistics API
 * ============================================================================ */

/**
 * @brief Get telemetry processor statistics
 *
 * @param processor Telemetry processor
 * @param total_events Total events stored
 * @param search_operations Total search operations performed
 * @param avg_search_time_ns Average search time in nanoseconds
 * @param memory_usage Memory usage in bytes
 * @return DSMIL_SEARCH_SUCCESS on success, error code otherwise
 */
int dsmil_telemetry_processor_get_stats(
    const dsmil_telemetry_processor_t *processor,
    uint32_t *total_events,
    uint32_t *search_operations,
    double *avg_search_time_ns,
    uint32_t *memory_usage
);

/**
 * @brief Clear all telemetry events from processor
 *
 * @param processor Telemetry processor
 * @return DSMIL_SEARCH_SUCCESS on success, error code otherwise
 */
int dsmil_telemetry_processor_clear(dsmil_telemetry_processor_t *processor);

/**
 * @brief Analyze telemetry patterns in time window
 *
 * Performs pattern analysis on telemetry events within the specified time window
 * using NOT_STISLA-accelerated searches.
 *
 * @param processor Telemetry processor
 * @param analysis_window_start Start of analysis window
 * @param analysis_window_end End of analysis window
 * @param analysis_report Buffer to store analysis report
 * @param max_report_length Maximum length of report buffer
 * @return DSMIL_SEARCH_SUCCESS on success, error code otherwise
 */
int dsmil_telemetry_processor_analyze_patterns(
    dsmil_telemetry_processor_t *processor,
    dsmil_timestamp_t analysis_window_start,
    dsmil_timestamp_t analysis_window_end,
    char *analysis_report,
    size_t max_report_length
);

#ifdef __cplusplus
}
#endif

#endif /* DSMIL_TELEMETRY_PROCESSOR_H */
