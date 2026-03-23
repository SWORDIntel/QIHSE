#ifndef DSMIL_NOT_STISLA_WRAPPER_H
#define DSMIL_NOT_STISLA_WRAPPER_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/**
 * @file dsmil_not_stisla_wrapper.h
 * @brief DSMIL-specific wrapper for NOT_STISLA high-performance search algorithm
 *
 * This wrapper provides a clean DSMIL-specific API for NOT_STISLA that integrates
 * with DSMIL error handling, data types, and component patterns.
 */

/* ============================================================================
 * DSMIL Error Codes
 * ============================================================================ */

#define DSMIL_SEARCH_SUCCESS              0
#define DSMIL_SEARCH_ERROR_INVALID_PARAM -1
#define DSMIL_SEARCH_ERROR_MEMORY        -2
#define DSMIL_SEARCH_ERROR_NOT_FOUND     -3
#define DSMIL_SEARCH_ERROR_NO_AVX2       -4
#define DSMIL_SEARCH_ERROR_INIT_FAILED   -5

/* ============================================================================
 * DSMIL Data Types
 * ============================================================================ */

/**
 * DSMIL timestamp type for telemetry and event data
 */
typedef uint64_t dsmil_timestamp_t;

/**
 * DSMIL security identifier type
 */
typedef uint32_t dsmil_security_id_t;

/**
 * DSMIL log entry ID type
 */
typedef uint64_t dsmil_log_id_t;

/* ============================================================================
 * Telemetry Search Structures
 * ============================================================================ */

/**
 * DSMIL telemetry event structure
 */
typedef struct {
    dsmil_timestamp_t timestamp;
    uint32_t event_type;
    uint32_t device_id;
    uint32_t layer_id;
    void *event_data;
    size_t data_size;
} dsmil_telemetry_event_t;

/**
 * DSMIL telemetry search result
 */
typedef struct {
    const dsmil_telemetry_event_t *event;
    size_t index;
    dsmil_timestamp_t exact_match_time;
    bool is_exact_match;
} dsmil_telemetry_result_t;

/* ============================================================================
 * Security Search Structures
 * ============================================================================ */

/**
 * DSMIL security event structure
 */
typedef struct {
    dsmil_timestamp_t timestamp;
    dsmil_security_id_t event_id;
    uint32_t severity;
    uint32_t category;
    char description[256];
} dsmil_security_event_t;

/**
 * DSMIL security search result
 */
typedef struct {
    const dsmil_security_event_t *event;
    size_t index;
    dsmil_security_id_t matched_id;
    bool is_exact_match;
} dsmil_security_result_t;

/* ============================================================================
 * Log Search Structures
 * ============================================================================ */

/**
 * DSMIL log entry structure
 */
typedef struct {
    dsmil_log_id_t log_id;
    dsmil_timestamp_t timestamp;
    uint32_t level;
    uint32_t facility;
    char message[1024];
    char source[64];
} dsmil_log_entry_t;

/**
 * DSMIL log search result
 */
typedef struct {
    const dsmil_log_entry_t *entry;
    size_t index;
    dsmil_log_id_t matched_id;
    bool is_exact_match;
} dsmil_log_result_t;

/* ============================================================================
 * Main Search Context
 * ============================================================================ */

/**
 * DSMIL search index - pre-extracted keys for high-performance search
 */
typedef struct {
    int64_t *keys;                    // Pre-extracted int64_t keys
    size_t num_elements;              // Number of elements in index
} dsmil_search_index_t;

/**
 * DSMIL search context - wraps NOT_STISLA anchor table with DSMIL-specific features
 */
typedef struct dsmil_search_context {
    void *not_stisla_table;           // NOT_STISLA anchor table
    bool avx2_available;              // AVX2 capability detected
    bool initialized;                 // Context properly initialized
    uint32_t search_operations;       // Statistics: total searches performed
    uint32_t cache_hits;              // Statistics: anchor table hits
    uint32_t memory_usage;            // Statistics: memory usage in bytes
    char last_error[256];             // Last error message for debugging

    // Internal cache for per-call key extraction optimization
    const void *last_data_ptr;        // Pointer to last used data array
    int64_t *cached_keys;             // Cached extracted keys
    size_t cached_count;              // Number of keys in cache
    size_t cached_capacity;           // Capacity of cached_keys array
} dsmil_search_context_t;

/* ============================================================================
 * Core API Functions
 * ============================================================================ */

/**
 * @brief Create a new DSMIL search context
 *
 * Initializes NOT_STISLA with AVX2 optimizations if available, otherwise
 * configures for fallback mode.
 *
 * @return Pointer to search context, or NULL on failure
 */
dsmil_search_context_t* dsmil_search_create(void);

/**
 * @brief Destroy a DSMIL search context
 *
 * Cleans up all resources associated with the search context.
 *
 * @param ctx Search context to destroy (can be NULL)
 */
void dsmil_search_destroy(dsmil_search_context_t *ctx);

/**
 * @brief Get last error message from search context
 *
 * @param ctx Search context
 * @return Pointer to error message string (empty if no error)
 */
const char* dsmil_search_get_last_error(const dsmil_search_context_t *ctx);

/* ============================================================================
 * Index Management Functions
 * ============================================================================ */

/**
 * @brief Create a pre-extracted index for telemetry events
 *
 * @param events Array of telemetry events
 * @param num_events Number of events
 * @return Pointer to new index, or NULL on failure
 */
dsmil_search_index_t* dsmil_search_index_create_telemetry(const dsmil_telemetry_event_t *events, size_t num_events);

/**
 * @brief Create a pre-extracted index for security events
 *
 * @param events Array of security events
 * @param num_events Number of events
 * @return Pointer to new index, or NULL on failure
 */
dsmil_search_index_t* dsmil_search_index_create_security(const dsmil_security_event_t *events, size_t num_events);

/**
 * @brief Create a pre-extracted index for log entries
 *
 * @param logs Array of log entries
 * @param num_logs Number of log entries
 * @return Pointer to new index, or NULL on failure
 */
dsmil_search_index_t* dsmil_search_index_create_logs(const dsmil_log_entry_t *logs, size_t num_logs);

/**
 * @brief Destroy a pre-extracted index
 *
 * @param index Index to destroy
 */
void dsmil_search_index_destroy(dsmil_search_index_t *index);

/* ============================================================================
 * Telemetry Search Functions
 * ============================================================================ */

/**
 * @brief Search telemetry events by timestamp
 *
 * Uses NOT_STISLA to find telemetry events closest to the target timestamp.
 * Events must be sorted by timestamp for optimal performance.
 *
 * @param ctx Search context
 * @param events Array of telemetry events (sorted by timestamp)
 * @param num_events Number of events in array
 * @param target_time Target timestamp to search for
 * @param result Pointer to store search result
 * @return DSMIL_SEARCH_SUCCESS on success, error code otherwise
 */
int dsmil_search_telemetry_events(
    dsmil_search_context_t *ctx,
    const dsmil_telemetry_event_t *events,
    size_t num_events,
    dsmil_timestamp_t target_time,
    dsmil_telemetry_result_t *result
);

/**
 * @brief Search telemetry events by timestamp using a pre-extracted index
 *
 * Optimized version that avoids key extraction overhead.
 *
 * @param ctx Search context
 * @param index Pre-extracted index
 * @param events Original array of telemetry events
 * @param target_time Target timestamp to search for
 * @param result Pointer to store search result
 * @return DSMIL_SEARCH_SUCCESS on success, error code otherwise
 */
int dsmil_search_telemetry_events_indexed(
    dsmil_search_context_t *ctx,
    const dsmil_search_index_t *index,
    const dsmil_telemetry_event_t *events,
    dsmil_timestamp_t target_time,
    dsmil_telemetry_result_t *result
);

/**
 * @brief Search telemetry events by device and timestamp range
 *
 * Finds all telemetry events for a specific device within a timestamp range.
 *
 * @param ctx Search context
 * @param events Array of telemetry events (sorted by timestamp)
 * @param num_events Number of events in array
 * @param device_id Device ID to filter by
 * @param start_time Start of timestamp range
 * @param end_time End of timestamp range
 * @param results Array to store matching events (caller allocated)
 * @param max_results Maximum number of results to return
 * @param num_found Pointer to store actual number of results found
 * @return DSMIL_SEARCH_SUCCESS on success, error code otherwise
 */
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
);

/* ============================================================================
 * Security Search Functions
 * ============================================================================ */

/**
 * @brief Search security events by event ID
 *
 * Uses NOT_STISLA to find security events by their unique identifier.
 *
 * @param ctx Search context
 * @param events Array of security events
 * @param num_events Number of events in array
 * @param target_id Target security event ID
 * @param result Pointer to store search result
 * @return DSMIL_SEARCH_SUCCESS on success, error code otherwise
 */
int dsmil_search_security_events(
    dsmil_search_context_t *ctx,
    const dsmil_security_event_t *events,
    size_t num_events,
    dsmil_security_id_t target_id,
    dsmil_security_result_t *result
);

/**
 * @brief Search security events by event ID using a pre-extracted index
 *
 * Optimized version that avoids key extraction overhead.
 *
 * @param ctx Search context
 * @param index Pre-extracted index
 * @param events Original array of security events
 * @param target_id Target security event ID
 * @param result Pointer to store search result
 * @return DSMIL_SEARCH_SUCCESS on success, error code otherwise
 */
int dsmil_search_security_events_indexed(
    dsmil_search_context_t *ctx,
    const dsmil_search_index_t *index,
    const dsmil_security_event_t *events,
    dsmil_security_id_t target_id,
    dsmil_security_result_t *result
);

/**
 * @brief Search security events by severity and time range
 *
 * Finds security events within a severity range and timestamp window.
 *
 * @param ctx Search context
 * @param events Array of security events (sorted by timestamp)
 * @param num_events Number of events in array
 * @param min_severity Minimum severity level (inclusive)
 * @param max_severity Maximum severity level (inclusive)
 * @param start_time Start of timestamp range
 * @param end_time End of timestamp range
 * @param results Array to store matching events (caller allocated)
 * @param max_results Maximum number of results to return
 * @param num_found Pointer to store actual number of results found
 * @return DSMIL_SEARCH_SUCCESS on success, error code otherwise
 */
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
);

/* ============================================================================
 * Log Search Functions
 * ============================================================================ */

/**
 * @brief Search log entries by log ID
 *
 * Uses NOT_STISLA to find log entries by their unique identifier.
 *
 * @param ctx Search context
 * @param logs Array of log entries
 * @param num_logs Number of log entries in array
 * @param target_id Target log entry ID
 * @param result Pointer to store search result
 * @return DSMIL_SEARCH_SUCCESS on success, error code otherwise
 */
int dsmil_search_log_entries(
    dsmil_search_context_t *ctx,
    const dsmil_log_entry_t *logs,
    size_t num_logs,
    dsmil_log_id_t target_id,
    dsmil_log_result_t *result
);

/**
 * @brief Search log entries by log ID using a pre-extracted index
 *
 * Optimized version that avoids key extraction overhead.
 *
 * @param ctx Search context
 * @param index Pre-extracted index
 * @param logs Original array of log entries
 * @param target_id Target log entry ID
 * @param result Pointer to store search result
 * @return DSMIL_SEARCH_SUCCESS on success, error code otherwise
 */
int dsmil_search_log_entries_indexed(
    dsmil_search_context_t *ctx,
    const dsmil_search_index_t *index,
    const dsmil_log_entry_t *logs,
    dsmil_log_id_t target_id,
    dsmil_log_result_t *result
);

/**
 * @brief Search log entries by facility and time range
 *
 * Finds log entries from specific facilities within a timestamp range.
 *
 * @param ctx Search context
 * @param logs Array of log entries (sorted by timestamp)
 * @param num_logs Number of log entries in array
 * @param facility Target facility code
 * @param start_time Start of timestamp range
 * @param end_time End of timestamp range
 * @param results Array to store matching entries (caller allocated)
 * @param max_results Maximum number of results to return
 * @param num_found Pointer to store actual number of results found
 * @return DSMIL_SEARCH_SUCCESS on success, error code otherwise
 */
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
);

/* ============================================================================
 * Utility Functions
 * ============================================================================ */

/**
 * @brief Get search performance statistics
 *
 * @param ctx Search context
 * @param total_searches Total number of searches performed
 * @param cache_hit_rate Cache hit rate (0.0 to 1.0)
 * @param memory_usage Memory usage in bytes
 * @param avg_search_time_ns Average search time in nanoseconds
 * @return DSMIL_SEARCH_SUCCESS on success, error code otherwise
 */
int dsmil_search_get_stats(
    const dsmil_search_context_t *ctx,
    uint32_t *total_searches,
    double *cache_hit_rate,
    uint32_t *memory_usage,
    double *avg_search_time_ns
);

/**
 * @brief Reset search statistics
 *
 * @param ctx Search context
 * @return DSMIL_SEARCH_SUCCESS on success, error code otherwise
 */
int dsmil_search_reset_stats(dsmil_search_context_t *ctx);

/**
 * @brief Check if AVX2 optimizations are available and enabled
 *
 * @param ctx Search context
 * @return true if AVX2 is available and enabled, false otherwise
 */
bool dsmil_search_avx2_enabled(const dsmil_search_context_t *ctx);

/**
 * @brief Get NOT_STISLA version information
 *
 * @return Version string
 */
const char* dsmil_search_get_version(void);

#endif /* DSMIL_NOT_STISLA_WRAPPER_H */
