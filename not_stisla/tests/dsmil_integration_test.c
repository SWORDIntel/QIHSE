#include "dsmil_not_stisla_wrapper.h"
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

/**
 * Basic integration test for DSMIL NOT_STISLA wrapper
 */

static void test_context_creation(void) {
    printf("Testing context creation...\n");

    dsmil_search_context_t *ctx = dsmil_search_create();
    assert(ctx != NULL);
    assert(ctx->initialized == true);
    assert(dsmil_search_avx2_enabled(ctx) == true);

    printf("✓ Context creation successful\n");
    printf("  AVX2 enabled: %s\n", dsmil_search_avx2_enabled(ctx) ? "yes" : "no");
    printf("  Version: %s\n", dsmil_search_get_version());

    dsmil_search_destroy(ctx);
}

static void test_telemetry_search(void) {
    printf("Testing telemetry search...\n");

    // Create test telemetry events
    dsmil_telemetry_event_t events[10];
    for (int i = 0; i < 10; i++) {
        events[i].timestamp = (dsmil_timestamp_t)(i * 1000); // 0, 1000, 2000, ...
        events[i].device_id = 107;
        events[i].layer_id = 3;
        events[i].event_type = 1;
    }

    dsmil_search_context_t *ctx = dsmil_search_create();
    assert(ctx != NULL);

    // Test exact match search
    dsmil_telemetry_result_t result;
    int ret = dsmil_search_telemetry_events(ctx, events, 10, 5000, &result);

    assert(ret == DSMIL_SEARCH_SUCCESS);
    assert(result.is_exact_match == true);
    assert(result.index == 5);
    assert(result.event->timestamp == 5000);

    printf("✓ Telemetry search successful\n");
    printf("  Found event at index %zu with timestamp %llu\n",
           result.index, (unsigned long long)result.exact_match_time);

    dsmil_search_destroy(ctx);
}

static void test_security_search(void) {
    printf("Testing security search...\n");

    // Create test security events
    dsmil_security_event_t events[5];
    for (int i = 0; i < 5; i++) {
        events[i].event_id = (dsmil_security_id_t)(i + 100);
        events[i].timestamp = (dsmil_timestamp_t)(i * 1000000);
        events[i].severity = 3;
        events[i].category = 1;
        snprintf(events[i].description, sizeof(events[i].description),
                "Security event %d", i + 100);
    }

    dsmil_search_context_t *ctx = dsmil_search_create();
    assert(ctx != NULL);

    // Test security event search
    dsmil_security_result_t result;
    int ret = dsmil_search_security_events(ctx, events, 5, 102, &result);

    assert(ret == DSMIL_SEARCH_SUCCESS);
    assert(result.is_exact_match == true);
    assert(result.index == 2);
    assert(result.matched_id == 102);

    printf("✓ Security search successful\n");
    printf("  Found security event %u at index %zu\n",
           result.matched_id, result.index);

    dsmil_search_destroy(ctx);
}

static void test_log_search(void) {
    printf("Testing log search...\n");

    // Create test log entries
    dsmil_log_entry_t logs[3];
    for (int i = 0; i < 3; i++) {
        logs[i].log_id = (dsmil_log_id_t)(i + 1000);
        logs[i].timestamp = (dsmil_timestamp_t)(i * 500000);
        logs[i].level = 4;
        logs[i].facility = 1;
        snprintf(logs[i].source, sizeof(logs[i].source), "device107");
        snprintf(logs[i].message, sizeof(logs[i].message),
                "Log message %d", i + 1000);
    }

    dsmil_search_context_t *ctx = dsmil_search_create();
    assert(ctx != NULL);

    // Test log search
    dsmil_log_result_t result;
    int ret = dsmil_search_log_entries(ctx, logs, 3, 1001, &result);

    assert(ret == DSMIL_SEARCH_SUCCESS);
    assert(result.is_exact_match == true);
    assert(result.index == 1);
    assert(result.matched_id == 1001);

    printf("✓ Log search successful\n");
    printf("  Found log entry %llu at index %zu\n",
           (unsigned long long)result.matched_id, result.index);

    dsmil_search_destroy(ctx);
}

static void test_error_handling(void) {
    printf("Testing error handling...\n");

    // Test invalid parameters
    dsmil_telemetry_result_t result;
    int ret = dsmil_search_telemetry_events(NULL, NULL, 0, 0, &result);
    assert(ret == DSMIL_SEARCH_ERROR_INVALID_PARAM);

    // Test uninitialized context
    dsmil_search_context_t *ctx = calloc(1, sizeof(dsmil_search_context_t));
    assert(ctx != NULL);
    ctx->initialized = false;

    dsmil_telemetry_event_t dummy_event;
    ret = dsmil_search_telemetry_events(ctx, &dummy_event, 1, 0, &result);
    assert(ret == DSMIL_SEARCH_ERROR_INIT_FAILED);

    free(ctx);

    printf("✓ Error handling tests passed\n");
}

static void test_statistics(void) {
    printf("Testing statistics...\n");

    dsmil_search_context_t *ctx = dsmil_search_create();
    assert(ctx != NULL);

    // Create test data
    dsmil_telemetry_event_t events[5];
    for (int i = 0; i < 5; i++) {
        events[i].timestamp = (dsmil_timestamp_t)i;
    }

    // Perform some searches
    dsmil_telemetry_result_t result;
    for (int i = 0; i < 3; i++) {
        dsmil_search_telemetry_events(ctx, events, 5, i, &result);
    }

    // Check statistics
    uint32_t total_searches;
    double cache_hit_rate, avg_time;
    uint32_t memory_usage;

    int ret = dsmil_search_get_stats(ctx, &total_searches, &cache_hit_rate,
                                    &memory_usage, &avg_time);
    assert(ret == DSMIL_SEARCH_SUCCESS);
    assert(total_searches == 3);

    printf("✓ Statistics tracking works\n");
    printf("  Total searches: %u\n", total_searches);

    // Reset statistics
    ret = dsmil_search_reset_stats(ctx);
    assert(ret == DSMIL_SEARCH_SUCCESS);

    ret = dsmil_search_get_stats(ctx, &total_searches, &cache_hit_rate,
                                &memory_usage, &avg_time);
    assert(total_searches == 0);

    printf("  Statistics reset successful\n");

    dsmil_search_destroy(ctx);
}

int main(int argc, char **argv) {
    printf("🧪 DSMIL NOT_STISLA Integration Test Suite\n");
    printf("==========================================\n\n");

    test_context_creation();
    printf("\n");

    test_telemetry_search();
    printf("\n");

    test_security_search();
    printf("\n");

    test_log_search();
    printf("\n");

    test_error_handling();
    printf("\n");

    test_statistics();
    printf("\n");

    printf("✅ All integration tests passed!\n");
    printf("NOT_STISLA is successfully integrated into DSMIL.\n");

    return 0;
}
