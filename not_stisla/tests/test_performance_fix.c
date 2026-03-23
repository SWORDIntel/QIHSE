#include "dsmil_not_stisla_wrapper.h"
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>

/**
 * Test to verify the performance fix for O(N) allocations and copies
 */

void test_cache_mechanism() {
    printf("Testing internal cache mechanism...\n");

    dsmil_search_context_t *ctx = dsmil_search_create();
    assert(ctx != NULL);

    // Create test telemetry events
    size_t num_events = 1000;
    dsmil_telemetry_event_t *events = malloc(num_events * sizeof(dsmil_telemetry_event_t));
    for (size_t i = 0; i < num_events; i++) {
        events[i].timestamp = (dsmil_timestamp_t)(i * 10);
        events[i].device_id = 1;
    }

    dsmil_telemetry_result_t result;

    // First call - should extract keys (O(N))
    dsmil_search_telemetry_events(ctx, events, num_events, 500, &result);

    uint32_t total_searches, memory_usage;
    double cache_hit_rate, avg_time;
    dsmil_search_get_stats(ctx, &total_searches, &cache_hit_rate, &memory_usage, &avg_time);

    assert(total_searches == 1);
    assert(cache_hit_rate == 0.0);

    // Second call with same events pointer - should use cache
    dsmil_search_telemetry_events(ctx, events, num_events, 600, &result);
    dsmil_search_get_stats(ctx, &total_searches, &cache_hit_rate, &memory_usage, &avg_time);

    assert(total_searches == 2);
    assert(cache_hit_rate == 0.5); // 1 hit out of 2 searches

    printf("✓ Internal cache mechanism verified (hit rate: %.2f)\n", cache_hit_rate);

    free(events);
    dsmil_search_destroy(ctx);
}

void test_indexed_search() {
    printf("Testing explicit indexed search...\n");

    dsmil_search_context_t *ctx = dsmil_search_create();
    assert(ctx != NULL);

    // Create test telemetry events
    size_t num_events = 1000;
    dsmil_telemetry_event_t *events = malloc(num_events * sizeof(dsmil_telemetry_event_t));
    for (size_t i = 0; i < num_events; i++) {
        events[i].timestamp = (dsmil_timestamp_t)(i * 10);
    }

    // Create index explicitly
    dsmil_search_index_t *index = dsmil_search_index_create_telemetry(events, num_events);
    assert(index != NULL);
    assert(index->num_elements == num_events);

    dsmil_telemetry_result_t result;

    // Search using index
    int ret = dsmil_search_telemetry_events_indexed(ctx, index, events, 500, &result);
    assert(ret == DSMIL_SEARCH_SUCCESS);
    assert(result.index == 50);
    assert(result.event->timestamp == 500);

    uint32_t total_searches, memory_usage;
    double cache_hit_rate, avg_time;
    dsmil_search_get_stats(ctx, &total_searches, &cache_hit_rate, &memory_usage, &avg_time);

    assert(total_searches == 1);
    assert(cache_hit_rate == 1.0); // Indexed search counts as cache hit for extraction

    printf("✓ Explicit indexed search verified\n");

    dsmil_search_index_destroy(index);
    free(events);
    dsmil_search_destroy(ctx);
}

int main() {
    printf("🧪 Verification of Performance Fix\n");
    printf("=================================\n\n");

    test_cache_mechanism();
    printf("\n");
    test_indexed_search();
    printf("\n");

    printf("✅ All performance fix tests passed!\n");
    return 0;
}
