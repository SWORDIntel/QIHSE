/*
 * QIHSE - Memory Allocation Policy Tests
 */

#include "../memory/include/qihse_memory_allocation_policy.h"

#include <assert.h>

static void test_fallback_order(void)
{
    qihse_memory_type_t order[4];
    size_t count;

    count = qihse_memory_allocation_policy_fallback_order(
        QIHSE_MEM_DEVICE,
        order,
        4u
    );

    assert(count == 4u);
    assert(order[0] == QIHSE_MEM_DEVICE);
    assert(order[1] == QIHSE_MEM_UNIFIED);
    assert(order[2] == QIHSE_MEM_PINNED);
    assert(order[3] == QIHSE_MEM_HOST);

    count = qihse_memory_allocation_policy_fallback_order(
        QIHSE_MEM_DEVICE,
        order,
        2u
    );

    assert(count == 4u);
    assert(order[0] == QIHSE_MEM_DEVICE);
    assert(order[1] == QIHSE_MEM_UNIFIED);

    assert(qihse_memory_allocation_policy_has_fallback(
        QIHSE_MEM_HMA_SUPERPOSITION,
        QIHSE_MEM_HOST
    ));
    assert(!qihse_memory_allocation_policy_has_fallback(
        QIHSE_MEM_HOST,
        QIHSE_MEM_DEVICE
    ));
    assert(qihse_memory_allocation_policy_fallback_order(
        (qihse_memory_type_t)99,
        order,
        4u
    ) == 0u);
}

static void test_stats_accounting(void)
{
    qihse_memory_allocation_stats_t stats;
    const qihse_memory_allocation_type_stats_t* device_stats;
    const qihse_memory_allocation_type_stats_t* host_stats;
    const qihse_memory_allocation_type_stats_t* pinned_stats;

    qihse_memory_allocation_stats_init(&stats);

    qihse_memory_allocation_stats_record_success(
        &stats,
        QIHSE_MEM_DEVICE,
        QIHSE_MEM_HOST,
        64u
    );
    qihse_memory_allocation_stats_record_success(
        &stats,
        QIHSE_MEM_HOST,
        QIHSE_MEM_HOST,
        16u
    );
    qihse_memory_allocation_stats_record_free(
        &stats,
        QIHSE_MEM_HOST,
        32u
    );
    qihse_memory_allocation_stats_record_failure(
        &stats,
        QIHSE_MEM_PINNED
    );

    device_stats = qihse_memory_allocation_stats_get_type(&stats, QIHSE_MEM_DEVICE);
    host_stats = qihse_memory_allocation_stats_get_type(&stats, QIHSE_MEM_HOST);
    pinned_stats = qihse_memory_allocation_stats_get_type(&stats, QIHSE_MEM_PINNED);

    assert(device_stats != NULL);
    assert(host_stats != NULL);
    assert(pinned_stats != NULL);

    assert(device_stats->allocation_attempts == 1u);
    assert(device_stats->successful_allocations == 0u);
    assert(device_stats->fallback_from_count == 1u);

    assert(host_stats->allocation_attempts == 1u);
    assert(host_stats->successful_allocations == 2u);
    assert(host_stats->fallback_to_count == 1u);
    assert(host_stats->current_bytes == 48u);
    assert(host_stats->peak_bytes == 80u);
    assert(host_stats->total_allocated_bytes == 80u);
    assert(host_stats->total_freed_bytes == 32u);

    assert(pinned_stats->allocation_attempts == 1u);
    assert(pinned_stats->allocation_failures == 1u);

    qihse_memory_allocation_stats_record_free(
        &stats,
        QIHSE_MEM_HOST,
        128u
    );
    host_stats = qihse_memory_allocation_stats_get_type(&stats, QIHSE_MEM_HOST);
    assert(host_stats != NULL);
    assert(host_stats->current_bytes == 0u);
    assert(host_stats->total_freed_bytes == 80u);
}

int main(void)
{
    test_fallback_order();
    test_stats_accounting();
    return 0;
}
