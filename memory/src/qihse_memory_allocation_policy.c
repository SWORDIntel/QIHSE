/*
 * QIHSE - Memory Allocation Policy Helpers
 */

#include "../include/qihse_memory_allocation_policy.h"

#include <string.h>

typedef struct qihse_memory_fallback_order_s {
    qihse_memory_type_t preferred_type;
    const qihse_memory_type_t* order;
    size_t count;
} qihse_memory_fallback_order_t;

static const qihse_memory_type_t qihse_memory_fallback_host[] = {
    QIHSE_MEM_HOST
};

static const qihse_memory_type_t qihse_memory_fallback_pinned[] = {
    QIHSE_MEM_PINNED,
    QIHSE_MEM_HOST
};

static const qihse_memory_type_t qihse_memory_fallback_device[] = {
    QIHSE_MEM_DEVICE,
    QIHSE_MEM_UNIFIED,
    QIHSE_MEM_PINNED,
    QIHSE_MEM_HOST
};

static const qihse_memory_type_t qihse_memory_fallback_unified[] = {
    QIHSE_MEM_UNIFIED,
    QIHSE_MEM_PINNED,
    QIHSE_MEM_HOST
};

static const qihse_memory_type_t qihse_memory_fallback_hma_superposition[] = {
    QIHSE_MEM_HMA_SUPERPOSITION,
    QIHSE_MEM_UNIFIED,
    QIHSE_MEM_PINNED,
    QIHSE_MEM_HOST
};

static const qihse_memory_type_t qihse_memory_fallback_hma_interaction[] = {
    QIHSE_MEM_HMA_INTERACTION,
    QIHSE_MEM_UNIFIED,
    QIHSE_MEM_PINNED,
    QIHSE_MEM_HOST
};

static const qihse_memory_type_t qihse_memory_fallback_hma_entanglement[] = {
    QIHSE_MEM_HMA_ENTANGLEMENT,
    QIHSE_MEM_UNIFIED,
    QIHSE_MEM_PINNED,
    QIHSE_MEM_HOST
};

static const qihse_memory_type_t qihse_memory_fallback_anchor_table[] = {
    QIHSE_MEM_ANCHOR_TABLE,
    QIHSE_MEM_UNIFIED,
    QIHSE_MEM_PINNED,
    QIHSE_MEM_HOST
};

static const qihse_memory_type_t qihse_memory_fallback_anchor_workspace[] = {
    QIHSE_MEM_ANCHOR_WORKSPACE,
    QIHSE_MEM_UNIFIED,
    QIHSE_MEM_PINNED,
    QIHSE_MEM_HOST
};

#define QIHSE_MEMORY_ARRAY_COUNT(array_) (sizeof(array_) / sizeof((array_)[0]))

static const qihse_memory_fallback_order_t qihse_memory_fallback_orders[] = {
    {
        QIHSE_MEM_HOST,
        qihse_memory_fallback_host,
        QIHSE_MEMORY_ARRAY_COUNT(qihse_memory_fallback_host)
    },
    {
        QIHSE_MEM_PINNED,
        qihse_memory_fallback_pinned,
        QIHSE_MEMORY_ARRAY_COUNT(qihse_memory_fallback_pinned)
    },
    {
        QIHSE_MEM_DEVICE,
        qihse_memory_fallback_device,
        QIHSE_MEMORY_ARRAY_COUNT(qihse_memory_fallback_device)
    },
    {
        QIHSE_MEM_UNIFIED,
        qihse_memory_fallback_unified,
        QIHSE_MEMORY_ARRAY_COUNT(qihse_memory_fallback_unified)
    },
    {
        QIHSE_MEM_HMA_SUPERPOSITION,
        qihse_memory_fallback_hma_superposition,
        QIHSE_MEMORY_ARRAY_COUNT(qihse_memory_fallback_hma_superposition)
    },
    {
        QIHSE_MEM_HMA_INTERACTION,
        qihse_memory_fallback_hma_interaction,
        QIHSE_MEMORY_ARRAY_COUNT(qihse_memory_fallback_hma_interaction)
    },
    {
        QIHSE_MEM_HMA_ENTANGLEMENT,
        qihse_memory_fallback_hma_entanglement,
        QIHSE_MEMORY_ARRAY_COUNT(qihse_memory_fallback_hma_entanglement)
    },
    {
        QIHSE_MEM_ANCHOR_TABLE,
        qihse_memory_fallback_anchor_table,
        QIHSE_MEMORY_ARRAY_COUNT(qihse_memory_fallback_anchor_table)
    },
    {
        QIHSE_MEM_ANCHOR_WORKSPACE,
        qihse_memory_fallback_anchor_workspace,
        QIHSE_MEMORY_ARRAY_COUNT(qihse_memory_fallback_anchor_workspace)
    }
};

static const qihse_memory_fallback_order_t*
qihse_memory_allocation_policy_find_order(qihse_memory_type_t mem_type)
{
    size_t i;

    for (i = 0u; i < QIHSE_MEMORY_ARRAY_COUNT(qihse_memory_fallback_orders); ++i) {
        if (qihse_memory_fallback_orders[i].preferred_type == mem_type) {
            return &qihse_memory_fallback_orders[i];
        }
    }

    return NULL;
}

static bool qihse_memory_allocation_policy_to_index(
    qihse_memory_type_t mem_type,
    size_t* index
)
{
    if (!qihse_memory_allocation_policy_is_valid_type(mem_type)) {
        return false;
    }

    if (index != NULL) {
        *index = (size_t)mem_type;
    }

    return true;
}

static void qihse_memory_allocation_stats_note_invalid(
    qihse_memory_allocation_stats_t* stats
)
{
    if (stats != NULL) {
        stats->invalid_type_events += 1u;
    }
}

bool qihse_memory_allocation_policy_is_valid_type(qihse_memory_type_t mem_type)
{
    return mem_type >= QIHSE_MEM_HOST &&
        mem_type <= QIHSE_MEM_ANCHOR_WORKSPACE;
}

size_t qihse_memory_allocation_policy_type_count(void)
{
    return QIHSE_MEMORY_ALLOCATION_POLICY_TYPE_COUNT;
}

size_t qihse_memory_allocation_policy_fallback_order(
    qihse_memory_type_t preferred_type,
    qihse_memory_type_t* out_types,
    size_t max_types
)
{
    const qihse_memory_fallback_order_t* fallback_order;
    size_t i;
    size_t write_count;

    fallback_order = qihse_memory_allocation_policy_find_order(preferred_type);
    if (fallback_order == NULL) {
        return 0u;
    }

    write_count = fallback_order->count;
    if (write_count > max_types) {
        write_count = max_types;
    }

    if (out_types != NULL) {
        for (i = 0u; i < write_count; ++i) {
            out_types[i] = fallback_order->order[i];
        }
    }

    return fallback_order->count;
}

bool qihse_memory_allocation_policy_has_fallback(
    qihse_memory_type_t preferred_type,
    qihse_memory_type_t candidate_type
)
{
    const qihse_memory_fallback_order_t* fallback_order;
    size_t i;

    fallback_order = qihse_memory_allocation_policy_find_order(preferred_type);
    if (fallback_order == NULL) {
        return false;
    }

    for (i = 0u; i < fallback_order->count; ++i) {
        if (fallback_order->order[i] == candidate_type) {
            return true;
        }
    }

    return false;
}

void qihse_memory_allocation_stats_init(
    qihse_memory_allocation_stats_t* stats
)
{
    if (stats != NULL) {
        memset(stats, 0, sizeof(*stats));
    }
}

void qihse_memory_allocation_stats_record_success(
    qihse_memory_allocation_stats_t* stats,
    qihse_memory_type_t requested_type,
    qihse_memory_type_t actual_type,
    size_t bytes
)
{
    size_t requested_index = 0u;
    size_t actual_index;
    bool requested_valid;
    qihse_memory_allocation_type_stats_t* actual_stats;

    if (stats == NULL) {
        return;
    }

    requested_valid = qihse_memory_allocation_policy_to_index(requested_type, &requested_index);
    if (requested_valid) {
        stats->by_type[requested_index].allocation_attempts += 1u;
    } else {
        qihse_memory_allocation_stats_note_invalid(stats);
    }

    if (!qihse_memory_allocation_policy_to_index(actual_type, &actual_index)) {
        qihse_memory_allocation_stats_note_invalid(stats);
        return;
    }

    actual_stats = &stats->by_type[actual_index];
    actual_stats->successful_allocations += 1u;
    actual_stats->current_bytes += bytes;
    actual_stats->total_allocated_bytes += bytes;

    if (actual_stats->current_bytes > actual_stats->peak_bytes) {
        actual_stats->peak_bytes = actual_stats->current_bytes;
    }

    if (requested_type != actual_type && requested_valid) {
        stats->by_type[requested_index].fallback_from_count += 1u;
        actual_stats->fallback_to_count += 1u;
    }
}

void qihse_memory_allocation_stats_record_failure(
    qihse_memory_allocation_stats_t* stats,
    qihse_memory_type_t requested_type
)
{
    size_t requested_index;

    if (stats == NULL) {
        return;
    }

    if (!qihse_memory_allocation_policy_to_index(requested_type, &requested_index)) {
        qihse_memory_allocation_stats_note_invalid(stats);
        return;
    }

    stats->by_type[requested_index].allocation_attempts += 1u;
    stats->by_type[requested_index].allocation_failures += 1u;
}

void qihse_memory_allocation_stats_record_free(
    qihse_memory_allocation_stats_t* stats,
    qihse_memory_type_t actual_type,
    size_t bytes
)
{
    size_t actual_index;
    size_t released_bytes;
    qihse_memory_allocation_type_stats_t* actual_stats;

    if (stats == NULL) {
        return;
    }

    if (!qihse_memory_allocation_policy_to_index(actual_type, &actual_index)) {
        qihse_memory_allocation_stats_note_invalid(stats);
        return;
    }

    actual_stats = &stats->by_type[actual_index];
    released_bytes = bytes;
    if (released_bytes > actual_stats->current_bytes) {
        released_bytes = actual_stats->current_bytes;
    }

    actual_stats->frees += 1u;
    actual_stats->current_bytes -= released_bytes;
    actual_stats->total_freed_bytes += released_bytes;
}

const qihse_memory_allocation_type_stats_t*
qihse_memory_allocation_stats_get_type(
    const qihse_memory_allocation_stats_t* stats,
    qihse_memory_type_t mem_type
)
{
    size_t index;

    if (stats == NULL ||
        !qihse_memory_allocation_policy_to_index(mem_type, &index)) {
        return NULL;
    }

    return &stats->by_type[index];
}
