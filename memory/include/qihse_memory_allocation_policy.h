/*
 * QIHSE - Memory Allocation Policy Helpers
 *
 * Allocation fallback order and per-memory-type accounting support.
 * This module is intentionally independent from the allocator implementation
 * so it can be integrated into qihse_memory_allocate_for_workload later.
 */

#ifndef QIHSE_MEMORY_ALLOCATION_POLICY_H
#define QIHSE_MEMORY_ALLOCATION_POLICY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "qihse_memory.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Keep this in sync with qihse_memory_type_t in qihse_memory.h.
 * The enum currently spans QIHSE_MEM_HOST through QIHSE_MEM_ANCHOR_WORKSPACE.
 */
#define QIHSE_MEMORY_ALLOCATION_POLICY_TYPE_COUNT 9u

typedef struct qihse_memory_allocation_type_stats_s {
    uint64_t allocation_attempts;      /* Requests that targeted this type */
    uint64_t allocation_failures;      /* Failed requests that targeted this type */
    uint64_t successful_allocations;   /* Allocations actually placed in this type */
    uint64_t frees;                    /* Frees recorded for this actual type */
    uint64_t fallback_from_count;      /* Requests for this type satisfied elsewhere */
    uint64_t fallback_to_count;        /* Requests for other types satisfied here */
    size_t current_bytes;              /* Live bytes currently placed in this type */
    size_t peak_bytes;                 /* Peak live bytes placed in this type */
    size_t total_allocated_bytes;      /* Cumulative bytes placed in this type */
    size_t total_freed_bytes;          /* Cumulative bytes released from this type */
} qihse_memory_allocation_type_stats_t;

typedef struct qihse_memory_allocation_stats_s {
    qihse_memory_allocation_type_stats_t by_type[QIHSE_MEMORY_ALLOCATION_POLICY_TYPE_COUNT];
    uint64_t invalid_type_events;
} qihse_memory_allocation_stats_t;

bool qihse_memory_allocation_policy_is_valid_type(qihse_memory_type_t mem_type);

size_t qihse_memory_allocation_policy_type_count(void);

/*
 * Writes the fallback order for preferred_type into out_types.
 *
 * The preferred type is always first when preferred_type is valid. The returned
 * value is the full fallback order length, even when max_types truncates the
 * number of entries written. Passing out_types as NULL is valid and returns the
 * required length without writing entries.
 */
size_t qihse_memory_allocation_policy_fallback_order(
    qihse_memory_type_t preferred_type,
    qihse_memory_type_t* out_types,
    size_t max_types
);

bool qihse_memory_allocation_policy_has_fallback(
    qihse_memory_type_t preferred_type,
    qihse_memory_type_t candidate_type
);

void qihse_memory_allocation_stats_init(
    qihse_memory_allocation_stats_t* stats
);

void qihse_memory_allocation_stats_record_success(
    qihse_memory_allocation_stats_t* stats,
    qihse_memory_type_t requested_type,
    qihse_memory_type_t actual_type,
    size_t bytes
);

void qihse_memory_allocation_stats_record_failure(
    qihse_memory_allocation_stats_t* stats,
    qihse_memory_type_t requested_type
);

void qihse_memory_allocation_stats_record_free(
    qihse_memory_allocation_stats_t* stats,
    qihse_memory_type_t actual_type,
    size_t bytes
);

const qihse_memory_allocation_type_stats_t*
qihse_memory_allocation_stats_get_type(
    const qihse_memory_allocation_stats_t* stats,
    qihse_memory_type_t mem_type
);

#ifdef __cplusplus
}
#endif

#endif /* QIHSE_MEMORY_ALLOCATION_POLICY_H */
