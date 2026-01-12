/*
 * QIHSE - Unified Memory Management Implementation
 *
 * Core memory management for quantum-inspired search operations.
 *
 * Version: 1.0.0
 * Author: DSMIL System
 * License: MIT
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include "../include/qihse_memory.h"
#include "../../orchestration/include/qihse_hetero.h"
#include "../../not_stisla/include/not_stisla.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdatomic.h>
#include <pthread.h>

/* ============================================================================
 * INTERNAL STRUCTURES
 * ============================================================================ */

/**
 * Memory manager internal structure.
 */
typedef struct qihse_memory_manager_s {
    qihse_context_t ctx;             /* Phase 0 ABI context */
    const char* backend_type;        /* Backend type string */

    /* Statistics (atomically updated for thread safety) */
    atomic_size_t total_allocated;
    atomic_size_t total_used;
    atomic_size_t peak_usage;
    atomic_size_t num_buffers;

    /* Per-type statistics */
    atomic_size_t host_memory;
    atomic_size_t device_memory;
    atomic_size_t unified_memory;

    /* Performance tracking */
    atomic_uint_fast64_t total_allocations;
    atomic_uint_fast64_t total_frees;
    atomic_uint_fast64_t total_migrations;
    double avg_allocation_time;      /* Microseconds */

    /* Policy and configuration */
    qihse_memory_policy_t policy;
    pthread_mutex_t policy_mutex;

    /* Buffer tracking */
    qihse_memory_buffer_t** buffers;
    size_t max_buffers;
    size_t num_tracked_buffers;
    pthread_mutex_t buffer_mutex;
} qihse_memory_manager_internal_t;

/* ============================================================================
 * UTILITY FUNCTIONS
 * ============================================================================ */

size_t qihse_memory_get_alignment(qihse_memory_type_t mem_type) {
    switch (mem_type) {
        case QIHSE_MEM_HOST:
            return 64;  /* Cache line alignment */
        case QIHSE_MEM_PINNED:
            return 4096; /* Page alignment */
        case QIHSE_MEM_DEVICE:
            return 256; /* SIMD alignment */
        case QIHSE_MEM_UNIFIED:
            return 64;  /* Cache line alignment */
        case QIHSE_MEM_HMA_SUPERPOSITION:
            return 64;  /* SIMD alignment */
        case QIHSE_MEM_HMA_INTERACTION:
            return 64;  /* Cache alignment */
        case QIHSE_MEM_HMA_ENTANGLEMENT:
            return 4096; /* Page alignment */
        case QIHSE_MEM_ANCHOR_TABLE:
            return 4096; /* Large table aligned to page size */
        case QIHSE_MEM_ANCHOR_WORKSPACE:
            return 64;   /* Workspace benefits from cache alignment */
        default:
            return 64;
    }
}

bool qihse_memory_is_accessible(qihse_memory_type_t mem_type, qihse_device_type_t device) {
    bool device_is_cpu = (device == QIHSE_DEVICE_CPU_AVX2 ||
                          device == QIHSE_DEVICE_CPU_AVX512 ||
                          device == QIHSE_DEVICE_CPU_AMX);
    switch (mem_type) {
        case QIHSE_MEM_HOST:
            return true; /* Host memory always accessible */
        case QIHSE_MEM_PINNED:
            return true; /* Pinned host memory accessible */
        case QIHSE_MEM_DEVICE:
            return !device_is_cpu;
        case QIHSE_MEM_UNIFIED:
            return true; /* Unified memory accessible by all */
        case QIHSE_MEM_HMA_SUPERPOSITION:
        case QIHSE_MEM_HMA_INTERACTION:
        case QIHSE_MEM_HMA_ENTANGLEMENT:
            return true; /* HMA memory accessible by all */
        case QIHSE_MEM_ANCHOR_TABLE:
        case QIHSE_MEM_ANCHOR_WORKSPACE:
            return true; /* Anchor data accessible system-wide */
        default:
            return false;
    }
}

const char* qihse_memory_type_string(qihse_memory_type_t mem_type) {
    switch (mem_type) {
        case QIHSE_MEM_HOST: return "HOST";
        case QIHSE_MEM_PINNED: return "PINNED";
        case QIHSE_MEM_DEVICE: return "DEVICE";
        case QIHSE_MEM_UNIFIED: return "UNIFIED";
        case QIHSE_MEM_HMA_SUPERPOSITION: return "HMA_SUPERPOSITION";
        case QIHSE_MEM_HMA_INTERACTION: return "HMA_INTERACTION";
        case QIHSE_MEM_HMA_ENTANGLEMENT: return "HMA_ENTANGLEMENT";
        case QIHSE_MEM_ANCHOR_TABLE: return "ANCHOR_TABLE";
        case QIHSE_MEM_ANCHOR_WORKSPACE: return "ANCHOR_WORKSPACE";
        default: return "UNKNOWN";
    }
}

/* ============================================================================
 * MEMORY MANAGER LIFECYCLE
 * ============================================================================ */

qihse_memory_manager_t qihse_memory_manager_create(qihse_context_t ctx, const char* backend_type) {
    if (!ctx || !backend_type) {
        errno = EINVAL;
        return NULL;
    }

    qihse_memory_manager_internal_t* manager = calloc(1, sizeof(qihse_memory_manager_internal_t));
    if (!manager) {
        errno = ENOMEM;
        return NULL;
    }

    manager->ctx = ctx;
    manager->backend_type = strdup(backend_type);
    if (!manager->backend_type) {
        free(manager);
        errno = ENOMEM;
        return NULL;
    }

    /* Initialize atomics */
    atomic_init(&manager->total_allocated, 0);
    atomic_init(&manager->total_used, 0);
    atomic_init(&manager->peak_usage, 0);
    atomic_init(&manager->num_buffers, 0);
    atomic_init(&manager->host_memory, 0);
    atomic_init(&manager->device_memory, 0);
    atomic_init(&manager->unified_memory, 0);
    atomic_init(&manager->total_allocations, 0);
    atomic_init(&manager->total_frees, 0);
    atomic_init(&manager->total_migrations, 0);

    manager->avg_allocation_time = 0.0;
    manager->policy = QIHSE_POLICY_FIRST_FIT;

    /* Initialize mutexes */
    if (pthread_mutex_init(&manager->policy_mutex, NULL) != 0) {
        free((void*)manager->backend_type);
        free(manager);
        errno = ENOMEM;
        return NULL;
    }

    /* Buffer tracking */
    manager->max_buffers = 1024;
    manager->buffers = calloc(manager->max_buffers, sizeof(qihse_memory_buffer_t*));
    if (!manager->buffers) {
        pthread_mutex_destroy(&manager->policy_mutex);
        free((void*)manager->backend_type);
        free(manager);
        errno = ENOMEM;
        return NULL;
    }

    if (pthread_mutex_init(&manager->buffer_mutex, NULL) != 0) {
        free(manager->buffers);
        pthread_mutex_destroy(&manager->policy_mutex);
        free((void*)manager->backend_type);
        free(manager);
        errno = ENOMEM;
        return NULL;
    }

    return (qihse_memory_manager_t)manager;
}

void qihse_memory_manager_destroy(qihse_memory_manager_t manager) {
    if (!manager) return;

    qihse_memory_manager_internal_t* internal = (qihse_memory_manager_internal_t*)manager;

    /* Clean up tracked buffers */
    pthread_mutex_lock(&internal->buffer_mutex);
    for (size_t i = 0; i < internal->num_tracked_buffers; i++) {
        if (internal->buffers[i]) {
            qihse_memory_free(manager, internal->buffers[i]);
        }
    }
    pthread_mutex_unlock(&internal->buffer_mutex);

    /* Clean up resources */
    pthread_mutex_destroy(&internal->buffer_mutex);
    pthread_mutex_destroy(&internal->policy_mutex);
    free(internal->buffers);
    free((void*)internal->backend_type);
    free(internal);
}

/* ============================================================================
 * BUFFER ALLOCATION AND MANAGEMENT
 * ============================================================================ */

qihse_memory_buffer_t* qihse_memory_allocate(
    qihse_memory_manager_t manager,
    size_t size,
    qihse_memory_type_t mem_type,
    qihse_memory_access_t access_pattern,
    uint32_t flags
) {
    if (!manager || size == 0) {
        return NULL;
    }

    qihse_memory_manager_internal_t* internal = (qihse_memory_manager_internal_t*)manager;

    /* Allocate buffer structure */
    qihse_memory_buffer_t* buffer = calloc(1, sizeof(qihse_memory_buffer_t));
    if (!buffer) {
        return NULL;
    }

    /* Determine allocation size with alignment */
    size_t alignment = qihse_memory_get_alignment(mem_type);
    buffer->allocated_size = ((size + alignment - 1) / alignment) * alignment;
    buffer->logical_size = size;
    buffer->mem_type = mem_type;
    buffer->access_pattern = access_pattern;
    buffer->flags = flags;
    buffer->preferred_device = 0; /* Default CPU device */
    buffer->is_migratable = true;

    /* Allocate actual memory */
    void* data = NULL;
    int alloc_result = posix_memalign(&data, alignment, buffer->allocated_size);

    if (alloc_result != 0) {
        free(buffer);
        return NULL;
    }

    /* Initialize ABI buffer */
    buffer->abi_buffer.data = data;
    buffer->abi_buffer.size = buffer->allocated_size;
    buffer->abi_buffer.flags = 0; /* ABI flags */

    /* Apply zero initialization if requested */
    if (flags & QIHSE_MEM_ZERO) {
        memset(data, 0, buffer->allocated_size);
    }

    /* Update statistics atomically */
    atomic_fetch_add(&internal->total_allocated, buffer->allocated_size);
    atomic_fetch_add(&internal->total_used, size);
    atomic_fetch_add(&internal->num_buffers, 1);

    /* Update per-type statistics */
    switch (mem_type) {
        case QIHSE_MEM_HOST:
        case QIHSE_MEM_PINNED:
            atomic_fetch_add(&internal->host_memory, buffer->allocated_size);
            break;
        case QIHSE_MEM_DEVICE:
            atomic_fetch_add(&internal->device_memory, buffer->allocated_size);
            break;
        case QIHSE_MEM_UNIFIED:
        case QIHSE_MEM_HMA_SUPERPOSITION:
        case QIHSE_MEM_HMA_INTERACTION:
        case QIHSE_MEM_HMA_ENTANGLEMENT:
            atomic_fetch_add(&internal->unified_memory, buffer->allocated_size);
            break;
        case QIHSE_MEM_ANCHOR_TABLE:
        case QIHSE_MEM_ANCHOR_WORKSPACE:
            atomic_fetch_add(&internal->host_memory, buffer->allocated_size);
            break;
    }

    atomic_fetch_add(&internal->total_allocations, 1);

    /* Update peak usage */
    size_t current_used = atomic_load(&internal->total_used);
    size_t current_peak = atomic_load(&internal->peak_usage);
    while (current_used > current_peak) {
        if (atomic_compare_exchange_weak(&internal->peak_usage, &current_peak, current_used)) {
            break;
        }
    }

    /* Track buffer if requested */
    if (flags & QIHSE_MEM_TRACKED) {
        pthread_mutex_lock(&internal->buffer_mutex);
        if (internal->num_tracked_buffers < internal->max_buffers) {
            internal->buffers[internal->num_tracked_buffers++] = buffer;
        }
        pthread_mutex_unlock(&internal->buffer_mutex);
    }

    return buffer;
}

void qihse_memory_free(qihse_memory_manager_t manager, qihse_memory_buffer_t* buffer) {
    if (!manager || !buffer) return;

    qihse_memory_manager_internal_t* internal = (qihse_memory_manager_internal_t*)manager;

    /* Update statistics */
    atomic_fetch_sub(&internal->total_allocated, buffer->allocated_size);
    atomic_fetch_sub(&internal->total_used, buffer->logical_size);
    atomic_fetch_sub(&internal->num_buffers, 1);

    /* Update per-type statistics */
    switch (buffer->mem_type) {
        case QIHSE_MEM_HOST:
        case QIHSE_MEM_PINNED:
            atomic_fetch_sub(&internal->host_memory, buffer->allocated_size);
            break;
        case QIHSE_MEM_DEVICE:
            atomic_fetch_sub(&internal->device_memory, buffer->allocated_size);
            break;
        case QIHSE_MEM_UNIFIED:
        case QIHSE_MEM_HMA_SUPERPOSITION:
        case QIHSE_MEM_HMA_INTERACTION:
        case QIHSE_MEM_HMA_ENTANGLEMENT:
            atomic_fetch_sub(&internal->unified_memory, buffer->allocated_size);
            break;
        case QIHSE_MEM_ANCHOR_TABLE:
        case QIHSE_MEM_ANCHOR_WORKSPACE:
            atomic_fetch_sub(&internal->host_memory, buffer->allocated_size);
            break;
    }

    atomic_fetch_add(&internal->total_frees, 1);

    /* Free actual memory */
    free(buffer->abi_buffer.data);

    /* Remove from tracking if present */
    pthread_mutex_lock(&internal->buffer_mutex);
    for (size_t i = 0; i < internal->num_tracked_buffers; i++) {
        if (internal->buffers[i] == buffer) {
            internal->buffers[i] = internal->buffers[--internal->num_tracked_buffers];
            break;
        }
    }
    pthread_mutex_unlock(&internal->buffer_mutex);

    /* Free buffer structure */
    free(buffer);
}

bool qihse_memory_resize(qihse_memory_manager_t manager, qihse_memory_buffer_t* buffer, size_t new_size) {
    if (!manager || !buffer || new_size == 0) {
        return false;
    }

    qihse_memory_manager_internal_t* internal = (qihse_memory_manager_internal_t*)manager;

    /* Implement basic reallocation */
    /* Future optimization: in-place resize when possible */

    size_t old_logical_size = buffer->logical_size;
    size_t alignment = qihse_memory_get_alignment(buffer->mem_type);
    size_t new_allocated_size = ((new_size + alignment - 1) / alignment) * alignment;

    void* new_data = NULL;
    int alloc_result = posix_memalign(&new_data, alignment, new_allocated_size);

    if (alloc_result != 0) {
        return false;
    }

    /* Copy existing data */
    size_t copy_size = (new_size < old_logical_size) ? new_size : old_logical_size;
    memcpy(new_data, buffer->abi_buffer.data, copy_size);

    /* Zero new space if expanding and zero flag set */
    if (new_size > old_logical_size && (buffer->flags & QIHSE_MEM_ZERO)) {
        memset((char*)new_data + old_logical_size, 0, new_size - old_logical_size);
    }

    /* Free old memory */
    free(buffer->abi_buffer.data);

    size_t old_allocated_size = buffer->allocated_size;

    /* Update buffer */
    buffer->abi_buffer.data = new_data;
    buffer->abi_buffer.size = new_allocated_size;
    buffer->allocated_size = new_allocated_size;
    buffer->logical_size = new_size;

    /* Update statistics */
    atomic_fetch_sub(&internal->total_used, old_logical_size);
    atomic_fetch_add(&internal->total_used, new_size);

    /* Update per-type statistics */
    size_t size_diff = new_allocated_size - old_allocated_size;
    switch (buffer->mem_type) {
        case QIHSE_MEM_HOST:
        case QIHSE_MEM_PINNED:
            atomic_fetch_add(&internal->host_memory, size_diff);
            break;
        case QIHSE_MEM_DEVICE:
            atomic_fetch_add(&internal->device_memory, size_diff);
            break;
        case QIHSE_MEM_UNIFIED:
        case QIHSE_MEM_HMA_SUPERPOSITION:
        case QIHSE_MEM_HMA_INTERACTION:
        case QIHSE_MEM_HMA_ENTANGLEMENT:
            atomic_fetch_add(&internal->unified_memory, size_diff);
            break;
        case QIHSE_MEM_ANCHOR_TABLE:
        case QIHSE_MEM_ANCHOR_WORKSPACE:
            atomic_fetch_add(&internal->host_memory, size_diff);
            break;
    }

    return true;
}

/* ============================================================================
 * DATA TRANSFER AND MIGRATION
 * ============================================================================ */

bool qihse_memory_copy(
    qihse_memory_manager_t manager,
    qihse_memory_buffer_t* dst,
    size_t dst_offset,
    const qihse_memory_buffer_t* src,
    size_t src_offset,
    size_t size
) {
    if (!manager || !dst || !src || !dst->abi_buffer.data || !src->abi_buffer.data) {
        return false;
    }

    if (dst_offset + size > dst->allocated_size || src_offset + size > src->allocated_size) {
        return false;
    }

    /* Perform copy */
    memcpy((char*)dst->abi_buffer.data + dst_offset,
           (char*)src->abi_buffer.data + src_offset, size);

    /* Update access tracking */
    atomic_fetch_add(&dst->access_count, 1);
    atomic_fetch_add(&((qihse_memory_buffer_t*)src)->access_count, 1); /* Cast away const for statistics */

    return true;
}

bool qihse_memory_migrate(
    qihse_memory_manager_t manager,
    qihse_memory_buffer_t* buffer,
    int target_device,
    qihse_memory_type_t target_type
) {
    if (!manager || !buffer) {
        return false;
    }

    qihse_memory_manager_internal_t* internal = (qihse_memory_manager_internal_t*)manager;

    /* Check if migration is possible */
    if (!buffer->is_migratable) {
        return false;
    }

    if (!qihse_memory_is_accessible(target_type, target_device)) {
        return false;
    }

    /* Migration is no-op in unified memory model */
    /* Future: Implement device-specific migration when needed */

    buffer->preferred_device = target_device;
    buffer->mem_type = target_type;

    atomic_fetch_add(&internal->total_migrations, 1);

    return true;
}

bool qihse_memory_prefetch(
    qihse_memory_manager_t manager,
    qihse_memory_buffer_t* buffer,
    int device
) {
    if (!manager || !buffer) {
        return false;
    }

    /* Prefetch not implemented in this version */
    /* Future: Implement prefetching for device-specific memory */

    buffer->preferred_device = device;
    return true;
}

/* ============================================================================
 * STATISTICS AND MONITORING
 * ============================================================================ */

bool qihse_memory_get_stats(qihse_memory_manager_t manager, qihse_memory_stats_t* stats) {
    if (!manager || !stats) {
        return false;
    }

    qihse_memory_manager_internal_t* internal = (qihse_memory_manager_internal_t*)manager;

    /* Atomically read all statistics */
    stats->total_allocated = atomic_load(&internal->total_allocated);
    stats->total_used = atomic_load(&internal->total_used);
    stats->peak_usage = atomic_load(&internal->peak_usage);
    stats->num_buffers = atomic_load(&internal->num_buffers);
    stats->host_memory = atomic_load(&internal->host_memory);
    stats->device_memory = atomic_load(&internal->device_memory);
    stats->unified_memory = atomic_load(&internal->unified_memory);
    stats->total_allocations = atomic_load(&internal->total_allocations);
    stats->total_frees = atomic_load(&internal->total_frees);
    stats->total_migrations = atomic_load(&internal->total_migrations);
    stats->avg_allocation_time = internal->avg_allocation_time;

    return true;
}

void qihse_memory_reset_stats(qihse_memory_manager_t manager) {
    if (!manager) return;

    qihse_memory_manager_internal_t* internal = (qihse_memory_manager_internal_t*)manager;

    /* Reset atomic counters */
    atomic_store(&internal->total_allocations, 0);
    atomic_store(&internal->total_frees, 0);
    atomic_store(&internal->total_migrations, 0);
    internal->avg_allocation_time = 0.0;
}

/* ============================================================================
 * POLICY MANAGEMENT
 * ============================================================================ */

void qihse_memory_set_policy(qihse_memory_manager_t manager, qihse_memory_policy_t policy) {
    if (!manager) return;

    qihse_memory_manager_internal_t* internal = (qihse_memory_manager_internal_t*)manager;

    pthread_mutex_lock(&internal->policy_mutex);
    internal->policy = policy;
    pthread_mutex_unlock(&internal->policy_mutex);
}

qihse_memory_policy_t qihse_memory_get_policy(qihse_memory_manager_t manager) {
    if (!manager) return QIHSE_POLICY_FIRST_FIT;

    qihse_memory_manager_internal_t* internal = (qihse_memory_manager_internal_t*)manager;

    pthread_mutex_lock(&internal->policy_mutex);
    qihse_memory_policy_t policy = internal->policy;
    pthread_mutex_unlock(&internal->policy_mutex);

    return policy;
}

/* ============================================================================
 * QIHSE-NOT_STISLA INTEGRATION: ANCHOR MEMORY MANAGEMENT
 * ============================================================================ */

/**
 * Anchor table entry for LRU tracking.
 */
typedef struct qihse_anchor_table_entry_s {
    qihse_memory_buffer_t* buffer;    /* The anchor table buffer */
    int workload_type;                /* Associated workload type */
    size_t memory_used;               /* Memory usage of this table */
    uint64_t last_access_time;        /* Last access timestamp */
    uint64_t creation_time;           /* Creation timestamp */
    struct qihse_anchor_table_entry_s* next; /* LRU list next pointer */
    struct qihse_anchor_table_entry_s* prev; /* LRU list prev pointer */
} qihse_anchor_table_entry_t;

/**
 * Anchor memory manager internal structure.
 */
typedef struct qihse_anchor_memory_manager_s {
    qihse_memory_manager_t parent_manager; /* Parent memory manager */

    /* Memory limits */
    size_t max_memory_bytes;          /* Maximum memory budget */
    bool enable_lru;                  /* Enable LRU pruning */

    /* Current state */
    size_t current_memory_used;       /* Current memory usage */
    size_t num_active_tables;         /* Number of active anchor tables */
    size_t total_pruned_count;        /* Total anchors pruned */

    /* LRU tracking */
    qihse_anchor_table_entry_t* lru_head; /* Most recently used */
    qihse_anchor_table_entry_t* lru_tail; /* Least recently used */

    /* Statistics */
    uint64_t total_allocations;       /* Total anchor table allocations */
    uint64_t total_prunings;          /* Total LRU pruning operations */

    /* Thread safety */
    pthread_mutex_t mutex;            /* Protect all operations */
} qihse_anchor_memory_manager_internal_t;

qihse_anchor_memory_manager_t qihse_anchor_memory_manager_create(
    qihse_memory_manager_t manager,
    size_t max_memory_mb,
    bool enable_lru
) {
    if (!manager || max_memory_mb == 0) {
        return NULL;
    }

    qihse_anchor_memory_manager_internal_t* anchor_manager =
        calloc(1, sizeof(qihse_anchor_memory_manager_internal_t));

    if (!anchor_manager) {
        return NULL;
    }

    anchor_manager->parent_manager = manager;
    anchor_manager->max_memory_bytes = max_memory_mb * 1024 * 1024; /* Convert MB to bytes */
    anchor_manager->enable_lru = enable_lru;
    anchor_manager->current_memory_used = 0;
    anchor_manager->num_active_tables = 0;
    anchor_manager->total_pruned_count = 0;
    anchor_manager->total_allocations = 0;
    anchor_manager->total_prunings = 0;
    anchor_manager->lru_head = NULL;
    anchor_manager->lru_tail = NULL;

    /* Initialize mutex */
    if (pthread_mutex_init(&anchor_manager->mutex, NULL) != 0) {
        free(anchor_manager);
        return NULL;
    }

    return (qihse_anchor_memory_manager_t)anchor_manager;
}

void qihse_anchor_memory_manager_destroy(qihse_anchor_memory_manager_t anchor_manager) {
    if (!anchor_manager) return;

    qihse_anchor_memory_manager_internal_t* internal =
        (qihse_anchor_memory_manager_internal_t*)anchor_manager;

    pthread_mutex_lock(&internal->mutex);

    /* Free all anchor table entries */
    qihse_anchor_table_entry_t* entry = internal->lru_head;
    while (entry) {
        qihse_anchor_table_entry_t* next = entry->next;

        /* Free the buffer */
        if (entry->buffer) {
            qihse_memory_free(internal->parent_manager, entry->buffer);
        }

        free(entry);
        entry = next;
    }

    pthread_mutex_unlock(&internal->mutex);
    pthread_mutex_destroy(&internal->mutex);
    free(internal);
}

qihse_memory_buffer_t* qihse_anchor_memory_allocate_table(
    qihse_anchor_memory_manager_t anchor_manager,
    size_t max_anchors,
    int workload_type
) {
    if (!anchor_manager || max_anchors == 0) {
        return NULL;
    }

    qihse_anchor_memory_manager_internal_t* internal =
        (qihse_anchor_memory_manager_internal_t*)anchor_manager;

    /* Calculate required memory for anchor table */
    size_t anchor_size = sizeof(not_stisla_anchor_t);
    size_t table_overhead = sizeof(not_stisla_anchor_table_t);
    size_t required_memory = (max_anchors * anchor_size) + table_overhead;

    pthread_mutex_lock(&internal->mutex);

    /* Check if allocation exceeds memory limits */
    if (!qihse_anchor_memory_check_limits(anchor_manager, required_memory)) {
        /* Try LRU pruning if enabled */
        if (internal->enable_lru) {
            size_t pruned = qihse_anchor_memory_prune_lru(anchor_manager, required_memory);
            if (pruned == 0 || !qihse_anchor_memory_check_limits(anchor_manager, required_memory)) {
                pthread_mutex_unlock(&internal->mutex);
                return NULL; /* Still can't allocate */
            }
        } else {
            pthread_mutex_unlock(&internal->mutex);
            return NULL; /* LRU disabled and over limit */
        }
    }

    /* Allocate the anchor table buffer */
    qihse_memory_buffer_t* buffer = qihse_memory_allocate(
        internal->parent_manager,
        required_memory,
        QIHSE_MEM_ANCHOR_TABLE,
        QIHSE_ACCESS_RANDOM, /* Anchor tables have random access patterns */
        0 /* No special flags */
    );

    if (!buffer) {
        pthread_mutex_unlock(&internal->mutex);
        return NULL;
    }

    /* Create anchor table entry for tracking */
    qihse_anchor_table_entry_t* entry = calloc(1, sizeof(qihse_anchor_table_entry_t));
    if (!entry) {
        qihse_memory_free(internal->parent_manager, buffer);
        pthread_mutex_unlock(&internal->mutex);
        return NULL;
    }

    entry->buffer = buffer;
    entry->workload_type = workload_type;
    entry->memory_used = required_memory;
    entry->creation_time = time(NULL);
    entry->last_access_time = entry->creation_time;

    /* Add to LRU list (as most recently used) */
    if (internal->lru_head) {
        internal->lru_head->prev = entry;
        entry->next = internal->lru_head;
    } else {
        internal->lru_tail = entry;
    }
    internal->lru_head = entry;

    /* Update statistics */
    internal->current_memory_used += required_memory;
    internal->num_active_tables++;
    internal->total_allocations++;

    pthread_mutex_unlock(&internal->mutex);
    return buffer;
}

qihse_memory_buffer_t* qihse_anchor_memory_allocate_workspace(
    qihse_anchor_memory_manager_t anchor_manager,
    size_t workspace_size
) {
    if (!anchor_manager || workspace_size == 0) {
        return NULL;
    }

    qihse_anchor_memory_manager_internal_t* internal =
        (qihse_anchor_memory_manager_internal_t*)anchor_manager;

    /* Allocate workspace buffer */
    return qihse_memory_allocate(
        internal->parent_manager,
        workspace_size,
        QIHSE_MEM_ANCHOR_WORKSPACE,
        QIHSE_ACCESS_SEQUENTIAL, /* Workspace typically sequential access */
        0 /* No special flags */
    );
}

bool qihse_anchor_memory_check_limits(
    qihse_anchor_memory_manager_t anchor_manager,
    size_t requested_size
) {
    if (!anchor_manager) return false;

    qihse_anchor_memory_manager_internal_t* internal =
        (qihse_anchor_memory_manager_internal_t*)anchor_manager;

    return (internal->current_memory_used + requested_size) <= internal->max_memory_bytes;
}

size_t qihse_anchor_memory_prune_lru(
    qihse_anchor_memory_manager_t anchor_manager,
    size_t target_free_bytes
) {
    if (!anchor_manager) return 0;

    qihse_anchor_memory_manager_internal_t* internal =
        (qihse_anchor_memory_manager_internal_t*)anchor_manager;

    size_t freed_bytes = 0;
    size_t pruned_count = 0;

    /* Remove least recently used entries until we free enough memory */
    while (internal->lru_tail && freed_bytes < target_free_bytes) {
        qihse_anchor_table_entry_t* victim = internal->lru_tail;

        /* Remove from LRU list */
        if (victim->prev) {
            victim->prev->next = NULL;
        } else {
            internal->lru_head = NULL;
        }
        internal->lru_tail = victim->prev;

        /* Free the buffer */
        if (victim->buffer) {
            qihse_memory_free(internal->parent_manager, victim->buffer);
        }

        /* Update statistics */
        freed_bytes += victim->memory_used;
        internal->current_memory_used -= victim->memory_used;
        internal->num_active_tables--;
        pruned_count++;

        free(victim);
    }

    if (pruned_count > 0) {
        internal->total_prunings++;
        internal->total_pruned_count += pruned_count;
    }

    return pruned_count;
}

void qihse_anchor_memory_get_stats(
    qihse_anchor_memory_manager_t anchor_manager,
    size_t* current_usage_bytes,
    size_t* max_usage_bytes,
    size_t* num_tables,
    size_t* pruned_count
) {
    if (!anchor_manager) return;

    qihse_anchor_memory_manager_internal_t* internal =
        (qihse_anchor_memory_manager_internal_t*)anchor_manager;

    if (current_usage_bytes) *current_usage_bytes = internal->current_memory_used;
    if (max_usage_bytes) *max_usage_bytes = internal->max_memory_bytes;
    if (num_tables) *num_tables = internal->num_active_tables;
    if (pruned_count) *pruned_count = internal->total_pruned_count;
}

bool qihse_anchor_memory_optimize_for_workload(
    qihse_anchor_memory_manager_t anchor_manager,
    qihse_memory_buffer_t* table,
    int workload_type
) {
    if (!anchor_manager || !table) return false;

    qihse_anchor_memory_manager_internal_t* internal =
        (qihse_anchor_memory_manager_internal_t*)anchor_manager;

    /* Find the table entry and update its workload type */
    pthread_mutex_lock(&internal->mutex);

    qihse_anchor_table_entry_t* entry = internal->lru_head;
    while (entry) {
        if (entry->buffer == table) {
            entry->workload_type = workload_type;
            entry->last_access_time = time(NULL);
            pthread_mutex_unlock(&internal->mutex);
            return true;
        }
        entry = entry->next;
    }

    pthread_mutex_unlock(&internal->mutex);
    return false; /* Table not found */
}
