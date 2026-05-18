/*
 * QIHSE - Memory Migration Backend Helpers
 *
 * Copy/DMA-style migration execution helpers. This layer is intentionally
 * lower level than the migration policy planner: policy decides whether a
 * migration is appropriate, while this backend layer plans and executes the
 * byte movement mechanism.
 */

#ifndef QIHSE_MEMORY_MIGRATION_BACKEND_H
#define QIHSE_MEMORY_MIGRATION_BACKEND_H

#include "qihse_memory.h"

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum qihse_memory_migration_backend_e {
    QIHSE_MEMORY_MIGRATION_BACKEND_HOST_MEMCPY = 0,
    QIHSE_MEMORY_MIGRATION_BACKEND_HARDWARE_DMA = 1,
    QIHSE_MEMORY_MIGRATION_BACKEND_DEVICE_COPY = 2
} qihse_memory_migration_backend_t;

typedef enum qihse_memory_migration_backend_status_e {
    QIHSE_MEMORY_MIGRATION_BACKEND_OK = 0,
    QIHSE_MEMORY_MIGRATION_BACKEND_INVALID_ARGUMENT = 1,
    QIHSE_MEMORY_MIGRATION_BACKEND_RANGE_OVERFLOW = 2,
    QIHSE_MEMORY_MIGRATION_BACKEND_OVERLAP_UNSUPPORTED = 3,
    QIHSE_MEMORY_MIGRATION_BACKEND_UNSUPPORTED_DMA = 4,
    QIHSE_MEMORY_MIGRATION_BACKEND_UNSUPPORTED_DEVICE = 5,
    QIHSE_MEMORY_MIGRATION_BACKEND_UNSUPPORTED_BACKEND = 6
} qihse_memory_migration_backend_status_t;

typedef struct qihse_memory_migration_backend_request_s {
    void* dst;
    const void* src;
    size_t byte_count;
    qihse_memory_type_t source_type;
    qihse_memory_type_t target_type;
    int source_device;
    int target_device;
    qihse_memory_migration_backend_t backend;
    void* backend_context;
} qihse_memory_migration_backend_request_t;

typedef qihse_memory_migration_backend_status_t (*qihse_memory_migration_backend_copy_fn)(
    const qihse_memory_migration_backend_request_t* request,
    void* user_context
);

typedef struct qihse_memory_migration_backend_registry_s {
    qihse_memory_migration_backend_copy_fn hardware_dma_copy;
    void* hardware_dma_context;
    qihse_memory_migration_backend_copy_fn device_copy;
    void* device_copy_context;
} qihse_memory_migration_backend_registry_t;

typedef struct qihse_memory_migration_backend_plan_s {
    qihse_memory_migration_backend_t backend;
    qihse_memory_migration_backend_status_t status;
    size_t byte_count;
    bool executable;
    bool preserves_bytes;
} qihse_memory_migration_backend_plan_t;

const char* qihse_memory_migration_backend_name(
    qihse_memory_migration_backend_t backend
);

const char* qihse_memory_migration_backend_status_name(
    qihse_memory_migration_backend_status_t status
);

bool qihse_memory_migration_backend_is_supported(
    qihse_memory_migration_backend_t backend
);

void qihse_memory_migration_backend_init_registry(
    qihse_memory_migration_backend_registry_t* registry
);

bool qihse_memory_migration_backend_register_copy_callback(
    qihse_memory_migration_backend_t backend,
    qihse_memory_migration_backend_copy_fn callback,
    void* user_context
);

qihse_memory_migration_backend_request_t qihse_memory_migration_backend_request(
    void* dst,
    const void* src,
    size_t byte_count,
    qihse_memory_migration_backend_t backend
);

qihse_memory_migration_backend_status_t qihse_memory_migration_backend_plan(
    const qihse_memory_migration_backend_request_t* request,
    qihse_memory_migration_backend_plan_t* plan
);

qihse_memory_migration_backend_status_t qihse_memory_migration_backend_execute_plan(
    const qihse_memory_migration_backend_request_t* request,
    const qihse_memory_migration_backend_plan_t* plan
);

qihse_memory_migration_backend_status_t qihse_memory_migration_backend_execute(
    const qihse_memory_migration_backend_request_t* request
);

#ifdef __cplusplus
}
#endif

#endif /* QIHSE_MEMORY_MIGRATION_BACKEND_H */
