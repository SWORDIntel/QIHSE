/*
 * QIHSE - Memory Migration Policy Helpers
 */

#ifndef QIHSE_MEMORY_MIGRATION_POLICY_H
#define QIHSE_MEMORY_MIGRATION_POLICY_H

#include "qihse_memory.h"

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define QIHSE_MEMORY_MIGRATION_REASON_SIZE 128u

typedef enum qihse_memory_migration_kind_e {
    QIHSE_MEMORY_MIGRATION_REJECT = 0,
    QIHSE_MEMORY_MIGRATION_ZERO_COPY = 1,
    QIHSE_MEMORY_MIGRATION_COPY_REQUIRED = 2
} qihse_memory_migration_kind_t;

typedef struct qihse_memory_migration_plan_s {
    qihse_memory_type_t source_type;
    qihse_memory_type_t target_type;
    int source_device;
    int target_device;
    qihse_memory_migration_kind_t kind;
    bool preserves_coherence;
    char reason[QIHSE_MEMORY_MIGRATION_REASON_SIZE];
} qihse_memory_migration_plan_t;

bool qihse_memory_migration_type_is_host_coherent(
    qihse_memory_type_t mem_type
);

bool qihse_memory_migration_is_zero_copy(
    qihse_memory_type_t source_type,
    qihse_memory_type_t target_type
);

bool qihse_memory_migration_plan(
    const qihse_memory_buffer_t* buffer,
    int target_device,
    qihse_memory_type_t target_type,
    qihse_memory_migration_plan_t* plan
);

const char* qihse_memory_migration_kind_name(
    qihse_memory_migration_kind_t kind
);

#ifdef __cplusplus
}
#endif

#endif /* QIHSE_MEMORY_MIGRATION_POLICY_H */
