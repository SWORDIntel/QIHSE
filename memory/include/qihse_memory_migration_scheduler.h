/*
 * QIHSE - Memory Migration Scheduler Helpers
 *
 * Deterministic predictive/background migration queue helpers. Background here
 * means caller-drained scheduled work; this module does not create threads.
 */

#ifndef QIHSE_MEMORY_MIGRATION_SCHEDULER_H
#define QIHSE_MEMORY_MIGRATION_SCHEDULER_H

#include "qihse_memory_migration_policy.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define QIHSE_MEMORY_MIGRATION_SCHEDULER_DEFAULT_HOT_ACCESS_THRESHOLD 1024u

typedef struct qihse_memory_migration_scheduler_config_s {
    double residency_weight;
    double access_weight;
    double coherence_weight;
    double target_weight;
    double policy_weight;
    uint64_t hot_access_threshold;
    double minimum_score;
} qihse_memory_migration_scheduler_config_t;

typedef struct qihse_memory_migration_candidate_s {
    qihse_memory_buffer_t* buffer;
    int target_device;
    qihse_memory_type_t target_type;
} qihse_memory_migration_candidate_t;

typedef struct qihse_memory_migration_task_s {
    qihse_memory_buffer_t* buffer;
    int target_device;
    qihse_memory_type_t target_type;
    qihse_memory_migration_plan_t plan;
    double score;
    uint64_t order;
} qihse_memory_migration_task_t;

typedef struct qihse_memory_migration_scheduler_s {
    qihse_memory_migration_task_t* tasks;
    size_t capacity;
    size_t count;
    uint64_t next_order;
    qihse_memory_migration_scheduler_config_t config;
} qihse_memory_migration_scheduler_t;

void qihse_memory_migration_scheduler_default_config(
    qihse_memory_migration_scheduler_config_t* config
);

bool qihse_memory_migration_scheduler_init(
    qihse_memory_migration_scheduler_t* scheduler,
    qihse_memory_migration_task_t* storage,
    size_t capacity,
    const qihse_memory_migration_scheduler_config_t* config
);

void qihse_memory_migration_scheduler_reset(
    qihse_memory_migration_scheduler_t* scheduler
);

bool qihse_memory_migration_scheduler_score(
    qihse_memory_buffer_t* buffer,
    int target_device,
    qihse_memory_type_t target_type,
    const qihse_memory_migration_scheduler_config_t* config,
    qihse_memory_migration_task_t* out_task
);

bool qihse_memory_migration_scheduler_enqueue(
    qihse_memory_migration_scheduler_t* scheduler,
    const qihse_memory_migration_candidate_t* candidate
);

size_t qihse_memory_migration_scheduler_enqueue_many(
    qihse_memory_migration_scheduler_t* scheduler,
    const qihse_memory_migration_candidate_t* candidates,
    size_t candidate_count
);

const qihse_memory_migration_task_t* qihse_memory_migration_scheduler_peek(
    const qihse_memory_migration_scheduler_t* scheduler
);

bool qihse_memory_migration_scheduler_pop(
    qihse_memory_migration_scheduler_t* scheduler,
    qihse_memory_migration_task_t* out_task
);

size_t qihse_memory_migration_scheduler_run(
    qihse_memory_manager_t manager,
    qihse_memory_migration_scheduler_t* scheduler,
    size_t max_tasks
);

#ifdef __cplusplus
}
#endif

#endif /* QIHSE_MEMORY_MIGRATION_SCHEDULER_H */
