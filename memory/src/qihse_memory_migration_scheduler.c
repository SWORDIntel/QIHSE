/*
 * QIHSE - Memory Migration Scheduler Helpers
 */

#include "../include/qihse_memory_migration_scheduler.h"

#include <string.h>

static double qihse_scheduler_clamp(double value, double min_value, double max_value)
{
    if (value != value) {
        return min_value;
    }
    if (value < min_value) {
        return min_value;
    }
    if (value > max_value) {
        return max_value;
    }
    return value;
}

static uint64_t qihse_scheduler_max_u64(uint64_t a, uint64_t b)
{
    return a > b ? a : b;
}

static qihse_memory_migration_scheduler_config_t qihse_scheduler_effective_config(
    const qihse_memory_migration_scheduler_config_t* config
)
{
    qihse_memory_migration_scheduler_config_t effective;

    if (config) {
        effective = *config;
    } else {
        qihse_memory_migration_scheduler_default_config(&effective);
    }

    if (effective.hot_access_threshold == 0u) {
        effective.hot_access_threshold = QIHSE_MEMORY_MIGRATION_SCHEDULER_DEFAULT_HOT_ACCESS_THRESHOLD;
    }

    return effective;
}

static double qihse_scheduler_access_score(uint64_t access_count, uint64_t hot_threshold)
{
    if (hot_threshold == 0u) {
        return access_count > 0u ? 1.0 : 0.0;
    }
    if (access_count >= hot_threshold) {
        return 1.0;
    }
    return (double)access_count / (double)hot_threshold;
}

static double qihse_scheduler_coherence_score(
    const qihse_memory_buffer_t* buffer,
    const qihse_memory_migration_plan_t* plan
)
{
    uint64_t observed_version;
    uint64_t lag;
    double score;

    observed_version = qihse_scheduler_max_u64(
        buffer->coherence_last_read_version,
        buffer->coherence_last_write_version
    );

    lag = buffer->coherence_version > observed_version
        ? buffer->coherence_version - observed_version
        : 0u;

    score = 0.0;

    if (buffer->coherence_shared) {
        score += 0.20;
    }

    if (buffer->coherence_last_write_version > buffer->coherence_last_read_version) {
        score -= 0.25;
    }

    if (lag > 0u) {
        score -= qihse_scheduler_clamp((double)lag / 16.0, 0.0, 0.35);
    }

    switch (buffer->coherence_state) {
        case 0u:
            score += 0.00;
            break;
        case 1u:
            score += 0.10;
            break;
        case 2u:
            score -= 0.15;
            break;
        default:
            score -= 0.05;
            break;
    }

    if (plan->preserves_coherence) {
        score += 0.35;
    } else {
        score -= 0.35;
    }

    return qihse_scheduler_clamp(score, -1.0, 1.0);
}

static double qihse_scheduler_target_score(qihse_memory_type_t target_type)
{
    switch (target_type) {
        case QIHSE_MEM_HOST:
            return 0.10;
        case QIHSE_MEM_PINNED:
            return 0.45;
        case QIHSE_MEM_DEVICE:
            return 0.80;
        case QIHSE_MEM_UNIFIED:
            return 0.65;
        case QIHSE_MEM_HMA_SUPERPOSITION:
            return 0.90;
        case QIHSE_MEM_HMA_INTERACTION:
            return 0.75;
        case QIHSE_MEM_HMA_ENTANGLEMENT:
            return 0.85;
        case QIHSE_MEM_ANCHOR_TABLE:
            return 0.40;
        case QIHSE_MEM_ANCHOR_WORKSPACE:
            return 0.50;
        default:
            return 0.0;
    }
}

static double qihse_scheduler_policy_score(const qihse_memory_migration_plan_t* plan)
{
    double score;

    switch (plan->kind) {
        case QIHSE_MEMORY_MIGRATION_ZERO_COPY:
            score = 1.0;
            break;
        case QIHSE_MEMORY_MIGRATION_COPY_REQUIRED:
            score = 0.55;
            break;
        case QIHSE_MEMORY_MIGRATION_REJECT:
        default:
            return -1.0;
    }

    if (plan->preserves_coherence) {
        score += 0.20;
    } else {
        score -= 0.30;
    }

    return qihse_scheduler_clamp(score, -1.0, 1.0);
}

static bool qihse_scheduler_task_precedes(
    const qihse_memory_migration_task_t* lhs,
    const qihse_memory_migration_task_t* rhs
)
{
    if (lhs->score > rhs->score) {
        return true;
    }
    if (lhs->score < rhs->score) {
        return false;
    }
    return lhs->order < rhs->order;
}

void qihse_memory_migration_scheduler_default_config(
    qihse_memory_migration_scheduler_config_t* config
)
{
    if (!config) {
        return;
    }

    config->residency_weight = 40.0;
    config->access_weight = 25.0;
    config->coherence_weight = 15.0;
    config->target_weight = 10.0;
    config->policy_weight = 10.0;
    config->hot_access_threshold = QIHSE_MEMORY_MIGRATION_SCHEDULER_DEFAULT_HOT_ACCESS_THRESHOLD;
    config->minimum_score = 1.0;
}

bool qihse_memory_migration_scheduler_init(
    qihse_memory_migration_scheduler_t* scheduler,
    qihse_memory_migration_task_t* storage,
    size_t capacity,
    const qihse_memory_migration_scheduler_config_t* config
)
{
    if (!scheduler || (!storage && capacity > 0u)) {
        return false;
    }

    scheduler->tasks = storage;
    scheduler->capacity = capacity;
    scheduler->count = 0u;
    scheduler->next_order = 0u;
    scheduler->config = qihse_scheduler_effective_config(config);

    return true;
}

void qihse_memory_migration_scheduler_reset(
    qihse_memory_migration_scheduler_t* scheduler
)
{
    if (!scheduler) {
        return;
    }

    scheduler->count = 0u;
    scheduler->next_order = 0u;
}

bool qihse_memory_migration_scheduler_score(
    qihse_memory_buffer_t* buffer,
    int target_device,
    qihse_memory_type_t target_type,
    const qihse_memory_migration_scheduler_config_t* config,
    qihse_memory_migration_task_t* out_task
)
{
    qihse_memory_migration_scheduler_config_t effective;
    qihse_memory_migration_plan_t plan;
    double residency_component;
    double access_component;
    double coherence_component;
    double target_component;
    double policy_component;
    double score;

    if (!buffer || !out_task || !buffer->is_migratable) {
        return false;
    }

    if (buffer->mem_type == target_type && buffer->preferred_device == target_device) {
        return false;
    }

    if (!qihse_memory_migration_plan(buffer, target_device, target_type, &plan)) {
        return false;
    }

    if (plan.kind == QIHSE_MEMORY_MIGRATION_REJECT) {
        return false;
    }

    effective = qihse_scheduler_effective_config(config);

    residency_component = effective.residency_weight *
        qihse_scheduler_clamp(buffer->residency_score, 0.0, 1.0);
    access_component = effective.access_weight *
        qihse_scheduler_access_score(buffer->access_count, effective.hot_access_threshold);
    coherence_component = effective.coherence_weight *
        qihse_scheduler_coherence_score(buffer, &plan);
    target_component = effective.target_weight *
        qihse_scheduler_target_score(target_type);
    policy_component = effective.policy_weight *
        qihse_scheduler_policy_score(&plan);

    score = residency_component + access_component + coherence_component +
        target_component + policy_component;

    if (score < effective.minimum_score) {
        return false;
    }

    memset(out_task, 0, sizeof(*out_task));
    out_task->buffer = buffer;
    out_task->target_device = target_device;
    out_task->target_type = target_type;
    out_task->plan = plan;
    out_task->score = score;
    out_task->order = 0u;

    return true;
}

bool qihse_memory_migration_scheduler_enqueue(
    qihse_memory_migration_scheduler_t* scheduler,
    const qihse_memory_migration_candidate_t* candidate
)
{
    qihse_memory_migration_task_t task;
    size_t insert_at;
    size_t i;

    if (!scheduler || !candidate || !scheduler->tasks || scheduler->count >= scheduler->capacity) {
        return false;
    }

    if (!qihse_memory_migration_scheduler_score(
            candidate->buffer,
            candidate->target_device,
            candidate->target_type,
            &scheduler->config,
            &task)) {
        return false;
    }

    task.order = scheduler->next_order++;
    insert_at = scheduler->count;

    for (i = 0u; i < scheduler->count; ++i) {
        if (qihse_scheduler_task_precedes(&task, &scheduler->tasks[i])) {
            insert_at = i;
            break;
        }
    }

    for (i = scheduler->count; i > insert_at; --i) {
        scheduler->tasks[i] = scheduler->tasks[i - 1u];
    }

    scheduler->tasks[insert_at] = task;
    scheduler->count++;

    return true;
}

size_t qihse_memory_migration_scheduler_enqueue_many(
    qihse_memory_migration_scheduler_t* scheduler,
    const qihse_memory_migration_candidate_t* candidates,
    size_t candidate_count
)
{
    size_t enqueued;
    size_t i;

    if (!scheduler || (!candidates && candidate_count > 0u)) {
        return 0u;
    }

    enqueued = 0u;
    for (i = 0u; i < candidate_count; ++i) {
        if (qihse_memory_migration_scheduler_enqueue(scheduler, &candidates[i])) {
            enqueued++;
        }
    }

    return enqueued;
}

const qihse_memory_migration_task_t* qihse_memory_migration_scheduler_peek(
    const qihse_memory_migration_scheduler_t* scheduler
)
{
    if (!scheduler || scheduler->count == 0u || !scheduler->tasks) {
        return 0;
    }

    return &scheduler->tasks[0];
}

bool qihse_memory_migration_scheduler_pop(
    qihse_memory_migration_scheduler_t* scheduler,
    qihse_memory_migration_task_t* out_task
)
{
    size_t i;

    if (!scheduler || scheduler->count == 0u || !scheduler->tasks) {
        return false;
    }

    if (out_task) {
        *out_task = scheduler->tasks[0];
    }

    for (i = 1u; i < scheduler->count; ++i) {
        scheduler->tasks[i - 1u] = scheduler->tasks[i];
    }

    scheduler->count--;
    return true;
}

size_t qihse_memory_migration_scheduler_run(
    qihse_memory_manager_t manager,
    qihse_memory_migration_scheduler_t* scheduler,
    size_t max_tasks
) {
    size_t executed;
    size_t processed;
    size_t limit;
    qihse_memory_migration_task_t task;
    qihse_memory_migration_candidate_t requeue_candidate;

    if (!manager || !scheduler || scheduler->tasks == NULL || scheduler->count == 0u) {
        return 0u;
    }

    limit = max_tasks;
    if (limit == 0u || limit > scheduler->count) {
        limit = scheduler->count;
    }

    processed = 0u;
    executed = 0u;
    while (processed < limit && scheduler->count > 0u) {
        if (!qihse_memory_migration_scheduler_pop(scheduler, &task)) {
            break;
        }

        processed++;

        if (task.buffer == NULL) {
            continue;
        }

        if (qihse_memory_migrate(
                manager,
                task.buffer,
                task.target_device,
                task.target_type)) {
            executed++;
            continue;
        }

        requeue_candidate.buffer = task.buffer;
        requeue_candidate.target_device = task.target_device;
        requeue_candidate.target_type = task.target_type;
        (void)qihse_memory_migration_scheduler_enqueue(scheduler, &requeue_candidate);
    }

    return executed;
}
