/*
 * QIHSE - Memory Migration Policy Helpers Implementation
 */

#include "../include/qihse_memory_migration_policy.h"
#include "../include/qihse_memory_allocation_policy.h"

#include <stdio.h>
#include <string.h>

static void qihse_memory_migration_format_reason(
    qihse_memory_migration_plan_t* plan,
    const char* reason
) {
    if (!plan) {
        return;
    }

    (void)snprintf(plan->reason,
                   sizeof(plan->reason),
                   "%s source=%s target=%s source_device=%d target_device=%d",
                   reason ? reason : "migration",
                   qihse_memory_type_string(plan->source_type),
                   qihse_memory_type_string(plan->target_type),
                   plan->source_device,
                   plan->target_device);
}

bool qihse_memory_migration_type_is_host_coherent(
    qihse_memory_type_t mem_type
) {
    switch (mem_type) {
        case QIHSE_MEM_HOST:
        case QIHSE_MEM_PINNED:
        case QIHSE_MEM_UNIFIED:
        case QIHSE_MEM_HMA_SUPERPOSITION:
        case QIHSE_MEM_HMA_INTERACTION:
        case QIHSE_MEM_HMA_ENTANGLEMENT:
        case QIHSE_MEM_ANCHOR_TABLE:
        case QIHSE_MEM_ANCHOR_WORKSPACE:
            return true;
        case QIHSE_MEM_DEVICE:
        default:
            return false;
    }
}

bool qihse_memory_migration_is_zero_copy(
    qihse_memory_type_t source_type,
    qihse_memory_type_t target_type
) {
    if (!qihse_memory_allocation_policy_is_valid_type(source_type) ||
        !qihse_memory_allocation_policy_is_valid_type(target_type)) {
        return false;
    }

    if (source_type == target_type) {
        return true;
    }

    return qihse_memory_migration_type_is_host_coherent(source_type) &&
        qihse_memory_migration_type_is_host_coherent(target_type);
}

bool qihse_memory_migration_plan(
    const qihse_memory_buffer_t* buffer,
    int target_device,
    qihse_memory_type_t target_type,
    qihse_memory_migration_plan_t* plan
) {
    if (!buffer || !plan ||
        !qihse_memory_allocation_policy_is_valid_type(target_type)) {
        return false;
    }

    memset(plan, 0, sizeof(*plan));
    plan->source_type = buffer->mem_type;
    plan->target_type = target_type;
    plan->source_device = buffer->preferred_device;
    plan->target_device = target_device;
    plan->preserves_coherence = true;

    if (!buffer->is_migratable) {
        plan->kind = QIHSE_MEMORY_MIGRATION_REJECT;
        plan->preserves_coherence = false;
        qihse_memory_migration_format_reason(plan, "rejected-not-migratable");
        return true;
    }

    if (!qihse_memory_allocation_policy_is_valid_type(buffer->mem_type)) {
        plan->kind = QIHSE_MEMORY_MIGRATION_REJECT;
        plan->preserves_coherence = false;
        qihse_memory_migration_format_reason(plan, "rejected-invalid-source");
        return true;
    }

    if (qihse_memory_migration_is_zero_copy(buffer->mem_type, target_type)) {
        plan->kind = QIHSE_MEMORY_MIGRATION_ZERO_COPY;
        qihse_memory_migration_format_reason(plan, "zero-copy");
        return true;
    }

    plan->kind = QIHSE_MEMORY_MIGRATION_COPY_REQUIRED;
    plan->preserves_coherence = false;
    qihse_memory_migration_format_reason(plan, "copy-required");
    return true;
}

const char* qihse_memory_migration_kind_name(
    qihse_memory_migration_kind_t kind
) {
    switch (kind) {
        case QIHSE_MEMORY_MIGRATION_REJECT:
            return "reject";
        case QIHSE_MEMORY_MIGRATION_ZERO_COPY:
            return "zero-copy";
        case QIHSE_MEMORY_MIGRATION_COPY_REQUIRED:
            return "copy-required";
        default:
            return "unknown";
    }
}
