#include "../memory/include/qihse_memory_migration_policy.h"

#include <assert.h>
#include <string.h>

static void test_zero_copy_classification(void)
{
    assert(qihse_memory_migration_is_zero_copy(
        QIHSE_MEM_HMA_SUPERPOSITION,
        QIHSE_MEM_HMA_INTERACTION));
    assert(qihse_memory_migration_is_zero_copy(
        QIHSE_MEM_UNIFIED,
        QIHSE_MEM_HOST));
    assert(!qihse_memory_migration_is_zero_copy(
        QIHSE_MEM_DEVICE,
        QIHSE_MEM_HOST));
}

static void test_migration_plan(void)
{
    qihse_memory_buffer_t buffer;
    qihse_memory_migration_plan_t plan;

    memset(&buffer, 0, sizeof(buffer));
    buffer.mem_type = QIHSE_MEM_HMA_SUPERPOSITION;
    buffer.preferred_device = 0;
    buffer.is_migratable = true;

    memset(&plan, 0, sizeof(plan));
    assert(qihse_memory_migration_plan(
        &buffer,
        1,
        QIHSE_MEM_HMA_INTERACTION,
        &plan));
    assert(plan.kind == QIHSE_MEMORY_MIGRATION_ZERO_COPY);
    assert(plan.preserves_coherence);
    assert(plan.source_type == QIHSE_MEM_HMA_SUPERPOSITION);
    assert(plan.target_type == QIHSE_MEM_HMA_INTERACTION);

    buffer.mem_type = QIHSE_MEM_DEVICE;
    memset(&plan, 0, sizeof(plan));
    assert(qihse_memory_migration_plan(
        &buffer,
        0,
        QIHSE_MEM_HOST,
        &plan));
    assert(plan.kind == QIHSE_MEMORY_MIGRATION_COPY_REQUIRED);
    assert(!plan.preserves_coherence);

    buffer.is_migratable = false;
    memset(&plan, 0, sizeof(plan));
    assert(qihse_memory_migration_plan(
        &buffer,
        0,
        QIHSE_MEM_HOST,
        &plan));
    assert(plan.kind == QIHSE_MEMORY_MIGRATION_REJECT);
}

int main(void)
{
    test_zero_copy_classification();
    test_migration_plan();
    return 0;
}
