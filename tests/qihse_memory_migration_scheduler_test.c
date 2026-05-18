/*
 * QIHSE - Memory Migration Scheduler helper tests
 */

#include "../memory/include/qihse_memory_migration_scheduler.h"

#include <assert.h>
#include <string.h>

static qihse_memory_buffer_t make_buffer(
    qihse_memory_type_t source_type,
    int source_device,
    double residency_score,
    uint64_t access_count,
    bool migratable
)
{
    qihse_memory_buffer_t buffer;

    memset(&buffer, 0, sizeof(buffer));
    buffer.mem_type = source_type;
    buffer.preferred_device = source_device;
    buffer.is_migratable = migratable;
    buffer.residency_score = residency_score;
    buffer.access_count = access_count;
    buffer.coherence_version = 8u;
    buffer.coherence_last_read_version = 8u;
    buffer.coherence_last_write_version = 8u;
    buffer.coherence_state = 1u;
    buffer.coherence_shared = true;

    return buffer;
}

static void test_score_rejects_unschedulable_buffers(void)
{
    qihse_memory_buffer_t buffer;
    qihse_memory_migration_task_t task;

    buffer = make_buffer(QIHSE_MEM_HOST, 0, 1.0, 1024u, false);

    assert(!qihse_memory_migration_scheduler_score(
        &buffer,
        1,
        QIHSE_MEM_DEVICE,
        0,
        &task
    ));
}

static void test_queue_orders_by_score_then_fifo(void)
{
    qihse_memory_migration_scheduler_t scheduler;
    qihse_memory_migration_task_t storage[4];
    qihse_memory_migration_candidate_t candidates[3];
    qihse_memory_buffer_t cold;
    qihse_memory_buffer_t hot_a;
    qihse_memory_buffer_t hot_b;
    const qihse_memory_migration_task_t* first;
    qihse_memory_migration_task_t popped;

    cold = make_buffer(QIHSE_MEM_HOST, 0, 0.05, 1u, true);
    hot_a = make_buffer(QIHSE_MEM_HOST, 0, 0.95, 4096u, true);
    hot_b = make_buffer(QIHSE_MEM_HOST, 0, 0.95, 4096u, true);

    assert(qihse_memory_migration_scheduler_init(&scheduler, storage, 4u, 0));

    candidates[0].buffer = &cold;
    candidates[0].target_device = 1;
    candidates[0].target_type = QIHSE_MEM_DEVICE;
    candidates[1].buffer = &hot_a;
    candidates[1].target_device = 1;
    candidates[1].target_type = QIHSE_MEM_DEVICE;
    candidates[2].buffer = &hot_b;
    candidates[2].target_device = 1;
    candidates[2].target_type = QIHSE_MEM_DEVICE;

    assert(qihse_memory_migration_scheduler_enqueue_many(&scheduler, candidates, 3u) == 3u);
    assert(scheduler.count == 3u);

    first = qihse_memory_migration_scheduler_peek(&scheduler);
    assert(first != 0);
    assert(first->buffer == &hot_a);

    assert(qihse_memory_migration_scheduler_pop(&scheduler, &popped));
    assert(popped.buffer == &hot_a);
    assert(qihse_memory_migration_scheduler_pop(&scheduler, &popped));
    assert(popped.buffer == &hot_b);
    assert(qihse_memory_migration_scheduler_pop(&scheduler, &popped));
    assert(popped.buffer == &cold);
    assert(!qihse_memory_migration_scheduler_pop(&scheduler, &popped));
}

static void test_queue_capacity_is_respected(void)
{
    qihse_memory_migration_scheduler_t scheduler;
    qihse_memory_migration_task_t storage[1];
    qihse_memory_migration_candidate_t candidate;
    qihse_memory_buffer_t first;
    qihse_memory_buffer_t second;

    first = make_buffer(QIHSE_MEM_HOST, 0, 0.8, 2048u, true);
    second = make_buffer(QIHSE_MEM_HOST, 0, 0.7, 2048u, true);

    assert(qihse_memory_migration_scheduler_init(&scheduler, storage, 1u, 0));

    candidate.buffer = &first;
    candidate.target_device = 1;
    candidate.target_type = QIHSE_MEM_DEVICE;
    assert(qihse_memory_migration_scheduler_enqueue(&scheduler, &candidate));

    candidate.buffer = &second;
    assert(!qihse_memory_migration_scheduler_enqueue(&scheduler, &candidate));
    assert(scheduler.count == 1u);
}

int main(void)
{
    test_score_rejects_unschedulable_buffers();
    test_queue_orders_by_score_then_fifo();
    test_queue_capacity_is_respected();
    return 0;
}
