#include "../memory/include/qihse_memory_coherence.h"

#include <assert.h>
#include <string.h>

static void test_coherence_lifecycle(void)
{
    qihse_memory_coherence_record_t record;

    memset(&record, 0, sizeof(record));
    qihse_memory_coherence_init(&record, QIHSE_MEM_HMA_SUPERPOSITION, 0);

    assert(record.version == 1u);
    assert(record.state == QIHSE_MEMORY_COHERENCE_CLEAN);
    assert(qihse_memory_coherence_can_read(&record));
    assert(qihse_memory_coherence_can_write(&record));

    assert(qihse_memory_coherence_mark_read(&record));
    assert(record.active_readers == 1u);
    assert(record.last_read_version == record.version);

    assert(qihse_memory_coherence_mark_write(&record));
    assert(record.version == 2u);
    assert(record.state == QIHSE_MEMORY_COHERENCE_DIRTY);
    assert(!record.shared);

    assert(qihse_memory_coherence_begin_migration(&record));
    assert(record.state == QIHSE_MEMORY_COHERENCE_MIGRATING);
    assert(!qihse_memory_coherence_can_read(&record));

    assert(qihse_memory_coherence_complete_migration(
        &record,
        QIHSE_MEM_HMA_INTERACTION,
        1));
    assert(record.version == 3u);
    assert(record.state == QIHSE_MEMORY_COHERENCE_CLEAN);
    assert(record.resident_type == QIHSE_MEM_HMA_INTERACTION);
    assert(record.owner_device == 1);
    assert(record.shared);

    assert(qihse_memory_coherence_invalidate(&record));
    assert(record.state == QIHSE_MEMORY_COHERENCE_INVALID);
    assert(!qihse_memory_coherence_can_write(&record));
}

static void test_buffer_coherence_bridge(void)
{
    qihse_memory_buffer_t buffer;
    qihse_memory_coherence_record_t record;

    memset(&buffer, 0, sizeof(buffer));
    buffer.mem_type = QIHSE_MEM_HMA_SUPERPOSITION;
    buffer.preferred_device = 0;

    assert(qihse_memory_coherence_init_buffer(&buffer));
    assert(buffer.coherence_version == 1u);
    assert(buffer.coherence_state == QIHSE_MEMORY_COHERENCE_CLEAN);
    assert(buffer.coherence_shared);

    assert(qihse_memory_coherence_load_buffer(&buffer, &record));
    assert(qihse_memory_coherence_mark_write(&record));
    assert(qihse_memory_coherence_apply_buffer(&buffer, &record));

    assert(buffer.coherence_version == 2u);
    assert(buffer.coherence_state == QIHSE_MEMORY_COHERENCE_DIRTY);
    assert(!buffer.coherence_shared);
}

int main(void)
{
    test_coherence_lifecycle();
    test_buffer_coherence_bridge();
    return 0;
}
