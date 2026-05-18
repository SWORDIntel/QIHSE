/*
 * QIHSE - Memory Coherence Helpers Implementation
 */

#include "../include/qihse_memory_coherence.h"

#include <string.h>

void qihse_memory_coherence_init(
    qihse_memory_coherence_record_t* record,
    qihse_memory_type_t resident_type,
    int owner_device
) {
    if (!record) {
        return;
    }

    memset(record, 0, sizeof(*record));
    record->version = 1u;
    record->last_read_version = 1u;
    record->last_write_version = 1u;
    record->state = QIHSE_MEMORY_COHERENCE_CLEAN;
    record->resident_type = resident_type;
    record->owner_device = owner_device;
    record->shared = true;
}

bool qihse_memory_coherence_init_buffer(
    qihse_memory_buffer_t* buffer
) {
    qihse_memory_coherence_record_t record;

    if (!buffer) {
        return false;
    }

    qihse_memory_coherence_init(&record, buffer->mem_type, buffer->preferred_device);
    return qihse_memory_coherence_apply_buffer(buffer, &record);
}

bool qihse_memory_coherence_load_buffer(
    const qihse_memory_buffer_t* buffer,
    qihse_memory_coherence_record_t* record
) {
    if (!buffer || !record) {
        return false;
    }

    if (buffer->coherence_version == 0u) {
        qihse_memory_coherence_init(record, buffer->mem_type, buffer->preferred_device);
        return true;
    }

    record->version = buffer->coherence_version;
    record->last_read_version = buffer->coherence_last_read_version;
    record->last_write_version = buffer->coherence_last_write_version;
    record->state = (qihse_memory_coherence_state_t)buffer->coherence_state;
    record->resident_type = buffer->mem_type;
    record->owner_device = buffer->preferred_device;
    record->active_readers = 0u;
    record->shared = buffer->coherence_shared;
    return true;
}

bool qihse_memory_coherence_apply_buffer(
    qihse_memory_buffer_t* buffer,
    const qihse_memory_coherence_record_t* record
) {
    if (!buffer || !record) {
        return false;
    }

    buffer->coherence_version = record->version;
    buffer->coherence_last_read_version = record->last_read_version;
    buffer->coherence_last_write_version = record->last_write_version;
    buffer->coherence_state = (uint32_t)record->state;
    buffer->coherence_shared = record->shared;
    buffer->mem_type = record->resident_type;
    buffer->preferred_device = record->owner_device;
    return true;
}

bool qihse_memory_coherence_mark_read(
    qihse_memory_coherence_record_t* record
) {
    if (!qihse_memory_coherence_can_read(record)) {
        return false;
    }

    record->active_readers += 1u;
    record->last_read_version = record->version;
    return true;
}

bool qihse_memory_coherence_mark_write(
    qihse_memory_coherence_record_t* record
) {
    if (!qihse_memory_coherence_can_write(record)) {
        return false;
    }

    record->version += 1u;
    record->last_write_version = record->version;
    record->state = QIHSE_MEMORY_COHERENCE_DIRTY;
    record->shared = false;
    return true;
}

bool qihse_memory_coherence_invalidate(
    qihse_memory_coherence_record_t* record
) {
    if (!record) {
        return false;
    }

    record->state = QIHSE_MEMORY_COHERENCE_INVALID;
    record->active_readers = 0u;
    record->shared = false;
    return true;
}

bool qihse_memory_coherence_begin_migration(
    qihse_memory_coherence_record_t* record
) {
    if (!record || record->state == QIHSE_MEMORY_COHERENCE_INVALID) {
        return false;
    }

    record->state = QIHSE_MEMORY_COHERENCE_MIGRATING;
    record->active_readers = 0u;
    return true;
}

bool qihse_memory_coherence_complete_migration(
    qihse_memory_coherence_record_t* record,
    qihse_memory_type_t resident_type,
    int owner_device
) {
    if (!record || record->state != QIHSE_MEMORY_COHERENCE_MIGRATING) {
        return false;
    }

    record->version += 1u;
    record->last_read_version = record->version;
    record->last_write_version = record->version;
    record->state = QIHSE_MEMORY_COHERENCE_CLEAN;
    record->resident_type = resident_type;
    record->owner_device = owner_device;
    record->shared = true;
    return true;
}

bool qihse_memory_coherence_can_read(
    const qihse_memory_coherence_record_t* record
) {
    return record &&
        record->state != QIHSE_MEMORY_COHERENCE_INVALID &&
        record->state != QIHSE_MEMORY_COHERENCE_MIGRATING;
}

bool qihse_memory_coherence_can_write(
    const qihse_memory_coherence_record_t* record
) {
    return record &&
        record->state != QIHSE_MEMORY_COHERENCE_INVALID &&
        record->state != QIHSE_MEMORY_COHERENCE_MIGRATING;
}

const char* qihse_memory_coherence_state_name(
    qihse_memory_coherence_state_t state
) {
    switch (state) {
        case QIHSE_MEMORY_COHERENCE_INVALID:
            return "invalid";
        case QIHSE_MEMORY_COHERENCE_CLEAN:
            return "clean";
        case QIHSE_MEMORY_COHERENCE_DIRTY:
            return "dirty";
        case QIHSE_MEMORY_COHERENCE_MIGRATING:
            return "migrating";
        default:
            return "unknown";
    }
}
