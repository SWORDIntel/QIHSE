/*
 * QIHSE - Memory Coherence Helpers
 */

#ifndef QIHSE_MEMORY_COHERENCE_H
#define QIHSE_MEMORY_COHERENCE_H

#include "qihse_memory.h"

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum qihse_memory_coherence_state_e {
    QIHSE_MEMORY_COHERENCE_INVALID = 0,
    QIHSE_MEMORY_COHERENCE_CLEAN = 1,
    QIHSE_MEMORY_COHERENCE_DIRTY = 2,
    QIHSE_MEMORY_COHERENCE_MIGRATING = 3
} qihse_memory_coherence_state_t;

typedef struct qihse_memory_coherence_record_s {
    uint64_t version;
    uint64_t last_read_version;
    uint64_t last_write_version;
    qihse_memory_coherence_state_t state;
    qihse_memory_type_t resident_type;
    int owner_device;
    uint32_t active_readers;
    bool shared;
} qihse_memory_coherence_record_t;

void qihse_memory_coherence_init(
    qihse_memory_coherence_record_t* record,
    qihse_memory_type_t resident_type,
    int owner_device
);

bool qihse_memory_coherence_init_buffer(
    qihse_memory_buffer_t* buffer
);

bool qihse_memory_coherence_load_buffer(
    const qihse_memory_buffer_t* buffer,
    qihse_memory_coherence_record_t* record
);

bool qihse_memory_coherence_apply_buffer(
    qihse_memory_buffer_t* buffer,
    const qihse_memory_coherence_record_t* record
);

bool qihse_memory_coherence_mark_read(
    qihse_memory_coherence_record_t* record
);

bool qihse_memory_coherence_mark_write(
    qihse_memory_coherence_record_t* record
);

bool qihse_memory_coherence_invalidate(
    qihse_memory_coherence_record_t* record
);

bool qihse_memory_coherence_begin_migration(
    qihse_memory_coherence_record_t* record
);

bool qihse_memory_coherence_complete_migration(
    qihse_memory_coherence_record_t* record,
    qihse_memory_type_t resident_type,
    int owner_device
);

bool qihse_memory_coherence_can_read(
    const qihse_memory_coherence_record_t* record
);

bool qihse_memory_coherence_can_write(
    const qihse_memory_coherence_record_t* record
);

const char* qihse_memory_coherence_state_name(
    qihse_memory_coherence_state_t state
);

#ifdef __cplusplus
}
#endif

#endif /* QIHSE_MEMORY_COHERENCE_H */
