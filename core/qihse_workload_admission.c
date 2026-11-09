#include "qihse_workload_admission.h"

#include <limits.h>
#include <pthread.h>
#include <stdlib.h>

#define QIHSE_WORKLOAD_MAX_SLOTS 1024u

typedef struct {
    uint64_t id;
    uint32_t tenant;
    qihse_workload_class_t workload;
    size_t reserved_bytes;
} admission_slot_t;

struct qihse_workload_admission {
    pthread_mutex_t mutex;
    admission_slot_t* slots;
    size_t total_limit;
    size_t heavy_limit;
    size_t tenant_limit;
    size_t active;
    size_t heavy_active;
    bool memory_enabled;
    size_t total_bytes_limit;
    size_t heavy_bytes_limit;
    size_t tenant_bytes_limit;
    size_t reserved_bytes;
    size_t heavy_reserved_bytes;
    uint64_t next_id;
};

static qihse_workload_admission_t* admission_create(
    size_t total_limit, size_t heavy_limit, size_t tenant_limit,
    bool memory_enabled, size_t total_bytes_limit,
    size_t heavy_bytes_limit, size_t tenant_bytes_limit) {
    if (total_limit < 2 || total_limit > QIHSE_WORKLOAD_MAX_SLOTS ||
        heavy_limit == 0 || heavy_limit >= total_limit ||
        tenant_limit == 0 || tenant_limit > total_limit ||
        (memory_enabled && (total_bytes_limit < 2 ||
            heavy_bytes_limit == 0 || heavy_bytes_limit >= total_bytes_limit ||
            tenant_bytes_limit == 0 || tenant_bytes_limit > total_bytes_limit)))
        return NULL;
    qihse_workload_admission_t* gate = calloc(1, sizeof(*gate));
    if (!gate) return NULL;
    gate->slots = calloc(total_limit, sizeof(*gate->slots));
    if (!gate->slots || pthread_mutex_init(&gate->mutex, NULL) != 0) {
        free(gate->slots);
        free(gate);
        return NULL;
    }
    gate->total_limit = total_limit;
    gate->heavy_limit = heavy_limit;
    gate->tenant_limit = tenant_limit;
    gate->memory_enabled = memory_enabled;
    gate->total_bytes_limit = total_bytes_limit;
    gate->heavy_bytes_limit = heavy_bytes_limit;
    gate->tenant_bytes_limit = tenant_bytes_limit;
    return gate;
}

qihse_workload_admission_t* qihse_workload_admission_create(
    size_t total_limit, size_t heavy_limit, size_t tenant_limit) {
    return admission_create(total_limit, heavy_limit, tenant_limit,
                            false, 0, 0, 0);
}

qihse_workload_admission_t* qihse_workload_admission_create_with_memory(
    size_t total_limit, size_t heavy_limit, size_t tenant_limit,
    size_t total_bytes_limit, size_t heavy_bytes_limit,
    size_t tenant_bytes_limit) {
    return admission_create(total_limit, heavy_limit, tenant_limit,
                            true, total_bytes_limit, heavy_bytes_limit,
                            tenant_bytes_limit);
}

bool qihse_workload_admission_destroy(qihse_workload_admission_t* gate) {
    if (!gate) return false;
    pthread_mutex_lock(&gate->mutex);
    if (gate->active) {
        pthread_mutex_unlock(&gate->mutex);
        return false;
    }
    pthread_mutex_unlock(&gate->mutex);
    pthread_mutex_destroy(&gate->mutex);
    free(gate->slots);
    free(gate);
    return true;
}

static qihse_admission_result_t admission_try_acquire(
    qihse_workload_admission_t* gate, qihse_user_t* user,
    qihse_workload_class_t workload, size_t bytes, bool memory_call,
    qihse_workload_lease_t* lease) {
    if (!gate || !lease || lease->owner || lease->id ||
        memory_call != gate->memory_enabled || (memory_call && !bytes) ||
        (workload != QIHSE_WORKLOAD_FOREGROUND && workload != QIHSE_WORKLOAD_HEAVY))
        return QIHSE_ADMISSION_INVALID;
    bool active = false;
    uint32_t tenant = QIHSE_TENANT_INVALID;
    qihse_auth_user_active_and_tenant(user, &active, &tenant);
    if (!active || tenant == QIHSE_TENANT_INVALID) return QIHSE_ADMISSION_INVALID;

    pthread_mutex_lock(&gate->mutex);
    size_t tenant_active = 0;
    size_t tenant_reserved_bytes = 0;
    size_t empty = gate->total_limit;
    for (size_t i = 0; i < gate->total_limit; i++) {
        if (!gate->slots[i].id) empty = i;
        else if (gate->slots[i].tenant == tenant) {
            tenant_active++;
            if (gate->slots[i].reserved_bytes > SIZE_MAX - tenant_reserved_bytes) {
                pthread_mutex_unlock(&gate->mutex);
                return QIHSE_ADMISSION_BUSY;
            }
            tenant_reserved_bytes += gate->slots[i].reserved_bytes;
        }
    }
    qihse_admission_result_t result = QIHSE_ADMISSION_BUSY;
    if (gate->next_id == UINT64_MAX) result = QIHSE_ADMISSION_INVALID;
    else if (gate->reserved_bytes > gate->total_bytes_limit ||
             gate->heavy_reserved_bytes > gate->heavy_bytes_limit ||
             tenant_reserved_bytes > gate->tenant_bytes_limit)
        result = QIHSE_ADMISSION_INVALID;
    else if (empty < gate->total_limit && gate->active < gate->total_limit &&
             tenant_active < gate->tenant_limit &&
             (workload != QIHSE_WORKLOAD_HEAVY || gate->heavy_active < gate->heavy_limit) &&
             (!memory_call ||
              (bytes <= gate->total_bytes_limit - gate->reserved_bytes &&
               bytes <= gate->tenant_bytes_limit - tenant_reserved_bytes &&
               (workload != QIHSE_WORKLOAD_HEAVY ||
                bytes <= gate->heavy_bytes_limit - gate->heavy_reserved_bytes)))) {
        admission_slot_t* slot = &gate->slots[empty];
        slot->id = ++gate->next_id;
        slot->tenant = tenant;
        slot->workload = workload;
        slot->reserved_bytes = bytes;
        gate->active++;
        if (workload == QIHSE_WORKLOAD_HEAVY) gate->heavy_active++;
        gate->reserved_bytes += bytes;
        if (workload == QIHSE_WORKLOAD_HEAVY) gate->heavy_reserved_bytes += bytes;
        lease->owner = gate;
        lease->id = slot->id;
        result = QIHSE_ADMISSION_ACQUIRED;
    }
    pthread_mutex_unlock(&gate->mutex);
    return result;
}

qihse_admission_result_t qihse_workload_admission_try_acquire(
    qihse_workload_admission_t* gate, qihse_user_t* user,
    qihse_workload_class_t workload, qihse_workload_lease_t* lease) {
    return admission_try_acquire(gate, user, workload, 0, false, lease);
}

qihse_admission_result_t qihse_workload_admission_try_acquire_bytes(
    qihse_workload_admission_t* gate, qihse_user_t* user,
    qihse_workload_class_t workload, size_t bytes,
    qihse_workload_lease_t* lease) {
    return admission_try_acquire(gate, user, workload, bytes, true, lease);
}

bool qihse_workload_admission_release(qihse_workload_lease_t* lease) {
    if (!lease || !lease->owner || !lease->id) return false;
    qihse_workload_admission_t* gate = lease->owner;
    pthread_mutex_lock(&gate->mutex);
    bool released = false;
    for (size_t i = 0; i < gate->total_limit; i++) {
        admission_slot_t* slot = &gate->slots[i];
        if (slot->id != lease->id) continue;
        if (slot->reserved_bytes > gate->reserved_bytes ||
            (slot->workload == QIHSE_WORKLOAD_HEAVY &&
             slot->reserved_bytes > gate->heavy_reserved_bytes)) break;
        if (slot->workload == QIHSE_WORKLOAD_HEAVY) gate->heavy_active--;
        gate->reserved_bytes -= slot->reserved_bytes;
        if (slot->workload == QIHSE_WORKLOAD_HEAVY)
            gate->heavy_reserved_bytes -= slot->reserved_bytes;
        slot->id = 0;
        slot->reserved_bytes = 0;
        gate->active--;
        released = true;
        break;
    }
    pthread_mutex_unlock(&gate->mutex);
    lease->owner = NULL;
    lease->id = 0;
    return released;
}
