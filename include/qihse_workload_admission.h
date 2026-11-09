#ifndef QIHSE_WORKLOAD_ADMISSION_H
#define QIHSE_WORKLOAD_ADMISSION_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "qihse_auth.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Admission is a nonblocking, process-local concurrency and optional memory
 * reservation bound. It accounts for caller-declared bytes, not actual RSS.
 * A heavy job cannot consume slots or reserved bytes held for foreground
 * work. CPU, I/O, durable storage, and cross-process quotas are not enforced. */
typedef struct qihse_workload_admission qihse_workload_admission_t;

typedef enum {
    QIHSE_WORKLOAD_FOREGROUND = 1,
    QIHSE_WORKLOAD_HEAVY = 2
} qihse_workload_class_t;

typedef enum {
    QIHSE_ADMISSION_INVALID = 0,
    QIHSE_ADMISSION_ACQUIRED = 1,
    QIHSE_ADMISSION_BUSY = 2
} qihse_admission_result_t;

typedef struct {
    qihse_workload_admission_t* owner;
    uint64_t id;
} qihse_workload_lease_t;

/* Limits are fixed for the lifetime of a gate. heavy_limit < total_limit
 * guarantees at least one foreground slot. tenant_limit applies to tenant 0
 * too, so Operator maintenance cannot bypass the bound. */
qihse_workload_admission_t* qihse_workload_admission_create(
    size_t total_limit, size_t heavy_limit, size_t tenant_limit);

/* Every successful acquisition on this gate must reserve nonzero bytes.
 * heavy_bytes_limit < total_bytes_limit leaves foreground memory capacity. */
qihse_workload_admission_t* qihse_workload_admission_create_with_memory(
    size_t total_limit, size_t heavy_limit, size_t tenant_limit,
    size_t total_bytes_limit, size_t heavy_bytes_limit,
    size_t tenant_bytes_limit);

/* Returns false while leases remain active; callers must quiesce jobs first. */
bool qihse_workload_admission_destroy(qihse_workload_admission_t* gate);

/* The active principal and tenant are resolved from auth state, not caller
 * parameters. `lease` must start zeroed and is filled only on acquisition. */
qihse_admission_result_t qihse_workload_admission_try_acquire(
    qihse_workload_admission_t* gate, qihse_user_t* user,
    qihse_workload_class_t workload, qihse_workload_lease_t* lease);

/* Declared bytes are charged until lease release. Insufficient memory or
 * slots returns BUSY without modifying the lease. Legacy try_acquire is
 * invalid on a memory-configured gate, and this function is invalid on a
 * gate created without memory limits. */
qihse_admission_result_t qihse_workload_admission_try_acquire_bytes(
    qihse_workload_admission_t* gate, qihse_user_t* user,
    qihse_workload_class_t workload, size_t bytes,
    qihse_workload_lease_t* lease);

/* Idempotence protection: a copied or already released lease cannot free a
 * second slot. Returns false for an invalid/stale lease. */
bool qihse_workload_admission_release(qihse_workload_lease_t* lease);

#ifdef __cplusplus
}
#endif

#endif /* QIHSE_WORKLOAD_ADMISSION_H */
