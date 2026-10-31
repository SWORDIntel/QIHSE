#ifndef QIHSE_CLUSTER_MAINTENANCE_H
#define QIHSE_CLUSTER_MAINTENANCE_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct qihse_cluster_maintenance qihse_cluster_maintenance_t;
typedef enum {
    QIHSE_MAINT_WRITER_RESP = 0,
    QIHSE_MAINT_WRITER_BGSAVE,
    QIHSE_MAINT_WRITER_BUS_SLOT,
    QIHSE_MAINT_WRITER_FAILOVER,
    QIHSE_MAINT_WRITER_RECLAIM,
    QIHSE_MAINT_WRITER_BUS_GROUP,
    QIHSE_MAINT_WRITER_BUS_FEDERATION,
    QIHSE_MAINT_WRITER_REPLICA,
    QIHSE_MAINT_WRITER_EXPIRY,
    QIHSE_MAINT_WRITER_TASK_WORKER,
    QIHSE_MAINT_WRITER_BRAIN,
    QIHSE_MAINT_WRITER_CLASS_COUNT
} qihse_maintenance_writer_t;
typedef enum {
    QIHSE_MAINT_OPEN = 0,
    QIHSE_MAINT_DRAINING,
    QIHSE_MAINT_HELD,
    QIHSE_MAINT_EXPIRED_HELD
} qihse_maintenance_state_t;
typedef struct {
    qihse_maintenance_state_t state;
    uint64_t generation;
    uint8_t token[32];
    uint64_t lease_expires_ms;
    bool writer_coverage_complete;
    bool writer_registered[QIHSE_MAINT_WRITER_CLASS_COUNT];
    uint64_t active[QIHSE_MAINT_WRITER_CLASS_COUNT];
} qihse_cluster_maintenance_status_t;

qihse_cluster_maintenance_t* qihse_cluster_maintenance_create(void);
void qihse_cluster_maintenance_destroy(qihse_cluster_maintenance_t* gate);
/* Admission is atomic with begin: a successful entry is counted until leave. */
bool qihse_cluster_maintenance_enter(qihse_cluster_maintenance_t* gate,
                                     qihse_maintenance_writer_t writer);
void qihse_cluster_maintenance_leave(qihse_cluster_maintenance_t* gate,
                                     qihse_maintenance_writer_t writer);
/* All writer classes must be explicitly declared instrumented before a hold
 * can be published. Call false for any uninstrumented path; it is sticky. */
bool qihse_cluster_maintenance_register(qihse_cluster_maintenance_t* gate,
                                        qihse_maintenance_writer_t writer,
                                        bool instrumented);
/* Closes admission, drains all registered classes, then creates lease/token.
 * timeout_ms bounds drain; lease_ms is measured from monotonic time. */
bool qihse_cluster_maintenance_begin(qihse_cluster_maintenance_t* gate,
                                     uint64_t timeout_ms, uint64_t lease_ms,
                                     uint64_t* generation, uint8_t token[32]);
/* Trusted internal primitive only. Externally reachable callers MUST first
 * validate the actual active system-Operator context; a caller-supplied bool
 * is not authorization. */
bool qihse_cluster_maintenance_release_trusted(qihse_cluster_maintenance_t* gate,
                                               uint64_t generation,
                                               const uint8_t token[32]);
bool qihse_cluster_maintenance_status(qihse_cluster_maintenance_t* gate,
                                      qihse_cluster_maintenance_status_t* status);
#ifdef __cplusplus
}
#endif
#endif
