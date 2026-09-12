#ifndef QIHSE_QUOTA_H
#define QIHSE_QUOTA_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Per-tenant operation quotas for the session-delivery workload. Fixed-window
 * counters keyed by (tenant_id, quota class). Unlike the auth brute-force
 * rate limiter (which fails open), quota evaluation FAILS CLOSED when the
 * check cannot be performed (allocation failure): a tenant over its quota
 * must never be waved through by an internal error. Classes with no
 * configured policy are unlimited. Tenant 0 (system domain) is never
 * quota-enforced. */

typedef enum {
    QIHSE_QUOTA_BUNDLE_PULL = 0,     /* session-bundle compose/pull per window */
    QIHSE_QUOTA_TELEMETRY_INGEST = 1,/* telemetry record writes per window */
    QIHSE_QUOTA_ANN_QUERY = 2,       /* vector ANN query cost per window */
    QIHSE_QUOTA_KV_WRITE = 3,        /* generic KV writes per window */
    QIHSE_QUOTA_CLASS_COUNT = 4
} qihse_quota_class_t;

typedef struct qihse_quota_table qihse_quota_table_t;

/* Create a quota table with capacity for max_tenants distinct tenant ids.
 * Returns NULL on allocation failure or invalid arguments. */
qihse_quota_table_t* qihse_quota_table_create(size_t max_tenants);

void qihse_quota_table_destroy(qihse_quota_table_t* table);

/* Configure (or reconfigure) a quota class for a tenant. max_ops operations
 * are allowed per window_seconds sliding fixed window; 0 disables the class
 * for that tenant. Returns false on invalid arguments or capacity exhaustion. */
bool qihse_quota_configure(qihse_quota_table_t* table, uint32_t tenant_id,
                           qihse_quota_class_t quota_class,
                           uint32_t max_ops, uint32_t window_seconds);

/* Consume one operation from the tenant's quota class. Returns true when the
 * operation is allowed (counter consumed), false when rate-limited, the class
 * is disabled for the tenant, or the internal state cannot be maintained
 * (fail closed). */
bool qihse_quota_allow(qihse_quota_table_t* table, uint32_t tenant_id,
                       qihse_quota_class_t quota_class);

/* Drop all counters (used by tests and administrative resets). */
void qihse_quota_reset(qihse_quota_table_t* table);

/* Remove per-tenant state older than 2x the largest configured window. */
void qihse_quota_cleanup(qihse_quota_table_t* table);

#ifdef __cplusplus
}
#endif

#endif /* QIHSE_QUOTA_H */
