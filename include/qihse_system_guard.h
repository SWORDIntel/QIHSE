#ifndef QIHSE_SYSTEM_GUARD_H
#define QIHSE_SYSTEM_GUARD_H

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

void qihse_system_guard_profile(void);
bool qihse_system_guard_check_operation(size_t required_bytes, bool is_brute_force);

/*
 * Bus-saturation sliding-window throttling.
 *
 * Tracks the total bytes processed by the cluster engine over a sliding
 * time window.  When the sustained throughput exceeds a configurable
 * fraction of the estimated memory bus bandwidth, the guard rejects
 * DENYOOM commands to prevent memory-controller saturation.
 */

typedef struct qihse_system_guard_window qihse_system_guard_window_t;

qihse_system_guard_window_t* qihse_system_guard_window_create(uint64_t window_ms,
                                                              double saturation_fraction);
void qihse_system_guard_window_destroy(qihse_system_guard_window_t* window);

/* Record that `bytes` were processed by the engine at the current time. */
void qihse_system_guard_window_record(qihse_system_guard_window_t* window, size_t bytes);

/* Returns true if the engine is currently within the safe throughput
 * envelope (i.e. the sliding-window average is below the saturation
 * threshold).  Returns false if the engine should throttle/reject
 * non-essential commands. */
bool qihse_system_guard_window_safe(const qihse_system_guard_window_t* window);

/* Get the current sliding-window throughput in bytes/second. */
uint64_t qihse_system_guard_window_bps(const qihse_system_guard_window_t* window);

/* Get the saturation threshold in bytes/second. */
uint64_t qihse_system_guard_window_threshold_bps(const qihse_system_guard_window_t* window);

#endif // QIHSE_SYSTEM_GUARD_H
