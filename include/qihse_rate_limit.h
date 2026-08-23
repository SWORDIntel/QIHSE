#ifndef QIHSE_RATE_LIMIT_H
#define QIHSE_RATE_LIMIT_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// Opaque rate limiter handle. Internally backed by a chained hash table
// keyed by source IP, thread-safe via a pthread mutex.
typedef struct qihse_rate_limiter qihse_rate_limiter_t;

// Create a new rate limiter.
//   max_entries     - capacity of the internal hash table (bucket slots).
//   max_attempts    - maximum failed attempts allowed within the window.
//   window_seconds  - sliding window length in seconds.
// Returns NULL on allocation failure or invalid arguments.
qihse_rate_limiter_t* qihse_rate_limiter_create(size_t max_entries,
                                                uint32_t max_attempts,
                                                uint32_t window_seconds);

// Destroy a rate limiter and free all associated resources.
// Passing NULL is a no-op.
void qihse_rate_limiter_destroy(qihse_rate_limiter_t* rl);

// Check whether an authentication attempt from `source_ip` is allowed.
// Each call increments the per-IP attempt counter. Returns:
//   true  - attempt is allowed (counter incremented).
//   false - attempt is rate-limited (counter already at/over the limit
//           and the window has not yet expired).
// When the window has expired since the first attempt, the counter is
// reset before evaluating the new attempt.
bool qihse_rate_limiter_check(qihse_rate_limiter_t* rl, uint32_t source_ip);

// Reset the attempt counter for `source_ip` (call on successful auth).
void qihse_rate_limiter_reset(qihse_rate_limiter_t* rl, uint32_t source_ip);

// Remove all entries older than 2x the configured window. Safe to call
// periodically from a maintenance thread.
void qihse_rate_limiter_cleanup(qihse_rate_limiter_t* rl);

#ifdef __cplusplus
}
#endif

#endif // QIHSE_RATE_LIMIT_H
