#include "qihse_rate_limit.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>

// A single tracked IP entry.
typedef struct qihse_rl_entry {
    uint32_t source_ip;             // 0 means empty slot
    uint32_t attempt_count;         // number of attempts within the window
    time_t   first_attempt_ts;      // timestamp of the first attempt in the window
    struct qihse_rl_entry* next;    // chaining pointer for collision resolution
} qihse_rl_entry_t;

struct qihse_rate_limiter {
    size_t              max_entries;     // number of hash buckets
    uint32_t            max_attempts;    // attempts allowed per window
    uint32_t            window_seconds;  // window length in seconds
    qihse_rl_entry_t**  buckets;         // bucket array (chaining)
    pthread_mutex_t     mutex;
};

// FNV-1a 32-bit hash for the source IP. Simple, fast, good distribution.
static size_t qihse_rl_hash(uint32_t source_ip, size_t max_entries) {
    uint32_t h = 2166136261u;
    h ^= (source_ip      & 0xFF); h *= 16777619u;
    h ^= ((source_ip >> 8)  & 0xFF); h *= 16777619u;
    h ^= ((source_ip >> 16) & 0xFF); h *= 16777619u;
    h ^= ((source_ip >> 24) & 0xFF); h *= 16777619u;
    return (size_t)(h % max_entries);
}

qihse_rate_limiter_t* qihse_rate_limiter_create(size_t max_entries,
                                                uint32_t max_attempts,
                                                uint32_t window_seconds) {
    if (max_entries == 0 || max_attempts == 0 || window_seconds == 0) {
        return NULL;
    }

    qihse_rate_limiter_t* rl = calloc(1, sizeof(*rl));
    if (!rl) {
        return NULL;
    }

    rl->buckets = calloc(max_entries, sizeof(qihse_rl_entry_t*));
    if (!rl->buckets) {
        free(rl);
        return NULL;
    }

    rl->max_entries    = max_entries;
    rl->max_attempts   = max_attempts;
    rl->window_seconds = window_seconds;

    if (pthread_mutex_init(&rl->mutex, NULL) != 0) {
        free(rl->buckets);
        free(rl);
        return NULL;
    }

    return rl;
}

void qihse_rate_limiter_destroy(qihse_rate_limiter_t* rl) {
    if (!rl) return;

    pthread_mutex_lock(&rl->mutex);
    for (size_t i = 0; i < rl->max_entries; i++) {
        qihse_rl_entry_t* e = rl->buckets[i];
        while (e) {
            qihse_rl_entry_t* next = e->next;
            free(e);
            e = next;
        }
        rl->buckets[i] = NULL;
    }
    free(rl->buckets);
    rl->buckets = NULL;
    pthread_mutex_unlock(&rl->mutex);

    pthread_mutex_destroy(&rl->mutex);
    free(rl);
}

bool qihse_rate_limiter_check(qihse_rate_limiter_t* rl, uint32_t source_ip) {
    if (!rl) return true; // fail-open if no limiter configured

    time_t now = time(NULL);
    bool allowed = true;

    pthread_mutex_lock(&rl->mutex);

    size_t idx = qihse_rl_hash(source_ip, rl->max_entries);
    qihse_rl_entry_t* e = rl->buckets[idx];
    while (e) {
        if (e->source_ip == source_ip) {
            break;
        }
        e = e->next;
    }

    if (!e) {
        // No existing entry: create one with a single attempt.
        e = calloc(1, sizeof(*e));
        if (e) {
            e->source_ip        = source_ip;
            e->attempt_count    = 1;
            e->first_attempt_ts = now;
            e->next             = rl->buckets[idx];
            rl->buckets[idx]    = e;
            allowed = true; // first attempt is always allowed
        } else {
            // allocation failure: fail-open
            allowed = true;
        }
    } else {
        // Existing entry: check window expiry.
        if (now - e->first_attempt_ts >= (time_t)rl->window_seconds) {
            // Window expired: reset and count this as the first attempt.
            e->attempt_count    = 1;
            e->first_attempt_ts = now;
            allowed = true;
        } else {
            // Within the window.
            if (e->attempt_count >= rl->max_attempts) {
                // Already at/over the limit: deny without incrementing further.
                allowed = false;
            } else {
                e->attempt_count++;
                // If this attempt reaches the limit, it is the last allowed one.
                allowed = true;
            }
        }
    }

    pthread_mutex_unlock(&rl->mutex);
    return allowed;
}

void qihse_rate_limiter_reset(qihse_rate_limiter_t* rl, uint32_t source_ip) {
    if (!rl) return;

    pthread_mutex_lock(&rl->mutex);

    size_t idx = qihse_rl_hash(source_ip, rl->max_entries);
    qihse_rl_entry_t* e = rl->buckets[idx];
    while (e) {
        if (e->source_ip == source_ip) {
            // Reset the counter so subsequent attempts start fresh.
            e->attempt_count    = 0;
            e->first_attempt_ts = 0;
            break;
        }
        e = e->next;
    }

    pthread_mutex_unlock(&rl->mutex);
}

void qihse_rate_limiter_cleanup(qihse_rate_limiter_t* rl) {
    if (!rl) return;

    time_t now = time(NULL);
    time_t stale_threshold = (time_t)(rl->window_seconds * 2);

    pthread_mutex_lock(&rl->mutex);

    for (size_t i = 0; i < rl->max_entries; i++) {
        qihse_rl_entry_t* prev = NULL;
        qihse_rl_entry_t* e = rl->buckets[i];
        while (e) {
            // An entry is stale if its first attempt is older than 2x window.
            // Entries with a zero timestamp (reset) are also removable.
            if (e->first_attempt_ts == 0 ||
                (now - e->first_attempt_ts) >= stale_threshold) {
                qihse_rl_entry_t* stale = e;
                if (prev) {
                    prev->next = e->next;
                } else {
                    rl->buckets[i] = e->next;
                }
                e = e->next;
                free(stale);
            } else {
                prev = e;
                e = e->next;
            }
        }
    }

    pthread_mutex_unlock(&rl->mutex);
}
