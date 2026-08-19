#include "qihse_system_guard.h"
#include "qihse_platform.h"
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifndef _WIN32
#include <time.h>
#include <pthread.h>
#else
#include <windows.h>
#endif

static size_t g_system_ram_bytes = 0;
static int g_cpu_cores = 0;
static size_t g_memory_bandwidth_estimate_bps = 0;
static bool g_guard_initialized = false;

void qihse_system_guard_profile(void) {
    if (g_guard_initialized) return;

    #ifndef _WIN32
    long pages = sysconf(_SC_PHYS_PAGES);
#else
    long pages = 1024;
#endif
    #ifndef _WIN32
    long page_size = sysconf(_SC_PAGESIZE);
#else
    long page_size = 4096;
#endif
    if (pages != -1 && page_size != -1) {
        g_system_ram_bytes = (size_t)pages * (size_t)page_size;
    } else {
        g_system_ram_bytes = 16ULL * 1024 * 1024 * 1024; // Fallback 16GB
    }

    #ifndef _WIN32
    g_cpu_cores = sysconf(_SC_NPROCESSORS_ONLN);
#else
    g_cpu_cores = 4;
#endif
    if (g_cpu_cores <= 0) g_cpu_cores = 4;

    // Estimate memory bandwidth: ~15 GB/s baseline + 5 GB/s per core, cap at ~68 GB/s for DDR4
    g_memory_bandwidth_estimate_bps = 15ULL * 1024 * 1024 * 1024 + ((size_t)g_cpu_cores * 5ULL * 1024 * 1024 * 1024);
    if (g_memory_bandwidth_estimate_bps > 100ULL * 1024 * 1024 * 1024) {
        g_memory_bandwidth_estimate_bps = 100ULL * 1024 * 1024 * 1024; // Capped max estimate
    }
    
    g_guard_initialized = true;
    
    fprintf(stderr,
            "[QIHSE System Guard] Profiled hardware on startup: %d cores, "
            "%zu MB physical RAM. DDR Bandwidth Est: %zu MB/s\n",
            g_cpu_cores, g_system_ram_bytes / (1024 * 1024),
            g_memory_bandwidth_estimate_bps / (1024 * 1024));
}

bool qihse_system_guard_check_operation(size_t required_bytes, bool is_brute_force) {
    if (!g_guard_initialized) qihse_system_guard_profile();

    bool safe = true;

    // 1. OOM Guard: Don't allow dataset sizes exceeding 85% of physical RAM
    size_t max_safe_ram = (size_t)(g_system_ram_bytes * 0.85);
    if (required_bytes > max_safe_ram) {
        fprintf(stderr, "\n[QIHSE GUARD EXCEPTION] ABORTING: Requested operation requires %zu MB, but system only has %zu MB safe RAM available. This will trigger massive OOM kills.\n\n", required_bytes / (1024*1024), max_safe_ram / (1024*1024));
        safe = false;
    }

    // 2. Bandwidth Guard: Massive brute force floats
    if (is_brute_force) {
        // If they try to brute force over an amount of data that takes more than 1 second to read from RAM completely
        if (required_bytes > g_memory_bandwidth_estimate_bps / 2) {
            fprintf(stderr, "\n[QIHSE GUARD WARNING] EXTREME BANDWIDTH PRESSURE DETECTED:\n");
            fprintf(stderr, "  -> You are requesting an exact float32 scan over %zu MB of data.\n", required_bytes / (1024*1024));
            fprintf(stderr, "  -> Your specific hardware memory controller theoretical max is %zu MB/s.\n", g_memory_bandwidth_estimate_bps / (1024*1024));
            fprintf(stderr, "  -> ACTION REQUIRED: This query will saturate 100%% of your memory bus and cause severe OS-level lagging. Enable 'qtri' or 'qmag' candidate pruning to prevent this.\n\n");
            safe = false; // Actually reject it as per "a guard that warns on the sort of shit thatd nuke your specific system"
        }
    }

    return safe;
}

/* ------------------------------------------------------------------ */
/* Bus-saturation sliding-window throttling                            */
/* ------------------------------------------------------------------ */

#define QIHSE_GUARD_WINDOW_BUCKETS 64u

struct qihse_system_guard_window {
    /* Ring of time buckets, each covering window_ms / BUCKETS duration.
     * The bucket at index (head) is the oldest; head advances as time
     * progresses.  Each bucket stores a timestamp and a byte count. */
    uint64_t bucket_time_ms[QIHSE_GUARD_WINDOW_BUCKETS];
    uint64_t bucket_bytes[QIHSE_GUARD_WINDOW_BUCKETS];
    uint32_t head;
    uint64_t bucket_duration_ms;
    uint64_t window_ms;
    uint64_t threshold_bps;
    pthread_mutex_t lock;
};

static uint64_t qihse_guard_now_ms(void) {
#ifndef _WIN32
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
#else
    return (uint64_t)GetTickCount64();
#endif
}

qihse_system_guard_window_t* qihse_system_guard_window_create(uint64_t window_ms,
                                                              double saturation_fraction) {
    if (window_ms == 0) window_ms = 1000u;
    if (saturation_fraction <= 0.0 || saturation_fraction > 1.0) saturation_fraction = 0.8;
    qihse_system_guard_window_t* w = (qihse_system_guard_window_t*)calloc(1, sizeof(*w));
    if (!w) return NULL;
    w->window_ms = window_ms;
    w->bucket_duration_ms = window_ms / QIHSE_GUARD_WINDOW_BUCKETS;
    if (w->bucket_duration_ms == 0) w->bucket_duration_ms = 1;
    if (!g_guard_initialized) qihse_system_guard_profile();
    w->threshold_bps = (uint64_t)((double)g_memory_bandwidth_estimate_bps * saturation_fraction);
    if (pthread_mutex_init(&w->lock, NULL) != 0) {
        free(w);
        return NULL;
    }
    return w;
}

void qihse_system_guard_window_destroy(qihse_system_guard_window_t* w) {
    if (!w) return;
    pthread_mutex_destroy(&w->lock);
    free(w);
}

static void qihse_guard_advance_locked(qihse_system_guard_window_t* w, uint64_t now_ms) {
    /* Expire buckets that are older than the window */
    uint64_t cutoff = (now_ms > w->window_ms) ? now_ms - w->window_ms : 0;
    for (uint32_t i = 0; i < QIHSE_GUARD_WINDOW_BUCKETS; i++) {
        uint32_t idx = (w->head + i) % QIHSE_GUARD_WINDOW_BUCKETS;
        if (w->bucket_time_ms[idx] < cutoff && w->bucket_time_ms[idx] != 0) {
            w->bucket_bytes[idx] = 0;
            w->bucket_time_ms[idx] = 0;
        }
    }
}

void qihse_system_guard_window_record(qihse_system_guard_window_t* w, size_t bytes) {
    if (!w || bytes == 0) return;
    uint64_t now = qihse_guard_now_ms();
    pthread_mutex_lock(&w->lock);
    qihse_guard_advance_locked(w, now);
    /* Find or create the current bucket */
    uint64_t bucket_start = now - (now % w->bucket_duration_ms);
    uint32_t target = QIHSE_GUARD_WINDOW_BUCKETS;
    for (uint32_t i = 0; i < QIHSE_GUARD_WINDOW_BUCKETS; i++) {
        uint32_t idx = (w->head + i) % QIHSE_GUARD_WINDOW_BUCKETS;
        if (w->bucket_time_ms[idx] == bucket_start) {
            target = idx;
            break;
        }
    }
    if (target == QIHSE_GUARD_WINDOW_BUCKETS) {
        /* Use the head (oldest) bucket for the new entry */
        target = w->head;
        w->bucket_time_ms[target] = bucket_start;
        w->bucket_bytes[target] = 0;
        w->head = (w->head + 1u) % QIHSE_GUARD_WINDOW_BUCKETS;
    }
    w->bucket_bytes[target] += (uint64_t)bytes;
    pthread_mutex_unlock(&w->lock);
}

uint64_t qihse_system_guard_window_bps(const qihse_system_guard_window_t* w) {
    if (!w) return 0;
    uint64_t now = qihse_guard_now_ms();
    pthread_mutex_lock((pthread_mutex_t*)&w->lock);
    qihse_guard_advance_locked((qihse_system_guard_window_t*)w, now);
    uint64_t total = 0;
    for (uint32_t i = 0; i < QIHSE_GUARD_WINDOW_BUCKETS; i++) {
        total += w->bucket_bytes[i];
    }
    pthread_mutex_unlock((pthread_mutex_t*)&w->lock);
    /* Convert window total to bytes/second */
    if (w->window_ms == 0) return 0;
    return total * 1000u / w->window_ms;
}

bool qihse_system_guard_window_safe(const qihse_system_guard_window_t* w) {
    if (!w) return true;
    return qihse_system_guard_window_bps(w) < w->threshold_bps;
}

uint64_t qihse_system_guard_window_threshold_bps(const qihse_system_guard_window_t* w) {
    return w ? w->threshold_bps : 0;
}
