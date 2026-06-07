#include "qihse_system_guard.h"
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>

static size_t g_system_ram_bytes = 0;
static int g_cpu_cores = 0;
static size_t g_memory_bandwidth_estimate_bps = 0;
static bool g_guard_initialized = false;

void qihse_system_guard_profile(void) {
    if (g_guard_initialized) return;

    long pages = sysconf(_SC_PHYS_PAGES);
    long page_size = sysconf(_SC_PAGESIZE);
    if (pages != -1 && page_size != -1) {
        g_system_ram_bytes = (size_t)pages * (size_t)page_size;
    } else {
        g_system_ram_bytes = 16ULL * 1024 * 1024 * 1024; // Fallback 16GB
    }

    g_cpu_cores = sysconf(_SC_NPROCESSORS_ONLN);
    if (g_cpu_cores <= 0) g_cpu_cores = 4;

    // Estimate memory bandwidth: ~15 GB/s baseline + 5 GB/s per core, cap at ~68 GB/s for DDR4
    g_memory_bandwidth_estimate_bps = 15ULL * 1024 * 1024 * 1024 + ((size_t)g_cpu_cores * 5ULL * 1024 * 1024 * 1024);
    if (g_memory_bandwidth_estimate_bps > 100ULL * 1024 * 1024 * 1024) {
        g_memory_bandwidth_estimate_bps = 100ULL * 1024 * 1024 * 1024; // Capped max estimate
    }
    
    g_guard_initialized = true;
    
    printf("[QIHSE System Guard] Profiled hardware on startup: %d cores, %zu MB physical RAM. DDR Bandwidth Est: %zu MB/s\n", 
           g_cpu_cores, g_system_ram_bytes / (1024 * 1024), g_memory_bandwidth_estimate_bps / (1024 * 1024));
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
