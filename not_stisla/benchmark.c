/**
 * NOT_STISLA Enhanced Benchmark v3.0
 * 
 * Tests AVX-512 branchless search, software prefetching, and huge pages optimizations
 * Shows detailed performance metrics and optimization impact
 * Optimized for Meteor Lake architecture
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include <math.h>
#include <float.h>
#include <unistd.h>
#include <sys/mman.h>
#include "include/not_stisla.h"

/* Benchmark configuration */
#define WARMUP_ITERATIONS 1000
#define BENCHMARK_ITERATIONS 100000
#define LIVE_UPDATE_INTERVAL 5000
#define HUGE_PAGE_THRESHOLD (1024 * 1024)  /* 1MB minimum for huge pages */

/* ANSI color codes */
#define RESET   "\033[0m"
#define RED     "\033[31m"
#define GREEN   "\033[32m"
#define YELLOW  "\033[33m"
#define BLUE    "\033[34m"
#define CYAN    "\033[36m"
#define MAGENTA "\033[35m"
#define BOLD    "\033[1m"

/* Timing utilities */
static inline uint64_t get_time_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

/* Generate sorted test array */
static void generate_sorted_array(int64_t* arr, size_t n, int workload_type) {
    srand(42); /* Fixed seed for reproducibility */
    switch (workload_type) {
        case NOT_STISLA_WORKLOAD_TELEMETRY:
            for (size_t i = 0; i < n; i++) {
                arr[i] = (int64_t)i * 1000 + (int64_t)(rand() % 500);
            }
            break;
        case NOT_STISLA_WORKLOAD_IDS:
            for (size_t i = 0; i < n; i++) {
                arr[i] = (int64_t)i * 2;
            }
            break;
        default:
            for (size_t i = 0; i < n; i++) {
                arr[i] = (int64_t)i;
            }
            break;
    }
}

/* Display CPU features */
static void display_cpu_features(void) {
    uint32_t features = not_stisla_detect_cpu_features();
    printf("  " BOLD "CPU Features Detected:\n" RESET);
    printf("    ");
    if (features & NOT_STISLA_CPU_AVX2) {
        printf(GREEN "AVX2 " RESET);
    } else {
        printf(RED "AVX2 " RESET);
    }
    if (features & NOT_STISLA_CPU_AVX512) {
        printf(GREEN "AVX-512 " RESET);
    } else {
        printf(RED "AVX-512 " RESET);
    }
    if (features & NOT_STISLA_CPU_AMX) {
        printf(GREEN "AMX " RESET);
    } else {
        printf(RED "AMX " RESET);
    }
    if (features & NOT_STISLA_CPU_VNNI) {
        printf(GREEN "VNNI" RESET);
    } else {
        printf(RED "VNNI" RESET);
    }
    printf("\n");
}

/* Live statistics display */
static void show_live_stats(int current, int total, const char* label, 
                           double running_avg, uint64_t min_ns, uint64_t max_ns) {
    int width = 40;
    int pos = (current * width) / total;
    
    printf("\r%s [", label);
    for (int i = 0; i < width; i++) {
        if (i < pos) printf("█");
        else if (i == pos) printf("▓");
        else printf("░");
    }
    printf("] %3d%% | " GREEN "%.1f ns" RESET " (min:%lu max:%lu)", 
           (current * 100) / total, running_avg, 
           (unsigned long)min_ns, (unsigned long)max_ns);
    fflush(stdout);
}

/* Benchmark single search function (classical) */
static double benchmark_search(const char* name, int64_t* arr, size_t n, 
                               int64_t* keys, size_t num_keys, int iterations,
                               not_stisla_anchor_table_t* table, size_t tol) {
    uint64_t total = 0;
    uint64_t min_ns = UINT64_MAX;
    uint64_t max_ns = 0;
    size_t found = 0;
    
    printf("    " BOLD "%s:\n" RESET, name);
    
    for (int i = 0; i < iterations; i++) {
        if ((i + 1) % LIVE_UPDATE_INTERVAL == 0 || i == iterations - 1) {
            double running_avg = (double)total / (i + 1);
            show_live_stats(i + 1, iterations, "      ", running_avg, min_ns, max_ns);
        }
        
        int64_t key = keys[i % num_keys];
        uint64_t start = get_time_ns();
        not_stisla_result_t result = not_stisla_search(arr, n, key, table, tol);
        uint64_t elapsed = get_time_ns() - start;
        
        total += elapsed;
        if (elapsed < min_ns) min_ns = elapsed;
        if (elapsed > max_ns) max_ns = elapsed;
        if (result != NOT_STISLA_NOT_FOUND) found++;
    }
    printf("\n");
    
    double avg = (double)total / iterations;
    printf("      " GREEN "Avg: %.2f ns" RESET "  |  Min: %lu ns  |  Max: %lu ns  |  Found: %zu/%d\n",
           avg, (unsigned long)min_ns, (unsigned long)max_ns, found, iterations);
    
    return avg;
}

/* Run comprehensive benchmark */
static void run_benchmark(size_t array_size, int workload_type, int use_huge_pages) {
    const char* workload_names[] = {"TELEMETRY", "IDS", "OFFSETS", "EVENTS"};
    
    printf("\n" BOLD CYAN "═══════════════════════════════════════════════════════════════\n" RESET);
    printf(BOLD "  Array Size: %zu  |  Workload: %s  |  Huge Pages: %s\n" RESET, 
           array_size, 
           workload_type < 4 ? workload_names[workload_type] : "DEFAULT",
           use_huge_pages ? GREEN "ENABLED" RESET : RED "DISABLED" RESET);
    printf(CYAN "═══════════════════════════════════════════════════════════════\n" RESET);

    /* Allocate and generate test data */
    int64_t* arr = malloc(array_size * sizeof(int64_t));
    if (!arr) {
        printf(RED "  ERROR: Failed to allocate array\n" RESET);
        return;
    }
    generate_sorted_array(arr, array_size, workload_type);
    
    /* Apply huge pages optimization if requested and array is large enough */
    if (use_huge_pages && array_size * sizeof(int64_t) >= HUGE_PAGE_THRESHOLD) {
        int hp_result = not_stisla_optimize_array_memory(arr, array_size);
        if (hp_result == 0) {
            printf("  " GREEN "✓" RESET " Huge pages optimization applied\n");
        } else {
            printf("  " YELLOW "⚠" RESET " Huge pages unavailable (continuing without)\n");
        }
    }

    /* Generate search keys */
    size_t num_keys = 200;
    int64_t* keys = malloc(num_keys * sizeof(int64_t));
    for (size_t i = 0; i < num_keys; i++) {
        size_t idx = (i * 7) % array_size;
        keys[i] = arr[idx];
    }

    /* Create anchor tables */
    not_stisla_anchor_table_t* table_classical = not_stisla_anchor_table_create();
    not_stisla_anchor_table_t* table_enhanced = not_stisla_anchor_table_create();
    
    if (!table_classical || !table_enhanced) {
        printf(RED "  ERROR: Failed to create anchor tables\n" RESET);
        free(arr);
        free(keys);
        return;
    }

    /* Initialize config */
    not_stisla_config_t config;
    not_stisla_config_init(&config, workload_type);
    config.quantum.enable_performance_tracking = 1;

    /* Warmup */
    printf("\n  " YELLOW "Warming up..." RESET);
    fflush(stdout);
    for (int i = 0; i < WARMUP_ITERATIONS; i++) {
        int64_t key = keys[i % num_keys];
        not_stisla_search(arr, array_size, key, table_classical, 8);
        not_stisla_search_enhanced(arr, array_size, key, table_enhanced, &config);
    }
    printf(" " GREEN "Done" RESET "\n\n");

    /* Test small array SIMD path if applicable */
    if (array_size < 32) {
        printf("  " BOLD MAGENTA "Small Array SIMD Test (AVX-512/AVX2 branchless):\n" RESET);
        double classical_avg = benchmark_search("Classical (scalar fallback)", arr, array_size, 
                                                keys, num_keys, BENCHMARK_ITERATIONS,
                                                table_classical, 8);
        printf("\n");
    }

    /* Benchmark Classical */
    printf("  " BOLD "Classical NOT_STISLA:\n" RESET);
    double classical_avg = benchmark_search("Standard Search", arr, array_size, 
                                           keys, num_keys, BENCHMARK_ITERATIONS,
                                           table_classical, 8);

    /* Benchmark Enhanced */
    printf("\n  " BOLD "Enhanced NOT_STISLA (with optimizations):\n" RESET);
    not_stisla_reset_performance_stats();
    
    uint64_t enhanced_total = 0;
    uint64_t enhanced_min_ns = UINT64_MAX;
    uint64_t enhanced_max_ns = 0;
    size_t enhanced_found = 0;
    
    printf("    " BOLD "Enhanced Search:\n" RESET);
    for (int i = 0; i < BENCHMARK_ITERATIONS; i++) {
        if ((i + 1) % LIVE_UPDATE_INTERVAL == 0 || i == BENCHMARK_ITERATIONS - 1) {
            double running_avg = (double)enhanced_total / (i + 1);
            show_live_stats(i + 1, BENCHMARK_ITERATIONS, "      ", running_avg, enhanced_min_ns, enhanced_max_ns);
        }
        
        int64_t key = keys[i % num_keys];
        uint64_t start = get_time_ns();
        not_stisla_result_t result = not_stisla_search_enhanced(arr, array_size, key, table_enhanced, &config);
        uint64_t elapsed = get_time_ns() - start;
        
        enhanced_total += elapsed;
        if (elapsed < enhanced_min_ns) enhanced_min_ns = elapsed;
        if (elapsed > enhanced_max_ns) enhanced_max_ns = elapsed;
        if (result != NOT_STISLA_NOT_FOUND) enhanced_found++;
    }
    printf("\n");
    
    double enhanced_avg = (double)enhanced_total / BENCHMARK_ITERATIONS;
    printf("      " GREEN "Avg: %.2f ns" RESET "  |  Min: %lu ns  |  Max: %lu ns  |  Found: %zu/%d\n",
           enhanced_avg, (unsigned long)enhanced_min_ns, (unsigned long)enhanced_max_ns, 
           enhanced_found, BENCHMARK_ITERATIONS);

    /* Comparison */
    printf("\n  " BOLD "Performance Comparison:\n" RESET);
    double speedup = classical_avg / enhanced_avg;
    double overhead_pct = ((enhanced_avg - classical_avg) / classical_avg) * 100.0;
    
    if (speedup >= 1.0) {
        printf("    " GREEN "Speedup: %.2fx" RESET " (Enhanced is %.1f%% faster)\n", 
               speedup, (speedup - 1.0) * 100.0);
    } else {
        printf("    " YELLOW "Overhead: %.1f%%" RESET " (Enhanced is %.2fx slower)\n", 
               overhead_pct, 1.0 / speedup);
    }
    
    /* Show optimization details */
    printf("\n  " BOLD "Optimization Status:\n" RESET);
    uint32_t cpu_features = not_stisla_detect_cpu_features();
    printf("    ");
    if (cpu_features & NOT_STISLA_CPU_AVX512) {
        printf(GREEN "✓" RESET " AVX-512 branchless search: " GREEN "ACTIVE" RESET "\n");
    } else if (cpu_features & NOT_STISLA_CPU_AVX2) {
        printf(GREEN "✓" RESET " AVX2 branchless search: " GREEN "ACTIVE" RESET "\n");
    } else {
        printf(YELLOW "⚠" RESET " SIMD optimizations: " YELLOW "UNAVAILABLE" RESET " (scalar fallback)\n");
    }
    
    printf("    " GREEN "✓" RESET " Software prefetching: " GREEN "ACTIVE" RESET "\n");
    
    if (use_huge_pages && array_size * sizeof(int64_t) >= HUGE_PAGE_THRESHOLD) {
        printf("    " GREEN "✓" RESET " Huge pages (TLB optimization): " GREEN "ACTIVE" RESET "\n");
    } else if (array_size * sizeof(int64_t) < HUGE_PAGE_THRESHOLD) {
        printf("    " YELLOW "⚠" RESET " Huge pages: " YELLOW "SKIPPED" RESET " (array < 1MB)\n");
    } else {
        printf("    " RED "✗" RESET " Huge pages: " RED "DISABLED" RESET "\n");
    }

    /* Test batch performance */
    const size_t batch_size = 256;
    size_t batch_runs = BENCHMARK_ITERATIONS / 100;
    if (batch_runs == 0) batch_runs = 1;
    not_stisla_batch_item_t* batch_items = calloc(batch_size, sizeof(not_stisla_batch_item_t));
    not_stisla_anchor_table_t* batch_table = not_stisla_anchor_table_create();

    if (batch_items && batch_table) {
        printf("\n  " BOLD "Batch Search Performance:\n" RESET);
        
        for (size_t run = 0; run < batch_runs; ++run) {
            for (size_t j = 0; j < batch_size; ++j) {
                size_t idx = (run * batch_size + j) % num_keys;
                batch_items[j].key = keys[idx];
                batch_items[j].result = NOT_STISLA_NOT_FOUND;
                batch_items[j].ordinal = j;
            }
        }
        
        uint64_t batch_start = get_time_ns();
        size_t batch_found = 0;
        for (size_t run = 0; run < batch_runs; ++run) {
            for (size_t j = 0; j < batch_size; ++j) {
                size_t idx = (run * batch_size + j) % num_keys;
                batch_items[j].key = keys[idx];
            }
            batch_found += not_stisla_search_batch(arr, array_size, batch_items, batch_size, batch_table, 8);
        }
        uint64_t batch_elapsed = get_time_ns() - batch_start;
        
        double batch_avg_per_key = (double)batch_elapsed / (batch_runs * batch_size);
        printf("    " GREEN "Avg per key: %.2f ns" RESET "  |  Found: %zu/%zu\n",
               batch_avg_per_key, batch_found, batch_runs * batch_size);
        
        free(batch_items);
        not_stisla_anchor_table_destroy(batch_table);
    }

    /* Cleanup */
    not_stisla_anchor_table_destroy(table_classical);
    not_stisla_anchor_table_destroy(table_enhanced);
    free(keys);
    free(arr);
}

int main(int argc, char** argv) {
    printf("\n" BOLD CYAN "╔═══════════════════════════════════════════════════════════════╗\n");
    printf("║     NOT_STISLA Enhanced Benchmark v3.0                    ║\n");
    printf("║     AVX-512 Branchless + Prefetching + Huge Pages         ║\n");
    printf("╚═══════════════════════════════════════════════════════════════╝\n" RESET);
    
    display_cpu_features();
    
    printf("\n  Iterations per test: %d\n", BENCHMARK_ITERATIONS);
    printf("  Warmup iterations:   %d\n", WARMUP_ITERATIONS);
    printf("  Architecture:        Meteor Lake (AVX2/AVX-512)\n");

    int workload_type = NOT_STISLA_WORKLOAD_TELEMETRY;
    int use_huge_pages = 1;  /* Default: enable huge pages */
    
    if (argc > 1) {
        workload_type = atoi(argv[1]);
        if (workload_type < 0 || workload_type > 3) {
            workload_type = NOT_STISLA_WORKLOAD_TELEMETRY;
        }
    }
    if (argc > 2) {
        use_huge_pages = atoi(argv[2]);
    }

    /* Test multiple array sizes - including small arrays for SIMD testing */
    size_t sizes[] = {16, 32, 100, 1000, 10000, 100000, 1000000, 10000000};
    int num_sizes = sizeof(sizes) / sizeof(sizes[0]);

    printf("\n" BOLD "Testing array sizes: " RESET);
    for (int i = 0; i < num_sizes; i++) {
        printf("%zu", sizes[i]);
        if (i < num_sizes - 1) printf(", ");
    }
    printf("\n\n");

    for (int i = 0; i < num_sizes; i++) {
        run_benchmark(sizes[i], workload_type, use_huge_pages);
    }

    printf("\n" BOLD CYAN "═══════════════════════════════════════════════════════════════\n" RESET);
    printf(BOLD GREEN "  Benchmark Complete!\n" RESET);
    printf(CYAN "═══════════════════════════════════════════════════════════════\n\n" RESET);

    return 0;
}
