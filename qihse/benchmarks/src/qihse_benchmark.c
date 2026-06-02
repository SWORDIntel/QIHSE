/**
 * QIHSE Benchmark Program
 *
 * Simple wrapper to run the comprehensive benchmark suite
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char* argv[]) {
    printf("🌀 QIHSE Benchmark Runner\n");
    printf("========================\n\n");

    /* Parse command line arguments */
    char* output_dir = "qihse_benchmark_results";
    char* benchmark_name = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--output-dir") == 0 && i + 1 < argc) {
            output_dir = argv[++i];
        } else if (strcmp(argv[i], "--benchmark") == 0 && i + 1 < argc) {
            benchmark_name = argv[++i];
        } else if (strcmp(argv[i], "--help") == 0) {
            printf("Usage: %s [options]\n\n", argv[0]);
            printf("Options:\n");
            printf("  --output-dir DIR    Output directory for results (default: qihse_benchmark_results)\n");
            printf("  --benchmark NAME    Run specific benchmark (default: all)\n");
            printf("  --help             Show this help\n\n");
            printf("Available benchmarks:\n");
            printf("  tiny_uniform, small_uniform, medium_uniform, large_uniform, huge_uniform\n");
            printf("  sparse variants: tiny_sparse, small_sparse, etc.\n");
            printf("  telemetry variants: small_telemetry, medium_telemetry, etc.\n");
            printf("  data types: double_precision, string_search\n");
            printf("  pathological cases: pathological\n");
            return 0;
        }
    }

    /* Execute the comprehensive benchmark suite */
    char cmd[1024];
    int ret;

    if (benchmark_name) {
        /* Run specific benchmark */
        printf("Running specific benchmark: %s\n", benchmark_name);
        printf("Output directory: %s\n\n", output_dir);

        snprintf(cmd, sizeof(cmd),
                "./qihse_benchmark_suite --benchmark %s --output-dir %s",
                benchmark_name, output_dir);
    } else {
        /* Run full benchmark suite */
        printf("Running full QIHSE benchmark suite...\n");
        printf("This may take several minutes depending on your hardware.\n");
        printf("Output directory: %s\n\n", output_dir);

        snprintf(cmd, sizeof(cmd),
                "./qihse_benchmark_suite --output-dir %s", output_dir);
    }

    /* Run the comprehensive benchmark */
    printf("Executing: %s\n\n", cmd);
    ret = system(cmd);

    if (ret == 0) {
        printf("\n✅ QIHSE benchmark completed successfully!\n");
        printf("📁 Results saved to: %s/\n", output_dir);

        /* Check if visualization script exists and can be run */
        if (access("benchmarks/scripts/visualize_benchmarks.py", F_OK) == 0) {
            printf("\n📊 Generating visualization charts...\n");
            char viz_cmd[1024];
            snprintf(viz_cmd, sizeof(viz_cmd),
                    "python3 benchmarks/scripts/visualize_benchmarks.py %s/results.json --output-dir %s_charts",
                    output_dir, output_dir);
            int viz_ret = system(viz_cmd);
            if (viz_ret == 0) {
                printf("📊 Charts saved to: %s_charts/\n", output_dir);
            } else {
                printf("⚠️  Chart generation failed (matplotlib may not be installed)\n");
            }
        } else {
            printf("⚠️  Visualization script not found\n");
        }
    } else {
        fprintf(stderr, "\n❌ QIHSE benchmark failed with exit code %d\n", ret);
        return ret;
    }

    return 0;
}
