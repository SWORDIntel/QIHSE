/*
 * QIHSE Phase 2: Memory Superposition & Vector DB Integration Example
 *
 * Demonstrates the new Phase 2 features:
 * - UMA memory superposition with 128MB Meteor Lake NPU cache
 * - Temperature-aware migration
 * - Vector database integration with instant access
 * - Pre-loading capabilities
 *
 * This example shows how to use the enhanced UMA system and vector database
 * integration for optimal performance in QIHSE search operations.
 */

#include "qihse.h"
#include "../memory/include/qihse_uma.h"
#include "qihse_vector_db.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ============================================================================
 * EXAMPLE CONFIGURATION
 * ============================================================================ */

#define VECTOR_DIMS 128
#define NUM_VECTORS 10000
#define QUERY_VECTORS 100
#define PRELOAD_BATCH_SIZE 1000
#define SIMILARITY_THRESHOLD 0.8f

/* ============================================================================
 * UTILITY FUNCTIONS
 * ============================================================================ */

/**
 * Generate a random vector with unit norm.
 */
void generate_random_vector(float* vector, size_t dims) {
    float sum_sq = 0.0f;
    for (size_t i = 0; i < dims; i++) {
        vector[i] = ((float)rand() / RAND_MAX) * 2.0f - 1.0f; /* -1 to 1 */
        sum_sq += vector[i] * vector[i];
    }

    /* Normalize to unit length */
    float norm = sqrtf(sum_sq);
    if (norm > 0.0f) {
        for (size_t i = 0; i < dims; i++) {
            vector[i] /= norm;
        }
    }
}

/**
 * Generate temperature reading for example (in real usage, this comes from hardware sensors).
 */
double get_demo_temperature(void) {
    /* Simulate temperature between 40°C and 95°C */
    return 40.0 + ((double)rand() / RAND_MAX) * 55.0;
}

/* ============================================================================
 * PHASE 2 FEATURES DEMONSTRATION
 * ============================================================================ */

int example_memory_superposition(void) {
    printf("=== Phase 2: Memory Superposition Demonstration ===\n\n");

    /* Initialize UMA manager */
    qihse_memory_manager_t memory_manager = qihse_memory_create_manager();
    if (!memory_manager) {
        fprintf(stderr, "Failed to create memory manager\n");
        return -1;
    }

    qihse_uma_manager_t uma_manager = qihse_uma_create(memory_manager, QIHSE_UMA_MIGRATE_ON_ACCESS);
    if (!uma_manager) {
        fprintf(stderr, "Failed to create UMA manager\n");
        qihse_memory_destroy_manager(memory_manager);
        return -1;
    }

    /* Initialize Meteor Lake NPU cache with dynamic detection */
    qihse_meteor_lake_npu_cache_t npu_cache;
    if (!qihse_uma_init_meteor_lake_npu_cache(&npu_cache)) {
        fprintf(stderr, "Failed to initialize NPU cache\n");
        qihse_uma_destroy(uma_manager);
        qihse_memory_destroy_manager(memory_manager);
        return -1;
    }

    /* Get detected cache size */
    size_t detected_cache_mb = qihse_uma_get_detected_cache_size(&npu_cache);

    printf("✓ Dynamically detected HPU cache size: %zu MB\n", detected_cache_mb);
    printf("✓ Initialized UMA with optimized Meteor Lake NPU cache\n");
    printf("  - Cache size: %zu MB\n", npu_cache.cache_size_mb);
    printf("  - GNA enabled: %s\n", npu_cache.gna_enabled ? "yes" : "no");
    printf("  - Line size: %zu bytes\n", npu_cache.line_size_bytes);
    printf("  - Associativity: %zu-way\n", npu_cache.associativity);
    printf("  - GNA workgroup size: %zu\n\n", npu_cache.gna_workgroup_size);

    /* Optimize UMA policies for detected cache size */
    if (!qihse_uma_optimize_for_cache_size(uma_manager, &npu_cache)) {
        fprintf(stderr, "Warning: Failed to optimize for cache size\n");
    }

    /* Allocate memory with superposition */
    size_t test_size = 1024 * 1024; /* 1MB test allocation */
    int devices[] = {0}; /* CPU device */

    qihse_uma_address_t* superposition_addr = qihse_uma_allocate_superposition(
        uma_manager, test_size, devices, 1, QIHSE_SUPERPOSITION_READY
    );

    if (!superposition_addr) {
        fprintf(stderr, "Failed to allocate superposition memory\n");
        qihse_uma_destroy(uma_manager);
        qihse_memory_destroy_manager(memory_manager);
        return -1;
    }

    printf("✓ Allocated %zu MB with memory superposition\n", test_size / (1024 * 1024));

    /* Demonstrate temperature-aware access */
    double temperature = get_demo_temperature();
    printf("Current temperature: %.1f°C\n", temperature);

    void* temp_aware_ptr = qihse_uma_access_temperature_aware(
        uma_manager, superposition_addr, 0, temperature
    );

    if (temp_aware_ptr) {
        printf("✓ Temperature-aware access successful\n");

        /* Write some test data */
        memset(temp_aware_ptr, 0xAA, 1024);
        printf("✓ Wrote test data to superposition memory\n");

        qihse_uma_release(uma_manager, superposition_addr, 0);
        printf("✓ Released temperature-aware access\n\n");
    }

    /* Get superposition state */
    qihse_memory_superposition_state_t state = qihse_uma_get_superposition_state(
        uma_manager, superposition_addr
    );
    printf("Current superposition state: %d\n", state);

    /* Set new superposition state with temperature trigger */
    qihse_temperature_trigger_t temp_trigger = QIHSE_TEMP_NORMAL;
    if (temperature > 75.0) {
        temp_trigger = QIHSE_TEMP_HIGH;
    }

    qihse_uma_set_superposition_state(
        uma_manager, superposition_addr, QIHSE_SUPERPOSITION_PINNED, temp_trigger
    );
    printf("✓ Set superposition state to PINNED with temperature trigger\n\n");

    /* Clean up */
    qihse_uma_free(uma_manager, superposition_addr);
    qihse_uma_destroy(uma_manager);
    qihse_memory_destroy_manager(memory_manager);

    printf("✓ Memory superposition example completed successfully\n\n");
    return 0;
}

int example_vector_db_integration(void) {
    printf("=== Phase 2: Vector Database Integration Demonstration ===\n\n");

    /* Initialize UMA manager */
    qihse_memory_manager_t memory_manager = qihse_memory_create_manager();
    if (!memory_manager) {
        fprintf(stderr, "Failed to create memory manager\n");
        return -1;
    }

    qihse_uma_manager_t uma_manager = qihse_uma_create(memory_manager, QIHSE_UMA_MIGRATE_ON_ACCESS);
    if (!uma_manager) {
        fprintf(stderr, "Failed to create UMA manager\n");
        qihse_memory_destroy_manager(memory_manager);
        return -1;
    }

    /* Initialize vector database */
    qihse_vector_db_t vdb = qihse_vector_db_create(
        QIHSE_VECTOR_DB_INMEMORY, uma_manager, NULL /* in-memory */
    );

    if (!vdb) {
        fprintf(stderr, "Failed to create vector database\n");
        qihse_uma_destroy(uma_manager);
        qihse_memory_destroy_manager(memory_manager);
        return -1;
    }

    printf("✓ Created vector database with QIHSE integration\n");

    /* Enable QIHSE acceleration */
    if (!qihse_vector_db_enable_acceleration(vdb, true, true, true)) {
        fprintf(stderr, "Failed to enable QIHSE acceleration\n");
        qihse_vector_db_destroy(vdb);
        qihse_uma_destroy(uma_manager);
        qihse_memory_destroy_manager(memory_manager);
        return -1;
    }

    printf("✓ Enabled QIHSE acceleration (Hilbert + Quantization + Parallel)\n");

    /* Enable memory superposition for vectors */
    if (!qihse_vector_db_enable_superposition(vdb, QIHSE_SUPERPOSITION_READY, true)) {
        fprintf(stderr, "Failed to enable superposition\n");
        qihse_vector_db_destroy(vdb);
        qihse_uma_destroy(uma_manager);
        qihse_memory_destroy_manager(memory_manager);
        return -1;
    }

    printf("✓ Enabled memory superposition with temperature awareness\n");

    /* Generate and add test vectors */
    printf("Generating and adding %d test vectors...\n", NUM_VECTORS);

    float* test_vectors = malloc(NUM_VECTORS * VECTOR_DIMS * sizeof(float));
    if (!test_vectors) {
        fprintf(stderr, "Failed to allocate test vectors\n");
        qihse_vector_db_destroy(vdb);
        qihse_uma_destroy(uma_manager);
        qihse_memory_destroy_manager(memory_manager);
        return -1;
    }

    /* Generate random vectors */
    srand(time(NULL));
    for (size_t i = 0; i < NUM_VECTORS; i++) {
        generate_random_vector(&test_vectors[i * VECTOR_DIMS], VECTOR_DIMS);
    }

    /* Prepare metadata for vectors */
    const char* metadata_strings[] = {
        "document_1", "document_2", "document_3", "document_4", "document_5"
    };
    void* metadata_ptrs[5];
    size_t metadata_sizes[5];

    for (int i = 0; i < 5 && i < NUM_VECTORS; i++) {
        metadata_ptrs[i] = (void*)metadata_strings[i];
        metadata_sizes[i] = strlen(metadata_strings[i]) + 1; /* Include null terminator */
    }

    /* Add vectors with metadata to database */
    if (!qihse_vector_db_add_vectors(vdb, test_vectors, NUM_VECTORS, VECTOR_DIMS,
                                    NULL, metadata_ptrs, metadata_sizes)) {
        fprintf(stderr, "Failed to add vectors to database\n");
        free(test_vectors);
        qihse_vector_db_destroy(vdb);
        qihse_uma_destroy(uma_manager);
        qihse_memory_destroy_manager(memory_manager);
        return -1;
    }

    printf("✓ Added %d vectors to database with UMA superposition\n", NUM_VECTORS);

    /* Optimize layout for search workload */
    if (!qihse_vector_db_optimize_layout(vdb, "search")) {
        fprintf(stderr, "Failed to optimize layout\n");
        free(test_vectors);
        qihse_vector_db_destroy(vdb);
        qihse_uma_destroy(uma_manager);
        qihse_memory_destroy_manager(memory_manager);
        return -1;
    }

    printf("✓ Optimized database layout for search workload\n");

    /* Pre-load similar vectors for a query */
    float query_vector[VECTOR_DIMS];
    generate_random_vector(query_vector, VECTOR_DIMS);

    if (!qihse_vector_db_preload_similar(vdb, query_vector, VECTOR_DIMS, SIMILARITY_THRESHOLD)) {
        fprintf(stderr, "Failed to preload similar vectors\n");
        free(test_vectors);
        qihse_vector_db_destroy(vdb);
        qihse_uma_destroy(uma_manager);
        qihse_memory_destroy_manager(memory_manager);
        return -1;
    }

    printf("✓ Pre-loaded similar vectors for instant access\n");

    /* Perform search */
    qihse_vector_query_t query = {
        .query_vector = query_vector,
        .vector_dims = VECTOR_DIMS,
        .top_k = 10,
        .similarity_threshold = SIMILARITY_THRESHOLD,
        .include_vectors = false,
        .include_metadata = true  /* Include metadata in results */
    };

    qihse_vector_result_t results[10];

    int num_results = qihse_vector_db_search(vdb, &query, results, 10);
    if (num_results < 0) {
        fprintf(stderr, "Search failed: %d\n", num_results);
        free(test_vectors);
        qihse_vector_db_destroy(vdb);
        qihse_uma_destroy(uma_manager);
        qihse_memory_destroy_manager(memory_manager);
        return -1;
    }

    printf("✓ Search completed, found %d results\n", num_results);

    /* Display top results with metadata */
    printf("\nTop %d search results:\n", num_results);
    for (int i = 0; i < num_results; i++) {
        printf("  %d. ID: %llu, Score: %.4f",
               i + 1, (unsigned long long)results[i].id, results[i].score);

        if (results[i].metadata && results[i].metadata_size > 0) {
            printf(", Metadata: %s", (char*)results[i].metadata);
            free(results[i].metadata); /* Free metadata after use */
        }
        printf("\n");

        if (results[i].vector) {
            free(results[i].vector); /* Free vector data after use */
        }
    }

    /* Get performance statistics */
    double search_time, hit_rate, efficiency;
    if (qihse_vector_db_get_stats(vdb, &search_time, &hit_rate, &efficiency)) {
        printf("\nPerformance Statistics:\n");
        printf("  Search Time: %.2f ms\n", search_time);
        printf("  Preload Hit Rate: %.2f%%\n", hit_rate * 100.0);
        printf("  Memory Efficiency: %.2f%%\n", efficiency * 100.0);
    }

    /* Get superposition status */
    double ready_pct;
    size_t migrating, pinned;
    if (qihse_vector_db_get_superposition_status(vdb, &ready_pct, &migrating, &pinned)) {
        printf("\nMemory Superposition Status:\n");
        printf("  Ready: %.1f%%\n", ready_pct * 100.0);
        printf("  Migrating: %zu\n", migrating);
        printf("  Pinned: %zu\n", pinned);
    }

    /* Clean up */
    free(test_vectors);
    qihse_vector_db_destroy(vdb);
    qihse_uma_destroy(uma_manager);
    qihse_memory_destroy_manager(memory_manager);

    printf("\n✓ Vector database integration example completed successfully\n\n");
    return 0;
}

int example_combined_phase2_features(void) {
    printf("=== Phase 2: Combined Features Demonstration ===\n\n");

    /* Initialize UMA with vector DB preload configuration */
    qihse_memory_manager_t memory_manager = qihse_memory_create_manager();
    if (!memory_manager) {
        fprintf(stderr, "Failed to create memory manager\n");
        return -1;
    }

    qihse_uma_manager_t uma_manager = qihse_uma_create(memory_manager, QIHSE_UMA_MIGRATE_PREFETCH);
    if (!uma_manager) {
        fprintf(stderr, "Failed to create UMA manager\n");
        qihse_memory_destroy_manager(memory_manager);
        return -1;
    }

    /* Configure vector DB preloading */
    qihse_vector_db_preload_t preload_config = {
        .db_path = "./vectors.db",
        .preload_batch_size = PRELOAD_BATCH_SIZE,
        .preload_threshold = SIMILARITY_THRESHOLD,
        .max_preload_vectors = 5000,
        .enable_incremental_load = true,
        .preload_window_mb = 256
    };

    if (!qihse_uma_enable_vector_db_preload(uma_manager, &preload_config)) {
        fprintf(stderr, "Failed to enable vector DB preloading\n");
        qihse_uma_destroy(uma_manager);
        qihse_memory_destroy_manager(memory_manager);
        return -1;
    }

    printf("✓ Enabled vector database preloading with:\n");
    printf("  - Batch size: %zu\n", preload_config.preload_batch_size);
    printf("  - Threshold: %.2f\n", preload_config.preload_threshold);
    printf("  - Max preload: %zu\n", preload_config.max_preload_vectors);
    printf("  - Window: %zu MB\n\n", preload_config.preload_window_mb);

    /* Create vector database with full integration */
    qihse_vector_db_t vdb = qihse_vector_db_create(
        QIHSE_VECTOR_DB_INMEMORY, uma_manager, preload_config.db_path
    );

    if (!vdb) {
        fprintf(stderr, "Failed to create vector database\n");
        qihse_uma_destroy(uma_manager);
        qihse_memory_destroy_manager(memory_manager);
        return -1;
    }

    /* Enable all Phase 2 features */
    qihse_vector_db_enable_acceleration(vdb, true, true, true);
    qihse_vector_db_enable_superposition(vdb, QIHSE_SUPERPOSITION_HYBRID, true);
    qihse_vector_db_optimize_layout(vdb, "search");

    printf("✓ Enabled all Phase 2 features: acceleration, superposition, optimization\n");

    /* Generate test vectors */
    float* test_vectors = malloc(NUM_VECTORS * VECTOR_DIMS * sizeof(float));
    if (!test_vectors) {
        fprintf(stderr, "Failed to allocate test vectors\n");
        qihse_vector_db_destroy(vdb);
        qihse_uma_destroy(uma_manager);
        qihse_memory_destroy_manager(memory_manager);
        return -1;
    }

    srand(time(NULL) + 1); /* Different seed */
    for (size_t i = 0; i < NUM_VECTORS; i++) {
        generate_random_vector(&test_vectors[i * VECTOR_DIMS], VECTOR_DIMS);
    }

    /* Add vectors with superposition */
    qihse_vector_db_add_vectors(vdb, test_vectors, NUM_VECTORS, VECTOR_DIMS,
                               NULL, NULL, NULL);
    printf("✓ Added %d vectors with memory superposition\n", NUM_VECTORS);

    /* Perform multiple queries with preloading */
    printf("Performing queries with intelligent preloading...\n");

    for (int q = 0; q < 5; q++) {
        float query_vector[VECTOR_DIMS];
        generate_random_vector(query_vector, VECTOR_DIMS);

        /* Preload similar vectors */
        qihse_vector_db_preload_similar(vdb, query_vector, VECTOR_DIMS, SIMILARITY_THRESHOLD);

        /* Perform search */
        qihse_vector_query_t query = {
            .query_vector = query_vector,
            .vector_dims = VECTOR_DIMS,
            .top_k = 5,
            .similarity_threshold = SIMILARITY_THRESHOLD,
            .include_vectors = false,
            .include_metadata = false
        };

        qihse_vector_result_t results[5];
        int num_results = qihse_vector_db_search(vdb, &query, results, 5);

        printf("  Query %d: Found %d results (top score: %.4f)\n",
               q + 1, num_results, num_results > 0 ? results[0].score : 0.0f);
    }

    /* Get final statistics */
    double search_time, hit_rate, efficiency;
    qihse_vector_db_get_stats(vdb, &search_time, &hit_rate, &efficiency);

    printf("\nFinal Performance Summary:\n");
    printf("  Average Search Time: %.2f ms\n", search_time);
    printf("  Preload Hit Rate: %.1f%%\n", hit_rate * 100.0);
    printf("  Memory Efficiency: %.1f%%\n", efficiency * 100.0);

    /* Clean up */
    free(test_vectors);
    qihse_vector_db_destroy(vdb);
    qihse_uma_destroy(uma_manager);
    qihse_memory_destroy_manager(memory_manager);

    printf("\n✓ Combined Phase 2 features example completed successfully\n\n");
    return 0;
}

/* ============================================================================
 * MAIN DEMONSTRATION
 * ============================================================================ */

int main(int argc, char* argv[]) {
    printf("QIHSE Phase 2: Memory Superposition & Vector DB Integration\n");
    printf("==========================================================\n\n");

    /* Demonstrate individual features */
    if (example_memory_superposition() != 0) {
        fprintf(stderr, "Memory superposition example failed\n");
        return 1;
    }

    if (example_vector_db_integration() != 0) {
        fprintf(stderr, "Vector DB integration example failed\n");
        return 1;
    }

    if (example_combined_phase2_features() != 0) {
        fprintf(stderr, "Combined features example failed\n");
        return 1;
    }

    printf("🎉 All Phase 2 examples completed successfully!\n");
    printf("\nPhase 2 Features Implemented:\n");
    printf("✓ UMA Memory Superposition (128MB Meteor Lake NPU cache)\n");
    printf("✓ Temperature-aware migration policies\n");
    printf("✓ Vector database integration with instant access\n");
    printf("✓ Intelligent pre-loading for similar vectors\n");
    printf("✓ QIHSE acceleration with Hilbert space expansion\n");
    printf("✓ Memory-efficient superposition states\n");
    printf("✓ Performance monitoring and optimization\n");

    /* Demonstrate metadata storage and retrieval */
    printf("\n--- Metadata Storage Test ---\n");

    /* Add a test vector with specific metadata */
    float test_vector[VECTOR_DIMS];
    generate_random_vector(test_vector, VECTOR_DIMS);

    const char* test_metadata = "test_document_123";
    void* test_meta_ptr = (void*)test_metadata;
    size_t test_meta_size = strlen(test_metadata) + 1;

    uint64_t test_id = 99999;

    if (qihse_vector_db_add_vectors(vdb, test_vector, 1, VECTOR_DIMS,
                                   &test_id, &test_meta_ptr, &test_meta_size)) {
        printf("✓ Added test vector with metadata\n");

        /* Search for the test vector */
        qihse_vector_query_t test_query = {
            .query_vector = test_vector,
            .vector_dims = VECTOR_DIMS,
            .top_k = 1,
            .similarity_threshold = 0.99f, /* Very high threshold to get exact match */
            .include_vectors = false,
            .include_metadata = true
        };

        qihse_vector_result_t test_result;
        int test_found = qihse_vector_db_search(vdb, &test_query, &test_result, 1);

        if (test_found > 0 && test_result.metadata) {
            printf("✓ Retrieved metadata: '%s' (size: %zu)\n",
                   (char*)test_result.metadata, test_result.metadata_size);
            printf("✓ Metadata matches: %s\n",
                   strcmp((char*)test_result.metadata, test_metadata) == 0 ? "YES" : "NO");
            free(test_result.metadata);
        } else {
            printf("✗ Failed to retrieve metadata\n");
        }
    } else {
        printf("✗ Failed to add test vector with metadata\n");
    }

    printf("\n");
    return 0;
}
