/* ============================================================================
 * QIHSE BENCHMARK SUITE - ENTERPRISE VALIDATION FRAMEWORK
 * ============================================================================
 *
 * Comprehensive benchmark suite for validating QIHSE performance across:
 * - Vector Search (SIFT1M, GIST1M, MS MARCO)
 * - Graph Search (LiveJournal, Freebase, MovieLens)
 * - Constraint Search (TSP, Job Shop, Knapsack)
 * - Hybrid Workloads (MS COCO, Product Catalog)
 *
 * Mission-critical validation ensuring commercial credibility and performance claims.
 * ============================================================================ */

#ifndef QIHSE_BENCHMARK_H
#define QIHSE_BENCHMARK_H

#include <stdint.h>
#include <stdbool.h>

/* ============================================================================
 * BENCHMARK TYPES AND ENUMS
 * ============================================================================ */

/**
 * Benchmark workload types
 */
typedef enum qihse_workload_type_e {
    QIHSE_WORKLOAD_VECTOR,        /* ANN/vector search */
    QIHSE_WORKLOAD_GRAPH,         /* Graph algorithms */
    QIHSE_WORKLOAD_CONSTRAINT,    /* Constraint optimization */
    QIHSE_WORKLOAD_HYBRID,        /* Multi-modal/structured search */
    QIHSE_WORKLOAD_MAX
} qihse_workload_type_t;

/**
 * Benchmark dataset types
 */
typedef enum qihse_dataset_type_e {
    QIHSE_DATASET_SIFT1M,         /* SIFT 1M descriptors */
    QIHSE_DATASET_GIST1M,         /* GIST 1M descriptors */
    QIHSE_DATASET_MSMARCO,        /* MS MARCO passage embeddings */
    QIHSE_DATASET_LIVEJOURNAL,    /* LiveJournal social graph */
    QIHSE_DATASET_FREEBASE,       /* Freebase knowledge graph */
    QIHSE_DATASET_MOVIELENS,      /* MovieLens recommendation graph */
    QIHSE_DATASET_TSPLIB,         /* TSPLIB optimization instances */
    QIHSE_DATASET_TAILLARD,       /* Taillard job shop instances */
    QIHSE_DATASET_KNAPSACK,       /* Multi-dimensional knapsack */
    QIHSE_DATASET_MSCOCO,         /* MS COCO multi-modal */
    QIHSE_DATASET_PRODUCT_CATALOG, /* E-commerce product catalog */
    QIHSE_DATASET_MAX
} qihse_dataset_type_t;

/* ============================================================================
 * DATA STRUCTURES
 * ============================================================================ */

/**
 * Vector dataset representation
 */
typedef struct qihse_vector_dataset_s {
    uint32_t num_vectors;
    uint32_t dimensions;
    float* vectors;               /* Row-major: [num_vectors * dimensions] */
    uint32_t* ids;                /* Vector IDs for ground truth */
} qihse_vector_dataset_t;

/**
 * Graph dataset representation
 */
typedef struct qihse_graph_dataset_s {
    uint32_t num_nodes;
    uint32_t num_edges;
    uint32_t* src_nodes;          /* Source nodes for each edge */
    uint32_t* dst_nodes;          /* Destination nodes for each edge */
    float* edge_weights;          /* Edge weights (optional) */
    uint32_t* node_features;      /* Node feature vectors (optional) */
} qihse_graph_dataset_t;

/**
 * Constraint optimization problem
 */
typedef struct qihse_constraint_dataset_s {
    uint32_t problem_size;
    uint32_t num_constraints;
    float* objective_coeffs;      /* Objective function coefficients */
    float* constraint_matrix;     /* Constraint matrix [num_constraints * problem_size] */
    float* constraint_bounds;     /* Constraint bounds [num_constraints] */
    float* variable_bounds;       /* Variable bounds [problem_size * 2] */
} qihse_constraint_dataset_t;

/**
 * Hybrid dataset (multi-modal/structured)
 */
typedef struct qihse_hybrid_dataset_s {
    uint32_t num_items;
    uint32_t vector_dims;         /* Vector feature dimensions */
    uint32_t text_dims;           /* Text feature dimensions */
    float* vector_features;       /* Vector features [num_items * vector_dims] */
    float* text_features;         /* Text features [num_items * text_dims] */
    char** metadata;              /* Structured metadata strings */
    uint32_t* category_ids;       /* Category/classification IDs */
} qihse_hybrid_dataset_t;

/**
 * Unified dataset container
 */
typedef union qihse_dataset_union_u {
    qihse_vector_dataset_t vector;
    qihse_graph_dataset_t graph;
    qihse_constraint_dataset_t constraint;
    qihse_hybrid_dataset_t hybrid;
} qihse_dataset_union_t;

typedef struct qihse_dataset_s {
    qihse_dataset_type_t type;
    qihse_workload_type_t workload_type;
    qihse_dataset_union_t data;
    char name[64];
    char version[16];
    uint64_t checksum;            /* Dataset integrity verification */
} qihse_dataset_t;

/**
 * Query specification
 */
typedef struct qihse_query_s {
    uint32_t query_id;
    qihse_workload_type_t type;
    union {
        struct {
            float* vector;        /* Query vector */
            uint32_t k;          /* Number of neighbors */
        } vector;
        struct {
            uint32_t src_node;   /* Source node */
            uint32_t dst_node;   /* Destination node (optional) */
            uint32_t algorithm;  /* BFS, PageRank, etc. */
        } graph;
        struct {
            float* initial_solution; /* Initial solution vector */
            uint32_t max_iterations; /* Optimization iterations */
        } constraint;
        struct {
            char* text_query;    /* Text query string */
            uint32_t category_filter; /* Category filter (optional) */
            float* vector_query; /* Vector query (optional) */
        } hybrid;
    } params;
} qihse_query_t;

/**
 * Query set container
 */
typedef struct qihse_query_set_s {
    uint32_t num_queries;
    qihse_query_t* queries;
    char name[64];
} qihse_query_set_t;

/**
 * Ground truth for validation
 */
typedef struct qihse_ground_truth_s {
    uint32_t num_queries;
    uint32_t** neighbor_ids;      /* Ground truth neighbor IDs [num_queries][k] */
    float** distances;            /* Ground truth distances [num_queries][k] */
    uint32_t* k_values;           /* k values per query */
} qihse_ground_truth_t;

/**
 * Performance metrics
 */
typedef struct qihse_performance_metrics_s {
    /* Throughput metrics */
    double qps;                   /* Queries per second */
    double latency_p50;          /* Median latency (microseconds) */
    double latency_p95;          /* 95th percentile latency */
    double latency_p99;          /* 99th percentile latency */

    /* Accuracy metrics */
    double recall_at_1;          /* Recall@1 */
    double recall_at_10;         /* Recall@10 */
    double ndcg_at_10;           /* NDCG@10 */
    double correctness_score;    /* Overall correctness (0.0-1.0) */

    /* Resource metrics */
    size_t peak_memory_mb;       /* Peak memory usage */
    double avg_cpu_percent;      /* Average CPU utilization */
    double avg_power_watts;      /* Average power consumption */

    /* Timing breakdown */
    double index_build_time_ms;  /* Index construction time */
    double query_time_total_ms;  /* Total query execution time */
    double aggregation_time_ms;  /* Result aggregation time */

    /* Verification metrics */
    uint64_t verification_failures; /* Number of verification failures */
    double verification_time_ms; /* Time spent on verification */
} qihse_performance_metrics_t;

/**
 * Benchmark results
 */
typedef struct qihse_benchmark_results_s {
    char benchmark_name[64];
    qihse_workload_type_t workload_type;
    qihse_dataset_type_t dataset_type;
    qihse_performance_metrics_t metrics;
    uint32_t num_queries_executed;
    uint32_t num_queries_failed;
    uint64_t start_time_us;
    uint64_t end_time_us;
    char qihse_version[32];
    char hardware_config[256];
} qihse_benchmark_results_t;

/**
 * Benchmark configuration
 */
typedef struct qihse_benchmark_config_s {
    char workload_name[64];
    qihse_workload_type_t type;
    qihse_dataset_t dataset;
    qihse_query_set_t queries;
    qihse_ground_truth_t ground_truth;
    uint32_t warmup_queries;      /* Number of warmup queries */
    uint32_t measurement_queries; /* Number of measurement queries */
    bool enable_verification;     /* Enable correctness verification */
    bool enable_regression_check; /* Enable regression detection */
    double confidence_threshold;  /* Confidence threshold for verification */
    char output_directory[256];   /* Results output directory */
} qihse_benchmark_config_t;

/* ============================================================================
 * BENCHMARK EXECUTION API
 * ============================================================================ */

/**
 * Initialize benchmark framework
 *
 * @return 0 on success, negative error code on failure
 */
int qihse_benchmark_init(void);

/**
 * Cleanup benchmark framework
 */
void qihse_benchmark_cleanup(void);

/**
 * Load dataset from file
 *
 * @param type Dataset type to load
 * @param dataset Output dataset structure
 * @return 0 on success, negative error code on failure
 */
int qihse_benchmark_load_dataset(
    qihse_dataset_type_t type,
    qihse_dataset_t* dataset
);

/**
 * Execute benchmark
 *
 * @param config Benchmark configuration
 * @param results Output results structure
 * @return 0 on success, negative error code on failure
 */
int qihse_benchmark_run(
    const qihse_benchmark_config_t* config,
    qihse_benchmark_results_t* results
);

/**
 * Validate benchmark results against ground truth
 *
 * @param results Benchmark results to validate
 * @param ground_truth Ground truth data
 * @param config Validation configuration
 * @return 0 on success, negative error code on failure
 */
int qihse_benchmark_validate(
    qihse_benchmark_results_t* results,
    const qihse_ground_truth_t* ground_truth,
    const qihse_benchmark_config_t* config
);

/**
 * Save benchmark results to file
 *
 * @param results Results to save
 * @param output_path Output file path
 * @return 0 on success, negative error code on failure
 */
int qihse_benchmark_save_results(
    const qihse_benchmark_results_t* results,
    const char* output_path
);

/* ============================================================================
 * INDIVIDUAL BENCHMARK IMPLEMENTATIONS
 * ============================================================================ */

/**
 * SIFT1M Vector Search Benchmark
 */
int qihse_benchmark_sift1m(qihse_benchmark_results_t* results);

/**
 * GIST1M Vector Search Benchmark
 */
int qihse_benchmark_gist1m(qihse_benchmark_results_t* results);

/**
 * MS MARCO Text Embedding Benchmark
 */
int qihse_benchmark_msmarco(qihse_benchmark_results_t* results);

/**
 * LiveJournal Graph Benchmark
 */
int qihse_benchmark_livejournal(qihse_benchmark_results_t* results);

/**
 * Freebase Graph Benchmark
 */
int qihse_benchmark_freebase(qihse_benchmark_results_t* results);

/**
 * MovieLens Recommendation Benchmark
 */
int qihse_benchmark_movielens(qihse_benchmark_results_t* results);

/**
 * TSPLIB Optimization Benchmark
 */
int qihse_benchmark_tsplib(qihse_benchmark_results_t* results);

/**
 * Taillard Job Shop Benchmark
 */
int qihse_benchmark_taillard(qihse_benchmark_results_t* results);

/**
 * Multi-dimensional Knapsack Benchmark
 */
int qihse_benchmark_knapsack(qihse_benchmark_results_t* results);

/**
 * MS COCO Multi-modal Benchmark
 */
int qihse_benchmark_mscoco(qihse_benchmark_results_t* results);

/**
 * Product Catalog Hybrid Benchmark
 */
int qihse_benchmark_product_catalog(qihse_benchmark_results_t* results);

/* ============================================================================
 * REGRESSION DETECTION
 * ============================================================================ */

/**
 * Regression detector configuration
 */
typedef struct qihse_regression_detector_s {
    double baseline_mean;         /* Baseline performance mean */
    double baseline_stddev;       /* Baseline performance standard deviation */
    double control_limit_sigma;   /* Control limit in standard deviations */
    uint32_t min_samples;         /* Minimum samples for stable baseline */
    uint32_t current_samples;     /* Current number of samples */
    double* sample_history;       /* Historical performance samples */
    bool baseline_established;    /* Whether baseline is established */
} qihse_regression_detector_t;

/**
 * Regression detection status
 */
typedef enum qihse_regression_status_e {
    QIHSE_REGRESSION_NONE,        /* No regression detected */
    QIHSE_REGRESSION_WARNING,     /* Performance degradation detected */
    QIHSE_REGRESSION_CRITICAL,    /* Critical regression detected */
    QIHSE_REGRESSION_IMPROVEMENT  /* Performance improvement detected */
} qihse_regression_status_t;

/**
 * Initialize regression detector
 *
 * @param detector Detector to initialize
 * @param control_limit_sigma Control limit in standard deviations
 * @param min_samples Minimum samples for baseline
 * @return 0 on success, negative error code on failure
 */
int qihse_regression_detector_init(
    qihse_regression_detector_t* detector,
    double control_limit_sigma,
    uint32_t min_samples
);

/**
 * Update regression detector with new measurement
 *
 * @param detector Detector instance
 * @param measurement New performance measurement
 * @return Regression status
 */
qihse_regression_status_t qihse_regression_detector_update(
    qihse_regression_detector_t* detector,
    double measurement
);

/**
 * Check if measurement indicates regression
 *
 * @param detector Detector instance
 * @param measurement Measurement to check
 * @return Regression status
 */
qihse_regression_status_t qihse_regression_detector_check(
    const qihse_regression_detector_t* detector,
    double measurement
);

/**
 * Destroy regression detector
 *
 * @param detector Detector to destroy
 */
void qihse_regression_detector_destroy(qihse_regression_detector_t* detector);

#endif /* QIHSE_BENCHMARK_H */
