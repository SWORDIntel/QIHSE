#ifndef QIHSE_SEARCH_H
#define QIHSE_SEARCH_H

#include "qihse.h"
#include "qihse_math.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * GROVER AMPLIFICATION CONFIGURATION
 * ============================================================================ */

void qihse_amplification_config_init(qihse_amplification_config_t* config,
                                    size_t problem_size);
int qihse_adaptive_amplify(qihse_superposition_t* superposition,
                           const void* query, qihse_data_type_t query_type,
                           const qihse_amplification_config_t* config);
void qihse_apply_grover_diffusion(qihse_superposition_t* superposition);
void qihse_apply_oracle(qihse_superposition_t* superposition,
                       const void* query, qihse_data_type_t type,
                       double selectivity);
void qihse_apply_diffusion(qihse_superposition_t* superposition);

/* ============================================================================
 * VERIFICATION AND ACCURACY
 * ============================================================================ */

void qihse_verify_config_init(qihse_verify_config_t* config, double target_accuracy);
qihse_collapse_result_t qihse_dimensional_collapse_l2_norm(
    const qihse_superposition_t* superposition);
not_stisla_result_t qihse_verify_result(
    const void* data, size_t n, const void* query, qihse_data_type_t type,
    const qihse_collapse_result_t* collapse, const qihse_verify_config_t* config);

/* ============================================================================
 * MULTI-RESOLUTION SEARCH
 * ============================================================================ */

typedef enum {
    QIHSE_RESOLUTION_LOW,
    QIHSE_RESOLUTION_MEDIUM,
    QIHSE_RESOLUTION_HIGH,
    QIHSE_RESOLUTION_ADAPTIVE
} qihse_resolution_level_t;

typedef struct {
    qihse_resolution_level_t level;
    size_t target_dimensions;
    double confidence_threshold;
    bool use_previous_results;
    size_t max_candidates;
    qihse_collapse_result_t* previous_result;
} qihse_resolution_config_t;

typedef struct {
    size_t num_resolutions;
    qihse_resolution_config_t* resolutions;
    qihse_collapse_result_t final_result;
    double total_time_ns;
    size_t resolutions_completed;
    bool early_termination;
} qihse_multires_result_t;

size_t qihse_init_multires_search(qihse_resolution_config_t* configs,
                                 size_t max_configs, qihse_data_type_t data_type,
                                 size_t array_size);
int qihse_execute_multires_search(const void* data, size_t n, const void* query,
                                not_stisla_anchor_table_t* table,
                                qihse_resolution_config_t* configs,
                                size_t num_configs, qihse_multires_result_t* result);
qihse_collapse_result_t qihse_get_multires_final_result(
    const qihse_multires_result_t* result);

/* ============================================================================
 * SELF-OPTIMIZATION
 * ============================================================================ */

typedef struct {
    uint64_t data_hash;
    size_t array_size;
    qihse_data_type_t data_type;
    double entropy;
    double gap_variance;
} qihse_data_signature_t;

typedef struct {
    qihse_data_signature_t signature;
    qihse_pipeline_type_t best_pipeline;
    size_t optimal_dimensions;
    double avg_speedup;
    double avg_confidence;
    size_t samples;
    uint64_t last_updated;
    bool use_anchor_search;
    size_t optimal_anchor_count;
    double anchor_hit_rate;
    double anchor_speedup;
    int workload_type;
} qihse_optimization_entry_t;

typedef struct {
    qihse_optimization_entry_t* entries;
    size_t num_entries;
    size_t max_entries;
    char* storage_path;
    bool enable_learning;
} qihse_optimization_db_t;

int qihse_optimization_init(qihse_optimization_db_t* db, size_t max_entries,
                           const char* storage_path);
void qihse_optimization_destroy(qihse_optimization_db_t* db);
void qihse_record_performance(qihse_optimization_db_t* db,
                             const qihse_data_signature_t* data_signature,
                             qihse_pipeline_type_t pipeline_type,
                             size_t dimensions, double speedup, double confidence);
void qihse_get_optimized_config(const qihse_optimization_db_t* db,
                               const qihse_data_signature_t* data_signature,
                               qihse_config_t* config);
qihse_optimization_entry_t* qihse_get_entry(qihse_optimization_db_t* db,
                                           const qihse_data_signature_t* sig);

/* ============================================================================
 * ANCHOR LEARNING AND HYBRID SEARCH
 * ============================================================================ */

typedef struct {
    not_stisla_result_t quantum_result;
    double quantum_confidence;
    not_stisla_result_t anchor_result;
    double anchor_confidence;
    not_stisla_result_t final_result;
    double final_confidence;
    bool used_hybrid;
} qihse_hybrid_result_t;

qihse_hybrid_result_t qihse_execute_hybrid_search(const void* data, size_t n,
                                                const void* query,
                                                not_stisla_anchor_table_t* table,
                                                const qihse_config_t* config);

void qihse_record_anchor_performance(qihse_optimization_db_t* db,
                                    const qihse_data_signature_t* data_signature,
                                    size_t anchor_count, double hit_rate,
                                    double speedup, int workload_type);
bool qihse_get_anchor_optimized_config(const qihse_optimization_db_t* db,
                                      const qihse_data_signature_t* data_signature,
                                      qihse_config_t* config);
int qihse_detect_workload_from_data(const void* data, size_t n,
                                  qihse_data_type_t data_type);
int qihse_save_optimization_db(const qihse_optimization_db_t* db);
int qihse_load_optimization_db(qihse_optimization_db_t* db);

/* Internal helper functions */
void qihse_record_anchor_search(bool used_anchor, double interpolation_error, double speedup);
void qihse_record_anchor_learning(size_t anchors_learned, size_t anchors_pruned);
typedef enum {
    QIHSE_ALGO_QUANTUM_ONLY,     /* Use only quantum-inspired search */
    QIHSE_ALGO_ANCHOR_ONLY,      /* Use only anchor-based search */
    QIHSE_ALGO_HYBRID_BALANCED,  /* Balance quantum and anchor approaches */
    QIHSE_ALGO_ADAPTIVE         /* Adapt based on real-time performance */
} qihse_algorithm_selection_t;

qihse_algorithm_selection_t qihse_select_algorithm(
    const qihse_data_signature_t* data_sig,
    const qihse_optimization_entry_t* opt_entry,
    size_t array_size,
    int detected_workload
);

void qihse_init_global_optimization(void);
extern qihse_optimization_db_t g_optimization_db;

#ifdef __cplusplus
}
#endif

#endif /* QIHSE_SEARCH_H */
