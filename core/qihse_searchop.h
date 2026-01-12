/*
 * QIHSE - Search Operation Contracts
 *
 * This header defines the contracts for different types of search operations.
 * Each operation type has a specific configuration structure and contract.
 *
 * Version: 1.0.0
 * Author: DSMIL System
 * License: MIT
 */

#ifndef QIHSE_SEARCHOP_H
#define QIHSE_SEARCHOP_H

#include "qihse_abi.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * VECTOR SEARCH CONTRACT
 * ============================================================================ */

/**
 * Vector k-NN search configuration.
 * Finds k nearest neighbors for query vectors in a dataset.
 */
typedef struct qihse_vector_knn_config_s {
    uint32_t k;                          /* Number of nearest neighbors */
    float radius;                        /* Search radius (0 = unlimited) */
    qihse_metric_type_t metric;          /* Distance/similarity metric */
    int normalize;                       /* 1 = normalize vectors before search */
    int include_distances;               /* 1 = return distances with indices */
} qihse_vector_knn_config_t;

/**
 * Vector k-NN search contract.
 *
 * Inputs:
 *   0: Query vectors [num_queries, dimensions] (FLOAT32)
 *   1: Database vectors [num_vectors, dimensions] (FLOAT32)
 *   2: Optional: Query filter mask [num_queries] (UINT8)
 *
 * Outputs:
 *   0: Indices [num_queries, k] (UINT32)
 *   1: Optional: Distances [num_queries, k] (FLOAT32)
 */
#define QIHSE_VECTOR_KNN_CONTRACT_INPUTS  3
#define QIHSE_VECTOR_KNN_CONTRACT_OUTPUTS 2

/**
 * Vector range search configuration.
 * Finds all vectors within a radius of query vectors.
 */
typedef struct qihse_vector_range_config_s {
    float radius;                        /* Search radius (required) */
    qihse_metric_type_t metric;          /* Distance/similarity metric */
    uint32_t max_results;                /* Maximum results per query */
    int include_distances;               /* 1 = return distances with indices */
} qihse_vector_range_config_t;

/**
 * Vector range search contract.
 *
 * Inputs:
 *   0: Query vectors [num_queries, dimensions] (FLOAT32)
 *   1: Database vectors [num_vectors, dimensions] (FLOAT32)
 *
 * Outputs:
 *   0: Indices [num_queries, variable_length] (UINT32)
 *   1: Optional: Distances [num_queries, variable_length] (FLOAT32)
 *   2: Counts [num_queries] (UINT32) - number of results per query
 */

/* ============================================================================
 * GRAPH SEARCH CONTRACT
 * ============================================================================ */

/**
 * Graph traversal configuration.
 */
typedef enum qihse_graph_algorithm_e {
    QIHSE_GRAPH_BFS = 1,                 /* Breadth-first search */
    QIHSE_GRAPH_DFS = 2,                 /* Depth-first search */
    QIHSE_GRAPH_DIJKSTRA = 3,            /* Shortest path (weighted) */
    QIHSE_GRAPH_ASTAR = 4,               /* A* search */
    QIHSE_GRAPH_CONNECTED_COMPONENTS = 5 /* Find connected components */
} qihse_graph_algorithm_t;

typedef struct qihse_graph_search_config_s {
    qihse_graph_algorithm_t algorithm;    /* Search algorithm */
    uint32_t max_depth;                  /* Maximum search depth */
    uint32_t max_nodes;                  /* Maximum nodes to visit */
    float heuristic_weight;              /* A* heuristic weight (0.0-1.0) */
    int bidirectional;                   /* 1 = bidirectional search */
    int return_paths;                    /* 1 = return full paths, 0 = just targets */
} qihse_graph_search_config_t;

/**
 * Graph search contract.
 *
 * Inputs:
 *   0: Adjacency matrix (CSR format) - indices [nnz] (UINT32)
 *   1: Adjacency matrix (CSR format) - indptr [num_nodes+1] (UINT32)
 *   2: Start nodes [num_queries] (UINT32)
 *   3: Optional: Edge weights [nnz] (FLOAT32)
 *   4: Optional: Node weights [num_nodes] (FLOAT32)
 *   5: Optional: Heuristic values [num_nodes] (FLOAT32) - for A*
 *
 * Outputs:
 *   0: Target nodes [num_queries, variable_length] (UINT32)
 *   1: Optional: Distances/costs [num_queries, variable_length] (FLOAT32)
 *   2: Optional: Paths [num_queries, variable_length, path_length] (UINT32)
 *   3: Counts [num_queries] (UINT32) - number of results per query
 */

/* ============================================================================
 * CONSTRAINT SEARCH CONTRACT
 * ============================================================================ */

/**
 * Constraint optimization configuration.
 */
typedef enum qihse_optimization_goal_e {
    QIHSE_OPTIMIZE_MINIMIZE = 1,         /* Minimize objective */
    QIHSE_OPTIMIZE_MAXIMIZE = 2          /* Maximize objective */
} qihse_optimization_goal_t;

typedef enum qihse_constraint_type_e {
    QIHSE_CONSTRAINT_LINEAR = 1,         /* Linear constraints */
    QIHSE_CONSTRAINT_QUADRATIC = 2,      /* Quadratic constraints */
    QIHSE_CONSTRAINT_NONLINEAR = 3       /* Nonlinear constraints */
} qihse_constraint_type_t;

typedef struct qihse_constraint_search_config_s {
    qihse_optimization_goal_t goal;       /* Optimization goal */
    qihse_constraint_type_t constraint_type; /* Constraint type */
    uint32_t max_iterations;             /* Maximum optimization iterations */
    float tolerance;                     /* Convergence tolerance */
    float initial_temperature;           /* Simulated annealing initial temp */
    int use_quantum_inspired;            /* 1 = use RFF/superposition methods */
} qihse_constraint_search_config_t;

/**
 * Constraint search contract.
 *
 * Inputs:
 *   0: Candidate solutions [num_candidates, num_variables] (FLOAT32)
 *   1: Objective coefficients [num_variables] (FLOAT32)
 *   2: Constraint matrix [num_constraints, num_variables] (FLOAT32)
 *   3: Constraint bounds [num_constraints, 2] (FLOAT32) - [lower, upper]
 *   4: Variable bounds [num_variables, 2] (FLOAT32) - [lower, upper]
 *
 * Outputs:
 *   0: Best solution [num_variables] (FLOAT32)
 *   1: Objective value (FLOAT32)
 *   2: Constraint violations [num_constraints] (FLOAT32)
 *   3: Convergence status (UINT32)
 */

/* ============================================================================
 * QUANTUM-INSPIRED OPERATIONS CONTRACT
 * ============================================================================ */

/**
 * Random Fourier Features (RFF) configuration.
 */
typedef struct qihse_rff_config_s {
    uint32_t input_dims;                 /* Input dimensionality */
    uint32_t output_dims;                /* RFF output dimensionality */
    double gamma;                        /* RBF kernel parameter */
    uint64_t seed;                       /* Random seed */
    qihse_data_type_t dtype;             /* Data type for computation */
} qihse_rff_config_t;

/**
 * RFF projection contract.
 *
 * Inputs:
 *   0: Input vectors [batch_size, input_dims] (FLOAT32)
 *
 * Outputs:
 *   0: RFF features [batch_size, output_dims] (FLOAT32/COMPLEX64)
 */
#define QIHSE_RFF_CONTRACT_INPUTS  1
#define QIHSE_RFF_CONTRACT_OUTPUTS 1

/**
 * Superposition state configuration.
 */
typedef struct qihse_superposition_config_s {
    uint32_t num_states;                 /* Number of quantum states */
    uint32_t hilbert_dims;               /* Hilbert space dimensions */
    double noise_scale;                  /* Initialization noise scale */
    int normalize_amplitudes;            /* 1 = normalize amplitudes */
    int use_complex;                     /* 1 = complex amplitudes, 0 = real only */
} qihse_superposition_config_t;

/**
 * Superposition creation contract.
 *
 * Inputs:
 *   0: RFF features [batch_size, rff_dims] (FLOAT32/COMPLEX64)
 *
 * Outputs:
 *   0: Real amplitudes [batch_size, num_states] (FLOAT32)
 *   1: Imaginary amplitudes [batch_size, num_states] (FLOAT32)
 *   2: Phases [batch_size, num_states] (FLOAT32)
 */
#define QIHSE_SUPERPOSITION_CONTRACT_INPUTS  1
#define QIHSE_SUPERPOSITION_CONTRACT_OUTPUTS 3

/**
 * Grover amplification configuration.
 */
typedef struct qihse_amplification_config_s {
    uint32_t num_iterations;             /* Number of amplification rounds */
    double oracle_threshold;             /* Oracle decision threshold */
    int adaptive_rounds;                 /* 1 = adapt rounds based on convergence */
    int use_diffusion;                   /* 1 = include diffusion operator */
} qihse_amplification_config_t;

/**
 * Grover amplification contract.
 *
 * Inputs:
 *   0: Real amplitudes [batch_size, num_states] (FLOAT32)
 *   1: Imaginary amplitudes [batch_size, num_states] (FLOAT32)
 *   2: Phases [batch_size, num_states] (FLOAT32)
 *
 * Outputs:
 *   0: Amplified real amplitudes [batch_size, num_states] (FLOAT32)
 *   1: Amplified imaginary amplitudes [batch_size, num_states] (FLOAT32)
 *   2: Amplified phases [batch_size, num_states] (FLOAT32)
 */
#define QIHSE_AMPLIFICATION_CONTRACT_INPUTS  3
#define QIHSE_AMPLIFICATION_CONTRACT_OUTPUTS 3

/* ============================================================================
 * STANDARD SEARCHOP DEFINITIONS
 * ============================================================================ */

/**
 * Predefined search operation info structures.
 * These provide standard implementations for common operations.
 */

extern const qihse_search_op_info_t QIHSE_OP_VECTOR_KNN;
extern const qihse_search_op_info_t QIHSE_OP_VECTOR_RANGE;
extern const qihse_search_op_info_t QIHSE_OP_GRAPH_BFS;
extern const qihse_search_op_info_t QIHSE_OP_GRAPH_SHORTEST_PATH;
extern const qihse_search_op_info_t QIHSE_OP_CONSTRAINT_OPTIMIZE;
extern const qihse_search_op_info_t QIHSE_OP_RFF_PROJECT;
extern const qihse_search_op_info_t QIHSE_OP_SUPERPOSITION_CREATE;
extern const qihse_search_op_info_t QIHSE_OP_GROVER_AMPLIFY;

/* ============================================================================
 * CONTRACT VALIDATION API
 * ============================================================================ */

/**
 * Validate operation inputs against contract.
 *
 * @param op_info Operation information
 * @param inputs Input buffers
 * @param num_inputs Number of inputs
 * @return QIHSE_OK if valid, error code otherwise
 */
qihse_error_t qihse_validate_contract_inputs(
    const qihse_search_op_info_t* op_info,
    const qihse_buffer_t* inputs,
    size_t num_inputs
);

/**
 * Validate operation outputs against contract.
 *
 * @param op_info Operation information
 * @param outputs Output buffers
 * @param num_outputs Number of outputs
 * @return QIHSE_OK if valid, error code otherwise
 */
qihse_error_t qihse_validate_contract_outputs(
    const qihse_search_op_info_t* op_info,
    const qihse_buffer_t* outputs,
    size_t num_outputs
);

/**
 * Get expected input count for operation.
 *
 * @param op_type Operation type
 * @return Expected input count, or -1 if variable
 */
int qihse_get_operation_input_count(qihse_search_op_type_t op_type);

/**
 * Get expected output count for operation.
 *
 * @param op_type Operation type
 * @return Expected output count, or -1 if variable
 */
int qihse_get_operation_output_count(qihse_search_op_type_t op_type);

/* ============================================================================
 * CONTRACT COMPLIANCE TESTING
 * ============================================================================ */

/**
 * Test case for contract validation.
 */
typedef struct qihse_contract_test_case_s {
    const char* name;                    /* Test case name */
    qihse_buffer_t* inputs;              /* Input buffers */
    size_t num_inputs;                   /* Number of inputs */
    qihse_buffer_t* expected_outputs;    /* Expected outputs */
    size_t num_expected_outputs;         /* Number of expected outputs */
    qihse_error_t expected_result;       /* Expected result */
} qihse_contract_test_case_t;

/**
 * Run contract compliance tests for an operation.
 *
 * @param op_info Operation information
 * @param test_cases Test cases to run
 * @param num_test_cases Number of test cases
 * @return QIHSE_OK if all tests pass, error code otherwise
 */
qihse_error_t qihse_run_contract_tests(
    const qihse_search_op_info_t* op_info,
    const qihse_contract_test_case_t* test_cases,
    size_t num_test_cases
);

/* ============================================================================
 * OPERATION REGISTRATION API
 * ============================================================================ */

/**
 * Register a custom search operation.
 *
 * @param op_info Operation information
 * @param op Output operation handle
 * @return QIHSE_OK on success, error code otherwise
 */
qihse_error_t qihse_register_search_operation(
    const qihse_search_op_info_t* op_info,
    qihse_search_op_t* op
);

/**
 * Unregister a search operation.
 *
 * @param op Operation to unregister
 */
void qihse_unregister_search_operation(qihse_search_op_t op);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* QIHSE_SEARCHOP_H */

