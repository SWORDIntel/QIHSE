#ifndef QIHSE_HNSW_H
#define QIHSE_HNSW_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// Callback definitions
typedef float (*qihse_hnsw_distance_fn_t)(const float* v1, const float* v2, size_t dim);
typedef const float* (*qihse_hnsw_get_vector_fn_t)(void* user_context, uint32_t node_id);

// HNSW configuration parameters (ef_construction, M, M0)
typedef struct {
    uint32_t M;               // Max number of connections per element in all layers except layer 0
    uint32_t M0;              // Max number of connections per element in layer 0
    uint32_t ef_construction; // Size of the dynamic candidate list during construction
    uint32_t ef_search;       // Size of the dynamic candidate list during search
    float mult;               // Multiplier for layer generation (typically 1 / ln(M))
    
    // Callbacks for vector distance calculations
    qihse_hnsw_distance_fn_t distance_fn;
    qihse_hnsw_get_vector_fn_t get_vector_fn;
    void* user_context;       // Passed to get_vector_fn (usually the qihse_vector_db_t)
    size_t dim;               // Vector dimension
} __attribute__((aligned(64))) qihse_hnsw_params_t;


// Node links array, representing edges to neighbors
typedef struct {
    uint32_t count;           // Current number of links
    uint32_t capacity;        // Max capacity (M or M0)
    uint32_t *neighbors;      // Array of neighbor node IDs
} __attribute__((aligned(32))) qihse_hnsw_links_t;

// A single layer in the HNSW graph
typedef struct {
    int level;                // Layer level (0 is the bottom layer)
    uint32_t num_nodes;       // Number of nodes in this layer
    uint32_t links_capacity;  // Allocated size of the links array
    qihse_hnsw_links_t **links; // Array of node links in this layer, indexed by node ID
} __attribute__((aligned(64))) qihse_hnsw_layer_t;

// The HNSW index structure
typedef struct {
    qihse_hnsw_params_t params;
    int max_level;            // Maximum level currently in the graph
    uint32_t enter_point;     // Entry point node ID
    uint32_t layers_capacity; // Allocated size of the layers array
    qihse_hnsw_layer_t **layers; // Array of layers
    uint32_t num_nodes;       // Total number of nodes in the index
} __attribute__((aligned(64))) qihse_hnsw_index_t;

// Function prototypes
void hnsw_insert(qihse_hnsw_index_t *index, uint32_t node_id, const float *vector, size_t dim);
void hnsw_search_layer(qihse_hnsw_index_t *index, const float *query, uint32_t ep, int ef, int level, uint32_t *results, size_t *num_results);
void hnsw_select_neighbors(qihse_hnsw_index_t *index, const float *query, uint32_t *candidates, size_t num_candidates, uint32_t M, uint32_t *selected, size_t *num_selected);
void hnsw_destroy(qihse_hnsw_index_t *index);

#ifdef __cplusplus
}
#endif

#endif // QIHSE_HNSW_H
