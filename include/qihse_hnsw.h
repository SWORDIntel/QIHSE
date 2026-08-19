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

// 1D projection callback used by Anchor-Guided Vector Proximity Seeding.
// Returns a double scalar projection of a vector; the HNSW layer scalar-
// quantizes this to int64 and keeps a sorted anchor table indexed by the
// keystone interpolation search. If NULL, a default sum-of-components
// projection is used.
typedef double (*qihse_hnsw_projection_fn_t)(const float* v, size_t dim);

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

    // Optional 1D projection used by Anchor-Guided Vector Proximity Seeding.
    qihse_hnsw_projection_fn_t projection_fn;
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

    // --- Anchor-Guided Vector Proximity Seeding state ---
    // Sorted 1D scalar-quantized projections of every inserted node, kept in
    // ascending order. anchor_node_ids[i] is the node id whose projection is
    // anchor_projections[i]. Used by qihse_keystone_anchor_search to locate a
    // seed entry point near the query projection, reducing search hops.
    int64_t *anchor_projections; // sorted scalar-quantized projections
    uint32_t *anchor_node_ids;   // node ids in projection-sorted order
    size_t anchor_count;         // number of registered projections
    size_t anchor_capacity;      // allocated capacity of anchor tables
    bool anchor_seeding_enabled; // toggle for anchor-seeded search
    // Diagnostic counter: number of distance evaluations in the last search.
    uint64_t last_search_dist_calls;
} __attribute__((aligned(64))) qihse_hnsw_index_t;

// Function prototypes
void hnsw_insert(qihse_hnsw_index_t *index, uint32_t node_id, const float *vector, size_t dim);
void hnsw_search_layer(qihse_hnsw_index_t *index, const float *query, uint32_t ep, int ef, int level, uint32_t *results, size_t *num_results);
void hnsw_select_neighbors(qihse_hnsw_index_t *index, const float *query, uint32_t *candidates, size_t num_candidates, uint32_t M, uint32_t *selected, size_t *num_selected);
void hnsw_destroy(qihse_hnsw_index_t *index);

// --- Anchor-Guided Vector Proximity Seeding API ---

// Compute the 1D scalar-quantized (int64) projection of a vector. Uses
// params.projection_fn if set, otherwise a default sum-of-components
// projection. Scaling factor is internal and deterministic.
int64_t qihse_hnsw_compute_projection(const float *v, size_t dim,
                                       qihse_hnsw_projection_fn_t proj_fn);

// Register/refresh a node's projection in the sorted anchor table. Called
// automatically by hnsw_insert when anchor seeding state is present, but may
// also be invoked explicitly by the caller. Returns 0 on success.
int qihse_hnsw_register_projection(qihse_hnsw_index_t *index, uint32_t node_id,
                                    const float *vector, size_t dim);

// Enable/disable anchor-guided entry-point seeding for subsequent searches.
void qihse_hnsw_enable_anchor_seeding(qihse_hnsw_index_t *index, bool enable);

// Resolve a seed entry-point node id for a query by computing its 1D
// projection and using qihse_keystone_anchor_search to locate the closest
// registered anchor. Falls back to index->enter_point when disabled or empty.
uint32_t qihse_hnsw_anchor_seed_entry(qihse_hnsw_index_t *index,
                                       const float *query, size_t dim);

// Top-level k-NN search that descends the HNSW layers starting from the
// anchor-seeded entry point instead of index->enter_point. Produces up to
// `ef` result node ids in `results` (sorted ascending by distance). On
// return *num_results holds the count. Updates index->last_search_dist_calls.
void qihse_hnsw_anchor_seed_search(qihse_hnsw_index_t *index,
                                    const float *query, size_t dim,
                                    uint32_t ef, uint32_t *results,
                                    size_t *num_results);

// Free anchor-seeding state owned by the index (invoked by hnsw_destroy).
void qihse_hnsw_anchor_destroy(qihse_hnsw_index_t *index);

#ifdef __cplusplus
}
#endif

#endif // QIHSE_HNSW_H
