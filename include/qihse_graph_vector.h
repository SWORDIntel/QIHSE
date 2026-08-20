#ifndef QIHSE_GRAPH_VECTOR_H
#define QIHSE_GRAPH_VECTOR_H

#include "qihse_graph_store.h"
#include "qihse_vector_db.h"
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Graph-guided vector search: find HNSW neighbors, then expand via graph edges */
size_t qihse_graph_vector_search(qihse_graph_t* g, qihse_vector_db_t vdb,
                                 const float* query, size_t dims, size_t k, size_t hops,
                                 uint64_t* out_vertex_ids, float* out_scores, size_t max_out);

/* Vector-guided traversal: only follow edges to similar vertices */
size_t qihse_graph_vector_traverse(qihse_graph_t* g, qihse_vector_db_t vdb,
                                   uint64_t start_vertex, const float* query, size_t dims,
                                   float similarity_threshold, size_t max_hops,
                                   uint64_t* out_vertex_ids, size_t max_out);

/* Subgraph embedding: aggregate vertex embeddings in a subgraph */
int qihse_graph_subgraph_embedding(qihse_graph_t* g, qihse_vector_db_t vdb,
                                   const uint64_t* vertex_ids, size_t num_vertices,
                                   size_t dims, float* out_embedding);

/* Hybrid recommendation: combine graph traversal with vector similarity */
size_t qihse_graph_vector_recommend(qihse_graph_t* g, qihse_vector_db_t vdb,
                                    uint64_t user_vertex, size_t k, size_t hops,
                                    uint64_t* out_vertex_ids, float* out_scores, size_t max_out);

#ifdef __cplusplus
}
#endif
#endif
