#ifndef QIHSE_GRAPH_VECTOR_H
#define QIHSE_GRAPH_VECTOR_H

#include "qihse_graph_store.h"
#include "qihse_vector_db.h"
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Graph-guided vector search: find HNSW neighbors, then expand via graph edges.
 *
 * A classified-capable read primitive, so it takes an explicit authenticated
 * security context (AGENTS.md invariant 1).  A NULL user is an argument error:
 * no rows are written and errno is set to EACCES.  There is no context-free
 * form. */
size_t qihse_graph_vector_search_user(qihse_graph_t* g, qihse_vector_db_t vdb,
                                      qihse_user_t* user,
                                      const float* query, size_t dims, size_t k, size_t hops,
                                      uint64_t* out_vertex_ids, float* out_scores, size_t max_out);

/* Vector-guided traversal: only follow edges to similar, user-visible
 * vector-backed vertices. A valid active user and vector database are
 * required even when query is NULL (which disables similarity scoring). */
size_t qihse_graph_vector_traverse_user(qihse_graph_t* g, qihse_vector_db_t vdb,
                                        qihse_user_t* user,
                                        uint64_t start_vertex, const float* query, size_t dims,
                                        float similarity_threshold, size_t max_hops,
                                        uint64_t* out_vertex_ids, size_t max_out);
/* Compatibility wrapper; always fails closed with EACCES because no
 * authenticated user was supplied. */
size_t qihse_graph_vector_traverse(qihse_graph_t* g, qihse_vector_db_t vdb,
                                   uint64_t start_vertex, const float* query, size_t dims,
                                   float similarity_threshold, size_t max_hops,
                                   uint64_t* out_vertex_ids, size_t max_out);

/* Subgraph embedding: aggregate only embeddings the active user may read. */
int qihse_graph_subgraph_embedding_user(qihse_graph_t* g, qihse_vector_db_t vdb,
                                        qihse_user_t* user,
                                        const uint64_t* vertex_ids, size_t num_vertices,
                                        size_t dims, float* out_embedding);
/* Compatibility wrapper; always fails closed with EACCES. */
int qihse_graph_subgraph_embedding(qihse_graph_t* g, qihse_vector_db_t vdb,
                                   const uint64_t* vertex_ids, size_t num_vertices,
                                   size_t dims, float* out_embedding);

/* Hybrid recommendation: combine graph traversal with vector similarity */
size_t qihse_graph_vector_recommend_user(qihse_graph_t* g, qihse_vector_db_t vdb,
                                         qihse_user_t* user,
                                         uint64_t user_vertex, size_t k, size_t hops,
                                         uint64_t* out_vertex_ids, float* out_scores, size_t max_out);
/* Context-free compatibility entry points are retained for source
 * compatibility, but fail closed because these APIs can return classified
 * vector-backed graph data. Call the corresponding _user function instead. */
size_t qihse_graph_vector_recommend(qihse_graph_t* g, qihse_vector_db_t vdb,
                                    uint64_t user_vertex, size_t k, size_t hops,
                                    uint64_t* out_vertex_ids, float* out_scores, size_t max_out);

#ifdef __cplusplus
}
#endif
#endif
