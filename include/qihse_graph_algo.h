#ifndef QIHSE_GRAPH_ALGO_H
#define QIHSE_GRAPH_ALGO_H

#include "qihse_graph_store.h"
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* BFS: returns vertices in BFS order from source */
size_t qihse_graph_bfs(qihse_graph_t* g, uint64_t source, uint64_t* out, size_t max_out);

/* DFS: returns vertices in DFS order from source */
size_t qihse_graph_dfs(qihse_graph_t* g, uint64_t source, uint64_t* out, size_t max_out);

/* Dijkstra shortest path: returns path vertex IDs, 0 if no path */
size_t qihse_graph_dijkstra(qihse_graph_t* g, uint64_t source, uint64_t target,
                            uint64_t* out_path, size_t max_path);

/* A* shortest path with heuristic callback */
size_t qihse_graph_astar(qihse_graph_t* g, uint64_t source, uint64_t target,
                         double (*heuristic)(uint64_t a, uint64_t b, void* ctx),
                         void* ctx, uint64_t* out_path, size_t max_path);

/* PageRank: iterative importance scoring */
int qihse_graph_pagerank(qihse_graph_t* g, double* out_scores, size_t max_scores,
                         int max_iterations, double damping, double tolerance);

/* Connected components via union-find */
size_t qihse_graph_connected_components(qihse_graph_t* g, uint32_t* out_ids, size_t max_out);

/* Strongly connected components (Tarjan's) */
size_t qihse_graph_scc(qihse_graph_t* g, uint32_t* out_ids, size_t max_out);

/* Betweenness centrality (Brandes' algorithm) */
int qihse_graph_betweenness(qihse_graph_t* g, double* out_scores, size_t max_scores);

/* Closeness centrality */
int qihse_graph_closeness(qihse_graph_t* g, double* out_scores, size_t max_scores);

/* Degree centrality: in, out, total */
int qihse_graph_degree_centrality(qihse_graph_t* g, int64_t* out_in, int64_t* out_out, int64_t* out_total, size_t max_out);

/* Triangle counting */
uint64_t qihse_graph_triangle_count(qihse_graph_t* g);

/* Cycle detection: returns 1 if cycle exists, 0 if not */
int qihse_graph_has_cycle(qihse_graph_t* g);

/* Topological sort: returns vertices in topo order, 0 if cycle exists */
size_t qihse_graph_topo_sort(qihse_graph_t* g, uint64_t* out, size_t max_out);

/* Jaccard similarity between two vertices' neighborhoods */
double qihse_graph_jaccard(qihse_graph_t* g, uint64_t a, uint64_t b);

/* All-pairs shortest path (Floyd-Warshall, for small graphs) */
int qihse_graph_all_pairs_shortest(qihse_graph_t* g, double* out_dist, size_t max_n);

#ifdef __cplusplus
}
#endif
#endif
