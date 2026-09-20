#include "qihse_graph_vector.h"
#include "qihse_arena.h"
#include "backends/cpu/qihse_cpu_distance.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

/* Simple visited set */
typedef struct { uint64_t* ids; size_t count; size_t cap; } visited_t;
static void vis_init(visited_t* v) { v->cap = 256; v->count = 0; v->ids = malloc(v->cap * sizeof(uint64_t)); }
static void vis_free(visited_t* v) { free(v->ids); }
static int vis_has(visited_t* v, uint64_t id) { for (size_t i = 0; i < v->count; i++) if (v->ids[i] == id) return 1; return 0; }
static void vis_add(visited_t* v, uint64_t id) {
    if (vis_has(v, id)) return;
    if (v->count >= v->cap) { v->cap *= 2; v->ids = realloc(v->ids, v->cap * sizeof(uint64_t)); }
    v->ids[v->count++] = id;
}

/* Scored vertex list */
typedef struct { uint64_t id; float score; } scored_vertex_t;
static void sv_push(scored_vertex_t** arr, size_t* n, size_t* cap, uint64_t id, float score) {
    if (*n >= *cap) { *cap = *cap ? *cap * 2 : 16; *arr = realloc(*arr, *cap * sizeof(scored_vertex_t)); }
    (*arr)[*n].id = id; (*arr)[*n].score = score; (*n)++;
}

/* Graph-guided vector search.  This is a classified-capable read primitive, so
 * it requires an explicit authenticated context and has no context-free form
 * (AGENTS.md invariant 1): a NULL principal yields no rows and errno = EACCES
 * rather than being replaced by a default identity. */
size_t qihse_graph_vector_search_user(qihse_graph_t* g, qihse_vector_db_t vdb,
                                      qihse_user_t* user,
                                      const float* query, size_t dims, size_t k, size_t hops,
                                      uint64_t* out_vertex_ids, float* out_scores, size_t max_out) {
    if (!user) { errno = EACCES; return 0; }
    if (!g || !vdb || !query || !out_vertex_ids || max_out == 0) return 0;

    /* Step 1: HNSW search to get initial nearest neighbors */
    qihse_vector_query_t vq;
    memset(&vq, 0, sizeof(vq));
    vq.query_vector = query;
    vq.vector_dims = dims;
    vq.top_k = k;
    vq.user = user;

    qihse_vector_result_t* results = malloc(k * sizeof(qihse_vector_result_t));
    if (!results) return 0;
    int nresults = qihse_vector_db_search(vdb, &vq, results, k);
    if (nresults < 0) nresults = 0;
    
    /* Step 2: Expand via graph edges */
    visited_t visited; vis_init(&visited);
    scored_vertex_t* scored = NULL; size_t nscored = 0, scap = 0;
    
    for (int i = 0; i < nresults; i++) {
        uint64_t vid = results[i].id;
        if (vis_has(&visited, vid)) continue;
        vis_add(&visited, vid);
        sv_push(&scored, &nscored, &scap, vid, results[i].score);
        
        /* BFS expand for `hops` levels */
        uint64_t* frontier = malloc(256 * sizeof(uint64_t));
        size_t fcount = 1; frontier[0] = vid;
        for (size_t h = 0; h < hops && fcount > 0; h++) {
            uint64_t* next_frontier = malloc(256 * sizeof(uint64_t));
            size_t next_count = 0;
            for (size_t f = 0; f < fcount; f++) {
                graph_adj_t adj[64];
                size_t nn = qihse_graph_get_neighbors(g, frontier[f], GRAPH_DIR_BOTH, NULL, adj, 64);
                for (size_t j = 0; j < nn; j++) {
                    uint64_t nb = adj[j].neighbor_id;
                    if (!vis_has(&visited, nb)) {
                        vis_add(&visited, nb);
                        /* Score: decay with hop distance */
                        float score = results[i].score * (float)(1.0 / (1.0 + (h + 1)));
                        sv_push(&scored, &nscored, &scap, nb, score);
                        if (next_count < 256) next_frontier[next_count++] = nb;
                    }
                }
            }
            free(frontier); frontier = next_frontier; fcount = next_count;
        }
        free(frontier);
    }
    
    /* Step 3: Sort by score (simple insertion sort for small arrays) */
    for (size_t i = 1; i < nscored; i++) {
        scored_vertex_t key = scored[i];
        size_t j = i;
        while (j > 0 && scored[j-1].score < key.score) { scored[j] = scored[j-1]; j--; }
        scored[j] = key;
    }
    
    /* Step 4: Output top max_out */
    size_t out_count = (nscored < max_out) ? nscored : max_out;
    for (size_t i = 0; i < out_count; i++) {
        out_vertex_ids[i] = scored[i].id;
        if (out_scores) out_scores[i] = scored[i].score;
    }
    
    free(scored); free(results); vis_free(&visited);
    return out_count;
}

/* Vector-guided traversal */
size_t qihse_graph_vector_traverse(qihse_graph_t* g, qihse_vector_db_t vdb,
                                   uint64_t start_vertex, const float* query, size_t dims,
                                   float similarity_threshold, size_t max_hops,
                                   uint64_t* out_vertex_ids, size_t max_out) {
    if (!g || !out_vertex_ids || max_out == 0) return 0;
    
    visited_t visited; vis_init(&visited);
    vis_add(&visited, start_vertex);
    
    uint64_t* frontier = malloc(256 * sizeof(uint64_t));
    size_t fcount = 1; frontier[0] = start_vertex;
    size_t out_count = 0;
    
    if (out_count < max_out) out_vertex_ids[out_count++] = start_vertex;
    
    for (size_t h = 0; h < max_hops && fcount > 0; h++) {
        uint64_t* next_frontier = malloc(256 * sizeof(uint64_t));
        size_t next_count = 0;
        for (size_t f = 0; f < fcount; f++) {
            graph_adj_t adj[64];
            size_t nn = qihse_graph_get_neighbors(g, frontier[f], GRAPH_DIR_BOTH, NULL, adj, 64);
            for (size_t j = 0; j < nn; j++) {
                uint64_t nb = adj[j].neighbor_id;
                if (vis_has(&visited, nb)) continue;
                /* Check vector similarity if vdb available: fetch the
                 * neighbour's vector and compare against the query.  A
                 * neighbour whose vector cannot be fetched is NOT accepted —
                 * "only follow edges to similar vertices" cannot be verified
                 * for it, so the filter fails closed rather than accepting. */
                if (vdb && query && dims > 0) {
                    float* nbv = (float*)malloc(dims * sizeof(float));
                    if (!nbv) continue;
                    size_t nb_dims = 0;
                    bool got = qihse_vector_db_get_vector_by_id(vdb, nb, nbv,
                                                              &nb_dims);
                    float score = -1.0f;
                    if (got && nb_dims == dims)
                        score = qihse_distance_cosine(query, nbv, dims);
                    free(nbv);
                    if (score < similarity_threshold) continue;
                }
                vis_add(&visited, nb);
                if (out_count < max_out) out_vertex_ids[out_count++] = nb;
                if (next_count < 256) next_frontier[next_count++] = nb;
            }
        }
        free(frontier); frontier = next_frontier; fcount = next_count;
    }
    free(frontier); vis_free(&visited);
    return out_count;
}

/* Subgraph embedding: mean of the member vertices' embeddings.  A vertex
 * whose vector cannot be fetched (no embedding, dimension mismatch) is
 * skipped rather than folded in as a zero vector — a zero would bias the
 * mean toward the origin for no reason.  If NO vertex has a vector the
 * call fails: an all-zero "embedding" is not a subgraph embedding. */
int qihse_graph_subgraph_embedding(qihse_graph_t* g, qihse_vector_db_t vdb,
                                   const uint64_t* vertex_ids, size_t num_vertices,
                                   size_t dims, float* out_embedding) {
    if (!g || !vdb || !vertex_ids || !out_embedding || dims == 0) return -1;
    memset(out_embedding, 0, dims * sizeof(float));
    float* buf = (float*)malloc(dims * sizeof(float));
    if (!buf) return -1;
    size_t valid = 0;
    for (size_t i = 0; i < num_vertices; i++) {
        size_t got_dims = 0;
        if (!qihse_vector_db_get_vector_by_id(vdb, vertex_ids[i], buf,
                                              &got_dims)) continue;
        if (got_dims != dims) continue;
        for (size_t d = 0; d < dims; d++) out_embedding[d] += buf[d];
        valid++;
    }
    free(buf);
    if (valid == 0) return -1;
    for (size_t d = 0; d < dims; d++) out_embedding[d] /= (float)valid;
    return 0;
}

/* Hybrid recommendation */
size_t qihse_graph_vector_recommend(qihse_graph_t* g, qihse_vector_db_t vdb,
                                    uint64_t user_vertex, size_t k, size_t hops,
                                    uint64_t* out_vertex_ids, float* out_scores, size_t max_out) {
    if (!g || !out_vertex_ids || max_out == 0) return 0;
    
    /* Step 1: Get graph neighbors of user_vertex */
    visited_t visited; vis_init(&visited);
    vis_add(&visited, user_vertex);
    
    uint64_t* frontier = malloc(256 * sizeof(uint64_t));
    size_t fcount = 1; frontier[0] = user_vertex;
    scored_vertex_t* candidates = NULL; size_t ncand = 0, ccap = 0;
    
    for (size_t h = 0; h < hops && fcount > 0; h++) {
        uint64_t* next_frontier = malloc(256 * sizeof(uint64_t));
        size_t next_count = 0;
        for (size_t f = 0; f < fcount; f++) {
            graph_adj_t adj[64];
            size_t nn = qihse_graph_get_neighbors(g, frontier[f], GRAPH_DIR_BOTH, NULL, adj, 64);
            for (size_t j = 0; j < nn; j++) {
                uint64_t nb = adj[j].neighbor_id;
                if (!vis_has(&visited, nb)) {
                    vis_add(&visited, nb);
                    /* Score: closer hops = higher score */
                    float score = 1.0f / (float)(h + 1);
                    sv_push(&candidates, &ncand, &ccap, nb, score);
                    if (next_count < 256) next_frontier[next_count++] = nb;
                }
            }
        }
        free(frontier); frontier = next_frontier; fcount = next_count;
    }
    free(frontier);
    
    /* Step 2: Sort by score */
    for (size_t i = 1; i < ncand; i++) {
        scored_vertex_t key = candidates[i];
        size_t j = i;
        while (j > 0 && candidates[j-1].score < key.score) { candidates[j] = candidates[j-1]; j--; }
        candidates[j] = key;
    }
    
    /* Step 3: Output top k */
    size_t out_count = (ncand < k) ? ncand : k;
    if (out_count > max_out) out_count = max_out;
    for (size_t i = 0; i < out_count; i++) {
        out_vertex_ids[i] = candidates[i].id;
        if (out_scores) out_scores[i] = candidates[i].score;
    }
    
    free(candidates); vis_free(&visited);
    (void)vdb;
    return out_count;
}
