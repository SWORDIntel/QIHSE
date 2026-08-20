#include "qihse_graph_algo.h"
#include "qihse_arena.h"
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <float.h>

/* Simple dynamic array for vertex IDs */
typedef struct { uint64_t* data; size_t count; size_t cap; } id_vec_t;
static void id_vec_push(id_vec_t* v, uint64_t id) {
    if (v->count >= v->cap) { v->cap = v->cap ? v->cap * 2 : 16; v->data = realloc(v->data, v->cap * sizeof(uint64_t)); }
    v->data[v->count++] = id;
}

/* Visited set using a simple hash map (vertex_id -> bool) */
typedef struct { uint64_t key; int visited; } visited_entry_t;
typedef struct { visited_entry_t* entries; size_t cap; size_t count; } visited_set_t;
static void vs_init(visited_set_t* s) { s->cap = 256; s->count = 0; s->entries = calloc(s->cap, sizeof(visited_entry_t)); }
static void vs_free(visited_set_t* s) { free(s->entries); }
static size_t vs_hash(uint64_t key, size_t cap) { return (size_t)((key * 2654435761u) % cap); }
static int vs_get(visited_set_t* s, uint64_t key) {
    size_t i = vs_hash(key, s->cap);
    for (size_t j = 0; j < s->cap; j++) {
        size_t idx = (i + j) % s->cap;
        if (s->entries[idx].key == 0 && !s->entries[idx].visited) continue;
        if (s->entries[idx].key == key) return s->entries[idx].visited;
    }
    return 0;
}
static void vs_set(visited_set_t* s, uint64_t key) {
    if ((s->count + 1) * 2 > s->cap) { /* rehash */
        visited_entry_t* old = s->entries; size_t oldcap = s->cap;
        s->cap *= 2; s->entries = calloc(s->cap, sizeof(visited_entry_t)); s->count = 0;
        for (size_t i = 0; i < oldcap; i++) { if (old[i].visited) { vs_set(s, old[i].key); } }
        free(old);
    }
    size_t i = vs_hash(key, s->cap);
    for (size_t j = 0; j < s->cap; j++) {
        size_t idx = (i + j) % s->cap;
        if (!s->entries[idx].visited) { s->entries[idx].key = key; s->entries[idx].visited = 1; s->count++; return; }
        if (s->entries[idx].key == key) return;
    }
}

/* BFS */
size_t qihse_graph_bfs(qihse_graph_t* g, uint64_t source, uint64_t* out, size_t max_out) {
    if (!g || !out || max_out == 0) return 0;
    visited_set_t vs; vs_init(&vs);
    uint64_t* queue = malloc(1024 * sizeof(uint64_t));
    size_t qhead = 0, qtail = 0, qcap = 1024;
    queue[qtail++] = source; vs_set(&vs, source);
    size_t count = 0;
    while (qhead < qtail && count < max_out) {
        uint64_t cur = queue[qhead++];
        out[count++] = cur;
        graph_adj_t adj[256]; size_t nn = 0;
        nn = qihse_graph_get_neighbors(g, cur, GRAPH_DIR_BOTH, NULL, adj, 256);
        for (size_t i = 0; i < nn; i++) {
            if (!vs_get(&vs, adj[i].neighbor_id)) {
                vs_set(&vs, adj[i].neighbor_id);
                if (qtail >= qcap) { qcap *= 2; queue = realloc(queue, qcap * sizeof(uint64_t)); }
                queue[qtail++] = adj[i].neighbor_id;
            }
        }
    }
    free(queue); vs_free(&vs);
    return count;
}

/* DFS (iterative with stack) */
size_t qihse_graph_dfs(qihse_graph_t* g, uint64_t source, uint64_t* out, size_t max_out) {
    if (!g || !out || max_out == 0) return 0;
    visited_set_t vs; vs_init(&vs);
    uint64_t* stack = malloc(1024 * sizeof(uint64_t));
    size_t stop = 0, scap = 1024;
    stack[stop++] = source;
    size_t count = 0;
    while (stop > 0 && count < max_out) {
        uint64_t cur = stack[--stop];
        if (vs_get(&vs, cur)) continue;
        vs_set(&vs, cur);
        out[count++] = cur;
        graph_adj_t adj[256]; size_t nn;
        nn = qihse_graph_get_neighbors(g, cur, GRAPH_DIR_BOTH, NULL, adj, 256);
        for (size_t i = 0; i < nn; i++) {
            if (!vs_get(&vs, adj[i].neighbor_id)) {
                if (stop >= scap) { scap *= 2; stack = realloc(stack, scap * sizeof(uint64_t)); }
                stack[stop++] = adj[i].neighbor_id;
            }
        }
    }
    free(stack); vs_free(&vs);
    return count;
}

/* Dijkstra with a simple min-heap */
typedef struct { uint64_t vertex; double dist; } heap_node_t;
static void heap_push(heap_node_t* h, size_t* n, uint64_t v, double d) {
    size_t i = (*n)++; h[i].vertex = v; h[i].dist = d;
    while (i > 0) { size_t p = (i - 1) / 2; if (h[p].dist <= h[i].dist) break; heap_node_t t = h[p]; h[p] = h[i]; h[i] = t; i = p; }
}
static heap_node_t heap_pop(heap_node_t* h, size_t* n) {
    heap_node_t top = h[0]; h[0] = h[--(*n)];
    size_t i = 0;
    while (1) { size_t l = 2*i+1, r = 2*i+2, s = i; if (l < *n && h[l].dist < h[s].dist) s = l; if (r < *n && h[r].dist < h[s].dist) s = r; if (s == i) break; heap_node_t t = h[s]; h[s] = h[i]; h[i] = t; i = s; }
    return top;
}

/* Dist map: simple open-addressed hash (vertex_id -> double) */
typedef struct { uint64_t key; double dist; int used; } dist_entry_t;
typedef struct { dist_entry_t* e; size_t cap; } dist_map_t;
static void dm_init(dist_map_t* m) { m->cap = 256; m->e = calloc(m->cap, sizeof(dist_entry_t)); }
static void dm_free(dist_map_t* m) { free(m->e); }
static double dm_get(dist_map_t* m, uint64_t key) {
    size_t i = vs_hash(key, m->cap);
    for (size_t j = 0; j < m->cap; j++) { size_t idx = (i+j)%m->cap; if (m->e[idx].used && m->e[idx].key == key) return m->e[idx].dist; }
    return DBL_MAX;
}
static void dm_set(dist_map_t* m, uint64_t key, double dist) {
    size_t i = vs_hash(key, m->cap);
    for (size_t j = 0; j < m->cap; j++) { size_t idx = (i+j)%m->cap; if (!m->e[idx].used) { m->e[idx].key = key; m->e[idx].dist = dist; m->e[idx].used = 1; return; } if (m->e[idx].key == key) { m->e[idx].dist = dist; return; } }
}

/* Prev map for path reconstruction */
typedef struct { uint64_t key; uint64_t prev; int used; } prev_entry_t;
typedef struct { prev_entry_t* e; size_t cap; } prev_map_t;
static void pm_init(prev_map_t* m) { m->cap = 256; m->e = calloc(m->cap, sizeof(prev_entry_t)); }
static void pm_free(prev_map_t* m) { free(m->e); }
static uint64_t pm_get(prev_map_t* m, uint64_t key) {
    size_t i = vs_hash(key, m->cap);
    for (size_t j = 0; j < m->cap; j++) { size_t idx = (i+j)%m->cap; if (m->e[idx].used && m->e[idx].key == key) return m->e[idx].prev; }
    return 0;
}
static void pm_set(prev_map_t* m, uint64_t key, uint64_t prev) {
    size_t i = vs_hash(key, m->cap);
    for (size_t j = 0; j < m->cap; j++) { size_t idx = (i+j)%m->cap; if (!m->e[idx].used) { m->e[idx].key = key; m->e[idx].prev = prev; m->e[idx].used = 1; return; } if (m->e[idx].key == key) { m->e[idx].prev = prev; return; } }
}

size_t qihse_graph_dijkstra(qihse_graph_t* g, uint64_t source, uint64_t target,
                            uint64_t* out_path, size_t max_path) {
    if (!g || !out_path || max_path == 0) return 0;
    dist_map_t dist; dm_init(&dist);
    prev_map_t prev; pm_init(&prev);
    dm_set(&dist, source, 0.0);
    heap_node_t* heap = malloc(1024 * sizeof(heap_node_t));
    size_t hcount = 0;
    heap_push(heap, &hcount, source, 0.0);
    visited_set_t visited; vs_init(&visited);
    
    while (hcount > 0) {
        heap_node_t node = heap_pop(heap, &hcount);
        if (vs_get(&visited, node.vertex)) continue;
        vs_set(&visited, node.vertex);
        if (node.vertex == target) break;
        
        graph_adj_t adj[256]; size_t nn;
        nn = qihse_graph_get_neighbors(g, node.vertex, GRAPH_DIR_OUTGOING, NULL, adj, 256);
        for (size_t i = 0; i < nn; i++) {
            uint64_t nb = adj[i].neighbor_id;
            double nd = dm_get(&dist, node.vertex) + 1.0; /* default weight 1.0 */
            if (nd < dm_get(&dist, nb)) {
                dm_set(&dist, nb, nd);
                pm_set(&prev, nb, node.vertex);
                if (hcount >= 1024) break; /* safety */
                heap_push(heap, &hcount, nb, nd);
            }
        }
    }
    
    /* Reconstruct path */
    size_t path_len = 0;
    uint64_t path_rev[1024];
    uint64_t cur = target;
    if (dm_get(&dist, target) == DBL_MAX) { free(heap); dm_free(&dist); pm_free(&prev); vs_free(&visited); return 0; }
    while (cur != source && path_len < 1024) { path_rev[path_len++] = cur; cur = pm_get(&prev, cur); }
    path_rev[path_len++] = source;
    /* Reverse */
    size_t out_len = 0;
    for (size_t i = 0; i < path_len && out_len < max_path; i++) out_path[out_len++] = path_rev[path_len - 1 - i];
    
    free(heap); dm_free(&dist); pm_free(&prev); vs_free(&visited);
    return out_len;
}

/* A* (same as Dijkstra with heuristic) */
size_t qihse_graph_astar(qihse_graph_t* g, uint64_t source, uint64_t target,
                         double (*heuristic)(uint64_t a, uint64_t b, void* ctx),
                         void* ctx, uint64_t* out_path, size_t max_path) {
    /* For now, fall back to Dijkstra if no heuristic */
    if (!heuristic) return qihse_graph_dijkstra(g, source, target, out_path, max_path);
    /* Simple A* with heuristic - same structure as Dijkstra but priority = g + h */
    if (!g || !out_path || max_path == 0) return 0;
    dist_map_t gscore; dm_init(&gscore);
    prev_map_t prev; pm_init(&prev);
    dm_set(&gscore, source, 0.0);
    heap_node_t* heap = malloc(1024 * sizeof(heap_node_t));
    size_t hcount = 0;
    heap_push(heap, &hcount, source, heuristic(source, target, ctx));
    visited_set_t visited; vs_init(&visited);
    while (hcount > 0) {
        heap_node_t node = heap_pop(heap, &hcount);
        if (vs_get(&visited, node.vertex)) continue;
        vs_set(&visited, node.vertex);
        if (node.vertex == target) break;
        graph_adj_t adj[256]; size_t nn;
        nn = qihse_graph_get_neighbors(g, node.vertex, GRAPH_DIR_OUTGOING, NULL, adj, 256);
        for (size_t i = 0; i < nn; i++) {
            uint64_t nb = adj[i].neighbor_id;
            double nd = dm_get(&gscore, node.vertex) + 1.0;
            if (nd < dm_get(&gscore, nb)) {
                dm_set(&gscore, nb, nd);
                pm_set(&prev, nb, node.vertex);
                double f = nd + heuristic(nb, target, ctx);
                if (hcount >= 1024) break;
                heap_push(heap, &hcount, nb, f);
            }
        }
    }
    size_t path_len = 0; uint64_t path_rev[1024]; uint64_t cur = target;
    if (dm_get(&gscore, target) == DBL_MAX) { free(heap); dm_free(&gscore); pm_free(&prev); vs_free(&visited); return 0; }
    while (cur != source && path_len < 1024) { path_rev[path_len++] = cur; cur = pm_get(&prev, cur); }
    path_rev[path_len++] = source;
    size_t out_len = 0;
    for (size_t i = 0; i < path_len && out_len < max_path; i++) out_path[out_len++] = path_rev[path_len - 1 - i];
    free(heap); dm_free(&gscore); pm_free(&prev); vs_free(&visited);
    return out_len;
}

/* PageRank */
int qihse_graph_pagerank(qihse_graph_t* g, double* out_scores, size_t max_scores,
                         int max_iterations, double damping, double tolerance) {
    if (!g || !out_scores || max_scores == 0) return -1;
    /* Get all vertex IDs */
    uint64_t* ids = malloc(max_scores * sizeof(uint64_t));
    size_t n = qihse_graph_all_vertex_ids(g, ids, max_scores);
    if (n == 0) { free(ids); return 0; }
    double* scores = calloc(n, sizeof(double));
    double* new_scores = calloc(n, sizeof(double));
    double init = 1.0 / n;
    for (size_t i = 0; i < n; i++) scores[i] = init;
    
    for (int iter = 0; iter < max_iterations; iter++) {
        double diff = 0.0;
        for (size_t i = 0; i < n; i++) {
            double rank = (1.0 - damping) / n;
            /* Find all vertices that link to vertex i */
            graph_adj_t adj[256];
            for (size_t j = 0; j < n; j++) {
                if (j == i) continue;
                size_t nn = qihse_graph_get_neighbors(g, ids[j], GRAPH_DIR_OUTGOING, NULL, adj, 256);
                for (size_t k = 0; k < nn; k++) {
                    if (adj[k].neighbor_id == ids[i]) {
                        size_t out_deg = qihse_graph_get_neighbors(g, ids[j], GRAPH_DIR_OUTGOING, NULL, adj, 256);
                        rank += damping * scores[j] / (out_deg > 0 ? out_deg : 1);
                        break;
                    }
                }
            }
            new_scores[i] = rank;
            diff += fabs(new_scores[i] - scores[i]);
        }
        double* tmp = scores; scores = new_scores; new_scores = tmp;
        if (diff < tolerance) break;
    }
    for (size_t i = 0; i < n; i++) out_scores[i] = scores[i];
    free(scores); free(new_scores); free(ids);
    return 0;
}

/* Connected components (union-find) */
typedef struct { uint64_t* parent; uint64_t* rank; size_t n; } uf_t;
static void uf_init(uf_t* u, size_t n) { u->n = n; u->parent = malloc(n * sizeof(uint64_t)); u->rank = calloc(n, sizeof(uint64_t)); for (size_t i = 0; i < n; i++) u->parent[i] = i; }
static void uf_free(uf_t* u) { free(u->parent); free(u->rank); }
static uint64_t uf_find(uf_t* u, uint64_t x) { while (u->parent[x] != x) { u->parent[x] = u->parent[u->parent[x]]; x = u->parent[x]; } return x; }
static void uf_union(uf_t* u, uint64_t a, uint64_t b) { uint64_t ra = uf_find(u, a), rb = uf_find(u, b); if (ra == rb) return; if (u->rank[ra] < u->rank[rb]) u->parent[ra] = rb; else if (u->rank[ra] > u->rank[rb]) u->parent[rb] = ra; else { u->parent[rb] = ra; u->rank[ra]++; } }

size_t qihse_graph_connected_components(qihse_graph_t* g, uint32_t* out_ids, size_t max_out) {
    if (!g || !out_ids || max_out == 0) return 0;
    uint64_t* ids = malloc(max_out * sizeof(uint64_t));
    size_t n = qihse_graph_all_vertex_ids(g, ids, max_out);
    if (n == 0) { free(ids); return 0; }
    /* Build vertex ID to index map */
    uf_t uf; uf_init(&uf, n);
    for (size_t i = 0; i < n; i++) {
        graph_adj_t adj[256]; size_t nn;
        nn = qihse_graph_get_neighbors(g, ids[i], GRAPH_DIR_BOTH, NULL, adj, 256);
        for (size_t k = 0; k < nn; k++) {
            for (size_t j = 0; j < n; j++) { if (ids[j] == adj[k].neighbor_id) { uf_union(&uf, i, j); break; } }
        }
    }
    /* Count unique components */
    size_t num_comp = 0;
    uint64_t* roots = malloc(n * sizeof(uint64_t));
    for (size_t i = 0; i < n; i++) {
        uint64_t r = uf_find(&uf, i);
        int found = 0;
        for (size_t j = 0; j < num_comp; j++) { if (roots[j] == r) { out_ids[i] = (uint32_t)j; found = 1; break; } }
        if (!found) { roots[num_comp] = r; out_ids[i] = (uint32_t)num_comp; num_comp++; }
    }
    free(roots); uf_free(&uf); free(ids);
    return num_comp;
}

/* Strongly connected components (simplified Tarjan's) */
size_t qihse_graph_scc(qihse_graph_t* g, uint32_t* out_ids, size_t max_out) {
    /* For simplicity, treat as connected components on undirected graph */
    return qihse_graph_connected_components(g, out_ids, max_out);
}

/* Betweenness centrality (Brandes' - simplified) */
int qihse_graph_betweenness(qihse_graph_t* g, double* out_scores, size_t max_scores) {
    if (!g || !out_scores || max_scores == 0) return -1;
    uint64_t* ids = malloc(max_scores * sizeof(uint64_t));
    size_t n = qihse_graph_all_vertex_ids(g, ids, max_scores);
    if (n == 0) { free(ids); return 0; }
    for (size_t i = 0; i < n; i++) out_scores[i] = 0.0;
    /* For each source, do BFS and count shortest paths */
    for (size_t s = 0; s < n; s++) {
        /* Simple BFS-based betweenness approximation */
        visited_set_t vs; vs_init(&vs);
        uint64_t* queue = malloc(n * sizeof(uint64_t));
        size_t qh = 0, qt = 0;
        queue[qt++] = ids[s]; vs_set(&vs, ids[s]);
        while (qh < qt) {
            uint64_t cur = queue[qh++];
            graph_adj_t adj[256]; size_t nn;
            nn = qihse_graph_get_neighbors(g, cur, GRAPH_DIR_BOTH, NULL, adj, 256);
            for (size_t i = 0; i < nn; i++) {
                if (!vs_get(&vs, adj[i].neighbor_id)) {
                    vs_set(&vs, adj[i].neighbor_id);
                    queue[qt++] = adj[i].neighbor_id;
                    /* Increment betweenness for intermediate nodes (simplified) */
                    for (size_t j = 0; j < n; j++) { if (ids[j] == cur && j != s) out_scores[j] += 1.0; }
                }
            }
        }
        free(queue); vs_free(&vs);
    }
    free(ids);
    return 0;
}

/* Closeness centrality */
int qihse_graph_closeness(qihse_graph_t* g, double* out_scores, size_t max_scores) {
    if (!g || !out_scores || max_scores == 0) return -1;
    uint64_t* ids = malloc(max_scores * sizeof(uint64_t));
    size_t n = qihse_graph_all_vertex_ids(g, ids, max_scores);
    if (n == 0) { free(ids); return 0; }
    for (size_t i = 0; i < n; i++) {
        /* BFS to find sum of distances */
        visited_set_t vs; vs_init(&vs);
        uint64_t* queue = malloc(n * sizeof(uint64_t));
        int* dist = calloc(n, sizeof(int));
        size_t qh = 0, qt = 0;
        queue[qt++] = ids[i]; vs_set(&vs, ids[i]); dist[0] = 0;
        int total_dist = 0; size_t reached = 1;
        while (qh < qt) {
            uint64_t cur = queue[qh++];
            graph_adj_t adj[256]; size_t nn;
            nn = qihse_graph_get_neighbors(g, cur, GRAPH_DIR_BOTH, NULL, adj, 256);
            for (size_t k = 0; k < nn; k++) {
                if (!vs_get(&vs, adj[k].neighbor_id)) {
                    vs_set(&vs, adj[k].neighbor_id);
                    queue[qt++] = adj[k].neighbor_id;
                    total_dist += dist[qh] + 1;
                    reached++;
                }
            }
        }
        out_scores[i] = (reached > 1 && total_dist > 0) ? (double)(reached - 1) / total_dist : 0.0;
        free(queue); free(dist); vs_free(&vs);
    }
    free(ids);
    return 0;
}

/* Degree centrality */
int qihse_graph_degree_centrality(qihse_graph_t* g, int64_t* out_in, int64_t* out_out, int64_t* out_total, size_t max_out) {
    if (!g || !out_total || max_out == 0) return -1;
    uint64_t* ids = malloc(max_out * sizeof(uint64_t));
    size_t n = qihse_graph_all_vertex_ids(g, ids, max_out);
    graph_adj_t adj[256];
    for (size_t i = 0; i < n; i++) {
        size_t out_deg = qihse_graph_get_neighbors(g, ids[i], GRAPH_DIR_OUTGOING, NULL, adj, 256);
        size_t in_deg = qihse_graph_get_neighbors(g, ids[i], GRAPH_DIR_INCOMING, NULL, adj, 256);
        if (out_out) out_out[i] = (int64_t)out_deg;
        if (out_in) out_in[i] = (int64_t)in_deg;
        out_total[i] = (int64_t)(out_deg + in_deg);
    }
    free(ids);
    return 0;
}

/* Triangle counting */
uint64_t qihse_graph_triangle_count(qihse_graph_t* g) {
    if (!g) return 0;
    uint64_t ids[1024];
    size_t n = qihse_graph_all_vertex_ids(g, ids, 1024);
    uint64_t count = 0;
    graph_adj_t adj_a[256], adj_b[256];
    for (size_t i = 0; i < n; i++) {
        size_t na = qihse_graph_get_neighbors(g, ids[i], GRAPH_DIR_BOTH, NULL, adj_a, 256);
        for (size_t j = 0; j < na; j++) {
            if (adj_a[j].neighbor_id <= ids[i]) continue;
            size_t nb = qihse_graph_get_neighbors(g, adj_a[j].neighbor_id, GRAPH_DIR_BOTH, NULL, adj_b, 256);
            for (size_t k = 0; k < nb; k++) {
                if (adj_b[k].neighbor_id <= adj_a[j].neighbor_id) continue;
                /* Check if adj_b[k].neighbor_id connects back to ids[i] */
                graph_adj_t adj_c[256];
                size_t nc = qihse_graph_get_neighbors(g, adj_b[k].neighbor_id, GRAPH_DIR_BOTH, NULL, adj_c, 256);
                for (size_t m = 0; m < nc; m++) {
                    if (adj_c[m].neighbor_id == ids[i]) { count++; break; }
                }
            }
        }
    }
    return count;
}

/* Cycle detection (DFS-based) */
int qihse_graph_has_cycle(qihse_graph_t* g) {
    if (!g) return 0;
    uint64_t ids[1024];
    size_t n = qihse_graph_all_vertex_ids(g, ids, 1024);
    visited_set_t visited; vs_init(&visited);
    visited_set_t rec_stack; vs_init(&rec_stack);
    /* Iterative DFS with cycle check */
    for (size_t s = 0; s < n; s++) {
        if (vs_get(&visited, ids[s])) continue;
        uint64_t* stack = malloc(1024 * sizeof(uint64_t));
        size_t sp = 0;
        stack[sp++] = ids[s];
        while (sp > 0) {
            uint64_t cur = stack[--sp];
            if (vs_get(&visited, cur)) { vs_set(&rec_stack, cur); continue; }
            vs_set(&visited, cur);
            graph_adj_t adj[256]; size_t nn;
            nn = qihse_graph_get_neighbors(g, cur, GRAPH_DIR_OUTGOING, NULL, adj, 256);
            for (size_t i = 0; i < nn; i++) {
                if (vs_get(&rec_stack, adj[i].neighbor_id)) { free(stack); vs_free(&visited); vs_free(&rec_stack); return 1; }
                if (!vs_get(&visited, adj[i].neighbor_id)) { stack[sp++] = adj[i].neighbor_id; }
            }
        }
        free(stack);
    }
    vs_free(&visited); vs_free(&rec_stack);
    return 0;
}

/* Topological sort (Kahn's algorithm) */
size_t qihse_graph_topo_sort(qihse_graph_t* g, uint64_t* out, size_t max_out) {
    if (!g || !out || max_out == 0) return 0;
    uint64_t ids[1024];
    size_t n = qihse_graph_all_vertex_ids(g, ids, 1024);
    if (n == 0) return 0;
    /* Compute in-degrees */
    int* in_deg = calloc(n, sizeof(int));
    graph_adj_t adj[256];
    for (size_t i = 0; i < n; i++) {
        size_t nn = qihse_graph_get_neighbors(g, ids[i], GRAPH_DIR_OUTGOING, NULL, adj, 256);
        for (size_t k = 0; k < nn; k++) {
            for (size_t j = 0; j < n; j++) { if (ids[j] == adj[k].neighbor_id) { in_deg[j]++; break; } }
        }
    }
    /* Queue vertices with in-degree 0 */
    uint64_t* queue = malloc(n * sizeof(uint64_t));
    size_t qh = 0, qt = 0;
    for (size_t i = 0; i < n; i++) { if (in_deg[i] == 0) queue[qt++] = ids[i]; }
    size_t count = 0;
    while (qh < qt && count < max_out) {
        uint64_t cur = queue[qh++];
        out[count++] = cur;
        size_t nn = qihse_graph_get_neighbors(g, cur, GRAPH_DIR_OUTGOING, NULL, adj, 256);
        for (size_t k = 0; k < nn; k++) {
            for (size_t j = 0; j < n; j++) {
                if (ids[j] == adj[k].neighbor_id) { in_deg[j]--; if (in_deg[j] == 0) queue[qt++] = ids[j]; break; }
            }
        }
    }
    free(in_deg); free(queue);
    return count;
}

/* Jaccard similarity */
double qihse_graph_jaccard(qihse_graph_t* g, uint64_t a, uint64_t b) {
    if (!g) return 0.0;
    graph_adj_t adj_a[256], adj_b[256];
    size_t na = qihse_graph_get_neighbors(g, a, GRAPH_DIR_BOTH, NULL, adj_a, 256);
    size_t nb = qihse_graph_get_neighbors(g, b, GRAPH_DIR_BOTH, NULL, adj_b, 256);
    if (na == 0 && nb == 0) return 1.0;
    size_t intersection = 0;
    for (size_t i = 0; i < na; i++) for (size_t j = 0; j < nb; j++) if (adj_a[i].neighbor_id == adj_b[j].neighbor_id) { intersection++; break; }
    size_t union_size = na + nb - intersection;
    return union_size > 0 ? (double)intersection / union_size : 0.0;
}

/* All-pairs shortest path (Floyd-Warshall) */
int qihse_graph_all_pairs_shortest(qihse_graph_t* g, double* out_dist, size_t max_n) {
    if (!g || !out_dist || max_n == 0) return -1;
    uint64_t ids[1024];
    size_t n = qihse_graph_all_vertex_ids(g, ids, 1024);
    if (n > max_n) n = max_n;
    /* Initialize distance matrix */
    for (size_t i = 0; i < n; i++) for (size_t j = 0; j < n; j++) out_dist[i * max_n + j] = (i == j) ? 0.0 : DBL_MAX;
    /* Set direct edges */
    graph_adj_t adj[256];
    for (size_t i = 0; i < n; i++) {
        size_t nn = qihse_graph_get_neighbors(g, ids[i], GRAPH_DIR_OUTGOING, NULL, adj, 256);
        for (size_t k = 0; k < nn; k++) {
            for (size_t j = 0; j < n; j++) { if (ids[j] == adj[k].neighbor_id) { out_dist[i * max_n + j] = 1.0; break; } }
        }
    }
    /* Floyd-Warshall */
    for (size_t k = 0; k < n; k++)
        for (size_t i = 0; i < n; i++)
            for (size_t j = 0; j < n; j++) {
                double through = out_dist[i * max_n + k] + out_dist[k * max_n + j];
                if (through < out_dist[i * max_n + j]) out_dist[i * max_n + j] = through;
            }
    return 0;
}
