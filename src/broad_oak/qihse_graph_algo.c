#include "qihse_graph_algo.h"
#include "qihse_arena.h"
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <float.h>
#include <errno.h>

static size_t graph_id_index(const uint64_t *ids, size_t n, uint64_t id);

/* BFS */
size_t qihse_graph_bfs(qihse_graph_t* g, uint64_t source, uint64_t* out, size_t max_out) {
    if (!g || !out || max_out == 0) return 0;
    errno = 0;
    size_t n = qihse_graph_vertex_count(g);
    if (!n || n > SIZE_MAX / sizeof(uint64_t)) return 0;
    uint64_t *ids = malloc(n * sizeof(*ids));
    uint64_t *queue = malloc(n * sizeof(*queue));
    unsigned char *visited = calloc(n, 1);
    if (!ids || !queue || !visited) { free(ids); free(queue); free(visited); errno = ENOMEM; return 0; }
    n = qihse_graph_all_vertex_ids(g, ids, n);
    size_t src = graph_id_index(ids, n, source);
    if (src == SIZE_MAX) { free(ids); free(queue); free(visited); return 0; }
    size_t qhead = 0, qtail = 0;
    queue[qtail++] = src; visited[src] = 1;
    size_t count = 0;
    while (qhead < qtail && count < max_out) {
        size_t cur = (size_t)queue[qhead++];
        out[count++] = ids[cur];
        graph_adj_t* adj = NULL;
        size_t nn = qihse_graph_get_neighbors_all(g, ids[cur], GRAPH_DIR_BOTH, NULL, &adj);
        if (nn == 0 && errno != 0) { free(adj); free(ids); free(queue); free(visited); return 0; }
        for (size_t i = 0; i < nn; i++) {
            size_t next = graph_id_index(ids, n, adj[i].neighbor_id);
            if (next != SIZE_MAX && !visited[next]) {
                visited[next] = 1;
                queue[qtail++] = next;
            }
        }
        free(adj);
    }
    free(ids); free(queue); free(visited);
    return count;
}

/* DFS (iterative with stack) */
size_t qihse_graph_dfs(qihse_graph_t* g, uint64_t source, uint64_t* out, size_t max_out) {
    if (!g || !out || max_out == 0) return 0;
    errno = 0;
    size_t n = qihse_graph_vertex_count(g);
    if (!n || n > SIZE_MAX / sizeof(size_t)) return 0;
    uint64_t *ids = malloc(n * sizeof(*ids));
    size_t *stack = malloc(n * sizeof(*stack));
    unsigned char *visited = calloc(n, 1);
    if (!ids || !stack || !visited) { free(ids); free(stack); free(visited); errno = ENOMEM; return 0; }
    n = qihse_graph_all_vertex_ids(g, ids, n);
    size_t src = graph_id_index(ids, n, source);
    if (src == SIZE_MAX) { free(ids); free(stack); free(visited); return 0; }
    size_t stop = 0;
    stack[stop++] = src; visited[src] = 1;
    size_t count = 0;
    while (stop > 0 && count < max_out) {
        size_t cur = stack[--stop];
        out[count++] = ids[cur];
        graph_adj_t* adj = NULL;
        size_t nn = qihse_graph_get_neighbors_all(g, ids[cur], GRAPH_DIR_BOTH, NULL, &adj);
        if (nn == 0 && errno != 0) { free(adj); free(ids); free(stack); free(visited); return 0; }
        for (size_t i = 0; i < nn; i++) {
            size_t next = graph_id_index(ids, n, adj[i].neighbor_id);
            if (next != SIZE_MAX && !visited[next]) {
                visited[next] = 1;
                stack[stop++] = next;
            }
        }
        free(adj);
    }
    free(ids); free(stack); free(visited);
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

static size_t graph_id_index(const uint64_t *ids, size_t n, uint64_t id) {
    size_t lo = 0, hi = n;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (ids[mid] < id) lo = mid + 1;
        else hi = mid;
    }
    return lo < n && ids[lo] == id ? lo : SIZE_MAX;
}

static size_t graph_shortest_path(qihse_graph_t *g, uint64_t source, uint64_t target,
                                  double (*heuristic)(uint64_t, uint64_t, void *),
                                  void *ctx, uint64_t *out_path, size_t max_path) {
    errno = 0;
    if (!g || !out_path || !max_path) { errno = EINVAL; return 0; }
    size_t n = qihse_graph_vertex_count(g);
    if (!n || n > SIZE_MAX / sizeof(uint64_t)) return 0;
    uint64_t *ids = malloc(n * sizeof(*ids));
    double *dist = malloc(n * sizeof(*dist));
    size_t *prev = malloc(n * sizeof(*prev));
    bool *visited = calloc(n, sizeof(*visited));
    size_t *reverse = malloc(n * sizeof(*reverse));
    heap_node_t *heap = NULL;
    size_t heap_n = 0, heap_cap = 0;
    if (!ids || !dist || !prev || !visited || !reverse) goto fail;
    n = qihse_graph_all_vertex_ids(g, ids, n);
    size_t src = graph_id_index(ids, n, source), dst = graph_id_index(ids, n, target);
    if (src == SIZE_MAX || dst == SIZE_MAX) goto done;
    for (size_t i = 0; i < n; ++i) { dist[i] = DBL_MAX; prev[i] = SIZE_MAX; }
    dist[src] = 0.0;
    heap_cap = 16;
    heap = malloc(heap_cap * sizeof(*heap));
    if (!heap) goto fail;
    heap_push(heap, &heap_n, src, heuristic ? heuristic(source, target, ctx) : 0.0);
    while (heap_n) {
        heap_node_t current = heap_pop(heap, &heap_n);
        size_t v = (size_t)current.vertex;
        if (v >= n || visited[v]) continue;
        visited[v] = true;
        if (v == dst) break;
        graph_adj_t *adj = NULL;
        size_t nn = qihse_graph_get_neighbors_all(g, ids[v], GRAPH_DIR_OUTGOING, NULL, &adj);
        if (!nn && errno) { free(adj); goto fail; }
        for (size_t k = 0; k < nn; ++k) {
            size_t w = graph_id_index(ids, n, adj[k].neighbor_id);
            if (w == SIZE_MAX || visited[w]) continue;
            double candidate = dist[v] + 1.0;
            if (candidate >= dist[w]) continue;
            dist[w] = candidate;
            prev[w] = v;
            if (heap_n == heap_cap) {
                if (heap_cap > SIZE_MAX / 2 / sizeof(*heap)) { free(adj); goto fail; }
                size_t cap = heap_cap * 2;
                heap_node_t *next = realloc(heap, cap * sizeof(*next));
                if (!next) { free(adj); goto fail; }
                heap = next; heap_cap = cap;
            }
            double priority = candidate + (heuristic ? heuristic(ids[w], target, ctx) : 0.0);
            heap_push(heap, &heap_n, w, priority);
        }
        free(adj);
    }
    if (dist[dst] == DBL_MAX) goto done;
    size_t path_len = 0, cur = dst;
    for (;;) {
        if (path_len == n) goto done;
        reverse[path_len++] = cur;
        if (cur == src) break;
        cur = prev[cur];
        if (cur == SIZE_MAX || cur >= n) goto done;
    }
    if (path_len > max_path) { errno = ENOBUFS; goto done; }
    for (size_t i = 0; i < path_len; ++i) out_path[i] = ids[reverse[path_len - 1 - i]];
    free(ids); free(dist); free(prev); free(visited); free(reverse); free(heap);
    return path_len;
fail:
    errno = errno ? errno : ENOMEM;
done:
    free(ids); free(dist); free(prev); free(visited); free(reverse); free(heap);
    return 0;
}

size_t qihse_graph_dijkstra(qihse_graph_t* g, uint64_t source, uint64_t target,
                            uint64_t* out_path, size_t max_path) {
    return graph_shortest_path(g, source, target, NULL, NULL, out_path, max_path);
}

/* A* (same as Dijkstra with heuristic) */
size_t qihse_graph_astar(qihse_graph_t* g, uint64_t source, uint64_t target,
                         double (*heuristic)(uint64_t a, uint64_t b, void* ctx),
                         void* ctx, uint64_t* out_path, size_t max_path) {
    return graph_shortest_path(g, source, target, heuristic, ctx, out_path, max_path);
}

/* PageRank */
int qihse_graph_pagerank(qihse_graph_t* g, double* out_scores, size_t max_scores,
                         int max_iterations, double damping, double tolerance) {
    if (!g || !out_scores || !max_scores || max_iterations < 0 ||
        !isfinite(damping) || damping < 0.0 || damping > 1.0 ||
        !isfinite(tolerance) || tolerance < 0.0) { errno = EINVAL; return -1; }
    errno = 0;
    size_t n = qihse_graph_vertex_count(g);
    if (!n) return 0;
    if (n > max_scores || n > SIZE_MAX / sizeof(uint64_t) || n == SIZE_MAX) {
        errno = ENOBUFS; return -1;
    }
    uint64_t *ids = malloc(n * sizeof(*ids));
    size_t *offsets = calloc(n + 1, sizeof(*offsets));
    double *scores = malloc(n * sizeof(*scores));
    double *next = malloc(n * sizeof(*next));
    if (!ids || !offsets || !scores || !next) { errno = ENOMEM; goto pagerank_fail; }
    n = qihse_graph_all_vertex_ids(g, ids, n);
    for (size_t i = 0; i < n; ++i) {
        graph_adj_t *adj = NULL;
        size_t degree = qihse_graph_get_neighbors_all(g, ids[i], GRAPH_DIR_OUTGOING, NULL, &adj);
        if (!degree && errno) { free(adj); goto pagerank_fail; }
        free(adj);
        if (degree > SIZE_MAX - offsets[i]) { errno = EOVERFLOW; goto pagerank_fail; }
        offsets[i + 1] = offsets[i] + degree;
    }
    if (offsets[n] > SIZE_MAX / sizeof(size_t)) { errno = EOVERFLOW; goto pagerank_fail; }
    size_t *targets = offsets[n] ? malloc(offsets[n] * sizeof(*targets)) : NULL;
    if (offsets[n] && !targets) { errno = ENOMEM; goto pagerank_fail; }
    for (size_t i = 0; i < n; ++i) {
        graph_adj_t *adj = NULL;
        size_t degree = qihse_graph_get_neighbors_all(g, ids[i], GRAPH_DIR_OUTGOING, NULL, &adj);
        if (!degree && errno) { free(adj); free(targets); goto pagerank_fail; }
        for (size_t k = 0; k < degree; ++k) {
            size_t dst = graph_id_index(ids, n, adj[k].neighbor_id);
            if (dst == SIZE_MAX) { free(adj); free(targets); errno = EINVAL; goto pagerank_fail; }
            targets[offsets[i] + k] = dst;
        }
        free(adj);
    }
    for (size_t i = 0; i < n; ++i) scores[i] = 1.0 / (double)n;
    for (int iter = 0; iter < max_iterations; ++iter) {
        double dangling = 0.0;
        for (size_t i = 0; i < n; ++i)
            if (offsets[i] == offsets[i + 1]) dangling += scores[i];
        double base = ((1.0 - damping) + damping * dangling) / (double)n;
        for (size_t i = 0; i < n; ++i) next[i] = base;
        for (size_t i = 0; i < n; ++i) {
            size_t degree = offsets[i + 1] - offsets[i];
            if (!degree) continue;
            double share = damping * scores[i] / (double)degree;
            for (size_t k = offsets[i]; k < offsets[i + 1]; ++k) next[targets[k]] += share;
        }
        double diff = 0.0;
        for (size_t i = 0; i < n; ++i) diff += fabs(next[i] - scores[i]);
        double *tmp = scores; scores = next; next = tmp;
        if (diff < tolerance) break;
    }
    memcpy(out_scores, scores, n * sizeof(*scores));
    free(targets); free(ids); free(offsets); free(scores); free(next);
    return 0;
pagerank_fail:
    free(ids); free(offsets); free(scores); free(next);
    return -1;
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
        graph_adj_t* adj = NULL;
        size_t nn = qihse_graph_get_neighbors_all(g, ids[i], GRAPH_DIR_BOTH, NULL, &adj);
        if (!nn && errno) { free(adj); uf_free(&uf); free(ids); return 0; }
        for (size_t k = 0; k < nn; k++) {
            size_t j = graph_id_index(ids, n, adj[k].neighbor_id);
            if (j != SIZE_MAX) uf_union(&uf, i, j);
        }
        free(adj);
    }
    /* Root-indexed labels avoid a quadratic scan over previously seen roots. */
    uint32_t *labels = malloc(n * sizeof(*labels));
    if (!labels) { uf_free(&uf); free(ids); return 0; }
    for (size_t i = 0; i < n; ++i) labels[i] = UINT32_MAX;
    size_t num_comp = 0;
    for (size_t i = 0; i < n; ++i) {
        size_t root = uf_find(&uf, i);
        if (labels[root] == UINT32_MAX) labels[root] = (uint32_t)num_comp++;
        out_ids[i] = labels[root];
    }
    free(labels); uf_free(&uf); free(ids);
    return num_comp;
}

/* Strongly connected components using iterative Kosaraju passes. */
size_t qihse_graph_scc(qihse_graph_t* g, uint32_t* out_ids, size_t max_out) {
    if (!g || !out_ids || !max_out) return 0;
    uint64_t *ids = malloc(max_out * sizeof(*ids));
    if (!ids) return 0;
    size_t n = qihse_graph_all_vertex_ids(g, ids, max_out);
    if (!n) { free(ids); return 0; }
    typedef struct { size_t vertex, next; graph_adj_t *adj; size_t count; } frame;
    frame *frames = calloc(n, sizeof(*frames));
    size_t *stack = malloc(n * sizeof(*stack));
    size_t *order = malloc(n * sizeof(*order));
    bool *seen = calloc(n, sizeof(*seen));
    if (!frames || !stack || !order || !seen) {
        free(ids); free(frames); free(stack); free(order); free(seen); return 0;
    }
    size_t ordered = 0;
    bool failed = false;
    for (size_t root = 0; root < n; ++root) {
        if (seen[root]) continue;
        size_t sp = 0;
        seen[root] = true;
        frames[sp++] = (frame){.vertex=root};
        while (sp) {
            frame *f = &frames[sp - 1];
            if (!f->adj && !f->count) {
                f->count = qihse_graph_get_neighbors_all(g, ids[f->vertex], GRAPH_DIR_OUTGOING, NULL, &f->adj);
                if (!f->count && errno) { failed = true; break; }
            }
            if (f->next < f->count) {
                uint64_t nb = f->adj[f->next++].neighbor_id;
                size_t j = graph_id_index(ids, n, nb);
                if (j != SIZE_MAX && !seen[j]) {
                    seen[j] = true;
                    frames[sp++] = (frame){.vertex=j};
                }
            } else {
                order[ordered++] = f->vertex;
                free(f->adj);
                f->adj = NULL;
                sp--;
            }
        }
        if (failed) break;
    }
    if (failed) {
        for (size_t i = 0; i < n; ++i) free(frames[i].adj);
        free(ids); free(frames); free(stack); free(order); free(seen); return 0;
    }
    memset(seen, 0, n * sizeof(*seen));
    size_t components = 0;
    for (size_t oi = ordered; oi > 0; --oi) {
        size_t root = order[oi - 1];
        if (seen[root]) continue;
        size_t sp = 0;
        stack[sp++] = root; seen[root] = true;
        while (sp) {
            size_t v = stack[--sp];
            out_ids[v] = (uint32_t)components;
            graph_adj_t *adj = NULL;
            size_t count = qihse_graph_get_neighbors_all(g, ids[v], GRAPH_DIR_INCOMING, NULL, &adj);
            if (!count && errno) { free(adj); failed = true; break; }
            for (size_t k = 0; k < count; ++k) {
                size_t j = graph_id_index(ids, n, adj[k].neighbor_id);
                if (j != SIZE_MAX && !seen[j]) { seen[j] = true; stack[sp++] = j; }
            }
            free(adj);
        }
        if (failed) break;
        components++;
    }
    if (failed) { free(ids); free(frames); free(stack); free(order); free(seen); return 0; }
    free(ids); free(frames); free(stack); free(order); free(seen);
    return components;
}

/* Betweenness centrality (Brandes' - simplified) */
int qihse_graph_betweenness(qihse_graph_t* g, double* out_scores, size_t max_scores) {
    if (!g || !out_scores || max_scores == 0) return -1;
    uint64_t* ids = malloc(max_scores * sizeof(uint64_t));
    size_t n = qihse_graph_all_vertex_ids(g, ids, max_scores);
    if (n == 0) { free(ids); return 0; }
    typedef struct { size_t *items, count, cap; } pred_list;
    size_t *queue = malloc(n * sizeof(*queue)), *stack = malloc(n * sizeof(*stack));
    int *dist = malloc(n * sizeof(*dist));
    double *sigma = calloc(n, sizeof(*sigma)), *delta = calloc(n, sizeof(*delta));
    pred_list *pred = calloc(n, sizeof(*pred));
    if (!queue || !stack || !dist || !sigma || !delta || !pred) {
        free(ids); free(queue); free(stack); free(dist); free(sigma); free(delta); free(pred); return -1;
    }
    for (size_t i = 0; i < n; i++) out_scores[i] = 0.0;
    for (size_t source = 0; source < n; ++source) {
        for (size_t i = 0; i < n; ++i) { dist[i] = -1; sigma[i] = delta[i] = 0.0; pred[i].count = 0; }
        size_t qh = 0, qt = 0, sp = 0;
        dist[source] = 0; sigma[source] = 1.0; queue[qt++] = source;
        while (qh < qt) {
            size_t v = queue[qh++]; stack[sp++] = v;
            graph_adj_t *adj = NULL;
            size_t nn = qihse_graph_get_neighbors_all(g, ids[v], GRAPH_DIR_BOTH, NULL, &adj);
            if (!nn && errno) { free(adj); goto betweenness_fail; }
            for (size_t k = 0; k < nn; ++k) {
                size_t w = graph_id_index(ids, n, adj[k].neighbor_id);
                if (w == SIZE_MAX) continue;
                if (dist[w] < 0) { dist[w] = dist[v] + 1; queue[qt++] = w; }
                if (dist[w] == dist[v] + 1) {
                    sigma[w] += sigma[v];
                    if (pred[w].count == pred[w].cap) {
                        size_t cap = pred[w].cap ? pred[w].cap * 2 : 4;
                        size_t *next = realloc(pred[w].items, cap * sizeof(*next));
                        if (!next) { free(adj); goto betweenness_fail; }
                        pred[w].items = next; pred[w].cap = cap;
                    }
                    pred[w].items[pred[w].count++] = v;
                }
            }
            free(adj);
        }
        while (sp) {
            size_t w = stack[--sp];
            if (sigma[w] != 0.0) for (size_t k = 0; k < pred[w].count; ++k) {
                size_t v = pred[w].items[k];
                delta[v] += (sigma[v] / sigma[w]) * (1.0 + delta[w]);
            }
            if (w != source) out_scores[w] += delta[w];
        }
    }
    /* GRAPH_DIR_BOTH treats an undirected edge as two directed arcs. */
    for (size_t i = 0; i < n; ++i) { out_scores[i] *= 0.5; free(pred[i].items); }
    free(queue); free(stack); free(dist); free(sigma); free(delta); free(pred);
    free(ids);
    return 0;
betweenness_fail:
    for (size_t i = 0; i < n; ++i) free(pred[i].items);
    free(ids); free(queue); free(stack); free(dist); free(sigma); free(delta); free(pred);
    return -1;
}

/* Closeness centrality */
int qihse_graph_closeness(qihse_graph_t* g, double* out_scores, size_t max_scores) {
    if (!g || !out_scores || max_scores == 0) return -1;
    uint64_t* ids = malloc(max_scores * sizeof(uint64_t));
    size_t n = qihse_graph_all_vertex_ids(g, ids, max_scores);
    if (n == 0) { free(ids); return 0; }
    for (size_t i = 0; i < n; i++) {
        /* BFS to find sum of distances */
        size_t* queue = malloc(n * sizeof(size_t));
        int* dist = malloc(n * sizeof(int));
        if (!queue || !dist) { free(queue); free(dist); free(ids); return -1; }
        size_t qh = 0, qt = 0;
        for (size_t j = 0; j < n; ++j) dist[j] = -1;
        queue[qt++] = i; dist[i] = 0;
        int total_dist = 0; size_t reached = 1;
        while (qh < qt) {
            size_t cur_index = queue[qh++];
            uint64_t cur = ids[cur_index];
            graph_adj_t* adj = NULL;
            size_t nn = qihse_graph_get_neighbors_all(g, cur, GRAPH_DIR_BOTH, NULL, &adj);
            if (!nn && errno) { free(adj); free(queue); free(dist); free(ids); return -1; }
            for (size_t k = 0; k < nn; k++) {
                size_t j = graph_id_index(ids, n, adj[k].neighbor_id);
                if (j != SIZE_MAX && dist[j] < 0) {
                    dist[j] = dist[cur_index] + 1;
                    queue[qt++] = j;
                    total_dist += dist[j];
                    reached++;
                }
            }
            free(adj);
        }
        out_scores[i] = (reached > 1 && total_dist > 0) ? (double)(reached - 1) / total_dist : 0.0;
        free(queue); free(dist);
    }
    free(ids);
    return 0;
}

/* Degree centrality */
int qihse_graph_degree_centrality(qihse_graph_t* g, int64_t* out_in, int64_t* out_out, int64_t* out_total, size_t max_out) {
    if (!g || !out_total || max_out == 0) return -1;
    uint64_t* ids = malloc(max_out * sizeof(uint64_t));
    size_t n = qihse_graph_all_vertex_ids(g, ids, max_out);
    for (size_t i = 0; i < n; i++) {
        graph_adj_t *all = NULL;
        size_t out_deg = qihse_graph_get_neighbors_all(g, ids[i], GRAPH_DIR_OUTGOING, NULL, &all);
        if (!out_deg && errno) { free(all); free(ids); return -1; }
        free(all); all = NULL;
        size_t in_deg = qihse_graph_get_neighbors_all(g, ids[i], GRAPH_DIR_INCOMING, NULL, &all);
        if (!in_deg && errno) { free(all); free(ids); return -1; }
        free(all);
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
    size_t capacity = qihse_graph_vertex_count(g);
    uint64_t *ids = capacity ? malloc(capacity * sizeof(*ids)) : NULL;
    if (capacity && !ids) return 0;
    size_t n = qihse_graph_all_vertex_ids(g, ids, capacity);
    uint64_t count = 0;
    for (size_t i = 0; i < n; i++) {
        graph_adj_t *adj_a = NULL;
        size_t na = qihse_graph_get_neighbors_all(g, ids[i], GRAPH_DIR_BOTH, NULL, &adj_a);
        if (!na && errno) { free(adj_a); free(ids); return 0; }
        for (size_t j = 0; j < na; j++) {
            if (adj_a[j].neighbor_id <= ids[i]) continue;
            graph_adj_t *adj_b = NULL;
            size_t nb = qihse_graph_get_neighbors_all(g, adj_a[j].neighbor_id, GRAPH_DIR_BOTH, NULL, &adj_b);
            if (!nb && errno) { free(adj_b); free(adj_a); free(ids); return 0; }
            for (size_t k = 0; k < nb; k++) {
                if (adj_b[k].neighbor_id <= adj_a[j].neighbor_id) continue;
                /* Check if adj_b[k].neighbor_id connects back to ids[i] */
                graph_adj_t *adj_c = NULL;
                size_t nc = qihse_graph_get_neighbors_all(g, adj_b[k].neighbor_id, GRAPH_DIR_BOTH, NULL, &adj_c);
                if (!nc && errno) { free(adj_c); free(adj_b); free(adj_a); free(ids); return 0; }
                for (size_t m = 0; m < nc; m++) {
                    if (adj_c[m].neighbor_id == ids[i]) { count++; break; }
                }
                free(adj_c);
            }
            free(adj_b);
        }
        free(adj_a);
    }
    free(ids);
    return count;
}

/* Directed cycle detection with explicit white/gray/black DFS state. */
int qihse_graph_has_cycle(qihse_graph_t* g) {
    if (!g) return 0;
    typedef struct { size_t vertex, next; graph_adj_t *adj; size_t count; } cycle_frame;
    size_t n = qihse_graph_vertex_count(g);
    uint64_t *ids = n ? malloc(n * sizeof(*ids)) : NULL;
    unsigned char *color = n ? calloc(n, 1) : NULL;
    cycle_frame *stack = n ? calloc(n, sizeof(*stack)) : NULL;
    if (n && (!ids || !color || !stack)) { free(ids); free(color); free(stack); return 0; }
    n = qihse_graph_all_vertex_ids(g, ids, n);
    bool failed = false;
    for (size_t root = 0; root < n; ++root) {
        if (color[root]) continue;
        size_t sp = 0;
        color[root] = 1;
        stack[sp++] = (cycle_frame){.vertex=root};
        while (sp) {
            cycle_frame *f = &stack[sp - 1];
            if (!f->adj && !f->count) {
                f->count = qihse_graph_get_neighbors_all(g, ids[f->vertex], GRAPH_DIR_OUTGOING, NULL, &f->adj);
                if (!f->count && errno) { failed = true; break; }
            }
            if (f->next < f->count) {
                size_t neighbor = graph_id_index(ids, n, f->adj[f->next++].neighbor_id);
                if (neighbor == SIZE_MAX) continue;
                if (color[neighbor] == 1) {
                    for (size_t k = 0; k < sp; ++k) free(stack[k].adj);
                    free(ids); free(color); free(stack); return 1;
                }
                if (!color[neighbor]) {
                    color[neighbor] = 1;
                    stack[sp++] = (cycle_frame){.vertex=neighbor};
                }
            } else {
                color[f->vertex] = 2;
                free(f->adj);
                f->adj = NULL;
                sp--;
            }
        }
        if (failed) break;
    }
    if (failed) { for (size_t i=0;i<n;++i) free(stack[i].adj); free(ids); free(color); free(stack); return 0; }
    free(ids); free(color); free(stack);
    return 0;
}

/* Topological sort (Kahn's algorithm) */
size_t qihse_graph_topo_sort(qihse_graph_t* g, uint64_t* out, size_t max_out) {
    if (!g || !out || max_out == 0) return 0;
    size_t capacity = qihse_graph_vertex_count(g);
    uint64_t *ids = capacity ? malloc(capacity * sizeof(*ids)) : NULL;
    if (capacity && !ids) return 0;
    size_t n = qihse_graph_all_vertex_ids(g, ids, capacity);
    if (n == 0) { free(ids); return 0; }
    /* Compute in-degrees */
    size_t* in_deg = calloc(n, sizeof(size_t));
    if (!in_deg) { free(ids); return 0; }
    for (size_t i = 0; i < n; i++) {
        graph_adj_t* adj = NULL;
        size_t nn = qihse_graph_get_neighbors_all(g, ids[i], GRAPH_DIR_OUTGOING, NULL, &adj);
        if (!nn && errno) { free(adj); free(in_deg); free(ids); return 0; }
        for (size_t k = 0; k < nn; k++) {
            size_t j = graph_id_index(ids, n, adj[k].neighbor_id);
            if (j != SIZE_MAX) in_deg[j]++;
        }
        free(adj);
    }
    /* Queue vertices with in-degree 0 */
    uint64_t* queue = malloc(n * sizeof(uint64_t));
    if (!queue) { free(in_deg); free(ids); return 0; }
    size_t qh = 0, qt = 0;
    for (size_t i = 0; i < n; i++) { if (in_deg[i] == 0) queue[qt++] = ids[i]; }
    size_t count = 0;
    while (qh < qt && count < max_out) {
        uint64_t cur = queue[qh++];
        out[count++] = cur;
        graph_adj_t* adj = NULL;
        size_t nn = qihse_graph_get_neighbors_all(g, cur, GRAPH_DIR_OUTGOING, NULL, &adj);
        if (!nn && errno) { free(adj); free(in_deg); free(queue); free(ids); return 0; }
        for (size_t k = 0; k < nn; k++) {
            size_t j = graph_id_index(ids, n, adj[k].neighbor_id);
            if (j != SIZE_MAX && in_deg[j] && --in_deg[j] == 0) queue[qt++] = ids[j];
        }
        free(adj);
    }
    free(in_deg); free(queue); free(ids);
    return count;
}

/* Jaccard similarity */
double qihse_graph_jaccard(qihse_graph_t* g, uint64_t a, uint64_t b) {
    if (!g) { errno = EINVAL; return NAN; }
    graph_adj_t *adj_a = NULL, *adj_b = NULL;
    errno = 0;
    size_t na = qihse_graph_get_neighbors_all(g, a, GRAPH_DIR_BOTH, NULL, &adj_a);
    int err = errno;
    if (!na && err) { free(adj_a); errno = err; return NAN; }
    errno = 0;
    size_t nb = qihse_graph_get_neighbors_all(g, b, GRAPH_DIR_BOTH, NULL, &adj_b);
    err = errno;
    if (!nb && err) { free(adj_a); free(adj_b); errno = err; return NAN; }
    if (na == 0 && nb == 0) { free(adj_a); free(adj_b); return 1.0; }
    size_t intersection = 0;
    for (size_t i = 0; i < na; i++) for (size_t j = 0; j < nb; j++) if (adj_a[i].neighbor_id == adj_b[j].neighbor_id) { intersection++; break; }
    size_t union_size = na + nb - intersection;
    double score = union_size > 0 ? (double)intersection / union_size : 0.0;
    free(adj_a); free(adj_b);
    return score;
}

/* All-pairs shortest path (Floyd-Warshall) */
int qihse_graph_all_pairs_shortest(qihse_graph_t* g, double* out_dist, size_t max_n) {
    if (!g || !out_dist || max_n == 0) return -1;
    size_t capacity = qihse_graph_vertex_count(g);
    uint64_t *ids = capacity ? malloc(capacity * sizeof(*ids)) : NULL;
    if (capacity && !ids) return -1;
    size_t n = qihse_graph_all_vertex_ids(g, ids, capacity);
    if (n > max_n) n = max_n;
    /* Initialize distance matrix */
    for (size_t i = 0; i < n; i++) for (size_t j = 0; j < n; j++) out_dist[i * max_n + j] = (i == j) ? 0.0 : DBL_MAX;
    /* Set direct edges */
    for (size_t i = 0; i < n; i++) {
        graph_adj_t* adj = NULL;
        size_t nn = qihse_graph_get_neighbors_all(g, ids[i], GRAPH_DIR_OUTGOING, NULL, &adj);
        if (!nn && errno) { free(adj); free(ids); return -1; }
        for (size_t k = 0; k < nn; k++) {
            for (size_t j = 0; j < n; j++) { if (ids[j] == adj[k].neighbor_id) { out_dist[i * max_n + j] = 1.0; break; } }
        }
        free(adj);
    }
    /* Floyd-Warshall */
    for (size_t k = 0; k < n; k++)
        for (size_t i = 0; i < n; i++)
            for (size_t j = 0; j < n; j++) {
                double through = out_dist[i * max_n + k] + out_dist[k * max_n + j];
                if (through < out_dist[i * max_n + j]) out_dist[i * max_n + j] = through;
            }
    free(ids);
    return 0;
}
