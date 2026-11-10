#include "qihse_graph_vector.h"
#include "backends/cpu/qihse_cpu_distance.h"
#include <errno.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    uint64_t* ids;
    size_t count;
    size_t capacity;
} id_list_t;

typedef struct {
    uint64_t id;
    float score;
} scored_vertex_t;

static bool request_allowed(qihse_graph_t* graph, qihse_vector_db_t vdb,
                            qihse_user_t* user) {
    if (!user || !qihse_auth_user_is_active(user)) {
        errno = EACCES;
        return false;
    }
    if (!graph || !vdb) {
        errno = EINVAL;
        return false;
    }
    return true;
}

static bool list_reserve(id_list_t* list, size_t needed) {
    if (needed <= list->capacity) return true;
    size_t next = list->capacity ? list->capacity : 32u;
    while (next < needed) {
        if (next > SIZE_MAX / 2u) {
            errno = EOVERFLOW;
            return false;
        }
        next *= 2u;
    }
    if (next > SIZE_MAX / sizeof(*list->ids)) {
        errno = EOVERFLOW;
        return false;
    }
    uint64_t* grown = realloc(list->ids, next * sizeof(*list->ids));
    if (!grown) {
        errno = ENOMEM;
        return false;
    }
    list->ids = grown;
    list->capacity = next;
    return true;
}

static bool list_has(const id_list_t* list, uint64_t id) {
    for (size_t i = 0; i < list->count; ++i)
        if (list->ids[i] == id) return true;
    return false;
}

static bool list_push(id_list_t* list, uint64_t id) {
    if (!list_reserve(list, list->count + 1u)) return false;
    list->ids[list->count++] = id;
    return true;
}

static void list_clear(id_list_t* list) {
    if (!list) return;
    free(list->ids);
    memset(list, 0, sizeof(*list));
}

static bool scored_push(scored_vertex_t** entries, size_t* count,
                        size_t* capacity, uint64_t id, float score) {
    if (*count == *capacity) {
        size_t next = *capacity ? *capacity * 2u : 32u;
        if (next < *capacity || next > SIZE_MAX / sizeof(**entries)) {
            errno = EOVERFLOW;
            return false;
        }
        scored_vertex_t* grown = realloc(*entries, next * sizeof(**entries));
        if (!grown) {
            errno = ENOMEM;
            return false;
        }
        *entries = grown;
        *capacity = next;
    }
    (*entries)[*count] = (scored_vertex_t){.id = id, .score = score};
    (*count)++;
    return true;
}

static int scored_compare(const void* left, const void* right) {
    const scored_vertex_t* a = left;
    const scored_vertex_t* b = right;
    if (a->score > b->score) return -1;
    if (a->score < b->score) return 1;
    return (a->id > b->id) - (a->id < b->id);
}

static bool fetch_visible_vector(qihse_vector_db_t vdb, qihse_user_t* user,
                                 uint64_t id, float* buffer,
                                 size_t expected_dims) {
    size_t actual_dims = 0u;
    if (!qihse_vector_db_get_vector_by_id_user(vdb, user, id, buffer,
                                               &actual_dims))
        return false;
    if (actual_dims != expected_dims) {
        errno = EINVAL;
        return false;
    }
    return true;
}

static graph_adj_t* all_neighbors(qihse_graph_t* graph, uint64_t id,
                                  size_t* out_count, bool* out_ok) {
    graph_adj_t* adjacency = NULL;
    errno = 0;
    size_t count = qihse_graph_get_neighbors_all(graph, id, GRAPH_DIR_BOTH,
                                                 NULL, &adjacency);
    if (count == 0u && errno != 0) {
        *out_ok = false;
        return NULL;
    }
    *out_count = count;
    *out_ok = true;
    return adjacency;
}

static bool add_visible_neighbor(qihse_vector_db_t vdb, qihse_user_t* user,
                                 uint64_t id, float* vector_buffer,
                                 size_t dims) {
    errno = 0;
    return fetch_visible_vector(vdb, user, id, vector_buffer, dims);
}

static bool query_dims_valid(qihse_vector_db_t vdb, const float* query,
                             size_t dims) {
    size_t db_dims = qihse_vector_db_get_dims(vdb);
    if (!db_dims || !query || !dims || dims != db_dims ||
        dims > SIZE_MAX / sizeof(float)) {
        errno = EINVAL;
        return false;
    }
    return true;
}

size_t qihse_graph_vector_search_user(qihse_graph_t* g, qihse_vector_db_t vdb,
                                      qihse_user_t* user,
                                      const float* query, size_t dims, size_t k,
                                      size_t hops, uint64_t* out_vertex_ids,
                                      float* out_scores, size_t max_out) {
    if (!request_allowed(g, vdb, user)) return 0u;
    if (!query || !out_vertex_ids || !max_out || !k) {
        errno = EINVAL;
        return 0u;
    }
    if (!query_dims_valid(vdb, query, dims)) return 0u;
    if (k > SIZE_MAX / sizeof(qihse_vector_result_t)) {
        errno = EOVERFLOW;
        return 0u;
    }

    size_t db_dims = qihse_vector_db_get_dims(vdb);
    float* vector_buffer = malloc(db_dims * sizeof(*vector_buffer));
    qihse_vector_result_t* results = malloc(k * sizeof(*results));
    if (!vector_buffer || !results) {
        free(vector_buffer);
        free(results);
        errno = ENOMEM;
        return 0u;
    }

    qihse_vector_query_t request;
    memset(&request, 0, sizeof(request));
    request.query_vector = query;
    request.vector_dims = dims;
    request.top_k = k;
    request.user = user;
    int found = qihse_vector_db_search(vdb, &request, results, k);
    if (found < 0) found = 0;
    size_t graph_vertices = qihse_graph_vertex_count(g);
    if (graph_vertices > SIZE_MAX - (size_t)found) {
        free(results);
        free(vector_buffer);
        errno = EOVERFLOW;
        return 0u;
    }
    size_t seen_limit = graph_vertices + (size_t)found;

    id_list_t visited = {0};
    scored_vertex_t* scored = NULL;
    size_t scored_count = 0u, scored_capacity = 0u;
    bool ok = true;
    for (int i = 0; i < found && ok; ++i) {
        uint64_t seed = results[i].id;
        if (list_has(&visited, seed)) continue;
        if (!add_visible_neighbor(vdb, user, seed, vector_buffer, db_dims))
            continue;
        if (!list_push(&visited, seed) ||
            !scored_push(&scored, &scored_count, &scored_capacity,
                         seed, results[i].score)) {
            ok = false;
            break;
        }

        id_list_t frontier = {0};
        if (!list_push(&frontier, seed)) {
            ok = false;
            list_clear(&frontier);
            break;
        }
        for (size_t hop = 0u; hop < hops && frontier.count && ok; ++hop) {
            id_list_t next = {0};
            for (size_t f = 0; f < frontier.count && ok; ++f) {
                size_t neighbor_count = 0u;
                graph_adj_t* neighbors = all_neighbors(g, frontier.ids[f],
                                                       &neighbor_count, &ok);
                if (!ok) {
                    free(neighbors);
                    break;
                }
                for (size_t j = 0u; j < neighbor_count; ++j) {
                    uint64_t neighbor = neighbors[j].neighbor_id;
                    if (list_has(&visited, neighbor)) continue;
                    if (visited.count >= seen_limit) {
                        errno = EOVERFLOW;
                        ok = false;
                        break;
                    }
                    if (!add_visible_neighbor(vdb, user, neighbor,
                                              vector_buffer, db_dims))
                        continue;
                    float score = results[i].score /
                        (float)(1.0 + (double)(hop + 1u));
                    if (!list_push(&visited, neighbor) ||
                        !scored_push(&scored, &scored_count, &scored_capacity,
                                     neighbor, score) ||
                        !list_push(&next, neighbor)) {
                        ok = false;
                        break;
                    }
                }
                free(neighbors);
            }
            list_clear(&frontier);
            frontier = next;
        }
        list_clear(&frontier);
    }

    size_t out_count = 0u;
    if (ok) {
        if (scored_count > 1u)
            qsort(scored, scored_count, sizeof(*scored), scored_compare);
        out_count = scored_count < max_out ? scored_count : max_out;
        for (size_t i = 0u; i < out_count; ++i) {
            out_vertex_ids[i] = scored[i].id;
            if (out_scores) out_scores[i] = scored[i].score;
        }
    }
    free(scored);
    list_clear(&visited);
    free(results);
    free(vector_buffer);
    return out_count;
}

size_t qihse_graph_vector_traverse_user(qihse_graph_t* g,
                                        qihse_vector_db_t vdb,
                                        qihse_user_t* user,
                                        uint64_t start_vertex,
                                        const float* query, size_t dims,
                                        float similarity_threshold,
                                        size_t max_hops,
                                        uint64_t* out_vertex_ids,
                                        size_t max_out) {
    if (!request_allowed(g, vdb, user)) return 0u;
    if (!out_vertex_ids || !max_out) {
        errno = EINVAL;
        return 0u;
    }
    if (query && !query_dims_valid(vdb, query, dims)) return 0u;
    if (!query && dims != 0u) {
        errno = EINVAL;
        return 0u;
    }
    size_t db_dims = qihse_vector_db_get_dims(vdb);
    if (!db_dims || db_dims > SIZE_MAX / sizeof(float)) {
        errno = EINVAL;
        return 0u;
    }
    float* vector_buffer = malloc(db_dims * sizeof(*vector_buffer));
    if (!vector_buffer) {
        errno = ENOMEM;
        return 0u;
    }

    /* Even query-free traversal is scoped by the authenticated vector view:
     * a graph vertex with no readable vector is not disclosed. */
    if (!fetch_visible_vector(vdb, user, start_vertex, vector_buffer, db_dims)) {
        free(vector_buffer);
        return 0u;
    }

    size_t graph_vertices = qihse_graph_vertex_count(g);
    if (graph_vertices == SIZE_MAX) {
        free(vector_buffer);
        errno = EOVERFLOW;
        return 0u;
    }
    size_t seen_limit = graph_vertices + 1u;
    id_list_t visited = {0}, frontier = {0}, output = {0};
    bool ok = list_push(&visited, start_vertex) &&
              list_push(&frontier, start_vertex) &&
              list_push(&output, start_vertex);
    for (size_t hop = 0u; hop < max_hops && frontier.count && ok; ++hop) {
        id_list_t next = {0};
        for (size_t f = 0u; f < frontier.count && ok; ++f) {
            size_t neighbor_count = 0u;
            graph_adj_t* neighbors = all_neighbors(g, frontier.ids[f],
                                                   &neighbor_count, &ok);
            if (!ok) {
                free(neighbors);
                break;
            }
            for (size_t j = 0u; j < neighbor_count; ++j) {
                uint64_t neighbor = neighbors[j].neighbor_id;
                if (list_has(&visited, neighbor)) continue;
                if (visited.count >= seen_limit) {
                    errno = EOVERFLOW;
                    ok = false;
                    break;
                }
                if (!fetch_visible_vector(vdb, user, neighbor, vector_buffer,
                                          db_dims))
                    continue;
                if (query && qihse_distance_cosine(query, vector_buffer, dims) <
                             similarity_threshold)
                    continue;
                if (!list_push(&visited, neighbor)) {
                    ok = false;
                    break;
                }
                if (output.count < max_out && !list_push(&output, neighbor)) {
                    ok = false;
                    break;
                }
                if (!list_push(&next, neighbor)) {
                    ok = false;
                    break;
                }
            }
            free(neighbors);
        }
        list_clear(&frontier);
        frontier = next;
    }
    if (ok) {
        memcpy(out_vertex_ids, output.ids, output.count * sizeof(*out_vertex_ids));
    }
    size_t out_count = ok ? output.count : 0u;
    list_clear(&visited);
    list_clear(&frontier);
    list_clear(&output);
    free(vector_buffer);
    return out_count;
}

size_t qihse_graph_vector_traverse(qihse_graph_t* g, qihse_vector_db_t vdb,
                                   uint64_t start_vertex, const float* query,
                                   size_t dims, float similarity_threshold,
                                   size_t max_hops, uint64_t* out_vertex_ids,
                                   size_t max_out) {
    return qihse_graph_vector_traverse_user(g, vdb, NULL, start_vertex, query,
        dims, similarity_threshold, max_hops, out_vertex_ids, max_out);
}

int qihse_graph_subgraph_embedding_user(qihse_graph_t* g,
                                        qihse_vector_db_t vdb,
                                        qihse_user_t* user,
                                        const uint64_t* vertex_ids,
                                        size_t num_vertices, size_t dims,
                                        float* out_embedding) {
    if (!user || !qihse_auth_user_is_active(user)) {
        errno = EACCES;
        return -1;
    }
    if (!g || !vdb || !vertex_ids || !out_embedding || !num_vertices ||
        !dims || qihse_vector_db_get_dims(vdb) != dims ||
        dims > SIZE_MAX / sizeof(float)) {
        errno = EINVAL;
        return -1;
    }
    memset(out_embedding, 0, dims * sizeof(*out_embedding));
    float* buffer = malloc(dims * sizeof(*buffer));
    if (!buffer) {
        errno = ENOMEM;
        return -1;
    }
    size_t valid = 0u;
    for (size_t i = 0u; i < num_vertices; ++i) {
        if (!fetch_visible_vector(vdb, user, vertex_ids[i], buffer, dims))
            continue;
        for (size_t d = 0u; d < dims; ++d) out_embedding[d] += buffer[d];
        valid++;
    }
    free(buffer);
    if (!valid) return -1;
    for (size_t d = 0u; d < dims; ++d) out_embedding[d] /= (float)valid;
    return 0;
}

int qihse_graph_subgraph_embedding(qihse_graph_t* g, qihse_vector_db_t vdb,
                                   const uint64_t* vertex_ids,
                                   size_t num_vertices, size_t dims,
                                   float* out_embedding) {
    return qihse_graph_subgraph_embedding_user(g, vdb, NULL, vertex_ids,
        num_vertices, dims, out_embedding);
}

size_t qihse_graph_vector_recommend_user(qihse_graph_t* g,
                                         qihse_vector_db_t vdb,
                                         qihse_user_t* user,
                                         uint64_t user_vertex, size_t k,
                                         size_t hops,
                                         uint64_t* out_vertex_ids,
                                         float* out_scores, size_t max_out) {
    if (!request_allowed(g, vdb, user)) return 0u;
    if (!out_vertex_ids || !max_out || !k) {
        errno = EINVAL;
        return 0u;
    }
    size_t db_dims = qihse_vector_db_get_dims(vdb);
    if (!db_dims || db_dims > SIZE_MAX / sizeof(float)) {
        errno = EINVAL;
        return 0u;
    }
    float* vector_buffer = malloc(db_dims * sizeof(*vector_buffer));
    if (!vector_buffer) {
        errno = ENOMEM;
        return 0u;
    }
    if (!fetch_visible_vector(vdb, user, user_vertex, vector_buffer, db_dims)) {
        free(vector_buffer);
        return 0u;
    }

    size_t graph_vertices = qihse_graph_vertex_count(g);
    if (graph_vertices == SIZE_MAX) {
        free(vector_buffer);
        errno = EOVERFLOW;
        return 0u;
    }
    size_t seen_limit = graph_vertices + 1u;
    id_list_t visited = {0}, frontier = {0};
    scored_vertex_t* candidates = NULL;
    size_t candidate_count = 0u, candidate_capacity = 0u;
    bool ok = list_push(&visited, user_vertex) &&
              list_push(&frontier, user_vertex);
    for (size_t hop = 0u; hop < hops && frontier.count && ok; ++hop) {
        id_list_t next = {0};
        for (size_t f = 0u; f < frontier.count && ok; ++f) {
            size_t neighbor_count = 0u;
            graph_adj_t* neighbors = all_neighbors(g, frontier.ids[f],
                                                   &neighbor_count, &ok);
            if (!ok) {
                free(neighbors);
                break;
            }
            for (size_t j = 0u; j < neighbor_count; ++j) {
                uint64_t neighbor = neighbors[j].neighbor_id;
                if (list_has(&visited, neighbor)) continue;
                if (visited.count >= seen_limit) {
                    errno = EOVERFLOW;
                    ok = false;
                    break;
                }
                if (!fetch_visible_vector(vdb, user, neighbor, vector_buffer,
                                          db_dims))
                    continue;
                float score = 1.0f / (float)(hop + 1u);
                if (!list_push(&visited, neighbor) ||
                    !scored_push(&candidates, &candidate_count,
                                 &candidate_capacity, neighbor, score) ||
                    !list_push(&next, neighbor)) {
                    ok = false;
                    break;
                }
            }
            free(neighbors);
        }
        list_clear(&frontier);
        frontier = next;
    }
    size_t out_count = 0u;
    if (ok) {
        if (candidate_count > 1u)
            qsort(candidates, candidate_count, sizeof(*candidates), scored_compare);
        out_count = candidate_count < k ? candidate_count : k;
        if (out_count > max_out) out_count = max_out;
        for (size_t i = 0u; i < out_count; ++i) {
            out_vertex_ids[i] = candidates[i].id;
            if (out_scores) out_scores[i] = candidates[i].score;
        }
    }
    free(candidates);
    list_clear(&visited);
    list_clear(&frontier);
    free(vector_buffer);
    return out_count;
}

size_t qihse_graph_vector_recommend(qihse_graph_t* g,
                                    qihse_vector_db_t vdb,
                                    uint64_t user_vertex, size_t k,
                                    size_t hops, uint64_t* out_vertex_ids,
                                    float* out_scores, size_t max_out) {
    return qihse_graph_vector_recommend_user(g, vdb, NULL, user_vertex, k,
        hops, out_vertex_ids, out_scores, max_out);
}
