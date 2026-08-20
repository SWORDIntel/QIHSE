#ifndef QIHSE_GRAPH_STORE_H
#define QIHSE_GRAPH_STORE_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * QIHSE Graph Storage Engine
 *
 * Native property-graph store with vertices, edges, adjacency lists, and
 * label / edge-type / property indexes. Thread-safe via a pthread rwlock.
 *
 * Persistence is layered on top of the QIHSE KV store (vertices under "v:ID",
 * edges under "e:ID", adjacency under "adj:ID"); the in-process handle keeps
 * hot indexes in memory for O(1)/O(log n) access.
 * ============================================================================ */

typedef enum {
    GRAPH_PROP_INT64 = 0,
    GRAPH_PROP_DOUBLE = 1,
    GRAPH_PROP_STRING = 2,
    GRAPH_PROP_BOOL = 3,
    GRAPH_PROP_ARRAY = 4
} graph_prop_type_t;

typedef struct graph_prop_array_s {
    void* data;        /* element data */
    size_t count;      /* number of elements */
    graph_prop_type_t elem_type; /* type of each element */
} graph_prop_array_t;

typedef struct graph_prop_s {
    graph_prop_type_t type;
    union {
        int64_t i;
        double d;
        char* s;
        bool b;
        graph_prop_array_t arr;
    } val;
} graph_prop_t;

typedef enum {
    GRAPH_DIR_OUTGOING = 0,
    GRAPH_DIR_INCOMING = 1,
    GRAPH_DIR_BOTH = 2
} graph_dir_t;

/* Adjacency tuple: (edge_id, direction, neighbor_id, edge_type) */
typedef struct graph_adj_s {
    uint64_t edge_id;
    graph_dir_t direction;   /* direction of the edge relative to the owner */
    uint64_t neighbor_id;
    char edge_type[32];
} graph_adj_t;

typedef struct graph_vertex_s {
    uint64_t id;
    char** labels;
    size_t num_labels;
    /* property map: parallel arrays */
    char** prop_keys;
    graph_prop_t* prop_vals;
    size_t num_props;
} graph_vertex_t;

typedef struct graph_edge_s {
    uint64_t id;
    char type[32];
    uint64_t start_vertex_id;
    uint64_t end_vertex_id;
    char** prop_keys;
    graph_prop_t* prop_vals;
    size_t num_props;
} graph_edge_t;

typedef struct qihse_graph_s qihse_graph_t;

/* --- Lifecycle --- */
qihse_graph_t* qihse_graph_create(void);
void qihse_graph_destroy(qihse_graph_t* g);

/* --- Vertex CRUD --- */
uint64_t qihse_graph_vertex_create(qihse_graph_t* g,
                                   const char* const* labels, size_t num_labels,
                                   const char* const* prop_keys,
                                   const graph_prop_t* prop_vals,
                                   size_t num_props);
graph_vertex_t* qihse_graph_vertex_get(qihse_graph_t* g, uint64_t vertex_id);
bool qihse_graph_vertex_update(qihse_graph_t* g, uint64_t vertex_id,
                               const char* const* prop_keys,
                               const graph_prop_t* prop_vals,
                               size_t num_props);
bool qihse_graph_vertex_delete(qihse_graph_t* g, uint64_t vertex_id);
bool qihse_graph_vertex_add_label(qihse_graph_t* g, uint64_t vertex_id,
                                  const char* label);

/* --- Edge CRUD --- */
uint64_t qihse_graph_edge_create(qihse_graph_t* g, const char* type,
                                 uint64_t start, uint64_t end,
                                 const char* const* prop_keys,
                                 const graph_prop_t* prop_vals,
                                 size_t num_props);
graph_edge_t* qihse_graph_edge_get(qihse_graph_t* g, uint64_t edge_id);
bool qihse_graph_edge_update(qihse_graph_t* g, uint64_t edge_id,
                             const char* const* prop_keys,
                             const graph_prop_t* prop_vals,
                             size_t num_props);
bool qihse_graph_edge_delete(qihse_graph_t* g, uint64_t edge_id);

/* --- Adjacency / lookups --- */
size_t qihse_graph_get_neighbors(qihse_graph_t* g, uint64_t vertex_id,
                                 graph_dir_t direction,
                                 const char* edge_type_filter,
                                 graph_adj_t* out, size_t max_out);

size_t qihse_graph_get_vertices_by_label(qihse_graph_t* g, const char* label,
                                         uint64_t* out, size_t max_out);
size_t qihse_graph_get_edges_by_type(qihse_graph_t* g, const char* type,
                                     uint64_t* out, size_t max_out);
size_t qihse_graph_get_vertices_by_property(qihse_graph_t* g, const char* label,
                                            const char* prop_name,
                                            const graph_prop_t* value,
                                            uint64_t* out, size_t max_out);

/* --- Helpers --- */
const graph_prop_t* graph_vertex_get_property(const graph_vertex_t* v,
                                              const char* key);
const graph_prop_t* graph_edge_get_property(const graph_edge_t* e,
                                            const char* key);
void graph_prop_free(graph_prop_t* p);
void graph_vertex_free(graph_vertex_t* v);
void graph_edge_free(graph_edge_t* e);
graph_prop_t graph_prop_make_int64(int64_t v);
graph_prop_t graph_prop_make_double(double v);
graph_prop_t graph_prop_make_string(const char* s);
graph_prop_t graph_prop_make_bool(bool b);
bool graph_prop_equals(const graph_prop_t* a, const graph_prop_t* b);

/* --- Introspection --- */
size_t qihse_graph_vertex_count(qihse_graph_t* g);
size_t qihse_graph_edge_count(qihse_graph_t* g);
size_t qihse_graph_all_vertex_ids(qihse_graph_t* g, uint64_t* out, size_t max_out);

#ifdef __cplusplus
}
#endif

#endif /* QIHSE_GRAPH_STORE_H */
