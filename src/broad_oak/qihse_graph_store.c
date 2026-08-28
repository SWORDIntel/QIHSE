/* QIHSE Graph Storage Engine — in-memory property graph with indexes.
 *
 * Self-contained: does not depend on the KV store at link time so it can be
 * built standalone for tests. Persistence can be layered on top of the QIHSE
 * KV store (vertices under "v:ID", edges under "e:ID", adjacency "adj:ID")
 * by a higher-level module. */

#include "qihse_graph_store.h"
#include "qihse_arena.h"
#include "qihse_platform.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* ---- internal hash map: string key -> dynamic uint64_t id set ---- */

typedef struct {
    char* key;
    uint64_t* ids;
    size_t count;
    size_t cap;
} id_set_t;

typedef struct {
    id_set_t* buckets;
    size_t num_buckets;
    size_t count;
} str_id_map_t;

static uint64_t fnv1a(const char* s) {
    uint64_t h = 1469598103934665603ULL;
    while (*s) { h ^= (unsigned char)(*s++); h *= 1099511628211ULL; }
    return h;
}

static void simap_init(str_id_map_t* m, size_t nb) {
    m->num_buckets = nb ? nb : 256;
    m->buckets = calloc(m->num_buckets, sizeof(id_set_t));
    m->count = 0;
}

static id_set_t* simap_find_bucket(str_id_map_t* m, const char* key) {
    size_t idx = fnv1a(key) % m->num_buckets;
    while (m->buckets[idx].key) {
        if (strcmp(m->buckets[idx].key, key) == 0) return &m->buckets[idx];
        idx = (idx + 1) % m->num_buckets;
    }
    return &m->buckets[idx]; /* empty slot */
}

static void simap_add(str_id_map_t* m, const char* key, uint64_t id) {
    if (m->count * 10 >= m->num_buckets * 7) {
        /* resize */
        size_t oldn = m->num_buckets;
        id_set_t* oldb = m->buckets;
        simap_init(m, oldn * 2);
        for (size_t i = 0; i < oldn; ++i) {
            if (oldb[i].key) {
                id_set_t* nb = simap_find_bucket(m, oldb[i].key);
                nb->key = oldb[i].key;
                nb->ids = oldb[i].ids;
                nb->count = oldb[i].count;
                nb->cap = oldb[i].cap;
                m->count++;
            }
        }
        free(oldb);
    }
    id_set_t* b = simap_find_bucket(m, key);
    if (!b->key) {
        b->key = strdup(key);
        b->ids = NULL; b->count = 0; b->cap = 0;
        m->count++;
    }
    if (b->count == b->cap) {
        b->cap = b->cap ? b->cap * 2 : 8;
        b->ids = realloc(b->ids, b->cap * sizeof(uint64_t));
    }
    b->ids[b->count++] = id;
}

static id_set_t* simap_get(str_id_map_t* m, const char* key) {
    size_t idx = fnv1a(key) % m->num_buckets;
    while (m->buckets[idx].key) {
        if (strcmp(m->buckets[idx].key, key) == 0) return &m->buckets[idx];
        idx = (idx + 1) % m->num_buckets;
    }
    return NULL;
}

static void simap_remove_id(str_id_map_t* m, const char* key, uint64_t id) {
    id_set_t* b = simap_get(m, key);
    if (!b) return;
    for (size_t i = 0; i < b->count; ++i) {
        if (b->ids[i] == id) {
            b->ids[i] = b->ids[--b->count];
            return;
        }
    }
}

static void simap_destroy(str_id_map_t* m) {
    for (size_t i = 0; i < m->num_buckets; ++i) {
        if (m->buckets[i].key) {
            free(m->buckets[i].key);
            free(m->buckets[i].ids);
        }
    }
    free(m->buckets);
}

/* ---- property index: (label, prop_name, serialized_value) -> id set ---- */

typedef struct {
    char* composite_key; /* "label\0prop\0value" */
    uint64_t* ids;
    size_t count;
    size_t cap;
} prop_entry_t;

typedef struct {
    prop_entry_t* buckets;
    size_t num_buckets;
    size_t count;
} prop_map_t;

static void pmap_init(prop_map_t* m, size_t nb) {
    m->num_buckets = nb ? nb : 256;
    m->buckets = calloc(m->num_buckets, sizeof(prop_entry_t));
    m->count = 0;
}

static char* make_composite(const char* label, const char* prop,
                            const char* valstr) {
    size_t ll = strlen(label), pl = strlen(prop), vl = strlen(valstr);
    char* k = malloc(ll + 1 + pl + 1 + vl + 1);
    memcpy(k, label, ll); k[ll] = '\0';
    memcpy(k + ll + 1, prop, pl); k[ll + 1 + pl] = '\0';
    memcpy(k + ll + 1 + pl + 1, valstr, vl); k[ll + 1 + pl + 1 + vl] = '\0';
    return k;
}

static prop_entry_t* pmap_find(prop_map_t* m, const char* ck, size_t cklen) {
    uint64_t h = fnv1a(ck);
    size_t idx = h % m->num_buckets;
    while (m->buckets[idx].composite_key) {
        if (memcmp(m->buckets[idx].composite_key, ck, cklen) == 0)
            return &m->buckets[idx];
        idx = (idx + 1) % m->num_buckets;
    }
    return &m->buckets[idx];
}

static void pmap_add(prop_map_t* m, const char* label, const char* prop,
                     const char* valstr, uint64_t id) {
    if (m->count * 10 >= m->num_buckets * 7) {
        size_t oldn = m->num_buckets;
        prop_entry_t* oldb = m->buckets;
        pmap_init(m, oldn * 2);
        for (size_t i = 0; i < oldn; ++i) {
            if (oldb[i].composite_key) {
                size_t cklen = strlen(oldb[i].composite_key) + 1 +
                               strlen(oldb[i].composite_key + strlen(oldb[i].composite_key) + 1) + 1 +
                               strlen(oldb[i].composite_key + strlen(oldb[i].composite_key) + 1 +
                                      strlen(oldb[i].composite_key + strlen(oldb[i].composite_key) + 1) + 1) + 1;
                prop_entry_t* nb = pmap_find(m, oldb[i].composite_key, cklen);
                *nb = oldb[i];
                m->count++;
            }
        }
        free(oldb);
    }
    char* ck = make_composite(label, prop, valstr);
    size_t cklen = strlen(label) + 1 + strlen(prop) + 1 + strlen(valstr) + 1;
    prop_entry_t* b = pmap_find(m, ck, cklen);
    if (!b->composite_key) {
        b->composite_key = ck;
        b->ids = NULL; b->count = 0; b->cap = 0;
        m->count++;
    } else {
        free(ck);
    }
    if (b->count == b->cap) {
        b->cap = b->cap ? b->cap * 2 : 8;
        b->ids = realloc(b->ids, b->cap * sizeof(uint64_t));
    }
    b->ids[b->count++] = id;
}

static void pmap_remove_id(prop_map_t* m, const char* label, const char* prop,
                           const char* valstr, uint64_t id) {
    char ckbuf[512];
    size_t ll = strlen(label), pl = strlen(prop), vl = strlen(valstr);
    if (ll + 1 + pl + 1 + vl + 1 > sizeof(ckbuf)) return;
    memcpy(ckbuf, label, ll); ckbuf[ll] = '\0';
    memcpy(ckbuf + ll + 1, prop, pl); ckbuf[ll + 1 + pl] = '\0';
    memcpy(ckbuf + ll + 1 + pl + 1, valstr, vl); ckbuf[ll + 1 + pl + 1 + vl] = '\0';
    size_t cklen = ll + 1 + pl + 1 + vl + 1;
    prop_entry_t* b = pmap_find(m, ckbuf, cklen);
    if (!b->composite_key) return;
    for (size_t i = 0; i < b->count; ++i) {
        if (b->ids[i] == id) { b->ids[i] = b->ids[--b->count]; return; }
    }
}

static void pmap_destroy(prop_map_t* m) {
    for (size_t i = 0; i < m->num_buckets; ++i) {
        if (m->buckets[i].composite_key) {
            free(m->buckets[i].composite_key);
            free(m->buckets[i].ids);
        }
    }
    free(m->buckets);
}

/* ---- graph handle ---- */

struct qihse_graph_s {
    pthread_rwlock_t lock;
    uint64_t next_vertex_id;
    uint64_t next_edge_id;

    /* vertex/edge storage: hash by id */
    graph_vertex_t** vertices;  /* by id slot */
    size_t v_cap;
    graph_edge_t** edges;
    size_t e_cap;

    str_id_map_t label_index;
    str_id_map_t edge_type_index;
    prop_map_t prop_index;

    qihse_arena_t* arena; /* scratch arena for returned transient objects */
};

static graph_vertex_t** vslot(qihse_graph_t* g, uint64_t id) {
    if (id >= g->v_cap) return NULL;
    return &g->vertices[id];
}
static graph_edge_t** eslot(qihse_graph_t* g, uint64_t id) {
    if (id >= g->e_cap) return NULL;
    return &g->edges[id];
}

static void ensure_v_cap(qihse_graph_t* g, uint64_t id) {
    if (id < g->v_cap) return;
    size_t ncap = g->v_cap ? g->v_cap : 16;
    while (ncap <= id) ncap *= 2;
    g->vertices = realloc(g->vertices, ncap * sizeof(graph_vertex_t*));
    memset(g->vertices + g->v_cap, 0, (ncap - g->v_cap) * sizeof(graph_vertex_t*));
    g->v_cap = ncap;
}
static void ensure_e_cap(qihse_graph_t* g, uint64_t id) {
    if (id < g->e_cap) return;
    size_t ncap = g->e_cap ? g->e_cap : 16;
    while (ncap <= id) ncap *= 2;
    g->edges = realloc(g->edges, ncap * sizeof(graph_edge_t*));
    memset(g->edges + g->e_cap, 0, (ncap - g->e_cap) * sizeof(graph_edge_t*));
    g->e_cap = ncap;
}

/* ---- property helpers ---- */

graph_prop_t graph_prop_make_int64(int64_t v) {
    graph_prop_t p; p.type = GRAPH_PROP_INT64; p.val.i = v; return p;
}
graph_prop_t graph_prop_make_double(double v) {
    graph_prop_t p; p.type = GRAPH_PROP_DOUBLE; p.val.d = v; return p;
}
graph_prop_t graph_prop_make_string(const char* s) {
    graph_prop_t p; p.type = GRAPH_PROP_STRING; p.val.s = strdup(s ? s : ""); return p;
}
graph_prop_t graph_prop_make_bool(bool b) {
    graph_prop_t p; p.type = GRAPH_PROP_BOOL; p.val.b = b; return p;
}

void graph_prop_free(graph_prop_t* p) {
    if (!p) return;
    if (p->type == GRAPH_PROP_STRING) { free(p->val.s); p->val.s = NULL; }
    else if (p->type == GRAPH_PROP_ARRAY) { free(p->val.arr.data); p->val.arr.data = NULL; }
}

static graph_prop_t graph_prop_dup(const graph_prop_t* src) {
    graph_prop_t p = *src;
    if (p.type == GRAPH_PROP_STRING) p.val.s = strdup(src->val.s ? src->val.s : "");
    else if (p.type == GRAPH_PROP_ARRAY) {
        size_t esz = (p.val.arr.elem_type == GRAPH_PROP_DOUBLE) ? sizeof(double) :
                     (p.val.arr.elem_type == GRAPH_PROP_INT64) ? sizeof(int64_t) :
                     (p.val.arr.elem_type == GRAPH_PROP_STRING) ? sizeof(char*) : sizeof(double);
        void* d = malloc(p.val.arr.count * esz);
        memcpy(d, src->val.arr.data, p.val.arr.count * esz);
        p.val.arr.data = d;
    }
    return p;
}

bool graph_prop_equals(const graph_prop_t* a, const graph_prop_t* b) {
    if (!a || !b) return false;
    if (a->type != b->type) return false;
    switch (a->type) {
        case GRAPH_PROP_INT64: return a->val.i == b->val.i;
        case GRAPH_PROP_DOUBLE: return a->val.d == b->val.d;
        case GRAPH_PROP_BOOL: return a->val.b == b->val.b;
        case GRAPH_PROP_STRING: return strcmp(a->val.s, b->val.s) == 0;
        default: return false;
    }
}

/* serialize a property value to a canonical string for indexing */
static void prop_to_str(const graph_prop_t* p, char* buf, size_t bufsz) {
    switch (p->type) {
        case GRAPH_PROP_INT64: snprintf(buf, bufsz, "i%lld", (long long)p->val.i); break;
        case GRAPH_PROP_DOUBLE: snprintf(buf, bufsz, "d%.17g", p->val.d); break;
        case GRAPH_PROP_BOOL: snprintf(buf, bufsz, "b%d", p->val.b ? 1 : 0); break;
        case GRAPH_PROP_STRING: snprintf(buf, bufsz, "s%s", p->val.s); break;
        default: snprintf(buf, bufsz, "x"); break;
    }
}

const graph_prop_t* graph_vertex_get_property(const graph_vertex_t* v, const char* key) {
    if (!v) return NULL;
    for (size_t i = 0; i < v->num_props; ++i)
        if (strcmp(v->prop_keys[i], key) == 0) return &v->prop_vals[i];
    return NULL;
}
const graph_prop_t* graph_edge_get_property(const graph_edge_t* e, const char* key) {
    if (!e) return NULL;
    for (size_t i = 0; i < e->num_props; ++i)
        if (strcmp(e->prop_keys[i], key) == 0) return &e->prop_vals[i];
    return NULL;
}

void graph_vertex_free(graph_vertex_t* v) {
    if (!v) return;
    for (size_t i = 0; i < v->num_labels; ++i) free(v->labels[i]);
    free(v->labels);
    for (size_t i = 0; i < v->num_props; ++i) { free(v->prop_keys[i]); graph_prop_free(&v->prop_vals[i]); }
    free(v->prop_keys); free(v->prop_vals);
    free(v);
}
void graph_edge_free(graph_edge_t* e) {
    if (!e) return;
    for (size_t i = 0; i < e->num_props; ++i) { free(e->prop_keys[i]); graph_prop_free(&e->prop_vals[i]); }
    free(e->prop_keys); free(e->prop_vals);
    free(e);
}

/* ---- lifecycle ---- */

qihse_graph_t* qihse_graph_create(void) {
    qihse_graph_t* g = calloc(1, sizeof(qihse_graph_t));
    if (!g) return NULL;
    pthread_rwlock_init(&g->lock, NULL);
    g->next_vertex_id = 1;
    g->next_edge_id = 1;
    simap_init(&g->label_index, 256);
    simap_init(&g->edge_type_index, 256);
    pmap_init(&g->prop_index, 256);
    g->arena = qihse_arena_create(65536);
    return g;
}

void qihse_graph_destroy(qihse_graph_t* g) {
    if (!g) return;
    for (size_t i = 0; i < g->v_cap; ++i) graph_vertex_free(g->vertices[i]);
    for (size_t i = 0; i < g->e_cap; ++i) graph_edge_free(g->edges[i]);
    free(g->vertices); free(g->edges);
    simap_destroy(&g->label_index);
    simap_destroy(&g->edge_type_index);
    pmap_destroy(&g->prop_index);
    if (g->arena) qihse_arena_destroy(g->arena);
    pthread_rwlock_destroy(&g->lock);
    free(g);
}

/* ---- vertex CRUD ---- */

uint64_t qihse_graph_vertex_create(qihse_graph_t* g,
                                   const char* const* labels, size_t num_labels,
                                   const char* const* prop_keys,
                                   const graph_prop_t* prop_vals,
                                   size_t num_props) {
    if (!g) return 0;
    pthread_rwlock_wrlock(&g->lock);
    uint64_t id = g->next_vertex_id++;
    ensure_v_cap(g, id);
    graph_vertex_t* v = calloc(1, sizeof(graph_vertex_t));
    v->id = id;
    v->num_labels = num_labels;
    v->labels = calloc(num_labels ? num_labels : 1, sizeof(char*));
    for (size_t i = 0; i < num_labels; ++i) {
        v->labels[i] = strdup(labels[i]);
        simap_add(&g->label_index, labels[i], id);
    }
    v->num_props = num_props;
    v->prop_keys = calloc(num_props ? num_props : 1, sizeof(char*));
    v->prop_vals = calloc(num_props ? num_props : 1, sizeof(graph_prop_t));
    for (size_t i = 0; i < num_props; ++i) {
        v->prop_keys[i] = strdup(prop_keys[i]);
        v->prop_vals[i] = graph_prop_dup(&prop_vals[i]);
        /* index by each label (or "" if none) */
        char vbuf[128]; prop_to_str(&prop_vals[i], vbuf, sizeof(vbuf));
        if (num_labels == 0) pmap_add(&g->prop_index, "", prop_keys[i], vbuf, id);
        else for (size_t l = 0; l < num_labels; ++l)
            pmap_add(&g->prop_index, labels[l], prop_keys[i], vbuf, id);
    }
    g->vertices[id] = v;
    pthread_rwlock_unlock(&g->lock);
    return id;
}

graph_vertex_t* qihse_graph_vertex_get(qihse_graph_t* g, uint64_t vertex_id) {
    if (!g) return NULL;
    pthread_rwlock_rdlock(&g->lock);
    graph_vertex_t** slot = vslot(g, vertex_id);
    graph_vertex_t* v = slot ? *slot : NULL;
    if (!v) { pthread_rwlock_unlock(&g->lock); return NULL; }
    /* return a deep copy so callers can use without holding lock */
    graph_vertex_t* copy = calloc(1, sizeof(graph_vertex_t));
    copy->id = v->id;
    copy->num_labels = v->num_labels;
    copy->labels = calloc(v->num_labels ? v->num_labels : 1, sizeof(char*));
    for (size_t i = 0; i < v->num_labels; ++i) copy->labels[i] = strdup(v->labels[i]);
    copy->num_props = v->num_props;
    copy->prop_keys = calloc(v->num_props ? v->num_props : 1, sizeof(char*));
    copy->prop_vals = calloc(v->num_props ? v->num_props : 1, sizeof(graph_prop_t));
    for (size_t i = 0; i < v->num_props; ++i) {
        copy->prop_keys[i] = strdup(v->prop_keys[i]);
        copy->prop_vals[i] = graph_prop_dup(&v->prop_vals[i]);
    }
    pthread_rwlock_unlock(&g->lock);
    return copy;
}

bool qihse_graph_vertex_update(qihse_graph_t* g, uint64_t vertex_id,
                               const char* const* prop_keys,
                               const graph_prop_t* prop_vals,
                               size_t num_props) {
    if (!g) return false;
    pthread_rwlock_wrlock(&g->lock);
    graph_vertex_t** slot = vslot(g, vertex_id);
    if (!slot || !*slot) { pthread_rwlock_unlock(&g->lock); return false; }
    graph_vertex_t* v = *slot;
    for (size_t i = 0; i < num_props; ++i) {
        /* find existing */
        size_t j;
        for (j = 0; j < v->num_props; ++j)
            if (strcmp(v->prop_keys[j], prop_keys[i]) == 0) break;
        if (j == v->num_props) {
            v->prop_keys = realloc(v->prop_keys, (v->num_props + 1) * sizeof(char*));
            v->prop_vals = realloc(v->prop_vals, (v->num_props + 1) * sizeof(graph_prop_t));
            v->prop_keys[j] = strdup(prop_keys[i]);
            v->prop_vals[j] = graph_prop_dup(&prop_vals[i]);
            v->num_props++;
        } else {
            graph_prop_free(&v->prop_vals[j]);
            v->prop_vals[j] = graph_prop_dup(&prop_vals[i]);
        }
        /* update prop index */
        char vbuf[128]; prop_to_str(&prop_vals[i], vbuf, sizeof(vbuf));
        if (v->num_labels == 0) pmap_add(&g->prop_index, "", prop_keys[i], vbuf, vertex_id);
        else for (size_t l = 0; l < v->num_labels; ++l)
            pmap_add(&g->prop_index, v->labels[l], prop_keys[i], vbuf, vertex_id);
    }
    pthread_rwlock_unlock(&g->lock);
    return true;
}

bool qihse_graph_vertex_remove_property(qihse_graph_t* g, uint64_t vertex_id,
                                        const char* prop_key) {
    if (!g || !prop_key) return false;
    pthread_rwlock_wrlock(&g->lock);
    graph_vertex_t** slot = vslot(g, vertex_id);
    if (!slot || !*slot) { pthread_rwlock_unlock(&g->lock); return false; }
    graph_vertex_t* v = *slot;
    size_t j;
    for (j = 0; j < v->num_props; ++j) {
        if (strcmp(v->prop_keys[j], prop_key) == 0) break;
    }
    if (j == v->num_props) {
        pthread_rwlock_unlock(&g->lock);
        return false;
    }
    /* remove from prop index */
    char vbuf[128];
    prop_to_str(&v->prop_vals[j], vbuf, sizeof(vbuf));
    if (v->num_labels == 0) {
        pmap_remove_id(&g->prop_index, "", v->prop_keys[j], vbuf, vertex_id);
    } else {
        for (size_t l = 0; l < v->num_labels; ++l) {
            pmap_remove_id(&g->prop_index, v->labels[l], v->prop_keys[j], vbuf, vertex_id);
        }
    }
    /* free key string and prop val */
    free(v->prop_keys[j]);
    graph_prop_free(&v->prop_vals[j]);
    /* shift remaining entries down */
    for (size_t k = j; k + 1 < v->num_props; ++k) {
        v->prop_keys[k] = v->prop_keys[k + 1];
        v->prop_vals[k] = v->prop_vals[k + 1];
    }
    v->num_props--;
    pthread_rwlock_unlock(&g->lock);
    return true;
}

bool qihse_graph_vertex_add_label(qihse_graph_t* g, uint64_t vertex_id,
                                  const char* label) {
    if (!g) return false;
    pthread_rwlock_wrlock(&g->lock);
    graph_vertex_t** slot = vslot(g, vertex_id);
    if (!slot || !*slot) { pthread_rwlock_unlock(&g->lock); return false; }
    graph_vertex_t* v = *slot;
    for (size_t i = 0; i < v->num_labels; ++i)
        if (strcmp(v->labels[i], label) == 0) { pthread_rwlock_unlock(&g->lock); return true; }
    v->labels = realloc(v->labels, (v->num_labels + 1) * sizeof(char*));
    v->labels[v->num_labels++] = strdup(label);
    simap_add(&g->label_index, label, vertex_id);
    pthread_rwlock_unlock(&g->lock);
    return true;
}

/* forward decl for edge deletion during vertex delete */
static bool qihse_graph_edge_delete_locked(qihse_graph_t* g, uint64_t edge_id);

bool qihse_graph_vertex_delete(qihse_graph_t* g, uint64_t vertex_id) {
    if (!g) return false;
    pthread_rwlock_wrlock(&g->lock);
    graph_vertex_t** slot = vslot(g, vertex_id);
    if (!slot || !*slot) { pthread_rwlock_unlock(&g->lock); return false; }
    graph_vertex_t* v = *slot;

    /* delete all connected edges */
    for (size_t i = 0; i < g->e_cap; ++i) {
        graph_edge_t* e = g->edges[i];
        if (e && (e->start_vertex_id == vertex_id || e->end_vertex_id == vertex_id))
            qihse_graph_edge_delete_locked(g, e->id);
    }
    /* remove from label index */
    for (size_t i = 0; i < v->num_labels; ++i)
        simap_remove_id(&g->label_index, v->labels[i], vertex_id);
    /* remove from prop index */
    for (size_t i = 0; i < v->num_props; ++i) {
        char vbuf[128]; prop_to_str(&v->prop_vals[i], vbuf, sizeof(vbuf));
        if (v->num_labels == 0) pmap_remove_id(&g->prop_index, "", v->prop_keys[i], vbuf, vertex_id);
        else for (size_t l = 0; l < v->num_labels; ++l)
            pmap_remove_id(&g->prop_index, v->labels[l], v->prop_keys[i], vbuf, vertex_id);
    }
    graph_vertex_free(v);
    g->vertices[vertex_id] = NULL;
    pthread_rwlock_unlock(&g->lock);
    return true;
}

/* ---- edge CRUD ---- */

uint64_t qihse_graph_edge_create(qihse_graph_t* g, const char* type,
                                 uint64_t start, uint64_t end,
                                 const char* const* prop_keys,
                                 const graph_prop_t* prop_vals,
                                 size_t num_props) {
    if (!g || !type) return 0;
    pthread_rwlock_wrlock(&g->lock);
    /* validate endpoints */
    if (start >= g->v_cap || !g->vertices[start] ||
        end >= g->v_cap || !g->vertices[end]) {
        pthread_rwlock_unlock(&g->lock); return 0;
    }
    uint64_t id = g->next_edge_id++;
    ensure_e_cap(g, id);
    graph_edge_t* e = calloc(1, sizeof(graph_edge_t));
    e->id = id;
    strncpy(e->type, type, sizeof(e->type) - 1);
    e->start_vertex_id = start;
    e->end_vertex_id = end;
    e->num_props = num_props;
    e->prop_keys = calloc(num_props ? num_props : 1, sizeof(char*));
    e->prop_vals = calloc(num_props ? num_props : 1, sizeof(graph_prop_t));
    for (size_t i = 0; i < num_props; ++i) {
        e->prop_keys[i] = strdup(prop_keys[i]);
        e->prop_vals[i] = graph_prop_dup(&prop_vals[i]);
    }
    g->edges[id] = e;
    simap_add(&g->edge_type_index, type, id);
    pthread_rwlock_unlock(&g->lock);
    return id;
}

graph_edge_t* qihse_graph_edge_get(qihse_graph_t* g, uint64_t edge_id) {
    if (!g) return NULL;
    pthread_rwlock_rdlock(&g->lock);
    graph_edge_t** slot = eslot(g, edge_id);
    graph_edge_t* e = slot ? *slot : NULL;
    if (!e) { pthread_rwlock_unlock(&g->lock); return NULL; }
    graph_edge_t* copy = calloc(1, sizeof(graph_edge_t));
    *copy = *e;
    copy->prop_keys = calloc(e->num_props ? e->num_props : 1, sizeof(char*));
    copy->prop_vals = calloc(e->num_props ? e->num_props : 1, sizeof(graph_prop_t));
    for (size_t i = 0; i < e->num_props; ++i) {
        copy->prop_keys[i] = strdup(e->prop_keys[i]);
        copy->prop_vals[i] = graph_prop_dup(&e->prop_vals[i]);
    }
    pthread_rwlock_unlock(&g->lock);
    return copy;
}

bool qihse_graph_edge_update(qihse_graph_t* g, uint64_t edge_id,
                             const char* const* prop_keys,
                             const graph_prop_t* prop_vals,
                             size_t num_props) {
    if (!g) return false;
    pthread_rwlock_wrlock(&g->lock);
    graph_edge_t** slot = eslot(g, edge_id);
    if (!slot || !*slot) { pthread_rwlock_unlock(&g->lock); return false; }
    graph_edge_t* e = *slot;
    for (size_t i = 0; i < num_props; ++i) {
        size_t j;
        for (j = 0; j < e->num_props; ++j)
            if (strcmp(e->prop_keys[j], prop_keys[i]) == 0) break;
        if (j == e->num_props) {
            e->prop_keys = realloc(e->prop_keys, (e->num_props + 1) * sizeof(char*));
            e->prop_vals = realloc(e->prop_vals, (e->num_props + 1) * sizeof(graph_prop_t));
            e->prop_keys[j] = strdup(prop_keys[i]);
            e->prop_vals[j] = graph_prop_dup(&prop_vals[i]);
            e->num_props++;
        } else {
            graph_prop_free(&e->prop_vals[j]);
            e->prop_vals[j] = graph_prop_dup(&prop_vals[i]);
        }
    }
    pthread_rwlock_unlock(&g->lock);
    return true;
}

bool qihse_graph_edge_remove_property(qihse_graph_t* g, uint64_t edge_id,
                                      const char* prop_key) {
    if (!g || !prop_key) return false;
    pthread_rwlock_wrlock(&g->lock);
    graph_edge_t** slot = eslot(g, edge_id);
    if (!slot || !*slot) { pthread_rwlock_unlock(&g->lock); return false; }
    graph_edge_t* e = *slot;
    size_t j;
    for (j = 0; j < e->num_props; ++j) {
        if (strcmp(e->prop_keys[j], prop_key) == 0) break;
    }
    if (j == e->num_props) {
        pthread_rwlock_unlock(&g->lock);
        return false;
    }
    /* free key string and prop val */
    free(e->prop_keys[j]);
    graph_prop_free(&e->prop_vals[j]);
    /* shift remaining entries down */
    for (size_t k = j; k + 1 < e->num_props; ++k) {
        e->prop_keys[k] = e->prop_keys[k + 1];
        e->prop_vals[k] = e->prop_vals[k + 1];
    }
    e->num_props--;
    pthread_rwlock_unlock(&g->lock);
    return true;
}

static bool qihse_graph_edge_delete_locked(qihse_graph_t* g, uint64_t edge_id) {
    graph_edge_t** slot = eslot(g, edge_id);
    if (!slot || !*slot) return false;
    graph_edge_t* e = *slot;
    simap_remove_id(&g->edge_type_index, e->type, edge_id);
    graph_edge_free(e);
    g->edges[edge_id] = NULL;
    return true;
}

bool qihse_graph_edge_delete(qihse_graph_t* g, uint64_t edge_id) {
    if (!g) return false;
    pthread_rwlock_wrlock(&g->lock);
    bool ok = qihse_graph_edge_delete_locked(g, edge_id);
    pthread_rwlock_unlock(&g->lock);
    return ok;
}

/* ---- adjacency / lookups ---- */

size_t qihse_graph_get_neighbors(qihse_graph_t* g, uint64_t vertex_id,
                                 graph_dir_t direction,
                                 const char* edge_type_filter,
                                 graph_adj_t* out, size_t max_out) {
    if (!g || !out || max_out == 0) return 0;
    pthread_rwlock_rdlock(&g->lock);
    if (vertex_id >= g->v_cap || !g->vertices[vertex_id]) {
        pthread_rwlock_unlock(&g->lock); return 0;
    }
    size_t n = 0;
    for (size_t i = 0; i < g->e_cap && n < max_out; ++i) {
        graph_edge_t* e = g->edges[i];
        if (!e) continue;
        graph_dir_t dir;
        uint64_t neighbor;
        if (e->start_vertex_id == vertex_id) {
            dir = GRAPH_DIR_OUTGOING; neighbor = e->end_vertex_id;
        } else if (e->end_vertex_id == vertex_id) {
            dir = GRAPH_DIR_INCOMING; neighbor = e->start_vertex_id;
        } else continue;
        if (direction != GRAPH_DIR_BOTH && direction != dir) continue;
        if (edge_type_filter && strcmp(e->type, edge_type_filter) != 0) continue;
        out[n].edge_id = e->id;
        out[n].direction = dir;
        out[n].neighbor_id = neighbor;
        strncpy(out[n].edge_type, e->type, sizeof(out[n].edge_type) - 1);
        out[n].edge_type[sizeof(out[n].edge_type) - 1] = '\0';
        n++;
    }
    pthread_rwlock_unlock(&g->lock);
    return n;
}

size_t qihse_graph_get_vertices_by_label(qihse_graph_t* g, const char* label,
                                         uint64_t* out, size_t max_out) {
    if (!g || !label || !out) return 0;
    pthread_rwlock_rdlock(&g->lock);
    id_set_t* s = simap_get(&g->label_index, label);
    size_t n = 0;
    if (s) {
        for (size_t i = 0; i < s->count && n < max_out; ++i) out[n++] = s->ids[i];
    }
    pthread_rwlock_unlock(&g->lock);
    return n;
}

size_t qihse_graph_get_edges_by_type(qihse_graph_t* g, const char* type,
                                     uint64_t* out, size_t max_out) {
    if (!g || !type || !out) return 0;
    pthread_rwlock_rdlock(&g->lock);
    id_set_t* s = simap_get(&g->edge_type_index, type);
    size_t n = 0;
    if (s) {
        for (size_t i = 0; i < s->count && n < max_out; ++i) out[n++] = s->ids[i];
    }
    pthread_rwlock_unlock(&g->lock);
    return n;
}

size_t qihse_graph_get_vertices_by_property(qihse_graph_t* g, const char* label,
                                            const char* prop_name,
                                            const graph_prop_t* value,
                                            uint64_t* out, size_t max_out) {
    if (!g || !prop_name || !value || !out) return 0;
    char vbuf[128]; prop_to_str(value, vbuf, sizeof(vbuf));
    const char* lbl = label ? label : "";
    pthread_rwlock_rdlock(&g->lock);
    char ckbuf[512];
    size_t ll = strlen(lbl), pl = strlen(prop_name), vl = strlen(vbuf);
    if (ll + 1 + pl + 1 + vl + 1 > sizeof(ckbuf)) { pthread_rwlock_unlock(&g->lock); return 0; }
    memcpy(ckbuf, lbl, ll); ckbuf[ll] = '\0';
    memcpy(ckbuf + ll + 1, prop_name, pl); ckbuf[ll + 1 + pl] = '\0';
    memcpy(ckbuf + ll + 1 + pl + 1, vbuf, vl); ckbuf[ll + 1 + pl + 1 + vl] = '\0';
    size_t cklen = ll + 1 + pl + 1 + vl + 1;
    prop_entry_t* b = pmap_find(&g->prop_index, ckbuf, cklen);
    size_t n = 0;
    if (b && b->composite_key) {
        for (size_t i = 0; i < b->count && n < max_out; ++i) out[n++] = b->ids[i];
    }
    pthread_rwlock_unlock(&g->lock);
    return n;
}

size_t qihse_graph_vertex_count(qihse_graph_t* g) {
    if (!g) return 0;
    pthread_rwlock_rdlock(&g->lock);
    size_t n = 0;
    for (size_t i = 0; i < g->v_cap; ++i) if (g->vertices[i]) n++;
    pthread_rwlock_unlock(&g->lock);
    return n;
}
size_t qihse_graph_edge_count(qihse_graph_t* g) {
    if (!g) return 0;
    pthread_rwlock_rdlock(&g->lock);
    size_t n = 0;
    for (size_t i = 0; i < g->e_cap; ++i) if (g->edges[i]) n++;
    pthread_rwlock_unlock(&g->lock);
    return n;
}

size_t qihse_graph_all_vertex_ids(qihse_graph_t* g, uint64_t* out, size_t max_out) {
    if (!g || !out) return 0;
    pthread_rwlock_rdlock(&g->lock);
    size_t n = 0;
    for (size_t i = 0; i < g->v_cap && n < max_out; ++i)
        if (g->vertices[i]) out[n++] = g->vertices[i]->id;
    pthread_rwlock_unlock(&g->lock);
    return n;
}
