/* SPDX-License-Identifier: LicenseRef-SRSL-1.1 */
#include "qihse_codegraph_csr.h"
#include <errno.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>

typedef struct string_block {
    struct string_block *next;
    size_t used, capacity;
    char data[];
} string_block;
typedef struct { const char *text; uint64_t hash; } string_slot;
struct cg_csr {
    qihse_user_t *principal;
    size_t nodes, capacity, used, bytes, strings, slots;
    cg_csr_edge *edges;
    uint32_t *out_offsets, *in_offsets, *out_edges, *in_edges;
    string_block *blocks;
    string_slot *table;
    bool sealed;
    uint16_t classification, sci;
    uint32_t tenant;
    cg_csr_edge_reader reader;
    void *reader_context;
};

static bool active_user(qihse_user_t *principal) {
    if (principal && qihse_auth_user_is_active(principal) &&
        qihse_auth_can_access(principal, 0, 0)) return true;
    errno = EACCES;
    return false;
}
static bool active(const cg_csr *g) {
    if (!active_user(g ? g->principal : NULL)) return false;
    if (((!g->classification && !g->sci) ||
         qihse_auth_can_access(g->principal, g->classification, g->sci)) &&
        qihse_user_get_tenant_id(g->principal) == g->tenant) return true;
    errno = EACCES; return false;
}

static uint64_t string_hash(const char *s) {
    uint64_t h = UINT64_C(14695981039346656037);
    for (; *s; ++s) { h ^= (unsigned char)*s; h *= UINT64_C(1099511628211); }
    return h;
}
static bool resize_strings(cg_csr *g, size_t count) {
    if (count > SIZE_MAX / sizeof(*g->table)) { errno = EOVERFLOW; return false; }
    string_slot *next = calloc(count, sizeof(*next));
    if (!next) return false;
    for (size_t i = 0; i < g->slots; ++i) if (g->table[i].text) {
        size_t at = (size_t)g->table[i].hash & (count - 1);
        while (next[at].text) at = (at + 1) & (count - 1);
        next[at] = g->table[i];
    }
    g->bytes += (count - g->slots) * sizeof(*next);
    free(g->table); g->table = next; g->slots = count;
    return true;
}
const char *cg_csr_intern(cg_csr *g, const char *text) {
    if (!active(g)) return NULL;
    if (g->sealed || !text) { errno = EINVAL; return NULL; }
    if (!g->slots || g->strings >= g->slots - g->slots / 4) {
        if (g->slots > SIZE_MAX / 2 || !resize_strings(g, g->slots ? g->slots * 2 : 256))
            return NULL;
    }
    uint64_t hash = string_hash(text);
    size_t at = (size_t)hash & (g->slots - 1);
    while (g->table[at].text) {
        if (g->table[at].hash == hash && !strcmp(g->table[at].text, text))
            return g->table[at].text;
        at = (at + 1) & (g->slots - 1);
    }
    size_t length = strlen(text) + 1;
    string_block *b = g->blocks;
    if (!b || length > b->capacity - b->used) {
        size_t cap = length > 65536 ? length : 65536;
        if (cap > SIZE_MAX - sizeof(*b)) { errno = EOVERFLOW; return NULL; }
        b = malloc(sizeof(*b) + cap);
        if (!b) return NULL;
        *b = (string_block){.next = g->blocks, .capacity = cap};
        g->blocks = b; g->bytes += sizeof(*b) + cap;
    }
    char *saved = b->data + b->used;
    memcpy(saved, text, length); b->used += length;
    g->table[at] = (string_slot){.text = saved, .hash = hash};
    ++g->strings;
    return saved;
}
cg_csr *cg_csr_create(qihse_user_t *principal, size_t nodes, size_t edges) {
    if (!active_user(principal)) return NULL;
    if (nodes > UINT32_MAX - 2 || edges > UINT32_MAX ||
        nodes + 2 > SIZE_MAX / sizeof(uint32_t) ||
        edges > SIZE_MAX / sizeof(cg_csr_edge)) { errno = EOVERFLOW; return NULL; }
    cg_csr *g = calloc(1, sizeof(*g));
    if (!g) return NULL;
    g->principal = principal; g->tenant = qihse_user_get_tenant_id(principal);
    g->nodes = nodes; g->capacity = edges; g->bytes = sizeof(*g);
    size_t ne = edges ? edges : 1;
    g->edges = calloc(ne, sizeof(*g->edges));
    g->out_offsets = calloc(nodes + 2, sizeof(*g->out_offsets));
    g->in_offsets = calloc(nodes + 2, sizeof(*g->in_offsets));
    g->out_edges = malloc(ne * sizeof(*g->out_edges));
    g->in_edges = malloc(ne * sizeof(*g->in_edges));
    if (!g->edges || !g->out_offsets || !g->in_offsets || !g->out_edges || !g->in_edges) {
        cg_csr_destroy(g); return NULL;
    }
    g->bytes += ne * (sizeof(*g->edges) + 2 * sizeof(uint32_t)) +
                2 * (nodes + 2) * sizeof(uint32_t);
    return g;
}
bool cg_csr_add_edge(cg_csr *g, uint32_t source, uint32_t target,
                     const char *type, const char *file, int64_t line, double confidence) {
    if (!active(g)) return false;
    if (g->sealed || g->used >= g->capacity || !source || source > g->nodes ||
        !target || target > g->nodes || !isfinite(confidence)) { errno = EINVAL; return false; }
    const char *saved_type = cg_csr_intern(g, type), *saved_file = cg_csr_intern(g, file);
    if (!saved_type || !saved_file) return false;
    g->edges[g->used++] = (cg_csr_edge){.type = saved_type, .file = saved_file,
        .line = line, .confidence = confidence, .source = source, .target = target};
    ++g->out_offsets[source + 1]; ++g->in_offsets[target + 1];
    return true;
}
bool cg_csr_finish(cg_csr *g) {
    if (!active(g)) return false;
    if (g->sealed || g->used != g->capacity) { errno = EINVAL; return false; }
    size_t size = (g->nodes + 2) * sizeof(uint32_t);
    uint32_t *out = malloc(size), *in = malloc(size);
    if (!out || !in) { free(out); free(in); return false; }
    for (size_t i = 1; i < g->nodes + 2; ++i) {
        g->out_offsets[i] += g->out_offsets[i - 1];
        g->in_offsets[i] += g->in_offsets[i - 1];
    }
    memcpy(out, g->out_offsets, size); memcpy(in, g->in_offsets, size);
    /* Counting sort preserves the source record order within each adjacency. */
    for (uint32_t i = 0; i < g->used; ++i) {
        const cg_csr_edge *e = &g->edges[i];
        g->out_edges[out[e->source]++] = i;
        g->in_edges[in[e->target]++] = i;
    }
    free(out); free(in);
    g->bytes -= g->slots * sizeof(*g->table);
    free(g->table); g->table = NULL; g->slots = 0; g->sealed = true;
    return true;
}
const uint32_t *cg_csr_incident(const cg_csr *g, uint32_t vertex,
                              bool incoming, size_t *count) {
    if (count) *count = 0;
    if (!active(g)) return NULL;
    if (!g->sealed || !count || !vertex || vertex > g->nodes) return NULL;
    const uint32_t *offsets = incoming ? g->in_offsets : g->out_offsets;
    *count = (size_t)offsets[vertex + 1] - offsets[vertex];
    return (incoming ? g->in_edges : g->out_edges) + offsets[vertex];
}
const cg_csr_edge *cg_csr_get_edge(const cg_csr *g, uint32_t edge) {
    if (!active(g) || !g->sealed || edge >= g->used) return NULL;
    if (!g->reader) return &g->edges[edge];
    const cg_csr_edge *result = g->reader(g->reader_context, edge);
    return active(g) ? result : NULL;
}
size_t cg_csr_edge_count(const cg_csr *g) { return active(g) ? g->used : 0; }
size_t cg_csr_bytes(const cg_csr *g) { return active(g) ? g->bytes : 0; }
void cg_csr_destroy(cg_csr *g) {
    if (!g) return;
    free(g->edges); free(g->out_offsets); free(g->in_offsets);
    free(g->out_edges); free(g->in_edges); free(g->table);
    string_block *b = g->blocks;
    while (b) { string_block *next = b->next; free(b); b = next; }
    free(g);
}

cg_csr *cg_csr_create_indexed(qihse_user_t *principal, size_t nodes,
    size_t edges, uint16_t classification, uint16_t sci,
    uint32_t *out_offsets, uint32_t *in_offsets,
    uint32_t *out_edges, uint32_t *in_edges,
    const uint32_t *sources, const uint32_t *targets,
    cg_csr_edge_reader reader, void *context) {
    if (!active_user(principal) || !qihse_auth_can_access(principal, classification, sci)) {
        errno = EACCES; return NULL;
    }
    if (nodes > UINT32_MAX - 2 || edges > UINT32_MAX || !reader ||
        !out_offsets || !in_offsets || !out_edges || !in_edges ||
        !sources || !targets || out_offsets[0] || in_offsets[0] ||
        out_offsets[1] || in_offsets[1] || out_offsets[nodes + 1] != edges ||
        in_offsets[nodes + 1] != edges) { errno = EINVAL; return NULL; }
    for (size_t i = 0; i < edges; ++i)
        if (!sources[i] || sources[i] > nodes || !targets[i] || targets[i] > nodes) {
            errno = EINVAL; return NULL;
        }
    for (size_t v = 1; v <= nodes; ++v) {
        if (out_offsets[v] > out_offsets[v + 1] || out_offsets[v + 1] > edges ||
            in_offsets[v] > in_offsets[v + 1] || in_offsets[v + 1] > edges) {
            errno = EINVAL; return NULL;
        }
        for (size_t p = out_offsets[v]; p < out_offsets[v + 1]; ++p)
            if (out_edges[p] >= edges || sources[out_edges[p]] != v ||
                (p > out_offsets[v] && out_edges[p - 1] >= out_edges[p])) {
                errno = EINVAL; return NULL;
            }
        for (size_t p = in_offsets[v]; p < in_offsets[v + 1]; ++p)
            if (in_edges[p] >= edges || targets[in_edges[p]] != v ||
                (p > in_offsets[v] && in_edges[p - 1] >= in_edges[p])) {
                errno = EINVAL; return NULL;
            }
    }
    cg_csr *g = calloc(1, sizeof(*g));
    if (!g) return NULL;
    g->principal = principal; g->tenant = qihse_user_get_tenant_id(principal); g->nodes = nodes; g->capacity = g->used = edges;
    g->classification = classification; g->sci = sci;
    g->out_offsets = out_offsets; g->in_offsets = in_offsets;
    g->out_edges = out_edges; g->in_edges = in_edges;
    g->reader = reader; g->reader_context = context; g->sealed = true;
    g->bytes = sizeof(*g) + 2 * (nodes + 2) * sizeof(uint32_t) +
        2 * edges * sizeof(uint32_t);
    if (!active(g)) { free(g); return NULL; }
    return g;
}

bool cg_csr_has_principal(const cg_csr *g, const qihse_user_t *principal) {
    if (g && principal && g->principal == principal && active(g)) return true;
    errno = EACCES; return false;
}
