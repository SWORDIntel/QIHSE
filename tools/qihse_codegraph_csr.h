/* SPDX-License-Identifier: LicenseRef-SRSL-1.1 */
#ifndef QIHSE_CODEGRAPH_CSR_H
#define QIHSE_CODEGRAPH_CSR_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "qihse_auth.h"

/* Immutable CodeGraph query projection. Original records remain in the
 * authoritative snapshot; this holds exactly the fields used by traversal.
 * Vertex IDs are dense, one-based, and private to a loaded generation. */
typedef struct cg_csr cg_csr;
typedef struct {
    const char *type, *file;
    int64_t line;
    double confidence;
    uint32_t source, target;
} cg_csr_edge;

/* The authenticated principal is borrowed and must outlive this projection.
 * Reads recheck its active state; this private projection is populated only
 * from CodeGraph records admitted by the authenticated KV loader. */
cg_csr *cg_csr_create(qihse_user_t *principal, size_t nodes, size_t edges);
void cg_csr_destroy(cg_csr *graph);
/* Export adapters must propagate the exact authenticated principal rather than
 * using another handle's inherited authority to read it. */
bool cg_csr_has_principal(const cg_csr *graph, const qihse_user_t *principal);
/* Internal immutable-index adapter for principal-bound persisted projections.
 * Takes ownership of the four CSR arrays only on success; endpoint arrays and
 * callback context remain borrowed. Validates complete ordered incidence against
 * endpoints before exposing any index. Returned evidence must remain stable until
 * graph destruction. All reads enforce the explicit aggregate labels. */
typedef const cg_csr_edge *(*cg_csr_edge_reader)(void *context, uint32_t edge);
cg_csr *cg_csr_create_indexed(qihse_user_t *principal, size_t nodes,
    size_t edges, uint16_t classification, uint16_t sci,
    uint32_t *out_offsets, uint32_t *in_offsets,
    uint32_t *out_edges, uint32_t *in_edges,
    const uint32_t *sources, const uint32_t *targets,
    cg_csr_edge_reader reader, void *context);
/* Borrowed, stable until destroy. Construction only; NULL reports failure. */
const char *cg_csr_intern(cg_csr *graph, const char *text);
bool cg_csr_add_edge(cg_csr *graph, uint32_t source, uint32_t target,
                     const char *type, const char *file, int64_t line,
                     double confidence);
/* Seals the graph, discards construction indexes; no later mutations allowed. */
bool cg_csr_finish(cg_csr *graph);
const uint32_t *cg_csr_incident(const cg_csr *graph, uint32_t vertex,
                              bool incoming, size_t *count);
const cg_csr_edge *cg_csr_get_edge(const cg_csr *graph, uint32_t edge);
size_t cg_csr_edge_count(const cg_csr *graph);
/* Actual owned allocation sizes, excluding allocator overhead. */
size_t cg_csr_bytes(const cg_csr *graph);
#endif
