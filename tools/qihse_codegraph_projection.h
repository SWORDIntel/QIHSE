/* SPDX-License-Identifier: LicenseRef-SRSL-1.1 */
#ifndef QIHSE_CODEGRAPH_PROJECTION_H
#define QIHSE_CODEGRAPH_PROJECTION_H
#include "qihse_codegraph_checksum.h"
#include "qihse_codegraph_csr.h"
#include <stdio.h>

/* A disposable query projection, never the authoritative graph. All unknown
 * fields/unresolved records remain in the canonical snapshot. The caller must
 * verify that snapshot against the current trusted manifest before using this
 * projection. The trusted manifest also supplies this binding and cache digest;
 * neither labels nor a digest found only inside a supplied file are authority.
 */
#define CG_PROJECTION_MAGIC "QCGI0001"
#define CG_PROJECTION_FORMAT "qihse-codegraph-query-v1"
typedef struct {
  cg_snapshot_checksum source;
  uint16_t classification, sci;
  uint32_t tenant, principal_id;
  /* Validated canonical storage contract: raw0, zstd1, packedv2=2, v3=3,
   * chunkedv4=4, incremental generation5. A cache cannot relabel its source. */
  uint32_t source_format;
} cg_projection_binding;

typedef struct {
  char id[65];
  const char *file, *name, *kind;
  int line, end_line, is_test;
  uint64_t vertex;
} cg_projection_node;

typedef struct cg_projection cg_projection;
typedef struct {
  cg_csr *graph;
  cg_projection_node *nodes;
  cg_projection_node **by_vertex, **by_name, **by_file;
  size_t node_count, edge_count, unresolved;
  const char *meta_json, *end_json;
} cg_projection_view;

/* Writes an empty private named staging FILE (owned, mode0600, one link), never
 * publishes by path. by_name and by_file are permutations of nodes[] in the
 * CLI's existing comparison order. The principal must be authorized for every
 * input; binding labels must be the aggregate of all input labels, not a
 * caller-selected downgrade. */
bool cg_projection_write(FILE *output, qihse_user_t *principal,
                         const cg_projection_binding *binding,
                         const cg_csr *graph, const cg_projection_node *nodes,
                         size_t node_count, cg_projection_node *const *by_name,
                         cg_projection_node *const *by_file, size_t total_edges,
                         size_t unresolved, const char *meta_json,
                         const char *end_json,
                         cg_snapshot_checksum *out_checksum);
/* Checks expected checksum and source/label/tenant/principal binding on an
 * immutable descriptor copy. Nothing is exposed on malformed/unauthorized
 * input. Node and topology sections load once; edge evidence decompresses in
 * bounded 256-edge blocks only when accessed. Materialized blocks remain until
 * destroy, so edge pointers are stable for the projection lifetime. An active
 * borrowed principal must outlive the projection. Revocation/label changes are
 * checked on reads. */
cg_projection *
cg_projection_open(FILE *input, qihse_user_t *principal,
                   const cg_projection_binding *binding,
                   const cg_snapshot_checksum *expected_checksum);
const cg_projection_view *cg_projection_get(cg_projection *projection);
size_t cg_projection_bytes(cg_projection *projection);
void cg_projection_destroy(cg_projection *projection);
#endif
