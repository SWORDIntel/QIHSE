/* Experimental W12.2 disposable sidecar. Not a VectorDB ABI or search mode. */
#ifndef QIHSE_TURBOQUANT_SIDECAR_H
#define QIHSE_TURBOQUANT_SIDECAR_H
#include "qihse_turboquant.h"
#include "qihse_auth.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define QIHSE_TQ_SIDECAR_VERSION 1u
#define QIHSE_TQ_SIDECAR_MAX_ROWS 100000u

typedef struct {
    uint64_t id;
    uint16_t classification;
    uint16_t sci;
    const float *vector;
} qihse_tq_sidecar_row;

typedef struct { uint64_t id; double estimate; } qihse_tq_candidate;

typedef struct {
    uint32_t tenant_id;
    uint64_t project_id;
} qihse_tq_scope;

/* Live source-scope predicate. Called only after QIHSE clearance/SCI approval
 * and before reading the row's code. Must enforce tenant/project/owner and
 * tombstone/generation visibility against the authoritative source. */
typedef bool (*qihse_tq_live_visible_fn)(const qihse_user_t *user,
                                         uint64_t id, void *opaque);

/* Exact authoritative fallback. It receives the same principal and must
 * independently enforce all live source authorization. */
typedef int (*qihse_tq_exact_fallback_fn)(const qihse_user_t *user,
                                          const float *query, size_t dimensions,
                                          qihse_tq_metric metric,
                                          qihse_tq_candidate *out, size_t capacity,
                                          size_t *out_count, void *opaque);

/* Publish a complete derived generation. Input rows must have unique,
 * ascending IDs and all be readable by actor. The caller owns a stable
 * authoritative snapshot for source_generation; this prototype cannot fence
 * a concurrent external mutation. Writes a 0600 temporary file, fsyncs,
 * renames, then fsyncs the parent directory. */
int qihse_tq_sidecar_publish(const char *path, const qihse_user_t *actor,
                             const qihse_tq_profile *profile,
                             uint64_t source_generation,
                             const qihse_tq_sidecar_row *rows, size_t row_count);

/* Reopen exact W12.1 profile from a generation-matched sidecar. No row codes
 * are returned. Every classified-capable read requires explicit user. */
int qihse_tq_sidecar_open_profile(const char *path, const qihse_user_t *user,
                                  uint64_t source_generation,
                                  qihse_tq_profile **out);

/* Candidate-only research query. On absent/stale/corrupt sidecar, the
 * authenticated exact callback is invoked and used_sidecar becomes false.
 * On a valid sidecar, output is approximate and is NOT FP32-reranked; W12.3
 * must do authoritative rerank before any production search use.
 * Outputs are unchanged on error. Requires non-NULL user/live_visible/fallback.
 * No user-visible row count or hidden IDs are exposed. */
int qihse_tq_sidecar_candidates_or_exact(
    const char *path, const qihse_user_t *user, uint64_t source_generation,
    const qihse_tq_profile *profile, const float *query, size_t dimensions,
    qihse_tq_metric metric, qihse_tq_live_visible_fn live_visible,
    qihse_tq_exact_fallback_fn exact_fallback, void *opaque,
    qihse_tq_candidate *out, size_t capacity, size_t *out_count,
    bool *used_sidecar);

/* W12.3 research-only scoped candidate search with exact FP32 rerank.
 * live_visible returns 0 for an authorized current row, EACCES for hidden,
 * ESTALE on source-generation change, or another errno on failure. It must
 * check tenant/project/owner/clearance/SCI/tombstone against the live source.
 * exact_score reauthorizes each selected ID and returns its canonical FP32
 * score in the metric's ordering (larger for DOT/COSINE, smaller for L2_SQUARED).
 * A newly denied selected ID causes complete authoritative fallback, preventing
 * hidden rows from consuming candidate capacity. The exact fallback must use
 * the same scope and generation and return exhaustive authorized top-K.
 * This interface does not fence the authoritative source snapshot and is not
 * suitable as a production VectorDB selector until that fence is implemented. */
typedef int (*qihse_tq_scoped_visible_fn)(const qihse_user_t *user, uint64_t id,
                                          qihse_tq_scope scope,
                                          uint64_t source_generation, void *opaque);
typedef int (*qihse_tq_scoped_score_fn)(const qihse_user_t *user, uint64_t id,
                                        qihse_tq_scope scope,
                                        uint64_t source_generation,
                                        const float *query, size_t dimensions,
                                        qihse_tq_metric metric, double *out_score,
                                        void *opaque);
typedef int (*qihse_tq_scoped_exact_fn)(const qihse_user_t *user,
                                        qihse_tq_scope scope,
                                        uint64_t source_generation,
                                        const float *query, size_t dimensions,
                                        qihse_tq_metric metric,
                                        qihse_tq_candidate *out, size_t capacity,
                                        size_t *out_count, void *opaque);
int qihse_tq_sidecar_search_scoped(
    const char *path, const qihse_user_t *user, qihse_tq_scope scope,
    uint64_t source_generation, const qihse_tq_profile *profile,
    const float *query, size_t dimensions, qihse_tq_metric metric,
    size_t candidate_pool, qihse_tq_scoped_visible_fn live_visible,
    qihse_tq_scoped_score_fn exact_score,
    qihse_tq_scoped_exact_fn exact_fallback, void *opaque,
    qihse_tq_candidate *out, size_t top_k, size_t *out_count,
    bool *used_sidecar);

#ifdef __cplusplus
}
#endif
#endif
