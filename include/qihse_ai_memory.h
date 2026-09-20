#ifndef QIHSE_AI_MEMORY_H
#define QIHSE_AI_MEMORY_H

/* Local-first AI memory — the MEMSHADOW successor surface (ai_fabric.md §5).
 *
 * Episodic and semantic memories live in the native KV namespace
 * (`aimem:<doc-id>`) and are indexed by the FTS engine for recall. Recall is
 * BM25-ranked over caller-visible documents only, so ranking cannot leak
 * hidden records.
 *
 * Every entry point takes an explicit security context: there is no
 * context-free variant. Records are written with the caller's classification
 * and SCI compartment, and reads are subject to the same RBAC as the
 * underlying store and index.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "qihse_auth.h"
#include "qihse_resp_wire.h"

#ifdef __cplusplus
extern "C" {
#endif

#define QIHSE_AIMEM_ID_LEN 36u /* formatted UUID */

typedef enum {
    QIHSE_AIMEM_EPISODIC = 1u, /* what happened */
    QIHSE_AIMEM_SEMANTIC = 2u  /* what is known  */
} qihse_ai_memory_kind_t;

/* A read FILTER value, not a storable kind: it selects both kinds.
 * `qihse_ai_memory_store()` still accepts only EPISODIC and SEMANTIC. */
#define QIHSE_AIMEM_KIND_ANY 0u

typedef struct {
    char id[QIHSE_AIMEM_ID_LEN + 1u];
    uint64_t created_ms;
    uint32_t kind;
    uint16_t classification;
    uint16_t sci_compartment;
    double score; /* ranking score; 0 when fetched by id rather than recalled */
    char* text;   /* caller frees */
} qihse_ai_memory_hit_t;

/* ── Embeddings (ai_fabric.md §5, the embedding-backed recall item) ─────── */

/* How recall ranks.
 *
 * BM25 is lexical: it matches the words the caller typed. SEMANTIC ranks by
 * vector similarity, so a query can match a memory that shares no words with
 * it. HYBRID fuses both, because either alone has a failure mode — lexical
 * misses paraphrase, and vector similarity alone drifts toward whatever is
 * nearest rather than whatever answers the question.
 *
 * Every mode is subject to the SAME visibility filter: candidates are
 * resolved through the KV store's authorization-aware read, so no mode can
 * rank, score, or even count a record the principal cannot see. That is the
 * property that matters here, because an embedding is derived from the text
 * and can leak it. */
typedef enum {
    QIHSE_AIMEM_MODE_BM25 = 0,
    QIHSE_AIMEM_MODE_SEMANTIC,
    QIHSE_AIMEM_MODE_HYBRID
} qihse_ai_memory_mode_t;

/* Maximum embedding dimension the storage and search paths accept. */
#define QIHSE_AIMEM_MAX_DIM 1024u

/* An embedding provider. `embed` fills exactly `dim` floats for `text` and
 * returns false on failure. `name` is recorded with the stored vector so a
 * memory embedded by one provider is never silently compared against a query
 * embedded by another — vectors from different models are not comparable, and
 * treating them as if they were would produce confident nonsense. */
typedef struct {
    const char* name;
    size_t dim;
    bool (*embed)(const char* text, float* out, size_t dim, void* ctx);
    void* ctx;
} qihse_ai_memory_embedder_t;

/* Install an embedding provider. Pass NULL to restore the built-in one.
 *
 * The built-in embedder is a DETERMINISTIC LEXICAL VECTOR, not a learned
 * model: it hashes tokens into a fixed-width space, so similarity reflects
 * shared vocabulary rather than meaning. It exists so the storage, ranking,
 * fusion and filtering paths are complete and testable with no model present,
 * and it is honest about being lexical. A real model plugs in here and
 * everything downstream is unchanged. */
bool qihse_ai_memory_set_embedder(const qihse_ai_memory_embedder_t* provider);

/* The dimension of the active embedder. */
size_t qihse_ai_memory_embedding_dim(void);

/* The active embedder's name, or "" when none is usable. */
const char* qihse_ai_memory_embedder_name(void);

/* Run the active embedder on `text`, filling exactly `dim` floats.
 * Returns false when no provider is usable, `dim` does not match the
 * provider, or the provider fails.  This is the "inference" primitive: the
 * embedder is the model backend, and this is the only way to run it without
 * storing a memory. */
bool qihse_ai_memory_embed_text(const char* text, float* out, size_t dim);

/* Remember: store `text` and index it for recall. Returns false when the
 * store or index rejects the write (including insufficient clearance). */
bool qihse_ai_memory_store(qihse_resp_server_t* server, qihse_user_t* user,
                           const char* text, uint32_t kind,
                           char out_id[QIHSE_AIMEM_ID_LEN + 1u]);

/* Recall with an explicit ranking mode. */
size_t qihse_ai_memory_recall_mode(qihse_resp_server_t* server, qihse_user_t* user,
                                   const char* query, size_t limit,
                                   qihse_ai_memory_mode_t mode,
                                   qihse_ai_memory_hit_t* out, size_t out_cap);

/* Recall with an explicit ranking mode AND a kind filter: pass
 * QIHSE_AIMEM_KIND_ANY, QIHSE_AIMEM_EPISODIC or QIHSE_AIMEM_SEMANTIC.
 *
 * The two kinds share one namespace and one index, so without a filter an
 * episodic question ("what happened") and a semantic one ("what is known")
 * compete for the same limit. The filter is applied to candidates that have
 * ALREADY been resolved through the authorization-aware read every other path
 * uses, so it can only remove hits the principal was allowed to see: it can
 * never widen the result set, and an unrecognised kind value is refused (0)
 * rather than treated as "any". */
size_t qihse_ai_memory_recall_kind(qihse_resp_server_t* server, qihse_user_t* user,
                                   const char* query, size_t limit,
                                   qihse_ai_memory_mode_t mode, uint32_t kind,
                                   qihse_ai_memory_hit_t* out, size_t out_cap);

/* Recall: BM25 search over visible memories. Fills up to `out_cap` hits and
 * returns how many were written; hits with `text` must be freed by the
 * caller (qihse_ai_memory_hits_free). */
size_t qihse_ai_memory_recall(qihse_resp_server_t* server, qihse_user_t* user,
                              const char* query, size_t limit,
                              qihse_ai_memory_hit_t* out, size_t out_cap);

/* Fetch one memory by id (RBAC enforced by the store). */
bool qihse_ai_memory_get(qihse_resp_server_t* server, qihse_user_t* user,
                         const char* id, qihse_ai_memory_hit_t* out);

/* Forget: delete the record. The search index may retain a stale posting for
 * the id; recall skips records whose KV entry is gone. */
bool qihse_ai_memory_forget(qihse_resp_server_t* server, qihse_user_t* user,
                            const char* id);

/* How many memories the caller can see. */
size_t qihse_ai_memory_count(qihse_resp_server_t* server, qihse_user_t* user);

/* How many memories of one kind the caller can see; QIHSE_AIMEM_KIND_ANY
 * counts every visible memory, which is what qihse_ai_memory_count() returns.
 * An unrecognised kind counts nothing rather than counting everything. */
size_t qihse_ai_memory_count_kind(qihse_resp_server_t* server, qihse_user_t* user,
                                  uint32_t kind);

void qihse_ai_memory_hits_free(qihse_ai_memory_hit_t* hits, size_t count);

/* Drop the process-local search index (tests / shutdown). */
void qihse_ai_memory_reset(void);

#ifdef __cplusplus
}
#endif

#endif /* QIHSE_AI_MEMORY_H */
