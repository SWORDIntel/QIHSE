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
#define QIHSE_AIMEM_IDEM_MAX_LEN 128u
#define QIHSE_AIMEM_SCOPE_ID_MAX 63u

/* Client-selected names are opaque identifiers, never authority claims.
 * Project is mandatory; the other dimensions narrow a project query. */
typedef struct {
    char project[QIHSE_AIMEM_SCOPE_ID_MAX + 1u];
    char worktree[QIHSE_AIMEM_SCOPE_ID_MAX + 1u];
    char workstream[QIHSE_AIMEM_SCOPE_ID_MAX + 1u];
    char session[QIHSE_AIMEM_SCOPE_ID_MAX + 1u];
} qihse_ai_memory_scope_t;

typedef enum {
    QIHSE_AIMEM_EPISODIC = 1u, /* what happened */
    QIHSE_AIMEM_SEMANTIC = 2u, /* what is known  */
    QIHSE_AIMEM_EVENT = 3u     /* immutable lifecycle event */
} qihse_ai_memory_kind_t;

/* QH-04 curated knowledge uses immutable version records.  These values are
 * deliberately separate from recall kinds: a caller cannot pass a claimed
 * knowledge type through an ordinary free-text memory admission path. */
typedef enum {
    QIHSE_AIMEM_KNOWLEDGE_DECISION = 1u,
    QIHSE_AIMEM_KNOWLEDGE_GOTCHA,
    QIHSE_AIMEM_KNOWLEDGE_PROCEDURE,
    QIHSE_AIMEM_KNOWLEDGE_ARCHITECTURE,
    QIHSE_AIMEM_KNOWLEDGE_RULE,
    QIHSE_AIMEM_KNOWLEDGE_SESSION_CAPSULE
} qihse_ai_memory_knowledge_type_t;

typedef enum {
    QIHSE_AIMEM_KNOWLEDGE_PROPOSED = 1u,
    QIHSE_AIMEM_KNOWLEDGE_APPROVED,
    QIHSE_AIMEM_KNOWLEDGE_SUPERSEDED,
    QIHSE_AIMEM_KNOWLEDGE_RETRACTED
} qihse_ai_memory_knowledge_status_t;

/* Immutable QH-04 version metadata. `content` and all IDs are owned by the
 * caller on input and by the result owner on output. */
typedef struct {
    char knowledge_id[QIHSE_AIMEM_ID_LEN + 1u];
    char version_id[QIHSE_AIMEM_ID_LEN + 1u];
    char supersedes_version[QIHSE_AIMEM_ID_LEN + 1u];
    qihse_ai_memory_scope_t scope;
    uint32_t type;
    uint32_t status;
    uint64_t revision;
    uint64_t created_at_ms;
    uint64_t valid_from_ingest_ms;
    uint64_t valid_to_ingest_ms;
    uint32_t created_by;
    char* content;
} qihse_ai_memory_knowledge_version_t;

bool qihse_ai_memory_knowledge_get(qihse_resp_server_t* server,
    qihse_user_t* user, const char* version_id,
    const qihse_ai_memory_scope_t* scope,
    qihse_ai_memory_knowledge_version_t* out);
void qihse_ai_memory_knowledge_free(qihse_ai_memory_knowledge_version_t* value);

#define QIHSE_AIMEM_EVENT_MAX_SUMMARY (16u * 1024u)

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

/* QH-00 retry-safe admission. When the same (tenant, actor, idempotency-key)
 * is retried after a pre-ACK crash, derive the same UUID from the existing
 * federation SHA-384 UUID helper. A conflicting kind/text is never replaced.
 *
 * This is a trusted native API: caller supplies an authenticated user and
 * must serialize same-key concurrent admission (RESP uses its KV write lock).
 * The old random-UUID store API and its return contract are unchanged.
 * Durable ACK still requires a separate KV sync fence. */
typedef enum {
    QIHSE_AIMEM_WRITE_FAILED = 0,
    QIHSE_AIMEM_WRITE_NEW = 1,
    QIHSE_AIMEM_WRITE_REPLAY = 2,
    QIHSE_AIMEM_WRITE_CONFLICT = 3
} qihse_ai_memory_write_result_t;

/* Append a registered, immutable lifecycle event. Event identity is
 * producer_namespace + event_id within the authenticated tenant/actor/scope. */
qihse_ai_memory_write_result_t qihse_ai_memory_event_append(
    qihse_resp_server_t* server, qihse_user_t* user,
    const qihse_ai_memory_scope_t* scope, const char* producer_namespace,
    const char* event_id, const char* event_kind, uint64_t source_time_ms,
    const char* summary, char out_id[QIHSE_AIMEM_ID_LEN + 1u]);
bool qihse_ai_memory_event_get(qihse_resp_server_t* server, qihse_user_t* user,
    const char* id, const qihse_ai_memory_scope_t* scope,
    qihse_ai_memory_hit_t* out);
bool qihse_ai_memory_project_grant(qihse_resp_server_t* server,
    qihse_user_t* grantor, const char* project, uint32_t reader_id);
bool qihse_ai_memory_project_revoke(qihse_resp_server_t* server,
    qihse_user_t* grantor, const char* project, uint32_t reader_id);
bool qihse_ai_memory_project_reader_allowed(qihse_resp_server_t* server,
    qihse_user_t* reader, const char* project);
bool qihse_ai_memory_project_owner_allowed(qihse_resp_server_t* server,
    qihse_user_t* owner, const char* project);

/* Move one system-domain legacy memory into an explicit scoped record while
 * preserving UUID, timestamp, kind, classification, SCI and content. Only an
 * active system Operator may call this. The operation fences the destination
 * before deleting and fencing the source, so retries complete safely after a
 * crash between phases. Callers must serialize against other AIMEM writes. */
qihse_ai_memory_write_result_t qihse_ai_memory_migrate_legacy(
    qihse_resp_server_t* server, qihse_user_t* operator_user,
    const char* id, const qihse_ai_memory_scope_t* destination);

/* QH-04 immutable curated-knowledge chains. Create/revise replace one
 * tenant-scoped chain record atomically; callers that promise a durable ACK
 * must serialize the call and qihse_kv_sync_store() under the server KV lock. */
qihse_ai_memory_write_result_t qihse_ai_memory_knowledge_create(
    qihse_resp_server_t* server, qihse_user_t* user,
    const qihse_ai_memory_scope_t* scope, uint32_t type, uint32_t status,
    const char* content, qihse_ai_memory_knowledge_version_t* out);
qihse_ai_memory_write_result_t qihse_ai_memory_knowledge_revise(
    qihse_resp_server_t* server, qihse_user_t* user,
    const char* knowledge_id, const char* expected_version_id,
    uint64_t expected_revision, uint32_t status, const char* content,
    qihse_ai_memory_knowledge_version_t* out);
bool qihse_ai_memory_knowledge_latest(qihse_resp_server_t* server,
    qihse_user_t* user, const char* knowledge_id,
    const qihse_ai_memory_scope_t* scope,
    qihse_ai_memory_knowledge_version_t* out);
bool qihse_ai_memory_knowledge_as_of(qihse_resp_server_t* server,
    qihse_user_t* user, const char* knowledge_id,
    const qihse_ai_memory_scope_t* scope, uint64_t ingestion_time_ms,
    qihse_ai_memory_knowledge_version_t* out);

qihse_ai_memory_write_result_t qihse_ai_memory_store_idempotent(
    qihse_resp_server_t* server, qihse_user_t* user, const char* text,
    uint32_t kind, const char* idempotency_key,
    char out_id[QIHSE_AIMEM_ID_LEN + 1u]);

/* QH-01 scoped variants. Scope is mandatory and project must be nonempty.
 * Scoped records are never visible through legacy global AIMEM reads. */
bool qihse_ai_memory_store_scoped(qihse_resp_server_t* server,
                                  qihse_user_t* user, const char* text,
                                  uint32_t kind,
                                  const qihse_ai_memory_scope_t* scope,
                                  char out_id[QIHSE_AIMEM_ID_LEN + 1u]);
qihse_ai_memory_write_result_t qihse_ai_memory_store_scoped_idempotent(
    qihse_resp_server_t* server, qihse_user_t* user, const char* text,
    uint32_t kind, const qihse_ai_memory_scope_t* scope,
    const char* idempotency_key,
    char out_id[QIHSE_AIMEM_ID_LEN + 1u]);
size_t qihse_ai_memory_recall_scoped(qihse_resp_server_t* server,
                                     qihse_user_t* user, const char* query,
                                     size_t limit, qihse_ai_memory_mode_t mode,
                                     uint32_t kind,
                                     const qihse_ai_memory_scope_t* scope,
                                     qihse_ai_memory_hit_t* out,
                                     size_t out_cap);
bool qihse_ai_memory_get_scoped(qihse_resp_server_t* server,
                                qihse_user_t* user, const char* id,
                                const qihse_ai_memory_scope_t* scope,
                                qihse_ai_memory_hit_t* out);
bool qihse_ai_memory_forget_scoped(qihse_resp_server_t* server,
                                   qihse_user_t* user, const char* id,
                                   const qihse_ai_memory_scope_t* scope);
size_t qihse_ai_memory_count_scoped(qihse_resp_server_t* server,
                                    qihse_user_t* user, uint32_t kind,
                                    const qihse_ai_memory_scope_t* scope);

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
