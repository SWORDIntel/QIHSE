#ifndef QIHSE_AIMEM_PROJECTION_STORE_H
#define QIHSE_AIMEM_PROJECTION_STORE_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
/* Derived cache only: caller must rebaseline against authoritative KV before use. */
#define QIHSE_AIMEM_PROJECTION_MAX_DIM 1024u
#define QIHSE_AIMEM_PROJECTION_MAX_ROWS 8192u
typedef struct qihse_aimem_projection_store qihse_aimem_projection_store_t;
typedef struct {
    char id[37];
    char content_sha256[65];
    uint64_t source_seq;
    uint32_t tenant, owner, kind;
    uint16_t classification, sci_compartment;
    char project[64], worktree[64], workstream[64], session[64];
} qihse_aimem_projection_row_t;
/* Existing parent must be private (0700, owned by effective user).
 * tenant and owner arguments identify the indexing principal (owner is its
 * user ID), not the owner of each row. The model fingerprint is immutable. */
qihse_aimem_projection_store_t* qihse_aimem_projection_store_open(
    const char* path, uint32_t tenant, uint32_t owner,
    const uint8_t model_sha256[32], size_t dimension);
/* Lookup reads the last committed generation even while a new generation is
 * staged. It verifies UUID, digest, model and vector checksum; out is untouched
 * on failure. Row.owner is the canonical memory owner, not the cache principal. */
bool qihse_aimem_projection_store_lookup(qihse_aimem_projection_store_t* store,
    const char* full_uuid, const char* content_sha256, float* out);
bool qihse_aimem_projection_store_begin_generation(qihse_aimem_projection_store_t* store);
bool qihse_aimem_projection_store_put(qihse_aimem_projection_store_t* store,
    const qihse_aimem_projection_row_t* row, const float* vector);
bool qihse_aimem_projection_store_commit_generation(
    qihse_aimem_projection_store_t* store, uint64_t source_seq,
    uint64_t projection_epoch);
void qihse_aimem_projection_store_abort_generation(qihse_aimem_projection_store_t* store);
/* Callback must not modify store; row/vector borrowed for duration of callback. */
typedef bool (*qihse_aimem_projection_visit_fn)(void* ctx,
    const qihse_aimem_projection_row_t* row, const float* vector, size_t dimension);
bool qihse_aimem_projection_store_iterate(qihse_aimem_projection_store_t* store,
    qihse_aimem_projection_visit_fn visit, void* ctx,
    uint64_t* source_seq, uint64_t* projection_epoch);
void qihse_aimem_projection_store_close(qihse_aimem_projection_store_t* store);
#endif
