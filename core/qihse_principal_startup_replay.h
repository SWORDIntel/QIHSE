#ifndef QIHSE_PRINCIPAL_STARTUP_REPLAY_H
#define QIHSE_PRINCIPAL_STARTUP_REPLAY_H

#include "qihse_principal_store.h"
#include "qihse_consensus_mesh.h"

/* Build a private, history-bound principal view from the exact local
 * committed prefix. Call only after mesh_create() has opened durable state
 * and before mesh_start() or any other consensus mutation thread. This
 * function does not publish auth state or grant listener readiness. It
 * checks the group/history/epoch against the mesh's opened identity. On any
 * missing/denied/corrupt entry it destroys the partial view and returns
 * false. A zero committed index is a valid empty registry. */
bool qihse_principal_startup_replay_user(
    qihse_consensus_mesh_t* mesh, qihse_consensus_blob_context_t* blobs,
    qihse_user_t* system_operator, const char* group_id,
    const uint8_t history_id[32], uint64_t writer_epoch_floor,
    qihse_principal_store_t** out_store);

/* A distinct result type for the exact committed-prefix replay above. A
 * bound store exported through the general store API cannot create one.
 * The result owns its private snapshot and no mutable store escapes. Use
 * only during startup, before mesh_start() and listener readiness. */
typedef struct qihse_principal_verified_startup_snapshot_s
    qihse_principal_verified_startup_snapshot_t;

bool qihse_principal_startup_replay_snapshot_user(
    qihse_consensus_mesh_t* mesh, qihse_consensus_blob_context_t* blobs,
    qihse_user_t* system_operator, const char* group_id,
    const uint8_t history_id[32], uint64_t writer_epoch_floor,
    qihse_principal_verified_startup_snapshot_t** out_snapshot);
bool qihse_principal_verified_startup_metadata_user(
    const qihse_principal_verified_startup_snapshot_t* verified,
    const qihse_user_t* requester,
    qihse_principal_snapshot_metadata_t* out_metadata);
bool qihse_principal_verified_startup_visit_user(
    const qihse_principal_verified_startup_snapshot_t* verified,
    const qihse_user_t* requester,
    qihse_principal_snapshot_visit_fn visit, void* opaque);
void qihse_principal_verified_startup_snapshot_free(
    qihse_principal_verified_startup_snapshot_t* verified);

#endif
