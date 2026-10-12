#ifndef QIHSE_PRINCIPAL_REPLAY_H
#define QIHSE_PRINCIPAL_REPLAY_H

#include "qihse_principal_store.h"
#include "qihse_consensus_blob.h"

/* Inactive startup building block. The caller must hold the consensus state
 * lock for the entire call, including capture of through_index, and must not
 * expose the returned store to authentication until an atomic auth-table
 * publication path exists. A failed replay may leave a partial private view:
 * discard that store and treat the failure as a readiness failure. */
bool qihse_principal_replay_committed_prefix(
    qihse_principal_store_t* store, const qihse_consensus_t* consensus,
    qihse_consensus_blob_context_t* blobs, qihse_user_t* system_operator,
    uint64_t through_index);

#endif
