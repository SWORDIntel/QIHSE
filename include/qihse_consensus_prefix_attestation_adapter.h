#ifndef QIHSE_CONSENSUS_PREFIX_ATTESTATION_ADAPTER_H
#define QIHSE_CONSENSUS_PREFIX_ATTESTATION_ADAPTER_H

#include "qihse_consensus_mesh.h"
#include "qihse_consensus_prefix_attestation.h"
#include "qihse_consensus_rejoin_guard.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Sign one bounded, access-checked committed-prefix inventory from a mesh.
 * The requester must be an active system Operator. The federation store user
 * must separately be authorized to look up the enrolled signing identity.
 * This statement alone is neither a quorum certificate nor a rejoin grant. */
bool qihse_consensus_mesh_attest_prefix_user(
    qihse_consensus_mesh_t* mesh, const qihse_user_t* requester,
    void* store, void* store_user, const qihse_uuid_t* signer_node,
    const qihse_consensus_prefix_expected_t* expected,
    uint64_t max_entries, qihse_consensus_prefix_attestation_t* out);

/* Capture a fresh local prefix under the mesh state lock, authenticate both
 * statements against enrolled identities, then classify the peer history.
 * Both expected identities must come from trusted local configuration.
 * EXACT is only a comparison result: it is not a quorum certificate, a
 * replay proof, a writer fence, or permission to serve traffic. A lagging
 * local prefix always returns PREFIX_PROOF_REQUIRED. */
qihse_consensus_rejoin_result_t qihse_consensus_mesh_compare_attested_peer_user(
    qihse_consensus_mesh_t* mesh, const qihse_user_t* requester,
    void* store, void* store_user, const qihse_uuid_t* local_signer_node,
    const qihse_consensus_prefix_expected_t* local_expected,
    const qihse_consensus_prefix_expected_t* peer_expected,
    const qihse_consensus_prefix_attestation_t* peer,
    uint64_t max_entries);

#ifdef __cplusplus
}
#endif

#endif
