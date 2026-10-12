#ifndef QIHSE_CONSENSUS_REPLAY_VERIFY_H
#define QIHSE_CONSENSUS_REPLAY_VERIFY_H

#include "qihse_consensus_mesh.h"
#include "qihse_consensus_prefix_attestation.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Compare a fresh, lock-consistent local committed history with a signed
 * target prefix from an enrolled peer. Both identities are trusted local
 * configuration, not values copied from the received statement. A match
 * proves equality of the two committed log prefixes through target_index,
 * including order, labels, SCI, and payloads in the core's canonical hash.
 *
 * This is a post-replay diagnostic only. It does not authenticate the replay
 * transport, prove source freshness or quorum, verify application state,
 * fence an old writer, authorize rejoin, or permit serving traffic. */
bool qihse_consensus_mesh_verify_replayed_prefix_user(
    qihse_consensus_mesh_t* mesh, const qihse_user_t* requester,
    void* store, void* store_user,
    const qihse_consensus_prefix_expected_t* local_expected,
    const qihse_consensus_prefix_expected_t* peer_expected,
    const qihse_consensus_prefix_attestation_t* peer_target,
    uint64_t target_index);

#ifdef __cplusplus
}
#endif

#endif
