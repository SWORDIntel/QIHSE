#ifndef QIHSE_CONSENSUS_REPLAY_TRACE_H
#define QIHSE_CONSENSUS_REPLAY_TRACE_H

#include "qihse_consensus_mesh.h"
#include "qihse_consensus_prefix_attestation.h"
#include "qihse_consensus_prefix_point_challenge.h"

#ifdef __cplusplus
extern "C" {
#endif

/* A bounded diagnostic over signed source checkpoints captured during an
 * ordered replay. Each checkpoint must advance its committed index and its
 * digest must match the local committed prefix at that exact index. Both
 * expected identities are trusted local configuration. The requester must
 * be a live system Operator authorized for every local entry inspected;
 * store_user separately authorizes federation identity lookup.
 *
 * A successful trace does not prove the replay transport, source freshness,
 * quorum, application state, writer fencing, or permission to serve traffic.
 * Local prefix points are observed one at a time, not as one snapshot. */
bool qihse_consensus_mesh_verify_replay_trace_user(
    qihse_consensus_mesh_t* mesh, const qihse_user_t* requester,
    void* store, void* store_user,
    const qihse_consensus_prefix_expected_t* local_expected,
    const qihse_consensus_prefix_expected_t* peer_expected,
    const qihse_consensus_prefix_attestation_t* checkpoints,
    size_t checkpoint_count, uint64_t final_index);

/* A bounded post-replay diagnostic using challenged source points. The
 * verifier supplies one independently generated, outstanding challenge per
 * checkpoint; challenges must be distinct, unexpired, and consumed once by
 * the caller regardless of this function's result. expected_challenges is
 * verifier-owned state, never copied from the received points. The source's
 * signed observed watermark must not retreat across the ordered points.
 *
 * This does not transfer entries, prove application replay, establish a
 * quorum, fence a writer, approve rejoin, or authorize serving traffic. */
bool qihse_consensus_mesh_verify_challenged_replay_trace_user(
    qihse_consensus_mesh_t* mesh, const qihse_user_t* requester,
    void* store, void* store_user,
    const qihse_consensus_prefix_expected_t* local_expected,
    const qihse_consensus_prefix_expected_t* peer_expected,
    const qihse_consensus_prefix_point_challenge_t* checkpoints,
    const uint8_t (*expected_challenges)
        [QIHSE_CONSENSUS_PREFIX_CHALLENGE_BYTES],
    size_t checkpoint_count, uint64_t final_index);

#ifdef __cplusplus
}
#endif

#endif
