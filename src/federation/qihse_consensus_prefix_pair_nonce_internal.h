#ifndef QIHSE_CONSENSUS_PREFIX_PAIR_NONCE_INTERNAL_H
#define QIHSE_CONSENSUS_PREFIX_PAIR_NONCE_INTERNAL_H

#include "qihse_consensus_prefix_pair_nonce.h"

/* Authenticates both challenged statements against the enrolled identities
 * before writing an owner-only accepted record tied to the durable one-use
 * claim. It is diagnostic, not rejoin authority. */
bool qihse_consensus_prefix_pair_nonce_accept_verified(
    const char* directory, void* store, void* store_user,
    const qihse_consensus_prefix_pair_expected_t* expected,
    const qihse_consensus_prefix_point_challenge_t* first,
    const qihse_consensus_prefix_point_challenge_t* second,
    char record_name_out[131]);

#endif
