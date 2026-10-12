#ifndef QIHSE_CONSENSUS_REJOIN_GUARD_H
#define QIHSE_CONSENSUS_REJOIN_GUARD_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "qihse_consensus.h"

/* A caller-supplied commitment to one full, ordered, committed history.
 * prefix_sha256 must cover entry index, term, generation, classification,
 * SCI, and payload bytes in a canonical encoding. This module compares
 * anchors; it does not compute that digest or authenticate its source. */
typedef struct {
    char group_id[QIHSE_CONSENSUS_GROUP_ID_MAX + 1u];
    uint8_t history_id[32];
    uint64_t writer_epoch;
    uint64_t commit_index;
    uint8_t prefix_sha256[32];
} qihse_consensus_history_anchor_t;

typedef enum {
    QIHSE_REJOIN_INVALID = 0,
    QIHSE_REJOIN_EXACT = 1,
    QIHSE_REJOIN_PREFIX_PROOF_REQUIRED = 2,
    QIHSE_REJOIN_CONFLICT = 3,
    QIHSE_REJOIN_NEW_GENESIS_REQUIRED = 4
} qihse_consensus_rejoin_result_t;

/* Identity-only validation for the durable consensus record header. */
bool qihse_consensus_history_identity_valid(const char* group_id,
                                             const uint8_t history_id[32],
                                             uint64_t writer_epoch);

/* Only EXACT permits automatic admission. A higher source index with the
 * same identity still needs a verified prefix and ordered replay. Different
 * epochs or history identities require an explicit, fenced new genesis. */
qihse_consensus_rejoin_result_t qihse_consensus_rejoin_compare(
    const qihse_consensus_history_anchor_t* local,
    const qihse_consensus_history_anchor_t* source);

/* True only for an empty, distinct group AND history with a higher writer
 * epoch. This validates an offline rebootstrap proposal; it does not prove
 * the record path is empty, publish a genesis, move data, or authorize
 * serving traffic. */
bool qihse_consensus_rejoin_new_genesis_candidate(
    const qihse_consensus_history_anchor_t* old_history,
    const qihse_consensus_history_anchor_t* proposed);

#endif
