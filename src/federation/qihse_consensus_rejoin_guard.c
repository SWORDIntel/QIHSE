#include "qihse_consensus_rejoin_guard.h"

#include <string.h>

static bool nonzero(const uint8_t* bytes, size_t len) {
    uint8_t value = 0;
    for (size_t i = 0; i < len; i++) value |= bytes[i];
    return value != 0;
}

bool qihse_consensus_history_identity_valid(const char* group_id,
                                             const uint8_t history_id[32],
                                             uint64_t writer_epoch) {
    if (!group_id || !history_id || writer_epoch == 0) return false;
    size_t group_len = strnlen(group_id, QIHSE_CONSENSUS_GROUP_ID_MAX + 1u);
    return group_len > 0 && group_len <= QIHSE_CONSENSUS_GROUP_ID_MAX &&
        nonzero(history_id, 32u);
}

static bool valid_anchor(const qihse_consensus_history_anchor_t* anchor) {
    if (!anchor) return false;
    if (!qihse_consensus_history_identity_valid(
            anchor->group_id, anchor->history_id, anchor->writer_epoch)) return false;
    if ((anchor->commit_index > 0 &&
         !nonzero(anchor->prefix_sha256, sizeof(anchor->prefix_sha256))) ||
        (anchor->commit_index == 0 &&
         nonzero(anchor->prefix_sha256, sizeof(anchor->prefix_sha256)))) return false;
    return true;
}

qihse_consensus_rejoin_result_t qihse_consensus_rejoin_compare(
    const qihse_consensus_history_anchor_t* local,
    const qihse_consensus_history_anchor_t* source) {
    if (!valid_anchor(local) || !valid_anchor(source)) return QIHSE_REJOIN_INVALID;
    if (strcmp(local->group_id, source->group_id) != 0 ||
        memcmp(local->history_id, source->history_id,
               sizeof(local->history_id)) != 0 ||
        local->writer_epoch != source->writer_epoch)
        return QIHSE_REJOIN_NEW_GENESIS_REQUIRED;
    if (local->commit_index == source->commit_index) {
        return memcmp(local->prefix_sha256, source->prefix_sha256,
                      sizeof(local->prefix_sha256)) == 0
            ? QIHSE_REJOIN_EXACT : QIHSE_REJOIN_CONFLICT;
    }
    if (local->commit_index > source->commit_index)
        return QIHSE_REJOIN_CONFLICT;
    return QIHSE_REJOIN_PREFIX_PROOF_REQUIRED;
}

bool qihse_consensus_rejoin_new_genesis_candidate(
    const qihse_consensus_history_anchor_t* old_history,
    const qihse_consensus_history_anchor_t* proposed) {
    if (!valid_anchor(old_history) || !valid_anchor(proposed)) return false;
    return proposed->commit_index == 0 &&
        proposed->writer_epoch > old_history->writer_epoch &&
        strcmp(proposed->group_id, old_history->group_id) != 0 &&
        memcmp(proposed->history_id, old_history->history_id,
               sizeof(proposed->history_id)) != 0;
}
