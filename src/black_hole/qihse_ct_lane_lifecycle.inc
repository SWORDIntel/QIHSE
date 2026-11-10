/*
 * Quantum-Inspired Hybrid Security Engine (QIHSE)
 * CT Lane Lifecycle Implementation
 *
 * Implements promotion retirement, receiver preparation, and receiver pruning
 * for CT replication lanes. Included at the end of qihse_kv_store.c.
 */

#ifndef QIHSE_CT_LANE_LIFECYCLE_INC
#define QIHSE_CT_LANE_LIFECYCLE_INC

bool qihse_kv_ct_lane_promotion_retire(qihse_kv_store_t* store,
    qihse_user_t* control_principal, qihse_user_t* data_principal,
    const qihse_kv_ct_lane_authority_claim_t* final_claim,
    const qihse_kv_ct_proof_t* final_proof,
    qihse_kv_ct_lane_authority_verify_fn verify, void* verify_context) {
    qihse_kv_ct_lane_authority_claim_t proof_claim;
    if (!store || !ct_admin(control_principal) || !data_principal ||
        !qihse_auth_user_is_active(data_principal) || !final_claim ||
        final_claim->operation != QIHSE_KV_CT_LANE_AUTH_PROMOTION ||
        !ct_lane_claim_valid(final_claim, true) ||
        !qihse_kv_ct_lane_authority_proof_validate(store, control_principal,
            data_principal, final_proof, verify, verify_context, true) ||
        !qihse_kv_ct_lane_authority_proof_fields(store, control_principal,
            data_principal, final_proof, &proof_claim) ||
        !ct_lane_claim_equal(final_claim, &proof_claim)) {
        errno = EACCES;
        return false;
    }

    kv_store_wrlock(store);
    if (store->recovery_pending) {
        kv_store_unlock(store);
        errno = EIO;
        return false;
    }

    qihse_kv_ct_lane_t* lane = ct_lane_find(store, final_claim->source_group_id);
    if (!lane) {
        kv_store_unlock(store);
        errno = ENOENT;
        return false;
    }

    /* Check if local lane has already moved to a newer generation.
     * A newer-generation local lane is left unchanged, never retired by historical replay. */
    if (strcmp(lane->status.generation, final_claim->source_generation) != 0) {
        kv_store_unlock(store);
        return true;
    }

    /* Generation matches. Must match source_qkp_id and exact old bitmap. */
    if (strcmp(lane->status.source_id, final_claim->source_qkp_id) != 0 ||
        memcmp(lane->status.slot_bitmap, final_claim->slots,
               QIHSE_KV_CT_SLOT_BITMAP_BYTES) != 0) {
        kv_store_unlock(store);
        errno = EACCES;
        return false;
    }

    /* Check if already retired (retry of same retired claim succeeds). */
    if (lane->status.mode == QIHSE_KV_CT_LANE_RECEIVER &&
        !lane->status.admitted &&
        !lane->status.baseline_sealed &&
        !lane->status.promotion_pending) {
        kv_store_unlock(store);
        return true;
    }

    /* Must be local SOURCE lane to be retired. */
    if (lane->status.mode != QIHSE_KV_CT_LANE_SOURCE) {
        kv_store_unlock(store);
        errno = EACCES;
        return false;
    }

    /* Durably change it to inactive RECEIVER, admitted=false, baseline_sealed=false,
     * promotion_pending=false; keep old IDs/generation for history. */
    qihse_kv_ct_lane_status_t old_status = lane->status;
    lane->status.mode = QIHSE_KV_CT_LANE_RECEIVER;
    lane->status.admitted = false;
    lane->status.baseline_sealed = false;
    lane->status.promotion_pending = false;

    bool ok = ct_lanes_state_write(store) && ct_lane_marker_write(store);
    if (!ok) {
        lane->status = old_status;
        store->recovery_pending = true;
        kv_store_unlock(store);
        errno = EIO;
        return false;
    }

    kv_store_unlock(store);
    return true;
}

bool qihse_kv_ct_lane_receiver_prepare(qihse_kv_store_t* store,
    qihse_user_t* control_principal, qihse_user_t* data_principal,
    const qihse_kv_ct_lane_authority_claim_t* reserved_claim,
    const qihse_kv_ct_proof_t* reserved_proof,
    qihse_kv_ct_lane_authority_verify_fn verify_reserved, void* verify_context,
    unsigned char out_owner_token[QIHSE_KV_CT_TOKEN_BYTES]) {
    if (out_owner_token) memset(out_owner_token, 0, QIHSE_KV_CT_TOKEN_BYTES);
    if (!store || !ct_admin(control_principal) || !data_principal ||
        !qihse_auth_user_is_active(data_principal) ||
        !reserved_claim || !reserved_proof || !verify_reserved || !out_owner_token) {
        errno = EACCES;
        return false;
    }

    /* Promotion only, source_group == target_group, final_decision_index == 0 */
    if (reserved_claim->operation != QIHSE_KV_CT_LANE_AUTH_PROMOTION ||
        strcmp(reserved_claim->source_group_id, reserved_claim->target_group_id) != 0 ||
        reserved_claim->final_decision_index != 0u ||
        !ct_digest_zero(reserved_claim->final_decision_digest) ||
        !ct_lane_claim_valid(reserved_claim, false) ||
        !ct_lane_id_valid(reserved_claim->target_group_id) ||
        !ct_id_valid(reserved_claim->target_qkp_id) ||
        !ct_id_valid(reserved_claim->successor_qkp_id) ||
        !ct_id_valid(reserved_claim->target_generation) ||
        !ct_lane_bitmap_valid(reserved_claim->slots)) {
        errno = EACCES;
        return false;
    }

    /* Strict verification requiring current common RESERVED proof and matching fields */
    qihse_kv_ct_lane_authority_claim_t proof_claim;
    if (!qihse_kv_ct_lane_authority_proof_validate(store, control_principal,
            data_principal, reserved_proof, verify_reserved, verify_context, false) ||
        !qihse_kv_ct_lane_authority_proof_fields(store, control_principal,
            data_principal, reserved_proof, &proof_claim) ||
        !ct_lane_claim_equal(reserved_claim, &proof_claim)) {
        errno = EACCES;
        return false;
    }

    kv_store_wrlock(store);
    if (store->recovery_pending) {
        kv_store_unlock(store);
        errno = EIO;
        return false;
    }

    const char* lane_id = reserved_claim->target_group_id;
    qihse_kv_ct_lane_t* lane = ct_lane_find(store, lane_id);
    bool is_new = (lane == NULL);

    /* Existing exact new tuple is idempotent and preserves baseline/cursors. */
    if (lane && lane->status.mode == QIHSE_KV_CT_LANE_RECEIVER &&
        strcmp(lane->status.source_id, reserved_claim->target_qkp_id) == 0 &&
        strcmp(lane->status.peer_id, reserved_claim->successor_qkp_id) == 0 &&
        strcmp(lane->status.generation, reserved_claim->target_generation) == 0 &&
        lane->tenant_policy == QIHSE_KV_CT_TENANT_SYSTEM_ALL &&
        lane->tenant_id == 0u &&
        memcmp(lane->status.slot_bitmap, reserved_claim->slots,
               QIHSE_KV_CT_SLOT_BITMAP_BYTES) == 0) {
        memcpy(out_owner_token, lane->owner_token, QIHSE_KV_CT_TOKEN_BYTES);
        kv_store_unlock(store);
        return true;
    }

    /* Allocate slot if new lane */
    if (is_new) {
        if (!ct_lane_reserve_one(store)) {
            kv_store_unlock(store);
            return false;
        }
        lane = &store->lanes[store->ct_lane_count];
    }

    /* Check bitmap and generation conflicts against all other lanes.
     * Pass lane as ignore_lane so replacing old SOURCE/RECEIVER doesn't self-conflict. */
    bool valid = lane && !ct_lane_bitmap_conflicts(store, reserved_claim->slots, is_new ? NULL : lane);
    for (size_t i = 0; valid && i < store->ct_lane_capacity; ++i) {
        qihse_kv_ct_lane_t* other = &store->lanes[i];
        if (!other->used || other == lane) continue;
        if (strcmp(other->status.generation, reserved_claim->target_generation) == 0) {
            valid = false;
        }
    }
    if (!valid) {
        kv_store_unlock(store);
        errno = EEXIST;
        return false;
    }

    /* Flush/rotate pre-lane ungrouped mutations before the QCTST004 marker
     * makes the new group-aware reader authoritative. */
    if (is_new && store->ct_lane_count == 0u && !store->ct_enabled &&
        !kv_sync_store_locked(store)) {
        kv_store_unlock(store);
        return false;
    }

    /* Rotate lane token on new tuple; reset baseline, stream positions,
     * admission, retained bytes and last-group digest. */
    qihse_kv_ct_lane_t old = *lane;
    memset(lane, 0, sizeof(*lane));
    lane->used = true;
    snprintf(lane->status.lane_id, sizeof(lane->status.lane_id), "%s", reserved_claim->target_group_id);
    snprintf(lane->status.source_id, sizeof(lane->status.source_id), "%s", reserved_claim->target_qkp_id);
    snprintf(lane->status.peer_id, sizeof(lane->status.peer_id), "%s", reserved_claim->successor_qkp_id);
    snprintf(lane->status.generation, sizeof(lane->status.generation), "%s", reserved_claim->target_generation);
    lane->status.mode = QIHSE_KV_CT_LANE_RECEIVER;
    memcpy(lane->status.slot_bitmap, reserved_claim->slots, QIHSE_KV_CT_SLOT_BITMAP_BYTES);
    lane->status.baseline_row_seq = 0u;
    lane->status.baseline_stream_cut = 0u;
    lane->status.durable_position = 0u;
    lane->status.acknowledged_position = 0u;
    lane->status.retained_bytes = 0u;
    lane->status.limit_bytes = KV_CT_DEFAULT_LANE_LIMIT_BYTES;
    lane->tenant_policy = QIHSE_KV_CT_TENANT_SYSTEM_ALL;
    lane->tenant_id = 0u;
    lane->status.baseline_sealed = false;
    lane->status.admitted = false;
    lane->status.promotion_pending = false;
    lane->status.baseline_refresh_needed = false;
    memset(lane->status.baseline_digest, 0, sizeof(lane->status.baseline_digest));
    memset(lane->last_group_digest, 0, sizeof(lane->last_group_digest));

    if (!ct_lane_digest_bitmap(lane->status.slot_bitmap, lane->status.slot_bitmap_digest) ||
        getrandom(lane->owner_token, sizeof(lane->owner_token), 0) != (ssize_t)sizeof(lane->owner_token)) {
        *lane = old;
        kv_store_unlock(store);
        errno = EIO;
        return false;
    }

    if (is_new) store->ct_lane_count++;
    store->ct_enabled = true;
    store->ct_system_principal = control_principal;
    bool ok = ct_lanes_state_write(store) && ct_lane_marker_write(store);
    if (!ok) {
        *lane = old;
        if (is_new) store->ct_lane_count--;
        store->ct_enabled = store->ct_lane_count != 0u || store->ct_mode != 0u;
        if (store->ct_lane_count) (void)ct_lanes_state_write(store);
        store->recovery_pending = true;
        kv_store_unlock(store);
        errno = EIO;
        return false;
    }

    memcpy(out_owner_token, lane->owner_token, QIHSE_KV_CT_TOKEN_BYTES);
    kv_store_unlock(store);
    return true;
}

bool qihse_kv_ct_lane_receiver_prune(qihse_kv_store_t* store,
    qihse_user_t* operator_principal, const char* lane_id,
    const char* generation,
    const uint8_t subset_bitmap[QIHSE_KV_CT_SLOT_BITMAP_BYTES],
    const unsigned char owner_token[QIHSE_KV_CT_TOKEN_BYTES]) {
    if (!store || !operator_principal || !ct_lane_id_valid(lane_id) ||
        !ct_id_valid(generation) || !subset_bitmap || !owner_token) {
        errno = EINVAL;
        return false;
    }
    if (!ct_admin(operator_principal)) {
        errno = EACCES;
        return false;
    }

    kv_store_wrlock(store);
    if (store->recovery_pending) {
        kv_store_unlock(store);
        errno = EIO;
        return false;
    }

    qihse_kv_ct_lane_t* lane = ct_lane_find(store, lane_id);
    if (!lane) {
        kv_store_unlock(store);
        errno = ENOENT;
        return false;
    }

    if (lane->status.mode != QIHSE_KV_CT_LANE_RECEIVER) {
        kv_store_unlock(store);
        errno = EINVAL;
        return false;
    }

    if (strcmp(lane->status.generation, generation) != 0) {
        kv_store_unlock(store);
        errno = EINVAL;
        return false;
    }

    unsigned mismatch = 0u;
    for (size_t i = 0; i < QIHSE_KV_CT_TOKEN_BYTES; ++i) {
        mismatch |= owner_token[i] ^ lane->owner_token[i];
    }
    if (mismatch != 0u) {
        kv_store_unlock(store);
        errno = EACCES;
        return false;
    }

    /* Subset check: every bit set in subset_bitmap must be set in lane->status.slot_bitmap */
    for (size_t i = 0; i < QIHSE_KV_CT_SLOT_BITMAP_BYTES; ++i) {
        if ((subset_bitmap[i] & ~lane->status.slot_bitmap[i]) != 0u) {
            kv_store_unlock(store);
            errno = EINVAL;
            return false;
        }
    }

    /* Repeated equal bitmap is a no-op. */
    if (memcmp(lane->status.slot_bitmap, subset_bitmap, QIHSE_KV_CT_SLOT_BITMAP_BYTES) == 0) {
        kv_store_unlock(store);
        return true;
    }

    /* Persist reduced bitmap and digest; invalidate cached baseline and set
     * baseline_sealed=false without changing existing durable cursor. */
    qihse_kv_ct_lane_status_t old_status = lane->status;
    memcpy(lane->status.slot_bitmap, subset_bitmap, QIHSE_KV_CT_SLOT_BITMAP_BYTES);
    if (!ct_lane_digest_bitmap(subset_bitmap, lane->status.slot_bitmap_digest)) {
        lane->status = old_status;
        kv_store_unlock(store);
        errno = EIO;
        return false;
    }

    if (!ct_lane_transfer_baseline_invalidate(store, lane)) {
        lane->status = old_status;
        kv_store_unlock(store);
        errno = EIO;
        return false;
    }

    bool ok = ct_lanes_state_write(store) && ct_lane_marker_write(store);
    if (!ok) {
        lane->status = old_status;
        store->recovery_pending = true;
        kv_store_unlock(store);
        errno = EIO;
        return false;
    }

    kv_store_unlock(store);
    return true;
}

#endif /* QIHSE_CT_LANE_LIFECYCLE_INC */
