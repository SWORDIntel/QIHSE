#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "qihse_auth.h"
#include "qihse_crc16.h"
#include "qihse_kv_store.h"
#include "aimem_fixture_cleanup.h"

/* Forward declarations for lifecycle helpers implemented in qihse_ct_lane_lifecycle.inc */
bool qihse_kv_ct_lane_promotion_retire(qihse_kv_store_t* store,
    qihse_user_t* control_principal, qihse_user_t* data_principal,
    const qihse_kv_ct_lane_authority_claim_t* final_claim,
    const qihse_kv_ct_proof_t* final_proof,
    qihse_kv_ct_lane_authority_verify_fn verify, void* verify_context);

bool qihse_kv_ct_lane_receiver_prepare(qihse_kv_store_t* store,
    qihse_user_t* control_principal, qihse_user_t* data_principal,
    const qihse_kv_ct_lane_authority_claim_t* reserved_claim,
    const qihse_kv_ct_proof_t* reserved_proof,
    qihse_kv_ct_lane_authority_verify_fn verify_reserved, void* verify_context,
    unsigned char out_owner_token[QIHSE_KV_CT_TOKEN_BYTES]);

bool qihse_kv_ct_lane_receiver_prune(qihse_kv_store_t* store,
    qihse_user_t* operator_principal, const char* lane_id,
    const char* generation,
    const uint8_t subset_bitmap[QIHSE_KV_CT_SLOT_BITMAP_BYTES],
    const unsigned char owner_token[QIHSE_KV_CT_TOKEN_BYTES]);

#define RETAINED_LIMIT (16u * 1024u * 1024u)

static const char LANE_A[QIHSE_KV_CT_LANE_ID_MAX + 1u] =
    "1111111111111111111111111111111111111111111111111111111111111111";
static const char LANE_B[QIHSE_KV_CT_LANE_ID_MAX + 1u] =
    "2222222222222222222222222222222222222222222222222222222222222222";
static const char GEN_A[33] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
static const char GEN_B[33] = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
static const char GEN_C[33] = "cccccccccccccccccccccccccccccccc";

static void bitmap_set(uint8_t bitmap[QIHSE_KV_CT_SLOT_BITMAP_BYTES], uint16_t slot) {
    bitmap[slot / 8u] |= (uint8_t)(1u << (slot % 8u));
}

static bool bitmap_has(const uint8_t bitmap[QIHSE_KV_CT_SLOT_BITMAP_BYTES], uint16_t slot) {
    return (bitmap[slot / 8u] & (uint8_t)(1u << (slot % 8u))) != 0;
}

static char* key_for_slot(const char* prefix, uint16_t wanted_slot) {
    char candidate[128];
    for (unsigned i = 0; i < 1000000u; ++i) {
        int n = snprintf(candidate, sizeof(candidate), "%s%u", prefix, i);
        assert(n > 0 && (size_t)n < sizeof(candidate));
        if (qihse_cluster_key_slot(candidate, (size_t)n) == wanted_slot) {
            char* out = strdup(candidate);
            assert(out);
            return out;
        }
    }
    assert(!"could not find key for requested cluster slot");
    return NULL;
}

static bool verify_lane_claim(void* context,
    const qihse_kv_ct_lane_authority_claim_t* claim, bool require_final) {
    const bool final_available = context && *(const bool*)context;
    if (!claim || claim->reserve_index != 11u) return false;
    return !require_final || (final_available && claim->final_decision_index == 12u);
}

static bool verify_strict_reserved(void* context,
    const qihse_kv_ct_lane_authority_claim_t* claim, bool require_final) {
    (void)context;
    if (require_final) return false; /* Strict RESERVED only, no final allowed */
    if (!claim || claim->reserve_index != 11u) return false;
    return claim->final_decision_index == 0u;
}

int main(void) {
    char data_dir[] = "./ct_lifecycle_XXXXXX";
    umask(0077);
    assert(mkdtemp(data_dir));
    assert(setenv("QIHSE_DATA_DIR", data_dir, 1) == 0);
    assert(setenv("QIHSE_FIPS_MODE", "disabled", 1) == 0);
    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator("CtLaneOperator1!"));
    qihse_user_t* op = qihse_auth_authenticate_id(0u, "CtLaneOperator1!");
    assert(op);
    qihse_user_t* low = qihse_auth_create_user(op, 8501u, QIHSE_ROLE_ANALYST,
                                                0u, 0u, "CtLaneLowPass1!", false);
    qihse_user_t* peer = qihse_auth_create_user(op, 8502u, QIHSE_ROLE_ANALYST,
                                                 5u, 3u, "CtLanePeerPass1!", false);
    assert(low && peer);

    uint8_t slots_a[QIHSE_KV_CT_SLOT_BITMAP_BYTES] = {0};
    uint8_t slots_b[QIHSE_KV_CT_SLOT_BITMAP_BYTES] = {0};
    uint16_t slot_a1 = 120u;
    uint16_t slot_a2 = 121u;
    uint16_t slot_b = 9000u;
    bitmap_set(slots_a, slot_a1);
    bitmap_set(slots_a, slot_a2);
    bitmap_set(slots_b, slot_b);
    assert(!bitmap_has(slots_a, slot_b) && !bitmap_has(slots_b, slot_a1));

    char* key_a = key_for_slot("data/a-", slot_a1);
    char* key_b = key_for_slot("data/b-", slot_b);

    qihse_kv_store_t* store = qihse_kv_store_create_user(op);
    assert(store);
    qihse_kv_store_set_replication_principal_id(store, qihse_user_get_id(peer));

    unsigned char token_a[QIHSE_KV_CT_TOKEN_BYTES];
    unsigned char token_b[QIHSE_KV_CT_TOKEN_BYTES];
    assert(qihse_kv_ct_lane_source_enable(store, op, LANE_A, slots_a,
        "node-a", "peer-a", GEN_A, token_a, RETAINED_LIMIT));
    assert(qihse_kv_ct_lane_source_enable(store, op, LANE_B, slots_b,
        "node-b", "peer-b", GEN_B, token_b, RETAINED_LIMIT));

    /* Admit LANE_A and LANE_B with baseline snapshots */
    qihse_kv_replica_snapshot_t* base_a = NULL;
    uint64_t seq_a = 0u;
    unsigned char digest_a[32];
    assert(qihse_kv_ct_lane_source_baseline_snapshot_create(store, op, LANE_A,
        &base_a, &seq_a, digest_a) == 0);
    assert(base_a && seq_a == 0u);
    char empty_image[256];
    assert(snprintf(empty_image, sizeof(empty_image), "%s/empty-baseline.bin", data_dir) > 0);
    FILE* empty_file = fopen(empty_image, "wb");
    assert(empty_file);
    uint64_t empty_bytes = 0u, empty_offset = 0u;
    assert(qihse_kv_replica_snapshot_size(base_a, op, &empty_bytes));
    while (empty_offset < empty_bytes) {
        unsigned char bytes[4096]; size_t got = 0u;
        assert(qihse_kv_replica_snapshot_read(base_a, op, empty_offset,
            bytes, sizeof(bytes), &got) && got);
        assert(fwrite(bytes, 1u, got, empty_file) == got);
        empty_offset += got;
    }
    assert(fclose(empty_file) == 0);
    qihse_kv_replica_snapshot_destroy(base_a);

    qihse_kv_replica_snapshot_t* base_b = NULL;
    uint64_t seq_b = 0u;
    unsigned char digest_b[32];
    assert(qihse_kv_ct_lane_source_baseline_snapshot_create(store, op, LANE_B,
        &base_b, &seq_b, digest_b) == 0);
    assert(base_b && seq_b == 0u);
    qihse_kv_replica_snapshot_destroy(base_b);

    qihse_kv_ct_lane_status_t status_a, status_b;
    assert(qihse_kv_ct_lane_source_reconcile_peer(store, op, peer, LANE_A,
        "peer-a", GEN_A, digest_a, 0u));
    assert(qihse_kv_ct_lane_source_reconcile_peer(store, op, peer, LANE_B,
        "peer-b", GEN_B, digest_b, 0u));
    assert(qihse_kv_ct_lane_status(store, op, LANE_A, &status_a) && status_a.admitted);
    assert(qihse_kv_ct_lane_status(store, op, LANE_B, &status_b) && status_b.admitted);

    /* Write some data in LANE_A and LANE_B */
    qihse_kv_ct_writer_scope_t* scope = NULL;
    assert(qihse_kv_ct_writer_scope_enter_lane(store, op, LANE_A, token_a, &scope));
    assert(qihse_kv_set_user(store, key_a, "val-a1", 6u, 1u, op));
    qihse_kv_ct_writer_scope_leave(scope);

    assert(qihse_kv_ct_writer_scope_enter_lane(store, op, LANE_B, token_b, &scope));
    assert(qihse_kv_set_user(store, key_b, "val-b1", 6u, 1u, op));
    qihse_kv_ct_writer_scope_leave(scope);

    /* =========================================================================
     * SECTION 1: qihse_kv_ct_lane_promotion_retire
     * ========================================================================= */
    printf("[TEST] Testing qihse_kv_ct_lane_promotion_retire...\n");

    /* Construct a RESERVED proof (final_decision_index == 0) */
    qihse_kv_ct_lane_authority_claim_t reserved_claim = {0};
    reserved_claim.operation = QIHSE_KV_CT_LANE_AUTH_PROMOTION;
    snprintf(reserved_claim.transfer_id, sizeof(reserved_claim.transfer_id), "retire-tx-1");
    snprintf(reserved_claim.source_group_id, sizeof(reserved_claim.source_group_id), "%s", LANE_A);
    snprintf(reserved_claim.target_group_id, sizeof(reserved_claim.target_group_id), "%s", LANE_A);
    snprintf(reserved_claim.source_qkp_id, sizeof(reserved_claim.source_qkp_id), "node-a");
    snprintf(reserved_claim.target_qkp_id, sizeof(reserved_claim.target_qkp_id), "node-target");
    snprintf(reserved_claim.source_generation, sizeof(reserved_claim.source_generation), "%s", GEN_A);
    snprintf(reserved_claim.target_generation, sizeof(reserved_claim.target_generation), "%s", GEN_C);
    snprintf(reserved_claim.successor_qkp_id, sizeof(reserved_claim.successor_qkp_id), "peer-succ");
    memcpy(reserved_claim.slots, slots_a, sizeof(slots_a));
    reserved_claim.grant_epoch = 1u;
    reserved_claim.reserve_index = 11u;
    memset(reserved_claim.reserve_digest, 0x11, sizeof(reserved_claim.reserve_digest));
    reserved_claim.source_cut = status_a.durable_position;
    memcpy(reserved_claim.range_digest, status_a.slot_bitmap_digest, 32u);
    memset(reserved_claim.promotion_event_digest, 0x33, sizeof(reserved_claim.promotion_event_digest));

    bool no_final = false;
    qihse_kv_ct_proof_t* reserved_proof = qihse_kv_ct_lane_authority_proof_create(
        store, op, op, &reserved_claim, verify_lane_claim, &no_final);
    assert(reserved_proof);

    /* Construct a FINAL proof */
    qihse_kv_ct_lane_authority_claim_t final_claim = reserved_claim;
    final_claim.final_decision_index = 12u;
    memset(final_claim.final_decision_digest, 0x44, sizeof(final_claim.final_decision_digest));
    bool final_available = true;
    qihse_kv_ct_proof_t* final_proof = qihse_kv_ct_lane_authority_proof_create(
        store, op, op, &final_claim, verify_lane_claim, &final_available);
    assert(final_proof);

    /* 1.1: Low/no principal checks */
    assert(!qihse_kv_ct_lane_promotion_retire(store, NULL, op, &final_claim, final_proof,
        verify_lane_claim, &final_available));
    assert(!qihse_kv_ct_lane_promotion_retire(store, low, op, &final_claim, final_proof,
        verify_lane_claim, &final_available));
    assert(!qihse_kv_ct_lane_promotion_retire(store, op, NULL, &final_claim, final_proof,
        verify_lane_claim, &final_available));

    /* 1.2: Wrong / RESERVED-not-FINAL proof for retirement */
    assert(!qihse_kv_ct_lane_promotion_retire(store, op, op, &reserved_claim, reserved_proof,
        verify_lane_claim, &no_final));
    assert(!qihse_kv_ct_lane_promotion_retire(store, op, op, &final_claim, reserved_proof,
        verify_lane_claim, &no_final));

    /* 1.3: Happy path retirement of LANE_A */
    assert(qihse_kv_ct_lane_promotion_retire(store, op, op, &final_claim, final_proof,
        verify_lane_claim, &final_available));

    /* Check LANE_A became inactive RECEIVER */
    assert(qihse_kv_ct_lane_status(store, op, LANE_A, &status_a));
    assert(status_a.mode == QIHSE_KV_CT_LANE_RECEIVER);
    assert(!status_a.admitted);
    assert(!status_a.baseline_sealed);
    assert(!status_a.promotion_pending);
    assert(strcmp(status_a.generation, GEN_A) == 0);
    assert(strcmp(status_a.source_id, "node-a") == 0);
    assert(memcmp(status_a.slot_bitmap, slots_a, sizeof(slots_a)) == 0);

    /* 1.4: Preservation of unrelated admitted SOURCE LANE_B */
    assert(qihse_kv_ct_lane_status(store, op, LANE_B, &status_b));
    assert(status_b.mode == QIHSE_KV_CT_LANE_SOURCE);
    assert(status_b.admitted);
    assert(qihse_kv_ct_writer_scope_enter_lane(store, op, LANE_B, token_b, &scope));
    assert(qihse_kv_set_user(store, key_b, "val-b2", 6u, 1u, op));
    qihse_kv_ct_writer_scope_leave(scope);

    /* 1.5: Old ACK / write / read rejection on retired LANE_A */
    assert(!qihse_kv_ct_writer_scope_enter_lane(store, op, LANE_A, token_a, &scope));
    assert(!qihse_kv_ct_lane_source_ack(store, peer, LANE_A, "peer-a", GEN_A, 1u));
    qihse_kv_ct_group_t* groups = NULL;
    size_t group_count = 0u;
    uint64_t resume = 0u;
    assert(!qihse_kv_ct_lane_source_read(store, peer, LANE_A, GEN_A, 0u, 8u, 65536u,
        &groups, &group_count, &resume));

    /* 1.6: Same retired retry succeeds */
    assert(qihse_kv_ct_lane_promotion_retire(store, op, op, &final_claim, final_proof,
        verify_lane_claim, &final_available));

    printf("[PASS] qihse_kv_ct_lane_promotion_retire passed\n");

    /* =========================================================================
     * SECTION 2: qihse_kv_ct_lane_receiver_prepare
     * ========================================================================= */
    printf("[TEST] Testing qihse_kv_ct_lane_receiver_prepare...\n");

    unsigned char new_token_a[QIHSE_KV_CT_TOKEN_BYTES];
    memset(new_token_a, 0, sizeof(new_token_a));

    /* 2.1: Low/no principal checks */
    assert(!qihse_kv_ct_lane_receiver_prepare(store, NULL, op, &reserved_claim, reserved_proof,
        verify_strict_reserved, NULL, new_token_a));
    assert(!qihse_kv_ct_lane_receiver_prepare(store, low, op, &reserved_claim, reserved_proof,
        verify_strict_reserved, NULL, new_token_a));
    assert(!qihse_kv_ct_lane_receiver_prepare(store, op, NULL, &reserved_claim, reserved_proof,
        verify_strict_reserved, NULL, new_token_a));

    /* 2.2: Strict RESERVED verifier check (rejects final proof) */
    assert(!qihse_kv_ct_lane_receiver_prepare(store, op, op, &final_claim, final_proof,
        verify_strict_reserved, NULL, new_token_a));

    /* 2.3: Rebind old SOURCE / retired RECEIVER LANE_A to new RECEIVER */
    assert(qihse_kv_ct_lane_receiver_prepare(store, op, op, &reserved_claim, reserved_proof,
        verify_strict_reserved, NULL, new_token_a));

    /* Check rotated token */
    unsigned token_diff = 0u;
    for (size_t i = 0; i < QIHSE_KV_CT_TOKEN_BYTES; ++i) {
        token_diff |= token_a[i] ^ new_token_a[i];
    }
    assert(token_diff != 0u);

    /* Verify new RECEIVER state */
    assert(qihse_kv_ct_lane_status(store, op, LANE_A, &status_a));
    assert(status_a.mode == QIHSE_KV_CT_LANE_RECEIVER);
    assert(strcmp(status_a.source_id, reserved_claim.target_qkp_id) == 0);
    assert(strcmp(status_a.peer_id, reserved_claim.successor_qkp_id) == 0);
    assert(strcmp(status_a.generation, GEN_C) == 0);
    assert(!status_a.admitted);
    assert(!status_a.baseline_sealed);
    assert(status_a.baseline_row_seq == 0u);
    assert(status_a.durable_position == 0u);
    assert(status_a.retained_bytes == 0u);

    /* 2.4: Newer-generation local lane left unchanged on historical replay of retirement */
    assert(qihse_kv_ct_lane_promotion_retire(store, op, op, &final_claim, final_proof,
        verify_lane_claim, &final_available));
    assert(qihse_kv_ct_lane_status(store, op, LANE_A, &status_a));
    assert(strcmp(status_a.generation, GEN_C) == 0);
    assert(strcmp(status_a.source_id, reserved_claim.target_qkp_id) == 0);

    /* 2.5: Idempotency: exact same tuple returns same token, preserves cursors */
    unsigned char repeat_token[QIHSE_KV_CT_TOKEN_BYTES];
    assert(qihse_kv_ct_lane_receiver_prepare(store, op, op, &reserved_claim, reserved_proof,
        verify_strict_reserved, NULL, repeat_token));
    assert(memcmp(new_token_a, repeat_token, QIHSE_KV_CT_TOKEN_BYTES) == 0);

    /* 2.6: Unrelated lane LANE_B remains intact */
    assert(qihse_kv_ct_lane_status(store, op, LANE_B, &status_b));
    assert(status_b.mode == QIHSE_KV_CT_LANE_SOURCE);
    assert(status_b.admitted);

    printf("[PASS] qihse_kv_ct_lane_receiver_prepare passed\n");

    /* =========================================================================
     * SECTION 3: qihse_kv_ct_lane_receiver_prune
     * ========================================================================= */
    printf("[TEST] Testing qihse_kv_ct_lane_receiver_prune...\n");

    /* 3.1: Low/no principal checks */
    assert(!qihse_kv_ct_lane_receiver_prune(store, NULL, LANE_A, GEN_C, slots_a, new_token_a));
    assert(!qihse_kv_ct_lane_receiver_prune(store, low, LANE_A, GEN_C, slots_a, new_token_a));

    /* 3.2: Wrong token / wrong generation */
    unsigned char bad_token[QIHSE_KV_CT_TOKEN_BYTES];
    memcpy(bad_token, new_token_a, sizeof(bad_token));
    bad_token[0] ^= 0xff;
    assert(!qihse_kv_ct_lane_receiver_prune(store, op, LANE_A, GEN_C, slots_a, bad_token));
    assert(!qihse_kv_ct_lane_receiver_prune(store, op, LANE_A, GEN_A, slots_a, new_token_a));

    /* 3.3: Reject prune on SOURCE lane */
    assert(!qihse_kv_ct_lane_receiver_prune(store, op, LANE_B, GEN_B, slots_b, token_b));

    /* 3.4: Subset rejection on additions */
    uint8_t added_bitmap[QIHSE_KV_CT_SLOT_BITMAP_BYTES];
    memcpy(added_bitmap, slots_a, sizeof(added_bitmap));
    bitmap_set(added_bitmap, 500u); /* slot 500 was not in slots_a */
    assert(!qihse_kv_ct_lane_receiver_prune(store, op, LANE_A, GEN_C, added_bitmap, new_token_a));

    /* 3.5: Repeated equal bitmap is a no-op */
    assert(qihse_kv_ct_lane_receiver_prune(store, op, LANE_A, GEN_C, slots_a, new_token_a));

    /* A historical receiver frame in the removed slot must not be replayed
     * against a later same-generation staging bitmap after restart. */
    assert(qihse_kv_ct_lane_receiver_baseline_install(store, op, op, LANE_A,
        slots_a, empty_image, 0u, 0u, digest_a, new_token_a));
    char* removed_key = key_for_slot("data/receiver-removed-", slot_a2);
    qihse_kv_ct_record_t received = {0};
    received.key = removed_key;
    received.value = "old-receiver-frame";
    received.classification = 4u;
    received.sci_compartment = 1u;
    received.change_seq = 1u;
    received.actor_kind = QIHSE_KV_CT_ACTOR_USER;
    qihse_kv_ct_group_t receiver_group = {0};
    snprintf(receiver_group.source_id, sizeof(receiver_group.source_id), "%s", reserved_claim.target_qkp_id);
    snprintf(receiver_group.generation, sizeof(receiver_group.generation), "%s", GEN_C);
    receiver_group.stream_position = 1u;
    receiver_group.first_seq = receiver_group.last_seq = 1u;
    receiver_group.records = &received;
    receiver_group.count = 1u;
    uint64_t received_cursor = 0u;
    assert(qihse_kv_ct_lane_receiver_apply(store, peer, LANE_A,
        &receiver_group, &received_cursor) && received_cursor == 1u);
    free(removed_key);

    /* 3.6: Strict subset prune: remove slot_a2, keep slot_a1 */
    uint8_t pruned_bitmap[QIHSE_KV_CT_SLOT_BITMAP_BYTES] = {0};
    bitmap_set(pruned_bitmap, slot_a1);
    assert(bitmap_has(slots_a, slot_a2));
    assert(!bitmap_has(pruned_bitmap, slot_a2));

    assert(qihse_kv_ct_lane_receiver_prune(store, op, LANE_A, GEN_C, pruned_bitmap, new_token_a));

    /* Check pruned status */
    assert(qihse_kv_ct_lane_status(store, op, LANE_A, &status_a));
    assert(memcmp(status_a.slot_bitmap, pruned_bitmap, sizeof(pruned_bitmap)) == 0);
    assert(!status_a.baseline_sealed);
    assert(status_a.durable_position == 1u);

    /* LANE_B remains intact */
    assert(qihse_kv_ct_lane_status(store, op, LANE_B, &status_b));
    assert(status_b.mode == QIHSE_KV_CT_LANE_SOURCE && status_b.admitted);

    qihse_kv_ct_lane_authority_claim_t incoming_transfer = reserved_claim;
    incoming_transfer.operation = QIHSE_KV_CT_LANE_AUTH_TRANSFER;
    snprintf(incoming_transfer.transfer_id, sizeof(incoming_transfer.transfer_id),
             "reuse-empty-staging");
    snprintf(incoming_transfer.target_group_id, sizeof(incoming_transfer.target_group_id),
             "%s", LANE_B);
    snprintf(incoming_transfer.source_qkp_id, sizeof(incoming_transfer.source_qkp_id),
             "%s", reserved_claim.target_qkp_id);
    snprintf(incoming_transfer.target_qkp_id, sizeof(incoming_transfer.target_qkp_id), "node-b");
    snprintf(incoming_transfer.successor_qkp_id, sizeof(incoming_transfer.successor_qkp_id), "peer-b");
    snprintf(incoming_transfer.source_generation, sizeof(incoming_transfer.source_generation), "%s", GEN_C);
    snprintf(incoming_transfer.target_generation, sizeof(incoming_transfer.target_generation), "%s", GEN_B);
    memcpy(incoming_transfer.slots, pruned_bitmap, sizeof(pruned_bitmap));
    qihse_kv_ct_proof_t* incoming_proof = qihse_kv_ct_lane_authority_proof_create(
        store, op, op, &incoming_transfer, verify_strict_reserved, NULL);
    assert(incoming_proof);
    unsigned char incoming_token[QIHSE_KV_CT_TOKEN_BYTES];
    /* A live nonempty receiver cannot be replaced by a transfer context. */
    assert(!qihse_kv_ct_lane_receiver_prepare(store, op, op, &incoming_transfer,
        incoming_proof, verify_strict_reserved, NULL, incoming_token));
    uint8_t no_slots[QIHSE_KV_CT_SLOT_BITMAP_BYTES] = {0};
    assert(qihse_kv_ct_lane_receiver_prune(store, op, LANE_A, GEN_C,
        no_slots, new_token_a));
    assert(!qihse_kv_ct_lane_receiver_prepare(store, low, op, &incoming_transfer,
        incoming_proof, verify_strict_reserved, NULL, incoming_token));
    assert(qihse_kv_ct_lane_receiver_prepare(store, op, op, &incoming_transfer,
        incoming_proof, verify_strict_reserved, NULL, incoming_token));
    assert(memcmp(incoming_token, new_token_a, sizeof(incoming_token)) != 0);
    unsigned char same_incoming_token[QIHSE_KV_CT_TOKEN_BYTES];
    assert(qihse_kv_ct_lane_receiver_prepare(store, op, op, &incoming_transfer,
        incoming_proof, verify_strict_reserved, NULL, same_incoming_token));
    assert(memcmp(incoming_token, same_incoming_token, sizeof(incoming_token)) == 0);
    assert(qihse_kv_ct_lane_status(store, op, LANE_A, &status_a));
    assert(!strcmp(status_a.peer_id, "node-b") && !status_a.admitted &&
        !status_a.baseline_sealed && status_a.durable_position == 0u &&
        !memcmp(status_a.slot_bitmap, pruned_bitmap, sizeof(pruned_bitmap)));
    assert(qihse_kv_ct_lane_status(store, op, LANE_B, &status_b));
    assert(status_b.mode == QIHSE_KV_CT_LANE_SOURCE && status_b.admitted);
    qihse_kv_ct_proof_destroy(incoming_proof);

    printf("[PASS] qihse_kv_ct_lane_receiver_prune passed\n");

    /* =========================================================================
     * SECTION 4: Restart persistence
     * ========================================================================= */
    printf("[TEST] Testing restart persistence...\n");

    qihse_kv_store_destroy(store);

    /* Reopen from disk */
    qihse_kv_store_t* store2 = qihse_kv_store_create_user(op);
    assert(store2);
    qihse_kv_store_set_replication_principal_id(store2, qihse_user_get_id(peer));

    assert(qihse_kv_ct_lane_status(store2, op, LANE_A, &status_a));
    assert(status_a.mode == QIHSE_KV_CT_LANE_RECEIVER);
    assert(strcmp(status_a.generation, GEN_C) == 0);
    assert(memcmp(status_a.slot_bitmap, pruned_bitmap, sizeof(pruned_bitmap)) == 0);
    assert(!status_a.baseline_sealed && status_a.durable_position == 0u);

    assert(qihse_kv_ct_lane_status(store2, op, LANE_B, &status_b));
    assert(status_b.mode == QIHSE_KV_CT_LANE_SOURCE);
    assert(strcmp(status_b.generation, GEN_B) == 0);
    /* A source lane requires peer reconciliation to become admitted after restart */
    assert(!status_b.admitted);
    assert(qihse_kv_ct_lane_source_reconcile_peer(store2, op, peer, LANE_B,
        "peer-b", GEN_B, digest_b, 0u));
    assert(qihse_kv_ct_lane_status(store2, op, LANE_B, &status_b));
    assert(status_b.admitted);

    unsigned char disable_token[QIHSE_KV_CT_TOKEN_BYTES] = {0};
    assert(qihse_kv_ct_lane_owner_token_get(store2, op, LANE_B, disable_token));
    assert(!qihse_kv_ct_lane_source_disable(store2, low, LANE_B, GEN_B, disable_token));
    assert(!qihse_kv_ct_lane_source_disable(store2, NULL, LANE_B, GEN_B, disable_token));
    assert(!qihse_kv_ct_lane_source_disable(store2, op, LANE_B, GEN_C, disable_token));
    disable_token[0] ^= 1u;
    assert(!qihse_kv_ct_lane_source_disable(store2, op, LANE_B, GEN_B, disable_token));
    disable_token[0] ^= 1u;
    assert(qihse_kv_ct_lane_source_disable(store2, op, LANE_B, GEN_B, disable_token));
    assert(qihse_kv_ct_lane_source_disable(store2, op, LANE_B, GEN_B, disable_token));
    assert(!qihse_kv_ct_lane_source_ack(store2, peer, LANE_B, "peer-b", GEN_B, 0u));
    assert(qihse_kv_ct_lane_status(store2, op, LANE_B, &status_b));
    assert(status_b.mode == QIHSE_KV_CT_LANE_RECEIVER && !status_b.admitted);

    qihse_kv_store_destroy(store2);

    qihse_kv_ct_proof_destroy(reserved_proof);
    qihse_kv_ct_proof_destroy(final_proof);
    qihse_auth_release_principal_scoped(op);
    qihse_auth_release_principal_scoped(low);
    qihse_auth_release_principal_scoped(peer);
    free(key_a);
    free(key_b);

    printf("[PASS] All CT lane lifecycle tests passed successfully!\n");
    aimem_fixture_cleanup(data_dir);
    return 0;
}
