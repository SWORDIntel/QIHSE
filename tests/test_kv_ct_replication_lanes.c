#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "qihse_auth.h"
#include "qihse_crc16.h"
#include "qihse_kv_store.h"
#include "aimem_fixture_cleanup.h"

#define RETAINED_LIMIT (16u * 1024u * 1024u)

static const char LANE_A[QIHSE_KV_CT_LANE_ID_MAX + 1u] =
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
static const char LANE_B[QIHSE_KV_CT_LANE_ID_MAX + 1u] =
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
static const char GEN_A[33] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
static const char GEN_B[33] = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
static const char GEN_C[33] = "cccccccccccccccccccccccccccccccc";

static void bitmap_set(uint8_t bitmap[QIHSE_KV_CT_SLOT_BITMAP_BYTES], uint16_t slot) {
    bitmap[slot / 8u] |= (uint8_t)(1u << (slot % 8u));
}

static bool bitmap_has(const uint8_t bitmap[QIHSE_KV_CT_SLOT_BITMAP_BYTES], uint16_t slot) {
    return (bitmap[slot / 8u] & (uint8_t)(1u << (slot % 8u))) != 0;
}

static char *key_for_slot(const char *prefix, uint16_t wanted_slot) {
    char candidate[128];
    for (unsigned i = 0; i < 1000000u; ++i) {
        int n = snprintf(candidate, sizeof(candidate), "%s%u", prefix, i);
        assert(n > 0 && (size_t)n < sizeof(candidate));
        if (qihse_cluster_key_slot(candidate, (size_t)n) == wanted_slot) {
            char *out = strdup(candidate);
            assert(out);
            return out;
        }
    }
    assert(!"could not find key for requested cluster slot");
    return NULL;
}

static void assert_value(qihse_kv_store_t *store, qihse_user_t *user,
                         const char *key, const char *expected) {
    char *value = qihse_kv_get_user(store, key, user);
    if (!expected) assert(value == NULL);
    else assert(value && strcmp(value, expected) == 0);
    free(value);
}

static bool verify_lane_claim(void *context,
    const qihse_kv_ct_lane_authority_claim_t *claim, bool require_final) {
    const bool final_available = context && *(const bool *)context;
    if (!claim || claim->reserve_index != 11u) return false;
    return !require_final || (final_available && claim->final_decision_index == 12u);
}

int main(void) {
    char data_dir[] = "./ct_lanes_XXXXXX";
    umask(0077);
    assert(mkdtemp(data_dir));
    assert(setenv("QIHSE_DATA_DIR", data_dir, 1) == 0);
    assert(setenv("QIHSE_FIPS_MODE", "disabled", 1) == 0);
    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator("CtLaneOperator1!"));
    qihse_user_t *op = qihse_auth_authenticate_id(0u, "CtLaneOperator1!");
    assert(op);
    qihse_user_t *low = qihse_auth_create_user(op, 8401u, QIHSE_ROLE_ANALYST,
                                                0u, 0u, "CtLaneLowPass1!", false);
    qihse_user_t *peer = qihse_auth_create_user(op, 8402u, QIHSE_ROLE_ANALYST,
                                                 5u, 3u, "CtLanePeerPass1!", false);
    assert(low && peer);

    /* Two disjoint lanes on one store. Keys are generated against the actual
     * cluster hash so this tests routing by slot rather than assumed prefixes. */
    uint8_t slots_a[QIHSE_KV_CT_SLOT_BITMAP_BYTES] = {0};
    uint8_t slots_b[QIHSE_KV_CT_SLOT_BITMAP_BYTES] = {0};
    uint16_t slot_a = 127u, slot_b = 12000u;
    assert(slot_a != slot_b);
    bitmap_set(slots_a, slot_a);
    bitmap_set(slots_b, slot_b);
    assert(!bitmap_has(slots_a, slot_b) && !bitmap_has(slots_b, slot_a));
    char *key_a = key_for_slot("commons/lane-a-", slot_a);
    char *key_a2 = key_for_slot("commons/lane-a-batch-", slot_a);
    char *key_b = key_for_slot("t:73/lane-b-", slot_b);

    qihse_kv_store_t *store = qihse_kv_store_create_user(op);
    assert(store);
    qihse_kv_store_set_replication_principal_id(store, qihse_user_get_id(peer));
    unsigned char token_a[QIHSE_KV_CT_TOKEN_BYTES];
    unsigned char token_b[QIHSE_KV_CT_TOKEN_BYTES];
    assert(qihse_kv_ct_lane_source_enable(store, op, LANE_A, slots_a,
        "node-a", "peer-a", GEN_A, token_a, RETAINED_LIMIT));
    char marker_path[256];
    int marker_n = snprintf(marker_path, sizeof(marker_path), "%s/ct-state.bin", data_dir);
    assert(marker_n > 0 && (size_t)marker_n < sizeof(marker_path));
    FILE *marker_file = fopen(marker_path, "rb"); assert(marker_file);
    char marker[8]; assert(fread(marker, 1u, sizeof(marker), marker_file) == sizeof(marker));
    assert(memcmp(marker, "QCTST004", sizeof(marker)) == 0);
    assert(fclose(marker_file) == 0);
    assert(qihse_kv_ct_lane_receiver_bind(store, op, LANE_B, slots_b,
        "peer-b", "node-a", GEN_B, QIHSE_KV_CT_TENANT_SYSTEM_ALL,
        0u, 0u, token_b));
    unsigned char rejected_token[QIHSE_KV_CT_TOKEN_BYTES];
    assert(!qihse_kv_ct_lane_receiver_bind(store, op,
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        slots_b, "peer-c", "node-a", GEN_C, QIHSE_KV_CT_TENANT_EXACT,
        73u, 0u, rejected_token));
    assert(qihse_kv_ct_lane_owner_token_get(store, op, LANE_A, token_a));
    assert(qihse_kv_ct_lane_owner_token_get(store, op, LANE_B, token_b));

    qihse_kv_ct_lane_status_t status_a = {0}, status_b = {0};
    assert(qihse_kv_ct_lane_status(store, op, LANE_A, &status_a));
    assert(qihse_kv_ct_lane_status(store, op, LANE_B, &status_b));
    assert(status_a.mode == QIHSE_KV_CT_LANE_SOURCE &&
           status_b.mode == QIHSE_KV_CT_LANE_RECEIVER);
    assert(memcmp(status_a.slot_bitmap, slots_a, sizeof(slots_a)) == 0);
    assert(memcmp(status_b.slot_bitmap, slots_b, sizeof(slots_b)) == 0);
    assert(!qihse_kv_ct_lane_status(store, low, LANE_A, &status_a));
    assert(!qihse_kv_ct_lane_status(store, peer, "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", &status_a));

    /* Lane B starts from a real canonical empty baseline, not cursor zero by
     * convention. Its lane-specific owner token seals only that lane. */
    unsigned char empty_digest[32];
    assert(qihse_kv_ct_lane_receiver_empty_baseline_seal(store, op, LANE_B,
        token_b, empty_digest));
    assert(qihse_kv_ct_lane_status(store, op, LANE_B, &status_b) &&
           status_b.baseline_sealed && status_b.baseline_row_seq == 0u);

    qihse_kv_replica_snapshot_t *baseline = NULL;
    uint64_t baseline_seq = UINT64_MAX;
    unsigned char baseline_digest[32];
    assert(qihse_kv_ct_lane_source_baseline_snapshot_create(store, op, LANE_A,
        &baseline, &baseline_seq, baseline_digest) == 0);
    assert(baseline && baseline_seq == 0u);
    assert(!qihse_kv_ct_lane_source_reconcile_peer(store, op, low, LANE_A,
        "peer-a", GEN_A, baseline_digest, 0u));
    assert(qihse_kv_ct_lane_source_reconcile_peer(store, op, peer, LANE_A,
        "peer-a", GEN_A, baseline_digest, 0u));
    qihse_kv_replica_snapshot_destroy(baseline);

    /* Exact original certificate bytes have their own durable, bounded page
     * and ACK cursor, separate from user-row deltas. */
    static const unsigned char certificate[] = {0x51, 0x42, 0x53, 0x31, 0x00, 0xff};
    unsigned char cert_digest[32], cert_page_digest[32];
    assert(qihse_kv_ct_lane_certificate_append(store, op, LANE_A, GEN_A,
        certificate, sizeof(certificate), cert_digest));
    assert(qihse_kv_ct_lane_certificate_append(store, op, LANE_A, GEN_A,
        certificate, sizeof(certificate), cert_page_digest));
    assert(memcmp(cert_digest, cert_page_digest, sizeof(cert_digest)) == 0);
    unsigned char cert_page[128]; size_t cert_page_len = 0u; bool cert_more = false;
    unsigned char zero_digest[32] = {0};
    assert(qihse_kv_ct_lane_certificate_page(store, peer, LANE_A, zero_digest,
        cert_page, sizeof(cert_page), &cert_page_len, cert_page_digest, &cert_more));
    assert(!cert_more && cert_page_len == 36u + sizeof(certificate));
    assert(memcmp(cert_page + 36u, certificate, sizeof(certificate)) == 0);
    assert(qihse_kv_ct_lane_certificate_ack(store, peer, LANE_A, "peer-a",
        GEN_A, cert_digest));

    qihse_kv_ct_lane_authority_claim_t authority = {0};
    authority.operation = QIHSE_KV_CT_LANE_AUTH_TRANSFER;
    snprintf(authority.transfer_id, sizeof(authority.transfer_id), "move-1");
    snprintf(authority.source_group_id, sizeof(authority.source_group_id), "%s", LANE_A);
    snprintf(authority.target_group_id, sizeof(authority.target_group_id), "%s", LANE_B);
    snprintf(authority.source_qkp_id, sizeof(authority.source_qkp_id), "peer-a");
    snprintf(authority.target_qkp_id, sizeof(authority.target_qkp_id), "peer-b");
    snprintf(authority.source_generation, sizeof(authority.source_generation), "%s", GEN_A);
    snprintf(authority.target_generation, sizeof(authority.target_generation), "%s", GEN_B);
    snprintf(authority.successor_qkp_id, sizeof(authority.successor_qkp_id), "peer-a");
    memcpy(authority.slots, slots_a, sizeof(slots_a));
    authority.grant_epoch = 1u;
    authority.reserve_index = 11u;
    memset(authority.reserve_digest, 0x11, sizeof(authority.reserve_digest));
    bool no_final_decision = false;
    qihse_kv_ct_proof_t *authority_proof =
        qihse_kv_ct_lane_authority_proof_create(store, op, op, &authority,
            verify_lane_claim, &no_final_decision);
    assert(authority_proof);
    assert(!qihse_kv_ct_lane_authority_proof_create(store, low, low, &authority,
        verify_lane_claim, &no_final_decision));
    assert(qihse_kv_ct_lane_authority_proof_validate(store, op, op,
        authority_proof, verify_lane_claim, &no_final_decision, false));
    assert(!qihse_kv_ct_lane_authority_proof_validate(store, op, op,
        authority_proof, verify_lane_claim, &no_final_decision, true));
    authority.final_decision_index = 12u;
    memset(authority.final_decision_digest, 0x12,
        sizeof(authority.final_decision_digest));
    bool final_available = true;
    qihse_kv_ct_proof_t *final_proof =
        qihse_kv_ct_lane_authority_proof_create(store, op, op, &authority,
            verify_lane_claim, &final_available);
    assert(final_proof && qihse_kv_ct_lane_authority_proof_validate(store,
        op, op, final_proof, verify_lane_claim, &final_available, true));
    qihse_kv_ct_proof_destroy(final_proof);
    qihse_kv_ct_proof_destroy(authority_proof);

    qihse_kv_ct_writer_scope_t *scope = NULL;
    assert(!qihse_kv_ct_writer_scope_enter_lane(store, op, LANE_A, token_b, &scope));
    assert(!qihse_kv_set_user(store, key_a, "scope-required", 4u, 1u, op));
    assert(qihse_kv_ct_writer_scope_enter_lane(store, op, LANE_A, token_a, &scope));
    /* The local metadata namespace has its own authenticated native-WAL
     * scope; a slot-lane token must not authorize it, and vice versa. */
    const char *local_key = "t:73/aimem:test-lane-local";
    assert(!qihse_kv_set_user(store, local_key, "wrong-scope", 4u, 1u, op));
    assert(!qihse_kv_set_batch_durable_user(store,
        (qihse_kv_batch_set_record_t[]){{key_a, "cross-lane", 0u, 4u, 1u},
                                       {key_b, "cross-lane", 0u, 4u, 1u}},
        2u, op));
    qihse_kv_ct_writer_scope_leave(scope);
    scope = NULL;
    assert(qihse_kv_ct_node_local_scope_enter(store, op, &scope));
    assert(qihse_kv_set_user(store, local_key, "local-wal", 4u, 1u, op));
    assert(!qihse_kv_set_user(store, key_a, "wrong-local-scope", 4u, 1u, op));
    assert_value(store, op, local_key, "local-wal");
    qihse_kv_ct_writer_scope_leave(scope);
    scope = NULL;
    assert(qihse_kv_ct_writer_scope_enter_lane(store, op, LANE_A, token_a, &scope));
    qihse_kv_batch_set_record_t batch_a[] = {
        {key_a, "lane-a-v1", 0u, 4u, 1u},
        {key_a2, "lane-a-v1-batch", 0u, 4u, 1u}
    };
    assert(qihse_kv_set_batch_durable_user(store, batch_a,
        sizeof(batch_a) / sizeof(batch_a[0]), op));
    assert(qihse_kv_get_user(store, key_a, op) == NULL);
    assert(!qihse_kv_set_user(store, key_b, "wrong-lane-write", 4u, 1u, op));
    assert_value(store, op, key_a, NULL); /* durable ACK gates primary reads */

    qihse_kv_ct_group_t *groups = NULL;
    size_t group_count = 0u;
    uint64_t resume = 0u;
    assert(!qihse_kv_ct_lane_source_read(store, low, LANE_A, GEN_A,
        0u, 8u, 65536u, &groups, &group_count, &resume));
    assert(qihse_kv_ct_lane_source_read(store, peer, LANE_A, GEN_A,
        0u, 8u, 65536u, &groups, &group_count, &resume));
    assert(group_count == 1u && resume == 1u && groups[0].count == 2u);
    assert(strcmp(groups[0].records[0].key, key_a) == 0 &&
           strcmp(groups[0].records[0].value, "lane-a-v1") == 0 &&
           groups[0].records[0].classification == 4u &&
           groups[0].records[0].sci_compartment == 1u &&
           groups[0].records[0].resource_tenant_id == 0u);
    assert(strcmp(groups[0].records[1].key, key_a2) == 0 &&
           strcmp(groups[0].records[1].value, "lane-a-v1-batch") == 0);
    assert(qihse_kv_ct_lane_source_ack(store, peer, LANE_A,
        "peer-a", GEN_A, resume));
    assert(qihse_kv_ct_writer_scope_finish(scope, 1000u, NULL));
    qihse_kv_ct_groups_free(groups, group_count);
    groups = NULL;
    assert_value(store, op, key_a, "lane-a-v1");

    /* Apply a B-lane delta while this same process remains the admitted A
     * source. Verify both slot routing and all security metadata survive. */
    qihse_kv_ct_record_t row_b = {
        .key = key_b, .value = "lane-b-v1", .change_seq = 1u,
        .actor_id = qihse_user_get_id(peer), .actor_tenant_id = 0u,
        .resource_tenant_id = 73u, .classification = 4u,
        .sci_compartment = 1u, .actor_kind = QIHSE_KV_CT_ACTOR_USER,
        .tombstone = false
    };
    qihse_kv_ct_group_t group_b = {0};
    snprintf(group_b.source_id, sizeof(group_b.source_id), "%s", "peer-b");
    snprintf(group_b.generation, sizeof(group_b.generation), "%s", GEN_B);
    group_b.stream_position = 1u;
    group_b.first_seq = group_b.last_seq = 1u;
    group_b.records = &row_b;
    group_b.count = 1u;
    uint64_t b_cursor = 0u;
    assert(!qihse_kv_ct_lane_receiver_apply(store, low, LANE_B,
        &group_b, &b_cursor));
    row_b.resource_tenant_id = 0u; /* key-derived tenant is authoritative */
    assert(!qihse_kv_ct_lane_receiver_apply(store, peer, LANE_B,
        &group_b, &b_cursor));
    row_b.resource_tenant_id = 73u;
    assert(qihse_kv_ct_lane_receiver_apply(store, peer, LANE_B,
        &group_b, &b_cursor) && b_cursor == 1u);
    assert_value(store, op, key_b, NULL); /* receiver lane is not yet promoted */
    assert(qihse_kv_ct_lane_status(store, op, LANE_A, &status_a) &&
           status_a.mode == QIHSE_KV_CT_LANE_SOURCE &&
           status_a.acknowledged_position == 1u);
    assert(qihse_kv_ct_lane_status(store, op, LANE_B, &status_b) &&
           status_b.mode == QIHSE_KV_CT_LANE_RECEIVER &&
           status_b.durable_position == 1u && status_b.baseline_sealed);

    qihse_kv_store_destroy(store);
    store = qihse_kv_store_create_user(op);
    assert(store);
    qihse_kv_store_set_replication_principal_id(store, qihse_user_get_id(peer));
    assert(qihse_kv_ct_lane_status(store, op, LANE_A, &status_a));
    assert(qihse_kv_ct_lane_status(store, op, LANE_B, &status_b));
    assert(status_a.mode == QIHSE_KV_CT_LANE_SOURCE &&
           status_a.acknowledged_position == 1u && !status_a.admitted);
    assert(status_b.mode == QIHSE_KV_CT_LANE_RECEIVER &&
           status_b.durable_position == 1u && status_b.baseline_sealed);
    assert_value(store, op, key_a, NULL); /* source requires peer re-admission */
    assert_value(store, op, key_b, NULL); /* recovery must not promote by itself */
    assert(qihse_kv_ct_lane_source_reconcile_peer(store, op, peer, LANE_A,
        "peer-a", GEN_A, status_a.baseline_digest, status_a.acknowledged_position));

    assert(qihse_kv_ct_writer_scope_enter_lane(store, op, LANE_A,
        token_a, &scope));
    assert(qihse_kv_set_user(store, key_a, "lane-a-v2", 4u, 1u, op));
    assert(qihse_kv_ct_lane_source_read(store, peer, LANE_A, GEN_A,
        1u, 8u, 65536u, &groups, &group_count, &resume));
    assert(group_count == 1u && resume == 2u &&
           strcmp(groups[0].records[0].value, "lane-a-v2") == 0);
    assert(qihse_kv_ct_lane_source_ack(store, peer, LANE_A,
        "peer-a", GEN_A, resume));
    assert(qihse_kv_ct_writer_scope_finish(scope, 1000u, NULL));
    qihse_kv_ct_groups_free(groups, group_count);

    /* Promote receiver B independently while source A remains admitted. The
     * new generation must discard B's old baseline and seal a fresh one. */
    assert(qihse_kv_ct_lane_status(store, op, LANE_B, &status_b));
    qihse_kv_ct_lane_authority_claim_t promotion = {0};
    promotion.operation = QIHSE_KV_CT_LANE_AUTH_PROMOTION;
    snprintf(promotion.transfer_id, sizeof(promotion.transfer_id), "promote-b-1");
    snprintf(promotion.source_group_id, sizeof(promotion.source_group_id), "%s", LANE_B);
    snprintf(promotion.target_group_id, sizeof(promotion.target_group_id), "%s", LANE_B);
    snprintf(promotion.source_qkp_id, sizeof(promotion.source_qkp_id), "peer-b");
    snprintf(promotion.target_qkp_id, sizeof(promotion.target_qkp_id), "node-a");
    snprintf(promotion.source_generation, sizeof(promotion.source_generation), "%s", GEN_B);
    snprintf(promotion.target_generation, sizeof(promotion.target_generation), "%s", GEN_C);
    snprintf(promotion.successor_qkp_id, sizeof(promotion.successor_qkp_id), "peer-a");
    memcpy(promotion.slots, slots_b, sizeof(slots_b));
    promotion.grant_epoch = 2u;
    promotion.reserve_index = 11u;
    memset(promotion.reserve_digest, 0x21, sizeof(promotion.reserve_digest));
    promotion.source_cut = status_b.durable_position;
    memcpy(promotion.range_digest, status_b.slot_bitmap_digest, 32u);
    memset(promotion.promotion_event_digest, 0x44,
        sizeof(promotion.promotion_event_digest));
    qihse_kv_ct_proof_t *promotion_proof =
        qihse_kv_ct_lane_authority_proof_create(store, op, op, &promotion,
            verify_lane_claim, &no_final_decision);
    assert(promotion_proof);
    assert(qihse_kv_ct_lane_receiver_promote(store, op, op, &promotion,
        promotion_proof, verify_lane_claim, &no_final_decision, token_b));
    qihse_kv_ct_proof_destroy(promotion_proof);
    assert(qihse_kv_ct_lane_status(store, op, LANE_B, &status_b) &&
           status_b.mode == QIHSE_KV_CT_LANE_SOURCE && !status_b.admitted &&
           !status_b.baseline_sealed && status_b.durable_position == 0u);
    qihse_kv_replica_snapshot_t *promotion_baseline = NULL;
    uint64_t promotion_baseline_seq = 0u;
    unsigned char promotion_baseline_digest[32];
    assert(qihse_kv_ct_lane_source_baseline_snapshot_create(store, op, LANE_B,
        &promotion_baseline, &promotion_baseline_seq, promotion_baseline_digest) == 0);
    qihse_kv_replica_snapshot_destroy(promotion_baseline);
    promotion.target_cursor = promotion_baseline_seq;
    memcpy(promotion.image_digest, promotion_baseline_digest, 32u);
    static const unsigned char promotion_cert[] = {0x51, 0x43, 0x50, 0x32, 0x44};
    unsigned char promotion_cert_digest[32];
    assert(qihse_kv_ct_lane_certificate_append(store, op, LANE_B, GEN_C,
        promotion_cert, sizeof(promotion_cert), promotion_cert_digest));
    memcpy(promotion.certificate_head_digest, promotion_cert_digest, 32u);
    unsigned char promotion_page[128], promotion_page_digest[32];
    size_t promotion_page_len = 0u; bool promotion_more = false;
    assert(qihse_kv_ct_lane_certificate_page(store, peer, LANE_B, zero_digest,
        promotion_page, sizeof(promotion_page), &promotion_page_len,
        promotion_page_digest, &promotion_more));
    assert(promotion_page_len == 36u + sizeof(promotion_cert) && !promotion_more);
    assert(qihse_kv_ct_lane_certificate_ack(store, peer, LANE_B, "peer-a",
        GEN_C, promotion_cert_digest));
    assert(qihse_kv_ct_lane_promotion_ready(store, op, op, &promotion,
        verify_lane_claim, &no_final_decision));
    qihse_kv_ct_proof_t *promoted_proof = qihse_kv_ct_lane_promoted_proof_get(
        store, op, op, LANE_B, promotion.promotion_event_digest,
        verify_lane_claim, &no_final_decision);
    assert(promoted_proof);
    qihse_kv_ct_lane_authority_claim_t promoted_claim;
    assert(qihse_kv_ct_lane_authority_proof_fields(store, op, op,
        promoted_proof, &promoted_claim));
    assert(memcmp(promoted_claim.promotion_event_digest,
        promotion.promotion_event_digest, 32u) == 0);
    qihse_kv_ct_proof_destroy(promoted_proof);
    assert(qihse_kv_ct_lane_source_reconcile_peer(store, op, peer, LANE_B,
        "peer-a", GEN_C, promotion_baseline_digest, 0u));
    assert_value(store, op, key_b, "lane-b-v1");
    assert_value(store, op, key_a, "lane-a-v2");

    /* A verified reservation fences only its selected slots and persists a
     * recoverable transfer state before source export begins. */
    authority.final_decision_index = 0u;
    memset(authority.final_decision_digest, 0,
        sizeof(authority.final_decision_digest));
    snprintf(authority.target_generation, sizeof(authority.target_generation), "%s", GEN_C);
    authority.source_cut = resume;
    qihse_kv_ct_proof_t *transfer_proof =
        qihse_kv_ct_lane_authority_proof_create(store, op, op, &authority,
            verify_lane_claim, &no_final_decision);
    assert(transfer_proof);
    uint64_t source_cut = UINT64_MAX;
    assert(qihse_kv_ct_lane_transfer_source_fence(store, op, op, &authority,
        transfer_proof, verify_lane_claim, &no_final_decision, token_a,
        &source_cut));
    assert(source_cut == resume);
    qihse_kv_ct_proof_destroy(transfer_proof);
    assert(qihse_kv_ct_writer_scope_enter_lane(store, op, LANE_A,
        token_a, &scope));
    assert(!qihse_kv_set_user(store, key_a, "fenced", 0u, 0u, op));
    qihse_kv_ct_writer_scope_leave(scope);
    char transfer_path[256];
    int transfer_n = snprintf(transfer_path, sizeof(transfer_path),
        "%s/ct-lane-transfer.bin", data_dir);
    assert(transfer_n > 0 && (size_t)transfer_n < sizeof(transfer_path));
    struct stat transfer_st;
    assert(stat(transfer_path, &transfer_st) == 0 && S_ISREG(transfer_st.st_mode));

    qihse_kv_store_destroy(store);
    qihse_auth_release_principal_scoped(op);
    qihse_auth_release_principal_scoped(low);
    qihse_auth_release_principal_scoped(peer);
    free(key_a);
    free(key_a2);
    free(key_b);
    aimem_fixture_cleanup(data_dir);
    return 0;
}
