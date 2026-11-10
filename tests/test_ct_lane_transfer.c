#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "aimem_fixture_cleanup.h"
#include "qihse_auth.h"
#include "qihse_crc16.h"
#include "qihse_kv_store.h"

#define RETAINED_LIMIT (16u * 1024u * 1024u)

static const char LANE_A[QIHSE_KV_CT_LANE_ID_MAX + 1u] =
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
static const char LANE_C[QIHSE_KV_CT_LANE_ID_MAX + 1u] =
    "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
static const char GEN_A[33] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
static const char GEN_C[33] = "cccccccccccccccccccccccccccccccc";

static void bitmap_set(uint8_t bitmap[QIHSE_KV_CT_SLOT_BITMAP_BYTES], uint16_t slot) {
    bitmap[slot / 8u] |= (uint8_t)(1u << (slot % 8u));
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

static bool verify_reserved(void *context,
    const qihse_kv_ct_lane_authority_claim_t *claim, bool require_final) {
    (void)context;
    return claim && claim->reserve_index == 11u &&
        (!require_final || claim->final_decision_index == 12u);
}

static void create_admitted_source_lane(qihse_kv_store_t *store,
    qihse_user_t *operator_user, qihse_user_t *replication_user,
    const char *lane_id, const uint8_t bitmap[QIHSE_KV_CT_SLOT_BITMAP_BYTES],
    const char *source_id, const char *peer_id, const char *generation,
    unsigned char token[QIHSE_KV_CT_TOKEN_BYTES]) {
    assert(qihse_kv_ct_lane_source_enable(store, operator_user, lane_id, bitmap,
        source_id, peer_id, generation, token, RETAINED_LIMIT));
    qihse_kv_replica_snapshot_t *snapshot = NULL;
    uint64_t baseline_seq = 0u;
    unsigned char baseline_digest[32];
    assert(qihse_kv_ct_lane_source_baseline_snapshot_create(store, operator_user,
        lane_id, &snapshot, &baseline_seq, baseline_digest) == 0);
    qihse_kv_replica_snapshot_destroy(snapshot);
    assert(qihse_kv_ct_lane_source_reconcile_peer(store, operator_user,
        replication_user, lane_id, peer_id, generation, baseline_digest, 0u));
}

static void empty_image_digest(unsigned char out[32]) {
    unsigned int size = 0u;
    assert(EVP_Digest("", 0u, out, &size, EVP_sha256(), NULL) == 1 && size == 32u);
}

static void empty_range_digest(
    const uint8_t slots[QIHSE_KV_CT_SLOT_BITMAP_BYTES], unsigned char out[32]) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    assert(ctx && EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1);
    assert(EVP_DigestUpdate(ctx, "QCT-LANE-RANGE-V1", 17u) == 1);
    assert(EVP_DigestUpdate(ctx, slots, QIHSE_KV_CT_SLOT_BITMAP_BYTES) == 1);
    static const unsigned char zero_count[8] = {0};
    assert(EVP_DigestUpdate(ctx, zero_count, sizeof(zero_count)) == 1);
    unsigned int size = 0u;
    assert(EVP_DigestFinal_ex(ctx, out, &size) == 1 && size == 32u);
    EVP_MD_CTX_free(ctx);
}

static void assert_value(qihse_kv_store_t *store, qihse_user_t *user,
                         const char *key, const char *expected) {
    char *value = qihse_kv_get_user(store, key, user);
    if (!expected) assert(value == NULL);
    else assert(value && strcmp(value, expected) == 0);
    free(value);
}

int main(void) {
    char data_dir[] = "./ct_lane_transfer_XXXXXX";
    umask(0077);
    assert(mkdtemp(data_dir));
    assert(setenv("QIHSE_DATA_DIR", data_dir, 1) == 0);
    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator("CtTransferOperator1!"));
    qihse_user_t *operator_user = qihse_auth_authenticate_id(0u,
        "CtTransferOperator1!");
    assert(operator_user);
    qihse_user_t *replication_user = qihse_auth_create_user(operator_user,
        8801u, QIHSE_ROLE_ANALYST, 5u, 3u, "CtTransferPeerPass1!", false);
    qihse_user_t *low_user = qihse_auth_create_user(operator_user,
        8802u, QIHSE_ROLE_ANALYST, 0u, 0u, "CtTransferLowPass1!", false);
    assert(replication_user && low_user);

    const uint16_t moved_slot = 301u, target_slot = 14000u;
    uint8_t moved_bitmap[QIHSE_KV_CT_SLOT_BITMAP_BYTES] = {0};
    uint8_t target_bitmap[QIHSE_KV_CT_SLOT_BITMAP_BYTES] = {0};
    bitmap_set(moved_bitmap, moved_slot);
    bitmap_set(target_bitmap, target_slot);
    char *stale_key = key_for_slot("commons/transfer-stale-", moved_slot);
    char *preserved_key = key_for_slot("commons/transfer-preserved-", target_slot);

    /* Start with stale A-slot data and live C-owned data. The empty incoming
     * baseline must delete only A's selected bitmap and retain C's row. */
    qihse_kv_store_t *store = qihse_kv_store_create_user(operator_user);
    assert(store);
    assert(qihse_kv_set_user(store, stale_key, "stale", 0u, 0u, operator_user));
    assert(qihse_kv_set_user(store, preserved_key, "keep", 0u, 0u, operator_user));
    qihse_kv_store_set_replication_principal_id(store,
        qihse_user_get_id(replication_user));
    unsigned char target_token[QIHSE_KV_CT_TOKEN_BYTES];
    create_admitted_source_lane(store, operator_user, replication_user,
        LANE_C, target_bitmap, "target-c", "target-c-successor", GEN_C,
        target_token);
    unsigned char receiver_token[QIHSE_KV_CT_TOKEN_BYTES];
    assert(qihse_kv_ct_lane_receiver_bind(store, operator_user, LANE_A,
        moved_bitmap, "source-a", "target-c", GEN_A,
        QIHSE_KV_CT_TENANT_SYSTEM_ALL, 0u, 0u, receiver_token));

    qihse_kv_ct_lane_authority_claim_t claim = {0};
    claim.operation = QIHSE_KV_CT_LANE_AUTH_TRANSFER;
    snprintf(claim.transfer_id, sizeof(claim.transfer_id), "move-empty-1");
    snprintf(claim.source_group_id, sizeof(claim.source_group_id), "%s", LANE_A);
    snprintf(claim.target_group_id, sizeof(claim.target_group_id), "%s", LANE_C);
    snprintf(claim.source_qkp_id, sizeof(claim.source_qkp_id), "source-a");
    snprintf(claim.target_qkp_id, sizeof(claim.target_qkp_id), "target-c");
    snprintf(claim.source_generation, sizeof(claim.source_generation), "%s", GEN_A);
    snprintf(claim.target_generation, sizeof(claim.target_generation), "%s", GEN_C);
    snprintf(claim.successor_qkp_id, sizeof(claim.successor_qkp_id),
        "target-c-successor");
    memcpy(claim.slots, moved_bitmap, sizeof(moved_bitmap));
    claim.grant_epoch = 1u;
    claim.reserve_index = 11u;
    memset(claim.reserve_digest, 0x11, sizeof(claim.reserve_digest));
    qihse_kv_ct_proof_t *proof = qihse_kv_ct_lane_authority_proof_create(
        store, operator_user, operator_user, &claim, verify_reserved, NULL);
    assert(proof);
    assert(qihse_kv_ct_lane_transfer_target_import_begin(store, operator_user,
        operator_user, &claim, proof, verify_reserved, NULL, target_token));

    /* A low-clearance data principal cannot import an above-clearance QFS
     * record through the file-backed transfer entry point. */
    int n = 0;
    qihse_kv_ct_proof_t *low_proof = qihse_kv_ct_lane_authority_proof_create(
        store, operator_user, low_user, &claim, verify_reserved, NULL);
    assert(low_proof);
    char denied_path[512];
    n = snprintf(denied_path, sizeof(denied_path), "%s/ct-denied-image.qfs", data_dir);
    assert(n > 0 && (size_t)n < sizeof(denied_path));
    char denied_bytes[512];
    n = snprintf(denied_bytes, sizeof(denied_bytes), "%zu %u 0 5 0 0 1\n%ssecret\n",
        strlen(stale_key), 6u, stale_key);
    assert(n > 0 && (size_t)n < sizeof(denied_bytes));
    int denied_fd = open(denied_path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    assert(denied_fd >= 0);
    assert(write(denied_fd, denied_bytes, (size_t)n) == n);
    assert(fsync(denied_fd) == 0 && close(denied_fd) == 0);
    unsigned char denied_digest[32];
    unsigned int denied_digest_len = 0u;
    assert(EVP_Digest(denied_bytes, (size_t)n, denied_digest,
        &denied_digest_len, EVP_sha256(), NULL) == 1 && denied_digest_len == 32u);
    uint64_t before_denied_import = qihse_kv_change_seq(store);
    assert(!qihse_kv_ct_lane_transfer_target_import_apply_file(store,
        operator_user, replication_user, low_user, &claim, low_proof,
        verify_reserved, NULL, denied_path, denied_digest, target_token));
    assert(qihse_kv_change_seq(store) == before_denied_import);
    qihse_kv_ct_proof_destroy(low_proof);

    char image_path[512];
    n = snprintf(image_path, sizeof(image_path), "%s/ct-empty-image.qfs", data_dir);
    assert(n > 0 && (size_t)n < sizeof(image_path));
    int image_fd = open(image_path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    assert(image_fd >= 0 && fsync(image_fd) == 0 && close(image_fd) == 0);
    unsigned char image_digest[32], range_digest[32];
    empty_image_digest(image_digest);
    empty_range_digest(moved_bitmap, range_digest);
    bool empty_import_ok = qihse_kv_ct_lane_transfer_target_import_apply_file(store,
        operator_user, replication_user, operator_user, &claim, proof,
        verify_reserved, NULL, image_path, image_digest, target_token);
    if (!empty_import_ok) {
        qihse_kv_ct_lane_transfer_status_t debug_transfer = {0};
        qihse_kv_ct_lane_status_t debug_receiver = {0};
        bool debug_status = qihse_kv_ct_lane_transfer_status(store, operator_user,
            &debug_transfer);
        bool debug_lane = qihse_kv_ct_lane_status(store, operator_user, LANE_A,
            &debug_receiver);
        fprintf(stderr, "empty import failed errno=%d transfer=%d phase=%u imported=%d lane=%d mode=%d sealed=%d durable=%llu\n",
            errno, debug_status, debug_transfer.phase, debug_transfer.target_imported,
            debug_lane, debug_receiver.mode, debug_receiver.baseline_sealed,
            (unsigned long long)debug_receiver.durable_position);
    }
    assert(empty_import_ok);
    claim.source_cut = 0u;
    claim.target_cursor = 0u;
    memcpy(claim.image_digest, image_digest, sizeof(image_digest));
    memcpy(claim.range_digest, range_digest, sizeof(range_digest));
    unsigned char checksum[32];
    assert(qihse_kv_ct_lane_transfer_target_seal(store, operator_user,
        operator_user, &claim, proof, verify_reserved, NULL,
        target_token, checksum));

    qihse_kv_ct_lane_transfer_status_t transfer = {0};
    assert(qihse_kv_ct_lane_transfer_status(store, operator_user, &transfer));
    assert(transfer.active && transfer.phase == 2u && transfer.target_imported &&
        transfer.source_cut == 0u && transfer.target_cursor == 0u &&
        memcmp(transfer.image_digest, image_digest, 32u) == 0 &&
        memcmp(transfer.range_digest, range_digest, 32u) == 0);
    qihse_kv_ct_lane_status_t receiver = {0};
    assert(qihse_kv_ct_lane_status(store, operator_user, LANE_A, &receiver));
    assert(receiver.baseline_sealed && !receiver.admitted &&
        receiver.durable_position == 0u && receiver.baseline_row_seq == 0u &&
        memcmp(receiver.baseline_digest, image_digest, 32u) == 0);
    assert_value(store, operator_user, preserved_key, "keep");
    /* The staged receiver isn't routed yet. Its exact empty content is
     * verified by target_seal; the stale row cannot leak to normal readers. */
    assert_value(store, operator_user, stale_key, NULL);

    /* A final proof moves only the selected bitmap from temporary receiver A
     * into the existing source C. Repeating finalization models recovery after
     * a lost response and must leave the same memberships. */
    claim.final_decision_index = 12u;
    memset(claim.final_decision_digest, 0x12, sizeof(claim.final_decision_digest));
    qihse_kv_ct_proof_t *final_proof = qihse_kv_ct_lane_authority_proof_create(
        store, operator_user, operator_user, &claim, verify_reserved, NULL);
    assert(final_proof);
    assert(qihse_kv_ct_lane_transfer_membership_finalize(store, operator_user,
        operator_user, &claim, final_proof, verify_reserved, NULL,
        receiver_token, target_token));
    assert(qihse_kv_ct_lane_transfer_membership_finalize(store, operator_user,
        operator_user, &claim, final_proof, verify_reserved, NULL,
        receiver_token, target_token));
    qihse_kv_ct_lane_status_t finalized_a = {0}, finalized_c = {0};
    assert(qihse_kv_ct_lane_status(store, operator_user, LANE_A, &finalized_a));
    assert(qihse_kv_ct_lane_status(store, operator_user, LANE_C, &finalized_c));
    assert(finalized_a.mode == QIHSE_KV_CT_LANE_RECEIVER &&
        !finalized_a.admitted && !memcmp(finalized_a.slot_bitmap,
            (uint8_t[QIHSE_KV_CT_SLOT_BITMAP_BYTES]){0}, sizeof(moved_bitmap)));
    for (size_t i = 0; i < sizeof(moved_bitmap); ++i)
        assert(finalized_c.slot_bitmap[i] == (uint8_t)(target_bitmap[i] | moved_bitmap[i]));
    assert(finalized_c.mode == QIHSE_KV_CT_LANE_SOURCE && finalized_c.admitted &&
        finalized_c.baseline_sealed && finalized_c.baseline_refresh_needed);

    qihse_kv_replica_snapshot_t *refreshed = NULL;
    uint64_t refreshed_row_seq = 0u;
    unsigned char refreshed_digest[32];
    assert(qihse_kv_ct_lane_source_baseline_snapshot_create(store, operator_user,
        LANE_C, &refreshed, &refreshed_row_seq, refreshed_digest) == 0);
    assert(refreshed && refreshed_row_seq == qihse_kv_change_seq(store));
    qihse_kv_replica_snapshot_destroy(refreshed);
    assert(qihse_kv_ct_lane_status(store, operator_user, LANE_C, &finalized_c));
    assert(finalized_c.mode == QIHSE_KV_CT_LANE_SOURCE && finalized_c.admitted &&
        finalized_c.baseline_sealed && !finalized_c.baseline_refresh_needed);

    qihse_kv_ct_proof_destroy(final_proof);
    qihse_kv_ct_proof_destroy(proof);
    qihse_kv_store_destroy(store);
    qihse_auth_release_principal_scoped(low_user);
    qihse_auth_release_principal_scoped(replication_user);
    qihse_auth_release_principal_scoped(operator_user);
    free(stale_key);
    free(preserved_key);
    aimem_fixture_cleanup(data_dir);
    return 0;
}
