/* tests/test_ownership_lane_transfer.c — focused unit tests for CT2 group lane
 * ownership transfer commit. */

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>

#include "qihse_cluster_ownership.h"
#include "qihse_cluster_ownership_journal.h"
#include "qihse_auth.h"
#include "aimem_fixture_cleanup.h"

struct qihse_cluster_ct_peer_receipt {
    char phase[16];
    char transfer_id[65], topology_source_id[65], topology_target_id[65];
    char qkp_source_id[QIHSE_KV_CT_ID_MAX + 1u];
    char qkp_target_id[QIHSE_KV_CT_ID_MAX + 1u];
    char generation[33];
    uint16_t first_slot, last_slot;
    uint64_t source_lsn, target_lsn, config_epoch;
    unsigned char checksum[32];
};

static qihse_kv_ct_lane_transfer_status_t mock_lane_transfer_status;
static bool mock_grant_allowed = true;

bool qihse_kv_ct_lane_transfer_status(qihse_kv_store_t* store,
    qihse_user_t* control_principal,
    qihse_kv_ct_lane_transfer_status_t* out_status) {
    (void)store; (void)control_principal;
    if (out_status) *out_status = mock_lane_transfer_status;
    return true;
}

static bool mock_peer_id(void* context, const char* topology_node_id,
    char out_qkp_node_id[QIHSE_KV_CT_ID_MAX + 1u]) {
    (void)context;
    snprintf(out_qkp_node_id, QIHSE_KV_CT_ID_MAX + 1u, "qkp-%s", topology_node_id);
    return true;
}

static bool mock_lane_claim(void* context, qihse_user_t* principal,
    const qihse_cluster_ownership_txn_t* txn,
    qihse_kv_ct_lane_authority_claim_t* out_claim) {
    (void)context; (void)principal;
    memset(out_claim, 0, sizeof(*out_claim));
    out_claim->operation = QIHSE_KV_CT_LANE_AUTH_TRANSFER;
    snprintf(out_claim->transfer_id, sizeof(out_claim->transfer_id), "%s", txn->transfer_id);
    snprintf(out_claim->source_group_id, sizeof(out_claim->source_group_id), "%s", txn->lane_id);
    snprintf(out_claim->target_group_id, sizeof(out_claim->target_group_id), "target-lane-id");
    snprintf(out_claim->source_qkp_id, sizeof(out_claim->source_qkp_id), "%s", txn->source_qkp_id);
    snprintf(out_claim->target_qkp_id, sizeof(out_claim->target_qkp_id), "%s", txn->target_qkp_id);
    snprintf(out_claim->source_generation, sizeof(out_claim->source_generation), "%s", txn->generation);
    snprintf(out_claim->target_generation, sizeof(out_claim->target_generation), "next-gen-001");
    snprintf(out_claim->successor_qkp_id, sizeof(out_claim->successor_qkp_id), "qkp-node-d");
    out_claim->grant_epoch = txn->config_epoch;
    out_claim->source_cut = txn->source_lsn;
    out_claim->target_cursor = txn->target_lsn;
    memcpy(out_claim->slots, txn->slot_bitmap, sizeof(txn->slot_bitmap));
    out_claim->reserve_index = 100u;
    memset(out_claim->reserve_digest, 0xaa, 32u);
    return true;
}

static bool mock_lane_verify_claim(void* context, qihse_user_t* principal,
    const qihse_kv_ct_lane_authority_claim_t* claim,
    bool require_final_decision) {
    (void)context; (void)principal;
    if (require_final_decision) return false;
    return mock_grant_allowed && claim && claim->reserve_index != 0;
}

static bool mock_range_reserve(void* context, qihse_user_t* principal,
    qihse_cluster_ownership_txn_t* draft, char* err, size_t err_cap) {
    (void)context; (void)principal; (void)draft; (void)err; (void)err_cap;
    return true;
}

static bool mock_range_finalize(void* context, qihse_user_t* principal,
    const qihse_cluster_ownership_txn_t* txn,
    const qihse_cluster_ct_activation_receipt_t* receipt,
    char* err, size_t err_cap) {
    (void)context; (void)principal; (void)txn; (void)receipt; (void)err; (void)err_cap;
    return true;
}

static bool mock_range_abort(void* context, qihse_user_t* principal,
    const qihse_cluster_ownership_txn_t* txn, char* err, size_t err_cap) {
    (void)context; (void)principal; (void)txn; (void)err; (void)err_cap;
    return true;
}

static bool mock_range_check_reserved(void* context, qihse_user_t* principal,
    const qihse_cluster_ownership_txn_t* txn, char* err, size_t err_cap) {
    (void)context; (void)principal; (void)txn; (void)err; (void)err_cap;
    return true;
}

static void test_lane_transfer_commit_success(void) {
    char data_dir[] = "./qihse_test_lane_commit_XXXXXX";
    assert(mkdtemp(data_dir));

    assert(setenv("QIHSE_DATA_DIR", data_dir, 1) == 0);
    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator("OperatorPass123!"));
    qihse_user_t* op = qihse_auth_get_user(0);
    assert(op);
    qihse_kv_store_t* store = qihse_kv_store_create_user(op);
    assert(store);
    qihse_cluster_topology_t* topo = qihse_cluster_topology_create();
    assert(topo);

    const char* node_a_id = "000000000000000000000000000000000000000a";
    const char* node_c_id = "000000000000000000000000000000000000000c";

    qihse_cluster_node_t node_a;
    memset(&node_a, 0, sizeof(node_a));
    snprintf(node_a.id, sizeof(node_a.id), "%s", node_a_id);
    snprintf(node_a.host, sizeof(node_a.host), "127.0.0.1");
    node_a.port = 7500u;
    node_a.bus_port = 17500u;
    node_a.role = QIHSE_CLUSTER_NODE_PRIMARY;
    node_a.primary_index = QIHSE_CLUSTER_NODE_NONE;
    node_a.healthy = true;
    node_a.config_epoch = 1u;

    qihse_cluster_node_t node_c;
    memset(&node_c, 0, sizeof(node_c));
    snprintf(node_c.id, sizeof(node_c.id), "%s", node_c_id);
    snprintf(node_c.host, sizeof(node_c.host), "127.0.0.1");
    node_c.port = 7501u;
    node_c.bus_port = 17501u;
    node_c.role = QIHSE_CLUSTER_NODE_PRIMARY;
    node_c.primary_index = QIHSE_CLUSTER_NODE_NONE;
    node_c.healthy = true;
    node_c.config_epoch = 1u;
    uint16_t idx_a = 0, idx_c = 1;
    assert(qihse_cluster_topology_upsert_node(topo, &node_a, &idx_a));
    assert(qihse_cluster_topology_upsert_node(topo, &node_c, &idx_c));
    assert(qihse_cluster_topology_set_local_node(topo, idx_a));
    assert(qihse_cluster_topology_adopt_range(topo, 10u, 20u, idx_a, 1u));

    qihse_cluster_ownership_context_t ownership;
    memset(&ownership, 0, sizeof(ownership));
    ownership.topology = topo;
    ownership.store = store;
    ownership.principal = op;
    ownership.data_principal = op;
    ownership.peer_id = mock_peer_id;
    ownership.lane_claim = mock_lane_claim;
    ownership.lane_verify_claim = mock_lane_verify_claim;
    ownership.range_reserve = mock_range_reserve;
    ownership.range_check_reserved = mock_range_check_reserved;
    ownership.range_finalize = mock_range_finalize;
    ownership.range_check_finalized = mock_range_check_reserved;
    ownership.range_abort = mock_range_abort;

    const char* transfer_id = "transfer-lane-001";
    const char* lane_id = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const char* gen = "generation-000000000000000000001";
    uint64_t source_cut = 1000u;
    uint64_t target_cursor = 2000u;
    uint64_t config_epoch = 5u;

    /* Write durable PREPARED txn to journal */
    qihse_cluster_ownership_txn_t prep;
    memset(&prep, 0, sizeof(prep));
    prep.phase = QIHSE_OWNERSHIP_PREPARED;
    prep.start = 10u; prep.end = 20u;
    snprintf(prep.transfer_id, sizeof(prep.transfer_id), "%s", transfer_id);
    snprintf(prep.source_id, sizeof(prep.source_id), "%s", node_a_id);
    snprintf(prep.target_id, sizeof(prep.target_id), "%s", node_c_id);
    snprintf(prep.source_qkp_id, sizeof(prep.source_qkp_id), "qkp-%s", node_a_id);
    snprintf(prep.target_qkp_id, sizeof(prep.target_qkp_id), "qkp-%s", node_c_id);
    snprintf(prep.generation, sizeof(prep.generation), "%s", gen);
    snprintf(prep.owner_id, sizeof(prep.owner_id), "%s", node_a_id);
    snprintf(prep.lane_id, sizeof(prep.lane_id), "%s", lane_id);
    prep.config_epoch = config_epoch;
    prep.source_lsn = source_cut;
    for (uint32_t slot = prep.start; slot <= prep.end; ++slot)
        prep.slot_bitmap[slot / 8u] |= (uint8_t)(1u << (slot % 8u));

    const char* store_dir = qihse_kv_store_data_directory(store);
    assert(store_dir);
    qihse_cluster_ownership_txn_t malformed = prep;
    malformed.slot_bitmap[15u / 8u] &= (uint8_t)~(1u << (15u % 8u));
    assert(qihse_cluster_ownership_journal_append_txn(store_dir, &malformed) != 0);
    malformed = prep;
    malformed.lane_id[0] = 0;
    assert(qihse_cluster_ownership_journal_append_txn(store_dir, &malformed) != 0);
    assert(qihse_cluster_ownership_journal_append_txn(store_dir, &prep) == 0);

    /* Set up mock persisted lane transfer status: phase 1, target_imported=false */
    memset(&mock_lane_transfer_status, 0, sizeof(mock_lane_transfer_status));
    mock_lane_transfer_status.active = true;
    mock_lane_transfer_status.phase = 1u;
    mock_lane_transfer_status.source_fenced = true;
    mock_lane_transfer_status.target_imported = false;
    mock_lane_transfer_status.source_cut = source_cut;
    mock_lane_transfer_status.target_cursor = target_cursor;
    memset(mock_lane_transfer_status.range_digest, 0x11, 32u);
    memset(mock_lane_transfer_status.image_digest, 0x22, 32u);
    snprintf(mock_lane_transfer_status.claim.transfer_id, sizeof(mock_lane_transfer_status.claim.transfer_id), "%s", transfer_id);
    snprintf(mock_lane_transfer_status.claim.source_group_id, sizeof(mock_lane_transfer_status.claim.source_group_id), "%s", lane_id);
    snprintf(mock_lane_transfer_status.claim.source_qkp_id, sizeof(mock_lane_transfer_status.claim.source_qkp_id), "qkp-%s", node_a_id);
    snprintf(mock_lane_transfer_status.claim.target_qkp_id, sizeof(mock_lane_transfer_status.claim.target_qkp_id), "qkp-%s", node_c_id);
    snprintf(mock_lane_transfer_status.claim.source_generation, sizeof(mock_lane_transfer_status.claim.source_generation), "%s", gen);
    mock_lane_transfer_status.claim.grant_epoch = config_epoch;
    memset(mock_lane_transfer_status.claim.slots, 0, sizeof(mock_lane_transfer_status.claim.slots));
    for (uint32_t s = 10u; s <= 20u; ++s) mock_lane_transfer_status.claim.slots[s / 8u] |= (uint8_t)(1u << (s % 8u));
    memcpy(mock_lane_transfer_status.claim.range_digest, mock_lane_transfer_status.range_digest, 32u);
    memcpy(mock_lane_transfer_status.claim.image_digest, mock_lane_transfer_status.image_digest, 32u);

    mock_lane_transfer_status.claim.operation = QIHSE_KV_CT_LANE_AUTH_TRANSFER;
    snprintf(mock_lane_transfer_status.claim.target_group_id, sizeof(mock_lane_transfer_status.claim.target_group_id), "target-lane-id");
    snprintf(mock_lane_transfer_status.claim.target_generation, sizeof(mock_lane_transfer_status.claim.target_generation), "next-gen-001");
    snprintf(mock_lane_transfer_status.claim.successor_qkp_id, sizeof(mock_lane_transfer_status.claim.successor_qkp_id), "qkp-node-d");
    mock_lane_transfer_status.claim.reserve_index = 100u;
    memset(mock_lane_transfer_status.claim.reserve_digest, 0xaa, 32u);
    mock_lane_transfer_status.claim.source_cut = source_cut;
    mock_lane_transfer_status.claim.target_cursor = target_cursor;

    /* Compute expected composite checksum */
    uint8_t composite_checksum[32] = {0};
    assert(qihse_kv_ct_lane_transfer_checksum(&mock_lane_transfer_status.claim, composite_checksum));

    /* Create mock peer receipt from target C */
    struct qihse_cluster_ct_peer_receipt receipt;
    memset(&receipt, 0, sizeof(receipt));
    snprintf(receipt.phase, sizeof(receipt.phase), "SEALED");
    snprintf(receipt.transfer_id, sizeof(receipt.transfer_id), "%s", transfer_id);
    snprintf(receipt.topology_source_id, sizeof(receipt.topology_source_id), "%s", node_a_id);
    snprintf(receipt.topology_target_id, sizeof(receipt.topology_target_id), "%s", node_c_id);
    snprintf(receipt.qkp_source_id, sizeof(receipt.qkp_source_id), "qkp-%s", node_a_id);
    snprintf(receipt.qkp_target_id, sizeof(receipt.qkp_target_id), "qkp-%s", node_c_id);
    snprintf(receipt.generation, sizeof(receipt.generation), "%s", gen);
    receipt.first_slot = 10u; receipt.last_slot = 20u;
    receipt.source_lsn = source_cut;
    receipt.target_lsn = target_cursor;
    receipt.config_epoch = config_epoch;
    memcpy(receipt.checksum, composite_checksum, 32u);

    char err[256] = {0};
    qihse_user_t* low = qihse_auth_create_user(op, 8509u, QIHSE_ROLE_ANALYST,
        0u, 0u, "CtLaneLowPass1!", false);
    assert(low);
    ownership.principal = low;
    assert(!qihse_cluster_ownership_transfer_commit(&ownership, transfer_id,
        idx_a, idx_c, &receipt, err, sizeof(err)));
    ownership.principal = NULL;
    assert(!qihse_cluster_ownership_transfer_commit(&ownership, transfer_id,
        idx_a, idx_c, &receipt, err, sizeof(err)));
    ownership.principal = op;
    mock_grant_allowed = false;
    assert(!qihse_cluster_ownership_transfer_commit(&ownership, transfer_id,
        idx_a, idx_c, &receipt, err, sizeof(err)));
    mock_grant_allowed = true;
    mock_lane_transfer_status.target_cursor = 0;
    assert(!qihse_cluster_ownership_transfer_commit(&ownership, transfer_id,
        idx_a, idx_c, &receipt, err, sizeof(err)));
    mock_lane_transfer_status.target_cursor = target_cursor;
    bool ok = qihse_cluster_ownership_transfer_commit(&ownership, transfer_id,
        idx_a, idx_c, &receipt, err, sizeof(err));
    if (!ok) {
        fprintf(stderr, "transfer_commit failed: %s\n", err);
    }
    assert(ok);

    /* Check that transfer_get_committed finds the COMMITTED txn */
    qihse_cluster_ownership_txn_t comm;
    memset(&comm, 0, sizeof(comm));
    assert(qihse_cluster_ownership_transfer_get_committed(&ownership, transfer_id, &comm, err, sizeof(err)));
    assert(comm.phase == QIHSE_OWNERSHIP_COMMITTED);
    assert(comm.target_lsn == target_cursor);
    assert(CRYPTO_memcmp(comm.proof_digest, composite_checksum, 32u) == 0);
    assert(strcmp(comm.owner_id, node_c_id) == 0);

    /* Verify rejection if checksum mismatches */
    receipt.checksum[0] ^= 0xff;
    ok = qihse_cluster_ownership_transfer_commit(&ownership, transfer_id,
        idx_a, idx_c, &receipt, err, sizeof(err));
    assert(!ok);

    char journal_path[PATH_MAX];
    snprintf(journal_path, sizeof(journal_path), "%s/slot-ownership.journal", store_dir);
    qihse_cluster_topology_destroy(topo);
    qihse_kv_store_destroy(store);
    unlink(journal_path);
    aimem_fixture_cleanup(data_dir);
    puts("[PASS] test_lane_transfer_commit_success");
}

int main(void) {
    test_lane_transfer_commit_success();
    puts("All ownership lane transfer tests passed.");
    return 0;
}
