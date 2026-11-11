#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "qihse_cluster_ownership.h"
#include "qihse_crc16.h"
#include "aimem_fixture_cleanup.h"
#include <assert.h>
#include <errno.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static const char LANE_A[] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
static const char LANE_C[] = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
static const char LANE_OTHER[] = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
static const char GEN_A[] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
static const char GEN_C[] = "cccccccccccccccccccccccccccccccc";
static const char GEN_OTHER[] = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

typedef struct {
    qihse_kv_ct_lane_authority_claim_t claim;
    unsigned phase; /* 0 RESERVED, 1 FINAL, 2 ABORT */
} decision_t;
typedef struct {
    decision_t decisions[4];
    char nodes[3][QIHSE_CLUSTER_NODE_ID_LEN + 1u];
    bool fail_abort, hide_abort;
} authority_t;

static bool operator_active(qihse_user_t* user) {
    return user && qihse_auth_user_is_active(user) &&
        qihse_user_get_role(user) == QIHSE_ROLE_OPERATOR &&
        qihse_user_get_tenant_id(user) == QIHSE_TENANT_SYSTEM;
}
static decision_t* decision(authority_t* a, const char* id) {
    for (size_t i = 0; i < 4; ++i)
        if (!strcmp(a->decisions[i].claim.transfer_id, id)) return &a->decisions[i];
    return NULL;
}
static bool peer_id(void* opaque, const char* node, char out[65]) {
    authority_t* a = opaque;
    const char* pins[] = {"qkp-a", "qkp-c", "qkp-d"};
    for (size_t i = 0; i < 3; ++i) if (!strcmp(a->nodes[i], node)) {
        snprintf(out, 65, "%s", pins[i]); return true;
    }
    return false;
}
static bool claim_get(void* opaque, qihse_user_t* op,
    const qihse_cluster_ownership_txn_t* txn, qihse_kv_ct_lane_authority_claim_t* out) {
    authority_t* a = opaque;
    decision_t* d = decision(a, txn->transfer_id);
    if (!operator_active(op) || !d ||
        (d->phase == 2 && txn->phase != QIHSE_OWNERSHIP_ABORTED)) return false;
    *out = d->claim;
    if (d->phase) {
        out->final_decision_index = out->reserve_index + 100u;
        memset(out->final_decision_digest, d->phase == 2 ? 0xAB : 0xFA, 32);
    }
    return true;
}
static bool verify_claim(void* opaque, qihse_user_t* op,
    const qihse_kv_ct_lane_authority_claim_t* claim, bool require_final) {
    authority_t* a = opaque;
    decision_t* d = decision(a, claim->transfer_id);
    return operator_active(op) && d && d->phase != 2 &&
        claim->reserve_index == d->claim.reserve_index &&
        !strcmp(claim->source_group_id, d->claim.source_group_id) &&
        !strcmp(claim->source_generation, d->claim.source_generation) &&
        claim->source_cut == d->claim.source_cut &&
        !memcmp(claim->slots, d->claim.slots, sizeof(claim->slots)) &&
        (!require_final || (d->phase == 1 &&
            claim->final_decision_index == claim->reserve_index + 100u));
}
static bool verify_aborted(void* opaque, qihse_user_t* op,
    const qihse_kv_ct_lane_authority_claim_t* claim) {
    authority_t* a = opaque;
    decision_t* d = decision(a, claim->transfer_id);
    return operator_active(op) && d && d->phase == 2 && !a->hide_abort &&
        claim->reserve_index == d->claim.reserve_index &&
        claim->source_cut == d->claim.source_cut && claim->target_cursor == 0u &&
        claim->final_decision_index == claim->reserve_index + 100u &&
        claim->final_decision_digest[0] == 0xAB &&
        !strcmp(claim->source_group_id, d->claim.source_group_id) &&
        !strcmp(claim->source_generation, d->claim.source_generation) &&
        !memcmp(claim->slots, d->claim.slots, sizeof(claim->slots));
}
static bool verify_adapter(void* opaque,
    const qihse_kv_ct_lane_authority_claim_t* claim, bool require_final) {
    void** p = opaque;
    return verify_claim(p[0], p[1], claim, require_final);
}
static bool range_check(void* opaque, qihse_user_t* op,
    const qihse_cluster_ownership_txn_t* txn, char* error, size_t cap) {
    (void)opaque; (void)txn; (void)error; (void)cap;
    return operator_active(op);
}
static bool range_reserve(void* opaque, qihse_user_t* op,
    qihse_cluster_ownership_txn_t* txn, char* error, size_t cap) {
    return range_check(opaque, op, txn, error, cap);
}
static bool range_final(void* opaque, qihse_user_t* op,
    const qihse_cluster_ownership_txn_t* txn,
    const qihse_cluster_ct_activation_receipt_t* receipt, char* error, size_t cap) {
    (void)receipt;
    return range_check(opaque, op, txn, error, cap);
}
static bool range_abort(void* opaque, qihse_user_t* op,
    const qihse_cluster_ownership_txn_t* txn, char* error, size_t cap) {
    authority_t* a = opaque;
    decision_t* d = decision(a, txn->transfer_id);
    (void)error; (void)cap;
    if (!operator_active(op) || !d || a->fail_abort || d->phase == 1 ||
        txn->phase != QIHSE_OWNERSHIP_ABORTED ||
        txn->source_lsn != d->claim.source_cut) return false;
    d->phase = 2;
    return true;
}
static void bit(uint8_t* slots, uint16_t slot) {
    slots[slot / 8u] |= (uint8_t)(1u << (slot % 8u));
}
static char* key_at_slot(uint16_t slot) {
    char key[64];
    for (unsigned i = 0; i < 1000000u; ++i) {
        snprintf(key, sizeof(key), "abort-key-%u", i);
        if (qihse_cluster_key_slot(key, strlen(key)) == slot) return strdup(key);
    }
    abort();
}
static void init_decision(authority_t* a, size_t index, const char* id,
    uint16_t slot, uint64_t cut) {
    decision_t* d = &a->decisions[index];
    memset(d, 0, sizeof(*d));
    qihse_kv_ct_lane_authority_claim_t* c = &d->claim;
    c->operation = QIHSE_KV_CT_LANE_AUTH_TRANSFER;
    snprintf(c->transfer_id, sizeof(c->transfer_id), "%s", id);
    snprintf(c->source_group_id, sizeof(c->source_group_id), "%s", LANE_A);
    snprintf(c->target_group_id, sizeof(c->target_group_id), "%s", LANE_C);
    snprintf(c->source_qkp_id, sizeof(c->source_qkp_id), "qkp-a");
    snprintf(c->target_qkp_id, sizeof(c->target_qkp_id), "qkp-c");
    snprintf(c->successor_qkp_id, sizeof(c->successor_qkp_id), "qkp-d");
    snprintf(c->source_generation, sizeof(c->source_generation), "%s", GEN_A);
    snprintf(c->target_generation, sizeof(c->target_generation), "%s", GEN_C);
    c->grant_epoch = index + 10u; c->reserve_index = index + 20u;
    memset(c->reserve_digest, (int)index + 1, 32); c->source_cut = cut;
    bit(c->slots, slot);
}
static qihse_cluster_ownership_txn_t txn_for(authority_t* a, size_t index,
    qihse_cluster_ownership_phase_t phase, uint16_t slot) {
    const qihse_kv_ct_lane_authority_claim_t* c = &a->decisions[index].claim;
    qihse_cluster_ownership_txn_t t = {0};
    t.phase = phase; t.start = t.end = slot; t.config_epoch = c->grant_epoch;
    t.source_lsn = c->source_cut;
    snprintf(t.transfer_id, sizeof(t.transfer_id), "%s", c->transfer_id);
    snprintf(t.source_id, sizeof(t.source_id), "%s", a->nodes[0]);
    snprintf(t.target_id, sizeof(t.target_id), "%s", a->nodes[1]);
    snprintf(t.source_qkp_id, sizeof(t.source_qkp_id), "%s", c->source_qkp_id);
    snprintf(t.target_qkp_id, sizeof(t.target_qkp_id), "%s", c->target_qkp_id);
    snprintf(t.generation, sizeof(t.generation), "%s", c->source_generation);
    snprintf(t.lane_id, sizeof(t.lane_id), "%s", c->source_group_id);
    snprintf(t.owner_id, sizeof(t.owner_id), "%s", t.source_id);
    memcpy(t.slot_bitmap, c->slots, sizeof(t.slot_bitmap));
    return t;
}
static void source_lane(qihse_kv_store_t* store, qihse_user_t* op,
    qihse_user_t* peer, const char* lane, const char* generation,
    const char* source, const char* successor, uint16_t slot, unsigned char token[32]) {
    uint8_t bitmap[QIHSE_KV_CT_SLOT_BITMAP_BYTES] = {0}; bit(bitmap, slot);
    if (!qihse_kv_ct_lane_source_enable(store, op, lane, bitmap, source,
            successor, generation, token, 1u << 20)) {
        fprintf(stderr, "source enable failed: lane=%s errno=%d\n", lane, errno);
        abort();
    }
    qihse_kv_replica_snapshot_t* snapshot = NULL;
    uint64_t seq = 0; unsigned char digest[32];
    assert(qihse_kv_ct_lane_source_baseline_snapshot_create(store, op, lane,
        &snapshot, &seq, digest) == 0);
    qihse_kv_replica_snapshot_destroy(snapshot);
    assert(qihse_kv_ct_lane_source_reconcile_peer(store, op, peer, lane,
        successor, generation, digest, 0u));
}
static void fence(qihse_kv_store_t* store, qihse_user_t* op,
    authority_t* authority, size_t index, const unsigned char token[32]) {
    qihse_kv_ct_lane_authority_claim_t* claim = &authority->decisions[index].claim;
    void* verification[] = {authority, op};
    qihse_kv_ct_proof_t* proof = qihse_kv_ct_lane_authority_proof_create(
        store, op, op, claim, verify_adapter, verification);
    uint64_t cut = UINT64_MAX;
    assert(proof && qihse_kv_ct_lane_transfer_source_fence(store, op, op,
        claim, proof, verify_adapter, verification, token, &cut));
    assert(cut == claim->source_cut);
    qihse_kv_ct_proof_destroy(proof);
}
static void assert_active(qihse_kv_store_t* store, qihse_user_t* op,
    const char* id) {
    qihse_kv_ct_lane_transfer_status_t state = {0};
    assert(qihse_kv_ct_lane_transfer_status(store, op, &state));
    assert(state.active == (id != NULL));
    if (id) assert(!strcmp(state.claim.transfer_id, id));
}

static int target_case(const char* directory, bool successor) {
    assert(setenv("QIHSE_DATA_DIR", directory, 1) == 0);
    assert(setenv("QIHSE_FIPS_MODE", "disabled", 1) == 0);
    assert(qihse_auth_init() && qihse_auth_bootstrap_operator("LaneAbortOperator1!"));
    qihse_user_t* op = qihse_auth_authenticate_id(0, "LaneAbortOperator1!");
    qihse_user_t* peer = qihse_auth_create_user(op, 8911, QIHSE_ROLE_ANALYST,
        5, 1, "LaneAbortPeer1!", false);
    qihse_user_t* low = qihse_auth_create_user(op, 8912, QIHSE_ROLE_ANALYST,
        0, 0, "LaneAbortLow1!", false);
    assert(op && peer && low);
    authority_t authority = {0};
    qihse_cluster_topology_t* topology = qihse_cluster_topology_create();
    assert(topology);
    uint16_t indices[3];
    for (size_t i = 0; i < 3; ++i) {
        qihse_cluster_node_t node = {0};
        char name[32]; snprintf(name, sizeof(name), "lane-abort-node-%zu", i);
        qihse_cluster_node_id_from_seed(name, strlen(name), node.id);
        snprintf(authority.nodes[i], sizeof(authority.nodes[i]), "%s", node.id);
        snprintf(node.host, sizeof(node.host), "127.0.0.1");
        node.port = (uint16_t)(7900 + i); node.bus_port = (uint16_t)(17900 + i);
        node.role = QIHSE_CLUSTER_NODE_PRIMARY; node.healthy = true;
        node.primary_index = QIHSE_CLUSTER_NODE_NONE;
        assert(qihse_cluster_topology_upsert_node(topology, &node, &indices[i]));
    }
    assert(qihse_cluster_topology_set_local_node(topology, indices[0]));
    assert(qihse_cluster_topology_adopt_range(topology, 100, 100, indices[0], 1));
    qihse_kv_store_t* store = NULL;
    qihse_cluster_ownership_context_t c = {.topology = topology, .store = store,
        .principal = op, .data_principal = op, .peer_id = peer_id,
        .peer_id_context = &authority, .range_reserve = range_reserve,
        .range_check_reserved = range_check, .range_finalize = range_final,
        .range_check_finalized = range_check, .range_abort = range_abort,
        .lane_claim = claim_get, .lane_verify_claim = verify_claim,
        .lane_verify_aborted = verify_aborted, .range_authority_context = &authority};
    char error[256]; bool unresolved = false;
    qihse_kv_ct_lane_status_t status;
    /* A cancelled stage on C has no source-local singleton fence. */
    store = qihse_kv_store_create_user(op); assert(store); c.store = store;
    qihse_kv_store_set_replication_principal_id(store, qihse_user_get_id(peer));
    assert(qihse_cluster_topology_set_local_node(topology, indices[successor ? 2 : 1]));
    unsigned char token_c[32], receiver_token[32];
    if (!successor) {
        source_lane(store, op, peer, LANE_C, GEN_C, "qkp-c", "qkp-d", 9000, token_c);
    } else {
        uint8_t bitmap[QIHSE_KV_CT_SLOT_BITMAP_BYTES] = {0}; bit(bitmap, 9000);
        assert(qihse_kv_ct_lane_receiver_bind(store, op, LANE_C, bitmap,
            "qkp-c", "qkp-d", GEN_C, QIHSE_KV_CT_TENANT_SYSTEM_ALL, 0, 0, token_c));
        unsigned char digest[32];
        assert(qihse_kv_ct_lane_receiver_empty_baseline_seal(store, op,
            LANE_C, token_c, digest));
    }
    qihse_kv_ct_lane_status_t target_before = {0};
    assert(qihse_kv_ct_lane_status(store, op, LANE_C, &target_before));
    init_decision(&authority, 3, successor ? "successor-cancel-stage" : "target-cancel-stage", 100, 0);
    qihse_kv_ct_lane_authority_claim_t* incoming = &authority.decisions[3].claim;
    assert(qihse_kv_ct_lane_receiver_bind(store, op, LANE_A, incoming->slots,
        "qkp-a", successor ? "qkp-d" : "qkp-c", GEN_A,
        QIHSE_KV_CT_TENANT_SYSTEM_ALL, 0, 0, receiver_token));
    void* verification[] = {&authority, op};
    qihse_kv_ct_proof_t* proof = qihse_kv_ct_lane_authority_proof_create(
        store, op, op, incoming, verify_adapter, verification);
    assert(proof && qihse_kv_ct_lane_transfer_target_import_begin(store, op, op,
        incoming, proof, verify_adapter, verification, token_c));
    qihse_kv_ct_proof_destroy(proof);
    qihse_cluster_ownership_txn_t target_prepared = txn_for(&authority, 3, QIHSE_OWNERSHIP_PREPARED, 100);
    if (!successor)
        assert(qihse_cluster_ownership_journal_append_txn(directory, &target_prepared) == 0);
    authority.decisions[3].phase = 1; /* Wrong terminal decision must not un-fence. */
    assert(!qihse_cluster_ownership_reconcile_lane_transfer(&c, error, sizeof(error)));
    assert_active(store, op, incoming->transfer_id);
    authority.decisions[3].phase = 0;
    proof = qihse_kv_ct_lane_authority_proof_create(store, op, op, incoming,
        verify_adapter, verification);
    assert(proof);
    char empty_path[512];
    assert(snprintf(empty_path, sizeof(empty_path), "%s/empty-incoming.qfs", directory) > 0);
    FILE* empty = fopen(empty_path, "wb");
    assert(empty && fclose(empty) == 0);
    unsigned char image_digest[32]; unsigned digest_bytes = 0u;
    assert(EVP_Digest("", 0u, image_digest, &digest_bytes, EVP_sha256(), NULL) == 1 &&
        digest_bytes == sizeof(image_digest));
    assert(qihse_kv_ct_lane_transfer_target_import_apply_file(store, op, peer, op,
        incoming, proof, verify_adapter, verification, empty_path, image_digest, token_c));
    qihse_kv_ct_proof_destroy(proof);
    authority.decisions[3].phase = 2;
    assert(qihse_cluster_ownership_reconcile_lane_transfer(&c, error, sizeof(error)));
    assert_active(store, op, NULL);
    if (!successor)
        assert(qihse_cluster_ownership_replay_control(&c, &unresolved, error, sizeof(error)) && !unresolved);
    assert(qihse_kv_ct_lane_status(store, op, LANE_C, &status));
    assert(status.mode == (successor ? QIHSE_KV_CT_LANE_RECEIVER : QIHSE_KV_CT_LANE_SOURCE));
    assert(status.admitted == target_before.admitted &&
        status.baseline_sealed == target_before.baseline_sealed &&
        status.durable_position == target_before.durable_position &&
        !memcmp(status.slot_bitmap, target_before.slot_bitmap, sizeof(status.slot_bitmap)));
    qihse_kv_store_destroy(store);
    qihse_cluster_topology_destroy(topology);
    qihse_auth_release_principal_scoped(low);
    qihse_auth_release_principal_scoped(peer);
    qihse_auth_release_principal_scoped(op);
    return 0;
}

int main(int argc, char** argv) {
    if (argc == 3 && !strcmp(argv[1], "--target")) return target_case(argv[2], false);
    if (argc == 3 && !strcmp(argv[1], "--successor")) return target_case(argv[2], true);
    assert(argc == 1);
    char source_dir[] = "./lane_abort_source_XXXXXX";
    char target_dir[] = "./lane_abort_target_XXXXXX";
    char successor_dir[] = "./lane_abort_successor_XXXXXX";
    umask(0077);
    assert(mkdtemp(source_dir) && mkdtemp(target_dir) && mkdtemp(successor_dir));
    assert(setenv("QIHSE_DATA_DIR", source_dir, 1) == 0);
    assert(setenv("QIHSE_FIPS_MODE", "disabled", 1) == 0);
    assert(qihse_auth_init() && qihse_auth_bootstrap_operator("LaneAbortOperator1!"));
    qihse_user_t* op = qihse_auth_authenticate_id(0, "LaneAbortOperator1!");
    qihse_user_t* peer = qihse_auth_create_user(op, 8911, QIHSE_ROLE_ANALYST,
        5, 1, "LaneAbortPeer1!", false);
    qihse_user_t* low = qihse_auth_create_user(op, 8912, QIHSE_ROLE_ANALYST,
        0, 0, "LaneAbortLow1!", false);
    assert(op && peer && low);
    authority_t authority = {0};
    qihse_cluster_topology_t* topology = qihse_cluster_topology_create();
    assert(topology);
    uint16_t indices[3];
    for (size_t i = 0; i < 3; ++i) {
        qihse_cluster_node_t node = {0};
        char name[32]; snprintf(name, sizeof(name), "lane-abort-node-%zu", i);
        qihse_cluster_node_id_from_seed(name, strlen(name), node.id);
        snprintf(authority.nodes[i], sizeof(authority.nodes[i]), "%s", node.id);
        snprintf(node.host, sizeof(node.host), "127.0.0.1");
        node.port = (uint16_t)(7900 + i); node.bus_port = (uint16_t)(17900 + i);
        node.role = QIHSE_CLUSTER_NODE_PRIMARY; node.healthy = true;
        node.primary_index = QIHSE_CLUSTER_NODE_NONE;
        assert(qihse_cluster_topology_upsert_node(topology, &node, &indices[i]));
    }
    assert(qihse_cluster_topology_set_local_node(topology, indices[0]));
    assert(qihse_cluster_topology_adopt_range(topology, 100, 100, indices[0], 1));
    qihse_kv_store_t* store = qihse_kv_store_create_user(op);
    assert(store);
    qihse_kv_store_set_replication_principal_id(store, qihse_user_get_id(peer));
    unsigned char token_a[32], token_other[32];
    source_lane(store, op, peer, LANE_A, GEN_A, "qkp-a", "qkp-c", 100, token_a);
    source_lane(store, op, peer, LANE_OTHER, GEN_OTHER, "qkp-a", "qkp-d", 9000, token_other);
    char* protected_key = key_at_slot(100);
    char* unrelated_key = key_at_slot(9000);
    assert(protected_key && unrelated_key);
    qihse_kv_ct_writer_scope_t* scope = NULL;
    assert(qihse_kv_ct_writer_scope_enter_lane(store, op, LANE_A, token_a, &scope));
    assert(qihse_kv_set_user(store, protected_key, "classified", 4, 1, op));
    qihse_kv_ct_writer_scope_leave(scope);
    assert(qihse_kv_ct_lane_source_ack(store, peer, LANE_A, "qkp-c", GEN_A, 1));
    assert(!qihse_kv_get_user(store, protected_key, low));
    qihse_cluster_ownership_context_t c = {.topology = topology, .store = store,
        .principal = op, .data_principal = op, .peer_id = peer_id,
        .peer_id_context = &authority, .range_reserve = range_reserve,
        .range_check_reserved = range_check, .range_finalize = range_final,
        .range_check_finalized = range_check, .range_abort = range_abort,
        .lane_claim = claim_get, .lane_verify_claim = verify_claim,
        .lane_verify_aborted = verify_aborted, .range_authority_context = &authority};
    init_decision(&authority, 0, "lane-abort-1", 100, 1);
    fence(store, op, &authority, 0, token_a);
    qihse_cluster_ownership_txn_t t = txn_for(&authority, 0, QIHSE_OWNERSHIP_PREPARED, 100);
    assert(qihse_cluster_ownership_journal_append_txn(source_dir, &t) == 0);
    assert(qihse_kv_ct_writer_scope_enter_lane(store, op, LANE_OTHER, token_other, &scope));
    assert(qihse_kv_set_user(store, unrelated_key, "unrelated remains usable", 0, 0, op));
    qihse_kv_ct_writer_scope_leave(scope);
    char error[256];
    c.principal = low;
    assert(!qihse_cluster_ownership_transfer_abort(&c, t.transfer_id, indices[0], indices[1], error, sizeof(error)));
    c.principal = op; authority.fail_abort = true;
    assert(!qihse_cluster_ownership_transfer_abort(&c, t.transfer_id, indices[0], indices[1], error, sizeof(error)));
    assert_active(store, op, t.transfer_id);
    authority.fail_abort = false; authority.hide_abort = true;
    assert(!qihse_cluster_ownership_transfer_abort(&c, t.transfer_id, indices[0], indices[1], error, sizeof(error)));
    assert(authority.decisions[0].phase == 2);
    assert_active(store, op, t.transfer_id);
    qihse_kv_store_destroy(store);
    store = qihse_kv_store_create_user(op); assert(store); c.store = store;
    authority.hide_abort = false;
    bool unresolved = true;
    assert(qihse_cluster_ownership_replay_control(&c, &unresolved, error, sizeof(error)) && !unresolved);
    assert_active(store, op, NULL);
    assert(qihse_cluster_ownership_transfer_abort(&c, t.transfer_id, indices[0], indices[1], error, sizeof(error)));

    /* A historical abort receipt cannot release the next operation's fence. */
    qihse_kv_store_set_replication_principal_id(store, qihse_user_get_id(peer));
    qihse_kv_ct_lane_status_t status;
    assert(qihse_kv_ct_lane_status(store, op, LANE_A, &status));
    assert(qihse_kv_ct_lane_source_reconcile_peer(store, op, peer, LANE_A,
        "qkp-c", GEN_A, status.baseline_digest, status.durable_position));
    assert(qihse_kv_ct_lane_owner_token_get(store, op, LANE_A, token_a));
    init_decision(&authority, 1, "lane-abort-2", 100, 1);
    fence(store, op, &authority, 1, token_a);
    qihse_cluster_ownership_txn_t t2 = txn_for(&authority, 1, QIHSE_OWNERSHIP_PREPARED, 100);
    assert(qihse_cluster_ownership_journal_append_txn(source_dir, &t2) == 0);
    t.phase = QIHSE_OWNERSHIP_ABORTED;
    unsigned char checksum[32];
    assert(qihse_cluster_ownership_source_phase_receipt(&c, "ABORTED", &t, checksum, error, sizeof(error)));
    assert_active(store, op, t2.transfer_id);
    assert(qihse_cluster_ownership_replay_control(&c, &unresolved, error, sizeof(error)) && unresolved);
    assert_active(store, op, t2.transfer_id);
    assert(qihse_cluster_ownership_transfer_abort(&c, t2.transfer_id, indices[0], indices[1], error, sizeof(error)));
    assert_active(store, op, NULL);

    /* The pre-fence INTENT crash window closes through the same common ABORT. */
    init_decision(&authority, 2, "lane-unfenced-intent", 100, 0);
    qihse_cluster_ownership_txn_t intent = txn_for(&authority, 2, QIHSE_OWNERSHIP_INTENT, 100);
    assert(qihse_cluster_ownership_journal_append_txn(source_dir, &intent) == 0);
    assert(qihse_cluster_ownership_replay_control(&c, &unresolved, error, sizeof(error)) && !unresolved);
    assert(authority.decisions[2].phase == 2);
    intent.phase = QIHSE_OWNERSHIP_ABORTED;
    intent.lane_id[0] = '\0'; /* Actual source-phase wire has no lane field. */
    memset(intent.slot_bitmap, 0, sizeof(intent.slot_bitmap));
    assert(qihse_cluster_ownership_source_phase_receipt(&c, "ABORTED", &intent,
        checksum, error, sizeof(error)));
    qihse_kv_store_destroy(store);

    char self[4096]; assert(realpath(argv[0], self));
    pid_t child = fork(); assert(child >= 0);
    if (child == 0) {
        execl(self, self, "--target", target_dir, (char*)NULL);
        _exit(127);
    }
    int child_status = 0;
    assert(waitpid(child, &child_status, 0) == child);
    assert(WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0);
    child = fork(); assert(child >= 0);
    if (child == 0) {
        execl(self, self, "--successor", successor_dir, (char*)NULL);
        _exit(127);
    }
    assert(waitpid(child, &child_status, 0) == child);
    assert(WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0);
    qihse_cluster_topology_destroy(topology);
    qihse_auth_release_principal_scoped(low);
    qihse_auth_release_principal_scoped(peer);
    qihse_auth_release_principal_scoped(op);
    free(protected_key); free(unrelated_key);
    aimem_fixture_cleanup(source_dir); aimem_fixture_cleanup(target_dir);
    aimem_fixture_cleanup(successor_dir);
    puts("PASS lane abort: typed decisions, crash retry, later-fence isolation and staged target recovery");
    return 0;
}
