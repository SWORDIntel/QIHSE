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
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "aimem_fixture_cleanup.h"
#include "qihse_auth.h"
#include "qihse_audit.h"
#include "qihse_crc16.h"
#include "qihse_kv_store.h"
#include "qihse_cluster_ownership.h"

#define RETAINED_LIMIT (16u * 1024u * 1024u)

static const char LANE_A[QIHSE_KV_CT_LANE_ID_MAX + 1u] =
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
static const char LANE_C[QIHSE_KV_CT_LANE_ID_MAX + 1u] =
    "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
static const char LANE_B[QIHSE_KV_CT_LANE_ID_MAX + 1u] =
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
static const char LANE_D[QIHSE_KV_CT_LANE_ID_MAX + 1u] =
    "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
static const char LANE_E[QIHSE_KV_CT_LANE_ID_MAX + 1u] =
    "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
static const char GEN_A[33] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
static const char GEN_C[33] = "cccccccccccccccccccccccccccccccc";
static const char GEN_B[33] = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
static const char GEN_D[33] = "dddddddddddddddddddddddddddddddd";
static const char GEN_E[33] = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";

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
    return claim && claim->reserve_index != 0u &&
        (!require_final || claim->final_decision_index == claim->reserve_index + 1u);
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

typedef struct {
    qihse_kv_ct_lane_authority_claim_t completed, pending[2];
    bool aborted[2];
    unsigned aborts[2], abort_calls;
    char nodes[3][QIHSE_CLUSTER_NODE_ID_LEN + 1u];
} intent_authority_t;

static bool intent_peer(void *context, const char *node, char out[65]) {
    intent_authority_t *a = context;
    const char *ids[] = {a->completed.source_qkp_id, a->completed.target_qkp_id, "target-e"};
    for (unsigned i = 0; i < 3u; ++i) if (!strcmp(node, a->nodes[i])) {
        snprintf(out, 65, "%s", ids[i]); return true;
    }
    return false;
}

static bool intent_operator(qihse_user_t *user) {
    return user && qihse_auth_user_is_active(user) &&
        qihse_user_get_role(user) == QIHSE_ROLE_OPERATOR &&
        qihse_user_get_tenant_id(user) == QIHSE_TENANT_SYSTEM;
}

static bool intent_claim(void *context, qihse_user_t *user,
    const qihse_cluster_ownership_txn_t *txn, qihse_kv_ct_lane_authority_claim_t *out) {
    intent_authority_t *a = context;
    if (!intent_operator(user)) return false;
    if (!strcmp(txn->transfer_id, a->completed.transfer_id)) {
        *out = a->completed; return true;
    }
    for (unsigned i = 0; i < 2u; ++i) if (!strcmp(txn->transfer_id, a->pending[i].transfer_id)) {
        if (a->aborted[i] && txn->phase != QIHSE_OWNERSHIP_ABORTED) return false;
        *out = a->pending[i]; return true;
    }
    return false;
}

static bool intent_verify(void *context, qihse_user_t *user,
    const qihse_kv_ct_lane_authority_claim_t *claim, bool final) {
    intent_authority_t *a = context;
    return intent_operator(user) && !memcmp(claim, &a->completed, sizeof(*claim)) &&
        (!final || claim->final_decision_index != 0u);
}

static bool intent_verify_abort(void *context, qihse_user_t *user,
    const qihse_kv_ct_lane_authority_claim_t *claim) {
    intent_authority_t *a = context;
    for (unsigned i = 0; i < 2u; ++i)
        if (a->aborted[i] && intent_operator(user) &&
            !memcmp(claim, &a->pending[i], sizeof(*claim))) return true;
    return false;
}

static bool intent_check(void *context, qihse_user_t *user,
    const qihse_cluster_ownership_txn_t *txn, char *error, size_t cap) {
    (void)context; (void)txn; (void)error; (void)cap;
    return intent_operator(user);
}

static bool intent_reserve(void *context, qihse_user_t *user,
    qihse_cluster_ownership_txn_t *txn, char *error, size_t cap) {
    return intent_check(context, user, txn, error, cap);
}

static bool intent_final(void *context, qihse_user_t *user,
    const qihse_cluster_ownership_txn_t *txn,
    const qihse_cluster_ct_activation_receipt_t *receipt, char *error, size_t cap) {
    (void)receipt;
    return intent_check(context, user, txn, error, cap);
}

static bool intent_abort(void *context, qihse_user_t *user,
    const qihse_cluster_ownership_txn_t *txn, char *error, size_t cap) {
    intent_authority_t *a = context;
    ++a->abort_calls;
    (void)error; (void)cap;
    for (unsigned i = 0; i < 2u; ++i) if (intent_operator(user) &&
        !strcmp(txn->transfer_id, a->pending[i].transfer_id) &&
        txn->phase == QIHSE_OWNERSHIP_ABORTED && txn->source_lsn == 0u) {
        if (!a->aborted[i]) ++a->aborts[i];
        a->aborted[i] = true;
        a->pending[i].final_decision_index = a->pending[i].reserve_index + 1u;
        memset(a->pending[i].final_decision_digest, 0xAB, 32u);
        return true;
    }
    return false;
}

static void journal_digest(const char *path, unsigned char out[32]) {
    FILE *f = fopen(path, "rb");
    EVP_MD_CTX *hash = EVP_MD_CTX_new();
    assert(f && hash && EVP_DigestInit_ex(hash, EVP_sha256(), NULL) == 1);
    unsigned char bytes[512]; size_t n;
    while ((n = fread(bytes, 1u, sizeof bytes, f)) != 0u)
        assert(EVP_DigestUpdate(hash, bytes, n) == 1);
    assert(!ferror(f) && fclose(f) == 0);
    unsigned size = 0u;
    assert(EVP_DigestFinal_ex(hash, out, &size) == 1 && size == 32u);
    EVP_MD_CTX_free(hash);
}

static __attribute__((noinline)) void rejected_intent(
    qihse_cluster_ownership_context_t *c, const uint16_t indices[3],
    unsigned phase, bool same_id, const char *preserved, const char *local) {
    struct guard {
        qihse_kv_ct_lane_transfer_status_t before, after;
        qihse_kv_ct_lane_status_t lanes[2], after_lane;
        qihse_cluster_ownership_txn_t txn;
    } *g = calloc(1u, sizeof(*g));
    assert(g && qihse_kv_ct_lane_transfer_status(c->store, c->principal, &g->before));
    assert(g->before.active && g->before.phase == phase);
    const char *lanes[] = {g->before.claim.source_group_id, g->before.claim.target_group_id};
    for (unsigned i = 0; i < 2u; ++i)
        assert(qihse_kv_ct_lane_status(c->store, c->principal, lanes[i], &g->lanes[i]));
    intent_authority_t *a = c->range_authority_context;
    qihse_cluster_ownership_txn_t *t = &g->txn;
    t->phase = QIHSE_OWNERSHIP_INTENT;
    t->start = t->end = phase == 4u ? 15000u : 14000u;
    t->config_epoch = 30u;
    snprintf(t->transfer_id, sizeof t->transfer_id, "%s",
        same_id ? g->before.claim.transfer_id : "foreign-unfenced-intent");
    strcpy(t->source_id, a->nodes[1]); strcpy(t->target_id, a->nodes[2]);
    strcpy(t->owner_id, t->source_id);
    strcpy(t->source_qkp_id, g->before.claim.target_qkp_id);
    strcpy(t->target_qkp_id, "target-e");
    strcpy(t->lane_id, g->before.claim.target_group_id);
    strcpy(t->generation, g->before.claim.target_generation);
    bitmap_set(t->slot_bitmap, t->start);
    t->source_lsn = phase == 4u && !same_id ? 1u : 0u;
    const char *directory = qihse_kv_store_data_directory(c->store);
    char journal[512], saved[512]; struct stat st;
    int n = snprintf(journal, sizeof journal, "%s/slot-ownership.journal", directory);
    assert(n > 0 && (size_t)n < sizeof journal);
    /* Only create an isolated guard journal where no original journal exists. */
    assert(lstat(journal, &st) == -1 && errno == ENOENT);
    n = snprintf(saved, sizeof saved, "%s/guard-phase-%u-%u.journal",
        directory, phase, (unsigned)same_id);
    assert(n > 0 && (size_t)n < sizeof saved);
    assert(lstat(saved, &st) == -1 && errno == ENOENT);
    assert(qihse_cluster_ownership_journal_append_txn(directory, t) == 0);
    unsigned char before_digest[32], after_digest[32];
    journal_digest(journal, before_digest);
    unsigned abort_calls = a->abort_calls;
    uint64_t rows = qihse_kv_change_seq(c->store);
    char *preserved_before = qihse_kv_get_user(c->store, preserved, c->principal);
    char *local_before = qihse_kv_get_user(c->store, local, c->principal);
    assert(local_before && !strcmp(local_before, "local-session"));
    /* This phase-3 fixture already has common FINAL: replay must finish it,
     * so only explicit abort can assert an unchanged native descriptor here. */
    for (unsigned replay = 0; replay < (phase == 3u ? 1u : 2u); ++replay) {
        char error[256] = {0}; bool unresolved = false;
        if (replay) {
            assert(!qihse_cluster_ownership_replay_control(c, &unresolved, error, sizeof error));
            assert(unresolved);
            assert(error[0]);
        } else {
            assert(!qihse_cluster_ownership_transfer_abort(c, t->transfer_id,
                indices[1], indices[2], error, sizeof error));
            assert(strstr(error, "does not match its durable source fence"));
        }
        assert(a->abort_calls == abort_calls);
        assert(qihse_kv_ct_lane_transfer_status(c->store, c->principal, &g->after) &&
            !memcmp(&g->before, &g->after, sizeof g->before));
        for (unsigned i = 0; i < 2u; ++i) {
            memset(&g->after_lane, 0, sizeof g->after_lane);
            assert(qihse_kv_ct_lane_status(c->store, c->principal, lanes[i], &g->after_lane) &&
                !memcmp(&g->lanes[i], &g->after_lane, sizeof g->after_lane));
        }
        assert(qihse_kv_change_seq(c->store) == rows);
        assert_value(c->store, c->principal, preserved, preserved_before);
        assert_value(c->store, c->principal, local, local_before);
        journal_digest(journal, after_digest);
        assert(!memcmp(before_digest, after_digest, sizeof before_digest));
    }
    assert(rename(journal, saved) == 0); /* Preserve this test's rejected INTENT. */
    free(preserved_before); free(local_before);
    free(g);
}

static __attribute__((noinline)) void completed_intent_recovery(qihse_kv_store_t **live,
    qihse_user_t *op, qihse_user_t *peer, qihse_user_t *low,
    const qihse_kv_ct_lane_authority_claim_t *completed, unsigned phase,
    const char *preserved, const char *local) {
    intent_authority_t *authority = calloc(1u, sizeof(*authority));
    assert(authority);
    authority->completed = *completed;
    qihse_cluster_topology_t *topology = qihse_cluster_topology_create();
    assert(topology);
    uint16_t indices[3];
    for (unsigned i = 0; i < 3u; ++i) {
        qihse_cluster_node_t node = {0};
        char seed[32]; snprintf(seed, sizeof seed, "completed-intent-%u", i);
        qihse_cluster_node_id_from_seed(seed, strlen(seed), node.id);
        strcpy(authority->nodes[i], node.id);
        strcpy(node.host, "127.0.0.1");
        node.port = (uint16_t)(8100u + i); node.bus_port = (uint16_t)(18100u + i);
        node.role = QIHSE_CLUSTER_NODE_PRIMARY; node.healthy = true;
        node.primary_index = QIHSE_CLUSTER_NODE_NONE;
        assert(qihse_cluster_topology_upsert_node(topology, &node, &indices[i]));
    }
    assert(qihse_cluster_topology_set_local_node(topology, indices[1]));
    assert(qihse_cluster_topology_adopt_range(topology, 15000, 15000, indices[1], 1));
    qihse_cluster_ownership_context_t c = {.topology = topology, .store = *live,
        .principal = op, .data_principal = op, .peer_id = intent_peer,
        .peer_id_context = authority, .range_reserve = intent_reserve,
        .range_check_reserved = intent_check, .range_finalize = intent_final,
        .range_check_finalized = intent_check, .range_abort = intent_abort,
        .lane_claim = intent_claim, .lane_verify_claim = intent_verify,
        .lane_verify_aborted = intent_verify_abort, .range_authority_context = authority};
    rejected_intent(&c, indices, phase, false, preserved, local);
    if (phase != 4u) {
        qihse_cluster_topology_destroy(topology);
        free(authority);
        return;
    }
    rejected_intent(&c, indices, phase, true, preserved, local);
    qihse_kv_ct_lane_transfer_status_t before = {0}, after = {0};
    assert(qihse_kv_ct_lane_transfer_status(*live, op, &before) &&
        before.active && before.phase == 4u);
    for (unsigned round = 0; round < 2u; ++round) {
        qihse_cluster_ownership_txn_t txn = {0};
        txn.phase = QIHSE_OWNERSHIP_INTENT; txn.start = txn.end = 15000u;
        txn.config_epoch = 30u + round;
        snprintf(txn.transfer_id, sizeof txn.transfer_id, "after-completed-%u", round);
        strcpy(txn.source_id, authority->nodes[1]); strcpy(txn.target_id, authority->nodes[2]);
        strcpy(txn.owner_id, txn.source_id);
        strcpy(txn.source_qkp_id, "target-d"); strcpy(txn.target_qkp_id, "target-e");
        strcpy(txn.lane_id, LANE_D); strcpy(txn.generation, GEN_D);
        bitmap_set(txn.slot_bitmap, txn.start);
        qihse_kv_ct_lane_authority_claim_t *claim = &authority->pending[round];
        claim->operation = QIHSE_KV_CT_LANE_AUTH_TRANSFER;
        strcpy(claim->transfer_id, txn.transfer_id);
        strcpy(claim->source_group_id, LANE_D); strcpy(claim->target_group_id, LANE_E);
        strcpy(claim->source_generation, GEN_D); strcpy(claim->target_generation, GEN_E);
        strcpy(claim->source_qkp_id, "target-d"); strcpy(claim->target_qkp_id, "target-e");
        strcpy(claim->successor_qkp_id, "target-e-successor");
        memcpy(claim->slots, txn.slot_bitmap, sizeof(claim->slots));
        claim->grant_epoch = txn.config_epoch; claim->reserve_index = 100u + round;
        memset(claim->reserve_digest, (int)round + 1, 32u);
        assert(qihse_cluster_ownership_journal_append_txn(
            qihse_kv_store_data_directory(*live), &txn) == 0);
        qihse_kv_store_destroy(*live);
        *live = qihse_kv_store_create_user(op); assert(*live); c.store = *live;
        qihse_kv_store_set_replication_principal_id(*live, qihse_user_get_id(peer));
        char error[256] = {0}; bool unresolved = true;
        c.principal = low;
        assert(!qihse_cluster_ownership_transfer_abort(&c, txn.transfer_id,
            indices[1], indices[2], error, sizeof error));
        c.principal = op;
        if (round == 0u)
            assert(qihse_cluster_ownership_transfer_abort(&c, txn.transfer_id,
                indices[1], indices[2], error, sizeof error));
        assert(qihse_cluster_ownership_replay_control(&c, &unresolved,
            error, sizeof error) && !unresolved);
        assert(authority->aborted[round] && authority->aborts[round] == 1u);
        assert(qihse_kv_ct_lane_transfer_status(*live, op, &after) &&
            !memcmp(&before, &after, sizeof(before)));
    }
    qihse_kv_ct_lane_status_t lane = {0};
    assert(qihse_kv_ct_lane_status(*live, op, LANE_D, &lane));
    unsigned char token[QIHSE_KV_CT_TOKEN_BYTES];
    create_admitted_source_lane(*live, op, peer, LANE_D, lane.slot_bitmap,
        "target-d", "target-d-successor", GEN_D, token);
    qihse_cluster_topology_destroy(topology);
    free(authority);
    puts("PASS completed phase-4 receipt survives later unfenced INTENT abort/reopen/replay");
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

    /* Occupied receiver data must be refused until explicit fixture cleanup;
     * C-owned rows and node-local trust state must remain untouched. */
    qihse_kv_store_t *store = qihse_kv_store_create_user(operator_user);
    assert(store);
    assert(qihse_kv_set_user(store, stale_key, "stale", 0u, 0u, operator_user));
    assert(qihse_kv_set_user(store, preserved_key, "keep", 0u, 0u, operator_user));
    uint64_t preserved_row_seq = qihse_kv_change_seq(store);
    char* local_statement = key_for_slot("fedstmt:fixture-", moved_slot);
    char* local_replay = key_for_slot("fedreplay:fixture-", moved_slot);
    assert(qihse_kv_set_user(store, local_statement, "local-session", 5, 1, operator_user));
    assert(qihse_kv_set_user(store, local_replay, "99", 5, 1, operator_user));
    qihse_kv_store_set_replication_principal_id(store,
        qihse_user_get_id(replication_user));
    unsigned char target_token[QIHSE_KV_CT_TOKEN_BYTES];
    create_admitted_source_lane(store, operator_user, replication_user,
        LANE_C, target_bitmap, "target-c", "target-c-successor", GEN_C,
        target_token);
    qihse_kv_replica_snapshot_t* pinned_scope = NULL;
    uint64_t pinned_row_seq = 0u;
    unsigned char pinned_image_digest[32], pinned_scope_digest[32];
    assert(qihse_kv_ct_lane_source_baseline_snapshot_create(store, operator_user,
        LANE_C, &pinned_scope, &pinned_row_seq, pinned_image_digest) == 0);
    assert(qihse_kv_ct_lane_baseline_scope_digest(pinned_scope, operator_user,
        pinned_scope_digest));
    unsigned char denied_scope[32]; memset(denied_scope, 0xff, sizeof(denied_scope));
    assert(!qihse_kv_ct_lane_baseline_scope_digest(pinned_scope, low_user, denied_scope));
    assert(memcmp(denied_scope, (unsigned char[32]){0}, 32u) == 0);
    assert(!qihse_kv_ct_lane_baseline_scope_digest(pinned_scope, NULL, denied_scope));
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
    uint64_t before_occupied_import = qihse_kv_change_seq(store);
    assert(!qihse_kv_ct_lane_transfer_target_import_apply_file(store,
        operator_user, replication_user, operator_user, &claim, proof,
        verify_reserved, NULL, image_path, image_digest, target_token));
    assert(errno == EBUSY && qihse_kv_change_seq(store) == before_occupied_import);
    /* Keep the occupied receiver fenced through common ABORT, then retire this
     * test-owned stale row before retrying with a distinct reservation. */
    claim.final_decision_index = claim.reserve_index + 1u;
    memset(claim.final_decision_digest, 0x12, sizeof(claim.final_decision_digest));
    qihse_kv_ct_proof_t *aborted_proof = qihse_kv_ct_lane_authority_proof_create(
        store, operator_user, operator_user, &claim, verify_reserved, NULL);
    assert(aborted_proof);
    assert(qihse_kv_ct_lane_transfer_abort(store, operator_user, operator_user,
        &claim, aborted_proof, verify_reserved, NULL, target_token));
    qihse_kv_ct_proof_destroy(aborted_proof);
    qihse_kv_ct_proof_destroy(proof);
    /* Explicit fixture cleanup after common ABORT; this is not an automatic
     * transfer retry and runs only because the row is synthetic test data. */
    assert(qihse_kv_ct_lane_receiver_baseline_install(store, operator_user,
        operator_user, LANE_A, moved_bitmap, image_path, 0u, 0u, image_digest,
        receiver_token));
    snprintf(claim.transfer_id, sizeof(claim.transfer_id), "move-empty-1-retry");
    claim.grant_epoch = 2u;
    claim.reserve_index = 13u;
    memset(claim.reserve_digest, 0x13, sizeof(claim.reserve_digest));
    claim.final_decision_index = 0u;
    memset(claim.final_decision_digest, 0, sizeof(claim.final_decision_digest));
    proof = qihse_kv_ct_lane_authority_proof_create(
        store, operator_user, operator_user, &claim, verify_reserved, NULL);
    assert(proof && qihse_kv_ct_lane_transfer_target_import_begin(store,
        operator_user, operator_user, &claim, proof, verify_reserved, NULL,
        target_token));
    bool empty_import_ok = qihse_kv_ct_lane_transfer_target_import_apply_file(store,
        operator_user, replication_user, operator_user, &claim, proof,
        verify_reserved, NULL, image_path, image_digest, target_token);
    assert(empty_import_ok);
    claim.source_cut = 0u;
    claim.target_cursor = 0u;
    memcpy(claim.image_digest, image_digest, sizeof(image_digest));
    memcpy(claim.range_digest, range_digest, sizeof(range_digest));
    unsigned char checksum[32];
    qihse_kv_ct_lane_authority_claim_t wrong_digest_claim = claim;
    wrong_digest_claim.image_digest[0] ^= 0x80u;
    qihse_kv_ct_proof_t *wrong_digest_proof =
        qihse_kv_ct_lane_authority_proof_create(store, operator_user,
            operator_user, &wrong_digest_claim, verify_reserved, NULL);
    assert(wrong_digest_proof);
    assert(!qihse_kv_ct_lane_transfer_target_import_begin(store, operator_user,
        operator_user, &wrong_digest_claim, wrong_digest_proof,
        verify_reserved, NULL, target_token));
    qihse_kv_ct_proof_destroy(wrong_digest_proof);
    qihse_kv_ct_proof_t *image_proof = qihse_kv_ct_lane_authority_proof_create(
        store, operator_user, operator_user, &claim, verify_reserved, NULL);
    assert(image_proof);
    assert(qihse_kv_ct_lane_transfer_target_seal(store, operator_user,
        operator_user, &claim, image_proof, verify_reserved, NULL,
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
    assert_value(store, operator_user, local_statement, "local-session");
    assert_value(store, operator_user, local_replay, "99");
    completed_intent_recovery(&store, operator_user, replication_user, low_user,
        &claim, 2u, preserved_key, local_statement);

    /* A final proof moves only the selected bitmap from temporary receiver A
     * into the existing source C. Repeating finalization models recovery after
     * a lost response and must leave the same memberships. */
    claim.final_decision_index = claim.reserve_index + 1u;
    memset(claim.final_decision_digest, 0x12, sizeof(claim.final_decision_digest));
    qihse_kv_ct_proof_t *final_proof = qihse_kv_ct_lane_authority_proof_create(
        store, operator_user, operator_user, &claim, verify_reserved, NULL);
    assert(final_proof);
    /* Fail the data WAL sync after phase-3 intent publication. The ownership
     * bitmaps must remain unchanged; reopening and retrying the same final
     * decision claim must replay the durable intent to completion. */
    qihse_kv_ct_proof_destroy(final_proof);
    qihse_kv_store_destroy(store);
    store = NULL;
    qihse_audit_shutdown();
    pid_t recovery_child = fork();
    assert(recovery_child >= 0);
    if (recovery_child == 0) {
        qihse_audit_init();
        qihse_kv_store_t* child_store = qihse_kv_store_create_user(operator_user);
        if (!child_store) _exit(20);
        qihse_kv_store_set_replication_principal_id(child_store,
            qihse_user_get_id(replication_user));
        qihse_kv_ct_proof_t* child_proof = qihse_kv_ct_lane_authority_proof_create(
            child_store, operator_user, operator_user, &claim, verify_reserved, NULL);
        if (!child_proof || setenv("QIHSE_AIMEM_FAIL_AT", "wal-fsync", 1) != 0)
            _exit(21);
        errno = 0;
        bool child_finalized = qihse_kv_ct_lane_transfer_membership_finalize(
            child_store, operator_user, operator_user, &claim, child_proof,
            verify_reserved, NULL, receiver_token, target_token);
        if (child_finalized || errno != EIO) _exit(22);
        qihse_kv_ct_lane_transfer_status_t child_status = {0};
        qihse_kv_ct_lane_status_t child_a = {0}, child_c = {0};
        if (!qihse_kv_ct_lane_transfer_status(child_store, operator_user, &child_status) ||
            !child_status.active || child_status.phase != 3u ||
            !qihse_kv_ct_lane_status(child_store, operator_user, LANE_A, &child_a) ||
            !qihse_kv_ct_lane_status(child_store, operator_user, LANE_C, &child_c) ||
            memcmp(child_a.slot_bitmap, moved_bitmap, sizeof(moved_bitmap)) != 0 ||
            memcmp(child_c.slot_bitmap, target_bitmap, sizeof(target_bitmap)) != 0 ||
            qihse_kv_ct_lane_transfer_write_allowed(child_store, operator_user, stale_key))
            _exit(23);
        _exit(0); /* Deliberately skip store/proof cleanup: simulate process death. */
    }
    int child_status = 0;
    assert(waitpid(recovery_child, &child_status, 0) == recovery_child);
    assert(WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0);
    qihse_audit_init();
    qihse_kv_ct_lane_transfer_status_t interrupted = {0};
    qihse_kv_ct_lane_status_t interrupted_a = {0}, interrupted_c = {0};
    store = qihse_kv_store_create_user(operator_user);
    assert(store);
    qihse_kv_store_set_replication_principal_id(store,
        qihse_user_get_id(replication_user));
    assert(qihse_kv_ct_lane_transfer_status(store, operator_user, &interrupted));
    assert(interrupted.active && interrupted.phase == 3u);
    assert(qihse_kv_ct_lane_status(store, operator_user, LANE_A, &interrupted_a));
    assert(qihse_kv_ct_lane_status(store, operator_user, LANE_C, &interrupted_c));
    assert(!memcmp(interrupted_a.slot_bitmap, moved_bitmap, sizeof(moved_bitmap)));
    assert(!memcmp(interrupted_c.slot_bitmap, target_bitmap, sizeof(target_bitmap)));
    assert(!qihse_kv_ct_lane_transfer_write_allowed(store, operator_user, stale_key));
    memset(&interrupted, 0, sizeof(interrupted));
    assert(qihse_kv_ct_lane_transfer_status(store, operator_user, &interrupted));
    assert(interrupted.active && interrupted.phase == 3u);
    memset(&interrupted_a, 0, sizeof(interrupted_a));
    memset(&interrupted_c, 0, sizeof(interrupted_c));
    assert(qihse_kv_ct_lane_status(store, operator_user, LANE_A, &interrupted_a));
    assert(qihse_kv_ct_lane_status(store, operator_user, LANE_C, &interrupted_c));
    assert(!memcmp(interrupted_a.slot_bitmap, moved_bitmap, sizeof(moved_bitmap)));
    assert(!memcmp(interrupted_c.slot_bitmap, target_bitmap, sizeof(target_bitmap)));
    completed_intent_recovery(&store, operator_user, replication_user, low_user,
        &claim, 3u, preserved_key, local_statement);
    final_proof = qihse_kv_ct_lane_authority_proof_create(
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
    unsigned char retained_scope_digest[32];
    assert(qihse_kv_ct_lane_baseline_scope_digest(pinned_scope, operator_user,
        retained_scope_digest));
    assert(memcmp(retained_scope_digest, pinned_scope_digest, 32u) == 0);
    assert(memcmp(retained_scope_digest, finalized_c.slot_bitmap_digest, 32u) != 0);
    qihse_kv_replica_snapshot_destroy(pinned_scope);
    assert(finalized_a.mode == QIHSE_KV_CT_LANE_RECEIVER &&
        !finalized_a.admitted && !memcmp(finalized_a.slot_bitmap,
            (uint8_t[QIHSE_KV_CT_SLOT_BITMAP_BYTES]){0}, sizeof(moved_bitmap)));
    for (size_t i = 0; i < sizeof(moved_bitmap); ++i)
        assert(finalized_c.slot_bitmap[i] == (uint8_t)(target_bitmap[i] | moved_bitmap[i]));
    assert(finalized_c.mode == QIHSE_KV_CT_LANE_SOURCE && !finalized_c.admitted &&
        finalized_c.baseline_sealed && finalized_c.baseline_refresh_needed);

    qihse_kv_replica_snapshot_t *refreshed = NULL;
    uint64_t refreshed_row_seq = 0u;
    unsigned char refreshed_digest[32];
    assert(qihse_kv_ct_lane_source_baseline_snapshot_create(store, operator_user,
        LANE_C, &refreshed, &refreshed_row_seq, refreshed_digest) == 0);
    assert(refreshed && refreshed_row_seq == preserved_row_seq &&
        refreshed_row_seq < qihse_kv_change_seq(store));
    qihse_kv_replica_snapshot_destroy(refreshed);
    assert(qihse_kv_ct_lane_status(store, operator_user, LANE_C, &finalized_c));
    bool reconciled = qihse_kv_ct_lane_source_reconcile_peer(store, operator_user,
        replication_user, LANE_C, "target-c-successor", GEN_C,
        refreshed_digest, finalized_c.durable_position);
    if (!reconciled) fprintf(stderr, "post-restart peer reconcile failed errno=%d position=%llu baseline_cut=%llu ack=%llu durable=%llu\n",
        errno, (unsigned long long)finalized_c.durable_position,
        (unsigned long long)finalized_c.baseline_stream_cut,
        (unsigned long long)finalized_c.acknowledged_position,
        (unsigned long long)finalized_c.durable_position);
    assert(reconciled);
    assert(qihse_kv_ct_lane_status(store, operator_user, LANE_C, &finalized_c));
    assert(finalized_c.mode == QIHSE_KV_CT_LANE_SOURCE && finalized_c.admitted &&
        finalized_c.baseline_sealed && !finalized_c.baseline_refresh_needed);
    assert(qihse_kv_ct_lane_transfer_write_allowed(store, operator_user, stale_key));

    /* A completed phase-4 receipt must be replaceable by a distinct next
     * transfer. This models a target node that received one range and later
     * receives another, without losing the ability to retry the first final. */
    const uint16_t moved_slot_2 = 1000u, target_slot_2 = 15000u;
    uint8_t moved_bitmap_2[QIHSE_KV_CT_SLOT_BITMAP_BYTES] = {0};
    uint8_t target_bitmap_2[QIHSE_KV_CT_SLOT_BITMAP_BYTES] = {0};
    bitmap_set(moved_bitmap_2, moved_slot_2);
    bitmap_set(target_bitmap_2, target_slot_2);
    unsigned char target_token_2[QIHSE_KV_CT_TOKEN_BYTES];
    create_admitted_source_lane(store, operator_user, replication_user,
        LANE_D, target_bitmap_2, "target-d", "target-d-successor", GEN_D,
        target_token_2);
    unsigned char receiver_token_2[QIHSE_KV_CT_TOKEN_BYTES];
    assert(qihse_kv_ct_lane_receiver_bind(store, operator_user, LANE_B,
        moved_bitmap_2, "source-b", "target-d", GEN_B,
        QIHSE_KV_CT_TENANT_SYSTEM_ALL, 0u, 0u, receiver_token_2));

    qihse_kv_ct_lane_authority_claim_t claim_2 = {0};
    claim_2.operation = QIHSE_KV_CT_LANE_AUTH_TRANSFER;
    snprintf(claim_2.transfer_id, sizeof(claim_2.transfer_id), "move-empty-2");
    snprintf(claim_2.source_group_id, sizeof(claim_2.source_group_id), "%s", LANE_B);
    snprintf(claim_2.target_group_id, sizeof(claim_2.target_group_id), "%s", LANE_D);
    snprintf(claim_2.source_qkp_id, sizeof(claim_2.source_qkp_id), "source-b");
    snprintf(claim_2.target_qkp_id, sizeof(claim_2.target_qkp_id), "target-d");
    snprintf(claim_2.source_generation, sizeof(claim_2.source_generation), "%s", GEN_B);
    snprintf(claim_2.target_generation, sizeof(claim_2.target_generation), "%s", GEN_D);
    snprintf(claim_2.successor_qkp_id, sizeof(claim_2.successor_qkp_id),
        "target-d-successor");
    memcpy(claim_2.slots, moved_bitmap_2, sizeof(moved_bitmap_2));
    claim_2.grant_epoch = 2u;
    claim_2.reserve_index = 21u;
    memset(claim_2.reserve_digest, 0x21, sizeof(claim_2.reserve_digest));
    qihse_kv_ct_proof_t *proof_2 = qihse_kv_ct_lane_authority_proof_create(
        store, operator_user, operator_user, &claim_2, verify_reserved, NULL);
    assert(proof_2);
    assert(qihse_kv_ct_lane_transfer_target_import_begin(store, operator_user,
        operator_user, &claim_2, proof_2, verify_reserved, NULL, target_token_2));
    char image_path_2[512];
    n = snprintf(image_path_2, sizeof(image_path_2), "%s/ct-empty-image-2.qfs", data_dir);
    assert(n > 0 && (size_t)n < sizeof(image_path_2));
    image_fd = open(image_path_2, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    assert(image_fd >= 0 && fsync(image_fd) == 0 && close(image_fd) == 0);
    unsigned char image_digest_2[32], range_digest_2[32];
    empty_image_digest(image_digest_2);
    empty_range_digest(moved_bitmap_2, range_digest_2);
    assert(qihse_kv_ct_lane_transfer_target_import_apply_file(store,
        operator_user, replication_user, operator_user, &claim_2, proof_2,
        verify_reserved, NULL, image_path_2, image_digest_2, target_token_2));
    memcpy(claim_2.image_digest, image_digest_2, sizeof(image_digest_2));
    memcpy(claim_2.range_digest, range_digest_2, sizeof(range_digest_2));
    qihse_kv_ct_proof_t *image_proof_2 = qihse_kv_ct_lane_authority_proof_create(
        store, operator_user, operator_user, &claim_2, verify_reserved, NULL);
    assert(image_proof_2);
    assert(qihse_kv_ct_lane_transfer_target_seal(store, operator_user,
        operator_user, &claim_2, image_proof_2, verify_reserved, NULL,
        target_token_2, checksum));
    claim_2.final_decision_index = 22u;
    memset(claim_2.final_decision_digest, 0x22,
           sizeof(claim_2.final_decision_digest));
    qihse_kv_ct_proof_t *final_proof_2 = qihse_kv_ct_lane_authority_proof_create(
        store, operator_user, operator_user, &claim_2, verify_reserved, NULL);
    assert(final_proof_2);
    assert(qihse_kv_ct_lane_transfer_membership_finalize(store, operator_user,
        operator_user, &claim_2, final_proof_2, verify_reserved, NULL,
        receiver_token_2, target_token_2));
    assert(qihse_kv_ct_lane_transfer_membership_finalize(store, operator_user,
        operator_user, &claim_2, final_proof_2, verify_reserved, NULL,
        receiver_token_2, target_token_2));
    qihse_kv_ct_lane_transfer_status_t transfer_2 = {0};
    assert(qihse_kv_ct_lane_transfer_status(store, operator_user, &transfer_2));
    assert(transfer_2.active && transfer_2.phase == 4u &&
        strcmp(transfer_2.claim.transfer_id, "move-empty-2") == 0);
    qihse_kv_ct_lane_status_t finalized_d = {0};
    assert(qihse_kv_ct_lane_status(store, operator_user, LANE_D, &finalized_d));
    for (size_t i = 0; i < sizeof(moved_bitmap_2); ++i)
        assert(finalized_d.slot_bitmap[i] ==
            (uint8_t)(target_bitmap_2[i] | moved_bitmap_2[i]));
    assert(finalized_d.mode == QIHSE_KV_CT_LANE_SOURCE && finalized_d.admitted &&
        finalized_d.baseline_sealed && finalized_d.baseline_refresh_needed);

    completed_intent_recovery(&store, operator_user, replication_user, low_user,
        &claim_2, 4u, preserved_key, local_statement);

    char* export_key = key_for_slot("commons/export-cut-", target_slot_2);
    qihse_kv_ct_writer_scope_t* write_scope = NULL;
    assert(qihse_kv_ct_writer_scope_enter_lane(store, operator_user, LANE_D,
        target_token_2, &write_scope));
    assert(qihse_kv_set_user(store, export_key, "source cut is nonzero", 0u, 0u,
        operator_user));
    qihse_kv_ct_writer_scope_leave(write_scope);
    assert(qihse_kv_ct_lane_source_ack(store, replication_user, LANE_D,
        "target-d-successor", GEN_D, 1u));

    /* The source-side fence may replace a completed phase-4 receipt, but an
     * unfinished phase-3 intent is never replaceable. */
    qihse_kv_ct_lane_authority_claim_t claim_3 = {0};
    claim_3.operation = QIHSE_KV_CT_LANE_AUTH_TRANSFER;
    snprintf(claim_3.transfer_id, sizeof(claim_3.transfer_id), "move-next-3");
    snprintf(claim_3.source_group_id, sizeof(claim_3.source_group_id), "%s", LANE_D);
    snprintf(claim_3.target_group_id, sizeof(claim_3.target_group_id), "%s", LANE_E);
    snprintf(claim_3.source_qkp_id, sizeof(claim_3.source_qkp_id), "target-d");
    snprintf(claim_3.target_qkp_id, sizeof(claim_3.target_qkp_id), "target-e");
    snprintf(claim_3.source_generation, sizeof(claim_3.source_generation), "%s", GEN_D);
    snprintf(claim_3.target_generation, sizeof(claim_3.target_generation), "%s", GEN_E);
    snprintf(claim_3.successor_qkp_id, sizeof(claim_3.successor_qkp_id),
        "target-e-successor");
    memcpy(claim_3.slots, target_bitmap_2, sizeof(target_bitmap_2));
    claim_3.grant_epoch = 3u;
    claim_3.reserve_index = 31u;
    memset(claim_3.reserve_digest, 0x31, sizeof(claim_3.reserve_digest));
    qihse_kv_ct_proof_t *proof_3 = qihse_kv_ct_lane_authority_proof_create(
        store, operator_user, operator_user, &claim_3, verify_reserved, NULL);
    assert(proof_3);
    uint64_t source_cut_3 = UINT64_MAX;
    assert(qihse_kv_ct_lane_transfer_source_fence(store, operator_user,
        operator_user, &claim_3, proof_3, verify_reserved, NULL,
        target_token_2, &source_cut_3));
    assert(source_cut_3 == 1u);
    qihse_kv_ct_lane_transfer_status_t transfer_3 = {0};
    assert(qihse_kv_ct_lane_transfer_status(store, operator_user, &transfer_3));
    assert(transfer_3.active && transfer_3.phase == 1u &&
        strcmp(transfer_3.claim.transfer_id, "move-next-3") == 0 &&
        transfer_3.claim.source_cut == source_cut_3);

    /* The chosen target cut is a different stream domain from the source.
     * A source-only export must persist it and both seals for exact retry. */
    qihse_kv_ct_lane_authority_claim_t export_claim = claim_3;
    export_claim.source_cut = source_cut_3;
    export_claim.target_cursor = 7u;
    qihse_kv_ct_proof_t* export_proof = qihse_kv_ct_lane_authority_proof_create(
        store, operator_user, operator_user, &export_claim, verify_reserved, NULL);
    assert(export_proof);
    qihse_kv_replica_snapshot_t* exported = NULL;
    unsigned char export_range[32], export_image[32];
    assert(qihse_kv_ct_lane_transfer_source_export(store, operator_user,
        operator_user, &export_claim, export_proof, verify_reserved, NULL,
        &exported, export_range, export_image) == 0);
    qihse_kv_replica_snapshot_destroy(exported);
    assert(qihse_kv_ct_lane_transfer_status(store, operator_user, &transfer_3));
    assert(transfer_3.target_cursor == 7u && transfer_3.claim.target_cursor == 7u);
    assert(memcmp(transfer_3.claim.range_digest, export_range, 32u) == 0);
    assert(memcmp(transfer_3.claim.image_digest, export_image, 32u) == 0);
    export_claim.target_cursor = 8u;
    qihse_kv_ct_proof_t* changed_cut = qihse_kv_ct_lane_authority_proof_create(
        store, operator_user, operator_user, &export_claim, verify_reserved, NULL);
    assert(changed_cut);
    exported = NULL;
    assert(qihse_kv_ct_lane_transfer_source_export(store, operator_user,
        operator_user, &export_claim, changed_cut, verify_reserved, NULL,
        &exported, export_range, export_image) != 0 && !exported);
    qihse_kv_ct_proof_destroy(changed_cut);
    qihse_kv_ct_proof_destroy(export_proof);

    qihse_kv_ct_proof_destroy(proof_3);
    qihse_kv_ct_proof_destroy(final_proof_2);
    qihse_kv_ct_proof_destroy(image_proof_2);
    qihse_kv_ct_proof_destroy(proof_2);
    qihse_kv_ct_proof_destroy(final_proof);
    qihse_kv_ct_proof_destroy(image_proof);
    qihse_kv_ct_proof_destroy(proof);
    qihse_kv_store_destroy(store);
    store = qihse_kv_store_create_user(operator_user);
    assert(store);
    qihse_kv_ct_lane_transfer_status_t reopened_export = {0};
    assert(qihse_kv_ct_lane_transfer_status(store, operator_user, &reopened_export));
    assert(reopened_export.phase == 1u && reopened_export.source_cut == source_cut_3 &&
        reopened_export.target_cursor == 7u && reopened_export.claim.target_cursor == 7u);
    assert(memcmp(reopened_export.range_digest, transfer_3.claim.range_digest, 32u) == 0);
    assert(memcmp(reopened_export.image_digest, transfer_3.claim.image_digest, 32u) == 0);
    qihse_kv_store_set_replication_principal_id(store,
        qihse_user_get_id(replication_user));
    qihse_kv_ct_lane_status_t reopened_c = {0};
    assert(qihse_kv_ct_lane_status(store, operator_user, LANE_C, &reopened_c));
    assert(qihse_kv_ct_lane_source_reconcile_peer(store, operator_user,
        replication_user, LANE_C, "target-c-successor", GEN_C,
        reopened_c.baseline_digest, reopened_c.durable_position));
    assert_value(store, operator_user, preserved_key, "keep");
    assert_value(store, operator_user, stale_key, NULL);
    qihse_kv_store_destroy(store);
    qihse_auth_release_principal_scoped(low_user);
    qihse_auth_release_principal_scoped(replication_user);
    qihse_auth_release_principal_scoped(operator_user);
    free(export_key);
    free(stale_key);
    free(preserved_key);
    free(local_statement);
    free(local_replay);
    aimem_fixture_cleanup(data_dir);
    return 0;
}
