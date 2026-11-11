/* SPDX-License-Identifier: LicenseRef-SRSL-1.1 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#ifdef NDEBUG
#undef NDEBUG
#endif
#include "qihse_auth.h"
#include "qihse_cluster_failover.h"
#include "qihse_cluster_ownership.h"
#include "qihse_cluster_ownership_journal.h"
#include "qihse_cluster_bus.h"
#include <assert.h>
#include <errno.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* Real public producer, principal registry, topology and durable ownership
 * journal; deterministic doubles isolate the KV/authority/transport boundary.
 * Real signed-wire and storage tests cover those providers independently. */
struct qihse_kv_ct_proof { qihse_kv_ct_lane_authority_claim_t claim; };
static struct {
    qihse_user_t *op, *service;
    char directory[512];
    qihse_cluster_ownership_txn_t committed;
    qihse_kv_ct_lane_authority_claim_t marker;
    qihse_kv_ct_lane_status_t lane;
    qihse_cluster_bus_ct1_promotion_update_v2_t certificate;
    unsigned char certificate_digest[32];
    bool common_final, marker_available, fail_finalize;
    unsigned status_calls, reserves, prepares, finalizes, refreshes, signatures;
} fixture;
static const char lane_id[] =
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
static const unsigned char event_digest[32] = {0x61, 0x72, 0x83};
static char topology_ids[3][QIHSE_CLUSTER_NODE_ID_LEN + 1u];
static const char* qkp_ids[] = {"qkp-a", "qkp-b", "qkp-c"};

static bool hash(const void* data, size_t length, unsigned char out[32]) {
    unsigned int size = 0;
    return EVP_Digest(data, length, out, &size, EVP_sha256(), NULL) == 1 && size == 32u;
}

const char* qihse_kv_store_data_directory(qihse_kv_store_t* store) {
    assert(store == (qihse_kv_store_t*)(uintptr_t)1);
    return fixture.directory;
}

bool qihse_kv_ct_lane_status(qihse_kv_store_t* store, qihse_user_t* user,
    const char* lane, qihse_kv_ct_lane_status_t* out) {
    assert(store == (qihse_kv_store_t*)(uintptr_t)1 && user == fixture.op);
    assert(!strcmp(lane, lane_id) && out);
    fixture.status_calls++;
    *out = fixture.lane;
    return true;
}

static bool verify_claim(void* context, qihse_user_t* user,
    const qihse_kv_ct_lane_authority_claim_t* claim, bool final) {
    (void)context;
    return user == fixture.op && qihse_auth_user_is_active(user) && claim &&
        !strcmp(claim->transfer_id, fixture.committed.transfer_id) &&
        !strcmp(claim->source_group_id, lane_id) &&
        !strcmp(claim->target_group_id, lane_id) &&
        claim->grant_epoch == fixture.committed.config_epoch &&
        claim->source_cut == fixture.committed.source_lsn &&
        claim->target_cursor == fixture.committed.target_lsn &&
        (!final || (fixture.common_final && claim->final_decision_index == 19u));
}

qihse_kv_ct_proof_t* qihse_kv_ct_lane_authority_proof_create(
    qihse_kv_store_t* store, qihse_user_t* control, qihse_user_t* data,
    const qihse_kv_ct_lane_authority_claim_t* claim,
    qihse_kv_ct_lane_authority_verify_fn verify, void* context) {
    assert(store == (qihse_kv_store_t*)(uintptr_t)1);
    assert(control == fixture.op && data == fixture.service);
    if (!verify || !verify(context, claim, false)) return NULL;
    qihse_kv_ct_proof_t* proof = malloc(sizeof(*proof));
    assert(proof);
    proof->claim = *claim;
    return proof;
}

bool qihse_kv_ct_lane_authority_proof_fields(qihse_kv_store_t* store,
    qihse_user_t* control, qihse_user_t* data, const qihse_kv_ct_proof_t* proof,
    qihse_kv_ct_lane_authority_claim_t* out) {
    assert(store == (qihse_kv_store_t*)(uintptr_t)1);
    assert(control == fixture.op && data == fixture.service && out);
    if (!proof) return false;
    *out = proof->claim;
    return true;
}

bool qihse_kv_ct_lane_authority_proof_validate(qihse_kv_store_t* store,
    qihse_user_t* control, qihse_user_t* data, const qihse_kv_ct_proof_t* proof,
    qihse_kv_ct_lane_authority_verify_fn verify, void* context, bool final) {
    assert(store == (qihse_kv_store_t*)(uintptr_t)1);
    assert(control == fixture.op && data == fixture.service);
    return proof && verify && verify(context, &proof->claim, final);
}

void qihse_kv_ct_proof_destroy(qihse_kv_ct_proof_t* proof) { free(proof); }

qihse_kv_ct_proof_t* qihse_kv_ct_lane_promoted_proof_get(
    qihse_kv_store_t* store, qihse_user_t* control, qihse_user_t* data,
    const char* lane, const unsigned char event[32],
    qihse_kv_ct_lane_authority_verify_fn verify, void* context) {
    assert(!strcmp(lane, lane_id) && !memcmp(event, event_digest, 32u));
    if (!fixture.marker_available) return NULL;
    return qihse_kv_ct_lane_authority_proof_create(store, control, data,
        &fixture.marker, verify, context);
}

bool qihse_kv_ct_lane_promotion_finalize(qihse_kv_store_t* store,
    qihse_user_t* control, qihse_user_t* data,
    const qihse_kv_ct_lane_authority_claim_t* claim,
    const qihse_kv_ct_proof_t* proof,
    qihse_kv_ct_lane_authority_verify_fn verify, void* context) {
    fixture.finalizes++;
    assert(qihse_kv_ct_lane_authority_proof_validate(store, control, data,
        proof, verify, context, true));
    assert(!memcmp(claim->image_digest, fixture.marker.image_digest, 32u));
    assert(!memcmp(claim->certificate_head_digest,
        fixture.marker.certificate_head_digest, 32u));
    if (fixture.fail_finalize) { errno = EIO; return false; }
    fixture.lane.promotion_pending = false;
    fixture.lane.admitted = true;
    return true;
}

int qihse_kv_ct_lane_source_baseline_snapshot_create(qihse_kv_store_t* store,
    qihse_user_t* user, const char* lane, qihse_kv_replica_snapshot_t** out,
    uint64_t* row, unsigned char digest[32]) {
    assert(store == (qihse_kv_store_t*)(uintptr_t)1 && user == fixture.service);
    assert(!strcmp(lane, lane_id));
    *out = malloc(1u); assert(*out);
    *row = fixture.committed.target_lsn;
    memcpy(digest, fixture.marker.image_digest, 32u);
    return 0;
}
void qihse_kv_replica_snapshot_destroy(qihse_kv_replica_snapshot_t* snapshot) {
    free(snapshot);
}

bool qihse_kv_ct_lane_certificate_page(qihse_kv_store_t* store,
    qihse_user_t* user, const char* lane, const unsigned char after[32],
    void* buffer, size_t capacity, size_t* out_length,
    unsigned char out_last[32], bool* out_more) {
    assert(store == (qihse_kv_store_t*)(uintptr_t)1 && user == fixture.service);
    assert(!strcmp(lane, lane_id));
    size_t size = sizeof(fixture.certificate);
    assert(capacity >= size + 36u);
    *out_length = 0; *out_more = false;
    memset(out_last, 0, 32u);
    if (memcmp(after, (unsigned char[32]){0}, 32u)) return true;
    unsigned char* p = buffer;
    p[0] = (unsigned char)(size >> 24u); p[1] = (unsigned char)(size >> 16u);
    p[2] = (unsigned char)(size >> 8u); p[3] = (unsigned char)size;
    memcpy(p + 4u, fixture.certificate_digest, 32u);
    memcpy(p + 36u, &fixture.certificate, size);
    memcpy(out_last, fixture.certificate_digest, 32u);
    *out_length = size + 36u;
    return true;
}

bool qihse_cluster_bus_ct1_certificate_verify(qihse_cluster_bus_t* bus,
    const void* bytes, size_t length,
    qihse_cluster_bus_ct1_promotion_update_v2_t* out, qihse_uuid_t* signer) {
    assert(bus == (qihse_cluster_bus_t*)(uintptr_t)2);
    if (length != sizeof(*out)) return false;
    memcpy(out, bytes, length); memset(signer, 0, sizeof(*signer));
    return true;
}
bool qihse_cluster_bus_ct1_promotion_seal(qihse_cluster_bus_ct1_promotion_update_t* update) {
    assert(update); return true;
}
bool qihse_cluster_bus_ct1_promotion_v2_seal(qihse_cluster_bus_ct1_promotion_update_v2_t* update) {
    assert(update); memcpy(update->event_digest, event_digest, 32u); return true;
}
bool qihse_cluster_bus_ct1_promotion_certificate_create(qihse_cluster_bus_t* bus,
    const qihse_cluster_bus_ct1_promotion_update_v2_t* update,
    uint8_t** out, size_t* out_length) {
    (void)bus; (void)update; (void)out; (void)out_length;
    fixture.signatures++;
    assert(!"a COMMITTED retry must reuse the existing signed certificate");
    return false;
}
void qihse_cluster_bus_ct1_certificate_free(void* envelope, size_t length) {
    (void)length; free(envelope);
}
bool qihse_cluster_bus_relay_ct1_certificate(qihse_cluster_bus_t* bus,
    const void* bytes, size_t length) {
    assert(bus == (qihse_cluster_bus_t*)(uintptr_t)2 && bytes && length);
    return true;
}

static bool peer_id(void* context, const char* topology,
    char out[QIHSE_KV_CT_ID_MAX + 1u]) {
    (void)context;
    for (size_t i = 0; i < 3u; ++i) if (!strcmp(topology, topology_ids[i])) {
        strcpy(out, qkp_ids[i]); return true;
    }
    return false;
}

static bool read_claim(void* context, qihse_user_t* user,
    const qihse_cluster_ownership_txn_t* txn,
    qihse_kv_ct_lane_authority_claim_t* out) {
    (void)context;
    assert(user == fixture.op && !strcmp(txn->transfer_id, fixture.committed.transfer_id));
    *out = fixture.marker;
    memset(out->image_digest, 0, 32u);
    memset(out->certificate_head_digest, 0, 32u);
    if (fixture.common_final) {
        out->final_decision_index = 19u;
        memset(out->final_decision_digest, 19, 32u);
    }
    return true;
}

bool qihse_cluster_ownership_promotion_reserve(qihse_cluster_ownership_context_t* ownership,
    qihse_cluster_ownership_txn_t* txn,
    qihse_kv_ct_lane_authority_claim_t* claim, qihse_kv_ct_proof_t** proof,
    char* error, size_t cap) {
    (void)error; (void)cap;
    fixture.reserves++;
    assert(!fixture.common_final && txn->phase == QIHSE_OWNERSHIP_COMMITTED);
    *claim = fixture.marker;
    *proof = qihse_kv_ct_lane_authority_proof_create(ownership->store,
        ownership->principal, ownership->data_principal, claim,
        /* The real producer's adapter is not public; the double proves its
         * own bound reservation before returning an opaque storage token. */
        NULL, NULL);
    /* This path never introspects the reservation token after a lane is
     * already SOURCE. Supply a distinct owned token for destroy(). */
    *proof = malloc(sizeof(**proof)); assert(*proof); (*proof)->claim = *claim;
    return true;
}

static bool reserve_unused(void* context, qihse_user_t* user,
    qihse_cluster_ownership_txn_t* txn, char* error, size_t cap) {
    (void)context; (void)user; (void)txn; (void)error; (void)cap;
    assert(!"high-level reserve double owns the reserved test path"); return false;
}
static bool finalize_unused(void* context, qihse_user_t* user,
    const qihse_cluster_ownership_txn_t* txn, const qihse_kv_ct_proof_t* proof,
    const uint8_t event[32], char* error, size_t cap) {
    (void)context; (void)user; (void)txn; (void)proof; (void)event; (void)error; (void)cap;
    assert(!"test must stop before new FINAL proposal"); return false;
}
static bool successor_prepare(void* context, uint16_t index,
    const qihse_kv_ct_lane_authority_claim_t* claim, char* error, size_t cap) {
    (void)context; (void)error; (void)cap;
    assert(index == 2u && !fixture.common_final && claim->final_decision_index == 0u);
    fixture.prepares++;
    return false; /* Lost/refused prepare reply leaves the same COMMITTED ID. */
}
static bool refresh(void* context, qihse_user_t* user,
    const uint8_t slots[QIHSE_KV_CT_SLOT_BITMAP_BYTES], char* error, size_t cap) {
    (void)context; (void)error; (void)cap;
    assert(user == fixture.op && !memcmp(slots, fixture.committed.slot_bitmap,
        sizeof(fixture.committed.slot_bitmap)));
    fixture.refreshes++; return true;
}

typedef struct { unsigned total, committed, finalized; } journal_count_t;
static bool count_journal(const qihse_cluster_ownership_txn_t* txn, void* opaque) {
    journal_count_t* count = opaque;
    count->total++;
    count->committed += txn->phase == QIHSE_OWNERSHIP_COMMITTED;
    count->finalized += txn->phase == QIHSE_OWNERSHIP_FINALIZED;
    assert(!strcmp(txn->transfer_id, fixture.committed.transfer_id));
    return true;
}
static void assert_journal(unsigned records, unsigned terminal) {
    journal_count_t count = {0}; bool unresolved = false;
    assert(qihse_cluster_ownership_journal_replay_txn(fixture.directory,
        count_journal, &count, &unresolved) == (int)records);
    assert(count.total == records && count.committed == 1u && count.finalized == terminal);
    assert(unresolved == (terminal == 0u));
}

static void setup_committed(const char* directory, qihse_cluster_topology_t* topology) {
    snprintf(fixture.directory, sizeof(fixture.directory), "%s", directory);
    assert(mkdir(directory, 0700) == 0);
    qihse_cluster_ownership_txn_t txn = {0};
    txn.phase = QIHSE_OWNERSHIP_INTENT; txn.start = 10u; txn.end = 12u;
    txn.config_epoch = 101u; txn.source_lsn = 7u;
    strcpy(txn.transfer_id, "ct1-stable-recovery-id"); strcpy(txn.lane_id, lane_id);
    strcpy(txn.source_id, topology_ids[0]); strcpy(txn.target_id, topology_ids[1]);
    strcpy(txn.owner_id, topology_ids[2]);
    strcpy(txn.source_qkp_id, qkp_ids[0]); strcpy(txn.target_qkp_id, qkp_ids[1]);
    memset(txn.generation, 'a', 32u); memset(txn.next_generation, 'b', 32u);
    txn.slot_bitmap[1] = 0x14u; /* Two exact disjoint slots. */
    assert(qihse_cluster_ownership_journal_append_txn(directory, &txn) == 0);
    txn.phase = QIHSE_OWNERSHIP_PREPARED;
    assert(qihse_cluster_ownership_journal_append_txn(directory, &txn) == 0);
    txn.phase = QIHSE_OWNERSHIP_COMMITTED; txn.target_lsn = 17u;
    memset(txn.proof_digest, 0x22, 32u);
    assert(qihse_cluster_ownership_journal_append_txn(directory, &txn) == 0);
    fixture.committed = txn;
    fixture.marker = (qihse_kv_ct_lane_authority_claim_t){0};
    fixture.marker.operation = QIHSE_KV_CT_LANE_AUTH_PROMOTION;
    strcpy(fixture.marker.transfer_id, txn.transfer_id);
    strcpy(fixture.marker.source_group_id, lane_id); strcpy(fixture.marker.target_group_id, lane_id);
    strcpy(fixture.marker.source_qkp_id, qkp_ids[0]); strcpy(fixture.marker.target_qkp_id, qkp_ids[1]);
    strcpy(fixture.marker.successor_qkp_id, qkp_ids[2]);
    strcpy(fixture.marker.source_generation, txn.generation);
    strcpy(fixture.marker.target_generation, txn.next_generation);
    fixture.marker.grant_epoch = txn.config_epoch; fixture.marker.reserve_index = 17u;
    memset(fixture.marker.reserve_digest, 3, 32u);
    fixture.marker.source_cut = txn.source_lsn; fixture.marker.target_cursor = txn.target_lsn;
    memcpy(fixture.marker.slots, txn.slot_bitmap, sizeof(txn.slot_bitmap));
    memset(fixture.marker.range_digest, 0x44, 32u); memset(fixture.marker.image_digest, 0x55, 32u);
    memcpy(fixture.marker.promotion_event_digest, event_digest, 32u);
    fixture.certificate = (qihse_cluster_bus_ct1_promotion_update_v2_t){0};
    strcpy(fixture.certificate.lane_id, lane_id);
    memcpy(fixture.certificate.event_digest, event_digest, 32u);
    assert(hash(&fixture.certificate, sizeof(fixture.certificate), fixture.certificate_digest));
    memcpy(fixture.marker.certificate_head_digest, fixture.certificate_digest, 32u);
    fixture.lane = (qihse_kv_ct_lane_status_t){0};
    strcpy(fixture.lane.lane_id, lane_id); strcpy(fixture.lane.source_id, qkp_ids[1]);
    strcpy(fixture.lane.peer_id, qkp_ids[2]); strcpy(fixture.lane.generation, txn.next_generation);
    fixture.lane.mode = QIHSE_KV_CT_LANE_SOURCE;
    fixture.lane.promotion_pending = true; fixture.lane.admitted = true;
    fixture.lane.baseline_sealed = true; fixture.lane.baseline_row_seq = 17u;
    memcpy(fixture.lane.slot_bitmap, txn.slot_bitmap, sizeof(txn.slot_bitmap));
    fixture.marker_available = true;
    assert(qihse_cluster_topology_set_node_health(topology, 0u, false));
    assert(qihse_cluster_topology_set_node_health(topology, 2u, true));
}

int main(void) {
    char root[] = "./ct_lane_promotion_recovery_XXXXXX";
    assert(mkdtemp(root));
    assert(setenv("QIHSE_DATA_DIR", root, 1) == 0);
    assert(setenv("QIHSE_FIPS_MODE", "disabled", 1) == 0);
    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator("PromotionRecoveryOperator42!"));
    fixture.op = qihse_auth_authenticate_id(0u, "PromotionRecoveryOperator42!");
    fixture.service = qihse_auth_create_user(fixture.op, 919u, QIHSE_ROLE_GUEST,
        5u, 1u, "PromotionRecoveryService42!", false);
    qihse_user_t* low = qihse_auth_create_user(fixture.op, 920u, QIHSE_ROLE_GUEST,
        0u, 0u, "PromotionRecoveryLow42!", false);
    assert(fixture.op && fixture.service && low);
    qihse_cluster_topology_t* topology = qihse_cluster_topology_create();
    assert(topology);
    for (size_t i = 0; i < 3u; ++i) {
        qihse_cluster_node_t node = {0}; uint16_t index = UINT16_MAX;
        char seed[32]; snprintf(seed, sizeof(seed), "promotion-recovery-%zu", i);
        qihse_cluster_node_id_from_seed(seed, strlen(seed), node.id);
        strcpy(topology_ids[i], node.id); strcpy(node.host, "127.0.0.1");
        node.port = (uint16_t)(17100u + i); node.bus_port = (uint16_t)(27100u + i);
        node.role = QIHSE_CLUSTER_NODE_PRIMARY; node.primary_index = QIHSE_CLUSTER_NODE_NONE;
        node.healthy = true;
        assert(qihse_cluster_topology_upsert_node(topology, &node, &index) && index == i);
    }
    assert(qihse_cluster_topology_set_local_node(topology, 1u));
    char directory[512]; snprintf(directory, sizeof(directory), "%s/journal", root);
    setup_committed(directory, topology);
    qihse_cluster_ownership_context_t ownership = {.store = (void*)(uintptr_t)1,
        .bus = (void*)(uintptr_t)2, .topology = topology,
        .principal = fixture.op, .data_principal = fixture.service,
        .peer_id = peer_id, .lane_claim = read_claim, .lane_verify_claim = verify_claim,
        .range_reserve = reserve_unused, .range_finalize_promotion = finalize_unused,
        .range_refresh = refresh, .promotion_successor_prepare = successor_prepare};
    char error[256]; bool pending = false;
    ownership.principal = low;
    unsigned calls = fixture.status_calls;
    assert(!qihse_cluster_failover_promote_lane(&ownership, lane_id, 2u,
        &pending, error, sizeof(error)) && !pending && fixture.status_calls == calls);
    ownership.principal = fixture.op;

    /* COMMITTED with an unconfirmed prepare reply must resume the same ID,
     * not append COMMITTED a second time (which the real journal rejects). */
    for (unsigned attempt = 0; attempt < 2u; ++attempt) {
        assert(!qihse_cluster_failover_promote_lane(&ownership, lane_id, 2u,
            &pending, error, sizeof(error)) && pending);
        assert(fixture.prepares == attempt + 1u && fixture.signatures == 0u);
        assert_journal(3u, 0u);
    }

    /* FINAL is irreversible even if the old source has returned and the
     * recorded successor is currently unhealthy. Neither is a new election. */
    fixture.common_final = true; fixture.fail_finalize = true;
    assert(qihse_cluster_topology_set_node_health(topology, 0u, true));
    assert(qihse_cluster_topology_set_node_health(topology, 2u, false));
    assert(!qihse_cluster_failover_promote_lane(&ownership, lane_id, 2u,
        &pending, error, sizeof(error)) && pending);
    assert(fixture.prepares == 2u && fixture.reserves == 2u && fixture.finalizes == 1u);
    assert_journal(3u, 0u);
    fixture.fail_finalize = false;
    assert(qihse_cluster_failover_promote_lane(&ownership, lane_id, 2u,
        &pending, error, sizeof(error)) && !pending);
    assert(!fixture.lane.promotion_pending && fixture.prepares == 2u && fixture.reserves == 2u);
    assert_journal(4u, 1u);
    assert(qihse_cluster_failover_promote_lane(&ownership, lane_id, 2u,
        &pending, error, sizeof(error)) && !pending);
    assert_journal(4u, 1u);
    puts("PASS CT lane promotion recovery: real journal retries, committed FINAL recovery, stale-health independence and low-principal denial");
    qihse_cluster_topology_destroy(topology);
    return 0;
}
