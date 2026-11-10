#include "qihse_cluster_range_authority.h"
#include "qihse_resp_wire.h"
#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

/* The mesh's partition/restart tests exercise its durable state machine.
 * This fixture isolates the adapter: real principals, typed receipt checks,
 * immutable retries and correct binding of ownership evidence. */
struct qihse_cluster_ct_activation_receipt { bool valid; };
struct qihse_kv_ct_proof {
    qihse_kv_ct_lane_authority_claim_t claim;
    bool valid;
};
static qihse_kv_ct_lane_authority_claim_t ready_claim;
static bool marker_present;
static qihse_consensus_range_request_t saved;
static qihse_consensus_range_phase_t phase;
static uint8_t evidence[32];
static unsigned state_calls, reserve_calls, finalize_calls, resolve_calls;
static unsigned abort_calls;
static bool resolver_available = true;
static qihse_cluster_ownership_txn_t local_abort;
static uint16_t local_node_index = 1;
static uint16_t common_owner[16384], cached_owner[16384];
static uint64_t common_epoch[16384], cached_epoch[16384];
static bool bad_common_pin;
static unsigned adopted;
static const char source_generation[] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

bool qihse_consensus_mesh_range_genesis_user(qihse_consensus_mesh_t* mesh,
    const qihse_user_t* principal, const qihse_consensus_range_slot_t slots[16384],
    uint32_t timeout, uint64_t* index, uint8_t digest[32]) {
    assert(mesh && principal && slots && timeout);
    *index = 1; memset(digest, 1, 32); return true;
}

bool qihse_consensus_mesh_range_state_user(qihse_consensus_mesh_t* mesh,
    const qihse_user_t* principal, const uint8_t bitmap[2048], uint32_t timeout,
    qihse_consensus_range_slot_t slots[16384], uint8_t digest[32], uint64_t* index) {
    assert(mesh && principal && timeout);
    state_calls++;
    for (unsigned s = 0; s < 16384; ++s) if (bitmap[s / 8] & (1u << (s % 8))) {
        slots[s].slot = (uint16_t)s;
        uint16_t owner = common_owner[s] ? common_owner[s] : 1;
        strcpy(slots[s].owner_topology_id, owner == 1 ? "node-a" : owner == 2 ? "node-b" : "node-c");
        strcpy(slots[s].owner_qkp_id, owner == 1 ? "qkp-a" : owner == 2 ? "qkp-b" : "qkp-c");
        if (bad_common_pin && s == 11) strcpy(slots[s].owner_qkp_id, "untrusted-pin");
        memset(slots[s].group_id, '1', 64);
        slots[s].epoch = common_epoch[s] ? common_epoch[s] : 100;
    }
    memset(digest, 2, 32); *index = 1; return true;
}

bool qihse_consensus_mesh_range_reserve_user(qihse_consensus_mesh_t* mesh,
    const qihse_user_t* principal, const qihse_consensus_range_request_t* request,
    uint32_t timeout, qihse_consensus_range_grant_t* grant) {
    assert(mesh && principal && timeout);
    reserve_calls++;
    if (phase != QIHSE_RANGE_PHASE_NONE) return false;
    saved = *request; phase = QIHSE_RANGE_PHASE_RESERVED;
    grant->reserve_index = 17; grant->grant_epoch = 101;
    memset(grant->reserve_digest, 3, 32); return true;
}

bool qihse_consensus_mesh_range_lookup_user(qihse_consensus_mesh_t* mesh,
    const qihse_user_t* principal, const char* id,
    qihse_consensus_range_request_t* request, qihse_consensus_range_grant_t* grant,
    qihse_consensus_range_decision_t* decision, qihse_consensus_range_phase_t* out_phase) {
    assert(mesh && principal);
    if (!phase || strcmp(id, saved.transfer_id)) return false;
    *request = saved; *out_phase = phase;
    grant->reserve_index = 17; grant->grant_epoch = 101;
    memset(grant->reserve_digest, 3, 32);
    if (phase == QIHSE_RANGE_PHASE_FINALIZED || phase == QIHSE_RANGE_PHASE_ABORTED) {
        unsigned terminal = phase == QIHSE_RANGE_PHASE_FINALIZED ? 18u : 19u;
        decision->decision_index = terminal; decision->grant_epoch = 101;
        memset(decision->decision_digest, terminal, 32);
        memcpy(decision->evidence_digest, evidence, 32);
    }
    return true;
}

bool qihse_consensus_mesh_range_finalize_user(qihse_consensus_mesh_t* mesh,
    const qihse_user_t* principal, const qihse_consensus_range_request_t* request,
    const qihse_consensus_range_grant_t* grant, const uint8_t digest[32],
    uint32_t timeout, qihse_consensus_range_decision_t* decision) {
    assert(mesh && principal && timeout && request && grant->reserve_index == 17);
    finalize_calls++; phase = QIHSE_RANGE_PHASE_FINALIZED;
    memcpy(evidence, digest, 32);
    decision->decision_index = 18; decision->grant_epoch = 101;
    memset(decision->decision_digest, 18, 32);
    memcpy(decision->evidence_digest, digest, 32); return true;
}

bool qihse_consensus_mesh_range_abort_user(qihse_consensus_mesh_t* mesh,
    const qihse_user_t* principal, const qihse_consensus_range_request_t* request,
    const qihse_consensus_range_grant_t* grant, const uint8_t digest[32],
    uint32_t timeout, qihse_consensus_range_decision_t* decision) {
    assert(mesh && principal && timeout && request && grant->reserve_index == 17);
    abort_calls++; phase = QIHSE_RANGE_PHASE_ABORTED;
    memcpy(evidence, digest, 32);
    decision->decision_index = 19; decision->grant_epoch = 101;
    memset(decision->decision_digest, 19, 32);
    memcpy(decision->evidence_digest, digest, 32); return true;
}

bool qihse_cluster_ownership_transfer_get_aborted(qihse_cluster_ownership_context_t* ctx,
    const char* id, qihse_cluster_ownership_txn_t* out, char* err, size_t cap) {
    (void)err; (void)cap;
    assert(ctx && ctx->principal);
    if (local_abort.phase != QIHSE_OWNERSHIP_ABORTED ||
        strcmp(id, local_abort.transfer_id)) return false;
    *out = local_abort; return true;
}

bool qihse_cluster_topology_find_node(const qihse_cluster_topology_t* topology,
    const char* id, uint16_t* out) {
    assert(topology);
    if (!strcmp(id, "node-a")) *out = 1;
    else if (!strcmp(id, "node-b")) *out = 2;
    else if (!strcmp(id, "node-c")) *out = 3;
    else return false;
    return true;
}
bool qihse_cluster_topology_get_slot(const qihse_cluster_topology_t* t, uint16_t slot,
    uint16_t* owner, qihse_cluster_slot_state_t* state, uint16_t* peer) {
    assert(t && slot < 16384);
    if (owner) *owner = cached_owner[slot];
    if (state) *state = QIHSE_CLUSTER_SLOT_STABLE;
    if (peer) *peer = QIHSE_CLUSTER_NODE_NONE;
    return true;
}
bool qihse_cluster_topology_get_slot_epoch(const qihse_cluster_topology_t* t,
    uint16_t slot, uint64_t* epoch) {
    assert(t && slot < 16384 && epoch); *epoch = cached_epoch[slot]; return true;
}
bool qihse_cluster_topology_adopt_range(qihse_cluster_topology_t* t,
    uint16_t first, uint16_t last, uint16_t owner, uint64_t epoch) {
    assert(t && first <= last && last < 16384); adopted++;
    for (unsigned s = first; s <= last; ++s) {
        if (cached_epoch[s] == epoch && cached_owner[s] != owner) return false;
        if (cached_epoch[s] >= epoch) continue;
        cached_epoch[s] = epoch; cached_owner[s] = owner;
    }
    return true;
}
uint16_t qihse_cluster_topology_local_node(const qihse_cluster_topology_t* topology) {
    assert(topology); return local_node_index;
}
static bool peer_id(void* ctx, const char* node, char out[65]) {
    (void)ctx;
    if (!strcmp(node, "node-a")) strcpy(out, "qkp-a");
    else if (!strcmp(node, "node-b")) strcpy(out, "qkp-b");
    else if (!strcmp(node, "node-c")) strcpy(out, "qkp-c");
    else return false;
    return true;
}

bool qihse_kv_ct_lane_transfer_checksum(const qihse_kv_ct_lane_authority_claim_t* c,
    uint8_t out[32]) {
    if (!c->range_digest[0] || !c->image_digest[0]) return false;
    memset(out, c->range_digest[0] == 11 && c->image_digest[0] == 12 ? 7 : 8, 32);
    return true;
}

bool qihse_cluster_ownership_promotion_event_digest(
    qihse_cluster_ownership_context_t* ctx, const qihse_cluster_ownership_txn_t* t,
    uint8_t out[32]) {
    assert(ctx && t->next_generation[0]);
    memset(out, (unsigned char)(t->proof_digest[0] ^ t->source_lsn ^ t->next_generation[0]), 32);
    return true;
}

bool qihse_kv_ct_lane_authority_proof_fields(qihse_kv_store_t* store,
    qihse_user_t* control, qihse_user_t* data, const qihse_kv_ct_proof_t* p,
    qihse_kv_ct_lane_authority_claim_t* out) {
    assert(store && control && data);
    if (!p || !p->valid) return false;
    *out = p->claim; return true;
}

qihse_kv_ct_proof_t* qihse_kv_ct_lane_promoted_proof_get(qihse_kv_store_t* store,
    qihse_user_t* control, qihse_user_t* data, const char* group,
    const uint8_t event[32], qihse_kv_ct_lane_authority_verify_fn verify, void* ctx) {
    assert(store && control && data && group);
    if (!marker_present || strcmp(group, ready_claim.target_group_id) ||
        memcmp(event, ready_claim.promotion_event_digest, 32) ||
        !verify(ctx, &ready_claim, false)) return NULL;
    qihse_kv_ct_proof_t* p = calloc(1, sizeof(*p)); assert(p);
    p->claim = ready_claim; p->valid = true; return p;
}
void qihse_kv_ct_proof_destroy(qihse_kv_ct_proof_t* p) { free(p); }

bool qihse_resp_ct_activation_receipt_validate(
    const qihse_cluster_ct_activation_receipt_t* receipt,
    const char* transfer, const char* source, const char* target,
    const char* source_qkp, const char* target_qkp, const char* generation,
    uint16_t first, uint16_t last, uint64_t source_lsn, uint64_t epoch,
    uint64_t* target_lsn, unsigned char checksum[32]) {
    assert(!strcmp(transfer, "transfer-1") && !strcmp(source, "node-a") &&
        !strcmp(target, "node-b") && !strcmp(source_qkp, "qkp-a") &&
        !strcmp(target_qkp, "qkp-b") && !strcmp(generation, source_generation) &&
        first == 10 && last == 12 && source_lsn == 4 && epoch == 101);
    *target_lsn = 6; memset(checksum, 7, 32);
    return receipt && receipt->valid;
}

static bool resolve(void* ctx, const qihse_user_t* principal,
    const char* node, const uint8_t slots[2048], qihse_cluster_range_group_role_t role,
    char group[65], char generation[33]) {
    (void)ctx; assert(principal && (slots[1] & 0x1cu) == 0x1cu);
    resolve_calls++;
    assert(role == (!strcmp(node, "node-a") ? QIHSE_CLUSTER_RANGE_SOURCE_GROUP :
        QIHSE_CLUSTER_RANGE_TARGET_GROUP));
    if (!resolver_available) return false;
    memset(group, !strcmp(node, "node-a") ? '1' : '2', 64);
    group[64] = 0;
    memset(generation, !strcmp(node, "node-a") ? 'a' : 'b', 32);
    generation[32] = 0; return true;
}

static bool successor(void* ctx, const qihse_user_t* principal,
    const char* group, char topology[41], char qkp[65]) {
    (void)ctx; assert(principal && group[0] == '2');
    strcpy(topology, "node-c"); strcpy(qkp, "qkp-c"); return true;
}

int main(void) {
    assert(mkdir("build", 0700) == 0 || errno == EEXIST);
    char directory[] = "build/range-authority-adapter-XXXXXX";
    assert(mkdtemp(directory));
    assert(!setenv("QIHSE_DATA_DIR", directory, 1));
    assert(!setenv("QIHSE_AUTH_STATE_DIR", directory, 1));
    assert(!setenv("QIHSE_AUDIT_DIR", directory, 1));
    assert(qihse_auth_init());
    qihse_user_t* op = qihse_auth_get_user(0);
    assert(op);
    qihse_user_t* low = qihse_auth_create_user(op, 63991, QIHSE_ROLE_ANALYST,
        0, 0, "RangeAdapterAnalyst1!", false);
    assert(low);
    qihse_cluster_range_authority_t a = {0};
    a.mesh = (qihse_consensus_mesh_t*)(uintptr_t)1; a.resolve_group = resolve;
    a.resolve_successor = successor;
    qihse_cluster_ownership_txn_t transaction = {0};
    strcpy(transaction.transfer_id, "transfer-1");
    strcpy(transaction.source_id, "node-a"); strcpy(transaction.target_id, "node-b");
    strcpy(transaction.source_qkp_id, "qkp-a"); strcpy(transaction.target_qkp_id, "qkp-b");
    strcpy(transaction.generation, source_generation);
    transaction.start = 10; transaction.end = 12;
    assert(!qihse_cluster_range_authority_reserve(&a, NULL, &transaction, NULL, 0));
    assert(!qihse_cluster_range_authority_reserve(&a, low, &transaction, NULL, 0));
    assert(!state_calls && !reserve_calls && !resolve_calls);
    assert(qihse_cluster_range_authority_reserve(&a, op, &transaction, NULL, 0));
    assert(transaction.config_epoch == 101 && reserve_calls == 1 && state_calls == 1);
    unsigned resolutions = resolve_calls;
    resolver_available = false;
    assert(qihse_cluster_range_authority_reserve(&a, op, &transaction, NULL, 0));
    assert(resolve_calls == resolutions && state_calls == 1 && reserve_calls == 1);
    assert(qihse_cluster_range_authority_check_reserved(&a, op, &transaction, NULL, 0));
    qihse_kv_ct_lane_authority_claim_t reserved_claim;
    qihse_cluster_range_verifier_t reserved_verifier = {.authority = &a, .principal = op};
    assert(qihse_cluster_range_authority_claim(&a, op, &transaction, &reserved_claim));
    assert(qihse_cluster_range_authority_verify_reservation_claim(&reserved_verifier,
        &reserved_claim, false));
    assert(!qihse_cluster_range_authority_verify_reservation_claim(&reserved_verifier,
        &reserved_claim, true));
    transaction.source_lsn = 4; transaction.target_lsn = 6;
    memset(transaction.proof_digest, 7, 32);
    qihse_cluster_ct_activation_receipt_t receipt = {.valid = false};
    assert(!qihse_cluster_range_authority_finalize(&a, op, &transaction, &receipt, NULL, 0));
    assert(!finalize_calls);
    receipt.valid = true;
    assert(!qihse_cluster_range_authority_finalize(&a, low, &transaction, &receipt, NULL, 0));
    assert(!finalize_calls);
    assert(qihse_cluster_range_authority_finalize(&a, op, &transaction, &receipt, NULL, 0));
    assert(finalize_calls == 1);
    assert(!qihse_cluster_range_authority_verify_reservation_claim(&reserved_verifier,
        &reserved_claim, false)); /* finalized reservations cannot reset a receiver */
    assert(qihse_cluster_range_authority_check_finalized(&a, op, &transaction, NULL, 0));
    qihse_kv_ct_lane_authority_claim_t claim;
    assert(qihse_cluster_range_authority_claim(&a, op, &transaction, &claim));
    memset(claim.range_digest, 11, 32); memset(claim.image_digest, 12, 32);
    qihse_cluster_range_verifier_t verifier = {.authority = &a, .principal = op};
    assert(qihse_cluster_range_authority_verify_claim(&verifier, &claim, true));
    verifier.principal = low;
    assert(!qihse_cluster_range_authority_verify_claim(&verifier, &claim, false));
    verifier.principal = op;
    claim.image_digest[0]++;
    assert(!qihse_cluster_range_authority_verify_claim(&verifier, &claim, true));
    claim.image_digest[0]--;
    claim.source_cut++;
    assert(!qihse_cluster_range_authority_verify_claim(&verifier, &claim, true));
    claim.source_cut--;
    claim.final_decision_index++;
    assert(!qihse_cluster_range_authority_verify_claim(&verifier, &claim, true));
    claim.final_decision_index--;
    strcpy(claim.successor_qkp_id, "wrong-successor");
    assert(!qihse_cluster_range_authority_verify_claim(&verifier, &claim, false));
    transaction.target_lsn++;
    assert(!qihse_cluster_range_authority_check_finalized(&a, op, &transaction, NULL, 0));
    transaction.target_lsn--;
    transaction.end++;
    assert(!qihse_cluster_range_authority_check_reserved(&a, op, &transaction, NULL, 0));
    transaction.end--;
    qihse_cluster_ownership_context_t ownership = {0};
    ownership.topology = (qihse_cluster_topology_t*)(uintptr_t)2;
    ownership.peer_id = peer_id;
    a.local_ownership = &ownership;
    phase = QIHSE_RANGE_PHASE_RESERVED;
    transaction.phase = QIHSE_OWNERSHIP_ABORTED;
    transaction.target_lsn = 0; memset(transaction.proof_digest, 0, 32);
    local_abort = transaction;
    assert(!qihse_cluster_range_authority_abort(&a, low, &transaction, NULL, 0));
    assert(!abort_calls);
    local_abort.phase = QIHSE_OWNERSHIP_COMMITTED;
    assert(!qihse_cluster_range_authority_abort(&a, op, &transaction, NULL, 0));
    assert(!abort_calls);
    local_abort.phase = QIHSE_OWNERSHIP_ABORTED;
    local_node_index = 2;
    assert(!qihse_cluster_range_authority_abort(&a, op, &transaction, NULL, 0));
    assert(!abort_calls);
    local_node_index = 1;
    assert(qihse_cluster_range_authority_abort(&a, op, &transaction, NULL, 0));
    assert(abort_calls == 1 && phase == QIHSE_RANGE_PHASE_ABORTED);
    assert(qihse_cluster_range_authority_claim(&a, op, &transaction, &claim));
    assert(!qihse_cluster_range_authority_verify_claim(&verifier, &claim, false));
    assert(qihse_cluster_range_authority_verify_aborted_claim(&verifier, &claim, true));
    verifier.principal = low;
    assert(!qihse_cluster_range_authority_verify_aborted_claim(&verifier, &claim, false));
    verifier.principal = op;
    claim.source_cut++;
    assert(!qihse_cluster_range_authority_verify_aborted_claim(&verifier, &claim, true));
    claim.source_cut--;
    claim.final_decision_digest[0]++;
    assert(!qihse_cluster_range_authority_verify_aborted_claim(&verifier, &claim, true));
    claim.final_decision_digest[0]--;
    phase = QIHSE_RANGE_PHASE_FINALIZED;
    assert(!qihse_cluster_range_authority_verify_aborted_claim(&verifier, &claim, true));
    phase = QIHSE_RANGE_PHASE_ABORTED;
    assert(!qihse_cluster_range_authority_reserve(&a, op, &transaction, NULL, 0));
    /* A receiver can reserve promotion while the old source/resolver is down.
     * The sparse bitmap and old stream cursor remain exact authority inputs. */
    phase = QIHSE_RANGE_PHASE_NONE;
    transaction.phase = QIHSE_OWNERSHIP_PREPARED; transaction.config_epoch = 0;
    strcpy(transaction.transfer_id, "promotion-1");
    memset(transaction.lane_id, '1', 64); transaction.lane_id[64] = 0;
    memset(transaction.next_generation, 'b', 32); transaction.next_generation[32] = 0;
    strcpy(transaction.owner_id, "node-c");
    transaction.slot_bitmap[1] = 0x14; /* slots 10 and 12, excluding 11 */
    transaction.source_lsn = 0; /* sealed empty streams are legitimate */
    memset(transaction.proof_digest, 25, 32);
    ownership.store = (qihse_kv_store_t*)(uintptr_t)3;
    ownership.principal = op; ownership.data_principal = op;
    assert(qihse_cluster_range_authority_reserve(&a, op, &transaction, NULL, 0));
    assert(saved.op == QIHSE_RANGE_OP_PROMOTION && saved.durable_cursor == 0);
    assert(!strcmp(saved.source_group_id, saved.target_group_id));
    assert(qihse_cluster_range_authority_claim(&a, op, &transaction, &claim));
    memset(claim.image_digest, 99, 32); memset(claim.certificate_head_digest, 88, 32);
    uint8_t event[32];
    assert(qihse_cluster_ownership_promotion_event_digest(&ownership, &transaction, event));
    memcpy(claim.promotion_event_digest, event, 32);
    qihse_kv_ct_proof_t proposed = {.claim = claim, .valid = true};
    /* A valid generic reservation proof cannot substitute for a durable ready marker. */
    unsigned completed = finalize_calls;
    assert(!qihse_cluster_range_authority_finalize_promotion(&a, op, &transaction,
        &proposed, event, NULL, 0));
    assert(finalize_calls == completed);
    ready_claim = claim; marker_present = true;
    ready_claim.certificate_head_digest[0]++;
    assert(!qihse_cluster_range_authority_finalize_promotion(&a, op, &transaction,
        &proposed, event, NULL, 0));
    assert(finalize_calls == completed);
    ready_claim = claim;
    assert(qihse_cluster_range_authority_finalize_promotion(&a, op, &transaction,
        &proposed, event, NULL, 0));
    assert(finalize_calls == completed + 1);
    assert(qihse_cluster_range_authority_check_finalized(&a, op, &transaction, NULL, 0));
    assert(qihse_cluster_range_authority_claim(&a, op, &transaction, &claim));
    /* An observer verifies the committed event without reading the promoted
     * node's private baseline/certificate marker. This cannot create the
     * producer's durable-readiness proof, tested separately above. */
    assert(!memcmp(claim.promotion_event_digest, event, 32));
    assert(qihse_cluster_range_authority_verify_claim(&verifier, &claim, true));
    memcpy(claim.image_digest, ready_claim.image_digest, 32);
    memcpy(claim.certificate_head_digest, ready_claim.certificate_head_digest, 32);
    memcpy(claim.promotion_event_digest, event, 32);
    assert(qihse_cluster_range_authority_verify_claim(&verifier, &claim, true));
    claim.source_cut++;
    assert(!qihse_cluster_range_authority_verify_claim(&verifier, &claim, true));
    transaction.slot_bitmap[1] |= 8;
    assert(!qihse_cluster_range_authority_check_reserved(&a, op, &transaction, NULL, 0));
    uint8_t selected[2048] = {0}; selected[1] = 0x1c;
    for (unsigned s = 10; s <= 12; ++s) {
        common_owner[s] = 2; common_epoch[s] = 102;
        cached_owner[s] = 1; cached_epoch[s] = 100;
    }
    /* An intervening CT2 transition can change one slot independently of
     * promotion ancestry. Routing comes from the actual committed map. */
    common_owner[11] = 3; common_epoch[11] = 103;
    unsigned queried = state_calls;
    assert(!qihse_cluster_range_authority_refresh(&a, low, selected, NULL, 0));
    assert(!qihse_cluster_range_authority_refresh(&a, NULL, selected, NULL, 0));
    assert(state_calls == queried && !adopted);
    bad_common_pin = true;
    assert(!qihse_cluster_range_authority_refresh(&a, op, selected, NULL, 0));
    assert(!adopted && cached_owner[10] == 1); /* validate whole map before adoption */
    bad_common_pin = false;
    assert(qihse_cluster_range_authority_refresh(&a, op, selected, NULL, 0));
    assert(cached_owner[10] == 2 && cached_owner[11] == 3 && cached_owner[12] == 2);
    assert(cached_epoch[11] == 103);
    common_owner[11] = 2; common_epoch[11] = 101;
    assert(qihse_cluster_range_authority_refresh(&a, op, selected, NULL, 0));
    assert(cached_owner[11] == 3 && cached_epoch[11] == 103); /* no rollback */
    common_owner[11] = 2; common_epoch[11] = 103;
    assert(!qihse_cluster_range_authority_refresh(&a, op, selected, NULL, 0));
    assert(cached_owner[11] == 3); /* equal-epoch conflicting authority diagnosed */
    puts("PASS range authority adapter: scoped claims, immutable retry, typed activation and durable promotion binding");
    return 0;
}
