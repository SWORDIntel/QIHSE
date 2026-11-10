#include "qihse_cluster_range_authority.h"
#include "qihse_resp_wire.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static bool fail(char* error, size_t cap, const char* message) {
    if (error && cap) snprintf(error, cap, "%s", message);
    return false;
}

static bool operator_active(const qihse_user_t* principal) {
    return principal && qihse_auth_user_is_active(principal) &&
        qihse_user_get_role(principal) == QIHSE_ROLE_OPERATOR &&
        qihse_user_get_tenant_id(principal) == QIHSE_TENANT_SYSTEM;
}

static uint32_t budget(const qihse_cluster_range_authority_t* a) {
    return a->timeout_ms ? a->timeout_ms : 2000u;
}

static bool text_valid(const char* value, size_t cap) {
    return value && value[0] && strnlen(value, cap) < cap;
}

static bool hex_valid(const char* value, size_t length) {
    if (!value || strnlen(value, length + 1u) != length) return false;
    for (size_t i = 0; i < length; ++i)
        if (!((value[i] >= '0' && value[i] <= '9') ||
              (value[i] >= 'a' && value[i] <= 'f'))) return false;
    return true;
}

static bool bitmap_for(const qihse_cluster_ownership_txn_t* t,
                       uint8_t out[QIHSE_CONSENSUS_RANGE_BITMAP_BYTES]) {
    memset(out, 0, QIHSE_CONSENSUS_RANGE_BITMAP_BYTES);
    if (!t || t->start > t->end ||
        t->end >= QIHSE_CONSENSUS_RANGE_SLOT_COUNT ||
        !text_valid(t->transfer_id, sizeof(t->transfer_id)) ||
        !text_valid(t->source_id, sizeof(t->source_id)) ||
        !text_valid(t->target_id, sizeof(t->target_id)) ||
        !text_valid(t->source_qkp_id, sizeof(t->source_qkp_id)) ||
        !text_valid(t->target_qkp_id, sizeof(t->target_qkp_id)) ||
        !hex_valid(t->generation, 32u)) return false;
    if (t->next_generation[0]) {
        if (!hex_valid(t->lane_id, 64u) || !hex_valid(t->next_generation, 32u) ||
            !strcmp(t->generation, t->next_generation) ||
            !text_valid(t->owner_id, sizeof(t->owner_id))) return false;
        memcpy(out, t->slot_bitmap, QIHSE_CONSENSUS_RANGE_BITMAP_BYTES);
        bool present = false;
        for (uint32_t s = 0; s < QIHSE_CONSENSUS_RANGE_SLOT_COUNT; ++s) {
            if (!(out[s / 8u] & (1u << (s % 8u)))) continue;
            if (s < t->start || s > t->end) return false;
            present = true;
        }
        return present && (out[t->start / 8u] & (1u << (t->start % 8u))) &&
            (out[t->end / 8u] & (1u << (t->end % 8u)));
    }
    for (uint32_t s = t->start; s <= t->end; ++s)
        out[s / 8u] |= (uint8_t)(1u << (s % 8u));
    return true;
}

static bool request_matches(const qihse_consensus_range_request_t* r,
                             const qihse_cluster_ownership_txn_t* t) {
    uint8_t bitmap[QIHSE_CONSENSUS_RANGE_BITMAP_BYTES];
    bool promotion = t && t->next_generation[0];
    return bitmap_for(t, bitmap) &&
        r->op == (promotion ? QIHSE_RANGE_OP_PROMOTION : QIHSE_RANGE_OP_TRANSFER) &&
        !strcmp(r->transfer_id, t->transfer_id) &&
        !strcmp(r->source_topology_id, t->source_id) &&
        !strcmp(r->target_topology_id, t->target_id) &&
        !strcmp(r->source_qkp_id, t->source_qkp_id) &&
        !strcmp(r->target_qkp_id, t->target_qkp_id) &&
        !strcmp(r->source_generation, t->generation) &&
        (!t->lane_id[0] || !strcmp(r->source_group_id, t->lane_id)) &&
        (!promotion || (!strcmp(r->source_group_id, t->lane_id) &&
          !strcmp(r->target_group_id, t->lane_id) &&
          !strcmp(r->target_generation, t->next_generation) &&
          !strcmp(r->successor_topology_id, t->owner_id) &&
          r->durable_cursor == t->source_lsn)) &&
        CRYPTO_memcmp(r->slots, bitmap, sizeof(bitmap)) == 0;
}

static bool lookup(qihse_cluster_range_authority_t* a, qihse_user_t* principal,
                    const qihse_cluster_ownership_txn_t* t,
                    qihse_consensus_range_request_t* request,
                    qihse_consensus_range_grant_t* grant,
                    qihse_consensus_range_decision_t* decision,
                    qihse_consensus_range_phase_t* phase) {
    return a && a->mesh && operator_active(principal) && t &&
        qihse_consensus_mesh_range_lookup_user(a->mesh, principal,
            t->transfer_id, request, grant, decision, phase) &&
        request_matches(request, t) && grant->reserve_index &&
        grant->grant_epoch && (!t->config_epoch ||
            t->config_epoch == grant->grant_epoch);
}

bool qihse_cluster_range_authority_initialize(
    qihse_cluster_range_authority_t* a, const qihse_user_t* principal,
    const qihse_consensus_range_slot_t slots[QIHSE_CONSENSUS_RANGE_SLOT_COUNT],
    char* error, size_t cap) {
    if (!a || !a->mesh || !slots || !operator_active(principal))
        return fail(error, cap, "range authority requires an active system Operator and common group map");
    uint64_t index = 0;
    uint8_t digest[32];
    if (!qihse_consensus_mesh_range_genesis_user(a->mesh, principal,
            slots, budget(a), &index, digest) || !index)
        return fail(error, cap, "common range authority initialization is unconfirmed; retry the same group map");
    if (error && cap) error[0] = 0;
    return true;
}

bool qihse_cluster_range_authority_refresh(void* opaque,
    qihse_user_t* principal,
    const uint8_t bitmap[QIHSE_CONSENSUS_RANGE_BITMAP_BYTES],
    char* error, size_t cap) {
    qihse_cluster_range_authority_t* a = opaque;
    if (!a || !a->mesh || !a->local_ownership || !bitmap ||
        !operator_active(principal) || !a->local_ownership->topology ||
        !a->local_ownership->peer_id)
        return fail(error, cap, "active system Operator and common routing context are required");
    bool any = false;
    for (size_t i = 0; i < QIHSE_CONSENSUS_RANGE_BITMAP_BYTES; ++i) any |= bitmap[i] != 0;
    if (!any) return fail(error, cap, "routing refresh needs an explicit nonempty slot set");
    qihse_consensus_range_slot_t* state = calloc(QIHSE_CONSENSUS_RANGE_SLOT_COUNT, sizeof(*state));
    uint16_t* owners = calloc(QIHSE_CONSENSUS_RANGE_SLOT_COUNT, sizeof(*owners));
    uint8_t digest[32]; uint64_t index = 0;
    qihse_cluster_ownership_context_t* local = a->local_ownership;
    bool ok = state && owners && qihse_consensus_mesh_range_state_user(a->mesh,
        principal, bitmap, budget(a), state, digest, &index) && index != 0;
    /* Validate the complete response and pin mapping before any mutation.
     * Authority cannot be supplied as a caller-built slot map. */
    for (uint32_t s = 0; ok && s < QIHSE_CONSENSUS_RANGE_SLOT_COUNT; ++s) {
        if (!(bitmap[s / 8u] & (1u << (s % 8u)))) continue;
        char qkp[65] = {0}; uint64_t old_epoch = 0;
        uint16_t old_owner = QIHSE_CLUSTER_NODE_NONE;
        ok = state[s].slot == s && state[s].epoch &&
            text_valid(state[s].owner_topology_id, sizeof(state[s].owner_topology_id)) &&
            text_valid(state[s].owner_qkp_id, sizeof(state[s].owner_qkp_id)) &&
            hex_valid(state[s].group_id, 64) &&
            qihse_cluster_topology_find_node(local->topology,
                state[s].owner_topology_id, &owners[s]) &&
            local->peer_id(local->peer_id_context, state[s].owner_topology_id, qkp) &&
            text_valid(qkp, sizeof(qkp)) && !strcmp(qkp, state[s].owner_qkp_id) &&
            qihse_cluster_topology_get_slot(local->topology, (uint16_t)s,
                &old_owner, NULL, NULL) &&
            qihse_cluster_topology_get_slot_epoch(local->topology, (uint16_t)s, &old_epoch) &&
            (old_epoch != state[s].epoch || old_owner == owners[s]);
    }
    for (uint32_t s = 0; ok && s < QIHSE_CONSENSUS_RANGE_SLOT_COUNT;) {
        if (!(bitmap[s / 8u] & (1u << (s % 8u)))) { ++s; continue; }
        uint32_t first = s;
        uint16_t owner = owners[s]; uint64_t epoch = state[s].epoch;
        while (++s < QIHSE_CONSENSUS_RANGE_SLOT_COUNT &&
            (bitmap[s / 8u] & (1u << (s % 8u))) && owners[s] == owner && state[s].epoch == epoch) {}
        ok = operator_active(principal) && qihse_cluster_topology_adopt_range(
            local->topology, (uint16_t)first, (uint16_t)(s - 1u), owner, epoch);
    }
    free(owners); free(state);
    if (!ok) return fail(error, cap, "committed routing map or trusted pin/epoch reconciliation is unavailable");
    if (error && cap) error[0] = 0;
    return true;
}

bool qihse_cluster_range_authority_reserve(void* opaque,
    qihse_user_t* principal, qihse_cluster_ownership_txn_t* t,
    char* error, size_t cap) {
    qihse_cluster_range_authority_t* a = opaque;
    qihse_consensus_range_request_t request = {0};
    qihse_consensus_range_grant_t grant = {0};
    qihse_consensus_range_decision_t decision = {0};
    qihse_consensus_range_phase_t phase = QIHSE_RANGE_PHASE_NONE;
    if (!a || !a->mesh || !a->resolve_group || !operator_active(principal) ||
        !bitmap_for(t, request.slots))
        return fail(error, cap, "valid range, group resolver and active system Operator are required");
    if (lookup(a, principal, t, &request, &grant, &decision, &phase)) {
        if (phase != QIHSE_RANGE_PHASE_RESERVED && phase != QIHSE_RANGE_PHASE_FINALIZED)
            return fail(error, cap, "the immutable range operation was aborted");
        t->config_epoch = grant.grant_epoch;
        if (!t->lane_id[0]) memcpy(t->lane_id, request.source_group_id, 65);
        if (error && cap) error[0] = 0;
        return true;
    }
    /* A failed lookup is never permission to publish. Build a candidate from
     * a complete committed state read; the mesh performs its own fresh CAS. */
    memset(&request, 0, sizeof(request));
    if (!bitmap_for(t, request.slots)) return false;
    bool promotion = t->next_generation[0];
    request.op = promotion ? QIHSE_RANGE_OP_PROMOTION : QIHSE_RANGE_OP_TRANSFER;
    snprintf(request.transfer_id, sizeof(request.transfer_id), "%s", t->transfer_id);
    snprintf(request.source_topology_id, sizeof(request.source_topology_id), "%s", t->source_id);
    snprintf(request.target_topology_id, sizeof(request.target_topology_id), "%s", t->target_id);
    snprintf(request.source_qkp_id, sizeof(request.source_qkp_id), "%s", t->source_qkp_id);
    snprintf(request.target_qkp_id, sizeof(request.target_qkp_id), "%s", t->target_qkp_id);
    memcpy(request.source_generation, t->generation, sizeof(request.source_generation));
    char source_generation[33] = {0};
    if (promotion) {
        /* The old owner may be down. The quorum's committed slot map and
         * exact receiver evidence replace a live lookup of that owner. */
        if (!a->local_ownership || !a->local_ownership->peer_id ||
            !a->local_ownership->peer_id(a->local_ownership->peer_id_context,
                t->owner_id, request.successor_qkp_id))
            return fail(error, cap, "promotion successor has no provisioned identity");
        memcpy(request.source_group_id, t->lane_id, 65);
        memcpy(request.target_group_id, t->lane_id, 65);
        memcpy(request.target_generation, t->next_generation, 33);
        snprintf(request.successor_topology_id, sizeof(request.successor_topology_id),
            "%s", t->owner_id);
        request.durable_cursor = t->source_lsn;
    } else if (!a->resolve_group(a->group_context, principal, t->source_id,
            request.slots, QIHSE_CLUSTER_RANGE_SOURCE_GROUP,
            request.source_group_id, source_generation) ||
        !a->resolve_group(a->group_context, principal, t->target_id,
            request.slots, QIHSE_CLUSTER_RANGE_TARGET_GROUP,
            request.target_group_id, request.target_generation) ||
        !hex_valid(request.source_group_id, 64u) ||
        !hex_valid(request.target_group_id, 64u) ||
        !hex_valid(source_generation, 32u) ||
        !hex_valid(request.target_generation, 32u) ||
        strcmp(source_generation, t->generation))
        return fail(error, cap, "range does not resolve to the provisioned source and target groups");
    if (!promotion && a->resolve_successor &&
        (!a->resolve_successor(a->group_context, principal, request.target_group_id,
            request.successor_topology_id, request.successor_qkp_id) ||
         !text_valid(request.successor_topology_id, sizeof(request.successor_topology_id)) ||
         !text_valid(request.successor_qkp_id, sizeof(request.successor_qkp_id))))
        return fail(error, cap, "destination group successor has no provisioned identity");
    qihse_consensus_range_slot_t* state = calloc(QIHSE_CONSENSUS_RANGE_SLOT_COUNT, sizeof(*state));
    uint64_t index = 0;
    bool ok = state && qihse_consensus_mesh_range_state_user(a->mesh,
        principal, request.slots, budget(a), state, request.expected_state_digest, &index);
    for (uint32_t s = t->start; ok && s <= t->end; ++s) {
        if (!(request.slots[s / 8u] & (1u << (s % 8u)))) continue;
        ok = state[s].slot == s &&
            !strcmp(state[s].owner_topology_id, t->source_id) &&
            !strcmp(state[s].owner_qkp_id, t->source_qkp_id) &&
            !strcmp(state[s].group_id, request.source_group_id);
    }
    free(state);
    if (!ok || !index ||
        !qihse_consensus_mesh_range_reserve_user(a->mesh, principal,
            &request, budget(a), &grant) || !grant.reserve_index || !grant.grant_epoch)
        return fail(error, cap, "range reservation is unconfirmed or ownership changed; retry the same transfer ID");
    t->config_epoch = grant.grant_epoch;
    memcpy(t->lane_id, request.source_group_id, 65);
    if (error && cap) error[0] = 0;
    return true;
}

bool qihse_cluster_range_authority_check_reserved(void* opaque,
    qihse_user_t* principal, const qihse_cluster_ownership_txn_t* t,
    char* error, size_t cap) {
    qihse_consensus_range_request_t request = {0};
    qihse_consensus_range_grant_t grant = {0};
    qihse_consensus_range_decision_t decision = {0};
    qihse_consensus_range_phase_t phase = QIHSE_RANGE_PHASE_NONE;
    if (!t || !t->config_epoch || !lookup(opaque, principal, t,
            &request, &grant, &decision, &phase) ||
        (phase != QIHSE_RANGE_PHASE_RESERVED && phase != QIHSE_RANGE_PHASE_FINALIZED))
        return fail(error, cap, "matching quorum range reservation is unavailable");
    if (error && cap) error[0] = 0;
    return true;
}

static bool digest_field(EVP_MD_CTX* md, const void* bytes, size_t size) {
    uint8_t length[8];
    for (unsigned i = 0; i < 8; ++i) length[7u - i] = (uint8_t)((uint64_t)size >> (i * 8u));
    return EVP_DigestUpdate(md, length, sizeof(length)) == 1 &&
        EVP_DigestUpdate(md, bytes, size) == 1;
}

static bool transition_digest(const qihse_cluster_ownership_txn_t* t,
                               const char* domain, uint8_t out[32]) {
    EVP_MD_CTX* md = EVP_MD_CTX_new();
    bool ok = md && EVP_DigestInit_ex(md, EVP_sha256(), NULL) == 1;
    const char* fields[] = {domain, t->transfer_id,
        t->source_id, t->target_id, t->source_qkp_id, t->target_qkp_id, t->generation};
    for (size_t i = 0; ok && i < sizeof(fields) / sizeof(fields[0]); ++i)
        ok = digest_field(md, fields[i], strlen(fields[i]));
    const uint64_t numbers[] = {t->start, t->end, t->config_epoch, t->source_lsn, t->target_lsn};
    for (size_t i = 0; ok && i < sizeof(numbers) / sizeof(numbers[0]); ++i) {
        uint8_t value[8];
        for (unsigned j = 0; j < 8; ++j) value[7u - j] = (uint8_t)(numbers[i] >> (j * 8u));
        ok = digest_field(md, value, sizeof(value));
    }
    if (ok) ok = digest_field(md, t->proof_digest, sizeof(t->proof_digest));
    unsigned size = 0;
    if (ok) ok = EVP_DigestFinal_ex(md, out, &size) == 1 && size == 32;
    EVP_MD_CTX_free(md);
    return ok;
}

bool qihse_cluster_range_authority_finalize(void* opaque,
    qihse_user_t* principal, const qihse_cluster_ownership_txn_t* t,
    const qihse_cluster_ct_activation_receipt_t* receipt, char* error, size_t cap) {
    qihse_cluster_range_authority_t* a = opaque;
    qihse_consensus_range_request_t request = {0};
    qihse_consensus_range_grant_t grant = {0};
    qihse_consensus_range_decision_t decision = {0};
    qihse_consensus_range_phase_t phase = QIHSE_RANGE_PHASE_NONE;
    if (!t || t->next_generation[0] || !t->config_epoch || !receipt || !lookup(a, principal, t,
            &request, &grant, &decision, &phase) ||
        (phase != QIHSE_RANGE_PHASE_RESERVED && phase != QIHSE_RANGE_PHASE_FINALIZED))
        return fail(error, cap, "exact range grant and typed activation receipt are required");
    uint64_t target_lsn = 0;
    uint8_t checksum[32] = {0}, digest[32] = {0};
    bool ok = qihse_resp_ct_activation_receipt_validate(receipt,
        t->transfer_id, t->source_id, t->target_id, t->source_qkp_id,
        t->target_qkp_id, t->generation, t->start, t->end, t->source_lsn,
        t->config_epoch, &target_lsn, checksum) && target_lsn == t->target_lsn &&
        CRYPTO_memcmp(checksum, t->proof_digest, sizeof(checksum)) == 0 &&
        transition_digest(t, "QIHSE-RANGE-ACTIVATED-1", digest) &&
        qihse_consensus_mesh_range_finalize_user(a->mesh, principal, &request,
            &grant, digest, budget(a), &decision);
    OPENSSL_cleanse(checksum, sizeof(checksum));
    OPENSSL_cleanse(digest, sizeof(digest));
    if (!ok) return fail(error, cap, "target activation did not produce a confirmed quorum ownership decision");
    if (error && cap) error[0] = 0;
    return true;
}

bool qihse_cluster_range_authority_check_finalized(void* opaque,
    qihse_user_t* principal, const qihse_cluster_ownership_txn_t* t,
    char* error, size_t cap) {
    qihse_consensus_range_request_t request = {0};
    qihse_consensus_range_grant_t grant = {0};
    qihse_consensus_range_decision_t decision = {0};
    qihse_consensus_range_phase_t phase = QIHSE_RANGE_PHASE_NONE;
    qihse_cluster_range_authority_t* a = opaque;
    uint8_t digest[32] = {0};
    bool promotion = t && t->next_generation[0];
    if (!t || !t->config_epoch || !lookup(opaque, principal, t,
            &request, &grant, &decision, &phase) ||
        phase != QIHSE_RANGE_PHASE_FINALIZED || !decision.decision_index ||
        decision.grant_epoch != t->config_epoch ||
        !(promotion ? (a->local_ownership &&
            qihse_cluster_ownership_promotion_event_digest(a->local_ownership, t, digest)) :
            transition_digest(t, "QIHSE-RANGE-ACTIVATED-1", digest)) ||
        CRYPTO_memcmp(digest, decision.evidence_digest, sizeof(digest)) != 0)
        return fail(error, cap, "committed quorum decision does not bind this activated transfer");
    if (error && cap) error[0] = 0;
    return true;
}

static bool digest_present(const uint8_t digest[32]) {
    uint8_t any = 0;
    for (size_t i = 0; i < 32; ++i) any |= digest[i];
    return any != 0;
}

static bool claim_request_matches(const qihse_kv_ct_lane_authority_claim_t* c,
                                   const qihse_consensus_range_request_t* r) {
    bool promotion = r->op == QIHSE_RANGE_OP_PROMOTION;
    return c->operation == (promotion ? QIHSE_KV_CT_LANE_AUTH_PROMOTION :
            QIHSE_KV_CT_LANE_AUTH_TRANSFER) &&
        !strcmp(c->transfer_id, r->transfer_id) &&
        !strcmp(c->source_group_id, r->source_group_id) &&
        !strcmp(c->target_group_id, r->target_group_id) &&
        !strcmp(c->source_qkp_id, r->source_qkp_id) &&
        !strcmp(c->target_qkp_id, r->target_qkp_id) &&
        !strcmp(c->source_generation, r->source_generation) &&
        !strcmp(c->target_generation, r->target_generation) &&
        !strcmp(c->successor_qkp_id, r->successor_qkp_id) &&
        (!promotion || c->source_cut == r->durable_cursor) &&
        CRYPTO_memcmp(c->slots, r->slots, sizeof(c->slots)) == 0;
}

bool qihse_cluster_range_authority_claim(void* opaque,
    qihse_user_t* principal, const qihse_cluster_ownership_txn_t* t,
    qihse_kv_ct_lane_authority_claim_t* c) {
    if (c) memset(c, 0, sizeof(*c));
    qihse_consensus_range_request_t r = {0};
    qihse_consensus_range_grant_t grant = {0};
    qihse_consensus_range_decision_t decision = {0};
    qihse_consensus_range_phase_t phase = QIHSE_RANGE_PHASE_NONE;
    if (!c || !lookup(opaque, principal, t, &r, &grant, &decision, &phase) ||
        (phase != QIHSE_RANGE_PHASE_RESERVED && phase != QIHSE_RANGE_PHASE_FINALIZED))
        return false;
    c->operation = r.op == QIHSE_RANGE_OP_PROMOTION ?
        QIHSE_KV_CT_LANE_AUTH_PROMOTION : QIHSE_KV_CT_LANE_AUTH_TRANSFER;
    snprintf(c->transfer_id, sizeof(c->transfer_id), "%s", r.transfer_id);
    snprintf(c->source_group_id, sizeof(c->source_group_id), "%s", r.source_group_id);
    snprintf(c->target_group_id, sizeof(c->target_group_id), "%s", r.target_group_id);
    snprintf(c->source_qkp_id, sizeof(c->source_qkp_id), "%s", r.source_qkp_id);
    snprintf(c->target_qkp_id, sizeof(c->target_qkp_id), "%s", r.target_qkp_id);
    snprintf(c->source_generation, sizeof(c->source_generation), "%s", r.source_generation);
    snprintf(c->target_generation, sizeof(c->target_generation), "%s", r.target_generation);
    snprintf(c->successor_qkp_id, sizeof(c->successor_qkp_id), "%s", r.successor_qkp_id);
    memcpy(c->slots, r.slots, sizeof(c->slots));
    c->grant_epoch = grant.grant_epoch; c->reserve_index = grant.reserve_index;
    memcpy(c->reserve_digest, grant.reserve_digest, 32);
    c->source_cut = t->source_lsn; c->target_cursor = t->target_lsn;
    if (phase == QIHSE_RANGE_PHASE_FINALIZED) {
        c->final_decision_index = decision.decision_index;
        memcpy(c->final_decision_digest, decision.decision_digest, 32);
        if (r.op == QIHSE_RANGE_OP_PROMOTION)
            memcpy(c->promotion_event_digest, decision.evidence_digest, 32);
    }
    if (r.op == QIHSE_RANGE_OP_PROMOTION) {
        unsigned length = 0;
        if (!EVP_Digest(c->slots, sizeof(c->slots), c->range_digest, &length,
                EVP_sha256(), NULL) || length != 32) {
            memset(c, 0, sizeof(*c)); return false;
        }
    }
    return true;
}

bool qihse_cluster_range_authority_verify_claim_user(void* opaque,
    qihse_user_t* principal, const qihse_kv_ct_lane_authority_claim_t* c,
    bool require_final) {
    qihse_cluster_range_authority_t* a = opaque;
    if (!a || !a->mesh || !operator_active(principal) || !c ||
        !text_valid(c->transfer_id, sizeof(c->transfer_id)) ||
        !hex_valid(c->source_group_id, 64) || !hex_valid(c->target_group_id, 64) ||
        !text_valid(c->source_qkp_id, sizeof(c->source_qkp_id)) ||
        !text_valid(c->target_qkp_id, sizeof(c->target_qkp_id)) ||
        !text_valid(c->successor_qkp_id, sizeof(c->successor_qkp_id)) ||
        !hex_valid(c->source_generation, 32) || !hex_valid(c->target_generation, 32))
        return false;
    qihse_consensus_range_request_t r = {0};
    qihse_consensus_range_grant_t grant = {0};
    qihse_consensus_range_decision_t decision = {0};
    qihse_consensus_range_phase_t phase = QIHSE_RANGE_PHASE_NONE;
    if (!qihse_consensus_mesh_range_lookup_user(a->mesh, principal, c->transfer_id,
            &r, &grant, &decision, &phase) ||
        (phase != QIHSE_RANGE_PHASE_RESERVED && phase != QIHSE_RANGE_PHASE_FINALIZED) ||
        !claim_request_matches(c, &r) || c->grant_epoch != grant.grant_epoch ||
        c->reserve_index != grant.reserve_index ||
        CRYPTO_memcmp(c->reserve_digest, grant.reserve_digest, 32) != 0)
        return false;
    if (r.op == QIHSE_RANGE_OP_PROMOTION) {
        uint8_t bitmap_digest[32]; unsigned length = 0;
        if (!EVP_Digest(c->slots, sizeof(c->slots), bitmap_digest, &length,
                EVP_sha256(), NULL) || length != 32 ||
            CRYPTO_memcmp(c->range_digest, bitmap_digest, 32) != 0) return false;
    }
    /* A half-filled final token is never accepted as a reservation. */
    bool has_final = c->final_decision_index != 0;
    if (has_final != digest_present(c->final_decision_digest)) return false;
    if (!require_final && !has_final) return true;
    if (phase != QIHSE_RANGE_PHASE_FINALIZED || !has_final ||
        c->final_decision_index != decision.decision_index ||
        c->grant_epoch != decision.grant_epoch ||
        CRYPTO_memcmp(c->final_decision_digest, decision.decision_digest, 32) != 0)
        return false;
    uint8_t expected[32] = {0};
    if (r.op == QIHSE_RANGE_OP_PROMOTION) {
        /* The original signed QCP2 was durably replicated before FINALIZE.
         * Its canonical event digest remains verifiable after later hops. */
        return digest_present(c->promotion_event_digest) &&
            CRYPTO_memcmp(c->promotion_event_digest, decision.evidence_digest, 32) == 0;
    }
    qihse_cluster_ownership_txn_t t = {0};
    snprintf(t.transfer_id, sizeof(t.transfer_id), "%s", r.transfer_id);
    snprintf(t.source_id, sizeof(t.source_id), "%s", r.source_topology_id);
    snprintf(t.target_id, sizeof(t.target_id), "%s", r.target_topology_id);
    snprintf(t.source_qkp_id, sizeof(t.source_qkp_id), "%s", r.source_qkp_id);
    snprintf(t.target_qkp_id, sizeof(t.target_qkp_id), "%s", r.target_qkp_id);
    snprintf(t.generation, sizeof(t.generation), "%s", r.source_generation);
    bool seen = false, ended = false;
    for (uint32_t s = 0; s < QIHSE_CONSENSUS_RANGE_SLOT_COUNT; ++s) {
        if (r.slots[s / 8u] & (1u << (s % 8u))) {
            if (ended) return false; /* CT2's typed receipt is one exact interval. */
            if (!seen) t.start = (uint16_t)s;
            seen = true; t.end = (uint16_t)s;
        } else if (seen) ended = true;
    }
    t.config_epoch = c->grant_epoch;
    t.source_lsn = c->source_cut; t.target_lsn = c->target_cursor;
    return seen && qihse_kv_ct_lane_transfer_checksum(c, t.proof_digest) &&
        transition_digest(&t, "QIHSE-RANGE-ACTIVATED-1", expected) &&
        CRYPTO_memcmp(expected, decision.evidence_digest, 32) == 0;
}

bool qihse_cluster_range_authority_verify_claim(void* opaque,
    const qihse_kv_ct_lane_authority_claim_t* c, bool require_final) {
    qihse_cluster_range_verifier_t* verifier = opaque;
    return verifier && qihse_cluster_range_authority_verify_claim_user(
        verifier->authority, verifier->principal, c, require_final);
}

bool qihse_cluster_range_authority_finalize_promotion(void* opaque,
    qihse_user_t* principal, const qihse_cluster_ownership_txn_t* t,
    const qihse_kv_ct_proof_t* proof, const uint8_t event_digest[32],
    char* error, size_t cap) {
    qihse_cluster_range_authority_t* a = opaque;
    qihse_consensus_range_request_t r = {0};
    qihse_consensus_range_grant_t grant = {0};
    qihse_consensus_range_decision_t decision = {0};
    qihse_consensus_range_phase_t phase = QIHSE_RANGE_PHASE_NONE;
    if (!a || !a->local_ownership || !t || !t->next_generation[0] ||
        !proof || !event_digest || !lookup(a, principal, t, &r, &grant, &decision, &phase) ||
        (phase != QIHSE_RANGE_PHASE_RESERVED && phase != QIHSE_RANGE_PHASE_FINALIZED))
        return fail(error, cap, "promotion requires its exact quorum grant and durable readiness proof");
    qihse_cluster_ownership_context_t local = *a->local_ownership;
    local.principal = principal;
    qihse_cluster_range_verifier_t verifier = {.authority = a, .principal = principal};
    qihse_kv_ct_lane_authority_claim_t claim = {0}, durable = {0};
    uint8_t canonical[32] = {0};
    bool ok = local.store && local.data_principal &&
        qihse_kv_ct_lane_authority_proof_fields(local.store, principal,
            local.data_principal, proof, &claim) &&
        claim_request_matches(&claim, &r) &&
        qihse_cluster_range_authority_verify_claim(&verifier, &claim, false) &&
        qihse_cluster_ownership_promotion_event_digest(&local, t, canonical) &&
        CRYPTO_memcmp(canonical, event_digest, 32) == 0 &&
        CRYPTO_memcmp(claim.promotion_event_digest, canonical, 32) == 0;
    /* A generic reservation proof is insufficient. Recover the actual
     * persisted baseline/certificate-ACK marker from this store instance. */
    qihse_kv_ct_proof_t* ready = ok ? qihse_kv_ct_lane_promoted_proof_get(
        local.store, principal, local.data_principal, t->lane_id,
        canonical, qihse_cluster_range_authority_verify_claim, &verifier) : NULL;
    ok = ready && qihse_kv_ct_lane_authority_proof_fields(local.store, principal,
            local.data_principal, ready, &durable) &&
        claim_request_matches(&durable, &r) &&
        durable.source_cut == claim.source_cut && durable.target_cursor == claim.target_cursor &&
        CRYPTO_memcmp(durable.image_digest, claim.image_digest, 32) == 0 &&
        CRYPTO_memcmp(durable.range_digest, claim.range_digest, 32) == 0 &&
        CRYPTO_memcmp(durable.certificate_head_digest, claim.certificate_head_digest, 32) == 0 &&
        CRYPTO_memcmp(durable.promotion_event_digest, canonical, 32) == 0;
    qihse_kv_ct_proof_destroy(ready);
    if (ok) ok = qihse_consensus_mesh_range_finalize_user(a->mesh, principal,
        &r, &grant, canonical, budget(a), &decision);
    OPENSSL_cleanse(&claim, sizeof(claim)); OPENSSL_cleanse(&durable, sizeof(durable));
    if (!ok) return fail(error, cap, "promotion data and original certificate are not confirmed durable");
    if (error && cap) error[0] = 0;
    return true;
}

bool qihse_cluster_range_authority_abort(void* opaque,
    qihse_user_t* principal, const qihse_cluster_ownership_txn_t* t,
    char* error, size_t cap) {
    qihse_cluster_range_authority_t* a = opaque;
    qihse_consensus_range_request_t request = {0};
    qihse_consensus_range_grant_t grant = {0};
    qihse_consensus_range_decision_t decision = {0};
    qihse_consensus_range_phase_t phase = QIHSE_RANGE_PHASE_NONE;
    if (!a || !a->local_ownership || !operator_active(principal) || !t ||
        t->phase != QIHSE_OWNERSHIP_ABORTED || !t->config_epoch ||
        !lookup(a, principal, t, &request, &grant, &decision, &phase) ||
        (phase != QIHSE_RANGE_PHASE_RESERVED && phase != QIHSE_RANGE_PHASE_ABORTED))
        return fail(error, cap, "a matching reservation and durable local abort are required");
    qihse_cluster_ownership_context_t local = *a->local_ownership;
    local.principal = principal;
    qihse_cluster_ownership_txn_t aborted;
    memset(&aborted, 0, sizeof(aborted));
    uint16_t source_index = QIHSE_CLUSTER_NODE_NONE;
    char source_qkp[65] = {0}, target_qkp[65] = {0};
    /* ABORTED is written through the journal's guarded PREPARED transition.
     * It excludes a COMMITTED/ACTIVATE history for this immutable ID. Keep
     * the source fence until the corresponding quorum abort is confirmed. */
    bool ok = local.topology && local.peer_id &&
        qihse_cluster_ownership_transfer_get_aborted(&local, t->transfer_id,
            &aborted, error, cap) && request_matches(&request, &aborted) &&
        aborted.source_lsn == t->source_lsn &&
        aborted.target_lsn == t->target_lsn && aborted.config_epoch == t->config_epoch &&
        CRYPTO_memcmp(aborted.proof_digest, t->proof_digest, 32) == 0 &&
        qihse_cluster_topology_find_node(local.topology, t->source_id, &source_index) &&
        qihse_cluster_topology_local_node(local.topology) == source_index &&
        local.peer_id(local.peer_id_context, t->source_id, source_qkp) &&
        local.peer_id(local.peer_id_context, t->target_id, target_qkp) &&
        !strcmp(source_qkp, t->source_qkp_id) && !strcmp(target_qkp, t->target_qkp_id);
    uint8_t digest[32] = {0};
    if (ok) ok = transition_digest(&aborted, "QIHSE-RANGE-ABORTED-1", digest) &&
        qihse_consensus_mesh_range_abort_user(a->mesh, principal, &request,
            &grant, digest, budget(a), &decision);
    OPENSSL_cleanse(&aborted, sizeof(aborted));
    OPENSSL_cleanse(digest, sizeof(digest));
    if (!ok) return fail(error, cap, "quorum cancellation of the durable local abort is unconfirmed");
    if (error && cap) error[0] = 0;
    return true;
}
