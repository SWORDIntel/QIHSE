#include "qihse_cluster_certificate_recovery.h"
#include "qihse_resp_wire.h"
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

enum { CERT_PAGE_BYTES = QIHSE_CLUSTER_BUS_CT1_CERTIFICATE_MAX + 36u };

static bool recovery_error(char* error, size_t cap, const char* message) {
    if (error && cap) snprintf(error, cap, "%s", message);
    return false;
}

static uint64_t recovery_now(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint64_t)t.tv_sec * 1000u + (uint64_t)t.tv_nsec / 1000000u;
}

static void recovery_hex(const uint8_t bytes[32], char out[65]) {
    static const char alphabet[] = "0123456789abcdef";
    for (size_t i = 0; i < 32; ++i) {
        out[2u * i] = alphabet[bytes[i] >> 4u];
        out[2u * i + 1u] = alphabet[bytes[i] & 15u];
    }
    out[64] = 0;
}

static bool recovery_lane_valid(const char* lane) {
    if (!lane || strnlen(lane, 65u) != 64u) return false;
    for (size_t i = 0; i < 64; ++i)
        if (!((lane[i] >= '0' && lane[i] <= '9') ||
              (lane[i] >= 'a' && lane[i] <= 'f'))) return false;
    return true;
}

static bool recovery_bulk(const qihse_resp_ct_reply_t* reply,
                            const uint8_t** body, size_t* length) {
    *body = NULL; *length = 0;
    if (!reply || !reply->data || reply->len < 6u || reply->data[0] != '$')
        return false;
    size_t pos = 1u, size = 0u;
    bool digit = false;
    while (pos < reply->len && reply->data[pos] >= '0' && reply->data[pos] <= '9') {
        unsigned value = reply->data[pos++] - '0';
        if (size > ((size_t)CERT_PAGE_BYTES - value) / 10u) return false;
        size = size * 10u + value; digit = true;
    }
    if (!digit || pos + 2u > reply->len || reply->data[pos] != '\r' ||
        reply->data[pos + 1u] != '\n') return false;
    pos += 2u;
    if (reply->len - pos < 2u || size != reply->len - pos - 2u ||
        reply->data[pos + size] != '\r' || reply->data[pos + size + 1u] != '\n')
        return false;
    *body = reply->data + pos; *length = size;
    return true;
}

typedef struct {
    uint8_t** certificates;
    size_t* lengths;
    size_t count, capacity;
} recovery_chain_t;

static bool recovery_committed(qihse_cluster_ownership_context_t* c,
    const qihse_cluster_bus_ct1_promotion_update_v2_t* u) {
    qihse_cluster_ownership_txn_t t = {0};
    t.phase = QIHSE_OWNERSHIP_ADOPTED;
    t.start = u->base.start; t.end = u->base.end;
    t.config_epoch = u->base.config_epoch;
    t.source_lsn = u->base.durable_cursor; t.target_lsn = u->target_cursor;
    snprintf(t.transfer_id, sizeof(t.transfer_id), "%s", u->base.transfer_id);
    snprintf(t.source_id, sizeof(t.source_id), "%s", u->base.source_id);
    snprintf(t.target_id, sizeof(t.target_id), "%s", u->base.target_id);
    snprintf(t.source_qkp_id, sizeof(t.source_qkp_id), "%s", u->base.source_qkp_id);
    snprintf(t.target_qkp_id, sizeof(t.target_qkp_id), "%s", u->base.target_qkp_id);
    snprintf(t.generation, sizeof(t.generation), "%s", u->base.generation);
    snprintf(t.next_generation, sizeof(t.next_generation), "%s", u->base.next_generation);
    snprintf(t.lane_id, sizeof(t.lane_id), "%s", u->lane_id);
    snprintf(t.owner_id, sizeof(t.owner_id), "%s", u->base.successor_id);
    memcpy(t.slot_bitmap, u->base.slot_bitmap, sizeof(t.slot_bitmap));
    memcpy(t.proof_digest, u->base.promotion_digest, sizeof(t.proof_digest));
    return c->range_check_finalized(c->range_authority_context, c->principal,
        &t, NULL, 0);
}

static bool recovery_append(recovery_chain_t* chain, const uint8_t* data, size_t size) {
    if (chain->count == chain->capacity) {
        if (chain->capacity > SIZE_MAX / 2u) return false;
        size_t next = chain->capacity ? chain->capacity * 2u : 8u;
        if (next > SIZE_MAX / sizeof(*chain->certificates) ||
            next > SIZE_MAX / sizeof(*chain->lengths)) return false;
        uint8_t** certificates = realloc(chain->certificates, next * sizeof(*certificates));
        if (!certificates) return false;
        chain->certificates = certificates;
        size_t* lengths = realloc(chain->lengths, next * sizeof(*lengths));
        if (!lengths) return false;
        chain->lengths = lengths; chain->capacity = next;
    }
    uint8_t* copy = malloc(size);
    if (!copy) return false;
    memcpy(copy, data, size);
    chain->certificates[chain->count] = copy;
    chain->lengths[chain->count++] = size;
    return true;
}

bool qihse_cluster_ownership_pull_ct1_promotion_chain(
    qihse_cluster_ownership_context_t* c, uint16_t peer_index,
    const char* lane_id, const uint8_t through[32], uint32_t timeout_ms,
    char* error, size_t cap) {
    if (error && cap) error[0] = 0;
    if (!c || !c->principal || !qihse_auth_user_is_active(c->principal) ||
        qihse_user_get_role(c->principal) != QIHSE_ROLE_OPERATOR ||
        qihse_user_get_tenant_id(c->principal) != QIHSE_TENANT_SYSTEM ||
        !c->topology || !c->bus || !c->resp_server || !c->peer_id ||
        !c->range_check_finalized ||
        !through || !recovery_lane_valid(lane_id))
        return recovery_error(error, cap, "active system Operator and pinned certificate peer are required");
    uint8_t nonzero = 0;
    for (size_t i = 0; i < 32; ++i) nonzero |= through[i];
    qihse_cluster_node_t peer;
    char qkp[QIHSE_KV_CT_ID_MAX + 1u] = {0};
    if (!nonzero || !qihse_cluster_topology_get_node(c->topology, peer_index, &peer) ||
        !c->peer_id(c->peer_id_context, peer.id, qkp) ||
        !qkp[0] || strnlen(qkp, sizeof(qkp)) == sizeof(qkp))
        return recovery_error(error, cap, "certificate peer has no trusted topology-to-QKP identity");
    recovery_chain_t chain = {0};
    uint8_t after[32] = {0};
    bool reached = false, ok = true;
    uint64_t deadline = recovery_now() + (timeout_ms ? timeout_ms : 10000u);
    while (ok && !reached && recovery_now() < deadline) {
        char cursor[65], capacity[16];
        recovery_hex(after, cursor);
        snprintf(capacity, sizeof(capacity), "%u", (unsigned)CERT_PAGE_BYTES);
        qihse_resp_ct_arg_t args[] = {
            {"REPL.CT1", 8u}, {"CERTPAGE", 8u},
            {lane_id, 64u}, {cursor, 64u}, {capacity, strlen(capacity)}
        };
        qihse_resp_ct_reply_t reply = {0};
        ok = qihse_resp_ct_peer_command_to(c->resp_server, peer_index, qkp,
            args, sizeof(args) / sizeof(args[0]), &reply);
        const uint8_t* page = NULL; size_t bytes = 0;
        if (ok) ok = recovery_bulk(&reply, &page, &bytes) && bytes != 0u;
        size_t pos = 0u;
        uint8_t previous[32]; memcpy(previous, after, 32);
        while (ok && pos < bytes && !reached) {
            if (bytes - pos < 36u) { ok = false; break; }
            uint32_t size = (uint32_t)page[pos] << 24u |
                (uint32_t)page[pos + 1u] << 16u |
                (uint32_t)page[pos + 2u] << 8u | page[pos + 3u];
            const uint8_t* stored_digest = page + pos + 4u;
            pos += 36u;
            if (!size || size > QIHSE_CLUSTER_BUS_CT1_CERTIFICATE_MAX || size > bytes - pos) {
                ok = false; break;
            }
            uint8_t digest[32]; unsigned digest_size = 0u;
            qihse_cluster_bus_ct1_promotion_update_v2_t update;
            qihse_uuid_t signer;
            ok = EVP_Digest(page + pos, size, digest, &digest_size,
                    EVP_sha256(), NULL) == 1 && digest_size == 32u &&
                CRYPTO_memcmp(digest, stored_digest, 32) == 0 &&
                qihse_cluster_bus_ct1_certificate_verify(c->bus,
                    page + pos, size, &update, &signer) &&
                !strcmp(update.lane_id, lane_id);
            if (ok) {
                memcpy(after, digest, 32);
                /* A signed event is appended before its quorum decision, so
                 * prepared/aborted attempts can share the certificate log.
                 * They never become links in the committed ownership chain. */
                if (recovery_committed(c, &update)) {
                    ok = recovery_append(&chain, page + pos, size);
                    reached = ok && CRYPTO_memcmp(update.event_digest, through, 32) == 0;
                }
            }
            pos += size;
        }
        if (ok && !reached && CRYPTO_memcmp(previous, after, 32) == 0) ok = false;
        qihse_resp_ct_reply_free(&reply);
    }
    ok = ok && reached && recovery_now() < deadline;
    if (ok) ok = qihse_cluster_ownership_receive_ct1_promotion_chain(c,
        (const uint8_t* const*)chain.certificates, chain.lengths,
        chain.count, error, cap);
    for (size_t i = 0; i < chain.count; ++i) free(chain.certificates[i]);
    free(chain.certificates); free(chain.lengths);
    if (!ok && (!error || !cap || !error[0]))
        return recovery_error(error, cap, "complete authenticated promotion chain is unavailable; retry recovery");
    if (ok && error && cap) error[0] = 0;
    return ok;
}
