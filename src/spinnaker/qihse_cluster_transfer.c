#include "qihse_cluster_transfer.h"

#include "qihse_kv_store.h"
#include "qihse_resp_wire.h"
#include "qihse_cluster_range_authority.h"

#include <errno.h>
#include <openssl/crypto.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CT_TRANSFER_DEFAULT_CHUNK (12u << 10)
#define CT_TRANSFER_MAX_CHUNK (12u << 10)
#define CT_TRANSFER_MAX_RESUMES 3u

static const char hex_digits[] = "0123456789abcdef";
static const unsigned char group_claim_magic[8] =
    {'Q','C','T','G','0','0','0','1'};

static bool group_claim_text_valid(const char* text, size_t width,
                                   size_t exact_length, bool hex_only) {
    if (!text) return false;
    size_t len = strnlen(text, width + 1u);
    if (!len || len > width || (exact_length && len != exact_length)) return false;
    for (size_t i = 0; i < len; ++i) {
        unsigned char c = (unsigned char)text[i];
        if (hex_only) {
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
                return false;
        } else if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                     (c >= '0' && c <= '9') || c == '-' || c == '_' ||
                     c == '.' || c == ':')) return false;
    }
    return true;
}

static void group_claim_put64(unsigned char* p, uint64_t value) {
    for (size_t i = 0; i < 8u; ++i)
        p[i] = (unsigned char)(value >> (56u - 8u * i));
}

static uint64_t group_claim_get64(const unsigned char* p) {
    uint64_t value = 0;
    for (size_t i = 0; i < 8u; ++i) value = (value << 8u) | p[i];
    return value;
}

static bool group_claim_encode_text(unsigned char** cursor,
        const char* text, size_t width, size_t exact_length, bool hex_only) {
    if (!group_claim_text_valid(text, width, exact_length, hex_only)) return false;
    size_t len = strlen(text);
    memset(*cursor, 0, width);
    memcpy(*cursor, text, len);
    *cursor += width;
    return true;
}

static bool group_claim_decode_text(const unsigned char** cursor, char* out,
        size_t width, size_t exact_length, bool hex_only) {
    const unsigned char* p = *cursor;
    size_t len = 0;
    while (len < width && p[len]) ++len;
    if (!len || len > width || (exact_length && len != exact_length)) return false;
    for (size_t i = len; i < width; ++i) if (p[i]) return false;
    memcpy(out, p, len);
    out[len] = '\0';
    if (!group_claim_text_valid(out, width, exact_length, hex_only)) return false;
    *cursor += width;
    return true;
}

bool qihse_cluster_transfer_claim_encode(
        const qihse_kv_ct_lane_authority_claim_t* claim,
        unsigned char out[QIHSE_CT_GROUP_CLAIM_WIRE_BYTES]) {
    if (!claim || !out || (claim->operation != QIHSE_KV_CT_LANE_AUTH_TRANSFER &&
            claim->operation != QIHSE_KV_CT_LANE_AUTH_PROMOTION)) return false;
    unsigned char* p = out;
    memcpy(p, group_claim_magic, sizeof(group_claim_magic)); p += sizeof(group_claim_magic);
    *p++ = (unsigned char)claim->operation;
    if (!group_claim_encode_text(&p, claim->transfer_id,
            QIHSE_KV_CT_ID_MAX, 0u, false) ||
        !group_claim_encode_text(&p, claim->source_group_id,
            QIHSE_KV_CT_LANE_ID_MAX, QIHSE_KV_CT_LANE_ID_MAX, true) ||
        !group_claim_encode_text(&p, claim->target_group_id,
            QIHSE_KV_CT_LANE_ID_MAX, QIHSE_KV_CT_LANE_ID_MAX, true) ||
        !group_claim_encode_text(&p, claim->source_qkp_id,
            QIHSE_KV_CT_ID_MAX, 0u, false) ||
        !group_claim_encode_text(&p, claim->target_qkp_id,
            QIHSE_KV_CT_ID_MAX, 0u, false) ||
        !group_claim_encode_text(&p, claim->source_generation,
            QIHSE_KV_CT_ID_MAX, 32u, true) ||
        !group_claim_encode_text(&p, claim->target_generation,
            QIHSE_KV_CT_ID_MAX, 32u, true) ||
        !group_claim_encode_text(&p, claim->successor_qkp_id,
            QIHSE_KV_CT_ID_MAX, 0u, false)) {
        OPENSSL_cleanse(out, QIHSE_CT_GROUP_CLAIM_WIRE_BYTES);
        return false;
    }
    memcpy(p, claim->slots, sizeof(claim->slots)); p += sizeof(claim->slots);
    group_claim_put64(p, claim->grant_epoch); p += 8u;
    group_claim_put64(p, claim->reserve_index); p += 8u;
    memcpy(p, claim->reserve_digest, 32u); p += 32u;
    group_claim_put64(p, claim->final_decision_index); p += 8u;
    memcpy(p, claim->final_decision_digest, 32u); p += 32u;
    group_claim_put64(p, claim->source_cut); p += 8u;
    group_claim_put64(p, claim->target_cursor); p += 8u;
    memcpy(p, claim->range_digest, 32u); p += 32u;
    memcpy(p, claim->image_digest, 32u); p += 32u;
    memcpy(p, claim->certificate_head_digest, 32u); p += 32u;
    memcpy(p, claim->promotion_event_digest, 32u); p += 32u;
    if ((size_t)(p - out) != QIHSE_CT_GROUP_CLAIM_WIRE_BYTES) {
        OPENSSL_cleanse(out, QIHSE_CT_GROUP_CLAIM_WIRE_BYTES);
        return false;
    }
    return true;
}

bool qihse_cluster_transfer_claim_decode(const void* wire, size_t wire_len,
        qihse_kv_ct_lane_authority_claim_t* out_claim) {
    if (!wire || wire_len != QIHSE_CT_GROUP_CLAIM_WIRE_BYTES || !out_claim)
        return false;
    memset(out_claim, 0, sizeof(*out_claim));
    const unsigned char* p = wire;
    const unsigned char* end = p + wire_len;
    if (memcmp(p, group_claim_magic, sizeof(group_claim_magic))) return false;
    p += sizeof(group_claim_magic);
    if (p >= end) return false;
    out_claim->operation = (qihse_kv_ct_lane_authority_op_t)*p++;
    if (out_claim->operation != QIHSE_KV_CT_LANE_AUTH_TRANSFER &&
        out_claim->operation != QIHSE_KV_CT_LANE_AUTH_PROMOTION) return false;
    if (!group_claim_decode_text(&p, out_claim->transfer_id,
            QIHSE_KV_CT_ID_MAX, 0u, false) ||
        !group_claim_decode_text(&p, out_claim->source_group_id,
            QIHSE_KV_CT_LANE_ID_MAX, QIHSE_KV_CT_LANE_ID_MAX, true) ||
        !group_claim_decode_text(&p, out_claim->target_group_id,
            QIHSE_KV_CT_LANE_ID_MAX, QIHSE_KV_CT_LANE_ID_MAX, true) ||
        !group_claim_decode_text(&p, out_claim->source_qkp_id,
            QIHSE_KV_CT_ID_MAX, 0u, false) ||
        !group_claim_decode_text(&p, out_claim->target_qkp_id,
            QIHSE_KV_CT_ID_MAX, 0u, false) ||
        !group_claim_decode_text(&p, out_claim->source_generation,
            QIHSE_KV_CT_ID_MAX, 32u, true) ||
        !group_claim_decode_text(&p, out_claim->target_generation,
            QIHSE_KV_CT_ID_MAX, 32u, true) ||
        !group_claim_decode_text(&p, out_claim->successor_qkp_id,
            QIHSE_KV_CT_ID_MAX, 0u, false)) goto invalid;
    if ((size_t)(end - p) < sizeof(out_claim->slots)) goto invalid;
    memcpy(out_claim->slots, p, sizeof(out_claim->slots)); p += sizeof(out_claim->slots);
    if ((size_t)(end - p) != 232u) goto invalid;
    out_claim->grant_epoch = group_claim_get64(p); p += 8u;
    out_claim->reserve_index = group_claim_get64(p); p += 8u;
    memcpy(out_claim->reserve_digest, p, 32u); p += 32u;
    out_claim->final_decision_index = group_claim_get64(p); p += 8u;
    memcpy(out_claim->final_decision_digest, p, 32u); p += 32u;
    out_claim->source_cut = group_claim_get64(p); p += 8u;
    out_claim->target_cursor = group_claim_get64(p); p += 8u;
    memcpy(out_claim->range_digest, p, 32u); p += 32u;
    memcpy(out_claim->image_digest, p, 32u); p += 32u;
    memcpy(out_claim->certificate_head_digest, p, 32u); p += 32u;
    memcpy(out_claim->promotion_event_digest, p, 32u); p += 32u;
    if (p != end || !out_claim->grant_epoch || !out_claim->reserve_index)
        goto invalid;
    return true;
invalid:
    OPENSSL_cleanse(out_claim, sizeof(*out_claim));
    return false;
}

static void hex32(const unsigned char in[32], char out[65]) {
    for (size_t i = 0; i < 32; ++i) {
        out[2u * i] = hex_digits[in[i] >> 4];
        out[2u * i + 1u] = hex_digits[in[i] & 15u];
    }
    out[64] = '\0';
}

static bool source_range_checksum(qihse_cluster_ownership_context_t *c,
                                  const qihse_cluster_ownership_txn_t *txn,
                                  unsigned char out[32]) {
    qihse_kv_ct_proof_t *proof = qihse_kv_ct_source_transfer_proof_create(
        c->store, c->principal, c->data_principal, txn->transfer_id, txn->source_qkp_id,
        txn->target_qkp_id, txn->generation, txn->start, txn->end, txn->source_lsn);
    const char *transfer = NULL, *source = NULL, *target = NULL, *generation = NULL;
    uint16_t first = 0, last = 0;
    uint64_t source_lsn = 0, target_lsn = 0;
    bool ok = proof && qihse_kv_ct_proof_validate(c->store, c->principal,
        c->data_principal, proof) &&
        qihse_kv_ct_proof_fields(c->store, c->principal, c->data_principal, proof, &transfer,
            &source, &target, &generation, &first, &last, &source_lsn,
            &target_lsn, out) && transfer && source && target && generation &&
        !strcmp(transfer, txn->transfer_id) && !strcmp(source, txn->source_qkp_id) &&
        !strcmp(target, txn->target_qkp_id) && !strcmp(generation, txn->generation) &&
        first == txn->start && last == txn->end && source_lsn == txn->source_lsn &&
        target_lsn == 0;
    if (proof) qihse_kv_ct_proof_destroy(proof);
    if (!ok) OPENSSL_cleanse(out, 32);
    return ok;
}

static bool resp_uint_reply(const qihse_resp_ct_reply_t *reply, uint64_t *out) {
    if (!reply || !reply->data || !reply->len || !out || reply->data[0] != ':') return false;
    uint64_t value = 0;
    size_t pos = 1;
    if (pos >= reply->len || reply->data[pos] < '0' || reply->data[pos] > '9') return false;
    while (pos < reply->len && reply->data[pos] >= '0' && reply->data[pos] <= '9') {
        unsigned digit = (unsigned)(reply->data[pos++] - '0');
        if (value > (UINT64_MAX - digit) / 10u) return false;
        value = value * 10u + digit;
    }
    if (pos + 2u != reply->len || reply->data[pos] != '\r' || reply->data[pos + 1u] != '\n')
        return false;
    *out = value;
    return true;
}

/* RESP error replies are bounded by the peer parser, but copy only printable
 * error text into diagnostics. Never include bulk payloads or malformed
 * framing in the Operator-facing error path. */
static void resp_error_text(const qihse_resp_ct_reply_t *reply,
                            char *out, size_t cap) {
    if (!out || !cap) return;
    out[0] = '\0';
    if (!reply || !reply->data || reply->len < 3u || reply->data[0] != '-')
        return;
    size_t end = 1u;
    while (end + 1u < reply->len &&
           !(reply->data[end] == '\r' && reply->data[end + 1u] == '\n'))
        ++end;
    if (end + 1u >= reply->len) return;
    size_t n = end - 1u;
    if (n >= cap) n = cap - 1u;
    for (size_t i = 0; i < n; ++i) {
        unsigned char c = reply->data[i + 1u];
        out[i] = (c >= 0x20u && c <= 0x7eu) ? (char)c : '?';
    }
    out[n] = '\0';
}

static bool ct_rpc(qihse_cluster_ownership_context_t *c, uint16_t target_index,
                   const char *expected_qkp_id, const void *const *parts,
                   const size_t *lengths, size_t count, qihse_resp_ct_reply_t *reply) {
    qihse_resp_ct_arg_t argv[16];
    if (!c || !c->resp_server || !parts || !lengths || !reply ||
        count < 2u || count > 16u) return false;
    memset(reply, 0, sizeof(*reply));
    for (size_t i = 0; i < count; ++i) {
        argv[i].data = parts[i];
        argv[i].len = lengths[i];
    }
    return qihse_resp_ct_peer_command_to(c->resp_server, target_index,
                                         expected_qkp_id, argv, count, reply);
}

static bool ct_rpc_uint(qihse_cluster_ownership_context_t *c, uint16_t target_index,
                        const char *expected_qkp_id, const void *const *parts,
                        const size_t *lengths, size_t count, uint64_t *out,
                        char *diagnostic, size_t diagnostic_cap) {
    if (diagnostic && diagnostic_cap) diagnostic[0] = '\0';
    qihse_resp_ct_reply_t reply = {0};
    bool received = ct_rpc(c, target_index, expected_qkp_id, parts, lengths, count, &reply);
    bool ok = received && resp_uint_reply(&reply, out);
    if (received && !ok) resp_error_text(&reply, diagnostic, diagnostic_cap);
    qihse_resp_ct_reply_free(&reply);
    return ok;
}

static bool group_topology_index(qihse_cluster_ownership_context_t* ownership,
        const char* qkp_id, uint16_t* out_index) {
    if (!ownership || !ownership->topology || !ownership->peer_id ||
        !qkp_id || !out_index) return false;
    for (uint16_t i = 0; i < QIHSE_CLUSTER_MAX_NODES; ++i) {
        qihse_cluster_node_t node;
        if (!qihse_cluster_topology_get_node(ownership->topology, i, &node)) break;
        char mapped[QIHSE_KV_CT_ID_MAX + 1u] = {0};
        bool ok = ownership->peer_id(ownership->peer_id_context, node.id, mapped) &&
            mapped[0] && strcmp(mapped, qkp_id) == 0;
        OPENSSL_cleanse(mapped, sizeof(mapped));
        if (ok) { *out_index = i; return true; }
    }
    return false;
}

static bool group_rpc_integer(qihse_cluster_ownership_context_t* ownership,
        uint16_t target_index, const char* target_qkp,
        const char* operation, const unsigned char* claim, size_t claim_len,
        const char* value, uint64_t* out, char* diagnostic, size_t diagnostic_cap) {
    const void* parts[5] = {"REPL.CT2", operation, claim, value, NULL};
    const size_t lens[5] = {8u, strlen(operation), claim_len,
        value ? strlen(value) : 0u, 0u};
    qihse_resp_ct_reply_t reply = {0};
    size_t argc = value ? 4u : 3u;
    bool received = ct_rpc(ownership, target_index, target_qkp,
        parts, lens, argc, &reply);
    bool ok = received && resp_uint_reply(&reply, out);
    if (received && !ok) resp_error_text(&reply, diagnostic, diagnostic_cap);
    qihse_resp_ct_reply_free(&reply);
    return ok;
}

static bool group_rpc_chunk(qihse_cluster_ownership_context_t* ownership,
        uint16_t target_index, const char* target_qkp,
        const unsigned char* claim, size_t claim_len, uint64_t offset,
        uint64_t total, const unsigned char* bytes, size_t length,
        uint64_t* out_next) {
    char offset_text[32], total_text[32];
    snprintf(offset_text, sizeof(offset_text), "%llu", (unsigned long long)offset);
    snprintf(total_text, sizeof(total_text), "%llu", (unsigned long long)total);
    const void* parts[] = {"REPL.CT2", "GROUP-CHUNK", claim, offset_text,
                           total_text, bytes};
    const size_t lens[] = {8u, 11u, claim_len, strlen(offset_text),
                           strlen(total_text), length};
    return ct_rpc_uint(ownership, target_index, target_qkp, parts, lens, 6u,
        out_next, NULL, 0u);
}

static bool group_rpc_seal(qihse_cluster_ownership_context_t* ownership,
        uint16_t target_index, const char* target_qkp,
        const unsigned char* claim, size_t claim_len, uint64_t total,
        unsigned char out_seal[32]) {
    char total_text[32], hex[65];
    snprintf(total_text, sizeof(total_text), "%llu", (unsigned long long)total);
    const void* parts[] = {"REPL.CT2", "GROUP-SEAL", claim, total_text};
    const size_t lens[] = {8u, 10u, claim_len, strlen(total_text)};
    qihse_resp_ct_reply_t reply = {0};
    bool ok = ct_rpc(ownership, target_index, target_qkp, parts, lens, 4u, &reply) &&
        reply.len == 71u && reply.data[0] == '$' &&
        reply.data[1] == '6' && reply.data[2] == '4' &&
        reply.data[3] == '\r' && reply.data[4] == '\n' &&
        reply.data[69] == '\r' && reply.data[70] == '\n';
    if (ok) {
        memcpy(hex, reply.data + 5u, 64u); hex[64] = '\0';
        for (size_t i = 0; i < 32u; ++i) {
            unsigned char a = (unsigned char)hex[i * 2u];
            unsigned char b = (unsigned char)hex[i * 2u + 1u];
            int hi = a >= '0' && a <= '9' ? a - '0' : a >= 'a' && a <= 'f' ? a - 'a' + 10 : -1;
            int lo = b >= '0' && b <= '9' ? b - '0' : b >= 'a' && b <= 'f' ? b - 'a' + 10 : -1;
            if (hi < 0 || lo < 0) { ok = false; break; }
            out_seal[i] = (unsigned char)((hi << 4) | lo);
        }
        OPENSSL_cleanse(hex, sizeof(hex));
    }
    qihse_resp_ct_reply_free(&reply);
    return ok;
}

static bool ct_begin_or_status(qihse_cluster_ownership_context_t *c,
                               uint16_t target_index,
                               const qihse_cluster_ownership_txn_t *txn,
                               uint64_t total, const char image_sha[65],
                               const char range_sha[65],
                               const char *verb, uint64_t *out_offset,
                               char *diagnostic, size_t diagnostic_cap) {
    char first[8], last[8], source_lsn[32], epoch[32], bytes[32];
    snprintf(first, sizeof(first), "%u", (unsigned)txn->start);
    snprintf(last, sizeof(last), "%u", (unsigned)txn->end);
    snprintf(source_lsn, sizeof(source_lsn), "%llu", (unsigned long long)txn->source_lsn);
    snprintf(epoch, sizeof(epoch), "%llu", (unsigned long long)txn->config_epoch);
    snprintf(bytes, sizeof(bytes), "%llu", (unsigned long long)total);
    const void *parts[] = {"REPL.CT2", verb, txn->transfer_id, txn->source_id,
        txn->target_id, txn->source_qkp_id, txn->target_qkp_id, txn->generation,
        first, last, source_lsn, epoch, bytes, image_sha, range_sha};
    const size_t lens[] = {8u, strlen(verb), strlen(txn->transfer_id), strlen(txn->source_id),
        strlen(txn->target_id), strlen(txn->source_qkp_id), strlen(txn->target_qkp_id),
        strlen(txn->generation), strlen(first), strlen(last), strlen(source_lsn),
        strlen(epoch), strlen(bytes), 64u, 64u};
    return ct_rpc_uint(c, target_index, txn->target_qkp_id, parts, lens,
                       sizeof(parts) / sizeof(parts[0]), out_offset,
                       diagnostic, diagnostic_cap);
}

static bool ct_chunk(qihse_cluster_ownership_context_t *c,
                     uint16_t target_index,
                     const qihse_cluster_ownership_txn_t *txn,
                     uint64_t offset, uint64_t total, const char sha[65],
                     const unsigned char *buf, size_t len, uint64_t *out_next) {
    char off[32], bytes[32];
    snprintf(off, sizeof(off), "%llu", (unsigned long long)offset);
    snprintf(bytes, sizeof(bytes), "%llu", (unsigned long long)total);
    const void *parts[] = {"REPL.CT2", "CHUNK", txn->transfer_id, off, bytes, sha, buf};
    const size_t lens[] = {8u, 5u, strlen(txn->transfer_id), strlen(off), strlen(bytes), 64u, len};
    return ct_rpc_uint(c, target_index, txn->target_qkp_id, parts, lens,
                       sizeof(parts) / sizeof(parts[0]), out_next, NULL, 0u);
}

static bool ct_seal(qihse_cluster_ownership_context_t *c,
                    uint16_t target_index,
                    const qihse_cluster_ownership_txn_t *txn,
                    uint64_t total, const char image_sha[65],
                    const char range_sha[65]) {
    char first[8], last[8], source_lsn[32], epoch[32], bytes[32];
    snprintf(first, sizeof(first), "%u", (unsigned)txn->start);
    snprintf(last, sizeof(last), "%u", (unsigned)txn->end);
    snprintf(source_lsn, sizeof(source_lsn), "%llu", (unsigned long long)txn->source_lsn);
    snprintf(epoch, sizeof(epoch), "%llu", (unsigned long long)txn->config_epoch);
    snprintf(bytes, sizeof(bytes), "%llu", (unsigned long long)total);
    const void *parts[] = {"REPL.CT2", "SEAL", txn->transfer_id, txn->source_id,
        txn->target_id, txn->source_qkp_id, txn->target_qkp_id, txn->generation,
        first, last, source_lsn, epoch, bytes, image_sha, range_sha};
    const size_t lens[] = {8u, 4u, strlen(txn->transfer_id), strlen(txn->source_id),
        strlen(txn->target_id), strlen(txn->source_qkp_id), strlen(txn->target_qkp_id),
        strlen(txn->generation), strlen(first), strlen(last), strlen(source_lsn),
        strlen(epoch), strlen(bytes), 64u, 64u};
    qihse_resp_ct_reply_t reply = {0};
    bool ok = ct_rpc(c, target_index, txn->target_qkp_id, parts, lens,
              sizeof(parts) / sizeof(parts[0]), &reply) && reply.data &&
              reply.len == 5u && memcmp(reply.data, "+OK\r\n", 5u) == 0;
    qihse_resp_ct_reply_free(&reply);
    /* The response can be lost after the target has durably sealed. The
     * caller resolves that ambiguity using the QKP-pinned receipt, whose
     * exact tuple is independently validated before COMMIT. */
    return ok;
}

static void set_error(char *out, size_t cap, const char *text) {
    if (out && cap) snprintf(out, cap, "%s", text ? text : "CT2 transfer failed");
}

static qihse_cluster_transfer_result_t prewire_failure(
    qihse_cluster_transfer_context_t *c, const char *transfer_id,
    uint16_t source_index, uint16_t target_index, bool newly_prepared,
    const char *reason, char *err, size_t err_cap) {
    if (!newly_prepared) {
        set_error(err, err_cap, reason);
        return QIHSE_CLUSTER_TRANSFER_PENDING;
    }
    char abort_error[256] = {0};
    if (qihse_cluster_ownership_transfer_abort(c->ownership, transfer_id,
            source_index, target_index, abort_error, sizeof(abort_error))) {
        set_error(err, err_cap, reason);
        return QIHSE_CLUSTER_TRANSFER_REJECTED;
    }
    set_error(err, err_cap, "pre-network preparation failed and safe source abort was unavailable; range remains fenced");
    return QIHSE_CLUSTER_TRANSFER_PENDING;
}

static void progress(qihse_cluster_transfer_context_t *c,
                     qihse_cluster_transfer_phase_t phase,
                     uint64_t done, uint64_t total) {
    if (c->progress) c->progress(c->progress_context, phase, done, total);
}

static bool valid_txn(const qihse_cluster_ownership_txn_t *t,
                      const char *transfer_id, uint16_t source, uint16_t target,
                      uint16_t first, uint16_t last) {
    return t && t->phase == QIHSE_OWNERSHIP_PREPARED &&
           !strcmp(t->transfer_id, transfer_id) &&
           !strcmp(t->source_id, t->owner_id) && strcmp(t->source_id, t->target_id) &&
           t->source_qkp_id[0] && t->target_qkp_id[0] &&
           strcmp(t->source_qkp_id, t->target_qkp_id) && t->generation[0] &&
           t->start == first && t->end == last &&
           source != target && t->config_epoch != 0;
}

static bool valid_committed_txn(const qihse_cluster_ownership_txn_t *t,
                                const char *transfer_id, uint16_t source,
                                uint16_t target, uint16_t first, uint16_t last) {
    return t && t->phase == QIHSE_OWNERSHIP_COMMITTED &&
           !strcmp(t->transfer_id, transfer_id) &&
           !strcmp(t->owner_id, t->target_id) && strcmp(t->source_id, t->target_id) &&
           t->source_qkp_id[0] && t->target_qkp_id[0] &&
           strcmp(t->source_qkp_id, t->target_qkp_id) && t->generation[0] &&
           t->start == first && t->end == last && source != target &&
           t->config_epoch != 0;
}

static bool valid_finalized_txn(const qihse_cluster_ownership_txn_t *t,
                                const char *transfer_id, uint16_t source,
                                uint16_t target, uint16_t first, uint16_t last) {
    unsigned char proof_or = 0;
    if (t) {
        for (size_t i = 0; i < sizeof(t->proof_digest); ++i)
            proof_or |= t->proof_digest[i];
    }
    return t && t->phase == QIHSE_OWNERSHIP_FINALIZED &&
        !strcmp(t->transfer_id, transfer_id) &&
        !strcmp(t->owner_id, t->target_id) && strcmp(t->source_id, t->target_id) &&
        t->source_qkp_id[0] && t->target_qkp_id[0] &&
        strcmp(t->source_qkp_id, t->target_qkp_id) && strlen(t->generation) == 32u &&
        !t->next_generation[0] && t->start == first && t->end == last &&
        source != target && t->source_lsn != 0 && t->target_lsn != 0 &&
        t->config_epoch != 0 && proof_or != 0;
}

static bool trusted_topology_mapping_matches(qihse_cluster_transfer_context_t *c,
                                       const qihse_cluster_ownership_txn_t *txn,
                                       uint16_t source, uint16_t target) {
    qihse_cluster_node_t source_node, target_node;
    char source_qkp[QIHSE_KV_CT_ID_MAX + 1u] = {0};
    char target_qkp[QIHSE_KV_CT_ID_MAX + 1u] = {0};
    return c && c->ownership && c->ownership->topology && c->ownership->peer_id && txn &&
        qihse_cluster_topology_local_node(c->ownership->topology) == source &&
        qihse_cluster_topology_get_node(c->ownership->topology, source, &source_node) &&
        qihse_cluster_topology_get_node(c->ownership->topology, target, &target_node) &&
        !strcmp(source_node.id, txn->source_id) && !strcmp(target_node.id, txn->target_id) &&
        c->ownership->peer_id(c->ownership->peer_id_context, source_node.id, source_qkp) &&
        c->ownership->peer_id(c->ownership->peer_id_context, target_node.id, target_qkp) &&
        !strcmp(source_qkp, txn->source_qkp_id) && !strcmp(target_qkp, txn->target_qkp_id);
}

static bool topology_matches(qihse_cluster_transfer_context_t *c,
                            const qihse_cluster_ownership_txn_t *txn,
                            uint16_t source, uint16_t target,
                            uint16_t first, uint16_t last) {
    qihse_cluster_node_t source_node, target_node;
    char source_qkp[QIHSE_KV_CT_ID_MAX + 1u] = {0};
    char target_qkp[QIHSE_KV_CT_ID_MAX + 1u] = {0};
    if (!c || !c->ownership || !c->ownership->topology || !txn ||
        !c->ownership->peer_id ||
        qihse_cluster_topology_local_node(c->ownership->topology) != source ||
        !qihse_cluster_topology_get_node(c->ownership->topology, source, &source_node) ||
        !qihse_cluster_topology_get_node(c->ownership->topology, target, &target_node) ||
        source_node.role != QIHSE_CLUSTER_NODE_PRIMARY ||
        target_node.role != QIHSE_CLUSTER_NODE_PRIMARY || !target_node.healthy ||
        strcmp(source_node.id, txn->source_id) || strcmp(target_node.id, txn->target_id) ||
        !c->ownership->peer_id(c->ownership->peer_id_context, source_node.id, source_qkp) ||
        !c->ownership->peer_id(c->ownership->peer_id_context, target_node.id, target_qkp) ||
        strcmp(source_qkp, txn->source_qkp_id) || strcmp(target_qkp, txn->target_qkp_id))
        return false;
    for (uint32_t slot = first; slot <= last; ++slot) {
        uint16_t owner = QIHSE_CLUSTER_NODE_NONE;
        qihse_cluster_slot_state_t state = QIHSE_CLUSTER_SLOT_STABLE;
        if (!qihse_cluster_topology_get_slot(c->ownership->topology, (uint16_t)slot,
                &owner, &state, NULL) || owner != source ||
            state != QIHSE_CLUSTER_SLOT_STABLE) return false;
    }
    return true;
}

static bool activate_and_publish(qihse_cluster_transfer_context_t *c,
                                 uint16_t target_index,
                                 const qihse_cluster_ownership_txn_t *txn,
                                 char *err, size_t err_cap) {
    char first[8], last[8], source_lsn[32], epoch[32], target_lsn[32], checksum[65];
    snprintf(first, sizeof(first), "%u", (unsigned)txn->start);
    snprintf(last, sizeof(last), "%u", (unsigned)txn->end);
    snprintf(source_lsn, sizeof(source_lsn), "%llu", (unsigned long long)txn->source_lsn);
    snprintf(epoch, sizeof(epoch), "%llu", (unsigned long long)txn->config_epoch);
    snprintf(target_lsn, sizeof(target_lsn), "%llu", (unsigned long long)txn->target_lsn);
    hex32(txn->proof_digest, checksum);
    const void *parts[] = {"REPL.CT2", "ACTIVATE", txn->transfer_id,
        txn->source_id, txn->target_id, txn->source_qkp_id, txn->target_qkp_id,
        txn->generation, first, last, source_lsn, epoch, target_lsn, checksum};
    const size_t lens[] = {8u, 8u, strlen(txn->transfer_id), strlen(txn->source_id),
        strlen(txn->target_id), strlen(txn->source_qkp_id), strlen(txn->target_qkp_id),
        strlen(txn->generation), strlen(first), strlen(last), strlen(source_lsn),
        strlen(epoch), strlen(target_lsn), 64u};
    qihse_resp_ct_reply_t reply = {0};
    (void)ct_rpc(c->ownership, target_index, txn->target_qkp_id,
                 parts, lens, 14u, &reply);
    qihse_resp_ct_reply_free(&reply);
    qihse_cluster_ct_activation_receipt_t *receipt = NULL;
    /* Treat the typed durable receipt as the completion authority. ACTIVATE
     * may have committed at the target even when its transport reply was
     * lost; querying only after +OK strands a recoverable transfer fenced. */
    bool activated = qihse_resp_ct_peer_activation_receipt_query_to(c->ownership->resp_server,
            target_index, txn->target_qkp_id, txn->transfer_id,
            txn->source_id, txn->target_id, txn->source_qkp_id,
            txn->target_qkp_id, txn->generation, txn->start, txn->end,
            txn->source_lsn, txn->config_epoch, txn->target_lsn,
            txn->proof_digest, &receipt) && receipt;
    if (!activated) {
        set_error(err, err_cap, "target activation is unconfirmed; source remains fenced and unpublished");
        return false;
    }
    uint64_t received_target_lsn = 0;
    unsigned char received_checksum[32] = {0};
    bool valid = qihse_resp_ct_activation_receipt_validate(receipt,
        txn->transfer_id, txn->source_id, txn->target_id,
        txn->source_qkp_id, txn->target_qkp_id, txn->generation,
        txn->start, txn->end, txn->source_lsn, txn->config_epoch,
        &received_target_lsn, received_checksum) &&
        received_target_lsn == txn->target_lsn &&
        CRYPTO_memcmp(received_checksum, txn->proof_digest, 32) == 0;
    OPENSSL_cleanse(received_checksum, sizeof(received_checksum));
    bool published = valid && qihse_cluster_ownership_transfer_publish(
        c->ownership, txn->transfer_id, receipt, err, err_cap);
    qihse_resp_ct_activation_receipt_free(receipt);
    if (!valid) set_error(err, err_cap, "QKP activation receipt failed exact tuple validation");
    return published;
}

static bool valid_resume(uint64_t offset, uint64_t total, size_t chunk) {
    return offset <= total && (offset == total || offset % chunk == 0);
}

static bool send_chunk(qihse_cluster_transfer_context_t *c,
                       uint16_t target_index,
                       const qihse_cluster_ownership_txn_t *txn,
                       const char image_sha[65], const char range_sha[65],
                       uint64_t offset, const unsigned char *bytes, size_t len,
                       uint64_t total, size_t chunk, uint64_t *out_next) {
    uint64_t next = 0;
    for (unsigned attempt = 0; attempt < CT_TRANSFER_MAX_RESUMES; ++attempt) {
        if (ct_chunk(c->ownership, target_index, txn, offset, total, image_sha, bytes, len, &next) &&
            next == offset + len) {
            *out_next = next;
            return true;
        }
        /* A lost ACK is ambiguous: ask the target's durable cursor before
         * retrying. The same bytes at the same offset are idempotent. */
        next = 0;
        if (!ct_begin_or_status(c->ownership, target_index, txn, total,
                image_sha, range_sha, "STATUS", &next, NULL, 0u) ||
            !valid_resume(next, total, chunk) || next > offset + len) return false;
        if (next == offset + len) {
            *out_next = next;
            return true;
        }
        if (next != offset) return false;
    }
    return false;
}

qihse_cluster_transfer_result_t qihse_cluster_transfer_range(
    qihse_cluster_transfer_context_t *c, const char *transfer_id,
    uint16_t source_index, uint16_t target_index,
    uint16_t first_slot, uint16_t last_slot,
    char *err, size_t err_cap) {
    if (err && err_cap) err[0] = '\0';
    if (!c || !c->ownership || !c->ownership->store || !c->ownership->principal ||
        !c->ownership->data_principal ||
        !c->ownership->resp_server ||
        !transfer_id || !*transfer_id || strlen(transfer_id) > QIHSE_OWNERSHIP_ID_MAX ||
        first_slot > last_slot || last_slot >= QIHSE_CLUSTER_SLOT_COUNT ||
        source_index == target_index) {
        set_error(err, err_cap, "invalid CT2 transfer context or range");
        errno = EINVAL;
        return QIHSE_CLUSTER_TRANSFER_REJECTED;
    }
    if (!qihse_auth_user_is_active(c->ownership->principal) ||
        qihse_user_get_role(c->ownership->principal) != QIHSE_ROLE_OPERATOR ||
        qihse_user_get_tenant_id(c->ownership->principal) != QIHSE_TENANT_SYSTEM) {
        set_error(err, err_cap, "CT2 range transfer requires an active system Operator");
        errno = EACCES;
        return QIHSE_CLUSTER_TRANSFER_REJECTED;
    }
    if (!qihse_auth_user_is_active(c->ownership->data_principal) ||
        !qihse_auth_can_access(c->ownership->data_principal, UINT16_MAX, UINT16_MAX)) {
        set_error(err, err_cap, "CT2 source data principal lacks full range clearance and SCI scope");
        errno = EACCES;
        return QIHSE_CLUSTER_TRANSFER_REJECTED;
    }

    /* A finalized retry is a local historical lookup only. Do it before any
     * live ownership checks or network traffic: later valid moves may have
     * changed the current owner, but must not make a lost COMMITTED reply
     * unsafe to reconcile. */
    qihse_cluster_ownership_txn_t finalized;
    memset(&finalized, 0, sizeof(finalized));
    if (qihse_cluster_ownership_transfer_get_finalized(c->ownership, transfer_id,
            &finalized, NULL, 0)) {
        bool exact = valid_finalized_txn(&finalized, transfer_id, source_index,
                target_index, first_slot, last_slot) &&
            trusted_topology_mapping_matches(c, &finalized, source_index, target_index);
        if (!exact) {
            OPENSSL_cleanse(&finalized, sizeof(finalized));
            set_error(err, err_cap, "finalized CT2 retry tuple or trusted topology mapping differs");
            errno = EINVAL;
            return QIHSE_CLUSTER_TRANSFER_REJECTED;
        }
        progress(c, QIHSE_CLUSTER_TRANSFER_COMMITTING, 0, 0);
        /* FINALIZED already records verified target activation. Repair the
         * local publication crash window and reannounce from that evidence;
         * a completed operation must not become pending because its former
         * target is now offline or has advanced to another generation. */
        bool finished = qihse_cluster_ownership_transfer_finish_finalized(
            c->ownership, transfer_id, err, err_cap);
        OPENSSL_cleanse(&finalized, sizeof(finalized));
        return finished ? QIHSE_CLUSTER_TRANSFER_COMMITTED : QIHSE_CLUSTER_TRANSFER_PENDING;
    }
    OPENSSL_cleanse(&finalized, sizeof(finalized));

    size_t chunk = c->chunk_bytes ? c->chunk_bytes : CT_TRANSFER_DEFAULT_CHUNK;
    if (!chunk || chunk > CT_TRANSFER_MAX_CHUNK) {
        set_error(err, err_cap, "CT2 chunk size must be 1..12288 bytes");
        errno = EINVAL;
        return QIHSE_CLUSTER_TRANSFER_REJECTED;
    }

    qihse_cluster_ownership_txn_t txn;
    memset(&txn, 0, sizeof(txn));
    if (qihse_cluster_ownership_transfer_get_committed(c->ownership, transfer_id,
            &txn, NULL, 0)) {
        if (!valid_committed_txn(&txn, transfer_id, source_index, target_index,
                                 first_slot, last_slot) ||
            !trusted_topology_mapping_matches(c, &txn, source_index, target_index)) {
            set_error(err, err_cap, "committed CT2 retry tuple or trusted topology mapping differs");
            return QIHSE_CLUSTER_TRANSFER_PENDING;
        }
        progress(c, QIHSE_CLUSTER_TRANSFER_COMMITTING, 0, 0);
        return activate_and_publish(c, target_index, &txn, err, err_cap)
            ? QIHSE_CLUSTER_TRANSFER_COMMITTED : QIHSE_CLUSTER_TRANSFER_PENDING;
    }

    uint64_t prepared_cut = 0;
    bool newly_prepared = false;
    if (!qihse_cluster_ownership_transfer_get_prepared(c->ownership, transfer_id,
            &txn, NULL, 0)) {
        bool fence_may_be_active = false;
        if (!qihse_cluster_ownership_transfer_prepare_ex(c->ownership, transfer_id,
                source_index, target_index, first_slot, last_slot,
                &prepared_cut, &fence_may_be_active, err, err_cap)) {
            /* PREPARE can fail after INTENT and the KV fence are durable but
             * before PREPARED was appended. Recovery may now bind that fence
             * to the intent; report the unresolved outcome as PENDING instead
             * of claiming that no transfer was prepared. */
            bool recovered = qihse_cluster_ownership_transfer_get_prepared(
                c->ownership, transfer_id, &txn, NULL, 0);
            if (recovered && txn.phase == QIHSE_OWNERSHIP_PREPARED &&
                !strcmp(txn.transfer_id, transfer_id)) {
                OPENSSL_cleanse(&txn, sizeof(txn));
                if (!err || !err_cap || !err[0])
                    set_error(err, err_cap,
                        "CT2 prepare failed after fencing; source remains fenced and recovery is required");
                return QIHSE_CLUSTER_TRANSFER_PENDING;
            }
            OPENSSL_cleanse(&txn, sizeof(txn));
            if (fence_may_be_active) {
                if (!err || !err_cap || !err[0])
                    set_error(err, err_cap,
                        "CT2 prepare outcome is unresolved after fencing began; source may remain fenced");
                return QIHSE_CLUSTER_TRANSFER_PENDING;
            }
            return QIHSE_CLUSTER_TRANSFER_REJECTED;
        }
        newly_prepared = true;
        progress(c, QIHSE_CLUSTER_TRANSFER_FENCED, 0, 0);
        memset(&txn, 0, sizeof(txn));
        if (!qihse_cluster_ownership_transfer_get_prepared(c->ownership, transfer_id,
                &txn, err, err_cap)) {
            return prewire_failure(c, transfer_id, source_index, target_index,
                newly_prepared, "durable CT2 PREPARED tuple is unavailable", err, err_cap);
        }
    } else {
        prepared_cut = txn.source_lsn;
        progress(c, QIHSE_CLUSTER_TRANSFER_FENCED, 0, 0);
    }
    if (!valid_txn(&txn, transfer_id, source_index, target_index,
                   first_slot, last_slot) || txn.source_lsn != prepared_cut ||
        !topology_matches(c, &txn, source_index, target_index,
                          first_slot, last_slot)) {
        return prewire_failure(c, transfer_id, source_index, target_index,
            newly_prepared, "durable CT2 PREPARED tuple failed validation", err, err_cap);
    }

    unsigned char owner_token[QIHSE_KV_CT_TOKEN_BYTES] = {0};
    qihse_kv_ct_range_snapshot_t *snapshot = NULL;
    unsigned char image_sha256[32] = {0};
    uint64_t source_cut = 0;
    errno = 0;
    bool exported = qihse_kv_ct_owner_token_get(c->ownership->store,
                         c->ownership->principal, owner_token) &&
        qihse_kv_ct_range_export(c->ownership->store, c->ownership->principal,
            c->ownership->data_principal,
            transfer_id, txn.target_qkp_id, txn.generation, first_slot, last_slot,
            owner_token, &snapshot, &source_cut, image_sha256) == 0;
    int export_errno = errno;
    OPENSSL_cleanse(owner_token, sizeof(owner_token));
    if (!exported || !snapshot || source_cut != txn.source_lsn) {
        if (snapshot) qihse_kv_ct_range_snapshot_destroy(snapshot);
        qihse_cluster_transfer_result_t failed = prewire_failure(c, transfer_id, source_index, target_index,
            newly_prepared, "authenticated range snapshot failed or source cut changed", err, err_cap);
        return !exported && (export_errno == E2BIG || export_errno == EFBIG) &&
            failed == QIHSE_CLUSTER_TRANSFER_REJECTED
            ? QIHSE_CLUSTER_TRANSFER_TOO_LARGE : failed;
    }
    uint64_t total = 0;
    if (!qihse_kv_ct_range_snapshot_size(snapshot, c->ownership->data_principal, &total)) total = 0;
    if (!total || total > (uint64_t)INT64_MAX) {
        qihse_kv_ct_range_snapshot_destroy(snapshot);
        qihse_cluster_transfer_result_t failed = prewire_failure(c, transfer_id, source_index, target_index,
            newly_prepared, "CT2 range snapshot is empty or exceeds supported file offsets", err, err_cap);
        return total > (uint64_t)INT64_MAX && failed == QIHSE_CLUSTER_TRANSFER_REJECTED
            ? QIHSE_CLUSTER_TRANSFER_TOO_LARGE : failed;
    }
    progress(c, QIHSE_CLUSTER_TRANSFER_SNAPSHOTTED, 0, total);
    char image_sha_hex[65], range_sha_hex[65];
    unsigned char range_sha256[32] = {0};
    hex32(image_sha256, image_sha_hex);
    if (!source_range_checksum(c->ownership, &txn, range_sha256)) {
        qihse_kv_ct_range_snapshot_destroy(snapshot);
        return prewire_failure(c, transfer_id, source_index, target_index,
            newly_prepared, "canonical CT2 source range checksum is unavailable", err, err_cap);
    }
    hex32(range_sha256, range_sha_hex);
    OPENSSL_cleanse(range_sha256, sizeof(range_sha256));

    uint64_t offset = 0;
    char begin_diag[160] = {0}, status_diag[160] = {0};
    bool started = ct_begin_or_status(c->ownership, target_index, &txn, total,
                                      image_sha_hex, range_sha_hex, "BEGIN", &offset,
                                      begin_diag, sizeof(begin_diag));
    if (!started) {
        /* BEGIN might have reached the peer before the connection failed. Only
         * a matching durable STATUS can resolve this ambiguity. */
        offset = 0;
        started = ct_begin_or_status(c->ownership, target_index, &txn, total,
                                     image_sha_hex, range_sha_hex, "STATUS", &offset,
                                     status_diag, sizeof(status_diag));
    }
    if (!started || !valid_resume(offset, total, chunk)) {
        qihse_kv_ct_range_snapshot_destroy(snapshot);
        if (begin_diag[0] || status_diag[0]) {
            char message[256];
            snprintf(message, sizeof(message),
                "target CT2 cursor unavailable (BEGIN: %.72s; STATUS: %.72s); source remains fenced",
                begin_diag[0] ? begin_diag : "no error reply",
                status_diag[0] ? status_diag : "no error reply");
            set_error(err, err_cap, message);
        } else {
            set_error(err, err_cap, "target CT2 transfer cursor is unavailable or invalid; source remains fenced");
        }
        return QIHSE_CLUSTER_TRANSFER_PENDING;
    }

    unsigned char *buffer = malloc(chunk);
    if (!buffer) {
        qihse_kv_ct_range_snapshot_destroy(snapshot);
        set_error(err, err_cap, "cannot allocate bounded CT2 chunk buffer; source remains fenced");
        return QIHSE_CLUSTER_TRANSFER_PENDING;
    }
    bool stream_ok = true;
    while (offset < total) {
        size_t want = total - offset < chunk ? (size_t)(total - offset) : chunk;
        size_t got = 0;
        if (!qihse_kv_ct_range_snapshot_read(snapshot, c->ownership->data_principal,
                offset, buffer, want, &got) ||
            got != want) {
            stream_ok = false;
            break;
        }
        uint64_t next = 0;
        progress(c, QIHSE_CLUSTER_TRANSFER_SENDING, offset, total);
        if (!send_chunk(c, target_index, &txn, image_sha_hex, range_sha_hex, offset, buffer, got,
                        total, chunk, &next)) {
            stream_ok = false;
            break;
        }
        offset = next;
    }
    OPENSSL_cleanse(buffer, chunk);
    free(buffer);
    qihse_kv_ct_range_snapshot_destroy(snapshot);
    if (!stream_ok || offset != total) {
        set_error(err, err_cap, "CT2 chunk transfer interrupted; source remains fenced for resume");
        return QIHSE_CLUSTER_TRANSFER_PENDING;
    }

    progress(c, QIHSE_CLUSTER_TRANSFER_SEALING, total, total);
    /* SEAL may have durably completed even if its reply was lost. The
     * following pinned receipt query decides whether COMMIT is authorized. */
    (void)ct_seal(c->ownership, target_index, &txn, total,
                  image_sha_hex, range_sha_hex);
    qihse_cluster_ct_peer_receipt_t *receipt = NULL;
    if (!qihse_resp_ct_peer_receipt_query_to(c->ownership->resp_server, target_index,
            txn.target_qkp_id,
            txn.transfer_id, txn.source_id, txn.target_id,
            txn.source_qkp_id, txn.target_qkp_id, txn.generation,
            txn.start, txn.end, txn.source_lsn, txn.config_epoch, &receipt) || !receipt) {
        set_error(err, err_cap, "QKP-pinned target receipt is unavailable; source remains fenced");
        return QIHSE_CLUSTER_TRANSFER_PENDING;
    }
    uint64_t target_lsn = 0;
    unsigned char target_checksum[32] = {0};
    bool receipt_ok = qihse_resp_ct_peer_receipt_validate(receipt,
        txn.transfer_id, txn.source_id, txn.target_id,
        txn.source_qkp_id, txn.target_qkp_id, txn.generation,
        txn.start, txn.end, txn.source_lsn, txn.config_epoch,
        &target_lsn, target_checksum);
    OPENSSL_cleanse(target_checksum, sizeof(target_checksum));
    if (!receipt_ok) {
        qihse_resp_ct_peer_receipt_free(receipt);
        set_error(err, err_cap, "target receipt does not match the prepared transfer tuple");
        return QIHSE_CLUSTER_TRANSFER_PENDING;
    }

    progress(c, QIHSE_CLUSTER_TRANSFER_COMMITTING, total, total);
    bool committed = qihse_cluster_ownership_transfer_commit(c->ownership,
        transfer_id, source_index, target_index, receipt, err, err_cap);
    qihse_resp_ct_peer_receipt_free(receipt);
    if (!committed) {
        OPENSSL_cleanse(target_checksum, sizeof(target_checksum));
        return QIHSE_CLUSTER_TRANSFER_PENDING;
    }
    /* The ownership commit persists the source's COMMITTED phase and permanent
     * fence but intentionally does not publish topology. Only durable target
     * activation can authorize the final owner-map publication. */
    qihse_cluster_ownership_txn_t committed_txn;
    memset(&committed_txn, 0, sizeof(committed_txn));
    if (!qihse_cluster_ownership_transfer_get_committed(c->ownership, transfer_id,
            &committed_txn, err, err_cap)) {
        OPENSSL_cleanse(target_checksum, sizeof(target_checksum));
        set_error(err, err_cap, "source COMMITTED journal state needs recovery before activation");
        return QIHSE_CLUSTER_TRANSFER_PENDING;
    }
    OPENSSL_cleanse(target_checksum, sizeof(target_checksum));
    if (!valid_committed_txn(&committed_txn, transfer_id, source_index, target_index,
                             first_slot, last_slot) ||
        !topology_matches(c, &committed_txn, source_index, target_index,
                          first_slot, last_slot) ||
        !activate_and_publish(c, target_index, &committed_txn, err, err_cap))
        return QIHSE_CLUSTER_TRANSFER_PENDING;
    set_error(err, err_cap, "");
    return QIHSE_CLUSTER_TRANSFER_COMMITTED;
}

static bool group_claim_bitmap_matches(const qihse_kv_ct_lane_authority_claim_t* claim,
        uint16_t first, uint16_t last) {
    if (!claim || first > last || last >= QIHSE_CLUSTER_SLOT_COUNT) return false;
    uint8_t expected[QIHSE_KV_CT_SLOT_BITMAP_BYTES] = {0};
    for (uint32_t slot = first; slot <= last; ++slot)
        expected[slot / 8u] |= (uint8_t)(1u << (slot % 8u));
    bool ok = CRYPTO_memcmp(expected, claim->slots, sizeof(expected)) == 0;
    OPENSSL_cleanse(expected, sizeof(expected));
    return ok;
}

static bool group_digest_nonzero(const unsigned char digest[32]) {
    unsigned char value = 0u;
    for (size_t i = 0; i < 32u; ++i) value |= digest[i];
    return value != 0u;
}

static bool group_claim_reservation_matches(
        const qihse_kv_ct_lane_authority_claim_t* a,
        const qihse_kv_ct_lane_authority_claim_t* b) {
    return a && b && a->operation == b->operation &&
        !strcmp(a->transfer_id, b->transfer_id) &&
        !strcmp(a->source_group_id, b->source_group_id) &&
        !strcmp(a->target_group_id, b->target_group_id) &&
        !strcmp(a->source_qkp_id, b->source_qkp_id) &&
        !strcmp(a->target_qkp_id, b->target_qkp_id) &&
        !strcmp(a->source_generation, b->source_generation) &&
        !strcmp(a->target_generation, b->target_generation) &&
        !strcmp(a->successor_qkp_id, b->successor_qkp_id) &&
        CRYPTO_memcmp(a->slots, b->slots, sizeof(a->slots)) == 0 &&
        a->grant_epoch == b->grant_epoch && a->reserve_index == b->reserve_index &&
        CRYPTO_memcmp(a->reserve_digest, b->reserve_digest, 32u) == 0 &&
        a->final_decision_index == b->final_decision_index &&
        CRYPTO_memcmp(a->final_decision_digest, b->final_decision_digest, 32u) == 0 &&
        CRYPTO_memcmp(a->certificate_head_digest, b->certificate_head_digest, 32u) == 0 &&
        CRYPTO_memcmp(a->promotion_event_digest, b->promotion_event_digest, 32u) == 0 &&
        a->source_cut == b->source_cut;
}

static bool group_stage_begin(qihse_cluster_ownership_context_t* ownership,
        uint16_t index, const char* peer, const unsigned char* claim,
        size_t claim_len, uint64_t total, uint64_t* out_offset) {
    char total_text[32];
    snprintf(total_text, sizeof(total_text), "%llu", (unsigned long long)total);
    return group_rpc_integer(ownership, index, peer, "GROUP-BEGIN",
        claim, claim_len, total_text, out_offset, NULL, 0u);
}

static bool group_send_one_peer(qihse_cluster_ownership_context_t* ownership,
        uint16_t index, const char* peer, const unsigned char* claim,
        size_t claim_len, qihse_kv_replica_snapshot_t* snapshot,
        qihse_user_t* data_principal, uint64_t total, uint64_t* offset,
        unsigned char* buffer, size_t chunk) {
    if (!ownership || !snapshot || !offset || *offset >= total) return false;
    size_t want = total - *offset < chunk ? (size_t)(total - *offset) : chunk;
    size_t got = 0u;
    if (!qihse_kv_replica_snapshot_read(snapshot, data_principal, *offset,
            buffer, want, &got) || got != want) return false;
    uint64_t next = 0u;
    bool sent = group_rpc_chunk(ownership, index, peer, claim, claim_len,
        *offset, total, buffer, got, &next) && next == *offset + got;
    if (!sent) {
        /* A lost ACK or process restart is resolved from the peer's durable
         * file size. GROUP-BEGIN is idempotent for an exact claim. */
        uint64_t durable = 0u;
        if (!group_stage_begin(ownership, index, peer, claim, claim_len,
                total, &durable)) return false;
        if (durable == *offset + got) sent = true;
        else if (durable == *offset) {
            sent = group_rpc_chunk(ownership, index, peer, claim, claim_len,
                *offset, total, buffer, got, &next) && next == *offset + got;
        }
    }
    if (sent) *offset += got;
    OPENSSL_cleanse(buffer, want);
    return sent;
}

static bool group_successor(qihse_cluster_ownership_context_t* ownership,
        const qihse_kv_ct_lane_authority_claim_t* claim,
        uint16_t* out_index, bool* out_is_source) {
    if (out_index) *out_index = 0u;
    if (out_is_source) *out_is_source = false;
    if (!ownership || !claim || !out_index || !out_is_source ||
        !ownership->range_authority_context) return false;
    qihse_cluster_range_authority_t* authority = ownership->range_authority_context;
    if (!authority->resolve_successor || !authority->group_context) return false;
    char topology_id[QIHSE_CLUSTER_NODE_ID_LEN + 1u] = {0};
    char qkp_id[QIHSE_KV_CT_ID_MAX + 1u] = {0};
    bool ok = authority->resolve_successor(authority->group_context,
            ownership->principal, claim->target_group_id, topology_id, qkp_id) &&
        strcmp(qkp_id, claim->successor_qkp_id) == 0 &&
        group_topology_index(ownership, qkp_id, out_index);
    if (ok) *out_is_source = strcmp(qkp_id, claim->source_qkp_id) == 0;
    OPENSSL_cleanse(topology_id, sizeof(topology_id));
    OPENSSL_cleanse(qkp_id, sizeof(qkp_id));
    return ok;
}

qihse_cluster_transfer_result_t qihse_cluster_transfer_range_group(
    qihse_cluster_transfer_context_t* c, const char* transfer_id,
    uint16_t source_index, uint16_t target_index, uint16_t first_slot,
    uint16_t last_slot, const char* expected_source_generation,
    char* err, size_t err_cap) {
    if (err && err_cap) err[0] = '\0';
    qihse_cluster_ownership_context_t* ownership = c ? c->ownership : NULL;
    if (!c || !ownership || !ownership->store || !ownership->principal ||
        !ownership->data_principal || !ownership->resp_server || !transfer_id ||
        !*transfer_id || strlen(transfer_id) > QIHSE_OWNERSHIP_ID_MAX ||
        first_slot > last_slot || last_slot >= QIHSE_CLUSTER_SLOT_COUNT ||
        source_index == target_index || !ownership->range_authority_context ||
        !ownership->lane_claim || !ownership->lane_verify_claim) {
        set_error(err, err_cap, "invalid quorum-authoritative CT group transfer context");
        errno = EINVAL;
        return QIHSE_CLUSTER_TRANSFER_REJECTED;
    }
    if (!qihse_auth_user_is_active(ownership->principal) ||
        qihse_user_get_role(ownership->principal) != QIHSE_ROLE_OPERATOR ||
        qihse_user_get_tenant_id(ownership->principal) != QIHSE_TENANT_SYSTEM ||
        !qihse_auth_user_is_active(ownership->data_principal) ||
        qihse_user_get_tenant_id(ownership->data_principal) != QIHSE_TENANT_SYSTEM) {
        set_error(err, err_cap, "group transfer requires an active system Operator and system data principal");
        errno = EACCES;
        return QIHSE_CLUSTER_TRANSFER_REJECTED;
    }
    /* Manual callers omit the generation. Pin it to the original local
     * operation when retrying, or to the actual SOURCE group for a new move. */
    char resolved_generation[33] = {0};
    if (!expected_source_generation) {
        qihse_cluster_ownership_txn_t previous = {0};
        if (qihse_cluster_ownership_transfer_get_finalized(ownership, transfer_id,
                &previous, NULL, 0) ||
            qihse_cluster_ownership_transfer_get_committed(ownership, transfer_id,
                &previous, NULL, 0) ||
            qihse_cluster_ownership_transfer_get_prepared(ownership, transfer_id,
                &previous, NULL, 0)) {
            if (strlen(previous.generation) == 32u)
                memcpy(resolved_generation, previous.generation, 33u);
        } else {
            uint8_t slots[QIHSE_KV_CT_SLOT_BITMAP_BYTES] = {0};
            for (uint32_t slot = first_slot; slot <= last_slot; ++slot)
                slots[slot / 8u] |= (uint8_t)(1u << (slot % 8u));
            qihse_kv_ct_lane_status_t source = {0};
            if (qihse_kv_ct_lane_source_for_slots(ownership->store,
                    ownership->principal, slots, &source) &&
                strlen(source.generation) == 32u)
                memcpy(resolved_generation, source.generation, 33u);
        }
        expected_source_generation = resolved_generation;
    }
    if (strlen(expected_source_generation) != 32u) {
        set_error(err, err_cap, "source group generation is unavailable");
        return QIHSE_CLUSTER_TRANSFER_REJECTED;
    }
    /* Resolve durable group history against the common FINAL decision before
     * consulting the current local owner/generation map. A restart may have
     * left only the source journal COMMITTED after C already activated. */
    bool unresolved = false;
    if (!qihse_cluster_ownership_replay_control(ownership, &unresolved,
            err, err_cap)) {
        set_error(err, err_cap, "group ownership history remains unresolved");
        return QIHSE_CLUSTER_TRANSFER_PENDING;
    }
    size_t chunk = c->chunk_bytes ? c->chunk_bytes : CT_TRANSFER_DEFAULT_CHUNK;
    if (!chunk || chunk > CT_TRANSFER_MAX_CHUNK) {
        set_error(err, err_cap, "CT2 chunk size must be 1..12288 bytes");
        errno = EINVAL;
        return QIHSE_CLUSTER_TRANSFER_REJECTED;
    }

    qihse_cluster_ownership_txn_t txn;
    memset(&txn, 0, sizeof(txn));
    if (qihse_cluster_ownership_transfer_get_finalized(ownership, transfer_id,
            &txn, NULL, 0)) {
        bool exact = txn.phase == QIHSE_OWNERSHIP_FINALIZED &&
            !strcmp(txn.transfer_id, transfer_id) &&
            txn.start == first_slot && txn.end == last_slot && txn.lane_id[0] &&
            !strcmp(txn.generation, expected_source_generation);
        bool done = exact && qihse_cluster_ownership_transfer_finish_finalized(
            ownership, transfer_id, err, err_cap);
        OPENSSL_cleanse(&txn, sizeof(txn));
        return done ? QIHSE_CLUSTER_TRANSFER_COMMITTED
                    : QIHSE_CLUSTER_TRANSFER_REJECTED;
    }
    memset(&txn, 0, sizeof(txn));
    if (qihse_cluster_ownership_transfer_get_committed(ownership, transfer_id,
            &txn, NULL, 0)) {
        bool ok = txn.start == first_slot && txn.end == last_slot &&
            !strcmp(txn.generation, expected_source_generation) &&
            trusted_topology_mapping_matches(c, &txn, source_index, target_index) &&
            activate_and_publish(c, target_index, &txn, err, err_cap);
        OPENSSL_cleanse(&txn, sizeof(txn));
        return ok ? QIHSE_CLUSTER_TRANSFER_COMMITTED
                  : QIHSE_CLUSTER_TRANSFER_PENDING;
    }

    uint64_t source_cut = 0u;
    bool recovery_may_be_needed = false;
    if (!qihse_cluster_ownership_transfer_get_prepared(ownership,
            transfer_id, &txn, NULL, 0)) {
        uint8_t selected_slots[QIHSE_KV_CT_SLOT_BITMAP_BYTES] = {0};
        for (uint32_t slot = first_slot; slot <= last_slot; ++slot)
            selected_slots[slot / 8u] |= (uint8_t)(1u << (slot % 8u));
        qihse_kv_ct_lane_status_t current_lane;
        memset(&current_lane, 0, sizeof(current_lane));
        bool generation_current = qihse_kv_ct_lane_source_for_slots(
            ownership->store, ownership->principal, selected_slots,
            &current_lane) &&
            strcmp(current_lane.generation, expected_source_generation) == 0;
        OPENSSL_cleanse(selected_slots, sizeof(selected_slots));
        OPENSSL_cleanse(&current_lane, sizeof(current_lane));
        if (!generation_current) {
            set_error(err, err_cap,
                "selected source generation changed before a new transfer");
            return QIHSE_CLUSTER_TRANSFER_REJECTED;
        }
        if (!qihse_cluster_ownership_transfer_prepare_ex(ownership, transfer_id,
                source_index, target_index, first_slot, last_slot,
                &source_cut, &recovery_may_be_needed, err, err_cap))
            return recovery_may_be_needed ? QIHSE_CLUSTER_TRANSFER_PENDING
                                          : QIHSE_CLUSTER_TRANSFER_REJECTED;
        if (!qihse_cluster_ownership_transfer_get_prepared(ownership,
                transfer_id, &txn, err, err_cap))
            return QIHSE_CLUSTER_TRANSFER_PENDING;
    } else source_cut = txn.source_lsn;

    if (txn.phase != QIHSE_OWNERSHIP_PREPARED ||
        strcmp(txn.transfer_id, transfer_id) || txn.start != first_slot ||
        txn.end != last_slot || txn.source_lsn != source_cut ||
        strcmp(txn.generation, expected_source_generation) != 0 ||
        !txn.lane_id[0] || !txn.generation[0] || !txn.source_qkp_id[0] ||
        !txn.target_qkp_id[0] ||
        !topology_matches(c, &txn, source_index, target_index,
                          first_slot, last_slot)) {
        OPENSSL_cleanse(&txn, sizeof(txn));
        set_error(err, err_cap, "durable group PREPARED tuple is missing its exact source lane or cut");
        return QIHSE_CLUSTER_TRANSFER_PENDING;
    }

    qihse_kv_ct_lane_authority_claim_t claim;
    memset(&claim, 0, sizeof(claim));
    bool claimed = ownership->lane_claim(ownership->range_authority_context,
        ownership->principal, &txn, &claim) &&
        claim.operation == QIHSE_KV_CT_LANE_AUTH_TRANSFER &&
        !strcmp(claim.transfer_id, transfer_id) &&
        !strcmp(claim.source_group_id, txn.lane_id) &&
        !strcmp(claim.source_qkp_id, txn.source_qkp_id) &&
        !strcmp(claim.target_qkp_id, txn.target_qkp_id) &&
        claim.source_cut == source_cut &&
        group_claim_bitmap_matches(&claim, first_slot, last_slot);
    if (!claimed) {
        OPENSSL_cleanse(&claim, sizeof(claim));
        OPENSSL_cleanse(&txn, sizeof(txn));
        set_error(err, err_cap, "quorum reservation did not resolve the exact source slot group");
        return QIHSE_CLUSTER_TRANSFER_PENDING;
    }

    qihse_kv_ct_lane_status_t source_lane;
    memset(&source_lane, 0, sizeof(source_lane));
    bool source_ready = qihse_kv_ct_lane_source_for_slots(ownership->store,
        ownership->principal, claim.slots, &source_lane) &&
        strcmp(source_lane.lane_id, claim.source_group_id) == 0 &&
        strcmp(source_lane.generation, claim.source_generation) == 0;
    OPENSSL_cleanse(&source_lane, sizeof(source_lane));
    if (!source_ready) {
        OPENSSL_cleanse(&claim, sizeof(claim));
        OPENSSL_cleanse(&txn, sizeof(txn));
        set_error(err, err_cap, "selected slots are no longer admitted by the reserved SOURCE group");
        return QIHSE_CLUSTER_TRANSFER_PENDING;
    }

    uint16_t successor_index = 0u;
    bool successor_is_source = false;
    if (!group_successor(ownership, &claim, &successor_index, &successor_is_source)) {
        OPENSSL_cleanse(&claim, sizeof(claim));
        OPENSSL_cleanse(&txn, sizeof(txn));
        set_error(err, err_cap, "quorum target group successor has no trusted QKP topology mapping");
        return QIHSE_CLUSTER_TRANSFER_PENDING;
    }
    unsigned char claim_wire[QIHSE_CT_GROUP_CLAIM_WIRE_BYTES];
    if (!qihse_cluster_transfer_claim_encode(&claim, claim_wire)) {
        OPENSSL_cleanse(&claim, sizeof(claim));
        OPENSSL_cleanse(&txn, sizeof(txn));
        set_error(err, err_cap, "cannot encode canonical quorum reservation");
        return QIHSE_CLUSTER_TRANSFER_PENDING;
    }
    uint64_t target_cursor = 0u, successor_cursor = 0u;
    char diagnostic[160] = {0};
    qihse_kv_ct_lane_transfer_status_t prior_transfer;
    memset(&prior_transfer, 0, sizeof(prior_transfer));
    bool got_prior = qihse_kv_ct_lane_transfer_status(ownership->store,
        ownership->principal, &prior_transfer);
    if (!got_prior) {
        OPENSSL_cleanse(&prior_transfer, sizeof(prior_transfer));
        OPENSSL_cleanse(claim_wire, sizeof(claim_wire));
        OPENSSL_cleanse(&claim, sizeof(claim));
        OPENSSL_cleanse(&txn, sizeof(txn));
        set_error(err, err_cap, "durable lane transfer status is unavailable");
        return QIHSE_CLUSTER_TRANSFER_PENDING;
    }
    bool cursor_pinned = got_prior && prior_transfer.active &&
        prior_transfer.source_fenced &&
        group_claim_reservation_matches(&claim, &prior_transfer.claim) &&
        group_digest_nonzero(prior_transfer.claim.range_digest) &&
        group_digest_nonzero(prior_transfer.claim.image_digest);
    bool prior_matches = got_prior && prior_transfer.active &&
        prior_transfer.source_fenced &&
        group_claim_reservation_matches(&claim, &prior_transfer.claim);
    bool prior_has_partial_digest = got_prior && prior_transfer.active &&
        (group_digest_nonzero(prior_transfer.claim.range_digest) !=
         group_digest_nonzero(prior_transfer.claim.image_digest));
    if (got_prior && prior_transfer.active &&
        (!prior_matches || prior_has_partial_digest)) {
        OPENSSL_cleanse(&prior_transfer, sizeof(prior_transfer));
        OPENSSL_cleanse(claim_wire, sizeof(claim_wire));
        OPENSSL_cleanse(&claim, sizeof(claim));
        OPENSSL_cleanse(&txn, sizeof(txn));
        set_error(err, err_cap, "another or incomplete durable lane transfer must recover before staging");
        return QIHSE_CLUSTER_TRANSFER_PENDING;
    }
    if (cursor_pinned) {
        claim = prior_transfer.claim;
        target_cursor = claim.target_cursor;
        if (!qihse_cluster_transfer_claim_encode(&claim, claim_wire)) {
            OPENSSL_cleanse(&prior_transfer, sizeof(prior_transfer));
            OPENSSL_cleanse(claim_wire, sizeof(claim_wire));
            OPENSSL_cleanse(&claim, sizeof(claim));
            OPENSSL_cleanse(&txn, sizeof(txn));
            set_error(err, err_cap, "cannot restore the pinned target cursor claim");
            return QIHSE_CLUSTER_TRANSFER_PENDING;
        }
        bool successor_ok = false;
        if (successor_is_source) {
            qihse_kv_ct_lane_status_t local_target;
            memset(&local_target, 0, sizeof(local_target));
            successor_ok = qihse_kv_ct_lane_status(ownership->store,
                    ownership->data_principal, claim.target_group_id, &local_target) &&
                local_target.mode == QIHSE_KV_CT_LANE_RECEIVER &&
                strcmp(local_target.source_id, claim.target_qkp_id) == 0 &&
                strcmp(local_target.peer_id, claim.successor_qkp_id) == 0 &&
                strcmp(local_target.generation, claim.target_generation) == 0;
            successor_cursor = local_target.durable_position;
            OPENSSL_cleanse(&local_target, sizeof(local_target));
        } else {
            successor_ok = group_rpc_integer(ownership, successor_index,
                claim.successor_qkp_id, "GROUP-CURSOR", claim_wire,
                sizeof(claim_wire), NULL, &successor_cursor, diagnostic,
                sizeof(diagnostic));
        }
        if (!successor_ok || successor_cursor < target_cursor) {
            OPENSSL_cleanse(&prior_transfer, sizeof(prior_transfer));
            OPENSSL_cleanse(claim_wire, sizeof(claim_wire));
            OPENSSL_cleanse(&claim, sizeof(claim));
            OPENSSL_cleanse(&txn, sizeof(txn));
            set_error(err, err_cap, "pinned target cursor is no longer durable at its successor");
            return QIHSE_CLUSTER_TRANSFER_PENDING;
        }
    } else {
        bool cursor_ok = group_rpc_integer(ownership, target_index,
                claim.target_qkp_id, "GROUP-CURSOR", claim_wire,
                sizeof(claim_wire), NULL, &target_cursor, diagnostic, sizeof(diagnostic));
        if (cursor_ok && successor_is_source) {
            qihse_kv_ct_lane_status_t local_target;
            memset(&local_target, 0, sizeof(local_target));
            cursor_ok = qihse_kv_ct_lane_status(ownership->store,
                ownership->data_principal, claim.target_group_id, &local_target) &&
                local_target.mode == QIHSE_KV_CT_LANE_RECEIVER &&
                strcmp(local_target.source_id, claim.target_qkp_id) == 0 &&
                strcmp(local_target.peer_id, claim.successor_qkp_id) == 0 &&
                strcmp(local_target.generation, claim.target_generation) == 0;
            successor_cursor = local_target.durable_position;
            OPENSSL_cleanse(&local_target, sizeof(local_target));
        } else if (cursor_ok) {
            cursor_ok = group_rpc_integer(ownership, successor_index,
                claim.successor_qkp_id, "GROUP-CURSOR", claim_wire,
                sizeof(claim_wire), NULL, &successor_cursor, diagnostic, sizeof(diagnostic));
        }
        if (!cursor_ok || successor_cursor < target_cursor) {
            OPENSSL_cleanse(&prior_transfer, sizeof(prior_transfer));
            OPENSSL_cleanse(claim_wire, sizeof(claim_wire));
            OPENSSL_cleanse(&claim, sizeof(claim));
            OPENSSL_cleanse(&txn, sizeof(txn));
            set_error(err, err_cap, "target successor has not durably reached the chosen target ACK cut");
            return QIHSE_CLUSTER_TRANSFER_PENDING;
        }
        claim.target_cursor = target_cursor;
    }
    OPENSSL_cleanse(&prior_transfer, sizeof(prior_transfer));
    if (successor_cursor < target_cursor) {
        OPENSSL_cleanse(claim_wire, sizeof(claim_wire));
        OPENSSL_cleanse(&claim, sizeof(claim));
        OPENSSL_cleanse(&txn, sizeof(txn));
        set_error(err, err_cap, "target successor has not durably reached the chosen target ACK cut");
        return QIHSE_CLUSTER_TRANSFER_PENDING;
    }

    qihse_cluster_range_authority_t* authority = ownership->range_authority_context;
    qihse_cluster_range_verifier_t verifier = {authority, ownership->principal};
    qihse_kv_ct_proof_t* proof = qihse_kv_ct_lane_authority_proof_create(
        ownership->store, ownership->principal, ownership->data_principal,
        &claim, qihse_cluster_range_authority_verify_claim, &verifier);
    if (!proof) {
        if (proof) qihse_kv_ct_proof_destroy(proof);
        OPENSSL_cleanse(claim_wire, sizeof(claim_wire));
        OPENSSL_cleanse(&claim, sizeof(claim));
        OPENSSL_cleanse(&txn, sizeof(txn));
        set_error(err, err_cap, "cannot create reservation-bound source transfer proof");
        return QIHSE_CLUSTER_TRANSFER_PENDING;
    }
    qihse_kv_replica_snapshot_t* snapshot = NULL;
    unsigned char range_digest[32] = {0}, image_digest[32] = {0};
    int export_rc = qihse_kv_ct_lane_transfer_source_export(ownership->store,
        ownership->principal, ownership->data_principal, &claim, proof,
        qihse_cluster_range_authority_verify_claim, &verifier,
        &snapshot, range_digest, image_digest);
    if (proof) qihse_kv_ct_proof_destroy(proof);
    uint64_t total = 0u;
    bool exported = export_rc == 0 && snapshot &&
        qihse_kv_replica_snapshot_size(snapshot, ownership->data_principal, &total) &&
        total <= (uint64_t)INT64_MAX;
    if (!exported) {
        if (snapshot) qihse_kv_replica_snapshot_destroy(snapshot);
        OPENSSL_cleanse(range_digest, sizeof(range_digest));
        OPENSSL_cleanse(image_digest, sizeof(image_digest));
        OPENSSL_cleanse(claim_wire, sizeof(claim_wire));
        OPENSSL_cleanse(&claim, sizeof(claim));
        OPENSSL_cleanse(&txn, sizeof(txn));
        if (export_rc != 0 && errno == EACCES) {
            bool aborted = qihse_cluster_ownership_transfer_abort(ownership,
                transfer_id, source_index, target_index, err, err_cap);
            return aborted ? QIHSE_CLUSTER_TRANSFER_REJECTED
                           : QIHSE_CLUSTER_TRANSFER_PENDING;
        }
        set_error(err, err_cap, "source group export is unresolved; the selected range remains fenced");
        return QIHSE_CLUSTER_TRANSFER_PENDING;
    }
    claim.range_digest[0] = 0u;
    memcpy(claim.range_digest, range_digest, sizeof(range_digest));
    memcpy(claim.image_digest, image_digest, sizeof(image_digest));
    OPENSSL_cleanse(range_digest, sizeof(range_digest));
    OPENSSL_cleanse(image_digest, sizeof(image_digest));
    if (!qihse_cluster_transfer_claim_encode(&claim, claim_wire)) {
        qihse_kv_replica_snapshot_destroy(snapshot);
        OPENSSL_cleanse(claim_wire, sizeof(claim_wire));
        OPENSSL_cleanse(&claim, sizeof(claim));
        OPENSSL_cleanse(&txn, sizeof(txn));
        set_error(err, err_cap, "cannot encode authenticated source image claim");
        return QIHSE_CLUSTER_TRANSFER_PENDING;
    }
    unsigned char expected_seal[32] = {0};
    if (!qihse_kv_ct_lane_transfer_checksum(&claim, expected_seal)) {
        qihse_kv_replica_snapshot_destroy(snapshot);
        OPENSSL_cleanse(claim_wire, sizeof(claim_wire));
        OPENSSL_cleanse(&claim, sizeof(claim));
        OPENSSL_cleanse(&txn, sizeof(txn));
        set_error(err, err_cap, "cannot compute composite transfer checksum");
        return QIHSE_CLUSTER_TRANSFER_PENDING;
    }

    progress(c, QIHSE_CLUSTER_TRANSFER_SNAPSHOTTED, 0u, total);
    uint64_t source_offset = 0u, successor_offset = 0u;
    bool started = group_stage_begin(ownership, target_index, claim.target_qkp_id,
        claim_wire, sizeof(claim_wire), total, &source_offset);
    if (started && !successor_is_source)
        started = group_stage_begin(ownership, successor_index,
            claim.successor_qkp_id, claim_wire, sizeof(claim_wire), total,
            &successor_offset);
    else if (successor_is_source) successor_offset = total;
    if (!started || source_offset > total || successor_offset > total) {
        qihse_kv_replica_snapshot_destroy(snapshot);
        OPENSSL_cleanse(expected_seal, sizeof(expected_seal));
        OPENSSL_cleanse(claim_wire, sizeof(claim_wire));
        OPENSSL_cleanse(&claim, sizeof(claim));
        OPENSSL_cleanse(&txn, sizeof(txn));
        set_error(err, err_cap, "target or successor group stage is unavailable; source remains fenced");
        return QIHSE_CLUSTER_TRANSFER_PENDING;
    }
    unsigned char* buffer = malloc(chunk ? chunk : 1u);
    if (!buffer) {
        qihse_kv_replica_snapshot_destroy(snapshot);
        OPENSSL_cleanse(expected_seal, sizeof(expected_seal));
        OPENSSL_cleanse(claim_wire, sizeof(claim_wire));
        OPENSSL_cleanse(&claim, sizeof(claim));
        OPENSSL_cleanse(&txn, sizeof(txn));
        set_error(err, err_cap, "cannot allocate the bounded transfer buffer; source remains fenced");
        return QIHSE_CLUSTER_TRANSFER_PENDING;
    }
    bool stream_ok = true;
    while (source_offset < total || successor_offset < total) {
        bool send_source = source_offset < total &&
            (successor_offset >= total || source_offset <= successor_offset);
        uint64_t* offset = send_source ? &source_offset : &successor_offset;
        uint16_t peer_index = send_source ? target_index : successor_index;
        const char* peer_qkp = send_source ? claim.target_qkp_id : claim.successor_qkp_id;
        progress(c, QIHSE_CLUSTER_TRANSFER_SENDING,
            source_offset < successor_offset ? source_offset : successor_offset, total);
        if (!group_send_one_peer(ownership, peer_index, peer_qkp,
                claim_wire, sizeof(claim_wire), snapshot,
                ownership->data_principal, total, offset, buffer, chunk)) {
            stream_ok = false;
            break;
        }
    }
    OPENSSL_cleanse(buffer, chunk);
    free(buffer);
    qihse_kv_replica_snapshot_destroy(snapshot);
    if (!stream_ok) {
        OPENSSL_cleanse(expected_seal, sizeof(expected_seal));
        OPENSSL_cleanse(claim_wire, sizeof(claim_wire));
        OPENSSL_cleanse(&claim, sizeof(claim));
        OPENSSL_cleanse(&txn, sizeof(txn));
        set_error(err, err_cap, "group snapshot transfer interrupted; source remains fenced for retry");
        return QIHSE_CLUSTER_TRANSFER_PENDING;
    }
    progress(c, QIHSE_CLUSTER_TRANSFER_SEALING, total, total);
    unsigned char source_seal[32] = {0}, successor_seal[32] = {0};
    bool sealed = group_rpc_seal(ownership, target_index, claim.target_qkp_id,
        claim_wire, sizeof(claim_wire), total, source_seal) &&
        CRYPTO_memcmp(source_seal, expected_seal, 32u) == 0;
    if (sealed && !successor_is_source)
        sealed = group_rpc_seal(ownership, successor_index,
            claim.successor_qkp_id, claim_wire, sizeof(claim_wire), total,
            successor_seal) && CRYPTO_memcmp(successor_seal, expected_seal, 32u) == 0;
    else if (successor_is_source) memcpy(successor_seal, expected_seal, 32u);
    if (!sealed) {
        OPENSSL_cleanse(source_seal, sizeof(source_seal));
        OPENSSL_cleanse(successor_seal, sizeof(successor_seal));
        OPENSSL_cleanse(expected_seal, sizeof(expected_seal));
        OPENSSL_cleanse(claim_wire, sizeof(claim_wire));
        OPENSSL_cleanse(&claim, sizeof(claim));
        OPENSSL_cleanse(&txn, sizeof(txn));
        set_error(err, err_cap, "C or D did not persist the identical composite image seal");
        return QIHSE_CLUSTER_TRANSFER_PENDING;
    }

    bool successor_ready = false;
    if (!successor_is_source) {
        qihse_resp_ct_group_stage_receipt_t* successor_receipt = NULL;
        uint64_t receipt_source_cut = 0u, receipt_target_cursor = 0u;
        successor_ready = qihse_resp_ct_group_stage_receipt_query_to(
            ownership->resp_server, successor_index, claim.successor_qkp_id,
            claim_wire, sizeof(claim_wire), &successor_receipt) &&
            qihse_resp_ct_group_stage_receipt_validate(successor_receipt,
                claim_wire, sizeof(claim_wire), claim.successor_qkp_id,
                expected_seal, &receipt_source_cut, &receipt_target_cursor) &&
            receipt_source_cut == claim.source_cut &&
            receipt_target_cursor == claim.target_cursor;
        qihse_resp_ct_group_stage_receipt_free(successor_receipt);
    } else {
        qihse_kv_ct_lane_transfer_status_t local;
        memset(&local, 0, sizeof(local));
        unsigned char local_wire[QIHSE_CT_GROUP_CLAIM_WIRE_BYTES];
        successor_ready = qihse_kv_ct_lane_transfer_status(ownership->store,
                ownership->principal, &local) && local.active && local.source_fenced &&
            qihse_cluster_transfer_claim_encode(&local.claim, local_wire) &&
            qihse_cluster_transfer_claim_encode(&claim, claim_wire) &&
            CRYPTO_memcmp(local_wire, claim_wire, sizeof(local_wire)) == 0;
        OPENSSL_cleanse(local_wire, sizeof(local_wire));
        OPENSSL_cleanse(&local, sizeof(local));
    }
    if (!successor_ready) {
        OPENSSL_cleanse(source_seal, sizeof(source_seal));
        OPENSSL_cleanse(successor_seal, sizeof(successor_seal));
        OPENSSL_cleanse(expected_seal, sizeof(expected_seal));
        OPENSSL_cleanse(claim_wire, sizeof(claim_wire));
        OPENSSL_cleanse(&claim, sizeof(claim));
        OPENSSL_cleanse(&txn, sizeof(txn));
        set_error(err, err_cap, "pinned successor readiness receipt is unavailable");
        return QIHSE_CLUSTER_TRANSFER_PENDING;
    }

    qihse_cluster_ct_peer_receipt_t* receipt = NULL;
    bool receipt_ok = qihse_resp_ct_peer_receipt_query_to(
        ownership->resp_server, target_index, claim.target_qkp_id,
        txn.transfer_id, txn.source_id, txn.target_id, txn.source_qkp_id,
        txn.target_qkp_id, txn.generation, txn.start, txn.end, txn.source_lsn,
        txn.config_epoch, &receipt);
    uint64_t target_lsn = 0u;
    unsigned char receipt_checksum[32] = {0};
    receipt_ok = receipt_ok && receipt && qihse_resp_ct_peer_receipt_validate(
        receipt, txn.transfer_id, txn.source_id, txn.target_id,
        txn.source_qkp_id, txn.target_qkp_id, txn.generation,
        txn.start, txn.end, txn.source_lsn, txn.config_epoch,
        &target_lsn, receipt_checksum) && target_lsn == claim.target_cursor &&
        CRYPTO_memcmp(receipt_checksum, expected_seal, 32u) == 0;
    OPENSSL_cleanse(receipt_checksum, sizeof(receipt_checksum));
    if (!receipt_ok) {
        if (receipt) qihse_resp_ct_peer_receipt_free(receipt);
        OPENSSL_cleanse(source_seal, sizeof(source_seal));
        OPENSSL_cleanse(successor_seal, sizeof(successor_seal));
        OPENSSL_cleanse(expected_seal, sizeof(expected_seal));
        OPENSSL_cleanse(claim_wire, sizeof(claim_wire));
        OPENSSL_cleanse(&claim, sizeof(claim));
        OPENSSL_cleanse(&txn, sizeof(txn));
        set_error(err, err_cap, "target C has not issued the exact group image seal receipt");
        return QIHSE_CLUSTER_TRANSFER_PENDING;
    }
    bool committed = qihse_cluster_ownership_transfer_commit(ownership,
        transfer_id, source_index, target_index, receipt, err, err_cap);
    qihse_resp_ct_peer_receipt_free(receipt);
    OPENSSL_cleanse(source_seal, sizeof(source_seal));
    OPENSSL_cleanse(successor_seal, sizeof(successor_seal));
    OPENSSL_cleanse(expected_seal, sizeof(expected_seal));
    OPENSSL_cleanse(claim_wire, sizeof(claim_wire));
    OPENSSL_cleanse(&claim, sizeof(claim));
    OPENSSL_cleanse(&txn, sizeof(txn));
    if (!committed) return QIHSE_CLUSTER_TRANSFER_PENDING;
    qihse_cluster_ownership_txn_t committed_txn;
    memset(&committed_txn, 0, sizeof(committed_txn));
    bool activated = qihse_cluster_ownership_transfer_get_committed(ownership,
            transfer_id, &committed_txn, err, err_cap) &&
        activate_and_publish(c, target_index, &committed_txn, err, err_cap);
    OPENSSL_cleanse(&committed_txn, sizeof(committed_txn));
    if (!activated) return QIHSE_CLUSTER_TRANSFER_PENDING;
    set_error(err, err_cap, "");
    return QIHSE_CLUSTER_TRANSFER_COMMITTED;
}
