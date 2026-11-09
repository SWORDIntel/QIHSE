#include "qihse_cluster_transfer.h"

#include "qihse_kv_store.h"
#include "qihse_resp_wire.h"

#include <errno.h>
#include <openssl/crypto.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CT_TRANSFER_MAX_IMAGE ((uint64_t)64u << 20)
#define CT_TRANSFER_DEFAULT_CHUNK (12u << 10)
#define CT_TRANSFER_MAX_CHUNK (12u << 10)
#define CT_TRANSFER_MAX_RESUMES 3u

static const char hex_digits[] = "0123456789abcdef";

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

static bool finalized_topology_matches(qihse_cluster_transfer_context_t *c,
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
    bool activated_command = ct_rpc(c->ownership, target_index, txn->target_qkp_id,
                                    parts, lens, 14u, &reply) && reply.data &&
                             reply.len == 5u && memcmp(reply.data, "+OK\r\n", 5u) == 0;
    qihse_resp_ct_reply_free(&reply);
    qihse_cluster_ct_activation_receipt_t *receipt = NULL;
    bool activated = activated_command &&
        qihse_resp_ct_peer_activation_receipt_query_to(c->ownership->resp_server,
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
            finalized_topology_matches(c, &finalized, source_index, target_index);
        OPENSSL_cleanse(&finalized, sizeof(finalized));
        if (!exact) {
            set_error(err, err_cap, "finalized CT2 retry tuple or trusted topology mapping differs");
            errno = EINVAL;
            return QIHSE_CLUSTER_TRANSFER_REJECTED;
        }
        progress(c, QIHSE_CLUSTER_TRANSFER_COMMITTING, 0, 0);
        return QIHSE_CLUSTER_TRANSFER_COMMITTED;
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
            !topology_matches(c, &txn, source_index, target_index,
                              first_slot, last_slot)) {
            set_error(err, err_cap, "committed CT2 tuple does not match requested retry");
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
        if (!qihse_cluster_ownership_transfer_prepare(c->ownership, transfer_id,
                source_index, target_index, first_slot, last_slot,
                &prepared_cut, err, err_cap))
            return QIHSE_CLUSTER_TRANSFER_REJECTED;
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
    if (!total || total > CT_TRANSFER_MAX_IMAGE) {
        qihse_kv_ct_range_snapshot_destroy(snapshot);
        qihse_cluster_transfer_result_t failed = prewire_failure(c, transfer_id, source_index, target_index,
            newly_prepared, "CT2 range snapshot is empty or exceeds 64 MiB", err, err_cap);
        return total > CT_TRANSFER_MAX_IMAGE && failed == QIHSE_CLUSTER_TRANSFER_REJECTED
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
    if (!ct_seal(c->ownership, target_index, &txn, total, image_sha_hex, range_sha_hex)) {
        set_error(err, err_cap, "target CT2 seal is unconfirmed; source remains fenced");
        return QIHSE_CLUSTER_TRANSFER_PENDING;
    }

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
