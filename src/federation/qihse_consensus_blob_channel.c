#include "qihse_consensus_blob_channel.h"

#include <openssl/crypto.h>
#include <stdio.h>
#include <string.h>

#define QBC_PREFIX_MAX (4u + 16u + 16u + 1u + QIHSE_CONSENSUS_GROUP_ID_MAX + 8u + 8u + 4u + 2u + 2u + 2u + QIHSE_CONSENSUS_BLOB_REF_BYTES)
#define QBC_ACK_BYTES 53u
#define QBC_STREAM_CHUNK QIHSE_QKP_MAX_PAYLOAD

typedef struct {
    qihse_qkp_session_t* session;
    int fd;
    uint64_t expected;
    uint64_t received;
} qbc_stream_t;

static bool qbc_group_valid(const char* group);

static bool qbc_system_operator(const qihse_user_t* principal) {
    return principal && qihse_auth_user_is_active(principal) &&
           qihse_user_get_role((qihse_user_t*)principal) == QIHSE_ROLE_OPERATOR &&
           qihse_user_get_tenant_id((qihse_user_t*)principal) == QIHSE_TENANT_SYSTEM;
}

static bool qbc_peer_pinned(const qihse_qkp_session_t* session,
                            const qihse_consensus_channel_config_t* channel) {
    if (!session || !channel || !channel->peer_node_id || !*channel->peer_node_id ||
        !channel->peer_dsa_pub_path || !*channel->peer_dsa_pub_path) return false;
    return qihse_qkp_session_is_replication_peer(session, channel->peer_node_id,
                                                  channel->peer_dsa_pub_path) ||
           qihse_qkp_client_session_is_replication_peer(session, channel->peer_node_id,
                                                         channel->peer_dsa_pub_path);
}

static bool qbc_channel_valid(const qihse_qkp_session_t* session, int fd,
                              const qihse_consensus_channel_config_t* channel,
                              const qihse_user_t* principal) {
    return fd >= 0 && principal && qihse_auth_user_is_active(principal) &&
           channel && qbc_group_valid(channel->group_id) &&
           !qihse_uuid_is_nil(&channel->local_member) &&
           !qihse_uuid_is_nil(&channel->peer_member) &&
           !qihse_uuid_equal(&channel->local_member, &channel->peer_member) &&
           qbc_peer_pinned(session, channel);
}

static void qbc_put_u16(uint8_t* p, uint16_t value) {
    p[0] = (uint8_t)(value >> 8); p[1] = (uint8_t)value;
}

static void qbc_put_u32(uint8_t* p, uint32_t value) {
    p[0] = (uint8_t)(value >> 24); p[1] = (uint8_t)(value >> 16);
    p[2] = (uint8_t)(value >> 8); p[3] = (uint8_t)value;
}

static void qbc_put_u64(uint8_t* p, uint64_t value) {
    for (unsigned i = 0; i < 8u; i++) p[7u - i] = (uint8_t)(value >> (8u * i));
}

static uint16_t qbc_get_u16(const uint8_t* p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

static uint32_t qbc_get_u32(const uint8_t* p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static uint64_t qbc_get_u64(const uint8_t* p) {
    uint64_t value = 0u;
    for (unsigned i = 0; i < 8u; i++) value = (value << 8) | p[i];
    return value;
}

static bool qbc_group_valid(const char* group) {
    if (!group || !*group) return false;
    size_t n = 0u;
    while (n <= QIHSE_CONSENSUS_GROUP_ID_MAX && group[n]) {
        unsigned char c = (unsigned char)group[n];
        if (c < 0x21u || c > 0x7eu) return false;
        n++;
    }
    return n > 0u && n <= QIHSE_CONSENSUS_GROUP_ID_MAX;
}

static bool qbc_build_prefix(const qihse_consensus_channel_config_t* channel,
                             const qihse_consensus_entry_t* entry,
                             uint8_t* out, size_t cap, size_t* out_len) {
    if (!channel || !entry || !out || !out_len || !qbc_group_valid(channel->group_id) ||
        entry->type != QIHSE_CONSENSUS_ENTRY_DATA ||
        entry->payload_len != QIHSE_CONSENSUS_BLOB_REF_BYTES ||
        memcmp(entry->payload, "QBR1", 4u) != 0) return false;
    size_t group_len = strlen(channel->group_id);
    size_t need = 4u + 16u + 16u + 1u + group_len + 8u + 8u + 4u + 2u + 2u + 2u + entry->payload_len;
    if (need > cap || group_len > QIHSE_CONSENSUS_GROUP_ID_MAX ||
        entry->journal_generation == 0u ||
        memcmp(entry->payload, "QBR1", 4u) != 0) return false;
    size_t p = 0u;
    memcpy(out + p, "QBT1", 4u); p += 4u;
    memcpy(out + p, channel->local_member.bytes, 16u); p += 16u;
    memcpy(out + p, channel->peer_member.bytes, 16u); p += 16u;
    out[p++] = (uint8_t)group_len;
    memcpy(out + p, channel->group_id, group_len); p += group_len;
    qbc_put_u64(out + p, entry->journal_generation); p += 8u;
    qbc_put_u64(out + p, entry->hlc.physical_ms); p += 8u;
    qbc_put_u32(out + p, entry->hlc.logical); p += 4u;
    qbc_put_u16(out + p, entry->classif); p += 2u;
    qbc_put_u16(out + p, entry->sci); p += 2u;
    qbc_put_u16(out + p, (uint16_t)entry->payload_len); p += 2u;
    memcpy(out + p, entry->payload, entry->payload_len); p += entry->payload_len;
    *out_len = p;
    return true;
}

static bool qbc_parse_prefix(const qihse_consensus_channel_config_t* channel,
                             const qihse_user_t* principal,
                             const uint8_t* wire, size_t wire_len,
                             qihse_consensus_entry_t* out) {
    if (!channel || !principal || !wire || !out || wire_len < 4u + 33u ||
        memcmp(wire, "QBT1", 4u) != 0 ||
        memcmp(wire + 4u, channel->peer_member.bytes, 16u) != 0 ||
        memcmp(wire + 20u, channel->local_member.bytes, 16u) != 0 ||
        !qbc_system_operator(principal)) return false;
    size_t p = 36u;
    size_t group_len = wire[p++];
    if (group_len == 0u || group_len > QIHSE_CONSENSUS_GROUP_ID_MAX ||
        wire_len < p + group_len + 8u + 8u + 4u + 2u + 2u + 2u) return false;
    if (strlen(channel->group_id) != group_len ||
        memcmp(wire + p, channel->group_id, group_len) != 0) return false;
    qihse_consensus_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    p += group_len;
    entry.journal_generation = qbc_get_u64(wire + p); p += 8u;
    entry.hlc.physical_ms = qbc_get_u64(wire + p); p += 8u;
    entry.hlc.logical = qbc_get_u32(wire + p); p += 4u;
    entry.classif = qbc_get_u16(wire + p); p += 2u;
    entry.sci = qbc_get_u16(wire + p); p += 2u;
    uint16_t payload_len = qbc_get_u16(wire + p); p += 2u;
    if (payload_len != QIHSE_CONSENSUS_BLOB_REF_BYTES ||
        wire_len != p + payload_len || entry.journal_generation == 0u ||
        !qihse_auth_can_access((qihse_user_t*)principal, entry.classif, entry.sci)) return false;
    entry.type = QIHSE_CONSENSUS_ENTRY_DATA;
    entry.payload_len = payload_len;
    memcpy(entry.payload, wire + p, payload_len);
    if (memcmp(entry.payload, "QBR1", 4u) != 0 ||
        qbc_get_u64(entry.payload + 52u) != entry.journal_generation ||
        qbc_get_u16(entry.payload + 60u) != entry.classif ||
        qbc_get_u16(entry.payload + 62u) != entry.sci) return false;
    *out = entry;
    return true;
}

static bool qbc_send_ack(qihse_qkp_session_t* session, int fd, uint8_t status,
                         const uint8_t* reference) {
    uint8_t ack[QBC_ACK_BYTES];
    memcpy(ack, "QBA1", 4u);
    ack[4] = status;
    memcpy(ack + 5u, reference + 64u, QIHSE_BLOB_HASH_BYTES);
    return qihse_qkp_send_sealed(session, fd, ack, sizeof(ack));
}

static bool qbc_receive_status(qihse_qkp_session_t* session, int fd,
                               const uint8_t* reference, uint8_t* out_status) {
    uint8_t ack[QBC_ACK_BYTES];
    ssize_t n = qihse_qkp_recv_sealed(session, fd, ack, sizeof(ack));
    if (n != (ssize_t)sizeof(ack) || memcmp(ack, "QBA1", 4u) != 0 ||
        CRYPTO_memcmp(ack + 5u, reference + 64u, QIHSE_BLOB_HASH_BYTES) != 0 ||
        ack[4] > 2u) return false;
    if (out_status) *out_status = ack[4];
    return true;
}

static int64_t qbc_import_read(void* opaque, uint8_t* out, size_t cap) {
    qbc_stream_t* stream = opaque;
    if (!stream || !out || cap == 0u) return -1;
    if (stream->received == stream->expected) return 0;
    size_t copied = 0u;
    while (copied < cap && stream->received < stream->expected) {
        uint64_t remain = stream->expected - stream->received;
        size_t request = cap - copied;
        if ((uint64_t)request > remain) request = (size_t)remain;
        ssize_t n = qihse_qkp_recv_sealed(stream->session, stream->fd, out + copied, request);
        if (n <= 0 || (size_t)n > request) return -1;
        copied += (size_t)n;
        stream->received += (uint64_t)n;
    }
    return copied ? (int64_t)copied : -1;
}

bool qihse_consensus_blob_channel_send(
    qihse_consensus_blob_context_t* blobs, qihse_qkp_session_t* session, int fd,
    const qihse_consensus_channel_config_t* channel, const qihse_user_t* principal,
    const qihse_consensus_entry_t* entry) {
    if (!blobs || !blobs->blobs || !qbc_channel_valid(session, fd, channel, principal) ||
        !qbc_system_operator(principal) ||
        !entry || !qihse_auth_can_access((qihse_user_t*)principal, entry->classif, entry->sci) ||
        !qihse_consensus_blob_validate(blobs, entry)) return false;
    uint8_t prefix[QBC_PREFIX_MAX]; size_t prefix_len = 0u;
    if (!qbc_build_prefix(channel, entry, prefix, sizeof(prefix), &prefix_len) ||
        !qihse_qkp_send_sealed(session, fd, prefix, prefix_len)) return false;

    const uint8_t* reference = entry->payload;
    uint8_t status = 0u;
    if (!qbc_receive_status(session, fd, reference, &status)) return false;
    if (status == 2u) return true;
    if (status != 1u) return false;

    uint64_t expected = qbc_get_u64(reference + 112u);
    if (expected <= QIHSE_CONSENSUS_BLOB_HEADER_BYTES || expected > QIHSE_BLOB_MAX_SIZE) return false;
    uint8_t chunk[QBC_STREAM_CHUNK];
    uint64_t offset = 0u;
    while (offset < expected) {
        size_t request = sizeof(chunk);
        if ((uint64_t)request > expected - offset) request = (size_t)(expected - offset);
        size_t got = 0u;
        if (!qihse_blob_get_user(blobs->blobs, reference + 64u, offset,
                chunk, request, &got, blobs->principal) || got == 0u || got > request ||
            !qihse_qkp_send_sealed(session, fd, chunk, got)) return false;
        offset += got;
    }
    uint8_t end[4u + QIHSE_BLOB_HASH_BYTES];
    memcpy(end, "QBE1", 4u);
    memcpy(end + 4u, reference + 64u, QIHSE_BLOB_HASH_BYTES);
    if (!qihse_qkp_send_sealed(session, fd, end, sizeof(end))) return false;
    return qbc_receive_status(session, fd, reference, &status) && status == 2u;
}

bool qihse_consensus_blob_channel_receive(
    qihse_consensus_blob_context_t* blobs, qihse_qkp_session_t* session, int fd,
    const qihse_consensus_channel_config_t* channel, const qihse_user_t* principal,
    qihse_consensus_entry_t* out_entry) {
    if (!blobs || !blobs->blobs || !out_entry ||
        !qbc_channel_valid(session, fd, channel, principal)) return false;
    uint8_t prefix[QBC_PREFIX_MAX];
    ssize_t n = qihse_qkp_recv_sealed(session, fd, prefix, sizeof(prefix));
    return n > 0 && qihse_consensus_blob_channel_receive_prefix(blobs, session,
        fd, channel, principal, prefix, (size_t)n, out_entry);
}

bool qihse_consensus_blob_channel_receive_prefix(
    qihse_consensus_blob_context_t* blobs, qihse_qkp_session_t* session, int fd,
    const qihse_consensus_channel_config_t* channel, const qihse_user_t* principal,
    const uint8_t* prefix, size_t prefix_len, qihse_consensus_entry_t* out_entry) {
    if (!blobs || !blobs->blobs || !out_entry || !prefix ||
        prefix_len > QBC_PREFIX_MAX ||
        !qbc_channel_valid(session, fd, channel, principal)) return false;
    qihse_consensus_entry_t entry;
    bool authorized = qbc_parse_prefix(channel, principal, prefix, prefix_len, &entry);
    if (!authorized) {
        uint8_t denied[QBC_ACK_BYTES] = {0};
        memcpy(denied, "QBA1", 4u); denied[4] = 0u;
        if (prefix_len >= 36u + 1u) {
            size_t glen = prefix[36u];
            size_t hash_offset = 36u + 1u + glen + 8u + 8u + 4u + 2u + 2u + 2u + 64u;
            if (glen <= QIHSE_CONSENSUS_GROUP_ID_MAX && prefix_len >= hash_offset + 48u)
                memcpy(denied + 5u, prefix + hash_offset, 48u);
        }
        (void)qihse_qkp_send_sealed(session, fd, denied, sizeof(denied));
        return false;
    }
    const uint8_t* reference = entry.payload;
    if (qihse_consensus_blob_validate(blobs, &entry)) {
        if (!qbc_send_ack(session, fd, 2u, reference)) return false;
        *out_entry = entry;
        return true;
    }
    if (!qbc_send_ack(session, fd, 1u, reference)) return false;
    uint64_t expected = qbc_get_u64(reference + 112u);
    if (expected <= QIHSE_CONSENSUS_BLOB_HEADER_BYTES || expected > QIHSE_BLOB_MAX_SIZE) return false;
    qbc_stream_t stream = {.session=session, .fd=fd, .expected=expected, .received=0u};
    if (!qihse_consensus_blob_import_user(blobs, &entry, qbc_import_read, &stream) ||
        stream.received != expected) {
        (void)qbc_send_ack(session, fd, 0u, reference);
        return false;
    }
    uint8_t end[4u + QIHSE_BLOB_HASH_BYTES];
    ssize_t end_len = qihse_qkp_recv_sealed(session, fd, end, sizeof(end));
    if (end_len != (ssize_t)sizeof(end) || memcmp(end, "QBE1", 4u) != 0 ||
        CRYPTO_memcmp(end + 4u, reference + 64u, QIHSE_BLOB_HASH_BYTES) != 0) {
        (void)qihse_blob_delete_user(blobs->blobs, reference + 64u, blobs->principal);
        (void)qbc_send_ack(session, fd, 0u, reference);
        return false;
    }
    if (!qbc_send_ack(session, fd, 2u, reference)) return false;
    *out_entry = entry;
    return true;
}
