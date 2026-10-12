#include "qihse_consensus_channel.h"

#include <string.h>

#if QIHSE_CONSENSUS_WIRE_MAX > QIHSE_QKP_MAX_PAYLOAD
#error QCS1 messages must fit in one QKP1 sealed record
#endif

#define QCS_HELLO_FIXED (4u + 1u + 16u + 16u + 32u + 8u)

static bool qcs_peer_pinned(const qihse_qkp_session_t* session,
                            const qihse_consensus_channel_config_t* channel) {
    if (!session || !channel || !channel->peer_node_id || !*channel->peer_node_id ||
        !channel->peer_dsa_pub_path || !*channel->peer_dsa_pub_path) return false;
    return qihse_qkp_session_is_replication_peer(session, channel->peer_node_id,
                                                  channel->peer_dsa_pub_path) ||
           qihse_qkp_client_session_is_replication_peer(session, channel->peer_node_id,
                                                         channel->peer_dsa_pub_path);
}

static bool qcs_channel_valid(const qihse_qkp_session_t* session,
                              const qihse_consensus_channel_config_t* channel,
                              const qihse_user_t* principal) {
    uint8_t history_bits = 0u;
    if (channel) {
        for (size_t i = 0; i < sizeof(channel->history_id); i++)
            history_bits |= channel->history_id[i];
    }
    return principal && qihse_auth_user_is_active(principal) &&
           channel && channel->group_id && *channel->group_id &&
           ((channel->writer_epoch == 0u && history_bits == 0u) ||
            (channel->writer_epoch != 0u && history_bits != 0u)) &&
           !qihse_uuid_is_nil(&channel->local_member) &&
           !qihse_uuid_is_nil(&channel->peer_member) &&
           !qihse_uuid_equal(&channel->local_member, &channel->peer_member) &&
           qcs_peer_pinned(session, channel);
}

static void qcs_put_u64(uint8_t* p, uint64_t v) {
    for (unsigned i = 0u; i < 8u; i++) p[7u - i] = (uint8_t)(v >> (i * 8u));
}

static uint64_t qcs_get_u64(const uint8_t* p) {
    uint64_t v = 0u;
    for (unsigned i = 0u; i < 8u; i++) v = (v << 8) | p[i];
    return v;
}

bool qihse_consensus_channel_send_hello(
    qihse_qkp_session_t* session, int fd,
    const qihse_consensus_channel_config_t* channel,
    const qihse_user_t* principal) {
    if (fd < 0 || !qcs_channel_valid(session, channel, principal) ||
        channel->writer_epoch == 0u) return false;
    size_t group_len = strnlen(channel->group_id,
                               QIHSE_CONSENSUS_GROUP_ID_MAX + 1u);
    if (!group_len || group_len > QIHSE_CONSENSUS_GROUP_ID_MAX) return false;
    uint8_t wire[QCS_HELLO_FIXED + QIHSE_CONSENSUS_GROUP_ID_MAX];
    size_t p = 0u;
    memcpy(wire + p, "QCH2", 4u); p += 4u;
    wire[p++] = (uint8_t)group_len;
    memcpy(wire + p, channel->local_member.bytes, 16u); p += 16u;
    memcpy(wire + p, channel->peer_member.bytes, 16u); p += 16u;
    memcpy(wire + p, channel->history_id, 32u); p += 32u;
    qcs_put_u64(wire + p, channel->writer_epoch); p += 8u;
    memcpy(wire + p, channel->group_id, group_len); p += group_len;
    return qihse_qkp_send_sealed(session, fd, wire, p);
}

bool qihse_consensus_channel_decode_hello(
    qihse_qkp_session_t* session,
    const qihse_consensus_channel_config_t* channel,
    const qihse_user_t* principal,
    const uint8_t* wire, size_t wire_len) {
    if (!wire || !qcs_channel_valid(session, channel, principal) ||
        channel->writer_epoch == 0u || wire_len < QCS_HELLO_FIXED ||
        memcmp(wire, "QCH2", 4u) != 0) return false;
    size_t group_len = wire[4u];
    size_t local_len = strnlen(channel->group_id,
                               QIHSE_CONSENSUS_GROUP_ID_MAX + 1u);
    if (!group_len || group_len != local_len ||
        wire_len != QCS_HELLO_FIXED + group_len) return false;
    size_t p = 5u;
    if (memcmp(wire + p, channel->peer_member.bytes, 16u) != 0) return false;
    p += 16u;
    if (memcmp(wire + p, channel->local_member.bytes, 16u) != 0) return false;
    p += 16u;
    if (memcmp(wire + p, channel->history_id, 32u) != 0) return false;
    p += 32u;
    if (qcs_get_u64(wire + p) != channel->writer_epoch) return false;
    p += 8u;
    return memcmp(wire + p, channel->group_id, group_len) == 0;
}

bool qihse_consensus_channel_send(qihse_qkp_session_t* session, int fd,
                                 const qihse_consensus_channel_config_t* channel,
                                 const qihse_user_t* principal,
                                 const qihse_consensus_msg_t* message) {
    if (fd < 0 || !message || !qcs_channel_valid(session, channel, principal) ||
        strcmp(message->group_id, channel->group_id) != 0 ||
        !qihse_uuid_equal(&message->from, &channel->local_member) ||
        !qihse_uuid_equal(&message->to, &channel->peer_member)) return false;
    uint8_t wire[QIHSE_CONSENSUS_WIRE_MAX];
    size_t wire_len = 0u;
    bool encoded = channel->writer_epoch
        ? qihse_consensus_wire_encode_bound(
            principal, message, channel->history_id, channel->writer_epoch,
            wire, sizeof(wire), &wire_len)
        : qihse_consensus_wire_encode(principal, message, wire, sizeof(wire), &wire_len);
    if (!encoded ||
        wire_len > QIHSE_QKP_MAX_PAYLOAD) return false;
    return qihse_qkp_send_sealed(session, fd, wire, wire_len);
}

bool qihse_consensus_channel_receive(qihse_qkp_session_t* session, int fd,
                                     const qihse_consensus_channel_config_t* channel,
                                     const qihse_user_t* principal,
                                     qihse_consensus_msg_t* out_message) {
    if (fd < 0 || !out_message || !qcs_channel_valid(session, channel, principal)) return false;
    uint8_t wire[QIHSE_CONSENSUS_WIRE_MAX];
    ssize_t received = qihse_qkp_recv_sealed(session, fd, wire, sizeof(wire));
    if (received <= 0 || (size_t)received > sizeof(wire)) return false;
    return qihse_consensus_channel_decode(session, channel, principal,
        wire, (size_t)received, out_message);
}

bool qihse_consensus_channel_decode(qihse_qkp_session_t* session,
                                    const qihse_consensus_channel_config_t* channel,
                                    const qihse_user_t* principal,
                                    const uint8_t* wire, size_t wire_len,
                                    qihse_consensus_msg_t* out_message) {
    if (!out_message || !wire || wire_len == 0u ||
        wire_len > QIHSE_CONSENSUS_WIRE_MAX ||
        !qcs_channel_valid(session, channel, principal)) return false;
    qihse_consensus_msg_t decoded;
    bool decoded_ok = channel->writer_epoch
        ? qihse_consensus_wire_decode_bound(
            principal, wire, wire_len, channel->history_id,
            channel->writer_epoch, &decoded)
        : qihse_consensus_wire_decode(principal, wire, wire_len, &decoded);
    if (!decoded_ok ||
        strcmp(decoded.group_id, channel->group_id) != 0 ||
        !qihse_uuid_equal(&decoded.from, &channel->peer_member) ||
        !qihse_uuid_equal(&decoded.to, &channel->local_member)) return false;
    *out_message = decoded;
    return true;
}
