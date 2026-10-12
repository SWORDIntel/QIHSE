#include "qihse_consensus_channel.h"

#include <string.h>

#if QIHSE_CONSENSUS_WIRE_MAX > QIHSE_QKP_MAX_PAYLOAD
#error QCS1 messages must fit in one QKP1 sealed record
#endif

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
    return principal && qihse_auth_user_is_active(principal) &&
           channel && channel->group_id && *channel->group_id &&
           !qihse_uuid_is_nil(&channel->local_member) &&
           !qihse_uuid_is_nil(&channel->peer_member) &&
           !qihse_uuid_equal(&channel->local_member, &channel->peer_member) &&
           qcs_peer_pinned(session, channel);
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
    if (!qihse_consensus_wire_encode(principal, message, wire, sizeof(wire), &wire_len) ||
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
    if (!qihse_consensus_wire_decode(principal, wire, wire_len, &decoded) ||
        strcmp(decoded.group_id, channel->group_id) != 0 ||
        !qihse_uuid_equal(&decoded.from, &channel->peer_member) ||
        !qihse_uuid_equal(&decoded.to, &channel->local_member)) return false;
    *out_message = decoded;
    return true;
}
