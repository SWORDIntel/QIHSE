#ifndef QIHSE_CONSENSUS_CHANNEL_H
#define QIHSE_CONSENSUS_CHANNEL_H

/* One-message QCS1 transport over an already-negotiated QKP1 session.
 * The caller must serialize concurrent access to a session and must enqueue
 * received messages before invoking qihse_consensus_receive() so transport
 * callbacks never re-enter the consensus state machine. */

#include "qihse_consensus_wire.h"
#include "qihse_qkp.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    const char* group_id;
    qihse_uuid_t local_member;
    qihse_uuid_t peer_member;
    const char* peer_node_id;       /* exact QKP1 signed node label */
    const char* peer_dsa_pub_path;  /* exact pinned ML-DSA key */
} qihse_consensus_channel_config_t;

/* Sends one canonical consensus message as one QKP1 sealed record. Message
 * group/from/to fields must match the channel binding. */
bool qihse_consensus_channel_send(qihse_qkp_session_t* session, int fd,
                                 const qihse_consensus_channel_config_t* channel,
                                 const qihse_user_t* principal,
                                 const qihse_consensus_msg_t* message);

/* Receives and validates one QKP1 record. The decoded message is published
 * only after QKP signer pin, member/group binding, and SCI checks succeed. */
bool qihse_consensus_channel_receive(qihse_qkp_session_t* session, int fd,
                                     const qihse_consensus_channel_config_t* channel,
                                     const qihse_user_t* principal,
                                     qihse_consensus_msg_t* out_message);

/* Decode a QCS1 sealed payload already read by a protocol dispatcher. This
 * preserves the same session pin, member/group binding, and SCI checks as
 * receive(). */
bool qihse_consensus_channel_decode(qihse_qkp_session_t* session,
                                    const qihse_consensus_channel_config_t* channel,
                                    const qihse_user_t* principal,
                                    const uint8_t* wire, size_t wire_len,
                                    qihse_consensus_msg_t* out_message);

#ifdef __cplusplus
}
#endif

#endif
