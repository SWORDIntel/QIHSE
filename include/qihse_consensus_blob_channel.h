#ifndef QIHSE_CONSENSUS_BLOB_CHANNEL_H
#define QIHSE_CONSENSUS_BLOB_CHANNEL_H

/* Authenticated QBR1 transaction-blob staging over an existing QKP1 stream.
 * The caller must complete staging on the required voter quorum before it
 * proposes the corresponding DATA entry. */

#include "qihse_consensus_blob.h"
#include "qihse_consensus_channel.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Send the already-staged entry blob to the pinned peer. The receiver checks
 * its local copy first and replies HAVE or NEED before any blob bytes move.
 * On NEED, the sender streams bounded sealed records and waits for a durable
 * import acknowledgement. */
bool qihse_consensus_blob_channel_send(
    qihse_consensus_blob_context_t* blobs,
    qihse_qkp_session_t* session, int fd,
    const qihse_consensus_channel_config_t* channel,
    const qihse_user_t* principal,
    const qihse_consensus_entry_t* entry);

/* Receive one QBT1 stage request. The supplied principal must be the active
 * local replication principal; classification and SCI are checked before
 * requesting payload bytes. out_entry is assigned only after HAVE or a full
 * digest-verified durable import succeeds. */
bool qihse_consensus_blob_channel_receive(
    qihse_consensus_blob_context_t* blobs,
    qihse_qkp_session_t* session, int fd,
    const qihse_consensus_channel_config_t* channel,
    const qihse_user_t* principal,
    qihse_consensus_entry_t* out_entry);

/* Dispatcher variant: process a QBT1 prefix already read from this session. */
bool qihse_consensus_blob_channel_receive_prefix(
    qihse_consensus_blob_context_t* blobs,
    qihse_qkp_session_t* session, int fd,
    const qihse_consensus_channel_config_t* channel,
    const qihse_user_t* principal,
    const uint8_t* prefix, size_t prefix_len,
    qihse_consensus_entry_t* out_entry);

#ifdef __cplusplus
}
#endif

#endif
