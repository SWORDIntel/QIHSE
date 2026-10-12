#ifndef QIHSE_CONSENSUS_WIRE_H
#define QIHSE_CONSENSUS_WIRE_H

/* Canonical, authorization-checked wire encoding for QIHSE consensus
 * messages. The codec does not provide transport authentication; callers
 * must carry these bytes inside an authenticated QKP session and bind the
 * session peer to the configured member before delivery. */

#include "qihse_consensus.h"

#ifdef __cplusplus
extern "C" {
#endif

#define QIHSE_CONSENSUS_WIRE_MAX 8192u

/* Encode/decode one complete legacy message using the QCS1 format.
 * A non-NULL authenticated principal is required. Every entry's
 * classification and SCI are checked before it is disclosed or accepted.
 * The decoder rejects noncanonical lengths, unknown types, malformed
 * booleans, invalid group IDs, nil member IDs, stale epoch shapes, and
 * trailing bytes. */
bool qihse_consensus_wire_encode(const qihse_user_t* principal,
                                 const qihse_consensus_msg_t* message,
                                 uint8_t* out, size_t out_cap,
                                 size_t* out_len);
bool qihse_consensus_wire_decode(const qihse_user_t* principal,
                                 const uint8_t* wire, size_t wire_len,
                                 qihse_consensus_msg_t* out);

/* QCS2 binds every sealed message to the durable group history. The caller
 * must obtain these values from its validated local record and its pinned
 * peer configuration. QCS1 and QCS2 are deliberately not interchangeable:
 * a bound decoder rejects legacy frames before exposing any entries. */
bool qihse_consensus_wire_encode_bound(const qihse_user_t* principal,
                                       const qihse_consensus_msg_t* message,
                                       const uint8_t history_id[32],
                                       uint64_t writer_epoch,
                                       uint8_t* out, size_t out_cap,
                                       size_t* out_len);
bool qihse_consensus_wire_decode_bound(const qihse_user_t* principal,
                                       const uint8_t* wire, size_t wire_len,
                                       const uint8_t history_id[32],
                                       uint64_t writer_epoch,
                                       qihse_consensus_msg_t* out);

/* Build/verify the canonical chunk digest. It binds all transfer metadata,
 * the final marker, and the digest of the encoded entries. */
uint64_t qihse_consensus_snapshot_chunk_digest(
    const qihse_consensus_snapshot_chunk_t* chunk);

/* SNAPSHOT_CHUNK is additive: existing QCS1 encodings are unchanged. Older
 * peers reject the new type, so senders use it only for explicitly provisioned
 * chunk-capable peers. QCS2 retains the same body after its bound header. */

#ifdef __cplusplus
}
#endif

#endif
