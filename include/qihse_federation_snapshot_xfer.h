#ifndef QIHSE_FEDERATION_SNAPSHOT_XFER_H
#define QIHSE_FEDERATION_SNAPSHOT_XFER_H

/*
 * QIHSE federation snapshot transfer — W7: chunked, resumable bulk state
 * transfer for node rejoin (CITADEL 0.4 migration/HA, KEYSTONE snapshot
 * bootstrap).
 *
 * Moves a sealed backup container (v3: signed header + data section + WAL
 * section) from the node that wrote it to a rejoining node, over the SAME
 * verified replication transport the range sync uses (mTLS session in
 * production, loopback pair in tests).  The wire protocol is deliberately
 * dumb: bounded frames, stop-and-wait, per-chunk CRC32 for early refusal —
 * and final authority ALWAYS stays with the container's own SHA-384
 * sections and ML-DSA signature via qihse_backup_verify(), which the
 * receiver runs as an authenticated principal before anything is applied.
 *
 * Frame unit (little-endian):
 *   u32 magic 'QSX1' | u16 kind | u32 payload_len | payload
 *
 * Kinds and payloads:
 *   FETCH  (rx -> tx): { u64 resume_offset, u64 max_total }
 *   BEGIN  (tx -> rx): { u64 total_len, u32 chunk_size, u8 header_sha384[48] }
 *   CHUNK  (tx -> rx): { u64 offset, u8 data[n], u32 crc32(data) }
 *   ACK    (rx -> tx): { u64 offset_acked }
 *   DONE   (tx -> rx): { u64 total_len }
 *   ABORT  (either):   { char reason[128] }
 *
 * Resume: the receiver persists "<dest>.xfer" (atomically, via tmp+rename)
 * after every accepted chunk: { total_len, chunk_size, header_sha384,
 * offset }.  A fetch call interrupted by `max_chunks` returns
 * QIHSE_SNAPSHOT_XFER_IN_PROGRESS with the state durable; the next call
 * sends FETCH with the persisted offset and the sender serves only the
 * remainder.  A BEGIN that does not match the persisted resume point is a
 * protocol error — the container changed mid-transfer and the receiver
 * must restart deliberately, not splice two containers together.
 *
 * Security: both ends require a VERIFIED peer (the transport's
 * fingerprint gate — an unverified session may not carry state that holds
 * authority, exactly like the range transfer).  Chunk decode is bounded:
 * payload capped at QIHSE_SNAPSHOT_XFER_CHUNK + 64, offsets checked
 * against total_len with overflow-safe arithmetic, one reusable heap
 * buffer, single cleanup path.  The transfer itself moves opaque bytes;
 * verify/restore run under the caller's explicit user context.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "qihse_federation_repl.h"

#ifdef __cplusplus
extern "C" {
#endif

#define QIHSE_SNAPSHOT_XFER_CHUNK 65536u                 /* default frame body */
#define QIHSE_SNAPSHOT_XFER_MAX_TOTAL (8ull << 30)       /* 8 GiB container cap */
#define QIHSE_SNAPSHOT_XFER_ERR_MAX 160u

typedef enum {
    QIHSE_SNAPSHOT_XFER_OK = 0,
    QIHSE_SNAPSHOT_XFER_IN_PROGRESS,   /* max_chunks reached; state persisted */
    QIHSE_SNAPSHOT_XFER_ERR_ARGS,
    QIHSE_SNAPSHOT_XFER_ERR_PEER,      /* unverified peer */
    QIHSE_SNAPSHOT_XFER_ERR_PROTOCOL,  /* malformed/mismatched frame */
    QIHSE_SNAPSHOT_XFER_ERR_BOUNDS,    /* length/offset beyond declared total */
    QIHSE_SNAPSHOT_XFER_ERR_CRC,
    QIHSE_SNAPSHOT_XFER_ERR_IO
} qihse_snapshot_xfer_result_t;

const char* qihse_snapshot_xfer_result_name(qihse_snapshot_xfer_result_t r);

/*
 * Serve the whole container (blocking).  Reads the receiver's FETCH and
 * streams from its resume offset.  Returns bytes served, or 0 on failure
 * with a human reason in `err` (never NULL-unsafe: err may be NULL when
 * err_cap is 0).  The container file is opened read-only and never
 * written.
 */
uint64_t qihse_snapshot_xfer_serve(qihse_repl_transport_t* t,
                                   const char* container_path,
                                   char* err, size_t err_cap);

/*
 * Fetch (assemble) the container into `dest_path` (blocking, or bounded
 * by `max_chunks` — 0 means unlimited).  On IN_PROGRESS the resume state
 * is durable and the next call continues.  On OK the file is complete and
 * flushed; the CALLER then runs qihse_backup_verify()/restore under its
 * own authenticated context — this module never applies state.
 * `max_total` caps what the receiver will accept (0 = module cap).
 * `out_offset` (optional) reports bytes received so far.
 */
qihse_snapshot_xfer_result_t qihse_snapshot_xfer_fetch(
    qihse_repl_transport_t* t, const char* dest_path,
    uint64_t max_total, uint32_t max_chunks, uint64_t* out_offset,
    char* err, size_t err_cap);

/* The resume sidecar path for a destination (exposed for tests/cleanup). */
void qihse_snapshot_xfer_state_path(const char* dest_path,
                                    char* out, size_t cap);

#ifdef __cplusplus
}
#endif

#endif /* QIHSE_FEDERATION_SNAPSHOT_XFER_H */
