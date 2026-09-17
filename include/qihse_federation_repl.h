#ifndef QIHSE_FEDERATION_REPL_H
#define QIHSE_FEDERATION_REPL_H

/*
 * QIHSE federation replication transport and range transfer.
 * See v3.md §10 (anti-entropy and reconciliation), §22 (replication
 * transport) and §43 (reconciliation safety).
 *
 * F3 produced manifests and sync plans: it can tell you WHICH ranges
 * diverge.  This is what moves the records and proves the range arrived.
 *
 * Two rules drive the design:
 *
 *   1. The transport is pluggable and the protocol knows nothing about it
 *      (§22).  AF_XDP is a performance optimisation and never a correctness
 *      dependency, so the protocol must be exercisable without a network.
 *
 *   2. A cursor advances ONLY after the range verifies against the manifest
 *      digest.  That single rule is what makes the whole thing resumable: a
 *      crash mid-range means that range is re-shipped, not that state is
 *      inconsistent.  Re-shipping is harmless because journal records carry
 *      event ids and the F2 request ledger deduplicates them.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "qihse_federation.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ── Transport abstraction (v3.md §22) ─────────────────────────────────── */

typedef struct {
    /* Establish a connection.  `peer` is transport-specific: a host:port for
     * TCP, a peer name for loopback. */
    bool (*connect)(void* ctx, const char* peer);
    /* Send exactly `len` bytes.  Returns bytes sent, or -1. */
    long (*send)(void* ctx, const uint8_t* buf, size_t len);
    /* Receive up to `cap` bytes.  Returns bytes read, 0 at end of stream, or
     * -1 on error. */
    long (*recv)(void* ctx, uint8_t* buf, size_t cap);
    void (*close)(void* ctx);
    /* The authenticated identity of the far end, if the transport has one.
     * A transport that cannot report this yields a connection that may be
     * used for nothing that carries authority. */
    bool (*peer_fingerprint)(void* ctx, uint8_t* out_fingerprint);
} qihse_repl_transport_ops_t;

typedef struct {
    const qihse_repl_transport_ops_t* ops;
    void* ctx;
    /* Set when peer_fingerprint succeeded.  A session without a verified
     * fingerprint may not apply authoritative state. */
    bool peer_verified;
    uint8_t peer_fingerprint[QIHSE_FEDERATION_NODE_FINGERPRINT_BYTES];
} qihse_repl_transport_t;

bool qihse_repl_transport_open(qihse_repl_transport_t* t,
                               const qihse_repl_transport_ops_t* ops,
                               void* ctx, const char* peer);
void qihse_repl_transport_close(qihse_repl_transport_t* t);

/* ── Loopback transport (tests, and same-process peers) ────────────────── */

/* A pair of connected in-memory endpoints.  Deliberately has NO network
 * dependency: the protocol must be exercisable without one, and the F8
 * simulator injects loss and reordering above this layer rather than inside
 * it. */
#define QIHSE_REPL_LOOPBACK_CAP 262144u

typedef struct qihse_repl_loopback {
    /* Bytes waiting to be RECEIVED by this endpoint. */
    uint8_t buf[QIHSE_REPL_LOOPBACK_CAP];
    size_t head;
    size_t tail;
    bool closed;
    /* This endpoint's own identity, which its peer will see. */
    uint8_t fingerprint[QIHSE_FEDERATION_NODE_FINGERPRINT_BYTES];
    bool has_fingerprint;
    /* Fault injection, so a caller can exercise a stalled or failed link. */
    size_t fail_after_bytes;   /* 0 = never fail */
    size_t sent;
    /* send() appends to peer->buf and recv() reads from this->buf, so which
     * endpoint you pass as the transport context is unambiguous. */
    struct qihse_repl_loopback* peer;
} qihse_repl_loopback_t;

/* Create a connected pair.  Either endpoint may be used as a transport
 * context: send() writes into the PEER's buffer and recv() reads from its
 * own, so a transport built on `a` talks to `b` and vice versa. */
bool qihse_repl_loopback_pair(qihse_repl_loopback_t* a, qihse_repl_loopback_t* b);
const qihse_repl_transport_ops_t* qihse_repl_loopback_ops(void);

/* ── Range transfer ────────────────────────────────────────────────────── */

/* A transfer moves one divergent range at a time, in the direction the sync
 * plan chose.  Records are journal events addressed by stream offset, so the
 * unit of work is (range, cursor) and resumption is just the cursor. */
typedef enum {
    QIHSE_REPL_IDLE = 0,
    QIHSE_REPL_SENDING,
    QIHSE_REPL_RECEIVING,
    QIHSE_REPL_VERIFYING,
    QIHSE_REPL_COMPLETE,
    QIHSE_REPL_FAILED,
    QIHSE_REPL_ABORTED
} qihse_repl_phase_t;

const char* qihse_repl_phase_name(qihse_repl_phase_t phase);

/* The wire unit: one journal record. */
typedef struct {
    uint64_t stream_offset;      /* position in the sender's journal */
    qihse_uuid_t event_id;
    char event_type[QIHSE_FEDERATION_EVENT_TYPE_MAX + 1u];
    char resource_id[64];
    uint16_t payload_len;
    uint8_t payload[512];
} qihse_repl_record_t;

/* Encode/decode a record for the wire.  A decoder must refuse a record it
 * could not have produced, so the declared payload length is validated
 * against the encoded length. */
size_t qihse_repl_record_wire_size(const qihse_repl_record_t* rec);
bool qihse_repl_record_encode(const qihse_repl_record_t* rec,
                              uint8_t* out, size_t out_cap, size_t* out_len);
bool qihse_repl_record_decode(const uint8_t* in, size_t in_len,
                              qihse_repl_record_t* out);

/* ── The transfer state machine ────────────────────────────────────────── */

/* Bound on how much one round may move, so reconciliation cannot saturate a
 * link or a CPU (v3.md §10: rate limited, bounded). */
#define QIHSE_REPL_MAX_RECORDS_PER_ROUND 64u

typedef struct {
    qihse_repl_phase_t phase;
    char namespace_name[QIHSE_FEDERATION_NS_NAME_MAX + 1u];
    char range_start[64];
    char range_end[64];
    /* The expected digest of the range once it has been applied.  Taken from
     * the sender's manifest, so the receiver can prove what it got. */
    uint8_t expected_digest[48];
    uint64_t expected_count;
    /* Cursor: the journal offset the next round resumes from. */
    uint64_t cursor;
    uint64_t applied;
    uint64_t duplicates;
    char last_error[128];
} qihse_repl_sync_t;

/* Begin a transfer for one divergent range.
 *
 * `local_is_sender` selects direction: the side that holds the records sends,
 * the side that needs them receives.  Both sides construct this identically
 * from the manifest comparison, so neither has to be told which it is. */
bool qihse_repl_sync_begin(qihse_repl_sync_t* sync,
                           const char* namespace_name,
                           const qihse_federation_manifest_entry_t* range,
                           bool local_is_sender);

/* Move one bounded round.
 *
 * As the receiver, `store` receives the applied records and `journal` is the
 * local journal being caught up.  As the sender, `journal` is the source.
 * Returns the number of records moved, or 0 when the round had nothing to do.
 * A transport error moves the phase to FAILED without advancing the cursor,
 * which is what makes a retry safe. */
size_t qihse_repl_sync_round(qihse_repl_sync_t* sync,
                             qihse_repl_transport_t* transport,
                             void* store_void, void* user_void,
                             void* journal_void);

/* Finish: verify the received range against the expected digest and only then
 * declare COMPLETE.  Returns false and moves to FAILED if verification does
 * not hold, so a partial transfer can never be mistaken for a finished one. */
bool qihse_repl_sync_finish(qihse_repl_sync_t* sync,
                            void* store_void, void* user_void);

/* May this sync's outcome be published as authoritative state?
 *
 * Only after verification.  A receiver that has not verified its range must
 * not treat what it holds as reconciled — the same discipline the rejoin
 * sequence applies to ownership. */
bool qihse_repl_sync_may_publish(const qihse_repl_sync_t* sync);

/* ── Reconciliation ordering (v3.md §43) ───────────────────────────────── */

/* The rejoin sequence ends with VERIFY_CHECKSUMS and COMPLETE.  A transfer
 * may only run while the sequence is at or past TRANSFER_EVENTS, so a node
 * cannot start pulling records before it has authenticated the peer and
 * compared manifests. */
bool qihse_repl_transfer_permitted(uint32_t rejoin_step);

#ifdef __cplusplus
}
#endif

#endif /* QIHSE_FEDERATION_REPL_H */
