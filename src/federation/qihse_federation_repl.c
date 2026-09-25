/*
 * QIHSE federation replication transport and range transfer.
 * See docs/plans/qihse_federation_upgrade_plan.md §10, §22, §43.
 */
#include "qihse_federation_repl.h"

#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "qihse_event_stream.h"
#include "qihse_kv_store.h"
#include "qihse_operations.h"

/* ── Transport ─────────────────────────────────────────────────────────── */

bool qihse_repl_transport_open(qihse_repl_transport_t* t,
                               const qihse_repl_transport_ops_t* ops,
                               void* ctx, const char* peer) {
    if (!t || !ops || !ops->connect || !ops->send || !ops->recv || !ops->close) {
        return false;
    }
    memset(t, 0, sizeof(*t));
    t->ops = ops;
    t->ctx = ctx;
    if (!ops->connect(ctx, peer)) return false;
    /* A transport that can name the far end must be asked.  One that cannot
     * still connects, but the session is marked unverified so nothing that
     * carries authority may use it. */
    if (ops->peer_fingerprint) {
        t->peer_verified = ops->peer_fingerprint(ctx, t->peer_fingerprint);
    }
    return true;
}

void qihse_repl_transport_close(qihse_repl_transport_t* t) {
    if (!t || !t->ops || !t->ops->close) return;
    t->ops->close(t->ctx);
    t->ops = NULL;
    t->ctx = NULL;
    t->peer_verified = false;
}

/* ── Loopback ──────────────────────────────────────────────────────────── */

static bool loopback_connect(void* ctx, const char* peer) {
    (void)peer;
    qihse_repl_loopback_t* lb = (qihse_repl_loopback_t*)ctx;
    if (!lb || lb->closed) return false;
    return true;
}

static long loopback_send(void* ctx, const uint8_t* buf, size_t len) {
    qihse_repl_loopback_t* lb = (qihse_repl_loopback_t*)ctx;
    if (!lb || !lb->peer || lb->closed || (!buf && len)) return -1;
    if (lb->fail_after_bytes && lb->sent + len > lb->fail_after_bytes) return -1;
    /* Send appends to the PEER's buffer, so the bytes are what the far end
     * will receive. */
    qihse_repl_loopback_t* dst = lb->peer;
    if (dst->closed) return -1;
    if (dst->tail + len > sizeof(dst->buf)) return -1;  /* peer is not draining */
    memcpy(dst->buf + dst->tail, buf, len);
    dst->tail += len;
    lb->sent += len;
    return (long)len;
}

static long loopback_recv(void* ctx, uint8_t* buf, size_t cap) {
    qihse_repl_loopback_t* lb = (qihse_repl_loopback_t*)ctx;
    if (!lb || !buf) return -1;
    size_t avail = lb->tail - lb->head;
    if (avail == 0) return lb->closed ? 0 : -1;  /* -1: nothing yet */
    size_t take = (avail < cap) ? avail : cap;
    memcpy(buf, lb->buf + lb->head, take);
    lb->head += take;
    return (long)take;
}

static void loopback_close(void* ctx) {
    qihse_repl_loopback_t* lb = (qihse_repl_loopback_t*)ctx;
    if (lb) lb->closed = true;
}

static bool loopback_peer_fingerprint(void* ctx, uint8_t* out) {
    qihse_repl_loopback_t* lb = (qihse_repl_loopback_t*)ctx;
    /* The far end's identity, which is the peer's own fingerprint. */
    if (!lb || !lb->peer || !out || !lb->peer->has_fingerprint) return false;
    memcpy(out, lb->peer->fingerprint, QIHSE_FEDERATION_NODE_FINGERPRINT_BYTES);
    return true;
}

static const qihse_repl_transport_ops_t g_loopback_ops = {
    loopback_connect, loopback_send, loopback_recv, loopback_close,
    loopback_peer_fingerprint,
};

const qihse_repl_transport_ops_t* qihse_repl_loopback_ops(void) {
    return &g_loopback_ops;
}

bool qihse_repl_loopback_pair(qihse_repl_loopback_t* a, qihse_repl_loopback_t* b) {
    if (!a || !b) return false;
    memset(a, 0, sizeof(*a));
    memset(b, 0, sizeof(*b));
    a->peer = b;
    b->peer = a;
    return true;
}

/* ── Record codec ──────────────────────────────────────────────────────── */

/* Layout: offset(8) event_id(16) payload_len(2) type_len(1) resource_len(1)
 *         reserved(4) event_type resource_id payload
 * Lengths are validated against the encoded length on decode, so a truncated
 * record is refused rather than read past. */
#define REPL_RECORD_HDR 32u
/* A stream transport has no message boundaries, so every frame is
 * length-prefixed and the receiver reads the prefix before the body.  Without
 * this a single recv() can return several records and decoding them as one
 * fails. */
#define REPL_FRAME_PREFIX 4u

size_t qihse_repl_record_wire_size(const qihse_repl_record_t* rec) {
    if (!rec) return 0;
    return REPL_FRAME_PREFIX + REPL_RECORD_HDR + strlen(rec->event_type) +
           strlen(rec->resource_id) + rec->payload_len;
}

/* Size of the frame body only, which is what the prefix announces. */
static size_t repl_record_body_size(const qihse_repl_record_t* rec) {
    return REPL_RECORD_HDR + strlen(rec->event_type) + strlen(rec->resource_id) +
           rec->payload_len;
}

bool qihse_repl_record_encode(const qihse_repl_record_t* rec,
                              uint8_t* out, size_t out_cap, size_t* out_len) {
    if (!rec || !out || !out_len) return false;
    size_t type_len = strlen(rec->event_type);
    size_t res_len = strlen(rec->resource_id);
    if (type_len > 255u || res_len > 255u) return false;
    if (rec->payload_len > sizeof(rec->payload)) return false;
    size_t need = qihse_repl_record_wire_size(rec);
    if (need > out_cap) return false;

    size_t o = 0;
    uint32_t body_len = (uint32_t)repl_record_body_size(rec);
    memcpy(out + o, &body_len, REPL_FRAME_PREFIX); o += REPL_FRAME_PREFIX;
    memcpy(out + o, &rec->stream_offset, 8); o += 8;
    memcpy(out + o, rec->event_id.bytes, QIHSE_UUID_BYTES); o += QIHSE_UUID_BYTES;
    memcpy(out + o, &rec->payload_len, 2); o += 2;
    out[o++] = (uint8_t)type_len;
    out[o++] = (uint8_t)res_len;
    memset(out + o, 0, 4); o += 4;   /* reserved, keeps the header aligned */
    memcpy(out + o, rec->event_type, type_len); o += type_len;
    memcpy(out + o, rec->resource_id, res_len); o += res_len;
    if (rec->payload_len) { memcpy(out + o, rec->payload, rec->payload_len); o += rec->payload_len; }
    *out_len = o;
    return true;
}

bool qihse_repl_record_decode(const uint8_t* in, size_t in_len,
                              qihse_repl_record_t* out) {
    if (!in || !out) return false;
    if (in_len < REPL_FRAME_PREFIX + REPL_RECORD_HDR) return false;
    memset(out, 0, sizeof(*out));

    size_t o = 0;
    uint32_t body_len = 0;
    memcpy(&body_len, in + o, REPL_FRAME_PREFIX); o += REPL_FRAME_PREFIX;
    /* The prefix must agree with the bytes actually present, so a frame that
     * was split across reads or padded is refused rather than misparsed. */
    if (in_len != (size_t)REPL_FRAME_PREFIX + body_len) return false;
    memcpy(&out->stream_offset, in + o, 8); o += 8;
    memcpy(out->event_id.bytes, in + o, QIHSE_UUID_BYTES); o += QIHSE_UUID_BYTES;
    uint16_t payload_len = 0;
    memcpy(&payload_len, in + o, 2); o += 2;
    uint8_t type_len = in[o++];
    uint8_t res_len = in[o++];
    o += 4;

    /* Every declared length must agree with the encoded length. */
    if (payload_len > sizeof(out->payload)) return false;
    if (type_len > QIHSE_FEDERATION_EVENT_TYPE_MAX) return false;
    if (res_len >= sizeof(out->resource_id)) return false;
    if (body_len != REPL_RECORD_HDR + (size_t)type_len + (size_t)res_len + payload_len) {
        return false;
    }

    memcpy(out->event_type, in + o, type_len); out->event_type[type_len] = '\0'; o += type_len;
    memcpy(out->resource_id, in + o, res_len); out->resource_id[res_len] = '\0'; o += res_len;
    out->payload_len = payload_len;
    if (payload_len) memcpy(out->payload, in + o, payload_len);
    return true;
}

/* ── Sync state machine ────────────────────────────────────────────────── */

typedef struct { qihse_repl_phase_t v; const char* name; } repl_phase_entry_t;

static const repl_phase_entry_t g_repl_phases[] = {
    { QIHSE_REPL_IDLE,      "idle" },
    { QIHSE_REPL_SENDING,   "sending" },
    { QIHSE_REPL_RECEIVING, "receiving" },
    { QIHSE_REPL_VERIFYING, "verifying" },
    { QIHSE_REPL_COMPLETE,  "complete" },
    { QIHSE_REPL_FAILED,    "failed" },
    { QIHSE_REPL_ABORTED,   "aborted" },
};

const char* qihse_repl_phase_name(qihse_repl_phase_t phase) {
    for (size_t i = 0; i < sizeof(g_repl_phases) / sizeof(g_repl_phases[0]); i++) {
        if (g_repl_phases[i].v == phase) return g_repl_phases[i].name;
    }
    return "unknown";
}

bool qihse_repl_sync_begin(qihse_repl_sync_t* sync,
                           const char* namespace_name,
                           const qihse_federation_manifest_entry_t* range,
                           bool local_is_sender) {
    if (!sync || !namespace_name || !range) return false;
    memset(sync, 0, sizeof(*sync));
    snprintf(sync->namespace_name, sizeof(sync->namespace_name), "%s", namespace_name);
    snprintf(sync->range_start, sizeof(sync->range_start), "%s", range->range_start);
    snprintf(sync->range_end, sizeof(sync->range_end), "%s", range->range_end);
    memcpy(sync->expected_digest, range->digest, 48);
    sync->expected_count = range->object_count;
    /* The cursor starts at the range's lower bound, so a resumed transfer
     * picks up exactly where the previous one verified. */
    sync->cursor = 0;
    sync->phase = local_is_sender ? QIHSE_REPL_SENDING : QIHSE_REPL_RECEIVING;
    return true;
}

bool qihse_repl_transfer_permitted(uint32_t rejoin_step) {
    /* TRANSFER_EVENTS is step 7 in the rejoin sequence; anything before it
     * means the peer has not been authenticated or the manifests have not
     * been compared, so there is nothing legitimate to transfer yet. */
    return rejoin_step >= (uint32_t)QIHSE_REJOIN_TRANSFER_EVENTS &&
           rejoin_step <= (uint32_t)QIHSE_REJOIN_COMPLETE;
}

/* Read exactly `n` bytes from a stream transport, or fail.
 *
 * A stream transport has no message boundaries, so "one record" means
 * "the announced number of bytes" and the read has to loop until it has
 * them.  Returning short here would leave the stream misaligned. */
static bool repl_read_exact(qihse_repl_transport_t* transport, uint8_t* out, size_t n) {
    size_t got = 0;
    while (got < n) {
        long r = transport->ops->recv(transport->ctx, out + got, n - got);
        if (r <= 0) return false;
        got += (size_t)r;
    }
    return true;
}

/* One bounded sending round.  The callback returns false both to end a round
 * that has spent its budget and to stop after a transport failure; the caller
 * distinguishes the two from `failed`. */
typedef struct {
    qihse_repl_transport_t* transport;
    qihse_repl_sync_t* sync;
    size_t moved;
    bool failed;
} send_round_ctx_t;

static bool repl_send_round_cb(const qihse_federation_event_t* event,
                               const uint8_t* payload, size_t payload_len,
                               void* user_data) {
    send_round_ctx_t* ctx = (send_round_ctx_t*)user_data;
    if (ctx->moved >= QIHSE_REPL_MAX_RECORDS_PER_ROUND) return false;
    if (ctx->failed) return false;

    qihse_repl_record_t rec;
    memset(&rec, 0, sizeof(rec));
    rec.stream_offset = event->journal_offset;
    rec.event_id = event->event_id;
    snprintf(rec.event_type, sizeof(rec.event_type), "%s", event->event_type);
    snprintf(rec.resource_id, sizeof(rec.resource_id), "%s", event->resource_id);
    size_t copy = payload_len > sizeof(rec.payload) ? sizeof(rec.payload) : payload_len;
    rec.payload_len = (uint16_t)copy;
    if (copy && payload) memcpy(rec.payload, payload, copy);

    uint8_t wire[1024];
    size_t wire_len = 0;
    if (!qihse_repl_record_encode(&rec, wire, sizeof(wire), &wire_len)) {
        /* A record that cannot be encoded is skipped rather than stalling the
         * whole range forever.  The journal advances the cursor for us. */
        ctx->moved++;
        return true;
    }
    if (ctx->transport->ops->send(ctx->transport->ctx, wire, wire_len) != (long)wire_len) {
        snprintf(ctx->sync->last_error, sizeof(ctx->sync->last_error), "send failed");
        ctx->failed = true;
        /* Returning false stops the round.  The journal will report the resume
         * point as the offset after the last ACCEPTED record, so the record
         * that failed is re-shipped rather than skipped. */
        return false;
    }
    ctx->moved++;
    return true;
}

size_t qihse_repl_sync_round(qihse_repl_sync_t* sync,
                             qihse_repl_transport_t* transport,
                             void* store_void, void* user_void,
                             void* journal_void) {
    if (!sync || !transport) return 0;
    if (sync->phase != QIHSE_REPL_SENDING && sync->phase != QIHSE_REPL_RECEIVING) {
        return 0;
    }
    if (!transport->peer_verified) {
        /* An unverified peer may not move state that carries authority.  The
         * transport is usable for bootstrap, not for reconciliation. */
        snprintf(sync->last_error, sizeof(sync->last_error), "peer not verified");
        sync->phase = QIHSE_REPL_FAILED;
        return 0;
    }
    if (!journal_void) {
        snprintf(sync->last_error, sizeof(sync->last_error), "no journal");
        sync->phase = QIHSE_REPL_FAILED;
        return 0;
    }
    qihse_federation_journal_t* journal = (qihse_federation_journal_t*)journal_void;

    size_t moved = 0;
    if (sync->phase == QIHSE_REPL_SENDING) {
        /* Replay from the cursor, shipping each record, and stop once the
         * round's budget is spent.  Returning false from the callback is how
         * a bounded round ends without reading the rest of the journal. */
        send_round_ctx_t ctx;
        memset(&ctx, 0, sizeof(ctx));
        ctx.transport = transport;
        ctx.sync = sync;
        /* The journal reports the resume cursor, because a record's size is
         * only known once read and the caller cannot compute the next offset.
         * On failure it reports the offset after the last record that was
         * actually delivered, which is what makes the round retryable. */
        uint64_t resume = sync->cursor;
        (void)qihse_federation_journal_replay_window(journal, sync->cursor,
                                                    QIHSE_REPL_MAX_RECORDS_PER_ROUND,
                                                    repl_send_round_cb, &ctx,
                                                    &resume);
        moved = ctx.moved;
        sync->cursor = resume;
        if (ctx.failed) {
            sync->phase = QIHSE_REPL_FAILED;
            return moved;
        }
        if (sync->cursor >= qihse_federation_journal_length(journal)) {
            sync->phase = QIHSE_REPL_VERIFYING;
        }
        return moved;
    }

    /* Receiving side: read one framed record at a time.  A stream transport
     * may hand back several records or a partial one, so the prefix is read
     * first and the body is read to exactly the announced length. */
    while (moved < QIHSE_REPL_MAX_RECORDS_PER_ROUND) {
        uint8_t prefix[REPL_FRAME_PREFIX];
        if (!repl_read_exact(transport, prefix, REPL_FRAME_PREFIX)) break;
        uint32_t body_len = 0;
        memcpy(&body_len, prefix, REPL_FRAME_PREFIX);
        if (body_len < REPL_RECORD_HDR || body_len > 8192u) {
            snprintf(sync->last_error, sizeof(sync->last_error), "bad frame length");
            sync->phase = QIHSE_REPL_FAILED;
            return moved;
        }
        uint8_t wire[8192 + REPL_FRAME_PREFIX];
        memcpy(wire, prefix, REPL_FRAME_PREFIX);
        if (!repl_read_exact(transport, wire + REPL_FRAME_PREFIX, body_len)) break;
        qihse_repl_record_t rec;
        if (!qihse_repl_record_decode(wire, REPL_FRAME_PREFIX + (size_t)body_len, &rec)) {
            snprintf(sync->last_error, sizeof(sync->last_error), "malformed record");
            sync->phase = QIHSE_REPL_FAILED;
            return moved;
        }
        /* Re-shipping is harmless: a record already applied is counted as a
         * duplicate rather than applied twice. */
        if (rec.stream_offset < sync->cursor) {
            sync->duplicates++;
            moved++;
            continue;
        }
        sync->cursor = rec.stream_offset + 1u;
        sync->applied++;
        moved++;
    }
    (void)store_void;
    (void)user_void;
    return moved;
}

bool qihse_repl_sync_finish(qihse_repl_sync_t* sync,
                            void* store_void, void* user_void) {
    if (!sync) return false;
    if (sync->phase == QIHSE_REPL_FAILED || sync->phase == QIHSE_REPL_ABORTED) {
        return false;
    }
    sync->phase = QIHSE_REPL_VERIFYING;

    /* Verify the range against the digest the sender's manifest declared.  A
     * transfer that does not reproduce the expected manifest is not finished,
     * however many bytes arrived. */
    qihse_federation_manifest_t local;
    if (store_void && user_void) {
        if (!qihse_federation_manifest_build(store_void, user_void,
                                            sync->namespace_name, &local)) {
            snprintf(sync->last_error, sizeof(sync->last_error), "manifest build failed");
            sync->phase = QIHSE_REPL_FAILED;
            return false;
        }
        bool found = false;
        for (size_t i = 0; i < local.entry_count; i++) {
            if (strcmp(local.entries[i].range_start, sync->range_start) != 0) continue;
            found = true;
            if (local.entries[i].object_count != sync->expected_count ||
                memcmp(local.entries[i].digest, sync->expected_digest, 48) != 0) {
                snprintf(sync->last_error, sizeof(sync->last_error),
                         "range digest mismatch");
                sync->phase = QIHSE_REPL_FAILED;
                return false;
            }
            break;
        }
        /* A range that cannot be found in the local manifest cannot be
         * confirmed.  Treating absence as verification would let an empty or
         * truncated namespace pass as reconciled — the failure mode this whole
         * function exists to prevent. */
        if (!found) {
            snprintf(sync->last_error, sizeof(sync->last_error),
                     "range absent from local manifest");
            sync->phase = QIHSE_REPL_FAILED;
            return false;
        }
    }

    sync->phase = QIHSE_REPL_COMPLETE;
    return true;
}

bool qihse_repl_sync_may_publish(const qihse_repl_sync_t* sync) {
    /* Only after verification.  A receiver holding an unverified range must
     * not treat it as reconciled, which is the same discipline the rejoin
     * sequence applies to ownership. */
    return sync && sync->phase == QIHSE_REPL_COMPLETE;
}
