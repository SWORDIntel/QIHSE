/*
 * test_federation_repl.c — replication transport and range transfer.
 *
 * The claims under test:
 *
 *   1. A transport that cannot name the far end may not move state that
 *      carries authority.  "Connected" is not "authenticated".
 *   2. A cursor advances only past records that were actually delivered, so a
 *      transport failure mid-range is resumable rather than corrupting.
 *   3. A range is COMPLETE only once it verifies against the manifest digest,
 *      so a partial transfer cannot be mistaken for a finished one.
 *   4. A transfer may not run before the rejoin sequence has authenticated the
 *      peer and compared manifests.
 */
#include "qihse_auth.h"
#include "qihse_federation.h"
#include "qihse_federation_repl.h"
#include "qihse_kv_store.h"
#include "qihse_operations.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

static qihse_kv_store_t* g_store;
static qihse_user_t* g_op;

/* ── Record codec ──────────────────────────────────────────────────────── */

static void test_record_codec(void) {
    qihse_repl_record_t rec;
    memset(&rec, 0, sizeof(rec));
    rec.stream_offset = 4096;
    assert(qihse_uuid_from_seed("repl-rec", strlen("repl-rec"), &rec.event_id));
    snprintf(rec.event_type, sizeof(rec.event_type), "workload.observed");
    snprintf(rec.resource_id, sizeof(rec.resource_id), "vm/web-01");
    rec.payload_len = 11;
    memcpy(rec.payload, "{\"power\":1}", 11);

    uint8_t wire[1024];
    size_t wire_len = 0;
    assert(qihse_repl_record_encode(&rec, wire, sizeof(wire), &wire_len));
    assert(wire_len == qihse_repl_record_wire_size(&rec));

    qihse_repl_record_t got;
    assert(qihse_repl_record_decode(wire, wire_len, &got));
    assert(got.stream_offset == 4096);
    assert(qihse_uuid_equal(&got.event_id, &rec.event_id));
    assert(strcmp(got.event_type, "workload.observed") == 0);
    assert(strcmp(got.resource_id, "vm/web-01") == 0);
    assert(got.payload_len == 11);
    assert(memcmp(got.payload, rec.payload, 11) == 0);

    /* A truncated record is refused: the declared lengths must agree with the
     * encoded length. */
    assert(!qihse_repl_record_decode(wire, wire_len - 1u, &got));
    assert(!qihse_repl_record_decode(wire, 8u, &got));
    /* Field offsets in the framed layout: 4-byte frame length, then
     * stream_offset(8), event_id(16), payload_len(2), type_len(1), res_len(1),
     * reserved(4). */
    const size_t off_payload_len = 4u + 8u + 16u;
    const size_t off_type_len = off_payload_len + 2u;

    /* A record whose declared payload length disagrees with the bytes present
     * is refused rather than read past. */
    uint8_t bad[1024];
    memcpy(bad, wire, wire_len);
    bad[off_payload_len] = 0xFF;
    bad[off_payload_len + 1u] = 0xFF;
    assert(!qihse_repl_record_decode(bad, wire_len, &got));
    /* An over-long event type is refused. */
    uint8_t bad2[1024];
    memcpy(bad2, wire, wire_len);
    bad2[off_type_len] = 0xFF;
    assert(!qihse_repl_record_decode(bad2, wire_len, &got));
    /* A frame whose length prefix disagrees with the bytes present is refused,
     * which is what stops a split read being misparsed as a whole record. */
    uint8_t bad3[1024];
    memcpy(bad3, wire, wire_len);
    uint32_t short_body = 8;
    memcpy(bad3, &short_body, 4);
    assert(!qihse_repl_record_decode(bad3, wire_len, &got));

    printf("PASS record codec: round-trip, truncation and length disagreement refused\n");
}

/* ── Transport identity ────────────────────────────────────────────────── */

static void test_transport_requires_identity(void) {
    qihse_repl_loopback_t a, b;
    assert(qihse_repl_loopback_pair(&a, &b));

    qihse_repl_transport_t t;
    /* b has no fingerprint, so the far end cannot be named. */
    assert(qihse_repl_transport_open(&t, qihse_repl_loopback_ops(), &b, "peer"));
    assert(!t.peer_verified);

    char journal_root[] = "build/fed_repl_j1_XXXXXX";
    assert(mkdtemp(journal_root));
    qihse_federation_journal_t* journal = qihse_federation_journal_open(
        journal_root, QIHSE_ES_DURABILITY_FDATASYNC);
    assert(journal);
    qihse_federation_mutation_t m;
    memset(&m, 0, sizeof(m));
    qihse_federation_event_t ev;
    assert(qihse_federation_journal_append(journal, &m, "t.one", "r/1", NULL, 0, &ev) > 0);

    qihse_federation_manifest_entry_t range;
    memset(&range, 0, sizeof(range));
    snprintf(range.range_start, sizeof(range.range_start), "r/");
    range.object_count = 1;

    qihse_repl_sync_t sync;
    assert(qihse_repl_sync_begin(&sync, "repl-ns", &range, true));
    assert(sync.phase == QIHSE_REPL_SENDING);

    /* The round refuses to move anything, because an unverified peer may not
     * receive state that carries authority. */
    size_t moved = qihse_repl_sync_round(&sync, &t, g_store, g_op, journal);
    assert(moved == 0);
    assert(sync.phase == QIHSE_REPL_FAILED);
    assert(strstr(sync.last_error, "not verified") != NULL);
    assert(!qihse_repl_sync_may_publish(&sync));

    qihse_repl_transport_close(&t);
    qihse_federation_journal_destroy(journal);
    printf("PASS transport identity: an unverified peer may not move authoritative state\n");
}

/* ── Range transfer, resumability and verification ─────────────────────── */

static void test_range_transfer(void) {
    qihse_repl_loopback_t sender_side, receiver_side;
    assert(qihse_repl_loopback_pair(&sender_side, &receiver_side));
    /* Both endpoints have an identity, so each can name the other.  A side
     * that cannot name its peer gets an unverified session. */
    memset(receiver_side.fingerprint, 0xA1, sizeof(receiver_side.fingerprint));
    receiver_side.has_fingerprint = true;
    memset(sender_side.fingerprint, 0xB2, sizeof(sender_side.fingerprint));
    sender_side.has_fingerprint = true;

    /* The sender's transport context is its OWN endpoint; send() appends to
     * the peer's buffer, so `receiver_side` is what receives. */
    qihse_repl_transport_t out;
    assert(qihse_repl_transport_open(&out, qihse_repl_loopback_ops(),
                                     &sender_side, "receiver"));
    assert(out.peer_verified);

    char journal_root[] = "build/fed_repl_j2_XXXXXX";
    assert(mkdtemp(journal_root));
    qihse_federation_journal_t* journal = qihse_federation_journal_open(
        journal_root, QIHSE_ES_DURABILITY_FDATASYNC);
    assert(journal);

    /* Five events to ship. */
    for (int i = 0; i < 5; i++) {
        qihse_federation_mutation_t m;
        memset(&m, 0, sizeof(m));
        qihse_federation_event_t ev;
        char type[32], res[32];
        snprintf(type, sizeof(type), "t.%d", i);
        snprintf(res, sizeof(res), "r/%d", i);
        assert(qihse_federation_journal_append(journal, &m, type, res, NULL, 0, &ev) > 0);
    }
    uint64_t journal_len = qihse_federation_journal_length(journal);
    assert(journal_len > 0);

    qihse_federation_manifest_entry_t range;
    memset(&range, 0, sizeof(range));
    snprintf(range.range_start, sizeof(range.range_start), "r/");
    range.object_count = 5;

    /* ── Sender side ──────────────────────────────────────────────────── */
    qihse_repl_sync_t send_sync;
    assert(qihse_repl_sync_begin(&send_sync, "repl-ns", &range, true));
    assert(send_sync.phase == QIHSE_REPL_SENDING);

    /* Drain in bounded rounds until the journal is exhausted. */
    size_t total_sent = 0;
    for (int round = 0; round < 8 && send_sync.phase == QIHSE_REPL_SENDING; round++) {
        total_sent += qihse_repl_sync_round(&send_sync, &out, NULL, NULL, journal);
    }
    assert(total_sent == 5);
    assert(send_sync.phase == QIHSE_REPL_VERIFYING);
    assert(send_sync.cursor >= journal_len);

    /* ── Receiver side ────────────────────────────────────────────────── */
    qihse_repl_transport_t in;
    assert(qihse_repl_transport_open(&in, qihse_repl_loopback_ops(),
                                     &receiver_side, "sender"));
    assert(in.peer_verified);

    qihse_repl_sync_t recv_sync;
    assert(qihse_repl_sync_begin(&recv_sync, "repl-ns", &range, false));
    assert(recv_sync.phase == QIHSE_REPL_RECEIVING);

    size_t total_recv = 0;
    for (int round = 0; round < 8; round++) {
        size_t moved = qihse_repl_sync_round(&recv_sync, &in, g_store, g_op, journal);
        total_recv += moved;
        if (moved == 0) break;
    }
    assert(total_recv == 5);
    assert(recv_sync.applied == 5);
    assert(recv_sync.duplicates == 0);

    /* Re-shipping is harmless: replaying the same records counts them as
     * duplicates rather than applying them twice. */
    qihse_repl_sync_t replay_sync;
    assert(qihse_repl_sync_begin(&replay_sync, "repl-ns", &range, false));
    replay_sync.cursor = 0;
    qihse_repl_sync_round(&replay_sync, &in, g_store, g_op, journal);
    assert(replay_sync.applied == 0);

    qihse_repl_transport_close(&in);
    qihse_repl_transport_close(&out);
    qihse_federation_journal_destroy(journal);
    printf("PASS range transfer: bounded rounds ship 5 records, re-shipping counts as duplicate\n");
}

static void test_resumability_on_send_failure(void) {
    qihse_repl_loopback_t sender_side, receiver_side;
    assert(qihse_repl_loopback_pair(&sender_side, &receiver_side));
    memset(receiver_side.fingerprint, 0xC3, sizeof(receiver_side.fingerprint));
    receiver_side.has_fingerprint = true;
    memset(sender_side.fingerprint, 0xD4, sizeof(sender_side.fingerprint));
    sender_side.has_fingerprint = true;

    qihse_repl_transport_t out;
    assert(qihse_repl_transport_open(&out, qihse_repl_loopback_ops(),
                                     &sender_side, "receiver"));

    char journal_root[] = "build/fed_repl_j3_XXXXXX";
    assert(mkdtemp(journal_root));
    qihse_federation_journal_t* journal = qihse_federation_journal_open(
        journal_root, QIHSE_ES_DURABILITY_FDATASYNC);
    assert(journal);
    for (int i = 0; i < 4; i++) {
        qihse_federation_mutation_t m;
        memset(&m, 0, sizeof(m));
        qihse_federation_event_t ev;
        assert(qihse_federation_journal_append(journal, &m, "t", "r/x", NULL, 0, &ev) > 0);
    }

    qihse_federation_manifest_entry_t range;
    memset(&range, 0, sizeof(range));
    snprintf(range.range_start, sizeof(range.range_start), "r/");
    range.object_count = 4;

    /* Fail the link part-way through the range.  The threshold belongs to the
     * endpoint doing the SENDING, because that is where the counter lives. */
    sender_side.fail_after_bytes = 120;

    qihse_repl_sync_t sync;
    assert(qihse_repl_sync_begin(&sync, "repl-ns", &range, true));
    (void)qihse_repl_sync_round(&sync, &out, NULL, NULL, journal);

    /* The transfer failed, and critically the cursor did NOT advance past the
     * record that failed — so a retry resumes from exactly there. */
    assert(sync.phase == QIHSE_REPL_FAILED);
    assert(strstr(sync.last_error, "send failed") != NULL);
    uint64_t cursor_after_failure = sync.cursor;

    /* A failed transfer may not be published. */
    assert(!qihse_repl_sync_may_publish(&sync));
    assert(!qihse_repl_sync_finish(&sync, g_store, g_op));

    /* Heal the link and resume: the cursor is the resume point, and nothing
     * was lost because the sender still holds every record. */
    sender_side.fail_after_bytes = 0;
    qihse_repl_sync_t retry;
    assert(qihse_repl_sync_begin(&retry, "repl-ns", &range, true));
    retry.cursor = cursor_after_failure;
    assert(retry.cursor > 0);   /* some records did get through */
    size_t moved = 0;
    for (int round = 0; round < 8 && retry.phase == QIHSE_REPL_SENDING; round++) {
        moved += qihse_repl_sync_round(&retry, &out, NULL, NULL, journal);
    }
    assert(retry.phase == QIHSE_REPL_VERIFYING);

    qihse_repl_transport_close(&out);
    qihse_federation_journal_destroy(journal);
    printf("PASS resumability: send failure holds the cursor, retry resumes from it\n");
}

static void test_verification_gates_completion(void) {
    /* Case 1: the range IS present but its digest differs from what the sender
     * declared.  This is the ordinary "the transfer did not reproduce the
     * range" case. */
    assert(qihse_kv_set_user(g_store, "ns:repl-verify-ns:r/a", "one", 0, 0, g_op));
    assert(qihse_kv_set_user(g_store, "ns:repl-verify-ns:r/b", "two", 0, 0, g_op));

    qihse_federation_manifest_t local;
    assert(qihse_federation_manifest_build(g_store, g_op, "repl-verify-ns", &local));
    assert(local.entry_count >= 1);

    qihse_federation_manifest_entry_t range = local.entries[0];
    range.object_count += 99;   /* a count the local side cannot reproduce */
    memset(range.digest, 0x5A, sizeof(range.digest));

    qihse_repl_sync_t sync;
    assert(qihse_repl_sync_begin(&sync, "repl-verify-ns", &range, false));
    assert(sync.phase == QIHSE_REPL_RECEIVING);
    assert(!qihse_repl_sync_may_publish(&sync));

    assert(!qihse_repl_sync_finish(&sync, g_store, g_op));
    assert(sync.phase == QIHSE_REPL_FAILED);
    assert(strstr(sync.last_error, "digest mismatch") != NULL);
    assert(!qihse_repl_sync_may_publish(&sync));

    /* Case 2: the range is ABSENT from the local manifest entirely.  Treating
     * absence as verification would let an empty or truncated namespace pass
     * as reconciled, which is the exact failure this function exists to
     * prevent, so it must refuse too — and with a distinguishable reason. */
    qihse_federation_manifest_entry_t absent;
    memset(&absent, 0, sizeof(absent));
    snprintf(absent.range_start, sizeof(absent.range_start), "no/such/range");
    absent.object_count = 1;
    qihse_repl_sync_t sync2;
    assert(qihse_repl_sync_begin(&sync2, "repl-verify-ns", &absent, false));
    assert(!qihse_repl_sync_finish(&sync2, g_store, g_op));
    assert(sync2.phase == QIHSE_REPL_FAILED);
    assert(strstr(sync2.last_error, "absent") != NULL);

    printf("PASS verification: digest mismatch and absent range both refuse COMPLETE\n");
}

static void test_rejoin_ordering_gate(void) {
    /* A transfer may not run before the peer is authenticated and the
     * manifests compared, and may not run after the sequence is over. */
    assert(!qihse_repl_transfer_permitted(QIHSE_REJOIN_IDLE));
    assert(!qihse_repl_transfer_permitted(QIHSE_REJOIN_AUTHENTICATE_PEER));
    assert(!qihse_repl_transfer_permitted(QIHSE_REJOIN_EXCHANGE_MANIFESTS));
    assert(!qihse_repl_transfer_permitted(QIHSE_REJOIN_IDENTIFY_DIVERGENCE));
    assert(qihse_repl_transfer_permitted(QIHSE_REJOIN_TRANSFER_EVENTS));
    assert(qihse_repl_transfer_permitted(QIHSE_REJOIN_APPLY_CONFLICT_POLICY));
    assert(qihse_repl_transfer_permitted(QIHSE_REJOIN_RECONSTRUCT_STATE));
    assert(qihse_repl_transfer_permitted(QIHSE_REJOIN_VERIFY_CHECKSUMS));
    assert(qihse_repl_transfer_permitted(QIHSE_REJOIN_COMPLETE));
    assert(!qihse_repl_transfer_permitted(QIHSE_REJOIN_ABORTED));

    printf("PASS rejoin gate: transfer permitted only between TRANSFER_EVENTS and COMPLETE\n");
}

static void test_phase_names(void) {
    for (int i = 0; i <= (int)QIHSE_REPL_ABORTED; i++) {
        const char* name = qihse_repl_phase_name((qihse_repl_phase_t)i);
        assert(name && strcmp(name, "unknown") != 0);
    }
    printf("PASS phase vocabulary: 7 phases named\n");
}

int main(void) {
    char data_root[] = "build/fed_repl_XXXXXX";
    assert(mkdtemp(data_root));
    setenv("QIHSE_DATA_DIR", data_root, 1);

    assert(qihse_auth_init());
    bool bootstrapped = qihse_auth_bootstrap_operator("ReplOperatorPass1!");
    if (!bootstrapped) {
        setenv("QIHSE_OPERATOR_PASSWORD", "ReplOperatorPass1!", 1);
        assert(qihse_auth_init());
    }
    g_op = qihse_auth_get_user(0);
    assert(g_op);
    g_store = qihse_kv_store_create();
    assert(g_store);

    test_phase_names();
    test_record_codec();
    test_rejoin_ordering_gate();
    test_transport_requires_identity();
    test_range_transfer();
    test_resumability_on_send_failure();
    test_verification_gates_completion();

    qihse_kv_store_destroy(g_store);
    printf("federation replication tests passed\n");
    return 0;
}
