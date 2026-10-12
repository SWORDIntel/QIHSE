#include "qihse_consensus_wire.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    char dir[96];
    snprintf(dir, sizeof(dir), "build/test_consensus_wire_XXXXXX");
    assert(mkdtemp(dir));
    assert(setenv("QIHSE_DATA_DIR", dir, 1) == 0);
    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator("ConsensusWireOperator1!"));
    qihse_user_t* op = qihse_auth_get_user(0u);
    assert(op);
    qihse_user_t* analyst = qihse_auth_create_user(
        op, 62001u, QIHSE_ROLE_ANALYST, 1u, 0u, "WireAnalystPass1!", false);
    assert(analyst);

    qihse_consensus_msg_t input;
    memset(&input, 0, sizeof(input));
    input.type = QIHSE_CONSENSUS_MSG_APPEND;
    snprintf(input.group_id, sizeof(input.group_id), "%s", "qihse.test.app");
    assert(qihse_uuid_from_seed("wire-from", 9u, &input.from));
    assert(qihse_uuid_from_seed("wire-to", 7u, &input.to));
    input.term = 4u;
    input.fencing_epoch = 4u;
    input.u.append.prev_log_index = 12u;
    input.u.append.prev_log_term = 3u;
    input.u.append.leader_commit = 11u;
    input.u.append.entry_count = 2u;
    qihse_consensus_entry_t* first = &input.u.append.entries[0];
    first->index = 13u; first->term = 4u; first->journal_generation = 77u;
    first->hlc.physical_ms = 1700000000123u; first->hlc.logical = 9u;
    first->classif = 0u; first->sci = 0u;
    first->type = QIHSE_CONSENSUS_ENTRY_DATA;
    first->payload_len = 5u; memcpy(first->payload, "plain", 5u);
    qihse_consensus_entry_t* second = &input.u.append.entries[1];
    second->index = 14u; second->term = 4u; second->journal_generation = 78u;
    second->hlc.physical_ms = 1700000000124u; second->hlc.logical = 0u;
    second->classif = 3u; second->sci = 4u;
    second->type = QIHSE_CONSENSUS_ENTRY_DATA;
    second->payload_len = 6u; memcpy(second->payload, "secret", 6u);

    uint8_t wire[QIHSE_CONSENSUS_WIRE_MAX];
    size_t wire_len = 0u;
    assert(qihse_consensus_wire_encode(op, &input, wire, sizeof(wire), &wire_len));
    assert(wire_len > 0u && wire_len < sizeof(wire));
    qihse_consensus_msg_t decoded;
    qihse_consensus_msg_t untouched;
    memset(&decoded, 0, sizeof(decoded));
    assert(qihse_consensus_wire_decode(op, wire, wire_len, &decoded));
    assert(decoded.type == input.type);
    assert(strcmp(decoded.group_id, input.group_id) == 0);
    assert(qihse_uuid_equal(&decoded.from, &input.from));
    assert(qihse_uuid_equal(&decoded.to, &input.to));
    assert(decoded.u.append.entry_count == 2u);
    assert(decoded.u.append.entries[0].hlc.physical_ms == first->hlc.physical_ms);
    assert(decoded.u.append.entries[1].classif == 3u && decoded.u.append.entries[1].sci == 4u);
    assert(decoded.u.append.entries[1].payload_len == 6u);
    assert(memcmp(decoded.u.append.entries[1].payload, "secret", 6u) == 0);

    qihse_consensus_msg_t variants[6];
    memset(variants, 0, sizeof(variants));
    for (size_t i = 0; i < sizeof(variants) / sizeof(variants[0]); i++) {
        snprintf(variants[i].group_id, sizeof(variants[i].group_id), "%s", "qihse.test.app");
        variants[i].from = input.from; variants[i].to = input.to;
        variants[i].term = 4u; variants[i].fencing_epoch = 4u;
    }
    variants[0].type = QIHSE_CONSENSUS_MSG_REQUEST_VOTE;
    variants[0].u.vote.last_log_index = 40u; variants[0].u.vote.last_log_term = 3u;
    variants[1].type = QIHSE_CONSENSUS_MSG_VOTE_REPLY;
    variants[1].u.vote_reply.granted = true;
    variants[2].type = QIHSE_CONSENSUS_MSG_APPEND_REPLY;
    variants[2].u.append_reply.success = true; variants[2].u.append_reply.match_index = 41u;
    variants[3].type = QIHSE_CONSENSUS_MSG_SNAPSHOT;
    variants[3].u.snapshot.last_included_index = 1u;
    variants[3].u.snapshot.last_included_term = 4u;
    variants[3].u.snapshot.fencing_epoch = 4u;
    variants[3].u.snapshot.journal_generation = 91u;
    variants[3].u.snapshot.digest = 12345u;
    variants[3].u.snapshot.entry_count = 1u;
    variants[3].u.snapshot.entries[0] = *first;
    variants[3].u.snapshot.entries[0].index = 1u;
    variants[4].type = QIHSE_CONSENSUS_MSG_SNAPSHOT_REPLY;
    variants[4].u.snapshot_reply.success = true;
    variants[4].u.snapshot_reply.match_index = 1u;
    variants[5].type = QIHSE_CONSENSUS_MSG_SNAPSHOT_CHUNK;
    variants[5].u.snapshot_chunk.transfer_id = 0x1122334455667788ULL;
    variants[5].u.snapshot_chunk.total_entries = 1u;
    variants[5].u.snapshot_chunk.first_entry_index = 1u;
    variants[5].u.snapshot_chunk.last_included_term = 4u;
    variants[5].u.snapshot_chunk.snapshot_fencing_epoch = 4u;
    variants[5].u.snapshot_chunk.journal_generation = 91u;
    variants[5].u.snapshot_chunk.digest = 12345u;
    variants[5].u.snapshot_chunk.entry_count = 1u;
    variants[5].u.snapshot_chunk.final_chunk = true;
    variants[5].u.snapshot_chunk.entries[0] = *first;
    variants[5].u.snapshot_chunk.entries[0].index = 1u;
    variants[5].u.snapshot_chunk.entries[0].journal_generation = 91u;
    variants[5].u.snapshot_chunk.chunk_digest =
        qihse_consensus_snapshot_chunk_digest(&variants[5].u.snapshot_chunk);
    for (size_t i = 0; i < sizeof(variants) / sizeof(variants[0]); i++) {
        assert(qihse_consensus_wire_encode(op, &variants[i], wire, sizeof(wire), &wire_len));
        assert(qihse_consensus_wire_decode(op, wire, wire_len, &decoded));
        assert(decoded.type == variants[i].type);
        assert(qihse_uuid_equal(&decoded.from, &variants[i].from));
        if (decoded.type == QIHSE_CONSENSUS_MSG_SNAPSHOT) {
            assert(decoded.u.snapshot.entry_count == 1u);
            assert(decoded.u.snapshot.digest == variants[i].u.snapshot.digest);
            assert(decoded.u.snapshot.entries[0].index == 1u);
        } else if (decoded.type == QIHSE_CONSENSUS_MSG_SNAPSHOT_CHUNK) {
            assert(decoded.u.snapshot_chunk.transfer_id ==
                   variants[i].u.snapshot_chunk.transfer_id);
            assert(decoded.u.snapshot_chunk.total_entries == 1u);
            assert(decoded.u.snapshot_chunk.first_entry_index == 1u);
            assert(decoded.u.snapshot_chunk.final_chunk);
            assert(decoded.u.snapshot_chunk.chunk_digest ==
                   variants[i].u.snapshot_chunk.chunk_digest);
        }
    }

    qihse_consensus_entry_t prefix[3];
    memset(prefix, 0, sizeof(prefix));
    for (size_t i = 0u; i < 3u; i++) {
        prefix[i] = *first;
        prefix[i].index = (uint64_t)i + 1u;
        prefix[i].journal_generation = 89u + (uint64_t)i;
    }

    qihse_consensus_msg_t bad_order = variants[5];
    bad_order.u.snapshot_chunk.total_entries = 2u;
    bad_order.u.snapshot_chunk.entry_count = 2u;
    bad_order.u.snapshot_chunk.final_chunk = true;
    bad_order.u.snapshot_chunk.entries[0] = prefix[0];
    bad_order.u.snapshot_chunk.entries[1] = prefix[2];
    bad_order.u.snapshot_chunk.journal_generation = 91u;
    bad_order.u.snapshot_chunk.chunk_digest =
        qihse_consensus_snapshot_chunk_digest(&bad_order.u.snapshot_chunk);
    assert(!qihse_consensus_wire_encode(op, &bad_order, wire, sizeof(wire), &wire_len));

    /* Hostile chunk frames: invalid final marker, zero count, and tampered
     * chunk digest must fail closed without modifying caller output. */
    qihse_consensus_msg_t bad_chunk = variants[5];
    assert(qihse_consensus_wire_encode(op, &bad_chunk, wire, sizeof(wire), &wire_len));
    const size_t chunk_body = 4u + 2u + 1u + 1u + 16u + 16u + 8u + 8u +
                              strlen(bad_chunk.group_id);
    wire[chunk_body + 65u] = 2u;
    assert(!qihse_consensus_wire_decode(op, wire, wire_len, &decoded));
    assert(qihse_consensus_wire_encode(op, &bad_chunk, wire, sizeof(wire), &wire_len));
    wire[chunk_body + 64u] = 0u;
    assert(!qihse_consensus_wire_decode(op, wire, wire_len, &decoded));
    assert(qihse_consensus_wire_encode(op, &bad_chunk, wire, sizeof(wire), &wire_len));
    wire[chunk_body + 56u] ^= 0x01u;
    assert(!qihse_consensus_wire_decode(op, wire, wire_len, &decoded));
    assert(qihse_consensus_wire_encode(op, &bad_chunk, wire, sizeof(wire), &wire_len));
    wire[chunk_body] ^= 0x01u; /* transfer ID is digest-bound */
    assert(!qihse_consensus_wire_decode(op, wire, wire_len, &decoded));
    assert(qihse_consensus_wire_encode(op, &bad_chunk, wire, sizeof(wire), &wire_len));
    wire[chunk_body + 16u + 7u] = 2u; /* first index moves out of range */
    assert(!qihse_consensus_wire_decode(op, wire, wire_len, &decoded));
    assert(qihse_consensus_wire_encode(op, &bad_chunk, wire, sizeof(wire), &wire_len));
    wire[chunk_body + 66u + 41u] = 0u;
    wire[chunk_body + 66u + 42u] = (uint8_t)(QIHSE_CONSENSUS_PAYLOAD_MAX + 1u);
    assert(!qihse_consensus_wire_decode(op, wire, wire_len, &decoded));

    /* Classified chunks remain subject to the codec's low-clearance denial. */
    bad_chunk.u.snapshot_chunk.entries[0].classif = 3u;
    bad_chunk.u.snapshot_chunk.entries[0].sci = 4u;
    bad_chunk.u.snapshot_chunk.chunk_digest =
        qihse_consensus_snapshot_chunk_digest(&bad_chunk.u.snapshot_chunk);
    assert(!qihse_consensus_wire_encode(analyst, &bad_chunk, wire, sizeof(wire), &wire_len));
    assert(qihse_consensus_wire_encode(op, &bad_chunk, wire, sizeof(wire), &wire_len));
    memset(&decoded, 0xa5, sizeof(decoded));
    untouched = decoded;
    assert(!qihse_consensus_wire_decode(analyst, wire, wire_len, &decoded));
    assert(memcmp(&decoded, &untouched, sizeof(decoded)) == 0);

    /* The adapter must neither encode nor disclose an SCI/classified entry
     * to a low-clearance principal. Failed decode leaves caller output alone. */
    assert(qihse_consensus_wire_encode(op, &input, wire, sizeof(wire), &wire_len));
    size_t denied_len = 999u;
    assert(!qihse_consensus_wire_encode(analyst, &input, wire, sizeof(wire), &denied_len));
    assert(denied_len == 999u);
    memset(&decoded, 0xa5, sizeof(decoded));
    untouched = decoded;
    assert(!qihse_consensus_wire_decode(analyst, wire, wire_len, &decoded));
    assert(memcmp(&decoded, &untouched, sizeof(decoded)) == 0);

    /* A low principal can still decode authorized, unclassified entries. */
    input.u.append.entry_count = 1u;
    assert(qihse_consensus_wire_encode(op, &input, wire, sizeof(wire), &wire_len));
    assert(qihse_consensus_wire_decode(analyst, wire, wire_len, &decoded));
    assert(decoded.u.append.entry_count == 1u);

    /* Strict parser: reject trailing data, bad version, malformed booleans,
     * and undersized buffers without accepting a partial message. */
    assert(!qihse_consensus_wire_decode(op, wire, wire_len + 1u, &decoded));
    assert(!qihse_consensus_wire_decode(op, wire, wire_len - 1u, &decoded));
    wire[4] = 0u; wire[5] = 2u;
    assert(!qihse_consensus_wire_decode(op, wire, wire_len, &decoded));
    /* QCS1 has no ignorable extension/type range: an authenticated post-QKP
     * capability probe using a new type is a protocol error for legacy
     * peers, so it cannot safely be sent before capability is known. */
    wire[4] = 0u; wire[5] = 1u;
    wire[6] = 9u;
    assert(!qihse_consensus_wire_decode(op, wire, wire_len, &decoded));
    assert(!qihse_consensus_wire_encode(op, &input, wire, 2u, &denied_len));

    assert(qihse_auth_destroy_user(op, qihse_user_get_id(analyst)));
    puts("PASS consensus QCS1 wire codec: canonical round-trip, bounds, and SCI denial");
    return 0;
}
