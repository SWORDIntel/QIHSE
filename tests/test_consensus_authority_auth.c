#include "qihse_consensus_blob.h"
#include "qihse_pqc_crypto.h"
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

int main(void) {
    char root[] = "build/test_authority_auth_XXXXXX";
    assert(mkdtemp(root)); assert(!setenv("QIHSE_DATA_DIR", root, 1));
    assert(!setenv("QIHSE_FIPS_MODE", "disabled", 1));
    assert(qihse_pqc_init_providers() >= 0);
    assert(qihse_auth_init() && qihse_auth_bootstrap_operator("AuthorityAuthOperator1!"));
    qihse_user_t* op = qihse_auth_get_user(0u);
    qihse_user_t* low = qihse_auth_create_user(op, 63010u, QIHSE_ROLE_ANALYST, 0u, 0u, "AuthorityAnalyst1!", false);
    qihse_user_t* no_sci = qihse_auth_create_user(op, 63011u, QIHSE_ROLE_ANALYST, 3u, 0u, "AuthorityNoSci1!", false);
    assert(op && low && no_sci);
    qihse_consensus_config_t cfg = {0};
    snprintf(cfg.group_id, sizeof(cfg.group_id), "authority-auth");
    snprintf(cfg.record_path, sizeof(cfg.record_path), "%s/log.rec", root);
    assert(qihse_uuid_from_seed("first", 5u, &cfg.self));
    cfg.member_count = 3u; cfg.members[0] = cfg.self;
    assert(qihse_uuid_from_seed("second", 6u, &cfg.members[1]));
    assert(qihse_uuid_from_seed("third", 5u, &cfg.members[2]));
    cfg.election_timeout_base_ms = 100u; cfg.election_timeout_spread_ms = 3u; cfg.heartbeat_interval_ms = 20u;
    qihse_consensus_t* core = qihse_consensus_open(&cfg, NULL, NULL); assert(core);
    for (uint64_t now = 10u; now < 30000u && qihse_consensus_role(core) == QIHSE_CONSENSUS_FOLLOWER; now += 10u)
        qihse_consensus_tick(core, now);
    qihse_consensus_msg_t vote = {0}; vote.type = QIHSE_CONSENSUS_MSG_VOTE_REPLY;
    snprintf(vote.group_id, sizeof(vote.group_id), "authority-auth");
    vote.from = cfg.members[1]; vote.to = cfg.self;
    vote.term = qihse_consensus_term(core); vote.fencing_epoch = qihse_consensus_fencing_epoch(core);
    vote.u.vote_reply.granted = true; qihse_consensus_receive(core, &vote);
    assert(qihse_consensus_role(core) == QIHSE_CONSENSUS_LEADER);
    const char value[] = "classified-uncommitted-do-not-disclose";
    qihse_hlc_t hlc = {1u, 0u};
    assert(qihse_consensus_propose(core, op, 1u, hlc, 3u, 4u, value, sizeof(value)));
    assert(!qihse_consensus_commit_index(core));
    qihse_consensus_entry_t entry, zero = {0};
    assert(qihse_consensus_read_durable_entry_user(core, op, 1u, &entry));
    assert(entry.payload_len == sizeof(value) && !memcmp(entry.payload, value, sizeof(value)));
    qihse_user_t* denied[] = {NULL, low, no_sci};
    for (size_t i = 0; i < 3u; ++i) {
        memset(&entry, 0xA5, sizeof(entry));
        assert(!qihse_consensus_read_durable_entry_user(core, denied[i], 1u, &entry));
        assert(!memcmp(&entry, &zero, sizeof(entry)));
    }
    char path[320]; snprintf(path, sizeof(path), "%s/blobs", root);
    qihse_blob_store_t* blobs = qihse_blob_store_create(path); assert(blobs);
    qihse_consensus_blob_context_t context;
    assert(qihse_consensus_blob_context_init(&context, blobs, op, cfg.group_id));
    uint8_t reference[QIHSE_CONSENSUS_BLOB_REF_BYTES];
    assert(qihse_consensus_blob_stage_user(&context, 2u, 3u, 4u, value, sizeof(value), reference));
    assert(qihse_consensus_propose(core, op, 2u, hlc, 3u, 4u, reference, sizeof(reference)));
    uint8_t out[128]; size_t len = 0u;
    assert(qihse_consensus_blob_read_durable_transaction_user(&context, core, op, 2u, out, sizeof(out), &len));
    assert(len == sizeof(value) && !memcmp(out, value, len));
    for (size_t i = 0; i < 3u; ++i) {
        memset(out, 0xA5, sizeof(out)); len = 99u;
        assert(!qihse_consensus_blob_read_durable_transaction_user(&context, core, denied[i], 2u, out, sizeof(out), &len) && !len);
        for (size_t j = 0; j < sizeof(out); ++j) assert(out[j] == 0xA5);
    }
    qihse_consensus_close(core); qihse_blob_store_destroy(blobs);
    puts("PASS durable suffix protected payload: low clearance, NULL and missing SCI denied without disclosure");
    return 0;
}
