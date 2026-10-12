#include "qihse_consensus_snapshot_stage.h"

#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static bool accept_any_data(void* context, const qihse_consensus_entry_t* e) {
    const bool* allow = (const bool*)context;
    return allow && *allow && e && e->type == QIHSE_CONSENSUS_ENTRY_DATA;
}

static void make_prefix(qihse_consensus_entry_t entries[3]) {
    memset(entries, 0, 3u * sizeof(*entries));
    for (size_t i = 0u; i < 3u; i++) {
        entries[i].index = i + 1u;
        entries[i].term = i == 2u ? 4u : 2u;
        entries[i].journal_generation = 41u + i;
        entries[i].hlc.physical_ms = 1000u + i;
        entries[i].type = QIHSE_CONSENSUS_ENTRY_DATA;
        entries[i].payload_len = 5u;
        memcpy(entries[i].payload, "row!!", 5u);
    }
}

static bool entries_equal(const qihse_consensus_entry_t* a,
                         const qihse_consensus_entry_t* b) {
    return a->index == b->index && a->term == b->term &&
           a->journal_generation == b->journal_generation &&
           a->hlc.physical_ms == b->hlc.physical_ms &&
           a->hlc.logical == b->hlc.logical && a->classif == b->classif &&
           a->sci == b->sci && a->type == b->type &&
           a->payload_len == b->payload_len &&
           memcmp(a->payload, b->payload, a->payload_len) == 0;
}

static qihse_consensus_msg_t make_chunk(
    const qihse_uuid_t* from, const qihse_uuid_t* to,
    const qihse_consensus_entry_t entries[3], uint64_t transfer_id,
    uint64_t full_digest, uint64_t first, size_t count) {
    qihse_consensus_msg_t m;
    memset(&m, 0, sizeof(m));
    m.type = QIHSE_CONSENSUS_MSG_SNAPSHOT_CHUNK;
    snprintf(m.group_id, sizeof(m.group_id), "%s", "qihse.test.stage");
    m.from = *from; m.to = *to;
    m.term = 4u; m.fencing_epoch = 4u;
    qihse_consensus_snapshot_chunk_t* c = &m.u.snapshot_chunk;
    c->transfer_id = transfer_id;
    c->total_entries = 3u;
    c->first_entry_index = first;
    c->last_included_term = 4u;
    c->snapshot_fencing_epoch = 4u;
    c->journal_generation = 43u;
    c->digest = full_digest;
    c->entry_count = count;
    c->final_chunk = first + (uint64_t)count - 1u == c->total_entries;
    for (size_t i = 0u; i < count; i++)
        c->entries[i] = entries[(size_t)first - 1u + i];
    c->chunk_digest = qihse_consensus_snapshot_chunk_digest(c);
    return m;
}

static qihse_consensus_msg_t make_prefix_chunk(
    const qihse_uuid_t* from, const qihse_uuid_t* to,
    const qihse_consensus_entry_t* entries, uint64_t total,
    uint64_t transfer_id, uint64_t digest, uint64_t first, size_t count) {
    qihse_consensus_msg_t m;
    memset(&m, 0, sizeof(m));
    m.type = QIHSE_CONSENSUS_MSG_SNAPSHOT_CHUNK;
    snprintf(m.group_id, sizeof(m.group_id), "%s", "qihse.test.stage");
    m.from = *from; m.to = *to;
    m.term = 4u; m.fencing_epoch = 4u;
    qihse_consensus_snapshot_chunk_t* c = &m.u.snapshot_chunk;
    c->transfer_id = transfer_id;
    c->total_entries = total;
    c->first_entry_index = first;
    c->last_included_term = 4u;
    c->snapshot_fencing_epoch = 4u;
    c->journal_generation = entries[total - 1u].journal_generation;
    c->digest = digest;
    c->entry_count = count;
    c->final_chunk = first + (uint64_t)count - 1u == total;
    for (size_t i = 0u; i < count; i++)
        c->entries[i] = entries[(size_t)first - 1u + i];
    c->chunk_digest = qihse_consensus_snapshot_chunk_digest(c);
    return m;
}

static qihse_consensus_msg_t make_newer_prefix_chunk(
    const qihse_uuid_t* from, const qihse_uuid_t* to,
    const qihse_consensus_entry_t* entries, uint64_t total,
    uint64_t transfer_id, uint64_t digest, uint64_t first, size_t count) {
    qihse_consensus_msg_t m = make_prefix_chunk(from, to, entries, total,
        transfer_id, digest, first, count);
    m.term = 6u;
    m.fencing_epoch = 6u;
    m.u.snapshot_chunk.last_included_term = 5u;
    m.u.snapshot_chunk.snapshot_fencing_epoch = 5u;
    m.u.snapshot_chunk.journal_generation = entries[total - 1u].journal_generation;
    m.u.snapshot_chunk.chunk_digest =
        qihse_consensus_snapshot_chunk_digest(&m.u.snapshot_chunk);
    return m;
}

static void write_record(FILE* f, const char* body) {
    uint64_t h = 0xCBF2CE48D222D25BULL;
    for (const unsigned char* p = (const unsigned char*)body; *p; p++) {
        h ^= *p;
        h *= 1099511628211ULL;
    }
    fprintf(f, "%s %016llx\n", body, (unsigned long long)h);
}

static void encode_hex(const uint8_t* src, size_t len, char* out) {
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0u; i < len; i++) {
        out[2u * i] = hex[src[i] >> 4];
        out[2u * i + 1u] = hex[src[i] & 0x0fu];
    }
    out[2u * len] = '\0';
}

static void write_snapshot_entry(FILE* f, const qihse_consensus_entry_t* e) {
    char payload[2u * QIHSE_CONSENSUS_PAYLOAD_MAX + 1u];
    char body[512];
    encode_hex(e->payload, e->payload_len, payload);
    snprintf(body, sizeof(body), "SE %llu %llu %llu %llu %u %u %u %s",
             (unsigned long long)e->index, (unsigned long long)e->term,
             (unsigned long long)e->journal_generation,
             (unsigned long long)e->hlc.physical_ms,
             (unsigned)e->hlc.logical, (unsigned)e->classif,
             (unsigned)e->sci, payload);
    write_record(f, body);
}

static qihse_consensus_t* open_stage_consensus(const char* path,
                                               const qihse_uuid_t* from,
                                               const qihse_uuid_t* self) {
    qihse_consensus_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.group_id, sizeof(cfg.group_id), "%s", "qihse.test.stage");
    cfg.self = *self;
    cfg.member_count = 2u;
    cfg.members[0] = *from;
    cfg.members[1] = *self;
    cfg.election_timeout_base_ms = 150u;
    cfg.election_timeout_spread_ms = 300u;
    cfg.heartbeat_interval_ms = 50u;
    snprintf(cfg.record_path, sizeof(cfg.record_path), "%s", path);
    return qihse_consensus_open(&cfg, NULL, NULL);
}

static qihse_consensus_snapshot_stage_t* open_stage(
    const char* path, const qihse_user_t* principal,
    qihse_consensus_validate_data_fn validate_data, void* context,
    bool require_validator) {
    qihse_consensus_snapshot_stage_t* s = NULL;
    assert(qihse_consensus_snapshot_stage_open(
        path, "qihse.test.stage", principal, validate_data, context,
        require_validator, &s));
    assert(s);
    return s;
}

static qihse_consensus_snapshot_stage_progress_t progress(
    qihse_consensus_snapshot_stage_t* s, const qihse_user_t* principal) {
    qihse_consensus_snapshot_stage_progress_t p;
    assert(qihse_consensus_snapshot_stage_get_progress(s, principal, &p));
    return p;
}

int main(void) {
    char dir[] = "build/test_consensus_stage_XXXXXX";
    assert(mkdtemp(dir));
    assert(setenv("QIHSE_DATA_DIR", dir, 1) == 0);
    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator("SnapshotStageOperator1!"));
    qihse_user_t* op = qihse_auth_get_user(0u);
    assert(op);
    qihse_user_t* analyst = qihse_auth_create_user(
        op, 62001u, QIHSE_ROLE_ANALYST, 1u, 0u,
        "WireAnalystPass1!", false);
    assert(analyst);

    qihse_uuid_t from, to;
    assert(qihse_uuid_from_seed("stage-leader", 12u, &from));
    assert(qihse_uuid_from_seed("stage-follower", 14u, &to));
    qihse_consensus_entry_t prefix[3];
    make_prefix(prefix);
    uint64_t digest = qihse_consensus_snapshot_entries_digest(prefix, 3u);
    bool validate = true;

    char path[160];
    snprintf(path, sizeof(path), "%s/prefix.stage", dir);
    qihse_consensus_snapshot_stage_t* s = open_stage(
        path, op, accept_any_data, &validate, true);
    qihse_consensus_snapshot_stage_progress_t p = progress(s, op);
    assert(!p.has_transfer && !p.complete && p.next_entry_index == 1u);

    qihse_consensus_msg_t first = make_chunk(&from, &to, prefix, 101u,
                                              digest, 1u, 1u);
    qihse_consensus_msg_t final = make_chunk(&from, &to, prefix, 101u,
                                              digest, 2u, 2u);
    qihse_consensus_msg_t gap = make_chunk(&from, &to, prefix, 101u,
                                            digest, 2u, 2u);
    assert(qihse_consensus_snapshot_stage_accept(s, op, &gap) ==
           QIHSE_SNAPSHOT_STAGE_GAP);
    assert(!progress(s, op).has_transfer);
    assert(qihse_consensus_snapshot_stage_accept(s, op, &first) ==
           QIHSE_SNAPSHOT_STAGE_OK);
    assert(qihse_consensus_snapshot_stage_accept(s, op, &first) ==
           QIHSE_SNAPSHOT_STAGE_DUPLICATE);
    qihse_consensus_entry_t unavailable[1];
    size_t unavailable_count = 77u;
    assert(!qihse_consensus_snapshot_stage_read(
        s, op, 1u, unavailable, 1u, &unavailable_count));
    assert(unavailable_count == 0u);

    qihse_consensus_msg_t changed = first;
    changed.u.snapshot_chunk.entries[0].payload[0] ^= 0x1u;
    changed.u.snapshot_chunk.chunk_digest =
        qihse_consensus_snapshot_chunk_digest(&changed.u.snapshot_chunk);
    assert(qihse_consensus_snapshot_stage_accept(s, op, &changed) ==
           QIHSE_SNAPSHOT_STAGE_CONFLICT);
    changed = first;
    changed.u.snapshot_chunk.transfer_id++;
    changed.u.snapshot_chunk.chunk_digest =
        qihse_consensus_snapshot_chunk_digest(&changed.u.snapshot_chunk);
    assert(qihse_consensus_snapshot_stage_accept(s, op, &changed) ==
           QIHSE_SNAPSHOT_STAGE_CONFLICT);
    changed = first;
    changed.u.snapshot_chunk.first_entry_index = 3u;
    changed.u.snapshot_chunk.entries[0] = prefix[2];
    changed.u.snapshot_chunk.final_chunk = true;
    changed.u.snapshot_chunk.chunk_digest =
        qihse_consensus_snapshot_chunk_digest(&changed.u.snapshot_chunk);
    assert(qihse_consensus_snapshot_stage_accept(s, op, &changed) ==
           QIHSE_SNAPSHOT_STAGE_GAP);

    p = progress(s, op);
    assert(p.has_transfer && !p.complete && p.transfer_id == 101u &&
           p.total_entries == 3u && p.next_entry_index == 2u);
    qihse_consensus_snapshot_stage_close(s);

    /* A torn final record is discarded on reopen. The preceding durable
     * chunk remains and the sender can resume from its first missing index. */
    int fd = open(path, O_WRONLY | O_APPEND | O_CLOEXEC);
    assert(fd >= 0);
    const uint8_t torn[2] = {0u, 0u};
    assert(write(fd, torn, sizeof(torn)) == (ssize_t)sizeof(torn));
    close(fd);
    s = open_stage(path, op, accept_any_data, &validate, true);
    p = progress(s, op);
    assert(p.has_transfer && !p.complete && p.next_entry_index == 2u);
    qihse_consensus_msg_t resumed_first = first;
    resumed_first.term = 5u;
    resumed_first.fencing_epoch = 5u;
    assert(qihse_consensus_snapshot_stage_rebind(s, op, &resumed_first) ==
           QIHSE_SNAPSHOT_STAGE_OK);
    assert(qihse_consensus_snapshot_stage_accept(s, op, &resumed_first) ==
           QIHSE_SNAPSHOT_STAGE_DUPLICATE);

    qihse_consensus_msg_t changed_descriptor = resumed_first;
    changed_descriptor.term = 6u;
    changed_descriptor.fencing_epoch = 6u;
    changed_descriptor.u.snapshot_chunk.digest ^= 1u;
    changed_descriptor.u.snapshot_chunk.chunk_digest =
        qihse_consensus_snapshot_chunk_digest(
            &changed_descriptor.u.snapshot_chunk);
    assert(qihse_consensus_snapshot_stage_rebind(s, op,
        &changed_descriptor) == QIHSE_SNAPSHOT_STAGE_CONFLICT);
    qihse_consensus_msg_t stale_rebind = resumed_first;
    stale_rebind.term = 4u;
    stale_rebind.fencing_epoch = 4u;
    assert(qihse_consensus_snapshot_stage_rebind(s, op, &stale_rebind) ==
           QIHSE_SNAPSHOT_STAGE_CONFLICT);

    p = progress(s, op);
    assert(p.has_transfer && !p.complete && p.next_entry_index == 2u);
    qihse_consensus_snapshot_stage_close(s);
    s = open_stage(path, op, accept_any_data, &validate, true);
    p = progress(s, op);
    assert(p.has_transfer && !p.complete && p.next_entry_index == 2u);
    assert(qihse_consensus_snapshot_stage_accept(s, op, &resumed_first) ==
           QIHSE_SNAPSHOT_STAGE_DUPLICATE);
    qihse_consensus_msg_t resumed_final = final;
    resumed_final.term = 5u;
    resumed_final.fencing_epoch = 5u;
    assert(qihse_consensus_snapshot_stage_accept(s, op, &resumed_final) ==
           QIHSE_SNAPSHOT_STAGE_OK);
    p = progress(s, op);
    assert(p.complete && p.next_entry_index == 4u);
    assert(qihse_consensus_snapshot_stage_accept(s, op, &resumed_final) ==
           QIHSE_SNAPSHOT_STAGE_DUPLICATE);
    qihse_consensus_snapshot_stage_close(s);
    s = open_stage(path, op, accept_any_data, &validate, true);
    p = progress(s, op);
    assert(p.complete && p.next_entry_index == 4u);
    qihse_consensus_snapshot_stage_close(s);

    /* A current authenticated leader may replace only an incomplete stage
     * when its snapshot strictly extends the committed prefix. A process
     * crash after atomic replacement must reopen as the new empty stage. */
    char replacement_path[160];
    snprintf(replacement_path, sizeof(replacement_path), "%s/replacement.stage", dir);
    s = open_stage(replacement_path, op, accept_any_data, &validate, true);
    assert(qihse_consensus_snapshot_stage_accept(s, op, &first) ==
           QIHSE_SNAPSHOT_STAGE_OK);

    qihse_consensus_entry_t newer_prefix[4];
    memset(newer_prefix, 0, sizeof(newer_prefix));
    memcpy(newer_prefix, prefix, sizeof(prefix));
    newer_prefix[3].index = 4u;
    newer_prefix[3].term = 5u;
    newer_prefix[3].journal_generation = 44u;
    newer_prefix[3].hlc.physical_ms = 1004u;
    newer_prefix[3].type = QIHSE_CONSENSUS_ENTRY_DATA;
    newer_prefix[3].payload_len = 5u;
    memcpy(newer_prefix[3].payload, "new!!", 5u);
    uint64_t newer_digest =
        qihse_consensus_snapshot_entries_digest(newer_prefix, 4u);
    qihse_consensus_msg_t newer_first = make_newer_prefix_chunk(
        &from, &to, newer_prefix, 4u, 202u, newer_digest, 1u, 1u);

    assert(qihse_consensus_snapshot_stage_replace(s, op, NULL, &newer_first) ==
           QIHSE_SNAPSHOT_STAGE_AUTH);
    qihse_uuid_t other_leader;
    assert(qihse_uuid_from_seed("not-current-leader", 18u, &other_leader));
    assert(qihse_consensus_snapshot_stage_replace(
        s, op, &other_leader, &newer_first) == QIHSE_SNAPSHOT_STAGE_AUTH);
    qihse_consensus_msg_t same_term_replacement = newer_first;
    same_term_replacement.term = 4u;
    same_term_replacement.fencing_epoch = 4u;
    assert(qihse_consensus_snapshot_stage_replace(
        s, op, &from, &same_term_replacement) != QIHSE_SNAPSHOT_STAGE_OK);

    qihse_consensus_entry_t fencing_only_prefix[4];
    memcpy(fencing_only_prefix, newer_prefix, sizeof(fencing_only_prefix));
    fencing_only_prefix[3].term = 4u;
    uint64_t fencing_only_digest =
        qihse_consensus_snapshot_entries_digest(fencing_only_prefix, 4u);
    qihse_consensus_msg_t fencing_only_replacement = make_prefix_chunk(
        &from, &to, fencing_only_prefix, 4u, 204u, fencing_only_digest,
        1u, 1u);
    fencing_only_replacement.fencing_epoch = 5u;
    assert(qihse_consensus_snapshot_stage_replace(
        s, op, &from, &fencing_only_replacement) != QIHSE_SNAPSHOT_STAGE_OK);

    /* Same descriptor with altered content is still a conflict, even from a
     * newer term. It cannot take the replacement path. */
    qihse_consensus_msg_t same_descriptor_conflict = first;
    same_descriptor_conflict.term = 6u;
    same_descriptor_conflict.fencing_epoch = 6u;
    same_descriptor_conflict.u.snapshot_chunk.entries[0].payload[0] ^= 1u;
    same_descriptor_conflict.u.snapshot_chunk.chunk_digest =
        qihse_consensus_snapshot_chunk_digest(
            &same_descriptor_conflict.u.snapshot_chunk);
    assert(qihse_consensus_snapshot_stage_replace(
        s, op, &from, &same_descriptor_conflict) ==
        QIHSE_SNAPSHOT_STAGE_CONFLICT);
    p = progress(s, op);
    assert(p.has_transfer && !p.complete && p.transfer_id == 101u &&
           p.next_entry_index == 2u);
    qihse_consensus_snapshot_stage_close(s);
    s = open_stage(replacement_path, op, accept_any_data, &validate, true);
    p = progress(s, op);
    assert(p.has_transfer && !p.complete && p.transfer_id == 101u &&
           p.next_entry_index == 2u);
    qihse_consensus_snapshot_stage_close(s);

    pid_t replacer = fork();
    assert(replacer >= 0);
    if (replacer == 0) {
        qihse_consensus_snapshot_stage_t* child_stage = NULL;
        if (!qihse_consensus_snapshot_stage_open(replacement_path,
                "qihse.test.stage", op, accept_any_data, &validate, true,
                &child_stage)) _exit(10);
        qihse_consensus_snapshot_stage_result_t replaced =
            qihse_consensus_snapshot_stage_replace(
                child_stage, op, &from, &newer_first);
        /* _exit models process death without stage_close after the rename. */
        _exit(replaced == QIHSE_SNAPSHOT_STAGE_OK ? 0 : 11);
    }
    int child_status = 0;
    assert(waitpid(replacer, &child_status, 0) == replacer);
    assert(WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0);
    s = open_stage(replacement_path, op, accept_any_data, &validate, true);
    p = progress(s, op);
    assert(p.has_transfer && !p.complete && p.transfer_id == 202u &&
           p.total_entries == 4u && p.next_entry_index == 1u);
    assert(qihse_consensus_snapshot_stage_accept(s, op, &first) ==
           QIHSE_SNAPSHOT_STAGE_CONFLICT);
    assert(qihse_consensus_snapshot_stage_accept(s, op, &newer_first) ==
           QIHSE_SNAPSHOT_STAGE_OK);
    qihse_consensus_snapshot_stage_close(s);

    s = open_stage(replacement_path, op, accept_any_data, &validate, true);
    p = progress(s, op);
    assert(p.has_transfer && !p.complete && p.transfer_id == 202u &&
           p.next_entry_index == 2u);
    qihse_consensus_msg_t newer_rest = make_newer_prefix_chunk(
        &from, &to, newer_prefix, 4u, 202u, newer_digest, 2u, 3u);
    assert(qihse_consensus_snapshot_stage_accept(s, op, &newer_rest) ==
           QIHSE_SNAPSHOT_STAGE_OK);
    p = progress(s, op);
    assert(p.complete && p.next_entry_index == 5u);
    qihse_consensus_msg_t complete_stage_replacement = newer_first;
    complete_stage_replacement.term = 7u;
    complete_stage_replacement.fencing_epoch = 7u;
    complete_stage_replacement.u.snapshot_chunk.transfer_id = 203u;
    complete_stage_replacement.u.snapshot_chunk.chunk_digest =
        qihse_consensus_snapshot_chunk_digest(
            &complete_stage_replacement.u.snapshot_chunk);
    assert(qihse_consensus_snapshot_stage_replace(
        s, op, &from, &complete_stage_replacement) ==
        QIHSE_SNAPSHOT_STAGE_CONFLICT);
    qihse_consensus_entry_t recovered_newer[4];
    size_t recovered_newer_count = 0u;
    assert(qihse_consensus_snapshot_stage_read(s, op, 1u, recovered_newer,
        4u, &recovered_newer_count));
    assert(recovered_newer_count == 4u);
    for (size_t i = 0u; i < 4u; i++)
        assert(entries_equal(&recovered_newer[i], &newer_prefix[i]));
    qihse_consensus_snapshot_stage_close(s);

    /* A stage at the recovery size ceiling rejects another record before
     * writing any bytes, so accepted data can always be reopened. */
    char limit_path[160];
    snprintf(limit_path, sizeof(limit_path), "%s/size-limit.stage", dir);
    s = open_stage(limit_path, op, accept_any_data, &validate, true);
    int limit_fd = open(limit_path, O_RDWR | O_CLOEXEC);
    assert(limit_fd >= 0);
    const off_t stage_file_max = 32 * 1024 * 1024;
    assert(ftruncate(limit_fd, stage_file_max) == 0);
    close(limit_fd);
    qihse_consensus_msg_t limit_chunk = make_chunk(&from, &to, prefix, 909u,
                                                   digest, 1u, 1u);
    assert(qihse_consensus_snapshot_stage_accept(s, op, &limit_chunk) ==
           QIHSE_SNAPSHOT_STAGE_LIMIT);
    struct stat limit_stat;
    assert(stat(limit_path, &limit_stat) == 0 &&
           limit_stat.st_size == stage_file_max);
    qihse_consensus_snapshot_stage_close(s);
    remove(limit_path);

    /* A final chunk whose full-prefix digest is wrong is not persisted as
     * complete and is rejected after the prior prefix remains resumable. */
    char bad_path[160];
    snprintf(bad_path, sizeof(bad_path), "%s/bad-digest.stage", dir);
    s = open_stage(bad_path, op, accept_any_data, &validate, true);
    qihse_consensus_msg_t bad_first = make_chunk(&from, &to, prefix, 202u,
                                                  digest ^ 1u, 1u, 1u);
    qihse_consensus_msg_t bad_final = make_chunk(&from, &to, prefix, 202u,
                                                  digest ^ 1u, 2u, 2u);
    assert(qihse_consensus_snapshot_stage_accept(s, op, &bad_first) ==
           QIHSE_SNAPSHOT_STAGE_OK);
    assert(qihse_consensus_snapshot_stage_accept(s, op, &bad_final) ==
           QIHSE_SNAPSHOT_STAGE_INTEGRITY);
    p = progress(s, op);
    assert(!p.complete && p.next_entry_index == 2u);
    qihse_consensus_snapshot_stage_close(s);
    s = open_stage(bad_path, op, accept_any_data, &validate, true);
    p = progress(s, op);
    assert(!p.complete && p.next_entry_index == 2u);
    qihse_consensus_snapshot_stage_close(s);

    /* Staging applies SCI authorization and the configured durable DATA
     * validator before writing any header or chunk record. */
    char auth_path[160];
    snprintf(auth_path, sizeof(auth_path), "%s/auth.stage", dir);
    s = open_stage(auth_path, op, accept_any_data, &validate, true);
    qihse_consensus_msg_t classified = make_chunk(&from, &to, prefix, 303u,
                                                   digest, 1u, 1u);
    classified.u.snapshot_chunk.entries[0].classif = 3u;
    classified.u.snapshot_chunk.entries[0].sci = 4u;
    classified.u.snapshot_chunk.chunk_digest =
        qihse_consensus_snapshot_chunk_digest(&classified.u.snapshot_chunk);
    assert(qihse_consensus_snapshot_stage_accept(s, analyst, &classified) ==
           QIHSE_SNAPSHOT_STAGE_AUTH);
    assert(!progress(s, op).has_transfer);
    qihse_consensus_msg_t rejected = make_chunk(&from, &to, prefix, 304u,
                                                 digest, 1u, 1u);
    qihse_consensus_snapshot_stage_t* no_validator = NULL;
    assert(!qihse_consensus_snapshot_stage_open(
        "build/missing-validator.stage", "qihse.test.stage", op,
        NULL, NULL, true, &no_validator));
    validate = false;
    assert(qihse_consensus_snapshot_stage_accept(s, op, &rejected) ==
           QIHSE_SNAPSHOT_STAGE_INTEGRITY);
    assert(!progress(s, op).has_transfer);
    qihse_consensus_snapshot_stage_close(s);

    /* A complete long prefix can be read in bounded authenticated windows,
     * published with S2, and recovered after restart. A trailing incomplete
     * S2 transaction must retain the prior snapshot and be truncated so the
     * resumed node can accept a later publication. */
    qihse_consensus_entry_t long_prefix[30];
    memcpy(long_prefix, prefix, sizeof(prefix));
    for (size_t i = 3u; i < 30u; i++) {
        memset(&long_prefix[i], 0, sizeof(long_prefix[i]));
        long_prefix[i].index = i + 1u;
        long_prefix[i].term = 4u;
        long_prefix[i].journal_generation = 41u + i;
        long_prefix[i].hlc.physical_ms = 2000u + i;
        long_prefix[i].type = QIHSE_CONSENSUS_ENTRY_DATA;
        long_prefix[i].payload_len = 5u;
        memcpy(long_prefix[i].payload, "long!", 5u);
    }
    long_prefix[8].classif = 3u;
    long_prefix[8].sci = 4u;
    validate = true;
    uint64_t long_digest =
        qihse_consensus_snapshot_entries_digest(long_prefix, 30u);
    char long_stage_path[160];
    snprintf(long_stage_path, sizeof(long_stage_path), "%s/long.stage", dir);
    s = open_stage(long_stage_path, op, accept_any_data, &validate, true);
    for (uint64_t first_index = 1u; first_index <= 30u; first_index += 8u) {
        size_t n = 30u - (size_t)first_index + 1u;
        if (n > QIHSE_CONSENSUS_SNAPSHOT_CHUNK_MAX_ENTRIES)
            n = QIHSE_CONSENSUS_SNAPSHOT_CHUNK_MAX_ENTRIES;
        qihse_consensus_msg_t chunk = make_prefix_chunk(
            &from, &to, long_prefix, 30u, 404u, long_digest,
            first_index, n);
        qihse_consensus_snapshot_stage_result_t chunk_result =
            qihse_consensus_snapshot_stage_accept(s, op, &chunk);
        if (chunk_result != QIHSE_SNAPSHOT_STAGE_OK)
            fprintf(stderr, "long chunk first=%llu result=%s\n",
                    (unsigned long long)first_index,
                    qihse_consensus_snapshot_stage_result_name(chunk_result));
        assert(chunk_result == QIHSE_SNAPSHOT_STAGE_OK);
    }
    qihse_consensus_entry_t window[QIHSE_CONSENSUS_SNAPSHOT_CHUNK_MAX_ENTRIES];
    size_t window_count = 0u;
    assert(qihse_consensus_snapshot_stage_read(
        s, op, 9u, window, QIHSE_CONSENSUS_SNAPSHOT_CHUNK_MAX_ENTRIES,
        &window_count));
    assert(window_count == QIHSE_CONSENSUS_SNAPSHOT_CHUNK_MAX_ENTRIES);
    assert(window[0].index == 9u && window[0].classif == 3u &&
           window[0].sci == 4u);
    assert(!qihse_consensus_snapshot_stage_read(
        s, analyst, 9u, window, QIHSE_CONSENSUS_SNAPSHOT_CHUNK_MAX_ENTRIES,
        &window_count));
    assert(window_count == 0u);

    char consensus_path[160];
    snprintf(consensus_path, sizeof(consensus_path), "%s/long.rec", dir);
    qihse_consensus_t* consensus = open_stage_consensus(consensus_path,
                                                        &from, &to);
    assert(consensus);
    assert(!qihse_consensus_snapshot_stage_publish(s, analyst, consensus));
    assert(qihse_consensus_snapshot_index(consensus) == 0u);
    qihse_consensus_snapshot_descriptor_t old_descriptor;
    memset(&old_descriptor, 0, sizeof(old_descriptor));
    snprintf(old_descriptor.group_id, sizeof(old_descriptor.group_id),
             "%s", "qihse.test.stage");
    old_descriptor.from = from; old_descriptor.to = to;
    old_descriptor.term = old_descriptor.fencing_epoch = 4u;
    old_descriptor.last_included_index = 3u;
    old_descriptor.last_included_term = 4u;
    old_descriptor.snapshot_fencing_epoch = 4u;
    old_descriptor.journal_generation = 43u;
    old_descriptor.digest = digest;
    assert(qihse_consensus_install_snapshot_prefix(
        consensus, op, &old_descriptor, prefix, 3u));
    assert(qihse_consensus_snapshot_index(consensus) == 3u);
    qihse_consensus_close(consensus);

    qihse_consensus_snapshot_descriptor_t long_descriptor;
    assert(qihse_consensus_snapshot_stage_get_descriptor(
        s, op, &long_descriptor));
    FILE* interrupted = fopen(consensus_path, "a");
    assert(interrupted);
    char s2_header[160];
    snprintf(s2_header, sizeof(s2_header), "S2 30 4 4 70 %016llx 30",
             (unsigned long long)long_digest);
    write_record(interrupted, s2_header);
    for (size_t i = 0u; i < 3u; i++)
        write_snapshot_entry(interrupted, &long_prefix[i]);
    fclose(interrupted);

    consensus = open_stage_consensus(consensus_path, &from, &to);
    assert(consensus);
    assert(qihse_consensus_snapshot_index(consensus) == 3u);
    assert(qihse_consensus_commit_index(consensus) == 3u);
    assert(qihse_consensus_snapshot_stage_publish(s, op, consensus));
    assert(qihse_consensus_snapshot_index(consensus) == 30u);
    assert(qihse_consensus_commit_index(consensus) == 30u);
    qihse_consensus_close(consensus);
    consensus = open_stage_consensus(consensus_path, &from, &to);
    assert(consensus);
    assert(qihse_consensus_snapshot_index(consensus) == 30u);
    assert(qihse_consensus_commit_index(consensus) == 30u);
    qihse_consensus_entry_t recovered[30];
    size_t recovered_count = 0u;
    assert(qihse_consensus_read_committed(consensus, op, 1u,
                                           recovered, 30u,
                                           &recovered_count));
    assert(recovered_count == 30u);
    for (size_t i = 0u; i < 30u; i++)
        assert(entries_equal(&recovered[i], &long_prefix[i]));
    qihse_consensus_close(consensus);
    qihse_consensus_snapshot_stage_close(s);
    remove(long_stage_path);
    remove(consensus_path);

    assert(qihse_auth_destroy_user(op, qihse_user_get_id(analyst)));
    remove(path); remove(bad_path); remove(auth_path);
    remove(replacement_path);
    rmdir(dir);
    puts("PASS consensus snapshot staging: ordered durable chunks, exact retries, "
         "atomic newer-prefix replacement, crash/restart resume, digest gate, and SCI denial");
    return 0;
}
