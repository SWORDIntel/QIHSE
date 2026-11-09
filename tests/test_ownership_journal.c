/* test_ownership_journal.c — append/replay/corruption tests for the durable
 * slot-ownership journal (COPY → PERSIST → SWITCH → GC). */

#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "qihse_cluster_ownership.h"
#include "qihse_cluster_ownership_journal.h"
#include "qihse_audit.h"

static void remove_fixture(const char* path) {
    DIR* dir = opendir(path);
    assert(dir);
    struct dirent* entry;
    while ((entry = readdir(dir))) {
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        assert(unlinkat(dirfd(dir), entry->d_name, 0) == 0);
    }
    assert(closedir(dir) == 0);
    assert(rmdir(path) == 0);
}

typedef struct {
    int count;
    uint16_t last_start, last_end;
    char last_owner[QIHSE_CLUSTER_NODE_ID_LEN + 1u];
    uint64_t last_epoch;
} replay_ctx_t;

static void on_entry(const qihse_cluster_ownership_entry_t* e, void* ctx) {
    replay_ctx_t* r = (replay_ctx_t*)ctx;
    r->count++;
    r->last_start = e->start;
    r->last_end = e->end;
    strncpy(r->last_owner, e->owner_id, QIHSE_CLUSTER_NODE_ID_LEN);
    r->last_owner[QIHSE_CLUSTER_NODE_ID_LEN] = '\0';
    r->last_epoch = e->config_epoch;
}

typedef struct { unsigned count; qihse_cluster_ownership_phase_t last; } txn_replay_t;
static bool on_txn(const qihse_cluster_ownership_txn_t* t, void* ctx) {
    txn_replay_t* r = ctx;
    r->count++;
    r->last = t->phase;
    return true;
}
static qihse_cluster_ownership_txn_t txn(qihse_cluster_ownership_phase_t phase) {
    qihse_cluster_ownership_txn_t t;
    memset(&t, 0, sizeof(t));
    t.phase = phase; t.start = 500; t.end = 550; t.config_epoch = 8;
    t.source_lsn = 100; t.target_lsn = phase == QIHSE_OWNERSHIP_COMMITTED ? 100 : 0;
    strcpy(t.transfer_id, "ct2-test-1"); strcpy(t.source_id, "node-a");
    strcpy(t.target_id, "node-b"); strcpy(t.generation, "generation-3");
    strcpy(t.source_qkp_id, "qkp-source-configured");
    strcpy(t.target_qkp_id, "qkp-target-configured");
    strcpy(t.owner_id, phase == QIHSE_OWNERSHIP_COMMITTED ? "node-b" : "node-a");
    if (phase == QIHSE_OWNERSHIP_COMMITTED) memset(t.proof_digest, 0x5a, sizeof(t.proof_digest));
    return t;
}

static void assert_txn_zero(const qihse_cluster_ownership_txn_t* t) {
    const unsigned char* p = (const unsigned char*)t;
    for (size_t i = 0; i < sizeof(*t); ++i) assert(p[i] == 0);
}

static qihse_cluster_ownership_txn_t finalized_ct2(const char* id,
                                                    uint16_t first,
                                                    uint16_t last,
                                                    uint64_t epoch) {
    qihse_cluster_ownership_txn_t p = txn(QIHSE_OWNERSHIP_PREPARED);
    snprintf(p.transfer_id, sizeof(p.transfer_id), "%s", id);
    p.start = first; p.end = last; p.config_epoch = epoch;
    qihse_cluster_ownership_txn_t c = p;
    c.phase = QIHSE_OWNERSHIP_COMMITTED;
    c.target_lsn = 1u; /* target and source cursors are independent domains */
    snprintf(c.owner_id, sizeof(c.owner_id), "%s", c.target_id);
    memset(c.proof_digest, 0x6b, sizeof(c.proof_digest));
    c.phase = QIHSE_OWNERSHIP_FINALIZED;
    return c;
}

typedef struct {
    const char* dir;
    qihse_cluster_ownership_txn_t txn;
    int result;
} terminal_race_t;
static void* append_terminal_race(void* opaque) {
    terminal_race_t* r = opaque;
    r->result = qihse_cluster_ownership_journal_append_txn(r->dir, &r->txn);
    return NULL;
}

int main(void) {
    char dir[] = "./tests/.qihse_journal_XXXXXX";
    assert(mkdtemp(dir));

    /* append 3 entries */
    assert(qihse_cluster_ownership_journal_append(dir, 100, 199, "node-a", 5) == 0);
    assert(qihse_cluster_ownership_journal_append(dir, 200, 299, "node-b", 6) == 0);
    assert(qihse_cluster_ownership_journal_append(dir, 300, 399, "node-c", 4) == 0);

    /* replay: 3 entries, front-to-back, content preserved (incl. a lower epoch) */
    replay_ctx_t r;
    memset(&r, 0, sizeof(r));
    int n = qihse_cluster_ownership_journal_replay(dir, on_entry, &r);
    assert(n == 3);
    assert(r.count == 3);
    assert(r.last_start == 300 && r.last_end == 399);
    assert(strcmp(r.last_owner, "node-c") == 0);
    assert(r.last_epoch == 4);
    printf("[PASS] journal append + replay (3 entries, order + content)\n");

    /* corrupt the tail byte of the LAST record — replay must skip it, keep the 3 valid */
    char path[1024];
    snprintf(path, sizeof(path), "%s/slot-ownership.journal", dir);
    FILE* f = fopen(path, "r+b");
    assert(f);
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, sz - 1, SEEK_SET);
    fputc(0xFF, f);
    fclose(f);

    memset(&r, 0, sizeof(r));
    n = qihse_cluster_ownership_journal_replay(dir, on_entry, &r);
    assert(n == 2);
    assert(r.last_start == 200 && r.last_end == 299); /* the corrupt 3rd record is skipped */
    printf("[PASS] corrupt tail record skipped, earlier entries preserved\n");

    /* no journal → 0 (not an error) */
    char dir2[] = "./tests/.qihse_journal_empty_XXXXXX";
    assert(mkdtemp(dir2));
    memset(&r, 0, sizeof(r));
    n = qihse_cluster_ownership_journal_replay(dir2, on_entry, &r);
    assert(n == 0);
    printf("[PASS] absent journal replays as empty\n");

    /* V2 transfer phases are ordered, durable and distinct from v1 ownership
     * entries. PREPARED/COMMITTED remain unresolved until FINALIZED or ABORTED. */
    char dir3[] = "./tests/.qihse_journal_v2_XXXXXX";
    assert(mkdtemp(dir3));
    assert(qihse_cluster_ownership_journal_append(dir3, 1, 9, "legacy", 2) == 0);
    qihse_cluster_ownership_txn_t prepared = txn(QIHSE_OWNERSHIP_PREPARED);
    assert(qihse_cluster_ownership_journal_append_txn(dir3, &prepared) == 0);
    bool unresolved = false; txn_replay_t tr = {0};
    n = qihse_cluster_ownership_journal_replay_txn(dir3, on_txn, &tr, &unresolved);
    assert(n == 1 && unresolved && tr.last == QIHSE_OWNERSHIP_PREPARED);
    assert(qihse_cluster_ownership_journal_append_txn(dir3, &prepared) < 0);
    qihse_cluster_ownership_txn_t committed = txn(QIHSE_OWNERSHIP_COMMITTED);
    assert(qihse_cluster_ownership_journal_append_txn(dir3, &committed) == 0);
    qihse_cluster_ownership_txn_t finalized = committed;
    finalized.phase = QIHSE_OWNERSHIP_FINALIZED;
    assert(qihse_cluster_ownership_journal_append_txn(dir3, &finalized) == 0);
    memset(&tr, 0, sizeof(tr)); unresolved = true;
    n = qihse_cluster_ownership_journal_replay_txn(dir3, on_txn, &tr, &unresolved);
    assert(n == 3 && !unresolved && tr.count == 3 && tr.last == QIHSE_OWNERSHIP_FINALIZED);
    memset(&r, 0, sizeof(r));
    assert(qihse_cluster_ownership_journal_replay(dir3, on_entry, &r) == 1);
    assert(r.last_start == 1 && strcmp(r.last_owner, "legacy") == 0);
    qihse_cluster_ownership_txn_t ct1_prepare = txn(QIHSE_OWNERSHIP_PREPARED);
    strcpy(ct1_prepare.transfer_id, "ct1-test-1");
    strcpy(ct1_prepare.next_generation, "next-generation-4");
    ct1_prepare.slot_bitmap[10 / 8u] |= (uint8_t)(1u << (10 % 8u));
    ct1_prepare.slot_bitmap[11 / 8u] |= (uint8_t)(1u << (11 % 8u));
    ct1_prepare.slot_bitmap[12 / 8u] |= (uint8_t)(1u << (12 % 8u));
    ct1_prepare.start = 10; ct1_prepare.end = 12;
    /* CT1 uses the fixed owner field to persist its explicitly selected next
     * successor across a crash before receiver generation promotion. */
    strcpy(ct1_prepare.owner_id, "node-c");
    assert(qihse_cluster_ownership_journal_append_txn(dir3, &ct1_prepare) == 0);
    qihse_cluster_ownership_txn_t ct1_commit = ct1_prepare;
    ct1_commit.phase = QIHSE_OWNERSHIP_COMMITTED;
    ct1_commit.target_lsn = ct1_commit.source_lsn;
    memset(ct1_commit.proof_digest, 0x35, sizeof(ct1_commit.proof_digest));
    assert(qihse_cluster_ownership_journal_append_txn(dir3, &ct1_commit) == 0);
    qihse_cluster_ownership_txn_t ct1_finalized = ct1_commit;
    ct1_finalized.phase = QIHSE_OWNERSHIP_FINALIZED;
    assert(qihse_cluster_ownership_journal_append_txn(dir3, &ct1_finalized) == 0);
    char dir_cross_domain[] = "./tests/.qihse_journal_cross_domain_XXXXXX";
    assert(mkdtemp(dir_cross_domain));
    qihse_cluster_ownership_txn_t cross_domain_prepare = txn(QIHSE_OWNERSHIP_PREPARED);
    strcpy(cross_domain_prepare.transfer_id, "ct2-cross-domain-cursors");
    cross_domain_prepare.source_lsn = 1000;
    assert(qihse_cluster_ownership_journal_append_txn(dir_cross_domain,
        &cross_domain_prepare) == 0);
    qihse_cluster_ownership_txn_t cross_domain_commit = cross_domain_prepare;
    cross_domain_commit.phase = QIHSE_OWNERSHIP_COMMITTED;
    cross_domain_commit.target_lsn = 1;
    strcpy(cross_domain_commit.owner_id, cross_domain_commit.target_id);
    memset(cross_domain_commit.proof_digest, 0x44, sizeof(cross_domain_commit.proof_digest));
    assert(qihse_cluster_ownership_journal_append_txn(dir_cross_domain,
        &cross_domain_commit) == 0);
    puts("[PASS] CT2 source/target cursors are independent domains");
    qihse_cluster_ownership_txn_t abort_prepare = txn(QIHSE_OWNERSHIP_PREPARED);
    strcpy(abort_prepare.transfer_id, "ct2-abort-1");
    assert(qihse_cluster_ownership_journal_append_txn(dir3, &abort_prepare) == 0);
    qihse_cluster_ownership_txn_t aborted = abort_prepare;
    aborted.phase = QIHSE_OWNERSHIP_ABORTED;
    assert(qihse_cluster_ownership_journal_append_txn(dir3, &aborted) == 0);
    memset(&tr, 0, sizeof(tr)); unresolved = true;
    n = qihse_cluster_ownership_journal_replay_txn(dir3, on_txn, &tr, &unresolved);
    assert(n == 8 && !unresolved && tr.count == 8 && tr.last == QIHSE_OWNERSHIP_ABORTED);
    printf("[PASS] v1 compatibility + v2 CT1/CT2 prepare/commit recovery ordering\n");

    /* Two processes/threads may race to finalize one PREPARED transfer. The
     * stable sidecar lock must serialize replay/validate/append/fsync so only
     * one terminal phase becomes durable. */
    char dir_race[] = "./tests/.qihse_journal_race_XXXXXX";
    assert(mkdtemp(dir_race));
    qihse_cluster_ownership_txn_t race_prepare = txn(QIHSE_OWNERSHIP_PREPARED);
    strcpy(race_prepare.transfer_id, "ct2-terminal-race");
    assert(qihse_cluster_ownership_journal_append_txn(dir_race, &race_prepare) == 0);
    terminal_race_t commit_race = {.dir = dir_race, .txn = txn(QIHSE_OWNERSHIP_COMMITTED)};
    terminal_race_t abort_race = {.dir = dir_race, .txn = txn(QIHSE_OWNERSHIP_ABORTED)};
    strcpy(commit_race.txn.transfer_id, "ct2-terminal-race");
    strcpy(abort_race.txn.transfer_id, "ct2-terminal-race");
    pthread_t commit_thread, abort_thread;
    assert(pthread_create(&commit_thread, NULL, append_terminal_race, &commit_race) == 0);
    assert(pthread_create(&abort_thread, NULL, append_terminal_race, &abort_race) == 0);
    assert(pthread_join(commit_thread, NULL) == 0 && pthread_join(abort_thread, NULL) == 0);
    assert((commit_race.result == 0) != (abort_race.result == 0));
    if (commit_race.result == 0) {
        qihse_cluster_ownership_txn_t race_final = commit_race.txn;
        race_final.phase = QIHSE_OWNERSHIP_FINALIZED;
        assert(qihse_cluster_ownership_journal_append_txn(dir_race, &race_final) == 0);
    }
    memset(&tr, 0, sizeof(tr)); unresolved = true;
    n = qihse_cluster_ownership_journal_replay_txn(dir_race, on_txn, &tr, &unresolved);
    assert(!unresolved);
    assert((abort_race.result == 0 && n == 2 && tr.last == QIHSE_OWNERSHIP_ABORTED) ||
           (commit_race.result == 0 && n == 3 && tr.last == QIHSE_OWNERSHIP_FINALIZED));
    printf("[PASS] concurrent COMMIT/ABORT permits exactly one durable terminal phase\n");

    char dir_multi[] = "./tests/.qihse_journal_multi_XXXXXX";
    assert(mkdtemp(dir_multi));
    for (unsigned i = 0; i < 2; ++i) {
        qihse_cluster_ownership_txn_t p = txn(QIHSE_OWNERSHIP_PREPARED);
        snprintf(p.transfer_id, sizeof(p.transfer_id), "ct2-sequential-%u", i);
        p.config_epoch += i;
        p.start = (uint16_t)(500 + i); p.end = p.start;
        assert(qihse_cluster_ownership_journal_append_txn(dir_multi, &p) == 0);
        qihse_cluster_ownership_txn_t c = p;
        c.phase = QIHSE_OWNERSHIP_COMMITTED; c.target_lsn = c.source_lsn;
        strcpy(c.owner_id, c.target_id); memset(c.proof_digest, (int)(0x70 + i), 32);
        assert(qihse_cluster_ownership_journal_append_txn(dir_multi, &c) == 0);
        c.phase = QIHSE_OWNERSHIP_FINALIZED;
        assert(qihse_cluster_ownership_journal_append_txn(dir_multi, &c) == 0);
    }
    memset(&tr, 0, sizeof(tr)); unresolved = true;
    n = qihse_cluster_ownership_journal_replay_txn(dir_multi, on_txn, &tr, &unresolved);
    assert(n == 6 && !unresolved && tr.count == 6 && tr.last == QIHSE_OWNERSHIP_FINALIZED);
    printf("[PASS] sequential ownership transactions replay after restart without current peer seals\n");

    /* A torn prepared record is not silently discarded: startup receives a
     * hard error and a fence-required unresolved indication. */
    char dir4[] = "./tests/.qihse_journal_torn_XXXXXX";
    assert(mkdtemp(dir4));
    assert(qihse_cluster_ownership_journal_append_txn(dir4, &prepared) == 0);
    snprintf(path, sizeof(path), "%s/slot-ownership.journal", dir4);
    int fd = open(path, O_WRONLY | O_APPEND);
    assert(fd >= 0 && write(fd, "partial", 7) == 7 && close(fd) == 0);
    unresolved = false; errno = 0;
    assert(qihse_cluster_ownership_journal_replay_txn(dir4, NULL, NULL, &unresolved) < 0);
    assert(unresolved);
    printf("[PASS] torn v2 tail requires fenced recovery\n");

    char dir5[] = "./tests/.qihse_journal_corrupt_v2_XXXXXX";
    assert(mkdtemp(dir5));
    assert(qihse_cluster_ownership_journal_append_txn(dir5, &prepared) == 0);
    snprintf(path, sizeof(path), "%s/slot-ownership.journal", dir5);
    fd = open(path, O_RDWR);
    assert(fd >= 0);
    assert(lseek(fd, 70, SEEK_SET) == 70);
    unsigned char byte = 0;
    assert(read(fd, &byte, 1) == 1);
    byte ^= 0x80;
    assert(lseek(fd, 70, SEEK_SET) == 70 && write(fd, &byte, 1) == 1 && close(fd) == 0);
    unresolved = false;
    assert(qihse_cluster_ownership_journal_replay_txn(dir5, NULL, NULL, &unresolved) < 0);
    assert(unresolved);
    printf("[PASS] corrupt v2 record is rejected and fenced\n");

    /* Public ownership getters are Operator-only, zero outputs on every
     * refusal, and finalized CT2 outcomes remain queryable after later work. */
    char auth_dir[] = "./tests/.qihse_ownership_lookup_XXXXXX";
    assert(mkdtemp(auth_dir));
    assert(setenv("QIHSE_DATA_DIR", auth_dir, 1) == 0);
    assert(setenv("QIHSE_FIPS_MODE", "disabled", 1) == 0);
    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator("OwnershipLookup-Op-Password-9!"));
    qihse_user_t* op = qihse_auth_get_user(0u);
    assert(op && qihse_auth_user_is_active(op));
    qihse_user_t* guest = qihse_auth_create_user(op, 991u, QIHSE_ROLE_GUEST,
        0u, 0u, "OwnershipLookup-Guest-Password-9!", false);
    assert(guest);
    qihse_kv_store_t* store = qihse_kv_store_create();
    assert(store);
    const char* store_dir = qihse_kv_store_data_directory(store);
    assert(store_dir && *store_dir);
    qihse_cluster_ownership_context_t ownership = {.store = store, .principal = op};

    qihse_cluster_ownership_txn_t old_final = finalized_ct2(
        "terminal-retry-original", 100u, 120u, 20u);
    qihse_cluster_ownership_txn_t prep_old = old_final;
    prep_old.phase = QIHSE_OWNERSHIP_PREPARED;
    prep_old.target_lsn = 0u; memset(prep_old.proof_digest, 0, sizeof(prep_old.proof_digest));
    snprintf(prep_old.owner_id, sizeof(prep_old.owner_id), "%s", prep_old.source_id);
    assert(qihse_cluster_ownership_journal_append_txn(store_dir, &prep_old) == 0);
    qihse_cluster_ownership_txn_t commit_old = old_final;
    commit_old.phase = QIHSE_OWNERSHIP_COMMITTED;
    assert(qihse_cluster_ownership_journal_append_txn(store_dir, &commit_old) == 0);
    assert(qihse_cluster_ownership_journal_append_txn(store_dir, &old_final) == 0);

    qihse_cluster_ownership_txn_t later = finalized_ct2(
        "terminal-retry-later", 121u, 140u, 21u);
    qihse_cluster_ownership_txn_t prep_later = later;
    prep_later.phase = QIHSE_OWNERSHIP_PREPARED;
    prep_later.target_lsn = 0u; memset(prep_later.proof_digest, 0, sizeof(prep_later.proof_digest));
    snprintf(prep_later.owner_id, sizeof(prep_later.owner_id), "%s", prep_later.source_id);
    assert(qihse_cluster_ownership_journal_append_txn(store_dir, &prep_later) == 0);
    qihse_cluster_ownership_txn_t commit_later = later;
    commit_later.phase = QIHSE_OWNERSHIP_COMMITTED;
    assert(qihse_cluster_ownership_journal_append_txn(store_dir, &commit_later) == 0);
    assert(qihse_cluster_ownership_journal_append_txn(store_dir, &later) == 0);

    qihse_cluster_ownership_txn_t current = txn(QIHSE_OWNERSHIP_PREPARED);
    snprintf(current.transfer_id, sizeof(current.transfer_id), "terminal-retry-current");
    current.config_epoch = 22u;
    assert(qihse_cluster_ownership_journal_append_txn(store_dir, &current) == 0);

    qihse_cluster_ownership_txn_t got;
    memset(&got, 0xa5, sizeof(got));
    assert(qihse_cluster_ownership_transfer_get_finalized(&ownership,
        "terminal-retry-original", &got, NULL, 0));
    assert(got.phase == QIHSE_OWNERSHIP_FINALIZED &&
        !strcmp(got.transfer_id, old_final.transfer_id) &&
        got.config_epoch == old_final.config_epoch &&
        got.start == old_final.start && got.end == old_final.end &&
        got.target_lsn == old_final.target_lsn &&
        memcmp(got.proof_digest, old_final.proof_digest, 32u) == 0);
    memset(&got, 0xa5, sizeof(got));
    assert(!qihse_cluster_ownership_transfer_get_finalized(&ownership,
        "terminal-retry-current", &got, NULL, 0));
    assert_txn_zero(&got);
    memset(&got, 0xa5, sizeof(got));
    assert(qihse_cluster_ownership_transfer_get_prepared(&ownership,
        "terminal-retry-current", &got, NULL, 0));
    assert(got.phase == QIHSE_OWNERSHIP_PREPARED);

    qihse_cluster_ownership_context_t denied = ownership;
    denied.principal = guest;
    memset(&got, 0xa5, sizeof(got));
    assert(!qihse_cluster_ownership_transfer_get_finalized(&denied,
        "terminal-retry-original", &got, NULL, 0));
    assert_txn_zero(&got);
    memset(&got, 0xa5, sizeof(got));
    assert(!qihse_cluster_ownership_transfer_get_prepared(&denied,
        "terminal-retry-current", &got, NULL, 0));
    assert_txn_zero(&got);

    qihse_cluster_ownership_txn_t current_commit = current;
    current_commit.phase = QIHSE_OWNERSHIP_COMMITTED;
    current_commit.target_lsn = 1u;
    snprintf(current_commit.owner_id, sizeof(current_commit.owner_id), "%s",
        current_commit.target_id);
    memset(current_commit.proof_digest, 0x7c, sizeof(current_commit.proof_digest));
    assert(qihse_cluster_ownership_journal_append_txn(store_dir, &current_commit) == 0);
    memset(&got, 0xa5, sizeof(got));
    assert(qihse_cluster_ownership_transfer_get_committed(&ownership,
        "terminal-retry-current", &got, NULL, 0));
    assert(got.phase == QIHSE_OWNERSHIP_COMMITTED &&
        !strcmp(got.transfer_id, current_commit.transfer_id));
    memset(&got, 0xa5, sizeof(got));
    assert(!qihse_cluster_ownership_transfer_get_prepared(&ownership,
        "terminal-retry-current", &got, NULL, 0));
    assert_txn_zero(&got);
    memset(&got, 0xa5, sizeof(got));
    assert(!qihse_cluster_ownership_transfer_get_committed(&denied,
        "terminal-retry-current", &got, NULL, 0));
    assert_txn_zero(&got);
    assert(qihse_auth_destroy_user(op, 991u));
    memset(&got, 0xa5, sizeof(got));
    assert(!qihse_cluster_ownership_transfer_get_finalized(&denied,
        "terminal-retry-original", &got, NULL, 0));
    assert_txn_zero(&got);
    memset(&got, 0xa5, sizeof(got));
    assert(!qihse_cluster_ownership_transfer_get_committed(&denied,
        "terminal-retry-current", &got, NULL, 0));
    assert_txn_zero(&got);
    denied.principal = NULL;
    memset(&got, 0xa5, sizeof(got));
    assert(!qihse_cluster_ownership_transfer_get_finalized(&denied,
        "terminal-retry-original", &got, NULL, 0));
    assert_txn_zero(&got);
    memset(&got, 0xa5, sizeof(got));
    assert(!qihse_cluster_ownership_transfer_get_committed(&denied,
        "terminal-retry-current", &got, NULL, 0));
    assert_txn_zero(&got);
    qihse_kv_store_destroy(store);
    qihse_audit_shutdown();
    const char* fixtures[] = {dir, dir2, dir3, dir_cross_domain, dir_race,
                             dir_multi, dir4, dir5, auth_dir};
    for (size_t i = 0; i < sizeof(fixtures) / sizeof(fixtures[0]); ++i)
        remove_fixture(fixtures[i]);
    printf("[PASS] finalized CT2 retry survives later phases; getters require active system Operator\n");

    printf("All ownership journal tests passed.\n");
    return 0;
}
