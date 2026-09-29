/*
 * test_federation_ingest.c — W7 item 3: the KEYSTONE live-ingestion
 * contract (brief §5.2) and the snapshot↔watch cursor handshake (§5.1).
 *
 *   - tombstone append/replay: object.delete rides the reserved mutation
 *     flag; the on-disk envelope layout is unchanged (old records decode
 *     with the bit clear)
 *   - boot(C) handshake: live consumption starts at the snapshot cursor;
 *     snapshot-tail overlap is discarded by event-id dedup, and stale
 *     writers by the generation gate
 *   - at-least-once idempotency: re-running (crash before checkpoint) and
 *     a duplicated request_id never reach the apply callback twice
 *   - generation ordering: regressions skipped and counted; a tombstone
 *     resets the lifecycle so a later lower-generation create applies
 *   - checkpoint roundtrip: cursor, dedup ring, gates and stats survive
 *     destroy/open
 *   - boot() refuses on a consumer with progress (no silent ring discard)
 */

#include "qihse_auth.h"
#include "qihse_federation.h"
#include "qihse_federation_ingest.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static char g_dir[512];

static void test_path(char* out, size_t cap, const char* name) {
    int n = snprintf(out, cap, "%s/%s", g_dir, name);
    assert(n > 0 && (size_t)n < cap);
}

static void mk_mutation(qihse_federation_mutation_t* m, const char* seed,
                        uint64_t gen) {
    memset(m, 0, sizeof(*m));
    assert(qihse_uuid_from_seed(seed, strlen(seed), &m->request_id));
    assert(qihse_uuid_from_seed("ingest-origin", strlen("ingest-origin"),
                                &m->origin_node));
    m->expected_generation = gen;
    m->consistency = QIHSE_CONSISTENCY_QUORUM;
}

/* apply callback recording what actually reached the consumer */
#define APPLIED_MAX 64
typedef struct {
    struct { char resource[64]; uint64_t gen; int del; } applied[APPLIED_MAX];
    size_t count;
    int refuse_at;            /* refuse the Nth apply (1-based); 0 = never */
} apply_log_t;

static bool log_apply(qihse_federation_ingest_op_t op,
                      const qihse_federation_event_t* ev,
                      const uint8_t* payload, size_t payload_len,
                      void* ud) {
    (void)payload; (void)payload_len;
    apply_log_t* log = (apply_log_t*)ud;
    if (log->refuse_at > 0 && (int)log->count + 1 == log->refuse_at) {
        return false;                        /* simulated consumer failure */
    }
    assert(log->count < APPLIED_MAX);
    snprintf(log->applied[log->count].resource, 64, "%s", ev->resource_id);
    log->applied[log->count].gen = ev->mutation.expected_generation;
    log->applied[log->count].del =
        (op == QIHSE_INGEST_APPLY_DELETE) ? 1 : 0;
    log->count++;
    return true;
}

static void test_tombstone_envelope(void) {
    char jdir[576];
    test_path(jdir, sizeof(jdir), "j_tomb");
    assert(mkdir(jdir, 0700) == 0);
    qihse_federation_journal_t* j = qihse_federation_journal_open(
        jdir, QIHSE_ES_DURABILITY_FDATASYNC);
    assert(j);

    qihse_federation_mutation_t m;
    qihse_federation_event_t ev;

    /* Ordinary upsert: flag clear. */
    mk_mutation(&m, "put-one", 11);
    assert(qihse_federation_journal_append(j, &m, "object.put", "vm/1",
                                           (const uint8_t*)"x", 1u, &ev) > 0);
    assert(!qihse_federation_event_is_tombstone(&ev));

    /* Tombstone: flag set, event_type object.delete, no payload. */
    mk_mutation(&m, "del-one", 12);
    assert(qihse_federation_journal_append_tombstone(j, &m, "vm/1", &ev) > 0);
    assert(qihse_federation_event_is_tombstone(&ev));
    assert(strcmp(ev.event_type, "object.delete") == 0);

    /* A tombstone without a generation is an argument error — an
     * unconditional delete cannot be ordered against upserts. */
    mk_mutation(&m, "del-nogen", 0);
    assert(qihse_federation_journal_append_tombstone(j, &m, "vm/2", NULL) == 0);
    assert(qihse_federation_journal_append_tombstone(NULL, &m, "vm/2", NULL) == 0);

    /* The replay round-trip is covered by test_tombstone_replay_typed. */
    qihse_federation_journal_destroy(j);
    printf("[PASS] tombstone envelope: append flag set, no-gen refused\n");
}

/* replay shim with a closure-free context */
typedef struct {
    int puts;
    int deletes;
} tally_t;

static bool tally_cb(const qihse_federation_event_t* ev,
                     const uint8_t* payload, size_t len, void* ud) {
    (void)payload; (void)len;
    tally_t* t = (tally_t*)ud;
    if (qihse_federation_event_is_tombstone(ev)) t->deletes++;
    else t->puts++;
    return true;
}

static void test_tombstone_replay_typed(void) {
    char jdir[576];
    test_path(jdir, sizeof(jdir), "j_tomb2");
    assert(mkdir(jdir, 0700) == 0);
    qihse_federation_journal_t* j = qihse_federation_journal_open(
        jdir, QIHSE_ES_DURABILITY_FDATASYNC);
    assert(j);

    qihse_federation_mutation_t m;
    qihse_federation_event_t ev;
    mk_mutation(&m, "p1", 1);
    assert(qihse_federation_journal_append(j, &m, "object.put", "r/a",
                                           NULL, 0u, &ev) > 0);
    mk_mutation(&m, "d1", 2);
    assert(qihse_federation_journal_append_tombstone(j, &m, "r/a", &ev) > 0);
    mk_mutation(&m, "p2", 3);
    assert(qihse_federation_journal_append(j, &m, "object.put", "r/b",
                                           NULL, 0u, &ev) > 0);

    tally_t t = {0, 0};
    assert(qihse_federation_journal_replay(j, 0, tally_cb, &t) == 3);
    assert(t.puts == 2 && t.deletes == 1);
    qihse_federation_journal_destroy(j);
    printf("[PASS] tombstone replay: puts/deletes distinguished over the wire record\n");
}

static void test_handshake_and_gates(void) {
    char jdir[576], ckpath[576];
    test_path(jdir, sizeof(jdir), "j_hs");
    test_path(ckpath, sizeof(ckpath), "ck_hs.ckpt");
    assert(mkdir(jdir, 0700) == 0);
    unlink(ckpath);
    qihse_federation_journal_t* j = qihse_federation_journal_open(
        jdir, QIHSE_ES_DURABILITY_FDATASYNC);
    assert(j);

    qihse_federation_mutation_t m;
    qihse_federation_event_t ev;

    /* Events BEFORE the snapshot cursor: the snapshot already has them. */
    mk_mutation(&m, "pre-1", 5);
    assert(qihse_federation_journal_append(j, &m, "object.put", "vm/1",
                                           NULL, 0u, &ev) > 0);
    mk_mutation(&m, "pre-2", 6);
    assert(qihse_federation_journal_append(j, &m, "object.put", "vm/2",
                                           NULL, 0u, &ev) > 0);

    /* The cursor AFTER pre-2 — the §5.1 handshake point C. */
    uint64_t C = qihse_federation_journal_length(j);

    /* Post-snapshot live events: an overlapping duplicate of pre-2's
     * request_id (the snapshot materialized slightly later), a stale
     * writer on vm/1, a fresh upsert, then a tombstone and a reborn
     * create at a lower generation. */
    mk_mutation(&m, "pre-2", 6);              /* SAME request_id as pre-2 */
    assert(qihse_federation_journal_append(j, &m, "object.put", "vm/2",
                                           NULL, 0u, &ev) > 0);
    mk_mutation(&m, "stale-1", 4);            /* gen 4 <= 5 on vm/1 */
    assert(qihse_federation_journal_append(j, &m, "object.put", "vm/1",
                                           NULL, 0u, &ev) > 0);
    mk_mutation(&m, "live-1", 9);
    assert(qihse_federation_journal_append(j, &m, "object.put", "vm/1",
                                           (const uint8_t*)"v9", 2u, &ev) > 0);
    mk_mutation(&m, "del-1", 10);
    assert(qihse_federation_journal_append_tombstone(j, &m, "vm/1", &ev) > 0);
    mk_mutation(&m, "reborn-1", 2);           /* new lifecycle after delete */
    assert(qihse_federation_journal_append(j, &m, "object.put", "vm/1",
                                           NULL, 0u, &ev) > 0);
    /* A RETRY of live-1: same request_id (idempotency key), newer
     * generation — the dedup ring must refuse it even though gen 11 > 9
     * would pass the generation gate. */
    mk_mutation(&m, "live-1", 11);
    assert(qihse_federation_journal_append(j, &m, "object.put", "vm/1",
                                           NULL, 0u, &ev) > 0);

    /* Consumer boots at C and seeds its generation gates from the
     * SNAPSHOT state (vm/1@5, vm/2@6): overlap events hit the stale
     * gate, not the callback. */
    qihse_federation_ingest_t* ing = qihse_federation_ingest_open(ckpath);
    assert(ing);
    assert(qihse_federation_ingest_boot(ing, C));
    assert(qihse_federation_ingest_seed_generation(ing, "vm/1", 5));
    assert(qihse_federation_ingest_seed_generation(ing, "vm/2", 6));
    /* boot() is one-shot: a consumer with progress refuses a re-boot. */
    assert(!qihse_federation_ingest_boot(ing, C));

    apply_log_t log;
    memset(&log, 0, sizeof(log));
    uint64_t consumed = qihse_federation_ingest_run(ing, j, 0, log_apply,
                                                    &log, NULL);
    assert(consumed == 6);
    /* Exactly three applies: live-1 (9), del-1 (10, delete), reborn (2).
     * The duplicate pre-2 and stale-1 never reached the callback. */
    assert(log.count == 3);
    assert(strcmp(log.applied[0].resource, "vm/1") == 0 &&
           log.applied[0].gen == 9 && !log.applied[0].del);
    assert(strcmp(log.applied[1].resource, "vm/1") == 0 &&
           log.applied[1].gen == 10 && log.applied[1].del);
    assert(strcmp(log.applied[2].resource, "vm/1") == 0 &&
           log.applied[2].gen == 2 && !log.applied[2].del);

    qihse_federation_ingest_stats_t st;
    qihse_federation_ingest_stats(ing, &st);
    assert(st.applied_upserts == 2 && st.applied_deletes == 1);
    /* 2 stale (the snapshot-overlap pre-2 retry at gen 6, the old writer
     * at gen 4) and 1 duplicate (live-1's retry — refused by the ring
     * before its newer generation could matter). */
    assert(st.skipped_duplicates == 1 && st.skipped_stale == 2);

    /* Re-run: nothing new, nothing applied. */
    memset(&log, 0, sizeof(log));
    assert(qihse_federation_ingest_run(ing, j, 0, log_apply, &log, NULL) == 0);
    assert(log.count == 0);

    qihse_federation_ingest_destroy(ing);
    qihse_federation_journal_destroy(j);
    printf("[PASS] handshake + gates: overlap deduped, stale skipped, tombstone resets lifecycle\n");
}

static void test_at_least_once_idempotent(void) {
    char jdir[576], ckpath[576];
    test_path(jdir, sizeof(jdir), "j_alo");
    test_path(ckpath, sizeof(ckpath), "ck_alo.ckpt");
    assert(mkdir(jdir, 0700) == 0);
    unlink(ckpath);
    qihse_federation_journal_t* j = qihse_federation_journal_open(
        jdir, QIHSE_ES_DURABILITY_FDATASYNC);
    assert(j);

    qihse_federation_mutation_t m;
    qihse_federation_event_t ev;
    for (int i = 0; i < 4; i++) {
        char seed[32];
        snprintf(seed, sizeof(seed), "alo-%d", i);
        mk_mutation(&m, seed, (uint64_t)(i + 1));
        assert(qihse_federation_journal_append(j, &m, "object.put", "r/x",
                                               NULL, 0u, &ev) > 0);
    }

    qihse_federation_ingest_t* ing = qihse_federation_ingest_open(ckpath);
    assert(ing);

    /* Simulated crash: the consumer refuses the 3rd apply (its own write
     * failed).  run() stops; the checkpoint holds the first two. */
    apply_log_t log;
    memset(&log, 0, sizeof(log));
    log.refuse_at = 3;
    uint64_t consumed = qihse_federation_ingest_run(ing, j, 0, log_apply,
                                                    &log, NULL);
    assert(consumed == 3);                    /* two applied, third refused */
    assert(log.count == 2);

    /* A checkpoint roundtrip in between: cursor + dedup ring survive. */
    qihse_federation_ingest_destroy(ing);
    ing = qihse_federation_ingest_open(ckpath);
    assert(ing);
    qihse_federation_ingest_stats_t st;
    qihse_federation_ingest_stats(ing, &st);
    assert(st.applied_upserts == 2);

    /* Retry: the refused event re-delivers (at-least-once) and this time
     * applies; the first two are NOT re-applied (idempotent). */
    memset(&log, 0, sizeof(log));
    consumed = qihse_federation_ingest_run(ing, j, 0, log_apply, &log, NULL);
    assert(consumed == 2);                    /* events 3 and 4 */
    assert(log.count == 2);
    assert(log.applied[0].gen == 3 && log.applied[1].gen == 4);

    qihse_federation_ingest_stats(ing, &st);
    assert(st.applied_upserts == 4 && st.skipped_duplicates == 0);

    qihse_federation_ingest_destroy(ing);
    qihse_federation_journal_destroy(j);
    printf("[PASS] at-least-once + idempotent: refused event re-delivers once, never twice-applied\n");
}

static void test_checkpoint_fail_closed(void) {
    char bad[576];
    test_path(bad, sizeof(bad), "ck_bad.ckpt");
    FILE* f = fopen(bad, "wb");
    assert(f);
    fwrite("garbage-not-a-checkpoint", 1u, 25u, f);
    fclose(f);
    /* A torn/foreign checkpoint file fails closed: the consumer must
     * re-bootstrap deliberately, never silently restart from zero. */
    assert(qihse_federation_ingest_open(bad) == NULL);
    printf("[PASS] unreadable checkpoint fails closed (no silent from-zero restart)\n");
}

int main(void) {
    snprintf(g_dir, sizeof(g_dir), "build/federation_ingest_test_XXXXXX");
    assert(mkdtemp(g_dir) != NULL);
    assert(setenv("QIHSE_DATA_DIR", g_dir, 1) == 0);

    test_tombstone_envelope();
    test_tombstone_replay_typed();
    test_handshake_and_gates();
    test_at_least_once_idempotent();
    test_checkpoint_fail_closed();

    char cmd[768];
    snprintf(cmd, sizeof(cmd), "rm -rf -- '%s'", g_dir);
    for (int attempt = 0; attempt < 5; attempt++) {
        if (system(cmd) == 0) break;
        usleep(200000);
    }

    printf("federation ingest tests passed\n");
    return 0;
}
