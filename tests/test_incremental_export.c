/*
 * test_incremental_export.c — the store's change sequence and the delta
 * (incremental) export family it enables.
 *
 * The KV layer stamps one store-global monotonic sequence on every
 * authorized mutation; the delta export returns exactly the mutations above
 * a caller-supplied cursor plus a continuation point.  The tests hold the
 * surface to its documented contract:
 *
 *   - the sequence advances on authorized set/delete, never on reads, and
 *     never on an unauthorized mutation; the high-water query is exact
 *   - a delta is exactly the mutations strictly greater than the cursor,
 *     in ascending sequence order, with correct classification/SCI metadata
 *     and tombstones for deletions
 *   - resume: export, mutate, export from the resume point returns only the
 *     new mutations; an exhausted cursor returns nothing and does not move
 *   - LOW-CLEARANCE NEGATIVE (AGENTS.md invariants 1 and 3): a guest/analyst
 *     below a record's classification gets only permitted records and no
 *     protected payload bytes, and — the no-leak design — the resume point
 *     is the highest sequence the principal was ALLOWED to see, so hidden
 *     mutations cannot be counted from it even though the store's global
 *     high-water moved; a NULL context is refused on the export surface
 *   - persistence: a flush to SSTables and a restart preserve sequences,
 *     the high-water never regresses, a pre-persist cursor still works
 *     post-restart, and a WAL-only record survives via re-stamping replay
 *   - backward compatibility: a pre-sequence record file (5- and 6-field
 *     headers) decodes with the defined default sequence 0 and round-trips;
 *     sequence-0 records are never part of a delta (bootstrap boundary)
 *   - qihse_backup_incremental_user delivers the documented incremental
 *     coverage (it used to refuse with UNSUPPORTED); its container carries
 *     only the delta, the guest's container carries no protected bytes, and
 *     whole-store restore still refuses a delta container on purpose
 */
#include "qihse_auth.h"
#include "qihse_backup.h"
#include "qihse_export.h"
#include "qihse_kv_store.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static qihse_kv_store_t* g_store;
static qihse_user_t* g_op;      /* OPERATOR: 0xFFFF clearance, all compartments */
static qihse_user_t* g_guest;   /* GUEST: clearance 0, no compartments */
static qihse_user_t* g_analyst; /* ANALYST: clearance 3, compartment 0x1 only */

static char g_dir[512];     /* store data dir + artefacts (relative paths) */

#define SECRET_B_VALUE "CLASSB-PROTECTED-PAYLOAD"      /* class 3, sci 0x2 */
#define SECRET_D_VALUE "CLASSD-PROTECTED-PAYLOAD"      /* class 5, sci 0x1 */
#define BACKUP_SECRET_VALUE "BACKUP-PROTECTED-PAYLOAD" /* class 3, sci 0x2 */

/* The whole-store container's data section starts after the 64-byte header. */
#define BACKUP_HEADER_BYTES 64u

/* ── Helpers ──────────────────────────────────────────────────────────── */

static void test_path(char* out, size_t cap, const char* name) {
    int n = snprintf(out, cap, "%s/%s", g_dir, name);
    assert(n > 0 && (size_t)n < cap);
}

static void put(qihse_user_t* user, const char* key, const char* value,
                uint16_t classif, uint16_t sci) {
    assert(qihse_kv_set_user(g_store, key, value, classif, sci, user));
}

static void del(qihse_user_t* user, const char* key) {
    assert(qihse_kv_del_user(g_store, key, user));
}

static uint64_t seq_now(void) { return qihse_kv_change_seq(g_store); }

static uint8_t* slurp(const char* path, size_t* out_len) {
    FILE* f = fopen(path, "rb");
    if (!f) return NULL;
    assert(fseek(f, 0L, SEEK_END) == 0);
    long size = ftell(f);
    assert(size >= 0);
    assert(fseek(f, 0L, SEEK_SET) == 0);
    uint8_t* buf = (uint8_t*)malloc((size_t)size + 1u);
    assert(buf);
    assert(fread(buf, 1u, (size_t)size, f) == (size_t)size);
    assert(fclose(f) == 0);
    buf[size] = '\0';
    if (out_len) *out_len = (size_t)size;
    return buf;
}

static bool buffer_holds(const uint8_t* hay, size_t hay_len, const char* needle) {
    size_t n = strlen(needle);
    if (n == 0u || hay_len < n) return false;
    for (size_t i = 0; i + n <= hay_len; i++) {
        if (memcmp(hay + i, needle, n) == 0) return true;
    }
    return false;
}

static const qihse_kv_delta_record_t* delta_find(const qihse_kv_delta_record_t* recs,
                                                 size_t count, const char* key) {
    for (size_t i = 0; i < count; i++) {
        if (strcmp(recs[i].key, key) == 0) return &recs[i];
    }
    return NULL;
}

/* One parsed text record (the store's own on-disk format). */
typedef struct {
    char key[256];
    char* val;         /* heap; NULL for tombstone */
    uint64_t expire;
    unsigned classif, sci, flags;
    uint64_t seq;
    int fields;        /* header field count as parsed */
} parsed_rec_t;

static void parsed_free(parsed_rec_t* r, size_t count) {
    for (size_t i = 0; i < count; i++) free(r[i].val);
    free(r);
}

/* Parse a sequence of text records (the store's record stream — a delta
 * file, a snapshot, or a container's data section at a byte offset). */
static parsed_rec_t* parse_records(const uint8_t* data, size_t len, size_t offset,
                                   size_t* out_count) {
    size_t cap = 16u, count = 0u;
    parsed_rec_t* recs = (parsed_rec_t*)calloc(cap, sizeof(*recs));
    assert(recs);
    size_t pos = offset;
    while (pos < len) {
        const char* line = (const char*)data + pos;
        const char* nl = (const char*)memchr(line, '\n', len - pos);
        assert(nl != NULL); /* header line must be terminated */
        size_t klen = 0u, vlen = 0u;
        unsigned long long expire = 0u, seq = 0u;
        unsigned classif = 0u, sci = 0u, flags = 0u;
        int fields = sscanf(line, "%zu %zu %llu %u %u %u %llu", &klen, &vlen,
                            &expire, &classif, &sci, &flags, &seq);
        assert(fields >= 5 && fields <= 7);
        assert(klen > 0u && klen < sizeof(recs[0].key));
        pos += (size_t)(nl - line) + 1u;
        assert(pos + klen + vlen + 1u <= len);
        if (count == cap) {
            size_t new_cap = cap * 2u;
            parsed_rec_t* next = (parsed_rec_t*)realloc(recs, new_cap * sizeof(*next));
            assert(next);
            recs = next;
            cap = new_cap;
        }
        parsed_rec_t* r = &recs[count];
        memset(r, 0, sizeof(*r));
        memcpy(r->key, data + pos, klen);
        r->key[klen] = '\0';
        pos += klen;
        if (vlen > 0u) {
            r->val = (char*)malloc(vlen + 1u);
            assert(r->val);
            memcpy(r->val, data + pos, vlen);
            r->val[vlen] = '\0';
        }
        pos += vlen;
        assert(data[pos] == '\n');
        pos += 1u;
        r->expire = (uint64_t)expire;
        r->classif = classif;
        r->sci = sci;
        r->flags = flags;
        r->seq = (uint64_t)seq;
        r->fields = fields;
        count++;
    }
    *out_count = count;
    return recs;
}

/* ── 1. Sequence discipline ───────────────────────────────────────────── */

static void test_sequence_discipline(void) {
    assert(qihse_kv_change_seq(NULL) == 0u);
    uint64_t s0 = seq_now();
    assert(s0 == 0u); /* a fresh store in a fresh data dir */

    put(g_op, "seq:one", "v1", 0, 0);
    assert(seq_now() == s0 + 1u);
    put(g_op, "seq:two", "v2", 3, 0x2);
    assert(seq_now() == s0 + 2u);

    /* Reads do not advance: the sequence is a mutation counter. */
    char* v = qihse_kv_get_user(g_store, "seq:one", g_op);
    assert(v && strcmp(v, "v1") == 0);
    free(v);
    assert(qihse_kv_exists_user(g_store, "seq:two", g_op));
    assert(seq_now() == s0 + 2u);

    /* An unauthorized mutation neither happens nor advances: the guest may
     * not write at class 3 / sci 0x2. */
    assert(!qihse_kv_set_user(g_store, "seq:guest-secret", "x", 3, 0x2, g_guest));
    assert(seq_now() == s0 + 2u);

    /* An authorized delete advances and stamps the tombstone. */
    del(g_op, "seq:one");
    assert(seq_now() == s0 + 3u);

    /* An unauthorized delete neither happens nor advances. */
    assert(!qihse_kv_del_user(g_store, "seq:two", g_guest));
    assert(seq_now() == s0 + 3u);

    printf("PASS sequence discipline: advances on authorized set/delete, "
           "not on reads, not on denials; high-water exact\n");
}

/* ── 2. Delta content ─────────────────────────────────────────────────── */

static void test_delta_returns_exactly_mutations(void) {
    uint64_t before = seq_now();
    put(g_op, "delta:pub1", "pv1", 0, 0);                 /* before+1 */
    put(g_op, "delta:secret1", SECRET_B_VALUE, 3, 0x2);   /* before+2 */
    put(g_op, "delta:pub2", "pv2", 0, 0);                 /* before+3 */
    uint64_t after = seq_now();
    assert(after == before + 3u);

    qihse_kv_delta_record_t* recs = NULL;
    size_t count = 0u;
    uint64_t resume = 0u;

    assert(qihse_kv_export_incremental_user(g_store, g_op, before,
                                            &recs, &count, &resume) == 0);
    assert(count == 3u);
    assert(resume == after);
    /* Ascending sequence order with exact keys, values and metadata. */
    assert(strcmp(recs[0].key, "delta:pub1") == 0);
    assert(!recs[0].tombstone && strcmp(recs[0].value, "pv1") == 0);
    assert(recs[0].classification == 0u && recs[0].sci_compartment == 0u);
    assert(strcmp(recs[1].key, "delta:secret1") == 0);
    assert(strcmp(recs[1].value, SECRET_B_VALUE) == 0);
    assert(recs[1].classification == 3u && recs[1].sci_compartment == 0x2u);
    assert(strcmp(recs[2].key, "delta:pub2") == 0);
    assert(recs[0].change_seq < recs[1].change_seq &&
           recs[1].change_seq < recs[2].change_seq);
    assert(recs[0].change_seq == before + 1u && recs[2].change_seq == after);
    qihse_kv_delta_records_free(recs, count);
    recs = NULL;

    /* STRICTLY greater: the cursor itself is excluded. */
    assert(qihse_kv_export_incremental_user(g_store, g_op, before + 1u,
                                            &recs, &count, &resume) == 0);
    assert(count == 2u);
    assert(delta_find(recs, count, "delta:pub1") == NULL);
    assert(delta_find(recs, count, "delta:secret1") != NULL);
    assert(resume == after);
    qihse_kv_delta_records_free(recs, count);
    recs = NULL;

    /* An exhausted cursor: nothing, and the resume point equals the cursor. */
    assert(qihse_kv_export_incremental_user(g_store, g_op, after,
                                            &recs, &count, &resume) == 0);
    assert(count == 0u && recs == NULL && resume == after);

    /* Argument errors are refused with nothing handed back. */
    assert(qihse_kv_export_incremental_user(NULL, g_op, 0u, &recs, &count, &resume) == -1);
    assert(qihse_kv_export_incremental_user(g_store, g_op, 0u, NULL, &count, &resume) == -1);
    assert(recs == NULL && count == 0u && resume == 0u);

    printf("PASS delta content: exactly the mutations strictly greater than "
           "the cursor, ascending, with classification metadata intact\n");
}

/* ── 3. Resume behavior ───────────────────────────────────────────────── */

static void test_resume_behavior(void) {
    uint64_t base = seq_now();
    qihse_kv_delta_record_t* recs = NULL;
    size_t count = 0u;
    uint64_t r1 = 0u;

    /* Export from a point with nothing outstanding. */
    assert(qihse_kv_export_incremental_user(g_store, g_op, base,
                                            &recs, &count, &r1) == 0);
    assert(count == 0u && recs == NULL && r1 == base);

    /* Mutate after the first export: a new key, a DELETE, an overwrite. */
    put(g_op, "resume:pub3", "pv3", 0, 0);            /* r1+1 */
    del(g_op, "delta:pub1");                          /* r1+2 tombstone */
    put(g_op, "delta:secret1", "rewritten", 3, 0x2);  /* r1+3 overwrite */
    assert(seq_now() == r1 + 3u);

    /* Export from the resume point: ONLY the new mutations, in sequence
     * order — the new key, the tombstone, the overwrite in its LATEST
     * state (last-writer-wins). */
    uint64_t r2 = 0u;
    assert(qihse_kv_export_incremental_user(g_store, g_op, r1,
                                            &recs, &count, &r2) == 0);
    assert(count == 3u);
    assert(strcmp(recs[0].key, "resume:pub3") == 0);
    assert(strcmp(recs[0].value, "pv3") == 0 && !recs[0].tombstone);
    assert(strcmp(recs[1].key, "delta:pub1") == 0);
    assert(recs[1].tombstone && recs[1].value == NULL);
    assert(recs[1].classification == 0u); /* the tombstone keeps the record's class */
    assert(strcmp(recs[2].key, "delta:secret1") == 0);
    assert(strcmp(recs[2].value, "rewritten") == 0);
    assert(recs[2].classification == 3u && recs[2].sci_compartment == 0x2u);
    assert(r2 == r1 + 3u);
    qihse_kv_delta_records_free(recs, count);
    recs = NULL;

    /* The next export from the new resume point: exhausted and stable. */
    uint64_t r3 = 0u;
    assert(qihse_kv_export_incremental_user(g_store, g_op, r2,
                                            &recs, &count, &r3) == 0);
    assert(count == 0u && recs == NULL && r3 == r2);

    printf("PASS resume behavior: export -> mutate -> export-from-resume "
           "yields only the new mutations, deletions carried as tombstones\n");
}

/* ── 4. Low-clearance negative: filtered, byte-absent, no-leak ────────── */

static void test_low_clearance_no_leak(void) {
    uint64_t base = seq_now();
    put(g_op, "leak:pub-a", "public-a", 0, 0);        /* base+1 guest-visible */
    put(g_op, "leak:secret-b", SECRET_B_VALUE, 3, 0x2); /* base+2 hidden: guest AND analyst */
    put(g_op, "leak:pub-c", "public-c", 0, 0);        /* base+3 guest-visible */
    put(g_op, "leak:secret-d", SECRET_D_VALUE, 5, 0x1); /* base+4 hidden: above analyst too */
    assert(seq_now() == base + 4u);

    qihse_kv_delta_record_t* recs = (qihse_kv_delta_record_t*)0x1;
    size_t count = 99u;
    uint64_t resume = 99u;
    char err[128];

    /* NULL context: an argument error on the export family surface, never
     * the KV layer's unclassified-only fallback, never "export everything". */
    assert(!qihse_export_incremental_user(g_store, NULL, base,
                                          &recs, &count, &resume, err, sizeof(err)));
    assert(recs == NULL && count == 0u && resume == 0u);
    assert(!qihse_export_incremental_user(NULL, g_op, base,
                                          &recs, &count, &resume, err, sizeof(err)));
    assert(!qihse_export_incremental_user(g_store, g_op, base,
                                          NULL, &count, &resume, err, sizeof(err)));
    assert(err[0] != '\0');

    /* The guest's delta: ONLY the permitted records — no protected keys,
     * no protected values, nothing above class 0. */
    assert(qihse_export_incremental_user(g_store, g_guest, base,
                                         &recs, &count, &resume, err, sizeof(err)));
    assert(count == 2u);
    for (size_t i = 0; i < count; i++) {
        assert(recs[i].classification == 0u && recs[i].sci_compartment == 0u);
        assert(strstr(recs[i].key, "secret") == NULL);
        assert(recs[i].value == NULL || strstr(recs[i].value, "PROTECTED") == NULL);
        assert(!recs[i].tombstone);
    }
    assert(delta_find(recs, count, "leak:pub-a") != NULL);
    assert(delta_find(recs, count, "leak:pub-c") != NULL);
    /* THE NO-LEAK PROPERTY: the resume point is the highest sequence the
     * guest was ALLOWED to see (base+3) — not the global high-water
     * (base+4), which would reveal that one hidden mutation occurred. */
    assert(resume == base + 3u);
    assert(seq_now() == base + 4u); /* the store really is ahead */
    qihse_kv_delta_records_free(recs, count);
    recs = NULL;

    /* A hidden mutation AFTER the resume point: the guest's next delta is
     * empty and its resume point DOES NOT MOVE — it cannot count hidden
     * mutations from successive exports. */
    put(g_op, "leak:secret-e", SECRET_B_VALUE, 3, 0x2); /* base+5, hidden */
    assert(seq_now() == base + 5u);
    assert(qihse_export_incremental_user(g_store, g_guest, base + 3u,
                                         &recs, &count, &resume, err, sizeof(err)));
    assert(count == 0u && recs == NULL);
    assert(resume == base + 3u); /* unchanged: no gap to count */

    /* The analyst (clearance 3, compartment 0x1) is below/compartment-
     * mismatched for every secret in this window: same two public records,
     * same no-leak resume point. */
    assert(qihse_export_incremental_user(g_store, g_analyst, base,
                                         &recs, &count, &resume, err, sizeof(err)));
    assert(count == 2u && resume == base + 3u);
    qihse_kv_delta_records_free(recs, count);
    recs = NULL;

    /* The operator sees everything, and its resume point is the store's
     * last mutation — the only principal for which the two coincide. */
    assert(qihse_export_incremental_user(g_store, g_op, base,
                                         &recs, &count, &resume, err, sizeof(err)));
    assert(count == 5u && resume == base + 5u);
    qihse_kv_delta_records_free(recs, count);
    recs = NULL;

    printf("PASS low-clearance negative: guest/analyst deltas hold only "
           "permitted records with no protected bytes, resume points reveal "
           "no hidden-mutation counts, NULL context refused\n");
}

/* ── 5. Persistence round trip (flush -> restart, WAL replay) ─────────── */

static void test_persistence_round_trip(void) {
    /* Push past the memtable limit so the records are FLUSHED to an
     * SSTable (heap buffer: no giant stack frames). */
    const size_t big_len = 200u * 1024u;
    char* big = (char*)malloc(big_len + 1u);
    assert(big);
    memset(big, 'B', big_len);
    big[big_len] = '\0';

    uint64_t base = seq_now();
    put(g_op, "persist:big1", big, 0, 0); /* base+1 */
    put(g_op, "persist:big2", big, 0, 0); /* base+2 */
    put(g_op, "persist:big3", big, 0, 0); /* base+3 -> ~600KB: flush fires */
    uint64_t hw = seq_now();
    assert(hw == base + 3u);

    char sst[576];
    test_path(sst, sizeof(sst), "sstable_0.db");
    struct stat st;
    assert(stat(sst, &st) == 0 && st.st_size > (off_t)(3u * big_len / 2u));

    /* Restart: destroy and recreate the store in the same data dir. */
    qihse_kv_store_destroy(g_store);
    g_store = qihse_kv_store_create();
    assert(g_store);

    /* The high-water did not regress: the flushed sequences were recovered
     * from the SSTable headers (exactly — the WAL was rotated empty at
     * flush, so no replay adjustments). */
    uint64_t hw2 = seq_now();
    assert(hw2 == hw);

    /* A pre-persist cursor still works post-restart: the delta returns the
     * flushed records with their sequences and payloads intact. */
    qihse_kv_delta_record_t* recs = NULL;
    size_t count = 0u;
    uint64_t resume = 0u;
    assert(qihse_kv_export_incremental_user(g_store, g_op, base,
                                            &recs, &count, &resume) == 0);
    assert(count == 3u);
    assert(resume == hw2);
    for (size_t i = 0; i < count; i++) {
        assert(strlen(recs[i].value) == big_len);
        assert(recs[i].change_seq > base && recs[i].change_seq <= hw2);
    }
    qihse_kv_delta_records_free(recs, count);
    recs = NULL;
    free(big);

    /* A WAL-only record (not yet flushed) survives a restart through WAL
     * replay, re-stamped with a fresh sequence: order preserved, high-water
     * not regressed. */
    uint64_t before_wal = seq_now();
    put(g_op, "persist:walonly", "wal-value", 0, 0); /* before_wal+1 */
    assert(seq_now() == before_wal + 1u);
    qihse_kv_store_destroy(g_store);
    g_store = qihse_kv_store_create();
    assert(g_store);
    uint64_t hw3 = seq_now();
    assert(hw3 >= before_wal + 1u);
    assert(qihse_kv_export_incremental_user(g_store, g_op, before_wal,
                                            &recs, &count, &resume) == 0);
    const qihse_kv_delta_record_t* walrec = delta_find(recs, count, "persist:walonly");
    assert(walrec != NULL);
    assert(!walrec->tombstone && strcmp(walrec->value, "wal-value") == 0);
    assert(walrec->change_seq > before_wal);
    qihse_kv_delta_records_free(recs, count);
    recs = NULL;

    printf("PASS persistence: flush+restart preserve sequences, high-water "
           "does not regress, pre-persist cursors work post-restart, WAL-only "
           "records survive replay re-stamped\n");
}

/* ── 6. Legacy record files decode with sequence 0 ────────────────────── */

static void test_legacy_format_decodes(void) {
    /* One file mixing both pre-sequence formats: a 6-field record (flags,
     * no sequence) and a 5-field record (no flags, no sequence).  A load
     * REPLACES the live dataset, so both records go in one file. */
    char path_legacy[576];
    test_path(path_legacy, sizeof(path_legacy), "legacy.snap");

    FILE* f = fopen(path_legacy, "wb");
    assert(f);
    /* key "legacy:key" (10), val "old" (3), class 3 sci 2, flags 0 */
    assert(fprintf(f, "10 3 0 3 2 0\nlegacy:keyold\n") > 0);
    /* key "legacy5:key" (11), val "fw" (2), unclassified, 5 fields */
    assert(fprintf(f, "11 2 0 0 0\nlegacy5:keyfw\n") > 0);
    assert(fclose(f) == 0);

    uint64_t before = seq_now();
    assert(qihse_kv_load_user(g_store, path_legacy, g_op) == 0);

    /* The legacy records decoded with the defined default sequence 0: the
     * store still answers reads for them. */
    char* v = qihse_kv_get_user(g_store, "legacy:key", g_op);
    assert(v && strcmp(v, "old") == 0);
    free(v);
    v = qihse_kv_get_user(g_store, "legacy5:key", g_op);
    assert(v && strcmp(v, "fw") == 0);
    free(v);

    /* The load neither regressed nor advanced the high-water: sequence-0
     * records floor at 0 and a restore is not a mutation. */
    assert(seq_now() == before);

    /* Bootstrap boundary: sequence-0 records are NEVER part of a delta
     * (seq > since with since >= 0 excludes them) — a caller bootstraps
     * with a full export, then tracks deltas. */
    qihse_kv_delta_record_t* recs = NULL;
    size_t count = 0u;
    uint64_t resume = 0u;
    assert(qihse_kv_export_incremental_user(g_store, g_op, before,
                                            &recs, &count, &resume) == 0);
    assert(count == 0u && recs == NULL && resume == before);

    /* A mutation after the load gets the next sequence normally. */
    put(g_op, "legacy:new", "post-legacy", 0, 0);
    assert(seq_now() == before + 1u);
    assert(qihse_kv_export_incremental_user(g_store, g_op, before,
                                            &recs, &count, &resume) == 0);
    assert(count == 1u && strcmp(recs[0].key, "legacy:new") == 0);
    assert(recs[0].change_seq == before + 1u);
    assert(resume == before + 1u);
    qihse_kv_delta_records_free(recs, count);
    recs = NULL;

    /* The v4 round trip: a full snapshot now writes 7-field headers, and
     * reloading preserves the stamped sequences (the legacy records keep
     * their 0s, the new record keeps before+1). */
    char snap[576];
    test_path(snap, sizeof(snap), "v4roundtrip.snap");
    assert(qihse_kv_save_user(g_store, snap, g_op) == 0);
    size_t len = 0u;
    uint8_t* bytes = slurp(snap, &len);
    assert(bytes);
    parsed_rec_t* parsed = parse_records(bytes, len, 0u, &count);
    free(bytes);
    assert(count == 3u);
    for (size_t i = 0; i < count; i++) assert(parsed[i].fields == 7);
    parsed_free(parsed, count);

    assert(qihse_kv_load_user(g_store, snap, g_op) == 0);
    assert(seq_now() >= before + 1u); /* floor raised to the file's max, never lowered */
    assert(qihse_kv_export_incremental_user(g_store, g_op, before,
                                            &recs, &count, &resume) == 0);
    assert(count == 1u && strcmp(recs[0].key, "legacy:new") == 0);
    assert(recs[0].change_seq == before + 1u);
    qihse_kv_delta_records_free(recs, count);
    recs = NULL;

    /* The delta FILE form: the same stream, written atomically, with the
     * resume point reported to the caller. */
    char dpath[576];
    test_path(dpath, sizeof(dpath), "delta-file.bin");
    uint64_t file_resume = 0u;
    assert(qihse_kv_save_delta_user(g_store, dpath, g_op, before, &file_resume) == 0);
    assert(file_resume == before + 1u);
    bytes = slurp(dpath, &len);
    assert(bytes);
    parsed = parse_records(bytes, len, 0u, &count);
    free(bytes);
    assert(count == 1u);
    assert(strcmp(parsed[0].key, "legacy:new") == 0);
    assert(parsed[0].seq == before + 1u && parsed[0].fields == 7);
    parsed_free(parsed, count);

    unlink(path_legacy);
    unlink(snap);
    unlink(dpath);

    printf("PASS legacy compatibility: 5- and 6-field records decode with "
           "sequence 0 and round-trip; v4 files carry sequences; sequence-0 "
           "records are a full-export bootstrap, never a delta\n");
}

/* ── 7. qihse_backup_incremental_user delivers the contract ───────────── */

static void test_backup_incremental_wired(void) {
    /* Store state here: the two legacy records (sequence 0) + legacy:new.
     * Add two fresh mutations: one public, one classified. */
    uint64_t base = seq_now();
    put(g_op, "backup:one", "backup-pub", 0, 0);            /* base+1 */
    put(g_op, "backup:secret", BACKUP_SECRET_VALUE, 3, 0x2); /* base+2 */
    uint64_t hw = seq_now();
    assert(hw == base + 2u);

    char op_path[576], guest_path[576];
    test_path(op_path, sizeof(op_path), "incr-op.bak");
    test_path(guest_path, sizeof(guest_path), "incr-guest.bak");

    /* NULL is an argument error, never an implicit everything-export. */
    qihse_backup_info_t info;
    memset(&info, 0xAB, sizeof(info));
    assert(qihse_backup_incremental_user(g_store, NULL, op_path, base, &info) ==
           QIHSE_BACKUP_EXPORT_ERR);
    assert(qihse_backup_incremental_user(NULL, g_op, op_path, base, &info) ==
           QIHSE_BACKUP_EXPORT_ERR);
    assert(qihse_backup_incremental_user(g_store, g_op, NULL, base, &info) ==
           QIHSE_BACKUP_EXPORT_ERR);
    assert(info.path == NULL && info.checksum == NULL);

    /* The operator's delta container: the documented incremental coverage
     * — this is the change: it answers the contract instead of
     * UNSUPPORTED. */
    memset(&info, 0, sizeof(info));
    assert(qihse_backup_incremental_user(g_store, g_op, op_path, base, &info) ==
           QIHSE_BACKUP_EXPORT_OK);
    assert(info.type == BACKUP_INCREMENTAL);
    assert(info.start_lsn == base);
    assert(info.end_lsn == hw); /* the operator sees everything */
    assert(info.path && strcmp(info.path, op_path) == 0);
    assert(info.checksum && strlen(info.checksum) == 16u);
    assert(info.classification == qihse_user_get_classification(g_op));
    assert(info.sci_compartment == qihse_user_get_sci(g_op));
    struct stat st;
    assert(stat(op_path, &st) == 0);
    assert((size_t)st.st_size == info.size_bytes);
    assert((st.st_mode & 0777u) == 0600u); /* classified-adjacent: not world-readable */

    /* The container's data section is EXACTLY the two mutations since the
     * cursor — not a full snapshot: the pre-cursor records are absent. */
    size_t len = 0u;
    uint8_t* bytes = slurp(op_path, &len);
    assert(bytes && len > BACKUP_HEADER_BYTES);
    size_t count = 0u;
    parsed_rec_t* parsed = parse_records(bytes, len, BACKUP_HEADER_BYTES, &count);
    free(bytes);
    assert(count == 2u);
    assert(strcmp(parsed[0].key, "backup:one") == 0);
    assert(strcmp(parsed[0].val, "backup-pub") == 0);
    assert(parsed[0].seq == base + 1u);
    assert(strcmp(parsed[1].key, "backup:secret") == 0);
    assert(parsed[1].classif == 3u && parsed[1].sci == 0x2u);
    assert(parsed[1].seq == base + 2u);
    parsed_free(parsed, count);
    qihse_backup_info_free(&info);

    /* The guest's delta container: clearance-FILTERED at the KV layer —
     * only the public mutation, and NO protected payload bytes anywhere. */
    memset(&info, 0, sizeof(info));
    assert(qihse_backup_incremental_user(g_store, g_guest, guest_path, base, &info) ==
           QIHSE_BACKUP_EXPORT_OK);
    assert(info.type == BACKUP_INCREMENTAL);
    assert(info.start_lsn == base);
    assert(info.end_lsn == base + 1u); /* no-leak resume: highest VISIBLE seq */
    bytes = slurp(guest_path, &len);
    assert(bytes);
    assert(!buffer_holds(bytes, len, BACKUP_SECRET_VALUE));
    parsed = parse_records(bytes, len, BACKUP_HEADER_BYTES, &count);
    free(bytes);
    assert(count == 1u);
    assert(strcmp(parsed[0].key, "backup:one") == 0);
    assert(parsed[0].classif == 0u);
    parsed_free(parsed, count);
    qihse_backup_info_free(&info);

    /* An exhausted cursor yields an honest empty delta container. */
    memset(&info, 0, sizeof(info));
    assert(qihse_backup_incremental_user(g_store, g_op, op_path, hw, &info) ==
           QIHSE_BACKUP_EXPORT_OK);
    assert(info.type == BACKUP_INCREMENTAL && info.start_lsn == hw && info.end_lsn == hw);
    bytes = slurp(op_path, &len);
    assert(bytes && len == BACKUP_HEADER_BYTES); /* header only: empty section */
    free(bytes);
    qihse_backup_info_free(&info);

    /* Whole-store restore refuses a delta container ON PURPOSE: a delta is
     * not a whole-store image, and applying it as one would silently drop
     * every record it does not carry. */
    assert(qihse_backup_incremental_user(g_store, g_op, op_path, base, &info) ==
           QIHSE_BACKUP_EXPORT_OK);
    qihse_backup_info_free(&info);
    assert(qihse_restore_user(g_store, g_op, op_path) == QIHSE_BACKUP_EXPORT_UNSUPPORTED);
    /* And the refusal left the live dataset untouched. */
    char* v = qihse_kv_get_user(g_store, "backup:one", g_op);
    assert(v && strcmp(v, "backup-pub") == 0);
    free(v);

    unlink(op_path);
    unlink(guest_path);

    printf("PASS backup wiring: qihse_backup_incremental_user delivers the "
           "documented incremental coverage with a continuation point "
           "(no longer UNSUPPORTED), filters the guest's container, and "
           "whole-store restore still refuses a delta\n");
}

/* ── Driver ───────────────────────────────────────────────────────────── */

int main(void) {
    snprintf(g_dir, sizeof(g_dir), "build/incr_test_XXXXXX");
    assert(mkdtemp(g_dir) != NULL);
    assert(setenv("QIHSE_DATA_DIR", g_dir, 1) == 0);

    assert(qihse_auth_init());
    bool bootstrapped = qihse_auth_bootstrap_operator("IncrTestPass1!");
    if (!bootstrapped) {
        setenv("QIHSE_OPERATOR_PASSWORD", "IncrTestPass1!", 1);
        assert(qihse_auth_init());
    }
    g_op = qihse_auth_get_user(0);
    assert(g_op);
    g_guest = qihse_auth_create_user(g_op, 5210u, QIHSE_ROLE_GUEST, 0u, 0u,
                                     "IncrGuestPass1!", false);
    assert(g_guest);
    g_analyst = qihse_auth_create_user(g_op, 5211u, QIHSE_ROLE_ANALYST, 3u, 0x1u,
                                       "IncrAnalystPass1!", false);
    assert(g_analyst);

    g_store = qihse_kv_store_create();
    assert(g_store);

    test_sequence_discipline();
    test_delta_returns_exactly_mutations();
    test_resume_behavior();
    test_low_clearance_no_leak();
    test_persistence_round_trip();
    test_legacy_format_decodes();
    test_backup_incremental_wired();

    qihse_kv_store_destroy(g_store);

    char cmd[600];
    snprintf(cmd, sizeof(cmd), "rm -rf -- '%s'", g_dir);
    for (int attempt = 0; attempt < 5; attempt++) {
        if (system(cmd) == 0) break;
        usleep(200000);
    }

    printf("incremental export tests passed\n");
    return 0;
}
