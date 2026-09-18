/*
 * gold_repl_apply_wal.c — gold workload (area: persistence-recovery).
 *
 * A KNOWN-DEFECT probe for the replication applier:
 *
 *   GOLD: KNOWN-BUG <workload-id> <check>: <detail>
 *   GOLD: OK        <workload-id> <check>: <detail>
 *
 * qihse_repl_apply_wal() is the replica-side apply entry point.  It records the
 * LSN and does nothing else ("In a real implementation, this would replay the
 * WAL into the local store"), so a replica that applies a record does not
 * change any data.  This probe:
 *
 *   1. writes a real record with the public WAL API (qihse_wal_append) into a
 *      relative scratch directory;
 *   2. reads the bytes back from the segment file and proves they are a valid,
 *      replayable record by driving qihse_wal_replay() over them (control);
 *   3. applies those exact bytes with qihse_repl_apply_wal() and checks whether
 *      a local KV store that the record targets changed.
 *
 * If the control fails the probe exits non-zero instead of reporting a defect.
 *
 * Exit status: 0 when the probe ran and reported; non-zero when the control
 * failed.
 */
#include "qihse_kv_store.h"
#include "qihse_repl.h"
#include "qihse_wal.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define GOLD_ID       "gold_repl_apply_wal"
#define GOLD_TMP_DIR  "tests/gold/.tmp"
#define GOLD_WAL_DIR  GOLD_TMP_DIR "/wal-apply-probe"
#define GOLD_KEY      "gold:wal-apply"
#define GOLD_BEFORE   "before"
#define GOLD_AFTER    "after"

typedef struct replay_seen_s {
    int records;
    int matched;
} replay_seen_t;

static bool replay_cb(const qihse_wal_record_t* record, const void* key,
                      uint32_t key_len, const void* value, uint32_t value_len,
                      void* user_data) {
    replay_seen_t* seen = (replay_seen_t*)user_data;
    seen->records++;
    if (record && key && value && key_len == strlen(GOLD_KEY) &&
        memcmp(key, GOLD_KEY, key_len) == 0 && value_len == strlen(GOLD_AFTER) &&
        memcmp(value, GOLD_AFTER, value_len) == 0) {
        seen->matched++;
    }
    return true;
}

/* Read the first (only) WAL segment into a heap buffer. */
static uint8_t* read_segment(const char* path, size_t* out_len) {
    FILE* f = fopen(path, "rb");
    if (!f) return NULL;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    long size = ftell(f);
    if (size <= 0) { fclose(f); return NULL; }
    if (fseek(f, 0, SEEK_SET) != 0) { fclose(f); return NULL; }
    uint8_t* buf = (uint8_t*)malloc((size_t)size);
    if (!buf) { fclose(f); return NULL; }
    if (fread(buf, 1, (size_t)size, f) != (size_t)size) {
        free(buf);
        fclose(f);
        return NULL;
    }
    fclose(f);
    *out_len = (size_t)size;
    return buf;
}

int main(void) {
    if (mkdir(GOLD_TMP_DIR, 0700) != 0 && errno != EEXIST) {
        fprintf(stderr, "%s: probe control failed: mkdir %s: %s\n",
                GOLD_ID, GOLD_TMP_DIR, strerror(errno));
        return 1;
    }
    if (mkdir(GOLD_WAL_DIR, 0700) != 0 && errno != EEXIST) {
        fprintf(stderr, "%s: probe control failed: mkdir %s: %s\n",
                GOLD_ID, GOLD_WAL_DIR, strerror(errno));
        return 1;
    }

    /* 1. Produce a real record with the public WAL API. */
    qihse_wal_t* wal = qihse_wal_create(GOLD_WAL_DIR, 1u << 20,
                                        QIHSE_WAL_DURABILITY_FDATASYNC);
    if (!wal) {
        fprintf(stderr, "%s: probe control failed: qihse_wal_create\n", GOLD_ID);
        return 1;
    }
    uint64_t lsn = qihse_wal_append(wal, 7u, 0u, QIHSE_WAL_OP_UPDATE,
                                    GOLD_KEY, (uint32_t)strlen(GOLD_KEY),
                                    GOLD_AFTER, (uint32_t)strlen(GOLD_AFTER));
    if (lsn == QIHSE_WAL_INVALID_LSN || qihse_wal_flush(wal) != 0) {
        fprintf(stderr, "%s: probe control failed: qihse_wal_append/flush\n",
                GOLD_ID);
        qihse_wal_destroy(wal);
        return 1;
    }
    qihse_wal_destroy(wal);

    char seg[512];
    snprintf(seg, sizeof(seg), "%s/wal_%020lu.log", GOLD_WAL_DIR, 0ul);
    size_t record_len = 0;
    uint8_t* record = read_segment(seg, &record_len);
    if (!record) {
        fprintf(stderr, "%s: probe control failed: could not read %s: %s\n",
                GOLD_ID, seg, strerror(errno));
        return 1;
    }

    /* 2. Control: the same bytes must replay as one matching record. */
    qihse_wal_t* reader = qihse_wal_create(GOLD_WAL_DIR, 1u << 20,
                                           QIHSE_WAL_DURABILITY_NONE);
    replay_seen_t seen;
    memset(&seen, 0, sizeof(seen));
    int replayed = reader ? qihse_wal_replay(reader, 0u, replay_cb, &seen) : -1;
    if (reader) qihse_wal_destroy(reader);
    if (replayed != 1 || seen.records != 1 || seen.matched != 1) {
        fprintf(stderr,
                "%s: probe control failed: the WAL record did not replay "
                "(replayed=%d records=%d matched=%d); the record bytes cannot "
                "be trusted for the apply check\n",
                GOLD_ID, replayed, seen.records, seen.matched);
        free(record);
        return 1;
    }

    /* 3. The defect check: applying the record must change the store. */
    qihse_kv_store_t* store = qihse_kv_store_create();
    if (!store || !qihse_kv_set(store, GOLD_KEY, GOLD_BEFORE, 0, 0)) {
        fprintf(stderr, "%s: probe control failed: KV store setup\n", GOLD_ID);
        free(record);
        return 1;
    }

    qihse_repl_context_t* ctx = qihse_repl_create(REPL_ROLE_REPLICA);
    if (!ctx || qihse_repl_apply_wal(ctx, record, record_len, lsn) != 0) {
        fprintf(stderr, "%s: probe control failed: qihse_repl_apply_wal "
                "refused the valid record\n", GOLD_ID);
        free(record);
        return 1;
    }

    uint64_t last_lsn = 0, flush_lsn = 0;
    repl_state_t state = REPL_STATE_ERROR;
    (void)qihse_repl_get_status(ctx, &last_lsn, &flush_lsn, &state);

    char* got = qihse_kv_get(store, GOLD_KEY);
    if (got && strcmp(got, GOLD_AFTER) == 0) {
        printf("GOLD: OK %s wal-apply-replays-record: the applied record "
               "changed the local store (%s -> %s), flush_lsn=%llu\n",
               GOLD_ID, GOLD_BEFORE, got, (unsigned long long)flush_lsn);
    } else {
        char detail[640];
        snprintf(detail, sizeof(detail),
                 "qihse_repl_apply_wal accepted a valid WAL record (lsn=%llu, "
                 "flush_lsn=%llu) but the local store still holds \"%s\": the "
                 "record was not replayed, only the LSN was recorded "
                 "(src/spinnaker/qihse_repl.c:109-118; the repl context has no "
                 "local store to replay into, include/qihse_repl.h:34-50; "
                 "docs/architecture/replication_backup.md)",
                 (unsigned long long)lsn, (unsigned long long)flush_lsn,
                 got ? got : "(null)");
        printf("GOLD: KNOWN-BUG %s wal-apply-replays-record: %s\n", GOLD_ID, detail);
    }
    free(got);

    qihse_repl_destroy(ctx);
    qihse_kv_store_destroy(store);
    free(record);
    unlink(seg);
    rmdir(GOLD_WAL_DIR);
    rmdir(GOLD_TMP_DIR);
    return 0;
}
