/*
 * QIHSE federation ingest — implementation.
 * See include/qihse_federation_ingest.h for the contract.
 *
 * The checkpoint is a fixed-layout file written atomically (tmp+rename):
 *   magic 'QFI1' | version | cursor | stats | dedup ring | resource gates
 * The resource table is bounded (open-addressed, fixed capacity): entries
 * evicted by insertion pressure simply lose their generation gate, which
 * degrades to first-write-wins for that resource — never to a safety
 * failure, and the bound is recorded here so it is a visible tradeoff.
 */

#include "qihse_federation_ingest.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define QFI_MAGIC 0x31494651u          /* 'Q','F','I','1' */
#define QFI_VERSION 1u
#define QFI_RING_CAP QIHSE_FEDERATION_INGEST_DEDUP_RING

#pragma pack(push, 1)
typedef struct {
    uint32_t magic;
    uint32_t version;
    uint64_t cursor;
    qihse_federation_ingest_stats_t stats;
    /* dedup ring: most recent request ids, oldest first */
    uint32_t ring_count;
    qihse_uuid_t ring[QFI_RING_CAP];
    /* resource generation gates */
    uint32_t resource_count;
    struct {
        char resource_id[64];
        uint64_t generation;
    } resources[QIHSE_FEDERATION_INGEST_RESOURCES_MAX];
} qfi_checkpoint_t;
#pragma pack(pop)

struct qihse_federation_ingest {
    char path[512];
    qfi_checkpoint_t ck;
};

/* ── checkpoint IO ────────────────────────────────────────────────────── */

static bool ck_save(qihse_federation_ingest_t* ing) {
    char tmp[540];
    snprintf(tmp, sizeof(tmp), "%s.tmp", ing->path);
    FILE* f = fopen(tmp, "wb");
    if (!f) return false;
    if (fwrite(&ing->ck, sizeof(ing->ck), 1u, f) != 1u) {
        fclose(f);
        unlink(tmp);
        return false;
    }
    if (fflush(f) != 0) { fclose(f); unlink(tmp); return false; }
    int fd = fileno(f);
    if (fd >= 0) (void)fsync(fd);
    fclose(f);
    if (rename(tmp, ing->path) != 0) { unlink(tmp); return false; }
    return true;
}

static bool ck_load(qihse_federation_ingest_t* ing) {
    FILE* f = fopen(ing->path, "rb");
    if (!f) return true;                       /* fresh consumer */
    bool ok = fread(&ing->ck, sizeof(ing->ck), 1u, f) == 1u;
    fclose(f);
    return ok && ing->ck.magic == QFI_MAGIC && ing->ck.version == QFI_VERSION;
}

/* ── gates ────────────────────────────────────────────────────────────── */

static bool ring_seen(const qihse_federation_ingest_t* ing, const qihse_uuid_t* id) {
    for (uint32_t i = 0; i < ing->ck.ring_count && i < QFI_RING_CAP; i++) {
        if (qihse_uuid_equal(&ing->ck.ring[i], id)) return true;
    }
    return false;
}

static void ring_push(qihse_federation_ingest_t* ing, const qihse_uuid_t* id) {
    uint32_t cap = QFI_RING_CAP;
    if (ing->ck.ring_count < cap) {
        ing->ck.ring[ing->ck.ring_count++] = *id;
        return;
    }
    memmove(&ing->ck.ring[0], &ing->ck.ring[1], (cap - 1u) * sizeof(ing->ck.ring[0]));
    ing->ck.ring[cap - 1u] = *id;
}

/* FNV-1a over the resource id, for the open-addressed table. */
static uint32_t res_hash(const char* key) {
    uint32_t h = 2166136261u;
    for (const unsigned char* p = (const unsigned char*)key; *p; p++) {
        h ^= (uint32_t)*p;
        h *= 16777619u;
    }
    return h;
}

/* Find the gate slot for a resource: occupied-by-key, or the first empty
 * slot (claimed by the caller when inserting). */
static size_t res_slot(qfi_checkpoint_t* ck, const char* key, bool* found) {
    size_t cap = QIHSE_FEDERATION_INGEST_RESOURCES_MAX;
    size_t i = res_hash(key) & (cap - 1u);
    for (size_t probe = 0; probe < cap; probe++) {
        if (ck->resources[i].resource_id[0] == '\0') {
            *found = false;
            return i;
        }
        if (strncmp(ck->resources[i].resource_id, key,
                    sizeof(ck->resources[i].resource_id)) == 0) {
            *found = true;
            return i;
        }
        i = (i + 1u) & (cap - 1u);
    }
    *found = false;                            /* table full */
    return (size_t)-1;
}

/* ── public API ───────────────────────────────────────────────────────── */

qihse_federation_ingest_t* qihse_federation_ingest_open(const char* checkpoint_path) {
    if (!checkpoint_path || !checkpoint_path[0] ||
        strlen(checkpoint_path) >= sizeof(((qihse_federation_ingest_t*)0)->path)) {
        return NULL;
    }
    qihse_federation_ingest_t* ing =
        (qihse_federation_ingest_t*)calloc(1u, sizeof(*ing));
    if (!ing) return NULL;
    snprintf(ing->path, sizeof(ing->path), "%s", checkpoint_path);
    if (!ck_load(ing)) {
        /* Unreadable/torn checkpoint: fail closed — the consumer must
         * re-bootstrap deliberately, not silently restart from zero on a
         * file it cannot trust. */
        free(ing);
        return NULL;
    }
    if (ing->ck.magic == 0u) {                 /* fresh file never written */
        ing->ck.magic = QFI_MAGIC;
        ing->ck.version = QFI_VERSION;
    }
    return ing;
}

void qihse_federation_ingest_destroy(qihse_federation_ingest_t* ingest) {
    free(ingest);
}

bool qihse_federation_ingest_boot(qihse_federation_ingest_t* ingest,
                                  uint64_t snapshot_cursor) {
    if (!ingest) return false;
    /* boot() is only meaningful on a fresh (or reset) consumer: a consumer
     * with progress has a live cursor and re-bootstrapping would silently
     * discard its dedup ring — exactly the double-apply we exist to stop. */
    if (ingest->ck.cursor != 0u || ingest->ck.ring_count != 0u ||
        ingest->ck.stats.applied_upserts != 0u ||
        ingest->ck.stats.applied_deletes != 0u) {
        return false;
    }
    ingest->ck.cursor = snapshot_cursor;
    return ck_save(ingest);
}

bool qihse_federation_ingest_seed_generation(qihse_federation_ingest_t* ingest,
                                             const char* resource_id,
                                             uint64_t generation) {
    if (!ingest || !resource_id || !resource_id[0]) return false;
    bool found = false;
    size_t slot = res_slot(&ingest->ck, resource_id, &found);
    if (slot == (size_t)-1) return false;      /* table pressure: degrade loudly */
    if (!found) {
        snprintf(ingest->ck.resources[slot].resource_id,
                 sizeof(ingest->ck.resources[slot].resource_id), "%s",
                 resource_id);
        ingest->ck.resources[slot].generation = generation;
        ingest->ck.resource_count++;
    } else if (generation > ingest->ck.resources[slot].generation) {
        ingest->ck.resources[slot].generation = generation;
    }
    return ck_save(ingest);
}

bool qihse_federation_ingest_reset(qihse_federation_ingest_t* ingest) {
    if (!ingest) return false;
    memset(&ingest->ck, 0, sizeof(ingest->ck));
    ingest->ck.magic = QFI_MAGIC;
    ingest->ck.version = QFI_VERSION;
    return ck_save(ingest);
}

/* The run() inner loop rides replay_window through this shim. */
typedef struct {
    qihse_federation_ingest_t* ing;
    qihse_federation_ingest_apply_fn apply;
    void* user;
    uint64_t consumed;
    bool stopped;
} qfi_run_ctx_t;

static bool qfi_deliver(const qihse_federation_event_t* ev,
                        const uint8_t* payload, size_t payload_len,
                        void* ud) {
    qfi_run_ctx_t* ctx = (qfi_run_ctx_t*)ud;
    qihse_federation_ingest_t* ing = ctx->ing;

    ctx->consumed++;

    /* Gate 1 — idempotency: an event id we have already applied (snapshot
     * overlap, crash-replay) is counted and dropped before the callback. */
    if (ring_seen(ing, &ev->mutation.request_id)) {
        ing->ck.stats.skipped_duplicates++;
        return true;
    }

    /* Gate 2 — generation ordering per resource. */
    bool tombstone = qihse_federation_event_is_tombstone(ev);
    uint64_t gen = ev->mutation.expected_generation;
    size_t slot = (size_t)-1;
    bool found = false;
    if (ev->resource_id[0] != '\0') {
        slot = res_slot(&ing->ck, ev->resource_id, &found);
        if (found && gen <= ing->ck.resources[slot].generation) {
            ing->ck.stats.skipped_stale++;
            return true;
        }
    }

    /* Apply (the caller's write must be retryable — at-least-once). */
    qihse_federation_ingest_op_t op =
        tombstone ? QIHSE_INGEST_APPLY_DELETE : QIHSE_INGEST_APPLY_UPSERT;
    if (!ctx->apply(op, ev, payload, payload_len, ctx->user)) {
        ctx->stopped = true;
        return false;                          /* re-delivered next run */
    }

    /* Record: id into the ring, generation into the gate.  A tombstone
     * RESETS the gate — a later create at a lower generation is a new
     * object lifecycle, not a regression. */
    ring_push(ing, &ev->mutation.request_id);
    if (slot != (size_t)-1) {
        if (tombstone) {
            ing->ck.resources[slot].resource_id[0] = '\0';   /* free the slot */
            if (ing->ck.resource_count > 0u) ing->ck.resource_count--;
        } else {
            if (!found) {
                snprintf(ing->ck.resources[slot].resource_id,
                         sizeof(ing->ck.resources[slot].resource_id),
                         "%s", ev->resource_id);
                ing->ck.resource_count++;
            }
            ing->ck.resources[slot].generation = gen;
        }
    }
    if (tombstone) ing->ck.stats.applied_deletes++;
    else ing->ck.stats.applied_upserts++;
    return true;
}

uint64_t qihse_federation_ingest_run(qihse_federation_ingest_t* ingest,
                                     qihse_federation_journal_t* journal,
                                     uint64_t max_events,
                                     qihse_federation_ingest_apply_fn apply,
                                     void* user_data,
                                     uint64_t* out_cursor) {
    if (!ingest || !journal || !apply) return 0;
    qfi_run_ctx_t ctx = {ingest, apply, user_data, 0u, false};

    /* One event per window: replay_window advances its reported cursor
     * past a record the callback REFUSES (it books the offset before the
     * callback runs), so a refused event is only re-deliverable if we
     * persist the cursor of the last SUCCESSFUL window.  Single-event
     * windows make that exact: on refusal the checkpoint stays where the
     * last apply succeeded and the refused event leads the next run —
     * the at-least-once contract. */
    uint64_t safe = ingest->ck.cursor;
    uint64_t budget = max_events ? max_events : UINT64_MAX;
    while (ctx.consumed < budget) {
        uint64_t advanced = 0;
        uint64_t n = qihse_federation_journal_replay_window(
            journal, ingest->ck.cursor, 1u, qfi_deliver, &ctx, &advanced);
        if (n == 0) break;                       /* journal drained */
        if (ctx.stopped) break;                  /* refused: do NOT advance */
        ingest->ck.cursor = advanced;
        safe = advanced;
    }

    if (!ck_save(ingest)) return 0;
    if (out_cursor) *out_cursor = safe;
    return ctx.consumed;
}

uint64_t qihse_federation_ingest_cursor(const qihse_federation_ingest_t* ingest) {
    return ingest ? ingest->ck.cursor : 0u;
}

void qihse_federation_ingest_stats(const qihse_federation_ingest_t* ingest,
                                   qihse_federation_ingest_stats_t* out) {
    if (!out) return;
    if (!ingest) { memset(out, 0, sizeof(*out)); return; }
    *out = ingest->ck.stats;
}
