#ifndef QIHSE_KV_STORE_H
#define QIHSE_KV_STORE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "qihse_trinary_trie.h"
#include "qihse_auth.h"

/** Opaque handle for the QIHSE Key-Value Store. */
typedef struct qihse_kv_store qihse_kv_store_t;

qihse_kv_store_t* qihse_kv_store_create(void);
void qihse_kv_store_destroy(qihse_kv_store_t* store);

/*
 * Context-free writes are intentionally restricted to unclassified data.
 * Classified/SCI writes MUST use qihse_kv_set_user().
 */
bool qihse_kv_set(qihse_kv_store_t* store, const char* key, const char* value,
                  uint16_t classification, uint16_t sci_compartment);
bool qihse_kv_set_user(qihse_kv_store_t* store, const char* key, const char* value,
                       uint16_t classification, uint16_t sci_compartment,
                       qihse_user_t* user);

char* qihse_kv_get_user(qihse_kv_store_t* store, const char* key, qihse_user_t* user);
static inline char* qihse_kv_get(qihse_kv_store_t* store, const char* key) {
    return qihse_kv_get_user(store, key, NULL);
}

bool qihse_kv_del_user(qihse_kv_store_t* store, const char* key, qihse_user_t* user);
static inline bool qihse_kv_del(qihse_kv_store_t* store, const char* key) {
    return qihse_kv_del_user(store, key, NULL);
}

bool qihse_kv_exists_user(qihse_kv_store_t* store, const char* key, qihse_user_t* user);
static inline bool qihse_kv_exists(qihse_kv_store_t* store, const char* key) {
    return qihse_kv_exists_user(store, key, NULL);
}

bool qihse_kv_expire(qihse_kv_store_t* store, const char* key, uint64_t ttl_ms,
                     qihse_user_t* user);
int64_t qihse_kv_ttl_ms_user(qihse_kv_store_t* store, const char* key, qihse_user_t* user);
void qihse_kv_sweep_expired(qihse_kv_store_t* store);

bool qihse_kv_store_is_under_attack(qihse_kv_store_t* store);

/*
 * Persistence is authorization-aware. *_user variants deny the whole export/import
 * if any live record is outside the caller's clearance/SCI. Legacy variants run
 * as NULL/unclassified and therefore cannot export/import classified records.
 */
int qihse_kv_save_user(qihse_kv_store_t* store, const char* filepath, qihse_user_t* user);
int qihse_kv_load_user(qihse_kv_store_t* store, const char* filepath, qihse_user_t* user);
int qihse_kv_save(qihse_kv_store_t* store, const char* filepath);
int qihse_kv_load(qihse_kv_store_t* store, const char* filepath);

/* Bulk-load mode disables WAL buffering/automatic flush only; authorization rules remain. */
void qihse_kv_bulk_load_begin(qihse_kv_store_t* store);
void qihse_kv_bulk_load_end(qihse_kv_store_t* store);

typedef bool (*qihse_kv_iter_cb)(const char* key, const char* value, void* user_data);

/* Authorization-aware enumeration. Returns false on compaction/storage failure. */
bool qihse_kv_foreach_user(qihse_kv_store_t* store, qihse_user_t* user,
                           qihse_kv_iter_cb cb, void* user_data);
void qihse_kv_foreach(qihse_kv_store_t* store, qihse_kv_iter_cb cb, void* user_data);

size_t qihse_kv_clear_user(qihse_kv_store_t* store, qihse_user_t* user);
size_t qihse_kv_clear(qihse_kv_store_t* store);

size_t qihse_kv_count_user(qihse_kv_store_t* store, qihse_user_t* user);
size_t qihse_kv_count(qihse_kv_store_t* store);

/* Operator-triggered durability (RESP SAVE / BGSAVE):
 *   1. fsync the WAL (stdio buffer out, then the fd itself),
 *   2. flush the memtable into a new SSTable (atomic rename, file fsynced)
 *      and rotate the WAL empty -- skipped when the memtable is empty,
 *   3. fsync the data directory so the renames survive power loss.
 * Returns true on full success. NOT internally serialized: the caller must
 * hold the engine kv_lock write-side across the call (the RESP surface
 * does), so concurrent readers/writers are excluded for its duration. */
bool qihse_kv_sync_store(qihse_kv_store_t* store);

/* ── Change sequence and incremental (delta) export ──────────────────────
 *
 * Every authorized mutation (set with classification/SCI, delete, expiry
 * update, sweep tombstone) advances ONE store-global 64-bit monotonic
 * counter and is stamped with the sequence it received, on the record's
 * metadata, persisted with the record format: the text record header line
 * is versioned by FIELD COUNT ("key_len val_len expire classif sci [flags
 * [seq]]"), so a record written before sequences existed decodes with the
 * defined value 0 and every older snapshot, SSTable and fixture stays
 * readable.  Reads never advance the sequence; failed or unauthorized
 * mutations never advance it and never receive one; compaction preserves
 * stamped sequences; a load/restore preserves them and only ever RAISES the
 * high-water to the loaded file's maximum (it never re-stamps and never
 * regresses).  Crash recovery replays the WAL (whose binary format is
 * unchanged for compatibility) and re-stamps each replayed mutation with a
 * fresh sequence — order-preserving and monotonic.
 *
 * Records with sequence 0 (they predate the sequence, from pre-sequence
 * files) are never part of a delta: "seq > since" with since >= 0 excludes
 * them.  Bootstrap with a full export (which carries them), then track
 * deltas. */

/* The store's high-water sequence: the last sequence issued to an
 * authorized mutation (0 for a fresh store or NULL store).
 *
 * This is a store progress metric, not a classified read: it discloses no
 * key, value or classification.  But it DOES move when hidden mutations
 * occur, which is exactly why it is NOT what a restricted principal's delta
 * resumes from — use the delta export's resume point below, which only
 * advances on what the principal was allowed to see. */
uint64_t qihse_kv_change_seq(qihse_kv_store_t* store);

/* One delta record: the principal-visible state of one key whose last
 * mutation carries a sequence above the caller's cursor.  A tombstone
 * carries the deletion (value is NULL, tombstone true) at the deleted
 * record's classification/SCI — the deletion is as protected as the record
 * it removed. */
typedef struct {
    char* key;
    char* value;              /* NULL iff tombstone */
    uint64_t change_seq;
    uint16_t classification;
    uint16_t sci_compartment;
    uint64_t expire_time_ms;
    bool tombstone;
} qihse_kv_delta_record_t;

void qihse_kv_delta_records_free(qihse_kv_delta_record_t* records, size_t count);

/* Export the delta since `since_seq`: every record whose stamped sequence
 * is STRICTLY greater than `since_seq`, in ascending sequence order,
 * enumerated through the same authorization-aware iteration as the full
 * export (each record checked with qihse_auth_can_access at THIS, the
 * lowest data-retrieval layer — AGENTS.md invariant 1).  A NULL user keeps
 * this layer's family convention: the deliberately unclassified-only view
 * (never a bypass); higher layers that must refuse NULL add their own gate.
 *
 * *out_resume_seq is the continuation point for the next call.
 *
 * METADATA-DISCLOSURE DECISION (default and ONLY form — there is no
 * opt-in alternative): the resume point is the highest sequence among the
 * records THIS principal was ALLOWED to see, never the store-global
 * high-water.  Mutations the principal may not see are filtered out before
 * the resume point is computed, so they are never enumerated, and comparing
 * successive resume points cannot reveal how many hidden mutations
 * occurred: the resume point simply does not move until the principal is
 * allowed to see something newer.  The cost is that records between the
 * resume point and the global high-water are re-scanned (a sequence compare
 * during iteration) and skipped on every export.  A "global high-water with
 * gaps visible" form would disclose the count of hidden mutations and is
 * therefore not provided.
 *
 * If the caller's view produced no records, the resume point equals
 * `since_seq` unchanged.  A delta holds each key's LATEST state (an
 * intermediate overwrite is superseded, last-writer-wins).
 *
 * Known boundary: a tombstone can be physically dropped by compaction
 * (qihse_kv_sweep_expired / clear) after the delta that carried it was
 * consumed; a deletion whose tombstone is compacted away before any export
 * saw it is not re-deliverable — consumers that must not miss deletes
 * should take deltas before compaction GC or re-baseline with a full
 * export.  Similarly, a caller holding a cursor from BEFORE a
 * qihse_kv_load_user() restore should re-baseline: the restore is not a
 * mutation and does not re-stamp the restored records.
 *
 * Returns 0 on success; -1 on iteration/allocation failure (outputs zeroed,
 * nothing partially returned); this form filters rather than refusing
 * whole — a partial-by-clearance delta IS the delta contract. */
int qihse_kv_export_incremental_user(qihse_kv_store_t* store, qihse_user_t* user,
                                     uint64_t since_seq,
                                     qihse_kv_delta_record_t** out_records,
                                     size_t* out_count, uint64_t* out_resume_seq);

/* File form of the same delta: the store's text record stream (v4 headers,
 * sequences and tombstones included), written atomically like
 * qihse_kv_save_user.  Same authorization-filtering semantics and resume
 * point as qihse_kv_export_incremental_user; same return convention as
 * qihse_kv_save_user (0, -1 error). */
int qihse_kv_save_delta_user(qihse_kv_store_t* store, const char* filepath,
                             qihse_user_t* user, uint64_t since_seq,
                             uint64_t* out_resume_seq);

#endif /* QIHSE_KV_STORE_H */
