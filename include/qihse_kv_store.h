#ifndef QIHSE_KV_STORE_H
#define QIHSE_KV_STORE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "qihse_trinary_trie.h"
#include "qihse_auth.h"

/** Opaque handle for the QIHSE Key-Value Store. */
typedef struct qihse_kv_store qihse_kv_store_t;
typedef struct qihse_kv_replica_snapshot qihse_kv_replica_snapshot_t;

qihse_kv_store_t* qihse_kv_store_create(void);
void qihse_kv_store_destroy(qihse_kv_store_t* store);

/* Authenticated internal components may place derived projections beneath
 * the configured private store directory. The returned path is borrowed and
 * remains valid for process lifetime; callers must still use private,
 * no-follow, atomic file operations. */
const char* qihse_kv_store_data_directory(qihse_kv_store_t* store);

/*
 * Context-free writes are intentionally restricted to unclassified data.
 * Classified/SCI writes MUST use qihse_kv_set_user().
 */
bool qihse_kv_set(qihse_kv_store_t* store, const char* key, const char* value,
                  uint16_t classification, uint16_t sci_compartment);
bool qihse_kv_set_user(qihse_kv_store_t* store, const char* key, const char* value,
                       uint16_t classification, uint16_t sci_compartment,
                       qihse_user_t* user);

/* Apply one ordered record received from the configured single primary.
 * The caller must serialize this with all other store writes (normally by
 * holding the engine's kv_lock write-side).  Source sequence is preserved in
 * the record and replica WAL; equal-sequence retries are idempotent only when
 * every field and value matches.  A non-NULL active Operator principal
 * authorized for both incoming metadata and any existing key is mandatory.
 * Tombstones must have a NULL value and zero expiry. */
typedef struct {
    const char* key;
    const char* value; /* NULL iff tombstone */
    uint64_t change_seq; /* nonzero primary sequence */
    uint16_t classification;
    uint16_t sci_compartment;
    uint64_t expire_time_ms;
    bool tombstone;
} qihse_kv_replica_record_t;

bool qihse_kv_apply_replica_record(qihse_kv_store_t* store,
                                   const qihse_kv_replica_record_t* record,
                                   qihse_user_t* principal);

/* Permanently fence ordinary mutations for this process lifetime. Replica
 * records may still be applied through qihse_kv_apply_replica_record(). */
bool qihse_kv_store_enable_replica_read_only(qihse_kv_store_t* store);
void qihse_kv_store_set_replication_principal_id(qihse_kv_store_t* store,
                                                 uint32_t principal_id);

/* Immutable, private snapshot artifact for a consistent replica bootstrap.
 * The caller must exclude writers while creating it and capture
 * qihse_kv_change_seq() under the same lock. The artifact is unlinked as soon
 * as it is opened and is readable only through this handle. Full-export
 * authorization semantics apply: a principal unable to read any live row is
 * refused rather than receiving a partial baseline. */
int qihse_kv_replica_snapshot_create(qihse_kv_store_t* store, qihse_user_t* user,
                                     const char* namespace_glob,
                                     qihse_kv_replica_snapshot_t** out_snapshot);
uint64_t qihse_kv_replica_snapshot_size(const qihse_kv_replica_snapshot_t* snapshot);
bool qihse_kv_replica_snapshot_read(qihse_kv_replica_snapshot_t* snapshot,
                                    uint64_t offset, void* out, size_t capacity,
                                    size_t* out_read);
void qihse_kv_replica_snapshot_destroy(qihse_kv_replica_snapshot_t* snapshot);
bool qihse_kv_replica_snapshot_installed(qihse_kv_store_t* store,
                                         const char* peer_id,
                                         const char* namespace_glob,
                                         qihse_user_t* principal,
                                         bool* out_installed);
bool qihse_kv_replica_snapshot_install(qihse_kv_store_t* store,
                                       const char* filepath,
                                       qihse_user_t* principal,
                                       const char* peer_id,
                                       const char* namespace_glob,
                                       uint64_t source_highwater);

/* Durable receiver progress, scoped to this store's data directory and keyed
 * by authenticated peer plus namespace. Caller must serialize with store
 * writes (normally engine kv_lock write-side). Only active Operators may
 * inspect/update cursors. Advance is monotonic; success means the replacement
 * cursor file and its directory entry were fsynced before return/ACK. */
bool qihse_kv_replica_cursor_get(qihse_kv_store_t* store, const char* peer_id,
                                const char* namespace_id, qihse_user_t* principal,
                                uint64_t* out_seq);
bool qihse_kv_replica_cursor_advance(qihse_kv_store_t* store, const char* peer_id,
                                    const char* namespace_id, uint64_t seq,
                                    qihse_user_t* principal);

char* qihse_kv_get_user(qihse_kv_store_t* store, const char* key, qihse_user_t* user);

/* Authorization-aware single-key compare-and-set. expected_value == NULL
 * means the key must be absent. The comparison and replacement occur under
 * one store write lock; inaccessible existing records return FAILED rather
 * than revealing whether they exist. */
typedef enum {
    QIHSE_KV_CAS_FAILED = 0,
    QIHSE_KV_CAS_UPDATED = 1,
    QIHSE_KV_CAS_MISMATCH = 2
} qihse_kv_cas_result_t;
qihse_kv_cas_result_t qihse_kv_compare_set_user(
    qihse_kv_store_t* store, const char* key, const char* expected_value,
    const char* new_value, uint16_t classification, uint16_t sci_compartment,
    qihse_user_t* user);

/* Metadata-only lookup (W7 introspection): reports a live record's
 * classification, SCI compartment, expiry and WAL flags WITHOUT ever
 * returning the value.  The authorization gate is IDENTICAL to
 * qihse_kv_get_user — a principal that could not read the record cannot
 * read its metadata either (a record's classification is itself
 * classified-adjacent information).  Returns false for miss, expired, or
 * not-cleared, which are deliberately indistinguishable. */
typedef struct {
    uint16_t classification;
    uint16_t sci_compartment;
    uint64_t expire_time_ms;   /* 0 = no expiry */
    uint64_t change_seq;       /* immutable local mutation LSN */
    uint8_t  flags;            /* WAL record flags (tombstone bit etc.) */
} qihse_kv_record_meta_t;

bool qihse_kv_meta_user(qihse_kv_store_t* store, const char* key,
                        qihse_user_t* user, qihse_kv_record_meta_t* out);

/* Authenticated mutations with the exact local WAL LSN assigned to the
 * resulting live record/tombstone. The LSN is stable across QKV4 recovery. */
bool qihse_kv_set_user_with_seq(qihse_kv_store_t* store, const char* key,
                                const char* value, uint16_t classification,
                                uint16_t sci_compartment, qihse_user_t* user,
                                uint64_t* out_change_seq);
bool qihse_kv_del_user_with_seq(qihse_kv_store_t* store, const char* key,
                                qihse_user_t* user, uint64_t* out_change_seq);
/* Read the sequence only for an authorized live record or tombstone. Expired
 * live rows and misses are indistinguishable from denied rows. */
bool qihse_kv_change_seq_user(qihse_kv_store_t* store, const char* key,
                              qihse_user_t* user, uint64_t* out_change_seq,
                              bool* out_tombstone);
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
typedef bool (*qihse_kv_key_iter_cb)(const char* key, void* user_data);

/* Authorization-aware enumeration. Returns false on compaction/storage failure. */
bool qihse_kv_foreach_user(qihse_kv_store_t* store, qihse_user_t* user,
                           qihse_kv_iter_cb cb, void* user_data);
/* Filter keys before authorization and callback.  A NULL principal may see
 * only unclassified rows under the same access gate as foreach_user.  This
 * uses the SST metadata index for matching records' disk offsets, avoiding
 * unrelated SST value reads. It still scans in-memory keys/index metadata. */
bool qihse_kv_foreach_prefix_user(qihse_kv_store_t* store, const char* prefix,
                                  qihse_user_t* user, qihse_kv_iter_cb cb,
                                  void* user_data);
/* Authorization-aware key-only iteration. Does not read SSTable values. The
 * callback runs under the store read lock and must not mutate this store. */
bool qihse_kv_foreach_key_user(qihse_kv_store_t* store, qihse_user_t* user,
                               qihse_kv_key_iter_cb cb, void* user_data);
void qihse_kv_foreach(qihse_kv_store_t* store, qihse_kv_iter_cb cb, void* user_data);

/* Metadata-carrying enumeration.  The classification and SCI are read from
 * the SAME record read that produced value, so a projection that copies them
 * onto derived state (an inverted index, a cache) cannot pick up a newer ACL
 * than the bytes it copied.  A per-key qihse_kv_meta_user() lookup would open
 * exactly that race.  Same authorization gate as qihse_kv_foreach_user. */
typedef bool (*qihse_kv_iter_meta_cb)(const char* key, const char* value,
                                      uint16_t classification,
                                      uint16_t sci_compartment,
                                      void* user_data);
bool qihse_kv_foreach_meta_user(qihse_kv_store_t* store, qihse_user_t* user,
                                qihse_kv_iter_meta_cb cb, void* user_data);

/* Enumerate only records both visible to a live actor and within an explicit
 * delegated label. The label filter runs before any callback sees a value. */
bool qihse_kv_foreach_meta_bounded_user(qihse_kv_store_t* store,
    qihse_user_t* actor, uint16_t max_classification, uint16_t allowed_sci,
    qihse_kv_iter_meta_cb cb, void* user_data);

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

/* Store-local invalidation marker for derived projections. Starts at 1 on
 * creation and advances after a successful restore or SSTable compaction.
 * A changed marker requires a full authorized reconciliation: delta export
 * may no longer contain removed keys. This is NOT persistent across store
 * instances; always rebaseline on startup regardless of its value. Sample
 * before and after a reconciliation/delta pass and discard work if changed.
 * Like change_seq, this is a store progress metric, not a data read. */
uint64_t qihse_kv_projection_epoch(qihse_kv_store_t* store);
/* Random instance identity; never persisted or reused to authorize old projections. */
uint64_t qihse_kv_instance_id(qihse_kv_store_t* store);

/* Read both projection source markers under the store read lock. Unlike two
 * independent atomic loads, this cannot observe a sequence issued by an
 * in-flight writer before its trie mutation completes. Capture before and
 * after an authorized full snapshot/delta pass; publish only if both pairs
 * match. A caller still MUST rebaseline after restart (epoch is process-local)
 * and recheck authorization and canonical content when serving candidates. */
bool qihse_kv_projection_marker(qihse_kv_store_t* store,
                                uint64_t* out_seq, uint64_t* out_epoch);

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
/* Bounded namespace form used by the replication wire handler. Retains only
 * the earliest records that fit both limits; temporary record storage is
 * bounded by max_bytes plus one candidate record. Returns -1 and zeroed
 * outputs if any authorized matching record exceeds max_bytes (the caller
 * must increase the bound or rebaseline, never advance past that record). */
int qihse_kv_export_incremental_user_bounded(qihse_kv_store_t* store,
                                     qihse_user_t* user, const char* namespace_glob,
                                     uint64_t since_seq, size_t max_records,
                                     size_t max_bytes,
                                     qihse_kv_delta_record_t** out_records,
                                     size_t* out_count, uint64_t* out_resume_seq);
/* Identical bounded export with a completeness signal for projection workers.
 * out_complete is false on failure or if ANY authorized matching row did not
 * fit either bound. A false value on success requires continuation with the
 * returned principal-visible resume cursor; do not publish this as a fully
 * reconciled source boundary. It is true even for a successful empty delta. */
int qihse_kv_export_incremental_user_bounded_complete(qihse_kv_store_t* store,
    qihse_user_t* user, const char* namespace_glob, uint64_t since_seq,
    size_t max_records, size_t max_bytes,
    qihse_kv_delta_record_t** out_records, size_t* out_count,
    uint64_t* out_resume_seq, bool* out_complete);

/* File form of the same delta: the store's text record stream (v4 headers,
 * sequences and tombstones included), written atomically like
 * qihse_kv_save_user.  Same authorization-filtering semantics and resume
 * point as qihse_kv_export_incremental_user; same return convention as
 * qihse_kv_save_user (0, -1 error). */
int qihse_kv_save_delta_user(qihse_kv_store_t* store, const char* filepath,
                             qihse_user_t* user, uint64_t since_seq,
                             uint64_t* out_resume_seq);

#endif /* QIHSE_KV_STORE_H */
