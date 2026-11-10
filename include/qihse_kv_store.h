#ifndef QIHSE_KV_STORE_H
#define QIHSE_KV_STORE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include "qihse_trinary_trie.h"
#include "qihse_auth.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Opaque handle for the QIHSE Key-Value Store. */
typedef struct qihse_kv_store qihse_kv_store_t;
typedef struct qihse_kv_replica_snapshot qihse_kv_replica_snapshot_t;
typedef struct qihse_kv_ct_range_snapshot qihse_kv_ct_range_snapshot_t;

/* CT storage protocol. IDs are stable, printable 1..64-byte configuration
 * identifiers. The 32-byte owner capability is generated or supplied at
 * initialization, persisted, and retrievable only by an active Operator for
 * internal control-plane setup. CT mode is opt-in and persisted. */
#define QIHSE_KV_CT_ID_MAX 64u
#define QIHSE_KV_CT_TOKEN_BYTES 32u
#define QIHSE_KV_CT_MAX_GROUP_RECORDS 4096u
typedef struct qihse_kv_ct_writer_scope qihse_kv_ct_writer_scope_t;
typedef struct qihse_kv_ct_proof qihse_kv_ct_proof_t;

typedef enum {
    QIHSE_KV_CT_ACTOR_USER = 1,
    QIHSE_KV_CT_ACTOR_EXPIRY = 2,
    QIHSE_KV_CT_ACTOR_REPLICA = 3
} qihse_kv_ct_actor_t;
typedef enum {
    QIHSE_KV_CT_TENANT_EXACT = 1,
    QIHSE_KV_CT_TENANT_SYSTEM_ALL = 2
} qihse_kv_ct_tenant_policy_t;

typedef struct {
    char* key;
    char* value; /* NULL for tombstone */
    uint64_t change_seq;
    uint64_t expire_time_ms;
    uint32_t actor_id;
    uint32_t actor_tenant_id;
    uint32_t resource_tenant_id;
    uint16_t classification;
    uint16_t sci_compartment;
    qihse_kv_ct_actor_t actor_kind;
    bool tombstone;
} qihse_kv_ct_record_t;

typedef struct {
    char source_id[QIHSE_KV_CT_ID_MAX + 1u];
    char generation[QIHSE_KV_CT_ID_MAX + 1u];
    uint64_t stream_position; /* dense committed group ordinal */
    uint64_t first_seq;
    uint64_t last_seq;
    qihse_kv_ct_record_t* records;
    size_t count;
} qihse_kv_ct_group_t;

typedef struct {
    char source_id[QIHSE_KV_CT_ID_MAX + 1u];
    char generation[QIHSE_KV_CT_ID_MAX + 1u];
    char successor_id[QIHSE_KV_CT_ID_MAX + 1u];
    uint64_t durable_lsn; /* dense group position, not row change_seq */
    uint64_t oldest_lsn;
    uint64_t acknowledged_lsn;
    uint64_t retained_bytes;
    uint64_t limit_bytes;
    uint64_t baseline_row_seq;
    unsigned char baseline_digest[32];
    bool admitted; /* source reconciled with its pinned successor this process */
} qihse_kv_ct_source_status_t;

typedef struct {
    char source_id[QIHSE_KV_CT_ID_MAX + 1u];
    char generation[QIHSE_KV_CT_ID_MAX + 1u];
    uint64_t durable_cursor; /* dense group position */
    uint32_t tenant_id;
    qihse_kv_ct_tenant_policy_t tenant_policy;
    bool baseline_sealed;
    unsigned char baseline_digest[32];
} qihse_kv_ct_receiver_status_t;

/* A thread-bound writer scope lets existing KV mutators called by RESP use
 * the persisted CT owner capability. It is tied to this store and principal;
 * direct calls outside the scope fail closed. The caller must leave on every
 * path before returning to a pooled thread. */
bool qihse_kv_ct_writer_scope_enter(qihse_kv_store_t* store,
    qihse_user_t* principal, const unsigned char owner_token[QIHSE_KV_CT_TOKEN_BYTES],
    qihse_kv_ct_writer_scope_t** out_scope);
void qihse_kv_ct_writer_scope_leave(qihse_kv_ct_writer_scope_t* scope);
/* Call only after releasing any outer server KV lock. Waits for the durable
 * successor ACK covering every mutation issued in this scope, then leaves
 * the scope. False means the write outcome is unresolved for the caller. */
bool qihse_kv_ct_writer_scope_finish(qihse_kv_ct_writer_scope_t* scope,
    uint32_t timeout_ms, uint64_t* out_last_seq);
bool qihse_kv_ct_owner_token_get(qihse_kv_store_t* store,
    qihse_user_t* principal, unsigned char out[QIHSE_KV_CT_TOKEN_BYTES]);

/* Source capture and exact bounded ordered history. A successful read never
 * coalesces intermediate overwrites. The active principal is checked at the
 * lowest read layer before any protected body allocation. */
bool qihse_kv_ct_source_enable(qihse_kv_store_t* store, qihse_user_t* principal,
    const char* source_id, const char* successor_id, const char* generation,
    const unsigned char owner_token[QIHSE_KV_CT_TOKEN_BYTES],
    uint64_t max_retained_bytes);
bool qihse_kv_ct_source_status(qihse_kv_store_t* store,
    qihse_user_t* principal, qihse_kv_ct_source_status_t* out);
int qihse_kv_ct_source_baseline_snapshot_create(qihse_kv_store_t* store,
    qihse_user_t* principal, qihse_kv_replica_snapshot_t** out_snapshot,
    uint64_t* out_baseline_row_seq, unsigned char out_digest[32]);
bool qihse_kv_ct_source_read(qihse_kv_store_t* store, qihse_user_t* principal,
    const char* generation, uint64_t after_seq, size_t max_groups,
    size_t max_bytes, qihse_kv_ct_group_t** out_groups, size_t* out_count,
    uint64_t* out_resume_seq);
void qihse_kv_ct_groups_free(qihse_kv_ct_group_t* groups, size_t count);
bool qihse_kv_ct_source_ack(qihse_kv_store_t* store, qihse_user_t* principal,
    const char* peer_id, const char* generation, uint64_t durable_lsn);
/* Called only after pinned QKP peer STATUS. Re-arms a reopened or timed-out
 * source when successor cursor covers every locally durable group. */
bool qihse_kv_ct_source_reconcile(qihse_kv_store_t* store,
    qihse_user_t* principal, const char* peer_id, const char* generation,
    const unsigned char receiver_baseline_digest[32],
    uint64_t peer_durable_position);

/* Runtime-only admission after authenticated, exact pinned QKP STATUS.
 * Local Operator control identity is not accepted from the wire. The separate
 * replication principal must match this store's configured service identity. */
bool qihse_kv_ct_source_reconcile_peer(qihse_kv_store_t* store,
    qihse_user_t* local_operator, qihse_user_t* replication_principal,
    const char* peer_id, const char* generation,
    const unsigned char receiver_baseline_digest[32],
    uint64_t peer_durable_position);

/* Receiver writes row group and cursor in one recoverable WAL transaction.
 * An identical retry succeeds; gaps, conflicting duplicates, stale generation,
 * unauthorized labels or tenant mismatch fail without advancing the cursor. */
bool qihse_kv_ct_receiver_bind(qihse_kv_store_t* store, qihse_user_t* principal,
    const char* source_id, const char* target_id, const char* generation,
    qihse_kv_ct_tenant_policy_t tenant_policy, uint32_t tenant_id,
    uint64_t baseline_lsn,
    const unsigned char owner_token[QIHSE_KV_CT_TOKEN_BYTES]);
bool qihse_kv_ct_receiver_install_baseline(qihse_kv_store_t* store,
    qihse_user_t* principal, qihse_user_t* data_principal,
    const char* source_id, const char* generation,
    const char* filepath, uint64_t baseline_row_seq,
    const unsigned char expected_digest[32],
    const unsigned char owner_token[QIHSE_KV_CT_TOKEN_BYTES]);
bool qihse_kv_ct_receiver_apply(qihse_kv_store_t* store, qihse_user_t* principal,
    const qihse_kv_ct_group_t* group, uint64_t* out_durable_cursor);
bool qihse_kv_ct_receiver_status(qihse_kv_store_t* store,
    qihse_user_t* principal, qihse_kv_ct_receiver_status_t* out);

/* Store-level durable fences and locally minted, opaque ownership evidence.
 * QKP peer pinning remains a transport responsibility. A proof is only valid
 * against the same live store and its current persisted generation/cursor. */
bool qihse_kv_ct_fence_range(qihse_kv_store_t* store, qihse_user_t* principal,
    const char* transfer_id, uint16_t first_slot, uint16_t last_slot,
    const unsigned char owner_token[QIHSE_KV_CT_TOKEN_BYTES],
    uint64_t* out_cut_position);
/* Read-only durable fence identity for journal recovery. An ABORTED journal
 * record may answer only after the matching source fence is absent/released. */
typedef struct {
    uint32_t mode, fence_state, transfer_phase;
    uint16_t first_slot, last_slot;
    uint64_t cut_position;
    char transfer_id[QIHSE_KV_CT_ID_MAX + 1u];
    char source_id[QIHSE_KV_CT_ID_MAX + 1u];
    char target_id[QIHSE_KV_CT_ID_MAX + 1u];
    char generation[QIHSE_KV_CT_ID_MAX + 1u];
} qihse_kv_ct_transfer_status_t;
bool qihse_kv_ct_transfer_status(qihse_kv_store_t* store,
    qihse_user_t* control_principal, qihse_kv_ct_transfer_status_t* out);
typedef struct {
    qihse_kv_ct_transfer_status_t base;
    char transfer_source_id[QIHSE_KV_CT_ID_MAX + 1u];
    char transfer_source_generation[QIHSE_KV_CT_ID_MAX + 1u];
    uint64_t transfer_source_cut;
} qihse_kv_ct_transfer_status_detail_t;
bool qihse_kv_ct_transfer_status_detail(qihse_kv_store_t* store,
    qihse_user_t* control_principal,
    qihse_kv_ct_transfer_status_detail_t* out);
bool qihse_kv_ct_fence_finish(qihse_kv_store_t* store, qihse_user_t* principal,
    const char* transfer_id, bool transferred,
    const unsigned char owner_token[QIHSE_KV_CT_TOKEN_BYTES]);
typedef struct {
    char transfer_id[QIHSE_KV_CT_ID_MAX + 1u];
    char source_id[QIHSE_KV_CT_ID_MAX + 1u];
    char target_id[QIHSE_KV_CT_ID_MAX + 1u];
    char generation[QIHSE_KV_CT_ID_MAX + 1u];
    uint16_t first_slot, last_slot;
    uint64_t source_cut, target_durable_cursor;
    unsigned char range_checksum[32];
} qihse_kv_ct_target_receipt_claim_t;
/* Callback must verify the claim against the pinned authenticated QKP peer's
 * signed durable target receipt; it is called outside the KV lock. */
typedef bool (*qihse_kv_ct_receipt_verify_fn)(
    const qihse_kv_ct_target_receipt_claim_t* claim, void* context);
/* Prepare an incoming transfer on an existing CT1 primary, including a
 * range it previously moved away. The callback verifies a distinct pinned
 * source PREPARED receipt before this store persists the target fence. */
bool qihse_kv_ct_target_prepare(qihse_kv_store_t* store,
    qihse_user_t* principal,
    const qihse_kv_ct_target_receipt_claim_t* source_prepared_claim,
    qihse_kv_ct_receipt_verify_fn verify_source_prepared,
    void* verify_context,
    const unsigned char owner_token[QIHSE_KV_CT_TOKEN_BYTES],
    uint64_t* out_local_cut);
/* Abort a target PREPARED fence only with an authenticated, exact source
 * ABORTED receipt. Once an import group has started, abort stays unresolved
 * and the range remains frozen for recovery. */
bool qihse_kv_ct_target_abort(qihse_kv_store_t* store,
    qihse_user_t* principal,
    const qihse_kv_ct_target_receipt_claim_t* source_aborted_claim,
    qihse_kv_ct_receipt_verify_fn verify_source_aborted,
    void* verify_context,
    const unsigned char owner_token[QIHSE_KV_CT_TOKEN_BYTES]);
bool qihse_kv_ct_source_fence_commit(qihse_kv_store_t* store,
    qihse_user_t* principal, const qihse_kv_ct_proof_t* source_proof,
    const qihse_kv_ct_target_receipt_claim_t* target_claim,
    qihse_kv_ct_receipt_verify_fn verify_receipt, void* verify_context,
    const unsigned char owner_token[QIHSE_KV_CT_TOKEN_BYTES]);
/* Activate an imported target range only after an authenticated source commit
 * receipt. The callback verifies a distinct source COMMITTED phase, never a
 * target SEALED receipt. Exact retries are idempotent after durable activation. */
bool qihse_kv_ct_target_activate(qihse_kv_store_t* store,
    qihse_user_t* principal, const qihse_kv_ct_proof_t* target_seal,
    const qihse_kv_ct_target_receipt_claim_t* source_commit_claim,
    qihse_kv_ct_receipt_verify_fn verify_source_commit, void* verify_context,
    const unsigned char owner_token[QIHSE_KV_CT_TOKEN_BYTES]);
/* CT2 range snapshot is file-backed and not capped by the per-frame group
 * limits. Its practical bounds are addressable file size and available disk.
 * The source must already hold the matching durable range fence. */
int qihse_kv_ct_range_export(qihse_kv_store_t* store,
    qihse_user_t* control_principal, qihse_user_t* data_principal,
    const char* transfer_id, const char* target_id, const char* generation,
    uint16_t first_slot, uint16_t last_slot,
    const unsigned char owner_token[QIHSE_KV_CT_TOKEN_BYTES],
    qihse_kv_ct_range_snapshot_t** out_snapshot, uint64_t* out_source_cut,
    unsigned char out_sha256[32]);
bool qihse_kv_ct_range_snapshot_size(qihse_kv_ct_range_snapshot_t* snapshot,
    qihse_user_t* principal, uint64_t* out_size);
bool qihse_kv_ct_range_snapshot_read(qihse_kv_ct_range_snapshot_t* snapshot,
    qihse_user_t* principal, uint64_t offset, void* buffer, size_t capacity,
    size_t* out_read);
void qihse_kv_ct_range_snapshot_destroy(qihse_kv_ct_range_snapshot_t* snapshot);
/* Target remains a CT1 source for its own successor. Import merges the
 * source range into bounded, ordered QKV6 groups, including tombstones for
 * target-only keys. The durable transfer phase hides ownership until every
 * group is applied and the final receipt is published.
 * Source change_seq in the image is transfer provenance; imported mutations
 * receive target-local change_seq and ACTOR_REPLICA with the authenticated
 * transfer principal. Original historical actor identity is unavailable in
 * QFS and is not inferred.
 * The caller waits for target successor ACK before requesting a target seal. */
bool qihse_kv_ct_range_import(qihse_kv_store_t* store, qihse_user_t* principal,
    qihse_user_t* data_principal, const char* transfer_id, const char* source_id,
    const char* source_generation, uint16_t first_slot, uint16_t last_slot,
    uint64_t source_cut, const char* snapshot_filepath,
    const unsigned char expected_sha256[32],
    const unsigned char owner_token[QIHSE_KV_CT_TOKEN_BYTES],
    uint64_t* out_target_position);
qihse_kv_ct_proof_t* qihse_kv_ct_promotion_proof_create(
    qihse_kv_store_t* store, qihse_user_t* principal, const char* source_id,
    const char* target_id, const char* generation, uint64_t handoff_lsn);
/* Persistently seal receiver generation and promote it to source. The old
 * source generation must never be rebound after this transition. */
bool qihse_kv_ct_receiver_promote(qihse_kv_store_t* store,
    qihse_user_t* principal, const qihse_kv_ct_proof_t* proof,
    const char* new_generation, const char* new_successor_id,
    const unsigned char owner_token[QIHSE_KV_CT_TOKEN_BYTES]);
qihse_kv_ct_proof_t* qihse_kv_ct_target_seal_create(
    qihse_kv_store_t* store, qihse_user_t* principal,
    qihse_user_t* data_principal, const char* transfer_id,
    const char* source_id, const char* target_id, const char* generation,
    uint16_t first_slot, uint16_t last_slot, uint64_t source_lsn);
qihse_kv_ct_proof_t* qihse_kv_ct_source_transfer_proof_create(
    qihse_kv_store_t* store, qihse_user_t* principal,
    qihse_user_t* data_principal, const char* transfer_id,
    const char* source_id, const char* target_id, const char* generation,
    uint16_t first_slot, uint16_t last_slot, uint64_t source_lsn);
bool qihse_kv_ct_proof_fields(qihse_kv_store_t* store,
    qihse_user_t* principal, qihse_user_t* data_principal,
    const qihse_kv_ct_proof_t* proof,
    const char** out_transfer_id, const char** out_source_id,
    const char** out_target_id, const char** out_generation,
    uint16_t* out_first_slot, uint16_t* out_last_slot,
    uint64_t* out_source_lsn, uint64_t* out_target_lsn,
    unsigned char out_checksum[32]);
bool qihse_kv_ct_proof_validate(qihse_kv_store_t* store,
    qihse_user_t* principal, qihse_user_t* data_principal,
    const qihse_kv_ct_proof_t* proof);
void qihse_kv_ct_proof_destroy(qihse_kv_ct_proof_t* proof);

/* Context-free open refuses an unfinished full-image publication. Recovery
 * requires an active principal authorized for every record in the intent's
 * image; no replacement data is published on an authorization refusal. */
/* Authenticated whole-store open: requires a non-NULL active principal able
 * to read every persisted SST/WAL record, including tombstones/expired rows.
 * Authorization failure rejects the open, never filters data or repairs WAL.
 * Pending-image recovery additionally requires this explicit principal. */
qihse_kv_store_t* qihse_kv_store_create_user(qihse_user_t* user);
/* Open a bounded immutable in-memory snapshot from the current FILE position.
 * Does not close stream or read/write the configured data directory. Every
 * encoded label (including expired/tombstoned records) is authorized before
 * its payload is read. NULL/inactive principal, malformed/duplicate records
 * and I/O failure return NULL without publishing a partial store. Metadata,
 * expiry, flags and sequence numbers are retained. Ordinary writes, restore,
 * sync and replica mutations are rejected on the returned handle. Reads and
 * explicit authorized exports remain supported. max_bytes counts encoded
 * bytes; max_records bounds trie/node overhead. Limits must both be nonzero.
 * errno: EACCES authorization, EFBIG bytes, E2BIG records, EINVAL format.
 * Call qihse_kv_store_destroy() to release the detached handle. */
qihse_kv_store_t* qihse_kv_open_snapshot_user(FILE* stream, qihse_user_t* user,
                                             size_t max_bytes, size_t max_records);
/* Legacy internal bootstrap mode, deliberately separate from authenticated
 * open. Does not authorize pending-image recovery; not a user-facing adapter. */
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

#define QIHSE_KV_DURABLE_BATCH_MAX_RECORDS 4096u
#define QIHSE_KV_DURABLE_BATCH_MAX_BYTES (64u * 1024u * 1024u)

typedef struct {
    const char* key;
    const char* value;
    uint64_t expire_time_ms; /* absolute Unix milliseconds; zero means no expiry */
    uint16_t classification;
    uint16_t sci_compartment;
} qihse_kv_batch_set_record_t;

/* WAL-preserving durable SETs under one store write lock. Requires an active
 * authenticated user authorized for every incoming AND existing label. Rejects
 * empty batches, duplicate keys, bulk-load/replica-read-only/recovery states,
 * and batches exceeding either bound above (bytes include 40 WAL header bytes
 * per record plus key/value bytes, excluding C terminators). Caller-owned
 * strings/records must remain unchanged until return.
 * True means every record reached the WAL, fflush and exactly one fdatasync
 * succeeded; no memtable rotation occurs. This is NOT an atomic transaction:
 * false after mutation starts may leave a recoverable prefix, and fences all
 * data operations until reopen. Preflight refusal changes no store state. */
bool qihse_kv_set_batch_durable_user(qihse_kv_store_t* store,
                                     const qihse_kv_batch_set_record_t* records,
                                     size_t count, qihse_user_t* user);

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

/* Immutable, private snapshot artifact for a consistent replica bootstrap or
 * operator inventory. The artifact is unlinked as soon as it is opened and is
 * readable only through this handle. Its change-sequence watermark is
 * captured under the same store lock as the bytes. Full-export authorization
 * semantics apply: a principal unable to read any live row is refused rather
 * than receiving a partial snapshot. */
int qihse_kv_replica_snapshot_create(qihse_kv_store_t* store, qihse_user_t* user,
                                     const char* namespace_glob,
                                     qihse_kv_replica_snapshot_t** out_snapshot);
/* Authenticated, CT1-owner-only data backup. Unlike the replication baseline
 * snapshot, this captures tombstones and expired rows as well as live rows,
 * and it does not advance or persist a replication cursor. The snapshot is
 * data-only: it is not a continuation point for the CT journal. */
int qihse_kv_ct_owner_data_snapshot_create(qihse_kv_store_t* store,
    qihse_user_t* operator_principal,
    qihse_kv_replica_snapshot_t** out_snapshot);
bool qihse_kv_replica_snapshot_size(const qihse_kv_replica_snapshot_t* snapshot,
    qihse_user_t* principal, uint64_t* out_size);
/* Change-sequence watermark captured while the immutable snapshot bytes were
 * written under the store lock. It is principal-bound like size/read. */
bool qihse_kv_replica_snapshot_change_seq(
    const qihse_kv_replica_snapshot_t* snapshot, qihse_user_t* principal,
    uint64_t* out_change_seq);
bool qihse_kv_replica_snapshot_read(qihse_kv_replica_snapshot_t* snapshot,
                                    qihse_user_t* principal, uint64_t offset, void* out, size_t capacity,
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

typedef bool (*qihse_kv_snapshot_record_cb)(const char* key, const char* value,
    const qihse_kv_record_meta_t* metadata, void* user_data);
/* These helpers are restricted to detached snapshots opened by
 * qihse_kv_open_snapshot_user(). They enumerate/read retained dead records
 * too, with full per-record authorization. Callback strings are borrowed for
 * the callback duration; a callback false stops enumeration. */
bool qihse_kv_snapshot_foreach_record_user(qihse_kv_store_t* snapshot,
    qihse_user_t* user, qihse_kv_snapshot_record_cb callback, void* user_data);
bool qihse_kv_snapshot_get_record_user(qihse_kv_store_t* snapshot,
    const char* key, qihse_user_t* user, char** out_value,
    qihse_kv_record_meta_t* out_metadata);
/* Serialize every row of a detached snapshot, including tombstones and
 * expired values, to a private atomic QFS image. */
int qihse_kv_snapshot_save_user(qihse_kv_store_t* snapshot,
    const char* filepath, qihse_user_t* user);

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

/* Atomically publish a tombstone and a completed receipt as one durable WAL
 * frame. The source must be live at expected_source_seq and receipt_key must
 * contain exactly expected_prepared_value. Both rows and the new receipt
 * labels must be accessible to the active principal. build_receipt is called
 * once under the store write lock, before any WAL write, with the reserved
 * deletion sequence; it must only fill out_value and return success. The
 * receipt row receives delete_seq + 1. A false result after a WAL write fences
 * the store until authenticated reopen; replay either applies the entire
 * validated pair or neither row. Completed receipts are ordinary persistent
 * SET rows and survive tombstone compaction. */
#define QIHSE_KV_DELETE_RECEIPT_MAX_VALUE 4096u
typedef bool (*qihse_kv_receipt_builder_t)(uint64_t delete_seq, char* out_value,
                                            size_t capacity, void* context);
bool qihse_kv_del_with_receipt_user(qihse_kv_store_t* store,
    const char* source_key, uint64_t expected_source_seq,
    const char* receipt_key, const char* expected_prepared_value,
    uint16_t receipt_classification, uint16_t receipt_sci,
    qihse_kv_receipt_builder_t build_receipt, void* context,
    qihse_user_t* user, uint64_t* out_delete_seq);
/* Read state only for an authorized live record or retained tombstone.
 * Success with sequence 0 means LEGACY_UNVERSIONED, not ordered mutation,
 * version, or cursor evidence. Callers requiring such evidence must reject 0.
 * Misses, expired live rows, denied rows and recovery-pending stores return
 * false with any supplied outputs cleared. */
bool qihse_kv_change_seq_user(qihse_kv_store_t* store, const char* key,
                              qihse_user_t* user, uint64_t* out_change_seq,
                              bool* out_tombstone);

/* Authenticated metadata for an existing live row or a retained tombstone.
 * A miss, expired row, denied principal, or recovery-pending store returns
 * false and zeroes out. A tombstone can disappear after compaction, so this
 * is evidence only while retained; callers must not use absence as proof of
 * deletion. Sequence 0 denotes a legacy unversioned record. */
typedef struct {
    uint64_t change_seq;
    uint16_t classification;
    uint16_t sci_compartment;
    bool tombstone;
} qihse_kv_change_meta_t;

bool qihse_kv_change_meta_user(qihse_kv_store_t* store, const char* key,
                               qihse_user_t* user, qihse_kv_change_meta_t* out);
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
/* Storage health for INFO/monitoring: how many SST files a read has to
 * consult, and whether the metadata index that normally short-circuits that
 * is degraded. A degraded index means every read scans the files. */
typedef struct {
    size_t live_sstable_files;
    size_t sstable_counter;
    bool index_degraded;
} qihse_kv_sstable_stats_t;

bool qihse_kv_sstable_stats(qihse_kv_store_t* store, qihse_kv_sstable_stats_t* out);

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

#ifdef __cplusplus
}
#endif

#endif /* QIHSE_KV_STORE_H */
