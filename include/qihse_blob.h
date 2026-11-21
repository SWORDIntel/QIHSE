#ifndef QIHSE_BLOB_H
#define QIHSE_BLOB_H

/* U1 — content-addressed object/blob tier for session-delivery workloads
 * (SESSION_DELIVERY_UPGRADES.md). Blobs are immutable, addressed by their
 * SHA-384, streamed to/from disk (never fully buffered by the store), and
 * bound to a tenant + class tag + classification/SCI at write time.
 *
 * SECURITY (AGENTS.md invariant #1): every operation takes an authenticated
 * qihse_user_t* and NULL is unconditionally denied — there is deliberately
 * no context-free variant of any blob primitive. Tenant principals may only
 * touch blobs bound to their own tenant; commons collections are readable by
 * every authenticated tenant but writable only by the system domain.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "qihse_auth.h"

#ifdef __cplusplus
extern "C" {
#endif

#define QIHSE_BLOB_HASH_BYTES 48u  /* SHA-384 (CNSA 2.0 aligned; auth uses PBKDF2-HMAC-SHA-384) */
#define QIHSE_BLOB_HASH_HEX   (2u * QIHSE_BLOB_HASH_BYTES + 1u)
#define QIHSE_BLOB_MAX_SIZE   (64u * 1024u * 1024u) /* Existing session/consensus blobs */
#define QIHSE_BLOB_ARTIFACT_MAX_SIZE (4ull * 1024ull * 1024ull * 1024ull) /* Dump artifacts only */
#define QIHSE_BLOB_CHUNK_SIZE (256u * 1024u)

typedef enum {
    QIHSE_BLOB_TAG_ENTITLEMENT_SEED  = 1,
    QIHSE_BLOB_TAG_PATTERN_BUNDLE    = 2,
    QIHSE_BLOB_TAG_SCRIPT_SET        = 3,
    QIHSE_BLOB_TAG_COMMONS_SNAPSHOT  = 4,
    QIHSE_BLOB_TAG_REPL_TRANSACTION  = 5, /* system Operator only */
    QIHSE_BLOB_TAG_ANALYSIS_ARTIFACT = 6, /* KP14 analysis artifact payload */
    QIHSE_BLOB_TAG_DUMP_ARTIFACT     = 7  /* tenant-bound, classified large object */
} qihse_blob_tag_t;

typedef struct qihse_blob_store qihse_blob_store_t;

/* Metadata for one stored blob (list callback payload). */
typedef struct {
    uint8_t hash[QIHSE_BLOB_HASH_BYTES];
    uint64_t size;
    uint32_t tenant_id;
    uint16_t tag;          /* qihse_blob_tag_t */
    uint16_t classification;
    uint16_t sci_compartment;
    uint32_t refcount;
} qihse_blob_info_t;

/* Create a blob store rooted at base_dir (created if missing). Layout:
 *   base_dir/objects/ab/<hex>   immutable content files
 *   base_dir/index.log          append-only metadata log (crash-safe replay)
 * Returns NULL on failure. */
qihse_blob_store_t* qihse_blob_store_create(const char* base_dir);
void qihse_blob_store_destroy(qihse_blob_store_t* store);

/* Streaming write. read_fn is pulled chunk-by-chunk:
 *   return >0: bytes placed in buffer; 0: EOF; <0: read error (aborts put).
 * Dedup: an existing blob with identical content AND identical binding
 * (tenant, tag, classif, sci) just bumps its refcount. A hash collision with
 * a DIFFERENT binding is refused — tenants cannot claim each other's blobs.
 * Commons-tagged blobs require a system-domain writer. out_hash receives the
 * SHA-384 digest. */
typedef int64_t (*qihse_blob_read_fn)(void* opaque, uint8_t* buffer, size_t capacity);
bool qihse_blob_put_user(qihse_blob_store_t* store, uint32_t tenant_id,
                         qihse_blob_tag_t tag, uint16_t classification,
                         uint16_t sci_compartment, qihse_user_t* user,
                         qihse_blob_read_fn read_fn, void* read_opaque,
                         uint8_t out_hash[QIHSE_BLOB_HASH_BYTES], uint64_t* out_size);

/* Like put_user, but refuse a streamed object unless its complete SHA-384
 * and byte length match the caller's declaration BEFORE the index is
 * durably updated. Intended for authenticated replica payload import. */
bool qihse_blob_put_expected_user(qihse_blob_store_t* store,
                                  uint32_t tenant_id, qihse_blob_tag_t tag,
                                  uint16_t classification,
                                  uint16_t sci_compartment, qihse_user_t* user,
                                  qihse_blob_read_fn read_fn, void* read_opaque,
                                  const uint8_t expected_hash[QIHSE_BLOB_HASH_BYTES],
                                  uint64_t expected_size);

/* Durable 2PC participant operations. PREPARE validates authorization and
 * content hash/length, durably stages the object and metadata without making it
 * visible to reads or enumeration. Resolve is a control-plane operation: the
 * caller must supply the coordinator's durable irreversible decision. Exact
 * retries of recorded receipts are idempotent; conflicting recorded decisions
 * fail. An absent ID accepts ABORT as a no-op without creating a binding or
 * receipt; an absent COMMIT fails. The authoritative coordinator journal and its
 * captured ID floor must prevent late PREPARE and ID reuse: a standalone blob
 * archive cannot reconstruct unused coordinator IDs. Resolve rejects inherited
 * handles before locking. An unresolved prepared object is invisible after
 * reopen until replay. */
bool qihse_blob_prepare_expected_user(qihse_blob_store_t* store, uint64_t txn_id,
                                      uint32_t tenant_id, qihse_blob_tag_t tag,
                                      uint16_t classification, uint16_t sci_compartment,
                                      qihse_user_t* user, qihse_blob_read_fn read_fn,
                                      void* read_opaque,
                                      const uint8_t expected_hash[QIHSE_BLOB_HASH_BYTES],
                                      uint64_t expected_size);
bool qihse_blob_resolve_prepared(qihse_blob_store_t* store, uint64_t txn_id,
                                 bool commit);

/* Coordinator allocation fence, not a blob-data read: returns one greater than
 * every durable PREPARE/COMMIT/ABORT ID (1 for an empty store), under the store
 * lock. False for invalid arguments, a poisoned store or UINT64_MAX exhaustion;
 * leaves *next_id unchanged on failure. Advance the idle coordinator before
 * recovery; this query neither reserves IDs nor resolves orphan PREPAREs. */
bool qihse_blob_decision_next_id(qihse_blob_store_t* store, uint64_t* next_id);

/* Convenience one-shot write of an in-memory buffer. */
bool qihse_blob_put_buffer_user(qihse_blob_store_t* store, uint32_t tenant_id,
                                qihse_blob_tag_t tag, uint16_t classification,
                                uint16_t sci_compartment, qihse_user_t* user,
                                const uint8_t* data, size_t len,
                                uint8_t out_hash[QIHSE_BLOB_HASH_BYTES]);

/* Range read for resume/delta pulls. Reads up to buffer_len bytes starting
 * at offset; *out_read receives the byte count. Every call re-checks
 * authorization so a revoked principal cannot drain an in-flight transfer. */
bool qihse_blob_get_user(qihse_blob_store_t* store, const uint8_t* hash,
                         uint64_t offset, uint8_t* buffer, size_t buffer_len,
                         size_t* out_read, qihse_user_t* user);
bool qihse_blob_size_user(qihse_blob_store_t* store, const uint8_t* hash,
                          uint64_t* out_size, qihse_user_t* user);

/* Metadata lookup with full authorization (tenant binding + clearance).
 * Used by the bundle composer's sanity gate to verify a blob's binding. */
bool qihse_blob_info_user(qihse_blob_store_t* store, const uint8_t* hash,
                          qihse_blob_info_t* out_info, qihse_user_t* user);

/* Re-read a stored object and verify its size and SHA-384 digest against the
 * indexed hash before a caller treats it as a durable replicated payload.
 * This is a classified read: an explicit authorized principal is mandatory. */
bool qihse_blob_verify_user(qihse_blob_store_t* store, const uint8_t* hash,
                            qihse_user_t* user);

/* Verify the complete object through one authorized file descriptor and
 * return its indexed binding plus at most 256 leading bytes only on success.
 * This lets a consensus validator check a transaction envelope against the
 * same bytes whose SHA-384 was verified, without a second path-based read. */
bool qihse_blob_verify_with_info_user(qihse_blob_store_t* store,
                                      const uint8_t* hash, qihse_user_t* user,
                                      qihse_blob_info_t* out_info,
                                      uint8_t* out_prefix, size_t prefix_len);

/* Pin/unpin: manifest references so GC (U6) cannot reap in-use blobs. */
bool qihse_blob_ref_user(qihse_blob_store_t* store, const uint8_t* hash, qihse_user_t* user);
bool qihse_blob_unref_user(qihse_blob_store_t* store, const uint8_t* hash, qihse_user_t* user);

/* Protected manifest pin: prevents public delete (qihse_blob_delete_user) while held */
bool qihse_blob_pin_user(qihse_blob_store_t* store, const uint8_t* hash, qihse_user_t* user);
bool qihse_blob_unpin_user(qihse_blob_store_t* store, const uint8_t* hash, qihse_user_t* user);
bool qihse_blob_is_pinned_user(qihse_blob_store_t* store, const uint8_t* hash,
                               qihse_user_t* user, bool* out_pinned);
/* Read exact pin multiplicity for authorized backup/restore metadata. */
bool qihse_blob_pin_count_user(qihse_blob_store_t* store, const uint8_t* hash,
                               qihse_user_t* user, uint32_t* out_pin_count);

/* Delete one reference; the object is unlinked when the refcount hits zero. */
bool qihse_blob_delete_user(qihse_blob_store_t* store, const uint8_t* hash, qihse_user_t* user);

/* Tenant-scoped enumeration (a read primitive — clearance-checked per entry,
 * confined to the caller's tenant plus commons). Entries the caller cannot
 * read are omitted; success does not prove complete-store enumeration or form
 * a full-store backup snapshot. Callback returning false stops iteration. */
typedef bool (*qihse_blob_list_fn)(const qihse_blob_info_t* info, void* opaque);
bool qihse_blob_list_user(qihse_blob_store_t* store, qihse_user_t* user,
                          qihse_blob_list_fn callback, void* callback_opaque);

/* Complete point-in-time stream of live entries in the whole store (not 2PC
 * receipts or unresolved prepared content). Use the archive API for recovery.
 * Authorization is checked for every entry before the first callback.
 * Each callback must consume the complete verified reader and must not retain
 * callback data/reader after return. On any failure, discard its staged output.
 * This primitive does not itself serialize/authenticate or publish a backup. */
typedef bool (*qihse_blob_snapshot_entry_fn)(
    const qihse_blob_info_t* info, uint32_t pin_count,
    qihse_blob_read_fn read_fn, void* read_opaque, void* callback_opaque);
bool qihse_blob_snapshot_all_user(qihse_blob_store_t* store, qihse_user_t* user,
                                  qihse_blob_snapshot_entry_fn callback,
                                  void* callback_opaque);

/* Authenticated monotonic snapshot checkpoint for this same live handle only.
 * Covers live metadata, references, pins and terminal receipts; rejects pending
 * PREPAREs, poisoned/inherited handles and incomplete authorization. Leaves
 * *epoch unchanged on failure. Snapshot-retention references do not advance it.
 * Capture ALL participating sources before ANY export and compare ALL after ALL
 * exports; this query alone does not establish a shared cross-store snapshot. */
bool qihse_blob_snapshot_epoch_user(qihse_blob_store_t* store, qihse_user_t* user,
                                    uint64_t* epoch);

/* W11.6 archive v1/v2: authenticated, NOT encrypted. V2 adds terminal 2PC
 * receipts captured with live metadata; restore never reapplies their historical
 * COMMIT effects or resurrects deleted objects. V1 imports remain supported.
 * Export refuses unresolved PREPAREs before emitting bytes. This is a blob-only
 * snapshot, not a common coordinator/cross-store recovery point.
 * The caller supplies exactly
 * 48 cryptographically random secret key bytes, manages their lifetime/rotation,
 * and selects the key out of band. No key or principal credentials are archived.
 * Every byte preceding the final 48-byte HMAC-SHA-384 is authenticated.
 * Streaming uses one chunk plus O(live entries + terminal receipts) metadata;
 * no content-sized allocations. Export preflights the whole store before any
 * output; a false return requires discarding ALL output (including on I/O abort).
 * write_fn must consume the entire buffer or return false. Readers follow the
 * read_fn contract above; restore requires EOF immediately after the MAC.
 * Both calls require an active authenticated user. Restore also enforces normal
 * blob write authorization for every archived binding, not merely key possession.
 */
#define QIHSE_BLOB_ARCHIVE_KEY_BYTES 48u
typedef bool (*qihse_blob_write_fn)(void* opaque, const uint8_t* data, size_t length);
bool qihse_blob_archive_export_user(qihse_blob_store_t* store, qihse_user_t* user,
                                    const uint8_t* key, size_t key_length,
                                    qihse_blob_write_fn write_fn, void* opaque);

/* Fresh destination only: private unique sibling staging, verified content/MAC,
 * durable files/directories, Linux atomic no-replace rename, parent fsync. The
 * parent must already exist and be caller-controlled; no merge or replacement.
 * Unsupported no-replace publication fails closed. Failure before publication
 * leaves no destination. A parent-fsync error AFTER publication has its own
 * result: a complete authenticated store is visible, durability is uncertain;
 * do not retry blindly or remove it. Crash-orphaned staging dirs are private.
 */
typedef enum {
    QIHSE_BLOB_ARCHIVE_ERROR = -1,
    QIHSE_BLOB_ARCHIVE_OK = 0,
    QIHSE_BLOB_ARCHIVE_PUBLISHED_UNSYNCED = 1
} qihse_blob_archive_result_t;
qihse_blob_archive_result_t qihse_blob_archive_restore_user(
    const char* destination, qihse_user_t* user,
    const uint8_t* key, size_t key_length,
    qihse_blob_read_fn read_fn, void* opaque);

/* Hex helpers (hash <-> lowercase hex, NUL-terminated). */
void qihse_blob_hash_to_hex(const uint8_t* hash, char out[QIHSE_BLOB_HASH_HEX]);
bool qihse_blob_hash_from_hex(const char* hex, uint8_t out[QIHSE_BLOB_HASH_BYTES]);

#ifdef __cplusplus
}
#endif

#endif /* QIHSE_BLOB_H */
