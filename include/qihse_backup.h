#ifndef QIHSE_BACKUP_H
#define QIHSE_BACKUP_H

#include "qihse_kv_store.h"
#include "qihse_operations.h"
#include <stdint.h>
#include <stddef.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Legacy whole-store export (unclassified only) ────────────────────────
 *
 * This surface takes no security context, so it can only ever move
 * unclassified data (the KV layer's NULL-user path denies classified/SCI
 * records).  It is retained for compatibility and for the unclassified
 * operational snapshot it was written for.  New work MUST use the
 * context-taking federation backup API below, which propagates an
 * authenticated principal to the lowest data-retrieval layer (AGENTS.md
 * invariant 1).
 * ───────────────────────────────────────────────────────────────────────── */

typedef enum {
    BACKUP_FULL = 0,
    BACKUP_INCREMENTAL = 1,
    BACKUP_WAL = 2
} backup_type_t;

typedef struct {
    backup_type_t type;
    char* path;
    uint64_t start_lsn;
    uint64_t end_lsn;
    time_t timestamp;
    size_t size_bytes;
    char* checksum;
} qihse_backup_info_t;

int qihse_backup_full(qihse_kv_store_t* kv, const char* output_path, qihse_backup_info_t* info);
int qihse_backup_incremental(qihse_kv_store_t* kv, const char* output_path, uint64_t since_lsn, qihse_backup_info_t* info);
int qihse_restore(qihse_kv_store_t* kv, const char* backup_path);
int qihse_backup_list(const char* dir, qihse_backup_info_t** out_backups, size_t* out_count);
int qihse_backup_verify(const char* backup_path);
void qihse_backup_info_free(qihse_backup_info_t* info);

/* ────────────────────────────────────────────────────────────────────────
 * Federation snapshot backup (v3.md §20, §21, §23)
 *
 * A snapshot manifest is a claim: this snapshot id, captured at this WAL
 * continuation offset, over this many objects, under this key id, with a
 * checksum over the claim itself.  Until the data the manifest refers to
 * exists there is nothing to restore — this is the writer and the reader
 * that make the claim true.
 *
 * Three rules drive the design:
 *
 *   1. The security context is mandatory and is propagated to the lowest
 *      data-retrieval layer (AGENTS.md invariant 1).  A NULL context is an
 *      argument error, never "back up everything".  Clearance and SCI are
 *      enforced by the KV layer on both export and import, so a principal
 *      that may not read a record may neither back it up nor restore it
 *      (invariant 2).  A refused call leaves no container and no partial
 *      dataset behind.
 *
 *   2. The manifest is the contract.  The writer refuses when the caller's
 *      authorized view is narrower than the object count the manifest
 *      declares, because it cannot produce the data the manifest refers to;
 *      the reader refuses when the container disagrees with the manifest on
 *      the WAL continuation point, because a restore that resumes from a
 *      different point restores a state that never existed.
 *
 *   3. Integrity is verified before anything is applied.  The manifest's
 *      checksum is verified through qihse_snapshot_verify() first, the
 *      container carries its own SHA-384 over its data section, and the KV
 *      layer's load is transactional — a truncated, edited or unauthorized
 *      restore is refused whole rather than half-applied.
 *
 * The container never carries key material.  The manifest's
 * encryption_key_id is a key id, is validated as an identifier, and is the
 * only key-related field written (v3.md §20, §21).  An empty key id records
 * a backup the snapshot declared unencrypted; a value that looks like key
 * material is refused rather than copied.  The data section carries the
 * dataset as the store holds it, and the store never holds private key
 * material (§20), so a backup cannot introduce any.
 *
 * The container holds the captured dataset plus the resume point.  It does
 * not hold the WAL segment that follows that point; replaying from
 * `wal_continuation_offset` is the caller's job, which is why the descriptor
 * reports the offset it was bound to.
 *
 * Known boundary: the container is integrity-checked, not authenticated.  It
 * is bound to the snapshot id, the manifest revision and the WAL
 * continuation point, and any edit is caught by the SHA-384 — but a writer
 * with filesystem access can substitute a container that agrees with all
 * three, because the manifest itself carries no signature.  Authenticating
 * backups against the node identity key is the follow-up; until then a
 * backup path must be as protected as the dataset it holds.
 * ──────────────────────────────────────────────────────────────────────── */

#define QIHSE_BACKUP_MAGIC "QIHSEBK1"
#define QIHSE_BACKUP_MAGIC_LEN 8u
#define QIHSE_BACKUP_VERSION 1u
/* Fixed-size header, so the data section's offset never depends on a
 * variable-length field and a truncated container is detectable by size. */
#define QIHSE_BACKUP_HEADER_BYTES 320u
/* Key ID only — never key material. */
#define QIHSE_BACKUP_KEY_ID_MAX 127u

typedef enum {
    QIHSE_BACKUP_OK = 0,
    /* A NULL context, NULL store, NULL manifest or NULL path.  Never a
     * fallback to a context-free read. */
    QIHSE_BACKUP_ERR_ARGUMENT,
    /* A record, or the manifest's declared scope, is outside the caller's
     * clearance/SCI.  The payload is not disclosed and nothing is written. */
    QIHSE_BACKUP_ERR_DENIED,
    /* The manifest is absent, fails its checksum, or is not the manifest the
     * caller presented. */
    QIHSE_BACKUP_ERR_MANIFEST,
    /* The container is short, malformed, or its declared lengths disagree
     * with the bytes present. */
    QIHSE_BACKUP_ERR_TRUNCATED,
    /* The container's data section does not match its recorded SHA-384. */
    QIHSE_BACKUP_ERR_CHECKSUM,
    /* The container belongs to a different snapshot than the manifest. */
    QIHSE_BACKUP_ERR_SNAPSHOT_MISMATCH,
    /* The container's WAL continuation point disagrees with the manifest's.
     * Restoring anyway would silently resume from the wrong point. */
    QIHSE_BACKUP_ERR_WAL_POINT,
    /* The container's declared coverage disagrees with the manifest's. */
    QIHSE_BACKUP_ERR_COVERAGE,
    /* The manifest carries something that looks like key material instead of
     * a key id. */
    QIHSE_BACKUP_ERR_KEY_MATERIAL,
    QIHSE_BACKUP_ERR_IO
} qihse_backup_result_t;

const char* qihse_backup_result_name(qihse_backup_result_t r);

/* What a written container holds.  Every field is a claim the container
 * itself carries, so a caller can compare it against the manifest it holds
 * without restoring. */
typedef struct {
    qihse_uuid_t snapshot_id;
    /* The point the restore resumes from — copied from the manifest and
     * verified against it on read. */
    uint64_t wal_continuation_offset;
    uint64_t max_generation;
    /* Records in the data section, counted through the caller's authorized
     * view immediately before the section was written.  Freezing writes for
     * the duration of a coordinated snapshot is the snapshot protocol's job
     * (QIHSE_SNAPSHOT_COORDINATED), not this writer's. */
    uint64_t object_count;
    uint64_t data_bytes;
    uint8_t data_checksum[48];      /* SHA-384 over the data section */
    uint8_t manifest_checksum[48];  /* the manifest body digest it was bound to */
    char encryption_key_id[QIHSE_BACKUP_KEY_ID_MAX + 1u];
    qihse_schema_header_t schema;
} qihse_backup_descriptor_t;

/* Write the data `manifest` refers to, as the authenticated principal
 * `user_void` (a qihse_user_t*).
 *
 * The manifest must already be recorded and verify (qihse_snapshot_verify),
 * and the caller must present exactly the recorded manifest, so a backup
 * cannot be bound to a manifest nobody recorded.  The caller's authorized
 * view must cover the manifest's declared object count; anything else means
 * the caller cannot produce the data the manifest refers to, which is
 * reported as QIHSE_BACKUP_ERR_COVERAGE (too narrow) or denied outright by
 * the KV layer's clearance gate (QIHSE_BACKUP_ERR_DENIED).
 *
 * `out` is zeroed on entry, so a failed call never hands back a partial
 * descriptor.  Nothing is written at `path` unless every gate passed. */
qihse_backup_result_t qihse_backup_write(void* store_void, void* user_void,
                                         const qihse_snapshot_manifest_t* manifest,
                                         const char* path,
                                         qihse_backup_descriptor_t* out);

/* Restore the data `manifest` refers to, as the authenticated principal
 * `user_void` (a qihse_user_t*).
 *
 * Refuses unless, in order: the recorded manifest verifies against its
 * checksum and is the manifest presented; the container parses, is not
 * truncated, and matches its recorded SHA-384; the container is bound to
 * this snapshot id, this manifest revision and this WAL continuation point.
 * Only then is the dataset replaced, through the KV layer's authorization
 * gate — which denies the whole load if any record is outside the caller's
 * clearance/SCI, leaving the live dataset untouched. */
qihse_backup_result_t qihse_backup_restore(void* store_void, void* user_void,
                                           const qihse_snapshot_manifest_t* manifest,
                                           const char* path,
                                           qihse_backup_descriptor_t* out);

#ifdef __cplusplus
}
#endif
#endif
