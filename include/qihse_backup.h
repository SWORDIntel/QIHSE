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

/* ── Whole-store export (manifest-free container) ────────────────────────
 *
 * A whole-store container: a 64-byte fixed header (magic, version, type,
 * LSN range, timestamp, data length, the writer's clearance/SCI bound and a
 * FNV-1a over the header prefix and the data section) followed by a data
 * section produced by the KV layer's own authorization-aware export.
 *
 * Every entry point takes an authenticated principal and fails closed
 * (AGENTS.md invariant 1).  A NULL context is an argument error, never
 * "export everything"; a revoked handle is denied.  The identity is
 * propagated to the KV layer — the only layer that knows a record's
 * classification — so a principal that may not read a record may neither
 * export nor restore it, and the KV layer refuses the WHOLE export/import
 * rather than producing a quietly partial one (invariant 2).  Nothing is
 * written or applied when a call is refused.
 *
 * The container records the writing principal's clearance/SCI as an upper
 * bound on what it can hold (the KV layer refuses an export containing a
 * record above the writer's clearance), which is the only classification
 * signal available when there is no store to ask — so list, verify and
 * restore refuse a container whose recorded bound the caller does not
 * dominate.  A listing is refused whole rather than filtered, because the
 * existence of a higher-bound container is itself metadata a lower
 * principal may not see.
 *
 * Return codes (this surface predates qihse_backup_result_t and stays an
 * int, matching the KV layer's own convention; a denial also sets
 * errno = EACCES, as the KV layer's export/import does):
 *    0  QIHSE_BACKUP_EXPORT_OK          success
 *   -1  QIHSE_BACKUP_EXPORT_ERR         argument, container or I/O error
 *   -2  QIHSE_BACKUP_EXPORT_DENIED      the principal is not live, or a
 *                                       record/container is outside its
 *                                       clearance/SCI
 *   -3  QIHSE_BACKUP_EXPORT_UNSUPPORTED this layer cannot honour the request
 * ───────────────────────────────────────────────────────────────────────── */

#define QIHSE_BACKUP_EXPORT_OK           0
#define QIHSE_BACKUP_EXPORT_ERR         (-1)
#define QIHSE_BACKUP_EXPORT_DENIED      (-2)
#define QIHSE_BACKUP_EXPORT_UNSUPPORTED (-3)

typedef enum {
    BACKUP_FULL = 0,
    BACKUP_INCREMENTAL = 1,
    BACKUP_WAL = 2
} backup_type_t;

typedef struct {
    backup_type_t type;
    char* path;
    /* This layer has no change sequence, so both are 0 in a container it
     * writes (see qihse_backup_incremental_user). */
    uint64_t start_lsn;
    uint64_t end_lsn;
    time_t timestamp;
    size_t size_bytes;
    char* checksum;
    /* The writing principal's clearance/SCI bound recorded in the header. */
    uint16_t classification;
    uint16_t sci_compartment;
    uint32_t writer_user_id;
} qihse_backup_info_t;

/* Write every record `user` is cleared for, as `user`.  The data section is
 * the KV layer's authorization-aware snapshot stream, so the classification
 * decision is made where the knowledge lives and a record above the
 * caller's clearance refuses the whole export (-2) with no container and no
 * scratch file left behind.
 *
 * `info` is zeroed on entry, so a refused call never hands back a partial
 * record; on success it owns `path` and `checksum`, which
 * qihse_backup_info_free() releases. */
int qihse_backup_full_user(qihse_kv_store_t* kv, qihse_user_t* user,
                           const char* output_path, qihse_backup_info_t* info);

/* Incremental export.  The KV layer exposes no change sequence or LSN, so a
 * delta cannot be produced honestly: this refuses with
 * QIHSE_BACKUP_EXPORT_UNSUPPORTED and writes nothing, rather than labelling
 * a full snapshot "incremental" (which would make a restore silently
 * non-incremental).  It exists so the surface stays context-taking and a
 * caller that needs a delta gets an explicit refusal instead of a
 * context-free fallback.  A manifest-bound federated backup with a WAL
 * continuation point is the supported answer for incremental coverage. */
int qihse_backup_incremental_user(qihse_kv_store_t* kv, qihse_user_t* user,
                                  const char* output_path, uint64_t since_lsn,
                                  qihse_backup_info_t* info);

/* Apply a container through the KV layer's transactional, authorization-aware
 * load.  The container's checksum is verified over the bytes that are about
 * to be applied, and a container whose recorded clearance/SCI bound the
 * caller does not dominate, or that holds a record above the caller's
 * clearance/SCI, is refused with -2 and the live dataset untouched. */
int qihse_restore_user(qihse_kv_store_t* kv, qihse_user_t* user, const char* backup_path);

/* List the containers in `dir` the caller may know about.  Refused whole
 * (-2) when any container's recorded bound is above the caller's
 * clearance/SCI; `*out_backups` is NULL and `*out_count` 0 on every failure,
 * and each entry's strings are released by qihse_backup_info_free(). */
int qihse_backup_list_user(qihse_user_t* user, const char* dir,
                           qihse_backup_info_t** out_backups, size_t* out_count);

/* Verify a container's checksum, as an authenticated principal.  Reads no
 * payload beyond hashing it and writes nothing. */
int qihse_backup_verify_user(qihse_user_t* user, const char* backup_path);

/* Release the strings owned by one qihse_backup_info_t.  Not a data
 * primitive: it neither reads nor discloses anything. */
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
