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
    /* The container's change-sequence range.  A FULL container claims no
     * sequence range: both are 0.  An INCREMENTAL container carries the
     * caller's cursor as start_lsn (the `since` the delta was taken from)
     * and the delta's continuation point as end_lsn — for a full-clearance
     * writer that is the store's last mutation; for a restricted writer it
     * is the highest sequence the principal was ALLOWED to see, by design
     * (see qihse_backup_incremental_user). */
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

/* Incremental export.  Writes the delta since the caller's change-sequence
 * cursor: the data section is the KV layer's delta stream (only records
 * whose stamped sequence is STRICTLY greater than `since_lsn`, tombstones
 * included, each key's latest state), produced through the KV layer's
 * authorization-aware iteration with this principal's identity (AGENTS.md
 * invariant 1: NULL is an argument error, never "export everything").
 *
 * The continuation point comes back as info->end_lsn (start_lsn echoes the
 * cursor).  Feed it to the next call as `since_lsn`.
 *
 * METADATA-DISCLOSURE DECISION (default and ONLY form): the continuation
 * point is the highest sequence among the records THIS principal was
 * ALLOWED to see — never the store-global high-water.  Mutations the
 * principal may not see are filtered at the KV layer before the resume
 * point is derived, so hidden mutations are never enumerated and comparing
 * successive resume points cannot reveal how many occurred.  A
 * full-clearance writer's resume point coincides with the store's last
 * mutation.  No "global high-water with gaps visible" form is offered,
 * even opt-in: it would disclose the count of hidden mutations.
 *
 * Unlike a FULL container (whose data section is refused whole if any live
 * record is above the writer's clearance — a full container claims complete
 * coverage), an INCREMENTAL container's section is clearance-FILTERED: a
 * delta is explicitly "the mutations you may see since the cursor".  The
 * container still records the writer's clearance/SCI bound, so the same
 * dominance gates apply on verify/list.
 *
 * Boundaries: records predating the change sequence (sequence 0) are never
 * in a delta — take a full backup first, then track deltas.  A delta
 * container is NOT restorable through qihse_restore_user (a whole-store
 * image restorer); it is applied by a delta-aware consumer against the base
 * it extends.  qihse_restore_user refuses it with
 * QIHSE_BACKUP_EXPORT_UNSUPPORTED, on purpose. */
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
 * Federation snapshot backup (plan §20, §21, §23)
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
 *      container carries its own SHA-384 over its data section and over its
 *      WAL section, and the KV layer's load is transactional — a truncated,
 *      edited or unauthorized restore is refused whole rather than
 *      half-applied.
 *
 * The container never carries key material.  The manifest's
 * encryption_key_id is a key id, is validated as an identifier, and is the
 * only key-related field written (plan §20, §21).  An empty key id records
 * a backup the snapshot declared unencrypted; a value that looks like key
 * material is refused rather than copied.  The data section carries the
 * dataset as the store holds it, and the store never holds private key
 * material (§20), so a backup cannot introduce any.
 *
 * ── Authentication (signed containers) ───────────────────────────────────
 *
 * The container is integrity-checked AND authenticated: it is bound to the
 * snapshot id, the manifest revision and the WAL continuation point, and it
 * is signed with the F5 node identity key, so a writer with filesystem
 * access cannot substitute a container that agrees with all three:
 *
 *   - qihse_backup_write_signed() resolves the signer through the store's
 *     enrolled identity records (fednode:<uuid>) as the authenticated
 *     principal, requires the identity to be APPROVED right now, and loads
 *     the private key from the record's key HANDLE — a filesystem reference.
 *     The private key never enters a QIHSE record and never enters the
 *     container (plan §20).  An absent, unenrolled, unapproved or keyless
 *     identity FAILS the write with QIHSE_BACKUP_ERR_SIGNER: there is no
 *     unsigned fallback and no development flag that creates one.
 *
 *   - The header carries the signer's node id and public-key fingerprint,
 *     the signature algorithm id and the signature length — never key
 *     material.  The algorithm, the fingerprint and the length sit INSIDE
 *     the signed region, so an algorithm-downgrade or signer-substitution
 *     edit invalidates the signature instead of reinterpreting it.
 *
 *   - The signature covers the whole fixed header, which carries the
 *     manifest checksum, the data section's SHA-384 and the WAL section's
 *     SHA-384, so one detached signature authenticates the manifest
 *     binding, both payload digests and the signer identity at once.  The
 *     layout is
 *       [ header ][ signature ][ data section ][ WAL section ]
 *     so a reader can refuse a bad signature BEFORE any payload byte is
 *     read, and refuse a bad WAL section before any WAL byte is applied.
 *
 *   - qihse_backup_restore_signed() and qihse_backup_verify() re-check the
 *     signer against the identity records at read time — mirroring
 *     qihse_federation_node_capability_lookup_admissible(), the trust state
 *     is re-read rather than snapshot, so a signer revoked after the backup
 *     was written stops being acceptable immediately.  Unknown, unapproved
 *     and revoked signers, and signatures that do not match the recorded
 *     fingerprint's enrolled key, are refused with
 *     QIHSE_BACKUP_ERR_SIGNATURE and nothing is applied.
 *
 *   - The single exception is the explicit operator override parameter on
 *     qihse_backup_restore_signed().  It skips ONLY the signature and
 *     signer-admissibility gate, it is available only to a principal that
 *     holds QIHSE_SCOPE_SECURITY_ADMIN (an operator, implicitly), and it
 *     leaves every other gate exactly where it was: manifest, structure,
 *     version, data and WAL checksums, snapshot binding, WAL continuation
 *     point, coverage, and the KV layer's clearance/SCI load check.  The
 *     override can never turn a clearance denial into a restore, and a
 *     checksum-tampered container is still refused under it.  Fail closed
 *     by default.
 *
 * ── The WAL section (v3 containers) ──────────────────────────────────────
 *
 * The container holds the captured dataset, the resume point, and a bounded
 * run of the WAL records that FOLLOW that point (plan §23: "backups must
 * include ... WAL continuation point" — the segment is what makes the
 * continuation point actionable inside one restore).  The section is
 * length-declared, digest-covered, signature-covered and bounded by
 * QIHSE_BACKUP_WAL_SECTION_MAX, and its records are self-describing with a
 * per-record CRC32 — the same integrity primitive and the same composition
 * qihse_wal uses (qihse_wal_crc32 over the header fields, key and value,
 * XOR-combined), the same bounded key/value lengths (QIHSE_WAL_MAX_KEY /
 * QIHSE_WAL_MAX_VALUE) and the same ordered-replay discipline as
 * qihse_wal_replay():
 *
 *   - The record header extends the tractable WAL's record with the two
 *     fields the KV layer needs to preserve classification through a
 *     replay (classification and SCI compartment).  A record that could
 *     not carry them could only be applied as unclassified, which would
 *     make a WAL replay a classification-downgrade channel.
 *
 *   - Replay is fail-closed on structure: the WHOLE section is validated —
 *     per-record CRC, declared-versus-present lengths, bounded key/value,
 *     strictly increasing LSNs, first/last LSN agreeing with the header —
 *     before the data section is loaded and before the first WAL byte is
 *     applied, so a truncated or mid-record tail refuses the restore rather
 *     than partially applying.
 *
 *   - Replay is idempotent-safe the way qihse_wal_replay() is: records
 *     whose LSN is below the manifest's WAL continuation point were already
 *     reflected in the snapshot and are SKIPPED, not re-applied; data ops
 *     are applied through the KV layer's set/delete primitives, which
 *     converge on re-application; and a DELETE whose key is already absent
 *     is satisfied rather than an error.
 *
 *   - Replay is authorization-checked before anything is applied: every
 *     INSERT/UPDATE record's classification/SCI is checked against the
 *     restoring principal with qihse_auth_can_access() — the exact
 *     predicate qihse_kv_set_user() applies — BEFORE the dataset is
 *     replaced, and every record the loaded snapshot can hold is already
 *     within the caller's access (the KV layer refuses the whole load
 *     otherwise), so a WAL record above the caller's clearance refuses the
 *     restore with QIHSE_BACKUP_ERR_DENIED and nothing is applied.
 *
 *   - The writer only produces a segment whose first record sits exactly at
 *     the manifest's WAL continuation point.  The reader refuses a segment
 *     that starts ABOVE it (records missing between the snapshot and the
 *     segment would silently lose writes — QIHSE_BACKUP_ERR_WAL_POINT) and
 *     skips one that starts below it (already-applied records).
 * ──────────────────────────────────────────────────────────────────────── */

#define QIHSE_BACKUP_MAGIC "QIHSEBK1"
#define QIHSE_BACKUP_MAGIC_LEN 8u
/* Container version history (the version is inside the signed region):
 *   1  unsigned, integrity-only          — RETIRED, no writer or reader
 *   2  signed, no WAL section            — RETIRED, no writer or reader
 *   3  signed + bounded WAL section      — the current format
 * Every entry point refuses version 1 and 2 containers with
 * QIHSE_BACKUP_ERR_VERSION rather than downgrading them to whatever checks
 * an older format could still run. */
#define QIHSE_BACKUP_VERSION_WAL 3u
/* Fixed-size header, so the data section's offset never depends on a
 * variable-length field and a truncated container is detectable by size:
 * 392 bytes of snapshot + signer fields, then wal_bytes (8), wal_checksum
 * (48), wal_first_lsn (8) and wal_last_lsn (8). */
#define QIHSE_BACKUP_HEADER_WAL_BYTES 464u
/* Key ID only — never key material. */
#define QIHSE_BACKUP_KEY_ID_MAX 127u
/* The WAL section is bounded: a declared length above this is refused by
 * writer and reader alike, so a container cannot promise an unbounded
 * segment (and the reader's single heap buffer stays bounded). */
#define QIHSE_BACKUP_WAL_SECTION_MAX (8u * 1024u * 1024u)
/* WAL record header: lsn (8), txn_id (8), engine_id (1), op_type (1),
 * classification (2), sci (2), key_length (4), value_length (4),
 * reserved (2, zero), checksum (4, CRC32) — followed by
 * key[key_length] and value[value_length]. */
#define QIHSE_BACKUP_WAL_RECORD_HEADER_BYTES 36u

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
    QIHSE_BACKUP_ERR_IO,
    /* Signed containers: the signing node identity is absent, not enrolled,
     * not APPROVED right now, or its private key does not load or does not
     * match the enrolled record.  The write fails rather than producing an
     * unsigned container. */
    QIHSE_BACKUP_ERR_SIGNER,
    /* Signed containers: the signature is absent, truncated or does not
     * verify, the recorded fingerprint does not match the signer's enrolled
     * key, or the signer is unknown, unapproved or revoked at read time. */
    QIHSE_BACKUP_ERR_SIGNATURE,
    /* The container's version is not QIHSE_BACKUP_VERSION_WAL: a container
     * this build's writer could not have produced.  Retired formats (the
     * unsigned v1 pair, the WAL-less v2) are refused here rather than
     * downgraded to whatever checks an older format could still run. */
    QIHSE_BACKUP_ERR_VERSION
} qihse_backup_result_t;

const char* qihse_backup_result_name(qihse_backup_result_t r);

/* What a written container holds.  Every field is a claim the container
 * itself carries, so a caller can compare it against the manifest it holds
 * without restoring. */
typedef struct {
    qihse_uuid_t snapshot_id;
    /* The point the restore resumes from — copied from the manifest and
     * verified against it on read.  The WAL section starts here. */
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
    /* Who vouches for everything above.  The signer's durable node identity
     * and the fingerprint of the enrolled public key that must verify the
     * signature. */
    qihse_uuid_t signer_node;
    uint8_t signer_fingerprint[QIHSE_FEDERATION_NODE_FINGERPRINT_BYTES];
    qihse_sig_alg_t sig_alg;
    /* The post-snapshot WAL section: its length, its SHA-384, and the LSN
     * range it covers.  An absent section is 0/zeroed throughout — the
     * container then resumes at `wal_continuation_offset` with nothing to
     * replay, which is what qihse_backup_write_signed() produces. */
    uint64_t wal_bytes;
    uint8_t wal_checksum[48];
    uint64_t wal_first_lsn;
    uint64_t wal_last_lsn;
} qihse_backup_descriptor_t;

/* Write the data `manifest` refers to, as the authenticated principal
 * `user_void` (a qihse_user_t*), as an AUTHENTICATED container signed with
 * the enrolled identity of `signer_node`.
 *
 * The manifest must already be recorded and verify (qihse_snapshot_verify),
 * and the caller must present exactly the recorded manifest, so a backup
 * cannot be bound to a manifest nobody recorded.  The caller's authorized
 * view must cover the manifest's declared object count; anything else means
 * the caller cannot produce the data the manifest refers to, which is
 * reported as QIHSE_BACKUP_ERR_COVERAGE (too narrow) or denied outright by
 * the KV layer's clearance gate (QIHSE_BACKUP_ERR_DENIED).
 *
 * The signer is resolved through the store's fednode:<uuid> records as the
 * authenticated principal `user_void` (the identity reaches the lowest
 * data-retrieval layer, AGENTS.md invariant 1), must be QIHSE_TRUST_APPROVED
 * right now, and its private key is loaded from the record's key handle —
 * the key lives on disk and never enters a record or the container.  An
 * absent, unenrolled, unapproved or keyless signer fails the whole write
 * with QIHSE_BACKUP_ERR_SIGNER and writes nothing: there is no unsigned
 * fallback.
 *
 * The container records the signer's node id, the fingerprint of the
 * enrolled public key, the algorithm id and the signature length — never key
 * material — and the signature covers the whole fixed header, which carries
 * the manifest checksum and the data section's SHA-384.  No WAL section is
 * written: the descriptor's wal fields come back zeroed.
 *
 * `out` is zeroed on entry; nothing is written at `path` unless every gate
 * passed. */
qihse_backup_result_t qihse_backup_write_signed(void* store_void, void* user_void,
                                                const qihse_snapshot_manifest_t* manifest,
                                                const qihse_uuid_t* signer_node,
                                                const char* path,
                                                qihse_backup_descriptor_t* out);

/* Write the data `manifest` refers to PLUS a bounded post-snapshot WAL
 * segment, as an AUTHENTICATED container signed with the enrolled identity
 * of `signer_node`.
 *
 * Every gate of qihse_backup_write_signed() applies unchanged.  The segment
 * is `wal_len` bytes of records in the container's WAL record format (see
 * QIHSE_BACKUP_WAL_RECORD_HEADER_BYTES): the caller captures it from its WAL
 * starting at the manifest's wal_continuation_offset.  The writer validates
 * the WHOLE segment before anything is written — per-record CRC32, bounded
 * and NUL-free keys/values, strictly increasing LSNs, a size within
 * QIHSE_BACKUP_WAL_SECTION_MAX — and refuses a segment whose first record
 * does not sit exactly at the manifest's wal_continuation_offset with
 * QIHSE_BACKUP_ERR_WAL_POINT: below it the records are pre-snapshot, above
 * it the gap would silently lose writes.  A segment that fails validation is
 * QIHSE_BACKUP_ERR_TRUNCATED; one that exceeds the bound is
 * QIHSE_BACKUP_ERR_ARGUMENT.
 *
 * The section's SHA-384, its length and its LSN range go into the header —
 * inside the signed region — so the signature authenticates the segment the
 * same way it authenticates the data section. */
qihse_backup_result_t qihse_backup_write_signed_wal(void* store_void, void* user_void,
                                                    const qihse_snapshot_manifest_t* manifest,
                                                    const qihse_uuid_t* signer_node,
                                                    const char* path,
                                                    const uint8_t* wal_segment,
                                                    size_t wal_len,
                                                    qihse_backup_descriptor_t* out);

/* Restore an AUTHENTICATED container, as the authenticated principal
 * `user_void`.
 *
 * Refuses unless, in order: the recorded manifest verifies against its
 * checksum and is the manifest presented; the container parses, is the
 * current version (a v1 or v2 container is QIHSE_BACKUP_ERR_VERSION), is
 * not truncated, and its declared lengths agree with the bytes present; the
 * container is bound to this snapshot id, this manifest revision and this
 * WAL continuation point; the signature verifies against the PUBLIC KEY OF
 * THE RECORDED SIGNER as it is enrolled right now; the data section and the
 * WAL section each match their recorded SHA-384; and the WAL section is
 * structurally whole.  Only then is the dataset replaced through the KV
 * layer's authorization gate — which denies the whole load if any record is
 * outside the caller's clearance/SCI, leaving the live dataset untouched —
 * and the WAL segment replayed in LSN order, through the same gate, with
 * records below the continuation point skipped (idempotent-safe, the
 * qihse_wal_replay() start-LSN rule) and a clearance pre-flight over every
 * record run BEFORE the dataset is replaced.  A truncated or mid-record WAL
 * tail is refused whole rather than partially applied.
 *
 * The identity record is re-read at restore time (so a revocation after the
 * write takes effect immediately, the way
 * qihse_federation_node_capability_lookup_admissible() re-checks trust), the
 * enrolled key's fingerprint must equal the recorded one, and the trust
 * state must be APPROVED.  An unknown, unapproved or revoked signer, a
 * mismatched fingerprint, or a tampered, stripped or absent signature is
 * refused with QIHSE_BACKUP_ERR_SIGNATURE and nothing is applied.
 *
 * `operator_override` is the single, explicit exception, and it is narrow:
 * it skips ONLY the signature and signer-admissibility gate above.  It is
 * offered only to a principal holding QIHSE_SCOPE_SECURITY_ADMIN (an
 * operator holds it implicitly) — anyone else passing true is refused with
 * QIHSE_BACKUP_ERR_DENIED outright.  The manifest gate, the version,
 * structural and length checks, both checksums, the snapshot/WAL/coverage
 * binding, the WAL structural gate and the KV layer's clearance/SCI load
 * check all still run, so the override can neither bypass classification
 * nor rescue a tampered container.  The default (false) fails closed. */
qihse_backup_result_t qihse_backup_restore_signed(void* store_void, void* user_void,
                                                  const qihse_snapshot_manifest_t* manifest,
                                                  const char* path,
                                                  bool operator_override,
                                                  qihse_backup_descriptor_t* out);

/* Verify a container without restoring it: checks the container's structure
 * and declared-versus-present lengths, its version, its data section and
 * its WAL section against their recorded SHA-384 digests, the WAL section's
 * structural coherence (per-record CRC32, bounded lengths, strictly
 * increasing LSNs, first/last LSN agreeing with the header, first record no
 * later than the recorded continuation point), and the signature against
 * the recorded signer's enrolled key with the signer's admissibility
 * re-checked (APPROVED right now).  As an authenticated principal (a
 * fednode lookup and the container's metadata are the inputs; NULL is an
 * argument error, never a bypass).
 *
 * The payload is never materialized and the WAL section is never applied:
 * the data section is streamed through the digest in bounded chunks, the
 * bounded WAL section is checked in a single heap buffer, no scratch file is
 * created, and the store is neither opened for load nor written.  On success
 * `out` (optional, zeroed on entry) carries the container's claims —
 * including the signer identity and the WAL section's LSN range — so a
 * caller can compare them against the manifest it holds without restoring. */
qihse_backup_result_t qihse_backup_verify(void* store_void, void* user_void,
                                          const char* path,
                                          qihse_backup_descriptor_t* out);

#ifdef __cplusplus
}
#endif
#endif
