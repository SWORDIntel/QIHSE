#ifndef QIHSE_CT1_RECOVERY_MANIFEST_H
#define QIHSE_CT1_RECOVERY_MANIFEST_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "qihse_auth.h"

#ifdef __cplusplus
extern "C" {
#endif

#define QIHSE_CT1_RECOVERY_ID_MAX 64u
#define QIHSE_CT1_RECOVERY_SOURCE_FILES 8u
#define QIHSE_CT1_RECOVERY_TARGET_FILES 7u
#define QIHSE_CT1_RECOVERY_FILE_NAME_MAX 64u
#define QIHSE_CT1_RECOVERY_WIRE_SIZE 2624u
#define QIHSE_CT1_RECOVERY_MAX_AGE_MS 900000u
#define QIHSE_CT1_RECOVERY_FRAME_BYTES 1644u
#define QIHSE_CT1_RECOVERY_ARCHIVE_BYTES \
    (QIHSE_CT1_RECOVERY_WIRE_SIZE + QIHSE_CT1_RECOVERY_FRAME_BYTES)
#define QIHSE_CT1_RECOVERY_FILE_SIZE_MAX (UINT64_C(1) << 40)

/* Kind is checked against the exact canonical native basename. SSTable
 * indexes must be canonical decimal; source/target rosters must have the
 * complete B shape. Arbitrary paths and sidecars are denied. */
typedef enum {
    QIHSE_CT1_FILE_WAL = 1, QIHSE_CT1_FILE_CT_STATE = 2,
    QIHSE_CT1_FILE_BASELINE = 3, QIHSE_CT1_FILE_SSTABLE = 4,
    QIHSE_CT1_FILE_REPLICA_CURSORS = 5,
    QIHSE_CT1_FILE_RESTORE_HIGHWATER = 6,
    QIHSE_CT1_FILE_SLOT_JOURNAL = 7,
    QIHSE_CT1_FILE_SLOT_JOURNAL_LOCK = 8
} qihse_ct1_file_kind_t;
typedef struct {
    uint8_t kind;
    char filename[QIHSE_CT1_RECOVERY_FILE_NAME_MAX + 1u];
    uint64_t size;
    unsigned char sha256[32];
} qihse_ct1_recovery_file_t;

#define QIHSE_CT1_RECOVERY_VERIFY 1u

/* These are evidence descriptors, NOT an authorization capability. IDs are
 * exact provisioned QKP identities; pins must be independently checked against
 * the live trusted configuration. Digests are SHA-256 of whole frozen files,
 * the exact source frame, and the source baseline, respectively. Labels are
 * metadata only: parsing never authorizes access to protected frame bytes. */
typedef struct {
    char issuer_qkp_id[QIHSE_CT1_RECOVERY_ID_MAX + 1u];
    char source_qkp_id[QIHSE_CT1_RECOVERY_ID_MAX + 1u];
    char target_qkp_id[QIHSE_CT1_RECOVERY_ID_MAX + 1u];
    char generation[QIHSE_CT1_RECOVERY_ID_MAX + 1u];
    char source_store_id[QIHSE_CT1_RECOVERY_ID_MAX + 1u];
    char target_store_id[QIHSE_CT1_RECOVERY_ID_MAX + 1u];
    char replication_principal_id[QIHSE_CT1_RECOVERY_ID_MAX + 1u];
    char row_key[QIHSE_CT1_RECOVERY_ID_MAX + 1u];
    char source_peer_qkp_id[QIHSE_CT1_RECOVERY_ID_MAX + 1u];
    char target_peer_qkp_id[QIHSE_CT1_RECOVERY_ID_MAX + 1u];
    unsigned char issuer_operator_pin[32];
    unsigned char source_peer_pin[32], target_peer_pin[32];
    qihse_ct1_recovery_file_t source_files[QIHSE_CT1_RECOVERY_SOURCE_FILES];
    qihse_ct1_recovery_file_t target_files[QIHSE_CT1_RECOVERY_TARGET_FILES];
    unsigned char frame_sha256[32], baseline_sha256[32], nonce[32];
    uint64_t epoch, issued_ms, expires_ms;
    uint64_t frame_offset, frame_length, frame_position, baseline_row_seq;
    uint64_t target_cursor, target_high_water, source_high_water;
    uint64_t row_change_seq, tombstone_position, tombstone_row_seq;
    uint32_t row_tenant_id, principal_tenant_id;
    uint16_t classification, sci, principal_classification, principal_sci;
    uint16_t operation;
} qihse_ct1_recovery_manifest_t;

/* Fixed-size canonical v2 wire record. Receipt has the same evidence plus a
 * durable spent bit. SHA-256 trailer detects corruption only; it is NOT a MAC
 * or issuer signature. Both encode and decode reject invalid records. */
bool qihse_ct1_recovery_encode(const qihse_ct1_recovery_manifest_t* manifest,
    bool receipt, bool spent, unsigned char out[QIHSE_CT1_RECOVERY_WIRE_SIZE]);
bool qihse_ct1_recovery_decode(const unsigned char* data, size_t length,
    bool receipt, qihse_ct1_recovery_manifest_t* out, bool* out_spent);
/* Rejects stale/mismatched/replayed evidence; expected MUST come from a
 * separately trusted authority, not the untrusted record or a caller hash.
 * This is only a structural comparison, never QKP authorization. */
bool qihse_ct1_recovery_matches(const qihse_ct1_recovery_manifest_t* actual,
    const qihse_ct1_recovery_manifest_t* expected, uint64_t now_ms, bool spent);
/* Exclusive new file creation under a private caller-owned directory, with
 * trusted non-writable, non-symlink ancestors. Receipts require a persistent
 * basename.lock sidecar; existing receipts without it fail closed. */
bool qihse_ct1_recovery_create(const char* path,
    const qihse_ct1_recovery_manifest_t* manifest, bool receipt);
bool qihse_ct1_recovery_load(const char* path, bool receipt,
    qihse_ct1_recovery_manifest_t* out, bool* out_spent);
/* Bookkeeping ONLY: serializes cross-process spend on basename.lock; fsyncs
 * irreversible intent then a complete replacement and parent directory.
 * An uncertain spend cannot be retried; an unspent receipt with intent denies
 * load/spend. No protection against same-UID rollback of the trusted directory.
 * Does not authorize recovery or mint a token; never perform protected work
 * based on this return value. */
bool qihse_ct1_recovery_spend(const char* path,
    const qihse_ct1_recovery_manifest_t* expected, uint64_t now_ms);
/* Local bookkeeping only, never an approval/authorization. Explicit bootstrap
 * creates a new, NON-AUTHORITATIVE empty ledger for one local node and one
 * source/target/generation tuple; it must only be called after an independent
 * trusted rollback check. Recreating a missing ledger can erase replay history.
 * consume requires an existing ledger and a separately authenticated manifest;
 * caller-provided time is NOT trusted here. A successful consume is not an
 * authorization capability. Both functions require a private trusted directory.
 * At most 1024 fixed-size entries; failure/uncertain intent denies retry. */
bool qihse_ct1_recovery_ledger_bootstrap(const char* path,
    const char* local_node, const qihse_ct1_recovery_manifest_t* manifest);
bool qihse_ct1_recovery_ledger_consume(const char* path,
    const char* local_node, const qihse_ct1_recovery_manifest_t* manifest,
    uint64_t caller_now_ms);
/* Structural evidence only: independently stream-hash the complete source or
 * target roster in a caller-supplied frozen directory. The files may contain
 * mixed tenants and all uint16_t labels: require an active, system-tenant
 * principal with maximum clearance/SCI, not the manifest's single-row label.
 * Never grants recovery or issuer authority. Requires private, caller-owned
 * regular files and a private directory under trusted ancestors. */
bool qihse_ct1_recovery_verify_frozen(const qihse_user_t* principal,
    const char* frozen_dir, const qihse_ct1_recovery_manifest_t* manifest,
    bool source);
/* INSECURE DEVELOPMENT-ONLY API: compiled only for disposable fixtures.
 * No authenticated security context or clearance/SCI check exists here.
 * Do not enable for production or use with classified frames. Verify reads
 * frame bytes internally for hashing but never returns them. File privacy
 * relies on OS ownership/mode, not clearance/SCI.
 * Archive is one exclusive private file: canonical B manifest wire followed
 * by exactly 1644 frame bytes. Reopen requires the same complete manifest,
 * exact size and frame digest. Failure leaves the artifact in place; no
 * rollback protection. Neither return authorizes recovery, ACK, suppression
 * or target apply. */
#ifdef QIHSE_CT1_INSECURE_DEV_ARCHIVE
bool qihse_ct1_recovery_archive_create(const char* path,
    const qihse_ct1_recovery_manifest_t* manifest,
    const unsigned char* frame, size_t frame_length);
bool qihse_ct1_recovery_archive_verify(const char* path,
    const qihse_ct1_recovery_manifest_t* manifest);
#endif
/* Deliberately fail-closed integration hook. Actual approval requires QKP
 * Operator issuer authentication, current pin checks and RESP/core policy. */
bool qihse_ct1_recovery_issuer_authorized(void);

#ifdef __cplusplus
}
#endif
#endif
