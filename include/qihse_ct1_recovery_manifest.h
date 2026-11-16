#ifndef QIHSE_CT1_RECOVERY_MANIFEST_H
#define QIHSE_CT1_RECOVERY_MANIFEST_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

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
    uint64_t row_change_seq, tombstone_position;
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
/* Exclusive new file creation, fd fsync and parent directory fsync. Does not
 * replace a preexisting receipt; a partial or failed write remains unusable. */
bool qihse_ct1_recovery_create(const char* path,
    const qihse_ct1_recovery_manifest_t* manifest, bool receipt);
bool qihse_ct1_recovery_load(const char* path, bool receipt,
    qihse_ct1_recovery_manifest_t* out, bool* out_spent);
/* Bookkeeping ONLY: marks a receipt spent with an fsynced write, failing
 * closed on torn records or I/O errors. Does not authorize recovery or mint a
 * token. Caller must not perform protected work based on this return value. */
bool qihse_ct1_recovery_spend(const char* path,
    const qihse_ct1_recovery_manifest_t* expected, uint64_t now_ms);
/* Deliberately fail-closed integration hook. Actual approval requires QKP
 * Operator issuer authentication, current pin checks and RESP/core policy. */
bool qihse_ct1_recovery_issuer_authorized(void);

#ifdef __cplusplus
}
#endif
#endif
