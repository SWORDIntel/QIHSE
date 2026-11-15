#ifndef QIHSE_SHARED_BACKUP_H
#define QIHSE_SHARED_BACKUP_H

#include "qihse_backup.h"
#include "qihse_blob.h"
#include "qihse_table_store.h"
#include "qihse_txn.h"

#ifdef __cplusplus
extern "C" {
#endif

#define QIHSE_SHARED_BACKUP_KEY_BYTES 48u
#define QIHSE_SHARED_BACKUP_MAX_MEMBERS 4096u
#define QIHSE_SHARED_BACKUP_MAX_PAYLOAD_BYTES (UINT64_C(3) << 30)
#define QIHSE_SHARED_BACKUP_KV_FILE "kv.qbp"
#define QIHSE_SHARED_BACKUP_SQL_FILE "sql.qts"
#define QIHSE_SHARED_BACKUP_BLOB_FILE "blob.qba"
#define QIHSE_SHARED_BACKUP_JOURNAL_FILE "coordinator.qtj"
#define QIHSE_SHARED_BACKUP_MANIFEST_FILE "manifest.qsb"

typedef struct {
    qihse_kv_store_t* kv;
    qihse_table_store_t* sql;
    qihse_blob_store_t* blob;
    qihse_txn_manager_t* coordinator;
    uint8_t sql_engine_id;
    uint8_t blob_engine_id;
} qihse_shared_backup_sources_t;

typedef struct {
    qihse_kv_snapshot_checkpoint_t kv;
    uint64_t sql_epoch;
    uint64_t blob_epoch;
    qihse_txn_backup_checkpoint_t coordinator;
    uint8_t sql_engine_id;
    uint8_t blob_engine_id;
    uint32_t member_count;
    uint64_t payload_bytes;
} qihse_shared_backup_info_t;

typedef enum {
    QIHSE_SHARED_BACKUP_ERROR = 0,
    QIHSE_SHARED_BACKUP_OK = 1,
    QIHSE_SHARED_BACKUP_PUBLISHED_UNSYNCED = 2
} qihse_shared_backup_result_t;

/* Local, CT-disabled durable sources only. Bootstrap Operator id0/tenant0 and
 * complete native-export authorization are required. The caller retains the
 * SAME live handles and user for the entire call and supplies the SQL/blob
 * engine IDs registered on this coordinator. No automatic retries are made.
 *
 * All starting checkpoints precede every native export; all ending checkpoints
 * follow every export. A mutation within that bracket, unresolved decision,
 * principal-generation change or invalid checkpoint rejects the whole attempt.
 * KV TTL visibility is
 * defined at the native KV snapshot's capture point in that common interval.
 *
 * A portable HMAC-SHA-384 manifest authenticates the checkpoints, declared
 * engine bindings, canonical member names, lengths and SHA-384 content hashes.
 * This authenticates but DOES NOT ENCRYPT classified payloads. The caller owns
 * exactly 48 random secret key bytes, key distribution and key retention.
 * This does not separately collect principal authority, external private keys,
 * ACL authority or service configuration. Native payloads retain authorized
 * application data as-is. It is not a full MVCC/distributed/service image.
 *
 * Export and unpack create a private sibling stage and publish once using
 * no-replace atomic directory rename, never replacing an existing destination.
 * PUBLISHED_UNSYNCED means the destination is visible but parent durability is
 * uncertain: do not blindly retry or remove it. ERROR leaves an optional *info
 * unchanged; successful publication (including UNSYNCED) fills it when non-NULL.
 */
qihse_shared_backup_result_t qihse_shared_backup_export_user(
    const char* destination, const qihse_shared_backup_sources_t* sources,
    qihse_user_t* user, const uint8_t* key, size_t key_length,
    qihse_shared_backup_info_t* info);

/* Verify only authenticated package structure/content, not engine replay or
 * deployment readiness. Reject unknown/duplicate/traversal members, links,
 * malformed manifests, wrong keys, altered content and incomplete authorization.
 * No protected metadata is returned on denial. Optional *info stays unchanged
 * on failure. */
bool qihse_shared_backup_verify_user(const char* bundle, qihse_user_t* user,
    const uint8_t* key, size_t key_length, qihse_shared_backup_info_t* info);

/* Authenticate and copy the native payload package to a fresh destination;
 * rehash copied bytes before publication. This does NOT apply into live stores.
 * Restore each payload through its native authenticated API in a fresh process,
 * register the manifest's engine IDs, advance the coordinator floor to at least
 * info.coordinator.next_txn_id and above every participant receipt BEFORE recovery,
 * and finish common-decision replay before exposing the restored application.
 * Output payload names are the constants above; SQL receipt sidecars accompany
 * sql.qts. Verification/unpacking alone is not proof of a successful restore. */
qihse_shared_backup_result_t qihse_shared_backup_unpack_user(
    const char* bundle, const char* destination, qihse_user_t* user,
    const uint8_t* key, size_t key_length, qihse_shared_backup_info_t* info);

#ifdef __cplusplus
}
#endif
#endif /* QIHSE_SHARED_BACKUP_H */
