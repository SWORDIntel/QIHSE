#ifndef QIHSE_AUTH_MAINTENANCE_H
#define QIHSE_AUTH_MAINTENANCE_H
#include "qihse_auth.h"
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#ifdef __cplusplus
extern "C" {
#endif
/* Durable handle contract (applies to ordinary qihse_auth.h mutators too):
 * successful password/bootstrap, username, ACL, clearance/SCI, delegation,
 * token-requirement or token-enrollment changes invalidate every old handle
 * for the target, including UID0's own actor/session. Reauthenticate; never
 * upgrade an existing session merely by looking up the same UID. Creation
 * returns the actual current handle. Transient token presence and lockout
 * counters do not invalidate handles. Volatile mode keeps legacy pointer
 * semantics. Import invalidates all nonroot handles, even unchanged rows.
 * Replacement allocation and retirement capacity are checked before durable
 * commit. Policy rotation/deletion and import share a process-lifetime bound
 * of 65536 retired allocations; exhaustion fails without committing. Retired
 * raw handles are never freed, reused or modified, even after scoped release:
 * unscoped readers cannot be counted. Their secret-bearing payload remains
 * resident until process exit; protect process memory accordingly. */
/* Standalone authority is never a consensus prefix. */
typedef enum { QIHSE_AUTH_AUTHORITY_DISABLED = 0,
 QIHSE_AUTH_AUTHORITY_STANDALONE = 1,
 QIHSE_AUTH_AUTHORITY_CONSENSUS = 2 } qihse_auth_authority_mode_t;
typedef enum { QIHSE_AUTH_MAINT_OK = 0, QIHSE_AUTH_MAINT_INVALID,
 QIHSE_AUTH_MAINT_DENIED, QIHSE_AUTH_MAINT_UNSUPPORTED,
 QIHSE_AUTH_MAINT_NOT_READY, QIHSE_AUTH_MAINT_CONFLICT,
 QIHSE_AUTH_MAINT_IO, QIHSE_AUTH_MAINT_CORRUPT,
 QIHSE_AUTH_MAINT_LIMIT, QIHSE_AUTH_MAINT_UNCERTAIN } qihse_auth_maintenance_status_t;
typedef enum { QIHSE_AUTH_START_PROVISION = 1,
 QIHSE_AUTH_START_RECOVER = 2 } qihse_auth_start_action_t;
typedef struct qihse_auth_recovery qihse_auth_recovery_t;
typedef struct qihse_auth_sealed qihse_auth_sealed_t;
#define QIHSE_AUTH_HISTORY_BYTES 16u
#define QIHSE_AUTH_ARCHIVE_MAX_BYTES (160u * 1024u * 1024u)
typedef struct {
 uint8_t history[QIHSE_AUTH_HISTORY_BYTES];
 uint8_t node[16];
 uint64_t epoch;
 uint64_t generation;
} qihse_auth_position_t;
#define QIHSE_AUTH_ARCHIVE_VERSION 1u
#define QIHSE_AUTH_ARCHIVE_PURPOSE_DURABLE 1u
#define QIHSE_AUTH_ARCHIVE_PURPOSE_TRANSFER 2u
/* Pins are SHA-384 of DER SubjectPublicKeyInfo. No implicit key lookup. */
typedef struct {
 const char *recipient_public_file;
 const char *recipient_private_file;
 const char *signer_private_file;
 const char *signer_public_file;
 uint8_t recipient_pin[48];
 uint8_t signer_pin[48];
} qihse_auth_archive_keys_t;
typedef struct {
 uint32_t version;
 uint32_t purpose;
 qihse_auth_authority_mode_t mode;
 uint8_t source_authority[16];
 qihse_auth_position_t source;
 uint8_t target_authority[16];
 qihse_auth_position_t target;
 uint8_t archive_id[16];
 bool allow_node_relocation;
} qihse_auth_archive_binding_t;
typedef struct qihse_auth_archive_config {
 qihse_auth_archive_keys_t keys;
 qihse_auth_archive_binding_t binding;
} qihse_auth_archive_config_t;
/* Protected startup only, before ordinary auth initialization. Bootstrap
 * verifier is loaded from a private file, never re-derived at boot. */
typedef struct {
 qihse_auth_authority_mode_t mode;
 qihse_auth_start_action_t action;
 const char *state_directory;
 const char *bootstrap_file;
 qihse_auth_archive_keys_t archive_keys;
 /* Explicit transfer trust; distinct from local persistence recipient keys. */
 qihse_auth_archive_keys_t transfer_keys;
 uint8_t authority_id[16];
 uint64_t minimum_generation;
 uint8_t node[16];
 uint64_t epoch;
 /* Required on recover. Provision: zero creates a fresh history; an explicit
  * existing history prepares a new recipient node of that same authority. */
 uint8_t expected_history[16];
} qihse_auth_startup_config_t;
typedef struct {
 qihse_auth_authority_mode_t mode;
 bool ready;
 bool export_supported;
 bool import_supported;
 bool checkpoint_supported;
 qihse_auth_position_t position;
} qihse_auth_maintenance_caps_t;
/* Offline, create-only private bootstrap provisioning. Passwords are never
 * persisted; normal verifier derivation and policy checks apply. */
qihse_auth_maintenance_status_t qihse_auth_bootstrap_provision(
 const char *file, const char *username, const char *password,
 bool requires_hardware_token, const char *credential_id, bool can_create_users);
qihse_auth_maintenance_status_t qihse_auth_maintenance_start(
 const qihse_auth_startup_config_t *config, qihse_auth_recovery_t **out);
void qihse_auth_maintenance_recovery_release(qihse_auth_recovery_t *recovery);
qihse_auth_maintenance_status_t qihse_auth_maintenance_capabilities(
 const qihse_user_t *actor, qihse_auth_maintenance_caps_t *out);
/* Resolves only operator-configured, pinned transfer keys, never wire paths. */
qihse_auth_maintenance_status_t qihse_auth_maintenance_transfer_config(
 const qihse_user_t *actor, const qihse_auth_archive_binding_t *binding,
 const uint8_t recipient_pin[48], const uint8_t signer_pin[48],
 qihse_auth_archive_config_t *out);
qihse_auth_maintenance_status_t qihse_auth_maintenance_export(
 const qihse_user_t *actor, const qihse_auth_position_t *expected,
 const qihse_auth_archive_config_t *transfer, qihse_auth_sealed_t **out);
qihse_auth_maintenance_status_t qihse_auth_maintenance_checkpoint(
 const qihse_user_t *actor, const qihse_auth_position_t *expected,
 qihse_auth_position_t *out);
/* Mandatory request identity; identical retries return the durable result,
 * conflicting reuse fails. Protected UID0 bootstrap is never imported. */
qihse_auth_maintenance_status_t qihse_auth_maintenance_import(
 const qihse_user_t *actor, const qihse_auth_position_t *expected,
 const uint8_t request_id[16], const qihse_auth_archive_config_t *transfer,
 const uint8_t *sealed, size_t sealed_len,
 qihse_auth_position_t *out);
qihse_auth_maintenance_status_t qihse_auth_maintenance_recover_import(
 qihse_auth_recovery_t *recovery, const qihse_auth_position_t *expected,
 const uint8_t request_id[16], const qihse_auth_archive_config_t *transfer,
 const uint8_t *sealed, size_t sealed_len,
 qihse_auth_position_t *out);
/* Immutable bounded ciphertext only. */
const uint8_t *qihse_auth_sealed_data(const qihse_auth_sealed_t *sealed);
size_t qihse_auth_sealed_size(const qihse_auth_sealed_t *sealed);
void qihse_auth_sealed_free(qihse_auth_sealed_t *sealed);
const char *qihse_auth_maintenance_status_string(qihse_auth_maintenance_status_t status);
#ifdef __cplusplus
}
#endif
#endif
