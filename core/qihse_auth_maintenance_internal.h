#ifndef QIHSE_AUTH_MAINTENANCE_INTERNAL_H
#define QIHSE_AUTH_MAINTENANCE_INTERNAL_H
#include "qihse_auth_maintenance.h"
#include "qihse_auth_internal.h"
#include <pthread.h>
#define QIHSE_AUTH_IMAGE_MAX_PRINCIPALS 65535u
#define QIHSE_AUTH_RETRY_MAX 128u
typedef struct {
 uint32_t user_id;
 bool active;
 uint64_t generation;
 uint32_t failed_count;
 uint64_t lockout_until;
 qihse_user_t principal;
} qihse_auth_image_row_t;
typedef struct {
 uint8_t request_id[16];
 uint8_t digest[48];
 uint32_t actor_id;
 uint64_t actor_generation;
 qihse_auth_position_t result;
} qihse_auth_retry_t;
/* Temporary owned image, NOT a live catalog. UID0 never appears in rows.
 * Never encode transient token presence, sessions, pointers or cache grants. */
typedef struct {
 qihse_auth_position_t position;
 uint8_t bootstrap_binding[48];
 /* Present only in purpose-bound encrypted local authority snapshots. */
 bool has_local_root;
 qihse_user_t local_root;
 uint64_t root_generation;
 uint32_t root_failed_count;
 uint64_t root_lockout_until;
 size_t count;
 qihse_auth_image_row_t *rows;
 size_t retry_count;
 qihse_auth_retry_t retries[QIHSE_AUTH_RETRY_MAX];
} qihse_auth_image_t;
typedef struct {
 const qihse_user_t *actor;
 const qihse_auth_recovery_t *recovery;
} qihse_auth_image_context_t;
/* Lowest materializing layers revalidate context. Exactly one member non-NULL.
 * Caller holds lifecycle mutex. */
bool qihse_auth_image_context_valid(const qihse_auth_image_context_t *context);
extern pthread_mutex_t qihse_auth_lifecycle_mutex;
void qihse_auth_lifecycle_enter(void);
void qihse_auth_lifecycle_leave(void);
bool qihse_auth_recovery_valid(const qihse_auth_recovery_t *recovery);
bool qihse_auth_maintenance_actor_valid(const qihse_user_t *actor);
void qihse_auth_image_free(qihse_auth_image_t *image);
qihse_auth_maintenance_status_t qihse_auth_image_capture(
 const qihse_auth_image_context_t *context, qihse_auth_image_t **out);
qihse_auth_maintenance_status_t qihse_auth_image_publish(
 const qihse_auth_image_context_t *context, qihse_auth_image_t *image);
qihse_auth_maintenance_status_t qihse_auth_archive_seal(
 const qihse_auth_image_context_t *context, const qihse_auth_image_t *image,
 const qihse_auth_archive_config_t *config, qihse_auth_sealed_t **out);
qihse_auth_maintenance_status_t qihse_auth_archive_open(
 const qihse_auth_image_context_t *context, const uint8_t *sealed, size_t length,
 const qihse_auth_archive_config_t *config, qihse_auth_image_t **out);
qihse_auth_maintenance_status_t qihse_auth_image_encode(
 const qihse_auth_image_context_t *context, const qihse_auth_image_t *image,
 uint8_t **out, size_t *length);
qihse_auth_maintenance_status_t qihse_auth_image_decode(
 const qihse_auth_image_context_t *context, const uint8_t *data, size_t length,
 qihse_auth_image_t **out);
#endif
