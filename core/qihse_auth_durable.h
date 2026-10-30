#ifndef QIHSE_AUTH_DURABLE_H
#define QIHSE_AUTH_DURABLE_H
#include "qihse_auth_maintenance_internal.h"
/* Lifecycle mutex held at all calls except atomic state predicates. */
bool qihse_auth_durable_active(void);
bool qihse_auth_durable_ready(void);
void qihse_auth_durable_fence(void);
void qihse_auth_durable_verified(void);
const uint8_t *qihse_auth_durable_authority_id(void);
const qihse_auth_archive_keys_t *qihse_auth_durable_archive_keys(void);
qihse_auth_position_t qihse_auth_durable_position(void);
bool qihse_auth_durable_image_metadata(const qihse_auth_image_context_t *context,
 qihse_auth_image_t *image);
qihse_auth_maintenance_status_t qihse_auth_durable_open(
 const qihse_auth_startup_config_t *config,
 const qihse_auth_image_context_t *context, qihse_user_t *bootstrap,
 qihse_auth_image_t **image);
qihse_auth_maintenance_status_t qihse_auth_durable_commit(
 const qihse_auth_image_context_t *context, qihse_auth_image_t *image,
 const qihse_user_t *root);
bool qihse_auth_durable_bootstrap(const qihse_auth_image_context_t *context,
 qihse_user_t *root);
const qihse_auth_recovery_t *qihse_auth_durable_recovery_context(void);
/* Auth module pre-serve and atomic publication hooks. */
bool qihse_auth_durable_prepare(const qihse_user_t *root);
void qihse_auth_durable_set_ready(bool ready);
bool qihse_auth_actor_identity(const qihse_user_t *actor,
 uint32_t *uid, uint64_t *generation);
#endif
