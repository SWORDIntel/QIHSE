#ifndef QIHSE_AUTH_ARCHIVE_CRYPTO_H
#define QIHSE_AUTH_ARCHIVE_CRYPTO_H
#include "qihse_auth_archive.h"
/* Memory only. Complete header and KEM are GCM AAD; signature is checked
 * before decapsulation or plaintext allocation. Lifecycle lock is required.
 * Decrypt returns OPENSSL-allocated staging: cleanse plaintext_length bytes
 * with OPENSSL_clear_free after use. No plaintext file is ever created. */
qihse_auth_maintenance_status_t qihse_auth_archive_encrypt(
    const qihse_auth_image_context_t *context,
    const qihse_auth_archive_config_t *config,
    const uint8_t *plaintext, size_t length, uint64_t count,
    uint64_t retry_count, qihse_auth_sealed_t **out);
qihse_auth_maintenance_status_t qihse_auth_archive_decrypt(
    const qihse_auth_image_context_t *context,
    const qihse_auth_archive_config_t *config,
    const uint8_t *sealed, size_t length,
    uint8_t **plaintext, size_t *plaintext_length,
    uint64_t *count, uint64_t *retry_count);
#endif
