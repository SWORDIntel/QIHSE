#ifndef QIHSE_PRINCIPAL_RECORD_H
#define QIHSE_PRINCIPAL_RECORD_H

#include "qihse_auth_internal.h"
#include <stddef.h>
#include <stdint.h>

/* Canonical principal-log payload. The enclosing consensus entry supplies
 * ordering and durability; this record supplies mutation identity and the
 * complete authorization state. User 0 is deliberately excluded. */
#define QIHSE_PRINCIPAL_RECORD_VERSION 1u
#define QIHSE_PRINCIPAL_RECORD_MAX_BYTES 2048u

typedef enum {
    QIHSE_PRINCIPAL_PUT = 1,
    QIHSE_PRINCIPAL_DELETE = 2
} qihse_principal_record_kind_t;

typedef struct {
    qihse_principal_record_kind_t kind;
    uint8_t request_id[16];
    uint64_t expected_registry_generation;
    uint32_t actor_id;
    uint64_t actor_generation;
    uint64_t principal_generation;
    uint32_t target_id;
    /* Valid only for PUT. Never store a plaintext password here. */
    qihse_user_t principal;
} qihse_principal_record_t;

/* Validate durable principal fields without fabricating a mutation record.
 * allow_root permits only a system/full-clearance Operator UID0 for a
 * separately trusted local bootstrap codec. The record codec below still
 * forbids UID0. This grants no authorization. */
bool qihse_principal_fields_valid(const qihse_user_t* user, bool allow_root);

/* Returns false for malformed, unsupported, or noncanonical records. The
 * decoder clears out before returning failure. Neither function performs
 * authorization or commits a mutation. */
bool qihse_principal_record_encode(const qihse_principal_record_t* record,
                                   uint8_t* out, size_t out_cap,
                                   size_t* out_len);
bool qihse_principal_record_decode(const uint8_t* data, size_t data_len,
                                   qihse_principal_record_t* out);

/* Ordered-apply policy gate for a decoded, committed record. The caller must
 * supply actor and target snapshots from the immediately preceding applied
 * registry state. A NULL target means this ID has never existed; deleted IDs
 * retain their last generation and cannot be reused. This checks authority
 * and generation only: the registry service must additionally prove the
 * commit prefix, deduplicate request IDs, and enforce username uniqueness
 * before changing its state. It must never authorize from an uncommitted
 * proposal or a caller-supplied principal handle. */
bool qihse_principal_record_authorize_transition(
    const qihse_principal_record_t* record,
    uint64_t registry_generation,
    const qihse_user_t* actor, uint64_t actor_generation,
    const qihse_user_t* target, uint64_t target_generation);

#endif
