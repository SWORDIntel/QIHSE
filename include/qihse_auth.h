#ifndef QIHSE_AUTH_H
#define QIHSE_AUTH_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "qihse_rate_limit.h"

#ifdef __cplusplus
extern "C" {
#endif

// Define Roles
#define QIHSE_ROLE_OPERATOR 0  // Full God-Mode Access
#define QIHSE_ROLE_CHUCK    0  // Full God-Mode Access (Supernatural Alias)
#define QIHSE_ROLE_ANALYST  1  // Restricted by Clearance & SCI
#define QIHSE_ROLE_GUEST    2  // Unclassified Only

// CNSA 2.0 / FIPS-aligned PBKDF2 Password Parameters
#define QIHSE_PW_ALGORITHM       "PBKDF2-HMAC-SHA384"
#define QIHSE_PW_SALT_BYTES      16
#define QIHSE_PW_HASH_BYTES      48
#define QIHSE_PW_MIN_ITERATIONS  600000

#define QIHSE_AUTH_USERNAME_MAX  64
#define QIHSE_OBJECT_ACL_MAX_ENTRIES 64
#define QIHSE_ACL_READ  0x01u
#define QIHSE_ACL_WRITE 0x02u
#define QIHSE_ACL_ADMIN 0x04u

typedef struct qihse_acl_entry_s {
    uint32_t namespace_id;
    uint64_t resource_id;
    uint8_t access_flags;
} qihse_acl_entry_t;

// Opaque user handle. Internal representation is isolated in core/qihse_auth_internal.h.
typedef struct qihse_user_s qihse_user_t;

// Global Auth Context
void qihse_auth_init(void);

// Bootstrap system operator with explicit password.
bool qihse_auth_bootstrap_operator(const char* initial_password);

// Create a user. An OPERATOR or a user with `can_create_users` flag can create a user.
qihse_user_t* qihse_auth_create_user(const qihse_user_t* creator, uint32_t user_id, uint16_t role, uint16_t classif, uint16_t sci, const char* plaintext_password, bool requires_hw_token);

qihse_user_t* qihse_auth_get_user(uint32_t user_id);

// Only an OPERATOR may destroy a user.
bool qihse_auth_destroy_user(const qihse_user_t* actor, uint32_t target_user_id);

// Operator can modify any user's settings, passwords, names, and hardware token mandates.
// Use -1 for integers/booleans to indicate "do not change", and NULL for strings to indicate "do not change".
bool qihse_auth_modify_user(const qihse_user_t* operator_user, uint32_t target_user_id, const char* new_username, const char* new_password, int new_requires_hw_token, int new_can_create_users);

// Set hardware token state on user.
bool qihse_auth_set_hardware_token(qihse_user_t* user, bool present, const char* credential_id);

// Check if a user can access a specific data row's clearance
bool qihse_auth_can_access(const qihse_user_t* user, uint16_t data_classif, uint16_t data_sci);

// Check access to an object requiring specific access flags (QIHSE_ACL_READ, QIHSE_ACL_WRITE, QIHSE_ACL_ADMIN)
bool qihse_auth_can_access_object(const qihse_user_t* user, uint32_t namespace_id, uint64_t resource_id, uint8_t required_flags);

// Only an OPERATOR may change another user's object ACL.
bool qihse_auth_grant_object(const qihse_user_t* operator_user, qihse_user_t* target_user,
                             uint32_t namespace_id, uint64_t resource_id, uint8_t access_flags);
bool qihse_auth_revoke_object(const qihse_user_t* operator_user, qihse_user_t* target_user,
                              uint32_t namespace_id, uint64_t resource_id);

bool qihse_auth_is_operator_password_default(void);
qihse_user_t* qihse_auth_authenticate(const char* username, const char* password);
qihse_user_t* qihse_auth_authenticate_from(uint32_t source_ip, const char* username, const char* password);
qihse_user_t* qihse_auth_authenticate_id(uint32_t user_id, const char* password);
qihse_user_t* qihse_auth_authenticate_id_from(uint32_t source_ip, uint32_t user_id, const char* password);

// Read-only user accessors (authoritatively resolved)
uint32_t qihse_user_get_id(const qihse_user_t* user);
uint16_t qihse_user_get_role(const qihse_user_t* user);
uint16_t qihse_user_get_classification(const qihse_user_t* user);
uint16_t qihse_user_get_sci(const qihse_user_t* user);
const char* qihse_user_get_username(const qihse_user_t* user);
bool qihse_user_has_hardware_token(const qihse_user_t* user);
bool qihse_user_requires_hardware_token(const qihse_user_t* user);
bool qihse_user_can_create_users(const qihse_user_t* user);

// --- IP-based auth rate limiting (brute-force protection) -------------------
#define QIHSE_AUTH_RATE_LIMIT_DEFAULT_MAX_ATTEMPTS 5
#define QIHSE_AUTH_RATE_LIMIT_DEFAULT_WINDOW_SEC  60
#define QIHSE_AUTH_RATE_LIMIT_DEFAULT_MAX_ENTRIES 1024

void qihse_auth_init_rate_limiter(uint32_t max_attempts, uint32_t window_seconds, size_t max_entries);
void qihse_auth_shutdown_rate_limiter(void);

bool qihse_auth_check_rate_limit(uint32_t source_ip);
void qihse_auth_rate_limit_reset(uint32_t source_ip);
void qihse_auth_rate_limit_cleanup(void);

#ifdef __cplusplus
}
#endif

#endif // QIHSE_AUTH_H
