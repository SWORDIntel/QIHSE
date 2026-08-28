#ifndef QIHSE_AUTH_H
#define QIHSE_AUTH_H

#include <stdint.h>
#include <stdbool.h>
#include "qihse_rate_limit.h"

#ifdef __cplusplus
extern "C" {
#endif

// Define Roles
#define QIHSE_ROLE_OPERATOR 0  // Full God-Mode Access
#define QIHSE_ROLE_CHUCK    0  // Full God-Mode Access (Supernatural Alias)
#define QIHSE_ROLE_ANALYST  1  // Restricted by Clearance & SCI
#define QIHSE_ROLE_GUEST    2  // Unclassified Only

#define QIHSE_AUTH_HASH_HEX_LEN 96
#define QIHSE_AUTH_HASH_LEN (QIHSE_AUTH_HASH_HEX_LEN + 1)

#define QIHSE_OBJECT_ACL_MAX_ENTRIES 64
#define QIHSE_ACL_READ  0x01u
#define QIHSE_ACL_WRITE 0x02u
#define QIHSE_ACL_ADMIN 0x04u

typedef struct qihse_acl_entry_s {
    uint32_t namespace_id;
    uint64_t resource_id;
    uint8_t access_flags;
} qihse_acl_entry_t;

typedef struct qihse_user_s {
    uint32_t user_id;
    uint16_t role;
    uint16_t classification_level;
    uint16_t sci_compartments;

    // Identity & Permissions
    char username[64];
    bool can_create_users; // Operator can delegate user creation

    // YubiKey / Hardware Token Auth
    bool hardware_token_present;
    bool requires_hardware_token; // Configurable at creation
    char fido2_credential_id[64];

    // Password Auth
    char password_hash[QIHSE_AUTH_HASH_LEN]; // SHA-384 hex hash

    // Per-object ACL. This initial implementation is limited to 64 entries/user.
    qihse_acl_entry_t object_acl[QIHSE_OBJECT_ACL_MAX_ENTRIES];
    uint8_t object_acl_count;
} qihse_user_t;

// Global Auth Context (Simplification for simulation)
void qihse_auth_init(void);

// Create a user. An OPERATOR or a user with `can_create_users` flag can create a user. The system pre-seeds User ID 0 as the God-Mode Operator.
qihse_user_t* qihse_auth_create_user(qihse_user_t* creator, uint32_t user_id, uint16_t role, uint16_t classif, uint16_t sci, const char* plaintext_password, bool requires_hw_token);

qihse_user_t* qihse_auth_get_user(uint32_t user_id);

void qihse_auth_destroy_user(uint32_t user_id);

// Operator can modify any user's settings, passwords, names, and hardware token mandates.
// Use -1 for integers/booleans to indicate "do not change", and NULL for strings to indicate "do not change".
bool qihse_auth_modify_user(qihse_user_t* operator_user, uint32_t target_user_id, const char* new_username, const char* new_password, int new_requires_hw_token, int new_can_create_users);

// Check if a user can access a specific data row's clearance
bool qihse_auth_can_access(qihse_user_t* user, uint16_t data_classif, uint16_t data_sci);

// Check access to an object independently of classification/SCI clearance.
bool qihse_auth_can_access_object(qihse_user_t* user, uint32_t namespace_id, uint64_t resource_id);

// Only an OPERATOR may change another user's object ACL.
bool qihse_auth_grant_object(qihse_user_t* operator_user, qihse_user_t* target_user,
                             uint32_t namespace_id, uint64_t resource_id, uint8_t access_flags);
bool qihse_auth_revoke_object(qihse_user_t* operator_user, qihse_user_t* target_user,
                              uint32_t namespace_id, uint64_t resource_id);

bool qihse_auth_is_operator_password_default(void);
qihse_user_t* qihse_auth_authenticate(const char* username, const char* password);
qihse_user_t* qihse_auth_authenticate_from(uint32_t source_ip, const char* username, const char* password);
qihse_user_t* qihse_auth_authenticate_id(uint32_t user_id, const char* password);

// --- IP-based auth rate limiting (brute-force protection) -------------------
// Defaults: 5 attempts per 60 seconds per source IP. The limiter is
// lazy-initialized on first use and can also be initialized explicitly via
// qihse_auth_init_rate_limiter().
#define QIHSE_AUTH_RATE_LIMIT_DEFAULT_MAX_ATTEMPTS 5
#define QIHSE_AUTH_RATE_LIMIT_DEFAULT_WINDOW_SEC  60
#define QIHSE_AUTH_RATE_LIMIT_DEFAULT_MAX_ENTRIES 1024

void qihse_auth_init_rate_limiter(uint32_t max_attempts, uint32_t window_seconds, size_t max_entries);
void qihse_auth_shutdown_rate_limiter(void);

// Returns true if an auth attempt from source_ip is allowed, false if it is
// rate-limited. Each call increments the per-IP attempt counter.
bool qihse_auth_check_rate_limit(uint32_t source_ip);

// Reset the per-IP counter (call on successful authentication).
void qihse_auth_rate_limit_reset(uint32_t source_ip);

// Remove stale entries from the rate limiter (safe to call periodically).
void qihse_auth_rate_limit_cleanup(void);

#ifdef __cplusplus
}
#endif

#endif // QIHSE_AUTH_H
