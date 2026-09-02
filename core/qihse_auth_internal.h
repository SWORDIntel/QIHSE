#ifndef QIHSE_AUTH_INTERNAL_H
#define QIHSE_AUTH_INTERNAL_H

#include "qihse_auth.h"
#include <stdbool.h>
#include <stdint.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint16_t version;
    uint16_t algorithm;
    uint32_t iterations;
    uint8_t salt[QIHSE_PW_SALT_BYTES];
    uint8_t verifier[QIHSE_PW_HASH_BYTES];
} qihse_password_verifier_t;

struct qihse_user_s {
    uint32_t user_id;
    uint16_t role;
    uint16_t classification_level;
    uint16_t sci_compartments;

    // Identity & Permissions
    char username[64];
    bool can_create_users;

    // YubiKey / Hardware Token Auth
    bool hardware_token_present;
    bool requires_hardware_token;
    char fido2_credential_id[64];

    // Password Verifier (PBKDF2-HMAC-SHA-384)
    qihse_password_verifier_t verifier;
    bool password_set;

    // Per-object ACL
    qihse_acl_entry_t object_acl[QIHSE_OBJECT_ACL_MAX_ENTRIES];
    uint8_t object_acl_count;
};

// Internal password derivation and verification primitives
bool qihse_password_compute(const char* password, uint32_t iterations, qihse_password_verifier_t* out_verifier);
bool qihse_password_verify(const char* password, const qihse_password_verifier_t* verifier);

#ifdef __cplusplus
}
#endif

#endif // QIHSE_AUTH_INTERNAL_H
