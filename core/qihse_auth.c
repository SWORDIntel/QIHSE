#include "qihse_auth.h"
#include "qihse_audit.h"
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <stdio.h>
#include <time.h>
#include <openssl/sha.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#ifndef _WIN32
#include <sys/mman.h>
#endif

#define MAX_USERS 1024
#define MAX_AUTH_ATTEMPTS 5
#define AUTH_LOCKOUT_SECONDS 300

typedef struct {
    uint32_t failed_count;
    time_t lockout_until;
} auth_rate_limit_t;

/*
 * qihse_user_t is part of the public ABI and callers can therefore mutate a
 * returned structure. Never use privilege-bearing fields from that public
 * object as the authority for delegated administration. Keep the canonical
 * authorization state private to this module and resolve presented user
 * handles back to a registered slot by pointer identity.
 */
typedef struct {
    bool active;
    uint16_t role;
    uint16_t classification_level;
    uint16_t sci_compartments;
    bool requires_hardware_token;
    bool can_create_users;
} authz_state_t;

static qihse_user_t* users[MAX_USERS];
static authz_state_t authz_states[MAX_USERS];
static pthread_mutex_t auth_mutex = PTHREAD_MUTEX_INITIALIZER;
static uint32_t active_user_count = 0;
static auth_rate_limit_t rate_limits[MAX_USERS];

static bool constant_time_compare(const char *a, const char *b, size_t len) {
    volatile unsigned char diff = 0;
    for (size_t i = 0; i < len; i++) {
        diff |= (unsigned char)(a[i] ^ b[i]);
    }
    return diff == 0;
}

static void compute_sha384_hex(const char *input, char *output) {
    unsigned char hash[SHA384_DIGEST_LENGTH];
    const unsigned char* data = (const unsigned char*)(input ? input : "");
    SHA384(data, strlen((const char*)data), hash);
    for (int i = 0; i < SHA384_DIGEST_LENGTH; i++) {
        snprintf(output + (i * 2), 3, "%02x", hash[i]);
    }
    output[QIHSE_AUTH_HASH_HEX_LEN] = '\0';
    OPENSSL_cleanse(hash, sizeof(hash));
}

/* auth_mutex must be held. */
static bool resolve_authoritative_user_locked(const qihse_user_t* presented,
                                              uint32_t* out_user_id,
                                              authz_state_t* out_state) {
    if (!presented) return false;

    for (uint32_t i = 0; i < MAX_USERS; i++) {
        if (users[i] == presented && authz_states[i].active) {
            if (out_user_id) *out_user_id = i;
            if (out_state) *out_state = authz_states[i];
            return true;
        }
    }
    return false;
}

static void set_authz_state_locked(uint32_t user_id, const qihse_user_t* user) {
    if (user_id >= MAX_USERS || !user) return;
    authz_states[user_id].active = true;
    authz_states[user_id].role = user->role;
    authz_states[user_id].classification_level = user->classification_level;
    authz_states[user_id].sci_compartments = user->sci_compartments;
    authz_states[user_id].requires_hardware_token = user->requires_hardware_token;
    authz_states[user_id].can_create_users = user->can_create_users;
}

void qihse_auth_init(void) {
    qihse_audit_init();
    pthread_mutex_lock(&auth_mutex);
    memset(users, 0, sizeof(users));
    memset(authz_states, 0, sizeof(authz_states));
    memset(rate_limits, 0, sizeof(rate_limits));
    active_user_count = 0;

    // PRE-SEED THE SYSTEM OPERATOR (User ID 0)
    qihse_user_t* op = calloc(1, sizeof(qihse_user_t));
    if (op) {
        op->user_id = 0;
        op->role = QIHSE_ROLE_OPERATOR;
        op->classification_level = 0xFFFF;
        op->sci_compartments = 0xFFFF;
        op->hardware_token_present = true;
        op->requires_hardware_token = true;
        op->can_create_users = true;
        strncpy(op->username, "GODMODE_OP", 64);
        strncpy(op->fido2_credential_id, "OP-GODMODE-YUBIKEY-0001", 64);
        compute_sha384_hex("OPERATOR_DEFAULT_P@SSW0RD_DO_NOT_USE", op->password_hash);
#ifndef _WIN32
        mlock(op, sizeof(qihse_user_t));
#endif
        users[0] = op;
        set_authz_state_locked(0, op);
        active_user_count = 1;
    }

    pthread_mutex_unlock(&auth_mutex);
}

qihse_user_t* qihse_auth_create_user(qihse_user_t* creator, uint32_t user_id,
                                     uint16_t role, uint16_t classif,
                                     uint16_t sci,
                                     const char* plaintext_password,
                                     bool requires_hw_token) {
    if (user_id >= MAX_USERS) return NULL;

    /* A NULL password previously became SHA384("") and created an account
     * authenticatable with the public empty string. All created accounts must
     * have a real password satisfying the same minimum-strength invariant. */
    if (!plaintext_password || strlen(plaintext_password) < 12) {
        fprintf(stderr,
                "[SECURITY ERROR] Password for User ID %u rejected: minimum 12 characters required.\n",
                user_id);
        return NULL;
    }

    pthread_mutex_lock(&auth_mutex);

    // Check if operator password is still default (unless we are creating operator during init)
    if (users[0] && user_id != 0) {
        char default_hash[QIHSE_AUTH_HASH_LEN];
        compute_sha384_hex("OPERATOR_DEFAULT_P@SSW0RD_DO_NOT_USE", default_hash);
        if (constant_time_compare(users[0]->password_hash, default_hash, QIHSE_AUTH_HASH_LEN)) {
            printf("[SECURITY ERROR] Default operator password must be changed before creating users.\n");
            pthread_mutex_unlock(&auth_mutex);
            return NULL;
        }
    }

    uint32_t creator_id = 0xFFFFFFFFu;
    authz_state_t creator_authz;
    if (!resolve_authoritative_user_locked(creator, &creator_id, &creator_authz)) {
        qihse_audit_log("USER_CREATE_DENIED_INVALID_CREATOR", creator_id,
                        user_id, classif, sci);
        pthread_mutex_unlock(&auth_mutex);
        return NULL;
    }

    // Only an authoritative OPERATOR or explicitly delegated user may create users.
    if (creator_authz.role != QIHSE_ROLE_OPERATOR &&
        !creator_authz.can_create_users) {
        qihse_audit_log("USER_CREATE_DENIED_DELEGATION", creator_id,
                        user_id, classif, sci);
        pthread_mutex_unlock(&auth_mutex);
        return NULL;
    }

    // Role numbers are ordered from most to least privileged (OPERATOR=0).
    if (role < creator_authz.role) {
        qihse_audit_log("USER_CREATE_DENIED_ROLE", creator_id,
                        user_id, classif, sci);
        pthread_mutex_unlock(&auth_mutex);
        return NULL;
    }

    // Ensure the creator possesses the clearance they are attempting to grant.
    if (classif > creator_authz.classification_level) {
        qihse_audit_log("USER_CREATE_DENIED_CLEARANCE", creator_id,
                        user_id, classif, sci);
        pthread_mutex_unlock(&auth_mutex);
        return NULL;
    }
    if ((sci & creator_authz.sci_compartments) != sci) {
        qihse_audit_log("USER_CREATE_DENIED_SCI", creator_id,
                        user_id, classif, sci);
        pthread_mutex_unlock(&auth_mutex);
        return NULL;
    }

    /* A delegated principal that is itself subject to hardware-token policy
     * cannot mint a child account that drops that requirement. Operators are
     * intentionally exempt because the current access model already treats
     * OPERATOR as the root authority and does not enforce its token flag. */
    if (creator_authz.role != QIHSE_ROLE_OPERATOR &&
        creator_authz.requires_hardware_token && !requires_hw_token) {
        qihse_audit_log("USER_CREATE_DENIED_TOKEN_POLICY", creator_id,
                        user_id, classif, sci);
        pthread_mutex_unlock(&auth_mutex);
        return NULL;
    }

    // Do not allow overwriting an active session; must explicitly destroy first.
    if (users[user_id] != NULL) {
        pthread_mutex_unlock(&auth_mutex);
        return NULL;
    }

    qihse_user_t* u = calloc(1, sizeof(qihse_user_t));
    if (!u) {
        pthread_mutex_unlock(&auth_mutex);
        return NULL;
    }

    u->user_id = user_id;
    u->role = role;

    if (role == QIHSE_ROLE_OPERATOR) {
        // Operators get God Mode.
        u->classification_level = 0xFFFF;
        u->sci_compartments = 0xFFFF;
    } else {
        u->classification_level = classif;
        u->sci_compartments = sci;
    }

    compute_sha384_hex(plaintext_password, u->password_hash);
    u->requires_hardware_token = requires_hw_token;
    u->can_create_users = false;
    snprintf(u->username, 64, "User_%u", user_id);

    users[user_id] = u;
    set_authz_state_locked(user_id, u);
    active_user_count++;
#ifndef _WIN32
    mlock(u, sizeof(qihse_user_t));
#endif

    qihse_audit_log("USER_CREATE", creator_id, user_id,
                    u->classification_level, u->sci_compartments);

    pthread_mutex_unlock(&auth_mutex);
    return u;
}

qihse_user_t* qihse_auth_get_user(uint32_t user_id) {
    if (user_id >= MAX_USERS) return NULL;
    pthread_mutex_lock(&auth_mutex);
    qihse_user_t* u = users[user_id];
    pthread_mutex_unlock(&auth_mutex);
    return u;
}

void qihse_auth_destroy_user(uint32_t user_id) {
    if (user_id >= MAX_USERS) return;

    if (user_id == 0) {
        printf("[WARNING] You are about to literally kill God.\n");
        printf("You must have created roles that satisfy all your needed functions. Once God is dead, he ain't coming back.\n");
        printf("If that is acceptable, I will load the Colt, bless the bullet, and we can fire away. (Y/N): ");
        fflush(stdout);
        char response[10];
        if (fgets(response, sizeof(response), stdin) != NULL) {
            if (response[0] != 'Y' && response[0] != 'y') {
                printf("Crisis averted. The Operator lives.\n");
                return;
            }
        } else {
            return;
        }
        printf("Firing away...\n");
    }

    pthread_mutex_lock(&auth_mutex);
    if (users[user_id]) {
        qihse_audit_log("USER_DESTROY", 0, user_id,
                        authz_states[user_id].classification_level,
                        authz_states[user_id].sci_compartments);
        OPENSSL_cleanse(users[user_id], sizeof(qihse_user_t));
#ifndef _WIN32
        munlock(users[user_id], sizeof(qihse_user_t));
#endif
        free(users[user_id]);
        users[user_id] = NULL;
        memset(&authz_states[user_id], 0, sizeof(authz_states[user_id]));
        memset(&rate_limits[user_id], 0, sizeof(rate_limits[user_id]));
        active_user_count--;
    }
    pthread_mutex_unlock(&auth_mutex);
}

bool qihse_auth_modify_user(qihse_user_t* operator_user,
                            uint32_t target_user_id,
                            const char* new_username,
                            const char* new_password,
                            int new_requires_hw_token,
                            int new_can_create_users) {
    if (target_user_id >= MAX_USERS) return false;

    if (new_password != NULL && strlen(new_password) < 12) {
        fprintf(stderr,
                "[SECURITY ERROR] Password for User ID %u rejected: minimum 12 characters required.\n",
                target_user_id);
        return false;
    }

    if (target_user_id != 0 && qihse_auth_is_operator_password_default()) {
        printf("[SECURITY ERROR] Default operator password must be changed before modifying other users.\n");
        return false;
    }

    pthread_mutex_lock(&auth_mutex);

    uint32_t operator_id = 0xFFFFFFFFu;
    authz_state_t operator_authz;
    if (!resolve_authoritative_user_locked(operator_user,
                                           &operator_id,
                                           &operator_authz) ||
        operator_authz.role != QIHSE_ROLE_OPERATOR) {
        pthread_mutex_unlock(&auth_mutex);
        qihse_audit_log("USER_MODIFY_DENIED", operator_id,
                        target_user_id, 0, 0);
        return false;
    }

    qihse_user_t* target = users[target_user_id];
    if (!target || !authz_states[target_user_id].active) {
        pthread_mutex_unlock(&auth_mutex);
        return false;
    }

    if (new_username != NULL) {
        strncpy(target->username, new_username, 63);
        target->username[63] = '\0';
    }

    if (new_password != NULL) {
        compute_sha384_hex(new_password, target->password_hash);
    }

    if (new_requires_hw_token != -1) {
        bool value = (new_requires_hw_token != 0);
        target->requires_hardware_token = value;
        authz_states[target_user_id].requires_hardware_token = value;
    }

    if (new_can_create_users != -1) {
        bool value = (new_can_create_users != 0);
        target->can_create_users = value;
        authz_states[target_user_id].can_create_users = value;
    }

    qihse_audit_log("USER_MODIFY", operator_id, target_user_id,
                    authz_states[target_user_id].classification_level,
                    authz_states[target_user_id].sci_compartments);
    pthread_mutex_unlock(&auth_mutex);
    return true;
}

bool qihse_auth_can_access(qihse_user_t* user,
                           uint16_t data_classif,
                           uint16_t data_sci) {
    uint32_t uid = user ? user->user_id : 0xFFFFFFFFu;

    // Callout webhook for non-UNCLASSIFIED file/data access.
    if (data_classif > 0) {
        qihse_audit_webhook_ping(uid, data_classif, data_sci);
    }

    if (!user) {
        // Security is optional by default — grant full access when no user context
        // is configured. This matches the README: "by default, QIHSE grants full access."
        // To enable security, call db.authenticate() explicitly.
        return true;
    }

    /* Privilege-bearing values come from the private canonical record rather
     * than the mutable public qihse_user_t. hardware_token_present remains
     * connection/runtime state on the public object for compatibility. */
    authz_state_t authz;
    bool hardware_token_present = false;
    pthread_mutex_lock(&auth_mutex);
    bool valid = resolve_authoritative_user_locked(user, &uid, &authz);
    if (valid) hardware_token_present = users[uid]->hardware_token_present;
    pthread_mutex_unlock(&auth_mutex);

    if (!valid) {
        qihse_audit_log("ACCESS_DENIED_INVALID_CONTEXT", uid, 0,
                        data_classif, data_sci);
        return false;
    }

    // Hardware Token Enforcement — only enforced when explicitly enabled.
    if (authz.requires_hardware_token && !hardware_token_present &&
        authz.role != QIHSE_ROLE_OPERATOR) {
        qihse_audit_log("ACCESS_DENIED_MISSING_TOKEN", uid, 0,
                        data_classif, data_sci);
        return false;
    }

    // God Mode requires authoritative operator role assignment.
    if (authz.role == QIHSE_ROLE_OPERATOR) {
        if (data_classif > 0) {
            qihse_audit_log("ACCESS_GRANTED_OPERATOR", uid, 0,
                            data_classif, data_sci);
        }
        return true;
    }

    // Clearance Check.
    if (authz.classification_level < data_classif) {
        qihse_audit_log("ACCESS_DENIED_CLEARANCE", uid, 0,
                        data_classif, data_sci);
        return false;
    }

    // SCI Check.
    if ((data_sci & authz.sci_compartments) != data_sci) {
        qihse_audit_log("ACCESS_DENIED_SCI", uid, 0,
                        data_classif, data_sci);
        return false;
    }

    qihse_audit_log("ACCESS_GRANTED", uid, 0, data_classif, data_sci);
    return true;
}

bool qihse_auth_is_operator_password_default(void) {
    pthread_mutex_lock(&auth_mutex);
    qihse_user_t* op = users[0];
    if (!op) {
        pthread_mutex_unlock(&auth_mutex);
        return false;
    }
    char default_hash[QIHSE_AUTH_HASH_LEN];
    compute_sha384_hex("OPERATOR_DEFAULT_P@SSW0RD_DO_NOT_USE", default_hash);
    bool is_default = constant_time_compare(op->password_hash,
                                            default_hash,
                                            QIHSE_AUTH_HASH_LEN);
    pthread_mutex_unlock(&auth_mutex);
    return is_default;
}

qihse_user_t* qihse_auth_authenticate(const char* username,
                                      const char* password) {
    if (!username || !password) return NULL;
    pthread_mutex_lock(&auth_mutex);
    for (int i = 0; i < MAX_USERS; i++) {
        if (users[i] && strcmp(users[i]->username, username) == 0) {
            time_t now = time(NULL);
            if (rate_limits[i].lockout_until > now) {
                fprintf(stderr,
                        "[AUTH] User '%s' is locked out. Try again in %ld seconds.\n",
                        username,
                        (long)(rate_limits[i].lockout_until - now));
                pthread_mutex_unlock(&auth_mutex);
                return NULL;
            }
            char expected_hash[QIHSE_AUTH_HASH_LEN];
            compute_sha384_hex(password, expected_hash);
            if (constant_time_compare(users[i]->password_hash,
                                      expected_hash,
                                      QIHSE_AUTH_HASH_LEN)) {
                rate_limits[i].failed_count = 0;
                rate_limits[i].lockout_until = 0;
                qihse_user_t* u = users[i];
                pthread_mutex_unlock(&auth_mutex);
                return u;
            } else {
                rate_limits[i].failed_count++;
                if (rate_limits[i].failed_count >= MAX_AUTH_ATTEMPTS) {
                    rate_limits[i].lockout_until = now + AUTH_LOCKOUT_SECONDS;
                    rate_limits[i].failed_count = 0;
                    fprintf(stderr,
                            "[AUTH] User '%s' locked out after %d failed attempts for %d seconds.\n",
                            username, MAX_AUTH_ATTEMPTS, AUTH_LOCKOUT_SECONDS);
                }
                pthread_mutex_unlock(&auth_mutex);
                return NULL;
            }
        }
    }
    pthread_mutex_unlock(&auth_mutex);
    return NULL;
}

qihse_user_t* qihse_auth_authenticate_id(uint32_t user_id,
                                         const char* password) {
    if (user_id >= MAX_USERS || !password) return NULL;
    pthread_mutex_lock(&auth_mutex);
    qihse_user_t* u = users[user_id];
    if (u) {
        char expected_hash[QIHSE_AUTH_HASH_LEN];
        compute_sha384_hex(password, expected_hash);
        if (constant_time_compare(u->password_hash,
                                  expected_hash,
                                  QIHSE_AUTH_HASH_LEN)) {
            pthread_mutex_unlock(&auth_mutex);
            return u;
        }
    }
    pthread_mutex_unlock(&auth_mutex);
    return NULL;
}
