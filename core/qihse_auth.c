#include "qihse_auth.h"
#include "qihse_audit.h"
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <stdio.h>
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

static qihse_user_t* users[MAX_USERS];
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

void qihse_auth_init(void) {
    qihse_audit_init();
    pthread_mutex_lock(&auth_mutex);
    memset(users, 0, sizeof(users));
    active_user_count = 0;
    
    // PRE-SEED THE SYSTEM OPERATOR (User ID 0)
    qihse_user_t* op = malloc(sizeof(qihse_user_t));
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
        active_user_count = 1;
    }
    
    pthread_mutex_unlock(&auth_mutex);
}

qihse_user_t* qihse_auth_create_user(qihse_user_t* creator, uint32_t user_id, uint16_t role, uint16_t classif, uint16_t sci, const char* plaintext_password, bool requires_hw_token) {
    if (user_id >= MAX_USERS) return NULL;
    
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
    
    // Enforce that only an OPERATOR or delegated user can create new users.
    if (!creator || (creator->role != QIHSE_ROLE_OPERATOR && !creator->can_create_users)) {
        pthread_mutex_unlock(&auth_mutex);
        return NULL;
    }
    
    // Ensure the creator possesses the clearance they are attempting to grant
    if (classif > creator->classification_level) {
        pthread_mutex_unlock(&auth_mutex);
        return NULL;
    }
    if ((sci & creator->sci_compartments) != sci) {
        pthread_mutex_unlock(&auth_mutex);
        return NULL;
    }

    // Do not allow overwriting an active session; must explicitly destroy first
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
        // Operators get God Mode
        u->classification_level = 0xFFFF; // Max possible clearance
        u->sci_compartments = 0xFFFF;     // All compartments
    } else {
        u->classification_level = classif;
        u->sci_compartments = sci;
    }

    // Handle Password
    if (plaintext_password) {
        if (strlen(plaintext_password) < 12) {
            fprintf(stderr, "[SECURITY ERROR] Password for User ID %u rejected: minimum 12 characters required.\n", user_id);
            free(u);
            pthread_mutex_unlock(&auth_mutex);
            return NULL;
        }
        compute_sha384_hex(plaintext_password, u->password_hash);
    } else {
        compute_sha384_hex("", u->password_hash);
    }
    
    u->requires_hardware_token = requires_hw_token;
    u->can_create_users = false;
    snprintf(u->username, 64, "User_%u", user_id);

    users[user_id] = u;
    active_user_count++;
#ifndef _WIN32
    mlock(u, sizeof(qihse_user_t));
#endif
    
    qihse_audit_log("USER_CREATE", creator->user_id, user_id, u->classification_level, u->sci_compartments);
    
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
        qihse_audit_log("USER_DESTROY", 0, user_id, users[user_id]->classification_level, users[user_id]->sci_compartments);
        OPENSSL_cleanse(users[user_id], sizeof(qihse_user_t));
#ifndef _WIN32
        munlock(users[user_id], sizeof(qihse_user_t));
#endif
        free(users[user_id]);
        users[user_id] = NULL;
        active_user_count--;
    }
    pthread_mutex_unlock(&auth_mutex);
}

bool qihse_auth_modify_user(qihse_user_t* operator_user, uint32_t target_user_id, const char* new_username, const char* new_password, int new_requires_hw_token, int new_can_create_users) {
    if (!operator_user || operator_user->role != QIHSE_ROLE_OPERATOR) {
        qihse_audit_log("USER_MODIFY_DENIED", operator_user ? operator_user->user_id : 0xFFFFFFFF, target_user_id, 0, 0);
        return false;
    }

    if (target_user_id != 0 && qihse_auth_is_operator_password_default()) {
        printf("[SECURITY ERROR] Default operator password must be changed before modifying other users.\n");
        return false;
    }

    if (target_user_id >= MAX_USERS) return false;

    pthread_mutex_lock(&auth_mutex);
    qihse_user_t* target = users[target_user_id];
    if (!target) {
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
        target->requires_hardware_token = (new_requires_hw_token != 0);
    }

    if (new_can_create_users != -1) {
        target->can_create_users = (new_can_create_users != 0);
    }

    qihse_audit_log("USER_MODIFY", operator_user->user_id, target_user_id, target->classification_level, target->sci_compartments);
    pthread_mutex_unlock(&auth_mutex);
    return true;
}

bool qihse_auth_can_access(qihse_user_t* user, uint16_t data_classif, uint16_t data_sci) {
    uint32_t uid = user ? user->user_id : 0xFFFFFFFF;
    
    // Callout webhook for non-UNCLASSIFIED file/data access
    if (data_classif > 0) {
        qihse_audit_webhook_ping(uid, data_classif, data_sci);
    }

    if (!user) {
        qihse_audit_log("ACCESS_DENIED_NO_USER", uid, 0, data_classif, data_sci);
        return false;
    }

    // Hardware Token Enforcement configured per-user (e.g. Mandatory for Operator/Analyst)
    if (user->requires_hardware_token && !user->hardware_token_present) {
        qihse_audit_log("ACCESS_DENIED_MISSING_TOKEN", uid, 0, data_classif, data_sci);
        return false;
    }

    // God Mode requires explicit operator role assignment
    if (user->role == QIHSE_ROLE_OPERATOR) {
        if (data_classif > 0) {
            qihse_audit_log("ACCESS_GRANTED_OPERATOR", uid, 0, data_classif, data_sci);
        }
        return true;
    }

    // Clearance Check
    if (user->classification_level < data_classif) {
        qihse_audit_log("ACCESS_DENIED_CLEARANCE", uid, 0, data_classif, data_sci);
        return false;
    }

    // SCI Check
    if ((data_sci & user->sci_compartments) != data_sci) {
        qihse_audit_log("ACCESS_DENIED_SCI", uid, 0, data_classif, data_sci);
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
    bool is_default = constant_time_compare(op->password_hash, default_hash, QIHSE_AUTH_HASH_LEN);
    pthread_mutex_unlock(&auth_mutex);
    return is_default;
}

qihse_user_t* qihse_auth_authenticate(const char* username, const char* password) {
    if (!username || !password) return NULL;
    pthread_mutex_lock(&auth_mutex);
    for (int i = 0; i < MAX_USERS; i++) {
        if (users[i] && strcmp(users[i]->username, username) == 0) {
            time_t now = time(NULL);
            if (rate_limits[i].lockout_until > now) {
                fprintf(stderr, "[AUTH] User '%s' is locked out. Try again in %ld seconds.\n",
                        username, (long)(rate_limits[i].lockout_until - now));
                pthread_mutex_unlock(&auth_mutex);
                return NULL;
            }
            char expected_hash[QIHSE_AUTH_HASH_LEN];
            compute_sha384_hex(password, expected_hash);
            if (constant_time_compare(users[i]->password_hash, expected_hash, QIHSE_AUTH_HASH_LEN)) {
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
                    fprintf(stderr, "[AUTH] User '%s' locked out after %d failed attempts for %d seconds.\n",
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

qihse_user_t* qihse_auth_authenticate_id(uint32_t user_id, const char* password) {
    if (user_id >= MAX_USERS || !password) return NULL;
    pthread_mutex_lock(&auth_mutex);
    qihse_user_t* u = users[user_id];
    if (u) {
        char expected_hash[QIHSE_AUTH_HASH_LEN];
        compute_sha384_hex(password, expected_hash);
        if (constant_time_compare(u->password_hash, expected_hash, QIHSE_AUTH_HASH_LEN)) {
            pthread_mutex_unlock(&auth_mutex);
            return u;
        }
    }
    pthread_mutex_unlock(&auth_mutex);
    return NULL;
}
