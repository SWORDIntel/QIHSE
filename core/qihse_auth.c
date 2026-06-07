#include "qihse_auth.h"
#include "qihse_audit.h"
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <stdio.h>

#define MAX_USERS 1024

static qihse_user_t* users[MAX_USERS];
static pthread_mutex_t auth_mutex = PTHREAD_MUTEX_INITIALIZER;
static uint32_t active_user_count = 0;

// Simulate SHA-256 hashing for password storage
static void compute_sha256_sim(const char *input, char *output) {
    if (!input) {
        strcpy(output, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"); // empty string hash
        return;
    }
    unsigned long long hash1 = 5381;
    unsigned long long hash2 = 0xDEADBEEF;
    int c;
    while ((c = *input++)) {
        hash1 = ((hash1 << 5) + hash1) + c; 
        hash2 = hash2 ^ (c << 3);
    }
    snprintf(output, 65, "%016llx%016llx%016llx%016llx", 
             hash1, hash2, hash1 ^ 0x1234567890ABCDEF, hash2 ^ 0xFEDCBA0987654321);
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
        op->hardware_token_present = true; // Operator REQUIRES physical token
        strncpy(op->fido2_credential_id, "OP-GODMODE-YUBIKEY-0001", 64);
        compute_sha256_sim("OPERATOR_DEFAULT_P@SSW0RD_DO_NOT_USE", op->password_hash);
        users[0] = op;
        active_user_count = 1;
    }
    
    pthread_mutex_unlock(&auth_mutex);
}

qihse_user_t* qihse_auth_create_user(qihse_user_t* creator, uint32_t user_id, uint16_t role, uint16_t classif, uint16_t sci, const char* plaintext_password) {
    if (user_id >= MAX_USERS) return NULL;
    
    pthread_mutex_lock(&auth_mutex);
    
    // Enforce that only an OPERATOR can create new users.
    if (!creator || creator->role != QIHSE_ROLE_OPERATOR) {
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

    qihse_user_t* u = malloc(sizeof(qihse_user_t));
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
        if (strlen(plaintext_password) < 6) {
            printf("\n[WARNING] The password assigned to User ID %u is pathetically weak (under 6 characters).\n", user_id);
            printf("          Assuming an adversary is not currently typing this at the terminal.\n");
            printf("          Reminder: A weak password still beats a sticky note on the monitor.\n\n");
        }
        compute_sha256_sim(plaintext_password, u->password_hash);
    } else {
        compute_sha256_sim("", u->password_hash);
    }

    users[user_id] = u;
    active_user_count++;
    
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
        free(users[user_id]);
        users[user_id] = NULL;
        active_user_count--;
    }
    pthread_mutex_unlock(&auth_mutex);
}

bool qihse_auth_can_access(qihse_user_t* user, uint16_t data_classif, uint16_t data_sci) {
    uint32_t uid = user ? user->user_id : 0xFFFFFFFF;
    
    // Callout webhook for non-UNCLASSIFIED file/data access
    if (data_classif > 0) {
        qihse_audit_webhook_ping(uid, data_classif, data_sci);
    }

    if (!user) {
        qihse_audit_log("ACCESS_GRANTED_NO_USER", uid, 0, data_classif, data_sci);
        return true;
    }

    // God Mode requires explicit operator role assignment AND a YubiKey
    if (user->role == QIHSE_ROLE_OPERATOR) {
        if (!user->hardware_token_present) {
            qihse_audit_log("ACCESS_DENIED_MISSING_TOKEN_OPERATOR", uid, 0, data_classif, data_sci);
            return false;
        }
        qihse_audit_log("ACCESS_GRANTED_OPERATOR", uid, 0, data_classif, data_sci);
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
