#include "qihse_auth.h"
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#define MAX_USERS 1024

static qihse_user_t* users[MAX_USERS];
static pthread_mutex_t auth_mutex = PTHREAD_MUTEX_INITIALIZER;
static uint32_t active_user_count = 0;

void qihse_auth_init(void) {
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
        users[0] = op;
        active_user_count = 1;
    }
    
    pthread_mutex_unlock(&auth_mutex);
}

qihse_user_t* qihse_auth_create_user(qihse_user_t* creator, uint32_t user_id, uint16_t role, uint16_t classif, uint16_t sci) {
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

    users[user_id] = u;
    active_user_count++;
    
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
    if (user_id >= MAX_USERS || user_id == 0) return; // Cannot destroy the pre-seeded operator
    pthread_mutex_lock(&auth_mutex);
    if (users[user_id]) {
        free(users[user_id]);
        users[user_id] = NULL;
        active_user_count--;
    }
    pthread_mutex_unlock(&auth_mutex);
}

bool qihse_auth_can_access(qihse_user_t* user, uint16_t data_classif, uint16_t data_sci) {
    if (!user) return true; // Default: full access if no user provided

    // God Mode requires explicit operator role assignment
    if (user->role == QIHSE_ROLE_OPERATOR) return true;

    // Clearance Check
    if (user->classification_level < data_classif) return false;

    // SCI Check
    if ((data_sci & user->sci_compartments) != data_sci) return false;

    return true;
}
