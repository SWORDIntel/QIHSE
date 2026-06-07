#include "qihse_auth.h"
#include <stdlib.h>
#include <string.h>

#define MAX_USERS 1024

static qihse_user_t* users[MAX_USERS];

void qihse_auth_init(void) {
    memset(users, 0, sizeof(users));
}

qihse_user_t* qihse_auth_create_user(uint32_t user_id, uint16_t role, uint16_t classif, uint16_t sci) {
    if (user_id >= MAX_USERS) return NULL;
    
    if (users[user_id] != NULL) {
        free(users[user_id]);
    }

    qihse_user_t* u = malloc(sizeof(qihse_user_t));
    if (!u) return NULL;

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
    return u;
}

qihse_user_t* qihse_auth_get_user(uint32_t user_id) {
    if (user_id >= MAX_USERS) return NULL;
    return users[user_id];
}

void qihse_auth_destroy_user(uint32_t user_id) {
    if (user_id >= MAX_USERS) return;
    if (users[user_id]) {
        free(users[user_id]);
        users[user_id] = NULL;
    }
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
