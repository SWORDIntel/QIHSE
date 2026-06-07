#ifndef QIHSE_AUTH_H
#define QIHSE_AUTH_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// Define Roles
#define QIHSE_ROLE_OPERATOR 0  // Full God-Mode Access
#define QIHSE_ROLE_CHUCK    0  // Full God-Mode Access (Supernatural Alias)
#define QIHSE_ROLE_ANALYST  1  // Restricted by Clearance & SCI
#define QIHSE_ROLE_GUEST    2  // Unclassified Only

typedef struct qihse_user_s {
    uint32_t user_id;
    uint16_t role;
    uint16_t classification_level;
    uint16_t sci_compartments;
    // ... potentially other fields
} qihse_user_t;

// Global Auth Context (Simplification for simulation)
void qihse_auth_init(void);

// Create a user. Only an OPERATOR can create a user. The system pre-seeds User ID 0 as the God-Mode Operator.
qihse_user_t* qihse_auth_create_user(qihse_user_t* creator, uint32_t user_id, uint16_t role, uint16_t classif, uint16_t sci);

qihse_user_t* qihse_auth_get_user(uint32_t user_id);

void qihse_auth_destroy_user(uint32_t user_id);

// Check if a user can access a specific data row's clearance
bool qihse_auth_can_access(qihse_user_t* user, uint16_t data_classif, uint16_t data_sci);

#ifdef __cplusplus
}
#endif

#endif // QIHSE_AUTH_H
