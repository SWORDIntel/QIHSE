#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include "qihse_auth.h"

int main() {
    printf("Initializing QIHSE Auth Engine...\n");
    qihse_auth_init();

    // Get God-Mode Operator (User 0)
    qihse_user_t* operator = qihse_auth_get_user(0);
    if (operator == NULL) {
        printf("Failed to get operator user.\n");
        return 1;
    }
    printf("Operator retrieved. Hardware token present: %d, FIDO ID: %s\n", 
            operator->hardware_token_present, operator->fido2_credential_id);

    // Operator accessing classified data
    bool op_access = qihse_auth_can_access(operator, 5, 0);
    printf("Operator accessing Classif 5 data... Granted: %d\n", op_access);
    assert(op_access == true);

    // Create Analyst (User 1)
    qihse_user_t* analyst = qihse_auth_create_user(operator, 1, QIHSE_ROLE_ANALYST, 5, 0, "default_password", true);
    if (!analyst) {
        printf("Failed to create analyst.\n");
        return 1;
    }
    printf("Analyst created.\n");

    // Analyst accessing Unclassified data (Classif 0) without token
    bool analyst_unclass = qihse_auth_can_access(analyst, 0, 0);
    printf("Analyst accessing Unclassified data (no token)... Granted: %d\n", analyst_unclass);
    assert(analyst_unclass == false);

    // Analyst accessing Classified data (Classif 5) without token
    // Should be DENIED because tokens are now mandatory for Analyst too
    bool analyst_class_no_token = qihse_auth_can_access(analyst, 5, 0);
    printf("Analyst accessing Classified data (no token)... Granted: %d\n", analyst_class_no_token);
    assert(analyst_class_no_token == false);

    // Analyst accessing Classified data (Classif 5) with token
    analyst->hardware_token_present = true;
    strcpy(analyst->fido2_credential_id, "USER-FIPS-YUBIKEY");
    bool analyst_class_token = qihse_auth_can_access(analyst, 5, 0);
    printf("Analyst accessing Classified data (WITH token)... Granted: %d\n", analyst_class_token);
    assert(analyst_class_token == true);

    printf("\nAll hardware token enforcement tests passed successfully.\n");
    return 0;
}
