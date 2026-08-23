#include "qihse_auth.h"

#include <assert.h>
#include <stdio.h>

int main(void) {
    qihse_auth_init();

    qihse_user_t* operator_user = qihse_auth_get_user(0);
    assert(operator_user != NULL);
    assert(operator_user->role == QIHSE_ROLE_OPERATOR);

    /* User creation is intentionally disabled until the seeded password changes. */
    assert(qihse_auth_modify_user(operator_user, 0, NULL,
                                  "object-acl-test-password", -1, -1));
    qihse_user_t* analyst = qihse_auth_create_user(
        operator_user, 1, QIHSE_ROLE_ANALYST, 0, 0,
        "analyst-test-password", false);
    assert(analyst != NULL);

    assert(qihse_auth_grant_object(operator_user, analyst, 0, 42, QIHSE_ACL_READ));
    assert(qihse_auth_can_access_object(analyst, 0, 42));
    assert(!qihse_auth_can_access_object(analyst, 0, 99));
    assert(qihse_auth_can_access_object(operator_user, UINT32_MAX, UINT64_MAX));

    assert(!qihse_auth_grant_object(analyst, analyst, 0, 99, QIHSE_ACL_READ));
    assert(!qihse_auth_revoke_object(analyst, analyst, 0, 42));
    assert(qihse_auth_can_access_object(analyst, 0, 42));

    assert(qihse_auth_revoke_object(operator_user, analyst, 0, 42));
    assert(!qihse_auth_can_access_object(analyst, 0, 42));

    printf("PASS object ACL grant, deny, operator bypass, and revoke\n");
    return 0;
}
