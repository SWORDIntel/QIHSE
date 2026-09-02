#include "qihse_auth.h"

#include <assert.h>
#include <stdio.h>

int main(void) {
    qihse_auth_init();

    qihse_user_t* operator_user = qihse_auth_get_user(0);
    assert(operator_user != NULL);
    assert(qihse_user_get_role(operator_user) == QIHSE_ROLE_OPERATOR);

    /* Bootstrap operator password */
    assert(qihse_auth_bootstrap_operator("object-acl-test-password"));

    qihse_user_t* analyst = qihse_auth_create_user(
        operator_user, 1, QIHSE_ROLE_ANALYST, 0, 0,
        "analyst-test-password", false);
    assert(analyst != NULL);

    /* Grant ONLY READ */
    assert(qihse_auth_grant_object(operator_user, analyst, 0, 42, QIHSE_ACL_READ));

    /* Check READ: allowed */
    assert(qihse_auth_can_access_object(analyst, 0, 42, QIHSE_ACL_READ));
    /* Check WRITE: MUST BE DENIED with only READ permission */
    assert(!qihse_auth_can_access_object(analyst, 0, 42, QIHSE_ACL_WRITE));
    /* Check ADMIN: MUST BE DENIED */
    assert(!qihse_auth_can_access_object(analyst, 0, 42, QIHSE_ACL_ADMIN));

    /* Non-existent resource */
    assert(!qihse_auth_can_access_object(analyst, 0, 99, QIHSE_ACL_READ));

    /* Operator bypasses all object ACL requirements */
    assert(qihse_auth_can_access_object(operator_user, UINT32_MAX, UINT64_MAX,
                                        QIHSE_ACL_READ | QIHSE_ACL_WRITE | QIHSE_ACL_ADMIN));

    /* Non-operator cannot grant or revoke ACLs */
    assert(!qihse_auth_grant_object(analyst, analyst, 0, 99, QIHSE_ACL_READ));
    assert(!qihse_auth_revoke_object(analyst, analyst, 0, 42));

    /* Grant WRITE as well */
    assert(qihse_auth_grant_object(operator_user, analyst, 0, 42, QIHSE_ACL_READ | QIHSE_ACL_WRITE));
    assert(qihse_auth_can_access_object(analyst, 0, 42, QIHSE_ACL_READ));
    assert(qihse_auth_can_access_object(analyst, 0, 42, QIHSE_ACL_WRITE));
    assert(!qihse_auth_can_access_object(analyst, 0, 42, QIHSE_ACL_ADMIN));

    /* Grant ADMIN */
    assert(qihse_auth_grant_object(operator_user, analyst, 0, 42,
                                   QIHSE_ACL_READ | QIHSE_ACL_WRITE | QIHSE_ACL_ADMIN));
    assert(qihse_auth_can_access_object(analyst, 0, 42, QIHSE_ACL_ADMIN));

    /* Revoke */
    assert(qihse_auth_revoke_object(operator_user, analyst, 0, 42));
    assert(!qihse_auth_can_access_object(analyst, 0, 42, QIHSE_ACL_READ));
    assert(!qihse_auth_can_access_object(analyst, 0, 42, QIHSE_ACL_WRITE));
    assert(!qihse_auth_can_access_object(analyst, 0, 42, QIHSE_ACL_ADMIN));

    printf("PASS object ACL grant, deny, operator bypass, and revoke with discrete READ/WRITE/ADMIN flags\n");
    return 0;
}
