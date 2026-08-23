#include <assert.h>
#include <stdio.h>

#include "qihse_auth.h"

int main(void) {
    qihse_auth_init();

    qihse_user_t* operator_user = qihse_auth_get_user(0);
    assert(operator_user != NULL);

    /* User creation is intentionally blocked until the seeded operator password is rotated. */
    assert(qihse_auth_modify_user(operator_user, 0, NULL, "SecureOpPass1!", -1, -1));

    qihse_user_t* analyst = qihse_auth_create_user(
        operator_user,
        1,
        QIHSE_ROLE_ANALYST,
        5,
        0x0003,
        "AnalystPass123!",
        false
    );
    assert(analyst != NULL);

    /* Delegate account creation without delegating Operator authority. */
    assert(qihse_auth_modify_user(operator_user, 1, NULL, NULL, -1, 1));
    assert(analyst->can_create_users);

    /* Regression: a delegated Analyst must never be able to mint an Operator. */
    qihse_user_t* escalated_operator = qihse_auth_create_user(
        analyst,
        2,
        QIHSE_ROLE_OPERATOR,
        5,
        0x0001,
        "EscalatePass123!",
        false
    );
    assert(escalated_operator == NULL);

    /* Same-level/subordinate creation remains valid when clearance and SCI are subsets. */
    qihse_user_t* peer_analyst = qihse_auth_create_user(
        analyst,
        3,
        QIHSE_ROLE_ANALYST,
        5,
        0x0001,
        "PeerAnalyst123!",
        false
    );
    assert(peer_analyst != NULL);

    qihse_user_t* guest = qihse_auth_create_user(
        operator_user,
        4,
        QIHSE_ROLE_GUEST,
        0,
        0,
        "GuestAccount123!",
        false
    );
    assert(guest != NULL);
    assert(qihse_auth_modify_user(operator_user, 4, NULL, NULL, -1, 1));

    /* The invariant is generic: a delegated Guest cannot create an Analyst either. */
    qihse_user_t* escalated_analyst = qihse_auth_create_user(
        guest,
        5,
        QIHSE_ROLE_ANALYST,
        0,
        0,
        "GuestEscalate123!",
        false
    );
    assert(escalated_analyst == NULL);

    puts("auth privilege-boundary regression tests passed");
    return 0;
}
