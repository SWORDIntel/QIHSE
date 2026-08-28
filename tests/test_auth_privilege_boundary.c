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

    /* A genuine public user object is not itself authoritative. Mutating its
     * role must not change the repository's canonical privilege state. */
    uint16_t saved_analyst_role = analyst->role;
    analyst->role = QIHSE_ROLE_OPERATOR;
    qihse_user_t* mutated_role_operator = qihse_auth_create_user(
        analyst,
        6,
        QIHSE_ROLE_OPERATOR,
        5,
        0x0001,
        "MutatedRole123!",
        false
    );
    assert(mutated_role_operator == NULL);
    assert(!qihse_auth_modify_user(analyst, 3, NULL, NULL, -1, 1));
    analyst->role = saved_analyst_role;

    /* A forged stack copy, even with Operator-looking fields, is not a
     * registered authenticated principal and must be rejected. */
    qihse_user_t forged_operator = *analyst;
    forged_operator.user_id = 0;
    forged_operator.role = QIHSE_ROLE_OPERATOR;
    forged_operator.classification_level = 0xFFFF;
    forged_operator.sci_compartments = 0xFFFF;
    forged_operator.can_create_users = true;
    qihse_user_t* forged_child = qihse_auth_create_user(
        &forged_operator,
        7,
        QIHSE_ROLE_OPERATOR,
        0xFFFF,
        0xFFFF,
        "ForgedCreator123!",
        false
    );
    assert(forged_child == NULL);
    assert(!qihse_auth_modify_user(&forged_operator, 3, NULL, NULL, -1, 1));

    /* Directly flipping can_create_users on a returned object must not grant
     * delegated authority unless the canonical auth state was modified. */
    assert(!peer_analyst->can_create_users);
    peer_analyst->can_create_users = true;
    qihse_user_t* forged_delegation_child = qihse_auth_create_user(
        peer_analyst,
        8,
        QIHSE_ROLE_GUEST,
        0,
        0,
        "ForgedDelegate123!",
        false
    );
    assert(forged_delegation_child == NULL);
    peer_analyst->can_create_users = false;

    /* Delegated principals subject to hardware-token policy cannot create an
     * otherwise-equivalent child that removes that requirement. */
    qihse_user_t* token_analyst = qihse_auth_create_user(
        operator_user,
        9,
        QIHSE_ROLE_ANALYST,
        5,
        0x0003,
        "TokenAnalyst123!",
        true
    );
    assert(token_analyst != NULL);
    assert(qihse_auth_modify_user(operator_user, 9, NULL, NULL, -1, 1));

    qihse_user_t* weakened_token_child = qihse_auth_create_user(
        token_analyst,
        10,
        QIHSE_ROLE_ANALYST,
        5,
        0x0001,
        "WeakTokenChild123!",
        false
    );
    assert(weakened_token_child == NULL);

    qihse_user_t* preserved_token_child = qihse_auth_create_user(
        token_analyst,
        11,
        QIHSE_ROLE_ANALYST,
        5,
        0x0001,
        "TokenChildPass123!",
        true
    );
    assert(preserved_token_child != NULL);

    /* NULL must never be interpreted as the publicly known empty password. */
    qihse_user_t* passwordless_child = qihse_auth_create_user(
        analyst,
        12,
        QIHSE_ROLE_ANALYST,
        5,
        0x0001,
        NULL,
        false
    );
    assert(passwordless_child == NULL);
    assert(qihse_auth_authenticate_id(12, "") == NULL);

    /* A forged role mutation must not elevate data-access authorization either. */
    analyst->role = QIHSE_ROLE_OPERATOR;
    assert(!qihse_auth_can_access(analyst, 6, 0x0001));
    analyst->role = saved_analyst_role;

    puts("auth privilege-boundary regression tests passed");
    return 0;
}
