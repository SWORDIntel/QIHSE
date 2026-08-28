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
        operator_user, 1, QIHSE_ROLE_ANALYST, 5, 0x0003,
        "AnalystPass123!", false);
    assert(analyst != NULL);

    /* Delegate account creation without delegating Operator authority. */
    assert(qihse_auth_modify_user(operator_user, 1, NULL, NULL, -1, 1));
    assert(analyst->can_create_users);

    /* Delegated Analyst cannot mint an Operator. */
    assert(qihse_auth_create_user(
        analyst, 2, QIHSE_ROLE_OPERATOR, 5, 0x0001,
        "EscalatePass123!", false) == NULL);

    /* Same-level/subordinate creation remains valid for permitted subsets. */
    qihse_user_t* peer_analyst = qihse_auth_create_user(
        analyst, 3, QIHSE_ROLE_ANALYST, 5, 0x0001,
        "PeerAnalyst123!", false);
    assert(peer_analyst != NULL);

    qihse_user_t* guest = qihse_auth_create_user(
        operator_user, 4, QIHSE_ROLE_GUEST, 0, 0,
        "GuestAccount123!", false);
    assert(guest != NULL);
    assert(qihse_auth_modify_user(operator_user, 4, NULL, NULL, -1, 1));

    /* Delegated Guest cannot create an Analyst. */
    assert(qihse_auth_create_user(
        guest, 5, QIHSE_ROLE_ANALYST, 0, 0,
        "GuestEscalate123!", false) == NULL);

    /* Mutating the public user object must not alter canonical authority. */
    uint16_t saved_role = analyst->role;
    uint16_t saved_classification = analyst->classification_level;
    analyst->role = QIHSE_ROLE_OPERATOR;
    analyst->classification_level = 0xFFFF;
    assert(qihse_auth_create_user(
        analyst, 6, QIHSE_ROLE_OPERATOR, 5, 0x0001,
        "MutatedRole123!", false) == NULL);
    assert(qihse_auth_create_user(
        analyst, 7, QIHSE_ROLE_ANALYST, 6, 0x0001,
        "MutatedClass123!", false) == NULL);
    assert(!qihse_auth_modify_user(analyst, 3, NULL, NULL, -1, 1));
    analyst->role = saved_role;
    analyst->classification_level = saved_classification;

    /* A forged stack copy is not an authenticated repository principal. */
    qihse_user_t forged_operator = *analyst;
    forged_operator.user_id = 0;
    forged_operator.role = QIHSE_ROLE_OPERATOR;
    forged_operator.classification_level = 0xFFFF;
    forged_operator.sci_compartments = 0xFFFF;
    forged_operator.can_create_users = true;
    assert(qihse_auth_create_user(
        &forged_operator, 8, QIHSE_ROLE_OPERATOR, 0xFFFF, 0xFFFF,
        "ForgedCreator123!", false) == NULL);
    assert(!qihse_auth_modify_user(&forged_operator, 3, NULL, NULL, -1, 1));

    /* Flipping can_create_users directly must not create delegated authority. */
    assert(!peer_analyst->can_create_users);
    peer_analyst->can_create_users = true;
    assert(qihse_auth_create_user(
        peer_analyst, 9, QIHSE_ROLE_GUEST, 0, 0,
        "ForgedDelegate123!", false) == NULL);
    peer_analyst->can_create_users = false;

    /* A delegated user with mandatory hardware auth cannot create a child
     * that weakens that requirement, even if its public flag is tampered. */
    qihse_user_t* token_analyst = qihse_auth_create_user(
        operator_user, 10, QIHSE_ROLE_ANALYST, 5, 0x0003,
        "TokenAnalyst123!", true);
    assert(token_analyst != NULL);
    assert(qihse_auth_modify_user(operator_user, 10, NULL, NULL, -1, 1));
    token_analyst->requires_hardware_token = false;
    assert(qihse_auth_create_user(
        token_analyst, 11, QIHSE_ROLE_ANALYST, 5, 0x0001,
        "WeakTokenChild123!", false) == NULL);
    token_analyst->requires_hardware_token = true;
    assert(qihse_auth_create_user(
        token_analyst, 12, QIHSE_ROLE_ANALYST, 5, 0x0001,
        "TokenChildPass123!", true) != NULL);

    /* NULL must never become SHA384("") and create an empty-password account. */
    assert(qihse_auth_create_user(
        analyst, 13, QIHSE_ROLE_ANALYST, 5, 0x0001,
        NULL, false) == NULL);
    assert(qihse_auth_authenticate_id(13, "") == NULL);

    puts("auth privilege-boundary regression tests passed");
    return 0;
}
