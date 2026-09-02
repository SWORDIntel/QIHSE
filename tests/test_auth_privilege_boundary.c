#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "qihse_auth.h"
#include "core/qihse_auth_internal.h"

int main(void) {
    qihse_auth_init();

    qihse_user_t* operator_user = qihse_auth_get_user(0);
    assert(operator_user != NULL);

    /* Bootstrap operator password */
    assert(qihse_auth_bootstrap_operator("SecureOpPass1!"));

    qihse_user_t* analyst = qihse_auth_create_user(
        operator_user, 1, QIHSE_ROLE_ANALYST, 5, 0x0003,
        "AnalystPass123!", false);
    assert(analyst != NULL);

    /* Delegate account creation without delegating Operator authority. */
    assert(qihse_auth_modify_user(operator_user, 1, NULL, NULL, -1, 1));
    assert(qihse_user_can_create_users(analyst));

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

    /* --- Validation: Mutating user->role cannot elevate qihse_auth_can_access --- */
    uint16_t saved_role = analyst->role;
    uint16_t saved_classification = analyst->classification_level;
    uint16_t saved_sci = analyst->sci_compartments;

    analyst->role = QIHSE_ROLE_OPERATOR;
    analyst->classification_level = 0xFFFF;
    analyst->sci_compartments = 0xFFFF;

    /* Creator check still fails despite mutated fields */
    assert(qihse_auth_create_user(
        analyst, 6, QIHSE_ROLE_OPERATOR, 5, 0x0001,
        "MutatedRole123!", false) == NULL);
    assert(qihse_auth_create_user(
        analyst, 7, QIHSE_ROLE_ANALYST, 6, 0x0001,
        "MutatedClass123!", false) == NULL);
    assert(!qihse_auth_modify_user(analyst, 3, NULL, NULL, -1, 1));

    /* Ordinary access checks MUST also reject mutated role & clearance */
    assert(!qihse_auth_can_access(analyst, 10, 0x0001)); /* Clearance 10 > 5 */
    assert(!qihse_auth_can_access(analyst, 5, 0x0004));  /* SCI 0x0004 not in 0x0003 */

    analyst->role = saved_role;
    analyst->classification_level = saved_classification;
    analyst->sci_compartments = saved_sci;

    /* --- Validation: Mutating clearance/SCI cannot elevate access --- */
    analyst->classification_level = 100;
    assert(!qihse_auth_can_access(analyst, 10, 0x0001));
    analyst->classification_level = saved_classification;

    analyst->sci_compartments = 0xFFFF;
    assert(!qihse_auth_can_access(analyst, 5, 0x0004));
    analyst->sci_compartments = saved_sci;
    printf("[PASS] Mutating user->role and clearance/SCI cannot elevate qihse_auth_can_access\n");

    /* --- Validation: Mutating hardware_token_present cannot bypass MFA --- */
    qihse_user_t* mfa_user = qihse_auth_create_user(
        operator_user, 20, QIHSE_ROLE_ANALYST, 5, 0x0001,
        "MfaUserPassword123!", true);
    assert(mfa_user != NULL);
    assert(qihse_user_requires_hardware_token(mfa_user));
    assert(!qihse_user_has_hardware_token(mfa_user));

    /* Unauthenticated access denied due to missing token */
    assert(!qihse_auth_can_access(mfa_user, 0, 0));

    /* Attacker tampers directly with the struct memory */
    mfa_user->hardware_token_present = true;
    assert(!qihse_auth_can_access(mfa_user, 0, 0)); /* Authoritative check rejects */
    mfa_user->hardware_token_present = false;

    /* Authoritatively registering token via official API */
    assert(qihse_auth_set_hardware_token(mfa_user, true, "TOKEN-001"));
    assert(qihse_auth_can_access(mfa_user, 0, 0));
    printf("[PASS] Mutating hardware_token_present cannot bypass MFA\n");

    /* --- Validation: Forged stack/heap pointer cannot elevate access or grant ACLs --- */
    qihse_user_t forged_operator;
    memset(&forged_operator, 0, sizeof(forged_operator));
    forged_operator.user_id = 0;
    forged_operator.role = QIHSE_ROLE_OPERATOR;
    forged_operator.classification_level = 0xFFFF;
    forged_operator.sci_compartments = 0xFFFF;
    forged_operator.hardware_token_present = true;
    forged_operator.can_create_users = true;

    assert(!qihse_auth_can_access(&forged_operator, 5, 1));
    assert(!qihse_auth_can_access_object(&forged_operator, 0, 42, QIHSE_ACL_READ));
    assert(!qihse_auth_grant_object(&forged_operator, guest, 0, 42, QIHSE_ACL_READ));
    assert(!qihse_auth_revoke_object(&forged_operator, guest, 0, 42));
    assert(!qihse_auth_destroy_user(&forged_operator, 3));
    assert(qihse_auth_create_user(&forged_operator, 8, QIHSE_ROLE_OPERATOR, 0xFFFF, 0xFFFF,
                                  "ForgedCreator123!", false) == NULL);
    assert(!qihse_auth_modify_user(&forged_operator, 3, NULL, NULL, -1, 1));
    printf("[PASS] Forged qihse_user_t cannot grant/revoke ACLs or gain access\n");

    /* --- Validation: READ ACL cannot execute any mutation, WRITE cannot grant ACLs --- */
    assert(qihse_auth_grant_object(operator_user, analyst, 0, 200, QIHSE_ACL_READ));
    assert(qihse_auth_can_access_object(analyst, 0, 200, QIHSE_ACL_READ));
    assert(!qihse_auth_can_access_object(analyst, 0, 200, QIHSE_ACL_WRITE));
    assert(!qihse_auth_can_access_object(analyst, 0, 200, QIHSE_ACL_ADMIN));

    /* Upgrade to WRITE */
    assert(qihse_auth_grant_object(operator_user, analyst, 0, 200, QIHSE_ACL_READ | QIHSE_ACL_WRITE));
    assert(qihse_auth_can_access_object(analyst, 0, 200, QIHSE_ACL_WRITE));
    assert(!qihse_auth_can_access_object(analyst, 0, 200, QIHSE_ACL_ADMIN));

    /* User with WRITE permission cannot grant or revoke ACLs */
    assert(!qihse_auth_grant_object(analyst, guest, 0, 200, QIHSE_ACL_READ));
    assert(!qihse_auth_revoke_object(analyst, guest, 0, 200));

    /* ADMIN ACL semantics */
    assert(qihse_auth_grant_object(operator_user, analyst, 0, 200,
                                   QIHSE_ACL_READ | QIHSE_ACL_WRITE | QIHSE_ACL_ADMIN));
    assert(qihse_auth_can_access_object(analyst, 0, 200, QIHSE_ACL_ADMIN));
    printf("[PASS] READ ACL cannot write, WRITE ACL cannot modify ACLs, ADMIN ACL semantics verified\n");

    /* --- Validation: destroy_user fails without canonical operator authority --- */
    qihse_user_t* target = qihse_auth_create_user(
        operator_user, 50, QIHSE_ROLE_GUEST, 0, 0,
        "TargetUser123!", false);
    assert(target != NULL);

    /* Guest, analyst, and forged operator cannot destroy user */
    assert(!qihse_auth_destroy_user(guest, 50));
    assert(!qihse_auth_destroy_user(analyst, 50));
    assert(!qihse_auth_destroy_user(&forged_operator, 50));
    assert(qihse_auth_get_user(50) != NULL);

    /* Real operator can destroy user */
    assert(qihse_auth_destroy_user(operator_user, 50));
    assert(qihse_auth_get_user(50) == NULL);
    printf("[PASS] destroy_user fails without canonical operator authority\n");

    /* --- Validation: Every authentication API shares rate limiting and lockout --- */
    qihse_user_t* rate_target = qihse_auth_create_user(
        operator_user, 60, QIHSE_ROLE_ANALYST, 0, 0,
        "RateTargetPass1!", false);
    assert(rate_target != NULL);

    /* Fail 5 consecutive login attempts via authenticate_id */
    for (int i = 0; i < 5; i++) {
        assert(qihse_auth_authenticate_id(60, "WrongPassword123!") == NULL);
    }

    /* 6th attempt with CORRECT password via authenticate_id MUST FAIL due to lockout */
    assert(qihse_auth_authenticate_id(60, "RateTargetPass1!") == NULL);

    /* Username authenticate MUST ALSO FAIL due to shared user lockout */
    assert(qihse_auth_authenticate("User_60", "RateTargetPass1!") == NULL);
    printf("[PASS] Every authentication API shares rate limiting and lockout\n");

    puts("\nALL privilege-boundary and authorization regression tests PASSED!");
    return 0;
}
