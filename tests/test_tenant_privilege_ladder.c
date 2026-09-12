/* Tenant privilege-ladder regression test (AGENTS.md invariant #2, U2).
 *
 * A tenant-scoped delegated creator must never be able to mint a principal
 * outside its own tenant — neither in another tenant nor in the system
 * domain — nor above itself in role/clearance/SCI. Only system-domain
 * creators can mint principals in arbitrary tenants or in the system domain,
 * and qihse_auth_create_tenant_user refuses to mint tenant-0 principals
 * outright.
 */
#define _GNU_SOURCE

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "qihse_auth.h"

#define ADMIN_PW "TenantAdminPass1!"
#define MEMBER_PW "TenantMemberPas1!"
#define OPERATOR_PASSWORD "OperatorLadderPa1!"

int main(void) {
    char data_dir[] = "/tmp/qihse-tenant-ladder-XXXXXX";
    assert(mkdtemp(data_dir) != NULL);
    assert(setenv("QIHSE_DATA_DIR", data_dir, 1) == 0);
    assert(setenv("QIHSE_FIPS_MODE", "disabled", 1) == 0);

    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator(OPERATOR_PASSWORD));
    qihse_user_t* operator_user = qihse_auth_get_user(0);
    assert(operator_user != NULL);

    /* Tenant 7 delegated creator (GUEST role, clearance 91, SCI 0). */
    qihse_user_t* admin7 = qihse_auth_create_tenant_user(operator_user, 7, 71,
                                                         QIHSE_ROLE_GUEST, 91, 0,
                                                         ADMIN_PW, false);
    assert(admin7 != NULL);
    assert(qihse_user_get_tenant_id(admin7) == 7);
    /* Delegation of account creation only — never Operator authority. */
    assert(qihse_auth_modify_user(operator_user, 71, NULL, NULL, -1, 1, -1, -1));
    assert(qihse_user_can_create_users(admin7));

    /* Cross-tenant creation: denied. */
    assert(qihse_auth_create_tenant_user(admin7, 8, 81, QIHSE_ROLE_GUEST, 91, 0, MEMBER_PW, false) == NULL);
    /* System-domain creation via the tenant path: denied. */
    assert(qihse_auth_create_tenant_user(admin7, QIHSE_TENANT_SYSTEM, 82, QIHSE_ROLE_GUEST, 91, 0, MEMBER_PW, false) == NULL);
    /* System-domain creation via the legacy path: denied for a tenant creator. */
    assert(qihse_auth_create_user(admin7, 83, QIHSE_ROLE_GUEST, 91, 0, MEMBER_PW, false) == NULL);
    /* Privilege escalation inside the own tenant: denied (clearance above own). */
    assert(qihse_auth_create_tenant_user(admin7, 7, 84, QIHSE_ROLE_GUEST, 92, 0, MEMBER_PW, false) == NULL);
    /* Privilege escalation inside the own tenant: denied (role above own). */
    assert(qihse_auth_create_tenant_user(admin7, 7, 85, QIHSE_ROLE_ANALYST, 91, 0, MEMBER_PW, false) == NULL);
    /* SCI compartment not possessed by the creator: denied. */
    assert(qihse_auth_create_tenant_user(admin7, 7, 86, QIHSE_ROLE_GUEST, 91, 0x1, MEMBER_PW, false) == NULL);

    /* In-tenant, at-or-below-self creation: allowed — but the new principal
     * is floored to the LOWEST rank by default: delegated account creation
     * never carries authority, so the requested clearance (91) is not
     * granted. Elevation is a separate operator action. */
    qihse_user_t* member7 = qihse_auth_create_tenant_user(admin7, 7, 87,
                                                          QIHSE_ROLE_GUEST, 91, 0,
                                                          MEMBER_PW, false);
    assert(member7 != NULL);
    assert(qihse_user_get_tenant_id(member7) == 7);
    assert(qihse_user_get_role(member7) == QIHSE_ROLE_GUEST);
    assert(qihse_user_get_classification(member7) == 0);
    assert(qihse_user_get_sci(member7) == 0);
    /* Delegation does not propagate: created principals cannot create. */
    assert(!qihse_user_can_create_users(member7));

    /* A delegated elevated creator cannot duplicate its own rank either:
     * an ANALYST with the creation flag still only mints GUEST/0/0. */
    qihse_user_t* analyst = qihse_auth_create_user(operator_user, 91, QIHSE_ROLE_ANALYST,
                                                   91, 0, "AnalystPass123456!", false);
    assert(analyst != NULL);
    /* Operator creation honors the explicitly requested clearance/SCI. */
    assert(qihse_user_get_classification(analyst) == 91);
    assert(qihse_user_get_sci(analyst) == 0);
    assert(qihse_auth_modify_user(operator_user, 91, NULL, NULL, -1, 1, -1, -1));
    qihse_user_t* peer = qihse_auth_create_user(analyst, 92, QIHSE_ROLE_ANALYST,
                                                91, 0, "PeerPass12345678!", false);
    assert(peer != NULL);
    assert(qihse_user_get_role(peer) == QIHSE_ROLE_GUEST);
    assert(qihse_user_get_classification(peer) == 0);
    assert(qihse_user_get_sci(peer) == 0);

    /* System-domain creator may mint principals in any tenant — with the
     * explicitly requested clearance (operator creation is never floored). */
    qihse_user_t* member8 = qihse_auth_create_tenant_user(operator_user, 8, 88,
                                                          QIHSE_ROLE_GUEST, 91, 0x5,
                                                          MEMBER_PW, false);
    assert(member8 != NULL);
    assert(qihse_user_get_tenant_id(member8) == 8);
    assert(qihse_user_get_classification(member8) == 91);
    assert(qihse_user_get_sci(member8) == 0x5);
    /* ...but the tenant-0 system domain is reserved to qihse_auth_create_user. */
    assert(qihse_auth_create_tenant_user(operator_user, QIHSE_TENANT_SYSTEM, 89, QIHSE_ROLE_GUEST, 91, 0, MEMBER_PW, false) == NULL);
    /* The legacy path still mints system-domain principals for tenant-0 creators. */
    qihse_user_t* system_user = qihse_auth_create_user(operator_user, 90, QIHSE_ROLE_GUEST, 91, 0, MEMBER_PW, false);
    assert(system_user != NULL);
    assert(qihse_user_get_tenant_id(system_user) == QIHSE_TENANT_SYSTEM);

    /* Operator can SET clearance and SCI after creation: elevate the floored
     * member7 (0) into the tenant's working clearance, with compartments. */
    assert(qihse_auth_modify_user(operator_user, 87, NULL, NULL, -1, -1, 91, 0x5));
    assert(qihse_user_get_classification(member7) == 91);
    assert(qihse_user_get_sci(member7) == 0x5);
    /* Partial updates leave the untouched field alone. */
    assert(qihse_auth_modify_user(operator_user, 87, NULL, NULL, -1, -1, 50, -1));
    assert(qihse_user_get_classification(member7) == 50);
    assert(qihse_user_get_sci(member7) == 0x5);
    /* Out-of-range values are rejected, not truncated. */
    assert(!qihse_auth_modify_user(operator_user, 87, NULL, NULL, -1, -1, 0x10000, -1));
    assert(!qihse_auth_modify_user(operator_user, 87, NULL, NULL, -1, -1, -1, -2));
    /* Delegated principals still cannot modify anyone (operator-only). */
    assert(!qihse_auth_modify_user(admin7, 87, NULL, NULL, -1, -1, 91, 0x5));

    /* Revocation: a destroyed principal's handle stops resolving. */
    assert(qihse_auth_destroy_user(operator_user, 87));
    assert(!qihse_auth_user_is_active(member7));
    assert(qihse_auth_user_is_active(member8));

    printf("test_tenant_privilege_ladder: all assertions passed\n");
    return 0;
}
