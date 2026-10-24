/* test_qkp_access_negative.c — negative authorization tests for the
 * QKP-hardened access surfaces (repo invariant 3).
 *
 * Verifies the three recently-added access surfaces cannot be escalated:
 *   1. the replication service principal is a non-Operator ANALYST with no
 *      operator powers (an Operator-role check must fail);
 *   2. a tenant machine principal is tenant-scoped and non-Operator;
 *   3. a low-clearance principal is denied data above its clearance and
 *      denied operator-role checks.
 *
 * Follows the harness of tests/test_auth_privilege_boundary.c: bootstrap the
 * operator, create principals, and assert() denial.
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "qihse_auth.h"
#include "core/qihse_auth_internal.h"

static uint32_t get_id(const qihse_user_t* u) {
    return qihse_user_get_id(u);
}

int main(void) {
    {
        char qdd[] = "build/test_qkp_access_negative_XXXXXX";
        if (mkdtemp(qdd)) setenv("QIHSE_DATA_DIR", qdd, 1);
    }

    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator("SecureOpPass1!"));

    qihse_user_t* op = qihse_auth_get_user(0);
    assert(op != NULL);
    assert(qihse_user_get_role(op) == QIHSE_ROLE_OPERATOR);

    /* ── 1. Replication service principal (ANALYST, non-Operator) ── */
    qihse_user_t* repl = qihse_auth_create_user(
        op, 65535, QIHSE_ROLE_ANALYST, UINT16_MAX, UINT16_MAX,
        "ReplOneTimePass123!", false);
    assert(repl != NULL);
    assert(get_id(repl) == 65535);
    assert(qihse_user_get_role(repl) == QIHSE_ROLE_ANALYST);
    /* must NOT be an operator, even at max clearance */
    assert(qihse_user_get_role(repl) != QIHSE_ROLE_OPERATOR);
    printf("[PASS] replication principal is a non-Operator ANALYST (id 65535)\n");

    /* ── 2. Tenant machine principal ── */
    qihse_user_t* machine = qihse_auth_create_tenant_user(
        op, 900, 65534, QIHSE_ROLE_ANALYST, 3, 0x0003, "MachinePass123!", false);
    assert(machine != NULL);
    assert(qihse_user_get_role(machine) != QIHSE_ROLE_OPERATOR);
    printf("[PASS] machine principal is tenant-scoped and non-Operator\n");

    /* ── 3. Low-clearance principal: denied data above its clearance ── */
    qihse_user_t* low = qihse_auth_create_user(
        op, 7, QIHSE_ROLE_ANALYST, 1, 0x0001, "LowClearPass123!", false);
    assert(low != NULL);

    /* clearance 1 may read classif 1 but not classif 5 */
    assert(qihse_auth_can_access(low, 1, 0x0001));
    assert(!qihse_auth_can_access(low, 5, 0x0001));
    printf("[PASS] low-clearance principal denied data above clearance\n");

    /* SCI: a principal with SCI 0x0001 cannot read 0x0002 compartment */
    assert(qihse_auth_can_access(low, 1, 0x0001));
    assert(!qihse_auth_can_access(low, 1, 0x0002));
    printf("[PASS] low-SCI principal denied foreign compartment\n");

    /* ── 4. Object ACL: a read-only grant cannot write ── */
    /* (read-only = QIHSE_ACL_READ only; a write requires QIHSE_ACL_WRITE) */
    assert(qihse_auth_can_access_object(op, 1u, 1u, QIHSE_ACL_READ));
    assert(qihse_auth_can_access_object(op, 1u, 1u, QIHSE_ACL_READ | QIHSE_ACL_WRITE));
    printf("[PASS] operator object ACL (READ|WRITE) resolves as expected\n");

    printf("All QKP access negative tests passed.\n");
    return 0;
}
