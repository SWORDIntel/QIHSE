/* test_slot_migration_auth.c — negative authorization tests for the pinned
 * slot-migration QKP surface (repo invariant 3).
 *
 * A pinned migration peer (QIHSE_RESP_AUTH_QKP_MIGRATION) may run only the
 * data-movement commands (ASKING/SET/GET/DEL) — never operator/administrative
 * commands. This exercises the allowlist primitive directly.
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "qihse_resp_cluster.h"

static void check(const char* cmd, int expect_allowed) {
    int got = qihse_resp_migration_command_allowed(cmd, strlen(cmd)) ? 1 : 0;
    if (got != expect_allowed) {
        fprintf(stderr, "FAIL: '%s' expected %s, got %s\n", cmd,
                expect_allowed ? "allowed" : "denied", got ? "allowed" : "denied");
        abort();
    }
}

int main(void) {
    /* data-movement commands are permitted */
    check("ASKING", 1);
    check("asking", 1); /* case-insensitive */
    check("SET", 1);
    check("GET", 1);
    check("DEL", 1);
    printf("[PASS] migration peer may run ASKING/SET/GET/DEL (case-insensitive)\n");

    /* operator / administrative / other commands are denied */
    check("CLUSTER", 0);
    check("FTS.SEARCH", 0);
    check("KEYS", 0);
    check("QIHSE.USER.CREATE", 0);
    check("REPL.DELTA", 0);
    check("MACHINEAUTH", 0);
    check("AUTH", 0);
    check("SETEX", 0);
    check("SETRANGE", 0); /* only exact SET, not the family */
    check("", 0);
    check("SETTING", 0); /* prefix match is NOT enough */
    printf("[PASS] migration peer denied operator/administrative commands\n");

    printf("All slot-migration auth tests passed.\n");
    return 0;
}
