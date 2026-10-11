/*
 * qihse_browser_fixture.c — the C half of the browser negative-auth test.
 *
 * AGENTS.md invariant 3 requires every new externally reachable
 * data-access surface to ship a low-clearance/high-data negative test in
 * CI.  The browser's reachable surface is the HTTP bridge; this fixture
 * provides the data plane it talks to:
 *
 *   - an in-process RESP server on loopback (auth required),
 *   - a low-clearance ANALYST principal (classification 2),
 *   - classified keys above that clearance (classification 3/4) plus
 *     unclassified controls,
 *
 * and then execs python/tests/test_browser_negative_auth.py, which
 * starts the bridge pointed at this fixture and asserts over HTTP that
 * the ANALYST session can neither list nor fetch the classified keys
 * and that FEDERATION.* surfaces render NOPERM instead of leaking.
 *
 * C owns the principals (user creation is C-API only); Python owns the
 * HTTP assertions against the actual adapter under test.
 */

#include "qihse_auth.h"
#include "qihse_kv_store.h"
#include "qihse_vector_db.h"
#include "qihse_resp_wire.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#define DEFAULT_PORT 7390

static const char* OPERATOR_PASS = "FixtureOpPass1!";
static const char* ANALYST_NAME  = "fixture_analyst";
static const char* ANALYST_PASS  = "AnalystPass123!";
static const char* TENANT_NAME   = "fixture_tenant";
static const char* TENANT_PASS   = "TenantPass1234!";

int main(int argc, char** argv) {
    uint16_t port = DEFAULT_PORT;
    if (argc > 1) port = (uint16_t)atoi(argv[1]);

    {
        /* Per-test audit/chain isolation (parallel aggregates). */
        char qdd[] = "build/qihse_browser_fixture_XXXXXX";
        if (mkdtemp(qdd)) setenv("QIHSE_DATA_DIR", qdd, 1);
    }

    assert(qihse_auth_init());
    qihse_user_t* op = qihse_auth_get_user(0);
    assert(op != NULL);
    assert(qihse_auth_bootstrap_operator(OPERATOR_PASS));

    /* Low-clearance principal: ANALYST role, classification 2, no SCI.
     * create_user auto-names it User_<id>; give it a wire-authable name.
     * System-domain: exercises the CLASSIFICATION gates through the
     * bridge (must see pub:*, never sec:*). */
    qihse_user_t* analyst = qihse_auth_create_user(
        op, 6001, QIHSE_ROLE_ANALYST, 2, 0x0000, ANALYST_PASS, false);
    assert(analyst != NULL);
    assert(qihse_auth_modify_user(op, 6001, ANALYST_NAME, NULL, -1, -1, -1, -1));

    /* Tenant-scoped principal: exercises the FEDERATION system-domain
     * gate through the bridge (FEDERATION.* must render NOPERM). */
    qihse_user_t* tenant_analyst = qihse_auth_create_tenant_user(
        op, 77, 6002, QIHSE_ROLE_ANALYST, 0, 0x0000, TENANT_PASS, false);
    assert(tenant_analyst != NULL);
    assert(qihse_auth_modify_user(op, 6002, TENANT_NAME, NULL, -1, -1, -1, -1));

    qihse_kv_store_t* store = qihse_kv_store_create();
    assert(store != NULL);
    qihse_vector_db_t vdb = qihse_vector_db_create(QIHSE_VECTOR_DB_INMEMORY, NULL, NULL);
    assert(vdb != NULL);

    /* Unclassified controls the analyst CAN see... */
    assert(qihse_kv_set_user(store, "pub:welcome", "hello analyst", 0, 0, op));
    assert(qihse_kv_set_user(store, "pub:status", "all systems nominal", 0, 0, op));
    /* ...and classified data far above clearance 2 that MUST be invisible
     * through any browser surface (invariant 1 + 3).  The sentinel values
     * are grepped for in the HTTP responses by the Python test. */
    assert(qihse_kv_set_user(store, "sec:natsec-brief",
                             "TOP SECRET payload SENTINEL-VALUE-9174", 4, 0, op));
    assert(qihse_kv_set_user(store, "sec:codeword-roster",
                             "SECRET roster SENTINEL-VALUE-5309", 3, 0x0004, op));

    qihse_resp_server_config_t config;
    qihse_resp_server_config_init(&config);
    config.store = store;
    config.vdb = vdb;
    config.port = port;
    config.bind_address = "127.0.0.1";
    config.advertise_address = "127.0.0.1";
    config.auth_required = true;
    config.enable_task_queue = false;
    config.enable_task_workers = false;
    config.enable_task_scheduler = false;

    qihse_resp_server_t* server = qihse_resp_server_create(&config);
    if (!server) {
        fprintf(stderr, "[fixture] server create failed (port %u busy?)\n", port);
        return 1;
    }
    assert(qihse_resp_server_start(server));
    printf("[fixture] RESP on 127.0.0.1:%u (auth required); "
           "analyst=%s clearance=2; classified keys seeded\n",
           qihse_resp_server_port(server), ANALYST_NAME);
    fflush(stdout);

    /* Hand the port the server actually bound (0 = ephemeral). */
    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%u", qihse_resp_server_port(server));

    char py_path[] = "python/tests/test_browser_negative_auth.py";
    char* child_argv[5] = {(char*)"python3", py_path, (char*)"--port", port_str, NULL};

    setenv("PYTHONPATH", "python", 1);
    setenv("LD_LIBRARY_PATH", ".", 1);

    pid_t pid = fork();
    if (pid == 0) {
        execvp("python3", child_argv);
        perror("execvp python3");
        _exit(127);
    }
    int status = 0;
    waitpid(pid, &status, 0);

    qihse_resp_server_stop(server);
    qihse_resp_server_destroy(server);

    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
        printf("[PASS] browser negative-auth (fixture + bridge asserts)\n");
        return 0;
    }
    fprintf(stderr, "[FAIL] python asserts exited status=%d\n",
            WIFEXITED(status) ? WEXITSTATUS(status) : -1);
    return 1;
}
