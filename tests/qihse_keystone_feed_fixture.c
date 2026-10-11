/*
 * qihse_keystone_feed_fixture.c — W7 item 5: the C half of the wire-level
 * KEYSTONE feed test.
 *
 * Boots a journal-backed RESP server on loopback with:
 *   - a provisioned KEYSTONE index identity (tenant 77, clearance 2,
 *     SCI 0x1) named "feedidx",
 *   - a second, LOWER identity (clearance 0, same tenant) named "feedlow",
 *   - six pre-published feed records: three the identities may see
 *     (classification <= 2 within SCI 0x1, tenant 77) and three they must
 *     not (classification 5; wrong compartment; foreign tenant) — the
 *     denied payloads carry SENTINEL strings the python test greps for.
 *
 * Then execs python/tests/test_keystone_feed_wire.py, which consumes the
 * feed through the real socket as both identities and asserts the
 * classification-preserving envelope plus the denials (AGENTS.md
 * invariant 3: the new disclosure surface is the SDK + wire path).
 */

#include "qihse_auth.h"
#include "qihse_federation.h"
#include "qihse_keystone.h"
#include "qihse_kv_store.h"
#include "qihse_vector_db.h"
#include "qihse_resp_wire.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#define DEFAULT_PORT 7403
#define INDEX_TENANT 77u
#define INDEX_USER 6101u
#define LOW_USER 6102u

static const char* OPERATOR_PASS = "FeedFixturePass1!";

static void publish(qihse_federation_journal_t* j, qihse_user_t* op,
                    const qihse_uuid_t* node, const char* type,
                    const char* resource, uint16_t classif, uint16_t sci,
                    uint32_t tenant, const char* payload) {
    qihse_keystone_feed_record_t rec;
    memset(&rec, 0, sizeof(rec));
    rec.classification = classif;
    rec.sci = sci;
    rec.tenant_id = tenant;
    rec.generation = 1;
    assert(qihse_uuid_from_seed(resource, strlen(resource), &rec.object_id));
    qihse_federation_event_t ev;
    assert(qihse_keystone_feed_publish(j, op, node, type, resource, &rec,
                                       (const uint8_t*)payload, strlen(payload),
                                       &ev));
}

int main(int argc, char** argv) {
    uint16_t port = DEFAULT_PORT;
    if (argc > 1) port = (uint16_t)atoi(argv[1]);

    {
        char qdd[] = "build/keystone_feed_fixture_XXXXXX";
        if (mkdtemp(qdd)) setenv("QIHSE_DATA_DIR", qdd, 1);
    }

    assert(qihse_auth_init());
    qihse_user_t* op = qihse_auth_get_user(0);
    assert(op != NULL);
    assert(qihse_auth_bootstrap_operator(OPERATOR_PASS));

    /* The index identity: tenant-scoped ANALYST at clearance 2 / SCI 0x1,
     * renamed for wire AUTH.  A second identity at clearance 0 is the
     * low-clearance negative case. */
    qihse_user_t* idx = qihse_keystone_feed_identity_provision(
        op, INDEX_TENANT, INDEX_USER, 2, 0x1, "FeedIdxPass123!");
    assert(idx != NULL);
    assert(qihse_auth_modify_user(op, INDEX_USER, "feedidx", NULL, -1, -1, -1, -1));
    qihse_user_t* low = qihse_keystone_feed_identity_provision(
        op, INDEX_TENANT, LOW_USER, 0, 0, "FeedLowPass123!");
    assert(low != NULL);
    assert(qihse_auth_modify_user(op, LOW_USER, "feedlow", NULL, -1, -1, -1, -1));

    qihse_kv_store_t* store = qihse_kv_store_create();
    assert(store != NULL);
    qihse_vector_db_t vdb = qihse_vector_db_create(QIHSE_VECTOR_DB_INMEMORY, NULL, NULL);
    assert(vdb != NULL);

    /* Pre-publish into the journal directory the server will open. */
    const char* jdir = getenv("QIHSE_DATA_DIR");
    char jpath[600];
    snprintf(jpath, sizeof(jpath), "%s/journal", jdir);
    qihse_federation_journal_t* j = qihse_federation_journal_open(
        jpath, QIHSE_ES_DURABILITY_FDATASYNC);
    assert(j != NULL);
    qihse_uuid_t node;
    assert(qihse_uuid_from_seed("feed-fixture-node", strlen("feed-fixture-node"),
                                &node));

    /* Visible to feedidx (clearance 2, SCI 0x1, tenant 77). */
    publish(j, op, &node, "index.doc", "feed/doc/open-1", 0, 0, INDEX_TENANT,
            "OPEN-PAYLOAD-AA");
    publish(j, op, &node, "index.doc", "feed/doc/secret-2", 2, 0x1, INDEX_TENANT,
            "CLEARED-PAYLOAD-BB");
    publish(j, op, &node, "index.doc", "feed/doc/edge-3", 2, 0x0, INDEX_TENANT,
            "EDGE-PAYLOAD-CC");
    /* Denied for feedidx: above clearance, wrong compartment, foreign tenant. */
    publish(j, op, &node, "index.doc", "feed/doc/high", 5, 0x1, INDEX_TENANT,
            "SENTINEL-DENIED-HIGH");
    publish(j, op, &node, "index.doc", "feed/doc/compartment", 2, 0x4, INDEX_TENANT,
            "SENTINEL-DENIED-SCI");
    publish(j, op, &node, "index.doc", "feed/doc/foreign", 0, 0, 88,
            "SENTINEL-DENIED-TENANT");
    qihse_federation_journal_destroy(j);

    qihse_resp_server_config_t config;
    qihse_resp_server_config_init(&config);
    config.store = store;
    config.vdb = vdb;
    config.port = port;
    config.bind_address = "127.0.0.1";
    config.advertise_address = "127.0.0.1";
    config.auth_required = true;
    config.federation_journal_directory = jpath;
    config.federation_journal_durability = QIHSE_ES_DURABILITY_FDATASYNC;
    config.enable_task_queue = false;
    config.enable_task_workers = false;
    config.enable_task_scheduler = false;

    qihse_resp_server_t* server = qihse_resp_server_create(&config);
    if (!server) {
        fprintf(stderr, "[feed-fixture] server create failed (port %u busy?)\n", port);
        return 1;
    }
    assert(qihse_resp_server_start(server));
    printf("[feed-fixture] RESP on 127.0.0.1:%u (journal-backed; feedidx c2/s1/t77, "
           "feedlow c0; 3 visible + 3 denied records)\n",
           qihse_resp_server_port(server));
    fflush(stdout);

    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%u", qihse_resp_server_port(server));
    char py_path[] = "python/tests/test_keystone_feed_wire.py";
    char* child_argv[5] = {(char*)"python3", py_path, (char*)"--port", port_str, NULL};
    setenv("PYTHONPATH", "python", 1);
    setenv("LD_LIBRARY_PATH", ".", 1);

    if (argc > 2 && strcmp(argv[2], "serve") == 0) {
        /* Debug/serve-only mode: stay up until killed (cursor probes). */
        printf("[feed-fixture] serve-only; Ctrl-C to stop\n");
        for (;;) sleep(60);
    }
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
        printf("[PASS] keystone feed wire (fixture + SDK asserts)\n");
        return 0;
    }
    fprintf(stderr, "[FAIL] python asserts exited status=%d\n",
            WIFEXITED(status) ? WEXITSTATUS(status) : -1);
    return 1;
}
