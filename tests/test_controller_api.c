/*
 * test_controller_api — the typed controller client (§25) against a real
 * loopback RESP server: happy-path round-trips for status/epoch/object-CAS/
 * lease/event/watch/group, and the required negative tests (unauthenticated
 * and tenant-guest principals get refused, never served).
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>
#include <netinet/in.h>

#include "qihse_controller.h"
#include "qihse_resp_wire.h"
#include "qihse_kv_store.h"
#include "qihse_auth.h"
#include "qihse_cluster_slot.h"

static uint16_t free_tcp_port(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    assert(fd >= 0);
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    assert(bind(fd, (struct sockaddr*)&addr, sizeof addr) == 0);
    socklen_t len = sizeof addr;
    assert(getsockname(fd, (struct sockaddr*)&addr, &len) == 0);
    uint16_t port = ntohs(addr.sin_port);
    close(fd);
    return port;
}

int main(void) {
    char data_root[] = "build/ctrl_api_XXXXXX";
    assert(mkdtemp(data_root));
    setenv("QIHSE_DATA_DIR", data_root, 1);

    assert(qihse_auth_init());
    if (!qihse_auth_bootstrap_operator("CtrlOpPass1!")) {
        setenv("QIHSE_OPERATOR_PASSWORD", "CtrlOpPass1!", 1);
        assert(qihse_auth_init());
    }
    qihse_user_t* op = qihse_auth_get_user(0);
    assert(op);

    qihse_kv_store_t* store = qihse_kv_store_create();
    assert(store);

    char node_id[QIHSE_CLUSTER_NODE_ID_LEN + 1u];
    qihse_cluster_node_id_from_seed("ctrl-api-node", strlen("ctrl-api-node"), node_id);
    uint16_t port = free_tcp_port();
    qihse_resp_server_config_t scfg;
    qihse_resp_server_config_init(&scfg);
    scfg.node_id = node_id;
    scfg.bind_address = "127.0.0.1";
    scfg.advertise_address = "127.0.0.1";
    scfg.port = port;
    scfg.bus_port = free_tcp_port();
    scfg.store = store;
    scfg.enable_bus = false;
    scfg.enable_failover = false;
    scfg.auth_required = true;
    scfg.federation_journal_directory = data_root;
    qihse_resp_server_t* server = qihse_resp_server_create(&scfg);
    assert(server);
    assert(qihse_resp_server_start(server));

    /* ── Connect + AUTH via the client ─────────────────────────────── */
    qihse_controller_config_t cc = {
        .host = "127.0.0.1", .port = port,
        .username = "GODMODE_OP", .password = "CtrlOpPass1!",
    };
    qihse_controller_t* c = qihse_controller_connect(&cc);
    assert(c && qihse_controller_connected(c));

    qihse_ctrl_reply_t* r;
    int64_t n;

    /* Federation.Status → bulk text. */
    r = qihse_ctrl_federation_status(c);
    assert(r && r->kind == QIHSE_CTRL_BULK && r->text_len > 0);
    qihse_ctrl_reply_free(r);

    /* Namespace + epoch. */
    r = qihse_ctrl_ns_register(c, "ctl-ns", "LOCAL", NULL);
    assert(qihse_ctrl_reply_ok(r));
    qihse_ctrl_reply_free(r);
    r = qihse_ctrl_ns_writable(c, "ctl-ns");
    assert(qihse_ctrl_reply_int(r, &n) && n == 1);
    qihse_ctrl_reply_free(r);
    r = qihse_ctrl_epoch_next(c);
    assert(qihse_ctrl_reply_int(r, &n) && n >= 1);
    uint64_t epoch = (uint64_t)n;
    qihse_ctrl_reply_free(r);

    /* Object CAS: create, read back, reject a stale generation. */
    r = qihse_ctrl_object_cas(c, "ctl-ns", "workload/vm-1/desired", "running", 0);
    assert(qihse_ctrl_reply_int(r, &n) && n == 1);
    qihse_ctrl_reply_free(r);
    r = qihse_ctrl_object_get(c, "ctl-ns", "workload/vm-1/desired");
    assert(r && r->kind == QIHSE_CTRL_ARRAY && r->count == 2);
    assert(r->items[0].kind == QIHSE_CTRL_INT && r->items[0].integer == 1);
    assert(r->items[1].kind == QIHSE_CTRL_BULK &&
           strcmp(qihse_ctrl_reply_text(&r->items[1]), "running") == 0);
    qihse_ctrl_reply_free(r);
    r = qihse_ctrl_object_cas(c, "ctl-ns", "workload/vm-1/desired", "stopped", 7);
    assert(qihse_ctrl_reply_int(r, &n) && n == 0);   /* stale generation refused */
    qihse_ctrl_reply_free(r);

    /* Lease lifecycle: acquire at the epoch we hold, read, renew, release. */
    r = qihse_ctrl_lease_acquire(c, "ctl-ns", "vm-1", epoch, 60000u);
    assert(r && r->kind == QIHSE_CTRL_BULK);
    char lease_id[64];
    snprintf(lease_id, sizeof(lease_id), "%s", qihse_ctrl_reply_text(r));
    qihse_ctrl_reply_free(r);
    r = qihse_ctrl_lease_read(c, lease_id);
    assert(r && r->kind == QIHSE_CTRL_ARRAY && r->count == 5);
    assert(strcmp(qihse_ctrl_reply_text(&r->items[0]), "vm-1") == 0);
    qihse_ctrl_reply_free(r);
    r = qihse_ctrl_lease_renew(c, lease_id, 120000u);
    assert(qihse_ctrl_reply_ok(r));
    qihse_ctrl_reply_free(r);
    r = qihse_ctrl_lease_release(c, lease_id);
    assert(qihse_ctrl_reply_ok(r));
    qihse_ctrl_reply_free(r);
    printf("PASS object CAS + lease lifecycle through the controller client\n");

    /* Event journal + resumable watch. */
    r = qihse_ctrl_event_append(c, "workload.observed.running", "vm-1",
                                "{\"domain_id\":7}", 15);
    assert(qihse_ctrl_reply_int(r, &n) && n > 0);
    qihse_ctrl_reply_free(r);

    r = qihse_ctrl_watch_open(c, "vm-1");
    assert(qihse_ctrl_reply_int(r, &n) && n >= 0);
    uint32_t wid = (uint32_t)n;
    qihse_ctrl_reply_free(r);
    r = qihse_ctrl_watch_next(c, wid);
    assert(r && r->kind == QIHSE_CTRL_ARRAY && r->count == 4);
    assert(r->items[0].kind == QIHSE_CTRL_INT);
    assert(strcmp(qihse_ctrl_reply_text(&r->items[1]), "workload.observed.running") == 0);
    assert(strcmp(qihse_ctrl_reply_text(&r->items[2]), "vm-1") == 0);
    uint64_t seen_off = (uint64_t)r->items[0].integer;
    qihse_ctrl_reply_free(r);
    r = qihse_ctrl_watch_ack(c, wid, seen_off);
    assert(qihse_ctrl_reply_ok(r));
    qihse_ctrl_reply_free(r);
    /* Watch resume: rewind, the same event is delivered again (at-least-once). */
    r = qihse_ctrl_watch_resume(c, wid, 0);
    assert(qihse_ctrl_reply_ok(r));
    qihse_ctrl_reply_free(r);
    r = qihse_ctrl_watch_next(c, wid);
    if (!r || r->kind != QIHSE_CTRL_ARRAY || r->count != 4)
        fprintf(stderr, "watch_next after resume: kind=%d text=%s\n",
                r ? (int)r->kind : -1, r && r->text ? r->text : "(none)");
    assert(r && r->kind == QIHSE_CTRL_ARRAY && r->count == 4);
    qihse_ctrl_reply_free(r);
    r = qihse_ctrl_event_replay(c, 0);
    assert(r && r->kind == QIHSE_CTRL_ARRAY && r->count >= 3);
    qihse_ctrl_reply_free(r);
    printf("PASS event append + resumable watch through the controller client\n");

    /* Groups, conflicts, metrics, rejoin (negative shape). */
    r = qihse_ctrl_group_create(c, "core-security", "QUORUM");
    assert(qihse_ctrl_reply_ok(r));
    qihse_ctrl_reply_free(r);
    r = qihse_ctrl_group_list(c);
    assert(r && r->kind == QIHSE_CTRL_ARRAY);
    qihse_ctrl_reply_free(r);
    r = qihse_ctrl_conflict_list(c);
    assert(r && r->kind == QIHSE_CTRL_ARRAY);
    qihse_ctrl_reply_free(r);
    r = qihse_ctrl_node_list(c);
    assert(r && r->kind == QIHSE_CTRL_ARRAY);
    qihse_ctrl_reply_free(r);
    r = qihse_ctrl_metrics(c, NULL);
    assert(r && r->kind == QIHSE_CTRL_BULK && r->text_len > 0);
    qihse_ctrl_reply_free(r);
    r = qihse_ctrl_security_observe(c);
    assert(r && r->kind == QIHSE_CTRL_ARRAY && r->count == 9);
    qihse_ctrl_reply_free(r);

    /* ── Negative: unauthenticated connect is refused every command ─── */
    qihse_controller_config_t nc = { .host = "127.0.0.1", .port = port };
    qihse_controller_t* u = qihse_controller_connect(&nc);
    assert(u);
    r = qihse_ctrl_federation_status(u);
    assert(r && r->kind == QIHSE_CTRL_ERROR);
    assert(strstr(qihse_ctrl_reply_text(r), "NOAUTH") != NULL ||
           strstr(qihse_ctrl_reply_text(r), "NOPERM") != NULL);
    qihse_ctrl_reply_free(r);
    r = qihse_ctrl_object_get(u, "ctl-ns", "workload/vm-1/desired");
    assert(r && r->kind == QIHSE_CTRL_ERROR);
    qihse_ctrl_reply_free(r);
    qihse_controller_destroy(u);

    /* ── Negative: a tenant guest authenticates but gets NOPERM ─────── */
    qihse_user_t* tenant = qihse_auth_create_tenant_user(op,
        42u, 109u, QIHSE_ROLE_GUEST, 0, 0, "CtrlGuestP1!", false);
    assert(tenant);
    qihse_controller_config_t gc = {
        .host = "127.0.0.1", .port = port,
        .username = "User_109", .password = "CtrlGuestP1!",
    };
    qihse_controller_t* g = qihse_controller_connect(&gc);
    assert(g);
    r = qihse_ctrl_federation_status(g);
    assert(r && r->kind == QIHSE_CTRL_ERROR);
    assert(strstr(qihse_ctrl_reply_text(r), "NOPERM") != NULL);
    qihse_ctrl_reply_free(r);
    r = qihse_ctrl_lease_acquire(g, "ctl-ns", "vm-1", epoch, 60000u);
    assert(r && r->kind == QIHSE_CTRL_ERROR);
    assert(strstr(qihse_ctrl_reply_text(r), "NOPERM") != NULL);
    qihse_ctrl_reply_free(r);
    r = qihse_ctrl_watch_open(g, NULL);
    assert(r && r->kind == QIHSE_CTRL_ERROR);
    qihse_ctrl_reply_free(r);
    qihse_controller_destroy(g);
    printf("PASS negative: unauthenticated and tenant principals refused, no data served\n");

    qihse_controller_destroy(c);
    qihse_resp_server_stop(server);
    qihse_resp_server_destroy(server);
    qihse_kv_store_destroy(store);
    printf("controller api tests passed\n");
    return 0;
}
