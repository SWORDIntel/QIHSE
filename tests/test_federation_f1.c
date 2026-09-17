/*
 * test_federation_f1.c — F1 Sovereign local state.
 *
 * Acceptance criteria exercised:
 *   AC1 — A single isolated node can recover and service authorized LOCAL
 *         state without peer availability.
 *   AC2 — Loss of federation quorum does not globally force QIHSE read-only.
 *
 * Covers:
 *   - consistency class enum round-trips and local-safe/strong partitioning
 *   - federation state enum round-trips
 *   - namespace registry: register LOCAL/EVENTUAL/CAUSAL/QUORUM/LINEARIZABLE,
 *     lookup, unregister, foreach
 *   - namespace writability under each federation state
 *   - federation status: init, recompute per state, format
 *   - isolated node: LOCAL namespace writable, QUORUM namespace not writable,
 *     local_database stays read-write (AC1+AC2)
 *
 * The KV namespace is isolated under build/ via mkdtemp().
 */
#include "qihse_auth.h"
#include "qihse_cluster_slot.h"
#include "qihse_federation.h"
#include "qihse_kv_store.h"
#include "qihse_resp_wire.h"

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

static bool count_cb(const qihse_federation_namespace_t* n, void* ud) {
    (void)n; (*(size_t*)ud)++; return true;
}

static void test_consistency_classes(void) {
    for (int i = 0; i <= (int)QIHSE_CONSISTENCY_LINEARIZABLE; i++) {
        qihse_consistency_class_t c = (qihse_consistency_class_t)i;
        const char* name = qihse_consistency_class_name(c);
        assert(name);
        qihse_consistency_class_t parsed;
        assert(qihse_consistency_class_parse(name, &parsed));
        assert(parsed == c);
    }
    assert(!qihse_consistency_class_parse("BOGUS", &(qihse_consistency_class_t){0}));
    assert(qihse_consistency_class_is_local_safe(QIHSE_CONSISTENCY_LOCAL));
    assert(qihse_consistency_class_is_local_safe(QIHSE_CONSISTENCY_EVENTUAL));
    assert(qihse_consistency_class_is_local_safe(QIHSE_CONSISTENCY_CAUSAL));
    assert(!qihse_consistency_class_is_local_safe(QIHSE_CONSISTENCY_QUORUM));
    assert(!qihse_consistency_class_is_local_safe(QIHSE_CONSISTENCY_LINEARIZABLE));
    assert(qihse_consistency_class_is_strong(QIHSE_CONSISTENCY_QUORUM));
    assert(qihse_consistency_class_is_strong(QIHSE_CONSISTENCY_LINEARIZABLE));
    assert(!qihse_consistency_class_is_strong(QIHSE_CONSISTENCY_LOCAL));
    printf("PASS consistency class enum round-trips and local-safe/strong partition\n");
}

static void test_federation_states(void) {
    for (int i = 0; i <= (int)QIHSE_FEDERATION_STATE_MAINTENANCE; i++) {
        qihse_federation_state_t s = (qihse_federation_state_t)i;
        const char* name = qihse_federation_state_name(s);
        assert(name);
        qihse_federation_state_t parsed;
        assert(qihse_federation_state_parse(name, &parsed));
        assert(parsed == s);
    }
    assert(!qihse_federation_state_parse("bogus", &(qihse_federation_state_t){0}));
    assert(strcmp(qihse_local_db_state_name(QIHSE_LOCAL_DB_READ_WRITE), "read-write") == 0);
    assert(strcmp(qihse_local_db_state_name(QIHSE_LOCAL_DB_READ_ONLY), "read-only") == 0);
    printf("PASS federation state enum round-trips\n");
}

static void test_namespace_writability(void) {
    qihse_uuid_t local;
    assert(qihse_uuid_from_seed("f1-local", strlen("f1-local"), &local));
    qihse_uuid_t other;
    assert(qihse_uuid_from_seed("f1-other", strlen("f1-other"), &other));

    qihse_federation_namespace_t ns_local = {
        .consistency = QIHSE_CONSISTENCY_LOCAL,
        .authority_node = local,
        .local_authority = true,
    };
    qihse_federation_namespace_t ns_quorum = {
        .consistency = QIHSE_CONSISTENCY_QUORUM,
        .authority_node = local,
        .local_authority = true,
    };
    qihse_federation_namespace_t ns_linear = {
        .consistency = QIHSE_CONSISTENCY_LINEARIZABLE,
        .authority_node = other,
        .local_authority = false,
    };

    /* AC1+AC2: LOCAL stays writable in every state except maintenance. */
    for (int i = 0; i <= (int)QIHSE_FEDERATION_STATE_MAINTENANCE; i++) {
        qihse_federation_state_t s = (qihse_federation_state_t)i;
        bool w = qihse_federation_namespace_writable(&ns_local, s, &local);
        assert(w && "LOCAL must be writable in every federation state");
    }
    /* Strong namespaces fail closed when isolated/fenced/recovering/maintenance. */
    assert(qihse_federation_namespace_writable(&ns_quorum, QIHSE_FEDERATION_STATE_CONNECTED, &local));
    assert(qihse_federation_namespace_writable(&ns_quorum, QIHSE_FEDERATION_STATE_DEGRADED, &local));
    assert(!qihse_federation_namespace_writable(&ns_quorum, QIHSE_FEDERATION_STATE_ISOLATED, &local));
    assert(!qihse_federation_namespace_writable(&ns_quorum, QIHSE_FEDERATION_STATE_RECOVERING, &local));
    assert(!qihse_federation_namespace_writable(&ns_quorum, QIHSE_FEDERATION_STATE_FENCED, &local));
    assert(!qihse_federation_namespace_writable(&ns_quorum, QIHSE_FEDERATION_STATE_MAINTENANCE, &local));
    assert(qihse_federation_namespace_writable(&ns_linear, QIHSE_FEDERATION_STATE_CONNECTED, &local));
    assert(!qihse_federation_namespace_writable(&ns_linear, QIHSE_FEDERATION_STATE_ISOLATED, &local));
    printf("PASS namespace writability: LOCAL always writable, strong fail closed when isolated\n");
}

static void test_federation_status(void) {
    qihse_uuid_t node;
    assert(qihse_uuid_from_seed("f1-status-node", strlen("f1-status-node"), &node));
    qihse_federation_status_t st;
    qihse_federation_status_init(&st, &node);
    assert(st.federation_state == QIHSE_FEDERATION_STATE_CONNECTED);
    assert(st.local_database == QIHSE_LOCAL_DB_READ_WRITE);
    assert(st.strong_namespaces_available);
    assert(st.eventual_namespaces_available);
    assert(!st.reconciliation_required);

    /* AC2: isolated node keeps local_database read-write. */
    st.federation_state = QIHSE_FEDERATION_STATE_ISOLATED;
    qihse_federation_status_recompute(&st);
    assert(st.local_database == QIHSE_LOCAL_DB_READ_WRITE);
    assert(!st.strong_namespaces_available);
    assert(st.eventual_namespaces_available);
    assert(st.reconciliation_required);

    /* Fenced: local DB still RW for local-safe, strong unavailable. */
    st.federation_state = QIHSE_FEDERATION_STATE_FENCED;
    qihse_federation_status_recompute(&st);
    assert(st.local_database == QIHSE_LOCAL_DB_READ_WRITE);
    assert(!st.strong_namespaces_available);
    assert(st.reconciliation_required);

    /* Maintenance: local DB read-only by operator choice. */
    st.federation_state = QIHSE_FEDERATION_STATE_MAINTENANCE;
    qihse_federation_status_recompute(&st);
    assert(st.local_database == QIHSE_LOCAL_DB_READ_ONLY);
    assert(!st.strong_namespaces_available);

    /* Recovering: local DB RW, strong unavailable, reconciliation required. */
    st.federation_state = QIHSE_FEDERATION_STATE_RECOVERING;
    qihse_federation_status_recompute(&st);
    assert(st.local_database == QIHSE_LOCAL_DB_READ_WRITE);
    assert(!st.strong_namespaces_available);
    assert(st.reconciliation_required);

    /* Connected: everything available. */
    st.federation_state = QIHSE_FEDERATION_STATE_CONNECTED;
    qihse_federation_status_recompute(&st);
    assert(st.local_database == QIHSE_LOCAL_DB_READ_WRITE);
    assert(st.strong_namespaces_available);
    assert(st.eventual_namespaces_available);
    assert(!st.reconciliation_required);

    char buf[512];
    qihse_federation_status_format(&st, buf, sizeof(buf));
    assert(strstr(buf, "\"federation_state\":\"connected\"") != NULL);
    assert(strstr(buf, "\"local_database\":\"read-write\"") != NULL);
    assert(strstr(buf, "\"strong_namespaces_available\":true") != NULL);
    printf("PASS federation status recompute + format across all states\n");
}

/* ── Namespace registry (needs auth + KV) ───────────────────────────────── */

static void test_namespace_registry(void) {
    char data_root[] = "build/fed_f1_data_XXXXXX";
    assert(mkdtemp(data_root));
    setenv("QIHSE_DATA_DIR", data_root, 1);

    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator("F1OperatorPass1!"));
    qihse_user_t* op = qihse_auth_get_user(0);
    assert(op);

    qihse_kv_store_t* store = qihse_kv_store_create();
    assert(store);

    qihse_uuid_t local;
    assert(qihse_uuid_from_seed("f1-registry-local", strlen("f1-registry-local"), &local));
    qihse_uuid_t other;
    assert(qihse_uuid_from_seed("f1-registry-other", strlen("f1-registry-other"), &other));

    /* Register one namespace per consistency class. */
    assert(qihse_federation_namespace_register(store, op, "local-ns",
            QIHSE_CONSISTENCY_LOCAL, &local, &local));
    assert(qihse_federation_namespace_register(store, op, "eventual-ns",
            QIHSE_CONSISTENCY_EVENTUAL, &local, &local));
    assert(qihse_federation_namespace_register(store, op, "causal-ns",
            QIHSE_CONSISTENCY_CAUSAL, &local, &local));
    assert(qihse_federation_namespace_register(store, op, "quorum-ns",
            QIHSE_CONSISTENCY_QUORUM, &other, &local));
    assert(qihse_federation_namespace_register(store, op, "linear-ns",
            QIHSE_CONSISTENCY_LINEARIZABLE, &other, &local));

    /* Invalid name/class rejected. */
    assert(!qihse_federation_namespace_register(store, op, "",
            QIHSE_CONSISTENCY_LOCAL, &local, &local));
    assert(!qihse_federation_namespace_register(store, op, "bad-ns",
            (qihse_consistency_class_t)99, &local, &local));

    /* Lookups. */
    qihse_federation_namespace_t ns;
    assert(qihse_federation_namespace_lookup(store, op, "local-ns", &ns));
    assert(ns.consistency == QIHSE_CONSISTENCY_LOCAL);
    assert(ns.local_authority); /* LOCAL is always local-authority */
    assert(qihse_uuid_equal(&ns.authority_node, &local));

    assert(qihse_federation_namespace_lookup(store, op, "quorum-ns", &ns));
    assert(ns.consistency == QIHSE_CONSISTENCY_QUORUM);
    assert(!ns.local_authority); /* authority is `other`, not `local` */
    assert(qihse_uuid_equal(&ns.authority_node, &other));

    assert(qihse_federation_namespace_lookup(store, op, "eventual-ns", &ns));
    assert(ns.consistency == QIHSE_CONSISTENCY_EVENTUAL);
    assert(ns.local_authority); /* authority == local */

    assert(!qihse_federation_namespace_lookup(store, op, "missing-ns", &ns));

    /* foreach counts 5 registered namespaces. */
    size_t count = 0;
    qihse_federation_namespace_foreach(store, op, count_cb, &count);
    assert(count == 5);

    /* Unregister. */
    assert(qihse_federation_namespace_unregister(store, op, "causal-ns"));
    assert(!qihse_federation_namespace_lookup(store, op, "causal-ns", &ns));
    assert(!qihse_federation_namespace_unregister(store, op, "causal-ns"));

    /* AC1+AC2 end-to-end: an isolated node serves LOCAL writes, QUORUM fails closed. */
    qihse_federation_namespace_t local_ns, quorum_ns;
    assert(qihse_federation_namespace_lookup(store, op, "local-ns", &local_ns));
    assert(qihse_federation_namespace_lookup(store, op, "quorum-ns", &quorum_ns));
    assert(qihse_federation_namespace_writable(&local_ns, QIHSE_FEDERATION_STATE_ISOLATED, &local));
    assert(!qihse_federation_namespace_writable(&quorum_ns, QIHSE_FEDERATION_STATE_ISOLATED, &local));

    qihse_kv_store_destroy(store);
    printf("PASS namespace registry: register/lookup/unregister/foreach + isolated-node writability\n");
}

/* ── RESP-level FEDERATION.* commands ──────────────────────────────────── */

static uint16_t free_tcp_port(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    assert(fd >= 0);
    struct sockaddr_in addr; memset(&addr, 0, sizeof addr);
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

typedef struct { int fd; char buf[65536]; size_t fill; } client_t;

static bool read_line(client_t* c, char* out, size_t cap) {
    for (;;) {
        for (size_t i = 0; i < c->fill; i++) {
            if (c->buf[i] == '\n') {
                size_t len = i;
                if (len && c->buf[len - 1u] == '\r') len--;
                if (len >= cap) len = cap - 1u;
                memcpy(out, c->buf, len); out[len] = '\0';
                memmove(c->buf, c->buf + i + 1u, c->fill - i - 1u);
                c->fill -= i + 1u;
                return true;
            }
        }
        ssize_t n = recv(c->fd, c->buf + c->fill, sizeof(c->buf) - c->fill, 0);
        if (n <= 0) return false;
        c->fill += (size_t)n;
    }
}

static bool read_exact(client_t* c, char* out, size_t len) {
    while (c->fill < len) {
        ssize_t n = recv(c->fd, c->buf + c->fill, sizeof(c->buf) - c->fill, 0);
        if (n <= 0) return false;
        c->fill += (size_t)n;
    }
    memcpy(out, c->buf, len);
    memmove(c->buf, c->buf + len, c->fill - len);
    c->fill -= len;
    return true;
}

static bool read_reply(client_t* c, char* out, size_t cap, size_t* used) {
    char line[512];
    if (!read_line(c, line, sizeof(line))) return false;
    char type = line[0];
    const char* rest = line + 1;
    if (type == '+' || type == '-' || type == ':') {
        int n = snprintf(out + *used, cap - *used, "%s", rest);
        *used += (size_t)(n > 0 ? n : 0);
        return true;
    }
    if (type == '$') {
        int len = atoi(rest);
        if (len < 0) return true;
        char data[8192];
        if ((size_t)len >= sizeof(data)) return false;
        if (!read_exact(c, data, (size_t)len + 2u)) return false;
        data[len] = '\0';
        int n = snprintf(out + *used, cap - *used, "%s", data);
        *used += (size_t)(n > 0 ? n : 0);
        return true;
    }
    if (type == '*') {
        int count = atoi(rest);
        for (int i = 0; i < count; i++) {
            if (i && *used + 1u < cap) out[(*used)++] = '|';
            if (!read_reply(c, out, cap, used)) return false;
        }
        return true;
    }
    return false;
}

static void send_cmd(client_t* c, const char* a, const char* b, const char* d, const char* e) {
    const char* args[4] = { a, b, d, e };
    size_t argc = 0;
    for (size_t i = 0; i < 4u; i++) if (args[i]) argc++;
    char out[2048]; size_t off = 0;
    off += (size_t)snprintf(out + off, sizeof(out) - off, "*%zu\r\n", argc);
    for (size_t i = 0; i < argc; i++)
        off += (size_t)snprintf(out + off, sizeof(out) - off, "$%zu\r\n%s\r\n", strlen(args[i]), args[i]);
    assert(send(c->fd, out, off, 0) == (ssize_t)off);
}

static void test_resp_federation(void) {
    char data_root[] = "build/fed_f1_resp_XXXXXX";
    assert(mkdtemp(data_root));
    setenv("QIHSE_DATA_DIR", data_root, 1);

    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator("F1RespOpPass1!"));

    uint16_t port = free_tcp_port();
    qihse_kv_store_t* store = qihse_kv_store_create();
    assert(store);
    char node_id[QIHSE_CLUSTER_NODE_ID_LEN + 1u];
    qihse_cluster_node_id_from_seed("f1-resp-test-node", strlen("f1-resp-test-node"), node_id);
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
    qihse_resp_server_t* server = qihse_resp_server_create(&scfg);
    if (!server) {
        fprintf(stderr, "server create failed: errno=%d (%s) max_clients=%zu max_req=%zu\n",
                errno, strerror(errno), scfg.max_clients, scfg.max_request_bytes);
    }
    assert(server);
    assert(qihse_resp_server_start(server));

    client_t c; memset(&c, 0, sizeof c);
    struct sockaddr_in addr; memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(port);
    c.fd = socket(AF_INET, SOCK_STREAM, 0); assert(c.fd >= 0);
    assert(connect(c.fd, (struct sockaddr*)&addr, sizeof addr) == 0);

    char reply[8192]; size_t used;
    send_cmd(&c, "AUTH", "GODMODE_OP", "F1RespOpPass1!", NULL);
    used = 0; assert(read_reply(&c, reply, sizeof reply, &used));
    assert(strcmp(reply, "OK") == 0);

    /* FEDERATION.STATUS reports connected, read-write, strong available. */
    send_cmd(&c, "FEDERATION", "STATUS", NULL, NULL);
    used = 0; assert(read_reply(&c, reply, sizeof reply, &used));
    assert(strstr(reply, "\"federation_state\":\"connected\"") != NULL);
    assert(strstr(reply, "\"local_database\":\"read-write\"") != NULL);
    assert(strstr(reply, "\"strong_namespaces_available\":true") != NULL);

    /* Register a LOCAL and a QUORUM namespace. */
    send_cmd(&c, "FEDERATION", "NS.REGISTER", "local-ops", "LOCAL");
    used = 0; assert(read_reply(&c, reply, sizeof reply, &used));
    assert(strcmp(reply, "OK") == 0);
    send_cmd(&c, "FEDERATION", "NS.REGISTER", "cluster-cfg", "QUORUM");
    used = 0; assert(read_reply(&c, reply, sizeof reply, &used));
    assert(strcmp(reply, "OK") == 0);

    /* Both writable while connected. */
    send_cmd(&c, "FEDERATION", "NS.WRITABLE", "local-ops", NULL);
    used = 0; assert(read_reply(&c, reply, sizeof reply, &used));
    assert(strcmp(reply, "1") == 0);
    send_cmd(&c, "FEDERATION", "NS.WRITABLE", "cluster-cfg", NULL);
    used = 0; assert(read_reply(&c, reply, sizeof reply, &used));
    assert(strcmp(reply, "1") == 0);

    /* AC1+AC2: isolate the node. LOCAL stays writable, QUORUM fails closed,
     * and the status reports local_database=read-write. */
    send_cmd(&c, "FEDERATION", "STATE", "isolated", NULL);
    used = 0; assert(read_reply(&c, reply, sizeof reply, &used));
    assert(strcmp(reply, "OK") == 0);

    send_cmd(&c, "FEDERATION", "STATUS", NULL, NULL);
    used = 0; assert(read_reply(&c, reply, sizeof reply, &used));
    assert(strstr(reply, "\"federation_state\":\"isolated\"") != NULL);
    assert(strstr(reply, "\"local_database\":\"read-write\"") != NULL);
    assert(strstr(reply, "\"strong_namespaces_available\":false") != NULL);
    assert(strstr(reply, "\"reconciliation_required\":true") != NULL);

    send_cmd(&c, "FEDERATION", "NS.WRITABLE", "local-ops", NULL);
    used = 0; assert(read_reply(&c, reply, sizeof reply, &used));
    assert(strcmp(reply, "1") == 0); /* LOCAL still writable */
    send_cmd(&c, "FEDERATION", "NS.WRITABLE", "cluster-cfg", NULL);
    used = 0; assert(read_reply(&c, reply, sizeof reply, &used));
    assert(strcmp(reply, "0") == 0); /* QUORUM fails closed */

    /* NS.LIST shows both namespaces. */
    send_cmd(&c, "FEDERATION", "NS.LIST", NULL, NULL);
    used = 0; assert(read_reply(&c, reply, sizeof reply, &used));
    assert(strstr(reply, "local-ops") != NULL);
    assert(strstr(reply, "LOCAL") != NULL);
    assert(strstr(reply, "cluster-cfg") != NULL);
    assert(strstr(reply, "QUORUM") != NULL);

    /* NS.UNREGISTER removes one. */
    send_cmd(&c, "FEDERATION", "NS.UNREGISTER", "local-ops", NULL);
    used = 0; assert(read_reply(&c, reply, sizeof reply, &used));
    assert(strcmp(reply, "OK") == 0);
    send_cmd(&c, "FEDERATION", "NS.WRITABLE", "local-ops", NULL);
    used = 0; assert(read_reply(&c, reply, sizeof reply, &used));
    assert(strstr(reply, "namespace not found") != NULL);

    /* AGENTS.md invariant 3: low-clearance principal is denied FEDERATION.*
     * (a new externally reachable adapter). A tenant user (tenant_id != 0,
     * i.e. not the system domain) must be rejected with NOPERM and must not
     * see any federation status or namespace data. */
    qihse_user_t* tenant = qihse_auth_create_tenant_user(qihse_auth_get_user(0),
        42u, 100u, QIHSE_ROLE_GUEST, 0, 0, "TenantGuestPass1!", false);
    assert(tenant);
    /* Open a second connection and authenticate as the tenant guest. */
    client_t g; memset(&g, 0, sizeof g);
    g.fd = socket(AF_INET, SOCK_STREAM, 0); assert(g.fd >= 0);
    assert(connect(g.fd, (struct sockaddr*)&addr, sizeof addr) == 0);
    send_cmd(&g, "AUTH", "User_100", "TenantGuestPass1!", NULL);
    used = 0; assert(read_reply(&g, reply, sizeof reply, &used));
    assert(strcmp(reply, "OK") == 0);
    /* FEDERATION.STATUS is denied — no status disclosure to a tenant guest. */
    send_cmd(&g, "FEDERATION", "STATUS", NULL, NULL);
    used = 0; assert(read_reply(&g, reply, sizeof reply, &used));
    assert(strstr(reply, "NOPERM") != NULL);
    /* FEDERATION.NS.LIST is denied — no namespace enumeration. */
    send_cmd(&g, "FEDERATION", "NS.LIST", NULL, NULL);
    used = 0; assert(read_reply(&g, reply, sizeof reply, &used));
    assert(strstr(reply, "NOPERM") != NULL);
    /* FEDERATION.NS.REGISTER is denied — no namespace creation. */
    send_cmd(&g, "FEDERATION", "NS.REGISTER", "evil", "LOCAL");
    used = 0; assert(read_reply(&g, reply, sizeof reply, &used));
    assert(strstr(reply, "NOPERM") != NULL);
    close(g.fd);

    close(c.fd);
    qihse_resp_server_stop(server);
    qihse_resp_server_destroy(server);
    qihse_kv_store_destroy(store);
    printf("PASS RESP FEDERATION.STATUS/STATE/NS.REGISTER/LIST/WRITABLE/UNREGISTER (AC1+AC2) + tenant-guest NOPERM\n");
}

int main(void) {
    test_consistency_classes();
    test_federation_states();
    test_namespace_writability();
    test_federation_status();
    test_namespace_registry();
    test_resp_federation();
    printf("federation F1 tests passed\n");
    return 0;
}
