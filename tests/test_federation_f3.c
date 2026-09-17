/*
 * test_federation_f3.c — F3 Replication correctness.
 *
 * Acceptance criteria exercised:
 *   AC6 — Anti-entropy: peers can identify divergent ranges without full
 *         dataset transfer.
 *   AC7 — Conflicts: irreconcilable control-plane conflicts are recorded as
 *         explicit conflict objects, never silently overwritten.
 *
 * Covers:
 *   - conflict policy enum round-trip
 *   - conflict store: record, lookup, resolve, foreach
 *   - namespace manifest: build, compare (divergent vs identical)
 *   - anti-entropy sync plan: SEND, FETCH, CONFLICT actions
 *
 * The KV namespace is isolated under build/ via mkdtemp().  A single
 * shared data directory and KV store are used because qihse_kv_store
 * caches the data dir on first use.
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

/* ── Helpers ───────────────────────────────────────────────────────────── */

static bool conflict_count_cb(const qihse_federation_conflict_t* conflict,
                              void* user_data) {
    (void)conflict; (*(size_t*)user_data)++; return true;
}

/* ── Conflict policies ──────────────────────────────────────────────────── */

static void test_conflict_policies(void) {
    for (int i = 0; i <= (int)QIHSE_CONFLICT_CUSTOM; i++) {
        qihse_conflict_policy_t p = (qihse_conflict_policy_t)i;
        const char* name = qihse_conflict_policy_name(p);
        assert(name);
        qihse_conflict_policy_t parsed;
        assert(qihse_conflict_policy_parse(name, &parsed));
        assert(parsed == p);
    }
    qihse_conflict_policy_t dummy;
    assert(!qihse_conflict_policy_parse("bogus", &dummy));
    printf("PASS conflict policy enum round-trips\n");
}

/* ── Conflict store (uses shared store) ────────────────────────────────── */

static void test_conflict_store(qihse_kv_store_t* store, qihse_user_t* op) {
    /* Record a conflict. */
    qihse_federation_conflict_t c;
    memset(&c, 0, sizeof(c));
    assert(qihse_uuid_generate(&c.conflict_id));
    snprintf(c.namespace_name, sizeof(c.namespace_name), "core-security");
    snprintf(c.resource_id, sizeof(c.resource_id), "vm/web-01");
    c.policy = QIHSE_CONFLICT_MANUAL;
    c.local_mutation.consistency = QIHSE_CONSISTENCY_QUORUM;
    c.local_mutation.expected_generation = 5;
    c.remote_mutation.consistency = QIHSE_CONSISTENCY_QUORUM;
    c.remote_mutation.expected_generation = 5;
    const char* local_val = "running";
    const char* remote_val = "stopped";
    memcpy(c.local_value, local_val, strlen(local_val));
    c.local_value_len = strlen(local_val);
    memcpy(c.remote_value, remote_val, strlen(remote_val));
    c.remote_value_len = strlen(remote_val);
    snprintf(c.reason, sizeof(c.reason), "concurrent state transition");
    c.resolved = false;

    assert(qihse_federation_conflict_record(store, op, &c));

    /* Duplicate record is rejected. */
    assert(!qihse_federation_conflict_record(store, op, &c));

    /* Lookup returns the stored conflict. */
    qihse_federation_conflict_t fetched;
    assert(qihse_federation_conflict_lookup(store, op, &c.conflict_id, &fetched));
    assert(qihse_uuid_equal(&fetched.conflict_id, &c.conflict_id));
    assert(strcmp(fetched.namespace_name, "core-security") == 0);
    assert(strcmp(fetched.resource_id, "vm/web-01") == 0);
    assert(fetched.policy == QIHSE_CONFLICT_MANUAL);
    assert(!fetched.resolved);
    assert(fetched.local_value_len == strlen(local_val));
    assert(memcmp(fetched.local_value, local_val, strlen(local_val)) == 0);
    assert(fetched.remote_value_len == strlen(remote_val));
    assert(memcmp(fetched.remote_value, remote_val, strlen(remote_val)) == 0);
    assert(strcmp(fetched.reason, "concurrent state transition") == 0);

    printf("PASS conflict store: record/lookup/duplicate-rejection (AC7)\n");

    /* ── Resolve + foreach ──────────────────────────────────────────────── */

    /* Record two more conflicts. */
    qihse_federation_conflict_t c1, c2;
    memset(&c1, 0, sizeof(c1));
    memset(&c2, 0, sizeof(c2));
    assert(qihse_uuid_generate(&c1.conflict_id));
    assert(qihse_uuid_generate(&c2.conflict_id));
    snprintf(c1.namespace_name, sizeof(c1.namespace_name), "ns-a");
    snprintf(c2.namespace_name, sizeof(c2.namespace_name), "ns-b");
    c1.policy = QIHSE_CONFLICT_REJECT;
    c2.policy = QIHSE_CONFLICT_MANUAL;
    assert(qihse_federation_conflict_record(store, op, &c1));
    assert(qihse_federation_conflict_record(store, op, &c2));

    /* foreach finds all 3 unresolved (c + c1 + c2). */
    size_t count = 0;
    qihse_federation_conflict_foreach(store, op, conflict_count_cb, &count);
    assert(count == 3);

    /* Resolve c1. */
    qihse_uuid_t resolver;
    assert(qihse_uuid_from_seed("resolver", strlen("resolver"), &resolver));
    assert(qihse_federation_conflict_resolve(store, op, &c1.conflict_id, &resolver));

    /* foreach now finds 2 unresolved (c + c2). */
    count = 0;
    qihse_federation_conflict_foreach(store, op, conflict_count_cb, &count);
    assert(count == 2);

    /* Lookup c1 shows resolved. */
    qihse_federation_conflict_t fetched2;
    assert(qihse_federation_conflict_lookup(store, op, &c1.conflict_id, &fetched2));
    assert(fetched2.resolved);
    assert(qihse_uuid_equal(&fetched2.resolved_by, &resolver));

    /* Double-resolve is rejected. */
    assert(!qihse_federation_conflict_resolve(store, op, &c1.conflict_id, &resolver));

    printf("PASS conflict store: resolve + foreach skips resolved (AC7)\n");
}

/* ── Namespace manifest ────────────────────────────────────────────────── */

static void test_manifest(qihse_kv_store_t* store, qihse_user_t* op) {
    /* Populate the namespace "infra" with some objects. */
    qihse_kv_set_user(store, "ns:infra:vm/web-01", "running", 0, 0, op);
    qihse_kv_set_user(store, "ns:infra:vm/web-02", "running", 0, 0, op);
    qihse_kv_set_user(store, "ns:infra:vm/web-03", "stopped", 0, 0, op);
    qihse_kv_set_user(store, "ns:infra:volume/data-01", "attached", 0, 0, op);
    /* An unrelated namespace key should not appear. */
    qihse_kv_set_user(store, "ns:other:vm/web-99", "running", 0, 0, op);

    /* Build the manifest. */
    qihse_federation_manifest_t m;
    assert(qihse_federation_manifest_build(store, op, "infra", &m));
    assert(strcmp(m.namespace_name, "infra") == 0);
    assert(m.total_objects == 4);
    assert(m.entry_count >= 1);

    /* Build an identical manifest from a second store with the same data. */
    qihse_kv_store_t* store2 = qihse_kv_store_create();
    assert(store2);
    qihse_kv_set_user(store2, "ns:infra:vm/web-01", "running", 0, 0, op);
    qihse_kv_set_user(store2, "ns:infra:vm/web-02", "running", 0, 0, op);
    qihse_kv_set_user(store2, "ns:infra:vm/web-03", "stopped", 0, 0, op);
    qihse_kv_set_user(store2, "ns:infra:volume/data-01", "attached", 0, 0, op);
    qihse_federation_manifest_t m2;
    assert(qihse_federation_manifest_build(store2, op, "infra", &m2));

    /* AC6: identical manifests have zero divergent ranges. */
    qihse_federation_manifest_entry_t divergent[8];
    size_t ndiv = qihse_federation_manifest_compare(&m, &m2, divergent, 8);
    assert(ndiv == 0);

    /* Now diverge store2: change one value and add an object. */
    qihse_kv_set_user(store2, "ns:infra:vm/web-03", "running", 0, 0, op);
    qihse_kv_set_user(store2, "ns:infra:vm/web-04", "running", 0, 0, op);
    qihse_federation_manifest_t m3;
    assert(qihse_federation_manifest_build(store2, op, "infra", &m3));

    /* AC6: divergent manifests have at least 1 divergent range. */
    ndiv = qihse_federation_manifest_compare(&m, &m3, divergent, 8);
    assert(ndiv >= 1);

    /* AC6: a sync plan identifies the action needed. */
    qihse_federation_sync_range_t ranges[8];
    size_t nplan = qihse_federation_sync_plan(&m, &m3, ranges, 8);
    assert(nplan >= 1);
    bool found_action = false;
    for (size_t i = 0; i < nplan; i++) {
        if (ranges[i].action != QIHSE_SYNC_NONE) { found_action = true; break; }
    }
    assert(found_action);

    /* An empty namespace produces an empty manifest. */
    qihse_federation_manifest_t m_empty;
    assert(qihse_federation_manifest_build(store, op, "nonexistent", &m_empty));
    assert(m_empty.total_objects == 0);
    assert(m_empty.entry_count == 0);

    qihse_kv_store_destroy(store2);
    printf("PASS manifest: build + compare (AC6) + sync plan\n");
}

/* ── RESP-level F3 ────────────────────────────────────────────────────── */

static uint16_t f3_free_tcp_port(void) {
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

typedef struct { int fd; char buf[65536]; size_t fill; } f3_client_t;

static bool f3_read_line(f3_client_t* c, char* out, size_t cap) {
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

static bool f3_read_exact(f3_client_t* c, char* out, size_t len) {
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

static bool f3_read_reply(f3_client_t* c, char* out, size_t cap, size_t* used) {
    char line[512];
    if (!f3_read_line(c, line, sizeof(line))) return false;
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
        if (!f3_read_exact(c, data, (size_t)len + 2u)) return false;
        data[len] = '\0';
        int n = snprintf(out + *used, cap - *used, "%s", data);
        *used += (size_t)(n > 0 ? n : 0);
        return true;
    }
    if (type == '*') {
        int count = atoi(rest);
        for (int i = 0; i < count; i++) {
            if (i && *used + 1u < cap) out[(*used)++] = '|';
            if (!f3_read_reply(c, out, cap, used)) return false;
        }
        return true;
    }
    return false;
}

static void f3_send_cmd(f3_client_t* c, const char* a, const char* b, const char* d, const char* e) {
    const char* args[4] = { a, b, d, e };
    size_t argc = 0;
    for (size_t i = 0; i < 4u; i++) if (args[i]) argc++;
    char out[2048]; size_t off = 0;
    off += (size_t)snprintf(out + off, sizeof(out) - off, "*%zu\r\n", argc);
    for (size_t i = 0; i < argc; i++)
        off += (size_t)snprintf(out + off, sizeof(out) - off, "$%zu\r\n%s\r\n", strlen(args[i]), args[i]);
    assert(send(c->fd, out, off, 0) == (ssize_t)off);
}

static void test_resp_federation_f3(qihse_kv_store_t* store, qihse_user_t* op) {
    /* Populate the namespace "infra" with some objects for the manifest test. */
    qihse_kv_set_user(store, "ns:infra:vm/web-01", "running", 0, 0, op);
    qihse_kv_set_user(store, "ns:infra:vm/web-02", "running", 0, 0, op);

    uint16_t port = f3_free_tcp_port();
    char node_id[QIHSE_CLUSTER_NODE_ID_LEN + 1u];
    qihse_cluster_node_id_from_seed("f3-resp-test-node", strlen("f3-resp-test-node"), node_id);
    qihse_resp_server_config_t scfg;
    qihse_resp_server_config_init(&scfg);
    scfg.node_id = node_id;
    scfg.bind_address = "127.0.0.1";
    scfg.advertise_address = "127.0.0.1";
    scfg.port = port;
    scfg.bus_port = f3_free_tcp_port();
    scfg.store = store;
    scfg.enable_bus = false;
    scfg.enable_failover = false;
    scfg.auth_required = true;
    qihse_resp_server_t* server = qihse_resp_server_create(&scfg);
    if (!server) {
        fprintf(stderr, "server create failed: errno=%d (%s)\n", errno, strerror(errno));
    }
    assert(server);
    assert(qihse_resp_server_start(server));

    f3_client_t c; memset(&c, 0, sizeof c);
    struct sockaddr_in addr; memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(port);
    c.fd = socket(AF_INET, SOCK_STREAM, 0); assert(c.fd >= 0);
    assert(connect(c.fd, (struct sockaddr*)&addr, sizeof addr) == 0);

    char reply[8192]; size_t used;
    f3_send_cmd(&c, "AUTH", "GODMODE_OP", "F3OperatorPass1!", NULL);
    used = 0; assert(f3_read_reply(&c, reply, sizeof reply, &used));
    if (strcmp(reply, "OK") != 0) {
        fprintf(stderr, "AUTH failed reply='%.100s'\n", reply);
    }
    assert(strcmp(reply, "OK") == 0);

    /* FEDERATION.MANIFEST infra — returns a non-empty array. */
    f3_send_cmd(&c, "FEDERATION", "MANIFEST", "infra", NULL);
    used = 0; assert(f3_read_reply(&c, reply, sizeof reply, &used));
    /* The reply should contain "infra" and the object count. */
    assert(strstr(reply, "infra") != NULL);

    /* FEDERATION.CONFLICT.LIST — returns an array (possibly empty). */
    f3_send_cmd(&c, "FEDERATION", "CONFLICT.LIST", NULL, NULL);
    used = 0; assert(f3_read_reply(&c, reply, sizeof reply, &used));
    /* Should not be NOPERM or ERR. */
    assert(strstr(reply, "NOPERM") == NULL);
    assert(strstr(reply, "ERR") == NULL);

    /* Tenant guest is denied (AGENTS.md invariant 3). */
    qihse_user_t* tenant = qihse_auth_create_tenant_user(op,
        42u, 102u, QIHSE_ROLE_GUEST, 0, 0, "F3TenantGuestP1!", false);
    assert(tenant);
    f3_client_t g; memset(&g, 0, sizeof g);
    g.fd = socket(AF_INET, SOCK_STREAM, 0); assert(g.fd >= 0);
    assert(connect(g.fd, (struct sockaddr*)&addr, sizeof addr) == 0);
    f3_send_cmd(&g, "AUTH", "User_102", "F3TenantGuestP1!", NULL);
    used = 0; assert(f3_read_reply(&g, reply, sizeof reply, &used));
    assert(strcmp(reply, "OK") == 0);
    f3_send_cmd(&g, "FEDERATION", "MANIFEST", "infra", NULL);
    used = 0; assert(f3_read_reply(&g, reply, sizeof reply, &used));
    assert(strstr(reply, "NOPERM") != NULL);
    f3_send_cmd(&g, "FEDERATION", "CONFLICT.LIST", NULL, NULL);
    used = 0; assert(f3_read_reply(&g, reply, sizeof reply, &used));
    assert(strstr(reply, "NOPERM") != NULL);
    f3_send_cmd(&g, "FEDERATION", "CONFLICT.RESOLVE", "00000000-0000-0000-0000-000000000000",
                 "00000000-0000-0000-0000-000000000000");
    used = 0; assert(f3_read_reply(&g, reply, sizeof reply, &used));
    assert(strstr(reply, "NOPERM") != NULL);
    close(g.fd);

    close(c.fd);
    qihse_resp_server_stop(server);
    qihse_resp_server_destroy(server);
    printf("PASS RESP FEDERATION.MANIFEST/CONFLICT + tenant-guest NOPERM\n");
}

int main(void) {
    char data_root[] = "build/fed_f3_XXXXXX";
    assert(mkdtemp(data_root));
    setenv("QIHSE_DATA_DIR", data_root, 1);

    assert(qihse_auth_init());
    bool bootstrapped = qihse_auth_bootstrap_operator("F3OperatorPass1!");
    if (!bootstrapped) {
        /* The first auth_init() created the operator without a password.
         * Set QIHSE_OPERATOR_PASSWORD and re-init to configure the verifier. */
        setenv("QIHSE_OPERATOR_PASSWORD", "F3OperatorPass1!", 1);
        assert(qihse_auth_init());
    }
    qihse_user_t* op = qihse_auth_get_user(0);
    assert(op);

    qihse_kv_store_t* store = qihse_kv_store_create();
    assert(store);

    test_conflict_policies();
    test_conflict_store(store, op);
    test_manifest(store, op);
    test_resp_federation_f3(store, op);

    qihse_kv_store_destroy(store);
    printf("federation F3 tests passed\n");
    return 0;
}
