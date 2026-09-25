/*
 * test_federation_f4.c — F4 Strong namespace.
 *
 * Acceptance criteria exercised:
 *   AC3 — Native CAS: compare-and-swap on generation-tagged objects.
 *   AC4 — Fencing epochs: monotonic, non-reusable.
 *   AC10 — Leases: acquire, renew, release with server-side expiry.
 *
 * Covers:
 *   - CAS: initial create, successful swap, failed swap (wrong generation)
 *   - Fencing epochs: next is monotonic, current matches next
 *   - Leases: acquire, read, renew, release, idempotent release
 *   - Replication groups: create, lookup, add/remove members, advance term
 *   - RESP-level: OBJECT.CAS, EPOCH.NEXT, LEASE.ACQUIRE, GROUP.CREATE
 *   - Tenant-guest NOPERM (AGENTS.md invariant 3)
 *
 * A single shared data directory and KV store are used because
 * qihse_kv_store caches the data dir on first use.
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
#include <time.h>
#include <unistd.h>

/* ── CAS ─────────────────────────────────────────────────────────────────── */

static void test_cas(qihse_kv_store_t* store, qihse_user_t* op) {
    /* Initial create with expected_generation=0. */
    qihse_federation_cas_result_t r;
    assert(qihse_federation_object_cas(store, op, "core-security", "vm/web-01", 0, "running", &r));
    assert(r.swapped);
    assert(r.old_generation == 0);
    assert(r.new_generation == 1);

    /* Read back. */
    uint64_t gen;
    char val[256];
    assert(qihse_federation_object_get(store, op, "core-security", "vm/web-01", &gen, val, sizeof(val)));
    assert(gen == 1);
    assert(strcmp(val, "running") == 0);

    /* Successful CAS with correct expected generation. */
    assert(qihse_federation_object_cas(store, op, "core-security", "vm/web-01", 1, "stopped", &r));
    assert(r.swapped);
    assert(r.new_generation == 2);

    /* Failed CAS with wrong expected generation. */
    assert(qihse_federation_object_cas(store, op, "core-security", "vm/web-01", 1, "running", &r));
    assert(!r.swapped);
    assert(r.old_generation == 2);

    /* Verify the value didn't change. */
    assert(qihse_federation_object_get(store, op, "core-security", "vm/web-01", &gen, val, sizeof(val)));
    assert(gen == 2);
    assert(strcmp(val, "stopped") == 0);

    /* CAS on a non-existent object with expected_generation != 0 fails. */
    assert(qihse_federation_object_cas(store, op, "core-security", "vm/nonexistent", 5, "x", &r));
    assert(!r.swapped);

    printf("PASS CAS: create + swap + failed-swap (AC3)\n");
}

/* ── Fencing epochs ──────────────────────────────────────────────────────── */

static void test_epochs(qihse_kv_store_t* store, qihse_user_t* op) {
    qihse_uuid_t node;
    assert(qihse_uuid_from_seed("f4-epoch-node", strlen("f4-epoch-node"), &node));

    /* Current epoch starts at 0. */
    assert(qihse_federation_epoch_current(store, op, &node) == 0);

    /* Next advances to 1. */
    uint64_t e1 = qihse_federation_epoch_next(store, op, &node);
    assert(e1 == 1);
    assert(qihse_federation_epoch_current(store, op, &node) == 1);

    /* Next advances to 2. */
    uint64_t e2 = qihse_federation_epoch_next(store, op, &node);
    assert(e2 == 2);
    assert(e2 > e1);

    /* Epochs are monotonic. */
    uint64_t e3 = qihse_federation_epoch_next(store, op, &node);
    assert(e3 == 3);
    assert(e3 > e2);

    printf("PASS fencing epochs: monotonic next (AC4)\n");
}

/* ── Leases ──────────────────────────────────────────────────────────────── */

static void test_leases(qihse_kv_store_t* store, qihse_user_t* op) {
    qihse_uuid_t owner, issuer, request_id, lease_id;
    assert(qihse_uuid_from_seed("f4-lease-owner", strlen("f4-lease-owner"), &owner));
    assert(qihse_uuid_from_seed("f4-lease-issuer", strlen("f4-lease-issuer"), &issuer));
    assert(qihse_uuid_from_seed("f4-lease-req-1", strlen("f4-lease-req-1"), &request_id));
    assert(qihse_uuid_from_seed("f4-lease-id-1", strlen("f4-lease-id-1"), &lease_id));

    /* Acquire a lease.  Phase-B liveness: the expiry must be in the FUTURE
     * (absolute ms since epoch, like the RESP handler stamps) — the old
     * literal here was a 1970 timestamp, i.e. a born-dead lease, which the
     * Phase-B server-side expiry correctly refuses to renew. */
    uint64_t now_ms = (uint64_t)time(NULL) * 1000ULL;
    qihse_federation_lease_t req;
    memset(&req, 0, sizeof(req));
    req.lease_id = lease_id;
    req.owner_node = owner;
    snprintf(req.resource_id, sizeof(req.resource_id), "vm/web-01");
    req.fencing_epoch = 1;
    req.request_id = request_id;
    req.issuer = issuer;
    req.expires_hlc_physical = now_ms + 60000;

    qihse_federation_lease_t out;
    assert(qihse_federation_lease_acquire(store, op, &req, &out));
    assert(out.state == QIHSE_LEASE_GRANTED);
    assert(out.fencing_epoch == 1);
    assert(strcmp(out.resource_id, "vm/web-01") == 0);

    /* Read the lease. */
    qihse_federation_lease_t fetched;
    assert(qihse_federation_lease_read(store, op, &lease_id, &fetched));
    assert(fetched.state == QIHSE_LEASE_GRANTED);
    assert(qihse_uuid_equal(&fetched.owner_node, &owner));

    /* Renew the lease (extends further into the future). */
    qihse_federation_lease_t renewed;
    assert(qihse_federation_lease_renew(store, op, &lease_id,
                                        now_ms + 120000, &renewed));
    assert(renewed.state == QIHSE_LEASE_GRANTED);
    assert(renewed.expires_hlc_physical == now_ms + 120000);

    /* Release the lease. */
    assert(qihse_federation_lease_release(store, op, &lease_id));

    /* Verify it's released. */
    assert(qihse_federation_lease_read(store, op, &lease_id, &fetched));
    assert(fetched.state == QIHSE_LEASE_RELEASED);

    /* Idempotent release. */
    assert(qihse_federation_lease_release(store, op, &lease_id));

    /* Cannot renew a released lease. */
    assert(!qihse_federation_lease_renew(store, op, &lease_id, 7777777777ULL, &renewed));

    /* Fencing high-water mark: a stale holder at the same epoch cannot
     * re-acquire the released resource. */
    qihse_federation_lease_t stale;
    memset(&stale, 0, sizeof(stale));
    assert(qihse_uuid_from_seed("f4-lease-stale", strlen("f4-lease-stale"), &stale.lease_id));
    assert(qihse_uuid_from_seed("f4-lease-req-stale", strlen("f4-lease-req-stale"), &stale.request_id));
    stale.owner_node = owner;
    stale.issuer = issuer;
    snprintf(stale.resource_id, sizeof(stale.resource_id), "vm/web-01");
    stale.fencing_epoch = 1; /* same epoch as the released lease */
    assert(!qihse_federation_lease_acquire(store, op, &stale, &out));

    /* A fresh holder at a higher epoch may acquire. */
    qihse_federation_lease_t fresh;
    memset(&fresh, 0, sizeof(fresh));
    assert(qihse_uuid_from_seed("f4-lease-fresh", strlen("f4-lease-fresh"), &fresh.lease_id));
    assert(qihse_uuid_from_seed("f4-lease-req-fresh", strlen("f4-lease-req-fresh"), &fresh.request_id));
    fresh.owner_node = owner;
    fresh.issuer = issuer;
    snprintf(fresh.resource_id, sizeof(fresh.resource_id), "vm/web-01");
    fresh.fencing_epoch = 2; /* strictly greater */
    assert(qihse_federation_lease_acquire(store, op, &fresh, &out));
    assert(out.fencing_epoch == 2);

    /* Idempotent retry: the same request_id returns the same lease even when
     * the caller regenerates the lease_id. */
    qihse_federation_lease_t retry = fresh;
    assert(qihse_uuid_from_seed("f4-lease-retry-id", strlen("f4-lease-retry-id"), &retry.lease_id));
    qihse_federation_lease_t retry_out;
    assert(qihse_federation_lease_acquire(store, op, &retry, &retry_out));
    assert(qihse_uuid_equal(&retry_out.lease_id, &fresh.lease_id));

    printf("PASS leases: acquire + read + renew + release + idempotent (AC10)\n");
    printf("PASS leases: fencing high-water mark rejects stale holder (AC4)\n");
}

/* ── Replication groups ──────────────────────────────────────────────────── */

/* Named callback for group foreach (C99 compatible). */
static bool group_count_cb(const qihse_federation_group_t* group, void* user_data) {
    (void)group; (*(size_t*)user_data)++; return true;
}

static void test_groups(qihse_kv_store_t* store, qihse_user_t* op) {
    /* Create a group. */
    qihse_federation_group_t g;
    memset(&g, 0, sizeof(g));
    snprintf(g.group_id, sizeof(g.group_id), "core-security");
    g.consistency = QIHSE_CONSISTENCY_QUORUM;
    g.term = 1;
    g.member_count = 0;

    assert(qihse_federation_group_create(store, op, &g));

    /* Duplicate create fails. */
    assert(!qihse_federation_group_create(store, op, &g));

    /* Lookup. */
    qihse_federation_group_t fetched;
    assert(qihse_federation_group_lookup(store, op, "core-security", &fetched));
    assert(strcmp(fetched.group_id, "core-security") == 0);
    assert(fetched.term == 1);
    assert(fetched.member_count == 0);

    /* Add a member. */
    qihse_federation_group_member_t m1;
    memset(&m1, 0, sizeof(m1));
    assert(qihse_uuid_from_seed("f4-group-node-1", strlen("f4-group-node-1"), &m1.member_id));
    m1.is_voter = true;
    m1.is_witness = false;
    assert(qihse_federation_group_add_member(store, op, "core-security", &m1));

    /* Add a second member. */
    qihse_federation_group_member_t m2;
    memset(&m2, 0, sizeof(m2));
    assert(qihse_uuid_from_seed("f4-group-node-2", strlen("f4-group-node-2"), &m2.member_id));
    m2.is_voter = false;
    m2.is_witness = true;
    assert(qihse_federation_group_add_member(store, op, "core-security", &m2));

    /* Verify 2 members. */
    assert(qihse_federation_group_lookup(store, op, "core-security", &fetched));
    assert(fetched.member_count == 2);

    /* Remove a member. */
    assert(qihse_federation_group_remove_member(store, op, "core-security", &m1.member_id));
    assert(qihse_federation_group_lookup(store, op, "core-security", &fetched));
    assert(fetched.member_count == 1);

    /* Advance term. */
    uint64_t new_term = qihse_federation_group_advance_term(store, op, "core-security");
    assert(new_term == 2);
    assert(qihse_federation_group_lookup(store, op, "core-security", &fetched));
    assert(fetched.term == 2);

    /* Foreach finds the group. */
    size_t count = 0;
    qihse_federation_group_foreach(store, op, group_count_cb, &count);
    assert(count >= 1);

    printf("PASS replication groups: create + add/remove + advance term\n");
}

/* ── RESP-level F4 ──────────────────────────────────────────────────────── */

static uint16_t f4_free_tcp_port(void) {
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

typedef struct { int fd; char buf[65536]; size_t fill; } f4_client_t;

static bool f4_read_line(f4_client_t* c, char* out, size_t cap) {
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

static bool f4_read_exact(f4_client_t* c, char* out, size_t len) {
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

static bool f4_read_reply(f4_client_t* c, char* out, size_t cap, size_t* used) {
    char line[512];
    if (!f4_read_line(c, line, sizeof(line))) return false;
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
        if (!f4_read_exact(c, data, (size_t)len + 2u)) return false;
        data[len] = '\0';
        int n = snprintf(out + *used, cap - *used, "%s", data);
        *used += (size_t)(n > 0 ? n : 0);
        return true;
    }
    if (type == '*') {
        int count = atoi(rest);
        for (int i = 0; i < count; i++) {
            if (i && *used + 1u < cap) out[(*used)++] = '|';
            if (!f4_read_reply(c, out, cap, used)) return false;
        }
        return true;
    }
    return false;
}

static void f4_send_cmd6(f4_client_t* c, const char* a, const char* b, const char* d,
                         const char* e, const char* f, const char* g) {
    const char* args[6] = { a, b, d, e, f, g };
    size_t argc = 0;
    for (size_t i = 0; i < 6u; i++) if (args[i]) argc++;
    char out[4096]; size_t off = 0;
    off += (size_t)snprintf(out + off, sizeof(out) - off, "*%zu\r\n", argc);
    for (size_t i = 0; i < argc; i++)
        off += (size_t)snprintf(out + off, sizeof(out) - off, "$%zu\r\n%s\r\n", strlen(args[i]), args[i]);
    assert(send(c->fd, out, off, 0) == (ssize_t)off);
}

static void f4_send_cmd(f4_client_t* c, const char* a, const char* b, const char* d, const char* e) {
    f4_send_cmd6(c, a, b, d, e, NULL, NULL);
}

static void test_resp_federation_f4(qihse_kv_store_t* store, qihse_user_t* op) {
    uint16_t port = f4_free_tcp_port();
    char node_id[QIHSE_CLUSTER_NODE_ID_LEN + 1u];
    qihse_cluster_node_id_from_seed("f4-resp-test-node", strlen("f4-resp-test-node"), node_id);
    qihse_resp_server_config_t scfg;
    qihse_resp_server_config_init(&scfg);
    scfg.node_id = node_id;
    scfg.bind_address = "127.0.0.1";
    scfg.advertise_address = "127.0.0.1";
    scfg.port = port;
    scfg.bus_port = f4_free_tcp_port();
    scfg.store = store;
    scfg.enable_bus = false;
    scfg.enable_failover = false;
    scfg.auth_required = true;
    qihse_resp_server_t* server = qihse_resp_server_create(&scfg);
    if (!server) fprintf(stderr, "server create failed: errno=%d (%s)\n", errno, strerror(errno));
    assert(server);
    assert(qihse_resp_server_start(server));

    f4_client_t c; memset(&c, 0, sizeof c);
    struct sockaddr_in addr; memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(port);
    c.fd = socket(AF_INET, SOCK_STREAM, 0); assert(c.fd >= 0);
    assert(connect(c.fd, (struct sockaddr*)&addr, sizeof addr) == 0);

    char reply[8192]; size_t used;
    f4_send_cmd(&c, "AUTH", "GODMODE_OP", "F4OperatorPass1!", NULL);
    used = 0; assert(f4_read_reply(&c, reply, sizeof reply, &used));
    assert(strcmp(reply, "OK") == 0);

    /* EPOCH.NEXT — returns an integer > 0. */
    f4_send_cmd(&c, "FEDERATION", "EPOCH.NEXT", NULL, NULL);
    used = 0; assert(f4_read_reply(&c, reply, sizeof reply, &used));
    assert(atoi(reply) > 0);
    int64_t first_epoch = atoi(reply);

    /* EPOCH.CURRENT matches. */
    f4_send_cmd(&c, "FEDERATION", "EPOCH.CURRENT", NULL, NULL);
    used = 0; assert(f4_read_reply(&c, reply, sizeof reply, &used));
    assert(atoi(reply) == first_epoch);

    /* OBJECT.CAS — create a new object (expected_generation 0). */
    f4_send_cmd6(&c, "FEDERATION", "OBJECT.CAS", "infra", "vm/cas-01", "running", "0");
    used = 0; assert(f4_read_reply(&c, reply, sizeof reply, &used));
    assert(atoi(reply) == 1);

    /* OBJECT.CAS with a stale generation fails (returns 0). */
    f4_send_cmd6(&c, "FEDERATION", "OBJECT.CAS", "infra", "vm/cas-01", "stopped", "0");
    used = 0; assert(f4_read_reply(&c, reply, sizeof reply, &used));
    assert(atoi(reply) == 0);

    /* OBJECT.GET returns [generation, value]. */
    f4_send_cmd(&c, "FEDERATION", "OBJECT.GET", "infra", "vm/cas-01");
    used = 0; assert(f4_read_reply(&c, reply, sizeof reply, &used));
    assert(strstr(reply, "running") != NULL);

    /* GROUP.CREATE. */
    f4_send_cmd(&c, "FEDERATION", "GROUP.CREATE", "resp-group", NULL);
    used = 0; assert(f4_read_reply(&c, reply, sizeof reply, &used));
    assert(strstr(reply, "OK") != NULL);

    /* GROUP.LIST contains the group. */
    f4_send_cmd(&c, "FEDERATION", "GROUP.LIST", NULL, NULL);
    used = 0; assert(f4_read_reply(&c, reply, sizeof reply, &used));
    assert(strstr(reply, "resp-group") != NULL);

    /* GROUP.ADVANCE returns the new term. */
    f4_send_cmd(&c, "FEDERATION", "GROUP.ADVANCE", "resp-group", NULL);
    used = 0; assert(f4_read_reply(&c, reply, sizeof reply, &used));
    assert(atoi(reply) == 1);

    /* GROUP.SHOW reports the term. */
    f4_send_cmd(&c, "FEDERATION", "GROUP.SHOW", "resp-group", NULL);
    used = 0; assert(f4_read_reply(&c, reply, sizeof reply, &used));
    assert(strstr(reply, "resp-group") != NULL);

    /* LEASE.ACQUIRE returns a lease id.  Phase-B liveness: the expiry
     * argument is an absolute wall-clock ms timestamp and must be in the
     * future — the old literals here were 1970s timestamps (born-dead). */
    uint64_t now_ms = (uint64_t)time(NULL) * 1000ULL;
    char exp_arg[32], renew_arg[32];
    snprintf(exp_arg, sizeof exp_arg, "%llu", (unsigned long long)(now_ms + 60000));
    snprintf(renew_arg, sizeof renew_arg, "%llu", (unsigned long long)(now_ms + 120000));
    f4_send_cmd6(&c, "FEDERATION", "LEASE.ACQUIRE", "infra", "vm/lease-01", "7", exp_arg);
    used = 0; assert(f4_read_reply(&c, reply, sizeof reply, &used));
    assert(strlen(reply) > 20);
    char lease_id[64];
    assert(strlen(reply) < sizeof(lease_id));
    memcpy(lease_id, reply, strlen(reply) + 1u);

    /* LEASE.READ reports granted. */
    f4_send_cmd(&c, "FEDERATION", "LEASE.READ", lease_id, NULL);
    used = 0; assert(f4_read_reply(&c, reply, sizeof reply, &used));
    assert(strstr(reply, "granted") != NULL);

    /* LEASE.RENEW succeeds. */
    f4_send_cmd(&c, "FEDERATION", "LEASE.RENEW", lease_id, renew_arg);
    used = 0; assert(f4_read_reply(&c, reply, sizeof reply, &used));
    assert(strstr(reply, "OK") != NULL);

    /* LEASE.RELEASE succeeds and is idempotent. */
    f4_send_cmd(&c, "FEDERATION", "LEASE.RELEASE", lease_id, NULL);
    used = 0; assert(f4_read_reply(&c, reply, sizeof reply, &used));
    assert(strstr(reply, "OK") != NULL);
    f4_send_cmd(&c, "FEDERATION", "LEASE.RELEASE", lease_id, NULL);
    used = 0; assert(f4_read_reply(&c, reply, sizeof reply, &used));
    assert(strstr(reply, "OK") != NULL);

    /* Tenant guest is denied (AGENTS.md invariant 3). */
    qihse_user_t* tenant = qihse_auth_create_tenant_user(op,
        42u, 103u, QIHSE_ROLE_GUEST, 0, 0, "F4TenantGuestP1!", false);
    assert(tenant);
    f4_client_t g; memset(&g, 0, sizeof g);
    g.fd = socket(AF_INET, SOCK_STREAM, 0); assert(g.fd >= 0);
    assert(connect(g.fd, (struct sockaddr*)&addr, sizeof addr) == 0);
    f4_send_cmd(&g, "AUTH", "User_103", "F4TenantGuestP1!", NULL);
    used = 0; assert(f4_read_reply(&g, reply, sizeof reply, &used));
    assert(strcmp(reply, "OK") == 0);
    f4_send_cmd(&g, "FEDERATION", "EPOCH.NEXT", NULL, NULL);
    used = 0; assert(f4_read_reply(&g, reply, sizeof reply, &used));
    assert(strstr(reply, "NOPERM") != NULL);
    f4_send_cmd6(&g, "FEDERATION", "OBJECT.CAS", "infra", "vm/evil", "owned", "0");
    used = 0; assert(f4_read_reply(&g, reply, sizeof reply, &used));
    assert(strstr(reply, "NOPERM") != NULL);
    f4_send_cmd(&g, "FEDERATION", "OBJECT.GET", "infra", "vm/cas-01");
    used = 0; assert(f4_read_reply(&g, reply, sizeof reply, &used));
    assert(strstr(reply, "NOPERM") != NULL);
    assert(strstr(reply, "running") == NULL);
    f4_send_cmd(&g, "FEDERATION", "GROUP.CREATE", "evil-group", NULL);
    used = 0; assert(f4_read_reply(&g, reply, sizeof reply, &used));
    assert(strstr(reply, "NOPERM") != NULL);
    f4_send_cmd6(&g, "FEDERATION", "LEASE.ACQUIRE", "infra", "vm/evil", "1", "1");
    used = 0; assert(f4_read_reply(&g, reply, sizeof reply, &used));
    assert(strstr(reply, "NOPERM") != NULL);
    close(g.fd);

    close(c.fd);
    qihse_resp_server_stop(server);
    qihse_resp_server_destroy(server);
    printf("PASS RESP FEDERATION.EPOCH/OBJECT/GROUP/LEASE + tenant-guest NOPERM\n");
}

int main(void) {
    char data_root[] = "build/fed_f4_XXXXXX";
    assert(mkdtemp(data_root));
    setenv("QIHSE_DATA_DIR", data_root, 1);

    assert(qihse_auth_init());
    bool bootstrapped = qihse_auth_bootstrap_operator("F4OperatorPass1!");
    if (!bootstrapped) {
        setenv("QIHSE_OPERATOR_PASSWORD", "F4OperatorPass1!", 1);
        assert(qihse_auth_init());
    }
    qihse_user_t* op = qihse_auth_get_user(0);
    assert(op);

    qihse_kv_store_t* store = qihse_kv_store_create();
    assert(store);

    test_cas(store, op);
    test_epochs(store, op);
    test_leases(store, op);
    test_groups(store, op);
    test_resp_federation_f4(store, op);

    qihse_kv_store_destroy(store);
    printf("federation F4 tests passed\n");
    return 0;
}
