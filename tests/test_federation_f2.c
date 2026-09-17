/*
 * test_federation_f2.c — F2 Event journal + watches.
 *
 * Acceptance criteria exercised:
 *   AC5 — Duplicate mutation requests are idempotent.
 *
 * Covers:
 *   - mutation envelope construction and round-trip
 *   - idempotency ledger: record, lookup, seen, duplicate rejection
 *   - event journal: append with envelope, replay from cursor, hash chain
 *   - resumable watches: open, next, prefix filter, ack, resume
 *
 * The journal log directory is isolated under build/ via mkdtemp().
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

/* ── Idempotency ledger ─────────────────────────────────────────────────── */

static void test_idempotency_ledger(void) {
    char data_root[] = "build/fed_f2_idem_XXXXXX";
    assert(mkdtemp(data_root));
    setenv("QIHSE_DATA_DIR", data_root, 1);

    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator("F2IdemOpPass1!"));
    qihse_user_t* op = qihse_auth_get_user(0);
    assert(op);

    qihse_kv_store_t* store = qihse_kv_store_create();
    assert(store);

    qihse_uuid_t req_id;
    assert(qihse_uuid_generate(&req_id));

    /* Not seen yet. */
    assert(!qihse_federation_request_seen(store, op, &req_id));

    /* Record a completed request. */
    qihse_federation_request_result_t result;
    memset(&result, 0, sizeof(result));
    result.request_id = req_id;
    result.completed_generation = 42;
    result.result_code = 0;
    snprintf(result.result_digest, sizeof(result.result_digest), "abc123");
    assert(qihse_federation_request_record(store, op, &result));

    /* Now it's seen. */
    assert(qihse_federation_request_seen(store, op, &req_id));

    /* Lookup returns the stored result. */
    qihse_federation_request_result_t fetched;
    assert(qihse_federation_request_lookup(store, op, &req_id, &fetched));
    assert(qihse_uuid_equal(&fetched.request_id, &req_id));
    assert(fetched.completed_generation == 42);
    assert(fetched.result_code == 0);
    assert(strcmp(fetched.result_digest, "abc123") == 0);

    /* AC5: duplicate record is rejected (idempotent — no overwrite). */
    qihse_federation_request_result_t dup;
    memset(&dup, 0, sizeof(dup));
    dup.request_id = req_id;
    dup.completed_generation = 999; /* different — must not overwrite */
    dup.result_code = 1;
    assert(!qihse_federation_request_record(store, op, &dup));

    /* Lookup still returns the original. */
    assert(qihse_federation_request_lookup(store, op, &req_id, &fetched));
    assert(fetched.completed_generation == 42);
    assert(fetched.result_code == 0);

    /* A different request_id is not seen. */
    qihse_uuid_t other_id;
    assert(qihse_uuid_generate(&other_id));
    assert(!qihse_federation_request_seen(store, op, &other_id));
    assert(!qihse_federation_request_lookup(store, op, &other_id, &fetched));

    qihse_kv_store_destroy(store);
    printf("PASS idempotency ledger: record/lookup/seen + duplicate rejection (AC5)\n");
}

/* ── Event journal ──────────────────────────────────────────────────────── */

static int replay_count;
static char replay_types[16][64];
static char replay_resources[16][64];

static bool replay_cb(const qihse_federation_event_t* event,
                     const uint8_t* payload, size_t payload_len, void* user_data) {
    (void)payload; (void)payload_len; (void)user_data;
    if (replay_count < 16) {
        snprintf(replay_types[replay_count], 64, "%s", event->event_type);
        snprintf(replay_resources[replay_count], 64, "%s", event->resource_id);
    }
    replay_count++;
    return true;
}

static void test_event_journal(void) {
    char log_root[] = "build/fed_f2_journal_XXXXXX";
    assert(mkdtemp(log_root));

    qihse_federation_journal_t* journal = qihse_federation_journal_open(
        log_root, QIHSE_ES_DURABILITY_FDATASYNC);
    assert(journal);

    qihse_uuid_t origin, principal;
    assert(qihse_uuid_from_seed("f2-origin", strlen("f2-origin"), &origin));
    assert(qihse_uuid_from_seed("f2-principal", strlen("f2-principal"), &principal));

    /* Append three events. */
    qihse_federation_mutation_t m1;
    memset(&m1, 0, sizeof(m1));
    m1.origin_node = origin;
    m1.principal_id = principal;
    m1.consistency = QIHSE_CONSISTENCY_LOCAL;
    qihse_federation_event_t ev1;
    uint64_t off1 = qihse_federation_journal_append(journal, &m1,
        "workload.observed.running", "vm/web-01", (const uint8_t*)"payload1", 8, &ev1);
    assert(off1 > 0);
    assert(strcmp(ev1.event_type, "workload.observed.running") == 0);
    assert(strcmp(ev1.resource_id, "vm/web-01") == 0);
    assert(ev1.mutation.hlc.physical_ms > 0); /* HLC was ticked */

    qihse_federation_mutation_t m2;
    memset(&m2, 0, sizeof(m2));
    m2.origin_node = origin;
    m2.principal_id = principal;
    m2.consistency = QIHSE_CONSISTENCY_CAUSAL;
    m2.expected_generation = 5;
    qihse_federation_event_t ev2;
    uint64_t off2 = qihse_federation_journal_append(journal, &m2,
        "workload.desired.updated", "vm/web-01", (const uint8_t*)"payload2", 8, &ev2);
    assert(off2 > off1); /* monotonic offsets */

    qihse_federation_mutation_t m3;
    memset(&m3, 0, sizeof(m3));
    m3.origin_node = origin;
    m3.principal_id = principal;
    m3.consistency = QIHSE_CONSISTENCY_QUORUM;
    m3.fencing_epoch = 7;
    qihse_federation_event_t ev3;
    uint64_t off3 = qihse_federation_journal_append(journal, &m3,
        "lease.granted", "volume/data-01", (const uint8_t*)"payload3", 8, &ev3);
    assert(off3 > off2);

    /* HLC is monotonic across appends. */
    assert(qihse_hlc_compare(&ev2.mutation.hlc, &ev1.mutation.hlc) > 0);
    assert(qihse_hlc_compare(&ev3.mutation.hlc, &ev2.mutation.hlc) > 0);

    /* Hash chain: ev2.previous_hash should equal ev1.hash. */
    assert(memcmp(ev2.previous_hash, ev1.hash, 48) == 0);
    assert(memcmp(ev3.previous_hash, ev2.hash, 48) == 0);

    /* Replay all events from the beginning. */
    replay_count = 0;
    uint64_t n = qihse_federation_journal_replay(journal, 0, replay_cb, NULL);
    assert(n == 3);
    assert(replay_count == 3);
    assert(strcmp(replay_types[0], "workload.observed.running") == 0);
    assert(strcmp(replay_resources[0], "vm/web-01") == 0);
    assert(strcmp(replay_types[1], "workload.desired.updated") == 0);
    assert(strcmp(replay_resources[2], "volume/data-01") == 0);

    /* Journal length is non-zero. */
    assert(qihse_federation_journal_length(journal) > 0);

    qihse_federation_journal_destroy(journal);

    /* Reopen — the hash chain should continue across restarts. */
    qihse_federation_journal_t* journal2 = qihse_federation_journal_open(
        log_root, QIHSE_ES_DURABILITY_FDATASYNC);
    assert(journal2);
    replay_count = 0;
    n = qihse_federation_journal_replay(journal2, 0, replay_cb, NULL);
    assert(n == 3); /* all events survived */
    /* Append a 4th event — chain continues. */
    qihse_federation_mutation_t m4;
    memset(&m4, 0, sizeof(m4));
    m4.origin_node = origin;
    m4.principal_id = principal;
    m4.consistency = QIHSE_CONSISTENCY_LOCAL;
    qihse_federation_event_t ev4;
    uint64_t off4 = qihse_federation_journal_append(journal2, &m4,
        "workload.observed.stopped", "vm/web-01", NULL, 0, &ev4);
    assert(off4 > 0);
    /* ev4.previous_hash should be ev3.hash (the chain tip before reopen). */
    assert(memcmp(ev4.previous_hash, ev3.hash, 48) == 0);
    qihse_federation_journal_destroy(journal2);

    printf("PASS event journal: append + replay + hash chain + restart continuity\n");
}

/* ── Resumable watches ──────────────────────────────────────────────────── */

static void test_watches(void) {
    char log_root[] = "build/fed_f2_watch_XXXXXX";
    assert(mkdtemp(log_root));

    qihse_federation_journal_t* journal = qihse_federation_journal_open(
        log_root, QIHSE_ES_DURABILITY_FDATASYNC);
    assert(journal);

    qihse_uuid_t origin, principal;
    assert(qihse_uuid_from_seed("f2-watch-origin", strlen("f2-watch-origin"), &origin));
    assert(qihse_uuid_from_seed("f2-watch-principal", strlen("f2-watch-principal"), &principal));

    /* Append events for two resource prefixes. */
    qihse_federation_mutation_t m;
    memset(&m, 0, sizeof(m));
    m.origin_node = origin;
    m.principal_id = principal;
    m.consistency = QIHSE_CONSISTENCY_LOCAL;
    qihse_federation_event_t ev;
    qihse_federation_journal_append(journal, &m, "obs", "vm/web-01", (const uint8_t*)"a", 1, &ev);
    qihse_federation_journal_append(journal, &m, "obs", "vm/web-02", (const uint8_t*)"b", 1, &ev);
    qihse_federation_journal_append(journal, &m, "obs", "volume/data-01", (const uint8_t*)"c", 1, &ev);
    qihse_federation_journal_append(journal, &m, "obs", "vm/web-03", (const uint8_t*)"d", 1, &ev);

    /* Watch with prefix "vm/" — should see 3 events, skip the volume. */
    qihse_federation_watch_config_t wcfg;
    memset(&wcfg, 0, sizeof(wcfg));
    snprintf(wcfg.prefix, sizeof(wcfg.prefix), "vm/");
    wcfg.cursor = 0;
    wcfg.backlog_limit = 64;
    qihse_federation_watch_t* watch = qihse_federation_watch_open(journal, &wcfg);
    assert(watch);

    int vm_count = 0;
    char seen_resources[8][64];
    qihse_federation_event_t wev;
    uint8_t* wpayload = NULL;
    size_t wplen = 0;
    while (qihse_federation_watch_next(watch, &wev, &wpayload, &wplen)) {
        if (vm_count < 8) snprintf(seen_resources[vm_count], 64, "%s", wev.resource_id);
        vm_count++;
        if (wpayload) { free(wpayload); wpayload = NULL; }
    }
    assert(vm_count == 3);
    assert(strcmp(seen_resources[0], "vm/web-01") == 0);
    assert(strcmp(seen_resources[1], "vm/web-02") == 0);
    assert(strcmp(seen_resources[2], "vm/web-03") == 0);

    /* Ack up to the second event. */
    assert(qihse_federation_watch_ack(watch, 1));
    assert(qihse_federation_watch_last_ack(watch) >= 1);

    /* Resume from the beginning — at-least-once: unacked events re-deliver. */
    assert(qihse_federation_watch_resume(watch, 0));
    int round2 = 0;
    while (qihse_federation_watch_next(watch, &wev, &wpayload, &wplen)) {
        round2++;
        if (wpayload) { free(wpayload); wpayload = NULL; }
    }
    assert(round2 == 3); /* all 3 vm/ events re-delivered */

    /* Watch with no prefix sees everything. */
    qihse_federation_watch_config_t wcfg2;
    memset(&wcfg2, 0, sizeof(wcfg2));
    wcfg2.cursor = 0;
    qihse_federation_watch_t* watch2 = qihse_federation_watch_open(journal, &wcfg2);
    assert(watch2);
    int all_count = 0;
    while (qihse_federation_watch_next(watch2, &wev, &wpayload, &wplen)) {
        all_count++;
        if (wpayload) { free(wpayload); wpayload = NULL; }
    }
    assert(all_count == 4);
    qihse_federation_watch_destroy(watch2);

    qihse_federation_watch_destroy(watch);
    qihse_federation_journal_destroy(journal);
    printf("PASS watches: prefix filter + ack + resume (at-least-once)\n");
}

/* ── RESP-level FEDERATION.EVENT/WATCH ─────────────────────────────────── */

static uint16_t f2_free_tcp_port(void) {
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

typedef struct { int fd; char buf[65536]; size_t fill; } f2_client_t;

static bool f2_read_line(f2_client_t* c, char* out, size_t cap) {
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

static bool f2_read_exact(f2_client_t* c, char* out, size_t len) {
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

static bool f2_read_reply(f2_client_t* c, char* out, size_t cap, size_t* used) {
    char line[512];
    if (!f2_read_line(c, line, sizeof(line))) return false;
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
        if (!f2_read_exact(c, data, (size_t)len + 2u)) return false;
        data[len] = '\0';
        int n = snprintf(out + *used, cap - *used, "%s", data);
        *used += (size_t)(n > 0 ? n : 0);
        return true;
    }
    if (type == '*') {
        int count = atoi(rest);
        for (int i = 0; i < count; i++) {
            if (i && *used + 1u < cap) out[(*used)++] = '|';
            if (!f2_read_reply(c, out, cap, used)) return false;
        }
        return true;
    }
    return false;
}

static void f2_send_cmd(f2_client_t* c, const char* a, const char* b, const char* d, const char* e) {
    const char* args[4] = { a, b, d, e };
    size_t argc = 0;
    for (size_t i = 0; i < 4u; i++) if (args[i]) argc++;
    char out[2048]; size_t off = 0;
    off += (size_t)snprintf(out + off, sizeof(out) - off, "*%zu\r\n", argc);
    for (size_t i = 0; i < argc; i++)
        off += (size_t)snprintf(out + off, sizeof(out) - off, "$%zu\r\n%s\r\n", strlen(args[i]), args[i]);
    assert(send(c->fd, out, off, 0) == (ssize_t)off);
}

static void test_resp_federation_f2(void) {
    char data_root[] = "build/fed_f2_resp_XXXXXX";
    assert(mkdtemp(data_root));
    char journal_root[256];
    snprintf(journal_root, sizeof(journal_root), "%s/journal", data_root);
    mkdir(journal_root, 0700);
    setenv("QIHSE_DATA_DIR", data_root, 1);

    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator("F2RespOpPass1!"));

    uint16_t port = f2_free_tcp_port();
    qihse_kv_store_t* store = qihse_kv_store_create();
    assert(store);
    char node_id[QIHSE_CLUSTER_NODE_ID_LEN + 1u];
    qihse_cluster_node_id_from_seed("f2-resp-test-node", strlen("f2-resp-test-node"), node_id);
    qihse_resp_server_config_t scfg;
    qihse_resp_server_config_init(&scfg);
    scfg.node_id = node_id;
    scfg.bind_address = "127.0.0.1";
    scfg.advertise_address = "127.0.0.1";
    scfg.port = port;
    scfg.bus_port = f2_free_tcp_port();
    scfg.store = store;
    scfg.enable_bus = false;
    scfg.enable_failover = false;
    scfg.auth_required = true;
    scfg.federation_journal_directory = journal_root;
    scfg.federation_journal_durability = QIHSE_ES_DURABILITY_FDATASYNC;
    qihse_resp_server_t* server = qihse_resp_server_create(&scfg);
    if (!server) {
        fprintf(stderr, "server create failed: errno=%d (%s)\n", errno, strerror(errno));
    }
    assert(server);
    assert(qihse_resp_server_start(server));

    f2_client_t c; memset(&c, 0, sizeof c);
    struct sockaddr_in addr; memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(port);
    c.fd = socket(AF_INET, SOCK_STREAM, 0); assert(c.fd >= 0);
    assert(connect(c.fd, (struct sockaddr*)&addr, sizeof addr) == 0);

    char reply[8192]; size_t used;
    f2_send_cmd(&c, "AUTH", "GODMODE_OP", "F2RespOpPass1!", NULL);
    used = 0; assert(f2_read_reply(&c, reply, sizeof reply, &used));
    assert(strcmp(reply, "OK") == 0);

    /* Append three events. */
    f2_send_cmd(&c, "FEDERATION", "EVENT.APPEND", "workload.observed", "vm/web-01");
    used = 0; assert(f2_read_reply(&c, reply, sizeof reply, &used));
    assert(atoi(reply) > 0); /* offset */
    f2_send_cmd(&c, "FEDERATION", "EVENT.APPEND", "workload.desired", "vm/web-01");
    used = 0; assert(f2_read_reply(&c, reply, sizeof reply, &used));
    assert(atoi(reply) > 0);
    f2_send_cmd(&c, "FEDERATION", "EVENT.APPEND", "lease.granted", "volume/data-01");
    used = 0; assert(f2_read_reply(&c, reply, sizeof reply, &used));
    assert(atoi(reply) > 0);

    /* EVENT.LENGTH reports non-zero. */
    f2_send_cmd(&c, "FEDERATION", "EVENT.LENGTH", NULL, NULL);
    used = 0; assert(f2_read_reply(&c, reply, sizeof reply, &used));
    assert(atoi(reply) > 0);

    /* EVENT.REPLAY returns 3 events (each as 3 fields = 9 array elements). */
    f2_send_cmd(&c, "FEDERATION", "EVENT.REPLAY", NULL, NULL);
    used = 0; assert(f2_read_reply(&c, reply, sizeof reply, &used));
    /* reply contains offset|type|resource|offset|type|resource|... */
    assert(strstr(reply, "workload.observed") != NULL);
    assert(strstr(reply, "workload.desired") != NULL);
    assert(strstr(reply, "lease.granted") != NULL);
    assert(strstr(reply, "vm/web-01") != NULL);
    assert(strstr(reply, "volume/data-01") != NULL);

    /* WATCH.OPEN with prefix "vm/" — should see 2 events. */
    f2_send_cmd(&c, "FEDERATION", "WATCH.OPEN", "vm/", NULL);
    used = 0; assert(f2_read_reply(&c, reply, sizeof reply, &used));
    int wid = atoi(reply);
    assert(wid >= 0);
    char wid_str[16]; snprintf(wid_str, sizeof(wid_str), "%d", wid);

    /* WATCH.NEXT returns the first vm/ event. */
    f2_send_cmd(&c, "FEDERATION", "WATCH.NEXT", wid_str, NULL);
    used = 0; assert(f2_read_reply(&c, reply, sizeof reply, &used));
    assert(strstr(reply, "workload.observed") != NULL);
    assert(strstr(reply, "vm/web-01") != NULL);

    /* Second WATCH.NEXT returns the second vm/ event. */
    f2_send_cmd(&c, "FEDERATION", "WATCH.NEXT", wid_str, NULL);
    used = 0; assert(f2_read_reply(&c, reply, sizeof reply, &used));
    assert(strstr(reply, "workload.desired") != NULL);

    /* Third WATCH.NEXT returns 0 (end of journal for this prefix). */
    f2_send_cmd(&c, "FEDERATION", "WATCH.NEXT", wid_str, NULL);
    used = 0; assert(f2_read_reply(&c, reply, sizeof reply, &used));
    assert(strcmp(reply, "0") == 0);

    /* WATCH.RESUME from 0 — re-deliver (at-least-once). */
    f2_send_cmd(&c, "FEDERATION", "WATCH.RESUME", wid_str, "0");
    used = 0; assert(f2_read_reply(&c, reply, sizeof reply, &used));
    assert(strcmp(reply, "OK") == 0);
    f2_send_cmd(&c, "FEDERATION", "WATCH.NEXT", wid_str, NULL);
    used = 0; assert(f2_read_reply(&c, reply, sizeof reply, &used));
    assert(strstr(reply, "workload.observed") != NULL);

    /* WATCH.ACK advances last_ack. */
    f2_send_cmd(&c, "FEDERATION", "WATCH.ACK", wid_str, "1");
    used = 0; assert(f2_read_reply(&c, reply, sizeof reply, &used));
    assert(strcmp(reply, "OK") == 0);

    /* Tenant guest is denied (AGENTS.md invariant 3). */
    qihse_user_t* tenant = qihse_auth_create_tenant_user(qihse_auth_get_user(0),
        42u, 101u, QIHSE_ROLE_GUEST, 0, 0, "F2TenantGuestP1!", false);
    assert(tenant);
    f2_client_t g; memset(&g, 0, sizeof g);
    g.fd = socket(AF_INET, SOCK_STREAM, 0); assert(g.fd >= 0);
    assert(connect(g.fd, (struct sockaddr*)&addr, sizeof addr) == 0);
    f2_send_cmd(&g, "AUTH", "User_101", "F2TenantGuestP1!", NULL);
    used = 0; assert(f2_read_reply(&g, reply, sizeof reply, &used));
    assert(strcmp(reply, "OK") == 0);
    f2_send_cmd(&g, "FEDERATION", "EVENT.APPEND", "evil", "vm/evil");
    used = 0; assert(f2_read_reply(&g, reply, sizeof reply, &used));
    assert(strstr(reply, "NOPERM") != NULL);
    f2_send_cmd(&g, "FEDERATION", "EVENT.REPLAY", NULL, NULL);
    used = 0; assert(f2_read_reply(&g, reply, sizeof reply, &used));
    assert(strstr(reply, "NOPERM") != NULL);
    f2_send_cmd(&g, "FEDERATION", "WATCH.OPEN", NULL, NULL);
    used = 0; assert(f2_read_reply(&g, reply, sizeof reply, &used));
    assert(strstr(reply, "NOPERM") != NULL);
    close(g.fd);

    close(c.fd);
    qihse_resp_server_stop(server);
    qihse_resp_server_destroy(server);
    qihse_kv_store_destroy(store);
    printf("PASS RESP FEDERATION.EVENT/WATCH + tenant-guest NOPERM\n");
}

int main(void) {
    test_idempotency_ledger();
    test_event_journal();
    test_watches();
    test_resp_federation_f2();
    printf("federation F2 tests passed\n");
    return 0;
}
