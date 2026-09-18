/*
 * test_keystone_feed_w25.c — W2.5: KEYSTONE consumes the resumable change
 * feed with a read/index identity — never database-admin privileges.
 *
 * Acceptance criterion exercised (federation plan §41 criterion 9):
 *   "KEYSTONE can consume resumable change streams without becoming
 *    authoritative."
 *
 * The identity under test is provisioned by
 * qihse_keystone_feed_identity_provision(): a tenant-scoped ANALYST at an
 * explicit clearance/SCI ceiling, holding QIHSE_SCOPE_FEDERATION_READ only.
 *
 * What this test asserts, and why each assertion exists:
 *
 *   A. Least privilege is ENFORCED, not assumed: the index identity is DENIED
 *      a write (KEYSTONE.FEED.PUBLISH and qihse_keystone_feed_publish), an
 *      administrative operation (creating a principal, promoting itself,
 *      destroying a principal, enrolling/revoking a federation node) and a
 *      federation control-plane command (FEDERATION.* over the wire).
 *   B. Invariant 2: no principal creates or promotes above itself — a
 *      delegated creator cannot mint an index identity, the index identity
 *      cannot mint anything, and the system domain (the administrative domain
 *      in this codebase) is refused outright.
 *   C. Invariant 3 (low-clearance/high-data negative test): records above the
 *      identity's clearance, outside its SCI compartments and in another
 *      tenant are withheld, and the protected payload BYTES are asserted
 *      absent from everything the identity received — not merely that a call
 *      returned an error.
 *   D. The feed does not leak through the cursor: rewinding and replaying
 *      re-denies the same records, and a cursor minted for a wider identity
 *      cannot be transplanted onto the index identity.
 *   E. Resume correctness: a cursor saved before a restart resumes after it
 *      and re-delivers only unacknowledged records.
 *
 * The RESP section drives the same identity over the wire, because the
 * externally reachable surface is what an attacker actually gets.
 */
#include "qihse_auth.h"
#include "qihse_cluster_slot.h"
#include "qihse_federation.h"
#include "qihse_keystone.h"
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

#define W25_OP_PASSWORD "W25OperatorPass1!"
#define W25_INDEXER_PASSWORD "W25IndexerPass1!"
#define W25_ANALYST_PASSWORD "W25AnalystPass1!"
#define W25_DELEGATE_PASSWORD "W25DelegatePass1!"

#define W25_INDEXER_USER 300u
#define W25_ANALYST_USER 301u
#define W25_DELEGATE_USER 302u
#define W25_INDEXER_TENANT 7u
#define W25_OTHER_TENANT 9u
#define W25_INDEXER_CLEARANCE 2u
#define W25_INDEXER_SCI 0x1u

/* Distinctive bytes that only exist in records the identity must never see. */
#define W25_SECRET_CLEARANCE "W25-SECRET-CLEARANCE-7F3A"
#define W25_SECRET_SCI "W25-SECRET-SCI-11B2"
#define W25_SECRET_TENANT "W25-SECRET-TENANT-4C5D"
#define W25_SECRET_MALFORMED "W25-SECRET-MALFORMED-9E6F"

/* Accumulates everything the identity received, so absence can be asserted
 * over the whole stream rather than per call. */
typedef struct {
    char bytes[8192];
    size_t len;
} w25_sink_t;

static void w25_sink_add(w25_sink_t* sink, const void* data, size_t len) {
    if (!sink || !data || len == 0u) return;
    if (len > sizeof(sink->bytes) - 1u - sink->len) len = sizeof(sink->bytes) - 1u - sink->len;
    memcpy(sink->bytes + sink->len, data, len);
    sink->len += len;
    sink->bytes[sink->len] = '\0';
}

static bool w25_sink_contains(const w25_sink_t* sink, const char* needle) {
    return sink && strstr(sink->bytes, needle) != NULL;
}

/* ── A record publisher and the index identity ─────────────────────────── */

static void w25_publish(qihse_federation_journal_t* journal, const qihse_user_t* publisher,
                        const qihse_uuid_t* node, const char* event_type,
                        const char* resource_id, uint16_t classif, uint16_t sci,
                        uint32_t tenant, uint64_t generation, const char* payload) {
    qihse_keystone_feed_record_t rec;
    memset(&rec, 0, sizeof(rec));
    rec.classification = classif;
    rec.sci = sci;
    rec.tenant_id = tenant;
    rec.generation = generation;
    assert(qihse_uuid_from_seed(resource_id, strlen(resource_id), &rec.object_id));
    qihse_federation_event_t ev;
    assert(qihse_keystone_feed_publish(journal, publisher, node, event_type, resource_id,
                                       &rec, payload, payload ? strlen(payload) : 0u, &ev));
    assert(ev.journal_offset > 0u);
}

/* ── A/B. Least privilege: write, administration, control plane ────────── */

static void test_least_privilege(qihse_kv_store_t* store, qihse_user_t* op,
                                 qihse_federation_journal_t* journal,
                                 qihse_user_t* indexer, qihse_user_t* analyst,
                                 qihse_user_t* delegate) {
    qihse_uuid_t node;
    assert(qihse_uuid_from_seed("w25-node", strlen("w25-node"), &node));

    /* --- The identity is what it claims to be, and no more. */
    assert(qihse_keystone_feed_identity_is_indexer(indexer));
    assert(qihse_user_get_role(indexer) == QIHSE_ROLE_ANALYST);
    assert(!qihse_user_can_create_users(indexer));
    assert(qihse_user_get_tenant_id(indexer) == W25_INDEXER_TENANT);
    assert(qihse_infra_scope_check(indexer, QIHSE_SCOPE_FEDERATION_READ));
    assert(!qihse_infra_scope_check(indexer, QIHSE_SCOPE_FEDERATION_WRITE));
    assert(!qihse_infra_scope_check(indexer, QIHSE_SCOPE_NODE_ENROLL));
    assert(!qihse_infra_scope_check(indexer, QIHSE_SCOPE_SECURITY_ADMIN));

    /* --- Write denied: publishing a feed record is a FEDERATION_WRITE. */
    qihse_keystone_feed_record_t rec;
    memset(&rec, 0, sizeof(rec));
    rec.classification = 0;
    rec.tenant_id = W25_INDEXER_TENANT;
    qihse_federation_event_t ev;
    assert(!qihse_keystone_feed_publish(journal, indexer, &node, "w25.write",
                                        "idx/forbidden", &rec, "x", 1u, &ev));
    /* The operator can, which proves the denial is about the identity. */
    assert(qihse_keystone_feed_publish(journal, op, &node, "w25.write",
                                       "idx/operator", &rec, "x", 1u, &ev));

    /* --- Administrative operations denied. */
    assert(qihse_keystone_feed_identity_provision(indexer, W25_INDEXER_TENANT, 310u,
                                                  0, 0, W25_INDEXER_PASSWORD) == NULL);
    assert(qihse_auth_get_user(310u) == NULL);
    assert(qihse_auth_create_user(indexer, 311u, QIHSE_ROLE_GUEST, 0, 0,
                                  W25_INDEXER_PASSWORD, false) == NULL);
    assert(qihse_auth_get_user(311u) == NULL);
    assert(!qihse_auth_modify_user(indexer, W25_INDEXER_USER, "promoted",
                                   NULL, -1, -1, 0xFFFF, -1));
    assert(qihse_user_get_classification(indexer) == W25_INDEXER_CLEARANCE);
    assert(!qihse_auth_destroy_user(indexer, W25_ANALYST_USER));
    assert(qihse_auth_get_user(W25_ANALYST_USER) != NULL);

    /* --- Federation control-plane commands denied. */
    qihse_federation_node_identity_t node_rec;
    memset(&node_rec, 0, sizeof(node_rec));
    assert(qihse_uuid_from_seed("w25-enroll", strlen("w25-enroll"), &node_rec.node_id));
    assert(!qihse_federation_node_enroll_request(store, indexer, &node_rec));
    assert(!qihse_federation_node_revoke(store, indexer, &node_rec.node_id));
    assert(!qihse_federation_node_enroll_approve(store, indexer, &node_rec.node_id, 1u));

    /* --- Invariant 2: a delegated creator cannot mint an index identity. */
    assert(!qihse_keystone_feed_identity_is_indexer(delegate));
    assert(qihse_user_can_create_users(delegate));
    assert(qihse_keystone_feed_identity_provision(delegate, W25_INDEXER_TENANT, 312u,
                                                  W25_INDEXER_CLEARANCE, W25_INDEXER_SCI,
                                                  W25_INDEXER_PASSWORD) == NULL);
    assert(qihse_auth_get_user(312u) == NULL);
    /* Nor may it create a principal above itself through the plain path. */
    assert(qihse_auth_create_user(delegate, 313u, QIHSE_ROLE_OPERATOR, 0, 0,
                                  W25_DELEGATE_PASSWORD, false) == NULL);
    assert(qihse_auth_get_user(313u) == NULL);

    /* --- The system domain (the administrative domain) is refused outright:
     * an index identity is never a system-domain principal. */
    assert(qihse_keystone_feed_identity_provision(op, QIHSE_TENANT_SYSTEM, 314u,
                                                  W25_INDEXER_CLEARANCE, W25_INDEXER_SCI,
                                                  W25_INDEXER_PASSWORD) == NULL);
    assert(qihse_auth_get_user(314u) == NULL);

    /* --- A plain analyst is not a feed reader: the surface stays narrow. */
    assert(!qihse_keystone_feed_identity_is_indexer(analyst));
    qihse_keystone_feed_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    assert(qihse_keystone_feed_open(journal, analyst, &cfg) == NULL);

    /* --- NULL never becomes an authorization bypass. */
    assert(qihse_keystone_feed_open(journal, NULL, &cfg) == NULL);
    assert(qihse_keystone_feed_open(NULL, indexer, &cfg) == NULL);
    assert(!qihse_keystone_feed_publish(journal, NULL, &node, "w25.null", "idx/null",
                                        &rec, "x", 1u, &ev));
    assert(!qihse_keystone_feed_publish(journal, indexer, NULL, "w25.null", "idx/null",
                                        &rec, "x", 1u, &ev));
    assert(!qihse_keystone_feed_publish(NULL, op, &node, "w25.null", "idx/null",
                                        &rec, "x", 1u, &ev));
    uint64_t cursor = 0;
    assert(!qihse_keystone_feed_cursor_load(NULL, "build/w25-null.cursor", &cursor));

    printf("PASS least privilege: index identity denied write, admin and control plane\n");
}

/* ── C/D/E. Clearance-filtered, resumable consumption ──────────────────── */

static void test_filtered_consumption(qihse_federation_journal_t* journal,
                                      qihse_user_t* op, qihse_user_t* indexer,
                                      const char* cursor_path) {
    qihse_uuid_t node;
    assert(qihse_uuid_from_seed("w25-node", strlen("w25-node"), &node));

    /* Records the identity IS cleared for: at/below clearance 2, SCI 0x1,
     * tenant 7. */
    w25_publish(journal, op, &node, "w25.index", "feed/one", 1u, 0x1u,
                W25_INDEXER_TENANT, 1u, "record-one");
    w25_publish(journal, op, &node, "w25.index", "feed/two", W25_INDEXER_CLEARANCE, 0x1u,
                W25_INDEXER_TENANT, 2u, "record-two");

    /* Records it is NOT cleared for, each with a distinctive payload. */
    w25_publish(journal, op, &node, "w25.index", "feed/secret-clearance", 9u, 0x1u,
                W25_INDEXER_TENANT, 3u, W25_SECRET_CLEARANCE);
    w25_publish(journal, op, &node, "w25.index", "feed/secret-sci", 1u, 0x4u,
                W25_INDEXER_TENANT, 4u, W25_SECRET_SCI);
    w25_publish(journal, op, &node, "w25.index", "feed/secret-tenant", 1u, 0x1u,
                W25_OTHER_TENANT, 5u, W25_SECRET_TENANT);

    /* A non-feed event (no feed header) and a malformed feed record must both
     * be withheld: an undecodable record is never delivered. */
    qihse_federation_mutation_t m;
    memset(&m, 0, sizeof(m));
    m.origin_node = node;
    m.consistency = QIHSE_CONSISTENCY_LOCAL;
    qihse_federation_event_t raw_ev;
    assert(qihse_federation_journal_append(journal, &m, "w25.raw", "feed/raw",
                                           (const uint8_t*)W25_SECRET_MALFORMED,
                                           strlen(W25_SECRET_MALFORMED), &raw_ev) > 0);
    uint8_t broken[QIHSE_KEYSTONE_FEED_HEADER_BYTES + 4u];
    qihse_keystone_feed_record_t broken_rec;
    memset(&broken_rec, 0, sizeof(broken_rec));
    broken_rec.tenant_id = W25_INDEXER_TENANT;
    size_t broken_len = 0;
    assert(qihse_keystone_feed_encode(&broken_rec, "abcd", 4u, broken,
                                      sizeof(broken), &broken_len));
    /* The header declares 4 body bytes; the frame is truncated to 2, so the
     * declared length disagrees with the encoded length. */
    assert(qihse_federation_journal_append(journal, &m, "w25.index", "feed/broken",
                                           broken, broken_len - 2u, &raw_ev) > 0);

    /* A third cleared record, published later, for the resume test. */
    w25_publish(journal, op, &node, "w25.index", "feed/three", 0u, 0x1u,
                W25_INDEXER_TENANT, 6u, "record-three");

    /* --- First pass. The prefix keeps this feed scoped to the records this
     * test published, so the delivery/denial counts below are exact. */
    qihse_keystone_feed_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.prefix, sizeof(cfg.prefix), "feed/");
    qihse_keystone_feed_t* feed = qihse_keystone_feed_open(journal, indexer, &cfg);
    assert(feed);

    w25_sink_t sink;
    memset(&sink, 0, sizeof(sink));
    size_t delivered = 0;
    bool saw_one = false, saw_two = false, saw_three = false;
    uint64_t last_offset = 0;
    qihse_federation_event_t ev;
    qihse_keystone_feed_record_t rec;
    uint8_t* payload = NULL;
    size_t payload_len = 0;
    while (qihse_keystone_feed_next(feed, &ev, &rec, &payload, &payload_len)) {
        delivered++;
        assert(rec.classification <= W25_INDEXER_CLEARANCE);
        assert((rec.sci & W25_INDEXER_SCI) == rec.sci);
        assert(rec.tenant_id == W25_INDEXER_TENANT);
        assert(rec.generation > 0u);
        assert(rec.hlc.physical_ms > 0u); /* inherited from the envelope */
        w25_sink_add(&sink, ev.event_type, strlen(ev.event_type));
        w25_sink_add(&sink, ev.resource_id, strlen(ev.resource_id));
        w25_sink_add(&sink, payload, payload_len);
        if (strcmp(ev.resource_id, "feed/one") == 0) saw_one = true;
        if (strcmp(ev.resource_id, "feed/two") == 0) saw_two = true;
        if (strcmp(ev.resource_id, "feed/three") == 0) saw_three = true;
        last_offset = ev.journal_offset;
        free(payload);
        payload = NULL;
    }
    assert(delivered == 3u);
    assert(saw_one && saw_two && saw_three);
    /* Five records withheld: clearance, SCI, tenant, raw (non-feed) and
     * malformed. */
    assert(qihse_keystone_feed_denied(feed) == 3u);
    assert(qihse_keystone_feed_malformed(feed) == 2u);

    /* The protected bytes are absent from EVERYTHING the identity received —
     * payloads and metadata alike. */
    assert(!w25_sink_contains(&sink, W25_SECRET_CLEARANCE));
    assert(!w25_sink_contains(&sink, W25_SECRET_SCI));
    assert(!w25_sink_contains(&sink, W25_SECRET_TENANT));
    assert(!w25_sink_contains(&sink, W25_SECRET_MALFORMED));
    assert(!w25_sink_contains(&sink, "feed/secret-clearance"));
    assert(!w25_sink_contains(&sink, "feed/secret-sci"));
    assert(!w25_sink_contains(&sink, "feed/secret-tenant"));
    assert(!w25_sink_contains(&sink, "feed/raw"));
    assert(!w25_sink_contains(&sink, "feed/broken"));

    /* --- D. A resume cursor cannot be used to replay past a denial. */
    assert(qihse_keystone_feed_resume(feed, 0));
    size_t replay_delivered = 0;
    while (qihse_keystone_feed_next(feed, &ev, &rec, &payload, &payload_len)) {
        replay_delivered++;
        w25_sink_add(&sink, ev.resource_id, strlen(ev.resource_id));
        w25_sink_add(&sink, payload, payload_len);
        free(payload);
        payload = NULL;
    }
    assert(replay_delivered == 3u);                 /* same three, no more */
    assert(qihse_keystone_feed_denied(feed) == 6u); /* denied again, not leaked */
    assert(!w25_sink_contains(&sink, W25_SECRET_CLEARANCE));
    assert(!w25_sink_contains(&sink, W25_SECRET_SCI));
    assert(!w25_sink_contains(&sink, W25_SECRET_TENANT));
    assert(!w25_sink_contains(&sink, W25_SECRET_MALFORMED));

    /* A cursor beyond the end of the journal is not a position the identity
     * ever occupied. */
    assert(!qihse_keystone_feed_resume(feed, UINT64_MAX));
    assert(!qihse_keystone_feed_resume(feed, qihse_federation_journal_length(journal) + 1u));

    /* --- E. Save the cursor, "restart", resume. */
    assert(qihse_keystone_feed_ack(feed, last_offset));
    assert(qihse_keystone_feed_last_ack(feed) >= last_offset);
    assert(qihse_keystone_feed_cursor_save(feed, cursor_path));
    uint64_t saved = qihse_keystone_feed_cursor(feed);
    qihse_keystone_feed_close(feed);

    /* Restart: a fresh handle, resumed from the stored cursor. */
    uint64_t loaded = 0;
    assert(qihse_keystone_feed_cursor_load(indexer, cursor_path, &loaded));
    assert(loaded == saved);
    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.prefix, sizeof(cfg.prefix), "feed/");
    cfg.cursor = loaded;
    feed = qihse_keystone_feed_open(journal, indexer, &cfg);
    assert(feed);
    assert(qihse_keystone_feed_cursor(feed) == loaded);

    /* Nothing new yet: the resumed feed re-delivers nothing. */
    assert(!qihse_keystone_feed_next(feed, &ev, &rec, &payload, &payload_len));

    /* A record published after the cursor is delivered, and only it. */
    w25_publish(journal, op, &node, "w25.index", "feed/four", 1u, 0x1u,
                W25_INDEXER_TENANT, 7u, "record-four");
    assert(qihse_keystone_feed_next(feed, &ev, &rec, &payload, &payload_len));
    assert(strcmp(ev.resource_id, "feed/four") == 0);
    assert(payload_len == strlen("record-four"));
    assert(memcmp(payload, "record-four", payload_len) == 0);
    free(payload);
    payload = NULL;
    assert(!qihse_keystone_feed_next(feed, &ev, &rec, &payload, &payload_len));
    qihse_keystone_feed_close(feed);

    /* --- D. A cursor minted for a wider identity cannot be transplanted. */
    char op_cursor_path[600];
    snprintf(op_cursor_path, sizeof(op_cursor_path), "%s.op", cursor_path);
    memset(&cfg, 0, sizeof(cfg));
    qihse_keystone_feed_t* op_feed = qihse_keystone_feed_open(journal, op, &cfg);
    assert(op_feed);
    while (qihse_keystone_feed_next(op_feed, &ev, &rec, &payload, &payload_len)) {
        free(payload);
        payload = NULL;
    }
    assert(qihse_keystone_feed_cursor_save(op_feed, op_cursor_path));
    qihse_keystone_feed_close(op_feed);
    uint64_t op_cursor = 0;
    assert(qihse_keystone_feed_cursor_load(op, op_cursor_path, &op_cursor));
    assert(!qihse_keystone_feed_cursor_load(indexer, op_cursor_path, &loaded));
    assert(qihse_keystone_feed_cursor_load(indexer, cursor_path, &loaded));
    remove(op_cursor_path);

    printf("PASS filtered feed: 3 delivered, 3 withheld, 2 malformed, "
           "no protected bytes, resume + cursor binding honored\n");
}

/* ── RESP: the same identity over the wire ─────────────────────────────── */

static uint16_t w25_free_tcp_port(void) {
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

typedef struct { int fd; char buf[65536]; size_t fill; } w25_client_t;

static bool w25_read_line(w25_client_t* c, char* out, size_t cap) {
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

static bool w25_read_exact(w25_client_t* c, char* out, size_t len) {
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

static bool w25_read_reply(w25_client_t* c, char* out, size_t cap, size_t* used) {
    char line[512];
    if (!w25_read_line(c, line, sizeof(line))) return false;
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
        if (!w25_read_exact(c, data, (size_t)len + 2u)) return false;
        data[len] = '\0';
        int n = snprintf(out + *used, cap - *used, "%s", data);
        *used += (size_t)(n > 0 ? n : 0);
        return true;
    }
    if (type == '*') {
        int count = atoi(rest);
        for (int i = 0; i < count; i++) {
            if (i && *used + 1u < cap) out[(*used)++] = '|';
            if (!w25_read_reply(c, out, cap, used)) return false;
        }
        return true;
    }
    return false;
}

/* Send a command with up to 8 arguments. */
static void w25_send_argv(w25_client_t* c, const char** argv, size_t argc) {
    char out[8192]; size_t off = 0;
    off += (size_t)snprintf(out + off, sizeof(out) - off, "*%zu\r\n", argc);
    for (size_t i = 0; i < argc; i++) {
        off += (size_t)snprintf(out + off, sizeof(out) - off, "$%zu\r\n%s\r\n",
                                strlen(argv[i]), argv[i]);
    }
    assert(send(c->fd, out, off, 0) == (ssize_t)off);
}

static void w25_send3(w25_client_t* c, const char* a, const char* b, const char* d) {
    const char* argv[3] = { a, b, d };
    size_t argc = 0;
    for (size_t i = 0; i < 3u; i++) if (argv[i]) argc++;
    w25_send_argv(c, argv, argc);
}

static void w25_connect(w25_client_t* c, struct sockaddr_in* addr) {
    memset(c, 0, sizeof(*c));
    c->fd = socket(AF_INET, SOCK_STREAM, 0);
    assert(c->fd >= 0);
    assert(connect(c->fd, (struct sockaddr*)addr, sizeof(*addr)) == 0);
}

/* Publish a feed record over the wire; the raw reply goes to the caller. */
static void w25_resp_publish(w25_client_t* c, const char* event_type,
                             const char* resource_id, const char* classif,
                             const char* sci, const char* tenant,
                             const char* generation, const char* payload,
                             char* reply_out, size_t reply_cap, size_t* used_out) {
    const char* argv[8] = { "KEYSTONE.FEED.PUBLISH", event_type, resource_id,
                            classif, sci, tenant, generation, payload };
    w25_send_argv(c, argv, 8u);
    size_t used = 0;
    assert(w25_read_reply(c, reply_out, reply_cap, &used));
    if (used_out) *used_out = used;
}

static void test_resp_surface(qihse_kv_store_t* store, qihse_user_t* op,
                              qihse_user_t* indexer, qihse_user_t* analyst,
                              const char* resp_journal_root) {
    uint16_t port = w25_free_tcp_port();
    char node_id[QIHSE_CLUSTER_NODE_ID_LEN + 1u];
    qihse_cluster_node_id_from_seed("w25-resp-node", strlen("w25-resp-node"), node_id);
    qihse_resp_server_config_t scfg;
    qihse_resp_server_config_init(&scfg);
    scfg.node_id = node_id;
    scfg.bind_address = "127.0.0.1";
    scfg.advertise_address = "127.0.0.1";
    scfg.port = port;
    scfg.bus_port = w25_free_tcp_port();
    scfg.store = store;
    scfg.enable_bus = false;
    scfg.enable_failover = false;
    scfg.auth_required = true;
    scfg.federation_journal_directory = resp_journal_root;
    scfg.federation_journal_durability = QIHSE_ES_DURABILITY_FDATASYNC;
    qihse_resp_server_t* server = qihse_resp_server_create(&scfg);
    if (!server) fprintf(stderr, "server create failed: errno=%d (%s)\n", errno, strerror(errno));
    assert(server);
    assert(qihse_resp_server_start(server));

    struct sockaddr_in addr; memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(port);

    char reply[16384]; size_t used;

    /* --- The operator publishes one cleared record and one above the index
     * identity's clearance. */
    w25_client_t opc; w25_connect(&opc, &addr);
    w25_send3(&opc, "AUTH", qihse_user_get_username(op), W25_OP_PASSWORD);
    used = 0; assert(w25_read_reply(&opc, reply, sizeof reply, &used));
    assert(strcmp(reply, "OK") == 0);

    w25_resp_publish(&opc, "w25.resp", "resp/cleared", "1", "1", "7", "1",
                     "resp-payload-cleared", reply, sizeof reply, &used);
    assert(atoi(reply) > 0);
    w25_resp_publish(&opc, "w25.resp", "resp/secret", "9", "1", "7", "2",
                     W25_SECRET_CLEARANCE, reply, sizeof reply, &used);
    assert(atoi(reply) > 0);

    /* The operator is not restricted by the index-identity allowlist. */
    w25_send3(&opc, "FEDERATION", "EVENT.LENGTH", NULL);
    used = 0; assert(w25_read_reply(&opc, reply, sizeof reply, &used));
    assert(atoi(reply) > 0);

    /* --- The index identity over the wire. */
    w25_client_t kc; w25_connect(&kc, &addr);
    w25_send3(&kc, "AUTH", qihse_user_get_username(indexer), W25_INDEXER_PASSWORD);
    used = 0; assert(w25_read_reply(&kc, reply, sizeof reply, &used));
    assert(strcmp(reply, "OK") == 0);

    w25_sink_t sink;
    memset(&sink, 0, sizeof(sink));
    char denial_sample[256];
    denial_sample[0] = '\0';

    /* Denied: a write. */
    w25_send3(&kc, "SET", "w25:forbidden", "value");
    used = 0; assert(w25_read_reply(&kc, reply, sizeof reply, &used));
    assert(strstr(reply, "NOPERM") != NULL);
    snprintf(denial_sample, sizeof(denial_sample), "%.200s", reply);
    w25_sink_add(&sink, reply, used);
    /* Denied: an administrative/ingest write. */
    w25_send3(&kc, "KEYSTONE.INGEST", "user@example.com:pw", NULL);
    used = 0; assert(w25_read_reply(&kc, reply, sizeof reply, &used));
    assert(strstr(reply, "NOPERM") != NULL);
    w25_sink_add(&sink, reply, used);
    /* Denied: a federation control-plane command (write and read). */
    w25_send3(&kc, "FEDERATION", "EVENT.APPEND", "evil");
    used = 0; assert(w25_read_reply(&kc, reply, sizeof reply, &used));
    assert(strstr(reply, "NOPERM") != NULL);
    w25_sink_add(&sink, reply, used);
    w25_send3(&kc, "FEDERATION", "WATCH.OPEN", NULL);
    used = 0; assert(w25_read_reply(&kc, reply, sizeof reply, &used));
    assert(strstr(reply, "NOPERM") != NULL);
    w25_sink_add(&sink, reply, used);
    /* Denied: node enrollment (the federation trust plane). */
    w25_send_argv(&kc, (const char*[]){ "FEDERATION", "NODE.ENROLL", "host-agent",
                                         "evil", "boot" }, 5u);
    used = 0; assert(w25_read_reply(&kc, reply, sizeof reply, &used));
    assert(strstr(reply, "NOPERM") != NULL);
    w25_sink_add(&sink, reply, used);
    /* Denied: cluster administration and fabric dispatch. */
    w25_send_argv(&kc, (const char*[]){ "CLUSTER", "MOVESLOTS", "0-10",
                                         "127.0.0.1:1" }, 4u);
    used = 0; assert(w25_read_reply(&kc, reply, sizeof reply, &used));
    assert(strstr(reply, "NOPERM") != NULL);
    w25_sink_add(&sink, reply, used);
    w25_send_argv(&kc, (const char*[]){ "FABRIC.SUBMIT", "0", "0", "job" }, 4u);
    used = 0; assert(w25_read_reply(&kc, reply, sizeof reply, &used));
    assert(strstr(reply, "NOPERM") != NULL);
    w25_sink_add(&sink, reply, used);
    /* Denied: the write half of the feed itself. */
    w25_resp_publish(&kc, "w25.resp", "resp/self", "0", "0", "7", "3",
                     "self-published", reply, sizeof reply, &used);
    assert(strstr(reply, "NOPERM") != NULL);
    w25_sink_add(&sink, reply, used);

    /* Allowed: consume the feed. */
    w25_send3(&kc, "KEYSTONE.FEED.OPEN", NULL, NULL);
    used = 0; assert(w25_read_reply(&kc, reply, sizeof reply, &used));
    int fid = atoi(reply);
    assert(fid >= 0);
    char fid_str[16]; snprintf(fid_str, sizeof(fid_str), "%d", fid);

    w25_send3(&kc, "KEYSTONE.FEED.NEXT", fid_str, NULL);
    used = 0; assert(w25_read_reply(&kc, reply, sizeof reply, &used));
    assert(strstr(reply, "resp/cleared") != NULL);
    assert(strstr(reply, "resp-payload-cleared") != NULL);
    w25_sink_add(&sink, reply, used);

    w25_send3(&kc, "KEYSTONE.FEED.NEXT", fid_str, NULL);
    used = 0; assert(w25_read_reply(&kc, reply, sizeof reply, &used));
    /* The classified record is withheld: the reply carries no record at all. */
    assert(strcmp(reply, "0") == 0);
    w25_sink_add(&sink, reply, used);

    w25_send3(&kc, "KEYSTONE.FEED.STATUS", fid_str, NULL);
    used = 0; assert(w25_read_reply(&kc, reply, sizeof reply, &used));
    assert(strstr(reply, "|1|") != NULL); /* denied >= 1 */
    w25_sink_add(&sink, reply, used);

    w25_send3(&kc, "KEYSTONE.FEED.ACK", fid_str, "1");
    used = 0; assert(w25_read_reply(&kc, reply, sizeof reply, &used));
    assert(strcmp(reply, "OK") == 0);
    w25_send3(&kc, "KEYSTONE.FEED.RESUME", fid_str, "0");
    used = 0; assert(w25_read_reply(&kc, reply, sizeof reply, &used));
    assert(strcmp(reply, "OK") == 0);
    w25_send3(&kc, "KEYSTONE.FEED.NEXT", fid_str, NULL);
    used = 0; assert(w25_read_reply(&kc, reply, sizeof reply, &used));
    assert(strstr(reply, "resp/cleared") != NULL);
    w25_sink_add(&sink, reply, used);
    w25_send3(&kc, "KEYSTONE.FEED.CLOSE", fid_str, NULL);
    used = 0; assert(w25_read_reply(&kc, reply, sizeof reply, &used));
    assert(strcmp(reply, "OK") == 0);

    /* Direct-ID lookup is not a way around the feed binding: the operator
     * session has no feed in that slot, so the same id reaches nothing. */
    w25_send3(&opc, "KEYSTONE.FEED.NEXT", fid_str, NULL);
    used = 0; assert(w25_read_reply(&opc, reply, sizeof reply, &used));
    assert(strstr(reply, "ERR unknown feed id") != NULL);
    w25_sink_add(&sink, reply, used);

    /* The protected payload bytes are absent from everything the identity
     * received over the wire — including error text and metadata. */
    assert(!w25_sink_contains(&sink, W25_SECRET_CLEARANCE));
    assert(!w25_sink_contains(&sink, "resp/secret"));

    /* A plain analyst (not the provisioned index identity) is refused the feed
     * surface too, even though it holds FEDERATION_READ. */
    w25_client_t ac; w25_connect(&ac, &addr);
    w25_send3(&ac, "AUTH", qihse_user_get_username(analyst), W25_ANALYST_PASSWORD);
    used = 0; assert(w25_read_reply(&ac, reply, sizeof reply, &used));
    assert(strcmp(reply, "OK") == 0);
    w25_send3(&ac, "KEYSTONE.FEED.OPEN", NULL, NULL);
    used = 0; assert(w25_read_reply(&ac, reply, sizeof reply, &used));
    assert(strstr(reply, "NOPERM") != NULL);
    close(ac.fd);

    close(kc.fd);
    close(opc.fd);
    qihse_resp_server_stop(server);
    qihse_resp_server_destroy(server);
    printf("PASS RESP surface: denied SET / KEYSTONE.INGEST / FEDERATION.* / CLUSTER MOVESLOTS / "
           "FABRIC.SUBMIT / KEYSTONE.FEED.PUBLISH; allowed KEYSTONE.FEED.OPEN|NEXT|ACK|RESUME|CLOSE|STATUS\n");
    printf("     sample denial: %s\n", denial_sample);
}

int main(void) {
    char data_root[] = "build/w25_XXXXXX";
    assert(mkdtemp(data_root));
    char journal_root[512];
    snprintf(journal_root, sizeof(journal_root), "%s/journal", data_root);
    assert(mkdir(journal_root, 0700) == 0);
    char resp_journal_root[512];
    snprintf(resp_journal_root, sizeof(resp_journal_root), "%s/resp-journal", data_root);
    assert(mkdir(resp_journal_root, 0700) == 0);
    char cursor_path[512];
    snprintf(cursor_path, sizeof(cursor_path), "%s/keystone.cursor", data_root);
    setenv("QIHSE_DATA_DIR", data_root, 1);

    assert(qihse_auth_init());
    bool bootstrapped = qihse_auth_bootstrap_operator(W25_OP_PASSWORD);
    if (!bootstrapped) {
        setenv("QIHSE_OPERATOR_PASSWORD", W25_OP_PASSWORD, 1);
        assert(qihse_auth_init());
    }
    qihse_user_t* op = qihse_auth_get_user(0);
    assert(op);
    /* This test authenticates several principals from loopback. */
    qihse_auth_init_rate_limiter(100, 60, 1024);

    qihse_kv_store_t* store = qihse_kv_store_create();
    assert(store);

    qihse_federation_journal_t* journal = qihse_federation_journal_open(
        journal_root, QIHSE_ES_DURABILITY_FDATASYNC);
    assert(journal);

    qihse_user_t* indexer = qihse_keystone_feed_identity_provision(
        op, W25_INDEXER_TENANT, W25_INDEXER_USER, W25_INDEXER_CLEARANCE,
        W25_INDEXER_SCI, W25_INDEXER_PASSWORD);
    assert(indexer);
    qihse_user_t* analyst = qihse_auth_create_tenant_user(
        op, W25_INDEXER_TENANT, W25_ANALYST_USER, QIHSE_ROLE_ANALYST, 4u, 0x1u,
        W25_ANALYST_PASSWORD, false);
    assert(analyst);
    qihse_user_t* delegate = qihse_auth_create_tenant_user(
        op, W25_INDEXER_TENANT, W25_DELEGATE_USER, QIHSE_ROLE_GUEST, 0u, 0u,
        W25_DELEGATE_PASSWORD, false);
    assert(delegate);
    assert(qihse_auth_modify_user(op, W25_DELEGATE_USER, NULL, NULL, -1, 1, -1, -1));

    test_least_privilege(store, op, journal, indexer, analyst, delegate);
    test_filtered_consumption(journal, op, indexer, cursor_path);
    test_resp_surface(store, op, indexer, analyst, resp_journal_root);

    /* Revocation: dropping the binding removes the identity's feed access
     * without waiting for account destruction, including on a feed handle
     * that was already open. */
    qihse_keystone_feed_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    qihse_keystone_feed_t* open_feed = qihse_keystone_feed_open(journal, indexer, &cfg);
    assert(open_feed);
    assert(qihse_keystone_feed_identity_revoke(op, W25_INDEXER_USER));
    assert(!qihse_keystone_feed_identity_is_indexer(indexer));
    qihse_federation_event_t ev;
    qihse_keystone_feed_record_t rec;
    uint8_t* payload = NULL;
    size_t payload_len = 0;
    assert(!qihse_keystone_feed_next(open_feed, &ev, &rec, &payload, &payload_len));
    qihse_keystone_feed_close(open_feed);
    assert(qihse_keystone_feed_open(journal, indexer, &cfg) == NULL);
    assert(!qihse_keystone_feed_identity_revoke(indexer, W25_INDEXER_USER));
    assert(!qihse_keystone_feed_identity_revoke(op, 0u)); /* never provisioned */

    qihse_federation_journal_destroy(journal);
    qihse_kv_store_destroy(store);
    printf("keystone feed W2.5 tests passed\n");
    return 0;
}
