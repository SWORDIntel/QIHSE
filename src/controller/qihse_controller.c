/*
 * qihse_controller — typed controller client (see qihse_controller.h).
 *
 * A synchronous RESP client with a bounded decoder plus the §25 wrappers.
 * Every wrapper is a pure wire mapping: the server remains the authority
 * for authentication, scopes, classification and replay — this library's
 * job is to make the correct call shape unforgeable-by-accident, not to
 * confer any privilege.
 */

#include "qihse_controller.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#ifdef _WIN32
#error "qihse_controller is POSIX-only for now"
#endif
#include <unistd.h>
#include <fcntl.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define CTRL_RX_CAP 65536u

struct qihse_controller {
    int fd;
    uint8_t* buf;       /* receive buffer, CTRL_RX_CAP bytes */
    size_t fill;
    bool dead;          /* transport failure — caller should reconnect */
};

/* ── Buffered reader ────────────────────────────────────────────────── */

static bool ctrl_recv_more(qihse_controller_t* c) {
    if (c->fill >= CTRL_RX_CAP) return false;   /* no CRLF in a full buffer */
    ssize_t n = recv(c->fd, c->buf + c->fill, CTRL_RX_CAP - c->fill, 0);
    if (n <= 0) { c->dead = true; return false; }
    c->fill += (size_t)n;
    return true;
}

/* Read one CRLF-terminated line (the terminator is consumed). */
static bool ctrl_read_line(qihse_controller_t* c, char* out, size_t cap) {
    for (;;) {
        for (size_t i = 0; i < c->fill; i++) {
            if (c->buf[i] == '\n') {
                size_t len = i;
                if (len && c->buf[len - 1u] == '\r') len--;
                if (len >= cap) return false;
                memcpy(out, c->buf, len);
                out[len] = '\0';
                memmove(c->buf, c->buf + i + 1u, c->fill - i - 1u);
                c->fill -= i + 1u;
                return true;
            }
        }
        if (!ctrl_recv_more(c)) return false;
    }
}

static bool ctrl_read_exact(qihse_controller_t* c, uint8_t* out, size_t len) {
    while (c->fill < len) {
        if (!ctrl_recv_more(c)) return false;
    }
    memcpy(out, c->buf, len);
    memmove(c->buf, c->buf + len, c->fill - len);
    c->fill -= len;
    return true;
}

/* ── Reply codec ────────────────────────────────────────────────────── */

static qihse_ctrl_reply_t* ctrl_reply_new(qihse_ctrl_kind_t kind) {
    qihse_ctrl_reply_t* r = (qihse_ctrl_reply_t*)calloc(1, sizeof(*r));
    if (r) r->kind = kind;
    return r;
}

void qihse_ctrl_reply_free(qihse_ctrl_reply_t* reply) {
    if (!reply) return;
    free(reply->text);
    if (reply->items) {
        for (size_t i = 0; i < reply->count; i++) qihse_ctrl_reply_free(&reply->items[i]);
        free(reply->items);
    }
}

static bool ctrl_parse_i64(const char* s, int64_t* out) {
    if (!s || !*s) return false;
    char* end = NULL;
    errno = 0;
    long long v = strtoll(s, &end, 10);
    if (errno || end == s) return false;
    *out = (int64_t)v;
    return true;
}

static qihse_ctrl_reply_t* ctrl_parse_reply(qihse_controller_t* c, unsigned depth) {
    if (depth > QIHSE_CTRL_MAX_DEPTH) return NULL;
    char line[128];
    if (!ctrl_read_line(c, line, sizeof(line))) return NULL;
    char type = line[0];
    const char* rest = line + 1;

    switch (type) {
    case '+': case '-': {
        qihse_ctrl_reply_t* r = ctrl_reply_new(type == '+' ? QIHSE_CTRL_SIMPLE
                                                          : QIHSE_CTRL_ERROR);
        if (!r) return NULL;
        r->text_len = strlen(rest);
        r->text = (char*)malloc(r->text_len + 1u);
        if (!r->text) { free(r); return NULL; }
        memcpy(r->text, rest, r->text_len + 1u);
        return r;
    }
    case ':': {
        qihse_ctrl_reply_t* r = ctrl_reply_new(QIHSE_CTRL_INT);
        if (!r) return NULL;
        if (!ctrl_parse_i64(rest, &r->integer)) { free(r); return NULL; }
        return r;
    }
    case '$': {
        int64_t len;
        if (!ctrl_parse_i64(rest, &len)) return NULL;
        if (len < 0) return ctrl_reply_new(QIHSE_CTRL_NIL);
        if ((uint64_t)len > QIHSE_CTRL_MAX_BULK) return NULL;
        qihse_ctrl_reply_t* r = ctrl_reply_new(QIHSE_CTRL_BULK);
        if (!r) return NULL;
        r->text = (char*)malloc((size_t)len + 1u);
        if (!r->text) { free(r); return NULL; }
        r->text_len = (size_t)len;
        if (!ctrl_read_exact(c, (uint8_t*)r->text, (size_t)len)) { qihse_ctrl_reply_free(r); return NULL; }
        r->text[len] = '\0';
        uint8_t crlf[2];
        if (!ctrl_read_exact(c, crlf, 2) || crlf[0] != '\r' || crlf[1] != '\n') {
            qihse_ctrl_reply_free(r);
            return NULL;
        }
        return r;
    }
    case '*': {
        int64_t count;
        if (!ctrl_parse_i64(rest, &count)) return NULL;
        if (count < 0) return ctrl_reply_new(QIHSE_CTRL_NIL);
        if ((uint64_t)count > QIHSE_CTRL_MAX_ITEMS) return NULL;
        qihse_ctrl_reply_t* r = ctrl_reply_new(QIHSE_CTRL_ARRAY);
        if (!r) return NULL;
        r->count = (size_t)count;
        if (count == 0) return r;
        r->items = (qihse_ctrl_reply_t*)calloc((size_t)count, sizeof(*r->items));
        if (!r->items) { free(r); return NULL; }
        for (int64_t i = 0; i < count; i++) {
            qihse_ctrl_reply_t* child = ctrl_parse_reply(c, depth + 1u);
            if (!child) { qihse_ctrl_reply_free(r); return NULL; }
            r->items[i] = *child;
            free(child);
        }
        return r;
    }
    default:
        return NULL;
    }
}

/* ── Command path ───────────────────────────────────────────────────── */

static bool ctrl_send_all(qihse_controller_t* c, const uint8_t* p, size_t len) {
    while (len) {
        ssize_t n = send(c->fd, p, len, 0);
        if (n <= 0) { c->dead = true; return false; }
        p += n;
        len -= (size_t)n;
    }
    return true;
}

qihse_ctrl_reply_t* qihse_ctrl_callv(qihse_controller_t* ctrl,
                                    size_t argc, const char* const argv[],
                                    const size_t* lens) {
    if (!ctrl || ctrl->dead || argc == 0 || !argv) return NULL;
    /* Single header + per-arg frames; assembled in one malloc to keep the
     * send atomic-ish rather than interleaving partial frames. */
    size_t total = 32u;
    for (size_t i = 0; i < argc; i++) {
        size_t l = lens ? lens[i] : (argv[i] ? strlen(argv[i]) : 0u);
        total += 32u + l + 2u;
        if (total > QIHSE_CTRL_MAX_BULK) return NULL;   /* absurdly large command */
    }
    uint8_t* wire = (uint8_t*)malloc(total);
    if (!wire) return NULL;
    size_t pos = (size_t)snprintf((char*)wire, total, "*%zu\r\n", argc);
    for (size_t i = 0; i < argc; i++) {
        size_t l = lens ? lens[i] : (argv[i] ? strlen(argv[i]) : 0u);
        pos += (size_t)snprintf((char*)wire + pos, total - pos, "$%zu\r\n", l);
        if (l) { memcpy(wire + pos, argv[i], l); pos += l; }
        wire[pos++] = '\r';
        wire[pos++] = '\n';
    }
    bool sent = ctrl_send_all(ctrl, wire, pos);
    free(wire);
    if (!sent) return NULL;
    qihse_ctrl_reply_t* r = ctrl_parse_reply(ctrl, 0);
    if (!r) ctrl->dead = true;
    return r;
}

qihse_ctrl_reply_t* qihse_ctrl_call(qihse_controller_t* ctrl,
                                    size_t argc, const char* const argv[]) {
    return qihse_ctrl_callv(ctrl, argc, argv, NULL);
}

/* Internal: prepend "FEDERATION" and forward. */
static qihse_ctrl_reply_t* fed_call(qihse_controller_t* c, const char* sub,
                                    size_t argc, const char* const argv[],
                                    const size_t* lens) {
    const char* a[10];
    size_t l[10];
    if (argc > 8) return NULL;
    a[0] = "FEDERATION"; l[0] = 10u;
    a[1] = sub;          l[1] = strlen(sub);
    for (size_t i = 0; i < argc; i++) {
        a[2 + i] = argv[i];
        l[2 + i] = lens ? lens[i] : strlen(argv[i]);
    }
    return qihse_ctrl_callv(c, argc + 2u, a, l);
}

/* ── Connect ────────────────────────────────────────────────────────── */

qihse_controller_t* qihse_controller_connect(const qihse_controller_config_t* config) {
    if (!config || !config->host || !*config->host || config->port == 0) return NULL;
    qihse_controller_t* c = (qihse_controller_t*)calloc(1, sizeof(*c));
    if (!c) return NULL;
    c->buf = (uint8_t*)malloc(CTRL_RX_CAP);
    if (!c->buf) { free(c); return NULL; }
    c->fd = -1;

    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%u", (unsigned)config->port);
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo* ai = NULL;
    if (getaddrinfo(config->host, port_str, &hints, &ai) != 0 || !ai) {
        qihse_controller_destroy(c);
        return NULL;
    }
    c->fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (c->fd < 0 || connect(c->fd, ai->ai_addr, ai->ai_addrlen) != 0) {
        freeaddrinfo(ai);
        qihse_controller_destroy(c);
        return NULL;
    }
    freeaddrinfo(ai);

    uint32_t ms = config->timeout_ms ? config->timeout_ms
                                     : QIHSE_CTRL_DEFAULT_TIMEOUT_MS;
    struct timeval tv;
    tv.tv_sec = (time_t)(ms / 1000u);
    tv.tv_usec = (suseconds_t)((ms % 1000u) * 1000u);
    (void)setsockopt(c->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    (void)setsockopt(c->fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    if (config->username) {
        const char* auth[3] = { "AUTH", config->username,
                                config->password ? config->password : "" };
        qihse_ctrl_reply_t* r = qihse_ctrl_call(c, 3, auth);
        bool ok = qihse_ctrl_reply_ok(r);
        qihse_ctrl_reply_free(r);
        if (!ok) { qihse_controller_destroy(c); return NULL; }
    }
    return c;
}

void qihse_controller_destroy(qihse_controller_t* ctrl) {
    if (!ctrl) return;
    if (ctrl->fd >= 0) close(ctrl->fd);
    free(ctrl->buf);
    free(ctrl);
}

bool qihse_controller_connected(const qihse_controller_t* ctrl) {
    return ctrl && !ctrl->dead && ctrl->fd >= 0;
}

/* ── Reply helpers ──────────────────────────────────────────────────── */

bool qihse_ctrl_reply_ok(const qihse_ctrl_reply_t* r) {
    return r && r->kind == QIHSE_CTRL_SIMPLE && r->text &&
           strcmp(r->text, "OK") == 0;
}

bool qihse_ctrl_reply_int(const qihse_ctrl_reply_t* r, int64_t* out) {
    if (!r || r->kind != QIHSE_CTRL_INT || !out) return false;
    *out = r->integer;
    return true;
}

const char* qihse_ctrl_reply_text(const qihse_ctrl_reply_t* r) {
    if (!r || !r->text) return NULL;
    if (r->kind == QIHSE_CTRL_SIMPLE || r->kind == QIHSE_CTRL_BULK ||
        r->kind == QIHSE_CTRL_ERROR) return r->text;
    return NULL;
}

/* ── §25 wrappers ───────────────────────────────────────────────────── */

static void u64_str(uint64_t v, char out[24]) {
    snprintf(out, 24, "%llu", (unsigned long long)v);
}

qihse_ctrl_reply_t* qihse_ctrl_node_list(qihse_controller_t* c) {
    return fed_call(c, "NODE.LIST", 0, NULL, NULL);
}

qihse_ctrl_reply_t* qihse_ctrl_node_get(qihse_controller_t* c, const char* uuid) {
    const char* a[] = { uuid };
    return fed_call(c, "NODE.SHOW", 1, a, NULL);
}

qihse_ctrl_reply_t* qihse_ctrl_object_get(qihse_controller_t* c,
                                         const char* ns, const char* rid) {
    const char* a[] = { ns, rid };
    return fed_call(c, "OBJECT.GET", 2, a, NULL);
}

qihse_ctrl_reply_t* qihse_ctrl_object_cas(qihse_controller_t* c,
                                         const char* ns, const char* rid,
                                         const char* value, uint64_t expected) {
    char gen[24];
    u64_str(expected, gen);
    const char* a[] = { ns, rid, value, gen };
    return fed_call(c, "OBJECT.CAS", 4, a, NULL);
}

qihse_ctrl_reply_t* qihse_ctrl_lease_acquire(qihse_controller_t* c,
                                            const char* ns, const char* rid,
                                            uint64_t fencing_epoch, uint64_t expires_ms) {
    char ep[24], xp[24];
    u64_str(fencing_epoch, ep);
    const char* a[4];
    size_t n = 0;
    a[n++] = ns; a[n++] = rid; a[n++] = ep;
    if (expires_ms) { u64_str(expires_ms, xp); a[n++] = xp; }
    return fed_call(c, "LEASE.ACQUIRE", n, a, NULL);
}

qihse_ctrl_reply_t* qihse_ctrl_lease_read(qihse_controller_t* c, const char* lease_id) {
    const char* a[] = { lease_id };
    return fed_call(c, "LEASE.READ", 1, a, NULL);
}

qihse_ctrl_reply_t* qihse_ctrl_lease_renew(qihse_controller_t* c,
                                          const char* lease_id, uint64_t expires_ms) {
    char xp[24];
    u64_str(expires_ms, xp);
    const char* a[] = { lease_id, xp };
    return fed_call(c, "LEASE.RENEW", 2, a, NULL);
}

qihse_ctrl_reply_t* qihse_ctrl_lease_release(qihse_controller_t* c, const char* lease_id) {
    const char* a[] = { lease_id };
    return fed_call(c, "LEASE.RELEASE", 1, a, NULL);
}

qihse_ctrl_reply_t* qihse_ctrl_epoch_next(qihse_controller_t* c) {
    return fed_call(c, "EPOCH.NEXT", 0, NULL, NULL);
}

qihse_ctrl_reply_t* qihse_ctrl_epoch_current(qihse_controller_t* c) {
    return fed_call(c, "EPOCH.CURRENT", 0, NULL, NULL);
}

qihse_ctrl_reply_t* qihse_ctrl_event_append(qihse_controller_t* c,
                                            const char* event_type,
                                            const char* resource_id,
                                            const void* payload, size_t payload_len) {
    const char* a[3] = { event_type, resource_id, (const char*)payload };
    size_t l[3] = { strlen(event_type), strlen(resource_id), payload_len };
    return fed_call(c, "EVENT.APPEND", payload ? 3u : 2u, a, l);
}

qihse_ctrl_reply_t* qihse_ctrl_event_replay(qihse_controller_t* c, uint64_t from) {
    char cur[24];
    u64_str(from, cur);
    const char* a[] = { cur };
    return fed_call(c, "EVENT.REPLAY", 1, a, NULL);
}

qihse_ctrl_reply_t* qihse_ctrl_watch_open(qihse_controller_t* c, const char* prefix) {
    const char* a[] = { prefix ? prefix : "" };
    return fed_call(c, "WATCH.OPEN", prefix ? 1u : 0u, a, NULL);
}

qihse_ctrl_reply_t* qihse_ctrl_watch_next(qihse_controller_t* c, uint32_t watch_id) {
    char id[24];
    u64_str(watch_id, id);
    const char* a[] = { id };
    return fed_call(c, "WATCH.NEXT", 1, a, NULL);
}

qihse_ctrl_reply_t* qihse_ctrl_watch_ack(qihse_controller_t* c,
                                        uint32_t watch_id, uint64_t offset) {
    char id[24], off[24];
    u64_str(watch_id, id);
    u64_str(offset, off);
    const char* a[] = { id, off };
    return fed_call(c, "WATCH.ACK", 2, a, NULL);
}

qihse_ctrl_reply_t* qihse_ctrl_watch_resume(qihse_controller_t* c,
                                            uint32_t watch_id, uint64_t cursor) {
    char id[24], cur[24];
    u64_str(watch_id, id);
    u64_str(cursor, cur);
    const char* a[] = { id, cur };
    return fed_call(c, "WATCH.RESUME", 2, a, NULL);
}

qihse_ctrl_reply_t* qihse_ctrl_conflict_list(qihse_controller_t* c) {
    return fed_call(c, "CONFLICT.LIST", 0, NULL, NULL);
}

qihse_ctrl_reply_t* qihse_ctrl_conflict_resolve(qihse_controller_t* c,
                                                 const char* conflict_uuid,
                                                 const char* resolver_uuid) {
    const char* a[] = { conflict_uuid, resolver_uuid };
    return fed_call(c, "CONFLICT.RESOLVE", 2, a, NULL);
}

qihse_ctrl_reply_t* qihse_ctrl_federation_status(qihse_controller_t* c) {
    return fed_call(c, "STATUS", 0, NULL, NULL);
}

qihse_ctrl_reply_t* qihse_ctrl_rejoin_status(qihse_controller_t* c, const char* uuid) {
    const char* a[] = { uuid };
    return fed_call(c, "REJOIN.STATUS", 1, a, NULL);
}

qihse_ctrl_reply_t* qihse_ctrl_metrics(qihse_controller_t* c, const char* prefix) {
    const char* a[] = { prefix ? prefix : "" };
    return fed_call(c, "METRICS", prefix ? 1u : 0u, a, NULL);
}

/* ── Node administration ────────────────────────────────────────────── */

qihse_ctrl_reply_t* qihse_ctrl_node_enroll(qihse_controller_t* c,
                                          const char* identity_kind,
                                          const char* hostname,
                                          const char* boot_id) {
    const char* a[] = { identity_kind, hostname, boot_id };
    return fed_call(c, "NODE.ENROLL", 3, a, NULL);
}

qihse_ctrl_reply_t* qihse_ctrl_node_approve(qihse_controller_t* c,
                                            const char* node_uuid, uint64_t epoch) {
    char e[24];
    const char* a[2];
    size_t n = 0;
    a[n++] = node_uuid;
    if (epoch) { u64_str(epoch, e); a[n++] = e; }
    return fed_call(c, "NODE.APPROVE", n, a, NULL);
}

qihse_ctrl_reply_t* qihse_ctrl_node_revoke(qihse_controller_t* c, const char* node_uuid) {
    const char* a[] = { node_uuid };
    return fed_call(c, "NODE.REVOKE", 1, a, NULL);
}

qihse_ctrl_reply_t* qihse_ctrl_trust_set(qihse_controller_t* c,
                                         const char* node_uuid,
                                         const char* trust_state,
                                         const char* result) {
    const char* a[] = { node_uuid, trust_state, result };
    return fed_call(c, "TRUST.SET", 3, a, NULL);
}

qihse_ctrl_reply_t* qihse_ctrl_trust_states(qihse_controller_t* c) {
    return fed_call(c, "TRUST.STATES", 0, NULL, NULL);
}

qihse_ctrl_reply_t* qihse_ctrl_trust_admission(qihse_controller_t* c, const char* node_uuid) {
    const char* a[] = { node_uuid };
    return fed_call(c, "TRUST.ADMISSION", 1, a, NULL);
}

/* ── Namespaces and replication groups ──────────────────────────────── */

qihse_ctrl_reply_t* qihse_ctrl_ns_register(qihse_controller_t* c,
                                          const char* name, const char* consistency,
                                          const char* authority_node_uuid) {
    const char* a[3];
    size_t n = 0;
    a[n++] = name; a[n++] = consistency;
    if (authority_node_uuid) a[n++] = authority_node_uuid;
    return fed_call(c, "NS.REGISTER", n, a, NULL);
}

qihse_ctrl_reply_t* qihse_ctrl_ns_unregister(qihse_controller_t* c, const char* name) {
    const char* a[] = { name };
    return fed_call(c, "NS.UNREGISTER", 1, a, NULL);
}

qihse_ctrl_reply_t* qihse_ctrl_ns_list(qihse_controller_t* c) {
    return fed_call(c, "NS.LIST", 0, NULL, NULL);
}

qihse_ctrl_reply_t* qihse_ctrl_ns_writable(qihse_controller_t* c, const char* name) {
    const char* a[] = { name };
    return fed_call(c, "NS.WRITABLE", 1, a, NULL);
}

qihse_ctrl_reply_t* qihse_ctrl_manifest(qihse_controller_t* c, const char* ns) {
    const char* a[] = { ns };
    return fed_call(c, "MANIFEST", 1, a, NULL);
}

qihse_ctrl_reply_t* qihse_ctrl_group_create(qihse_controller_t* c,
                                            const char* group_id, const char* consistency) {
    const char* a[2];
    size_t n = 0;
    a[n++] = group_id;
    if (consistency) a[n++] = consistency;
    return fed_call(c, "GROUP.CREATE", n, a, NULL);
}

qihse_ctrl_reply_t* qihse_ctrl_group_add(qihse_controller_t* c,
                                        const char* group_id, const char* member_uuid,
                                        bool voter, bool witness) {
    const char* a[4];
    size_t n = 0;
    a[n++] = group_id; a[n++] = member_uuid;
    if (voter) a[n++] = "voter";
    if (witness) a[n++] = "witness";
    return fed_call(c, "GROUP.ADD", n, a, NULL);
}

qihse_ctrl_reply_t* qihse_ctrl_group_remove(qihse_controller_t* c,
                                            const char* group_id, const char* member_uuid) {
    const char* a[] = { group_id, member_uuid };
    return fed_call(c, "GROUP.REMOVE", 2, a, NULL);
}

qihse_ctrl_reply_t* qihse_ctrl_group_show(qihse_controller_t* c, const char* group_id) {
    const char* a[] = { group_id };
    return fed_call(c, "GROUP.SHOW", 1, a, NULL);
}

qihse_ctrl_reply_t* qihse_ctrl_group_list(qihse_controller_t* c) {
    return fed_call(c, "GROUP.LIST", 0, NULL, NULL);
}

qihse_ctrl_reply_t* qihse_ctrl_group_advance(qihse_controller_t* c, const char* group_id) {
    const char* a[] = { group_id };
    return fed_call(c, "GROUP.ADVANCE", 1, a, NULL);
}

/* ── Build coordination ─────────────────────────────────────────────── */

qihse_ctrl_reply_t* qihse_ctrl_build_job_create(qihse_controller_t* c,
                                                 const char* package, const char* revision,
                                                 const char* profile, const char* toolchain) {
    const char* a[] = { package, revision, profile, toolchain };
    return fed_call(c, "BUILD.CREATE", 4, a, NULL);
}

qihse_ctrl_reply_t* qihse_ctrl_build_job_transition(qihse_controller_t* c,
                                                     const char* build_id, const char* state,
                                                     const char* request_id, const char* reason) {
    const char* a[4];
    size_t n = 0;
    a[n++] = build_id; a[n++] = state; a[n++] = request_id;
    if (reason) a[n++] = reason;
    return fed_call(c, "BUILD.TRANSITION", n, a, NULL);
}

qihse_ctrl_reply_t* qihse_ctrl_build_job_get(qihse_controller_t* c, const char* build_id) {
    const char* a[] = { build_id };
    return fed_call(c, "BUILD.SHOW", 1, a, NULL);
}

qihse_ctrl_reply_t* qihse_ctrl_build_job_list(qihse_controller_t* c) {
    return fed_call(c, "BUILD.LIST", 0, NULL, NULL);
}

qihse_ctrl_reply_t* qihse_ctrl_build_states(qihse_controller_t* c) {
    return fed_call(c, "BUILD.STATES", 0, NULL, NULL);
}

qihse_ctrl_reply_t* qihse_ctrl_build_worker_publish(qihse_controller_t* c,
                                                    const char* node_uuid,
                                                    uint32_t cores, uint32_t ram_gb,
                                                    uint32_t depth) {
    char cs[24], rs[24], ds[24];
    u64_str(cores, cs);
    u64_str(ram_gb, rs);
    u64_str(depth, ds);
    const char* a[] = { node_uuid, cs, rs, ds };
    return fed_call(c, "BUILDER.CAP", 4, a, NULL);
}

qihse_ctrl_reply_t* qihse_ctrl_build_worker_get(qihse_controller_t* c, const char* node_uuid) {
    const char* a[] = { node_uuid };
    return fed_call(c, "BUILDER.SHOW", 1, a, NULL);
}

/* ── Supply chain ───────────────────────────────────────────────────── */

qihse_ctrl_reply_t* qihse_ctrl_pkg_set(qihse_controller_t* c,
                                        const char* package, const char* mode,
                                        const char* reason) {
    const char* a[] = { package, mode, reason };
    return fed_call(c, "PKG.SET", 3, a, NULL);
}

qihse_ctrl_reply_t* qihse_ctrl_pkg_get(qihse_controller_t* c, const char* package) {
    const char* a[] = { package };
    return fed_call(c, "PKG.GET", 1, a, NULL);
}

qihse_ctrl_reply_t* qihse_ctrl_pkg_modes(qihse_controller_t* c) {
    return fed_call(c, "PKG.MODES", 0, NULL, NULL);
}

qihse_ctrl_reply_t* qihse_ctrl_supply_sbom(qihse_controller_t* c,
                                            const char* artifact_digest,
                                            const char* sbom_digest,
                                            const char* signing_identity,
                                            const char* format) {
    const char* a[] = { artifact_digest, sbom_digest, signing_identity, format };
    return fed_call(c, "SUPPLY.SBOM", 4, a, NULL);
}

qihse_ctrl_reply_t* qihse_ctrl_supply_sbom_get(qihse_controller_t* c, const char* sbom_digest) {
    const char* a[] = { sbom_digest };
    return fed_call(c, "SUPPLY.SBOM.GET", 1, a, NULL);
}

qihse_ctrl_reply_t* qihse_ctrl_supply_snapshot(qihse_controller_t* c,
                                                const char* repository, const char* digest,
                                                const char* release, uint64_t package_count) {
    char pc[24];
    const char* a[4];
    size_t n = 0;
    a[n++] = repository; a[n++] = digest; a[n++] = release;
    if (package_count) { u64_str(package_count, pc); a[n++] = pc; }
    return fed_call(c, "SUPPLY.SNAPSHOT", n, a, NULL);
}

qihse_ctrl_reply_t* qihse_ctrl_supply_snapshot_list(qihse_controller_t* c,
                                                     const char* repository) {
    const char* a[] = { repository ? repository : "" };
    return fed_call(c, "SUPPLY.SNAPSHOT.LIST", repository ? 1u : 0u, a, NULL);
}

qihse_ctrl_reply_t* qihse_ctrl_supply_vuln(qihse_controller_t* c,
                                            const char* component_digest,
                                            const char* advisory, const char* severity,
                                            const char* status) {
    const char* a[] = { component_digest, advisory, severity, status };
    return fed_call(c, "SUPPLY.VULN", 4, a, NULL);
}

qihse_ctrl_reply_t* qihse_ctrl_supply_vuln_count(qihse_controller_t* c,
                                                  const char* component_digest) {
    const char* a[] = { component_digest };
    return fed_call(c, "SUPPLY.VULN.COUNT", 1, a, NULL);
}

qihse_ctrl_reply_t* qihse_ctrl_prov_node(qihse_controller_t* c,
                                          const char* entity, const char* id,
                                          const char* label) {
    const char* a[3];
    size_t n = 0;
    a[n++] = entity; a[n++] = id;
    if (label) a[n++] = label;
    return fed_call(c, "PROV.NODE", n, a, NULL);
}

qihse_ctrl_reply_t* qihse_ctrl_prov_edge(qihse_controller_t* c,
                                          const char* from_ref, const char* edge,
                                          const char* to_ref) {
    const char* a[] = { from_ref, edge, to_ref };
    return fed_call(c, "PROV.EDGE", 3, a, NULL);
}

qihse_ctrl_reply_t* qihse_ctrl_prov_show(qihse_controller_t* c,
                                          const char* entity, const char* id) {
    const char* a[] = { entity, id };
    return fed_call(c, "PROV.SHOW", 2, a, NULL);
}

qihse_ctrl_reply_t* qihse_ctrl_prov_trace(qihse_controller_t* c,
                                           const char* entity, const char* id,
                                           bool forward, uint32_t depth) {
    char d[24];
    const char* a[4];
    size_t n = 0;
    a[n++] = entity; a[n++] = id; a[n++] = forward ? "forward" : "reverse";
    if (depth) { u64_str(depth, d); a[n++] = d; }
    return fed_call(c, "PROV.TRACE", n, a, NULL);
}

qihse_ctrl_reply_t* qihse_ctrl_prov_impact(qihse_controller_t* c,
                                            const char* entity, const char* id,
                                            const char* want_entity, uint32_t depth) {
    char d[24];
    const char* a[4];
    size_t n = 0;
    a[n++] = entity; a[n++] = id; a[n++] = want_entity;
    if (depth) { u64_str(depth, d); a[n++] = d; }
    return fed_call(c, "PROV.IMPACT", n, a, NULL);
}

/* ── Operational admin ──────────────────────────────────────────────── */

qihse_ctrl_reply_t* qihse_ctrl_snapshot_create(qihse_controller_t* c,
                                                const char* kind, uint64_t max_generation,
                                                uint64_t wal_offset, const char* key_id) {
    char g[24], w[24];
    u64_str(max_generation, g);
    u64_str(wal_offset, w);
    const char* a[4];
    size_t n = 0;
    a[n++] = kind; a[n++] = g; a[n++] = w;
    if (key_id) a[n++] = key_id;
    return fed_call(c, "SNAPSHOT.CREATE", n, a, NULL);
}

qihse_ctrl_reply_t* qihse_ctrl_snapshot_show(qihse_controller_t* c, const char* snapshot_id) {
    const char* a[] = { snapshot_id };
    return fed_call(c, "SNAPSHOT.SHOW", 1, a, NULL);
}

qihse_ctrl_reply_t* qihse_ctrl_snapshot_verify(qihse_controller_t* c, const char* snapshot_id) {
    const char* a[] = { snapshot_id };
    return fed_call(c, "SNAPSHOT.VERIFY", 1, a, NULL);
}

qihse_ctrl_reply_t* qihse_ctrl_schema_status(qihse_controller_t* c,
                                              const char* schema_id, const char* version) {
    const char* a[] = { schema_id, version };
    return fed_call(c, "SCHEMA.STATUS", 2, a, NULL);
}

qihse_ctrl_reply_t* qihse_ctrl_schema_check(qihse_controller_t* c,
                                             const char* writer_version, const char* min_reader,
                                             const char* required_hex, const char* optional_hex) {
    const char* a[] = { writer_version, min_reader, required_hex, optional_hex };
    return fed_call(c, "SCHEMA.CHECK", 4, a, NULL);
}

qihse_ctrl_reply_t* qihse_ctrl_schema_migrate(qihse_controller_t* c,
                                               const char* schema_id,
                                               const char* from_version, const char* to_version,
                                               bool resumable) {
    const char* a[] = { schema_id, from_version, to_version, resumable ? "1" : "0" };
    return fed_call(c, "SCHEMA.MIGRATE", 4, a, NULL);
}

qihse_ctrl_reply_t* qihse_ctrl_schema_progress(qihse_controller_t* c,
                                                const char* schema_id, const char* version,
                                                uint64_t completed, uint64_t total) {
    char cd[24], td[24];
    u64_str(completed, cd);
    u64_str(total, td);
    const char* a[] = { schema_id, version, cd, td };
    return fed_call(c, "SCHEMA.PROGRESS", 4, a, NULL);
}

qihse_ctrl_reply_t* qihse_ctrl_security_audit(qihse_controller_t* c,
                                               const char* service, const char* version) {
    const char* a[2];
    size_t n = 0;
    if (service) a[n++] = service;
    if (version) a[n++] = version;
    return fed_call(c, "SECURITY.AUDIT", n, a, NULL);
}

qihse_ctrl_reply_t* qihse_ctrl_security_observe(qihse_controller_t* c) {
    return fed_call(c, "SECURITY.OBSERVE", 0, NULL, NULL);
}

qihse_ctrl_reply_t* qihse_ctrl_security_ifaces(qihse_controller_t* c) {
    return fed_call(c, "SECURITY.IFACES", 0, NULL, NULL);
}

qihse_ctrl_reply_t* qihse_ctrl_security_profile_get(qihse_controller_t* c,
                                                     const char* service, const char* version) {
    const char* a[] = { service, version };
    return fed_call(c, "SECURITY.PROFILE.GET", 2, a, NULL);
}

qihse_ctrl_reply_t* qihse_ctrl_security_net_get(qihse_controller_t* c,
                                                 const char* service, const char* version) {
    const char* a[] = { service, version };
    return fed_call(c, "SECURITY.NET.GET", 2, a, NULL);
}
