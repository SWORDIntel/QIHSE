#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>
#include <stddef.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "qihse_auth.h"
#include "core/qihse_auth_internal.h"
#include "qihse_pqc_crypto.h"
#include "qihse_qkp.h"
#include "qihse_resp_wire.h"
#include "qihse_resp_engine.h"
#include "qihse_cluster_failover.h"

/* Freeze the pre-peer-list public layout: adding peers must not grow config. */
typedef struct {
    const char *dsa_key_path, *kem_key_path, *kem_pub_path;
    const char *const *trusted_pubs;
    size_t trusted_count;
    const char *node_id;
    bool require;
    const char *replication_peer_node_id, *replication_peer_dsa_pub_path;
    const char *admin_peer_node_id, *admin_peer_dsa_pub_path;
    const char *const *migration_peer_node_ids, *const *migration_peer_dsa_pub_paths;
    size_t migration_peer_count;
} legacy_qkp_config_t;
_Static_assert(sizeof(qihse_qkp_config_t) == sizeof(legacy_qkp_config_t), "old QKP ABI");
_Static_assert(offsetof(qihse_qkp_config_t, migration_peer_count) ==
               offsetof(legacy_qkp_config_t, migration_peer_count), "old QKP tail ABI");

#define PASSWORD "MultiPeerOperator123!"
#define SERVICE_PASSWORD "MultiPeerService123!"
#define PAYLOAD "MULTI-PEER-CLASS5-SCI9-PROTECTED"
#define KEY "multi:protected"
#define GLOB "multi:*"

typedef struct {
    char dir[512], pub[640], dsa[640], kem[640], kem_pub[640];
} identity_t;

static void identity(identity_t *id, const char *root, const char *name) {
    assert(snprintf(id->dir, sizeof(id->dir), "%s/%s", root, name) > 0);
    assert(mkdir(id->dir, 0700) == 0);
    assert(qihse_pqc_keygen(id->dir));
    snprintf(id->pub, sizeof(id->pub), "%s/qihse_dsa_pub.pem", id->dir);
    snprintf(id->dsa, sizeof(id->dsa), "%s/qihse_dsa_key.pem", id->dir);
    snprintf(id->kem, sizeof(id->kem), "%s/qihse_kem_key.pem", id->dir);
    snprintf(id->kem_pub, sizeof(id->kem_pub), "%s/qihse_kem_pub.pem", id->dir);
}

typedef struct {
    int fd;
    const qihse_qkp_config_t *cfg;
    const qihse_qkp_replication_peer_t *peers;
    size_t count;
    qihse_qkp_session_t *session;
    qihse_qkp_result_t result;
} handshake_t;

static void *negotiate(void *opaque) {
    handshake_t *h = opaque;
    h->result = qihse_qkp_server_negotiate_with_replication_peers(
        h->fd, h->cfg, h->peers, h->count, &h->session);
    return NULL;
}

static void check_session(const qihse_qkp_config_t *cfg,
    const qihse_qkp_replication_peer_t *peers, size_t count,
    const identity_t *source, const identity_t *client,
    const char *node, bool expected) {
    int pair[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
    struct timeval timeout = {10, 0};
    for (size_t i = 0u; i < 2u; i++) {
        assert(setsockopt(pair[i], SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0);
        assert(setsockopt(pair[i], SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) == 0);
    }
    handshake_t h = {.fd = pair[0], .cfg = cfg, .peers = peers, .count = count};
    pthread_t thread;
    assert(pthread_create(&thread, NULL, negotiate, &h) == 0);
    const char *trust[] = {source->pub};
    qihse_qkp_config_t client_cfg = {.dsa_key_path = client->dsa,
        .trusted_pubs = trust, .trusted_count = 1u, .node_id = node, .require = true};
    qihse_qkp_session_t *session = NULL;
    assert(qihse_qkp_client_negotiate(pair[1], &client_cfg, &session) == QIHSE_QKP_SECURE);
    assert(pthread_join(thread, NULL) == 0);
    assert(h.result == QIHSE_QKP_SECURE && h.session);
    assert(qihse_qkp_session_is_replication_peer_any(h.session, peers, count) == expected);
    assert(!qihse_qkp_session_is_replication_peer_any(session, peers, count));
    assert(!qihse_qkp_session_is_replication_peer_any(NULL, peers, count));
    assert(!qihse_qkp_session_is_replication_peer_any(h.session, NULL, 1u));
    assert(!qihse_qkp_session_is_replication_peer_any(h.session, peers,
        QIHSE_QKP_MAX_REPLICATION_PEERS + 1u));
    qihse_qkp_session_free(session); qihse_qkp_session_free(h.session);
    close(pair[0]); close(pair[1]);
}

typedef struct {
    qihse_resp_server_t *server;
    int server_fd, fd;
    pthread_t thread;
    qihse_qkp_session_t *session;
    unsigned char input[QIHSE_QKP_MAX_PAYLOAD];
    size_t available, position;
} real_client_t;

static void *serve_client(void *opaque) {
    real_client_t *client = opaque;
    assert(qihse_resp_server_handle_client_fd(client->server, client->server_fd));
    return NULL;
}

/* Use the actual native engine accept seam, not a mocked wire/auth server.
 * AF_UNIX keeps this CI test independent of host loopback firewall rules. */
static real_client_t *connect_peer(qihse_resp_server_t *server,
    const identity_t *client, const identity_t *source, const char *node) {
    int pair[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
    struct timeval timeout = {10, 0};
    for (size_t i = 0u; i < 2u; i++) {
        assert(setsockopt(pair[i], SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0);
        assert(setsockopt(pair[i], SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) == 0);
    }
    real_client_t *out = calloc(1u, sizeof(*out));
    assert(out);
    out->server = server; out->server_fd = pair[0]; out->fd = pair[1];
    assert(pthread_create(&out->thread, NULL, serve_client, out) == 0);
    const char *trust[] = {source->pub};
    qihse_qkp_config_t cfg = {.dsa_key_path = client->dsa, .trusted_pubs = trust,
        .trusted_count = 1u, .node_id = node, .require = true};
    assert(qihse_qkp_client_negotiate(out->fd, &cfg, &out->session) == QIHSE_QKP_SECURE);
    return out;
}

static void close_peer(real_client_t *client) {
    shutdown(client->fd, SHUT_RDWR); close(client->fd);
    assert(pthread_join(client->thread, NULL) == 0);
    qihse_qkp_session_free(client->session);
    free(client);
}

static unsigned char next_byte(real_client_t *client) {
    if (client->position == client->available) {
        ssize_t n = qihse_qkp_recv_sealed(client->session, client->fd,
                                         client->input, sizeof(client->input));
        assert(n > 0);
        client->available = (size_t)n; client->position = 0u;
    }
    return client->input[client->position++];
}

typedef struct { char *bytes; size_t length, capacity; } reply_t;
static void append_byte(reply_t *reply, unsigned char c) {
    assert(reply->length < 1024u * 1024u);
    if (reply->length + 2u > reply->capacity) {
        reply->capacity = reply->capacity ? reply->capacity * 2u : 256u;
        reply->bytes = realloc(reply->bytes, reply->capacity);
        assert(reply->bytes);
    }
    reply->bytes[reply->length++] = (char)c;
    reply->bytes[reply->length] = '\0';
}

static void read_value(real_client_t *client, reply_t *reply, unsigned depth) {
    assert(depth < 8u);
    unsigned char type = next_byte(client);
    assert(type == '*' || type == '$' || type == '+' || type == '-' || type == ':');
    append_byte(reply, type);
    char line[512]; size_t n = 0u;
    do {
        assert(n + 1u < sizeof(line));
        line[n] = (char)next_byte(client);
        append_byte(reply, (unsigned char)line[n]);
    } while (line[n++] != '\n');
    assert(n >= 2u && line[n - 2u] == '\r');
    line[n] = '\0';
    long count = strtol(line, NULL, 10);
    if (type == '*') {
        assert(count >= -1 && count <= 128);
        for (long i = 0; i < count; i++) read_value(client, reply, depth + 1u);
    } else if (type == '$' && count >= 0) {
        assert(count <= 524288);
        for (long i = 0; i < count; i++) append_byte(reply, next_byte(client));
        assert(next_byte(client) == '\r'); append_byte(reply, '\r');
        assert(next_byte(client) == '\n'); append_byte(reply, '\n');
    }
}

static char *command(real_client_t *client, size_t argc,
                      const char *const *argv, size_t *length) {
    char request[4096];
    size_t used = (size_t)snprintf(request, sizeof(request), "*%zu\r\n", argc);
    for (size_t i = 0u; i < argc; i++) {
        int n = snprintf(request + used, sizeof(request) - used,
                         "$%zu\r\n%s\r\n", strlen(argv[i]), argv[i]);
        assert(n > 0 && (size_t)n < sizeof(request) - used);
        used += (size_t)n;
    }
    assert(qihse_qkp_send_sealed(client->session, client->fd, request, used));
    reply_t reply = {0};
    read_value(client, &reply, 0u);
    if (length) *length = reply.length;
    return reply.bytes;
}

static void denied(real_client_t *client, size_t argc,
                   const char *const *argv) {
    size_t n;
    char *reply = command(client, argc, argv, &n);
    if (reply[0] != '-') fprintf(stderr, "expected denial for %s: %.*s\n", argv[0], (int)n, reply);
    assert(reply[0] == '-');
    assert(!memmem(reply, n, PAYLOAD, strlen(PAYLOAD)));
    free(reply);
}

static void deny_data_plane(real_client_t *client) {
    const char *begin[] = {"REPL.SNAPSHOT.BEGIN", GLOB};
    const char *read[] = {"REPL.SNAPSHOT.READ", "0", "524288"};
    const char *end[] = {"REPL.SNAPSHOT.END"};
    const char *delta[] = {"REPL.DELTA", GLOB, "0", "8"};
    const char *cursor[] = {"REPL.CURSOR", GLOB};
    denied(client, 2u, begin);
    denied(client, 3u, read);
    denied(client, 1u, end);
    denied(client, 4u, delta);
    denied(client, 2u, cursor);
}

static void deny_protected_data(real_client_t *client) {
    const char *begin[] = {"REPL.SNAPSHOT.BEGIN", GLOB};
    const char *read[] = {"REPL.SNAPSHOT.READ", "0", "524288"};
    const char *delta[] = {"REPL.DELTA", GLOB, "0", "8"};
    const char *end[] = {"REPL.SNAPSHOT.END"};
    const char *cursor[] = {"REPL.CURSOR", GLOB};
    denied(client, 2u, begin);
    denied(client, 3u, read);
    size_t n;
    char *reply = command(client, 4u, delta, &n);
    /* The incremental exporter filters unreadable records: only an empty
     * result with no cursor advancement is valid for this fixture. */
    assert(strcmp(reply, "*2\r\n$1\r\n0\r\n$1\r\n0\r\n") == 0);
    assert(!memmem(reply, n, PAYLOAD, strlen(PAYLOAD)));
    free(reply);
    /* An authenticated low service may clean its own session and inspect
     * its own cursor; neither operation reads protected records. */
    reply = command(client, 1u, end, NULL);
    assert(strcmp(reply, "+OK\r\n") == 0);
    free(reply);
    reply = command(client, 2u, cursor, &n);
    assert(reply[0] == '$' || reply[0] == '-');
    assert(!memmem(reply, n, PAYLOAD, strlen(PAYLOAD)));
    free(reply);
}

static void auth_root(real_client_t *client) {
    const char *auth[] = {"AUTH", "GODMODE_OP", PASSWORD};
    char *reply = command(client, 3u, auth, NULL);
    assert(strcmp(reply, "+OK\r\n") == 0);
    free(reply);
}

static void peer_data(real_client_t *client) {
    const char *begin[] = {"REPL.SNAPSHOT.BEGIN", GLOB};
    const char *read[] = {"REPL.SNAPSHOT.READ", "0", "524288"};
    const char *end[] = {"REPL.SNAPSHOT.END"};
    const char *delta[] = {"REPL.DELTA", GLOB, "0", "8"};
    size_t n;
    char *reply = command(client, 2u, begin, &n);
    if (reply[0] != '*') fprintf(stderr, "snapshot: %.*s\n", (int)n, reply);
    assert(reply[0] == '*');
    free(reply);
    reply = command(client, 3u, read, &n);
    assert(reply[0] == '$' && memmem(reply, n, PAYLOAD, strlen(PAYLOAD)));
    free(reply);
    reply = command(client, 1u, end, NULL);
    assert(strcmp(reply, "+OK\r\n") == 0);
    free(reply);
    reply = command(client, 4u, delta, &n);
    assert(reply[0] == '*' && memmem(reply, n, PAYLOAD, strlen(PAYLOAD)));
    /* DELTA's class and SCI fields must survive the new peer path. */
    assert(memmem(reply, n, "$1\r\n5\r\n$1\r\n9\r\n", 14u));
    free(reply);
    const char *get[] = {"GET", KEY};
    const char *set[] = {"SET", "multi:forged", "forged"};
    const char *asking[] = {"ASKING"};
    const char *users[] = {"USER", "LIST"};
    const char *auth[] = {"AUTH", "GODMODE_OP", PASSWORD};
    const char *migration[] = {"CLUSTER", "MOVESLOTS", "1", "127.0.0.1", "1"};
    const char *status[] = {"REPL.STATUS"};
    const char *resume[] = {"CLUSTER", "FAILOVER.RESUME"};
    const char *failover[] = {"CLUSTER", "FAILOVER", "TAKEOVER"};
    denied(client, 2u, resume);
    reply = command(client, 3u, failover, NULL);
    assert(strcmp(reply, "-NOPERM command is outside the authenticated service capability\r\n") == 0);
    free(reply);
    denied(client, 2u, get);
    denied(client, 3u, set);
    denied(client, 1u, asking);
    denied(client, 2u, users);
    denied(client, 3u, auth);
    denied(client, 5u, migration);
    denied(client, 1u, status);
}

static int held_failback(void *user, uint16_t first, uint16_t last,
                         uint16_t target, char *err, size_t cap) {
    (void)first; (void)last; (void)target; (void)err; (void)cap;
    __atomic_add_fetch((unsigned *)user, 1u, __ATOMIC_RELEASE);
    return 0;
}

static void startup_coordinator_hold(void) {
    qihse_cluster_topology_t *topology = qihse_cluster_topology_create();
    assert(topology);
    qihse_cluster_node_t node = {0};
    node.role = QIHSE_CLUSTER_NODE_PRIMARY;
    strcpy(node.host, "127.0.0.1");
    node.port = 7100u;
    node.bus_port = 17100u;
    node.healthy = true;
    node.primary_index = QIHSE_CLUSTER_NODE_NONE;
    uint16_t old, local, owner;
    qihse_cluster_node_id_from_seed("held-old", 8u, node.id);
    assert(qihse_cluster_topology_upsert_node(topology, &node, &old));
    node.port++;
    node.bus_port++;
    qihse_cluster_node_id_from_seed("held-local", 10u, node.id);
    assert(qihse_cluster_topology_upsert_node(topology, &node, &local));
    assert(qihse_cluster_topology_assign_range(topology, 0u, 99u, old));
    unsigned calls = 0u;
    qihse_cluster_failover_config_t cfg = {0};
    cfg.topology = topology;
    cfg.local_node_index = local;
    cfg.failback_fn = held_failback;
    cfg.failback_user_data = &calls;
    cfg.failback_stable_ms = 1u;
    cfg.failback_poll_ms = 20u;
    qihse_cluster_failover_t *fo = qihse_cluster_failover_create_paused(&cfg);
    assert(fo && qihse_cluster_failover_is_paused(fo));
    assert(!qihse_cluster_failover_promote(fo, old, local));
    qihse_cluster_failover_on_fail_cb(topology, old, fo);
    assert(qihse_cluster_failover_handle(fo, old) == QIHSE_CLUSTER_NODE_NONE);
    assert(qihse_cluster_failover_events(fo) == 0u);
    assert(qihse_cluster_topology_get_slot(topology, 0u, &owner, NULL, NULL));
    assert(owner == old);
    /* Ownership gossip is outside this hold. Its debt must survive release. */
    assert(qihse_cluster_topology_assign_range(topology, 0u, 99u, local));
    qihse_cluster_failover_on_takeover_cb(topology, old, 0u, 99u, fo);
    usleep(100000u);
    assert(__atomic_load_n(&calls, __ATOMIC_ACQUIRE) == 0u);
    assert(qihse_cluster_failover_pending_failbacks(fo) == 1u);
    assert(qihse_cluster_failover_resume(fo));
    assert(!qihse_cluster_failover_resume(fo));
    assert(!qihse_cluster_failover_pause_startup(fo));
    for (unsigned i = 0; i < 100u &&
         qihse_cluster_failover_pending_failbacks(fo); i++) usleep(20000u);
    assert(qihse_cluster_failover_pending_failbacks(fo) == 0u);
    assert(__atomic_load_n(&calls, __ATOMIC_ACQUIRE) == 1u);
    assert(qihse_cluster_failover_promote(fo, old, local));
    qihse_cluster_failover_destroy(fo);
    qihse_cluster_topology_destroy(topology);
}

static void held_wire_manual_failover(const qihse_resp_server_config_t *base,
    qihse_user_t *op, const identity_t *source, const identity_t *client) {
    qihse_cluster_topology_t *topology = qihse_cluster_topology_create();
    assert(topology);
    qihse_cluster_node_t node = {0};
    node.role = QIHSE_CLUSTER_NODE_PRIMARY;
    node.primary_index = QIHSE_CLUSTER_NODE_NONE;
    node.healthy = true;
    strcpy(node.host, "127.0.0.1");
    node.port = 7100u;
    node.bus_port = 17100u;
    uint16_t local, primary;
    qihse_cluster_node_id_from_seed("held-wire-local", 15u, node.id);
    assert(qihse_cluster_topology_upsert_node(topology, &node, &local));
    node.port++;
    node.bus_port++;
    qihse_cluster_node_id_from_seed("held-wire-peer", 14u, node.id);
    assert(qihse_cluster_topology_upsert_node(topology, &node, &primary));
    assert(qihse_cluster_topology_assign_range(topology, 0u, 99u, local));
    assert(qihse_cluster_topology_assign_range(topology, 100u,
        QIHSE_CLUSTER_SLOT_COUNT - 1u, primary));
    qihse_resp_server_config_t cfg = *base;
    cfg.topology = topology;
    cfg.local_node_index = local;
    qihse_resp_server_t *server = qihse_resp_server_create(&cfg);
    assert(server && qihse_resp_server_start_failover_paused(server, op));
    real_client_t *wire = connect_peer(server, client, source, "unknown");
    auth_root(wire);
    const char *failover[] = {"CLUSTER", "FAILOVER", "TAKEOVER"};
    char *reply = command(wire, 3u, failover, NULL);
    assert(strcmp(reply, "-ERR failover is paused during startup\r\n") == 0);
    free(reply);
    qihse_cluster_node_t current;
    assert(qihse_cluster_topology_get_node(topology, local, &current));
    assert(current.role == QIHSE_CLUSTER_NODE_PRIMARY);
    const char *replicate[] = {"CLUSTER", "REPLICATE", node.id};
    reply = command(wire, 3u, replicate, NULL);
    assert(strcmp(reply, "+OK\r\n") == 0);
    free(reply);
    /* Even an authenticated root Operator cannot bypass the coordinator by
     * first changing the held primary into a replica. Check canonical state. */
    const char *options[] = {NULL, "FORCE", "TAKEOVER"};
    for (size_t i = 0u; i < 3u; i++) {
        failover[2] = options[i];
        reply = command(wire, i ? 3u : 2u, failover, NULL);
        assert(strcmp(reply, "-ERR failover is paused during startup\r\n") == 0);
        free(reply);
        assert(qihse_cluster_topology_get_node(topology, local, &current));
        assert(current.role == QIHSE_CLUSTER_NODE_REPLICA &&
               current.primary_index == primary);
        assert(qihse_cluster_topology_get_node(topology, primary, &current));
        assert(current.role == QIHSE_CLUSTER_NODE_PRIMARY);
        for (uint16_t slot = 0u; slot < QIHSE_CLUSTER_SLOT_COUNT; slot++) {
            uint16_t owner;
            assert(qihse_cluster_topology_get_slot(topology, slot, &owner, NULL, NULL));
            assert(owner == (slot < 100u ? local : primary));
        }
    }
    const char *resume[] = {"CLUSTER", "FAILOVER.RESUME"};
    reply = command(wire, 2u, resume, NULL);
    assert(strcmp(reply, "+RESUMED\r\n") == 0);
    free(reply);
    reply = command(wire, 3u, failover, NULL);
    assert(strcmp(reply, "+OK\r\n") == 0);
    free(reply);
    assert(qihse_cluster_topology_get_node(topology, local, &current));
    assert(current.role == QIHSE_CLUSTER_NODE_PRIMARY &&
           current.primary_index == QIHSE_CLUSTER_NODE_NONE);
    for (uint16_t slot = 0u; slot < QIHSE_CLUSTER_SLOT_COUNT; slot++) {
        uint16_t owner;
        assert(qihse_cluster_topology_get_slot(topology, slot, &owner, NULL, NULL));
        assert(owner == local);
    }
    close_peer(wire);
    qihse_resp_server_destroy(server);
    /* A server without a coordinator retains the compatibility behavior. */
    cfg.enable_failover = false;
    server = qihse_resp_server_create(&cfg);
    assert(server);
    wire = connect_peer(server, client, source, "unknown");
    auth_root(wire);
    reply = command(wire, 3u, replicate, NULL);
    assert(strcmp(reply, "+OK\r\n") == 0);
    free(reply);
    reply = command(wire, 3u, failover, NULL);
    assert(strcmp(reply, "+OK\r\n") == 0);
    free(reply);
    assert(qihse_cluster_topology_get_node(topology, local, &current));
    assert(current.role == QIHSE_CLUSTER_NODE_PRIMARY);
    close_peer(wire);
    qihse_resp_server_destroy(server);
    qihse_cluster_topology_destroy(topology);
}

static void embedded_execute_closes_startup(const qihse_resp_server_config_t *base,
                                           qihse_user_t *op) {
    qihse_resp_server_config_t cfg = *base;
    cfg.enable_uwp_bridge = true;
    qihse_resp_server_t *server = qihse_resp_server_create(&cfg);
    assert(server);
    qihse_resp_arg_t ping = {(const uint8_t *)"PING", 4u};
    uint8_t *reply = NULL;
    size_t length = 0u;
    /* Invalid invocations do not enter a session or consume startup. */
    assert(!qihse_resp_server_execute(server, NULL, 1u, &ping, &reply, &length));
    assert(qihse_resp_server_start_failover_paused(server, op));
    qihse_resp_server_destroy(server);
    server = qihse_resp_server_create(&cfg);
    assert(server);
    qihse_resp_arg_t get[] = {
        {(const uint8_t *)"GET", 3u}, {(const uint8_t *)KEY, sizeof(KEY) - 1u}
    };
    assert(qihse_resp_server_execute(server, op, 2u, get, &reply, &length));
    assert(reply[0] == '$' && memmem(reply, length, PAYLOAD, strlen(PAYLOAD)));
    free(reply);
    assert(!qihse_resp_server_start_failover_paused(server, op));
    qihse_resp_server_stop(server);
    assert(!qihse_resp_server_start_failover_paused(server, op));
    assert(!qihse_resp_server_execute(server, op, 1u, &ping, &reply, &length));
    qihse_resp_server_destroy(server);
    /* Admission is permanent even when the invoked command returns an error. */
    server = qihse_resp_server_create(&cfg);
    assert(server);
    qihse_resp_arg_t unknown = {(const uint8_t *)"NOT.A.COMMAND", 13u};
    assert(qihse_resp_server_execute(server, op, 1u, &unknown, &reply, &length));
    assert(length > 0u && reply[0] == '-');
    free(reply);
    assert(!qihse_resp_server_start_failover_paused(server, op));
    qihse_resp_server_destroy(server);
}

int main(void) {
    startup_coordinator_hold();
    char root[] = "build/replication-multi-peer-XXXXXX";
    assert(mkdtemp(root));
    char data[512];
    snprintf(data, sizeof(data), "%s/data", root);
    assert(mkdir(data, 0700) == 0);
    assert(setenv("QIHSE_DATA_DIR", data, 1) == 0);
    assert(setenv("QIHSE_FIPS_MODE", "disabled", 1) == 0);
    assert(qihse_pqc_init_providers() >= 0);
    identity_t source, first, second, wrong;
    identity(&source, root, "source");
    identity(&first, root, "first");
    identity(&second, root, "second");
    identity(&wrong, root, "wrong");
    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator(PASSWORD));
    qihse_user_t *op = qihse_auth_authenticate_id(0u, PASSWORD);
    assert(op && qihse_user_get_role(op) == QIHSE_ROLE_OPERATOR);
    qihse_user_t *service = qihse_auth_create_user(op, 71u, QIHSE_ROLE_GUEST,
        5u, 9u, SERVICE_PASSWORD, false);
    qihse_user_t *low = qihse_auth_create_user(op, 72u, QIHSE_ROLE_GUEST,
        0u, 0u, "MultiPeerLow123!", false);
    qihse_user_t *tenant_op = qihse_auth_create_tenant_user(op, 7u, 73u,
        QIHSE_ROLE_OPERATOR, 0u, 0u, "MultiPeerTenant123!", false);
    assert(service && low && tenant_op);
    assert(qihse_auth_authenticate_id(71u, SERVICE_PASSWORD) == service);
    assert(qihse_auth_authenticate_id(72u, "MultiPeerLow123!") == low);
    assert(qihse_auth_authenticate_id(73u, "MultiPeerTenant123!") == tenant_op);
    assert(qihse_user_get_role(service) != QIHSE_ROLE_OPERATOR);
    qihse_kv_store_t *store = qihse_kv_store_create_user(op);
    assert(store && qihse_kv_set_user(store, KEY, PAYLOAD, 5u, 9u, op));
    const char *trusted[] = {first.pub, second.pub, wrong.pub};
    const char *globs[] = {GLOB};
    char first_alias[1200];
    assert(snprintf(first_alias, sizeof(first_alias), "%s-alias", first.pub) > 0);
    assert(link(first.pub, first_alias) == 0);
    /* Ambiguous identities fail before transport negotiation. */
    qihse_qkp_config_t validation;
    memset(&validation, 0, sizeof(validation));
    qihse_qkp_replication_peer_t conflicting[] = {{"same-id", first.pub}, {"same-id", second.pub}};
    int validation_fd[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, validation_fd) == 0);
    assert(write(validation_fd[1], "x", 1) == 1);
    qihse_qkp_session_t *rejected = (qihse_qkp_session_t*)(uintptr_t)1;
    assert(qihse_qkp_server_negotiate_with_replication_peers(validation_fd[0], &validation,
           conflicting, 2, &rejected) == QIHSE_QKP_REJECTED && rejected == NULL);
    validation.replication_peer_node_id = "same-id";
    validation.replication_peer_dsa_pub_path = first.pub;
    assert(qihse_qkp_server_negotiate_with_replication_peers(validation_fd[0], &validation,
           &conflicting[1], 1, &rejected) == QIHSE_QKP_REJECTED && rejected == NULL);
    assert(qihse_qkp_server_negotiate_with_replication_peers(validation_fd[0], &validation,
           conflicting, 1, &rejected) == QIHSE_QKP_CLEARTEXT && rejected == NULL);
    qihse_qkp_replication_peer_t aliased[] = {{"same-id", first.pub}, {"same-id", first_alias}};
    assert(qihse_qkp_server_negotiate_with_replication_peers(validation_fd[0], &validation,
           &aliased[1], 1, &rejected) == QIHSE_QKP_CLEARTEXT && rejected == NULL);
    assert(qihse_qkp_server_negotiate_with_replication_peers(validation_fd[0], &validation,
           aliased, 2, &rejected) == QIHSE_QKP_CLEARTEXT && rejected == NULL);
    close(validation_fd[0]); close(validation_fd[1]);

    qihse_resp_server_config_t cfg;
    qihse_resp_server_config_init(&cfg);
    cfg.store = store;
    cfg.port = 0u;
    cfg.auth_required = true;
    cfg.enable_failover = true;
    cfg.pqc.require = true;
    cfg.pqc.node_id = "source";
    cfg.pqc.dsa_key_path = source.dsa;
    cfg.pqc.kem_key_path = source.kem;
    cfg.pqc.kem_pub_path = source.kem_pub;
    cfg.pqc.trusted_pubs = trusted;
    cfg.pqc.trusted_count = 3u;
    cfg.pqc.replication_peer_node_id = "first";
    cfg.pqc.replication_peer_dsa_pub_path = first.pub;
    cfg.replication_service_principal = service;
    cfg.replicate_globs = globs;
    cfg.replicate_glob_count = 1u;
    held_wire_manual_failover(&cfg, op, &source, &second);
    embedded_execute_closes_startup(&cfg, op);
    const qihse_qkp_replication_peer_t peers[] = {
        {"first", first.pub}, {"second", second.pub}
    };
    check_session(&cfg.pqc, peers, 2u, &source, &first, "first", true);
    check_session(&cfg.pqc, peers, 2u, &source, &second, "second", true);
    check_session(&cfg.pqc, peers, 2u, &source, &second, "unknown", false);
    check_session(&cfg.pqc, peers, 2u, &source, &wrong, "second", false);
    qihse_resp_server_t *server = qihse_resp_server_create(&cfg);
    assert(server);
    /* Pointer identity and current shadow authority, not caller-owned fields,
     * must authorize this pre-listen ownership hold. */
    qihse_user_t forged = *op;
    qihse_user_t *revoked = qihse_auth_create_user(op, 74u, QIHSE_ROLE_OPERATOR,
        0u, 0u, "MultiPeerRevoked123!", false);
    assert(revoked);
    assert(qihse_auth_authenticate_id(74u, "MultiPeerRevoked123!") == revoked);
    assert(qihse_auth_destroy_user(op, 74u));
    assert(!qihse_resp_server_start_failover_paused(NULL, op));
    assert(!qihse_resp_server_start_failover_paused(server, NULL));
    assert(!qihse_resp_server_start_failover_paused(server, &forged));
    assert(!qihse_resp_server_start_failover_paused(server, revoked));
    assert(!qihse_resp_server_start_failover_paused(server, tenant_op));
    assert(!qihse_resp_server_start_failover_paused(server, low));
    assert(qihse_resp_server_start_failover_paused(server, op));
    assert(!qihse_resp_server_add_replication_peer(server, "second", second.pub, NULL));
    assert(!qihse_resp_server_add_replication_peer(server, "second", second.pub, low));
    assert(!qihse_resp_server_add_replication_peer(server, "second", second.pub, tenant_op));
    assert(!qihse_resp_server_add_replication_peer(server, "", second.pub, op));
    assert(!qihse_resp_server_add_replication_peer(server, "second", "missing-key.pem", op));
    char overlong[66]; memset(overlong, 'x', sizeof(overlong)); overlong[65] = '\0';
    assert(!qihse_resp_server_add_replication_peer(server, overlong, second.pub, op));
    assert(qihse_resp_server_add_replication_peer(server, "first", first_alias, op));
    assert(qihse_resp_server_add_replication_peer(server, "second", second.pub, op));
    assert(!qihse_resp_server_add_replication_peer(server, "second", wrong.pub, op));
    assert(!qihse_resp_server_add_replication_peer(server, "first", wrong.pub, op));
    /* The registry is bounded even when each individual pin is valid. */
    size_t added = 2u;
    for (size_t i = 0u; i <= QIHSE_QKP_MAX_REPLICATION_PEERS; i++) {
        char node[32]; snprintf(node, sizeof(node), "bounded-%zu", i);
        if (!qihse_resp_server_add_replication_peer(server, node, second.pub, op)) break;
        added++;
    }
    assert(added == QIHSE_QKP_MAX_REPLICATION_PEERS);
    assert(!qihse_resp_server_add_replication_peer(server, "overflow", second.pub, op));
    assert(qihse_resp_server_start(server));
    assert(!qihse_resp_server_start_failover_paused(server, op));
    real_client_t *a = connect_peer(server, &first, &source, "first");
    real_client_t *b = connect_peer(server, &second, &source, "second");
    peer_data(a);
    peer_data(b);
    assert(qihse_user_get_id(service) == 71u);
    assert(qihse_user_get_role(service) == QIHSE_ROLE_GUEST);
    assert(qihse_user_get_classification(service) == 5u);
    assert(qihse_user_get_sci(service) == 9u);
    uint64_t first_cursor = 0u, second_cursor = 0u;
    assert(qihse_kv_replica_cursor_get(store, "first", GLOB, op, &first_cursor));
    assert(qihse_kv_replica_cursor_get(store, "second", GLOB, op, &second_cursor));
    assert(first_cursor > 0u && first_cursor == qihse_kv_change_seq(store));
    assert(second_cursor == first_cursor);
    /* A live legacy handle is mutated in place on downgrade. Its old
     * serialized snapshot must not remain readable, even after restoration. */
    const char *begin[] = {"REPL.SNAPSHOT.BEGIN", GLOB};
    const char *read[] = {"REPL.SNAPSHOT.READ", "0", "524288"};
    char *snapshot_reply = command(a, 2u, begin, NULL);
    assert(snapshot_reply[0] == '*'); free(snapshot_reply);
    assert(qihse_auth_modify_user(op, 71u, NULL, NULL, -1, -1, 0, 0));
    assert(qihse_user_get_classification(service) == 0u);
    assert(qihse_user_get_sci(service) == 0u);
    denied(a, 3u, read);
    denied(a, 2u, begin);
    assert(qihse_auth_modify_user(op, 71u, NULL, NULL, -1, -1, 5, 9));
    denied(a, 3u, read);
    peer_data(a);
    real_client_t *unknown = connect_peer(server, &second, &source, "unknown");
    deny_data_plane(unknown);
    const char *resume[] = {"CLUSTER", "FAILOVER.RESUME"};
    denied(unknown, 2u, resume);
    const char *tenant_auth[] = {"AUTH", qihse_user_get_username(tenant_op), "MultiPeerTenant123!"};
    char *auth_reply = command(unknown, 3u, tenant_auth, NULL);
    assert(strcmp(auth_reply, "+OK\r\n") == 0); free(auth_reply);
    denied(unknown, 2u, resume);
    const char *low_auth[] = {"AUTH", qihse_user_get_username(low), "MultiPeerLow123!"};
    auth_reply = command(unknown, 3u, low_auth, NULL);
    assert(strcmp(auth_reply, "+OK\r\n") == 0); free(auth_reply);
    denied(unknown, 2u, resume);
    qihse_user_t *revoked_session = qihse_auth_create_user(op, 75u,
        QIHSE_ROLE_OPERATOR, 0u, 0u, "MultiPeerSession123!", false);
    assert(revoked_session);
    const char *session_auth[] = {"AUTH", qihse_user_get_username(revoked_session),
                                  "MultiPeerSession123!"};
    auth_reply = command(unknown, 3u, session_auth, NULL);
    assert(strcmp(auth_reply, "+OK\r\n") == 0); free(auth_reply);
    assert(qihse_auth_destroy_user(op, 75u));
    denied(unknown, 2u, resume);
    auth_root(unknown);
    auth_reply = command(unknown, 2u, resume, NULL);
    assert(strcmp(auth_reply, "+RESUMED\r\n") == 0); free(auth_reply);
    auth_reply = command(unknown, 2u, resume, NULL);
    assert(strcmp(auth_reply, "+ALREADY-RUNNING\r\n") == 0); free(auth_reply);
    deny_data_plane(unknown);
    const char *get[] = {"GET", KEY};
    char *reply = command(unknown, 2u, get, NULL);
    assert(strstr(reply, PAYLOAD)); free(reply);
    close_peer(unknown);
    unknown = connect_peer(server, &wrong, &source, "second");
    deny_data_plane(unknown);
    close_peer(unknown);
    const char *status[] = {"REPL.STATUS"};
    const char *metadata[] = {"INTROSPECTION", "RECORD.META", KEY};
    denied(a, 1u, status); denied(b, 1u, status);
    denied(a, 3u, metadata); denied(b, 3u, metadata);
    assert(qihse_auth_destroy_user(op, 71u));
    deny_data_plane(a);
    deny_data_plane(b);
    close_peer(a); close_peer(b);
    /* Exercise the real acknowledged write path, then read it immediately
     * from the same node before a cold store reopen. */
    real_client_t *writer = connect_peer(server, &first, &source, "unknown");
    auth_root(writer);
    const char *write_client[] = {"SET", "acknowledged", "durable-value"};
    char *write_reply = command(writer, 3u, write_client, NULL);
    assert(strcmp(write_reply, "+OK\r\n") == 0);
    free(write_reply);
    const char *read_client[] = {"GET", "acknowledged"};
    char *read_reply = command(writer, 2u, read_client, NULL);
    assert(strstr(read_reply, "durable-value"));
    free(read_reply);
    close_peer(writer);
    qihse_resp_server_stop(server);
    assert(!qihse_resp_server_start_failover_paused(server, op));
    qihse_resp_server_destroy(server);

    /* A valid configured low-clearance context is not a NULL-auth test. */
    cfg.replication_service_principal = low;
    server = qihse_resp_server_create(&cfg);
    assert(server);
    assert(qihse_resp_server_add_replication_peer(server, "first", first_alias, op));
    assert(qihse_resp_server_add_replication_peer(server, "second", second.pub, op));
    /* The accepted-fd embedding seam also permanently closes startup, even
     * when the server has not opened a listening socket yet. */
    a = connect_peer(server, &first, &source, "first");
    denied(a, 2u, resume);
    assert(!qihse_resp_server_start_failover_paused(server, op));
    close_peer(a);
    assert(qihse_resp_server_start(server));
    a = connect_peer(server, &first, &source, "first");
    b = connect_peer(server, &second, &source, "second");
    deny_protected_data(a); deny_protected_data(b);
    denied(a, 2u, get); denied(b, 2u, get);
    denied(a, 1u, status); denied(b, 1u, status);
    denied(a, 3u, metadata); denied(b, 3u, metadata);
    assert(qihse_kv_get_user(store, KEY, low) == NULL);
    qihse_kv_record_meta_t meta = {0};
    assert(!qihse_kv_meta_user(store, KEY, low, &meta));
    qihse_kv_replica_snapshot_t *snapshot = NULL;
    assert(qihse_kv_replica_snapshot_create(store, low, GLOB, &snapshot) == -2);
    assert(snapshot == NULL);
    assert(qihse_user_get_id(low) == 72u && qihse_user_get_role(low) == QIHSE_ROLE_GUEST);
    close_peer(a); close_peer(b);
    qihse_resp_server_stop(server); qihse_resp_server_destroy(server);
    /* A replication context cannot acquire release authority by being
     * configured as an Operator: server creation rejects that configuration. */
    cfg.replication_service_principal = op;
    assert(qihse_resp_server_create(&cfg) == NULL);
    qihse_kv_store_destroy(store);
    /* Cold reopen the configured store after the acknowledged wire write.
     * This catches replies issued before the durable record is recoverable. */
    store = qihse_kv_store_create_user(op);
    assert(store);
    char *durable = qihse_kv_get_user(store, "acknowledged", op);
    assert(durable && strcmp(durable, "durable-value") == 0);
    free(durable);
    qihse_kv_store_destroy(store);
    puts("replication multi-peer real QKP/source authorization: OK");
    return 0;
}
