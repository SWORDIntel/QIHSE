#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <assert.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include "qihse_auth.h"
#include "qihse_pqc_crypto.h"
#include "qihse_qkp.h"
#include "qihse_resp_wire.h"

static void write_command(qihse_qkp_session_t* s, int fd, const char* a,
                          const char* b, const char* c, const char* d) {
    const char* args[4] = {a, b, c, d};
    size_t argc = d ? 4u : (c ? 3u : (b ? 2u : 1u));
    char buf[1024];
    size_t used = (size_t)snprintf(buf, sizeof(buf), "*%zu\r\n", argc);
    for (size_t i = 0; i < argc; i++) {
        int n = snprintf(buf + used, sizeof(buf) - used, "$%zu\r\n%s\r\n",
                         strlen(args[i]), args[i]);
        assert(n > 0 && (size_t)n < sizeof(buf) - used);
        used += (size_t)n;
    }
    assert(qihse_qkp_send_sealed(s, fd, buf, used));
}

typedef struct { qihse_qkp_session_t* session; int fd; uint8_t data[QIHSE_QKP_MAX_PAYLOAD]; size_t len, pos; char* out; size_t out_len, out_cap; } reply_reader_t;
static int reply_getc(reply_reader_t* r) {
    if (r->pos == r->len) {
        struct pollfd pfd = {r->fd, POLLIN, 0};
        assert(poll(&pfd, 1, 10000) > 0);
        ssize_t n = qihse_qkp_recv_sealed(r->session, r->fd, r->data, sizeof(r->data));
        assert(n > 0); r->len = (size_t)n; r->pos = 0u;
    }
    return r->data[r->pos++];
}
static void reply_putc(reply_reader_t* r, int c) {
    if (r->out_len + 2u > r->out_cap) {
        r->out_cap = r->out_cap ? r->out_cap * 2u : 256u;
        r->out = realloc(r->out, r->out_cap); assert(r->out);
    }
    r->out[r->out_len++] = (char)c; r->out[r->out_len] = '\0';
}
static void reply_value(reply_reader_t* r, unsigned depth) {
    assert(depth < 8u);
    int type = reply_getc(r); reply_putc(r, type);
    char line[128]; size_t n = 0u;
    for (;;) {
        int c = reply_getc(r); reply_putc(r, c);
        assert(n + 1u < sizeof(line)); line[n++] = (char)c;
        if (c == '\n') break;
    }
    line[n] = '\0';
    long count = strtol(line, NULL, 10);
    if (type == '*') { assert(count >= 0 && count < 128); for (long i = 0; i < count; i++) reply_value(r, depth + 1u); }
    else if (type == '$' && count >= 0) { assert(count < 16 * 1024 * 1024); for (long i = 0; i < count + 2; i++) reply_putc(r, reply_getc(r)); }
}
static char* read_reply(qihse_qkp_session_t* s, int fd) {
    reply_reader_t r = {.session=s, .fd=fd};
    reply_value(&r, 0u);
    return r.out;
}

static int connect_local(uint16_t port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    assert(fd >= 0);
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(port);
    assert(connect(fd, (struct sockaddr*)&addr, sizeof(addr)) == 0);
    return fd;
}

int main(void) {
    const char* root = getenv("QIHSE_REPLICA_QKP_DIR");
    assert(root && *root);
    char data[256], srv[256], cli[256], path[512];
    char client_pub[512], server_pub[512];
    snprintf(data, sizeof(data), "%s/data", root);
    snprintf(srv, sizeof(srv), "%s/server", root);
    snprintf(cli, sizeof(cli), "%s/client", root);
    assert(mkdir(data, 0700) == 0 && mkdir(srv, 0700) == 0 && mkdir(cli, 0700) == 0);
    assert(setenv("QIHSE_DATA_DIR", data, 1) == 0);
    assert(setenv("QIHSE_FIPS_MODE", "disabled", 1) == 0);
    assert(qihse_pqc_init_providers() == 0);
    assert(qihse_pqc_keygen(srv) && qihse_pqc_keygen(cli));

    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator("QkpOperatorPass1!"));
    qihse_user_t* op = qihse_auth_get_user(0u);
    assert(op);
    qihse_user_t* guest = qihse_auth_create_user(op, 71u, QIHSE_ROLE_GUEST,
        0u, 0u, "QkpGuestPass1!", false);
    assert(guest);
    assert(qihse_auth_modify_user(op, 71u, "QIHSE_GUEST_71", NULL,
                                  -1, -1, -1, -1));
    qihse_kv_store_t* store = qihse_kv_store_create();
    assert(store);
    assert(qihse_kv_set_user(store, "vendor:7:secret", "protected-replica-payload",
                             5u, 9u, op));

    snprintf(client_pub, sizeof(client_pub), "%s/qihse_dsa_pub.pem", cli);
    static const char* trusted[1]; trusted[0] = client_pub;
    qihse_resp_server_config_t config;
    qihse_resp_server_config_init(&config);
    config.store = store;
    config.port = 0u;
    config.auth_required = true;
    config.pqc.require = true;
    config.pqc.trusted_pubs = trusted;
    config.pqc.trusted_count = 1u;
    snprintf(path, sizeof(path), "%s/qihse_dsa_key.pem", srv);
    config.pqc.dsa_key_path = strdup(path);
    snprintf(path, sizeof(path), "%s/qihse_kem_key.pem", srv);
    config.pqc.kem_key_path = strdup(path);
    snprintf(path, sizeof(path), "%s/qihse_kem_pub.pem", srv);
    config.pqc.kem_pub_path = strdup(path);
    config.pqc.node_id = "replica-source";
    config.pqc.replication_peer_node_id = "replica-client";
    config.pqc.replication_peer_dsa_pub_path = strdup(client_pub);
    const char* marked_globs[] = {"vendor:7:*"};
    config.replicate_globs = marked_globs;
    config.replicate_glob_count = 1u;
    qihse_resp_server_t* server = qihse_resp_server_create(&config);
    assert(server && qihse_resp_server_start(server));

    qihse_qkp_config_t client_cfg = {0};
    snprintf(server_pub, sizeof(server_pub), "%s/qihse_dsa_pub.pem", srv);
    static const char* server_trust[1]; server_trust[0] = server_pub;
    client_cfg.trusted_pubs = server_trust;
    client_cfg.trusted_count = 1u;
    snprintf(path, sizeof(path), "%s/qihse_dsa_key.pem", cli);
    client_cfg.dsa_key_path = strdup(path);
    client_cfg.node_id = "replica-client";
    int fd = connect_local(qihse_resp_server_port(server));
    qihse_qkp_session_t* session = NULL;
    assert(qihse_qkp_client_negotiate(fd, &client_cfg, &session) == QIHSE_QKP_SECURE);
    assert(session);
    write_command(session, fd, "AUTH", "GODMODE_OP", "QkpOperatorPass1!", NULL);
    char* reply = read_reply(session, fd);
    assert(strstr(reply, "+OK\r\n"));
    free(reply);
    write_command(session, fd, "REPL.DELTA", "vendor:7:*", "0", "8");
    reply = read_reply(session, fd);
    assert(reply[0] == '*' && strstr(reply, "protected-replica-payload"));
    free(reply);

    write_command(session, fd, "AUTH", "QIHSE_GUEST_71", "QkpGuestPass1!", NULL);
    reply = read_reply(session, fd);
    assert(strstr(reply, "+OK\r\n"));
    free(reply);
    write_command(session, fd, "REPL.DELTA", "vendor:7:*", "0", "8");
    reply = read_reply(session, fd);
    assert(reply[0] == '-' && strstr(reply, "NOPERM"));
    assert(!strstr(reply, "protected-replica-payload"));
    free(reply);

    shutdown(fd, SHUT_RDWR);
    close(fd);
    qihse_qkp_session_free(session);
    qihse_resp_server_stop(server);
    qihse_resp_server_destroy(server);
    qihse_kv_store_destroy(store);
    puts("replica live QKP low-clearance denial: OK");
    return 0;
}
