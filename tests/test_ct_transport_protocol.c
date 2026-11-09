/* SPDX-License-Identifier: LicenseRef-SRSL-1.1 */
#define _GNU_SOURCE
#define _XOPEN_SOURCE 700
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>
#include <errno.h>
#include <ftw.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>

#include "qihse_auth.h"
#include "qihse_audit.h"
#include "qihse_kv_store.h"
#include "qihse_pqc_crypto.h"
#include "qihse_qkp.h"
#include "qihse_resp_engine.h"
#include "qihse_resp_wire.h"

#define OP_PASSWORD "CtWireOperator11!"
#define HIGH_PASSWORD "CtWireHighUser11!"
#define LOW_PASSWORD "CtWireLowUser11!"
#define PROTECTED "CT-WIRE-CLASS5-SCI9-PROTECTED"
#define GENERATION "0123456789abcdef0123456789abcdef"

static int remove_entry(const char* path, const struct stat* st, int type,
                        struct FTW* walk) {
    (void)st;
    (void)walk;
    return type == FTW_D || type == FTW_DP ? rmdir(path) : unlink(path);
}

typedef struct {
    char dir[512];
    char dsa[640];
    char pub[640];
    char kem[640];
    char kem_pub[640];
} identity_t;

static void make_identity(identity_t* id, const char* root, const char* name) {
    assert(snprintf(id->dir, sizeof(id->dir), "%s/%s", root, name) > 0);
    assert(mkdir(id->dir, 0700) == 0);
    assert(qihse_pqc_keygen(id->dir));
    assert(snprintf(id->dsa, sizeof(id->dsa), "%s/qihse_dsa_key.pem", id->dir) > 0);
    assert(snprintf(id->pub, sizeof(id->pub), "%s/qihse_dsa_pub.pem", id->dir) > 0);
    assert(snprintf(id->kem, sizeof(id->kem), "%s/qihse_kem_key.pem", id->dir) > 0);
    assert(snprintf(id->kem_pub, sizeof(id->kem_pub), "%s/qihse_kem_pub.pem", id->dir) > 0);
}

typedef struct {
    qihse_resp_server_t* server;
    int server_fd;
    int client_fd;
    pthread_t thread;
    qihse_qkp_session_t* session;
    bool expected_secure;
    unsigned char in[QIHSE_QKP_MAX_PAYLOAD];
    size_t have;
    size_t off;
} peer_t;

static void* serve_one_peer(void* opaque) {
    peer_t* p = opaque;
    bool accepted = qihse_resp_server_handle_client_fd(p->server, p->server_fd);
    assert(accepted == p->expected_secure);
    return NULL;
}

static peer_t* open_peer(qihse_resp_server_t* server,
                         const identity_t* client, const identity_t* source,
                         const char* client_node, bool expected_secure) {
    int pair[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
    struct timeval timeout = {10, 0};
    for (size_t i = 0; i < 2; ++i) {
        assert(setsockopt(pair[i], SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0);
        assert(setsockopt(pair[i], SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) == 0);
    }
    peer_t* p = calloc(1, sizeof(*p));
    assert(p);
    p->server = server;
    p->expected_secure = expected_secure;
    p->server_fd = pair[0];
    p->client_fd = pair[1];
    assert(pthread_create(&p->thread, NULL, serve_one_peer, p) == 0);
    const char* trusted[] = {source->pub};
    qihse_qkp_config_t cfg = {
        .dsa_key_path = client->dsa,
        .trusted_pubs = trusted,
        .trusted_count = 1,
        .node_id = client_node,
        .require = true,
    };
    qihse_qkp_result_t status = qihse_qkp_client_negotiate(
        p->client_fd, &cfg, &p->session);
    assert((status == QIHSE_QKP_SECURE) == expected_secure);
    if (expected_secure) {
        struct timeval no_timeout = {0, 0};
        assert(setsockopt(p->server_fd, SOL_SOCKET, SO_RCVTIMEO,
                          &no_timeout, sizeof(no_timeout)) == 0);
    }
    return p;
}

static void close_peer(peer_t* p) {
    if (!p) return;
    shutdown(p->client_fd, SHUT_RDWR);
    close(p->client_fd);
    assert(pthread_join(p->thread, NULL) == 0);
    qihse_qkp_session_free(p->session);
    free(p);
}

static unsigned char next_plain(peer_t* p) {
    if (p->off == p->have) {
        ssize_t n = qihse_qkp_recv_sealed(p->session, p->client_fd,
                                         p->in, sizeof(p->in));
        assert(n > 0);
        p->have = (size_t)n;
        p->off = 0;
    }
    return p->in[p->off++];
}

static char* read_resp(peer_t* p, size_t* out_len) {
    size_t cap = 512, len = 0;
    char* out = malloc(cap);
    assert(out);
    unsigned char line[128];
    for (size_t item = 0; item < 1; ++item) {
        (void)item;
        unsigned char marker = next_plain(p);
        assert(marker == '*' || marker == '$' || marker == '+' ||
               marker == '-' || marker == ':');
        if (len + 1 >= cap) { cap *= 2; out = realloc(out, cap); assert(out); }
        out[len++] = (char)marker;
        size_t ln = 0;
        do {
            assert(ln + 1 < sizeof(line));
            line[ln] = next_plain(p);
            if (len + 1 >= cap) { cap *= 2; out = realloc(out, cap); assert(out); }
            out[len++] = (char)line[ln];
        } while (line[ln++] != '\n');
        line[ln] = '\0';
        long count = strtol((char*)line, NULL, 10);
        size_t children = marker == '*' && count > 0 ? (size_t)count : 0;
        if (marker == '*' && (count < 0 || count > 8192)) assert(false);
        for (size_t i = 0; i < children; ++i) {
            unsigned char child = next_plain(p);
            assert(child == '$' || child == ':' || child == '+' || child == '-');
            if (len + 1 >= cap) { cap *= 2; out = realloc(out, cap); assert(out); }
            out[len++] = (char)child;
            size_t child_ln = 0;
            do {
                assert(child_ln + 1 < sizeof(line));
                line[child_ln] = next_plain(p);
                if (len + 1 >= cap) { cap *= 2; out = realloc(out, cap); assert(out); }
                out[len++] = (char)line[child_ln];
            } while (line[child_ln++] != '\n');
            line[child_ln] = '\0';
            long bytes = strtol((char*)line, NULL, 10);
            if (child == '$' && bytes >= 0) {
                assert(bytes <= 16 * 1024 * 1024);
                for (long j = 0; j < bytes + 2; ++j) {
                    unsigned char ch = next_plain(p);
                    if (len + 1 >= cap) { cap *= 2; out = realloc(out, cap); assert(out); }
                    out[len++] = (char)ch;
                }
            }
        }
    }
    out[len] = '\0';
    if (out_len) *out_len = len;
    return out;
}

static char* command(peer_t* p, size_t argc, const char* const* argv,
                     size_t* out_len) {
    char req[2048];
    size_t used = (size_t)snprintf(req, sizeof(req), "*%zu\r\n", argc);
    for (size_t i = 0; i < argc; ++i) {
        int n = snprintf(req + used, sizeof(req) - used, "$%zu\r\n%s\r\n",
                         strlen(argv[i]), argv[i]);
        assert(n > 0 && (size_t)n < sizeof(req) - used);
        used += (size_t)n;
    }
    assert(qihse_qkp_send_sealed(p->session, p->client_fd, req, used));
    return read_resp(p, out_len);
}

int main(void) {
    char root[] = "build/ct-transport-protocol-XXXXXX";
    assert(mkdtemp(root));
    char source_dir[600];
    assert(snprintf(source_dir, sizeof(source_dir), "%s/source", root) > 0);
    assert(mkdir(source_dir, 0700) == 0);
    assert(setenv("QIHSE_DATA_DIR", source_dir, 1) == 0);
    assert(setenv("QIHSE_FIPS_MODE", "disabled", 1) == 0);
    assert(qihse_pqc_init_providers() >= 0);
    identity_t source_id, target_id, forged_id;
    make_identity(&source_id, root, "source-identity");
    make_identity(&target_id, root, "target-identity");
    make_identity(&forged_id, root, "forged-identity");
    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator(OP_PASSWORD));
    qihse_user_t* op = qihse_auth_authenticate_id(0, OP_PASSWORD);
    assert(op && qihse_user_get_role(op) == QIHSE_ROLE_OPERATOR);
    qihse_user_t* high = qihse_auth_create_user(op, 7101, QIHSE_ROLE_ANALYST,
        5, 9, HIGH_PASSWORD, false);
    qihse_user_t* low = qihse_auth_create_user(op, 7102, QIHSE_ROLE_ANALYST,
        4, 0, LOW_PASSWORD, false);
    assert(high && low);
    assert(qihse_user_get_tenant_id(high) == QIHSE_TENANT_SYSTEM);
    assert(qihse_user_get_role(high) != QIHSE_ROLE_OPERATOR);
    assert(qihse_auth_user_is_active(high));

    qihse_kv_store_t* source = qihse_kv_store_create_user(op);
    assert(source);
    assert(qihse_kv_set_user(source, "t:71/ct1/preexisting", PROTECTED, 5, 9, op));
    assert(qihse_kv_set_user(source, "t:71/ct1/delete-me", "old-delete-value", 5, 9, op));
    assert(qihse_kv_ct_source_enable(source, op, "ct-primary", "ct-successor",
        GENERATION, NULL, 128u * 1024u * 1024u));
    unsigned char owner_token[QIHSE_KV_CT_TOKEN_BYTES], baseline_digest[32];
    assert(qihse_kv_ct_owner_token_get(source, op, owner_token));
    qihse_kv_replica_snapshot_t* snapshot = NULL;
    uint64_t baseline_seq = 0;
    assert(qihse_kv_ct_source_baseline_snapshot_create(source, op, &snapshot,
        &baseline_seq, baseline_digest) == 0);
    assert(snapshot && baseline_seq > 0);
    qihse_kv_replica_snapshot_destroy(snapshot);

    assert(qihse_kv_ct_source_reconcile(source, op, "ct-successor", GENERATION,
        baseline_digest, 0));
    /* Use the lower-clearance replication principal for the wire surface; the
     * same authenticated adapter must reject the protected class-5/SCI-9 log. */
    qihse_kv_store_set_replication_principal_id(source, qihse_user_get_id(low));

    qihse_resp_server_config_t cfg;
    qihse_resp_server_config_init(&cfg);
    cfg.store = source;
    cfg.port = 0;
    cfg.auth_required = true;
    cfg.replication_service_principal = low;
    cfg.ct_role = "primary";
    cfg.ct_peer_host = "127.0.0.1";
    cfg.ct_peer_port = 6399;
    cfg.ct_generation_hex = GENERATION;
    cfg.ct_log_limit_bytes = 128u * 1024u * 1024u;
    cfg.ct_ack_timeout_ms = 1000;
    cfg.ct_owner_token = owner_token;
    cfg.ct_control_principal = op;
    cfg.pqc.require = true;
    cfg.pqc.node_id = "ct-primary";
    cfg.pqc.dsa_key_path = source_id.dsa;
    cfg.pqc.kem_key_path = source_id.kem;
    cfg.pqc.kem_pub_path = source_id.kem_pub;
    cfg.pqc.replication_peer_node_id = "ct-successor";
    cfg.pqc.replication_peer_dsa_pub_path = target_id.pub;
    const char* trusted[] = {target_id.pub};
    cfg.pqc.trusted_pubs = trusted;
    cfg.pqc.trusted_count = 1;
    qihse_resp_server_t* server = qihse_resp_server_create(&cfg);
    assert(server);
    peer_t* successor = open_peer(server, &target_id, &source_id,
                                  "ct-successor", true);
    const char* status_cmd[] = {"REPL.CT1", "STATUS"};
    size_t reply_len = 0;
    char* reply = command(successor, 2, status_cmd, &reply_len);
    assert(reply[0] == '*' && memmem(reply, reply_len, GENERATION, 32));
    free(reply);

    qihse_kv_ct_writer_scope_t* scope = NULL;
    assert(qihse_kv_ct_writer_scope_enter(source, high, owner_token, &scope));
    uint64_t seq = 0;
    assert(qihse_kv_set_user_with_seq(source, "t:71/ct1/change",
        "CT1-VALUE-BEFORE", 5, 9, high, &seq) && seq > baseline_seq);
    assert(qihse_kv_set_user_with_seq(source, "t:71/ct1/change",
        "CT1-VALUE-AFTER", 5, 9, high, &seq));
    assert(qihse_kv_del_user_with_seq(source, "t:71/ct1/delete-me", high, &seq));
    qihse_kv_batch_set_record_t expiry = {
        .key = "t:71/ct1/expiry",
        .value = "CT1-EXPIRY-LABEL",
        .expire_time_ms = 4102444800000ULL,
        .classification = 5,
        .sci_compartment = 9,
    };
    assert(qihse_kv_set_batch_durable_user(source, &expiry, 1, high));

    qihse_kv_ct_group_t* groups = NULL;
    size_t group_count = 0;
    uint64_t resume = 0;
    assert(qihse_kv_ct_source_read(source, op, GENERATION, 0, 64,
        1u << 20, &groups, &group_count, &resume));
    assert(group_count >= 4);
    bool saw_before = false, saw_after = false, saw_delete = false, saw_expiry = false;
    for (size_t i = 0; i < group_count; ++i) {
        for (size_t j = 0; j < groups[i].count; ++j) {
            qihse_kv_ct_record_t* r = &groups[i].records[j];
            if (strcmp(r->key, "t:71/ct1/change") == 0 && r->value &&
                strcmp(r->value, "CT1-VALUE-BEFORE") == 0) saw_before = true;
            if (strcmp(r->key, "t:71/ct1/change") == 0 && r->value &&
                strcmp(r->value, "CT1-VALUE-AFTER") == 0) saw_after = true;
            if (strcmp(r->key, "t:71/ct1/delete-me") == 0 && r->tombstone) saw_delete = true;
            if (strcmp(r->key, "t:71/ct1/expiry") == 0 && r->value &&
                strcmp(r->value, "CT1-EXPIRY-LABEL") == 0 &&
                r->expire_time_ms == expiry.expire_time_ms) saw_expiry = true;
            assert(r->classification == 5 && r->sci_compartment == 9);
            assert(r->resource_tenant_id == 71 && r->actor_tenant_id == 0);
            assert(r->actor_id == qihse_user_get_id(high));
        }
    }
    assert(saw_before && saw_after && saw_delete && saw_expiry);
    const char* protected_read[] = {
        "REPL.CT1", "READ", GENERATION, "0", "64", "1048576", "v1"};
    reply = command(successor, 7, protected_read, &reply_len);
    assert(reply[0] == '-');
    assert(!memmem(reply, reply_len, "CT1-VALUE-BEFORE", 16));
    assert(!memmem(reply, reply_len, "CT1-VALUE-AFTER", 15));
    assert(!memmem(reply, reply_len, "CT1-EXPIRY-LABEL", 16));
    free(reply);

    const char* wrong_generation[] = {
        "REPL.CT1", "READ", "ffffffffffffffffffffffffffffffff",
        "0", "64", "1048576", "v1"};
    reply = command(successor, 7, wrong_generation, &reply_len);
    assert(reply[0] == '-');
    assert(!memmem(reply, reply_len, "CT1-VALUE-AFTER", 15));
    free(reply);

    qihse_kv_ct_groups_free(groups, group_count);
    close_peer(successor);

    peer_t* forged = open_peer(server, &forged_id, &source_id,
                              "ct-forged", false);
    close_peer(forged);
    qihse_resp_server_destroy(server);
    qihse_kv_store_destroy(source);
    /* The audit subsystem owns a process-wide lock under QIHSE_DATA_DIR and
     * has an atexit hook. Shut it down before removing this isolated tree. */
    qihse_audit_shutdown();
    assert(nftw(root, remove_entry, 16, FTW_DEPTH | FTW_PHYS) == 0);
    puts("CT1 pinned source metadata and high-data/forged-peer denial: PASS");
    return 0;
}
