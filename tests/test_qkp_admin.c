#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <assert.h>
#include <errno.h>
#include <ftw.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include "qihse_auth.h"
#include "core/qihse_audit.h"
#include "qihse_pqc_crypto.h"
#include "qihse_resp_wire.h"
#include "qihse_resp_engine.h"
#include "qihse_qkp.h"
extern char** environ;

static int remove_entry(const char* path, const struct stat* st, int kind, struct FTW* walk) {
    (void)st; (void)kind; (void)walk;
    return remove(path);
}

static void assert_admin_identity(uint16_t port, const char* node_id,
                                  const char* identity, const char* trusted_pub) {
    const char* get[] = {"GET", "admin-test:secret"};
    char* reply = NULL;
    size_t reply_len = 0u;
    char error[256];
    qihse_qkp_admin_client_t* client_handle = NULL;
    assert(qihse_qkp_admin_open("127.0.0.1", port, node_id, identity,
                                trusted_pub, 30000u, &client_handle,
                                error, sizeof(error)) == 0);
    assert(qihse_qkp_admin_command(client_handle, 2u, get, NULL, &reply,
                                   &reply_len, error, sizeof(error)) == 0);
    qihse_qkp_admin_close(client_handle);
    assert(reply && reply_len >= strlen("CLASSIFIED-ADMIN-TEST") &&
           memmem(reply, reply_len, "CLASSIFIED-ADMIN-TEST",
                  strlen("CLASSIFIED-ADMIN-TEST")) != NULL);
    qihse_qkp_admin_free(reply);
}

int main(void) {
    char root[] = "build/test_admin_XXXXXX";
    assert(mkdir("build", 0700) == 0 || errno == EEXIST);
    assert(mkdtemp(root));
    char data[256], client[256], client_new[256], client_repl[256], server_keys[256];
    snprintf(data, sizeof(data), "%s/data", root);
    snprintf(client, sizeof(client), "%s/client", root);
    snprintf(client_new, sizeof(client_new), "%s/client-new", root);
    snprintf(client_repl, sizeof(client_repl), "%s/client-repl", root);
    snprintf(server_keys, sizeof(server_keys), "%s/server", root);
    assert(mkdir(data, 0700) == 0 && mkdir(client, 0700) == 0 &&
           mkdir(client_new, 0700) == 0 && mkdir(client_repl, 0700) == 0 &&
           mkdir(server_keys, 0700) == 0);
    assert(setenv("QIHSE_DATA_DIR", data, 1) == 0);
    assert(setenv("QIHSE_FIPS_MODE", "disabled", 1) == 0);
    assert(qihse_pqc_init_providers() >= 0);
    assert(qihse_pqc_keygen(client) && qihse_pqc_keygen(client_new) &&
           qihse_pqc_keygen(client_repl) && qihse_pqc_keygen(server_keys));
    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator("AdminTestOperator1!"));
    qihse_user_t* op = qihse_auth_get_user(0u);
    assert(op);
    qihse_user_t* low = qihse_auth_create_user(op, 73u, QIHSE_ROLE_ANALYST,
                                               1u, 1u, "AdminTestLow1!", false);
    assert(low);
    qihse_user_t* replication = qihse_auth_create_user(op, 74u, QIHSE_ROLE_ANALYST,
                                                       1u, 1u, "AdminTestRepl1!", false);
    assert(replication);
    assert(qihse_auth_modify_user(op, 73u, "ADMIN_LOW", NULL, -1, -1, -1, -1));
    qihse_kv_store_t* store = qihse_kv_store_create();
    assert(store);
    assert(qihse_kv_set_user(store, "admin-test:secret", "CLASSIFIED-ADMIN-TEST", 5u, 9u, op));
    char client_pub[512], client_new_pub[512], client_repl_pub[512];
    char server_pub[512], dsa[512], kem[512], kem_pub[512];
    snprintf(client_pub, sizeof(client_pub), "%s/qihse_dsa_pub.pem", client);
    snprintf(client_new_pub, sizeof(client_new_pub), "%s/qihse_dsa_pub.pem", client_new);
    snprintf(client_repl_pub, sizeof(client_repl_pub), "%s/qihse_dsa_pub.pem", client_repl);
    snprintf(server_pub, sizeof(server_pub), "%s/qihse_dsa_pub.pem", server_keys);
    snprintf(dsa, sizeof(dsa), "%s/qihse_dsa_key.pem", server_keys);
    snprintf(kem, sizeof(kem), "%s/qihse_kem_key.pem", server_keys);
    snprintf(kem_pub, sizeof(kem_pub), "%s/qihse_kem_pub.pem", server_keys);
    const char* trusted[] = {client_pub, client_new_pub, client_repl_pub};
    qihse_resp_server_config_t config;
    qihse_resp_server_config_init(&config);
    config.store = store;
    config.port = 0u;
    config.auth_required = true;
    config.pqc.require = true;
    config.pqc.trusted_pubs = trusted;
    config.pqc.trusted_count = 3u;
    config.pqc.dsa_key_path = dsa;
    config.pqc.kem_key_path = kem;
    config.pqc.kem_pub_path = kem_pub;
    config.pqc.node_id = "admin-test-server";
    config.pqc.admin_peer_node_id = "admin-test-client";
    config.pqc.admin_peer_dsa_pub_path = client_pub;
    config.pqc.replication_peer_node_id = "admin-test-replication-only";
    config.pqc.replication_peer_dsa_pub_path = client_repl_pub;
    config.replication_service_principal = replication;
    qihse_resp_server_t* server = qihse_resp_server_create(&config);
    assert(server);
    assert(!qihse_resp_server_add_admin_peer(server, "incomplete", NULL, op));
    assert(!qihse_resp_server_add_admin_peer(server,
        "admin-test-replication-only", client_repl_pub, op));
    char overlap_id[] = "admin-test-client-new";
    char overlap_path[sizeof(client_new_pub)];
    snprintf(overlap_path, sizeof(overlap_path), "%s", client_new_pub);
    assert(qihse_resp_server_add_admin_peer(server, overlap_id, overlap_path, op));
    memset(overlap_id, 'x', strlen(overlap_id));
    memset(overlap_path, 'x', strlen(overlap_path));
    assert(qihse_resp_server_start(server));
    assert(!qihse_resp_server_add_admin_peer(server, "admin-test-client-new",
                                              client_new_pub, op));
    assert_admin_identity(qihse_resp_server_port(server), "admin-test-client",
                          client, server_pub);
    assert_admin_identity(qihse_resp_server_port(server), "admin-test-client-new",
                          client_new, server_pub);
    uint16_t peer_port = qihse_resp_server_port(server);
    qihse_qkp_admin_client_t* pinned_client = NULL;
    char peer_error[256];
    assert(qihse_qkp_admin_open_strict_peer("127.0.0.1", peer_port,
        "admin-test-client", client, server_pub, "admin-test-server", server_pub,
        30000u, &pinned_client, peer_error, sizeof(peer_error)) == 0);
    assert(pinned_client);
    qihse_qkp_admin_close(pinned_client);
    pinned_client = NULL;
    /* Both negatives complete a real trusted-key handshake; the strict
     * session check then rejects the signed server label or exact key pin. */
    assert(qihse_qkp_admin_open_strict_peer("127.0.0.1", peer_port,
        "admin-test-client", client, server_pub, "wrong-server", server_pub,
        30000u, &pinned_client, peer_error, sizeof(peer_error)) == 3);
    assert(!pinned_client && strstr(peer_error, "peer identity mismatch"));
    assert(qihse_qkp_admin_open_strict_peer("127.0.0.1", peer_port,
        "admin-test-client", client, server_pub, "admin-test-server", client_new_pub,
        30000u, &pinned_client, peer_error, sizeof(peer_error)) == 3);
    assert(!pinned_client && strstr(peer_error, "peer identity mismatch"));
    const char* get_secret[] = {"GET", "admin-test:secret"};
    char* reply = NULL;
    char error[256];
    assert(qihse_qkp_admin_exec("127.0.0.1", qihse_resp_server_port(server),
                                "admin-test-replication-only", client_repl,
                                server_pub, 2u, get_secret, &reply,
                                error, sizeof(error)) == 0);
    assert(reply && strcmp(reply, "CLASSIFIED-ADMIN-TEST") != 0);
    qihse_qkp_admin_free(reply);
    char port[16];
    snprintf(port, sizeof(port), "%u", qihse_resp_server_port(server));
    char* argv[] = {"python3", "tests/test_admin_cli.py", port, client, server_pub, NULL};
    pid_t pid;
    assert(posix_spawnp(&pid, argv[0], NULL, NULL, argv, environ) == 0);
    int status = 0;
    assert(waitpid(pid, &status, 0) == pid);
    qihse_resp_server_stop(server);
    qihse_resp_server_destroy(server);
    config.pqc.admin_peer_node_id = "admin-test-client-new";
    config.pqc.admin_peer_dsa_pub_path = client_new_pub;
    server = qihse_resp_server_create(&config);
    assert(server && qihse_resp_server_start(server));
    /* A fresh primary-only server models retirement: the old identity is no
     * longer pinned, while the replacement remains authorized. */
    reply = NULL;
    assert(qihse_qkp_admin_exec("127.0.0.1", qihse_resp_server_port(server),
                                "admin-test-client", client, server_pub, 2u,
                                get_secret, &reply, error, sizeof(error)) == 0);
    assert(reply && strcmp(reply, "CLASSIFIED-ADMIN-TEST") != 0);
    qihse_qkp_admin_free(reply);
    reply = NULL;
    assert(qihse_qkp_admin_exec("127.0.0.1", qihse_resp_server_port(server),
                                "admin-test-replication-only", client_repl,
                                server_pub, 2u, get_secret, &reply,
                                error, sizeof(error)) == 0);
    assert(reply && strcmp(reply, "CLASSIFIED-ADMIN-TEST") != 0);
    qihse_qkp_admin_free(reply);
    assert_admin_identity(qihse_resp_server_port(server), "admin-test-client-new",
                          client_new, server_pub);
    qihse_resp_server_stop(server);
    qihse_resp_server_destroy(server);
    qihse_kv_store_destroy(store);
    qihse_auth_shutdown_rate_limiter();
    qihse_auth_shutdown_volume_limiter();
    qihse_audit_shutdown();
    assert(nftw(root, remove_entry, 16, FTW_DEPTH | FTW_PHYS) == 0);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    puts("QKP admin CLI/API integration and low-clearance denial: OK");
    return 0;
}
