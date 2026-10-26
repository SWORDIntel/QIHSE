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
extern char** environ;

static int remove_entry(const char* path, const struct stat* st, int kind, struct FTW* walk) {
    (void)st; (void)kind; (void)walk;
    return remove(path);
}

int main(void) {
    char root[] = "build/test_admin_XXXXXX";
    assert(mkdir("build", 0700) == 0 || errno == EEXIST);
    assert(mkdtemp(root));
    char data[256], client[256], server_keys[256];
    snprintf(data, sizeof(data), "%s/data", root);
    snprintf(client, sizeof(client), "%s/client", root);
    snprintf(server_keys, sizeof(server_keys), "%s/server", root);
    assert(mkdir(data, 0700) == 0 && mkdir(client, 0700) == 0 && mkdir(server_keys, 0700) == 0);
    assert(setenv("QIHSE_DATA_DIR", data, 1) == 0);
    assert(setenv("QIHSE_FIPS_MODE", "disabled", 1) == 0);
    assert(qihse_pqc_init_providers() >= 0);
    assert(qihse_pqc_keygen(client) && qihse_pqc_keygen(server_keys));
    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator("AdminTestOperator1!"));
    qihse_user_t* op = qihse_auth_get_user(0u);
    assert(op);
    qihse_user_t* low = qihse_auth_create_user(op, 73u, QIHSE_ROLE_ANALYST,
                                               1u, 1u, "AdminTestLow1!", false);
    assert(low);
    assert(qihse_auth_modify_user(op, 73u, "ADMIN_LOW", NULL, -1, -1, -1, -1));
    qihse_kv_store_t* store = qihse_kv_store_create();
    assert(store);
    assert(qihse_kv_set_user(store, "admin-test:secret", "CLASSIFIED-ADMIN-TEST", 5u, 9u, op));
    char client_pub[512], server_pub[512], dsa[512], kem[512], kem_pub[512];
    snprintf(client_pub, sizeof(client_pub), "%s/qihse_dsa_pub.pem", client);
    snprintf(server_pub, sizeof(server_pub), "%s/qihse_dsa_pub.pem", server_keys);
    snprintf(dsa, sizeof(dsa), "%s/qihse_dsa_key.pem", server_keys);
    snprintf(kem, sizeof(kem), "%s/qihse_kem_key.pem", server_keys);
    snprintf(kem_pub, sizeof(kem_pub), "%s/qihse_kem_pub.pem", server_keys);
    const char* trusted[] = {client_pub};
    qihse_resp_server_config_t config;
    qihse_resp_server_config_init(&config);
    config.store = store;
    config.port = 0u;
    config.auth_required = true;
    config.pqc.require = true;
    config.pqc.trusted_pubs = trusted;
    config.pqc.trusted_count = 1u;
    config.pqc.dsa_key_path = dsa;
    config.pqc.kem_key_path = kem;
    config.pqc.kem_pub_path = kem_pub;
    config.pqc.node_id = "admin-test-server";
    config.pqc.admin_peer_node_id = "admin-test-client";
    config.pqc.admin_peer_dsa_pub_path = client_pub;
    qihse_resp_server_t* server = qihse_resp_server_create(&config);
    assert(server && qihse_resp_server_start(server));
    char port[16];
    snprintf(port, sizeof(port), "%u", qihse_resp_server_port(server));
    char* argv[] = {"python3", "tests/test_admin_cli.py", port, client, server_pub, NULL};
    pid_t pid;
    assert(posix_spawnp(&pid, argv[0], NULL, NULL, argv, environ) == 0);
    int status = 0;
    assert(waitpid(pid, &status, 0) == pid);
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
