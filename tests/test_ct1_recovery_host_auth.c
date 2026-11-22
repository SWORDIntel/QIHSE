#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <assert.h>
#include <errno.h>
#include <ftw.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "qihse_auth.h"
#include "core/qihse_audit.h"
#include "qihse_kv_store.h"
#include "qihse_pqc_crypto.h"
#include "qihse_qkp.h"
#include "qihse_resp_wire.h"

static int remove_entry(const char* path, const struct stat* st, int kind, struct FTW* walk) {
    (void)st; (void)kind; (void)walk;
    return remove(path);
}

static void denied(uint16_t port, const char* label, const char* keys,
                   const char* server_pub, const char* command, const char* arg,
                   const char* expected) {
    const char* argv[] = {command, arg};
    char* reply = NULL;
    char error[256];
    assert(qihse_qkp_admin_exec("127.0.0.1", port, label, keys, server_pub,
                                arg ? 2u : 1u, argv, &reply, error, sizeof(error)) == 0);
    assert(reply && strstr(reply, expected) != NULL);
    if (strcmp(expected, "CLASSIFIED-RECOVERY-SECRET") != 0)
        assert(strstr(reply, "CLASSIFIED-RECOVERY-SECRET") == NULL);
    qihse_qkp_admin_free(reply);
}

int main(void) {
    char root[] = "build/test_ct1_recovery_host_auth_XXXXXX";
    assert(mkdir("build", 0700) == 0 || errno == EEXIST);
    assert(mkdtemp(root));
    char data[256], server_keys[256], recovery_keys[256], wrong_keys[256];
    snprintf(data, sizeof(data), "%s/data", root);
    snprintf(server_keys, sizeof(server_keys), "%s/server", root);
    snprintf(recovery_keys, sizeof(recovery_keys), "%s/recovery", root);
    snprintf(wrong_keys, sizeof(wrong_keys), "%s/wrong", root);
    assert(mkdir(data, 0700) == 0 && mkdir(server_keys, 0700) == 0 &&
           mkdir(recovery_keys, 0700) == 0 && mkdir(wrong_keys, 0700) == 0);
    assert(setenv("QIHSE_DATA_DIR", data, 1) == 0);
    assert(setenv("QIHSE_FIPS_MODE", "disabled", 1) == 0);
    assert(qihse_pqc_init_providers() >= 0);
    assert(qihse_pqc_keygen(server_keys) && qihse_pqc_keygen(recovery_keys) &&
           qihse_pqc_keygen(wrong_keys));
    char server_pub[512], dsa[512], kem[512], kem_pub[512], recovery_pub[512], wrong_pub[512];
    snprintf(server_pub, sizeof(server_pub), "%s/qihse_dsa_pub.pem", server_keys);
    snprintf(dsa, sizeof(dsa), "%s/qihse_dsa_key.pem", server_keys);
    snprintf(kem, sizeof(kem), "%s/qihse_kem_key.pem", server_keys);
    snprintf(kem_pub, sizeof(kem_pub), "%s/qihse_kem_pub.pem", server_keys);
    snprintf(recovery_pub, sizeof(recovery_pub), "%s/qihse_dsa_pub.pem", recovery_keys);
    snprintf(wrong_pub, sizeof(wrong_pub), "%s/qihse_dsa_pub.pem", wrong_keys);
    const char* trusted[] = {recovery_pub, wrong_pub};
    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator("RecoveryFixtureOperator123!"));
    qihse_user_t* op = qihse_auth_get_user(0u);
    assert(op);
    qihse_kv_store_t* store = qihse_kv_store_create_user(op);
    assert(store);
    assert(qihse_kv_set_user(store, "classified", "CLASSIFIED-RECOVERY-SECRET", 5u, 9u, op));
    qihse_resp_server_config_t config;
    qihse_resp_server_config_init(&config);
    config.store = store;
    config.port = 0u;
    config.auth_required = true;
    config.pqc.require = true;
    config.pqc.trusted_pubs = trusted;
    config.pqc.trusted_count = 2u;
    config.pqc.node_id = "fixture-server";
    config.pqc.dsa_key_path = dsa;
    config.pqc.kem_key_path = kem;
    config.pqc.kem_pub_path = kem_pub;

    assert(qihse_qkp_recovery_pin_valid(&config.pqc, NULL, NULL, NULL, 0u));
    qihse_resp_server_t* server = qihse_resp_server_create(&config);
    assert(server && qihse_resp_server_start(server));
    denied(qihse_resp_server_port(server), "recovery", recovery_keys,
           server_pub, "GET", "classified", "NOAUTH");
    qihse_resp_server_stop(server);
    qihse_resp_server_destroy(server);

    config.pqc.recovery_peer_dsa_pub_path = recovery_pub;
    assert(!qihse_qkp_recovery_pin_valid(&config.pqc, NULL, NULL, NULL, 0u));
    assert(qihse_resp_server_create(&config) == NULL);
    config.pqc.recovery_peer_dsa_pub_path = NULL;
    config.pqc.recovery_peer_node_id = "recovery";
    assert(!qihse_qkp_recovery_pin_valid(&config.pqc, NULL, NULL, NULL, 0u));
    assert(qihse_resp_server_create(&config) == NULL);
    config.pqc.recovery_peer_dsa_pub_path = recovery_pub;
    assert(qihse_qkp_recovery_pin_valid(&config.pqc, NULL, NULL, NULL, 0u));
    config.pqc.require = false;
    assert(qihse_resp_server_create(&config) == NULL);
    config.pqc.require = true;
    config.pqc.admin_peer_node_id = "different-label";
    config.pqc.admin_peer_dsa_pub_path = recovery_pub;
    assert(!qihse_qkp_recovery_pin_valid(&config.pqc, NULL, NULL, NULL, 0u));
    assert(qihse_resp_server_create(&config) == NULL);
    config.pqc.admin_peer_dsa_pub_path = wrong_pub;
    config.pqc.admin_peer_node_id = "recovery";
    assert(!qihse_qkp_recovery_pin_valid(&config.pqc, NULL, NULL, NULL, 0u));
    config.pqc.admin_peer_node_id = "different-label";
    assert(!qihse_qkp_recovery_pin_valid(&config.pqc, NULL, recovery_pub, NULL, 0u));
    assert(qihse_qkp_recovery_pin_valid(&config.pqc, "admin-two", NULL, NULL, 0u));
    assert(!qihse_qkp_recovery_pin_valid(&config.pqc, "recovery", NULL, NULL, 0u));
    config.pqc.replication_peer_node_id = "replication";
    config.pqc.replication_peer_dsa_pub_path = recovery_pub;
    assert(!qihse_qkp_recovery_pin_valid(&config.pqc, NULL, NULL, NULL, 0u));
    config.pqc.replication_peer_dsa_pub_path = wrong_pub;
    config.pqc.replication_peer_node_id = "recovery";
    assert(!qihse_qkp_recovery_pin_valid(&config.pqc, NULL, NULL, NULL, 0u));
    config.pqc.replication_peer_node_id = "replication";
    const char* migration_ids[] = {"migration"};
    const char* migration_pubs[] = {recovery_pub};
    config.pqc.migration_peer_node_ids = migration_ids;
    config.pqc.migration_peer_dsa_pub_paths = migration_pubs;
    config.pqc.migration_peer_count = 1u;
    assert(!qihse_qkp_recovery_pin_valid(&config.pqc, NULL, NULL, NULL, 0u));
    migration_pubs[0] = wrong_pub;
    migration_ids[0] = "recovery";
    assert(!qihse_qkp_recovery_pin_valid(&config.pqc, NULL, NULL, NULL, 0u));
    config.pqc.migration_peer_count = 0u;
    qihse_qkp_replication_peer_t peer = {"other-label", recovery_pub};
    assert(!qihse_qkp_recovery_pin_valid(&config.pqc, NULL, NULL, &peer, 1u));
    peer.node_id = "recovery";
    peer.dsa_pub_path = wrong_pub;
    assert(!qihse_qkp_recovery_pin_valid(&config.pqc, NULL, NULL, &peer, 1u));
    config.pqc.admin_peer_node_id = "admin";
    server = qihse_resp_server_create(&config);
    assert(server && qihse_resp_server_start(server));
    uint16_t port = qihse_resp_server_port(server);
    qihse_qkp_admin_client_t* session = NULL;
    char error[256];
    assert(qihse_qkp_admin_open("127.0.0.1", port, "recovery", recovery_keys,
                                server_pub, 30000u, &session, error, sizeof(error)) == 0);
    const char* auth[] = {"AUTH", "RecoveryFixtureOperator123!"};
    const char* get[] = {"GET", "classified"};
    char* reply = NULL;
    size_t reply_len = 0u;
    assert(qihse_qkp_admin_command(session, 2u, auth, NULL, &reply,
                                   &reply_len, error, sizeof(error)) == 0);
    assert(reply && strstr(reply, "NOPERM"));
    qihse_qkp_admin_free(reply);
    reply = NULL;
    assert(qihse_qkp_admin_command(session, 2u, get, NULL, &reply,
                                   &reply_len, error, sizeof(error)) == 0);
    assert(reply && strstr(reply, "NOPERM") &&
           !strstr(reply, "CLASSIFIED-RECOVERY-SECRET"));
    qihse_qkp_admin_free(reply);
    qihse_qkp_admin_close(session);
    denied(port, "recovery", recovery_keys, server_pub, "GET", "classified", "NOPERM");
    denied(port, "recovery", recovery_keys, server_pub, "SET", "classified", "NOPERM");
    denied(port, "recovery", recovery_keys, server_pub, "REPL.DELTA", NULL, "NOPERM");
    denied(port, "recovery", recovery_keys, server_pub, "PING", NULL, "NOPERM");
    denied(port, "recovery", recovery_keys, server_pub, "HELLO", NULL, "NOPERM");
    denied(port, "recovery", recovery_keys, server_pub, "AUTH", "RecoveryFixtureOperator123!", "NOPERM");
    denied(port, "recovery", recovery_keys, server_pub, "REPL.CT1", NULL, "NOPERM");
    denied(port, "recovery", recovery_keys, server_pub, "CLUSTER", NULL, "NOPERM");
    denied(port, "recovery", recovery_keys, server_pub, "MIGRATE", NULL, "NOPERM");
    denied(port, "wrong-label", recovery_keys, server_pub, "GET", "classified", "NOAUTH");
    denied(port, "recovery", wrong_keys, server_pub, "GET", "classified", "NOAUTH");
    denied(port, "admin", wrong_keys, server_pub, "GET", "classified", "CLASSIFIED-RECOVERY-SECRET");
    qihse_resp_server_stop(server);
    qihse_resp_server_destroy(server);
    qihse_kv_store_destroy(store);
    qihse_auth_shutdown_rate_limiter();
    qihse_auth_shutdown_volume_limiter();
    qihse_audit_shutdown();
    assert(nftw(root, remove_entry, 16, FTW_DEPTH | FTW_PHYS) == 0);
    puts("CT1 recovery-host QKP identity and deny-all RESP capability: OK");
    return 0;
}
