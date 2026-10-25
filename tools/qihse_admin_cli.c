/* qihse-admin-cli — administration client for QKP-hardened QIHSE masters.
 *
 * The masters reject cleartext RESP (pqc_require) once replication pins are
 * configured, so plain redis-cli can no longer reach them. This tool is the
 * supported operator path:
 *
 *   1. TCP connect + QKP1 post-quantum handshake (sealed channel);
 *   2. verify the server against the configured QKP trust anchor; the server
 *      maps this client identity to operator scope only when its node id and
 *      signing public key match the configured admin-peer pin;
 *   3. send one RESP command inside the sealed session.
 *
 * Usage:
 *   qihse-admin-cli --host 192.168.1.91 --port 7100 \
 *       --identity-dir keys \
 *       --trusted-pub keys/qihse_dsa_pub_t420.pem \
 *       --node-id admin-cli --command "CLUSTER NODES"
 *
 * Exit codes: 0 ok, 2 usage/config, 3 connect/handshake, 5 command.
 * The local signing key is a privileged credential and must remain protected.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "qihse_qkp.h"

static const char* g_host = NULL;
static uint16_t g_port = 7100;
static const char* g_identity_dir = NULL;
static const char* g_trusted_pub = NULL;
static const char* g_node_id = "admin-cli";
static const char* g_command = "PING";
static const char* g_command_args[64];
static size_t g_command_argc = 0u;

static void usage(void) {
    fprintf(stderr,
        "usage: qihse-admin-cli --host H --port P --trusted-pub FILE\n"
        "       [--node-id ID] [--identity-dir DIR]\n"
        "       (default identity directory: QIHSE_IDENTITY_DIR or ./keys)\n"
        "       [--command \"CMD ARG...\" | --arg ARG ...] [--ping | --cluster-nodes | --repl-status]\n"
        "\nThe master must pin this identity with\n"
        "  --admin-peer-node-id ID --admin-peer-dsa-pub FILE\n"
        "and the identity key must match the pinned pub.\n");
    exit(2);
}

int main(int argc, char** argv) {
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--host") == 0 && i + 1 < argc) g_host = argv[++i];
        else if (strcmp(argv[i], "--port") == 0 && i + 1 < argc)
            g_port = (uint16_t)atoi(argv[++i]);
        else if (strcmp(argv[i], "--identity-dir") == 0 && i + 1 < argc)
            g_identity_dir = argv[++i];
        else if (strcmp(argv[i], "--trusted-pub") == 0 && i + 1 < argc)
            g_trusted_pub = argv[++i];
        else if (strcmp(argv[i], "--node-id") == 0 && i + 1 < argc)
            g_node_id = argv[++i];
        else if (strcmp(argv[i], "--command") == 0 && i + 1 < argc)
            g_command = argv[++i];
        else if (strcmp(argv[i], "--arg") == 0 && i + 1 < argc &&
                 g_command_argc < 63u)
            g_command_args[g_command_argc++] = argv[++i];
        else if (strcmp(argv[i], "--ping") == 0) g_command = "PING";
        else if (strcmp(argv[i], "--cluster-nodes") == 0)
            g_command = "CLUSTER NODES";
        else if (strcmp(argv[i], "--repl-status") == 0)
            g_command = "REPL.STATUS";
        else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0)
            usage();
        else usage();
    }
    if (!g_host || !g_trusted_pub) usage();

    char cmdbuf[1024];
    const char* cargv[64];
    size_t cargc = 0u;
    if (g_command_argc > 0u) {
        for (size_t i = 0; i < g_command_argc; i++)
            cargv[cargc++] = g_command_args[i];
    } else {
        snprintf(cmdbuf, sizeof(cmdbuf), "%s", g_command);
        char* save = NULL;
        for (char* tok = strtok_r(cmdbuf, " \t", &save);
             tok && cargc < 63u; tok = strtok_r(NULL, " \t", &save))
            cargv[cargc++] = tok;
    }
    if (cargc == 0u) cargv[cargc++] = "PING";

    char* out_text = NULL;
    char err_buf[512] = {0};
    int rc = qihse_qkp_admin_exec(g_host, g_port, g_node_id, g_identity_dir,
                                  g_trusted_pub, cargc, cargv, &out_text,
                                  err_buf, sizeof(err_buf));
    if (rc != 0) {
        fprintf(stderr, "%s\n", err_buf[0] ? err_buf : "admin command failed");
        qihse_qkp_admin_free(out_text);
        return rc;
    }
    if (out_text) {
        fputs(out_text, stdout);
        qihse_qkp_admin_free(out_text);
    }
    return 0;
}
