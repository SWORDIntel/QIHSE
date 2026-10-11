/*
 * test_controller_qkp.c — W7 item 4: external clients reach --pqc-require
 * nodes through the QKP1 sealed transport.
 *
 *   1. sealed connect + AUTH + command round-trip through the C
 *      controller (typed wrappers ride sealed frames transparently)
 *   2. a cleartext controller connect to the SAME --pqc-require node is
 *      refused — the sealed path is the only path
 *   3. a rogue client identity (not in the server's trust set) is
 *      rejected at the handshake
 *
 * Modeled on tests/test_pqc_handshake.c's daemon-spawn harness.
 */

#include "persistence/qihse_pqc_crypto.h"
#include "qihse_controller.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#define PORT 7395
#define BUS  17395
#define PW   "ControllerQkpPass1!"
#define ROOT "build/controller_qkp_XXXXXX"

static char g_root[64];
static char g_srv_dir[128], g_cli_dir[128], g_rogue_dir[128];
static char g_srv_pub[192];
static pid_t g_daemon = -1;

static void rmrf(void) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "rm -rf -- '%s'", g_root);
    for (int i = 0; i < 5; i++) {
        if (system(cmd) == 0) break;
        usleep(200000);
    }
}

static void stop_daemon(void) {
    if (g_daemon > 0) {
        kill(g_daemon, SIGKILL);
        waitpid(g_daemon, NULL, 0);
        g_daemon = -1;
    }
}

static bool wait_port(int port) {
    for (int i = 0; i < 60; i++) {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) return false;
        struct sockaddr_in a;
        memset(&a, 0, sizeof(a));
        a.sin_family = AF_INET;
        a.sin_port = htons((uint16_t)port);
        a.sin_addr.s_addr = htonl(0x7F000001u);
        if (connect(fd, (struct sockaddr*)&a, sizeof(a)) == 0) {
            close(fd);
            return true;
        }
        close(fd);
        usleep(250000);
    }
    return false;
}

static bool spawn_daemon(void) {
    /* Trust set = the server's own pub AND the proper client's pub (the
     * live cluster runs one --pqc-trusted-pub per node).  The rogue
     * identity is deliberately absent, which is what test 3 proves. */
    char port[8], bus[8], srv_pub[192], cli_pub[192];
    snprintf(port, sizeof(port), "%d", PORT);
    snprintf(bus, sizeof(bus), "%d", BUS);
    snprintf(srv_pub, sizeof(srv_pub), "%s/qihse_dsa_pub.pem", g_srv_dir);
    snprintf(cli_pub, sizeof(cli_pub), "%s/qihse_dsa_pub.pem", g_cli_dir);
    pid_t pid = fork();
    if (pid == 0) {
        execl("./qihse-cluster-daemon", "./qihse-cluster-daemon",
              "--index", "0", "--bind", "127.0.0.1", "--port", port,
              "--bus-port", bus, "--dir", g_srv_dir,
              "--operator-password", PW,
              "--pqc-identity-dir", g_srv_dir,
              "--pqc-trusted-pub", srv_pub,
              "--pqc-trusted-pub", cli_pub,
              "--pqc-require",
              (char*)NULL);
        _exit(127);
    }
    g_daemon = pid;
    return wait_port(PORT);
}

static void stop_daemon_safe(void) { stop_daemon(); }

int main(void) {
    signal(SIGPIPE, SIG_IGN);
    /* A previous aborted run may have leaked its daemon on our fixed
     * port; clear it so this run's spawn is the node under test. */
    (void)system("pkill -f '[q]ihse-cluster-daemon.*--port 7395' || true");
    usleep(300000);
    snprintf(g_root, sizeof(g_root), ROOT);
    if (!mkdtemp(g_root)) return 1;
    atexit(rmrf);

    snprintf(g_srv_dir, sizeof(g_srv_dir), "%s/srv", g_root);
    snprintf(g_cli_dir, sizeof(g_cli_dir), "%s/cli", g_root);
    snprintf(g_rogue_dir, sizeof(g_rogue_dir), "%s/rogue", g_root);
    snprintf(g_srv_pub, sizeof(g_srv_pub), "%s/qihse_dsa_pub.pem", g_srv_dir);

    /* The server trusts ONLY the proper client identity; the rogue key
     * pair exists but is never admitted. */
    mkdir(g_srv_dir, 0700);
    mkdir(g_cli_dir, 0700);
    mkdir(g_rogue_dir, 0700);
    assert(qihse_pqc_keygen(g_srv_dir));
    assert(qihse_pqc_keygen(g_cli_dir));
    assert(qihse_pqc_keygen(g_rogue_dir));

    if (!spawn_daemon()) {
        fprintf(stderr, "daemon did not come up\n");
        stop_daemon_safe();
        return 1;
    }

    /* ── 1. sealed connect + AUTH + typed round-trip ─────────────────── */
    {
        const char* pubs[1] = { g_srv_pub };
        qihse_controller_config_t cfg;
        memset(&cfg, 0, sizeof(cfg));
        cfg.host = "127.0.0.1";
        cfg.port = PORT;
        cfg.username = "GODMODE_OP";
        cfg.password = PW;
        cfg.timeout_ms = 20000;
        cfg.qkp_identity_dir = g_cli_dir;
        cfg.qkp_trusted_pubs = pubs;
        cfg.qkp_trusted_count = 1;

        qihse_controller_t* c = qihse_controller_connect(&cfg);
        assert(c != NULL);
        assert(qihse_controller_connected(c));

        const char* set[3] = { "SET", "qkp:probe", "sealed-value-42" };
        qihse_ctrl_reply_t* r = qihse_ctrl_call(c, 3, set);
        assert(qihse_ctrl_reply_ok(r));
        qihse_ctrl_reply_free(r);

        const char* get[2] = { "GET", "qkp:probe" };
        r = qihse_ctrl_call(c, 2, get);
        assert(r && r->kind == QIHSE_CTRL_BULK);
        assert(r->text_len == strlen("sealed-value-42"));
        assert(memcmp(r->text, "sealed-value-42", r->text_len) == 0);
        qihse_ctrl_reply_free(r);

        qihse_controller_destroy(c);
        printf("[PASS] sealed controller: connect + AUTH + SET/GET over QKP1\n");
    }

    /* ── 2. cleartext to a --pqc-require node is refused ─────────────── */
    {
        qihse_controller_config_t cfg;
        memset(&cfg, 0, sizeof(cfg));
        cfg.host = "127.0.0.1";
        cfg.port = PORT;
        cfg.username = "GODMODE_OP";
        cfg.password = PW;
        cfg.timeout_ms = 20000;
        qihse_controller_t* c = qihse_controller_connect(&cfg);
        assert(c == NULL);
        printf("[PASS] cleartext controller connect to --pqc-require refused\n");
    }

    /* ── 3. rogue client identity rejected at the handshake ───────────
     * (same daemon: the rogue pub is not in its trust set) */
    {
        const char* pubs[1] = { g_srv_pub };
        qihse_controller_config_t cfg;
        memset(&cfg, 0, sizeof(cfg));
        cfg.host = "127.0.0.1";
        cfg.port = PORT;
        cfg.username = "GODMODE_OP";
        cfg.password = PW;
        cfg.timeout_ms = 20000;
        cfg.qkp_identity_dir = g_rogue_dir;      /* not in the trust set */
        cfg.qkp_trusted_pubs = pubs;
        cfg.qkp_trusted_count = 1;
        qihse_controller_t* c = qihse_controller_connect(&cfg);
        assert(c == NULL);
        printf("[PASS] rogue client identity rejected at the handshake\n");
    }
    stop_daemon_safe();

    printf("controller QKP tests passed\n");
    return 0;
}
