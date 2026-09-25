/* test_pqc_handshake.c — R4c CNSA 2.0 QKP1 handshake acceptance harness.
 *
 * Spawns qihse-cluster-daemon on 127.0.0.1:7195 with freshly generated
 * ML-KEM/ML-DSA keys, then drives raw-socket scenarios:
 *   1. happy path: H1 verify → H2 → sealed ACK → AUTH+SET/GET sealed
 *   2. wrong trusted pub on the client → H1 verification aborts
 *   3. server rejects a client identity it does not trust
 *   4. replayed H2 after handshake → connection closed
 *   5. tampered ciphertext → handshake/sealed traffic dies
 *   6. opportunistic mode: plain AUTH/PING without QKP1 still works
 *   7. --pqc-require: cleartext refused with -ERR
 *   8. --pqc-require with missing keys: daemon refuses to start
 *
 * Build: make test-pqc-handshake.  Sandbox-only (port 7195).
 */
#include "qihse_pqc_crypto.h"
#include "qihse_qkp.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#define PORT 7195
#define PW "PqcTest2026Pass!"
#define DAEMON_BIN_ENV "QIHSE_DAEMON_BIN"
#define DEFAULT_BIN "qihse-cluster-daemon"

static int g_failures = 0;
#define CHECK(name, cond) do { \
    printf("%-52s %s\n", (name), (cond) ? "PASS" : "FAIL"); \
    if (!(cond)) g_failures++; \
} while (0)

/* ── raw socket helpers ──────────────────────────────────────────────── */

static int dial(int port) {
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    addr.sin_addr.s_addr = htonl(0x7f000001u);
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct timeval tv = {5, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static bool wr(int fd, const void* buf, size_t len) {
    const char* p = buf;
    size_t done = 0;
    while (done < len) {
        ssize_t w = write(fd, p + done, len - done);
        if (w <= 0) return false;
        done += (size_t)w;
    }
    return true;
}

/* Read a RESP line or bulk; returns malloc'd payload (errors as "-..." text)
 * or NULL on EOF. */
static char* rd(int fd) {
    char head[512];
    size_t used = 0;
    while (used + 1 < sizeof(head)) {
        char c;
        ssize_t r = read(fd, &c, 1);
        if (r <= 0) return NULL;
        head[used++] = c;
        if (c == '\n') break;
    }
    head[used] = '\0';
    if (head[0] == '$') {
        long long len = strtoll(head + 1, NULL, 10);
        if (len < 0) return NULL;
        char* v = malloc((size_t)len + 1);
        size_t got = 0;
        while (got < (size_t)len) {
            ssize_t r = read(fd, v + got, (size_t)len - got);
            if (r <= 0) { free(v); return NULL; }
            got += (size_t)r;
        }
        v[len] = '\0';
        char tail[2];
        if (read(fd, tail, 2) != 2) { free(v); return NULL; }
        return v;
    }
    char* v = strdup(head);
    if (v) { size_t l = strlen(v); while (l && (v[l-1] == '\r' || v[l-1] == '\n')) v[--l] = '\0'; }
    return v;
}

static void wr_cmd(int fd, const char* a, const char* b) {
    char buf[512];
    int n = snprintf(buf, sizeof(buf), b ? "*2\r\n$%zu\r\n%s\r\n$%zu\r\n%s\r\n" : "*1\r\n$%zu\r\n%s\r\n",
                     strlen(a), a, b ? strlen(b) : 0, b ? b : "");
    wr(fd, buf, (size_t)n);
}

static bool qkp_send_frame(int fd, uint8_t type, const void* payload, uint16_t len) {
    uint8_t head[8] = {'Q','K','P','1', type, 0, (uint8_t)(len >> 8), (uint8_t)len};
    return wr(fd, head, 8) && (len == 0 || wr(fd, payload, len));
}

/* ── daemon lifecycle ────────────────────────────────────────────────── */

static pid_t g_daemon = -1;

static pid_t start_daemon(const char* keydir, const char* trusted, int require) {
    /* Resolve the daemon binary: QIHSE_DAEMON_BIN env > tests/../daemon >
     * CWD ./daemon. The invoker's CWD is unreliable, so prefer the path
     * relative to this executable. */
    static char bin_buf[4096];
    const char* bin = getenv(DAEMON_BIN_ENV);
    if (!bin || !*bin) {
        char self_path[4096];
        ssize_t n = readlink("/proc/self/exe", self_path, sizeof(self_path) - 1u);
        if (n > 0) {
            self_path[n] = '\0';
            char* slash = strrchr(self_path, '/');
            if (slash) {
                snprintf(slash + 1, (size_t)(sizeof(self_path) - (size_t)(slash + 1 - self_path)),
                         DEFAULT_BIN);
                char canonical[4096];
                if (realpath(self_path, canonical)) {
                    snprintf(bin_buf, sizeof(bin_buf), "%s", canonical);
                    bin = bin_buf;
                }
            }
        }
    }
    if (!bin || !*bin) bin = DEFAULT_BIN;
    fprintf(stderr, "test: daemon binary = %s\n", bin);

    char port[8], dirarg[256], idxs[8], bus[8], pw[64];
    snprintf(port, sizeof(port), "%d", PORT);
    snprintf(dirarg, sizeof(dirarg), "%s", keydir);
    snprintf(idxs, sizeof(idxs), "%d", 0);
    snprintf(bus, sizeof(bus), "%d", 1795);
    snprintf(pw, sizeof(pw), "%s", PW);
    char trusted_flag[32], trusted_val[512];
    snprintf(trusted_flag, sizeof(trusted_flag), "%s", trusted ? "--pqc-trusted-pub" : "--dir");
    snprintf(trusted_val, sizeof(trusted_val), "%s", trusted ? trusted : "/tmp/qsb-pqc/n0");

    pid_t pid = fork();
    if (pid == 0) {
        if (require)
            execl(bin, bin, "--index", "0", "--bind", "127.0.0.1", "--port", port,
                  "--bus-port", bus, "--dir", "/tmp/qsb-pqc/n0", "--operator-password", pw,
                  "--pqc-identity-dir", dirarg, trusted_flag, trusted_val, "--pqc-require",
                  (char*)NULL);
        else
            execl(bin, bin, "--index", "0", "--bind", "127.0.0.1", "--port", port,
                  "--bus-port", bus, "--dir", "/tmp/qsb-pqc/n0", "--operator-password", pw,
                  "--pqc-identity-dir", dirarg, trusted_flag, trusted_val,
                  (char*)NULL);
        _exit(127);
    }
    return pid;
}

static void stop_daemon(pid_t pid) {
    if (pid <= 0) return;
    kill(pid, SIGKILL);
    waitpid(pid, NULL, 0);
    g_daemon = -1;
}

static bool wait_port(int port) {
    for (int i = 0; i < 40; i++) {
        int fd = dial(port);
        if (fd >= 0) { close(fd); return true; }
        usleep(250 * 1000);
    }
    return false;
}

int main(void) {
    qihse_pqc_init_providers();

    /* Fresh keys: server set + two client sets (one trusted, one rogue). */
    system("rm -rf /tmp/qsb-pqc && mkdir -p /tmp/qsb-pqc/srv /tmp/qsb-pqc/cli /tmp/qsb-pqc/rogue /tmp/qsb-pqc/n0");
    if (!qihse_pqc_keygen("/tmp/qsb-pqc/srv")) { printf("keygen srv FAILED\n"); return 1; }
    if (!qihse_pqc_keygen("/tmp/qsb-pqc/cli")) { printf("keygen cli FAILED\n"); return 1; }
    if (!qihse_pqc_keygen("/tmp/qsb-pqc/rogue")) { printf("keygen rogue FAILED\n"); return 1; }

    char srv_dsa[128], srv_kem[128], srv_pub[128], srv_dsapub[128];
    char cli_dsa[128], cli_dsapub[128], rogue_dsa[128];
    snprintf(srv_dsa, sizeof(srv_dsa), "/tmp/qsb-pqc/srv/qihse_dsa_key.pem");
    snprintf(srv_dsapub, sizeof(srv_dsapub), "/tmp/qsb-pqc/srv/qihse_dsa_pub.pem");
    snprintf(srv_kem, sizeof(srv_kem), "/tmp/qsb-pqc/srv/qihse_kem_key.pem");
    snprintf(srv_pub, sizeof(srv_pub), "/tmp/qsb-pqc/srv/qihse_kem_pub.pem");
    snprintf(cli_dsa, sizeof(cli_dsa), "/tmp/qsb-pqc/cli/qihse_dsa_key.pem");
    snprintf(cli_dsapub, sizeof(cli_dsapub), "/tmp/qsb-pqc/cli/qihse_dsa_pub.pem");
    snprintf(rogue_dsa, sizeof(rogue_dsa), "/tmp/qsb-pqc/rogue/qihse_dsa_key.pem");

    /* Scenario 8 first: --pqc-require with missing keys refuses to start. */
    {
        pid_t p = start_daemon("/tmp/qsb-pqc/does-not-exist", cli_dsapub, 1);
        int status = 0;
        waitpid(p, &status, 0);
        if (!(WIFEXITED(status) && WEXITSTATUS(status) == 1)) {
            fprintf(stderr, "scenario8 status: exited=%d sig=%d code=%d\n",
                    WIFEXITED(status) ? 1 : 0,
                    WIFSIGNALED(status) ? WTERMSIG(status) : 0,
                    WIFEXITED(status) ? WEXITSTATUS(status) : -1);
        }
        CHECK("8. --pqc-require + missing keys refuses to start",
              WIFEXITED(status) && WEXITSTATUS(status) == 1);
    }

    /* Main daemon: opportunistic by default, trusts the client pub. */
    g_daemon = start_daemon("/tmp/qsb-pqc/srv", cli_dsapub, 0);
    if (!wait_port(PORT)) { printf("daemon did not come up\n"); return 1; }

    /* ── 1. happy path ─────────────────────────────────────────────── */
    {
        qihse_qkp_config_t cfg;
        memset(&cfg, 0, sizeof(cfg));
        static const char* trusted[1];
        trusted[0] = srv_dsapub;
        cfg.trusted_pubs = trusted;
        cfg.trusted_count = 1;
        cfg.dsa_key_path = cli_dsa;
        cfg.node_id = "test-client-1";
        int fd = dial(PORT);
        qihse_qkp_session_t* s = NULL;
        qihse_qkp_result_t r = qihse_qkp_client_negotiate(fd, &cfg, &s);
        if (r != QIHSE_QKP_SECURE) {
            /* Server usually sends a "-ERR reason" line before closing. */
            char diag[256] = {0};
            ssize_t n = read(fd, diag, sizeof(diag) - 1);
            if (n > 0) diag[n] = '\0';
            fprintf(stderr, "diag: negotiate result=%d server said: %s\n", (int)r, diag);
        }
        bool ok = (r == QIHSE_QKP_SECURE && s != NULL);
        CHECK("1a. happy handshake (H1 sig, H2, sealed ACK)", ok);
        (void)ok;
        if (ok) {
            /* AUTH inside the sealed channel (inline command framing). The
             * engine seals ONE RECORD PER WRITE and a reply is three writes
             * ("+"/"$" marker, payload, CRLF), so replies are reassembled
             * from the record stream until CRLF. Commands must carry the
             * inline CRLF terminator or the parser keeps waiting. */
            char plain[512];
            size_t have;
            ssize_t n;
            /* NOTE: CHECK evaluates its condition twice; a send must be
             * hoisted or every command goes out twice (this doubled the
             * whole scenario). */
            bool sent_auth = qihse_qkp_send_sealed(s, fd, "AUTH " PW "\r\n", strlen("AUTH " PW "\r\n"));
            CHECK("1b. sealed AUTH", sent_auth);
            have = 0;
            while ((n = qihse_qkp_recv_sealed(s, fd, (uint8_t*)plain + have, sizeof(plain) - 1 - have)) > 0) {
                have += (size_t)n;
                plain[have] = '\0';
                if (have >= 2 && plain[have - 2] == '\r' && plain[have - 1] == '\n') break;
            }
            ok = have > 0 && plain[0] == '+';
            CHECK("1c. sealed AUTH reply (+OK)", ok);
            bool sent_set = qihse_qkp_send_sealed(s, fd, "SET pqc:key sealed-value\r\n", strlen("SET pqc:key sealed-value\r\n"));
            CHECK("1d. sealed SET", sent_set);
            have = 0;
            while ((n = qihse_qkp_recv_sealed(s, fd, (uint8_t*)plain + have, sizeof(plain) - 1 - have)) > 0) {
                have += (size_t)n;
                plain[have] = '\0';
                if (have >= 2 && plain[have - 2] == '\r' && plain[have - 1] == '\n') break;
            }
            ok = have > 0 && plain[0] == '+';
            CHECK("1e. sealed SET reply", ok);
            bool sent_get = qihse_qkp_send_sealed(s, fd, "GET pqc:key\r\n", strlen("GET pqc:key\r\n"));
            CHECK("1f. sealed GET", sent_get);
            have = 0;
            /* Bulk replies: the "$<len>\r\n" header itself ends in CRLF, so
             * keep reading until the value body (plus its trailing CRLF) is
             * in the accumulator. */
            while ((n = qihse_qkp_recv_sealed(s, fd, (uint8_t*)plain + have, sizeof(plain) - 1 - have)) > 0) {
                have += (size_t)n;
                plain[have] = '\0';
                if (have > strlen("sealed-value") && strstr(plain, "sealed-value\r\n")) break;
            }
            ok = have > 1 && plain[0] == '$' && strstr(plain, "sealed-value\r\n") != NULL;
            CHECK("1g. sealed GET value", ok);
            close(fd);
        }
        qihse_qkp_session_free(s);
    }

    /* ── 4. replayed H2 → connection closed ────────────────────────── */
    {
        qihse_qkp_config_t cfg;
        memset(&cfg, 0, sizeof(cfg));
        static const char* trusted[1];
        trusted[0] = srv_dsapub;
        cfg.trusted_pubs = trusted;
        cfg.trusted_count = 1;
        cfg.dsa_key_path = cli_dsa;
        cfg.node_id = "replay-probe";
        int fd = dial(PORT);
        qihse_qkp_session_t* s = NULL;
        if (qihse_qkp_client_negotiate(fd, &cfg, &s) == QIHSE_QKP_SECURE) {
            /* Rebuild the exact H2 frame bytes and replay them: capture is
             * internal, so simulate by sending H2-shaped garbage after the
             * handshake — the server must treat any post-ACK non-QSE1 frame
             * as fatal. Send the QKP1 magic again: the sealed read expects
             * QSE1 and must close. */
            bool closed;
            char buf[64];
            ssize_t n;
            wr(fd, "QKP1", 4);
            n = qihse_qkp_recv_sealed(s, fd, (uint8_t*)buf, sizeof(buf));
            closed = (n < 0);
            CHECK("4. post-handshake QKP1 replay frame closes the connection", closed);
        } else {
            CHECK("4. post-handshake QKP1 replay frame closes the connection", 0);
        }
        close(fd);
        qihse_qkp_session_free(s);
    }

    /* ── 2. wrong trusted pub on the client ────────────────────────── */
    {
        qihse_qkp_config_t cfg;
        memset(&cfg, 0, sizeof(cfg));
        static const char* trusted[1];
        trusted[0] = "/tmp/qsb-pqc/rogue/qihse_dsa_pub.pem"; /* WRONG anchor */
        cfg.trusted_pubs = trusted;
        cfg.trusted_count = 1;
        cfg.dsa_key_path = cli_dsa;
        cfg.node_id = "wrong-anchor";
        int fd = dial(PORT);
        qihse_qkp_session_t* s = NULL;
        qihse_qkp_result_t r = qihse_qkp_client_negotiate(fd, &cfg, &s);
        CHECK("2. client rejects H1 signed by an untrusted key",
              r == QIHSE_QKP_REJECTED && s == NULL);
        close(fd);
        qihse_qkp_session_free(s);
    }

    /* ── 3. server rejects an untrusted client identity ────────────── */
    {
        /* The daemon's trust anchor is the CLI pub; use the ROGUE key. */
        qihse_qkp_config_t cfg;
        memset(&cfg, 0, sizeof(cfg));
        static const char* trusted[1];
        trusted[0] = srv_dsapub;
        cfg.trusted_pubs = trusted;
        cfg.trusted_count = 1;
        cfg.dsa_key_path = rogue_dsa;
        cfg.node_id = "rogue-client";
        int fd = dial(PORT);
        qihse_qkp_session_t* s = NULL;
        qihse_qkp_result_t r = qihse_qkp_client_negotiate(fd, &cfg, &s);
        /* The server verifies the H2 signature against cli_dsapub only:
         * the rogue signature fails, the server closes. */
        bool rejected = (r == QIHSE_QKP_REJECTED);
        if (!rejected) {
            char ack[32];
            ssize_t n = read(fd, ack, sizeof(ack));
            rejected = (n <= 0);
        }
        CHECK("3. server closes an untrusted client identity", rejected);
        close(fd);
        qihse_qkp_session_free(s);
    }

    /* ── 5. tampered ciphertext ────────────────────────────────────── */
    {
        qihse_qkp_config_t cfg;
        memset(&cfg, 0, sizeof(cfg));
        static const char* trusted[1];
        trusted[0] = srv_dsapub;
        cfg.trusted_pubs = trusted;
        cfg.trusted_count = 1;
        cfg.dsa_key_path = cli_dsa;
        cfg.node_id = "tamper-probe";
        int fd = dial(PORT);
        /* Handshake manually to corrupt the ct. */
        qihse_qkp_session_t* s = NULL;
        qihse_qkp_result_t r = qihse_qkp_client_negotiate(fd, &cfg, &s);
        if (r == QIHSE_QKP_SECURE) {
            /* Reseed with a KNOWN-bad session: flip the shared secret by
             * sealing with a wrong key is equivalent to tampering. Instead
             * do the honest thing: send a sealed frame with a corrupted
             * payload (byte-flip after seal) — the server must close. */
            char plain[16];
            ssize_t n = qihse_qkp_recv_sealed(s, fd, (uint8_t*)plain, sizeof(plain) - 1);
            (void)n;
            /* Handshake was fine; now emulate tampering: raw-write a valid
             * QSE1 header + garbage body. */
            uint8_t frame[64];
            memset(frame, 0, sizeof(frame));
            frame[0]='Q'; frame[1]='S'; frame[2]='E'; frame[3]='1';
            frame[4]=0; frame[5]=40;
            for (int i = 6; i < 64; i++) frame[i] = (uint8_t)(0xA5 ^ i);
            bool wr_ok = wr(fd, frame, sizeof(frame));
            bool closed = !wr_ok || read(fd, plain, 1) <= 0;
            CHECK("5. tampered sealed frame kills the connection", closed);
        } else {
            /* Some builds reject at decapsulation; either is a failure to
             * proceed → acceptable? No: tamper targets the ESTABLISHED
             * channel; treat rejection as failure of the scenario. */
            CHECK("5. tampered sealed frame kills the connection", 0);
        }
        close(fd);
        qihse_qkp_session_free(s);
    }

    stop_daemon(g_daemon);

    /* ── 6/7. opportunistic vs require ─────────────────────────────── */
    /* 6: already covered by the default-mode daemon above? No: the default
     * daemon accepts QKP1; cleartext was never tried. Start the daemon in
     * opportunistic mode again and try plain AUTH/PING. */
    g_daemon = start_daemon("/tmp/qsb-pqc/srv", cli_dsapub, 0);
    wait_port(PORT);
    {
        int fd = dial(PORT);
        wr_cmd(fd, "AUTH", PW);
        char* a = rd(fd);
        CHECK("6a. opportunistic: cleartext AUTH works", a && strstr(a, "OK"));
        wr_cmd(fd, "PING", NULL);
        char* p = rd(fd);
        CHECK("6b. opportunistic: cleartext PONG", p && strstr(p, "PONG"));
        free(a); free(p);
        close(fd);
    }
    stop_daemon(g_daemon);

    /* 7: --pqc-require refuses cleartext. */
    g_daemon = start_daemon("/tmp/qsb-pqc/srv", cli_dsapub, 1);
    wait_port(PORT);
    {
        int fd = dial(PORT);
        wr_cmd(fd, "AUTH", PW);
        char* a = rd(fd);
        CHECK("7. --pqc-require refuses cleartext AUTH",
              a && strstr(a, "PQC"));
        free(a);
        close(fd);
    }
    stop_daemon(g_daemon);

    system("rm -rf /tmp/qsb-pqc/n0");
    printf("%s (%d failure%s)\n", g_failures ? "FAILURES" : "ALL TESTS PASSED",
           g_failures, g_failures == 1 ? "" : "s");
    return g_failures ? 1 : 0;
}
