/* test_pqc_handshake.c — R4c CNSA 2.0 QKP1 handshake acceptance harness.
 *
 * Spawns qihse-cluster-daemon on 127.0.0.1:7195 with freshly generated
 * ML-KEM/ML-DSA keys, then drives raw-socket scenarios:
 *   1. happy path: H1 verify → H2 → sealed ACK → AUTH+SET/GET sealed
 *   2. wrong trusted pub on the client → H1 verification aborts
 *   3. server rejects a client identity it does not trust
 *   4. replayed H2 after handshake → connection closed
 *   5. tampered ciphertext → handshake/sealed traffic dies
 *   9.  (a) 200 KiB sealed GET: chunked into records, reassembled byte-exact
 *   10. (b) KEYS array reply >16 KiB over the sealed session
 *   11. (c) max-size sealed record (16384 payload) round-trips both ways
 *   12. (d) MITM wire audit: per-direction seqs strictly monotonic from 1,
 *           no reuse, full-size records on the wire
 *   13. (g) degraded daemon (keys missing): QKP1 probe gets
 *           "-ERR PQC unavailable" + close; cleartext still served
 *   6. opportunistic mode: plain AUTH/PING without QKP1 still works
 *   7. --pqc-require: cleartext refused with -ERR
 *   8. --pqc-require with missing keys: daemon refuses to start
 *
 * Build: make test-pqc-handshake.  Sandbox-only (ports 7195/7196).
 */
#include "qihse_pqc_crypto.h"
#include "qihse_qkp.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <signal.h>
#include <sys/select.h>
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

/* ── sealed stream reader: RESP reassembled from chunked QSE1 records ──
 * A reply arrives as a run of sealed records (send-side chunking, one
 * strictly monotonic seq per record); the RESP framing spans record
 * boundaries, so everything is reassembled through a refill buffer. */
typedef struct {
    int fd;
    qihse_qkp_session_t* s;
    uint8_t buf[QIHSE_QKP_MAX_PAYLOAD];
    size_t len, pos;
    uint64_t records;
} sstream;

static sstream* sopen(qihse_qkp_session_t* s, int fd) {
    sstream* st = calloc(1u, sizeof(*st));
    if (st) { st->s = s; st->fd = fd; }
    return st;
}

static void sclose(sstream* st) { free(st); }

static bool sfill(sstream* st) {
    st->pos = 0; st->len = 0;
    ssize_t n = qihse_qkp_recv_sealed(st->s, st->fd, st->buf, sizeof(st->buf));
    if (n <= 0) return false;
    st->len = (size_t)n;
    st->records++;
    return true;
}

static int sgetc(sstream* st) {
    if (st->pos >= st->len && !sfill(st)) return -1;
    return st->buf[st->pos++];
}

static bool sread_exact(sstream* st, uint8_t* out, size_t n) {
    for (size_t i = 0; i < n; i++) {
        int c = sgetc(st);
        if (c < 0) return false;
        out[i] = (uint8_t)c;
    }
    return true;
}

static char* sline(sstream* st) {
    size_t cap = 128, len = 0;
    char* out = malloc(cap);
    if (!out) return NULL;
    for (;;) {
        int c = sgetc(st);
        if (c < 0) { free(out); return NULL; }
        if (c == '\n') break;
        if (len + 2 >= cap) {
            cap *= 2u;
            char* grown = realloc(out, cap);
            if (!grown) { free(out); return NULL; }
            out = grown;
        }
        out[len++] = (char)c;
    }
    if (len && out[len - 1] == '\r') len--;
    out[len] = '\0';
    return out;
}

typedef struct respval {
    char type;                          /* '+', '-', ':', '$', '*' */
    char* line;                         /* simple/error/integer line */
    uint8_t* data; size_t dlen;         /* bulk payload */
    struct respval* items; size_t count; /* array elements */
} respval;

static void resp_free(respval* v) {
    if (!v) return;
    free(v->line);
    free(v->data);
    for (size_t i = 0; i < v->count; i++) resp_free(&v->items[i]);
    free(v->items);
    memset(v, 0, sizeof(*v));
}

static bool resp_read(sstream* st, respval* v, int depth) {
    memset(v, 0, sizeof(*v));
    if (depth > 4) return false;
    char* ln = sline(st);
    if (!ln) return false;
    v->type = ln[0];
    if (ln[0] == '$') {
        long long n = strtoll(ln + 1, NULL, 10);
        free(ln);
        if (n < 0) return true;                      /* null bulk */
        v->data = malloc((size_t)n + 1u);
        if (!v->data) return false;
        if (!sread_exact(st, v->data, (size_t)n)) { free(v->data); v->data = NULL; return false; }
        char tail[2];
        if (!sread_exact(st, (uint8_t*)tail, 2u) || tail[0] != '\r' || tail[1] != '\n') {
            free(v->data); v->data = NULL; return false;
        }
        v->dlen = (size_t)n;
        return true;
    }
    if (ln[0] == '*') {
        long long n = strtoll(ln + 1, NULL, 10);
        free(ln);
        if (n < 0) return true;                      /* null array */
        if ((size_t)n > 1000000u) return false;
        v->items = calloc((size_t)n, sizeof(respval));
        if (!v->items) return false;
        v->count = (size_t)n;
        for (size_t i = 0; i < v->count; i++) {
            if (!resp_read(st, &v->items[i], depth + 1)) return false;
        }
        return true;
    }
    v->line = ln;                                    /* '+', '-', ':' */
    return true;
}

/* ── shared key paths (set in main) ──────────────────────────────────── */
static char g_srv_dsapub[128], g_cli_dsa[128];

/* Dial, negotiate QKP1, AUTH inside the sealed channel. The AUTH round trip
 * also proves the channel before the caller's first real command. */
static qihse_qkp_session_t* open_sealed_session(int port, const char* node_id, int* out_fd) {
    qihse_qkp_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    static const char* trusted[1];
    trusted[0] = g_srv_dsapub;
    cfg.trusted_pubs = trusted;
    cfg.trusted_count = 1;
    cfg.dsa_key_path = g_cli_dsa;
    cfg.node_id = node_id;
    int fd = dial(port);
    if (fd < 0) return NULL;
    qihse_qkp_session_t* s = NULL;
    if (qihse_qkp_client_negotiate(fd, &cfg, &s) != QIHSE_QKP_SECURE || !s) {
        close(fd);
        return NULL;
    }
    char auth[96];
    int n = snprintf(auth, sizeof(auth), "AUTH " PW "\r\n");
    if (n <= 0 || !qihse_qkp_send_sealed(s, fd, auth, (size_t)n)) {
        close(fd); qihse_qkp_session_free(s); return NULL;
    }
    sstream* st = sopen(s, fd);
    respval v = {0};
    bool ok = st && resp_read(st, &v, 0) && v.type == '+';
    resp_free(&v);
    sclose(st);
    if (!ok) { close(fd); qihse_qkp_session_free(s); return NULL; }
    if (out_fd) *out_fd = fd;
    return s;
}

/* Send one command, expect a '+' simple reply. */
static bool sealed_ok_reply(qihse_qkp_session_t* s, int fd, const char* cmd) {
    if (!qihse_qkp_send_sealed(s, fd, cmd, strlen(cmd))) return false;
    sstream* st = sopen(s, fd);
    respval v = {0};
    bool ok = st && resp_read(st, &v, 0) && v.type == '+';
    resp_free(&v);
    sclose(st);
    return ok;
}

/* ── in-harness MITM tee (d: nonce audit on the chunked path) ──────────
 * Forwards 127.0.0.1:listen_port → 127.0.0.1:target_port for ONE
 * connection, appending each direction's raw stream to its capture file
 * (same wire-audit approach as the R4c verification). */
static void mitm_child(int listen_port, int target_port,
                       const char* cap_c2s, const char* cap_s2c) {
    int lfd = socket(AF_INET, SOCK_STREAM, 0);
    if (lfd < 0) _exit(1);
    int one = 1;
    setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)listen_port);
    addr.sin_addr.s_addr = htonl(0x7f000001u);
    if (bind(lfd, (struct sockaddr*)&addr, sizeof(addr)) != 0 || listen(lfd, 1) != 0) _exit(1);
    int c = accept(lfd, NULL, NULL);
    if (c < 0) _exit(1);
    int t = socket(AF_INET, SOCK_STREAM, 0);
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)target_port);
    addr.sin_addr.s_addr = htonl(0x7f000001u);
    if (connect(t, (struct sockaddr*)&addr, sizeof(addr)) != 0) _exit(1);
    int fc = open(cap_c2s, O_WRONLY | O_CREAT | O_APPEND, 0600);
    int fs = open(cap_s2c, O_WRONLY | O_CREAT | O_APPEND, 0600);
    uint8_t buf[65536];
    for (;;) {
        fd_set rf;
        FD_ZERO(&rf);
        FD_SET(c, &rf);
        FD_SET(t, &rf);
        int mx = (c > t ? c : t) + 1;
        if (select(mx, &rf, NULL, NULL, NULL) < 0) {
            if (errno == EINTR) continue;
            break;
        }
        bool dead = false;
        if (FD_ISSET(c, &rf)) {
            ssize_t n = recv(c, buf, sizeof(buf), 0);
            if (n <= 0) break;
            if (fc >= 0 && write(fc, buf, (size_t)n) != n) dead = true;
            else if (!wr(t, buf, (size_t)n)) dead = true;
        }
        if (!dead && FD_ISSET(t, &rf)) {
            ssize_t n = recv(t, buf, sizeof(buf), 0);
            if (n <= 0) break;
            if (fs >= 0 && write(fs, buf, (size_t)n) != n) dead = true;
            else if (!wr(c, buf, (size_t)n)) dead = true;
        }
        if (dead) break;
    }
    if (fc >= 0) close(fc);
    if (fs >= 0) close(fs);
    close(c);
    close(t);
    close(lfd);
    _exit(0);
}

/* Walk one captured direction: QKP1 handshake frames are skipped, every
 * QSE1 record must carry the expected direction tag and the next seq
 * (strictly monotonic, step exactly 1, no reuse). Returns the largest
 * record payload seen and the record count. */
static bool audit_cap(const char* path, uint32_t expected_dir,
                      uint64_t* out_records, size_t* out_max_payload,
                      uint64_t* out_first_seq) {
    FILE* f = fopen(path, "rb");
    if (!f) return false;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0) { fclose(f); return false; }
    uint8_t* b = malloc((size_t)sz);
    if (!b || fread(b, 1u, (size_t)sz, f) != (size_t)sz) { free(b); fclose(f); return false; }
    fclose(f);
    size_t pos = 0;
    uint64_t next_seq = 1, records = 0;
    size_t max_payload = 0;
    bool ok = true;
    /* C2S streams open with the bare 4-byte "QKP1" probe followed by the H2
     * frame; without skipping the probe, the frame parser reads "P1" as a
     * length and desyncs. S2C opens with the H1 frame directly. */
    if (sz >= 8u && memcmp(b, "QKP1", 4u) == 0 && memcmp(b + 4, "QKP1", 4u) == 0) pos = 4u;
    while (pos < (size_t)sz) {
        if ((size_t)sz - pos < 6u) { ok = false; break; }   /* stray tail */
        if (memcmp(b + pos, "QKP1", 4u) == 0) {
            if ((size_t)sz - pos < 8u) { ok = false; break; }
            size_t flen = (size_t)(((uint16_t)b[pos + 6] << 8) | b[pos + 7]);
            pos += 8u + flen;
            continue;
        }
        if (memcmp(b + pos, "QSE1", 4u) != 0) { ok = false; break; }
        size_t flen = (size_t)(((uint16_t)b[pos + 4] << 8) | b[pos + 5]);
        if (flen < 28u || flen > QIHSE_QKP_MAX_FRAME) { ok = false; break; }
        if ((size_t)sz - pos < 6u + flen) { ok = false; break; }
        uint32_t dir = ((uint32_t)b[pos + 6] << 24) | ((uint32_t)b[pos + 7] << 16) |
                       ((uint32_t)b[pos + 8] << 8) | (uint32_t)b[pos + 9];
        uint64_t seq = 0;
        for (int i = 0; i < 8; i++) seq = (seq << 8) | b[pos + 10 + (size_t)i];
        if (dir != expected_dir) { ok = false; break; }
        if (records == 0 && out_first_seq) *out_first_seq = seq;
        if (seq != next_seq) { ok = false; break; }         /* gap/reuse/regression */
        next_seq++;
        records++;
        if (flen - 28u > max_payload) max_payload = flen - 28u;
        pos += 6u + flen;
    }
    free(b);
    if (out_records) *out_records = records;
    if (out_max_payload) *out_max_payload = max_payload;
    return ok;
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
    setvbuf(stdout, NULL, _IONBF, 0);   /* survive crashes with visible progress */
    /* A stray daemon on the sandbox port poisons every scenario (a previous
     * crashed run once held 7195 and the suite talked to the wrong process).
     * Refuse to run instead. */
    {
        int stray = dial(PORT);
        if (stray >= 0) {
            close(stray);
            int stray2 = dial(7196);
            if (stray2 >= 0) close(stray2);
            printf("FAILURES (port %d already in use — kill the stray daemon and rerun)\n", PORT);
            return 1;
        }
    }
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
    snprintf(g_srv_dsapub, sizeof(g_srv_dsapub), "%s", srv_dsapub);
    snprintf(g_cli_dsa, sizeof(g_cli_dsa), "%s", cli_dsa);

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

    /* ── 9. (a) chunked sealed GET: a 200 KiB value round-trips intact ── */
    {
        const size_t N = 200u * 1024u;
        uint8_t* payload = malloc(N);
        uint64_t lcg = 0x9E3779B97F4A7C15ull;
        for (size_t i = 0; i < N; i++) {
            lcg = lcg * 6364136223846793005ull + 1442695040888963407ull;
            uint8_t b = (uint8_t)(lcg >> 56);
            payload[i] = b ? b : 0x41u;   /* NUL-free: store rejects NUL values */
        }
        int fd = -1;
        qihse_qkp_session_t* s = open_sealed_session(PORT, "chunk-client", &fd);
        bool ok = (s != NULL);
        if (ok) {
            /* SET in ONE send_sealed call (~205 KB ⇒ 13 chunked records C2S;
             * the old hard limit rejected any write over 16 KiB). */
            char head[64];
            int hl = snprintf(head, sizeof(head), "*3\r\n$3\r\nSET\r\n$5\r\nbig:1\r\n$%zu\r\n", N);
            size_t total = (size_t)hl + N + 2u;
            uint8_t* cmd = malloc(total);
            memcpy(cmd, head, (size_t)hl);
            memcpy(cmd + hl, payload, N);
            memcpy(cmd + hl + N, "\r\n", 2u);
            ok = qihse_qkp_send_sealed(s, fd, cmd, total);
            if (!ok) fprintf(stderr, "diag: 200KiB SET send failed\n");
            free(cmd);
            sstream* st = sopen(s, fd);
            respval v = {0};
            bool set_reply = ok && st && resp_read(st, &v, 0);
            if (!set_reply || v.type != '+')
                fprintf(stderr, "diag: 200KiB SET reply: parsed=%d type='%c' line=%s\n",
                        (int)set_reply, v.type ? v.type : '?', v.line ? v.line : "(none)");
            ok = ok && set_reply && v.type == '+';
            resp_free(&v);
            sclose(st);
            /* GET: the reply ($204800 + payload + CRLF = 204811 bytes S2C)
             * crosses as ~13 chunked records reassembled by RESP framing. */
            const char* get = "*2\r\n$3\r\nGET\r\n$5\r\nbig:1\r\n";
            bool sent_get = qihse_qkp_send_sealed(s, fd, get, strlen(get));
            if (!sent_get) fprintf(stderr, "diag: 200KiB GET send failed\n");
            st = sopen(s, fd);
            respval g = {0};
            bool got = sent_get && st && resp_read(st, &g, 0);
            if (!got || g.type != '$' || g.dlen != N)
                fprintf(stderr, "diag: 200KiB GET reply: parsed=%d type='%c' dlen=%zu want=%zu\n",
                        (int)got, g.type ? g.type : '?', g.dlen, N);
            ok = ok && got && g.type == '$' &&
                 g.dlen == N && g.data && memcmp(g.data, payload, N) == 0;
            resp_free(&g);
            sclose(st);
        }
        CHECK("9. (a) 200 KiB sealed GET byte-exact (chunked records)", ok);
        if (s) { close(fd); qihse_qkp_session_free(s); }
        free(payload);
    }

    /* ── 10. (b) an array reply >16 KiB over the sealed session ─────── */
    {
        int fd = -1;
        qihse_qkp_session_t* s = open_sealed_session(PORT, "keys-client", &fd);
        bool ok = (s != NULL);
        char cmd[96];
        const size_t K = 600;   /* 600 × 43 B elements ⇒ ~25.8 KB reply */
        for (size_t i = 0; ok && i < K; i++) {
            snprintf(cmd, sizeof(cmd), "SET arr:%04zu:pad-pad-pad-pad-pad-pad-pad v\r\n", i);
            ok = sealed_ok_reply(s, fd, cmd);
        }
        const char* keys_cmd = "KEYS arr:*\r\n";
        ok = ok && qihse_qkp_send_sealed(s, fd, keys_cmd, strlen(keys_cmd));
        sstream* st = sopen(s, fd);
        respval arr = {0};
        ok = ok && st && resp_read(st, &arr, 0) && arr.type == '*' && arr.count == K;
        bool sentinel = false;
        if (ok) {
            const char* want = "arr:0000:pad-pad-pad-pad-pad-pad-pad";
            size_t want_len = strlen(want);
            for (size_t i = 0; i < arr.count; i++) {
                if (arr.items[i].type == '$' && arr.items[i].dlen == want_len &&
                    memcmp(arr.items[i].data, want, want_len) == 0) { sentinel = true; break; }
            }
        }
        ok = ok && sentinel;
        CHECK("10. (b) KEYS array reply >16 KiB over sealed session", ok);
        resp_free(&arr);
        sclose(st);
        if (s) { close(fd); qihse_qkp_session_free(s); }
    }

    /* ── 11. (c) max-size record (16384 payload) both directions ────── */
    {
        const size_t N = QIHSE_QKP_MAX_PAYLOAD;
        uint8_t* payload = malloc(N);
        for (size_t i = 0; i < N; i++) {
            uint8_t b = (uint8_t)(i * 7u + (i >> 8));
            payload[i] = b ? b : 0x41u;   /* NUL-free */
        }
        int fd = -1;
        qihse_qkp_session_t* s = open_sealed_session(PORT, "maxrec-client", &fd);
        bool ok = (s != NULL);
        if (ok) {
            /* Framing and value travel as separate sealed writes so the
             * value lands in a record with EXACTLY 16384 payload bytes
             * (flen 16412 — exactly what the old QIHSE_QKP_MAX_FRAME of
             * 16392 rejected on receipt). */
            const char* fr = "*3\r\n$3\r\nSET\r\n$5\r\nmax:1\r\n$16384\r\n";
            ok = qihse_qkp_send_sealed(s, fd, fr, strlen(fr));
            uint8_t* tail = malloc(N + 2u);
            memcpy(tail, payload, N);
            memcpy(tail + N, "\r\n", 2u);
            ok = ok && qihse_qkp_send_sealed(s, fd, tail, N + 2u);   /* 16384+2 → max record + spillover */
            free(tail);
            sstream* st = sopen(s, fd);
            respval v = {0};
            ok = ok && st && resp_read(st, &v, 0) && v.type == '+';
            resp_free(&v);
            sclose(st);
            /* GET back: the engine's bulk write puts all 16384 value bytes
             * through ONE record on S2C. */
            const char* get = "*2\r\n$3\r\nGET\r\n$5\r\nmax:1\r\n";
            ok = ok && qihse_qkp_send_sealed(s, fd, get, strlen(get));
            st = sopen(s, fd);
            respval g = {0};
            ok = ok && st && resp_read(st, &g, 0) && g.type == '$' &&
                 g.dlen == N && g.data && memcmp(g.data, payload, N) == 0;
            resp_free(&g);
            sclose(st);
        }
        CHECK("11. (c) max-size record (16384 payload) round-trips both ways", ok);
        if (s) { close(fd); qihse_qkp_session_free(s); }
        free(payload);
    }

    /* ── 12. (d) MITM wire audit on the chunked path ────────────────── */
    {
        const char* c2s_cap = "/tmp/qsb-pqc/audit_c2s.cap";
        const char* s2c_cap = "/tmp/qsb-pqc/audit_s2c.cap";
        unlink(c2s_cap);
        unlink(s2c_cap);
        fflush(NULL);
        pid_t mpid = fork();
        if (mpid == 0) mitm_child(7196, PORT, c2s_cap, s2c_cap);
        bool ok = mpid > 0;
        const size_t N = 200u * 1024u;
        uint8_t* payload = malloc(N);
        uint64_t lcg = 0xC0FFEE123456789ull;
        for (size_t i = 0; i < N; i++) {
            lcg = lcg * 6364136223846793005ull + 1442695040888963407ull;
            uint8_t b = (uint8_t)(lcg >> 56);
            payload[i] = b ? b : 0x42u;   /* NUL-free */
        }
        int fd = -1;
        qihse_qkp_session_t* s = ok ? open_sealed_session(7196, "mitm-audit", &fd) : NULL;
        ok = s != NULL;
        uint64_t session_s2c_records = 0;
        if (ok) {
            char head[64];
            int hl = snprintf(head, sizeof(head), "*3\r\n$3\r\nSET\r\n$5\r\nbig:2\r\n$%zu\r\n", N);
            size_t total = (size_t)hl + N + 2u;
            uint8_t* cmd = malloc(total);
            memcpy(cmd, head, (size_t)hl);
            memcpy(cmd + hl, payload, N);
            memcpy(cmd + hl + N, "\r\n", 2u);
            ok = qihse_qkp_send_sealed(s, fd, cmd, total);
            free(cmd);
            sstream* st = sopen(s, fd);
            respval v = {0};
            ok = ok && st && resp_read(st, &v, 0) && v.type == '+';
            resp_free(&v);
            sclose(st);
            const char* get = "*2\r\n$3\r\nGET\r\n$5\r\nbig:2\r\n";
            ok = ok && qihse_qkp_send_sealed(s, fd, get, strlen(get));
            st = sopen(s, fd);
            respval g = {0};
            ok = ok && st && resp_read(st, &g, 0) && g.type == '$' &&
                 g.dlen == N && g.data && memcmp(g.data, payload, N) == 0;
            session_s2c_records = st ? st->records : 0;
            resp_free(&g);
            sclose(st);
            ok = ok && session_s2c_records >= 13u;   /* 204811 B / 16384 B per record */
        }
        if (s) { shutdown(fd, SHUT_RDWR); close(fd); qihse_qkp_session_free(s); }
        if (mpid > 0) {
            for (int i = 0; i < 20; i++) {
                if (waitpid(mpid, NULL, WNOHANG) == mpid) break;
                usleep(100 * 1000);
            }
            kill(mpid, SIGKILL);
            waitpid(mpid, NULL, 0);
        }
        uint64_t c2s_n = 0, s2c_n = 0, c2s_first = 0, s2c_first = 0;
        size_t c2s_maxp = 0, s2c_maxp = 0;
        bool c2s_ok = ok && audit_cap(c2s_cap, 1u, &c2s_n, &c2s_maxp, &c2s_first);
        bool s2c_ok = ok && audit_cap(s2c_cap, 2u, &s2c_n, &s2c_maxp, &s2c_first);
        ok = c2s_ok && s2c_ok &&
             c2s_first == 1u && s2c_first == 1u &&        /* H2-ACK is S2C seq 1 */
             c2s_n >= 14u && s2c_n >= 14u &&              /* chunked traffic crossed */
             c2s_maxp == QIHSE_QKP_MAX_PAYLOAD &&         /* full 16384 B records on the wire */
             s2c_maxp == QIHSE_QKP_MAX_PAYLOAD;
        CHECK("12. (d) wire audit: seqs monotonic, no reuse, max record", ok);
        free(payload);
    }

    stop_daemon(g_daemon);

    /* ── 13. (g) f6: degraded daemon (keys missing) answers QKP1 probes ── */
    {
        system("rm -rf /tmp/qsb-pqc/emptykeys && mkdir -p /tmp/qsb-pqc/emptykeys");
        g_daemon = start_daemon("/tmp/qsb-pqc/emptykeys", cli_dsapub, 0);
        bool up = wait_port(PORT);
        bool clean_err = false, eof_after = false, cleartext_ok = false;
        if (up) {
            int fd = dial(PORT);
            wr(fd, "QKP1", 4);
            char* a = rd(fd);
            clean_err = a && strcmp(a, "-ERR PQC unavailable") == 0;
            if (a) {
                char c;
                eof_after = (read(fd, &c, 1) == 0);
            }
            free(a);
            close(fd);
            int fd2 = dial(PORT);
            wr_cmd(fd2, "AUTH", PW);
            char* b = rd(fd2);
            cleartext_ok = b && strstr(b, "OK") != NULL;
            free(b);
            close(fd2);
        }
        CHECK("13. (g) keys missing: QKP1 probe gets -ERR PQC unavailable", up && clean_err && eof_after);
        CHECK("13b. degraded daemon still serves cleartext", up && cleartext_ok);
        stop_daemon(g_daemon);
    }

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
