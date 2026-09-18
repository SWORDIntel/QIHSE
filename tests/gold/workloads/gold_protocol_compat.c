/*
 * gold_protocol_compat.c — gold workload (area: protocol-compat).
 *
 * A KNOWN-DEFECT probe.  It does not assert that the defects are correct; it
 * detects the current state and reports it in a machine-readable form so the
 * gold runner can print the true state of the system:
 *
 *   GOLD: KNOWN-BUG <workload-id> <check>: <detail>
 *   GOLD: OK        <workload-id> <check>: <detail>
 *
 * Checks:
 *   1. bolt-message-signatures — the QIHSE_BOLT_MSG_* constants in
 *      include/qihse_bolt.h versus the Bolt 4.x message signatures
 *      (https://neo4j.com/docs/bolt/current/bolt/message/).  The audit that
 *      motivated this suite found these disagree, which is why the adapter is
 *      not wire-compatible with a stock Neo4j driver.
 *   2. bolt-reset-on-the-wire — the consequence, observed on a real socket
 *      pair: a spec-conformant RESET (0x0F) must be answered with SUCCESS.
 *      The control message is the library's own RESET constant, which proves
 *      the harness can read framed responses; if the control fails the probe
 *      itself is broken and exits non-zero.
 *   3. mongo-wire-entry-points — the MongoDB wire protocol surface declared in
 *      include/qihse_mongo_wire.h versus what the shipped libqihse.so actually
 *      defines.  bson_create() is the positive control: if dlsym() cannot see
 *      it, the check is meaningless and the probe exits non-zero.
 *
 * Exit status: 0 when the probe ran and reported; non-zero when the probe's own
 * controls failed (which must never be reported as a defect).
 */
#include "qihse_bolt.h"
#include "qihse_mongo_wire.h"

#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define GOLD_ID "gold_protocol_compat"

/* Bolt 4.x message signatures, from the Bolt protocol message specification
 * (https://neo4j.com/docs/bolt/current/bolt/message/).  Only request/response
 * messages this adapter implements are listed. */
typedef struct bolt_spec_sig_s {
    const char* name;
    uint8_t spec;
    uint8_t qihse;
} bolt_spec_sig_t;

static const bolt_spec_sig_t BOLT_SIGS[] = {
    { "HELLO",    0x01, QIHSE_BOLT_MSG_HELLO },
    { "GOODBYE",  0x02, QIHSE_BOLT_MSG_GOODBYE },
    { "RESET",    0x0F, QIHSE_BOLT_MSG_RESET },
    { "RUN",      0x10, QIHSE_BOLT_MSG_RUN },
    { "BEGIN",    0x11, QIHSE_BOLT_MSG_BEGIN },
    { "COMMIT",   0x12, QIHSE_BOLT_MSG_COMMIT },
    { "ROLLBACK", 0x13, QIHSE_BOLT_MSG_ROLLBACK },
    { "DISCARD",  0x2F, QIHSE_BOLT_MSG_DISCARD },
    { "PULL",     0x3F, QIHSE_BOLT_MSG_PULL },
    { "SUCCESS",  0x70, QIHSE_BOLT_MSG_SUCCESS },
    { "RECORD",   0x71, QIHSE_BOLT_MSG_RECORD },
    { "IGNORED",  0x7E, QIHSE_BOLT_MSG_IGNORED },
    { "FAILURE",  0x7F, QIHSE_BOLT_MSG_FAILURE },
};

/* The declared MongoDB wire protocol surface.  These are the entry points a
 * client needs; the BSON helper layer is checked separately as the control. */
static const char* MONGO_SURFACE[] = {
    "qihse_mongo_server_create",
    "qihse_mongo_server_start",
    "qihse_mongo_server_stop",
    "qihse_mongo_server_destroy",
    "mongo_msg_parse",
    "mongo_msg_get_document",
    "mongo_catalog_create",
    "mongo_catalog_destroy",
    "mongo_catalog_get_db",
    "mongo_db_get_collection",
    "mongo_catalog_get_collection",
    "mongo_catalog_drop_collection",
    "mongo_dispatch_command",
};

static void report_known_bug(const char* check, const char* detail) {
    printf("GOLD: KNOWN-BUG %s %s: %s\n", GOLD_ID, check, detail);
}

static void report_ok(const char* check, const char* detail) {
    printf("GOLD: OK %s %s: %s\n", GOLD_ID, check, detail);
}

/* ── Check 1: message signatures ────────────────────────────────────────── */
static int check_signatures(void) {
    char mismatches[512];
    size_t off = 0;
    size_t bad = 0;
    mismatches[0] = '\0';

    for (size_t i = 0; i < sizeof(BOLT_SIGS) / sizeof(BOLT_SIGS[0]); i++) {
        if (BOLT_SIGS[i].qihse == BOLT_SIGS[i].spec) continue;
        bad++;
        int n = snprintf(mismatches + off, sizeof(mismatches) - off,
                         "%s%s=0x%02X (spec 0x%02X)", off ? ", " : "",
                         BOLT_SIGS[i].name, BOLT_SIGS[i].qihse, BOLT_SIGS[i].spec);
        if (n < 0 || (size_t)n >= sizeof(mismatches) - off) break;
        off += (size_t)n;
    }

    if (bad == 0) {
        report_ok("bolt-message-signatures",
                  "all implemented QIHSE_BOLT_MSG_* constants match the Bolt 4.x "
                  "message specification");
        return 0;
    }
    char detail[768];
    snprintf(detail, sizeof(detail),
             "%zu of %zu implemented signatures disagree with Bolt 4.x: %s "
             "(include/qihse_bolt.h:20-34)",
             bad, sizeof(BOLT_SIGS) / sizeof(BOLT_SIGS[0]), mismatches);
    report_known_bug("bolt-message-signatures", detail);
    return 0;
}

/* ── Check 2: a spec-conformant RESET on the wire ───────────────────────── */
static int read_frame(int fd, uint8_t* out_sig, size_t* out_len) {
    uint8_t buf[512];
    size_t have = 0;
    for (int attempt = 0; attempt < 8; attempt++) {
        ssize_t r = read(fd, buf + have, sizeof(buf) - have);
        if (r <= 0) return -1;
        have += (size_t)r;
        uint8_t* payload = NULL;
        size_t payload_len = 0;
        size_t consumed = 0;
        int rc = qihse_bolt_decode_message(buf, have, out_sig, &payload,
                                           &payload_len, &consumed);
        if (rc == 0) {
            *out_len = payload_len;
            free(payload);
            return 0;
        }
        free(payload);
        if (rc < 0) return -1;
    }
    return -1;
}

static int send_message(int fd, uint8_t sig) {
    qihse_bolt_buf_t msg;
    qihse_bolt_buf_init(&msg, 8);
    qihse_bolt_encode_message(&msg, sig, NULL, 0);
    size_t len = msg.len;
    ssize_t w = write(fd, msg.buf, len);
    qihse_bolt_buf_free(&msg);
    return w == (ssize_t)len ? 0 : -1;
}

static int check_reset_on_the_wire(void) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) return -1;

    uint8_t req[20];
    req[0] = 0x60; req[1] = 0x60; req[2] = 0xB0; req[3] = 0x17;
    for (int i = 0; i < 4; i++) {
        /* Bolt 4.0 is proposed as the big-endian 32-bit word 0x00000004
         * ("00 00 00 04"): reserved, reserved, minor, major. */
        uint32_t v = (i == 0) ? QIHSE_BOLT_VERSION_4 : 0;
        req[4 + i * 4] = (uint8_t)(v >> 24);
        req[5 + i * 4] = (uint8_t)(v >> 16);
        req[6 + i * 4] = (uint8_t)(v >> 8);
        req[7 + i * 4] = (uint8_t)v;
    }
    if (write(sv[0], req, sizeof(req)) != (ssize_t)sizeof(req)) return -1;

    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        close(sv[0]);
        qihse_bolt_handle_client(sv[1], NULL);
        _exit(0);
    }
    close(sv[1]);

    uint8_t version_response[4];
    if (read(sv[0], version_response, sizeof(version_response)) !=
        (ssize_t)sizeof(version_response)) {
        close(sv[0]);
        waitpid(pid, NULL, 0);
        return -1;
    }

    /* Control: the library's own RESET signature must be answered SUCCESS,
     * which proves the harness decodes framed responses correctly. */
    if (send_message(sv[0], QIHSE_BOLT_MSG_RESET) != 0) {
        close(sv[0]); waitpid(pid, NULL, 0); return -1;
    }
    uint8_t sig = 0;
    size_t len = 0;
    if (read_frame(sv[0], &sig, &len) != 0 || sig != QIHSE_BOLT_MSG_SUCCESS) {
        fprintf(stderr,
                "gold_protocol_compat: probe control failed: the library's own "
                "RESET (0x%02X) was not answered with SUCCESS (got 0x%02X)\n",
                QIHSE_BOLT_MSG_RESET, sig);
        close(sv[0]); waitpid(pid, NULL, 0);
        return -1;
    }

    /* The check: a Bolt 4.x RESET (0x0F) must be answered SUCCESS. */
    if (send_message(sv[0], 0x0F) != 0) {
        close(sv[0]); waitpid(pid, NULL, 0); return -1;
    }
    sig = 0;
    if (read_frame(sv[0], &sig, &len) != 0) {
        fprintf(stderr, "gold_protocol_compat: probe control failed: no framed "
                "response to a spec-conformant RESET\n");
        close(sv[0]); waitpid(pid, NULL, 0);
        return -1;
    }

    if (sig == QIHSE_BOLT_MSG_SUCCESS) {
        report_ok("bolt-reset-on-the-wire",
                  "a Bolt 4.x RESET (0x0F) was answered with SUCCESS");
    } else {
        char detail[256];
        snprintf(detail, sizeof(detail),
                 "a Bolt 4.x RESET (0x0F) was answered 0x%02X, not SUCCESS "
                 "(0x70); the server treats 0x0F as unknown because its RESET "
                 "constant is 0x%02X (src/spinnaker/qihse_bolt.c:806, "
                 "default: bolt_send_ignored)",
                 sig, QIHSE_BOLT_MSG_RESET);
        report_known_bug("bolt-reset-on-the-wire", detail);
    }

    /* End the session cleanly (GOODBYE is 0x02 in both the spec and QIHSE). */
    send_message(sv[0], QIHSE_BOLT_MSG_GOODBYE);
    uint8_t sink[8];
    (void)read(sv[0], sink, sizeof(sink));
    close(sv[0]);
    waitpid(pid, NULL, 0);
    return 0;
}

/* ── Check 3: MongoDB wire protocol entry points ────────────────────────── */
static int check_mongo_surface(void) {
    void* self = dlopen(NULL, RTLD_NOW);
    if (!self) {
        fprintf(stderr, "gold_protocol_compat: probe control failed: dlopen(NULL): %s\n",
                dlerror());
        return -1;
    }
    /* Positive control: the BSON helper layer is part of the same header and
     * is defined by the shipped library, so dlsym() must find it. */
    void* control = dlsym(self, "bson_create");
    if (!control) {
        fprintf(stderr,
                "gold_protocol_compat: probe control failed: bson_create is not "
                "visible to dlsym, so symbol presence cannot be tested\n");
        dlclose(self);
        return -1;
    }

    char missing[1024];
    size_t off = 0;
    size_t absent = 0;
    missing[0] = '\0';
    for (size_t i = 0; i < sizeof(MONGO_SURFACE) / sizeof(MONGO_SURFACE[0]); i++) {
        if (dlsym(self, MONGO_SURFACE[i])) continue;
        absent++;
        int n = snprintf(missing + off, sizeof(missing) - off, "%s%s",
                         off ? ", " : "", MONGO_SURFACE[i]);
        if (n < 0 || (size_t)n >= sizeof(missing) - off) break;
        off += (size_t)n;
    }
    dlclose(self);

    if (absent == 0) {
        report_ok("mongo-wire-entry-points",
                  "every declared MongoDB wire entry point is defined by "
                  "libqihse.so");
        return 0;
    }
    char detail[1400];
    snprintf(detail, sizeof(detail),
             "%zu of %zu declared MongoDB wire entry points are not defined by "
             "libqihse.so (only the BSON helper layer is compiled in): %s "
             "(declared in include/qihse_mongo_wire.h:97-175)",
             absent, sizeof(MONGO_SURFACE) / sizeof(MONGO_SURFACE[0]), missing);
    report_known_bug("mongo-wire-entry-points", detail);
    return 0;
}

int main(void) {
    if (check_signatures() != 0) return 1;
    if (check_reset_on_the_wire() != 0) return 1;
    if (check_mongo_surface() != 0) return 1;
    return 0;
}
