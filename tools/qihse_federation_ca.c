/*
 * tools/qihse_federation_ca.c — operator-side federation CA provisioning CLI.
 *
 * The "CA provisioning outside the process" half of the mTLS work: the
 * database can never mint its own authority because the CA private key only
 * ever exists in files this OFFLINE tool touches.  No network, no daemon.
 *
 * Subcommands:
 *   init-ca     create the federation CA (ML-DSA by default, PQ enforced)
 *   issue-node  certify a node's EXISTING identity public key
 *   revoke      append to the operator-side revocation list (CRL)
 *   verify      check a certificate against the CA + CRL
 *
 * Examples:
 *   qihse-federation-ca init-ca --key ca/federation-ca.key \
 *                               --cert ca/federation-ca.pem
 *   qihse-federation-ca issue-node --ca-key ca/federation-ca.key \
 *                                  --ca-cert ca/federation-ca.pem \
 *                                  --node-uuid <uuid> --alg ml-dsa-65 \
 *                                  --pubkey node.pub.hex --epoch 7 \
 *                                  --scope FEDERATION_READ,FEDERATION_WRITE \
 *                                  --out node.pem
 *   qihse-federation-ca revoke --crl ca/revocations.crl \
 *                              --node-uuid <uuid> --reason compromised
 *   qihse-federation-ca verify --ca-cert ca/federation-ca.pem \
 *                              --crl ca/revocations.crl --cert node.pem
 *
 * Mutating subcommands authenticate an OPERATOR principal out of the auth
 * store under $QIHSE_DATA_DIR (a relative --auth-dir may be given; default
 * "./build/qihse_ca_provision"), with the bootstrap password taken from
 * QIHSE_OPERATOR_PASSWORD — mirroring tests/test_federation_mtls.c.  The
 * CA private key is written 0600 and is never printed or returned.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "qihse_ca_provision.h"
#include "qihse_auth.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>

/* ── small helpers ─────────────────────────────────────────────────────── */

static void usage(FILE* out) {
    fputs(
"usage: qihse-federation-ca <subcommand> [options]\n"
"\n"
"subcommands:\n"
"  init-ca     --key PATH --cert PATH [--alg ml-dsa-87|ml-dsa-65|ml-dsa-44]\n"
"  issue-node  --ca-key PATH --ca-cert PATH --node-uuid UUID --alg ALG\n"
"              (--pubkey FILE | --pubkey-hex HEX) [--fingerprint HEX]\n"
"              [--epoch N] [--scope A,B] [--scope-hex N]\n"
"              [--validity SECONDS] [--not-before-offset SECONDS] --out PATH\n"
"  revoke      --crl PATH --node-uuid UUID [--fingerprint HEX]\n"
"              [--serial N] --reason TEXT\n"
"  verify      --ca-cert PATH [--crl PATH] --cert PATH\n"
"              [--scope A,B] [--scope-hex N] [--now UNIXTIME]\n"
"\n"
"common:\n"
"  --auth-dir PATH   auth store directory (default $QIHSE_DATA_DIR or\n"
"                    ./build/qihse_ca_provision); the operator bootstrap\n"
"                    password is read from QIHSE_OPERATOR_PASSWORD\n",
    out);
}

/* Find the value for "--name" in argv; NULL when absent. */
static const char* arg_value(int argc, char** argv, const char* name) {
    size_t n = strlen(name);
    for (int i = 1; i < argc - 1; i++) {
        if (strncmp(argv[i], name, n) == 0 && argv[i][n] == '\0') {
            return argv[i + 1];
        }
    }
    return NULL;
}

static bool arg_u64(const char* s, uint64_t* out) {
    if (!s || *s == '\0') return false;
    errno = 0;
    char* end = NULL;
    unsigned long long v = strtoull(s, &end, 0);
    if (errno != 0 || !end || *end != '\0') return false;
    *out = (uint64_t)v;
    return true;
}

static bool arg_i64(const char* s, int64_t* out) {
    if (!s || *s == '\0') return false;
    errno = 0;
    char* end = NULL;
    long long v = strtoll(s, &end, 0);
    if (errno != 0 || !end || *end != '\0') return false;
    *out = (int64_t)v;
    return true;
}

/* mkdir -p for relative operator-supplied paths. */
static bool mkdir_p(const char* path) {
    char tmp[512];
    int n = snprintf(tmp, sizeof(tmp), "%s", path);
    if (n <= 0 || (size_t)n >= sizeof(tmp)) return false;
    size_t len = (size_t)n;
    for (size_t i = 1; i <= len; i++) {
        if (tmp[i] == '/' || tmp[i] == '\0') {
            char save = tmp[i];
            tmp[i] = '\0';
            if (mkdir(tmp, 0755) != 0 && errno != EEXIST) return false;
            tmp[i] = save;
        }
    }
    return true;
}

/* Comma-separated scope names -> mask, via the federation module's own
 * parser so the CLI never invents scope spellings. */
static bool parse_scopes(const char* list, qihse_infra_scope_t* out) {
    *out = QIHSE_SCOPE_NONE;
    if (!list || *list == '\0') return true;
    char buf[512];
    if (strlen(list) >= sizeof(buf)) return false;
    snprintf(buf, sizeof(buf), "%s", list);
    char* save = NULL;
    for (char* tok = strtok_r(buf, ",", &save); tok;
         tok = strtok_r(NULL, ",", &save)) {
        qihse_infra_scope_t s;
        if (!qihse_infra_scope_parse(tok, &s)) return false;
        *out |= s;
    }
    return true;
}

/* Strict hex -> bytes (cap includes NUL space expectations of caller). */
static bool hex_to_bytes(const char* hex, uint8_t* out, size_t max,
                         size_t* out_len) {
    size_t hlen = hex ? strlen(hex) : 0;
    if (hlen == 0 || (hlen % 2u) != 0 || hlen / 2u > max) return false;
    for (size_t i = 0; i < hlen / 2u; i++) {
        unsigned byte = 0;
        if (sscanf(hex + i * 2, "%2x", &byte) != 1) return false;
        out[i] = (uint8_t)byte;
    }
    *out_len = hlen / 2u;
    return true;
}

/* The operator context: bootstrapped from QIHSE_OPERATOR_PASSWORD against
 * the auth store, exactly as tests/test_federation_mtls.c does it. */
static qihse_user_t* cli_operator(const char* auth_dir) {
    const char* pass = getenv("QIHSE_OPERATOR_PASSWORD");
    if (!pass || *pass == '\0') {
        fprintf(stderr,
                "qihse-federation-ca: QIHSE_OPERATOR_PASSWORD is required for "
                "mutating subcommands\n");
        return NULL;
    }
    if (!mkdir_p(auth_dir)) {
        fprintf(stderr, "qihse-federation-ca: cannot create auth dir %s\n",
                auth_dir);
        return NULL;
    }
    if (setenv("QIHSE_DATA_DIR", auth_dir, 1) != 0) return NULL;
    if (!qihse_auth_init()) return NULL;
    if (!qihse_auth_bootstrap_operator(pass)) {
        /* Already bootstrapped on a previous run: re-init with the password
         * in the environment, exactly as tests/test_federation_mtls.c does. */
        if (setenv("QIHSE_OPERATOR_PASSWORD", pass, 1) != 0) return NULL;
        if (!qihse_auth_init()) return NULL;
    }
    qihse_user_t* op = qihse_auth_get_user(0);
    if (!op) {
        fprintf(stderr,
                "qihse-federation-ca: could not establish operator context\n");
    }
    return op;
}

/* ── init-ca ───────────────────────────────────────────────────────────── */

static int cmd_init_ca(int argc, char** argv) {
    const char* key = arg_value(argc, argv, "--key");
    const char* cert = arg_value(argc, argv, "--cert");
    const char* alg_name = arg_value(argc, argv, "--alg");
    const char* auth_dir = arg_value(argc, argv, "--auth-dir");
    if (!key || !cert) {
        fprintf(stderr, "init-ca: --key and --cert are required\n");
        return 2;
    }
    qihse_sig_alg_t alg = QIHSE_SIG_ALG_DEFAULT;
    if (alg_name && !qihse_sig_alg_parse(alg_name, &alg)) {
        fprintf(stderr, "init-ca: unknown algorithm '%s'\n", alg_name);
        return 2;
    }

    qihse_user_t* op = cli_operator(auth_dir ? auth_dir
                              : (getenv("QIHSE_DATA_DIR")
                                     ? getenv("QIHSE_DATA_DIR")
                                     : "build/qihse_ca_provision"));
    if (!op) return 1;

    qihse_federation_ca_t ca;
    if (!qihse_ca_provision_init_ca(op, alg, key, cert, &ca)) {
        fprintf(stderr,
                "init-ca: failed (algorithm must be post-quantum; an existing "
                "CA key is never overwritten; operator must hold "
                "security-admin)\n");
        return 1;
    }
    /* The fingerprint is public identity material; the key never is. */
    printf("CA created\n");
    printf("  certificate : %s\n", cert);
    printf("  private key : %s (0600, never printed or returned)\n", key);
    printf("  fingerprint : %s\n", ca.fingerprint_hex);
    printf("Record the fingerprint out of band; nodes compare against it.\n");
    return 0;
}

/* ── issue-node ────────────────────────────────────────────────────────── */

static int cmd_issue_node(int argc, char** argv) {
    const char* ca_key = arg_value(argc, argv, "--ca-key");
    const char* ca_cert = arg_value(argc, argv, "--ca-cert");
    const char* node_uuid = arg_value(argc, argv, "--node-uuid");
    const char* alg_name = arg_value(argc, argv, "--alg");
    const char* pubkey_file = arg_value(argc, argv, "--pubkey");
    const char* pubkey_hex = arg_value(argc, argv, "--pubkey-hex");
    const char* expect_fp = arg_value(argc, argv, "--fingerprint");
    const char* scope_list = arg_value(argc, argv, "--scope");
    const char* scope_hex = arg_value(argc, argv, "--scope-hex");
    const char* out_path = arg_value(argc, argv, "--out");
    const char* auth_dir = arg_value(argc, argv, "--auth-dir");
    if (!ca_key || !ca_cert || !node_uuid || !out_path ||
        (!pubkey_file && !pubkey_hex)) {
        fprintf(stderr,
                "issue-node: --ca-key, --ca-cert, --node-uuid, "
                "(--pubkey | --pubkey-hex) and --out are required\n");
        return 2;
    }

    qihse_federation_ca_t ca;
    if (!qihse_ca_provision_load_ca(ca_cert, &ca)) {
        fprintf(stderr, "issue-node: cannot load CA certificate %s\n", ca_cert);
        return 1;
    }

    qihse_ca_provision_node_req_t req;
    memset(&req, 0, sizeof(req));
    if (!qihse_uuid_parse(node_uuid, &req.node_id)) {
        fprintf(stderr, "issue-node: bad --node-uuid '%s'\n", node_uuid);
        return 2;
    }
    req.sig_alg = QIHSE_SIG_ALG_DEFAULT;
    if (alg_name && !qihse_sig_alg_parse(alg_name, &req.sig_alg)) {
        fprintf(stderr, "issue-node: unknown --alg '%s'\n", alg_name);
        return 2;
    }

    /* The public key: hex on the command line, or a file containing hex. */
    char hexbuf[QIHSE_FEDERATION_PUBKEY_MAX_BYTES * 2u + 2u];
    const char* hex = pubkey_hex;
    if (!hex) {
        FILE* f = fopen(pubkey_file, "rb");
        if (!f) {
            fprintf(stderr, "issue-node: cannot read %s\n", pubkey_file);
            return 1;
        }
        size_t n = fread(hexbuf, 1, sizeof(hexbuf) - 1u, f);
        int err = ferror(f);
        fclose(f);
        if (err) {
            fprintf(stderr, "issue-node: read error on %s\n", pubkey_file);
            return 1;
        }
        hexbuf[n] = '\0';
        /* trim whitespace */
        char* e = hexbuf + n;
        while (e > hexbuf && (e[-1] == '\n' || e[-1] == '\r' ||
                              e[-1] == ' ' || e[-1] == '\t')) {
            *--e = '\0';
        }
        hex = hexbuf;
    }
    uint8_t pk[QIHSE_FEDERATION_PUBKEY_MAX_BYTES];
    size_t pk_len = 0;
    if (!hex_to_bytes(hex, pk, sizeof(pk), &pk_len)) {
        fprintf(stderr, "issue-node: --pubkey is not valid hex\n");
        return 2;
    }
    req.public_key = pk;
    req.public_key_len = pk_len;

    uint8_t expected[QIHSE_FEDERATION_NODE_FINGERPRINT_BYTES];
    if (expect_fp) {
        size_t fp_len = 0;
        if (!hex_to_bytes(expect_fp, expected, sizeof(expected), &fp_len) ||
            fp_len != QIHSE_FEDERATION_NODE_FINGERPRINT_BYTES) {
            fprintf(stderr, "issue-node: --fingerprint must be 96 hex chars\n");
            return 2;
        }
        req.expected_fingerprint = expected;
    }

    uint64_t epoch = 0;
    const char* epoch_s = arg_value(argc, argv, "--epoch");
    if (epoch_s && !arg_u64(epoch_s, &epoch)) {
        fprintf(stderr, "issue-node: bad --epoch\n");
        return 2;
    }
    req.enrollment_epoch = epoch;

    if (scope_hex) {
        uint64_t mask = 0;
        if (!arg_u64(scope_hex, &mask) ||
            mask > (uint64_t)QIHSE_SCOPE_ALL) {
            fprintf(stderr, "issue-node: bad --scope-hex\n");
            return 2;
        }
        req.scopes = (qihse_infra_scope_t)mask;
    } else {
        if (!parse_scopes(scope_list, &req.scopes)) {
            fprintf(stderr, "issue-node: unknown scope in --scope list\n");
            return 2;
        }
    }

    int64_t validity = QIHSE_CA_PROVISION_DEFAULT_VALIDITY_S;
    const char* validity_s = arg_value(argc, argv, "--validity");
    if (validity_s && !arg_i64(validity_s, &validity)) {
        fprintf(stderr, "issue-node: bad --validity\n");
        return 2;
    }
    req.validity_s = validity;
    req.not_before_offset_s = 0;
    const char* offset_s = arg_value(argc, argv, "--not-before-offset");
    if (offset_s && !arg_i64(offset_s, &req.not_before_offset_s)) {
        fprintf(stderr, "issue-node: bad --not-before-offset\n");
        return 2;
    }

    qihse_user_t* op = cli_operator(auth_dir ? auth_dir
                              : (getenv("QIHSE_DATA_DIR")
                                     ? getenv("QIHSE_DATA_DIR")
                                     : "build/qihse_ca_provision"));
    if (!op) return 1;

    char cert_pem[QIHSE_FEDERATION_PEM_MAX];
    if (!qihse_ca_provision_issue_node(op, ca_key, &ca, &req,
                                       cert_pem, sizeof(cert_pem))) {
        fprintf(stderr,
                "issue-node: refused (operator must hold node-enroll and every "
                "granted scope; key length must match the algorithm; the CA "
                "key must match the CA certificate; a recorded fingerprint "
                "must still describe the key)\n");
        return 1;
    }
    if (!qihse_ca_provision_write_cert_file(out_path, cert_pem)) {
        fprintf(stderr, "issue-node: cannot write %s\n", out_path);
        return 1;
    }

    uint8_t fp[QIHSE_FEDERATION_NODE_FINGERPRINT_BYTES];
    char fp_hex[97];
    if (qihse_federation_cert_fingerprint(cert_pem, fp)) {
        for (size_t i = 0; i < QIHSE_FEDERATION_NODE_FINGERPRINT_BYTES; i++) {
            snprintf(fp_hex + i * 2, 3, "%02x", fp[i]);
        }
        fp_hex[96] = '\0';
    } else {
        snprintf(fp_hex, sizeof(fp_hex), "(unavailable)");
    }
    printf("node certificate issued\n");
    printf("  certificate : %s\n", out_path);
    printf("  node uuid   : %s\n", node_uuid);
    printf("  epoch       : %llu\n", (unsigned long long)epoch);
    printf("  scopes      : 0x%x\n", (unsigned)req.scopes);
    printf("  fingerprint : %s (unchanged meaning from enrollment)\n", fp_hex);
    return 0;
}

/* ── revoke ────────────────────────────────────────────────────────────── */

static int cmd_revoke(int argc, char** argv) {
    const char* crl = arg_value(argc, argv, "--crl");
    const char* node_uuid = arg_value(argc, argv, "--node-uuid");
    const char* fp_hex = arg_value(argc, argv, "--fingerprint");
    const char* reason = arg_value(argc, argv, "--reason");
    const char* auth_dir = arg_value(argc, argv, "--auth-dir");
    if (!crl || !node_uuid || !reason) {
        fprintf(stderr,
                "revoke: --crl, --node-uuid and --reason are required\n");
        return 2;
    }
    qihse_uuid_t node_id;
    if (!qihse_uuid_parse(node_uuid, &node_id)) {
        fprintf(stderr, "revoke: bad --node-uuid '%s'\n", node_uuid);
        return 2;
    }
    uint8_t fp[QIHSE_FEDERATION_NODE_FINGERPRINT_BYTES];
    uint8_t* fp_ptr = NULL;
    if (fp_hex) {
        size_t fp_len = 0;
        if (!hex_to_bytes(fp_hex, fp, sizeof(fp), &fp_len) ||
            fp_len != QIHSE_FEDERATION_NODE_FINGERPRINT_BYTES) {
            fprintf(stderr, "revoke: --fingerprint must be 96 hex chars\n");
            return 2;
        }
        fp_ptr = fp;
    }
    uint64_t serial = 0;
    const char* serial_s = arg_value(argc, argv, "--serial");
    if (serial_s && !arg_u64(serial_s, &serial)) {
        fprintf(stderr, "revoke: bad --serial\n");
        return 2;
    }

    qihse_user_t* op = cli_operator(auth_dir ? auth_dir
                              : (getenv("QIHSE_DATA_DIR")
                                     ? getenv("QIHSE_DATA_DIR")
                                     : "build/qihse_ca_provision"));
    if (!op) return 1;

    if (!qihse_ca_provision_revoke(op, crl, &node_id, fp_ptr, serial, reason)) {
        fprintf(stderr,
                "revoke: refused (operator must hold node-revoke; reason must "
                "be printable, tab/newline-free, <= 128 chars)\n");
        return 1;
    }
    printf("revocation appended to %s\n", crl);
    return 0;
}

/* ── verify ────────────────────────────────────────────────────────────── */

static int cmd_verify(int argc, char** argv) {
    const char* ca_cert = arg_value(argc, argv, "--ca-cert");
    const char* crl = arg_value(argc, argv, "--crl");
    const char* cert_path = arg_value(argc, argv, "--cert");
    const char* scope_list = arg_value(argc, argv, "--scope");
    const char* scope_hex = arg_value(argc, argv, "--scope-hex");
    const char* now_s = arg_value(argc, argv, "--now");
    if (!ca_cert || !cert_path) {
        fprintf(stderr, "verify: --ca-cert and --cert are required\n");
        return 2;
    }

    qihse_federation_ca_t ca;
    if (!qihse_ca_provision_load_ca(ca_cert, &ca)) {
        fprintf(stderr, "verify: cannot load CA certificate %s\n", ca_cert);
        return 1;
    }
    char cert_pem[QIHSE_FEDERATION_PEM_MAX];
    size_t pem_len = 0;
    FILE* f = fopen(cert_path, "rb");
    if (!f) {
        fprintf(stderr, "verify: cannot read %s\n", cert_path);
        return 1;
    }
    pem_len = fread(cert_pem, 1, sizeof(cert_pem) - 1u, f);
    int ferr = ferror(f);
    fclose(f);
    if (ferr || pem_len == 0) {
        fprintf(stderr, "verify: bad certificate file %s\n", cert_path);
        return 1;
    }
    cert_pem[pem_len] = '\0';

    qihse_infra_scope_t required = QIHSE_SCOPE_NONE;
    if (scope_hex) {
        uint64_t mask = 0;
        if (!arg_u64(scope_hex, &mask)) {
            fprintf(stderr, "verify: bad --scope-hex\n");
            return 2;
        }
        required = (qihse_infra_scope_t)mask;
    } else if (!parse_scopes(scope_list, &required)) {
        fprintf(stderr, "verify: unknown scope in --scope list\n");
        return 2;
    }

    int64_t now = (int64_t)time(NULL);
    if (now_s && !arg_i64(now_s, &now)) {
        fprintf(stderr, "verify: bad --now\n");
        return 2;
    }

    qihse_ca_provision_cert_info_t info;
    qihse_ca_verify_result_t r =
        qihse_ca_provision_verify(&ca, crl, cert_pem, now, required, &info);
    char uuid_str[QIHSE_UUID_STR_LEN + 1u];
    qihse_uuid_format(&info.node_id, uuid_str);
    printf("result     : %s\n", qihse_ca_verify_result_name(r));
    printf("node uuid  : %s\n", uuid_str);
    printf("epoch      : %llu\n", (unsigned long long)info.enrollment_epoch);
    printf("scopes     : 0x%x (required 0x%x)\n", (unsigned)info.scopes,
           (unsigned)required);
    printf("validity   : [%lld, %lld) at %lld\n",
           (long long)info.not_before, (long long)info.not_after,
           (long long)now);
    printf("fingerprint: %s\n", info.fingerprint_hex);
    return r == QIHSE_CA_VERIFY_OK ? 0 : 1;
}

int main(int argc, char** argv) {
    if (argc < 2) {
        usage(stderr);
        return 2;
    }
    const char* cmd = argv[1];
    if (strcmp(cmd, "init-ca") == 0) return cmd_init_ca(argc, argv);
    if (strcmp(cmd, "issue-node") == 0) return cmd_issue_node(argc, argv);
    if (strcmp(cmd, "revoke") == 0) return cmd_revoke(argc, argv);
    if (strcmp(cmd, "verify") == 0) return cmd_verify(argc, argv);
    if (strcmp(cmd, "--help") == 0 || strcmp(cmd, "-h") == 0 ||
        strcmp(cmd, "help") == 0) {
        usage(stdout);
        return 0;
    }
    fprintf(stderr, "qihse-federation-ca: unknown subcommand '%s'\n", cmd);
    usage(stderr);
    return 2;
}
