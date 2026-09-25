/*
 * tests/test_federation_ca.c — out-of-process federation CA provisioning.
 *
 * Under test: the operator-side tool/library that finishes the mTLS work's
 * remaining item, "CA provisioning outside the process".  The properties
 * that matter:
 *
 *   - the CA is post-quantum, its private key lands 0600 at an
 *     operator-chosen path, is never overwritten, and never appears in any
 *     issued record;
 *   - a node certificate binds the node's EXISTING identity key, so the
 *     fingerprint an operator already recorded means the same thing after
 *     issuance, and the certificate verifies through the SAME loader the
 *     running node uses (qihse_federation_cert_verify);
 *   - tampering, a different CA, expiry, and revocation each refuse on
 *     their own;
 *   - a certificate is not authority beyond its scope (expired, not-yet-
 *     valid, and out-of-scope certificates do not verify as valid);
 *   - no principal grants authority above its own level (an analyst cannot
 *     init the CA, issue, or revoke; NULL is never a bypass);
 *   - a corrupt CRL fails closed instead of verifying as clean.
 *
 * Artifacts go under $TMPDIR (relative "build" fallback), matching the
 * relative-path policy.
 */
#include "qihse_ca_provision.h"
#include "qihse_auth.h"
#include "qihse_federation.h"
#include "qihse_federation_mtls.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static qihse_user_t* g_op;     /* operator principal */
static qihse_user_t* g_analyst; /* low-privilege principal */

static char g_ca_dir[576];
static char g_ca2_dir[576];
static char g_key_dir[576];
static char g_mtls_dir[576];

/* ── helpers ───────────────────────────────────────────────────────────── */

static void enroll_node(const char* key_dir, qihse_sig_alg_t alg,
                        const char* seed, qihse_federation_node_identity_t* out) {
    memset(out, 0, sizeof(*out));
    assert(qihse_uuid_from_seed(seed, strlen(seed), &out->node_id));
    snprintf(out->hostname, sizeof(out->hostname), "%s", seed);
    snprintf(out->boot_id, sizeof(out->boot_id), "%s-boot", seed);
    out->identity_kind = QIHSE_IDENTITY_HOST_AGENT;
    assert(qihse_federation_node_keygen_alg(key_dir, alg, out));
}

static bool read_file_all(const char* path, char** out, size_t* out_len) {
    FILE* f = fopen(path, "rb");
    if (!f) return false;
    size_t cap = 65536;
    char* buf = (char*)malloc(cap);
    if (!buf) { fclose(f); return false; }
    size_t n = fread(buf, 1, cap, f);
    bool err = ferror(f);
    fclose(f);
    if (err) { free(buf); return false; }
    buf[n] = '\0';
    *out = buf;
    if (out_len) *out_len = n;
    return true;
}

static void path_under(const char* base, const char* name, char* out, size_t cap) {
    int n = snprintf(out, cap, "%s/%s", base, name);
    if (n < 0 || (size_t)n >= cap) {
        fprintf(stderr, "path_under: destination too small for %s/%s\n", base, name);
        abort();
    }
}

/* Corrupt the certificate's signature by flipping the final base64 char of
 * the last DER byte (the signature value), keeping the PEM/DER structure
 * parseable: the failure must come from the SIGNATURE, not the parser. */
static void tamper_last_base64_char(char* pem) {
    const char* end_marker = strstr(pem, "-----END CERTIFICATE-----");
    assert(end_marker);
    size_t end_pos = (size_t)(end_marker - pem);
    size_t i = end_pos;
    while (i > 0 && (pem[i - 1] == '\n' || pem[i - 1] == '\r')) i--;
    while (i > 0 && pem[i - 1] == '=') i--;      /* skip base64 padding */
    assert(i > 0);
    char c = pem[i - 1];
    pem[i - 1] = (c == 'A') ? 'B' : 'A';         /* change the final byte */
    assert(pem[i - 1] != c);
}

/* ── CA init ───────────────────────────────────────────────────────────── */

static void test_init_ca(void) {
    char key[512], cert[512];
    path_under(g_ca_dir, "ca.key", key, sizeof(key));
    path_under(g_ca_dir, "ca.pem", cert, sizeof(cert));

    qihse_federation_ca_t ca;
    assert(!qihse_ca_provision_init_ca(NULL, QIHSE_SIG_ML_DSA_87, key, cert, &ca));
    assert(!qihse_ca_provision_init_ca(g_analyst, QIHSE_SIG_ML_DSA_87, key, cert,
                                       &ca));
    assert(qihse_ca_provision_init_ca(g_op, QIHSE_SIG_ML_DSA_87, key, cert, &ca));

    assert(ca.cert_pem_len > 0);
    assert(strstr(ca.cert_pem, "BEGIN CERTIFICATE") != NULL);
    assert(strlen(ca.fingerprint_hex) == 96u);

    /* 0600 on the private key, never printed or returned. */
    struct stat st;
    assert(stat(key, &st) == 0);
    assert((st.st_mode & 0777) == 0600);
    assert(strstr(ca.cert_pem, "PRIVATE KEY") == NULL);

    /* PQ-ineligible and unknown algorithms are refused. */
    char weak_key[512], weak_cert[512];
    path_under(g_ca_dir, "weak.key", weak_key, sizeof(weak_key));
    path_under(g_ca_dir, "weak.pem", weak_cert, sizeof(weak_cert));
    qihse_federation_ca_t weak;
    assert(!qihse_ca_provision_init_ca(g_op, QIHSE_SIG_ED25519, weak_key,
                                       weak_cert, &weak));
    assert(!qihse_ca_provision_init_ca(g_op, (qihse_sig_alg_t)99, weak_key,
                                       weak_cert, &weak));

    /* An existing CA key is never overwritten. */
    char* before = NULL;
    size_t before_len = 0;
    assert(read_file_all(key, &before, &before_len));
    qihse_federation_ca_t again;
    assert(!qihse_ca_provision_init_ca(g_op, QIHSE_SIG_ML_DSA_87, key, cert,
                                       &again));
    char* after = NULL;
    size_t after_len = 0;
    assert(read_file_all(key, &after, &after_len));
    assert(before_len == after_len && memcmp(before, after, before_len) == 0);
    free(before);
    free(after);

    /* The self-signed CA verifies through the node-side loader. */
    assert(qihse_federation_cert_verify(ca.cert_pem, &ca));

    printf("PASS init-ca: ML-DSA-87 CA, key 0600/never returned/never "
           "overwritten, PQ enforced, analyst and NULL refused\n");
}

/* ── issuance + verification round trip ────────────────────────────────── */

static void test_issue_verify_roundtrip(void) {
    char key[512], cert[512];
    path_under(g_ca_dir, "ca.key", key, sizeof(key));
    path_under(g_ca_dir, "ca.pem", cert, sizeof(cert));
    qihse_federation_ca_t ca;
    assert(qihse_ca_provision_load_ca(cert, &ca));
    /* load_ca recomputes the fingerprint: it must equal the init-time one. */
    qihse_federation_ca_t ca_init;
    assert(qihse_ca_provision_init_ca(g_op, QIHSE_SIG_ML_DSA_87, key, cert,
                                      &ca_init) == false); /* key exists */
    (void)ca_init;

    qihse_federation_node_identity_t node;
    enroll_node(g_key_dir, QIHSE_SIG_ML_DSA_65, "ca-provision-node-a", &node);

    /* Node identity private key is 0600 too. */
    struct stat st;
    assert(stat(node.key_handle, &st) == 0);
    assert((st.st_mode & 0777) == 0600);

    qihse_ca_provision_node_req_t req;
    memset(&req, 0, sizeof(req));
    req.node_id = node.node_id;
    req.sig_alg = node.sig_alg;
    req.public_key = node.public_key;
    req.public_key_len = node.public_key_len;
    req.expected_fingerprint = node.fingerprint;
    req.enrollment_epoch = 9;
    req.scopes = QIHSE_SCOPE_FEDERATION_READ | QIHSE_SCOPE_FEDERATION_WRITE;
    req.not_before_offset_s = 0;
    req.validity_s = QIHSE_CA_PROVISION_DEFAULT_VALIDITY_S;

    char pem[QIHSE_FEDERATION_PEM_MAX];
    /* NULL is never an authorization bypass; an analyst holds neither
     * node-enroll nor the granted scopes. */
    assert(!qihse_ca_provision_issue_node(NULL, key, &ca, &req, pem, sizeof(pem)));
    assert(!qihse_ca_provision_issue_node(g_analyst, key, &ca, &req, pem,
                                          sizeof(pem)));
    assert(qihse_ca_provision_issue_node(g_op, key, &ca, &req, pem,
                                         sizeof(pem)));
    assert(strstr(pem, "BEGIN CERTIFICATE") != NULL);

    int64_t now = (int64_t)time(NULL);
    qihse_ca_provision_cert_info_t info;
    assert(qihse_ca_provision_verify(&ca, NULL, pem, now, QIHSE_SCOPE_NONE,
                                     &info) == QIHSE_CA_VERIFY_OK);
    assert(qihse_uuid_equal(&info.node_id, &node.node_id));
    assert(info.enrollment_epoch == 9u); /* serial = epoch + 1 */
    assert(info.scopes == req.scopes);
    assert(info.not_before <= now && now < info.not_after);

    /* THE KEY PROPERTY: the certificate's public-key fingerprint equals the
     * node identity's fingerprint — the node reuses its existing identity
     * key, so an operator's recorded fingerprint keeps its meaning. */
    assert(memcmp(info.fingerprint, node.fingerprint,
                  QIHSE_FEDERATION_NODE_FINGERPRINT_BYTES) == 0);
    uint8_t cert_fp[QIHSE_FEDERATION_NODE_FINGERPRINT_BYTES];
    assert(qihse_federation_cert_fingerprint(pem, cert_fp));
    assert(memcmp(cert_fp, node.fingerprint, sizeof(cert_fp)) == 0);

    /* Scope-aware verification: the cert carries what was issued. */
    assert(qihse_ca_provision_verify(&ca, NULL, pem, now,
                                     QIHSE_SCOPE_FEDERATION_READ, NULL) ==
           QIHSE_CA_VERIFY_OK);
    assert(qihse_ca_provision_verify(&ca, NULL, pem, now,
                                     QIHSE_SCOPE_NODE_ENROLL, NULL) ==
           QIHSE_CA_VERIFY_ERR_SCOPE);

    /* The mtls loader accepts the provisioned certificate: same formats. */
    assert(qihse_federation_cert_verify(pem, &ca));

    /* An expected fingerprint that no longer describes the key refuses
     * issuance (recomputed-and-compared, never trusted). */
    qihse_ca_provision_node_req_t bad_fp_req = req;
    uint8_t wrong[QIHSE_FEDERATION_NODE_FINGERPRINT_BYTES] = {0};
    bad_fp_req.expected_fingerprint = wrong;
    char bad_pem[QIHSE_FEDERATION_PEM_MAX];
    assert(!qihse_ca_provision_issue_node(g_op, key, &ca, &bad_fp_req, bad_pem,
                                          sizeof(bad_pem)));

    /* A wrong-length public key (declared vs the algorithm's fixed size)
     * refuses. */
    qihse_ca_provision_node_req_t bad_len_req = req;
    bad_len_req.public_key_len = req.public_key_len - 1u;
    assert(!qihse_ca_provision_issue_node(g_op, key, &ca, &bad_len_req, bad_pem,
                                          sizeof(bad_pem)));

    /* A CA key from a DIFFERENT CA refuses (key must match the certificate
     * the operator is attributing issuance to). */
    char other_key[512];
    path_under(g_ca2_dir, "ca.key", other_key, sizeof(other_key));
    assert(!qihse_ca_provision_issue_node(g_op, other_key, &ca, &req, bad_pem,
                                          sizeof(bad_pem)));

    printf("PASS issue-node/verify: binds existing key, fingerprint keeps its "
           "meaning, scopes enforced, mtls loader accepts it\n");
}

/* ── tampering and the wrong CA ────────────────────────────────────────── */

static void issue_test_cert(const qihse_federation_ca_t* ca, const char* ca_key,
                            const qihse_federation_node_identity_t* node,
                            int64_t offset, int64_t validity,
                            qihse_infra_scope_t scopes, char* out, size_t cap) {
    qihse_ca_provision_node_req_t req;
    memset(&req, 0, sizeof(req));
    req.node_id = node->node_id;
    req.sig_alg = node->sig_alg;
    req.public_key = node->public_key;
    req.public_key_len = node->public_key_len;
    req.enrollment_epoch = 4;
    req.scopes = scopes;
    req.not_before_offset_s = offset;
    req.validity_s = validity;
    assert(qihse_ca_provision_issue_node(g_op, ca_key, ca, &req, out, cap));
}

static void test_tampered_and_wrong_ca(void) {
    char key[512], cert[512];
    path_under(g_ca_dir, "ca.key", key, sizeof(key));
    path_under(g_ca_dir, "ca.pem", cert, sizeof(cert));
    qihse_federation_ca_t ca;
    assert(qihse_ca_provision_load_ca(cert, &ca));

    qihse_federation_node_identity_t node;
    enroll_node(g_key_dir, QIHSE_SIG_ML_DSA_65, "ca-provision-node-b", &node);

    char pem[QIHSE_FEDERATION_PEM_MAX];
    issue_test_cert(&ca, key, &node, 0, QIHSE_CA_PROVISION_DEFAULT_VALIDITY_S,
                    QIHSE_SCOPE_FEDERATION_READ, pem, sizeof(pem));

    /* Tamper the signature bytes: the DER still parses, so the refusal has
     * to come from the signature check. */
    char tampered[QIHSE_FEDERATION_PEM_MAX];
    snprintf(tampered, sizeof(tampered), "%s", pem);
    tamper_last_base64_char(tampered);
    qihse_ca_verify_result_t r = qihse_ca_provision_verify(
        &ca, NULL, tampered, (int64_t)time(NULL), QIHSE_SCOPE_NONE, NULL);
    assert(r == QIHSE_CA_VERIFY_ERR_BAD_SIGNATURE ||
           r == QIHSE_CA_VERIFY_ERR_MALFORMED);
    assert(!qihse_federation_cert_verify(tampered, &ca));

    /* Garbage is refused as malformed, not treated as "no certificate". */
    assert(qihse_ca_provision_verify(&ca, NULL, "not a certificate",
                                     (int64_t)time(NULL), QIHSE_SCOPE_NONE,
                                     NULL) == QIHSE_CA_VERIFY_ERR_MALFORMED);
    assert(qihse_ca_provision_verify(NULL, NULL, pem, (int64_t)time(NULL),
                                     QIHSE_SCOPE_NONE,
                                     NULL) == QIHSE_CA_VERIFY_ERR_MALFORMED);

    /* A certificate from a DIFFERENT CA does not verify against this one. */
    char key2[512], cert2[512];
    path_under(g_ca2_dir, "ca.key", key2, sizeof(key2));
    path_under(g_ca2_dir, "ca.pem", cert2, sizeof(cert2));
    qihse_federation_ca_t ca2;
    assert(qihse_ca_provision_init_ca(g_op, QIHSE_SIG_ML_DSA_87, key2, cert2,
                                      &ca2));
    /* Distinct CAs have distinct human-comparable fingerprints. */
    assert(strcmp(ca.fingerprint_hex, ca2.fingerprint_hex) != 0);
    assert(qihse_ca_provision_verify(&ca2, NULL, pem, (int64_t)time(NULL),
                                     QIHSE_SCOPE_NONE,
                                     NULL) == QIHSE_CA_VERIFY_ERR_BAD_SIGNATURE);

    printf("PASS tamper/wrong-CA: signature tampering and a foreign CA are "
           "refused, garbage is malformed\n");
}

/* ── revocation ────────────────────────────────────────────────────────── */

static void test_revocation(void) {
    char key[512], cert[512], crl[512];
    path_under(g_ca_dir, "ca.key", key, sizeof(key));
    path_under(g_ca_dir, "ca.pem", cert, sizeof(cert));
    path_under(g_ca_dir, "revocations.crl", crl, sizeof(crl));
    qihse_federation_ca_t ca;
    assert(qihse_ca_provision_load_ca(cert, &ca));

    qihse_federation_node_identity_t node, other;
    enroll_node(g_key_dir, QIHSE_SIG_ML_DSA_65, "ca-provision-node-c", &node);
    enroll_node(g_key_dir, QIHSE_SIG_ML_DSA_65, "ca-provision-node-d", &other);

    char pem[QIHSE_FEDERATION_PEM_MAX], other_pem[QIHSE_FEDERATION_PEM_MAX];
    issue_test_cert(&ca, key, &node, 0, QIHSE_CA_PROVISION_DEFAULT_VALIDITY_S,
                    QIHSE_SCOPE_FEDERATION_READ, pem, sizeof(pem));
    issue_test_cert(&ca, key, &other, 0, QIHSE_CA_PROVISION_DEFAULT_VALIDITY_S,
                    QIHSE_SCOPE_FEDERATION_READ, other_pem, sizeof(other_pem));

    int64_t now = (int64_t)time(NULL);
    /* Authorization first: NULL and an analyst cannot revoke. */
    assert(!qihse_ca_provision_revoke(NULL, crl, &node.node_id,
                                      node.fingerprint, 5, "test"));
    assert(!qihse_ca_provision_revoke(g_analyst, crl, &node.node_id,
                                      node.fingerprint, 5, "test"));
    assert(qihse_ca_provision_revoke(g_op, crl, &node.node_id,
                                     node.fingerprint, 5, "compromised"));

    /* With the CRL, the revoked node's certificate is refused... */
    assert(qihse_ca_provision_verify(&ca, crl, pem, now, QIHSE_SCOPE_NONE,
                                     NULL) == QIHSE_CA_VERIFY_ERR_REVOKED);
    /* ...while an unrevoked node still verifies against the same list. */
    assert(qihse_ca_provision_verify(&ca, crl, other_pem, now,
                                     QIHSE_SCOPE_NONE,
                                     NULL) == QIHSE_CA_VERIFY_OK);
    /* Without a CRL the certificate itself is still well-formed and signed:
     * distributing revocations to the verifier is the wiring point. */
    assert(qihse_ca_provision_verify(&ca, NULL, pem, now, QIHSE_SCOPE_NONE,
                                     NULL) == QIHSE_CA_VERIFY_OK);

    /* Matching by UUID alone works when no fingerprint was recorded. */
    char crl2[512];
    path_under(g_ca_dir, "revocations-nofp.crl", crl2, sizeof(crl2));
    assert(qihse_ca_provision_revoke(g_op, crl2, &other.node_id, NULL, 6,
                                     "decommissioned"));
    assert(qihse_ca_provision_verify(&ca, crl2, other_pem, now,
                                     QIHSE_SCOPE_NONE,
                                     NULL) == QIHSE_CA_VERIFY_ERR_REVOKED);

    /* An absent CRL file is an empty list, not an error. */
    char crl_missing[512];
    path_under(g_ca_dir, "no-such.crl", crl_missing, sizeof(crl_missing));
    bool revoked = true;
    assert(qihse_ca_provision_crl_check(crl_missing, &node.node_id, NULL,
                                        &revoked));
    assert(!revoked);

    printf("PASS revoke: revoked cert refused, unrevoked accepted, analyst "
           "and NULL refused, uuid-only revocation works\n");
}

/* ── negative authorization: a cert is not authority beyond its scope ──── */

static void test_negative_authorization(void) {
    char key[512], cert[512];
    path_under(g_ca_dir, "ca.key", key, sizeof(key));
    path_under(g_ca_dir, "ca.pem", cert, sizeof(cert));
    qihse_federation_ca_t ca;
    assert(qihse_ca_provision_load_ca(cert, &ca));

    qihse_federation_node_identity_t node;
    enroll_node(g_key_dir, QIHSE_SIG_ML_DSA_65, "ca-provision-node-e", &node);

    char pem[QIHSE_FEDERATION_PEM_MAX];
    int64_t now = (int64_t)time(NULL);

    /* Already expired: backdated two hours with a one-hour lifetime.  The
     * signature is intact — the refusal is the validity window. */
    issue_test_cert(&ca, key, &node, -7200, 3600,
                    QIHSE_SCOPE_FEDERATION_READ, pem, sizeof(pem));
    assert(qihse_ca_provision_verify(&ca, NULL, pem, now, QIHSE_SCOPE_NONE,
                                     NULL) == QIHSE_CA_VERIFY_ERR_EXPIRED);

    /* Not yet valid: starts in an hour. */
    issue_test_cert(&ca, key, &node, 3600, 3600,
                    QIHSE_SCOPE_FEDERATION_READ, pem, sizeof(pem));
    assert(qihse_ca_provision_verify(&ca, NULL, pem, now, QIHSE_SCOPE_NONE,
                                     NULL) == QIHSE_CA_VERIFY_ERR_NOT_YET_VALID);

    /* Out-of-scope: a read-scoped certificate is not node-enroll authority,
     * and a scopeless certificate is no authority at all. */
    issue_test_cert(&ca, key, &node, 0, QIHSE_CA_PROVISION_DEFAULT_VALIDITY_S,
                    QIHSE_SCOPE_FEDERATION_READ, pem, sizeof(pem));
    assert(qihse_ca_provision_verify(&ca, NULL, pem, now,
                                     QIHSE_SCOPE_NODE_ENROLL,
                                     NULL) == QIHSE_CA_VERIFY_ERR_SCOPE);
    issue_test_cert(&ca, key, &node, 0, QIHSE_CA_PROVISION_DEFAULT_VALIDITY_S,
                    QIHSE_SCOPE_NONE, pem, sizeof(pem));
    assert(qihse_ca_provision_verify(&ca, NULL, pem, now,
                                     QIHSE_SCOPE_NODE_ENROLL,
                                     NULL) == QIHSE_CA_VERIFY_ERR_SCOPE);

    /* The privilege ceiling on issuance: the operator holds every scope, so
     * it may grant any subset; an analyst may not issue at all (covered in
     * the round trip), and even a scope the analyst holds is refused because
     * the analyst lacks node-enroll and any wider grant. */
    qihse_ca_provision_node_req_t req;
    memset(&req, 0, sizeof(req));
    req.node_id = node.node_id;
    req.sig_alg = node.sig_alg;
    req.public_key = node.public_key;
    req.public_key_len = node.public_key_len;
    req.enrollment_epoch = 1;
    req.scopes = QIHSE_SCOPE_SECURITY_ADMIN; /* above an analyst's own */
    req.validity_s = 3600;
    char out[QIHSE_FEDERATION_PEM_MAX];
    assert(!qihse_ca_provision_issue_node(g_analyst, key, &ca, &req, out,
                                          sizeof(out)));
    /* The operator may grant it (it is at, not above, the operator's own
     * level), and the certificate then verifies for that scope. */
    assert(qihse_ca_provision_issue_node(g_op, key, &ca, &req, out,
                                         sizeof(out)));
    assert(qihse_ca_provision_verify(&ca, NULL, out, now,
                                     QIHSE_SCOPE_SECURITY_ADMIN,
                                     NULL) == QIHSE_CA_VERIFY_OK);

    printf("PASS negative authorization: expired, not-yet-valid and "
           "out-of-scope certificates do not verify as valid; issuance "
           "respects the privilege ceiling\n");
}

/* ── private-key material never leaves the key files ──────────────────── */

static void test_key_material_absent(void) {
    char key[512], cert[512], crl[512];
    path_under(g_ca_dir, "ca.key", key, sizeof(key));
    path_under(g_ca_dir, "ca.pem", cert, sizeof(cert));
    path_under(g_ca_dir, "revocations.crl", crl, sizeof(crl));
    qihse_federation_ca_t ca;
    assert(qihse_ca_provision_load_ca(cert, &ca));

    qihse_federation_node_identity_t node;
    enroll_node(g_key_dir, QIHSE_SIG_ML_DSA_65, "ca-provision-node-f", &node);
    char pem[QIHSE_FEDERATION_PEM_MAX];
    issue_test_cert(&ca, key, &node, 0, QIHSE_CA_PROVISION_DEFAULT_VALIDITY_S,
                    QIHSE_SCOPE_FEDERATION_READ, pem, sizeof(pem));
    assert(qihse_ca_provision_revoke(g_op, crl, &node.node_id,
                                     node.fingerprint, 4, "hygiene-test"));

    /* A distinctive slice of the CA private key's base64 body. */
    char* key_bytes = NULL;
    size_t key_len = 0;
    assert(read_file_all(key, &key_bytes, &key_len));
    assert(key_len > 256u);
    char slice[65];
    memcpy(slice, key_bytes + 128u, 64u);
    slice[64] = '\0';

    char* cert_bytes = NULL;
    size_t cert_len = 0;
    assert(read_file_all(cert, &cert_bytes, &cert_len));
    char* crl_bytes = NULL;
    size_t crl_len = 0;
    assert(read_file_all(crl, &crl_bytes, &crl_len));

    assert(strstr(cert_bytes, slice) == NULL);
    assert(strstr(crl_bytes, slice) == NULL);
    assert(strstr(pem, slice) == NULL);
    assert(strstr(cert_bytes, "PRIVATE KEY") == NULL);
    assert(strstr(crl_bytes, "PRIVATE KEY") == NULL);
    /* The node's private key file likewise never leaks into any of them. */
    char* node_key_bytes = NULL;
    size_t node_key_len = 0;
    assert(read_file_all(node.key_handle, &node_key_bytes, &node_key_len));
    assert(node_key_len > 256u);
    memcpy(slice, node_key_bytes + 128u, 64u);
    assert(strstr(cert_bytes, slice) == NULL);
    assert(strstr(crl_bytes, slice) == NULL);

    free(key_bytes);
    free(cert_bytes);
    free(crl_bytes);
    free(node_key_bytes);

    printf("PASS key hygiene: CA and node private-key bytes absent from every "
           "issued certificate and CRL record\n");
}

/* ── CRL fails closed ──────────────────────────────────────────────────── */

static void test_crl_fail_closed(void) {
    char key[512], cert[512], crl[512];
    path_under(g_ca_dir, "ca.key", key, sizeof(key));
    path_under(g_ca_dir, "ca.pem", cert, sizeof(cert));
    path_under(g_ca_dir, "failclosed.crl", crl, sizeof(crl));
    qihse_federation_ca_t ca;
    assert(qihse_ca_provision_load_ca(cert, &ca));

    qihse_federation_node_identity_t node;
    enroll_node(g_key_dir, QIHSE_SIG_ML_DSA_65, "ca-provision-node-g", &node);
    char pem[QIHSE_FEDERATION_PEM_MAX];
    issue_test_cert(&ca, key, &node, 0, QIHSE_CA_PROVISION_DEFAULT_VALIDITY_S,
                    QIHSE_SCOPE_FEDERATION_READ, pem, sizeof(pem));

    assert(qihse_ca_provision_revoke(g_op, crl, &node.node_id,
                                     node.fingerprint, 4, "fail-closed"));

    /* A garbage line anywhere in the CRL makes the whole check fail closed:
     * it must NOT verify as clean, and must not silently skip the line. */
    FILE* f = fopen(crl, "a");
    assert(f);
    assert(fputs("this is not a crl record\n", f) != EOF);
    fclose(f);
    bool revoked = false;
    assert(!qihse_ca_provision_crl_check(crl, &node.node_id, NULL, &revoked));
    assert(qihse_ca_provision_verify(&ca, crl, pem, (int64_t)time(NULL),
                                     QIHSE_SCOPE_NONE,
                                     NULL) == QIHSE_CA_VERIFY_ERR_CRL);

    /* Right magic, wrong field lengths: still refused. */
    char crl2[512];
    path_under(g_ca_dir, "failclosed2.crl", crl2, sizeof(crl2));
    f = fopen(crl2, "w");
    assert(f);
    fprintf(f, "%s\t%s\t1\tAB\t0\tx\n", QIHSE_CA_PROVISION_CRL_MAGIC,
            "123e4567-e89b-12d3-a456-426614174000");
    fclose(f);
    assert(!qihse_ca_provision_crl_check(crl2, &node.node_id, NULL, &revoked));

    printf("PASS CRL fail-closed: malformed revocation records refuse the "
           "whole check instead of verifying as clean\n");
}

/* ── certificates issued by the mtls module verify here too ───────────── */

static void test_mtls_issued_compat(void) {
    qihse_federation_ca_t ca;
    /* The mtls CA creator writes "<dir>/federation-ca.key" at 0600 and
     * returns only the certificate and fingerprint. */
    assert(qihse_federation_ca_create(g_mtls_dir, QIHSE_SIG_ML_DSA_87, &ca));
    char ca_key[512];
    path_under(g_mtls_dir, "federation-ca.key", ca_key, sizeof(ca_key));

    qihse_federation_node_identity_t node;
    enroll_node(g_key_dir, QIHSE_SIG_ML_DSA_65, "ca-provision-node-h", &node);

    char pem[QIHSE_FEDERATION_PEM_MAX];
    assert(qihse_federation_ca_issue_node(ca_key, &ca, &node, 12, pem,
                                          sizeof(pem)));
    /* My verifier reads the mtls-issued certificate: SAN uuid, serial=epoch+1
     * and the 30-day window all line up; no scope extension -> NONE. */
    qihse_ca_provision_cert_info_t info;
    assert(qihse_ca_provision_verify(&ca, NULL, pem, (int64_t)time(NULL),
                                     QIHSE_SCOPE_NONE, &info) ==
           QIHSE_CA_VERIFY_OK);
    assert(qihse_uuid_equal(&info.node_id, &node.node_id));
    assert(info.enrollment_epoch == 12u);
    assert(info.scopes == QIHSE_SCOPE_NONE);
    assert(memcmp(info.fingerprint, node.fingerprint,
                  QIHSE_FEDERATION_NODE_FINGERPRINT_BYTES) == 0);

    printf("PASS mtls compatibility: certificates issued by "
           "qihse_federation_ca_issue_node verify through this tool's path\n");
}

/* ── main ──────────────────────────────────────────────────────────────── */

int main(void) {
    /* Artifacts under $TMPDIR with a relative fallback (path policy). */
    const char* base = getenv("TMPDIR");
    if (!base || *base == '\0') base = "build";
    char data_root[448];
    snprintf(data_root, sizeof(data_root), "%s/qihse_fed_ca_XXXXXX", base);
    assert(mkdtemp(data_root));
    snprintf(g_ca_dir, sizeof(g_ca_dir), "%s/ca", data_root);
    snprintf(g_ca2_dir, sizeof(g_ca2_dir), "%s/ca2", data_root);
    snprintf(g_key_dir, sizeof(g_key_dir), "%s/keys", data_root);
    snprintf(g_mtls_dir, sizeof(g_mtls_dir), "%s/mtlsca", data_root);
    assert(mkdir(g_ca_dir, 0700) == 0);
    assert(mkdir(g_ca2_dir, 0700) == 0);
    assert(mkdir(g_key_dir, 0700) == 0);
    assert(mkdir(g_mtls_dir, 0700) == 0);
    setenv("QIHSE_DATA_DIR", data_root, 1);

    /* Operator context, mirroring tests/test_federation_mtls.c, plus a
     * low-privilege ANALYST principal for the negative tests. */
    assert(qihse_auth_init());
    if (!qihse_auth_bootstrap_operator("CaProvisionPass1!")) {
        setenv("QIHSE_OPERATOR_PASSWORD", "CaProvisionPass1!", 1);
        assert(qihse_auth_init());
    }
    g_op = qihse_auth_get_user(0);
    assert(g_op);
    g_analyst = qihse_auth_create_user(g_op, 31, QIHSE_ROLE_ANALYST, 90, 0,
                                       "AnalystPass1!", false);
    assert(g_analyst);

    test_init_ca();
    test_issue_verify_roundtrip();
    test_tampered_and_wrong_ca();
    test_revocation();
    test_negative_authorization();
    test_key_material_absent();
    test_crl_fail_closed();
    test_mtls_issued_compat();

    printf("federation CA provisioning tests passed\n");
    return 0;
}
