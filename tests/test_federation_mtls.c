/*
 * test_federation_mtls.c — post-quantum mutual authentication for federation RPC.
 *
 * The claim under test is the one the brief makes explicitly: a valid
 * certificate proves IDENTITY, not current TRUSTWORTHINESS.  The three layers
 * are therefore tested separately, and the test asserts that each layer can
 * refuse on its own:
 *
 *   layer 1  TLS key possession      (out of scope here: no sockets)
 *   layer 2  enrolled fingerprint    -> unknown / pending / revoked
 *   layer 3  runtime trust state     -> LOCAL_ONLY withholds the session
 */
#include "qihse_auth.h"
#include "qihse_federation.h"
#include "qihse_federation_mtls.h"
#include "qihse_kv_store.h"
#include "qihse_runtime_trust.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

static qihse_kv_store_t* g_store;
static qihse_user_t* g_op;

/* Enroll and approve a node with the given algorithm, returning its identity. */
static void enroll_node(const char* key_dir, qihse_sig_alg_t alg,
                        const char* seed, qihse_federation_node_identity_t* out) {
    memset(out, 0, sizeof(*out));
    assert(qihse_uuid_from_seed(seed, strlen(seed), &out->node_id));
    snprintf(out->hostname, sizeof(out->hostname), "%s", seed);
    snprintf(out->boot_id, sizeof(out->boot_id), "%s-boot", seed);
    out->identity_kind = QIHSE_IDENTITY_HOST_AGENT;
    assert(qihse_federation_node_keygen_alg(key_dir, alg, out));
}

/* ── CA creation ───────────────────────────────────────────────────────── */

static void test_ca_creation(const char* dir) {
    qihse_federation_ca_t ca;
    assert(qihse_federation_ca_create(dir, QIHSE_SIG_ML_DSA_87, &ca));
    assert(ca.cert_pem_len > 0);
    assert(strstr(ca.cert_pem, "BEGIN CERTIFICATE") != NULL);
    assert(strlen(ca.fingerprint_hex) == 96u);

    /* The CA private key exists, is 0600, and is NOT in the returned struct:
     * the database process must not be able to mint its own authority. */
    char key_path[512];
    snprintf(key_path, sizeof(key_path), "%s/federation-ca.key", dir);
    struct stat st;
    assert(stat(key_path, &st) == 0);
    assert((st.st_mode & 0777) == 0600);
    assert(strstr(ca.cert_pem, "PRIVATE KEY") == NULL);

    /* A pre-quantum CA is refused: the CA is the root of every identity in the
     * federation, so it is the last place to accept a quantum-vulnerable key. */
    qihse_federation_ca_t weak;
    assert(!qihse_federation_ca_create(dir, QIHSE_SIG_ED25519, &weak));

    printf("PASS CA creation: ML-DSA-87 self-signed CA, key 0600 and never returned, PQ enforced\n");
}

/* ── Certificate issuance ──────────────────────────────────────────────── */

static void test_issuance_and_binding(const char* dir, const char* key_dir) {
    qihse_federation_ca_t ca;
    assert(qihse_federation_ca_create(dir, QIHSE_SIG_ML_DSA_87, &ca));
    char ca_key_path[512];
    snprintf(ca_key_path, sizeof(ca_key_path), "%s/federation-ca.key", dir);

    qihse_federation_node_identity_t node;
    enroll_node(key_dir, QIHSE_SIG_ML_DSA_65, "mtls-node-a", &node);

    char cert[QIHSE_FEDERATION_PEM_MAX];
    assert(qihse_federation_ca_issue_node(ca_key_path, &ca, &node, 7, cert, sizeof(cert)));
    assert(strstr(cert, "BEGIN CERTIFICATE") != NULL);

    /* The certificate's own signature verifies against the CA. */
    assert(qihse_federation_cert_verify(cert, &ca));

    /* THE KEY PROPERTY: the certificate's public-key fingerprint must equal the
     * node identity's fingerprint.  The node reuses its existing identity key
     * as the certificate key, so a fingerprint an operator already recorded
     * keeps meaning exactly the same thing after enrollment. */
    uint8_t cert_fp[QIHSE_FEDERATION_NODE_FINGERPRINT_BYTES];
    assert(qihse_federation_cert_fingerprint(cert, cert_fp));
    assert(memcmp(cert_fp, node.fingerprint, sizeof(cert_fp)) == 0);

    /* A certificate from a DIFFERENT CA must not verify against this one. */
    char other_dir[512];
    snprintf(other_dir, sizeof(other_dir), "%s/otherca", dir);
    assert(mkdir(other_dir, 0700) == 0);
    qihse_federation_ca_t other_ca;
    assert(qihse_federation_ca_create(other_dir, QIHSE_SIG_ML_DSA_87, &other_ca));
    assert(!qihse_federation_cert_verify(cert, &other_ca));
    /* ...and a substituted CA is detectable by a human-readable fingerprint. */
    assert(strcmp(ca.fingerprint_hex, other_ca.fingerprint_hex) != 0);

    /* Issuing with a missing CA key fails rather than silently producing an
     * unsigned certificate. */
    char bad_cert[QIHSE_FEDERATION_PEM_MAX];
    assert(!qihse_federation_ca_issue_node("/nonexistent/ca.key", &ca, &node, 7,
                                          bad_cert, sizeof(bad_cert)));

    printf("PASS issuance: cert binds the node key, verifies against its CA, other CAs rejected\n");
}

/* ── The three-layer peer decision ─────────────────────────────────────── */

static void test_peer_verify_layers(const char* dir, const char* key_dir) {
    qihse_federation_ca_t ca;
    assert(qihse_federation_ca_create(dir, QIHSE_SIG_ML_DSA_87, &ca));
    char ca_key_path[512];
    snprintf(ca_key_path, sizeof(ca_key_path), "%s/federation-ca.key", dir);

    qihse_federation_node_identity_t node;
    enroll_node(key_dir, QIHSE_SIG_ML_DSA_65, "mtls-peer", &node);

    char cert[QIHSE_FEDERATION_PEM_MAX];
    assert(qihse_federation_ca_issue_node(ca_key_path, &ca, &node, 3, cert, sizeof(cert)));
    uint8_t fp[QIHSE_FEDERATION_NODE_FINGERPRINT_BYTES];
    assert(qihse_federation_cert_fingerprint(cert, fp));

    qihse_uuid_t resolved;
    qihse_runtime_trust_t trust;

    /* Layer 2 refusal: the certificate is valid and CA-signed, but no enrolled
     * node has this fingerprint.  A credential for an identity we do not know
     * is not a peer. */
    qihse_peer_verdict_t v = qihse_federation_peer_verify(g_store, g_op, fp,
                                                         sizeof(fp), &resolved, &trust);
    assert(v == QIHSE_PEER_REJECT_UNKNOWN_FINGERPRINT);

    /* Enrolled but PENDING: layer 2 again, a different reason. */
    assert(qihse_federation_node_enroll_request(g_store, g_op, &node));
    v = qihse_federation_peer_verify(g_store, g_op, fp, sizeof(fp), &resolved, &trust);
    assert(v == QIHSE_PEER_REJECT_NOT_YET_APPROVED);

    /* Approved, with NO runtime evidence yet.  The brief requires runtime
     * evidence before voter or strong-write authority, not before a session,
     * so the session is granted and the caller learns the node is UNKNOWN.
     * Refusing outright would make enrollment useless. */
    assert(qihse_federation_node_enroll_approve(g_store, g_op, &node.node_id, 3));
    v = qihse_federation_peer_verify(g_store, g_op, fp, sizeof(fp), &resolved, &trust);
    assert(v == QIHSE_PEER_ACCEPT);
    assert(qihse_uuid_equal(&resolved, &node.node_id));
    assert(trust == QIHSE_RTRUST_UNKNOWN);

    /* The session carries no strong authority at that trust state, which is
     * the property that matters: the caller must read the trust state rather
     * than infer authority from the certificate. */
    qihse_admission_t adm_unknown;
    qihse_runtime_admission_evaluate(QIHSE_RTRUST_UNKNOWN, &adm_unknown);
    assert(!adm_unknown.may_strong_write && !adm_unknown.may_vote);

    /* With TRUSTED evidence recorded, the session carries full authority. */
    qihse_trust_verification_t ver_ok;
    memset(&ver_ok, 0, sizeof(ver_ok));
    ver_ok.node_id = node.node_id;
    ver_ok.trust_state = QIHSE_RTRUST_TRUSTED;
    ver_ok.verification_principal = node.node_id;
    snprintf(ver_ok.verification_result, sizeof(ver_ok.verification_result), "provenance_ok");
    assert(qihse_trust_verification_put(g_store, g_op, &ver_ok, NULL));
    v = qihse_federation_peer_verify(g_store, g_op, fp, sizeof(fp), &resolved, &trust);
    assert(v == QIHSE_PEER_ACCEPT);
    assert(trust == QIHSE_RTRUST_TRUSTED);

    /* LAYER 3: the certificate is still valid and the node still enrolled, but
     * provenance now fails.  The session must be refused while the node's own
     * database stays usable.  This is the layer that collapsing 2 and 3 would
     * lose. */
    qihse_trust_verification_t ver;
    memset(&ver, 0, sizeof(ver));
    ver.node_id = node.node_id;
    ver.trust_state = QIHSE_RTRUST_LOCAL_ONLY;
    ver.verification_principal = node.node_id;
    snprintf(ver.verification_result, sizeof(ver.verification_result), "provenance_mismatch");
    assert(qihse_trust_verification_put(g_store, g_op, &ver, NULL));

    v = qihse_federation_peer_verify(g_store, g_op, fp, sizeof(fp), &resolved, &trust);
    assert(v == QIHSE_PEER_REJECT_UNTRUSTED);
    assert(trust == QIHSE_RTRUST_LOCAL_ONLY);

    /* The certificate itself is unchanged and still verifies: layer 1 is
     * unaffected by a layer 3 failure.  That is the point of keeping them
     * separate. */
    assert(qihse_federation_cert_verify(cert, &ca));

    /* Degraded still gets a session, because it may replicate. */
    ver.trust_state = QIHSE_RTRUST_TRUSTED_DEGRADED;
    snprintf(ver.verification_result, sizeof(ver.verification_result), "hardening_drift");
    assert(qihse_trust_verification_put(g_store, g_op, &ver, NULL));
    v = qihse_federation_peer_verify(g_store, g_op, fp, sizeof(fp), &resolved, &trust);
    assert(v == QIHSE_PEER_ACCEPT);
    assert(trust == QIHSE_RTRUST_TRUSTED_DEGRADED);

    /* Revocation is layer 2 and outranks everything: a revoked node is refused
     * even with a valid certificate and a clean runtime record. */
    ver.trust_state = QIHSE_RTRUST_TRUSTED;
    assert(qihse_trust_verification_put(g_store, g_op, &ver, NULL));
    assert(qihse_federation_node_revoke(g_store, g_op, &node.node_id));
    v = qihse_federation_peer_verify(g_store, g_op, fp, sizeof(fp), &resolved, &trust);
    assert(v == QIHSE_PEER_REJECT_REVOKED);

    /* Malformed inputs are refused rather than treated as "no fingerprint". */
    assert(qihse_federation_peer_verify(g_store, g_op, fp, 12, &resolved, &trust) ==
           QIHSE_PEER_REJECT_MALFORMED);
    assert(qihse_federation_peer_verify(g_store, g_op, NULL, sizeof(fp), &resolved, &trust) ==
           QIHSE_PEER_REJECT_NO_CERT);

    printf("PASS peer verify: unknown/pending/revoked refused at layer 2, LOCAL_ONLY refused at layer 3\n");
}

/* ── TLS posture ───────────────────────────────────────────────────────── */

static void test_tls_posture(void) {
    /* Hybrid post-quantum key exchange, with the classical group retained for
     * interoperability.  X25519MLKEM768 is what this toolchain provides. */
    const char* groups = qihse_federation_tls_group_list();
    assert(strstr(groups, "X25519MLKEM768") != NULL);
    assert(strcmp(qihse_federation_tls_min_version(), "TLSv1.3") == 0);

    /* Verdict names are stable and greppable, so an operator can match a log
     * line to a reason without reading the enum. */
    assert(strcmp(qihse_peer_verdict_name(QIHSE_PEER_ACCEPT), "accept") == 0);
    assert(strcmp(qihse_peer_verdict_name(QIHSE_PEER_REJECT_REVOKED),
                  "reject_revoked") == 0);
    assert(strcmp(qihse_peer_verdict_name(QIHSE_PEER_REJECT_UNTRUSTED),
                  "reject_untrusted") == 0);

    printf("PASS TLS posture: hybrid X25519MLKEM768 group, TLS 1.3 floor\n");
}

int main(void) {
    char data_root[] = "build/fed_mtls_XXXXXX";
    assert(mkdtemp(data_root));
    char key_dir[512];
    snprintf(key_dir, sizeof(key_dir), "%s/keys", data_root);
    assert(mkdir(key_dir, 0700) == 0);
    char ca_dir[512];
    snprintf(ca_dir, sizeof(ca_dir), "%s/ca", data_root);
    assert(mkdir(ca_dir, 0700) == 0);
    setenv("QIHSE_DATA_DIR", data_root, 1);

    assert(qihse_auth_init());
    bool bootstrapped = qihse_auth_bootstrap_operator("MtlsOperatorPass1!");
    if (!bootstrapped) {
        setenv("QIHSE_OPERATOR_PASSWORD", "MtlsOperatorPass1!", 1);
        assert(qihse_auth_init());
    }
    g_op = qihse_auth_get_user(0);
    assert(g_op);
    g_store = qihse_kv_store_create();
    assert(g_store);

    test_tls_posture();
    test_ca_creation(ca_dir);
    test_issuance_and_binding(ca_dir, key_dir);
    test_peer_verify_layers(ca_dir, key_dir);

    qihse_kv_store_destroy(g_store);
    printf("federation mTLS tests passed\n");
    return 0;
}
