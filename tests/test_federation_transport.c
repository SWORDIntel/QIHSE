/*
 * test_federation_transport.c — mutual TLS for federation RPC.
 *
 * The claim under test is that a connection is refused unless the peer both
 * HOLDS a key the federation CA issued AND is a currently-trusted enrolled
 * node.  Every case below presents a real certificate over a real TLS
 * handshake, so a pass is evidence about the handshake rather than about a
 * policy function called in isolation.
 *
 * socketpair(2) is used instead of a listener, so the test needs no network
 * and no port: the handshake is the part under test, not the accept loop.
 */
#include "qihse_auth.h"
#include "qihse_federation.h"
#include "qihse_federation_mtls.h"
#include "qihse_federation_transport.h"
#include "qihse_kv_store.h"
#include "qihse_runtime_trust.h"

#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

static qihse_kv_store_t* g_store;
static qihse_user_t* g_op;

/* ── A node: identity, certificate, and the two ends of a socketpair ───── */

typedef struct {
    qihse_federation_node_identity_t id;
    char cert[QIHSE_FEDERATION_PEM_MAX];
    qihse_fed_tls_server_t* tls;
} test_node_t;

typedef struct {
    qihse_fed_tls_server_t* server;
    int fd;
    qihse_fed_tls_session_t* session;
    qihse_peer_verdict_t verdict;
} handshake_arg_t;

static void* accept_thread(void* arg) {
    handshake_arg_t* a = (handshake_arg_t*)arg;
    a->session = qihse_federation_tls_accept_fd(a->server, a->fd, &a->verdict);
    return NULL;
}

/* Run a full handshake between two contexts over a socketpair.  The server
 * side runs in a thread because a TLS handshake is bidirectional and a
 * blocking socketpair would deadlock if both sides were driven in sequence. */
static void run_handshake(qihse_fed_tls_server_t* server_ctx,
                          qihse_fed_tls_server_t* client_ctx,
                          qihse_fed_tls_session_t** out_server,
                          qihse_fed_tls_session_t** out_client,
                          qihse_peer_verdict_t* out_server_verdict) {
    int sv[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);

    handshake_arg_t a;
    memset(&a, 0, sizeof(a));
    a.server = server_ctx;
    a.fd = sv[0];
    a.verdict = QIHSE_PEER_REJECT_MALFORMED;

    pthread_t th;
    assert(pthread_create(&th, NULL, accept_thread, &a) == 0);

    qihse_peer_verdict_t client_verdict = QIHSE_PEER_REJECT_MALFORMED;
    qihse_fed_tls_session_t* client = qihse_federation_tls_connect_fd(client_ctx, sv[1],
                                                                     &client_verdict);
    pthread_join(th, NULL);

    if (out_server) *out_server = a.session;
    if (out_client) *out_client = client;
    if (out_server_verdict) *out_server_verdict = a.verdict;

    if (a.session) qihse_federation_tls_session_destroy(a.session);
    if (client) qihse_federation_tls_session_destroy(client);
    close(sv[0]);
    close(sv[1]);
}

/* Enroll a node, issue its certificate, and build its TLS context. */
static void make_node(const char* dir, const qihse_federation_ca_t* ca,
                      const char* ca_key_path, const char* seed,
                      qihse_runtime_trust_t trust,
                      bool enroll, test_node_t* out) {
    memset(out, 0, sizeof(*out));
    assert(qihse_uuid_from_seed(seed, strlen(seed), &out->id.node_id));
    snprintf(out->id.hostname, sizeof(out->id.hostname), "%s", seed);
    snprintf(out->id.boot_id, sizeof(out->id.boot_id), "%s-boot", seed);
    out->id.identity_kind = QIHSE_IDENTITY_HOST_AGENT;
    assert(qihse_federation_node_keygen_alg(dir, QIHSE_SIG_ML_DSA_65, &out->id));

    if (enroll) {
        assert(qihse_federation_node_enroll_request(g_store, g_op, &out->id));
        assert(qihse_federation_node_enroll_approve(g_store, g_op, &out->id.node_id, 1));
        qihse_trust_verification_t v;
        memset(&v, 0, sizeof(v));
        v.node_id = out->id.node_id;
        v.trust_state = trust;
        v.verification_principal = out->id.node_id;
        snprintf(v.verification_result, sizeof(v.verification_result), "test");
        assert(qihse_trust_verification_put(g_store, g_op, &v, NULL));
    }

    assert(qihse_federation_ca_issue_node(ca_key_path, ca, &out->id, 1,
                                         out->cert, sizeof(out->cert)));
    out->tls = qihse_federation_tls_server_create(ca, out->cert, out->id.key_handle,
                                                 g_store, g_op);
    assert(out->tls);
}

/* ── Context posture ───────────────────────────────────────────────────── */

static void test_context_posture(const char* dir, const char* ca_key_path,
                                 const qihse_federation_ca_t* ca) {
    test_node_t n;
    make_node(dir, ca, ca_key_path, "posture-node", QIHSE_RTRUST_TRUSTED, true, &n);

    /* Mutual authentication is on, not merely available. */
    assert(qihse_federation_tls_server_requires_client_cert(n.tls));

    /* A certificate that does not verify against this CA is refused at
     * context creation, so a misconfigured node fails to start rather than
     * starting with a weaker posture. */
    char other_dir[512];
    snprintf(other_dir, sizeof(other_dir), "%s/otherca2", dir);
    assert(mkdir(other_dir, 0700) == 0);
    qihse_federation_ca_t other_ca;
    assert(qihse_federation_ca_create(other_dir, QIHSE_SIG_ML_DSA_87, &other_ca));
    assert(qihse_federation_tls_server_create(&other_ca, n.cert, n.id.key_handle,
                                             g_store, g_op) == NULL);

    /* A missing private key is refused rather than producing a context that
     * cannot authenticate. */
    assert(qihse_federation_tls_server_create(ca, n.cert, "/nonexistent.key",
                                             g_store, g_op) == NULL);

    qihse_federation_tls_server_destroy(n.tls);
    printf("PASS context posture: client cert required, foreign CA and bad key refused\n");
}

/* ── The handshake decisions ───────────────────────────────────────────── */

static void test_trusted_peer_accepted(const char* dir, const char* ca_key_path,
                                       const qihse_federation_ca_t* ca) {
    test_node_t server_node, client_node;
    make_node(dir, ca, ca_key_path, "srv-a", QIHSE_RTRUST_TRUSTED, true, &server_node);
    make_node(dir, ca, ca_key_path, "cli-a", QIHSE_RTRUST_TRUSTED, true, &client_node);

    qihse_fed_tls_session_t* s = NULL;
    qihse_fed_tls_session_t* c = NULL;
    qihse_peer_verdict_t sv = QIHSE_PEER_REJECT_MALFORMED;
    run_handshake(server_node.tls, client_node.tls, &s, &c, &sv);
    assert(sv == QIHSE_PEER_ACCEPT);
    /* The client's own view: the server's certificate verified and resolved. */
    assert(c != NULL);

    /* The session names the peer, so the caller attributes the connection to
     * an identity rather than to an address. */
    qihse_uuid_t peer;
    qihse_runtime_trust_t trust;
    /* The sessions were destroyed by run_handshake, so re-run to inspect. */
    (void)peer; (void)trust;
    (void)s; (void)c;

    int sv2[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sv2) == 0);
    handshake_arg_t a;
    memset(&a, 0, sizeof(a));
    a.server = server_node.tls;
    a.fd = sv2[0];
    pthread_t th;
    assert(pthread_create(&th, NULL, accept_thread, &a) == 0);
    qihse_peer_verdict_t cv;
    qihse_fed_tls_session_t* client = qihse_federation_tls_connect_fd(client_node.tls,
                                                                     sv2[1], &cv);
    pthread_join(th, NULL);
    assert(a.session != NULL);
    assert(qihse_federation_tls_peer_identity(a.session, &peer, &trust));
    assert(qihse_uuid_equal(&peer, &client_node.id.node_id));
    assert(trust == QIHSE_RTRUST_TRUSTED);

    /* The negotiated parameters are readable, so a deployment can prove it is
     * running post-quantum key exchange rather than assume it. */
    char group[64], version[32];
    assert(qihse_federation_tls_negotiated(a.session, group, sizeof(group),
                                          version, sizeof(version)));
    assert(strcmp(version, "TLSv1.3") == 0);
    assert(strstr(group, "MLKEM") != NULL || strstr(group, "X25519") != NULL);

    qihse_federation_tls_session_destroy(a.session);
    qihse_federation_tls_session_destroy(client);
    close(sv2[0]); close(sv2[1]);
    qihse_federation_tls_server_destroy(server_node.tls);
    qihse_federation_tls_server_destroy(client_node.tls);
    printf("PASS trusted peer accepted: identity resolved, TLS1.3 with %s\n", group);
}

static void test_foreign_ca_refused(const char* dir, const char* ca_key_path,
                                    const qihse_federation_ca_t* ca) {
    test_node_t server_node;
    make_node(dir, ca, ca_key_path, "srv-b", QIHSE_RTRUST_TRUSTED, true, &server_node);

    /* A peer with a certificate from a DIFFERENT CA: it holds a valid key and
     * a valid certificate, just not one this federation issued. */
    char other_dir[512];
    snprintf(other_dir, sizeof(other_dir), "%s/otherca3", dir);
    assert(mkdir(other_dir, 0700) == 0);
    qihse_federation_ca_t other_ca;
    assert(qihse_federation_ca_create(other_dir, QIHSE_SIG_ML_DSA_87, &other_ca));
    char other_ca_key[512];
    snprintf(other_ca_key, sizeof(other_ca_key), "%s/federation-ca.key", other_dir);

    test_node_t foreign;
    make_node(dir, &other_ca, other_ca_key, "foreign-node", QIHSE_RTRUST_TRUSTED,
              true, &foreign);

    qihse_peer_verdict_t sv = QIHSE_PEER_REJECT_MALFORMED;
    qihse_fed_tls_session_t* s = NULL;
    run_handshake(server_node.tls, foreign.tls, &s, NULL, &sv);
    /* Refused: the server must not have produced a session. */
    assert(sv != QIHSE_PEER_ACCEPT);

    qihse_federation_tls_server_destroy(server_node.tls);
    qihse_federation_tls_server_destroy(foreign.tls);
    printf("PASS foreign CA refused: a valid certificate from another CA is not a peer\n");
}

static void test_unenrolled_peer_refused(const char* dir, const char* ca_key_path,
                                         const qihse_federation_ca_t* ca) {
    test_node_t server_node;
    make_node(dir, ca, ca_key_path, "srv-c", QIHSE_RTRUST_TRUSTED, true, &server_node);

    /* A certificate from the federation CA for a node that was never enrolled.
     * It proves key possession and CA issuance, and nothing else. */
    test_node_t stranger;
    make_node(dir, ca, ca_key_path, "stranger", QIHSE_RTRUST_UNKNOWN, false, &stranger);

    qihse_peer_verdict_t sv = QIHSE_PEER_REJECT_MALFORMED;
    qihse_fed_tls_session_t* s = NULL;
    run_handshake(server_node.tls, stranger.tls, &s, NULL, &sv);
    assert(sv != QIHSE_PEER_ACCEPT);

    qihse_federation_tls_server_destroy(server_node.tls);
    qihse_federation_tls_server_destroy(stranger.tls);
    printf("PASS unenrolled peer refused: CA issuance alone is not admission\n");
}

static void test_untrusted_enrolled_peer_refused(const char* dir, const char* ca_key_path,
                                                 const qihse_federation_ca_t* ca) {
    test_node_t server_node;
    make_node(dir, ca, ca_key_path, "srv-d", QIHSE_RTRUST_TRUSTED, true, &server_node);

    /* Enrolled, certificate valid, but runtime trust says LOCAL_ONLY — the
     * third layer.  This is the case that a server-auth-only posture would
     * admit. */
    test_node_t degraded;
    make_node(dir, ca, ca_key_path, "degraded", QIHSE_RTRUST_LOCAL_ONLY, true, &degraded);

    qihse_peer_verdict_t sv = QIHSE_PEER_REJECT_MALFORMED;
    qihse_fed_tls_session_t* s = NULL;
    run_handshake(server_node.tls, degraded.tls, &s, NULL, &sv);
    assert(sv != QIHSE_PEER_ACCEPT);

    qihse_federation_tls_server_destroy(server_node.tls);
    qihse_federation_tls_server_destroy(degraded.tls);
    printf("PASS untrusted enrolled peer refused: layer 3 decides, not the certificate\n");
}

static void test_degraded_peer_admitted_with_less_authority(const char* dir,
                                                            const char* ca_key_path,
                                                            const qihse_federation_ca_t* ca) {
    test_node_t server_node;
    make_node(dir, ca, ca_key_path, "srv-e", QIHSE_RTRUST_TRUSTED, true, &server_node);

    /* TRUSTED_DEGRADED may exchange federation state, so it gets a channel —
     * with reduced authority, which the admission record carries. */
    test_node_t degraded;
    make_node(dir, ca, ca_key_path, "degraded2", QIHSE_RTRUST_TRUSTED_DEGRADED,
              true, &degraded);

    int sv[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
    handshake_arg_t a;
    memset(&a, 0, sizeof(a));
    a.server = server_node.tls;
    a.fd = sv[0];
    pthread_t th;
    assert(pthread_create(&th, NULL, accept_thread, &a) == 0);
    qihse_peer_verdict_t cv;
    qihse_fed_tls_session_t* client = qihse_federation_tls_connect_fd(degraded.tls,
                                                                     sv[1], &cv);
    pthread_join(th, NULL);
    assert(a.session != NULL);

    qihse_uuid_t peer;
    qihse_runtime_trust_t trust;
    assert(qihse_federation_tls_peer_identity(a.session, &peer, &trust));
    assert(trust == QIHSE_RTRUST_TRUSTED_DEGRADED);

    /* The session exists but carries no strong authority. */
    qihse_admission_t adm;
    qihse_runtime_admission_evaluate(trust, &adm);
    assert(adm.local_usable);
    assert(!adm.may_strong_write && !adm.may_vote);

    qihse_federation_tls_session_destroy(a.session);
    qihse_federation_tls_session_destroy(client);
    close(sv[0]); close(sv[1]);
    qihse_federation_tls_server_destroy(server_node.tls);
    qihse_federation_tls_server_destroy(degraded.tls);
    printf("PASS degraded peer: channel granted, no strong authority\n");
}

/* ── The replication transport rides the verified channel ──────────────── */

static void test_transport_over_tls(const char* dir, const char* ca_key_path,
                                    const qihse_federation_ca_t* ca) {
    test_node_t server_node, client_node;
    make_node(dir, ca, ca_key_path, "srv-f", QIHSE_RTRUST_TRUSTED, true, &server_node);
    make_node(dir, ca, ca_key_path, "cli-f", QIHSE_RTRUST_TRUSTED, true, &client_node);

    int sv[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
    handshake_arg_t a;
    memset(&a, 0, sizeof(a));
    a.server = server_node.tls;
    a.fd = sv[0];
    pthread_t th;
    assert(pthread_create(&th, NULL, accept_thread, &a) == 0);
    qihse_peer_verdict_t cv;
    qihse_fed_tls_session_t* client = qihse_federation_tls_connect_fd(client_node.tls,
                                                                     sv[1], &cv);
    pthread_join(th, NULL);
    assert(a.session != NULL);

    /* The ops report the peer's fingerprint from the real certificate, so the
     * range transfer's "unverified peer" guard is satisfied by construction
     * rather than by the caller asserting it. */
    qihse_repl_transport_ops_t ops = qihse_federation_tls_transport_ops(a.session);
    assert(ops.connect && ops.send && ops.recv && ops.close && ops.peer_fingerprint);

    uint8_t fp[QIHSE_FEDERATION_NODE_FINGERPRINT_BYTES];
    assert(ops.peer_fingerprint(a.session, fp));
    /* And it matches the enrolled record for that node. */
    qihse_federation_node_identity_t looked_up;
    assert(qihse_federation_node_lookup(g_store, g_op, &client_node.id.node_id,
                                       &looked_up));
    assert(memcmp(fp, looked_up.fingerprint, sizeof(fp)) == 0);

    qihse_repl_transport_t t;
    assert(qihse_repl_transport_open(&t, &ops, a.session, "tls"));
    assert(t.peer_verified);

    /* A round-trip proves the channel actually carries bytes. */
    const uint8_t msg[] = "federation-repl-over-mtls";
    assert(ops.send(a.session, msg, sizeof(msg)) == (long)sizeof(msg));
    uint8_t got[64];
    assert(ops.recv(client, got, sizeof(got)) == (long)sizeof(msg));
    assert(memcmp(got, msg, sizeof(msg)) == 0);

    qihse_repl_transport_close(&t);
    qihse_federation_tls_session_destroy(a.session);
    qihse_federation_tls_session_destroy(client);
    close(sv[0]); close(sv[1]);
    qihse_federation_tls_server_destroy(server_node.tls);
    qihse_federation_tls_server_destroy(client_node.tls);
    printf("PASS transport over mTLS: peer fingerprint from the certificate, bytes round-trip\n");
}

int main(void) {
    char data_root[] = "build/fed_transport_XXXXXX";
    assert(mkdtemp(data_root));
    char key_dir[512];
    snprintf(key_dir, sizeof(key_dir), "%s/keys", data_root);
    assert(mkdir(key_dir, 0700) == 0);
    char ca_dir[512];
    snprintf(ca_dir, sizeof(ca_dir), "%s/ca", data_root);
    assert(mkdir(ca_dir, 0700) == 0);
    setenv("QIHSE_DATA_DIR", data_root, 1);

    assert(qihse_auth_init());
    bool bootstrapped = qihse_auth_bootstrap_operator("TransportPass1!");
    if (!bootstrapped) {
        setenv("QIHSE_OPERATOR_PASSWORD", "TransportPass1!", 1);
        assert(qihse_auth_init());
    }
    g_op = qihse_auth_get_user(0);
    assert(g_op);
    g_store = qihse_kv_store_create();
    assert(g_store);

    qihse_federation_ca_t ca;
    assert(qihse_federation_ca_create(ca_dir, QIHSE_SIG_ML_DSA_87, &ca));
    char ca_key_path[512];
    snprintf(ca_key_path, sizeof(ca_key_path), "%s/federation-ca.key", ca_dir);

    test_context_posture(key_dir, ca_key_path, &ca);
    test_trusted_peer_accepted(key_dir, ca_key_path, &ca);
    test_foreign_ca_refused(key_dir, ca_key_path, &ca);
    test_unenrolled_peer_refused(key_dir, ca_key_path, &ca);
    test_untrusted_enrolled_peer_refused(key_dir, ca_key_path, &ca);
    test_degraded_peer_admitted_with_less_authority(key_dir, ca_key_path, &ca);
    test_transport_over_tls(key_dir, ca_key_path, &ca);

    qihse_kv_store_destroy(g_store);
    printf("federation transport tests passed\n");
    return 0;
}
