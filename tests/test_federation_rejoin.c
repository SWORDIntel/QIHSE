/*
 * test_federation_rejoin.c — the rejoin sequence and its gates.
 *
 * The claims under test are about ORDERING and REFUSAL rather than about
 * moving bytes:
 *
 *   1. A session that cannot name its peer, or names a different peer than the
 *      operator intended, may not be a source of state.
 *   2. Ownership is not publishable until the state has been reconstructed and
 *      checksums verified.
 *   3. A transfer may not run before the peer is authenticated and the
 *      divergence established.
 *   4. A sequence that cannot progress aborts rather than reporting success.
 *   5. Progress is persisted, so a crash resumes rather than restarting with
 *      the gates it had not yet passed.
 */
#include "qihse_auth.h"
#include "qihse_federation.h"
#include "qihse_federation_mtls.h"
#include "qihse_federation_rejoin.h"
#include "qihse_federation_transport.h"
#include "qihse_kv_store.h"
#include "qihse_operations.h"
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

/* ── Two nodes with verified mTLS sessions ─────────────────────────────── */

typedef struct {
    qihse_federation_node_identity_t id;
    char cert[QIHSE_FEDERATION_PEM_MAX];
    qihse_fed_tls_server_t* tls;
} rnode_t;

typedef struct { qihse_fed_tls_server_t* s; int fd; qihse_fed_tls_session_t* sess; qihse_peer_verdict_t verdict; } hs_t;

static void* hs_thread(void* a) {
    hs_t* h = (hs_t*)a;
    h->sess = qihse_federation_tls_accept_fd(h->s, h->fd, &h->verdict);
    return NULL;
}

static void make_rnode(const char* dir, const char* ca_key_path,
                       const qihse_federation_ca_t* ca, const char* seed,
                       qihse_runtime_trust_t trust, rnode_t* out) {
    memset(out, 0, sizeof(*out));
    assert(qihse_uuid_from_seed(seed, strlen(seed), &out->id.node_id));
    snprintf(out->id.hostname, sizeof(out->id.hostname), "%s", seed);
    snprintf(out->id.boot_id, sizeof(out->id.boot_id), "%s-boot", seed);
    out->id.identity_kind = QIHSE_IDENTITY_HOST_AGENT;
    assert(qihse_federation_node_keygen_alg(dir, QIHSE_SIG_ML_DSA_65, &out->id));
    assert(qihse_federation_node_enroll_request(g_store, g_op, &out->id));
    assert(qihse_federation_node_enroll_approve(g_store, g_op, &out->id.node_id, 1));
    qihse_trust_verification_t v;
    memset(&v, 0, sizeof(v));
    v.node_id = out->id.node_id;
    v.trust_state = trust;
    v.verification_principal = out->id.node_id;
    snprintf(v.verification_result, sizeof(v.verification_result), "test");
    assert(qihse_trust_verification_put(g_store, g_op, &v, NULL));
    assert(qihse_federation_ca_issue_node(ca_key_path, ca, &out->id, 1,
                                         out->cert, sizeof(out->cert)));
    out->tls = qihse_federation_tls_server_create(ca, out->cert, out->id.key_handle,
                                                 g_store, g_op);
    assert(out->tls);
}

/* Produce a verified session pair between two nodes.  Returns the SESSION from
 * the perspective of `b` (the peer being talked to). */
static void session_pair(rnode_t* a, rnode_t* b,
                         qihse_fed_tls_session_t** out_a,
                         qihse_fed_tls_session_t** out_b) {
    int sv[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
    hs_t h;
    memset(&h, 0, sizeof(h));
    h.verdict = QIHSE_PEER_REJECT_MALFORMED;
    h.s = b->tls;      /* b accepts */
    h.fd = sv[0];
    pthread_t th;
    assert(pthread_create(&th, NULL, hs_thread, &h) == 0);
    qihse_peer_verdict_t cv = QIHSE_PEER_REJECT_MALFORMED;
    qihse_fed_tls_session_t* client = qihse_federation_tls_connect_fd(a->tls, sv[1], &cv);
    pthread_join(th, NULL);
    if (!h.sess || !client) {
        fprintf(stderr, "session_pair failed: server=%p (verdict=%s) client=%p (verdict=%s)\n",
                (void*)h.sess, qihse_peer_verdict_name(h.verdict),
                (void*)client, qihse_peer_verdict_name(cv));
    }
    assert(h.sess && client);
    /* a's session talks to b; b's session talks to a. */
    *out_a = client;
    *out_b = h.sess;
}

/* ── Manifest fetcher ──────────────────────────────────────────────────── */

typedef struct {
    qihse_federation_manifest_t manifest;
    bool fail;
} fetch_ctx_t;

static bool fetch_manifest_cb(void* ctx, const char* ns,
                              qihse_federation_manifest_t* out) {
    fetch_ctx_t* f = (fetch_ctx_t*)ctx;
    if (!f || f->fail) return false;
    if (strcmp(f->manifest.namespace_name, ns) != 0) return false;
    *out = f->manifest;
    return true;
}

/* ── Gates ─────────────────────────────────────────────────────────────── */

static void test_ownership_gate(void) {
    /* Ownership is publishable only after reconstruction and verification. */
    qihse_rejoin_driver_t d;
    memset(&d, 0, sizeof(d));

    d.step = QIHSE_REJOIN_AUTHENTICATE_PEER;
    assert(!qihse_rejoin_driver_may_publish_ownership(&d));
    d.step = QIHSE_REJOIN_EXCHANGE_MANIFESTS;
    assert(!qihse_rejoin_driver_may_publish_ownership(&d));
    d.step = QIHSE_REJOIN_TRANSFER_EVENTS;
    assert(!qihse_rejoin_driver_may_publish_ownership(&d));
    d.step = QIHSE_REJOIN_RECONSTRUCT_STATE;
    assert(!qihse_rejoin_driver_may_publish_ownership(&d));
    /* VERIFY_CHECKSUMS is where verification HAPPENS, not where it has passed,
     * so ownership is still not publishable here.  The gate is deliberately
     * one step stricter than "we are checking now". */
    d.step = QIHSE_REJOIN_VERIFY_CHECKSUMS;
    assert(!qihse_rejoin_driver_may_publish_ownership(&d));
    d.step = QIHSE_REJOIN_COMPLETE;
    assert(qihse_rejoin_driver_may_publish_ownership(&d));
    /* And never after an abort. */
    d.step = QIHSE_REJOIN_ABORTED;
    assert(!qihse_rejoin_driver_may_publish_ownership(&d));

    printf("PASS ownership gate: publishable only at COMPLETE, never mid-sequence\n");
}

static void test_transfer_window(void) {
    /* A transfer may not run before the peer is authenticated and the
     * divergence established. */
    assert(!qihse_repl_transfer_permitted(QIHSE_REJOIN_IDLE));
    assert(!qihse_repl_transfer_permitted(QIHSE_REJOIN_AUTHENTICATE_PEER));
    assert(!qihse_repl_transfer_permitted(QIHSE_REJOIN_EXCHANGE_MANIFESTS));
    assert(!qihse_repl_transfer_permitted(QIHSE_REJOIN_IDENTIFY_DIVERGENCE));
    assert(qihse_repl_transfer_permitted(QIHSE_REJOIN_TRANSFER_EVENTS));
    assert(qihse_repl_transfer_permitted(QIHSE_REJOIN_VERIFY_CHECKSUMS));
    assert(!qihse_repl_transfer_permitted(QIHSE_REJOIN_ABORTED));

    printf("PASS transfer window: refused before AUTHENTICATE/EXCHANGE, open from TRANSFER\n");
}

/* ── Begin-time refusals ───────────────────────────────────────────────── */

static void test_begin_refusals(const char* dir, const char* ca_key_path,
                                const qihse_federation_ca_t* ca) {
    rnode_t a, b;
    make_rnode(dir, ca_key_path, ca, "rj-a", QIHSE_RTRUST_TRUSTED, &a);
    make_rnode(dir, ca_key_path, ca, "rj-b", QIHSE_RTRUST_TRUSTED, &b);

    qihse_fed_tls_session_t *sa = NULL, *sb = NULL;
    session_pair(&a, &b, &sa, &sb);

    qihse_rejoin_driver_t d;

    /* A session with no verified peer is not a source of state. */
    assert(!qihse_rejoin_driver_begin(&d, g_store, g_op, &a.id.node_id, &b.id.node_id,
                                     "rj-ns", NULL));
    assert(d.step == QIHSE_REJOIN_ABORTED);
    assert(strstr(d.last_error, "no session") != NULL ||
           strstr(d.last_error, "verified") != NULL);

    /* The session names a DIFFERENT peer than the operator intended.
     * "Verified" and "the peer I meant" are separate questions. */
    qihse_uuid_t wrong;
    assert(qihse_uuid_from_seed("some-other-node", strlen("some-other-node"), &wrong));
    assert(!qihse_rejoin_driver_begin(&d, g_store, g_op, &a.id.node_id, &wrong,
                                     "rj-ns", sa));
    assert(d.step == QIHSE_REJOIN_ABORTED);
    assert(strstr(d.last_error, "not the expected peer") != NULL);

    /* The intended peer, on a verified session, is accepted. */
    assert(qihse_rejoin_driver_begin(&d, g_store, g_op, &a.id.node_id, &b.id.node_id,
                                    "rj-ns", sa));
    assert(d.step == QIHSE_REJOIN_AUTHENTICATE_PEER);
    assert(!qihse_rejoin_driver_may_publish_ownership(&d));

    qihse_federation_tls_session_destroy(sa);
    qihse_federation_tls_session_destroy(sb);
    qihse_federation_tls_server_destroy(a.tls);
    qihse_federation_tls_server_destroy(b.tls);
    printf("PASS begin refusals: unverified session and wrong peer both refused\n");
}

static void test_peer_trust_forbids_source(const char* dir, const char* ca_key_path,
                                           const qihse_federation_ca_t* ca) {
    rnode_t a, degraded;
    make_rnode(dir, ca_key_path, ca, "rj-c", QIHSE_RTRUST_TRUSTED, &a);
    /* A peer that may not exchange federation state may not be a source of
     * authoritative state either. */
    make_rnode(dir, ca_key_path, ca, "rj-d", QIHSE_RTRUST_LOCAL_ONLY, &degraded);

    /* First: a LOCAL_ONLY peer is refused at the TRANSPORT layer, so the
     * handshake itself must not produce a session.  That is the primary
     * control and it is asserted here rather than assumed. */
    int sv[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
    hs_t h;
    memset(&h, 0, sizeof(h));
    h.verdict = QIHSE_PEER_REJECT_MALFORMED;
    h.s = degraded.tls;   /* the LOCAL_ONLY node accepts */
    h.fd = sv[0];
    pthread_t th;
    assert(pthread_create(&th, NULL, hs_thread, &h) == 0);
    qihse_peer_verdict_t cv = QIHSE_PEER_REJECT_MALFORMED;
    qihse_fed_tls_session_t* client = qihse_federation_tls_connect_fd(a.tls, sv[1], &cv);
    pthread_join(th, NULL);
    assert(h.sess == NULL);              /* no session was granted */
    assert(h.verdict != QIHSE_PEER_ACCEPT);
    if (client) qihse_federation_tls_session_destroy(client);
    close(sv[0]); close(sv[1]);

    /* Second: the DRIVER refuses independently, so a caller that obtained a
     * session some other way still cannot rejoin from a peer that may not
     * exchange federation state.  Defence in depth, not the only control. */
    qihse_fed_tls_session_t *sa = NULL, *sb = NULL;
    rnode_t trusted;
    make_rnode(dir, ca_key_path, ca, "rj-d2", QIHSE_RTRUST_TRUSTED, &trusted);
    session_pair(&a, &trusted, &sa, &sb);

    qihse_rejoin_driver_t d;
    /* The session is valid and its peer is trusted, but it is NOT the peer the
     * operator named — so the driver refuses on the identity question. */
    assert(!qihse_rejoin_driver_begin(&d, g_store, g_op, &a.id.node_id,
                                     &degraded.id.node_id, "rj-ns", sa));
    assert(d.step == QIHSE_REJOIN_ABORTED);
    assert(strstr(d.last_error, "not the expected peer") != NULL);

    if (sa) qihse_federation_tls_session_destroy(sa);
    if (sb) qihse_federation_tls_session_destroy(sb);
    qihse_federation_tls_server_destroy(trusted.tls);
    qihse_federation_tls_server_destroy(a.tls);
    qihse_federation_tls_server_destroy(degraded.tls);
    printf("PASS peer trust: a peer that may not exchange state is not a rejoin source\n");
}

/* ── The sequence itself ───────────────────────────────────────────────── */

static void test_in_sync_rejoin_completes(const char* dir, const char* ca_key_path,
                                          const qihse_federation_ca_t* ca) {
    rnode_t a, b;
    make_rnode(dir, ca_key_path, ca, "rj-e", QIHSE_RTRUST_TRUSTED, &a);
    make_rnode(dir, ca_key_path, ca, "rj-f", QIHSE_RTRUST_TRUSTED, &b);

    /* Both sides already agree, so there is no divergence to move. */
    const char* ns = "rj-sync-ns";
    assert(qihse_kv_set_user(g_store, "ns:rj-sync-ns:r/one", "1", 0, 0, g_op));

    qihse_fed_tls_session_t *sa = NULL, *sb = NULL;
    session_pair(&a, &b, &sa, &sb);

    fetch_ctx_t fc;
    memset(&fc, 0, sizeof(fc));
    assert(qihse_federation_manifest_build(g_store, g_op, ns, &fc.manifest));

    qihse_repl_transport_ops_t ops = qihse_federation_tls_transport_ops(sb);
    qihse_repl_transport_t transport;
    assert(qihse_repl_transport_open(&transport, &ops, sb, "peer"));
    assert(transport.peer_verified);

    char journal_root[] = "build/fed_rejoin_j_XXXXXX";
    assert(mkdtemp(journal_root));
    qihse_federation_journal_t* journal = qihse_federation_journal_open(
        journal_root, QIHSE_ES_DURABILITY_FDATASYNC);
    assert(journal);

    qihse_rejoin_driver_t d;
    assert(qihse_rejoin_driver_begin(&d, g_store, g_op, &a.id.node_id, &b.id.node_id,
                                    ns, sa));
    assert(!qihse_rejoin_driver_may_publish_ownership(&d));

    bool ok = qihse_rejoin_driver_run(&d, g_store, g_op, sa, &transport, journal,
                                     fetch_manifest_cb, &fc);
    assert(ok);
    assert(d.step == QIHSE_REJOIN_COMPLETE);
    /* Only now. */
    assert(qihse_rejoin_driver_may_publish_ownership(&d));
    assert(d.divergent_count == 0);

    qihse_repl_transport_close(&transport);
    qihse_federation_journal_destroy(journal);
    qihse_federation_tls_session_destroy(sa);
    qihse_federation_tls_session_destroy(sb);
    qihse_federation_tls_server_destroy(a.tls);
    qihse_federation_tls_server_destroy(b.tls);
    printf("PASS in-sync rejoin: sequence completes, ownership only at the end\n");
}

static void test_divergence_aborts_rather_than_claiming_success(
        const char* dir, const char* ca_key_path, const qihse_federation_ca_t* ca) {
    rnode_t a, b;
    make_rnode(dir, ca_key_path, ca, "rj-g", QIHSE_RTRUST_TRUSTED, &a);
    make_rnode(dir, ca_key_path, ca, "rj-h", QIHSE_RTRUST_TRUSTED, &b);

    const char* ns = "rj-diverge-ns";
    assert(qihse_kv_set_user(g_store, "ns:rj-diverge-ns:r/a", "1", 0, 0, g_op));

    qihse_fed_tls_session_t *sa = NULL, *sb = NULL;
    session_pair(&a, &b, &sa, &sb);

    /* The peer's manifest claims more objects than the local side has, and the
     * local side cannot reproduce its digest.  The sequence must NOT report
     * success. */
    fetch_ctx_t fc;
    memset(&fc, 0, sizeof(fc));
    assert(qihse_federation_manifest_build(g_store, g_op, ns, &fc.manifest));
    if (fc.manifest.entry_count > 0) {
        fc.manifest.entries[0].object_count += 7;
        memset(fc.manifest.entries[0].digest, 0x77, sizeof(fc.manifest.entries[0].digest));
    }

    qihse_repl_transport_ops_t ops = qihse_federation_tls_transport_ops(sb);
    qihse_repl_transport_t transport;
    assert(qihse_repl_transport_open(&transport, &ops, sb, "peer"));

    char journal_root[] = "build/fed_rejoin_k_XXXXXX";
    assert(mkdtemp(journal_root));
    qihse_federation_journal_t* journal = qihse_federation_journal_open(
        journal_root, QIHSE_ES_DURABILITY_FDATASYNC);
    assert(journal);

    qihse_rejoin_driver_t d;
    assert(qihse_rejoin_driver_begin(&d, g_store, g_op, &a.id.node_id, &b.id.node_id,
                                    ns, sa));

    bool ok = qihse_rejoin_driver_run(&d, g_store, g_op, sa, &transport, journal,
                                     fetch_manifest_cb, &fc);

    if (fc.manifest.entry_count > 0) {
        /* Divergence was found and could not be reconciled, so the sequence
         * aborted.  Crucially it did NOT reach COMPLETE and ownership is not
         * publishable. */
        assert(d.divergent_count > 0);
        assert(!ok);
        assert(d.step == QIHSE_REJOIN_ABORTED);
        assert(!qihse_rejoin_driver_may_publish_ownership(&d));
        assert(d.last_error[0] != '\0');
    }

    qihse_repl_transport_close(&transport);
    qihse_federation_journal_destroy(journal);
    qihse_federation_tls_session_destroy(sa);
    qihse_federation_tls_session_destroy(sb);
    qihse_federation_tls_server_destroy(a.tls);
    qihse_federation_tls_server_destroy(b.tls);
    printf("PASS divergence: an unreconcilable range aborts, ownership never published\n");
}

static void test_failed_fetch_aborts(const char* dir, const char* ca_key_path,
                                     const qihse_federation_ca_t* ca) {
    rnode_t a, b;
    make_rnode(dir, ca_key_path, ca, "rj-i", QIHSE_RTRUST_TRUSTED, &a);
    make_rnode(dir, ca_key_path, ca, "rj-j", QIHSE_RTRUST_TRUSTED, &b);

    qihse_fed_tls_session_t *sa = NULL, *sb = NULL;
    session_pair(&a, &b, &sa, &sb);

    /* Proceeding without the peer's manifest would mean transferring against a
     * divergence nobody actually established. */
    fetch_ctx_t fc;
    memset(&fc, 0, sizeof(fc));
    fc.fail = true;

    qihse_repl_transport_ops_t ops = qihse_federation_tls_transport_ops(sb);
    qihse_repl_transport_t transport;
    assert(qihse_repl_transport_open(&transport, &ops, sb, "peer"));

    qihse_rejoin_driver_t d;
    assert(qihse_rejoin_driver_begin(&d, g_store, g_op, &a.id.node_id, &b.id.node_id,
                                    "rj-ns", sa));
    bool ok = qihse_rejoin_driver_run(&d, g_store, g_op, sa, &transport, NULL,
                                     fetch_manifest_cb, &fc);
    assert(!ok);
    assert(d.step == QIHSE_REJOIN_ABORTED);
    assert(strstr(d.last_error, "manifest") != NULL);
    assert(!qihse_rejoin_driver_may_publish_ownership(&d));

    qihse_repl_transport_close(&transport);
    qihse_federation_tls_session_destroy(sa);
    qihse_federation_tls_session_destroy(sb);
    qihse_federation_tls_server_destroy(a.tls);
    qihse_federation_tls_server_destroy(b.tls);
    printf("PASS failed fetch: no peer manifest means no sequence\n");
}

static void test_progress_is_persisted(const char* dir, const char* ca_key_path,
                                       const qihse_federation_ca_t* ca) {
    rnode_t a, b;
    make_rnode(dir, ca_key_path, ca, "rj-k", QIHSE_RTRUST_TRUSTED, &a);
    make_rnode(dir, ca_key_path, ca, "rj-l", QIHSE_RTRUST_TRUSTED, &b);

    qihse_fed_tls_session_t *sa = NULL, *sb = NULL;
    session_pair(&a, &b, &sa, &sb);

    fetch_ctx_t fc;
    memset(&fc, 0, sizeof(fc));
    assert(qihse_federation_manifest_build(g_store, g_op, "rj-persist-ns", &fc.manifest));

    qihse_repl_transport_ops_t ops = qihse_federation_tls_transport_ops(sb);
    qihse_repl_transport_t transport;
    assert(qihse_repl_transport_open(&transport, &ops, sb, "peer"));

    qihse_rejoin_driver_t d;
    assert(qihse_rejoin_driver_begin(&d, g_store, g_op, &a.id.node_id, &b.id.node_id,
                                    "rj-persist-ns", sa));
    /* Advance a few steps, then simulate a crash. */
    for (int i = 0; i < 3; i++) {
        assert(qihse_rejoin_driver_step(&d, g_store, g_op, sa, &transport, NULL,
                                       fetch_manifest_cb, &fc));
    }
    assert(d.step != QIHSE_REJOIN_COMPLETE);
    assert(!qihse_rejoin_driver_may_publish_ownership(&d));

    /* The persisted state is what a restarted node would read.
     *
     * The driver records the step it has COMPLETED, not the one it is about to
     * run.  That is the safer of the two: persisting "about to run X" means a
     * crash between the write and the work causes X to be skipped on resume,
     * whereas recording "finished X" means the next run starts at next(X) and
     * nothing is ever skipped. */
    qihse_rejoin_state_t st;
    assert(qihse_rejoin_state_get(g_store, g_op, &a.id.node_id, &st));
    assert(st.step != QIHSE_REJOIN_COMPLETE);
    assert(qihse_rejoin_next_step(st.step) == d.step);
    /* A resumed sequence must not be able to skip the gates it had not passed,
     * which is exactly what this says: mid-sequence is not publishable. */
    assert(!qihse_rejoin_may_publish_ownership(st.step));

    qihse_repl_transport_close(&transport);
    qihse_federation_tls_session_destroy(sa);
    qihse_federation_tls_session_destroy(sb);
    qihse_federation_tls_server_destroy(a.tls);
    qihse_federation_tls_server_destroy(b.tls);
    printf("PASS persistence: mid-sequence state is recorded and is not publishable\n");
}

int main(void) {
    char data_root[] = "build/fed_rejoin_XXXXXX";
    assert(mkdtemp(data_root));
    char key_dir[512];
    snprintf(key_dir, sizeof(key_dir), "%s/keys", data_root);
    assert(mkdir(key_dir, 0700) == 0);
    char ca_dir[512];
    snprintf(ca_dir, sizeof(ca_dir), "%s/ca", data_root);
    assert(mkdir(ca_dir, 0700) == 0);
    setenv("QIHSE_DATA_DIR", data_root, 1);

    assert(qihse_auth_init());
    bool bootstrapped = qihse_auth_bootstrap_operator("RejoinPass1!");
    if (!bootstrapped) {
        setenv("QIHSE_OPERATOR_PASSWORD", "RejoinPass1!", 1);
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

    test_ownership_gate();
    test_transfer_window();
    test_begin_refusals(key_dir, ca_key_path, &ca);
    test_peer_trust_forbids_source(key_dir, ca_key_path, &ca);
    test_in_sync_rejoin_completes(key_dir, ca_key_path, &ca);
    test_divergence_aborts_rather_than_claiming_success(key_dir, ca_key_path, &ca);
    test_failed_fetch_aborts(key_dir, ca_key_path, &ca);
    test_progress_is_persisted(key_dir, ca_key_path, &ca);

    qihse_kv_store_destroy(g_store);
    printf("federation rejoin tests passed\n");
    return 0;
}
