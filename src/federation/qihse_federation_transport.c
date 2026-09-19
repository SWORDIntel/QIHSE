/*
 * QIHSE federation mTLS transport.
 * See v3.md §18 and §22.
 *
 * The UWP TLS layer gives a server certificate and a session over an fd but
 * cannot require or read a client certificate, so federation builds its own
 * context here.  The peer decision is the three-layer check from
 * qihse_federation_mtls: the handshake proves key possession, the verify
 * callback resolves the fingerprint to an enrolled node and consults its
 * runtime trust, and a refusal is a failed connection.
 */
#include "qihse_federation_transport.h"

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

/* ── Server ────────────────────────────────────────────────────────────── */

struct qihse_fed_tls_server {
    /* A federation peer both accepts and initiates connections, so it needs
     * BOTH contexts.  A client handshake driven from a TLS_server_method()
     * context fails with SSL_R_CALLED_A_FUNCTION_YOU_SHOULD_NOT_CALL, which
     * is not an error that points at the real cause. */
    SSL_CTX* server_ctx;
    SSL_CTX* client_ctx;
    void* store;
    void* user;
    bool require_client_cert;
};

struct qihse_fed_tls_session {
    SSL* ssl;
    qihse_fed_tls_server_t* server;   /* not owned */
    bool peer_resolved;
    qihse_uuid_t peer_node;
    qihse_runtime_trust_t peer_trust;
};

/* Load the CA certificate into a store so the peer chain can be verified
 * against exactly the federation CA and nothing else. */
static bool build_ca_store(const qihse_federation_ca_t* ca, X509_STORE** out) {
    X509_STORE* store = X509_STORE_new();
    if (!store) return false;
    BIO* bio = BIO_new_mem_buf(ca->cert_pem, (int)ca->cert_pem_len);
    if (!bio) { X509_STORE_free(store); return false; }
    X509* cacert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    BIO_free(bio);
    if (!cacert) { X509_STORE_free(store); return false; }
    bool ok = X509_STORE_add_cert(store, cacert) == 1;
    X509_free(cacert);
    if (!ok) { X509_STORE_free(store); return false; }
    *out = store;
    return true;
}

/* The verify callback runs during the handshake.  It does NOT re-implement
 * chain validation: OpenSSL has already done that, and the CA store constrains
 * it to the federation CA.  This decides the second and third questions —
 * whether the key belongs to a node we enrolled, and whether that node is
 * currently trusted.
 *
 * Returning 0 here aborts the handshake, so an unauthorised peer never gets a
 * channel at all. */
static int fed_verify_cb(int preverify_ok, X509_STORE_CTX* store_ctx) {
    if (!preverify_ok) return 0;   /* chain validation failed; OpenSSL said so */

    SSL* ssl = (SSL*)X509_STORE_CTX_get_ex_data(store_ctx,
                    SSL_get_ex_data_X509_STORE_CTX_idx());
    if (!ssl) return 0;
    qihse_fed_tls_server_t* server = (qihse_fed_tls_server_t*)SSL_CTX_get_app_data(SSL_get_SSL_CTX(ssl));
    if (!server || !server->store || !server->user) return 0;

    X509* peer = X509_STORE_CTX_get0_cert(store_ctx);
    if (!peer) return 0;
    EVP_PKEY* pkey = X509_get_pubkey(peer);
    if (!pkey) return 0;

    /* Hash the raw public key, matching how the enrolled node record and the
     * certificate fingerprint are both computed.  One definition of "the
     * node's fingerprint" across enrollment, issuance and verification. */
    size_t raw_len = 0;
    int got = EVP_PKEY_get_raw_public_key(pkey, NULL, &raw_len);
    if (got != 1 || raw_len == 0 || raw_len > 4096u) { EVP_PKEY_free(pkey); return 0; }
    uint8_t raw[4096];
    if (EVP_PKEY_get_raw_public_key(pkey, raw, &raw_len) != 1) {
        EVP_PKEY_free(pkey);
        return 0;
    }
    EVP_PKEY_free(pkey);

    uint8_t fp[QIHSE_FEDERATION_NODE_FINGERPRINT_BYTES];
    unsigned int fp_len = 0;
    if (EVP_Digest(raw, raw_len, fp, &fp_len, EVP_sha384(), NULL) != 1 ||
        fp_len != QIHSE_FEDERATION_NODE_FINGERPRINT_BYTES) {
        return 0;
    }

    qihse_uuid_t node_id;
    qihse_runtime_trust_t trust;
    qihse_peer_verdict_t verdict = qihse_federation_peer_verify(
        server->store, server->user, fp, fp_len, &node_id, &trust);
    if (verdict != QIHSE_PEER_ACCEPT) return 0;

    /* Stash the resolved identity so the accepted session can report it
     * without recomputing anything. */
    SSL_set_ex_data(ssl, 0, NULL);
    uint8_t* stash = (uint8_t*)malloc(QIHSE_UUID_BYTES + 4u);
    if (stash) {
        memcpy(stash, node_id.bytes, QIHSE_UUID_BYTES);
        uint32_t t = (uint32_t)trust;
        memcpy(stash + QIHSE_UUID_BYTES, &t, 4);
        SSL_set_ex_data(ssl, 0, stash);
    }
    return 1;
}

/* Apply the certificate, key, CA store and verification policy shared by both
 * directions.  Keeping this in ONE place is what guarantees the accept and
 * initiate paths cannot drift into different security postures. */
static bool configure_ctx(SSL_CTX* ctx, qihse_fed_tls_server_t* owner,
                          const qihse_federation_ca_t* ca,
                          const char* node_cert_pem, const char* node_key_path) {
    if (SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION) != 1) return false;
    if (SSL_CTX_set1_groups_list(ctx, qihse_federation_tls_group_list()) != 1) return false;

    BIO* cert_bio = BIO_new_mem_buf(node_cert_pem, -1);
    X509* own = cert_bio ? PEM_read_bio_X509(cert_bio, NULL, NULL, NULL) : NULL;
    if (cert_bio) BIO_free(cert_bio);
    if (!own || SSL_CTX_use_certificate(ctx, own) != 1) {
        if (own) X509_free(own);
        return false;
    }
    X509_free(own);
    if (SSL_CTX_use_PrivateKey_file(ctx, node_key_path, SSL_FILETYPE_PEM) != 1) return false;
    if (SSL_CTX_check_private_key(ctx) != 1) return false;

    X509_STORE* ca_store = NULL;
    if (!build_ca_store(ca, &ca_store)) return false;
    SSL_CTX_set_cert_store(ctx, ca_store);

    /* THE line that makes this mutual authentication in BOTH directions.
     * Without SSL_VERIFY_FAIL_IF_NO_PEER_CERT a peer that presents no
     * certificate is admitted, which is exactly the server-auth-only posture
     * this replaces. */
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                       fed_verify_cb);
    SSL_CTX_set_app_data(ctx, owner);
    return true;
}

qihse_fed_tls_server_t* qihse_federation_tls_server_create(
    const qihse_federation_ca_t* ca,
    const char* node_cert_pem,
    const char* node_key_path,
    void* store_void, void* user_void) {
    if (!ca || !node_cert_pem || !node_key_path || !store_void || !user_void) return NULL;
    /* A misconfigured node must fail to start rather than start with a weaker
     * posture than intended. */
    if (strstr(ca->cert_pem, "CERTIFICATE") == NULL) return NULL;
    if (!qihse_federation_cert_verify(node_cert_pem, ca)) return NULL;

    qihse_fed_tls_server_t* s = (qihse_fed_tls_server_t*)calloc(1, sizeof(*s));
    if (!s) return NULL;
    s->store = store_void;
    s->user = user_void;
    s->require_client_cert = true;

    s->server_ctx = SSL_CTX_new(TLS_server_method());
    s->client_ctx = SSL_CTX_new(TLS_client_method());
    if (!s->server_ctx || !s->client_ctx) {
        qihse_federation_tls_server_destroy(s);
        return NULL;
    }
    if (!configure_ctx(s->server_ctx, s, ca, node_cert_pem, node_key_path) ||
        !configure_ctx(s->client_ctx, s, ca, node_cert_pem, node_key_path)) {
        qihse_federation_tls_server_destroy(s);
        return NULL;
    }
    return s;
}

void qihse_federation_tls_server_destroy(qihse_fed_tls_server_t* server) {
    if (!server) return;
    if (server->server_ctx) SSL_CTX_free(server->server_ctx);
    if (server->client_ctx) SSL_CTX_free(server->client_ctx);
    free(server);
}

bool qihse_federation_tls_server_requires_client_cert(const qihse_fed_tls_server_t* s) {
    return s && s->require_client_cert;
}

/* ── Sessions ──────────────────────────────────────────────────────────── */

/* Bound a handshake so a peer that connects and then stalls cannot hold a
 * thread indefinitely. */
static void fed_tls_set_handshake_timeout_ms(int fd, int timeout_ms) {
    struct timeval tv;
    if (timeout_ms <= 0) timeout_ms = QIHSE_FED_TLS_HANDSHAKE_TIMEOUT_SEC * 1000;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    if (tv.tv_sec == 0 && tv.tv_usec == 0) tv.tv_usec = 1000; /* never a zero timeout */
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

static qihse_fed_tls_session_t* session_from_ssl(SSL* ssl, qihse_fed_tls_server_t* server,
                                                bool is_server,
                                                qihse_peer_verdict_t* out_verdict) {
    if (!ssl) {
        if (out_verdict) *out_verdict = QIHSE_PEER_REJECT_NO_CERT;
        return NULL;
    }
    /* SSL_accept/SSL_connect rather than SSL_do_handshake: the role-specific
     * entry points set up the handshake state themselves. */
    int rc = is_server ? SSL_accept(ssl) : SSL_connect(ssl);
    if (rc != 1) {
        /* A refusal in the verify callback lands here, as does a peer that
         * presented no certificate. */
        if (out_verdict) *out_verdict = QIHSE_PEER_REJECT_UNTRUSTED;
        SSL_free(ssl);
        return NULL;
    }
    /* The handshake cannot complete without the callback having accepted, so
     * reaching here means the peer was resolved. */
    qihse_fed_tls_session_t* session = (qihse_fed_tls_session_t*)calloc(1, sizeof(*session));
    if (!session) { SSL_free(ssl); if (out_verdict) *out_verdict = QIHSE_PEER_REJECT_MALFORMED; return NULL; }
    session->ssl = ssl;
    session->server = server;

    uint8_t* stash = (uint8_t*)SSL_get_ex_data(ssl, 0);
    if (stash) {
        memcpy(session->peer_node.bytes, stash, QIHSE_UUID_BYTES);
        uint32_t t = 0;
        memcpy(&t, stash + QIHSE_UUID_BYTES, 4);
        session->peer_trust = (qihse_runtime_trust_t)t;
        session->peer_resolved = true;
    }
    if (out_verdict) *out_verdict = session->peer_resolved ? QIHSE_PEER_ACCEPT
                                                          : QIHSE_PEER_REJECT_UNTRUSTED;
    return session;
}

qihse_fed_tls_session_t* qihse_federation_tls_accept_fd(qihse_fed_tls_server_t* server,
                                                       int fd,
                                                       qihse_peer_verdict_t* out_verdict) {
    if (!server || !server->server_ctx || fd < 0) {
        if (out_verdict) *out_verdict = QIHSE_PEER_REJECT_MALFORMED;
        return NULL;
    }
    /* Bound the handshake.  A peer that connects and then stalls would
     * otherwise hold a thread indefinitely, which is a cheap denial of service
     * against a node that is also trying to serve its own database. */
    fed_tls_set_handshake_timeout_ms(fd, 0); /* the fixed default */

    SSL* ssl = SSL_new(server->server_ctx);
    if (!ssl) { if (out_verdict) *out_verdict = QIHSE_PEER_REJECT_MALFORMED; return NULL; }
    SSL_set_fd(ssl, fd);
    SSL_set_accept_state(ssl);
    return session_from_ssl(ssl, server, true, out_verdict);
}

qihse_fed_tls_session_t* qihse_federation_tls_connect_fd(qihse_fed_tls_server_t* ctx_holder,
                                                        int fd,
                                                        int timeout_ms,
                                                        qihse_peer_verdict_t* out_verdict) {
    if (!ctx_holder || !ctx_holder->client_ctx || fd < 0) {
        if (out_verdict) *out_verdict = QIHSE_PEER_REJECT_MALFORMED;
        return NULL;
    }
    fed_tls_set_handshake_timeout_ms(fd, timeout_ms);

    /* The CLIENT context.  This node presents its own certificate and verifies
     * the server's against the same CA under the same policy, so both
     * directions are mutually authenticated and cannot drift apart. */
    SSL* ssl = SSL_new(ctx_holder->client_ctx);
    if (!ssl) { if (out_verdict) *out_verdict = QIHSE_PEER_REJECT_MALFORMED; return NULL; }
    SSL_set_fd(ssl, fd);
    SSL_set_connect_state(ssl);
    return session_from_ssl(ssl, ctx_holder, false, out_verdict);
}

void qihse_federation_tls_session_destroy(qihse_fed_tls_session_t* session) {
    if (!session) return;
    if (session->ssl) {
        uint8_t* stash = (uint8_t*)SSL_get_ex_data(session->ssl, 0);
        if (stash) free(stash);
        SSL_shutdown(session->ssl);
        SSL_free(session->ssl);
    }
    free(session);
}

bool qihse_federation_tls_peer_identity(const qihse_fed_tls_session_t* session,
                                        qihse_uuid_t* out_node_id,
                                        qihse_runtime_trust_t* out_trust) {
    if (!session || !session->peer_resolved) return false;
    if (out_node_id) *out_node_id = session->peer_node;
    if (out_trust) *out_trust = session->peer_trust;
    return true;
}

bool qihse_federation_tls_negotiated(const qihse_fed_tls_session_t* session,
                                     char* out_group, size_t group_cap,
                                     char* out_version, size_t version_cap) {
    if (!session || !session->ssl) return false;
    const char* version = SSL_get_version(session->ssl);
    if (out_version && version_cap) snprintf(out_version, version_cap, "%s", version ? version : "");
    const char* group = NULL;
    /* The negotiated group is the evidence that key exchange is actually
     * post-quantum, rather than something the deployment assumes. */
    if (SSL_get_negotiated_group(session->ssl) != 0) {
        int nid = SSL_get_negotiated_group(session->ssl);
        group = SSL_group_to_name(session->ssl, nid);
    }
    if (out_group && group_cap) snprintf(out_group, group_cap, "%s", group ? group : "unknown");
    return true;
}

/* ── Listener ──────────────────────────────────────────────────────────── */

struct qihse_fed_listener {
    int fd;
    uint16_t port;
    qihse_fed_tls_server_t* server;   /* not owned */
};

/* Bound on how many connections may be queued before accept().  A larger
 * backlog lets a peer flood the queue faster than the node drains it. */
#define FED_TLS_BACKLOG 8

qihse_fed_listener_t* qihse_federation_listener_open(qihse_fed_tls_server_t* server,
                                                    const char* bind_address,
                                                    uint16_t port) {
    if (!server || !server->server_ctx || !bind_address) return NULL;
    /* A wildcard bind is refused rather than honoured by default: exposing a
     * federation port on every interface is an operator's decision. */
    if (bind_address[0] == '\0' || strcmp(bind_address, "*") == 0 ||
        strcmp(bind_address, "0.0.0.0") == 0 || strcmp(bind_address, "::") == 0) {
        return NULL;
    }

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_NUMERICHOST | AI_PASSIVE;

    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%u", (unsigned)port);

    struct addrinfo* res = NULL;
    if (getaddrinfo(bind_address, port_str, &hints, &res) != 0 || !res) return NULL;

    int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0) { freeaddrinfo(res); return NULL; }

    int one = 1;
    (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    if (bind(fd, res->ai_addr, res->ai_addrlen) != 0 ||
        listen(fd, FED_TLS_BACKLOG) != 0) {
        close(fd);
        freeaddrinfo(res);
        return NULL;
    }
    freeaddrinfo(res);

    /* Report the port the kernel actually assigned, which is the only way to
     * learn it when port 0 was requested. */
    struct sockaddr_storage ss;
    socklen_t slen = sizeof(ss);
    uint16_t bound_port = 0;
    if (getsockname(fd, (struct sockaddr*)&ss, &slen) == 0) {
        if (ss.ss_family == AF_INET) {
            bound_port = ntohs(((struct sockaddr_in*)&ss)->sin_port);
        } else if (ss.ss_family == AF_INET6) {
            bound_port = ntohs(((struct sockaddr_in6*)&ss)->sin6_port);
        }
    }

    qihse_fed_listener_t* l = (qihse_fed_listener_t*)calloc(1, sizeof(*l));
    if (!l) { close(fd); return NULL; }
    l->fd = fd;
    l->port = bound_port;
    l->server = server;
    return l;
}

void qihse_federation_listener_close(qihse_fed_listener_t* listener) {
    if (!listener) return;
    if (listener->fd >= 0) close(listener->fd);
    listener->fd = -1;
    free(listener);
}

uint16_t qihse_federation_listener_port(const qihse_fed_listener_t* listener) {
    return listener ? listener->port : 0;
}

qihse_fed_tls_session_t* qihse_federation_listener_accept(qihse_fed_listener_t* listener,
                                                         int timeout_ms,
                                                         qihse_peer_verdict_t* out_verdict) {
    if (out_verdict) *out_verdict = QIHSE_PEER_REJECT_MALFORMED;
    if (!listener || listener->fd < 0) return NULL;

    /* Wait for a connection without blocking indefinitely, so a caller can
     * still observe shutdown.  A timeout is not an error and leaves the
     * listener usable. */
    struct pollfd pfd;
    pfd.fd = listener->fd;
    pfd.events = POLLIN;
    pfd.revents = 0;
    int pr = poll(&pfd, 1, timeout_ms < 0 ? -1 : timeout_ms);
    if (pr <= 0) return NULL;
    if (!(pfd.revents & POLLIN)) return NULL;

    struct sockaddr_storage peer_addr;
    socklen_t peer_len = sizeof(peer_addr);
    int cfd = accept(listener->fd, (struct sockaddr*)&peer_addr, &peer_len);
    if (cfd < 0) return NULL;

    /* The handshake runs with its own bound (set inside accept_fd), so a peer
     * that connects and then stalls cannot hold this thread past it.  A
     * refusal here closes this connection only — the listener survives, which
     * is what stops a hostile peer from denying service by being refused. */
    qihse_peer_verdict_t verdict = QIHSE_PEER_REJECT_MALFORMED;
    qihse_fed_tls_session_t* session = qihse_federation_tls_accept_fd(listener->server,
                                                                     cfd, &verdict);
    if (!session) {
        close(cfd);
        if (out_verdict) *out_verdict = verdict;
        return NULL;
    }
    if (out_verdict) *out_verdict = verdict;
    return session;
}

bool qihse_federation_tls_session_peer_gone(qihse_fed_tls_session_t* session,
                                            int timeout_ms) {
    if (!session || !session->ssl) return true;

    /* A clean shutdown already tells us. */
    if (SSL_get_shutdown(session->ssl) != 0) return true;

    int fd = SSL_get_fd(session->ssl);
    if (fd < 0) return true;

    /* TLS 1.3 validates the client certificate AFTER the client's handshake
     * completes, so a refusal arrives as a post-handshake alert.  Wait a short
     * moment for one and read it if it lands. */
    struct pollfd pfd;
    pfd.fd = fd;
    pfd.events = POLLIN;
    pfd.revents = 0;
    int pr = poll(&pfd, 1, timeout_ms < 0 ? 0 : timeout_ms);
    if (pr <= 0) return false;   /* nothing waiting: the peer is still there */
    if (!(pfd.revents & (POLLIN | POLLHUP | POLLERR))) return false;

    uint8_t scratch[1];
    int n = SSL_read(session->ssl, scratch, 1);
    if (n > 0) return false;   /* real data, not an alert */
    int err = SSL_get_error(session->ssl, n);
    /* ZERO_RETURN is a clean close; SSL_ERROR_SSL is a fatal alert.  Both mean
     * the peer is gone, which for our purposes is the same answer. */
    return err == SSL_ERROR_ZERO_RETURN || err == SSL_ERROR_SSL ||
           err == SSL_ERROR_SYSCALL;
}

qihse_fed_tls_session_t* qihse_federation_tls_connect_to(qihse_fed_tls_server_t* server,
                                                        const char* host,
                                                        uint16_t port,
                                                        int timeout_ms,
                                                        qihse_peer_verdict_t* out_verdict) {
    if (out_verdict) *out_verdict = QIHSE_PEER_REJECT_MALFORMED;
    if (!server || !server->client_ctx || !host) return NULL;
    /* HONOURED, not decorative. This parameter was documented and silently
     * ignored: a caller passing 5000 got the fixed 10 s bound, and one passing
     * 100 also got 10 s. An API that takes a bound and ignores it is the same
     * defect class as a function that reports success without doing the work —
     * the signature promises something the implementation does not deliver.
     *
     * timeout_ms <= 0 means "use the default". */
    if (timeout_ms <= 0) timeout_ms = QIHSE_FED_TLS_HANDSHAKE_TIMEOUT_SEC * 1000;

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_NUMERICHOST;

    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%u", (unsigned)port);

    struct addrinfo* res = NULL;
    if (getaddrinfo(host, port_str, &hints, &res) != 0 || !res) return NULL;

    int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0) { freeaddrinfo(res); return NULL; }

    /* Bound the CONNECT itself.  A peer that is unreachable must not stall the
     * caller for the kernel's default SYN timeout. */
    fed_tls_set_handshake_timeout_ms(fd, timeout_ms);

    int rc = connect(fd, res->ai_addr, res->ai_addrlen);
    freeaddrinfo(res);
    if (rc != 0) { close(fd); return NULL; }

    qihse_fed_tls_session_t* session = qihse_federation_tls_connect_fd(server, fd,
                                                                      timeout_ms,
                                                                      out_verdict);
    if (!session) { close(fd); return NULL; }

    /* A completed handshake here means THIS side verified the peer.  The peer
     * may still have refused us, because TLS 1.3 validates the client
     * certificate after the client's handshake finishes.  Give a refusal a
     * brief window to arrive so the common case is reported honestly rather
     * than as a session that silently does nothing. */
    /* The alert window is a fraction of the caller's bound, capped: a short
     * connect timeout should not be spent entirely waiting for an alert that
     * may never come, and a long one should not add seconds of latency. */
    {
        int alert_window = timeout_ms / 10;
        if (alert_window > 200) alert_window = 200;
        if (alert_window < 20) alert_window = 20;
    if (qihse_federation_tls_session_peer_gone(session, alert_window)) {
        if (out_verdict) *out_verdict = QIHSE_PEER_REJECT_UNTRUSTED;
        qihse_federation_tls_session_destroy(session);
        close(fd);
        return NULL;
    }
    }
    return session;
}

/* ── Replication transport ─────────────────────────────────────────────── */

static bool tls_connect(void* ctx, const char* peer) {
    (void)peer;   /* the fd is already connected; identity came from the handshake */
    return ctx != NULL;
}

static long tls_send(void* ctx, const uint8_t* buf, size_t len) {
    qihse_fed_tls_session_t* s = (qihse_fed_tls_session_t*)ctx;
    if (!s || !s->ssl) return -1;
    size_t sent = 0;
    while (sent < len) {
        int n = SSL_write(s->ssl, buf + sent, (int)(len - sent));
        if (n <= 0) return -1;
        sent += (size_t)n;
    }
    return (long)sent;
}

static long tls_recv(void* ctx, uint8_t* buf, size_t cap) {
    qihse_fed_tls_session_t* s = (qihse_fed_tls_session_t*)ctx;
    if (!s || !s->ssl) return -1;
    int n = SSL_read(s->ssl, buf, (int)cap);
    if (n > 0) return (long)n;
    int err = SSL_get_error(s->ssl, n);
    if (err == SSL_ERROR_ZERO_RETURN) return 0;   /* clean close */
    return -1;
}

static void tls_close(void* ctx) {
    qihse_fed_tls_session_t* s = (qihse_fed_tls_session_t*)ctx;
    if (s && s->ssl) SSL_shutdown(s->ssl);
}

static bool tls_peer_fingerprint(void* ctx, uint8_t* out) {
    qihse_fed_tls_session_t* s = (qihse_fed_tls_session_t*)ctx;
    if (!s || !s->ssl || !out) return false;
    /* Recomputed from the peer's certificate rather than taken on trust from
     * the handshake, so the caller's comparison is against the real chain. */
    X509* peer = SSL_get1_peer_certificate(s->ssl);
    if (!peer) return false;
    EVP_PKEY* pkey = X509_get_pubkey(peer);
    bool ok = false;
    if (pkey) {
        size_t raw_len = 0;
        if (EVP_PKEY_get_raw_public_key(pkey, NULL, &raw_len) == 1 &&
            raw_len > 0 && raw_len <= 4096u) {
            uint8_t raw[4096];
            if (EVP_PKEY_get_raw_public_key(pkey, raw, &raw_len) == 1) {
                unsigned int fp_len = 0;
                ok = EVP_Digest(raw, raw_len, out, &fp_len, EVP_sha384(), NULL) == 1 &&
                     fp_len == QIHSE_FEDERATION_NODE_FINGERPRINT_BYTES;
            }
        }
        EVP_PKEY_free(pkey);
    }
    X509_free(peer);
    return ok;
}

qihse_repl_transport_ops_t qihse_federation_tls_transport_ops(qihse_fed_tls_session_t* session) {
    qihse_repl_transport_ops_t ops;
    memset(&ops, 0, sizeof(ops));
    ops.connect = tls_connect;
    ops.send = tls_send;
    ops.recv = tls_recv;
    ops.close = tls_close;
    ops.peer_fingerprint = tls_peer_fingerprint;
    (void)session;
    return ops;
}
