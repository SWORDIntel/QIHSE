#ifndef QIHSE_FEDERATION_TRANSPORT_H
#define QIHSE_FEDERATION_TRANSPORT_H

/*
 * QIHSE federation mTLS transport.
 * See v3.md §18 (node identity and trust) and §22 (replication transport).
 *
 * The generic UWP TLS layer provides a server certificate and a session over
 * an fd, but it has no way to REQUIRE a client certificate or to read the
 * peer's — which is the whole of mutual authentication.  So federation owns
 * its own TLS context here, built on the federation CA and the three-layer
 * peer decision.
 *
 * This module also supplies the transport that the replication range transfer
 * runs over, so a peer's identity is verified once at handshake and the
 * transfer rides the verified channel.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "qihse_federation.h"
#include "qihse_federation_mtls.h"
#include "qihse_federation_repl.h"
#include "qihse_runtime_trust.h"

/* A handshake that never completes would hold a thread indefinitely, which is
 * a cheap denial of service against a node that is also serving its own
 * database. */
#define QIHSE_FED_TLS_HANDSHAKE_TIMEOUT_SEC 10

#ifdef __cplusplus
extern "C" {
#endif

/* ── Server context ────────────────────────────────────────────────────── */

typedef struct qihse_fed_tls_server qihse_fed_tls_server_t;

/* Build an mTLS server context.
 *
 * `node_cert_pem` is this node's certificate and `node_key_path` its private
 * key.  `ca` is the federation CA whose issued client certificates are the
 * only ones accepted.  `store`/`user` are the context the three-layer peer
 * decision runs against, so a certificate that verifies but belongs to an
 * unenrolled or untrusted node is refused at handshake time rather than
 * admitted and checked later.
 *
 * A pre-quantum CA is refused, and so is a certificate that does not verify
 * against that CA — a misconfigured node fails to start rather than starting
 * with a weaker posture than intended. */
qihse_fed_tls_server_t* qihse_federation_tls_server_create(
    const qihse_federation_ca_t* ca,
    const char* node_cert_pem,
    const char* node_key_path,
    void* store_void, void* user_void);

void qihse_federation_tls_server_destroy(qihse_fed_tls_server_t* server);

/* Require a client certificate?  True by default; exposed so the setting is
 * visible and testable rather than implicit. */
bool qihse_federation_tls_server_requires_client_cert(const qihse_fed_tls_server_t* s);

/* ── Sessions ──────────────────────────────────────────────────────────── */

typedef struct qihse_fed_tls_session qihse_fed_tls_session_t;

/* Perform a server-side handshake on an already-connected fd.
 *
 * Returns NULL if the handshake fails, if the peer presents no certificate,
 * or if the three-layer decision refuses the peer.  A refusal is therefore a
 * failed connection, not a connection that later turns out to be unauthorised.
 *
 * On success `out_verdict` reports why it was accepted and the session knows
 * the peer's identity. */
qihse_fed_tls_session_t* qihse_federation_tls_accept_fd(qihse_fed_tls_server_t* server,
                                                       int fd,
                                                       qihse_peer_verdict_t* out_verdict);

/* Perform a client-side handshake on an already-connected fd. */
qihse_fed_tls_session_t* qihse_federation_tls_connect_fd(qihse_fed_tls_server_t* ctx_holder,
                                                        int fd,
                                                        int timeout_ms,
                                                        qihse_peer_verdict_t* out_verdict);

void qihse_federation_tls_session_destroy(qihse_fed_tls_session_t* session);

/* The verified peer identity.  False when the session has none, which must
 * never be treated as "any peer". */
bool qihse_federation_tls_peer_identity(const qihse_fed_tls_session_t* session,
                                        qihse_uuid_t* out_node_id,
                                        qihse_runtime_trust_t* out_trust);

/* The negotiated key-exchange group and TLS version, so a deployment can prove
 * it is actually running post-quantum key exchange rather than assuming it. */
bool qihse_federation_tls_negotiated(const qihse_fed_tls_session_t* session,
                                     char* out_group, size_t group_cap,
                                     char* out_version, size_t version_cap);

/* ── Listener ──────────────────────────────────────────────────────────── */

typedef struct qihse_fed_listener qihse_fed_listener_t;

/* Bind and listen for federation peers.
 *
 * `bind_address` is REQUIRED and is not defaulted to a wildcard: a federation
 * port exposed on every interface is a decision an operator must make
 * deliberately, not one this code makes for them.  Pass "127.0.0.1" for a
 * loopback-only node.  Port 0 asks the kernel for an ephemeral port, which
 * qihse_federation_listener_port() then reports.
 *
 * Returns NULL if the address is unusable or the bind fails, so a node that
 * cannot listen says so at startup rather than silently accepting nothing. */
qihse_fed_listener_t* qihse_federation_listener_open(qihse_fed_tls_server_t* server,
                                                    const char* bind_address,
                                                    uint16_t port);

void qihse_federation_listener_close(qihse_fed_listener_t* listener);

/* The port actually bound, which matters when port 0 was requested. */
uint16_t qihse_federation_listener_port(const qihse_fed_listener_t* listener);

/* Accept ONE connection and complete the handshake with peer verification.
 *
 * Returns NULL when no peer arrives within `timeout_ms` — that is not an error
 * and the listener remains usable — and also when a peer connects but is
 * refused.  A refusal is per-connection: a hostile peer cannot take the
 * listener down, and the caller cannot distinguish "refused" from "nobody
 * called" except through `out_verdict`, which is what keeps a refusal from
 * becoming an oracle.
 *
 * The returned session owns the connection; destroy it to close. */
qihse_fed_tls_session_t* qihse_federation_listener_accept(qihse_fed_listener_t* listener,
                                                         int timeout_ms,
                                                         qihse_peer_verdict_t* out_verdict);

/* Connect to a federation peer and complete the handshake.
 *
 * Symmetric with listener_accept: this node presents its certificate and
 * verifies the peer's against the same CA under the same policy, so the two
 * directions cannot drift apart.
 *
 * IMPORTANT ASYMMETRY, and it is a property of TLS 1.3 rather than of this
 * code: the server validates the client's certificate AFTER the client's own
 * handshake has completed.  So a client whose SSL_connect succeeded may be
 * talking to a server that has already refused it.  A completed handshake on
 * the initiating side therefore means "I verified the peer", NOT "the peer
 * accepted me", and any decision that depends on the peer's acceptance needs
 * an application-level confirmation.
 *
 * This function does a best-effort check for a post-handshake fatal alert so
 * the common case of immediate refusal is reported as failure, but the check
 * is a heuristic with a short window, not a guarantee.  Do not build an
 * authority decision on it. */
qihse_fed_tls_session_t* qihse_federation_tls_connect_to(qihse_fed_tls_server_t* server,
                                                        const char* host,
                                                        uint16_t port,
                                                        int timeout_ms,
                                                        qihse_peer_verdict_t* out_verdict);

/* True if the peer has sent a fatal alert or closed the connection.
 *
 * This is the reliable check: after the first successful exchange with a peer,
 * a refusal will have surfaced.  Call it before acting on a session whose
 * acceptance matters. */
bool qihse_federation_tls_session_peer_gone(qihse_fed_tls_session_t* session,
                                            int timeout_ms);

/* ── Replication transport over the verified channel ───────────────────── */

/* Build transport ops bound to a session.  The peer identity comes from the
 * handshake, so `peer_fingerprint` always succeeds and the range transfer's
 * "unverified peer" guard is satisfied by construction. */
qihse_repl_transport_ops_t qihse_federation_tls_transport_ops(qihse_fed_tls_session_t* session);

#ifdef __cplusplus
}
#endif

#endif /* QIHSE_FEDERATION_TRANSPORT_H */
