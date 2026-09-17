#ifndef QIHSE_FEDERATION_TRANSPORT_H
#define QIHSE_FEDERATION_TRANSPORT_H

/*
 * QIHSE federation mTLS transport.
 * See v3.md §18 (node identity and trust) and §22 (replication transport).
 *
 * STATUS: NOT FUNCTIONAL.  The mTLS security core this depends on (federation
 * CA, certificate issuance, and the three-layer peer decision) is complete and
 * tested in qihse_federation_mtls.  This transport layer is written but its
 * TLS handshake currently fails with SSL_R_CALLED_A_FUNCTION_YOU_SHOULD_NOT_CALL
 * on the client side, and it is deliberately NOT built or shipped until that
 * is resolved.  Do not wire it in.
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

/* ── Replication transport over the verified channel ───────────────────── */

/* Build transport ops bound to a session.  The peer identity comes from the
 * handshake, so `peer_fingerprint` always succeeds and the range transfer's
 * "unverified peer" guard is satisfied by construction. */
qihse_repl_transport_ops_t qihse_federation_tls_transport_ops(qihse_fed_tls_session_t* session);

#ifdef __cplusplus
}
#endif

#endif /* QIHSE_FEDERATION_TRANSPORT_H */
/*
 * LEAD on the handshake failure, for whoever picks this up:
 *
 * The client fails with SSL_R_CALLED_A_FUNCTION_YOU_SHOULD_NOT_CALL before any
 * certificate verification runs, and the server then blocks.  The prime
 * suspect is that fed_verify_cb() stores the resolved peer identity with
 * SSL_set_ex_data(ssl, 0, ...) and reads it back with SSL_get_ex_data(ssl, 0).
 * Index 0 in an SSL's ex_data space is not safe for user data — indices must be
 * allocated with SSL_get_ex_new_index().  Writing over a reserved slot would
 * corrupt OpenSSL's own state and produce exactly this class of error.
 *
 * First thing to try: allocate a proper index and use it.  Second: confirm the
 * server side actually reaches fed_verify_cb at all, since no callback entry
 * was observed in the diagnostic run.
 */
