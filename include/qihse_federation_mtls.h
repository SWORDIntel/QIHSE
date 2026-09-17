#ifndef QIHSE_FEDERATION_MTLS_H
#define QIHSE_FEDERATION_MTLS_H

/*
 * QIHSE federation mTLS — mutual authentication for federation RPC.
 * See v3.md §18 (node identity and trust) and §22 (replication transport).
 *
 * Post-quantum throughout: the CA and node certificates are ML-DSA, and the
 * key exchange uses the X25519MLKEM768 hybrid group, both of which this
 * toolchain provides natively.
 *
 * The CA private key lives OUTSIDE the database process (plan §3.8).  QIHSE
 * stores the CA certificate and the issued node certificates; it never holds
 * the CA key, and it is never able to mint its own authority.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "qihse_federation.h"
#include "qihse_runtime_trust.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Sized for a real post-quantum certificate: an ML-DSA-87 certificate carries
 * a 2592-byte public key AND a 4627-byte signature, which is roughly 10 KB of
 * base64 once PEM-encoded.  A pre-quantum-sized buffer silently truncates. */
#define QIHSE_FEDERATION_PEM_MAX 16384u

/* ── Federation CA ─────────────────────────────────────────────────────── */

typedef struct {
    char cert_pem[QIHSE_FEDERATION_PEM_MAX];
    size_t cert_pem_len;
    /* SHA-384 of the CA's public key, hex.  This is the value an operator
     * records out of band and compares against, so a substituted CA is
     * detectable by a human as well as by a fingerprint check. */
    char fingerprint_hex[97];
} qihse_federation_ca_t;

/* Create a federation CA: an ML-DSA keypair plus a self-signed certificate.
 *
 * The private key is written to "<dir>/federation-ca.key" at 0600 and is NOT
 * returned or cached — the caller must move it somewhere the database process
 * cannot read.  Only the certificate and its fingerprint come back. */
bool qihse_federation_ca_create(const char* dir, qihse_sig_alg_t alg,
                                qihse_federation_ca_t* out);

/* Issue a node certificate signed by the CA.
 *
 * The caller supplies the path to the CA private key, because only the
 * enrollment authority holds it.  The certificate binds the node's public key
 * to its UUID and carries the enrollment epoch, so a certificate issued before
 * a revocation is distinguishable from one issued after it. */
bool qihse_federation_ca_issue_node(const char* ca_key_path,
                                    const qihse_federation_ca_t* ca,
                                    const qihse_federation_node_identity_t* node,
                                    uint64_t enrollment_epoch,
                                    char* out_cert_pem, size_t out_cap);

/* SHA-384 fingerprint of a certificate's public key.  This is the value
 * compared against the enrolled node record, so it must be computed the same
 * way for issuance and for verification. */
bool qihse_federation_cert_fingerprint(const char* cert_pem,
                                       uint8_t* out_fingerprint);

/* True when the certificate's own signature verifies against the CA.  Proves
 * the certificate was issued by the CA and has not been altered. */
bool qihse_federation_cert_verify(const char* cert_pem,
                                  const qihse_federation_ca_t* ca);

/* ── The three-layer peer decision ─────────────────────────────────────── */

/* Each layer answers a DIFFERENT question, and collapsing them is how "valid
 * certificate" gets mistaken for "trusted":
 *
 *   1. Does the peer hold the private key?          -> TLS handshake
 *   2. Is that key a CURRENT enrolled node's?       -> fingerprint match
 *   3. Is that node currently TRUSTWORTHY?          -> runtime trust state
 *
 * This function answers 2 and 3.  Layer 1 has already happened by the time it
 * is called, which is why it takes a fingerprint rather than a certificate. */
typedef enum {
    QIHSE_PEER_ACCEPT = 0,
    QIHSE_PEER_REJECT_NO_CERT,
    QIHSE_PEER_REJECT_UNKNOWN_FINGERPRINT, /* layer 2: not an enrolled node */
    QIHSE_PEER_REJECT_NOT_YET_APPROVED,    /* layer 2: enrolled but pending */
    QIHSE_PEER_REJECT_REVOKED,             /* layer 2: permanently denied */
    QIHSE_PEER_REJECT_UNTRUSTED,           /* layer 3: runtime trust withholds */
    QIHSE_PEER_REJECT_MALFORMED
} qihse_peer_verdict_t;

const char* qihse_peer_verdict_name(qihse_peer_verdict_t v);

/* Decide whether a peer may hold a federation session.
 *
 * `out_node_id` receives the resolved node on success, so the caller attributes
 * the connection to an identity rather than to an address.  `out_trust` reports
 * the runtime trust state that was applied, which may be more restrictive than
 * the enrollment state. */
qihse_peer_verdict_t qihse_federation_peer_verify(void* store_void, void* user_void,
                                                 const uint8_t* cert_fingerprint,
                                                 size_t fingerprint_len,
                                                 qihse_uuid_t* out_node_id,
                                                 qihse_runtime_trust_t* out_trust);

/* ── TLS configuration helpers ─────────────────────────────────────────── */

/* The hybrid post-quantum key-exchange group list.
 *
 * X25519MLKEM768 protects the session key against harvest-now-decrypt-later,
 * which is the half of TLS that must move first: recorded traffic can be
 * decrypted years later, whereas a forged signature must be created at the
 * moment of the handshake. */
const char* qihse_federation_tls_group_list(void);

/* The minimum TLS version this deployment accepts. */
const char* qihse_federation_tls_min_version(void);

#ifdef __cplusplus
}
#endif

#endif /* QIHSE_FEDERATION_MTLS_H */
