#ifndef QIHSE_FEDERATION_MTLS_H
#define QIHSE_FEDERATION_MTLS_H

/*
 * QIHSE federation mTLS — mutual authentication for federation RPC.
 * See docs/plans/qihse_federation_upgrade_plan.md §18 (node identity and trust) and §22 (replication transport).
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
    QIHSE_PEER_REJECT_MALFORMED,
    /* Layer 2, file revocation source: a CRL is configured but could not be
     * parsed.  Fails the whole check closed rather than verifying as clean
     * (appended last so existing verdict values keep their ABI numbering). */
    QIHSE_PEER_REJECT_CRL
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

/* ── Node-side CRL: the file half of revocation state ────────────────────
 *
 * The out-of-process CA tool appends revocation records to a file the
 * running node can read (qihse_ca_provision_revoke, format
 * QIHSE-FED-CRL-V1 — see include/qihse_ca_provision.h).  The KV "fednode:"
 * record is the OTHER half.  The two COMPOSE: either source saying REVOKED
 * refuses the peer at layer 2 of qihse_federation_peer_verify, with the same
 * verdict a KV-revoked node produces.  The file is never sniffed
 * ambiently — an operator loads it explicitly, and a load that finds a
 * malformed record fails the whole check closed (sticky, until a good CRL
 * is loaded or the file source is explicitly cleared), mirroring the CA
 * tool's own qihse_ca_provision_crl_check semantics exactly.
 *
 * Matching follows the tool's parser: by node UUID, or by fingerprint when
 * the entry carries one.  A configured-but-absent file is an EMPTY list
 * (valid, nothing revoked), exactly as in the tool.
 *
 * Authorization decision (deliberate, per the repo security rules): the CRL
 * file is not classified user data — it carries node UUIDs, fingerprints and
 * free-text reasons — so loading it is not a classified-read primitive.
 * It IS security-relevant trust-plane configuration: installing it decides
 * which enrolled peers the node refuses, it is the node-side application of
 * the same QIHSE_SCOPE_NODE_REVOKE authority the CA tool needs to APPEND a
 * revocation, and an unauthenticated in-process caller must not be able to
 * point the node at a file of its choosing, poison the state, or clear it —
 * any more than it could call qihse_federation_node_revoke.  Hence
 * qihse_federation_crl_load takes an explicit authenticated operator
 * context holding QIHSE_SCOPE_NODE_REVOKE and REFUSES NULL (NULL is never
 * an authorization bypass).  qihse_federation_crl_check performs no I/O and
 * discloses a single bit of trust-plane state about a caller-supplied
 * identity, so it takes no context; the authority gate is at load time.
 */

/* Upper bound on in-memory entries.  A CRL line is bounded
 * (QIHSE_CA_PROVISION_CRL_LINE_MAX), so this caps the snapshot a runaway
 * or hostile file can force the node to hold; exceeding it fails closed. */
#define QIHSE_FEDERATION_CRL_MAX_ENTRIES 65536u

typedef struct {
    size_t entry_count;  /* revocation records currently loaded */
    bool configured;     /* a CRL path is installed (possibly an empty list) */
    bool failed;         /* last load failed: every check fails closed */
} qihse_federation_crl_status_t;

/* Load (or reload) the append-only CRL written by the CA tool.  The file is
 * parsed with the tool's own strict semantics: any malformed record fails
 * the load AND leaves the check failing closed for every peer until a valid
 * CRL is loaded or the source is cleared.  crl_path == NULL is an explicit
 * authorized opt-out that returns the node to KV-only revocation.
 * Requires an operator context holding QIHSE_SCOPE_NODE_REVOKE. */
bool qihse_federation_crl_load(void* operator_user, const char* crl_path);

/* Strict lookup against the loaded snapshot.  Returns false only when the
 * configured CRL failed to load (fail closed — never verifies as clean);
 * with no CRL configured it is a no-op returning true / not revoked. */
bool qihse_federation_crl_check(const qihse_uuid_t* node_id,
                                const uint8_t* node_fingerprint,
                                bool* out_revoked);

/* Current snapshot state, for diagnostics and tests. */
void qihse_federation_crl_state(qihse_federation_crl_status_t* out);

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
