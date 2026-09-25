#ifndef QIHSE_CA_PROVISION_H
#define QIHSE_CA_PROVISION_H

/*
 * qihse_ca_provision.h — OUT-OF-PROCESS federation CA provisioning.
 *
 * The mTLS layer (qihse_federation_mtls.h) states the invariant this module
 * exists to finish: "The CA private key lives OUTSIDE the database process.
 * QIHSE stores the CA certificate and the issued node certificates; it never
 * holds the CA key, and it is never able to mint its own authority."
 *
 * Everything here is an OPERATOR-SIDE, files-only facility: no sockets, no
 * long-running process, no QIHSE records are written.  It is compiled into the
 * offline tool (tools/qihse_federation_ca.c) and into tests — deliberately
 * NOT into libqihse.so, so linking the server can never give the database a
 * CA-minting primitive.
 *
 * Formats consumed/produced:
 *   - CA and node certificates are PEM X.509, byte-compatible with what
 *     qihse_federation_mtls.c loads (PEM_read_bio_X509) and verifies
 *     (qihse_federation_cert_verify).  Issuance mirrors
 *     qihse_federation_ca_issue_node: serial = enrollment_epoch + 1, CN
 *     "QIHSE node <uuid>", SAN "URI:qihse://node/<uuid>", EKU
 *     clientAuth,serverAuth, basicConstraints critical CA:FALSE, and the
 *     node's EXISTING identity public key as the certificate key — so the
 *     SHA-384 fingerprint an operator already recorded keeps meaning the
 *     same thing after issuance.
 *   - The revocation list is an append-only file; see
 *     QIHSE_CA_PROVISION_CRL_MAGIC.  The federation module currently holds
 *     revocation state in the KV node identity record
 *     (qihse_federation_node_revoke -> trust=REVOKED, scopes=NONE); this
 *     file is the operator-side, out-of-process form of that state and is a
 *     declared follow-up wiring point.
 *
 * Authorization model (AGENTS.md invariants 1 and 2):
 *   - Every mutating call takes an explicit authenticated operator context
 *     (a qihse_user_t*, passed as void* for header hygiene, matching the
 *     federation module's style).  NULL is refused, never a bypass.
 *   - No principal may grant above itself: issuance requires the operator to
 *     hold QIHSE_SCOPE_NODE_ENROLL and EVERY scope carried by the issued
 *     certificate (qihse_infra_scope_check enforces the subset relation).
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "qihse_federation.h"
#include "qihse_federation_mtls.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ── Revocation list (CRL) file format ───────────────────────────────────
 *
 * Append-only, one record per line, tab-separated like every other
 * federation record; binary fields are hex-encoded:
 *
 *   QIHSE-FED-CRL-V1 \t <node-uuid-36> \t <cert-serial-dec> \t
 *   <fingerprint-96-hex | -> \t <revoked-at-unix-dec> \t <reason> \n
 *
 * A certificate is revoked when its node UUID matches an entry, or when its
 * recomputed public-key fingerprint matches an entry that carries one.  The
 * decoder is strict: a malformed line fails the whole check (fail closed)
 * rather than being skipped. */
#define QIHSE_CA_PROVISION_CRL_MAGIC      "QIHSE-FED-CRL-V1"
#define QIHSE_CA_PROVISION_CRL_REASON_MAX 128u
#define QIHSE_CA_PROVISION_CRL_LINE_MAX   512u

/* Private (unregistered) OID arc for the enrollment-scope certificate
 * extension written by issue-node.  The extension is non-critical, and its
 * value is exactly 4 bytes: the qihse_infra_scope_t mask, big-endian. */
#define QIHSE_CA_PROVISION_SCOPE_OID "1.3.6.1.4.1.61117.1"

/* Node certificates are short-lived; the CA outlives them (plan §18). */
#define QIHSE_CA_PROVISION_DEFAULT_VALIDITY_S (60LL * 60 * 24 * 30)
#define QIHSE_CA_PROVISION_CA_VALIDITY_S      (60LL * 60 * 24 * 365 * 5)
/* Sanity bounds so a mistyped CLI flag cannot mint a 1000-year certificate. */
#define QIHSE_CA_PROVISION_MAX_VALIDITY_S     (60LL * 60 * 24 * 3650)
#define QIHSE_CA_PROVISION_MAX_TIME_OFFSET_S  (60LL * 60 * 24 * 3650)

/* ── Issuance request ──────────────────────────────────────────────────── */

typedef struct {
    qihse_uuid_t node_id;         /* the identity being certificated */
    qihse_sig_alg_t sig_alg;      /* algorithm of public_key */
    const uint8_t* public_key;    /* the node's EXISTING raw identity key */
    size_t public_key_len;
    /* Optional cross-check: when non-NULL (48 bytes), it must equal the
     * fingerprint recomputed from public_key, or issuance refuses.  This is
     * how "the fingerprint the operator already recorded" stays bound. */
    const uint8_t* expected_fingerprint;
    uint64_t enrollment_epoch;    /* carried as serial = epoch + 1 (mtls) */
    qihse_infra_scope_t scopes;   /* enrollment scope the cert grants */
    int64_t not_before_offset_s;  /* usually 0; negative backdates */
    int64_t validity_s;           /* lifetime; must be > 0 */
} qihse_ca_provision_node_req_t;

/* ── Verification outcome ──────────────────────────────────────────────── */

typedef struct {
    qihse_uuid_t node_id;
    uint64_t enrollment_epoch;    /* serial - 1, as the mtls issuer encodes */
    qihse_infra_scope_t scopes;   /* from the scope extension; NONE if absent */
    int64_t not_before;           /* unix seconds */
    int64_t not_after;
    uint8_t fingerprint[QIHSE_FEDERATION_NODE_FINGERPRINT_BYTES];
    char fingerprint_hex[97];
} qihse_ca_provision_cert_info_t;

typedef enum {
    QIHSE_CA_VERIFY_OK = 0,
    QIHSE_CA_VERIFY_ERR_MALFORMED,     /* unparsable cert / missing identity */
    QIHSE_CA_VERIFY_ERR_BAD_SIGNATURE, /* tampered, or a different CA */
    QIHSE_CA_VERIFY_ERR_NOT_YET_VALID,
    QIHSE_CA_VERIFY_ERR_EXPIRED,
    QIHSE_CA_VERIFY_ERR_REVOKED,       /* on the CRL */
    QIHSE_CA_VERIFY_ERR_SCOPE,         /* valid cert, insufficient scope */
    QIHSE_CA_VERIFY_ERR_CRL            /* CRL present but unparsable */
} qihse_ca_verify_result_t;

const char* qihse_ca_verify_result_name(qihse_ca_verify_result_t r);

/* ── Operations ────────────────────────────────────────────────────────── */

/* Create the federation CA.  alg must be post-quantum (ML-DSA family); a
 * PQ-ineligible algorithm is refused.  The private key is written PEM at
 * 0600 to the operator-chosen key_path with create-or-refuse semantics (an
 * existing CA is NEVER overwritten), and is never printed or returned.  The
 * self-signed certificate goes to cert_path (0644) and into *out_ca in the
 * same qihse_federation_ca_t form the mTLS layer consumes.
 * Requires the operator context to hold QIHSE_SCOPE_SECURITY_ADMIN. */
bool qihse_ca_provision_init_ca(void* operator_user, qihse_sig_alg_t alg,
                                const char* key_path, const char* cert_path,
                                qihse_federation_ca_t* out_ca);

/* Load a CA certificate file into the struct form qihse_federation_mtls.c
 * consumes.  The fingerprint is recomputed (SHA-384 over the raw public
 * key), never read from the file. */
bool qihse_ca_provision_load_ca(const char* cert_path,
                                qihse_federation_ca_t* out_ca);

/* Issue a node certificate binding the node's EXISTING identity public key.
 * The certificate mirrors what qihse_federation_ca_issue_node produces and
 * additionally carries the enrollment-scope extension.  The CA private key
 * file must match the CA certificate supplied, or issuance refuses — an
 * operator must not be able to sign with one key while attributing the
 * certificate to another CA.
 * Requires QIHSE_SCOPE_NODE_ENROLL and every scope being granted (the
 * privilege ceiling: no principal issues authority above its own). */
bool qihse_ca_provision_issue_node(void* operator_user, const char* ca_key_path,
                                   const qihse_federation_ca_t* ca,
                                   const qihse_ca_provision_node_req_t* req,
                                   char* out_cert_pem, size_t out_cap);

/* Append a revocation record to the CRL at crl_path (created 0644 if
 * absent).  node_fingerprint may be NULL (recorded as "-").
 * Requires QIHSE_SCOPE_NODE_REVOKE. */
bool qihse_ca_provision_revoke(void* operator_user, const char* crl_path,
                               const qihse_uuid_t* node_id,
                               const uint8_t* node_fingerprint,
                               uint64_t cert_serial, const char* reason);

/* Strict CRL lookup.  Returns false only on an unparsable CRL (fail
 * closed); a missing file is an empty list (*out_revoked = false, true).
 * Matching is by node UUID, or by fingerprint when the entry carries one. */
bool qihse_ca_provision_crl_check(const char* crl_path,
                                  const qihse_uuid_t* node_id,
                                  const uint8_t* node_fingerprint,
                                  bool* out_revoked);

/* Full verification: CA signature (via the same qihse_federation_cert_verify
 * the running node uses), validity window at now_s, CRL, and scope.  A
 * certificate is not authority beyond its scope: required_scopes is the
 * caller's demand, and a valid cert lacking it fails with _ERR_SCOPE.
 * out_info is optional and receives whatever was extracted. */
qihse_ca_verify_result_t qihse_ca_provision_verify(
    const qihse_federation_ca_t* ca, const char* crl_path,
    const char* cert_pem, int64_t now_s, qihse_infra_scope_t required_scopes,
    qihse_ca_provision_cert_info_t* out_info);

/* Write a PEM certificate to path at 0644 (bool; callers propagate). */
bool qihse_ca_provision_write_cert_file(const char* path, const char* cert_pem);

#ifdef __cplusplus
}
#endif

#endif /* QIHSE_CA_PROVISION_H */
