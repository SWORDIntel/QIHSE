#ifndef QIHSE_MACHINE_AUTH_H
#define QIHSE_MACHINE_AUTH_H

/*
 * Machine-client authentication for the RESP listener (MACHINEAUTH).
 *
 * Fleet agents and bridges today authenticate with the operator password,
 * which means every connection pays the full PBKDF2-HMAC-SHA384 password
 * KDF (hundreds of milliseconds to seconds at CNSA 2.0 iteration counts)
 * and carries a long-lived shared secret in client configuration. A machine
 * client instead presents a MACHINE-purpose capability token: the same wire
 * format the fabric dispatch uses, signed by the client node's ML-DSA-87
 * identity key and verified here against the node's FILE-CONFIGURED trusted
 * public keys (--pqc-trusted-pub, the same anchors the cluster bus trusts).
 *
 * Trust-model boundary (deliberate, and different from fabric RUN/FETCH
 * tokens): qihse_fabric_token_check verifies against store-ENROLLED node
 * identities over an mTLS channel. MACHINEAUTH runs on a plain RESP
 * connection with file-based anchors, matching the bus's existing trust
 * model. What it preserves from the fabric token's hardening:
 *
 *   - the token's own key material is never trusted to describe itself —
 *     the signature must verify against an anchor configured out of band;
 *   - purpose is inside the signed region, so a RUN/FETCH/SCATTER token
 *     cannot be presented here and vice versa;
 *   - the lifetime window is validated with clock skew, and a MACHINE token
 *     may not outlive QIHSE_MACHINE_TOKEN_MAX_TTL_MS;
 *   - a MACHINE token claims NO scope bits (federation authority refuses);
 *   - the nonce is consumed in a bounded replay ledger: one authentication
 *     per token, and a full ledger fails closed.
 *
 * On success the caller installs the token's claims as the session context
 * exactly like CLUSTER PEERAUTH does: role 0, no account capabilities, no
 * verifier — a claims context is a claim about clearance, nothing more, and
 * it dies with the connection.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "qihse_fabric_dispatch.h"

#ifdef __cplusplus
extern "C" {
#endif

/* A MACHINE token is a standing credential refreshed by the minting tool,
 * so its lifetime is measured in hours, not the fabric dispatch's 5-minute
 * job-binding window. 72 hours is the hard ceiling regardless of what a
 * token claims; deployments minting shorter tokens (12h default in
 * qihse-machine-token) shrink the stolen-token window further. */
#define QIHSE_MACHINE_TOKEN_MAX_TTL_MS (72ull * 3600ull * 1000ull)

typedef enum {
    QIHSE_MACHINE_AUTH_OK = 0,
    QIHSE_MACHINE_AUTH_DISABLED,        /* no trusted anchors configured */
    QIHSE_MACHINE_AUTH_MALFORMED,       /* bounds/length/field validation */
    QIHSE_MACHINE_AUTH_BAD_SIGNATURE,
    QIHSE_MACHINE_AUTH_WRONG_PURPOSE,   /* not a MACHINE token */
    QIHSE_MACHINE_AUTH_SCOPE_REFUSED,   /* scope bits set on a MACHINE token */
    QIHSE_MACHINE_AUTH_ISSUED_IN_FUTURE,
    QIHSE_MACHINE_AUTH_EXPIRED,
    QIHSE_MACHINE_AUTH_TTL_TOO_LONG,
    QIHSE_MACHINE_AUTH_REPLAY,          /* nonce already consumed */
    QIHSE_MACHINE_AUTH_LEDGER_FULL,     /* fail closed, never evict */
    QIHSE_MACHINE_AUTH_NO_TRUST         /* signature matched no anchor */
} qihse_machine_auth_verdict_t;

const char* qihse_machine_auth_verdict_name(qihse_machine_auth_verdict_t v);

/* Configure the trust anchors: ML-DSA public PEM paths (the same
 * --pqc-trusted-pub list the cluster bus loads). The strings are copied;
 * anchors that cannot be loaded are skipped, and configuring zero loadable
 * anchors disables machine auth (every check then returns DISABLED).
 * Call once at startup before serving. */
bool qihse_machine_auth_configure(const char* const* trusted_pub_paths, size_t count);

/* Number of anchors currently loaded and usable. */
size_t qihse_machine_auth_trusted_count(void);

/* Verify one MACHINEAUTH token blob (fabric token wire format, purpose
 * MACHINE). now_ms of 0 means "read the clock". On OK, out_claims receives
 * the verified claims and the nonce is consumed — one authentication per
 * token. The blob is never written to on failure. */
qihse_machine_auth_verdict_t qihse_machine_auth_check(
    const uint8_t* blob, size_t blob_len, uint64_t now_ms,
    qihse_fabric_token_t* out_claims);

/* Drop all anchors and ledger entries; back to DISABLED. Test/ops use. */
void qihse_machine_auth_reset(void);

/* Live (unexpired, unconsumed) ledger entry count — for tests and health. */
size_t qihse_machine_auth_ledger_live(void);

#ifdef __cplusplus
}
#endif

#endif /* QIHSE_MACHINE_AUTH_H */
