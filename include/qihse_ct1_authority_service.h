#ifndef QIHSE_CT1_AUTHORITY_SERVICE_H
#define QIHSE_CT1_AUTHORITY_SERVICE_H

#include <stddef.h>
#include "qihse_ct1_authority_store.h"
#include "qihse_ct1_recovery_manifest.h"
#include "qihse_ct1_node_quote.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Local TPM-free authority boundary, NOT a grant implementation. Only the
 * RESP server's authenticated, connection-bound configured QKP Operator
 * admission can initiate approval. A caller cannot supply a session, user,
 * manifest digest, signature, clock, or pin set as an approval substitute.
 * The strict root-owned checkpoint exists, but is not bound to an Operator
 * command or a manifest here. Role-specific live quote commands exist, but
 * strict quote verification alone cannot establish joint freshness, host-side
 * Operator provenance or one-use grant consumption.
 * No protected reads, ledger writes, token issuance, or recovery occur here.
 */
typedef enum {
    QIHSE_CT1_AUTHORITY_SERVICE_DISABLED = -1
} qihse_ct1_authority_service_result_t;

#define QIHSE_CT1_AUTHORITY_BLOCK_OPERATOR_SESSION (1u << 0)
#define QIHSE_CT1_AUTHORITY_BLOCK_INDEPENDENT_ANCHOR (1u << 1)
#define QIHSE_CT1_AUTHORITY_BLOCK_LIVE_NODE_COMMAND (1u << 2)
#define QIHSE_CT1_AUTHORITY_BLOCK_MANIFEST_CONSUMPTION (1u << 3)

/* Diagnostic constants only, never caller-set readiness/authentication flags. */
unsigned qihse_ct1_authority_service_blockers(void);
const char *qihse_ct1_authority_service_diagnostic(void);

/* Unconditionally DISABLED. Neither entry accepts a QKP session: a session
 * pointer cannot attest server ownership, connection lifetime or Operator
 * policy. All purported evidence/grants, including strict-store challenges,
 * are refused without parsing. No development macro enables these boundaries.
 * Upgrade: remove the obsolete session argument and rebuild callers; there
 * is no stored-data migration or reindex. Check: make -C tests/ct1_authority
 * test-service. Replacement must be invoked from the server's authenticated
 * QKP_ADMIN command context, not from this untrusted standalone API.
 */
qihse_ct1_authority_service_result_t qihse_ct1_authority_service_authorize(
    const void *evidence, size_t evidence_len);
qihse_ct1_authority_service_result_t qihse_ct1_authority_service_consume(
    const void *grant, size_t grant_len);

/* CT1G v1 signed record: "CT1G" | version(1) | reserved(3)=0 |
 * exact canonical unspent 2624-byte B manifest | ML-DSA-87 signature(4627).
 * Signature covers the complete prefix (including domain/version). This is
 * cryptographic verification ONLY, never authorization, nonce retirement or
 * permission to read/restore classified data. The caller must obtain expected
 * from a separate trusted source and challenge from the strict root ledger;
 * neither may be copied from the grant. operator_pub_path and operator_pin
 * must be independently provisioned and immutable for the duration of the
 * check, not supplied by the grant. The host's own clock enforces expiry.
 * No signer is exported: issuance remains disabled pending server-bound QKP
 * Operator admission and jointly fresh source/target state verification.
 * Upgrade: rebuild callers to use this additional verifier; existing stored
 * data needs no migration or reindex. Check: make test-ct1-authority-service.
 */
#define QIHSE_CT1_AUTHORITY_GRANT_SIGNED_SIZE (8u + QIHSE_CT1_RECOVERY_WIRE_SIZE)
#define QIHSE_CT1_AUTHORITY_GRANT_SIZE (QIHSE_CT1_AUTHORITY_GRANT_SIGNED_SIZE + 4627u)
int qihse_ct1_authority_service_verify_grant(
    const unsigned char *grant, size_t grant_len,
    const qihse_ct1_recovery_manifest_t *expected,
    const qihse_ct1_authority_challenge_t *challenge,
    const char *operator_pub_path, const unsigned char operator_pin[32]);

/* Host-side EVIDENCE ONLY. expected_manifest is the independently trusted B
 * record, not decoded from manifest_wire. challenge must originate from the
 * separately controlled strict store; this pure evaluator cannot prove store
 * provenance, one-use status, issuer approval or two-node snapshot atomicity.
 * Paths/expectations and frozen roots must be independently trusted and stable
 * for the check. No QKP pointer, grant or authority result is accepted/returned.
 * Rebuild standalone consumers with make -C tests/ct1_authority test-service;
 * stored data needs no migration or reindex. */
typedef struct {
    const unsigned char *manifest_wire;
    size_t manifest_len;
    const qihse_ct1_recovery_manifest_t *expected_manifest;
    /* Active system-tenant full-clearance non-Operator service principal,
     * resolved by the root host; required for every frozen-roster read,
     * not supplied by B. */
    const qihse_user_t *replication_principal;
    const qihse_ct1_authority_challenge_t *challenge;
    const unsigned char *source_quote;
    size_t source_quote_len;
    const unsigned char *target_quote;
    size_t target_quote_len;
    const char *source_pub_path, *target_pub_path;
    const qihse_ct1_node_quote_expected_t *source_expected, *target_expected;
    const char *frozen_source_dir, *frozen_target_dir;
} qihse_ct1_authority_pair_evidence_t;

bool qihse_ct1_authority_service_evaluate_pair(
    const qihse_ct1_authority_pair_evidence_t *evidence);

/* Evidence only: require a current strict-root-store binding before the
 * existing pair evaluator. The check releases the store lock before frozen
 * roster/quote evaluation; retirement, expiry or file changes between checks
 * are possible. Never grants, authorizes, consumes or reserves the challenge. */
bool qihse_ct1_authority_service_evaluate_pair_bound(
    qihse_ct1_authority_store_t *store,
    const qihse_ct1_authority_pair_evidence_t *evidence);

/* Root STRICT-store evidence bookkeeping only: checks the exact outstanding
 * bound canonical B, signed stale-role pair and both complete frozen 8/7
 * rosters under the SAME ledger/checkpoint flock, rechecks host clock and
 * binding, then durably retires that one nonce before returning true. A true
 * result means ONLY evidence checked and nonce retired. It is NOT Operator
 * approval, a grant, recovery authority, or a transferable token. Callers
 * must not pass untrusted paths/expected state as a substitute for independent
 * provenance. The caller must retain its live configured Operator QKP session
 * and recheck the root configuration before invoking this retirement immediately
 * before its local action; the return value is not a transferable capability.
 * The pure and non-retiring evaluators remain available; neither
 * authorizes recovery. authorize/consume remain unconditionally disabled.
 * Rebuild consumers; stored data needs no migration or reindex. Check:
 * sudo -n make -C tests/ct1_authority test-service. */
bool qihse_ct1_authority_service_check_and_retire_pair(
    qihse_ct1_authority_store_t *store,
    const qihse_ct1_authority_pair_evidence_t *evidence);

#ifdef __cplusplus
}
#endif
#endif
