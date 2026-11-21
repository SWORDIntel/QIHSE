#ifndef QIHSE_CT1_NODE_QUOTE_H
#define QIHSE_CT1_NODE_QUOTE_H

#include "qihse_ct1_recovery_manifest.h"

#ifdef __cplusplus
extern "C" {
#endif

#define QIHSE_CT1_NODE_QUOTE_NONCE_SIZE 32u
#define QIHSE_CT1_NODE_QUOTE_SIGNATURE_SIZE 4627u
/* Signed v2 wire (all integers big-endian; v1 is not accepted):
 * "CT1Q" | version(2) | role(1=source,2=target) | reserved(2)=0 |
 * host_nonce[32] | SHA256(exact canonical 2624-byte B manifest)[32] |
 * signer_label[65] | source_qkp_id[65] | target_qkp_id[65] |
 * signer_pin[32] | role_peer_qkp_id[65] | role_peer_pin[32] |
 * replication_principal[65] | generation[65] | baseline_sha256[32] |
 * target_cursor(8) | role_high_water(8).
 * signer_label is the role's own manifest QKP ID; role_peer fields describe
 * that node's configured peer, NOT its signer. The manifest's roster, peer
 * identity/pin, issuer epoch and state numbers are host-asserted, NOT verified
 * live state merely because a quote signature verifies. Labels are NUL-terminated and
 * zero-padded; the entire 574-byte prefix is signed with ML-DSA-87, followed
 * by exactly 4627 signature bytes. */
#define QIHSE_CT1_NODE_QUOTE_SIGNED_SIZE 574u
#define QIHSE_CT1_NODE_QUOTE_SIZE \
    (QIHSE_CT1_NODE_QUOTE_SIGNED_SIZE + QIHSE_CT1_NODE_QUOTE_SIGNATURE_SIZE)
#define QIHSE_CT1_NODE_QUOTE_SOURCE 1u
#define QIHSE_CT1_NODE_QUOTE_TARGET 2u

/* Verification evidence only, NEVER a read grant or live-state attestation by
 * itself. The caller must obtain a fresh, unpredictable, one-use nonce from
 * the trusted host and independently supply the signing node's public PEM
 * path, both nodes' distinct CURRENT t420 SHA256(DER SubjectPublicKeyInfo)
 * signer pins (source first, target second), and the exact replication service
 * principal. Neither signer pin may be learned from the manifest, peer pins,
 * or quote. The manifest's configured peer IDs/pins are signed separately.
 * manifest_wire must be the exact canonical unspent B manifest (not a receipt),
 * with its nonce equal to the independently supplied host nonce.
 * The public-key path must remain trusted and immutable during verification.
 * The live role-specific signing command and its measured-state provenance
 * must be independently authenticated before relying on either quote. */
bool qihse_ct1_node_quote_verify(const unsigned char *quote, size_t quote_len,
    const unsigned char *manifest_wire, size_t manifest_len, unsigned role,
    const unsigned char host_nonce[QIHSE_CT1_NODE_QUOTE_NONCE_SIZE],
    const char *current_node_pub_path,
    const unsigned char current_source_signer_pin[32],
    const unsigned char current_target_signer_pin[32],
    const char *current_replication_principal);

/* Independently sourced expected t420 configuration and live state, never
 * copied from the quote or decoded manifest. Fixed arrays must contain exact,
 * nonempty, NUL-terminated labels; pins are SHA256(DER SubjectPublicKeyInfo).
 * This is verification evidence only, not a live signer or recovery grant. */
typedef struct {
    char source_qkp_id[QIHSE_CT1_RECOVERY_ID_MAX + 1u];
    char target_qkp_id[QIHSE_CT1_RECOVERY_ID_MAX + 1u];
    unsigned char source_signer_pin[32], target_signer_pin[32];
    char source_peer_qkp_id[QIHSE_CT1_RECOVERY_ID_MAX + 1u];
    char target_peer_qkp_id[QIHSE_CT1_RECOVERY_ID_MAX + 1u];
    unsigned char source_peer_pin[32], target_peer_pin[32];
    char replication_principal_id[QIHSE_CT1_RECOVERY_ID_MAX + 1u];
    char generation[QIHSE_CT1_RECOVERY_ID_MAX + 1u];
    unsigned char baseline_sha256[32];
    uint64_t target_cursor, source_high_water, target_high_water;
} qihse_ct1_node_quote_expected_t;

/* Compare ALL expected identities and state to canonical B before checking
 * the signing public key and ML-DSA signature. The public key must be trusted
 * and immutable during verification; the host owns nonce freshness/one-use. */
bool qihse_ct1_node_quote_verify_strict(const unsigned char *quote, size_t quote_len,
    const unsigned char *manifest_wire, size_t manifest_len, unsigned role,
    const unsigned char host_nonce[QIHSE_CT1_NODE_QUOTE_NONCE_SIZE],
    const char *current_node_pub_path,
    const qihse_ct1_node_quote_expected_t *expected);

/* EVIDENCE ONLY: verify both roles over the same exact canonical B and host nonce
 * against independently trusted keys and expectations, enforce cross-role
 * peer identity/pin agreement with the opposite trusted signer, then require
 * a stale pending SET before the measured target tombstone. No grant, consumption,
 * file/roster measurement or same-UID authority. t420 separately owns trusted
 * time, complete rosters, Operator provenance and the one-use checkpoint. */
bool qihse_ct1_node_quote_verify_paired_stale(
    const unsigned char *source_quote, size_t source_quote_len,
    const unsigned char *target_quote, size_t target_quote_len,
    const unsigned char *manifest_wire, size_t manifest_len,
    const unsigned char host_nonce[QIHSE_CT1_NODE_QUOTE_NONCE_SIZE],
    const char *trusted_source_pub_path, const char *trusted_target_pub_path,
    const qihse_ct1_node_quote_expected_t *trusted_source_expected,
    const qihse_ct1_node_quote_expected_t *trusted_target_expected);

/* Pure quote construction for ALREADY VERIFIED evidence, not a network endpoint
 * or a grant. The trusted manifest must be independently assembled from the
 * local locked CT snapshot, configured identities/pins and frozen roster, NOT
 * copied from the request. expected must likewise originate from current
 * trusted configuration. A caller must authenticate an actual QKP_ADMIN
 * Operator, verify the complete role-specific roster under its startup root,
 * and bind the exact source frame or target tombstone before invoking this.
 * The host alone owns nonce/epoch one-use verification when deciding a grant.
 * Key paths and now_ms must come from trusted startup configuration and the
 * node clock, never the request. */
typedef struct {
    const unsigned char *manifest_wire;
    size_t manifest_len;
    const qihse_ct1_recovery_manifest_t *verified_manifest;
    const qihse_ct1_node_quote_expected_t *expected;
    unsigned role;
    uint64_t now_ms;
    const unsigned char *host_nonce; /* exactly 32 bytes, independently supplied */
    const char *own_private_key_path;
    const char *own_public_key_path;
} qihse_ct1_node_quote_signing_evidence_t;

/* Writes exactly QIHSE_CT1_NODE_QUOTE_SIZE bytes on success; zeroes output
 * on denial. No arbitrary-message signing API is exposed. */
bool qihse_ct1_node_quote_sign_verified(
    const qihse_ct1_node_quote_signing_evidence_t *evidence,
    unsigned char out[QIHSE_CT1_NODE_QUOTE_SIZE]);

#ifdef __cplusplus
}
#endif
#endif
