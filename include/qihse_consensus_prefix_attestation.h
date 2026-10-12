#ifndef QIHSE_CONSENSUS_PREFIX_ATTESTATION_H
#define QIHSE_CONSENSUS_PREFIX_ATTESTATION_H

#include "qihse_consensus.h"
#include "qihse_federation.h"
#include "qihse_qkp.h"

#ifdef __cplusplus
extern "C" {
#endif

/* A lock-consistent local committed-prefix inventory. The provider must
 * authorize requester for every included entry and fail closed on truncation
 * or an unavailable history. The mesh exporter supplies this shape. */
typedef struct {
    char group_id[QIHSE_CONSENSUS_GROUP_ID_MAX + 1u];
    uint8_t history_id[32];
    uint64_t writer_epoch_floor;
    uint64_t commit_index;
    uint8_t committed_prefix_sha256[32];
    qihse_uuid_t member_uuid;
    char qkp_node_id[QIHSE_QKP_NODE_ID_LEN + 1u];
} qihse_consensus_prefix_evidence_t;

typedef bool (*qihse_consensus_prefix_export_user_fn)(
    void* source, const qihse_user_t* requester, uint64_t max_entries,
    qihse_consensus_prefix_evidence_t* out);

/* A signed statement of one node's local committed prefix. Verification
 * authenticates the signer and these fields; it does not establish a quorum,
 * prove application state, or authorize a rejoin. */
typedef struct {
    qihse_consensus_prefix_evidence_t evidence;
    qihse_uuid_t signer_node;
    uint8_t signer_fingerprint[QIHSE_FEDERATION_NODE_FINGERPRINT_BYTES];
    qihse_sig_alg_t sig_alg;
    size_t signature_len;
    uint8_t signature[QIHSE_FEDERATION_SIG_MAX_BYTES];
} qihse_consensus_prefix_attestation_t;

typedef struct {
    char group_id[QIHSE_CONSENSUS_GROUP_ID_MAX + 1u];
    uint8_t history_id[32];
    uint64_t writer_epoch_floor;
    qihse_uuid_t member_uuid;
    char qkp_node_id[QIHSE_QKP_NODE_ID_LEN + 1u];
    qihse_uuid_t signer_node;
} qihse_consensus_prefix_expected_t;

/* Obtain lock-consistent, access-checked local evidence and sign it with an
 * approved enrolled node key. store_user is the authenticated context used
 * for the federation identity lookup; requester is the evidence export context.
 * expected is trusted local configuration and binds group, history,
 * member, QKP, and signer identities before signing. */
bool qihse_consensus_prefix_attest_user(
    void* source, qihse_consensus_prefix_export_user_fn export_user,
    const qihse_user_t* requester,
    void* store, void* store_user, const qihse_uuid_t* signer_node,
    const qihse_consensus_prefix_expected_t* expected,
    uint64_t max_entries, qihse_consensus_prefix_attestation_t* out);

/* Re-read enrolled identity on every verification so revocation and key
 * rotation take effect. expected comes from trusted local configuration,
 * never from the received statement. */
bool qihse_consensus_prefix_attestation_verify_user(
    void* store, void* store_user,
    const qihse_consensus_prefix_expected_t* expected,
    const qihse_consensus_prefix_attestation_t* statement);

#ifdef __cplusplus
}
#endif

#endif
