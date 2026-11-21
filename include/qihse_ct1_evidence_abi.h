#ifndef QIHSE_CT1_EVIDENCE_ABI_H
#define QIHSE_CT1_EVIDENCE_ABI_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* V1 is structural evidence only: no caller-supplied digest, label, principal,
 * Operator assertion or peer pin attests a native WAL frame or confers authority.
 * The C executor must mint/check process-local proof under its own store lock;
 * this interface never authorizes apply, suppression, ACK or cursor advance. */
#define QIHSE_CT1_EVIDENCE_ABI_VERSION_1 1u
#define QIHSE_CT1_MAX_KEY_BYTES 65535u
#define QIHSE_CT1_MAX_FRAME_BYTES (64u * 1024u * 1024u)
#define QIHSE_CT1_MUTATION_SET 1u
#define QIHSE_CT1_MUTATION_TOMBSTONE 2u
#define QIHSE_CT1_EVAL_OP_STRUCTURAL_ONLY 1u
#define QIHSE_CT1_EVAL_STATUS_STRUCTURAL_CANDIDATE_UNATTESTED 1u
#define QIHSE_CT1_ATTESTATION_NONE_STRUCTURAL_ONLY 0u
#define QIHSE_CT1_AUTHORIZED_ACTIONS_NONE 0u

#define QIHSE_CT1_EVAL_OK 0
#define QIHSE_CT1_EVAL_ERR_NULL_POINTER (-1)
#define QIHSE_CT1_EVAL_ERR_INVALID_VERSION (-2)
#define QIHSE_CT1_EVAL_ERR_INVALID_SIZE (-3)
#define QIHSE_CT1_EVAL_ERR_UNSUPPORTED_OPERATION (-4)
#define QIHSE_CT1_EVAL_ERR_NONZERO_RESERVED (-5)
#define QIHSE_CT1_EVAL_ERR_IDENTITY (-6)
#define QIHSE_CT1_EVAL_ERR_BASELINE (-7)
#define QIHSE_CT1_EVAL_ERR_DIGEST (-8)
#define QIHSE_CT1_EVAL_ERR_POSITION (-9)
#define QIHSE_CT1_EVAL_ERR_FORGED_METADATA (-10)
#define QIHSE_CT1_EVAL_ERR_STALE_ORDERING (-11)
#define QIHSE_CT1_EVAL_ERR_OVERFLOW (-12)
#define QIHSE_CT1_EVAL_ERR_PANIC (-13)

typedef struct qihse_ct1_fixed_row_identity_v1 {
    uint32_t resource_tenant_id;
    uint16_t classification;
    uint16_t sci;
    uint32_t key_len;
    uint32_t reserved;
    uint8_t key_digest[32]; /* caller-supplied, not key attestation */
} qihse_ct1_fixed_row_identity_v1_t;

typedef struct qihse_ct1_evidence_eval_request_v1 {
    uint32_t version;
    uint32_t size;
    uint32_t requested_operation;
    uint32_t reserved;

    uint8_t source_generation[16];
    uint8_t target_generation[16];
    uint8_t expected_baseline_digest[32];
    uint8_t target_baseline_digest[32];
    uint8_t original_frame_digest[32];
    uint8_t observed_frame_digest[32];

    uint64_t expected_baseline_row_seq;
    uint64_t target_baseline_row_seq;

    uint64_t source_acknowledged_position;
    uint64_t source_durable_position;
    uint64_t pending_position;
    uint64_t target_cursor;
    uint64_t deletion_position;

    uint64_t pending_row_sequence;
    uint64_t deletion_row_sequence;
    uint64_t latest_target_row_sequence;
    uint64_t target_highwater;
    uint64_t source_highwater;

    uint32_t pending_record_count;
    uint32_t pending_kind;
    uint32_t deletion_kind;
    uint32_t latest_target_kind;
    uint32_t original_frame_len;
    uint32_t observed_frame_len;
    uint32_t flags;
    uint32_t reserved2;

    qihse_ct1_fixed_row_identity_v1_t pending_row;
    qihse_ct1_fixed_row_identity_v1_t deletion_row;
    qihse_ct1_fixed_row_identity_v1_t latest_target_row;
} qihse_ct1_evidence_eval_request_v1_t;

typedef struct qihse_ct1_evidence_eval_output_v1 {
    uint32_t version;
    uint32_t size;
    uint32_t structural_status; /* success means candidate, NOT permission */
    uint32_t attestation_state; /* always NONE */
    uint32_t authorized_actions; /* always NONE */
    uint32_t reserved;
    uint64_t minimum_next_row_seq; /* advisory structural floor only */
    uint8_t transcript_digest[32]; /* input binding, NOT a signature */
} qihse_ct1_evidence_eval_output_v1_t;

/* input/out must be valid, aligned, nonoverlapping buffers of their full V1
 * sizes for the duration of the call, without concurrent access. Returns a
 * QIHSE_CT1_EVAL_* code. For an aligned, valid out pointer, failures zero out;
 * a null out or misaligned out cannot be written. No implicit version negotiation. */
int32_t qihse_ct1_structural_evidence_evaluate_v1(
    const qihse_ct1_evidence_eval_request_v1_t *input,
    qihse_ct1_evidence_eval_output_v1_t *out);

#ifdef __cplusplus
}
#endif

#endif /* QIHSE_CT1_EVIDENCE_ABI_H */
