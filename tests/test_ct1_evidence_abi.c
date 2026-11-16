/* Standalone C/Rust ABI smoke (no native CT1 executor or WAL integration):
 * cargo build --locked --offline --manifest-path rust/ct1-recovery/Cargo.toml
 * cc -std=c11 -Wall -Wextra -Werror -Iinclude tests/test_ct1_evidence_abi.c \
 *    rust/ct1-recovery/target/debug/libqihse_ct1_recovery.a -ldl -lpthread -lm \
 *    -o rust/ct1-recovery/target/debug/test_ct1_evidence_abi && \
 *    rust/ct1-recovery/target/debug/test_ct1_evidence_abi
 */
#include "qihse_ct1_evidence_abi.h"

#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#define OFFSET(type, member, expected) \
    _Static_assert(offsetof(type, member) == (expected), #type "." #member " offset")

_Static_assert(sizeof(qihse_ct1_fixed_row_identity_v1_t) == 48, "row size");
OFFSET(qihse_ct1_fixed_row_identity_v1_t, key_digest, 16);
_Static_assert(sizeof(qihse_ct1_evidence_eval_request_v1_t) == 448, "request size");
OFFSET(qihse_ct1_evidence_eval_request_v1_t, source_generation, 16);
OFFSET(qihse_ct1_evidence_eval_request_v1_t, expected_baseline_row_seq, 176);
OFFSET(qihse_ct1_evidence_eval_request_v1_t, pending_record_count, 272);
OFFSET(qihse_ct1_evidence_eval_request_v1_t, pending_row, 304);
OFFSET(qihse_ct1_evidence_eval_request_v1_t, latest_target_row, 400);
_Static_assert(sizeof(qihse_ct1_evidence_eval_output_v1_t) == 64, "output size");
OFFSET(qihse_ct1_evidence_eval_output_v1_t, minimum_next_row_seq, 24);
OFFSET(qihse_ct1_evidence_eval_output_v1_t, transcript_digest, 32);

static qihse_ct1_evidence_eval_request_v1_t fixture(void)
{
    qihse_ct1_evidence_eval_request_v1_t req = {0};
    qihse_ct1_fixed_row_identity_v1_t row = {0};
    req.version = QIHSE_CT1_EVIDENCE_ABI_VERSION_1;
    req.size = (uint32_t)sizeof(req);
    req.requested_operation = QIHSE_CT1_EVAL_OP_STRUCTURAL_ONLY;
    memset(req.source_generation, 1, sizeof(req.source_generation));
    memcpy(req.target_generation, req.source_generation, sizeof(req.target_generation));
    memset(req.expected_baseline_digest, 2, sizeof(req.expected_baseline_digest));
    memcpy(req.target_baseline_digest, req.expected_baseline_digest,
           sizeof(req.target_baseline_digest));
    memset(req.original_frame_digest, 3, sizeof(req.original_frame_digest));
    memcpy(req.observed_frame_digest, req.original_frame_digest,
           sizeof(req.observed_frame_digest));
    req.expected_baseline_row_seq = 5729400;
    req.target_baseline_row_seq = 5729400;
    req.source_acknowledged_position = 11110;
    req.source_durable_position = 11111;
    req.pending_position = 11111;
    req.target_cursor = 11110;
    req.deletion_position = 11103;
    req.pending_row_sequence = 5729448;
    req.deletion_row_sequence = 5729450;
    req.latest_target_row_sequence = 5729450;
    req.target_highwater = 5729457;
    req.source_highwater = 5729448;
    req.pending_record_count = 1;
    req.pending_kind = QIHSE_CT1_MUTATION_SET;
    req.deletion_kind = QIHSE_CT1_MUTATION_TOMBSTONE;
    req.latest_target_kind = QIHSE_CT1_MUTATION_TOMBSTONE;
    req.original_frame_len = 128;
    req.observed_frame_len = 128;
    row.resource_tenant_id = 7;
    row.classification = 4;
    row.sci = 2;
    row.key_len = 11;
    memset(row.key_digest, 9, sizeof(row.key_digest)); /* deliberately forged */
    req.pending_row = row;
    req.deletion_row = row;
    req.latest_target_row = row;
    return req;
}

static void assert_zero(const qihse_ct1_evidence_eval_output_v1_t *out)
{
    qihse_ct1_evidence_eval_output_v1_t zero = {0};
    assert(memcmp(out, &zero, sizeof(zero)) == 0);
}

int main(void)
{
    qihse_ct1_evidence_eval_request_v1_t req = fixture();
    qihse_ct1_evidence_eval_output_v1_t out = {0};
    assert(qihse_ct1_structural_evidence_evaluate_v1(&req, &out) == QIHSE_CT1_EVAL_OK);
    assert(out.version == QIHSE_CT1_EVIDENCE_ABI_VERSION_1);
    assert(out.size == sizeof(out));
    assert(out.structural_status == QIHSE_CT1_EVAL_STATUS_STRUCTURAL_CANDIDATE_UNATTESTED);
    assert(out.attestation_state == QIHSE_CT1_ATTESTATION_NONE_STRUCTURAL_ONLY);
    assert(out.authorized_actions == QIHSE_CT1_AUTHORIZED_ACTIONS_NONE);
    assert(out.minimum_next_row_seq == 5729458);

    req.version++;
    assert(qihse_ct1_structural_evidence_evaluate_v1(&req, &out) == QIHSE_CT1_EVAL_ERR_INVALID_VERSION);
    assert_zero(&out);
    req = fixture();
    req.size--;
    assert(qihse_ct1_structural_evidence_evaluate_v1(&req, &out) == QIHSE_CT1_EVAL_ERR_INVALID_SIZE);
    assert_zero(&out);
    req = fixture();
    req.requested_operation = 2; /* no apply/ACK operation exists */
    assert(qihse_ct1_structural_evidence_evaluate_v1(&req, &out) == QIHSE_CT1_EVAL_ERR_UNSUPPORTED_OPERATION);
    assert_zero(&out);
    req = fixture();
    req.flags = 1;
    assert(qihse_ct1_structural_evidence_evaluate_v1(&req, &out) == QIHSE_CT1_EVAL_ERR_NONZERO_RESERVED);
    assert_zero(&out);
    req = fixture();
    req.observed_frame_digest[0] ^= 1;
    assert(qihse_ct1_structural_evidence_evaluate_v1(&req, &out) == QIHSE_CT1_EVAL_ERR_DIGEST);
    assert_zero(&out);
    req = fixture();
    assert(qihse_ct1_structural_evidence_evaluate_v1(NULL, &out) == QIHSE_CT1_EVAL_ERR_NULL_POINTER);
    assert_zero(&out);
    assert(qihse_ct1_structural_evidence_evaluate_v1(&req, NULL) == QIHSE_CT1_EVAL_ERR_NULL_POINTER);
    puts("CT1 C/Rust structural-only ABI smoke passed");
    return 0;
}
