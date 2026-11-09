#ifndef QIHSE_CT_TARGET_H
#define QIHSE_CT_TARGET_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "qihse_cluster_ownership.h"

typedef struct qihse_resp_ct_abort_request qihse_resp_ct_abort_request_t;

#ifdef __cplusplus
extern "C" {
#endif

typedef struct qihse_ct_target qihse_ct_target_t;

typedef enum {
    QIHSE_CT_TARGET_ABSENT = 0,
    QIHSE_CT_TARGET_PREPARING = 1,
    QIHSE_CT_TARGET_RECEIVING = 2,
    QIHSE_CT_TARGET_SEALED = 3,
    QIHSE_CT_TARGET_FINALIZED = 4
} qihse_ct_target_state_t;

/* The ownership context supplies the local control Operator and topology.
 * The stage directory must already be private, owned by this daemon, and on
 * durable storage. local_qkp_id is the daemon's own configured QKP identity. */
qihse_ct_target_t *qihse_ct_target_create(
    qihse_cluster_ownership_context_t *ownership,
    const char *staging_directory, const char *local_qkp_id,
    char *err, size_t err_cap);
void qihse_ct_target_destroy(qihse_ct_target_t *target);

/* Called only after the RESP engine's typed ownership BEGIN handler verifies
 * the pinned source PREPARED receipt and durably fences/journals this target.
 * target_cut is the cut returned by that handler. BEGIN binds image staging
 * to the exact tuple and both independent image/range digests. */
bool qihse_ct_target_begin(qihse_ct_target_t *target,
    qihse_user_t *data_principal, const char *authenticated_source_qkp_id,
    const qihse_cluster_ownership_txn_t *source_txn, uint64_t total_bytes,
    const unsigned char image_sha256[32],
    const unsigned char canonical_range_sha256[32],
    uint64_t target_cut,
    uint64_t *out_resume_offset,
    char *err, size_t err_cap);

/* CHUNK is strict sequential append. Exact duplicate retries are idempotent;
 * gaps, overlaps with different bytes, and tuple/source changes fail closed. */
bool qihse_ct_target_chunk(qihse_ct_target_t *target,
    qihse_user_t *data_principal, const char *authenticated_source_qkp_id,
    const char *transfer_id, uint64_t offset, uint64_t total_bytes,
    const unsigned char image_sha256[32], const void *bytes, size_t length,
    uint64_t *out_next_offset, char *err, size_t err_cap);

/* STATUS may receive expected_txn=NULL only for the QKP-authenticated simple
 * progress form. When supplied, every field must match the durable stage. */
bool qihse_ct_target_status(qihse_ct_target_t *target,
    qihse_user_t *data_principal, const char *authenticated_source_qkp_id,
    const char *transfer_id, const qihse_cluster_ownership_txn_t *expected_txn,
    uint64_t expected_total_bytes, const unsigned char expected_image_sha256[32],
    const unsigned char expected_range_sha256[32],
    uint64_t expected_target_cut,
    uint64_t *out_offset, uint64_t *out_total_bytes,
    qihse_ct_target_state_t *out_state, char *err, size_t err_cap);

/* SEAL imports and replaces the authoritative range atomically, waits for the
 * target's CT1 successor ACK in storage, and returns the persisted target seal. */
bool qihse_ct_target_seal(qihse_ct_target_t *target,
    qihse_user_t *data_principal, const char *authenticated_source_qkp_id,
    const qihse_cluster_ownership_txn_t *source_txn,
    uint64_t expected_total_bytes,
    const unsigned char expected_image_sha256[32],
    const unsigned char canonical_range_sha256[32],
    uint64_t *out_target_lsn, unsigned char out_checksum[32],
    char *err, size_t err_cap);

/* Read the persisted sealed proof for the protected QKP RECEIPT command. */
bool qihse_ct_target_receipt(qihse_ct_target_t *target,
    qihse_user_t *data_principal, const char *authenticated_source_qkp_id,
    const qihse_cluster_ownership_txn_t *source_txn,
    const unsigned char canonical_range_sha256[32],
    uint64_t *out_target_lsn, unsigned char out_checksum[32],
    char *err, size_t err_cap);

/* Cleanup only after the RESP engine successfully ran the authenticated
 * ownership ABORT handler (which verifies source ABORTED receipt and durable
 * target fence transition). Never use this to release a fence. */
bool qihse_ct_target_cleanup_aborted(qihse_ct_target_t *target,
    qihse_user_t *data_principal, const char *authenticated_source_qkp_id,
    const qihse_resp_ct_abort_request_t *authenticated_abort_request,
    char *err, size_t err_cap);

/* Called only after the durable ownership ACTIVATE handler succeeds. Persists
 * FINALIZED in the stage manifest, removes only the bulky image, and retains
 * the manifest for receipt/replay. Startup replays ownership journal FINALIZED
 * records and repeats this cleanup idempotently. */
bool qihse_ct_target_finalize(qihse_ct_target_t *target,
    qihse_user_t *data_principal, const char *authenticated_source_qkp_id,
    const qihse_resp_ct_activation_request_t *authenticated_request,
    char *err, size_t err_cap);

#ifdef __cplusplus
}
#endif
#endif
