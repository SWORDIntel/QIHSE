#ifndef QIHSE_CT_CODEC_H
#define QIHSE_CT_CODEC_H

#include "qihse_kv_store.h"

#ifdef __cplusplus
extern "C" {
#endif

#define QIHSE_CT_CODEC_MAX_FRAME ((size_t)64u << 20)
#define QIHSE_CT_CODEC_MODE_SOURCE 1u
#define QIHSE_CT_CODEC_MODE_RECEIVER 2u

/* All entry points that inspect a group or frame require an active principal.
 * EXACT admits only the stated resource tenant (including tenant-authored
 * commons/ rows at tenant zero); SYSTEM_ALL requires a system
 * domain principal and an exact_tenant_id of zero. The caller verifies any
 * replication-service identity binding before invoking the codec. No function
 * flushes or syncs FILE*.
 * The caller owns the stream and its durability boundary. */
bool qihse_ct_codec_encoded_size(qihse_user_t* principal,
    qihse_kv_ct_tenant_policy_t policy, uint32_t exact_tenant_id,
    uint8_t mode, const qihse_kv_ct_group_t* group, size_t max_bytes,
    size_t* out_bytes);
/* Canonical digest for receiver duplicate detection; independent of WAL frame
 * source/receiver mode. Authorization and bounds match encoded_size. */
bool qihse_ct_codec_group_digest(qihse_user_t* principal,
    qihse_kv_ct_tenant_policy_t policy, uint32_t exact_tenant_id,
    const qihse_kv_ct_group_t* group, unsigned char out_sha256[32]);
bool qihse_ct_codec_write(FILE* out, qihse_user_t* principal,
    qihse_kv_ct_tenant_policy_t policy, uint32_t exact_tenant_id,
    uint8_t mode, const qihse_kv_ct_group_t* group, size_t max_bytes,
    size_t* out_written);

/* 1=complete frame, 0=clean EOF, -1=malformed/truncated/I/O,
 * -2=authorization refusal. An unsuccessful call leaves out_group empty and
 * never materializes protected key/value data. */
int qihse_ct_codec_read(FILE* in, qihse_user_t* principal,
    qihse_kv_ct_tenant_policy_t policy, uint32_t exact_tenant_id,
    size_t max_bytes, qihse_kv_ct_group_t* out_group, uint8_t* out_mode,
    size_t* out_read);
void qihse_ct_codec_clear(qihse_kv_ct_group_t* group);

#ifdef __cplusplus
}
#endif

#endif
