#ifndef QIHSE_CT1_DISPOSITION_H
#define QIHSE_CT1_DISPOSITION_H

#include "qihse_auth.h"
#include "qihse_ct1_recovery_manifest.h"

#ifdef __cplusplus
extern "C" {
#endif

#define QIHSE_CT1_DISPOSITION_SIZE (16u + QIHSE_CT1_RECOVERY_WIRE_SIZE + \
    QIHSE_CT1_RECOVERY_FRAME_BYTES + 32u)
/* Native QCT1SO02 WAL commit: magic[8], BE total[4], BE disposition
 * length[4], exact QCT1SO01, SHA-256 over header and disposition[32].
 * Only a complete validated frame advances a legacy receiver cursor; its
 * opaque SOURCE original must never enter the normal QKV6 row replay path.
 * No production exceptional writer/authority injection is enabled yet. */
#define QIHSE_CT1_SUPPRESSED_WAL_SIZE (16u + QIHSE_CT1_DISPOSITION_SIZE + 32u)

/* In-memory, fixed-size v1 SUPPRESSED_ORIGINAL candidate only. The embedded
 * canonical manifest and both SHA-256 checks are evidence, NOT approval,
 * authentication of a peer, a durable disposition, or permission to apply a
 * SOURCE frame. The expected manifest must be obtained separately; it is not
 * trusted merely because it appears in the record. No filesystem or KV API. */
typedef struct {
    const unsigned char *original_frame; /* borrowed from validated input */
    size_t original_length;
} qihse_ct1_disposition_view_t;

/* Both paths decode and authorize every QKV6 SOURCE row under the active
 * principal and require its identity, position, row key/sequence, label and
 * tenant to match the expected manifest before exposing frame bytes. Native
 * SYSTEM_ALL frames require a system principal and a tenant-zero manifest;
 * every selected row still matches the manifest exactly. The cold custody
 * reader additionally requires the active system principal's full clearance
 * and SCI bitmask before accepting SYSTEM_ALL. A caller must independently
 * enforce its real recovery authorization and custody policy. */
bool qihse_ct1_disposition_encode(const qihse_user_t *principal,
    const qihse_ct1_recovery_manifest_t *expected,
    const unsigned char *original_frame, size_t original_length,
    unsigned char out[QIHSE_CT1_DISPOSITION_SIZE]);

/* Rejects partial, oversized, substituted or noncanonical records; clears the
 * output on refusal. Reads and authorizes SOURCE rows without receiver replay
 * or store materialization. The view expires with data. */
bool qihse_ct1_disposition_decode(const qihse_user_t *principal,
    const qihse_ct1_recovery_manifest_t *expected,
    const unsigned char *data, size_t length,
    qihse_ct1_disposition_view_t *out);

#ifdef __cplusplus
}
#endif
#endif
