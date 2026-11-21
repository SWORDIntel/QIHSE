#ifndef QIHSE_CT1_AUTHORITY_PROTOCOL_H
#define QIHSE_CT1_AUTHORITY_PROTOCOL_H

/* Disposable structural codec only. The node statements mirror caller input;
 * neither a live QKP attestation nor a trusted approval is implemented. */
#ifdef QIHSE_CT1_INSECURE_DEV_AUTHORITY_PROTOCOL
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "qihse_ct1_recovery_manifest.h"
#include "qihse_qkp.h"

#ifdef __cplusplus
extern "C" {
#endif

/* CT1A v1 application records: "CT1A" | version u8 (=1) | type u8
 * (1 challenge, 2 response) | reserved u16 (=0) | total_length u32 BE |
 * canonical 2624-byte B manifest | (response only) source, target statements.
 * Each statement is qkp_id[65] | service_principal_id[65] | current_pin[32].
 * IDs are nonempty NUL-terminated, zero-padded canonical manifest IDs.
 * All lengths are exact, including the header. No trailing bytes or extensions.
 * Send as one sealed QKP application record (both sizes fit MAX_PAYLOAD);
 * receive with qihse_qkp_recv_sealed and pass its exact returned length here.
 * QKP protects transport but these codecs neither send nor authenticate records.
 * Statement bytes are UNTRUSTED claims, not live node attestations; an issuer
 * must obtain and verify both statements on separate live pinned node sessions.
 * No protected manifest/frame read or grant is implemented by these codecs. */
#define QIHSE_CT1_AUTHORITY_VERSION 1u
#define QIHSE_CT1_AUTHORITY_HEADER_SIZE 12u
#define QIHSE_CT1_AUTHORITY_STATEMENT_SIZE 162u
#define QIHSE_CT1_AUTHORITY_CHALLENGE_SIZE \
    (QIHSE_CT1_AUTHORITY_HEADER_SIZE + QIHSE_CT1_RECOVERY_WIRE_SIZE)
#define QIHSE_CT1_AUTHORITY_RESPONSE_SIZE \
    (QIHSE_CT1_AUTHORITY_CHALLENGE_SIZE + 2u * QIHSE_CT1_AUTHORITY_STATEMENT_SIZE)

typedef struct {
    char qkp_id[QIHSE_CT1_RECOVERY_ID_MAX + 1u];
    char service_principal_id[QIHSE_CT1_RECOVERY_ID_MAX + 1u];
    unsigned char current_pin[32];
} qihse_ct1_authority_statement_t;

/* Validation and serialization ONLY: these do not make authorization decisions.
 * The canonical manifest carries issuer identity/pin, both node identities/pins,
 * the service principal, epoch, nonce, and host-issued expiry (<=900000ms).
 * The host's actual clock, current pin config and anti-rollback checkpoint
 * cannot be inferred from a decoded record or caller-provided wall time. */
bool qihse_ct1_authority_challenge_encode(const qihse_ct1_recovery_manifest_t *manifest,
    unsigned char out[QIHSE_CT1_AUTHORITY_CHALLENGE_SIZE]);
bool qihse_ct1_authority_challenge_decode(const unsigned char *data, size_t length,
    qihse_ct1_recovery_manifest_t *manifest);
bool qihse_ct1_authority_response_encode(const qihse_ct1_recovery_manifest_t *manifest,
    const qihse_ct1_authority_statement_t *source,
    const qihse_ct1_authority_statement_t *target,
    unsigned char out[QIHSE_CT1_AUTHORITY_RESPONSE_SIZE]);
bool qihse_ct1_authority_response_decode(const unsigned char *data, size_t length,
    qihse_ct1_recovery_manifest_t *manifest,
    qihse_ct1_authority_statement_t *source,
    qihse_ct1_authority_statement_t *target);
/* Byte-exact manifest binding and canonical shape only; never an approval. */
bool qihse_ct1_authority_response_matches(const unsigned char *challenge,
    size_t challenge_length, const unsigned char *response, size_t response_length);

/* Fail-closed: no production approval until a caller integrates authenticated
 * Operator policy, two independent live challenge-bound node statements,
 * authority-host time, and an independent durable anti-rollback checkpoint
 * with atomic one-use consumption. Admin-peer identity alone is not a grant. */
bool qihse_ct1_authority_approve(const qihse_qkp_session_t *issuer_session,
    const qihse_qkp_config_t *config, const unsigned char *challenge,
    size_t challenge_length, const unsigned char *response, size_t response_length);

#ifdef __cplusplus
}
#endif
#endif /* QIHSE_CT1_INSECURE_DEV_AUTHORITY_PROTOCOL */
#endif
