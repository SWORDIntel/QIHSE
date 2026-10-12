#ifndef QIHSE_CONSENSUS_PREFIX_PAIR_NONCE_H
#define QIHSE_CONSENSUS_PREFIX_PAIR_NONCE_H

#include "qihse_consensus_prefix_pair.h"

#ifdef __cplusplus
extern "C" {
#endif

/* The directory must already exist, be owned by the effective uid and have
 * mode 0700. Its path is trusted local configuration. Issuance writes and
 * fsyncs an owner-only pending record before returning either challenge.
 * Both challenge fields in template_expected must be zero. */
bool qihse_consensus_prefix_pair_nonce_issue(
    const char* directory,
    const qihse_consensus_prefix_pair_expected_t* template_expected,
    qihse_consensus_prefix_pair_expected_t* issued);

/* Atomic one-use claim. The claimed record is retained as an owner-only
 * receipt even if signature verification later fails. Claims expire after
 * five minutes; a clock rollback refuses them. No recovery operation may
 * treat a claimed nonce as a valid attestation by itself. */
bool qihse_consensus_prefix_pair_nonce_claim(
    const char* directory,
    const qihse_consensus_prefix_pair_expected_t* expected);

#ifdef __cplusplus
}
#endif

#endif
