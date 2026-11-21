#ifndef QIHSE_CT1_AUTHORITY_WITNESS_H
#define QIHSE_CT1_AUTHORITY_WITNESS_H

#include <stdbool.h>
#include <stdint.h>
#include "qihse_ct1_recovery_manifest.h"

/* Insecure development-only storage fixture. No authenticated session,
 * clearance/SCI check or trusted time source exists here. Never link into a
 * production service or use classified manifests. Not an approval API.
 * A production t420 service requires live pinned QKP Operator authorization. */
#ifdef QIHSE_CT1_INSECURE_DEV_WITNESS

/* Local test STORAGE CORE; never an issuer, approval or QKP decision.
 * Directory must already exist, be separately owned, mode 0700, and live
 * beneath trusted non-writable ancestors. The operator must independently
 * establish host clock trust and retain the returned head outside this
 * writable directory; local wall time and a local head prove neither remote
 * clock trust nor protection against same-UID rollback. No classified frame
 * bytes are returned. This fixture does NOT authorize classified manifest
 * access; its caller-time checks are not a trusted expiry decision.
 * Initial creation is explicit and exclusive; missing/corrupt files never
 * self-repair. No automatic pruning or migration of stored records. */
bool qihse_ct1_witness_bootstrap(const char *dir,
    unsigned char initial_head[32]);

/* expected_head is an independently retained checkpoint, not read from the
 * ledger. Caller time is the ONLY source for issuance/expiry evaluation;
 * the host clock is also read internally and must be available. Successful
 * consumption is bookkeeping, NOT permission for protected work. On any
 * uncertainty, refuse further writes until independent investigation. */
bool qihse_ct1_witness_consume(const char *dir,
    const qihse_ct1_recovery_manifest_t *manifest, uint64_t caller_now_ms,
    const unsigned char expected_head[32], unsigned char next_head[32]);

#endif /* QIHSE_CT1_INSECURE_DEV_WITNESS */
#endif
