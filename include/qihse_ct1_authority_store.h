#ifndef QIHSE_CT1_AUTHORITY_STORE_H
#define QIHSE_CT1_AUTHORITY_STORE_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

/* Legacy UNTRUSTED FIXTURE API (initialize/open). The caller supplies an existing
 * private directory, never
 * a trusted clock. No function here verifies quotes or issues an approval/grant.
 * That legacy API provides NO independent anti-rollback checkpoint: restoring
 * an intact older ledger by the host owner cannot be detected by this component.
 * Consequently its challenges MUST NOT be used as authorization evidence.
 * A separate process under the same UID is not isolation: that UID can rewrite
 * ledger bytes or restore retired challenges and previously used epochs. The
 * hash chain detects corruption, not an independently witnessed state history.
 */
typedef struct qihse_ct1_authority_store qihse_ct1_authority_store_t;

typedef struct {
    uint64_t epoch;
    uint64_t issued_ms;
    uint64_t expires_ms;
    unsigned char nonce[32];
} qihse_ct1_authority_challenge_t;

/* Directory must already exist, belong to the effective UID and be mode 0700;
 * its ancestors must be root/host-owned and not writable by other users unless
 * protected by sticky-bit rename rules. Host and B must use distinct UIDs.
 * Separately controlled administrative provisioning must explicitly initialize a
 * genuinely empty directory once. Initialization is NOT a grant or an independent
 * rollback anchor: the host owner can restore an intact older ledger undetected.
 * It cannot prove a directory was never used: after deletion of both files an
 * administrator calling initialize again can reset it, so provisioning must be
 * separately controlled and must never be invoked by the runtime on open failure.
 * Existing deployments with a valid lock and log need no stored-data migration;
 * rebuild callers and provision new directories using initialize before open.
 * Missing or damaged state is a hard failure for open, including after deletion.
 * All operations return 0 on success, -1 on failure. Not safe for NFS or
 * filesystems without reliable fsync/flock semantics.
 */
int qihse_ct1_authority_store_initialize(const char *directory);
int qihse_ct1_authority_store_open(const char *directory,
                                    qihse_ct1_authority_store_t **out);
void qihse_ct1_authority_store_close(qihse_ct1_authority_store_t *store);

/* Separate LOCAL strict mode, not a grant/quote verifier or service enablement.
 * Both pre-provisioned directories must be distinct and non-nested, root-owned
 * 0700, with
 * root-owned safe ancestors; symlink path components are rejected. Checkpoint
 * retention must be independently administered, outside B's writable domain.
 * Runtime and provisioning require effective UID 0 and b_uid != 0. b_uid is
 * deployment identity, NOT a caller approval flag. B must lack root capabilities,
 * access to authority descriptors, mounts, tracing, and checkpoint backups.
 * Root compromise or rollback of BOTH domains is outside this local guarantee.
 *
 * initialize_strict requires BOTH directories empty; it never upgrades an old
 * untrusted fixture. open_strict never creates, resets, repairs or reconciles.
 * Each open/issue/retire compares the full ledger with the retained checkpoint:
 * epoch, latest used nonce, wall-clock low-water, outstanding state and hash head.
 * Ledger fsync + directory fsync precede checkpoint write + fsync + directory
 * fsync, all under the ledger lock, before revealing success. Missing, torn or
 * mismatched state fails closed, including a complete older-ledger restoration.
 * A crash between the two durable writes requires external investigation, NOT
 * retry provisioning. A fully committed issuance remains consumed even if its
 * reply was lost. No API accepts a caller clock or produces authorization.
 *
 * Migration: stored legacy data is unchanged, but CANNOT become strict state.
 * Rebuild callers; provision two NEW empty directories administratively and use
 * initialize_strict once, then open_strict. Validate locally with:
 *   make test-ct1-authority-store
 * This does not migrate live state or enable grants. Reliable local fsync/flock
 * semantics and independently retained root storage are required (not NFS).
 */
int qihse_ct1_authority_store_initialize_strict(const char *directory,
                                               const char *checkpoint_directory,
                                               uid_t b_uid);
int qihse_ct1_authority_store_open_strict(const char *directory,
                                         const char *checkpoint_directory,
                                         uid_t b_uid,
                                         qihse_ct1_authority_store_t **out);

/* Persists an issuance intent before revealing a nonce. ttl_ms is 1..900000.
 * Only one unexpired challenge can be outstanding. Epochs never wrap.
 */
int qihse_ct1_authority_store_issue(qihse_ct1_authority_store_t *store,
                                    uint64_t ttl_ms,
                                    qihse_ct1_authority_challenge_t *out);

/* Permanently retires exactly the current, unexpired challenge. This is NOT
 * a grant and cannot be used as one. Replay and mismatched nonces fail.
 */
int qihse_ct1_authority_store_retire(qihse_ct1_authority_store_t *store,
                                     const qihse_ct1_authority_challenge_t *challenge);

/* Strict root-checkpoint mode ONLY: bind the already-issued challenge to the
 * exact canonical, non-receipt B wire record. The record must contain that
 * challenge's epoch, nonce and issuance/expiry times. A durable binding intent
 * and matching independent checkpoint precede success; uncertainty denies
 * retry. retire_bound permanently spends precisely that binding and challenge.
 * Neither return authenticates the issuer, approves B or authorizes any work.
 * Legacy retire cannot spend a bound challenge. No stored legacy data migration;
 * rebuild the focused consumer with make test-ct1-authority-store. */
int qihse_ct1_authority_store_bind(qihse_ct1_authority_store_t *store,
    const qihse_ct1_authority_challenge_t *challenge,
    const unsigned char *canonical_b, size_t length);
int qihse_ct1_authority_store_retire_bound(qihse_ct1_authority_store_t *store,
    const qihse_ct1_authority_challenge_t *challenge,
    const unsigned char *canonical_b, size_t length);

/* Strict root-owned store only: under one store lock, replay the entire ledger,
 * compare its independently retained checkpoint head, and check that the exact
 * canonical B and host challenge remain bound, outstanding and unexpired at
 * the host wall clock (not below the recorded clock low-water). Never appends
 * a clock record or changes lifecycle state. This is evidence, NOT approval,
 * consumption, a grant or protection against a later retirement/expiry.
 * A handle inherited by B's distinct UID cannot perform this check. */
int qihse_ct1_authority_store_check_bound(qihse_ct1_authority_store_t *store,
    const qihse_ct1_authority_challenge_t *challenge,
    const unsigned char *canonical_b, size_t length);

#endif
