#ifndef QIHSE_CT1_HOST_ADMISSION_H
#define QIHSE_CT1_HOST_ADMISSION_H

#include "qihse_ct1_archive.h"
#include "qihse_ct1_recovery_manifest.h"

/* Local root-host transport admission and isolated no-op executor. No grant,
 * approval, recovered evidence or transferable session handle is returned.
 * This module is not installed in any daemon or production startup path. */
/* Exact V1 application request: one sealed QKP frame, no trailing fields.
 * This command requests only local transport admission, not an approval. */
#define QIHSE_CT1_HOST_ADMISSION_REQUEST_V1 "CT1.HOST.ADMIT.V1"
/* Challenge and ACK are sealed transport proof, never recovery authority. */
#define QIHSE_CT1_HOST_CHALLENGE_V1 "CT1.HOST.CHALLENGE.V1"
#define QIHSE_CT1_HOST_CHALLENGE_ACK_V1 "CT1.HOST.CHALLENGE.ACK.V1"
/* Exact wire suffix: big-endian epoch, issued_ms, expires_ms, then nonce. */
#define QIHSE_CT1_HOST_CHALLENGE_BYTES (8 + 8 + 8 + 32)
/* Separate evidence-only record: tag | canonical B | host challenge suffix. */
#define QIHSE_CT1_HOST_RECOVERY_INTENT_V1 "CT1.HOST.RECOVERY.INTENT.V1"
#define QIHSE_CT1_HOST_RECOVERY_INTENT_BYTES \
    (sizeof(QIHSE_CT1_HOST_RECOVERY_INTENT_V1) - 1 + \
     QIHSE_CT1_RECOVERY_WIRE_SIZE + QIHSE_CT1_HOST_CHALLENGE_BYTES)

typedef struct qihse_ct1_host_admission qihse_ct1_host_admission_t;

typedef enum {
    QIHSE_CT1_HOST_DENIED = 0,
    QIHSE_CT1_HOST_ADMITTED = 1 /* paired sequential evidence only, NEVER approval */
} qihse_ct1_host_admission_result_t;

/* root_dir is an existing root-owned mode-0700 private configuration directory
 * under trusted ancestors. It contains host/, operator/, replication/,
 * migration/ with QKP PEM keys and four root-owned node.id files, plus
 * root-owned single-link mode-0600 local-uids.conf with exactly two lines:
 * operator_uid=<nonzero decimal UID> and b_uid=<different nonzero decimal UID>.
 * These UID values are pinned at open and rechecked against the file on each
 * admission; replacements and in-place changes deny the existing handle.
 * expected-b.bin is a separately root-provisioned single-link mode-0400
 * canonical non-receipt B template, pinned at open. source/ and target/
 * contain root-owned QKP node.id and ML-DSA-87 public pins; frozen-source/
 * and frozen-target/ contain the complete private 8/7 file rosters named in
 * the template. At admission the live config IDs, DER pins, exact active
 * system replication-service principal, and both whole-file SHA-256 rosters
 * must match the independent template. No B field is trusted as an expectation.
 * socket_dir is a separate, preprovisioned root-owned mode-0711 directory
 * under trusted ancestors; it must not be inside root_dir. admission.sock is
 * mode 0666 so local clients of any UID can attempt signed QKP authentication.
 * ledger_dir and checkpoint_dir are separately preprovisioned, distinct,
 * non-nested root-owned mode-0700 strict-store directories. Runtime opens
 * existing strict state only and never provisions, repairs or resets it.
 * No network listener, daemon integration or authority to act is provided. */
qihse_ct1_host_admission_t *qihse_ct1_host_admission_open(const char *root_dir,
    const char *socket_dir, const char *ledger_dir, const char *checkpoint_dir);
/* Archive action only: archive_dir is a separate preprovisioned root-owned
 * 0700 private directory, disjoint from root/socket/ledger/checkpoint. The
 * ordinary opener has NO archive capability. No production wiring. */
qihse_ct1_host_admission_t *qihse_ct1_host_admission_open_archive(
    const char *root_dir, const char *socket_dir, const char *ledger_dir,
    const char *checkpoint_dir, const char *archive_dir);
/* Opt-in ROOT-ONLY receiver boundary for a disconnected host. receiver_dir
 * must already be a distinct root-owned 0700 disposable directory under
 * no-symlink, root-owned trusted ancestors, disjoint from root/socket/ledger/
 * checkpoint/archive. Pin its directory descriptor and identity; reject a
 * replacement, alias or permission change before nonce issue/retirement and
 * immediately before/after the protected archive action. B's UID cannot
 * traverse the receiver directory. No receiver bytes are written and neither
 * path nor descriptor nor authority token is exported to QKP peers. This is
 * not recovery authority; the receiver action requires the actual pinned
 * directory to match the signed complete TARGET roster and locked historical
 * WAL/state cursor and last matching-key tombstone before nonce issue. The
 * stable directory flock is held until the authenticated session closes.
 * A future root-only writer must use the pin inside the same authenticated
 * session. Existing openers do not opt in. Rebuild
 * callers; no stored-data migration or reindex. Focused test:
 * sudo -n make -C tests/ct1_authority test-host-admission. */
qihse_ct1_host_admission_t *qihse_ct1_host_admission_open_archive_receiver(
    const char *root_dir, const char *socket_dir, const char *ledger_dir,
    const char *checkpoint_dir, const char *archive_dir, const char *receiver_dir);
/* Separately opt-in ROOT-FRESH receiver. receiver_parent must already be a
 * root-owned 0700 private directory under trusted ancestors, disjoint from
 * all host stores; receiver_name must be a new single component. No existing
 * destination (even partial), symlink, alias or pre-existing receiver inode is
 * adopted. After signed pair evidence, the host copies the complete verified
 * frozen TARGET roster into NEW root-owned inodes and pins them for this
 * instance only. Crashes leave an unusable directory: choose a new name after
 * independently reconciling the outstanding nonce. Callers must rebuild;
 * stored data needs no migration or reindex. No production wiring. Focused
 * check: sudo -n make -C tests/ct1_authority test-host-native-evidence. */
qihse_ct1_host_admission_t *qihse_ct1_host_admission_open_archive_receiver_fresh(
    const char *root_dir, const char *socket_dir, const char *ledger_dir,
    const char *checkpoint_dir, const char *archive_dir,
    const char *receiver_parent, const char *receiver_name);
/* Accept exactly one connection; require a signed configured Operator QKP
 * session, the exact configured Operator SO_PEERCRED UID (never B's UID),
 * one exact sealed V1 request, then a sealed durable strict-store challenge
 * (epoch, host-issued time, expiry, nonce) and exact UID-checked sealed
 * acknowledgement on that connection within one deadline. Receive one
 * canonical B via the SAME live QKP session with per-fragment Operator UID
 * checks; replace only the template challenge fields with the strict-store
 * issuance, compare every byte, then durably bind while the session lives.
 * The issuance is not retired; a second issue while outstanding denies.
 * Receive separate exact SOURCE and TARGET QUOTE-V2 sealed frames with UID
 * checks on that same session. Independently derive both role expectations
 * from the current pinned root template and root node keys, then evaluate
 * both strict ML-DSA signatures, frozen rosters and outstanding binding via
 * the non-retiring pair evaluator. Only after paired evidence verifies,
 * require an exact sealed recovery intent (tag, canonical B, host challenge)
 * on that Operator session with per-fragment UID checks. The challenge remains
 * outstanding after success. This enum is sequential evidence only, not jointly fresh
 * node state, approval, grant, executor, target apply or production wiring.
 * Close the connection and destroy the session before returning an enum only. */
qihse_ct1_host_admission_result_t qihse_ct1_host_admission_once(qihse_ct1_host_admission_t *host);
/* Root-only local executor: keep the configured Operator QKP connection alive
 * through exact intent and independently verified pair; immediately before the
 * internal no-op, recheck config and retire the bound strict nonce durably.
 * A successful action writes root-owned ct1-noop-<epoch>.receipt in root_dir,
 * containing only the canonical B SHA-256 and epoch (not an authority token).
 * Crash/failure after retirement is spent and MUST NOT be retried. Returns no
 * approval or status to the peer/caller. This no-op never creates an archive,
 * SOURCE ACK or target apply; the separate archive action is opt-in root-only.
 * This does not authorize access to production data. Rebuild callers; no stored
 * data migration or reindex. Focused check: sudo -n make -C tests/ct1_authority
 * test-host-admission. */
void qihse_ct1_host_execute_noop_once(qihse_ct1_host_admission_t *host);
/* Protected root-only custody action. After paired signed evidence and exact
 * intent on the same live UID-checked QKP session, accept no further frame;
 * retire the strict nonce, then independently read the exact original from
 * the root-owned frozen SOURCE WAL into immutable archive custody. No status
 * or ACK is returned. Crash after retirement cannot be retried. Admission
 * and no-op remain unchanged. The quote signs B, not a live source WAL read:
 * custody is not authoritative proof of jointly fresh SOURCE state. */
void qihse_ct1_host_execute_archive_once(qihse_ct1_host_admission_t *host);
/* Receiver action is fail-closed: offline preflight locks the pinned actual
 * TARGET directory, verifies its signed roster, QCTST003 state and complete
 * historical receiver WAL prefix with the authenticated full-clearance principal.
 * It denies a contending owner or missing/rotated history before nonce issuance.
 * No nonce retirement, archive or receiver write occurs until durable write,
 * custody and crash-cut prerequisites can be established.
 * Requires the opt-in receiver opener; the independent archive-only action
 * above is unchanged. */
void qihse_ct1_host_execute_archive_receiver_once(qihse_ct1_host_admission_t *host);
/* ROOT-FRESH only: provision new TARGET inodes after signed pair, recheck
 * their provenance and locked history before publication on the live socket.
 * No archive action, QCT1SO02 append or nonce retirement. */
void qihse_ct1_host_execute_archive_receiver_fresh_once(qihse_ct1_host_admission_t *host);
/* Reserved ROOT-FRESH protected action: currently DENIES before nonce issue,
 * receiver provisioning, retirement, archive or append. The host's frozen
 * SOURCE WAL and paired signed quotes cannot install or verify a hold on the
 * live source store. A future implementation needs a root-live pinned source
 * QKP endpoint with an atomic durable hold bound to the exact generation,
 * baseline digest/sequence, source position, pending 1644-byte original and
 * canonical B before ANY irreversible step. An archive ID is only a locator,
 * never a hold-release token. No production wiring. Rebuild callers; stored
 * data needs no migration or reindex. */
void qihse_ct1_host_execute_archive_receiver_fresh_protected_once(
    qihse_ct1_host_admission_t *host);
/* Reopen and revalidate root config, signed quotes and source WAL independently.
 * expected is independently authenticated authority, not archive content. */
bool qihse_ct1_host_archive_verify(qihse_ct1_host_admission_t *host,
    const qihse_user_t *principal, const qihse_ct1_recovery_manifest_t *expected,
    const char *archive_id);
void qihse_ct1_host_admission_close(qihse_ct1_host_admission_t *host);

#endif
