#ifndef QIHSE_CT1_SOURCE_AUTHORITY_H
#define QIHSE_CT1_SOURCE_AUTHORITY_H

#include "qihse_ct1_recovery_manifest.h"
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ROOT-ONLY OFFLINE EVIDENCE, not a source HOLD, live ownership, recovery
 * approval, ACK, archive authority, or transferable capability. The caller
 * obtains expected and the original directory's dev/ino from independent
 * root-controlled startup configuration, NOT from B, an archive, or a QKP
 * request. The Operator handle must come from a current authenticated local
 * command; the configured service ID must come from that same trusted config.
 * Neither a forged user pointer nor a QKP session pointer is accepted as proof.
 * Returns only whether an EXCLUSIVE, nonblocking directory flock permitted a
 * observation of the original root-owned private directory, its complete
 * source roster hashes and the pinned 11111 QKV6 frame/header at the stated
 * physical WAL offset. This does NOT decode CT state or establish the frame's
 * full row semantics. The lock is released on return. A copied directory
 * with another inode is refused.
 * This observation CANNOT exclude previously opened B-UID writable FDs even
 * after chown, or prove root-owned files were created fresh by root. A future
 * installer must separately establish root ownership of the source namespace
 * and exclusive SCALAR CT writer admission (--ct-role primary/successor).
 * This probe is not that installer. Callers MUST NOT use this result for
 * source/target mutation or serve it as a live endpoint. No data bytes leave
 * this function. Rebuild callers; stored data needs no migration or reindex.
 */
bool qihse_ct1_source_authority_probe_offline(
    const char *original_dir, dev_t original_dev, ino_t original_ino,
    const qihse_user_t *authenticated_operator,
    const qihse_user_t *replication_service, uint32_t configured_service_id,
    const qihse_ct1_recovery_manifest_t *expected);

/* Root-only LOCAL staging experiment. Both original and staging parent dev/ino
 * must be independently pinned; staging_name must be a fresh single basename.
 * Creates a private root-owned directory and eight NEW, unlinked-from-original
 * inodes with exact source bytes, fsyncs files and both custody directories,
 * then revalidates the complete original and staged rosters and the staged
 * physical 1644-byte frame/header at the quoted WAL offset. An existing name
 * (including an interrupted/partial stage) is refused, never resumed or
 * cleaned up automatically. Failure may leave a partial non-authoritative
 * directory. This does not hold or replace the original, revoke stale B FDs,
 * grant live writer admission, or establish source transfer authority.
 * The caller must not treat a successful copy as an ACK or a HOLD. */
bool qihse_ct1_source_authority_stage_offline(
    const char *original_dir, dev_t original_dev, ino_t original_ino,
    const char *staging_parent, dev_t parent_dev, ino_t parent_ino,
    const char *staging_name, const qihse_user_t *authenticated_operator,
    const qihse_user_t *replication_service, uint32_t configured_service_id,
    const qihse_ct1_recovery_manifest_t *expected);

/* Independent OFFLINE check of a previously staged root-fresh namespace.
 * All three directory identities must be pinned outside this call. Rehashes
 * the complete staged roster and physical 1644-byte frame/header under the
 * configured service identity, checks every staged inode is distinct from its
 * original counterpart, and fsyncs
 * staged files, staging directory and parent before reporting success. The
 * original may have changed through an already-open B descriptor; this does
 * NOT attest provenance, current original contents, live exclusion, ownership
 * transfer or a source HOLD. A partial crash-cut stage is denied, not repaired.
 * No archive/receiver action or scalar KV open is authorized by this result. */
bool qihse_ct1_source_authority_verify_stage_offline(
    const char *original_dir, dev_t original_dev, ino_t original_ino,
    const char *staging_parent, dev_t parent_dev, ino_t parent_ino,
    const char *staging_name, dev_t staged_dev, ino_t staged_ino,
    const qihse_user_t *authenticated_operator,
    const qihse_user_t *replication_service, uint32_t configured_service_id,
    const qihse_ct1_recovery_manifest_t *expected);

/* Disposable fixture lease only: this is NOT a live B takeover or a CT
 * custody HOLD. The root host supplies pinned directory identities, a fresh
 * staging basename and its locally configured replication service ID. The
 * Operator password is checked against the local auth database (user ID 0);
 * neither caller-created user/session pointers nor B-supplied identities are
 * accepted. Creates fresh root-owned files and retains an exclusive flock on
 * that directory inode until the fixture lease is destroyed. No receiver,
 * archive, ACK, reconcile, release of a CT hold, or production writer admission
 * is available through this API. It never renames/replaces the original;
 * an existing name, including a crash-uncertain rename, is never resumed.
 * The flock excludes cooperating openers only, not an already-open B writer
 * on the original; the fresh root-owned inodes isolate that stale descriptor. */
typedef struct qihse_ct1_source_fixture_lease qihse_ct1_source_fixture_lease_t;
qihse_ct1_source_fixture_lease_t *qihse_ct1_source_fixture_lease_acquire(
    const char *original_dir, dev_t original_dev, ino_t original_ino,
    const char *staging_parent, dev_t parent_dev, ino_t parent_ino,
    const char *fresh_name, const char *local_operator_password,
    uint32_t configured_service_id,
    const qihse_ct1_recovery_manifest_t *expected);
/* A fixture-only lifetime end; never clears a persisted CT custody hold. */
void qihse_ct1_source_fixture_lease_destroy(qihse_ct1_source_fixture_lease_t *lease);

#ifdef __cplusplus
}
#endif
#endif
