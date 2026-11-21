#ifndef QIHSE_CT1_RECEIVER_WRITER_H
#define QIHSE_CT1_RECEIVER_WRITER_H

#include "qihse_ct1_recovery_manifest.h"
#include <sys/stat.h>

/* Internal ROOT-FRESH provisioner. Call only after the host has authenticated
 * the service principal and independently verified the signed TARGET quote.
 * On failure the exclusive directory is left in place and cannot be retried.
 * The caller retains dirfd and the seven inode pins for this host instance. */
bool qihse_ct1_receiver_fresh_provision(int parentfd, const char *basename,
    const char *source, const char *destination, const qihse_user_t *principal,
    const qihse_ct1_recovery_manifest_t *manifest, int *dirfd,
    struct stat pins[QIHSE_CT1_RECOVERY_TARGET_FILES]);
bool qihse_ct1_receiver_fresh_pinned(int dirfd, const char *destination,
    const qihse_user_t *principal, const qihse_ct1_recovery_manifest_t *manifest,
    const struct stat pins[QIHSE_CT1_RECOVERY_TARGET_FILES]);

/* Root-host internal, read-only offline receiver preflight. The caller owns an
 * exclusive flock on pinned_dirfd for the entire live Operator session. This
 * requires QCTST005 and is not an approval, writer, transferable token or
 * public mutation API. Pre-lease live handles remain outside this proof. */
bool qihse_ct1_receiver_preflight_locked(int pinned_dirfd, const char *pinned_path,
    const qihse_user_t *principal, const qihse_ct1_recovery_manifest_t *manifest);

#endif
