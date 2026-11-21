#ifndef QIHSE_CT1_ARCHIVE_H
#define QIHSE_CT1_ARCHIVE_H

#include "qihse_auth.h"
#include "qihse_ct1_node_quote.h"
#include "qihse_ct1_recovery_manifest.h"

#ifdef __cplusplus
extern "C" {
#endif

#define QIHSE_CT1_ARCHIVE_ID_SIZE 73u

/* Internal root-host custody context. All directories and key paths are
 * preprovisioned, private and pinned by host admission, never supplied by a
 * QKP client. A standalone caller-supplied B or digest is not evidence. */
typedef struct {
    int dirfd;
    const char *frozen_source_dir, *frozen_target_dir;
    const char *source_pub_path, *target_pub_path;
    const qihse_ct1_node_quote_expected_t *source_expected, *target_expected;
} qihse_ct1_archive_root_t;

/* Root-host only: called inside the SAME authenticated Operator QKP session
 * after canonical B, both verified quotes and exact intent. Archive checks
 * paired peer bindings, stale position/sequence and both high-water bounds;
 * these signed descriptors are not proof of live measured state. No peer
 * supplies the original: read the entire 1644-byte root-owned frozen SOURCE
 * WAL after complete roster verification, decode under the authenticated
 * full-clearance system principal, recheck the roster and persist exact bytes
 * with signed quotes and a committed root-owned seal. The SOURCE quote signs B,
 * including the frame digest and roster hashes, but its signer does not prove
 * a live read of that exact WAL: this custody record is not authoritative proof
 * of jointly fresh source state, a grant, ACK or exceptional receiver apply.
 * Even archive_verify(true) cannot release a source custody hold: root-host
 * approval and durable one-use release proof must additionally bind the exact
 * B, frame and source principal, not an archive ID or caller-provided digest.
 * Failure may leave an immutable incomplete file: never retry the same ID. */
bool qihse_ct1_archive_write_root(const qihse_ct1_archive_root_t *root,
    const qihse_user_t *principal, const qihse_ct1_recovery_manifest_t *expected,
    const unsigned char canonical[QIHSE_CT1_RECOVERY_WIRE_SIZE],
    const unsigned char source_quote[QIHSE_CT1_NODE_QUOTE_SIZE],
    const unsigned char target_quote[QIHSE_CT1_NODE_QUOTE_SIZE],
    char archive_id[QIHSE_CT1_ARCHIVE_ID_SIZE]);

/* expected is independent authenticated authority, never archive contents;
 * root config must be revalidated by the caller on every cold reopen. No
 * classified bytes are returned. Only exact persisted SOURCE originals pass. */
bool qihse_ct1_archive_verify(const qihse_ct1_archive_root_t *root,
    const qihse_user_t *principal, const qihse_ct1_recovery_manifest_t *expected,
    const char *archive_id);

/* Root-host custody read for a future protected receiver writer only. The
 * caller supplies independently authenticated expected B and pinned config;
 * archive ID is a locator, not write authority, source ACK or reconciliation.
 * Reuses full archive verification and rechecks principal before disclosure.
 * On denial the entire output is zeroed; no partial frame is exposed. */
bool qihse_ct1_archive_read_source_root(const qihse_ct1_archive_root_t *root,
    const qihse_user_t *principal, const qihse_ct1_recovery_manifest_t *expected,
    const char *archive_id,
    unsigned char out[QIHSE_CT1_RECOVERY_FRAME_BYTES]);

#ifdef __cplusplus
}
#endif
#endif
