/*
 * qihse_vfs_wal.h — Marmalade-backed WAL router for the QIHSE SQLite VFS
 * ========================================================================
 *
 * Routes SQLite WAL file I/O through qihse_event_stream (Marmalade).
 *
 * Each SQLite WAL frame becomes one Marmalade append-only record whose topic
 * is "wal".  The 8-byte little-endian byte-offset within the WAL file is
 * embedded at the start of every record payload so frames can be replayed
 * back into the correct position regardless of append order.
 *
 * Payload layout (per record):
 *   bytes 0–7   : 64-bit LE byte offset of this frame within the WAL file
 *   bytes 8–N   : raw WAL frame data (as written by SQLite)
 *
 * Recovery
 * --------
 * On the first xRead of any WAL file the module calls
 * qihse_vfs_wal_rebuild_flat() which:
 *   1. Calls qihse_event_stream_truncate_torn_tail() to discard any
 *      uncommitted tail records from a previous crash.
 *   2. Iterates every committed record and writes its data into a
 *      heap-allocated flat byte buffer at the embedded offset position.
 *   3. Subsequent xRead calls memcpy from this buffer.
 *
 * The flat buffer is invalidated (replayed=false) on every xWrite so that
 * the next xRead triggers a fresh rebuild incorporating new frames.
 */

#ifndef QIHSE_VFS_WAL_H
#define QIHSE_VFS_WAL_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "../include/qihse_event_stream.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Schema ID written into every Marmalade record for WAL frames. */
#define QIHSE_VFS_WAL_SCHEMA_ID  0xDB1Au

/* Marmalade topic name used for all WAL records. */
#define QIHSE_VFS_WAL_TOPIC  "wal"

/* Prefix embedded in the payload to carry the file offset. */
#define QIHSE_VFS_WAL_OFFSET_SIZE  8u   /* sizeof(uint64_t) */

typedef struct {
    qihse_event_stream_t* stream;    /* Marmalade handle */
    uint8_t*              replay_buf; /* Flat WAL image rebuilt from records */
    size_t                replay_len; /* Current length of replay_buf */
    size_t                replay_cap; /* Allocated capacity of replay_buf */
    bool                  replayed;   /* true → replay_buf is up to date */
} qihse_vfs_wal_t;

/*
 * qihse_vfs_wal_create — open (or create) the WAL event stream at log_dir.
 *
 * log_dir should be a directory path derived from the WAL file path, e.g.
 * "/path/to/database.db-wal.d/".
 *
 * Returns NULL on failure.
 */
qihse_vfs_wal_t* qihse_vfs_wal_create(const char* log_dir);

/*
 * qihse_vfs_wal_destroy — flush, close, and free the WAL handle.
 */
void qihse_vfs_wal_destroy(qihse_vfs_wal_t* wal);

/*
 * qihse_vfs_wal_append — record one WAL write at the given file offset.
 *
 * This is called from xWrite when the file was opened with SQLITE_OPEN_WAL.
 * Encodes payload as [8-byte LE offset][data] and appends to Marmalade.
 * Invalidates replay_buf so the next read triggers rebuild.
 *
 * Returns true on success.
 */
bool qihse_vfs_wal_append(qihse_vfs_wal_t* wal,
                           int64_t offset,
                           const uint8_t* data, size_t size);

/*
 * qihse_vfs_wal_read — copy size bytes at offset from the WAL image.
 *
 * Triggers a rebuild via qihse_vfs_wal_rebuild_flat() on first call or after
 * any write.  Returns true if offset+size is within the rebuilt image, false
 * (short read) otherwise.
 */
bool qihse_vfs_wal_read(qihse_vfs_wal_t* wal,
                         int64_t offset,
                         uint8_t* buf, size_t size);

/*
 * qihse_vfs_wal_size — return the logical byte size of the WAL image.
 */
uint64_t qihse_vfs_wal_size(qihse_vfs_wal_t* wal);

/*
 * qihse_vfs_wal_flush — fdatasync the underlying event-stream segment file.
 */
bool qihse_vfs_wal_flush(qihse_vfs_wal_t* wal);

/*
 * qihse_vfs_wal_rebuild_flat — internal; exposed for testing.
 * Reconstructs replay_buf from committed Marmalade records.
 */
bool qihse_vfs_wal_rebuild_flat(qihse_vfs_wal_t* wal);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* QIHSE_VFS_WAL_H */
