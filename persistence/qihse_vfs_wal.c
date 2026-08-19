/*
 * qihse_vfs_wal.c — Marmalade-backed WAL router for the QIHSE SQLite VFS
 * ========================================================================
 *
 * Implements the WAL routing layer defined in qihse_vfs_wal.h.
 *
 * Each SQLite WAL write is stored as one Marmalade append-only record.
 * The first 8 bytes of every record payload encode the 64-bit little-endian
 * byte offset so frames can be replayed back into the correct position in
 * the flat replay buffer regardless of the order in which they were appended.
 *
 * Crash recovery: qihse_event_stream_truncate_torn_tail() removes any
 * uncommitted tail before replay so only fully committed WAL frames are
 * replayed to SQLite, maintaining the SQLite WAL invariants exactly.
 */

#ifndef _POSIX_C_SOURCE
#  define _POSIX_C_SOURCE 200809L
#endif

#include "qihse_vfs_wal.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

/* Grow the replay buffer to at least new_size bytes.  Returns false on OOM. */
static bool wal_buf_grow(qihse_vfs_wal_t* wal, size_t new_size)
{
    if (new_size <= wal->replay_cap) return true;

    /* Round up to next 64 KB boundary to amortise reallocations. */
    size_t cap = wal->replay_cap ? wal->replay_cap : (64u * 1024u);
    while (cap < new_size) cap *= 2u;

    uint8_t* p = (uint8_t*)realloc(wal->replay_buf, cap);
    if (!p) return false;

    /* Zero-fill the newly allocated region so short reads return clean data. */
    memset(p + wal->replay_cap, 0, cap - wal->replay_cap);

    wal->replay_buf = p;
    wal->replay_cap = cap;
    return true;
}

/* ── Lifecycle ────────────────────────────────────────────────────────────── */

qihse_vfs_wal_t* qihse_vfs_wal_create(const char* log_dir)
{
    if (!log_dir) return NULL;

    qihse_vfs_wal_t* wal = (qihse_vfs_wal_t*)calloc(1, sizeof(qihse_vfs_wal_t));
    if (!wal) return NULL;

    wal->stream = qihse_event_stream_open(log_dir,
                                           QIHSE_ES_DURABILITY_FDATASYNC,
                                           false /* read_write */);
    if (!wal->stream) {
        /* Try creating a fresh stream. */
        wal->stream = qihse_event_stream_create(log_dir);
    }
    if (!wal->stream) {
        free(wal);
        return NULL;
    }

    wal->replay_buf = NULL;
    wal->replay_len = 0u;
    wal->replay_cap = 0u;
    wal->replayed   = false;

    return wal;
}

void qihse_vfs_wal_destroy(qihse_vfs_wal_t* wal)
{
    if (!wal) return;
    if (wal->stream) {
        qihse_event_stream_flush(wal->stream);
        qihse_event_stream_destroy(wal->stream);
        wal->stream = NULL;
    }
    free(wal->replay_buf);
    wal->replay_buf = NULL;
    free(wal);
}

/* ── Rebuild flat image ───────────────────────────────────────────────────── */

/*
 * Callback invoked by qihse_event_stream_replay() for each committed record.
 * Writes the record's data bytes into replay_buf at the embedded offset.
 */
static bool rebuild_cb(const qihse_es_record_header_t* hdr,
                        const uint8_t* payload,
                        size_t payload_size,
                        void* user_data)
{
    qihse_vfs_wal_t* wal = (qihse_vfs_wal_t*)user_data;
    (void)hdr;

    if (payload_size < QIHSE_VFS_WAL_OFFSET_SIZE) return true; /* skip corrupt */

    /* Extract the embedded byte offset (little-endian uint64_t). */
    uint64_t file_offset = 0u;
    memcpy(&file_offset, payload, QIHSE_VFS_WAL_OFFSET_SIZE);
    /* If host is big-endian, swap: */
#if defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
    {
        uint8_t* b = (uint8_t*)&file_offset;
        uint64_t v = ((uint64_t)b[0])       | ((uint64_t)b[1] << 8)  |
                     ((uint64_t)b[2] << 16)  | ((uint64_t)b[3] << 24) |
                     ((uint64_t)b[4] << 32)  | ((uint64_t)b[5] << 40) |
                     ((uint64_t)b[6] << 48)  | ((uint64_t)b[7] << 56);
        file_offset = v;
    }
#endif

    const uint8_t* frame_data = payload + QIHSE_VFS_WAL_OFFSET_SIZE;
    size_t         frame_size = payload_size - QIHSE_VFS_WAL_OFFSET_SIZE;

    /* Ensure the replay buffer is large enough. */
    size_t needed = (size_t)file_offset + frame_size;
    if (!wal_buf_grow(wal, needed)) return false;  /* stop on OOM */

    memcpy(wal->replay_buf + file_offset, frame_data, frame_size);

    if (needed > wal->replay_len) wal->replay_len = needed;

    return true; /* continue replay */
}

bool qihse_vfs_wal_rebuild_flat(qihse_vfs_wal_t* wal)
{
    if (!wal || !wal->stream) return false;

    /* Reset the flat image. */
    wal->replay_len = 0u;
    /* Do not free replay_buf — reuse the allocation. */

    /* 1. Discard any uncommitted torn tail from a previous crash. */
    qihse_event_stream_truncate_torn_tail(wal->stream, QIHSE_VFS_WAL_TOPIC);

    /* 2. Replay all committed records into the flat buffer. */
    uint64_t records_replayed =
        qihse_event_stream_replay(wal->stream,
                                   QIHSE_VFS_WAL_TOPIC,
                                   rebuild_cb,
                                   wal);

    /* replay returns the count of records processed; 0 is valid for empty WAL. */
    (void)records_replayed;

    wal->replayed = true;
    return true;
}

/* ── Append ──────────────────────────────────────────────────────────────── */

bool qihse_vfs_wal_append(qihse_vfs_wal_t* wal,
                           int64_t offset,
                           const uint8_t* data, size_t size)
{
    if (!wal || !wal->stream || !data || size == 0u) return false;
    if (offset < 0) return false;

    /* Build payload = [8-byte LE offset][frame bytes]. */
    size_t payload_len = QIHSE_VFS_WAL_OFFSET_SIZE + size;
    uint8_t* payload = (uint8_t*)malloc(payload_len);
    if (!payload) return false;

    uint64_t le_offset = (uint64_t)offset;
#if defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
    {
        uint8_t* b = (uint8_t*)&le_offset;
        uint64_t v = le_offset;
        b[0] = (uint8_t)(v);       b[1] = (uint8_t)(v >> 8);
        b[2] = (uint8_t)(v >> 16); b[3] = (uint8_t)(v >> 24);
        b[4] = (uint8_t)(v >> 32); b[5] = (uint8_t)(v >> 40);
        b[6] = (uint8_t)(v >> 48); b[7] = (uint8_t)(v >> 56);
    }
#endif
    memcpy(payload, &le_offset, QIHSE_VFS_WAL_OFFSET_SIZE);
    memcpy(payload + QIHSE_VFS_WAL_OFFSET_SIZE, data, size);

    /*
     * Use the legacy append which computes SHA-384(topic || payload) internally
     * as the event ID.  If the same frame is appended twice (same offset +
     * same data) Marmalade's duplicate-rejection guard discards the second
     * write silently — which is the correct behaviour.
     */
    bool ok = qihse_event_stream_append(wal->stream,
                                         QIHSE_VFS_WAL_TOPIC,
                                         payload, payload_len);
    free(payload);

    if (ok) {
        /* Invalidate the flat image so the next xRead triggers a rebuild. */
        wal->replayed = false;
    }
    return ok;
}

/* ── Read ────────────────────────────────────────────────────────────────── */

bool qihse_vfs_wal_read(qihse_vfs_wal_t* wal,
                         int64_t offset, uint8_t* buf, size_t size)
{
    if (!wal || !buf || size == 0u || offset < 0) return false;

    if (!wal->replayed) {
        if (!qihse_vfs_wal_rebuild_flat(wal)) return false;
    }

    uint64_t uoff = (uint64_t)offset;
    if (uoff + size > wal->replay_len) return false; /* short read */

    memcpy(buf, wal->replay_buf + uoff, size);
    return true;
}

/* ── Size ────────────────────────────────────────────────────────────────── */

uint64_t qihse_vfs_wal_size(qihse_vfs_wal_t* wal)
{
    if (!wal) return 0u;
    if (!wal->replayed) {
        qihse_vfs_wal_rebuild_flat(wal);
    }
    return (uint64_t)wal->replay_len;
}

/* ── Flush ───────────────────────────────────────────────────────────────── */

bool qihse_vfs_wal_flush(qihse_vfs_wal_t* wal)
{
    if (!wal || !wal->stream) return false;
    return qihse_event_stream_flush(wal->stream);
}
