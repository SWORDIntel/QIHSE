#ifndef QIHSE_WAL_H
#define QIHSE_WAL_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "qihse_platform.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ── Constants ──────────────────────────────────────────────────────────── */

#define QIHSE_WAL_MAGIC       0x5157414Cu  /* "QWAL" */
#define QIHSE_WAL_FORMAT_VER  1u
#define QIHSE_WAL_HEADER_SIZE 32u
#define QIHSE_WAL_DEFAULT_SEGMENT_SIZE (64u * 1024u * 1024u) /* 64 MiB */
#define QIHSE_WAL_MAX_KEY     4096u
#define QIHSE_WAL_MAX_VALUE   (16u * 1024u * 1024u) /* 16 MiB */
#define QIHSE_WAL_INVALID_LSN 0u

/* ── Operation types ────────────────────────────────────────────────────── */

typedef enum qihse_wal_op_e {
    QIHSE_WAL_OP_INSERT = 1,
    QIHSE_WAL_OP_UPDATE = 2,
    QIHSE_WAL_OP_DELETE = 3,
    QIHSE_WAL_OP_BEGIN  = 4,
    QIHSE_WAL_OP_COMMIT = 5,
    QIHSE_WAL_OP_ABORT  = 6,
    QIHSE_WAL_OP_CHECKPOINT = 7
} qihse_wal_op_t;

/* ── Durability modes ───────────────────────────────────────────────────── */

typedef enum qihse_wal_durability_e {
    QIHSE_WAL_DURABILITY_NONE      = 0,
    QIHSE_WAL_DURABILITY_FDATASYNC = 1,
    QIHSE_WAL_DURABILITY_GROUP_COMMIT = 2
} qihse_wal_durability_t;

/* ── WAL record (on-disk format) ────────────────────────────────────────── */

typedef struct qihse_wal_record_s {
    uint64_t   lsn;          /* 8 bytes: monotonic log sequence number */
    uint64_t   txn_id;       /* 8 bytes: transaction ID */
    uint8_t    engine_id;    /* 1 byte:  engine identifier */
    uint8_t    op_type;      /* 1 byte:  qihse_wal_op_t */
    uint32_t   key_length;   /* 4 bytes: key length */
    uint32_t   value_length; /* 4 bytes: value length (0 for DELETE) */
    uint32_t   checksum;     /* 4 bytes: CRC32 of payload + header fields */
    /* Followed by: key[key_length], value[value_length] */
} qihse_wal_record_t;

#define QIHSE_WAL_RECORD_HEADER_SIZE 30u  /* sizeof fields above (packed) */

/* ── WAL handle (opaque) ────────────────────────────────────────────────── */

typedef struct qihse_wal qihse_wal_t;

/* ── Lifecycle ──────────────────────────────────────────────────────────── */

/* Create / open a WAL in the given directory.
 * segment_size: max size per segment file (0 = default 64 MiB).
 * durability: fsync policy. */
qihse_wal_t* qihse_wal_create(const char* directory,
                              size_t segment_size,
                              qihse_wal_durability_t durability);
void qihse_wal_destroy(qihse_wal_t* wal);

/* ── Append operations ──────────────────────────────────────────────────── */

/* Append a mutation record.  Returns the assigned LSN, or 0 on failure. */
uint64_t qihse_wal_append(qihse_wal_t* wal,
                          uint64_t txn_id,
                          uint8_t engine_id,
                          qihse_wal_op_t op_type,
                          const void* key, uint32_t key_len,
                          const void* value, uint32_t value_len);

/* Append a BEGIN record for a transaction. */
uint64_t qihse_wal_append_begin(qihse_wal_t* wal, uint64_t txn_id);

/* Append a COMMIT record for a transaction. */
uint64_t qihse_wal_append_commit(qihse_wal_t* wal, uint64_t txn_id);

/* Append an ABORT record for a transaction. */
uint64_t qihse_wal_append_abort(qihse_wal_t* wal, uint64_t txn_id);

/* Append a CHECKPOINT record. */
uint64_t qihse_wal_append_checkpoint(qihse_wal_t* wal, uint64_t lsn);

/* Flush pending writes to disk according to durability policy. */
int qihse_wal_flush(qihse_wal_t* wal);

/* ── Replay / recovery ──────────────────────────────────────────────────── */

/* Callback invoked for each valid WAL record during replay. */
typedef bool (*qihse_wal_replay_cb)(const qihse_wal_record_t* record,
                                    const void* key, uint32_t key_len,
                                    const void* value, uint32_t value_len,
                                    void* user_data);

/* Replay all WAL records from the given start LSN (0 = from beginning).
 * Returns the number of records replayed, or -1 on error. */
int qihse_wal_replay(qihse_wal_t* wal, uint64_t start_lsn,
                     qihse_wal_replay_cb callback, void* user_data);

/* ── Checkpoint ─────────────────────────────────────────────────────────── */

/* Record a checkpoint and truncate WAL segments older than the checkpoint LSN.
 * Returns 0 on success. */
int qihse_wal_checkpoint(qihse_wal_t* wal, uint64_t checkpoint_lsn);

/* Get the current LSN (next LSN to be assigned). */
uint64_t qihse_wal_current_lsn(qihse_wal_t* wal);

/* Get the last checkpoint LSN. */
uint64_t qihse_wal_last_checkpoint(qihse_wal_t* wal);

/* ── CRC32 utility ──────────────────────────────────────────────────────── */

uint32_t qihse_wal_crc32(const void* data, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* QIHSE_WAL_H */
