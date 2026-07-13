/*
 * QIHSE single-file container format (.qdb).
 *
 * Layout:
 *   [File header  – QIHSE_CTR_HEADER_SIZE bytes]
 *   [Section table – QIHSE_CTR_MAX_SECTIONS * QIHSE_CTR_SECTION_ENTRY_SIZE bytes]
 *   [Section payloads at declared offsets]
 *
 * All multi-byte values are little-endian.
 * Atomic flush: write to <path>.tmp, fsync, rename over destination.
 * The file lock is held via POSIX fcntl(F_SETLK) on the open fd.
 */

#ifndef QIHSE_CONTAINER_H
#define QIHSE_CONTAINER_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "qihse_pqc_crypto.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ── Section IDs ──────────────────────────────────────────────────── */
#define QIHSE_CTR_SEC_MANIFEST  0x0001u
#define QIHSE_CTR_SEC_WAL       0x0002u
#define QIHSE_CTR_SEC_INDEX     0x0003u
#define QIHSE_CTR_SEC_IDMAP     0x0004u
#define QIHSE_CTR_SEC_VECTORS   0x0005u
#define QIHSE_CTR_SEC_METADATA  0x0006u
#define QIHSE_CTR_SEC_TRINARY   0x0007u
#define QIHSE_CTR_SEC_MAGNITUDE 0x0008u
#define QIHSE_CTR_SEC_GRAPH     0x0009u
#define QIHSE_CTR_SEC_INT8      0x000Au
#define QIHSE_CTR_SEC_TIER      0x000Bu
#define QIHSE_CTR_SEC_EDGES     0x000Cu
#define QIHSE_CTR_SEC_KEY       0x1000u
#define QIHSE_CTR_SEC_SIGNATURE 0x1001u

#define QIHSE_CTR_NUM_SECTIONS  14u

/* ── Layout constants ─────────────────────────────────────────────── */
#define QIHSE_CTR_MAGIC         "QIHSEQDB"
#define QIHSE_CTR_VERSION       1u
#define QIHSE_CTR_HEADER_SIZE   80u
#define QIHSE_CTR_SECTION_ENTRY_SIZE 80u
#define QIHSE_CTR_MAX_SECTIONS  QIHSE_CTR_NUM_SECTIONS
/* Table offset immediately follows the file header */
#define QIHSE_CTR_TABLE_OFFSET  QIHSE_CTR_HEADER_SIZE
#define QIHSE_CTR_TABLE_SIZE    (QIHSE_CTR_MAX_SECTIONS * QIHSE_CTR_SECTION_ENTRY_SIZE)
/* First payload byte starts after header + table */
#define QIHSE_CTR_PAYLOAD_BASE  (QIHSE_CTR_HEADER_SIZE + QIHSE_CTR_TABLE_SIZE)

/* ── Structs ──────────────────────────────────────────────────────── */

typedef struct qihse_ctr_section_s {
    uint16_t section_id;   /* QIHSE_CTR_SEC_* */
    uint16_t flags;
    uint32_t reserved;
    uint64_t offset;       /* Byte offset from start of file */
    uint64_t length;       /* Payload byte count */
    uint8_t  hmac_sha384[48]; /* HMAC-SHA-384 of payload */
} qihse_ctr_section_t;

/*
 * In-memory view of a container opened for reading/writing.
 * Callers must not modify fields directly; use the API functions.
 */
typedef struct qihse_container_s {
    int fd;
    char* path;            /* Owned copy of the file path */
    bool locked;
    qihse_ctr_section_t sections[QIHSE_CTR_MAX_SECTIONS];
    uint32_t section_count;
    qihse_pqc_ctx_t pqc_ctx;
} qihse_container_t;

/* ── Lifecycle ────────────────────────────────────────────────────── */

/*
 * Open an existing .qdb file for reading.
 * Returns true and populates *ctr on success.
 */
bool qihse_ctr_open_read(const char* path, qihse_container_t* ctr);

/*
 * Open or create a .qdb file for read/write access.
 * Acquires a POSIX write lock; fails if another writer holds the lock.
 * On create, initialises an empty section table.
 */
bool qihse_ctr_open_write(const char* path, bool create, qihse_container_t* ctr);

/*
 * Close the container fd and release the lock.  Always call this even
 * after a failed open to avoid resource leaks.
 */
void qihse_ctr_close(qihse_container_t* ctr);

/* ── Section access ───────────────────────────────────────────────── */

/*
 * Find a section entry by ID.  Returns NULL if not present or length==0.
 */
const qihse_ctr_section_t* qihse_ctr_find_section(const qihse_container_t* ctr,
                                                   uint16_t section_id);

/*
 * Allocate a buffer and read the full payload for section_id.
 * Sets *out and *out_size.  Caller must free(*out).
 * Returns false if the section is missing, empty, or fails HMAC-SHA-384 verification.
 */
bool qihse_ctr_read_section_alloc(const qihse_container_t* ctr,
                                  uint16_t section_id,
                                  uint8_t** out,
                                  size_t* out_size);

/*
 * Read exactly `size` bytes of section_id at byte offset `sec_offset`
 * within the section payload into caller-supplied `buf`.
 * Used for streaming reads (e.g. partial WAL replay).
 */
bool qihse_ctr_read_section_at(const qihse_container_t* ctr,
                                uint16_t section_id,
                                void* buf,
                                size_t size,
                                uint64_t sec_offset);

/*
 * Return the current length of a section (0 if absent).
 */
uint64_t qihse_ctr_section_length(const qihse_container_t* ctr, uint16_t section_id);

/* ── Atomic flush (snapshot sections) ────────────────────────────── */

typedef struct qihse_ctr_section_buf_s {
    uint16_t section_id;
    const void* data;
    size_t size;
} qihse_ctr_section_buf_t;

/*
 * Write a new container to <path>.tmp with the provided section payloads,
 * fsync, then rename over <path>.  The lock fd (ctr->fd) is kept open
 * and the section table in *ctr is updated to reflect the new layout.
 * Sections not listed in bufs[] are preserved from the existing ctr if
 * present; pass NULL data or size==0 to omit a section.
 */
bool qihse_ctr_flush(qihse_container_t* ctr,
                     const qihse_ctr_section_buf_t* bufs,
                     size_t buf_count);

/* ── WAL append helpers ───────────────────────────────────────────── */

/*
 * Append `size` bytes at the end of the WAL section, extending the
 * section.  Updates the section table entry (length only; HMAC is
 * intentionally not maintained for the WAL — individual WAL records
 * carry their own integrity per the existing protocol).
 * Does NOT fsync; caller is responsible.
 */
bool qihse_ctr_wal_append(qihse_container_t* ctr, const void* data, size_t size);

/*
 * Truncate the WAL section to `new_length` bytes.
 * If new_length == 0 the section entry length is zeroed.
 */
bool qihse_ctr_wal_truncate(qihse_container_t* ctr, uint64_t new_length);

/*
 * fsync the container fd.
 */
bool qihse_ctr_fsync(qihse_container_t* ctr);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* QIHSE_CONTAINER_H */
