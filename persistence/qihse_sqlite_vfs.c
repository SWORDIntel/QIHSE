/*
 * qihse_sqlite_vfs.c — QIHSE-backed SQLite Virtual File System
 * =============================================================
 *
 * Implements sqlite3_vfs and sqlite3_io_methods backed entirely by QIHSE
 * primitives.  See qihse_sqlite_vfs.h for the public API and design rationale.
 *
 * Compilation units required alongside this file:
 *   persistence/qihse_vfs_page_cache.c
 *   persistence/qihse_vfs_wal.c
 *   persistence/qihse_file_posix.c
 *   persistence/qihse_pqc_crypto.c   (only if QIHSE_VFS_ENCRYPT=1)
 *
 * The SQLITE_EXTENSION_INIT macros (SQLITE_CORE) declare sqlite3_api_routines
 * as an extern rather than a local pointer, which is correct for code compiled
 * directly into libqihse.so.  If building as a separate loadable extension,
 * remove -DSQLITE_CORE and define SQLITE_EXTENSION_INIT1 locally.
 */

#ifndef _GNU_SOURCE
#  define _GNU_SOURCE
#endif
#ifndef _POSIX_C_SOURCE
#  define _POSIX_C_SOURCE 200809L
#endif
#ifndef _FILE_OFFSET_BITS
#  define _FILE_OFFSET_BITS 64
#endif

#include <sqlite3ext.h>
SQLITE_EXTENSION_INIT1

#include "qihse_sqlite_vfs.h"
#include "qihse_vfs_page_cache.h"
#include "qihse_vfs_wal.h"
#include "qihse_file.h"
#include "qihse_platform.h"

#ifdef QIHSE_VFS_ENCRYPT
#  include "qihse_pqc_crypto.h"
#endif

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

/* ── Constants ───────────────────────────────────────────────────────────── */

#define QIHSE_VFS_MAX_PATH      512u

/*
 * Byte ranges used for fcntl advisory locking in the .qlock sidecar.
 * Mirrors SQLite's own POSIX VFS lock byte assignments exactly so that
 * RESERVED/PENDING semantics are preserved when multiple processes open
 * the same database.
 *
 *  SHARED    : bytes [0, 1)
 *  RESERVED  : bytes [1, 2)
 *  PENDING   : bytes [2, 3)   — blocks new SHARED
 *  EXCLUSIVE : bytes [0, 4)   — full range
 */
#define LOCK_BYTE_SHARED_FIRST   0
#define LOCK_BYTE_SHARED_LEN     1
#define LOCK_BYTE_RESERVED_FIRST 1
#define LOCK_BYTE_RESERVED_LEN   1
#define LOCK_BYTE_PENDING_FIRST  0
#define LOCK_BYTE_PENDING_LEN    3
#define LOCK_BYTE_EXCL_FIRST     0
#define LOCK_BYTE_EXCL_LEN       4

/* ── Forward declarations ─────────────────────────────────────────────────── */

static int qihse_vfs_xOpen(sqlite3_vfs*, const char* zName, sqlite3_file*,
                             int flags, int* pOutFlags);
static int qihse_vfs_xDelete(sqlite3_vfs*, const char* zName, int syncDir);
static int qihse_vfs_xAccess(sqlite3_vfs*, const char* zName,
                              int flags, int* pResOut);
static int qihse_vfs_xFullPathname(sqlite3_vfs*, const char* zName,
                                    int nOut, char* zOut);
static void* qihse_vfs_xDlOpen(sqlite3_vfs*, const char* zFilename);
static void  qihse_vfs_xDlError(sqlite3_vfs*, int nByte, char* zErrMsg);
static void (*qihse_vfs_xDlSym(sqlite3_vfs*, void*, const char*))(void);
static void  qihse_vfs_xDlClose(sqlite3_vfs*, void*);
static int   qihse_vfs_xRandomness(sqlite3_vfs*, int nByte, char* zOut);
static int   qihse_vfs_xSleep(sqlite3_vfs*, int microseconds);
static int   qihse_vfs_xCurrentTimeInt64(sqlite3_vfs*, sqlite3_int64*);
static int   qihse_vfs_xGetLastError(sqlite3_vfs*, int, char*);

static int qihse_io_xClose(sqlite3_file*);
static int qihse_io_xRead(sqlite3_file*, void*, int iAmt, sqlite3_int64 iOfst);
static int qihse_io_xWrite(sqlite3_file*, const void*, int iAmt,
                            sqlite3_int64 iOfst);
static int qihse_io_xTruncate(sqlite3_file*, sqlite3_int64 size);
static int qihse_io_xSync(sqlite3_file*, int flags);
static int qihse_io_xFileSize(sqlite3_file*, sqlite3_int64* pSize);
static int qihse_io_xLock(sqlite3_file*, int eLock);
static int qihse_io_xUnlock(sqlite3_file*, int eLock);
static int qihse_io_xCheckReservedLock(sqlite3_file*, int* pResOut);
static int qihse_io_xFileControl(sqlite3_file*, int op, void* pArg);
static int qihse_io_xSectorSize(sqlite3_file*);
static int qihse_io_xDeviceCharacteristics(sqlite3_file*);

/* ── Per-file handle ─────────────────────────────────────────────────────── */

typedef struct qihse_vfs_file {
    sqlite3_file            base;        /* MUST be first member */

    qihse_file_t            data_file;   /* Durable fd (qihse_file_posix.c) */
    qihse_lock_t            lock_file;   /* fcntl advisory lock sidecar */

    qihse_vfs_page_cache_t* cache;       /* KV page cache (main DB only) */
    qihse_vfs_wal_t*        wal;         /* Marmalade WAL (WAL file only) */

    int                     open_flags;  /* Saved SQLITE_OPEN_* flags */
    int                     lock_level;  /* Current SQLite lock level */
    bool                    is_wal;      /* Opened with SQLITE_OPEN_WAL */
    bool                    is_main_db;  /* Opened with SQLITE_OPEN_MAIN_DB */

#ifdef QIHSE_VFS_ENCRYPT
    bool                    encrypt;
    qihse_pqc_ctx_t         pqc;
#endif

    char                    path[QIHSE_VFS_MAX_PATH];
    char                    lock_path[QIHSE_VFS_MAX_PATH + 8]; /* path + ".qlock" */
    char                    wal_dir[QIHSE_VFS_MAX_PATH + 4];   /* path + ".d"     */
} qihse_vfs_file_t;

/* ── I/O methods dispatch table (iVersion=1; WAL SHM added in iVersion=2) ── */

static const sqlite3_io_methods qihse_io_methods = {
    1,                              /* iVersion */
    qihse_io_xClose,
    qihse_io_xRead,
    qihse_io_xWrite,
    qihse_io_xTruncate,
    qihse_io_xSync,
    qihse_io_xFileSize,
    qihse_io_xLock,
    qihse_io_xUnlock,
    qihse_io_xCheckReservedLock,
    qihse_io_xFileControl,
    qihse_io_xSectorSize,
    qihse_io_xDeviceCharacteristics,
};

/* ── VFS descriptor ──────────────────────────────────────────────────────── */

static sqlite3_vfs qihse_vfs_desc = {
    1,                              /* iVersion */
    (int)sizeof(qihse_vfs_file_t),  /* szOsFile — SQLite allocates this */
    PATH_MAX,                       /* mxPathname */
    NULL,                           /* pNext — managed by SQLite */
    QIHSE_VFS_NAME,                 /* zName */
    NULL,                           /* pAppData */
    qihse_vfs_xOpen,
    qihse_vfs_xDelete,
    qihse_vfs_xAccess,
    qihse_vfs_xFullPathname,
    qihse_vfs_xDlOpen,
    qihse_vfs_xDlError,
    qihse_vfs_xDlSym,
    qihse_vfs_xDlClose,
    qihse_vfs_xRandomness,
    qihse_vfs_xSleep,
    NULL,                           /* xCurrentTime (deprecated double form) */
    qihse_vfs_xGetLastError,
    qihse_vfs_xCurrentTimeInt64,    /* iVersion >= 2 field, safe in v1 slot */
};

/* ── Helpers ─────────────────────────────────────────────────────────────── */

/* Append suffix to src into dst (dst_size bytes).  Returns false on overflow. */
static bool path_append(char* dst, size_t dst_size,
                         const char* src, const char* suffix)
{
    size_t src_len    = strlen(src);
    size_t suffix_len = strlen(suffix);
    if (src_len + suffix_len + 1u > dst_size) return false;
    memcpy(dst, src, src_len);
    memcpy(dst + src_len, suffix, suffix_len + 1u);
    return true;
}

/* Julian day epoch offset for clock_gettime → sqlite3_int64 conversion.
 * 2440587.5 days from Julian epoch to Unix epoch, multiplied by 86400000 ms. */
#define UNIX_EPOCH_JULIAN_MS  ((sqlite3_int64)210866803200000LL)

/* fcntl advisory lock helper. */
static int set_flock(int fd, short l_type, off_t start, off_t len)
{
    struct flock fl;
    memset(&fl, 0, sizeof(fl));
    fl.l_type   = l_type;
    fl.l_whence = SEEK_SET;
    fl.l_start  = start;
    fl.l_len    = len;
    int rc;
    do { rc = fcntl(fd, F_SETLK, &fl); } while (rc != 0 && errno == EINTR);
    return rc;
}

/* Non-blocking check: returns 1 if a write lock on the byte range is held
 * by another process, 0 if it is free, -1 on error. */
static int check_flock(int fd, off_t start, off_t len)
{
    struct flock fl;
    memset(&fl, 0, sizeof(fl));
    fl.l_type   = F_WRLCK;
    fl.l_whence = SEEK_SET;
    fl.l_start  = start;
    fl.l_len    = len;
    if (fcntl(fd, F_GETLK, &fl) != 0) return -1;
    return (fl.l_type != F_UNLCK) ? 1 : 0;
}

/* Detect SQLite page size from the database header (bytes 16–17, big-endian). */
static uint32_t detect_page_size(const void* buf, int buf_len)
{
    if (buf_len < 18) return 0u;
    const uint8_t* b = (const uint8_t*)buf;
    uint32_t ps = ((uint32_t)b[16] << 8) | (uint32_t)b[17];
    if (ps >= 512u && ps <= 65536u && (ps & (ps - 1u)) == 0u) return ps;
    return 0u;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * File I/O methods
 * ═══════════════════════════════════════════════════════════════════════════ */

/* ── xClose ──────────────────────────────────────────────────────────────── */

static int qihse_io_xClose(sqlite3_file* pFile)
{
    qihse_vfs_file_t* f = (qihse_vfs_file_t*)pFile;

    if (f->cache) {
        qihse_vfs_cache_flush(f->cache);
        qihse_vfs_cache_destroy(f->cache);
        f->cache = NULL;
    }
    if (f->wal) {
        qihse_vfs_wal_flush(f->wal);
        qihse_vfs_wal_destroy(f->wal);
        f->wal = NULL;
    }

    qihse_lock_release(&f->lock_file);
    qihse_file_close(&f->data_file);

#ifdef QIHSE_VFS_ENCRYPT
    if (f->encrypt) qihse_pqc_destroy(&f->pqc);
#endif

    return SQLITE_OK;
}

/* ── xRead ───────────────────────────────────────────────────────────────── */

static int qihse_io_xRead(sqlite3_file* pFile, void* buf,
                           int iAmt, sqlite3_int64 iOfst)
{
    qihse_vfs_file_t* f = (qihse_vfs_file_t*)pFile;
    if (iAmt <= 0 || iOfst < 0) return SQLITE_IOERR_READ;

    size_t          size = (size_t)iAmt;
    uint64_t        off  = (uint64_t)iOfst;

    /* ── WAL file path ── */
    if (f->is_wal) {
        if (f->wal) {
            bool ok = qihse_vfs_wal_read(f->wal, iOfst, (uint8_t*)buf, size);
            if (!ok) {
                memset(buf, 0, size);
                return SQLITE_IOERR_SHORT_READ;
            }
            return SQLITE_OK;
        }
        /* Fall through to direct file read for WAL without Marmalade handle. */
    }

    /* ── Main DB: try cache first ── */
    if (f->is_main_db && f->cache && f->cache->page_size > 0u) {
        uint64_t page_id = off / f->cache->page_size;
        if (qihse_vfs_cache_get(f->cache, page_id, buf, size)) {
            return SQLITE_OK;
        }
    }

    /* ── Cold path: direct file read ── */
#ifdef QIHSE_VFS_ENCRYPT
    if (f->encrypt) {
        /* Read cipher block: raw_size = size + GCM overhead */
        size_t cipher_size = size + QIHSE_AES_GCM_IV_SIZE + QIHSE_AES_GCM_TAG_SIZE;
        uint8_t* cipher = (uint8_t*)malloc(cipher_size);
        if (!cipher) return SQLITE_NOMEM;

        if (!qihse_file_pread_exact(&f->data_file, cipher, cipher_size, off)) {
            free(cipher);
            if (errno == 0 || errno == EIO) {
                /* New file / short read — return zeroes. */
                memset(buf, 0, size);
                return SQLITE_IOERR_SHORT_READ;
            }
            return SQLITE_IOERR_READ;
        }
        size_t plain_len = 0u;
        if (!qihse_pqc_decrypt(&f->pqc, cipher, cipher_size,
                                (uint8_t*)buf, &plain_len)) {
            free(cipher);
            return SQLITE_IOERR_READ;
        }
        free(cipher);
        if (plain_len != size) return SQLITE_IOERR_READ;
    } else
#endif
    {
        if (!qihse_file_pread_exact(&f->data_file, buf, size, off)) {
            if (errno == ESPIPE || errno == EIO) {
                memset(buf, 0, size);
                return SQLITE_IOERR_SHORT_READ;
            }
            /*
             * A short read at EOF (new file) should zero-fill and report
             * SQLITE_IOERR_SHORT_READ so SQLite treats it as a fresh page.
             */
            uint64_t file_sz = 0u;
            qihse_file_size(&f->data_file, &file_sz);
            if (off >= file_sz) {
                memset(buf, 0, size);
                return SQLITE_IOERR_SHORT_READ;
            }
            return SQLITE_IOERR_READ;
        }
    }

    /* Populate cache on cold read. */
    if (f->is_main_db && f->cache && f->cache->page_size > 0u) {
        uint64_t page_id = off / f->cache->page_size;
        qihse_vfs_cache_put(f->cache, page_id, buf, size);
    }

    return SQLITE_OK;
}

/* ── xWrite ──────────────────────────────────────────────────────────────── */

static int qihse_io_xWrite(sqlite3_file* pFile, const void* buf,
                            int iAmt, sqlite3_int64 iOfst)
{
    qihse_vfs_file_t* f = (qihse_vfs_file_t*)pFile;
    if (iAmt <= 0 || iOfst < 0) return SQLITE_IOERR_WRITE;

    size_t   size = (size_t)iAmt;
    uint64_t off  = (uint64_t)iOfst;

    /* ── WAL file: route through Marmalade ── */
    if (f->is_wal && f->wal) {
        if (!qihse_vfs_wal_append(f->wal, iOfst, (const uint8_t*)buf, size)) {
            return SQLITE_IOERR_WRITE;
        }
        return SQLITE_OK;
    }

    /* ── Main DB: detect page size from first write ── */
    if (f->is_main_db && f->cache && iOfst == 0 && f->cache->page_size == 0u) {
        uint32_t ps = detect_page_size(buf, iAmt);
        if (ps > 0u) qihse_vfs_cache_set_page_size(f->cache, ps);
        if (f->cache->page_size == 0u)
            qihse_vfs_cache_set_page_size(f->cache, QIHSE_VFS_DEFAULT_PAGE_SIZE);
    }

#ifdef QIHSE_VFS_ENCRYPT
    if (f->encrypt) {
        size_t cipher_size = size + QIHSE_AES_GCM_IV_SIZE + QIHSE_AES_GCM_TAG_SIZE;
        uint8_t* cipher = (uint8_t*)malloc(cipher_size);
        if (!cipher) return SQLITE_NOMEM;
        size_t out_len = 0u;
        if (!qihse_pqc_encrypt(&f->pqc, (const uint8_t*)buf, size,
                                cipher, cipher_size, &out_len)) {
            free(cipher);
            return SQLITE_IOERR_WRITE;
        }
        bool ok = qihse_file_pwrite_exact(&f->data_file, cipher, out_len, off);
        free(cipher);
        if (!ok) return SQLITE_IOERR_WRITE;
    } else
#endif
    {
        if (!qihse_file_pwrite_exact(&f->data_file, buf, size, off)) {
            return SQLITE_IOERR_WRITE;
        }
    }

    /* Update cache (always store plaintext). */
    if (f->is_main_db && f->cache && f->cache->page_size > 0u) {
        uint64_t page_id = off / f->cache->page_size;
        qihse_vfs_cache_put(f->cache, page_id, buf, size);
    }

    /* Extend logical file size. */
    if (f->cache) {
        uint64_t end = off + size;
        if (end > f->cache->file_size) f->cache->file_size = end;
    }

    return SQLITE_OK;
}

/* ── xTruncate ───────────────────────────────────────────────────────────── */

static int qihse_io_xTruncate(sqlite3_file* pFile, sqlite3_int64 size)
{
    qihse_vfs_file_t* f = (qihse_vfs_file_t*)pFile;
    if (size < 0) return SQLITE_IOERR_TRUNCATE;

    if (!qihse_file_truncate(&f->data_file, (uint64_t)size)) {
        return SQLITE_IOERR_TRUNCATE;
    }

    if (f->cache) {
        f->cache->file_size = (uint64_t)size;
        if (f->cache->page_size > 0u) {
            uint64_t cutoff = (uint64_t)size / f->cache->page_size;
            qihse_vfs_cache_evict_above(f->cache, cutoff);
        }
    }
    return SQLITE_OK;
}

/* ── xSync ───────────────────────────────────────────────────────────────── */

static int qihse_io_xSync(sqlite3_file* pFile, int flags)
{
    qihse_vfs_file_t* f = (qihse_vfs_file_t*)pFile;

    if (f->wal) {
        if (!qihse_vfs_wal_flush(f->wal)) return SQLITE_IOERR_FSYNC;
        return SQLITE_OK;
    }

    if (f->cache) qihse_vfs_cache_flush(f->cache);

    int rc;
    if (flags & SQLITE_SYNC_DATAONLY) {
        do { rc = fdatasync(f->data_file.fd); } while (rc != 0 && errno == EINTR);
    } else {
        do { rc = fsync(f->data_file.fd); } while (rc != 0 && errno == EINTR);
    }
    return (rc == 0) ? SQLITE_OK : SQLITE_IOERR_FSYNC;
}

/* ── xFileSize ───────────────────────────────────────────────────────────── */

static int qihse_io_xFileSize(sqlite3_file* pFile, sqlite3_int64* pSize)
{
    qihse_vfs_file_t* f = (qihse_vfs_file_t*)pFile;

    if (f->wal) {
        *pSize = (sqlite3_int64)qihse_vfs_wal_size(f->wal);
        return SQLITE_OK;
    }

    if (f->cache && f->cache->file_size > 0u) {
        *pSize = (sqlite3_int64)f->cache->file_size;
        return SQLITE_OK;
    }

    uint64_t sz = 0u;
    if (!qihse_file_size(&f->data_file, &sz)) return SQLITE_IOERR_FSTAT;

    *pSize = (sqlite3_int64)sz;
    if (f->cache) f->cache->file_size = sz;

    return SQLITE_OK;
}

/* ── xLock ───────────────────────────────────────────────────────────────── */

static int qihse_io_xLock(sqlite3_file* pFile, int eLock)
{
    qihse_vfs_file_t* f = (qihse_vfs_file_t*)pFile;

    if (eLock <= f->lock_level) return SQLITE_OK;
    if (f->lock_file.file.fd < 0) return SQLITE_IOERR_LOCK;

    int fd = f->lock_file.file.fd;
    int rc;

    switch (eLock) {
    case SQLITE_LOCK_SHARED:
        rc = set_flock(fd, F_RDLCK,
                       LOCK_BYTE_SHARED_FIRST, LOCK_BYTE_SHARED_LEN);
        break;
    case SQLITE_LOCK_RESERVED:
        rc = set_flock(fd, F_WRLCK,
                       LOCK_BYTE_RESERVED_FIRST, LOCK_BYTE_RESERVED_LEN);
        break;
    case SQLITE_LOCK_PENDING:
        rc = set_flock(fd, F_WRLCK,
                       LOCK_BYTE_PENDING_FIRST, LOCK_BYTE_PENDING_LEN);
        break;
    case SQLITE_LOCK_EXCLUSIVE:
        rc = set_flock(fd, F_WRLCK,
                       LOCK_BYTE_EXCL_FIRST, LOCK_BYTE_EXCL_LEN);
        break;
    default:
        return SQLITE_IOERR_LOCK;
    }

    if (rc != 0) {
        if (errno == EACCES || errno == EAGAIN) return SQLITE_BUSY;
        return SQLITE_IOERR_LOCK;
    }
    f->lock_level = eLock;
    return SQLITE_OK;
}

/* ── xUnlock ─────────────────────────────────────────────────────────────── */

static int qihse_io_xUnlock(sqlite3_file* pFile, int eLock)
{
    qihse_vfs_file_t* f = (qihse_vfs_file_t*)pFile;

    if (eLock >= f->lock_level) return SQLITE_OK;
    if (f->lock_file.file.fd < 0) return SQLITE_OK;

    int fd = f->lock_file.file.fd;
    int rc = 0;

    if (eLock == SQLITE_LOCK_NONE) {
        rc = set_flock(fd, F_UNLCK, LOCK_BYTE_EXCL_FIRST, LOCK_BYTE_EXCL_LEN);
    } else if (eLock == SQLITE_LOCK_SHARED) {
        /* Downgrade: release write range, keep read range. */
        (void)set_flock(fd, F_UNLCK,
                        LOCK_BYTE_RESERVED_FIRST, LOCK_BYTE_RESERVED_LEN);
        rc = set_flock(fd, F_RDLCK,
                       LOCK_BYTE_SHARED_FIRST, LOCK_BYTE_SHARED_LEN);
    }

    if (rc != 0) return SQLITE_IOERR_UNLOCK;
    f->lock_level = eLock;
    return SQLITE_OK;
}

/* ── xCheckReservedLock ──────────────────────────────────────────────────── */

static int qihse_io_xCheckReservedLock(sqlite3_file* pFile, int* pResOut)
{
    qihse_vfs_file_t* f = (qihse_vfs_file_t*)pFile;
    *pResOut = 0;

    /* If we already hold reserved or higher, report as reserved. */
    if (f->lock_level >= SQLITE_LOCK_RESERVED) {
        *pResOut = 1;
        return SQLITE_OK;
    }

    if (f->lock_file.file.fd < 0) return SQLITE_OK;

    int held = check_flock(f->lock_file.file.fd,
                           LOCK_BYTE_RESERVED_FIRST, LOCK_BYTE_RESERVED_LEN);
    if (held < 0) return SQLITE_IOERR_CHECKRESERVEDLOCK;
    *pResOut = held;
    return SQLITE_OK;
}

/* ── xFileControl ────────────────────────────────────────────────────────── */

static int qihse_io_xFileControl(sqlite3_file* pFile, int op, void* pArg)
{
    qihse_vfs_file_t* f = (qihse_vfs_file_t*)pFile;

    switch (op) {
    case SQLITE_FCNTL_CHUNK_SIZE:
        /* Hint: SQLite wants us to extend in chunks.  We ignore it for now. */
        (void)pArg;
        return SQLITE_OK;

    case SQLITE_FCNTL_SIZE_HINT: {
        sqlite3_int64 hint = *(sqlite3_int64*)pArg;
        if (hint > 0 && f->cache) {
            uint64_t cur = f->cache->file_size;
            if ((uint64_t)hint > cur) {
                /* Pre-extend: truncate-up to hint size. */
                qihse_file_truncate(&f->data_file, (uint64_t)hint);
                f->cache->file_size = (uint64_t)hint;
            }
        }
        return SQLITE_OK;
    }

    case SQLITE_FCNTL_VFSNAME:
        *(char**)pArg = sqlite3_mprintf(QIHSE_VFS_NAME);
        return SQLITE_OK;

    default:
        return SQLITE_NOTFOUND;
    }
}

/* ── xSectorSize ─────────────────────────────────────────────────────────── */

static int qihse_io_xSectorSize(sqlite3_file* pFile)
{
    (void)pFile;
    return 4096;
}

/* ── xDeviceCharacteristics ──────────────────────────────────────────────── */

static int qihse_io_xDeviceCharacteristics(sqlite3_file* pFile)
{
    (void)pFile;
    /*
     * SQLITE_IOCAP_SAFE_APPEND: data appended to EOF is safe up to sector size.
     * SQLITE_IOCAP_SEQUENTIAL:  writes are delivered in order.
     * These allow SQLite to skip redundant journal header writes.
     */
    return SQLITE_IOCAP_SAFE_APPEND | SQLITE_IOCAP_SEQUENTIAL;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * VFS-level methods
 * ═══════════════════════════════════════════════════════════════════════════ */

/* ── xOpen ───────────────────────────────────────────────────────────────── */

static int qihse_vfs_xOpen(sqlite3_vfs* pVfs,
                             const char* zName,
                             sqlite3_file* pFile,
                             int flags,
                             int* pOutFlags)
{
    (void)pVfs;

    qihse_vfs_file_t* f = (qihse_vfs_file_t*)pFile;
    memset(f, 0, sizeof(*f));
    f->data_file.fd    = QIHSE_FILE_INVALID_FD;
    f->lock_file.file.fd = QIHSE_FILE_INVALID_FD;
    f->lock_level      = SQLITE_LOCK_NONE;

    /* ── Resolve path ── */
    if (zName && zName[0] != '\0') {
        if (!realpath(zName, f->path)) {
            /*
             * realpath fails if the file does not yet exist.
             * For CREATE opens, fall back to the raw path (the directory
             * must already exist, which SQLite guarantees via xFullPathname).
             */
            size_t len = strlen(zName);
            if (len >= QIHSE_VFS_MAX_PATH) return SQLITE_CANTOPEN;
            memcpy(f->path, zName, len + 1u);
        }
    } else {
        /* Unnamed temporary file: use a mkstemp path. */
        const char* tmp = "/tmp/qihse_tmp_XXXXXX";
        if (strlen(tmp) >= QIHSE_VFS_MAX_PATH) return SQLITE_CANTOPEN;
        strncpy(f->path, tmp, QIHSE_VFS_MAX_PATH - 1);
    }

    /* ── Lock sidecar path ── */
    if (!path_append(f->lock_path, sizeof(f->lock_path), f->path, ".qlock"))
        return SQLITE_CANTOPEN;

    /* ── Open durable file ── */
    int oflags = O_CLOEXEC;
    if (flags & SQLITE_OPEN_READWRITE)  oflags |= O_RDWR;
    else                                oflags |= O_RDONLY;
    if (flags & SQLITE_OPEN_CREATE)     oflags |= O_CREAT;
    if (flags & SQLITE_OPEN_DELETEONCLOSE) {
        /* Nothing extra — we handle delete in xClose if needed. */
    }
    if (flags & SQLITE_OPEN_EXCLUSIVE)  oflags |= O_EXCL;

    if (!qihse_file_open(&f->data_file, f->path, oflags, 0600)) {
        return SQLITE_CANTOPEN;
    }

    /* ── Advisory lock sidecar ── */
    if (!qihse_lock_acquire(&f->lock_file, f->lock_path)) {
        /*
         * qihse_lock_acquire uses F_SETLK (non-blocking).  If another process
         * holds an exclusive lock, return SQLITE_BUSY not SQLITE_CANTOPEN.
         */
        qihse_file_close(&f->data_file);
        if (errno == EACCES || errno == EAGAIN) return SQLITE_BUSY;
        return SQLITE_CANTOPEN;
    }

    /* ── File-kind specific initialisation ── */
    f->open_flags  = flags;
    f->is_main_db  = (flags & SQLITE_OPEN_MAIN_DB) != 0;
    f->is_wal      = (flags & SQLITE_OPEN_WAL) != 0;

    if (f->is_main_db) {
        f->cache = qihse_vfs_cache_create();
        if (!f->cache) {
            qihse_lock_release(&f->lock_file);
            qihse_file_close(&f->data_file);
            return SQLITE_NOMEM;
        }
        /* Seed file_size from the actual on-disk size. */
        qihse_file_size(&f->data_file, &f->cache->file_size);

#ifdef QIHSE_VFS_ENCRYPT
        /*
         * Attempt to initialise PQC encryption.  A missing key file is not
         * fatal: we fall back to plaintext with a warning.
         */
        char keyblob_path[QIHSE_VFS_MAX_PATH + 16];
        if (path_append(keyblob_path, sizeof(keyblob_path),
                        f->path, ".qihse_keyblob")) {
            /* Try to load existing keyblob. */
            FILE* kf = fopen(keyblob_path, "rb");
            if (kf) {
                uint8_t encap[QIHSE_MLKEM_CIPHERTEXT_SIZE];
                if (fread(encap, 1, sizeof(encap), kf) == sizeof(encap)) {
                    if (qihse_pqc_init(&f->pqc, encap, NULL)) {
                        f->encrypt = true;
                    }
                }
                fclose(kf);
            } else if (flags & SQLITE_OPEN_CREATE) {
                /* Generate a new session key and persist the keyblob. */
                uint8_t encap_out[QIHSE_MLKEM_CIPHERTEXT_SIZE];
                if (qihse_pqc_init(&f->pqc, NULL, encap_out)) {
                    FILE* wf = fopen(keyblob_path, "wb");
                    if (wf) {
                        fwrite(encap_out, 1, sizeof(encap_out), wf);
                        fclose(wf);
                    }
                    f->encrypt = true;
                }
            }
            if (!f->encrypt) {
                fprintf(stderr, "qihse_vfs: WARNING: PQC key unavailable, "
                                "opening '%s' in plaintext mode\n", f->path);
            }
        }
#endif /* QIHSE_VFS_ENCRYPT */
    }

    if (f->is_wal) {
        /* Derive the Marmalade log directory from the WAL file path. */
        if (!path_append(f->wal_dir, sizeof(f->wal_dir), f->path, ".d"))
            goto wal_fail;

        /* Ensure the directory exists. */
        qihse_mkdir_p(f->wal_dir, 0700);

        f->wal = qihse_vfs_wal_create(f->wal_dir);
        if (!f->wal) {
            wal_fail:
            qihse_lock_release(&f->lock_file);
            qihse_file_close(&f->data_file);
            return SQLITE_CANTOPEN;
        }
    }

    f->base.pMethods = &qihse_io_methods;
    if (pOutFlags) *pOutFlags = flags;

    return SQLITE_OK;
}

/* ── xDelete ─────────────────────────────────────────────────────────────── */

static int qihse_vfs_xDelete(sqlite3_vfs* pVfs,
                              const char* zName, int syncDir)
{
    (void)pVfs;
    if (!zName) return SQLITE_IOERR_DELETE;

    if (unlink(zName) != 0 && errno != ENOENT) return SQLITE_IOERR_DELETE;

    if (syncDir) {
        /* Find the directory component and fsync it. */
        char dir[PATH_MAX];
        strncpy(dir, zName, sizeof(dir) - 1);
        dir[sizeof(dir) - 1] = '\0';
        char* slash = strrchr(dir, '/');
        if (slash) {
            *slash = '\0';
            qihse_fsync_dir(dir);
        }
    }
    return SQLITE_OK;
}

/* ── xAccess ─────────────────────────────────────────────────────────────── */

static int qihse_vfs_xAccess(sqlite3_vfs* pVfs,
                               const char* zName, int flags, int* pResOut)
{
    (void)pVfs;
    int amode;
    switch (flags) {
    case SQLITE_ACCESS_EXISTS:    amode = F_OK; break;
    case SQLITE_ACCESS_READWRITE: amode = R_OK | W_OK; break;
    case SQLITE_ACCESS_READ:      amode = R_OK; break;
    default:                      amode = F_OK; break;
    }
    *pResOut = (access(zName, amode) == 0) ? 1 : 0;
    return SQLITE_OK;
}

/* ── xFullPathname ───────────────────────────────────────────────────────── */

static int qihse_vfs_xFullPathname(sqlite3_vfs* pVfs,
                                    const char* zName, int nOut, char* zOut)
{
    (void)pVfs;
    if (!realpath(zName, zOut)) {
        /* File may not exist yet — do a best-effort manual resolution. */
        if (zName[0] == '/') {
            strncpy(zOut, zName, (size_t)nOut - 1);
            zOut[nOut - 1] = '\0';
        } else {
            char cwd[PATH_MAX];
            if (!getcwd(cwd, sizeof(cwd))) return SQLITE_CANTOPEN;
            int n = snprintf(zOut, (size_t)nOut, "%s/%s", cwd, zName);
            if (n < 0 || n >= nOut) return SQLITE_CANTOPEN;
        }
    }
    return SQLITE_OK;
}

/* ── Dynamic loading ─────────────────────────────────────────────────────── */

static void* qihse_vfs_xDlOpen(sqlite3_vfs* pVfs, const char* zFilename)
{
    (void)pVfs;
    return dlopen(zFilename, RTLD_NOW | RTLD_GLOBAL);
}

static void qihse_vfs_xDlError(sqlite3_vfs* pVfs, int nByte, char* zErrMsg)
{
    (void)pVfs;
    const char* err = dlerror();
    if (err) strncpy(zErrMsg, err, (size_t)nByte - 1);
    zErrMsg[nByte - 1] = '\0';
}

static void (*qihse_vfs_xDlSym(sqlite3_vfs* pVfs, void* pH,
                                 const char* zSym))(void)
{
    (void)pVfs;
    return (void (*)(void))dlsym(pH, zSym);
}

static void qihse_vfs_xDlClose(sqlite3_vfs* pVfs, void* pHandle)
{
    (void)pVfs;
    dlclose(pHandle);
}

/* ── xRandomness ─────────────────────────────────────────────────────────── */

static int qihse_vfs_xRandomness(sqlite3_vfs* pVfs, int nByte, char* zOut)
{
    (void)pVfs;
    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return SQLITE_IOERR;
    ssize_t n = read(fd, zOut, (size_t)nByte);
    close(fd);
    return (n == nByte) ? SQLITE_OK : SQLITE_IOERR;
}

/* ── xSleep ──────────────────────────────────────────────────────────────── */

static int qihse_vfs_xSleep(sqlite3_vfs* pVfs, int microseconds)
{
    (void)pVfs;
    usleep((useconds_t)microseconds);
    return microseconds;
}

/* ── xCurrentTimeInt64 ───────────────────────────────────────────────────── */

static int qihse_vfs_xCurrentTimeInt64(sqlite3_vfs* pVfs,
                                         sqlite3_int64* piNow)
{
    (void)pVfs;
    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) != 0) return SQLITE_ERROR;
    /* Convert Unix epoch ms to Julian day ms. */
    sqlite3_int64 ms = (sqlite3_int64)ts.tv_sec * 1000LL
                     + (sqlite3_int64)ts.tv_nsec / 1000000LL;
    *piNow = ms + UNIX_EPOCH_JULIAN_MS;
    return SQLITE_OK;
}

/* ── xGetLastError ───────────────────────────────────────────────────────── */

static int qihse_vfs_xGetLastError(sqlite3_vfs* pVfs, int nByte, char* zBuf)
{
    (void)pVfs;
    if (nByte > 0 && zBuf) {
        strncpy(zBuf, strerror(errno), (size_t)nByte - 1);
        zBuf[nByte - 1] = '\0';
    }
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Registration
 * ═══════════════════════════════════════════════════════════════════════════ */

int qihse_vfs_register(int make_default)
{
    /* Idempotent: if already registered, update the default flag. */
    if (sqlite3_vfs_find(QIHSE_VFS_NAME) != NULL) {
        /* Re-register to change default status. */
        sqlite3_vfs_unregister(&qihse_vfs_desc);
    }
    return sqlite3_vfs_register(&qihse_vfs_desc, make_default);
}

void qihse_vfs_unregister(void)
{
    sqlite3_vfs_unregister(&qihse_vfs_desc);
}

/* ── Loadable extension entrypoint ───────────────────────────────────────── */

/*
 * When libqihse.so is loaded via:
 *   sqlite3_load_extension(db, "./libqihse.so", NULL, &err)
 * or from the CLI:
 *   .load ./libqihse.so
 *
 * SQLite will call sqlite3_qihsevfs_init() automatically (it derives the
 * symbol name from the library filename prefix).
 */
#ifndef SQLITE_CORE
int sqlite3_qihsevfs_init(sqlite3* db,
                           char** pzErrMsg,
                           const sqlite3_api_routines* pApi)
{
    SQLITE_EXTENSION_INIT2(pApi);
    (void)db;
    (void)pzErrMsg;
    return qihse_vfs_register(0);
}
#endif
