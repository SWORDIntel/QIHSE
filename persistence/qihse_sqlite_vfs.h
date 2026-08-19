/*
 * qihse_sqlite_vfs.h — QIHSE-backed SQLite Virtual File System
 * =============================================================
 *
 * Provides a sqlite3_vfs implementation backed entirely by QIHSE primitives:
 *
 *   Durable I/O   : qihse_file_t  (persistence/qihse_file_posix.c)
 *   Page cache    : qihse_kv_store_t  (src/black_hole/qihse_kv_store.c)
 *   WAL frames    : qihse_event_stream_t  (src/marmalade/qihse_event_stream.c)
 *   File locking  : qihse_lock_t  (persistence/qihse_file_posix.c)
 *   Encryption    : qihse_pqc_ctx_t  (persistence/qihse_pqc_crypto.c) [opt]
 *
 * Usage
 * -----
 *   Call qihse_vfs_register(0) once at startup to make the VFS available.
 *   Open a database via URI:  "file:foo.db?vfs=qihse"
 *
 *   Call qihse_vfs_register(1) to replace the default VFS so that all
 *   sqlite3_open("foo.db") calls use QIHSE storage transparently.
 *
 * Compile-time options
 * --------------------
 *   -DQIHSE_VFS_ENCRYPT=1   Enable transparent AES-256-GCM page encryption
 *                            via ML-KEM-1024 key encapsulation.  Key material
 *                            is read from /etc/qihse/keys/ (or the path set in
 *                            qihse_pqc_crypto.h).  If keys are absent the VFS
 *                            opens in plaintext mode with a warning.
 *
 * Thread-safety
 * -------------
 *   SQLite serialises all calls to a single database-file handle, so no
 *   internal mutex is required.  KV-store and event-stream handles are
 *   created per open file and never shared.
 *
 * Standards
 * ---------
 *   C99.  Depends on POSIX.1-2008 for pread/pwrite/fcntl/realpath.
 *   Windows is supported via qihse_platform.h stubs.
 */

#ifndef QIHSE_SQLITE_VFS_H
#define QIHSE_SQLITE_VFS_H

#ifdef __cplusplus
extern "C" {
#endif

/* The name used in the URI parameter:  file:foo.db?vfs=qihse */
#define QIHSE_VFS_NAME  "qihse"

/* Default page size assumed before SQLite writes the database header. */
#define QIHSE_VFS_DEFAULT_PAGE_SIZE  4096u

/*
 * qihse_vfs_register — register the QIHSE VFS with SQLite.
 *
 * make_default  0 → available but not the default; use URI parameter.
 *               1 → replaces the built-in "unix" VFS as the default.
 *
 * Returns SQLITE_OK on success, or an SQLITE_* error code.
 * Safe to call more than once; re-registration is a no-op.
 */
int qihse_vfs_register(int make_default);

/*
 * qihse_vfs_unregister — remove the QIHSE VFS from SQLite's registry.
 *
 * Safe to call even if the VFS was never registered.
 * Any databases already open through this VFS continue to work until closed.
 */
void qihse_vfs_unregister(void);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* QIHSE_SQLITE_VFS_H */
