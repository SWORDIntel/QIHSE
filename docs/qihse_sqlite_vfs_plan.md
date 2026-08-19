# QIHSE SQLite VFS — Native C Implementation Plan

> **Scope**: A production-quality, generalized SQLite Virtual File System implemented in C99 using only existing QIHSE primitives. Once registered, any program that uses SQLite — whether through `sqlite3.h`, the Python `sqlite3` module, ORMs, or the `sqlite3` CLI — routes all storage through QIHSE automatically, with zero changes to SQL code.

---

## 1. What SQLite Needs from a VFS

SQLite's portable I/O abstraction is defined by two C structures:

```
sqlite3_vfs        — file-system level:  open, delete, access, sleep, randomness
sqlite3_file       — open-file level:    read, write, sync, lock, file-size, truncate
sqlite3_io_methods — dispatch table embedded in sqlite3_file
```

Every SQLite database open resolves to exactly one VFS. SQLite then manages all of its internal state — B-trees, freelist pages, journals, WAL frames — through page-level I/O calls into that VFS. The VFS does not need to understand SQL.

A standard SQLite open sequence looks like:

```
sqlite3_open() → vfs.xOpen(path, SQLITE_OPEN_MAIN_DB)
               → vfs.xOpen(path-wal, SQLITE_OPEN_WAL)
               → vfs.xOpen(path-shm, SQLITE_OPEN_MAIN_JOURNAL)
```

All three file kinds pass through the same VFS.

---

## 2. QIHSE Primitives and Their VFS Roles

| SQLite concern | QIHSE primitive | Notes |
|---|---|---|
| **Durable block read/write** | `qihse_file_t` + `qihse_file_pread_exact` / `qihse_file_pwrite_exact` | Already cross-platform, handles EINTR retry, overflow checks |
| **Dirty page write-back cache** | `qihse_kv_store_t` (Black Hole) | Key = 8-byte page ID (little-endian), value = raw 4096-byte page |
| **WAL frame log** | `qihse_event_stream_t` (Marmalade) | Each WAL frame → one append-only SHA-384-identified record |
| **Crash recovery** | `qihse_event_stream_replay()` | Marmalade already handles torn-tail truncation |
| **File locking** | `qihse_lock_t` | `fcntl(F_SETLK)` POSIX exclusive lock per file |
| **Directory fsync** | `qihse_fsync_dir()` | Already implemented in `persistence/qihse_file_posix.c` |
| **Atomic rename** | `qihse_rename_file()` | Already implemented |
| **Path construction** | `qihse_path_join()` | Already implemented |
| **Transparent encryption** | `qihse_pqc_ctx_t` + `qihse_pqc_encrypt/decrypt` | AES-256-GCM applied at page I/O boundary; optional at compile time |
| **Randomness** | `/dev/urandom` | Small wrapper, 32 bytes is enough for SQLite |
| **Current time** | `clock_gettime(CLOCK_REALTIME)` | Exposed as `xCurrentTimeInt64` |

---

## 3. File Decomposition

```
QIHSE/persistence/
├── qihse_sqlite_vfs.h          — Public header: qihse_vfs_register() + QIHSE_VFS_NAME macro
├── qihse_sqlite_vfs.c          — Core VFS: sqlite3_vfs + sqlite3_file + sqlite3_io_methods
├── qihse_vfs_page_cache.h      — Internal: page-cache API over qihse_kv_store
├── qihse_vfs_page_cache.c      — KV-backed page cache: get/put/evict/flush
├── qihse_vfs_wal.h             — Internal: WAL-routing API over qihse_event_stream
└── qihse_vfs_wal.c             — Event-stream WAL: append frame / read frame / recover
```

`qihse_sqlite_vfs.c` is the only file that includes `sqlite3ext.h`. The page-cache and WAL modules include only QIHSE headers.

---

## 4. Data Structures

### 4.1 `qihse_vfs_file_t` — the per-open-file handle

```c
/*
 * Embedded at the front of every sqlite3_file allocated by xOpen().
 * SQLite allocates sizeof(qihse_vfs_file_t) bytes — set in sqlite3_vfs.szOsFile.
 */
typedef struct qihse_vfs_file {
    sqlite3_file          base;        /* MUST be first — SQLite casts the pointer */

    qihse_file_t          data_file;   /* Durable fd wrapper (qihse_file_posix.c) */
    qihse_lock_t          lock_file;   /* fcntl advisory lock (.qlock sidecar) */

    qihse_vfs_page_cache_t* cache;     /* Black Hole KV page cache (main db only) */
    qihse_vfs_wal_t*        wal;       /* Marmalade WAL handle (WAL file only) */

    int                   open_flags;  /* Saved SQLITE_OPEN_* flags */
    int                   lock_level;  /* Current SQLite lock level (SHARED…EXCLUSIVE) */
    bool                  is_wal_file; /* True when opened with SQLITE_OPEN_WAL */
    bool                  encrypt;     /* True when PQC encryption is active */
    qihse_pqc_ctx_t       pqc;        /* Per-file AES-256-GCM session key */

    char                  path[512];   /* Resolved absolute path */
} qihse_vfs_file_t;
```

### 4.2 `qihse_vfs_page_cache_t`

```c
typedef struct {
    qihse_kv_store_t* kv;
    uint32_t          page_size;   /* Bytes — default 4096, set on first write */
    uint64_t          file_size;   /* Tracks logical EOF for xFileSize */
} qihse_vfs_page_cache_t;
```

Page keys are the **8-byte little-endian page number** (offset / page_size). This gives O(log n) trie lookup through the trinary trie inside the KV store.

### 4.3 `qihse_vfs_wal_t`

```c
typedef struct {
    qihse_event_stream_t* stream;
    uint64_t              read_cursor;  /* Iterator cursor for WAL replay reads */
    uint8_t*              replay_buf;   /* Reconstructed flat WAL byte array */
    size_t                replay_len;   /* Length of replay_buf */
    bool                  replayed;     /* One-shot replay done flag */
} qihse_vfs_wal_t;
```

---

## 5. Method-by-Method Implementation Plan

### 5.1 `xOpen`

**Steps**:
1. Resolve the absolute path via `realpath()` into `f->path`.
2. Determine file kind from `flags`:
   - `SQLITE_OPEN_MAIN_DB` → allocate `qihse_vfs_page_cache_t`, open KV store keyed by path.
   - `SQLITE_OPEN_WAL` → allocate `qihse_vfs_wal_t`, open event stream for this path.
   - All others → bare `qihse_file_t` only (journals, temp files).
3. Open the durable file with `qihse_file_open(&f->data_file, path, flags, 0600)`.
4. Acquire advisory lock file: `qihse_lock_acquire(&f->lock_file, path + ".qlock")`.
5. If encryption enabled: call `qihse_pqc_init(&f->pqc, ...)` to derive or load session key.
6. Set `f->base.pMethods = &qihse_io_methods`.

**Error path**: any failure frees all allocated resources and returns `SQLITE_CANTOPEN`.

---

### 5.2 `xClose`

1. Flush all dirty cache pages to `f->data_file` via `qihse_vfs_cache_flush()`.
2. Flush the event stream WAL: `qihse_event_stream_flush(f->wal->stream)`.
3. Free `f->cache` and `f->wal`.
4. `qihse_lock_release(&f->lock_file)`.
5. `qihse_file_close(&f->data_file)`.
6. `qihse_pqc_destroy(&f->pqc)` (zeroes the AES key).

---

### 5.3 `xRead`

**Main DB (cache)**:
1. Compute `page_id = iOfst / f->cache->page_size`.
2. `qihse_vfs_cache_get(f->cache, page_id, buf, iAmt)`.
3. Cache hit → return `SQLITE_OK`.
4. Cache miss → `qihse_file_pread_exact(&f->data_file, buf, iAmt, iOfst)`.
5. If encryption active: `qihse_pqc_decrypt(&f->pqc, buf, iAmt)` in-place.
6. Populate cache: `qihse_vfs_cache_put(f->cache, page_id, buf, iAmt)`.
7. If `pread` returns short (new file past EOF): zero-fill remainder, return `SQLITE_IOERR_SHORT_READ`.

**WAL**:
1. On first read: `qihse_vfs_wal_rebuild_flat(f->wal)` — builds `replay_buf` from all committed Marmalade records.
2. Subsequent reads: `memcpy(buf, f->wal->replay_buf + iOfst, iAmt)`.

---

### 5.4 `xWrite`

**Main DB (cache + durable)**:
1. Compute `page_id`.
2. If encryption: `qihse_pqc_encrypt(&f->pqc, buf, iAmt, cipher)`.
3. `qihse_file_pwrite_exact(&f->data_file, cipher_or_plain, ...)`.
4. `qihse_vfs_cache_put(f->cache, page_id, plaintext_buf, iAmt)`.
5. Update `f->cache->file_size` if write extends EOF.

**WAL**:
1. Build event ID: SHA-384(`"wal_frame"` ‖ `iOfst` (8-byte LE) ‖ `buf`).
2. Payload = `[8-byte LE iOfst][buf bytes]`.
3. `qihse_event_stream_append_record(f->wal->stream, "wal", SCHEMA_WAL_FRAME, event_id, payload, payload_len)`.
4. Set `f->wal->replayed = false` so next read triggers fresh replay.

> Duplicate event IDs are silently rejected by Marmalade's guard — correct, because SQLite never re-writes the same WAL frame with different content at the same offset without a checkpoint.

---

### 5.5 `xTruncate`

1. `qihse_file_truncate(&f->data_file, size)`.
2. `f->cache->file_size = size`.
3. `qihse_vfs_cache_evict_above(f->cache, size / f->cache->page_size)`.

---

### 5.6 `xSync`

| Flag | Action |
|---|---|
| `SQLITE_SYNC_DATAONLY` | `fdatasync(f->data_file.fd)` |
| `SQLITE_SYNC_NORMAL` | `fsync(f->data_file.fd)` |
| `SQLITE_SYNC_FULL` | `fsync(f->data_file.fd)` |
| WAL path (any) | `qihse_event_stream_flush(f->wal->stream)` |

---

### 5.7 `xFileSize`

1. If `f->cache` valid: return `f->cache->file_size`.
2. Otherwise: `qihse_file_size(&f->data_file, &sz)`.

---

### 5.8 Locking — `xLock` / `xUnlock` / `xCheckReservedLock`

SQLite's five lock levels: `UNLOCKED → SHARED → RESERVED → PENDING → EXCLUSIVE`.

Uses `fcntl(F_SETLK)` on a `.qlock` sidecar file with byte-range locks:

| Transition | Byte range | `l_type` |
|---|---|---|
| UNLOCKED → SHARED | bytes 0–1 | `F_RDLCK` |
| SHARED → RESERVED | bytes 1–2 | `F_WRLCK` |
| RESERVED → PENDING | bytes 0–2 | `F_WRLCK` (blocks new SHAREDs) |
| PENDING → EXCLUSIVE | bytes 0–4 | `F_WRLCK` |
| Any → UNLOCKED | bytes 0–4 | `F_UNLCK` |

`xCheckReservedLock`: non-blocking `F_SETLK` attempt on bytes 1–2; if `EACCES/EAGAIN` → reserved lock held.

This mirrors SQLite's own POSIX VFS exactly, so all WAL co-process semantics remain correct.

---

### 5.9 `xFileControl`

| Command | Action |
|---|---|
| `SQLITE_FCNTL_CHUNK_SIZE` | Store hint in `f->cache->page_size` if not yet set |
| `SQLITE_FCNTL_SIZE_HINT` | Pre-extend file if hint > current size |
| All others | Return `SQLITE_NOTFOUND` |

---

### 5.10 `xSectorSize` / `xDeviceCharacteristics`

- `xSectorSize`: return `4096`.
- `xDeviceCharacteristics`: return `SQLITE_IOCAP_SAFE_APPEND | SQLITE_IOCAP_SEQUENTIAL`.

`SQLITE_IOCAP_SAFE_APPEND` tells SQLite that appended data is atomic up to sector size — allows skipping some journal header writes.

---

### 5.11 VFS-level methods

| Method | Implementation |
|---|---|
| `xDelete` | `unlink(path)` + `qihse_fsync_dir(dir)` |
| `xAccess` | `access(path, F_OK / R_OK / W_OK)` mapped to `SQLITE_ACCESS_*` |
| `xFullPathname` | `realpath(zName, zOut)` with POSIX fallback |
| `xDlOpen/Sym/Close` | `dlopen / dlsym / dlclose` wrappers |
| `xRandomness` | Read from `/dev/urandom` |
| `xSleep` | `usleep(microseconds)` |
| `xCurrentTimeInt64` | `clock_gettime(CLOCK_REALTIME)` → Julian day × 86400000 |
| `xGetLastError` | `strerror(errno)` into SQLite buffer |

---

## 6. Page Cache Internal Design (`qihse_vfs_page_cache.c`)

```
qihse_vfs_cache_get(cache, page_id, out_buf, size)
    Format key[9] = "P" + page_id as 8-byte LE
    val = qihse_kv_get_user(cache->kv, key, OPERATOR_USER)
    if val: memcpy(out_buf, val, size); free(val); return HIT
    return MISS

qihse_vfs_cache_put(cache, page_id, buf, size)
    Format key[9] as above
    hex_encode(buf, size) -> hex_str    /* interim until qihse_kv_set_binary exists */
    qihse_kv_set(cache->kv, key, hex_str, 0, 0)
    free(hex_str)

qihse_vfs_cache_evict_above(cache, cutoff_id)
    /* Scan kv keys, delete any page_id >= cutoff */
    /* O(n) scan — rare, triggered only by VACUUM/TRUNCATE */

qihse_vfs_cache_flush(cache)
    /* KV WAL already guarantees persistence; mark clean */
    cache->dirty = false
```

> **Future**: A `qihse_kv_set_binary` API should be added to Black Hole so page bytes are stored raw (eliminating hex overhead). This is deferred to keep the VFS work self-contained.

---

## 7. WAL Routing Internal Design (`qihse_vfs_wal.c`)

### Write path
Each `xWrite` call on a WAL file:
1. Build event ID: SHA-384(`"wal_frame"` ‖ `iOfst` (8-byte LE) ‖ `data`).
2. Payload = `[8-byte LE iOfst][data bytes]` — the offset is embedded so frames can be replayed in any order.
3. `qihse_event_stream_append_record(wal->stream, "wal", SCHEMA_WAL_FRAME, event_id, payload, len)`.
4. `wal->replayed = false`.

### Read path
1. If `!wal->replayed`: call `qihse_vfs_wal_rebuild_flat(wal)`.
2. `memcpy(buf, wal->replay_buf + iOfst, size)`.

### Rebuild (crash recovery)
1. `qihse_event_stream_truncate_torn_tail(wal->stream, "wal")`.
2. `qihse_event_stream_replay(wal->stream, "wal", rebuild_cb, wal)`.
3. `rebuild_cb` reads the 8-byte offset prefix from each record payload, writes record data into `wal->replay_buf` at that position (extending as needed).
4. `wal->replayed = true`.

---

## 8. Transparent PQC Encryption

Controlled by `#ifdef QIHSE_VFS_ENCRYPT`. Applied **per page**, transparent to SQLite.

### Encrypt on `xWrite` (main DB only)
```
Plaintext page → qihse_pqc_encrypt → [12-byte IV][ciphertext][16-byte GCM tag]
Total on-disk overhead: +28 bytes per page
Written to disk at encrypted offset
```

### Decrypt on `xRead` (main DB only)
```
Read cipher block from disk → qihse_pqc_decrypt → plaintext → cache + return to SQLite
```

### Key derivation
- First open: `qihse_pqc_init(&f->pqc, NULL, encap_out)` — generates fresh ML-KEM-1024 ciphertext, writes to `<db_path>.qihse_keyblob`.
- Subsequent opens: reads keyblob, calls `qihse_pqc_init(&f->pqc, encap_in, NULL)` to decapsulate.
- If key files absent: open in plaintext mode with a warning log. **No silent downgrade.**

---

## 9. Page Size Discovery

SQLite writes the page size into bytes 16–17 of the database file header on the first write:

```c
if (iOfst == 0 && iAmt >= 18 && f->cache->page_size == 0) {
    uint16_t ps;
    memcpy(&ps, (const uint8_t*)buf + 16, 2);
    ps = be16toh(ps);   /* SQLite stores it big-endian */
    if (ps >= 512 && ps <= 65536 && (ps & (ps - 1)) == 0)
        f->cache->page_size = ps;
}
if (f->cache->page_size == 0)
    f->cache->page_size = 4096;   /* safe default */
```

---

## 10. Registration Patterns

### As a loadable `.so` extension
```c
int sqlite3_qihsevfs_init(sqlite3* db, char** pzErrMsg,
                           const sqlite3_api_routines* pApi)
{
    SQLITE_EXTENSION_INIT2(pApi);
    return qihse_vfs_register(0);
}
```

### As the process-wide default
```c
qihse_vfs_register(1);   /* all sqlite3_open() calls use QIHSE */
```

### Via URI (non-default)
```
file:spectra.db?vfs=qihse
```

---

## 11. Build System Changes (`Makefile`)

```makefile
SRCS_VFS = persistence/qihse_sqlite_vfs.c \
           persistence/qihse_vfs_page_cache.c \
           persistence/qihse_vfs_wal.c

SRCS_BASE += $(SRCS_VFS)

# sqlite3 dev headers required
CFLAGS += $(shell pkg-config --cflags sqlite3 2>/dev/null) -DSQLITE_CORE

# Optional page-level encryption
ifeq ($(QIHSE_VFS_ENCRYPT),1)
CFLAGS += -DQIHSE_VFS_ENCRYPT=1
endif

# Standalone loadable extension target
qihse_vfs.so: $(SRCS_VFS)
	$(CC) $(CFLAGS) -shared -fPIC -o $@ $^ \
	    $(shell pkg-config --libs sqlite3) -lssl -lcrypto

# Integration test target
test-sqlite-vfs: qihse_vfs.so tests/test_sqlite_vfs.c
	$(CC) $(CFLAGS) -o $@ tests/test_sqlite_vfs.c \
	    -L. -lqihse $(shell pkg-config --libs sqlite3) -Wl,-rpath,.
	./$@
```

---

## 12. Test Plan

| Test | What it verifies |
|---|---|
| `test_vfs_register` | `qihse_vfs_register(0)` → `SQLITE_OK`; VFS visible via `sqlite3_vfs_find("qihse")` |
| `test_basic_create_open` | Open URI, `CREATE TABLE`, close, reopen, `SELECT` — all rows present |
| `test_write_read_pages` | 10,000-row transaction; close+reopen; full readback |
| `test_wal_mode` | `PRAGMA journal_mode=WAL`; concurrent writer + reader threads |
| `test_crash_recovery` | Child writes; `SIGKILL` mid-write; parent reopens; last committed tx intact |
| `test_truncate` | `DELETE` + `VACUUM`; file shrinks; remaining rows correct |
| `test_short_read` | Read past EOF; expect `SQLITE_IOERR_SHORT_READ` or zero-fill |
| `test_locking` | Two processes; exclusive lock blocks second writer |
| `test_encryption` | Build with `QIHSE_VFS_ENCRYPT=1`; raw file bytes not plaintext; decrypt verifies rows |
| `test_yoyo_migrations` | Run `yoyo apply` on QIHSE-backed db; exercises DDL: `CREATE/ALTER/DROP TABLE` |
| `test_compat_cli.sh` | `sqlite3 -cmd ".load ./qihse_vfs.so" "file:t.db?vfs=qihse"` full round-trip |

---

## 13. Implementation Phases

| Phase | Scope | Key deliverable |
|---|---|---|
| **1** | Skeleton & registration | `qihse_sqlite_vfs.h/c` with stubs; `test_vfs_register` passes |
| **2** | Core I/O against bare `qihse_file_t` | `xOpen/Close/Read/Write/Sync/FileSize/Truncate`; `test_basic_create_open` passes |
| **3** | Page cache (`qihse_vfs_page_cache.c`) | Black Hole KV behind `xRead/Write`; `test_write_read_pages` passes |
| **4** | Locking | `xLock/Unlock/CheckReservedLock` with `.qlock` sidecar; `test_locking` passes |
| **5** | WAL routing (`qihse_vfs_wal.c`) | Marmalade-backed WAL; `test_wal_mode` + `test_crash_recovery` pass |
| **6** | VFS-level methods | `xDelete/Access/FullPathname/Randomness/Sleep/CurrentTime` |
| **7** | PQC encryption | `#ifdef QIHSE_VFS_ENCRYPT` page-level AES-256-GCM; `test_encryption` passes |
| **8** | Build + compat | `Makefile` targets; `test_yoyo_migrations` + CLI compat test pass |

---

## 14. Known Constraints and Deferred Work

| Item | Status | Notes |
|---|---|---|
| **Binary KV values** | Deferred | KV API is currently string-valued; page bytes are hex-encoded. `qihse_kv_set_binary` should be added to Black Hole in a follow-on PR. |
| **Shared-memory WAL (`-shm`)** | Deferred | Multi-process WAL sharing requires a POSIX `mmap` over the SHM file with lock bytes. Deferred until Phase 5 single-process WAL is proven. |
| **Windows** | Partial | `qihse_platform.h` provides stubs; key-file path (`/etc/qihse/keys/`) needs a Windows equivalent. |
| **`SQLITE_IOCAP_ATOMIC_4K`** | Deferred | Would let SQLite skip journals for 4K writes, but requires OS-level atomic sector write guarantees (ZFS / ext4). |
| **KV compaction** | Deferred | LSM flush holds full key list in RAM; background compaction needed for databases > 8 MB. Deferred to Black Hole Phase 4. |
