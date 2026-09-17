# QIHSE ACID Transactions & MVCC Architecture

> **Status: partial.** The transaction manager, MVCC version store, WAL and
> recovery all have real implementations under `src/tractable/` and are
> exercised by `tests/test_txn.c` (run via `make test-txn`). Three limits are
> stated plainly rather than glossed over:
>
> 1. **SERIALIZABLE OCC validation only sees transactions that are still active
>    at commit time.** `qihse_txn_validate_occ()` walks the active list; the
>    read/write sets of transactions that already committed are not retained, so
>    a conflict with an already-committed concurrent transaction is not
>    detected. The source says so in place, and `tests/test_txn.c` therefore
>    asserts only the active-transaction cases.
> 2. **`qihse_mvcc_delete()` marks the chain head, which may be a version
>    written by a transaction that later aborted.** It therefore does not always
>    delete the version readers can see. Reproduced by `tests/test_txn.c` as a
>    `NOTE` line, not asserted.
> 3. **`qihse_mvcc_min_active_snapshot()` returns 0 as a placeholder** and must
>    not be used as a vacuum cutoff; callers pass the cutoff explicitly.

## 1. Overview

QIHSE provides transactional storage over the KV, document, columnar, vector and
event engines: a transaction manager, an MVCC version store, a unified
Write-Ahead Log, and a crash recovery module. The guarantee is snapshot-based
multi-version visibility with per-transaction commit/abort state; it is not a
distributed-systems-grade serializable engine (see the OCC limitation above).

## 2. Transaction Manager

**Files**: `include/qihse_txn.h`, `src/tractable/qihse_txn.c`

### Transaction Lifecycle

```
BEGIN ──> ACTIVE ──> PREPARED (2PC) ──> COMMITTED
                │                        │
                └──> ABORTED <───────────┘ (rollback)
```

### API

```c
// Create / destroy a transaction manager
qihse_txn_manager_t* qihse_txn_manager_create(void);
void qihse_txn_manager_destroy(qihse_txn_manager_t* mgr);

// Begin a transaction with specified isolation level
qihse_txn_t* qihse_txn_begin(qihse_txn_manager_t* mgr, qihse_isolation_level_t level);

// Commit / roll back a transaction
int qihse_txn_commit(qihse_txn_manager_t* mgr, qihse_txn_t* txn);
int qihse_txn_rollback(qihse_txn_manager_t* mgr, qihse_txn_t* txn);

// Savepoint operations (the manager is the first argument)
int qihse_txn_savepoint(qihse_txn_manager_t* mgr, qihse_txn_t* txn, const char* name);
int qihse_txn_rollback_to_savepoint(qihse_txn_manager_t* mgr,
                                    qihse_txn_t* txn, const char* name);

// Snapshot handling
void     qihse_txn_refresh_snapshot(qihse_txn_manager_t* mgr, qihse_txn_t* txn);
uint64_t qihse_txn_get_snapshot(const qihse_txn_t* txn);

// Read/write set tracking (SERIALIZABLE OCC)
int qihse_txn_record_read(qihse_txn_t* txn, uint8_t engine_id,
                          const void* key, size_t key_len);
int qihse_txn_record_write(qihse_txn_t* txn, uint8_t engine_id,
                           const void* key, size_t key_len);
int qihse_txn_validate_occ(qihse_txn_manager_t* mgr, qihse_txn_t* txn);

// Registry queries
bool qihse_txn_is_committed(qihse_txn_manager_t* mgr, uint64_t txn_id);
bool qihse_txn_is_aborted(qihse_txn_manager_t* mgr, uint64_t txn_id);
int  qihse_txn_active_list(qihse_txn_manager_t* mgr, uint64_t** out_ids, int* out_count);
int  qihse_txn_active_count(qihse_txn_manager_t* mgr);

// LSN plumbing
void     qihse_txn_set_start_lsn(qihse_txn_t* txn, uint64_t lsn);
uint64_t qihse_txn_get_start_lsn(const qihse_txn_t* txn);
```

### Isolation Levels

| Level | Snapshot | Conflict Detection | Description |
|---|---|---|---|
| READ COMMITTED | Per-statement | None | Each statement sees the latest committed data |
| REPEATABLE READ | Per-transaction | Write-write | Snapshot taken at BEGIN, held for entire transaction |
| SERIALIZABLE | Per-transaction | Read-write + Write-write | OCC validation at commit time against *active* transactions; aborts on conflict |

### SERIALIZABLE OCC Validation

At commit time the transaction's read set and write set are compared against the
read/write sets of the transactions that are **still active**:

1. **Read-write conflict**: if an active transaction with a newer id wrote a key
   this transaction read, abort.
2. **Write-write conflict**: if an active transaction with a newer id wrote a key
   this transaction wrote, abort.

If validation passes, the transaction commits. If it fails, the transaction is
aborted and the application must retry.

*Limitation*: because only active transactions are scanned, a conflict with a
transaction that already committed is not detected. `tests/test_txn.c` asserts
the active-transaction cases (both conflict kinds plus a disjoint-keys commit)
and does not assert the committed-conflict case, which the implementation does
not provide.

### Two-Phase Commit (2PC)

For cross-engine distributed transactions:

```c
// Register a participant (engine) with prepare/commit/abort callbacks
int qihse_txn_register_participant(qihse_txn_manager_t* mgr,
                                   qihse_txn_participant_t participant);

// Phase 1: Prepare all participants
int qihse_txn_prepare(qihse_txn_manager_t* mgr, qihse_txn_t* txn);

// Phase 2a: Commit all prepared participants
int qihse_txn_commit_prepared(qihse_txn_manager_t* mgr, qihse_txn_t* txn);

// Phase 2b: Abort all prepared participants
int qihse_txn_abort_prepared(qihse_txn_manager_t* mgr, qihse_txn_t* txn);
```

Each engine implements the participant interface:
- `prepare()`: Write changes to WAL, return success/failure
- `commit()`: Make changes visible, release locks
- `abort()`: Discard changes, release locks

A participant whose `prepare()` fails aborts the whole transaction; the
participant callback sequencing is covered by `tests/test_txn.c`.

## 3. MVCC Version Store

**Files**: `include/qihse_mvcc.h`, `src/tractable/qihse_mvcc.c`

### Version Chain Structure

Each row has a linked list of versions, newest first:

```
Row (engine_id, key)
  └── Version 3: xmin=103, xmax=0   (visible to txn >= 103)
      └── Version 2: xmin=101, xmax=103  (visible to 101 <= txn < 103)
          └── Version 1: xmin=99, xmax=101  (visible to 99 <= txn < 101)
```

### Visibility Check

A version is visible to transaction T with snapshot S if:
```
xmin <= S  AND  (xmax == 0  OR  xmax > S)
```
and both `xmin` and (when set) `xmax` refer to transactions that committed,
checked through the `qihse_mvcc_committed_cb` callback the caller supplies.

This means:
- The version was created by a transaction that committed before T's snapshot
- The version was not deleted by a transaction that committed before T's snapshot
- A version written by a transaction that has not committed, or that aborted, is
  invisible even to a snapshot at or above its `xmin`; a version whose `xmax`
  belongs to an uncommitted transaction stays visible.

### API

```c
qihse_mvcc_store_t* qihse_mvcc_store_create(size_t initial_buckets);
void qihse_mvcc_store_destroy(qihse_mvcc_store_t* store);

// Insert a new version (called within a transaction)
int qihse_mvcc_insert(qihse_mvcc_store_t* store, uint8_t engine_id,
    const void* key, size_t key_len, const void* value, size_t value_len,
    uint64_t txn_id);

// Update: set xmax on the previous head, insert new version
int qihse_mvcc_update(qihse_mvcc_store_t* store, uint8_t engine_id,
    const void* key, size_t key_len, const void* new_value, size_t new_value_len,
    uint64_t txn_id);

// Delete: set xmax on the chain head
// NOTE: the head may be a version written by a transaction that aborted, in
// which case the delete does not affect the version readers can see.
int qihse_mvcc_delete(qihse_mvcc_store_t* store, uint8_t engine_id,
    const void* key, size_t key_len, uint64_t txn_id);

// Read: find the version visible to the given snapshot
bool qihse_mvcc_read(qihse_mvcc_store_t* store, uint8_t engine_id,
    const void* key, size_t key_len, uint64_t snapshot,
    qihse_mvcc_committed_cb is_committed, void* committed_ctx,
    const void** out_value, size_t* out_value_len);
bool qihse_mvcc_exists(qihse_mvcc_store_t* store, uint8_t engine_id,
    const void* key, size_t key_len, uint64_t snapshot,
    qihse_mvcc_committed_cb is_committed, void* committed_ctx);

// Garbage collection: reclaim versions with xmax set and xmax < min_snapshot
int      qihse_mvcc_gc(qihse_mvcc_store_t* store, uint64_t min_snapshot);
int      qihse_mvcc_vacuum(qihse_mvcc_store_t* store, uint64_t min_snapshot);
uint64_t qihse_mvcc_min_active_snapshot(qihse_mvcc_store_t* store); /* placeholder: returns 0 */

// Inspection
int qihse_mvcc_version_count(qihse_mvcc_store_t* store);
int qihse_mvcc_row_count(qihse_mvcc_store_t* store);
```

### Engine IDs

| Engine | ID |
|---|---|
| KV Store | 0 |
| Document Store | 1 |
| Columnar Store | 2 |
| Vector DB | 3 |
| Event Stream | 4 |

## 4. Unified Write-Ahead Log

**Files**: `include/qihse_wal.h`, `src/tractable/qihse_wal.c`

### Record Format

```
+----------+----------+------------+---------+------------+-----+--------------+--------+
| LSN (8B) | TxnID(8B)| EngineID(1)| OpType  | KeyLen (4B)| Key | ValueLen(4B) | Value  |
+----------+----------+------------+---------+------------+-----+--------------+--------+
                                                                              +--------+
                                                                              | CRC32  |
                                                                              +--------+
```

The header is 30 bytes (`QIHSE_WAL_RECORD_HEADER_SIZE`) with the checksum at
offset 26; the checksum covers the header fields, the key and the value. Replay
recomputes it and stops at the first record that does not match, which
`tests/test_txn.c` asserts by corrupting a checksum byte.

### WAL Operations

```c
qihse_wal_t* qihse_wal_create(const char* directory, size_t segment_size,
    qihse_wal_durability_t durability);
void qihse_wal_destroy(qihse_wal_t* wal);

// Append a data mutation
uint64_t qihse_wal_append(qihse_wal_t* wal, uint64_t txn_id, uint8_t engine_id,
    qihse_wal_op_t op_type, const void* key, uint32_t key_len,
    const void* value, uint32_t value_len);

// Transaction markers
uint64_t qihse_wal_append_begin(qihse_wal_t* wal, uint64_t txn_id);
uint64_t qihse_wal_append_commit(qihse_wal_t* wal, uint64_t txn_id);
uint64_t qihse_wal_append_abort(qihse_wal_t* wal, uint64_t txn_id);
uint64_t qihse_wal_append_checkpoint(qihse_wal_t* wal, uint64_t lsn);

// Flush / replay / checkpoint
int      qihse_wal_flush(qihse_wal_t* wal);
int      qihse_wal_replay(qihse_wal_t* wal, uint64_t start_lsn,
                          qihse_wal_replay_cb callback, void* user_data);
int      qihse_wal_checkpoint(qihse_wal_t* wal, uint64_t checkpoint_lsn);
uint64_t qihse_wal_current_lsn(qihse_wal_t* wal);
uint64_t qihse_wal_last_checkpoint(qihse_wal_t* wal);
```

### Durability Modes

| Mode | Behavior | Use Case |
|---|---|---|
| `QIHSE_WAL_DURABILITY_NONE` | No fsync, fastest | Development, ephemeral data |
| `QIHSE_WAL_DURABILITY_FDATASYNC` | fdatasync after each record | Default, balanced |
| `QIHSE_WAL_DURABILITY_GROUP_COMMIT` | Batch fsync via `qihse_wal_flush()` | High-throughput production |

### Segment Rotation

WAL files are named `wal_00000000000000000000.log`, `wal_00000000000000000001.log`, etc. When a segment reaches the configured size (default 64 MB), it rotates to the next segment. `qihse_wal_checkpoint()` removes segments with an index below the current one.

## 5. Crash Recovery

**Files**: `include/qihse_recovery.h`, `src/tractable/qihse_recovery.c`

### Recovery Process

On startup, QIHSE replays the WAL in three phases:

#### Phase 1: Analysis
- Scan all WAL segments from the last checkpoint
- Build a transaction status table: which transactions committed, which aborted, which were active
- Collect the mutations of each transaction

#### Phase 2: Redo
- Re-apply the mutations of committed transactions to the MVCC store
- This restores the database to its last-committed state

#### Phase 3: Undo
- Register transactions that were active at crash time as aborted
- Their changes are not applied during redo and remain invisible to readers
  (`xmin` never commits)

### API

```c
qihse_recovery_t* qihse_recovery_create(qihse_txn_manager_t* txn_mgr,
                                        qihse_mvcc_store_t* mvcc,
                                        qihse_wal_t* wal);
void qihse_recovery_destroy(qihse_recovery_t* rec);

int qihse_recovery_replay(qihse_recovery_t* rec);

// Checkpoint: flush engine state through the callback, record the checkpoint
// LSN, and truncate older segments.
int qihse_recovery_checkpoint(qihse_recovery_t* rec,
                              qihse_recovery_flush_cb flush_cb, void* flush_ctx);

// Inspection after replay
bool qihse_recovery_txn_committed(qihse_recovery_t* rec, uint64_t txn_id);
bool qihse_recovery_txn_aborted(qihse_recovery_t* rec, uint64_t txn_id);
int  qihse_recovery_committed_count(qihse_recovery_t* rec);
int  qihse_recovery_aborted_count(qihse_recovery_t* rec);
```

Checkpoint procedure:
1. Call the flush callback to persist all engine state to disk
2. Flush the WAL and append a checkpoint record with the current LSN
3. Truncate WAL segments older than the checkpoint

## 6. Testing

`tests/test_txn.c` (run via `make test-txn`) covers:

1. **BEGIN/COMMIT/ROLLBACK**: lifecycle, registry state, active set, LSN
   plumbing, and refusal of a second commit or rollback.
2. **MVCC visibility**: an older snapshot still sees the superseded version; a
   version written by an uncommitted or aborted transaction is invisible; a
   committed delete hides the row; vacuum reclaims dead versions.
3. **SAVEPOINT and partial rollback**: savepoint stack and write-set trim.
4. **WAL append and replay**: LSN ordering, payload survival, `start_lsn`
   filtering, and refusal to replay a record whose CRC does not match.
5. **Crash recovery**: a committed transaction's insert is redone and visible; a
   transaction that never committed is registered aborted and its data stays
   invisible; transaction ids stay monotonic; checkpointing runs.
6. **SERIALIZABLE conflict detection**: read-write and write-write conflicts
   against active transactions abort; disjoint keys commit.
7. **Two-phase commit**: prepare / commit_prepared / abort_prepared callback
   sequencing, and a participant whose prepare fails aborting the transaction.

Reproduced as a `NOTE` line rather than asserted (so that fixing it cannot break
the test): `qihse_mvcc_delete()` after an aborted writer leaves the row visible
to committed readers.

Not covered: the committed-transaction OCC case (not implemented, see the status
note) and WAL segment rotation under load.
