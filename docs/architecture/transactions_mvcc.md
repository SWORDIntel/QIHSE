# QIHSE ACID Transactions & MVCC Architecture

## 1. Overview

QIHSE provides full ACID transaction support across all storage engines. The transaction layer consists of a transaction manager, an MVCC version store, a unified Write-Ahead Log, and a crash recovery module.

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
// Create a transaction manager
qihse_txn_manager_t* qihse_txn_manager_create(void);

// Begin a transaction with specified isolation level
qihse_txn_t* qihse_txn_begin(qihse_txn_manager_t* mgr, qihse_isolation_level_t level);

// Commit a transaction
int qihse_txn_commit(qihse_txn_manager_t* mgr, qihse_txn_t* txn);

// Rollback a transaction
int qihse_txn_rollback(qihse_txn_manager_t* mgr, qihse_txn_t* txn);

// Savepoint operations
int qihse_txn_savepoint(qihse_txn_t* txn, const char* name);
int qihse_txn_rollback_to_savepoint(qihse_txn_t* txn, const char* name);
```

### Isolation Levels

| Level | Snapshot | Conflict Detection | Description |
|---|---|---|---|
| READ COMMITTED | Per-statement | None | Each statement sees the latest committed data |
| REPEATABLE READ | Per-transaction | Write-write | Snapshot taken at BEGIN, held for entire transaction |
| SERIALIZABLE | Per-transaction | Read-write + Write-write | OCC validation at commit time; aborts on any conflict |

### SERIALIZABLE OCC Validation

At commit time, the transaction's read set and write set are validated against all concurrent transactions that committed during its execution:

1. **Read-write conflict**: If any committed transaction wrote to a key that this transaction read, abort
2. **Write-write conflict**: If any committed transaction wrote to a key that this transaction wrote, abort

If validation passes, the transaction commits. If it fails, the transaction is aborted and the application must retry.

### Two-Phase Commit (2PC)

For cross-engine distributed transactions:

```c
// Register a participant (engine) with prepare/commit/abort callbacks
int qihse_txn_register_participant(qihse_txn_manager_t* mgr,
    qihse_txn_participant_t* participant);

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

This means:
- The version was created by a transaction that committed before T's snapshot
- The version was not deleted by a transaction that committed before T's snapshot

### API

```c
qihse_mvcc_store_t* qihse_mvcc_create(void);

// Insert a new version (called within a transaction)
int qihse_mvcc_insert(qihse_mvcc_store_t* store, uint8_t engine_id,
    const void* key, size_t key_len, const void* value, size_t value_len,
    uint64_t txn_id);

// Update: set xmax on old version, insert new version
int qihse_mvcc_update(qihse_mvcc_store_t* store, uint8_t engine_id,
    const void* key, size_t key_len, const void* new_value, size_t new_value_len,
    uint64_t txn_id);

// Delete: set xmax on current visible version
int qihse_mvcc_delete(qihse_mvcc_store_t* store, uint8_t engine_id,
    const void* key, size_t key_len, uint64_t txn_id);

// Read: find version visible to the given snapshot
qihse_mvcc_version_t* qihse_mvcc_read(qihse_mvcc_store_t* store, uint8_t engine_id,
    const void* key, size_t key_len, uint64_t snapshot);

// Garbage collect dead versions
size_t qihse_mvcc_vacuum(qihse_mvcc_store_t* store, uint64_t min_active_snapshot);
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

### WAL Operations

```c
qihse_wal_t* qihse_wal_create(const char* directory, size_t segment_size,
    qihse_wal_durability_t durability);

// Append a data mutation
uint64_t qihse_wal_append(qihse_wal_t* wal, uint64_t txn_id, uint8_t engine_id,
    uint8_t op_type, const void* key, size_t key_len,
    const void* value, size_t value_len);

// Transaction markers
uint64_t qihse_wal_append_begin(qihse_wal_t* wal, uint64_t txn_id);
uint64_t qihse_wal_append_commit(qihse_wal_t* wal, uint64_t txn_id);
uint64_t qihse_wal_append_abort(qihse_wal_t* wal, uint64_t txn_id);
uint64_t qihse_wal_append_checkpoint(qihse_wal_t* wal, uint64_t lsn);

// Replay
int qihse_wal_replay(qihse_wal_t* wal, qihse_wal_replay_cb callback, void* ctx);

// Checkpoint
int qihse_wal_checkpoint(qihse_wal_t* wal, uint64_t lsn);
```

### Durability Modes

| Mode | Behavior | Use Case |
|---|---|---|
| `QIHSE_WAL_DURABILITY_NONE` | No fsync, fastest | Development, ephemeral data |
| `QIHSE_WAL_DURABILITY_FDATASYNC` | fdatasync after each commit | Default, balanced |
| `QIHSE_WAL_DURABILITY_GROUP_COMMIT` | Batch fsync every N ms | High-throughput production |

### Segment Rotation

WAL files are named `wal_00000000000000000000.log`, `wal_00000000000000000001.log`, etc. When a segment reaches the configured size (default 64 MB), it rotates to the next segment. Old segments before the checkpoint LSN are truncated.

## 5. Crash Recovery

**Files**: `include/qihse_recovery.h`, `src/tractable/qihse_recovery.c`

### Recovery Process

On startup, QIHSE replays the WAL in three phases:

#### Phase 1: Analysis
- Scan all WAL segments from the last checkpoint
- Build a transaction status table: which transactions committed, which aborted, which were active
- Identify the last valid LSN

#### Phase 2: Redo
- Re-apply all mutations from committed transactions to the MVCC store
- This restores the database to its last-committed state

#### Phase 3: Undo
- Mark all transactions that were active at crash time as aborted
- Their uncommitted changes are not visible (xmax not set, but xmin > any snapshot)

### Checkpoint

```c
int qihse_recovery_checkpoint(qihse_recovery_ctx_t* ctx,
    qihse_checkpoint_flush_cb flush, uint64_t* out_lsn);
```

Checkpoint procedure:
1. Call the flush callback to persist all engine state to disk
2. Write a checkpoint record to the WAL with the current LSN
3. Truncate all WAL segments before the checkpoint LSN
4. Update the recovery context's last-checkpoint LSN

## 6. Testing

Tests are in `tests/test_txn.c` (6 tests):

1. **BEGIN/COMMIT/ROLLBACK**: Basic transaction lifecycle
2. **MVCC visibility**: Two concurrent transactions, one sees old version, one sees new
3. **SAVEPOINT and partial rollback**: Savepoint creation, rollback to savepoint
4. **WAL append and replay**: Write records, replay, verify content
5. **Crash recovery**: Write WAL, replay, verify committed txns visible and uncommitted not
6. **SERIALIZABLE conflict detection**: Read-write conflict causes abort
