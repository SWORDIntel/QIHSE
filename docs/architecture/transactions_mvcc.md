# QIHSE ACID Transactions & MVCC Architecture

> **Status: partial.** The transaction manager, MVCC version store, WAL and
> recovery all have real implementations under `src/tractable/` and are
> exercised by `tests/test_txn.c` (run via `make test-txn`) and
> `tests/test_mvcc_delete.c` (run via `make test-mvcc-delete`). Two limits are
> stated plainly rather than glossed over:
>
> 1. **The SQL row store and public SQL transaction commands are not yet wired
>    through this transaction manager.** The guarantees below describe callers
>    that record every read and write through this API; they do not make direct
>    row-store mutations transactional.
> 2. **`qihse_mvcc_min_active_snapshot()` returns 0 as a placeholder** and must
>    not be used as a vacuum cutoff; callers pass the cutoff explicitly.
>
> One claim in an earlier revision of this document was wrong and is corrected
> in place: **`qihse_mvcc_delete()` no longer marks the chain head.** It records
> a delete intent carrying the deleting transaction and the snapshot the delete
> is evaluated at, and the read path — which does have commit context — resolves
> the intent so it hides exactly the versions that were visible at that
> snapshot. Marking the head did not always delete the version readers could
> see, because the head may be a version written by a transaction that later
> aborted. `tests/test_txn.c` asserts the corrected behaviour and
> `tests/test_mvcc_delete.c` asserts it in both directions, including the
> over-correction guards.

## 1. Overview

QIHSE provides transaction, MVCC, WAL and recovery components intended for the
KV, document, columnar, vector and event engines. The transaction manager now
retains committed point-key write sets for every active SERIALIZABLE snapshot,
so an already-committed concurrent transaction cannot disappear from OCC
validation. A caller receives that guarantee only when it records all reads and
writes. Predicate/range conflicts, public SQL integration and durable 2PC
coordinator recovery remain outside this component's current contract.

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
size_t qihse_txn_committed_history_count(qihse_txn_manager_t* mgr);

// LSN plumbing
void     qihse_txn_set_start_lsn(qihse_txn_t* txn, uint64_t lsn);
uint64_t qihse_txn_get_start_lsn(const qihse_txn_t* txn);
```

### Isolation Levels

| Level | Snapshot | Conflict Detection | Description |
|---|---|---|---|
| READ COMMITTED | Per-statement | None | Each statement sees the latest committed data |
| REPEATABLE READ | Per-transaction | Write-write | Snapshot taken at BEGIN, held for entire transaction |
| SERIALIZABLE | Per-transaction commit-sequence snapshot | Read-write + Write-write for recorded point keys | OCC validation against retained writes from every transaction committed after BEGIN; aborts on conflict |

### SERIALIZABLE OCC Validation

At BEGIN, each SERIALIZABLE transaction captures the manager's monotonically
increasing commit sequence. At commit, its read and write sets are compared
against the retained writes of every transaction with a later commit sequence:

1. **Read-write conflict**: if a transaction committed after the snapshot and
   wrote a recorded key this transaction read, abort.
2. **Write-write conflict**: if a transaction committed after the snapshot and
   wrote a recorded key this transaction wrote, abort.

Validation and commit-sequence assignment run under the manager lock. The first
committer can therefore publish its summary before the next committer validates.
If retaining a required summary cannot allocate memory, the committing
transaction aborts: silently dropping the summary would allow a conflicting
SERIALIZABLE transaction to commit.

Committed summaries are ordered by commit sequence. They are pruned only when
their sequence is at or before the oldest active SERIALIZABLE snapshot; when no
SERIALIZABLE transaction remains, all summaries can be released. A long-lived
transaction therefore retains every later write summary it might need.
`qihse_txn_committed_history_count()` exposes the retained-summary count for
inspection and tests.

This is point-key OCC. It does not detect predicate phantoms unless the caller
records a key representing the protected predicate/range, and it provides no
protection for an engine that bypasses `qihse_txn_record_read()` or
`qihse_txn_record_write()`. `tests/test_txn.c` covers committed-after-snapshot
read/write and write/write conflicts, disjoint commits, a long-lived snapshot
across several commits, safe pruning and manager destruction with retained
history.

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

// Delete: record a delete intent at the chain head, carrying the deleting
// transaction and the snapshot the delete is evaluated at. The read path
// resolves the intent with commit context and hides exactly the versions that
// were visible at that snapshot; readers whose snapshot predates the delete
// still see the row. Recording an intent instead of marking xmax matters
// because the head may be a version written by a transaction that aborted.
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
   committed delete hides the row (including when an aborted writer preceded
   it); deleting a missing key is an error rather than a silent success; vacuum
   reclaims dead versions.
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

`tests/test_mvcc_delete.c` (run via `make test-mvcc-delete`) covers delete
semantics in both directions: a committed DELETE hides the row for readers at or
after the deleting snapshot whatever aborted writers preceded it (aborted
UPDATE, aborted DELETE, several aborted writers, a hole under a committed
version), and it does **not** hide anything an older snapshot is entitled to
see, does not hide a version written by a transaction the deleter could not see
(silent data loss), and does not resurrect a row an earlier committed DELETE
hid. The last three cases are the over-correction guards: they fail against a
fix that marks xmax on every version of the chain.

The `mvcc-committed-delete` gold workload
(`tests/gold/workloads/gold_mvcc_committed_delete.c`) asserts the same rule
independently.

Not covered: the committed-transaction OCC case (not implemented, see the status
note) and WAL segment rotation under load.
