# Replication, Backup & Operational Features

> **Status: partial.** Streaming replication, read-replica routing and the
> connection pooler are implemented and are exercised by `tests/test_repl.c`
> (run via `make test-repl`). Backup/restore has an authenticated implementation
> under `src/tractable/qihse_backup.c`, but **no test in `tests/` covers that
> API** — the only backup test in the tree is
> `tests/test_federation_backup.c`, which covers the federation writer/reader
> instead; see
> [API_REFERENCE.md §2.3](../API_REFERENCE.md#23-snapshot-backup--includeqihse_backuph).
> **Parallel query is not implemented** (see below).
>
> Two further limits:
>
> - `qihse_repl_apply_wal()` records the LSN but does **not** replay the WAL
>   into a local store; the source says "In a real implementation, this would
>   replay the WAL into the local store". `tests/test_repl.c` asserts the LSN
>   bookkeeping and states this in its header comment.
> - `qihse_backup_incremental_user()` is not a delta export: it returns
>   UNSUPPORTED by design, because the KV store exposes no change sequence
>   (documented in the API snippet below).

## Overview

QIHSE provides streaming replication, read replica routing, backup/restore, parallel query execution, and an enhanced connection pooler for production operational maturity.

## Streaming Replication (`src/spinnaker/qihse_repl.c`)

### Architecture
- **Primary** ships WAL records to replicas via TCP
- **Replicas** connect, request WAL stream from a specific LSN, and apply records in order
- **Sync mode**: primary waits for at least one replica to confirm before committing
- **Async mode**: primary ships WAL without waiting

### Replication Slots
- Named slots track consumer position (restart_lsn, confirmed_flush_lsn)
- Prevent WAL premature WAL recycling
- Create/drop/advance operations

### API
```c
qihse_repl_context_t* ctx = qihse_repl_create(REPL_ROLE_REPLICA);
qihse_repl_connect_primary(ctx, "10.0.0.1", 5432);
qihse_repl_start_streaming(ctx);
qihse_repl_create_slot(ctx, "my_slot");
qihse_repl_apply_wal(ctx, wal_data, len, lsn);
```

## Read Replicas (`src/spinnaker/qihse_read_replica.c`)

### Pool Management
- Add/remove replica nodes by host:port
- Health checks via TCP connect with timeout
- Round-robin routing among healthy replicas
- Active connection tracking per replica

### API
```c
qihse_read_replica_pool_t* pool = qihse_read_replica_pool_create();
qihse_read_replica_pool_add(pool, "10.0.0.2", 5432);
qihse_read_replica_pool_add(pool, "10.0.0.3", 5432);
char* host; uint16_t port;
qihse_read_replica_route(pool, &host, &port);
```

## Backup & Restore (`src/tractable/qihse_backup.c`)

### Backup Types
- **Full**: Snapshot all KV store data
- **Incremental**: Only keys modified since a given LSN
- **WAL**: WAL segment archive

### Backup Format
```
[8-byte magic: "QIHSEBAK"]
[4-byte version]
[4-byte type]
[8-byte start_lsn]
[8-byte end_lsn]
[8-byte timestamp]
[8-byte checksum (FNV-1a)]
[8-byte data_length]
[data: key-value tuples]
```

### API
```c
qihse_backup_info_t info;
qihse_backup_full_user(kv, user, "/backups/full.bak", &info);
/* Incremental export is NOT implemented: the KV store exposes no change
   sequence, so this returns UNSUPPORTED rather than shipping a full snapshot
   labelled incremental. Use the manifest-bound federation backup, which
   carries a WAL continuation point, for delta restore. */
qihse_backup_incremental_user(kv, user, "/backups/incr.bak", since_lsn, &info);
qihse_restore_user(kv, user, "/backups/full.bak");
qihse_backup_verify_user(user, "/backups/full.bak");
```

## Parallel Query (`src/tractable/qihse_parallel_query.c`) — NOT IMPLEMENTED

> **Status: planned.** The entry points exist and return success, but the work
> inside them does not: the scan workers contain
> `TODO: actual KV store iteration with partitioning` and report a row count of
> zero, the aggregate is `TODO: actual aggregation over KV store partition`, and
> the join is `TODO: implement parallel hash join or merge join`. No test covers
> this file. The description below is the design, not the code.

### Architecture
- pthread-based worker threads
- Data partitioning by key range or hash
- Independent partition processing
- Result merging (sum, count, avg, min, max)

### Operations
- **Parallel scan**: Split table into chunks, scan in parallel
- **Parallel join**: Partition both tables, join in parallel
- **Parallel aggregate**: Compute aggregates in parallel, merge results

### API
```c
qihse_parallel_ctx_t* ctx = qihse_parallel_init(4);  // 4 workers
qihse_parallel_scan_t scan;
qihse_parallel_scan(ctx, kv, "users", &scan);
double count;
qihse_parallel_aggregate(ctx, kv, "users", "age", "count", &count);
```

## Enhanced Connection Pooler (`src/spinnaker/qihse_pooler.c`)

### Pooling Modes
- **Session** (`POOL_SESSION`): One backend per client (like pgbouncer session mode)
- **Transaction** (`POOL_TRANSACTION`): Backend returned to pool at transaction end
- **Statement** (`POOL_STATEMENT`): Backend returned after each statement

### Backend Management
- Add/remove backends by host:port
- Health checking
- Wait queue tracking
- Idle timeout, connect timeout, max connections

### API
```c
qihse_pooler_config_t config = {
    .mode = POOL_TRANSACTION,
    .max_connections = 100,
    .max_per_client = 10,
    .idle_timeout_ms = 30000,
};
qihse_pooler_t* pool = qihse_pooler_create_ex(&config);
qihse_pooler_add_backend(pool, "10.0.0.1", 5432);
```

## Testing

`tests/test_repl.c` (run via `make test-repl`) covers:

1. **Replication context**: role/state transitions, and refusal to ship WAL or
   start streaming before a connection exists.
2. **Replication slots**: create, duplicate refused, advance (including the
   refusal to move `restart_lsn` backwards), drop, count.
3. **WAL shipping over a real loopback socket**: the peer must receive the
   `[LSN][length][data]` frame byte-for-byte and `qihse_repl_get_status()` must
   report it; `qihse_repl_apply_wal()` advances the flush LSN.
4. **Refusals**: connecting to a closed port, an invalid address and a NULL host
   all fail and leave the context in `REPL_STATE_ERROR`.
5. **Read-replica pool**: add/remove, round-robin routing with wrap-around,
   active count, and health checking against unreachable addresses (all
   unhealthy, no route) and against a live listener (healthy, routable).
6. **Pooler**: config defaults and round-trip, backend add/remove/count, pooling
   modes, admin-console parse and execute (`SHOW VERSION`, `SHOW POOLS`,
   `PAUSE`), databases and users.

**Not covered by this test, because the code does not implement it:** parallel
query (stubbed, see above). **Not covered because no test exists:** the
authenticated backup/restore API in `src/tractable/qihse_backup.c`, and
`qihse_repl_apply_wal()` actually replaying WAL records into a store.
