# Replication, Backup & Operational Features

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
qihse_backup_full(kv, "/backups/full.bak", &info);
qihse_backup_incremental(kv, "/backups/incr.bak", since_lsn, &info);
qihse_restore(kv, "/backups/full.bak");
qihse_backup_verify("/backups/full.bak");
```

## Parallel Query (`src/tractable/qihse_parallel_query.c`)

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
9 tests in `tests/test_repl.c` covering all the above features.
