# Replication, Backup & Operational Features

> **Status: implemented.** Streaming replication, read-replica routing,
> parallel query, the connection pooler, and backup/restore on both sides are
> implemented and tested: the whole-store/incremental surface under
> `src/tractable/qihse_backup.c` is verified by
> `tests/test_incremental_export.c` (`make test-incremental-export`) plus the
> argument-refusal cases in `tests/test_federation_backup.c`, and the
> manifest-bound federation container under `src/federation/qihse_backup.c`
> is verified by `tests/test_federation_backup.c` and
> `tests/test_backup_auth.c` (`make test-backup-auth`); see
> [API_REFERENCE.md §2.3](../API_REFERENCE.md#23-snapshot-backup--includeqihse_backuph).
> What remains in the container family is documented residual choices, not
> gaps (the operator override's narrow scope; whole-store restore refusing a
> delta container on purpose).
>
> Three claims in earlier revisions of this document were wrong and are corrected
> in place:
>
> - **`qihse_repl_apply_wal()` replays.** It no longer only records an LSN: the
>   record is staged as a private single-record WAL segment and replayed through
>   `qihse_wal_replay()`, and the mutation reaches the bound store. A context
>   with no store bound refuses every record rather than advancing an LSN that
>   reached nothing (`qihse_repl_set_store()`). Verified by
>   `tests/test_repl.c` and by the `repl-apply-wal` gold workload
>   (`tests/gold/workloads/gold_repl_apply_wal.c`).
> - **Parallel query is implemented**, not a stub. Verified by
>   `tests/test_parallel_query.c` (`make test-parallel-query`) and the
>   `parallel-query` gold workload.
> - **Incremental export is real**, not UNSUPPORTED. The KV store now stamps a
>   store-global atomic change sequence (7th field of the record header), and
>   `qihse_backup_incremental_user()` delivers a `BACKUP_INCREMENTAL` container
>   built from the KV layer's clearance-filtered delta stream (documented in
>   the API snippet below).

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
/* Bind the local store that apply replays into. Borrowed, never owned; a
   context with no store bound refuses every record rather than advancing an
   LSN that reached no store. */
qihse_repl_set_store(ctx, kv);
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
- **Full**: Snapshot all KV store data, through the KV layer's
  authorization-aware export (a record outside the caller's clearance/SCI
  refuses the whole export — a full container claims complete coverage)
- **Incremental**: A real delta container (`BACKUP_INCREMENTAL`) built from
  the KV layer's change-sequence delta stream — only records whose stamped
  sequence is strictly greater than the cursor, tombstones included,
  clearance/SCI-filtered at the KV layer, carrying the no-leak resume point
  (the highest sequence the principal may see, never the global high-water)
  as its continuation
- **WAL**: WAL segment archive (the federation container's WAL section below)

### Backup Format (whole-store/incremental container)
```
[8-byte magic: "QIHSEBAK"]
[4-byte version (2)]
[4-byte type]
[8-byte start_lsn]
[8-byte end_lsn]
[8-byte timestamp]
[8-byte data_length]
[4-byte writer_user_id]
[2-byte writer_classification]
[2-byte writer_sci]
[8-byte checksum (FNV-1a over header[0..56) + data)]
[data: the KV layer's record stream, classification/SCI included]
```
A 64-byte fixed header, little-endian, written atomically (renamed into place
only once every byte is down, so a failed export leaves no container and no
partial dataset).

### API
```c
qihse_backup_info_t info;
qihse_backup_full_user(kv, user, "/backups/full.bak", &info);
/* Incremental export IS implemented: the KV store stamps a store-global
   change sequence, so this writes a BACKUP_INCREMENTAL container holding
   only the delta above since_lsn plus the no-leak resume point. */
qihse_backup_incremental_user(kv, user, "/backups/incr.bak", since_lsn, &info);
/* Whole-store restore deliberately refuses a delta container — a delta is
   not a whole-store image (returns UNSUPPORTED). */
qihse_restore_user(kv, user, "/backups/full.bak");
qihse_backup_verify_user(user, "/backups/full.bak");
```

### Federation containers (`src/federation/qihse_backup.c`)

The manifest-bound federation backup writes an authenticated container in the
signed v3 form: `[ header 464 ][ signature ][ data ][ WAL ]`. The ML-DSA
signature covers the whole fixed header — manifest checksum, data and WAL
SHA-384 digests, WAL LSN range, signer identity and algorithm inside the
signed region — and the WAL section's records carry classification/SCI, with
a clearance pre-flight and all-or-nothing replay. `qihse_backup_verify()` is
the verify-only entry point (checks the WAL section without applying it), and
the retired v1/v2 forms are refused by version with no downgrade. The single
deliberate residual choice in this family is the operator override on
`qihse_backup_restore_signed()`, which skips only the signature gate and only
for a `QIHSE_SCOPE_SECURITY_ADMIN` principal. See
[API_REFERENCE.md §2.3](../API_REFERENCE.md#23-snapshot-backup--includeqihse_backuph)
for the full surface.

## Parallel Query (`src/tractable/qihse_parallel_query.c`)

> **Status: implemented.** Verified by `tests/test_parallel_query.c` (run via
> `make test-parallel-query`) and by the `parallel-query` workload in
> `tests/gold/pack.v1.gold`. An earlier revision of this document said the
> module was a stub that returned success while doing nothing; that was true and
> is no longer. What the implementation does *not* claim is stated in the header
> and repeated here.

### Architecture
- pthread-based worker threads, 1..`QIHSE_PARALLEL_MAX_WORKERS` (64)
- The keyspace traversal itself is **serial**: `qihse_kv_foreach_user()` is the
  only enumeration the KV layer exposes and it has no prefix, range or resume
  form, so the rows under a table prefix are materialised on the calling thread
  and the resulting array is then partitioned across the workers (worker *i*
  takes rows *i*, *i+num_workers*, …). Every row is visited exactly once.
- Parallelised per-row work: the row copies a scan returns, the numeric parse an
  aggregate needs, and the hash build/probe a join needs. A prefix/range
  iterator in the KV API would remove the materialisation; until one exists this
  module does not claim to have it.
- Result merging (sum, count, avg, min, max)

### Operations
- **Parallel scan**: split the materialised rows into chunks, copy them in parallel
- **Parallel hash join**: build/probe in parallel, on a shared column name
- **Parallel aggregate**: parse and accumulate in parallel, merge results

### Security context
Rows are read through `qihse_kv_foreach_user()` with the principal bound to the
context (`qihse_parallel_set_user()`), so enumeration is authorization-aware. A
context with no user bound is unclassified-only — the same deliberate mode as
the context-free KV forms, not an authorization bypass.

### Failures are reported, never folded into a result
Every entry point returns `QIHSE_PARALLEL_OK` (0) or a negative code
(`QIHSE_PARALLEL_ERR_ARGS`, `_UNSUPPORTED`, `_THREAD`, `_NOMEM`, `_STORE`,
`_DATA`, `_NO_RESULT`, `_LIMIT`). A refusal exposes no partial result, so a
caller can tell "the query ran and matched nothing" from "the query could not
run". `avg`/`min`/`max` over an empty table are `_NO_RESULT` rather than 0, and
a join in which either table has no row carrying the join column is `_NO_RESULT`
rather than "0 rows matched".

### API
```c
qihse_parallel_ctx_t* ctx = qihse_parallel_init(4);  // 4 workers
qihse_parallel_set_user(ctx, user);                  // borrow the principal
qihse_parallel_scan_t scan;
qihse_parallel_scan(ctx, kv, "users", &scan);
double count;
qihse_parallel_aggregate(ctx, kv, "users", "age", "count", &count);
qihse_parallel_join_t join;
qihse_parallel_join(ctx, kv, "orders", "users", "user_id", &join);
qihse_parallel_scan_free(&scan);
qihse_parallel_join_free(&join);
qihse_parallel_cleanup(ctx);
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
   report it; `qihse_repl_apply_wal()` replays the record into the store bound
   with `qihse_repl_set_store()` and advances the flush LSN, a retransmitted
   record is a no-op rather than applied twice, a truncated, checksum-broken,
   length-inconsistent or unknown-op record is refused with nothing applied and
   no LSN advanced, and a context with no bound store refuses rather than
   acknowledging. The `repl-apply-wal` gold workload asserts the replay
   independently.
4. **Refusals**: connecting to a closed port, an invalid address and a NULL host
   all fail and leave the context in `REPL_STATE_ERROR`.
5. **Read-replica pool**: add/remove, round-robin routing with wrap-around,
   active count, and health checking against unreachable addresses (all
   unhealthy, no route) and against a live listener (healthy, routable).
6. **Pooler**: config defaults and round-trip, backend add/remove/count, pooling
   modes, admin-console parse and execute (`SHOW VERSION`, `SHOW POOLS`,
   `PAUSE`), databases and users.

`tests/test_parallel_query.c` (run via `make test-parallel-query`) covers the
parallel scan, aggregate and hash join described above, including the refusal
codes, the inherited security context and a real `pthread_create()` failure
(`RLIMIT_NPROC` 0) reported as `QIHSE_PARALLEL_ERR_THREAD` with no partial
result. The speedup it measures is printed rather than asserted, because the
traversal is serial.

**Backup coverage.** `tests/test_incremental_export.c`
(`make test-incremental-export`) covers the change sequence and the whole
delta-export family, including `qihse_backup_incremental_user`'s container
(only the delta, no protected bytes for a low-clearance principal) and the
whole-store restore's deliberate refusal of a delta container.
`tests/test_federation_backup.c` covers the manifest-bound federation surface
and the whole-store argument gates; `tests/test_backup_auth.c`
(`make test-backup-auth`) covers the signed v3 container's refusal paths
(tampered data/signature, wrong signer, revoked signer, retired v1/v2, the
operator override's narrow scope, and the low-clearance negative test).
An earlier revision of this section said no test covered the
`src/tractable/qihse_backup.c` API; that was true then and is no longer.
