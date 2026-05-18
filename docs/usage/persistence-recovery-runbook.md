# Persistence recovery and reopen runbook

Use this runbook whenever process restart, crash recovery, or corruption handling is involved.

## 1) Validate startup state

```c
qihse_vector_db_persistence_stats_t stats = {0};
if (!qihse_vector_db_get_persistence_stats(db, &stats)) {
    /* handle invalid/corrupt handle immediately */
}

if (stats.storage_mode == QIHSE_VDB_STORAGE_EPHEMERAL) {
    /* expected for in-memory-only workloads */
}
```

## 2) Default open flags by intent

- Warm start with durability: `QIHSE_VDB_OPEN_FILE_BACKED | QIHSE_VDB_OPEN_CREATE`
- Restart/read-only diagnostics: `QIHSE_VDB_OPEN_FILE_BACKED | QIHSE_VDB_OPEN_READ_ONLY`
- Memory-map replay-only path (read-only only): add `QIHSE_VDB_OPEN_MMAP`
- Rebuild from scratch: include `QIHSE_VDB_OPEN_TRUNCATE`

## 3) Open and check WAL replay outcomes

After `qihse_vector_db_open`, WAL replay is already applied internally.

```c
if (stats.wal_bytes_pending != 0u) {
    /* WAL had uncommitted changes. Open still replays them when valid. */
}

if (stats.wal_records_replayed > 0u) {
    /* Mutations were replayed from WAL; treat handle as changed state. */
}
```

## 4) Sidecar validity decision matrix

- Start in exact mode by default after restart:
  - `QIHSE_VDB_QUERY_FLOAT32`
- Enable fast-sidecar modes only when status is valid:
  - `QIHSE_VDB_TRINARY_VALID`
  - `QIHSE_VDB_MAGNITUDE_VALID`

If either status is stale/corrupt/absent:
- exact mode remains valid
- legacy `use_trinary_candidates` still requires `use_trinary_candidates=true` + explicit count
- explicit `QIHSE_VDB_QUERY_TRINARY_*` may fail when required sidecars are invalid

## 5) Corruption and partial-state recovery flow

When sidecars are missing, stale, or corrupt:

1. keep serving in exact mode;
2. run mutation repair operations if needed (delete/update/upsert);
3. call `qihse_vector_db_flush(db)` and `qihse_vector_db_checkpoint(db)`;
4. optionally `qihse_vector_db_compact(db)` for deterministic rewrite;
5. reopen and re-check stats.

```c
if (stats.trinary_status != QIHSE_VDB_TRINARY_VALID ||
    stats.magnitude_status != QIHSE_VDB_MAGNITUDE_VALID) {
    qihse_vector_db_flush(db);
    qihse_vector_db_checkpoint(db);
}
```

## 6) Safe shutdown sequence

```c
qihse_vector_db_persistence_stats_t final = {0};
qihse_vector_db_get_persistence_stats(db, &final);

if (final.needs_flush) {
    (void)qihse_vector_db_flush(db);      // flush WAL deltas
}
(void)qihse_vector_db_checkpoint(db);      // persist canonical snapshot
qihse_vector_db_close(db);                // safe destroy
```

This ensures the next startup observes a canonical snapshot and bounded recovery window.

