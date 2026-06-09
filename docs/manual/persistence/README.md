# File-Backed Trinary Persistence and Retrieval

## What is persisted
- `vectors.qtri` stores row-oriented trinary signatures generated from every committed vector.
- `vectors.qmag` stores row-wise magnitude data aligned to `vectors.qtri` rows.
- `manifest.bin` stores snapshot metadata (dimensions, row counts, flags, CRC).
- `vectors.wal` captures committed mutations between snapshots for crash-safe replay.

## Recommended persistence layout
- Database path: `./my-index/`
- Manifest + sidecars are created on first flush/checkpoint.
- Keep the whole directory durable (local SSD/NVMe or equivalent).

## How to implement file-backed write flow
1. Create/open a database with a real directory path.
   - Create: `qihse_vector_db_create(QIHSE_VECTOR_DB_INMEMORY, uma, "./my-index")`
   - Open existing: `qihse_vector_db_open(QIHSE_VECTOR_DB_INMEMORY, uma, QIHSE_VECTOR_DB_OPEN_READWRITE, "./my-index")`
2. Insert/update/delete vectors with normal APIs.
3. Check `qihse_vector_db_get_persistence_stats()` before shutdown.
   - If `needs_flush == true`, call `qihse_vector_db_flush(db)`.
4. Publish a durable snapshot with `qihse_vector_db_checkpoint(db)`.
5. Close with `qihse_vector_db_close(db)`.

`flush` writes the current WAL-backed snapshot candidate; `checkpoint` commits it
into durable sidecars and clears stale WAL windows.

## Read/recovery flow
1. Open the same path in read-write mode.
2. On startup, WAL is replayed when present and valid.
3. If `trinary_status`/`magnitude_status` are valid, search can use `qtri/qmag` candidates.
4. If trinary assets are stale/corrupt/missing, search falls back to exact float32.

## Basic query flow with persistence
- exact default remains authoritative: trinary/qmag are candidate selectors.
- `qmag` defaults can use adaptive pools based on active dimensions and top-k pressure.
- explicit pools (non-zero `candidate_pool_size`) keep behavior explicit and stable.

Example:
```c
qihse_vector_query_t query = {
    .query_vector = query_vec,
    .vector_dims = dims,
    .top_k = 10u,
    .query_mode = QIHSE_VDB_QUERY_TRINARY_MAGNITUDE,
    .similarity_threshold = 0.0f,
    .use_trinary_candidates = true,
    .candidate_pool_size = 0u,
    .include_vectors = true,
    .include_metadata = true,
};

qihse_vector_result_t out[10] = {0};
const int count = qihse_vector_db_search(db, &query, out, 10);
```

## Minimal runbook
- Use `make test-persist` for codec + snapshot/WAL recovery checks.
- Use `make validate-reference-workflow` for end-to-end persistence + benchmark
  gate execution.
