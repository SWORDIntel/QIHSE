# QIHSE Persistence Plan Migration Notes

Date: 2026-05-17
Source material: `SWORDIntel_QIHSE/plans/qihse_persistence_layer.md` and
`SWORDIntel_QIHSE/plans/qihse_persistence_pr0_pr1_enhancement.md`

## Migration Decision

The old `SWORDIntel_QIHSE/plans/` files should not remain the active planning
source because their resume commands and absolute paths point at
`/home/john/FRAMEWERX/SWORDIntel_QIHSE`. Their still-current technical content
is summarized here and should be read together with
`qihse/planning/file_persistence_checkpoint.md`, which is the current active
checkpoint.

Do not copy the old plans verbatim into future work. They contain completed
PR-0 through PR-3 details and pre-merge assumptions that are now historical.

## Still-Current Content

- QIHSE is a standalone native database engine. FRAMEWERX, Python wrappers,
  RAG, ingestion scripts, and external applications are clients only.
- `db_path` names a native QIHSE database directory and must not rely on a
  FRAMEWERX workspace layout, service lifecycle, or environment variable.
- Native C owns the storage format, WAL recovery behavior, indexing model,
  codec sidecars, and mutation semantics.
- `vectors.qvec` remains the authoritative float32 vector store. `vectors.qtri`
  and `vectors.qmag` are rebuildable derived sidecars used by explicit trinary
  query modes.
- Persistent files use explicit fixed-width formats and validation. New format
  fields should be versioned instead of persisting native C structs casually.
- Search result hydration must distinguish internal storage rows from external
  vector IDs. Sparse caller IDs must never index directly into vector or
  metadata arrays.
- File-backed copy, read-only mmap, WAL replay/truncation, snapshot flush,
  compaction, and read-only mutation rejection remain part of the native QIHSE
  contract.
- NOT_STISLA is not an active sibling runtime dependency for QIHSE. The useful
  anchor-search code is integrated under `qihse/algorithms/` and should remain
  behind QIHSE APIs.

## Historical Checkpoint Summary

The old plans record these completed or superseded milestones:

- PR-0 integrated NOT_STISLA-derived anchor search into native QIHSE.
- PR-1 made `qihse_vector_db_create(..., db_path)` create/open a durable
  file-backed database instead of a process-memory-only helper.
- PR-2 added ADD/COMMIT WAL records, previous-record offsets, committed-batch
  replay, and writable torn-tail truncation.
- PR-3 started read-only mmap for clean snapshots, covering vectors, metadata,
  id maps, and validated `index.qidx` rows.
- PR-4 implemented the public delete/update/upsert behavior, with mutation WAL
  record breadth and physical tombstone compaction called out as follow-up at
  the time.
- PR-5 started trinary candidate generation with exact float32 reranking.

Current status has moved beyond that checkpoint. Use
`file_persistence_checkpoint.md` for the latest verification targets and
remaining persistence/trinary work.

## Current Resume Commands

Run from the active source root:

```bash
cd /home/john/FRAMEWERX/qihse
make test-persist
make test-trinary-codec
make bench-trinary-codec
make bench-trinary-db-candidate
make bench-trinary-search-path
make bench-trinary-search-sweep
make bench-trinary-weighted-sweep
make bench-trinary-magnitude-sweep
```

Generated binaries from those targets belong outside source control. The root
`.gitignore` carries forward-looking coverage for QIHSE test executables,
precompiled headers, and NOT_STISLA test binaries; already tracked artifacts
need a later index cleanup before the ignore rules can take effect for them.
