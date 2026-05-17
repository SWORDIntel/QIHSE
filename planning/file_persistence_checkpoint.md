# QIHSE File Persistence Checkpoint

Date: 2026-05-17
Branch: `master`
Remote target: `gitlab/master`

## Current Direction

QIHSE is being treated as its own native program inside the merged FRAMEWERX tree.
The database layer is moving from in-memory-only behavior to file-backed
persistence across vectors, indexes, id maps, WAL replay, compaction, and derived
sidecars.

The trinary path remains active. It is not replacing authoritative float32
storage yet; it is currently an opt-in candidate generator backed by
`vectors.qtri` and, for the magnitude-aware path, `vectors.qmag`, followed by
exact float32 reranking.

## Completed Persistence Work

- File-backed vector store snapshots are present under the native QIHSE tree.
- WAL replay covers unflushed add, delete, update, and upsert mutations.
- Mutation APIs persist through reopen and read-only mode rejects writes.
- Physical compaction preserves live rows, rewrites indexes/id maps, clears WAL,
  and rebuilds derived sidecars.
- `vectors.qtri` is generated as a derived trinary sidecar and stale/corrupt
  sidecars are detected without breaking default float32 search.
- `vectors.qmag` is generated as a derived row-magnitude sidecar and is tracked
  independently from `vectors.qtri` in manifest stats/status.
- Default float32 search tolerates missing/corrupt qmag; the explicit
  magnitude-backed trinary query mode fails clearly when qmag is unavailable.
- The native caller contract for trinary query modes is documented in
  `qihse/qihse_vector_db.h`.
- The magnitude benchmark path now exercises the persisted
  `QIHSE_VDB_QUERY_TRINARY_MAGNITUDE` query mode instead of the older
  in-process qmag prototype selector.
- Explicit trinary modes now use a conservative candidate-pool resolver instead
  of one fixed `top_k * 8` fallback.
- Manifest/index loading rejects impossible snapshot metadata earlier,
  including malformed sidecar flags, mismatched qtri/qmag shapes, vector-byte
  inconsistencies, and invalid index row bounds.
- Checkpoint boundary coverage now verifies that a published snapshot clears
  dirty state, truncates `wal.qwal`, and reopens read-only without replaying old
  WAL records.
- Native integration cleanup is tracked in
  `qihse/planning/native_integration_cleanup.md`.
- Historical `SWORDIntel_QIHSE/plans/` material has been summarized into
  `qihse/planning/persistence_plan_migration.md`; the active checkpoint remains
  this file.
- Root `.gitignore` now covers generated QIHSE/native test executables and
  precompiled headers going forward. Already tracked generated artifacts still
  need an index-only cleanup pass.
- QIHSE has been merged back to FRAMEWERX `master` and pushed through GitLab.

## Current PR-5 Trinary Slice

- `qihse_vector_db_search_trinary_candidates(...)` is exposed as an explicit
  opt-in API.
- `qihse_vector_query_t` now has:
  - `use_trinary_candidates`
  - `candidate_count`
  - `query_mode`
  - `candidate_pool_size`
- Default `qihse_vector_db_search(...)` remains float32 unless the query opts
  into trinary candidates.
- `query_mode == QIHSE_VDB_QUERY_FLOAT32` is the default, including
  zero-initialized queries, and ignores qtri/qmag availability.
- The legacy `use_trinary_candidates` path remains scalar qtri-only and uses
  `candidate_count` exactly as supplied; callers must pass
  `candidate_count >= top_k`.
- `QIHSE_VDB_QUERY_TRINARY_SCALAR` uses `candidate_pool_size` when non-zero,
  then `candidate_count`, then an internal default based on mode, `top_k`,
  vector dimensions, and live/physical row density.
- The trinary path requires a valid `vectors.qtri`, selects tryte candidates,
  then reranks against authoritative float32 vectors.
- Missing, corrupt, stale, or mismatched `vectors.qtri` makes explicit trinary
  paths fail clearly while default search continues normally.
- qtri failure errno contract: absent -> `ENOENT`, stale/mismatched -> `ESTALE`
  when available or `EINVAL`, corrupt -> `EINVAL`.
- Deterministic benchmark datasets now include aligned cases where trinary
  candidate search works well and adversarial cases where sign-only trinary
  loses recall/order to float32 magnitude detail.

## Current PR-6 Magnitude Slice

- `vectors.qmag` is persisted as one unsigned magnitude bucket byte per
  vector dimension.
- Manifest format v2 stores qmag generation, row bytes, row count, CRC, and
  flags while still accepting the older manifest without qmag fields.
- Flush, close, compact, truncate, load, stats, and destroy paths now carry the
  qmag cache/sidecar lifecycle.
- `QIHSE_VDB_QUERY_TRINARY_MAGNITUDE` selects candidates with
  `query_sign * row_sign * query_weight * row_bucket`, then reranks the chosen
  candidates with authoritative float32 cosine similarity.
- `QIHSE_VDB_QUERY_TRINARY_MAGNITUDE` uses the same candidate-pool resolver as
  scalar query mode and caps the pool to total vectors.
- Magnitude mode requires both valid `vectors.qtri` and valid `vectors.qmag`.
  qmag absence reports `ENODATA` when available or `ENOENT`; stale reports
  `ESTALE` when available or `EINVAL`; corrupt reports `EINVAL`.
- The legacy `use_trinary_candidates` scalar path remains backward-compatible.

## Verification Snapshot

Run from `/home/john/FRAMEWERX/qihse`:

```bash
make test-persist
make test-trinary-codec
make bench-trinary-codec
make bench-trinary-db-candidate
make bench-trinary-search-path
make bench-trinary-search-sweep
make bench-trinary-weighted-sweep
make bench-trinary-magnitude-sweep
```

Latest local result in this slice: all listed targets passed after the qmag
integration.

Latest focused result after candidate-policy/manifest-hardening slice:
`make test-persist`, `make bench-trinary-db-candidate`, and
`make bench-trinary-magnitude-sweep` passed.

Latest focused result after checkpoint/metadata cleanup slice:
`make test-persist` passed with the new checkpoint publication fixture.

The search-path benchmark currently reports perfect recall/order on `aligned`,
`banded`, and `weighted`, and intentionally reports poor recall/order on
`magnitude_skew` and `near_tie`. Those hard datasets are useful because they
show where pure sign matching is insufficient without larger candidates,
weighted trits, magnitude bins, or a more expressive trinary scoring model.

`bench-trinary-search-sweep` reruns the persisted trinary search-path benchmark
with increasing candidate counts. It is the current tool for deciding whether a
dataset needs wider candidate selection, a better trinary score, or both. The
first sweep showed:

- `aligned` and `banded`: full recall/order at `top_k` candidates.
- `weighted`: full recall/order at 64 candidates.
- `magnitude_skew` and `near_tie`: full recall/order at 128 candidates, but
  slower than float32 on the current scalar trinary selector.

`bench-trinary-weighted-sweep` uses the same `vectors.qtri` sidecar but weights
signed-trit scores by query magnitude. That preserves the current file format
and is useful for proving what the sidecar can and cannot express. The first
weighted sweep did not improve the hard `magnitude_skew` or `near_tie` cases:
query-side weights alone cannot distinguish rows that share the same signs but
have different row-side magnitudes. The next trinary improvement should add a
row-side magnitude signal, such as magnitude buckets, ternary-plus-scale rows,
or learned per-row/per-dimension weights.

`bench-trinary-magnitude-sweep` now exercises the real file-backed qmag query
mode through `qihse_vector_db_search()` with
`QIHSE_VDB_QUERY_TRINARY_MAGNITUDE`. Its output marks that path as
`persisted_qmag:qihse_vector_db_search`, making it distinct from the scalar and
weighted prototype qtri selectors.

## Next Slice

1. Continue file persistence breadth with crash-recovery fixtures that simulate
   interrupted manifest publication and authoritative-file corruption after a
   valid snapshot exists.
2. Canonicalize runtime QIHSE loading onto the active `qihse/` root. Current
   blockers for deleting `native/qihse/` include `fw_launcher.py`,
   `src/framewerx/api/server.py`, `src/framewerx/state/qihse_wrapper.py`,
   `src/framewerx/state/db.py`, `src/framewerx/workers/embedding_worker.py`,
   `src/framewerx/hardware/discovery.py`, and
   `src/framewerx/artifacts/hashing.py`.
3. Do an index-only cleanup for tracked generated native artifacts listed in
   `qihse/planning/native_integration_cleanup.md`; do not delete source trees
   in the same change.
4. Keep independent `native/not_stisla/` cleanup separate from QIHSE deletion:
   FRAMEWERX exploit/CVSS paths still load `native/not_stisla/libnot_stisla.so`
   through `src/framewerx/evaluation/search_backend.py`.
5. Use fresh sweep results to tune the candidate-pool resolver once more real
   datasets exist; the current defaults are conservative and mode-aware.
