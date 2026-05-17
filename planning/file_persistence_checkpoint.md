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
`vectors.qtri`, followed by exact float32 reranking.

## Completed Persistence Work

- File-backed vector store snapshots are present under the native QIHSE tree.
- WAL replay covers unflushed add, delete, update, and upsert mutations.
- Mutation APIs persist through reopen and read-only mode rejects writes.
- Physical compaction preserves live rows, rewrites indexes/id maps, clears WAL,
  and rebuilds derived sidecars.
- `vectors.qtri` is generated as a derived trinary sidecar and stale/corrupt
  sidecars are detected without breaking default float32 search.
- QIHSE has been merged back to FRAMEWERX `master` and pushed through GitLab.

## Current PR-5 Trinary Slice

- `qihse_vector_db_search_trinary_candidates(...)` is exposed as an explicit
  opt-in API.
- `qihse_vector_query_t` now has:
  - `use_trinary_candidates`
  - `candidate_count`
- Default `qihse_vector_db_search(...)` remains float32 unless the query opts
  into trinary candidates.
- The trinary path requires a valid `vectors.qtri`, selects tryte candidates,
  then reranks against authoritative float32 vectors.
- Missing, corrupt, stale, or mismatched `vectors.qtri` makes the opt-in path
  fail clearly while default search continues normally.
- Deterministic benchmark datasets now include aligned cases where trinary
  candidate search works well and adversarial cases where sign-only trinary
  loses recall/order to float32 magnitude detail.

## Verification Snapshot

Run from `/home/john/FRAMEWERX/qihse`:

```bash
make test-persist
make test-trinary-codec
make bench-trinary-codec
make bench-trinary-db-candidate
make bench-trinary-search-path
```

Latest local result: all targets passed.

The search-path benchmark currently reports perfect recall/order on `aligned`,
`banded`, and `weighted`, and intentionally reports poor recall/order on
`magnitude_skew` and `near_tie`. Those hard datasets are useful because they
show where pure sign matching is insufficient without larger candidates,
weighted trits, magnitude bins, or a more expressive trinary scoring model.

## Next Slice

1. Make the opt-in trinary search path easier to use from native callers:
   document the API contract, expected `candidate_count`, and failure modes.
2. Add a benchmark sweep over multiple candidate counts so the recall/speed
   curve is visible instead of testing only one fixed candidate count.
3. Explore trinary improvements without replacing float32 yet:
   weighted trits, magnitude buckets, ternary-plus-scale rows, or per-dimension
   learned weights.
4. Continue file persistence breadth:
   manifest publication hardening, more crash-recovery fixtures, and cleanup of
   legacy subsystem-shaped layout as QIHSE becomes a naturally integrated native
   component.
