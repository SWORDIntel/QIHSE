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
make bench-trinary-search-sweep
make bench-trinary-weighted-sweep
make bench-trinary-magnitude-sweep
```

Latest local result: all targets passed.

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

`bench-trinary-magnitude-sweep` prototypes that row-side signal without changing
the persisted store yet. It derives unsigned row magnitude buckets plus
predecoded signed trits from the loaded snapshot, then scores candidates as
`query_sign * row_sign * query_weight * row_bucket`. That proved the trinary
direction: `magnitude_skew` and `near_tie` reached full recall/order at
`top_k` candidates and beat float32 in the local benchmark. This should become
a real file-backed derived sidecar after the prototype is hardened.

## Next Slice

1. Make the opt-in trinary search path easier to use from native callers:
   document the API contract, expected `candidate_count`, and failure modes.
2. Use the candidate-count sweep to pick sane default candidate ratios per
   dataset shape instead of a single fixed value.
3. Promote the magnitude prototype into a persisted derived sidecar:
   compact row magnitude buckets plus predecoded signed trits, with manifest
   validation and rebuild behavior matching `vectors.qtri`.
4. Continue file persistence breadth:
   manifest publication hardening, more crash-recovery fixtures, and cleanup of
   legacy subsystem-shaped layout as QIHSE becomes a naturally integrated native
   component.
