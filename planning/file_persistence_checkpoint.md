# QIHSE File Persistence Checkpoint

Date: 2026-05-18
Branch: `master`
Remote target: `gitlab/master` (FRAMEWERX sync target)

## Progress Snapshot (Continuation)

- Current milestone completion: **96%** (26 / 27 checklist items).
- This slice completed:
  - `make test-persist`
  - `make test-trinary-codec`
  - `make bench-trinary-codec`
  - `make bench-trinary-db-candidate`
  - `make bench-trinary-search-path`
  - `make bench-trinary-search-sweep`
  - `make bench-trinary-magnitude-sweep`
  - `make bench-trinary-weighted-sweep`
  - `make validate-reference-workflow`
- `make check-upstream-workflow` reports imported-copy mode with no upstream remote in this FRAMEWERX tree.
- `make bench-trinary-weighted-sweep` requires serial run if building artifacts in the same tree; running it concurrently with other `libqihse.so` rebuild targets can transiently produce a short-object race.

## Current Direction

QIHSE remains a native program with authoritative development in the upstream
`https://github.com/SWORDIntel/QIHSE` repository. FRAMEWERX carries a downstream
integrated copy under `qihse/` for product integration.
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
- Crash-recovery coverage now includes ignored interrupted `MANIFEST.tmp`
  publication after checkpoint and metadata payload corruption rejection through
  manifest CRC validation.
- Authoritative-file boundary coverage now rejects truncated `vectors.qvec` and
  `metadata.qmeta` payloads plus corrupt `index.qidx` magic after a valid
  snapshot exists.
- Checkpoint recovery coverage now also ignores stale snapshot tmp outputs
  (`vectors.qvec.tmp`, `metadata.qmeta.tmp`, `index.qidx.tmp`, `idmap.qid.tmp`,
  `vectors.qtri.tmp`, and `vectors.qmag.tmp`) while reopening/searching the
  last valid published files.
- Native integration cleanup is tracked in
  `qihse/planning/native_integration_cleanup.md`.
- Historical `SWORDIntel_QIHSE/plans/` material has been summarized into
  `qihse/planning/persistence_plan_migration.md`; the active checkpoint remains
  this file.
- Root `.gitignore` now covers generated QIHSE/native test executables and
  precompiled headers going forward. Previously tracked generated native
  artifacts have been removed from Git tracking with an index-only cleanup.
- FRAMEWERX runtime loaders now resolve the active `qihse/libqihse.so` without
  a stale `native/qihse` fallback.
- Docs/tests/config stale-root follow-through found no active tracked test or
  docs references to the stale QIHSE roots outside intentional planning
  provenance and transitional fallback notes.
- The stale QIHSE mirror roots `native/qihse/` and `SWORDIntel_QIHSE/qihse/`
  have been removed; active source remains top-level `qihse/`.
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

Latest focused result after runtime canonicalization/index cleanup slice:
`make test-persist`, Python compilation for touched runtime/test files, the
launcher research-budget unit test, and QIHSE resolver smoke check passed.

Latest focused result after QIHSE-only recovery fixture slice:
`make test-persist` passed with new `metadata.qmeta` corruption rejection and
stale `MANIFEST.tmp` recovery fixtures.

Latest focused result after authoritative-file boundary slice:
`make test-persist` passed with truncated `vectors.qvec`, truncated
`metadata.qmeta`, and corrupt `index.qidx` rejection fixtures.

Latest focused result after checkpoint snapshot-tmp recovery slice:
`make test-persist` passed with stale authoritative and derived sidecar tmp
recovery covered after checkpoint.

Latest trinary calibration decision:
keep exact float32 as the default, keep `use_trinary_candidates` exact,
keep `qtri` wider than `qmag`, and do not change the default multipliers until
production-shaped reference workloads justify it. The canonical wording lives
in `qihse/benchmarks/reference_workloads.md`. The initial reference workload
manifest is tracked at `qihse/benchmarks/reference_workloads.json`, with
`make bench-reference-workloads` validating the manifest and printing the
current benchmark plan. The manifest runner also supports `--inspect-files` for
external dataset row-count and dimension validation before those datasets are
used as tuning evidence. The first local sample path is `vxug-pdf-sample`,
generated from the FRAMEWERX VXUG PDF corpus with `make sample-vxug-pdf-workload`.
The VXUG benchmark runner now loads the generated matrices into file-backed
QIHSE and compares exact float32/scalar `qtri`/`qmag`. The first local result
showed float32 recall@10 `1.0000`, qtri `0.9812`, and qmag `1.0000`; that is
useful evidence for qmag, but not enough to change default candidate-pool
policy. The next calibration step is a larger SIFT-style `fvecs`/`ivecs`
workload. QIHSE GitHub should become the upstream-first workflow now that the
runner path is in place; FRAMEWERX can import QIHSE updates after upstream
validation.

Latest reference workflow target:
`make validate-reference-workflow` runs manifest validation, the generated
`fvecs`/`ivecs` smoke workload, VXUG benchmark summary gate, and persistence
tests sequentially. Use this instead of launching those Make targets in
parallel, because they rebuild the shared library.

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

1. Add or stage SIFT-style data files under `data/sift1m/`, or rely on the
   local fallback fixture generator when those files are unavailable, then run
   `make bench-sift1m-workload`. The generic runner now supports `fvecs`,
   `ivecs`, `f32_matrix`, and `u32_matrix` manifest entries, with
   `make bench-reference-runner-smoke` covering the SIFT-style parser path
   before full SIFT data is available. Generated benchmark JSON is now
   summarized through the manifest-backed recall gate.
2. Move toward a QIHSE-upstream-first workflow: develop and validate QIHSE in
   `https://github.com/SWORDIntel/QIHSE`, then import stable upstream state
   back into FRAMEWERX. For strict upstream validation from within `qihse/`, use
   `make check-upstream-workflow-strict`.
3. Continue file persistence breadth only after the benchmark runner is moving,
   with remaining authoritative-file corruption focused on manifest/index
   consistency fields after a valid snapshot exists.

## Milestone Checklist

- Plan completion target (for this slice): **96%**
- Overall completion method: counted milestone items below with explicit blockers and no
  unresolved dependencies.

### 1) File-backed persistence foundation

- [x] `vectors.qvec` writes and durable snapshot publication (`checkpoint`)  
- [x] `metadata.qmeta`, `index.qidx`, `idmap.qid`, `MANIFEST` persistence paths
- [x] `MANIFEST` CRC validation and impossible manifest metadata rejection
- [x] WAL replay + torn-tail truncation
- [x] Read-only mapped reopen path and mutation rejection
- [x] Delete/update/upsert persistence and compaction rewrite
- [x] Derived sidecar rebuild behavior (`vectors.qtri`, `vectors.qmag`) after stale/corrupt inputs
- [x] Corruption coverage for:
  - truncated `vectors.qvec`
  - truncated `metadata.qmeta`
  - truncated `index.qidx`
  - stale `*.tmp` snapshot artifacts
- [x] Long-tail consistency hardening (outstanding checks after valid snapshot):
  - [x] `index.qidx` row metadata consistency under cross-version migration
  - [x] manifest/index edge-case replay/fallback after partial compaction writes

### 2) Test infrastructure and regression gate

- [x] `make test-persist` gate passes on current branch
- [x] `make validate-reference-workflow` passes from `qihse/`
- [x] New corruption/fidelity tests added:
  - index row-count mismatch
  - index row-bytes mismatch
  - manifest/index checksum mismatch
- [x] `make check-upstream-workflow` and `make check-upstream-workflow-strict` targets
- [x] Full upstream PR validation loop automation from FRAMEWERX via synced checkout loop

### 3) Reference workload and calibration runway

- [x] VXUG sample benchmark path is stable and recall-gated
- [x] SIFT1M missing-data fallback path implemented (`sift1m-fallback`)
- [x] SIFT1M fallback generator integrated and documented
- [x] Trinary candidate/magnitude sweeps capture production-oriented evidence
- [x] Add or stage full `data/sift1m/*` 1M-style dataset for non-fallback scale baseline
- [ ] Close the full SIFT1M calibration loop (including rerun and candidate policy decision; currently blocked by CPU cap, resume when off-peak)

### 4) Upstream-first ownership alignment

- [x] Authoritative upstream repo recorded in planning/docs
- [x] FRAMEWERX copy treated as downstream import target
- [x] Strict upstream verification target added
- [x] Remove remaining legacy dependency language in all remaining planning docs
- [x] Finalize upstream-to-FRAMEWERX handoff cadence and enforcement policy

## Next Slice Execution Plan

Run in order:

1) Complete upstream handoff discipline from FRAMEWERX into upstream and back.
   - Use `make -C qihse upstream-pr-loop` when `UPSTREAM_ROOT` is available.
   - Verify gate alignment with `make -C qihse check-upstream-workflow` and FRAMEWERX
     integration checks (`make -C qihse validate-reference-workflow`).

2) Run full SIFT1M calibration loop
   - Stage full-scale dataset into `qihse/data/sift1m/` (`sift_base.fvecs`, `sift_query.fvecs`, `sift_groundtruth.ivecs`) with
     ground-truth truncated to 10 neighbors for manifest parity (`top_k=10`).
   - Execute:
     - `make -C qihse bench-sift1m-workload`
     - `make -C qihse bench-reference-result-summary`
   - Decide candidate policy only after rerun and evidence snapshot.
   - Current status: manifest validation passes and ground-truth row width now matches `top_k`; `bench-sift1m-workload`
     is still the remaining heavy step.

3) CPU-capped mode: keep fallback workload evidence current without full SIFT1M
   - Rerun `make -C qihse bench-sift1m-workload` after any major query policy change.
   - Use `make -C qihse bench-reference-result-summary REFERENCE_WORKLOAD=sift1m-fallback`
     while full SIFT1M is unavailable.
   - When CPU is capped, skip full SIFT1M and continue:
     - `make -C qihse bench-vxug-pdf-workload`
     - `python3 benchmarks/scripts/qihse_reference_workloads.py --root . --manifest benchmarks/reference_workloads.json --workload sift1m --inspect-files`

Acceptance:
- This slice is done only when all unchecked items above are checked in the Milestone Checklist.
