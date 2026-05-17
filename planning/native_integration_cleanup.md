# QIHSE Native Integration Cleanup Plan

Date: 2026-05-17
Branch: `master`
Scope: planning and repository metadata inspection only; no production C or test edits.

Status note: QIHSE source canonicalization points active development and runtime
documentation at the top-level `qihse/` tree. Mentions of `native/qihse/` and
`SWORDIntel_QIHSE/qihse/` below are intentionally historical, provenance, or
transition-fallback references unless explicitly called out as remaining work.

## Integration Direction

QIHSE is a native engine that lives inside this repository as source code, not a
FrameworkX-dependent subsystem. FRAMEWERX can call it through bindings, worker
bridges, or state adapters, but FRAMEWERX should not define QIHSE's native
layout, persistence contract, file format, build rules, or runtime lifecycle.

The useful NOT_STISLA work should remain integrated into QIHSE where it serves
QIHSE's native search model. In the current tree, that means retaining the
NOT_STISLA-derived anchor-search code under `qihse/algorithms/` and continuing
to use it as an internal native algorithm path. Do not resurrect `not_stisla`
as an independent top-level subsystem for QIHSE work.

## Current Duplication Found

- `qihse/` is the active native QIHSE tree. It contains the current persistence
  work, trinary codec/search-path files, `qihse/planning/file_persistence_checkpoint.md`,
  and NOT_STISLA-derived anchor search under `qihse/algorithms/`.
- `native/qihse/` is a second QIHSE-shaped tree. It is missing newer active-tree
  pieces including `qihse/persistence/`, `qihse/codecs/`, trinary benchmark
  files, and `qihse/algorithms/qihse_anchor_search.*`.
- `SWORDIntel_QIHSE/qihse/` is a third QIHSE-shaped tree. It is close to the
  active tree but still diverges in the Makefile, vector DB, persistence store,
  codec files, and persistence tests. It also carries local build artifacts.
- `SWORDIntel_QIHSE/plans/` contains older persistence planning docs that still
  point at `/home/john/FRAMEWERX/SWORDIntel_QIHSE`; the active continuation docs
  now belong under `qihse/planning/`.
- `native/not_stisla/` remains as an independent subtree with its own workflow,
  source, binaries, benchmarks, archives, and benchmark result dumps. For QIHSE,
  the intended useful piece is already represented by `qihse/algorithms/qihse_anchor_search.*`.
- `SWORDIntel_QIHSE/not_stisla.zip` and `native/not_stisla/NOT_STISLA.zip` are
  archive-shaped copies that should be treated as provenance or removable
  baggage after source provenance is documented.
- Build outputs are present inside source-like trees, including `libqihse.so`,
  `qihse_hetero.h.gch`, root-level ISA test executables, and generated test
  binaries. These make duplication harder to reason about because source,
  generated objects, and stale mirrors are mixed together.

## Cleanup Checklist

1. Declare `qihse/` the only active native QIHSE source root in repository
   docs and build metadata. References to `SWORDIntel_QIHSE/qihse` or
   `native/qihse` should become historical/provenance notes, not build inputs.
2. Diff `qihse/` against `SWORDIntel_QIHSE/qihse/` and `native/qihse/` one last
   time and classify every difference as active source, stale source, docs,
   generated artifact, or provenance-only material.
3. Move any still-useful non-code documentation from `SWORDIntel_QIHSE/plans/`
   into `qihse/planning/`, updating paths from `/home/john/FRAMEWERX/SWORDIntel_QIHSE`
   to `/home/john/FRAMEWERX/qihse` or relative paths.
4. Keep the NOT_STISLA-derived anchor-search implementation in
   `qihse/algorithms/` and document its provenance there. QIHSE callers should
   use QIHSE APIs; they should not depend on a sibling `not_stisla` library or
   folder.
5. Audit Python and FRAMEWERX adapter references for hardcoded QIHSE paths.
   They may discover or load native QIHSE, but they should not treat
   `FRAMEWERX_ROOT`, `SWORDIntel_QIHSE`, or `native/qihse` as part of QIHSE's
   native persistence contract.
6. Prepare a repository-metadata cleanup that ignores or removes generated
   native artifacts from source trees: `*.so`, `*.o`, `*.gch`, root-level
   `test_*` executables, generated test binaries, and `__pycache__/`.
7. After provenance and docs are captured, plan a deletion-only cleanup for
   stale mirrors: `SWORDIntel_QIHSE/qihse/` and `native/qihse/`. Do this in a
   dedicated change after confirming no build scripts, docs, or adapters still
   read them.
8. Decide the fate of independent NOT_STISLA material separately from QIHSE:
   either archive it as external provenance outside the active source layout or
   reduce it to a small provenance note plus the integrated QIHSE algorithm
   files. Do not keep it as a parallel runtime dependency for QIHSE.
9. Update top-level repository guidance after cleanup so the native-backend
   section points to the actual active QIHSE location and explicitly states
   that QIHSE is native and FRAMEWERX-adapted, not FRAMEWERX-owned.
10. Run native QIHSE verification from `qihse/` after any later delete/move
    pass: at minimum `make test-persist`, `make test-trinary-codec`, and the
    trinary search-path benchmarks listed in `file_persistence_checkpoint.md`.

## Metadata/Docs Slice Findings

Date: 2026-05-17

- Added root `.gitignore` coverage for generated QIHSE native artifacts that
  were missing from the repository metadata: precompiled headers (`*.gch`),
  root-level QIHSE `test_*` executables while preserving `test_*.c` sources,
  generated `qihse/tests/qihse_*_test` binaries while preserving their `.c`
  sources, stale mirror equivalents under `SWORDIntel_QIHSE/qihse/` and
  `native/qihse/`, and generated `native/not_stisla/test_*` binaries while
  preserving `native/not_stisla/tests/test_*.c` sources.
- Existing global rules already cover shared libraries, object files, static
  archives, dynamic libraries, Windows binaries, Python bytecode, model
  caches, and `native/llama-cpp-turboquant/build/`.
- The ignore additions are forward-looking only for files already tracked by
  Git. A later cleanup should remove generated artifacts from the index without
  deleting source trees.
- The old `SWORDIntel_QIHSE/plans/` material was summarized into
  `qihse/planning/persistence_plan_migration.md`. The current active
  persistence checkpoint remains `qihse/planning/file_persistence_checkpoint.md`.

Tracked generated/stale artifact cleanup candidates found during this slice:

- `qihse/qihse_hetero.h.gch`
- `qihse/test_all_isa`
- `qihse/test_amx_only`
- `qihse/test_avx2_only`
- `qihse/test_avx2_only_simple`
- `qihse/test_avx512_direct`
- `qihse/test_direct_execution`
- `qihse/test_simple_exec`
- `qihse/test_vnni_bench`
- `qihse/test_vnni_only`
- `qihse/tests/qihse_trinary_codec_test`
- `native/qihse/qihse_hetero.h.gch`
- `native/qihse/test_all_isa`
- `native/qihse/test_amx_only`
- `native/qihse/test_avx2_only`
- `native/qihse/test_avx2_only_simple`
- `native/qihse/test_avx512_direct`
- `native/qihse/test_direct_execution`
- `native/qihse/test_simple_exec`
- `native/qihse/test_vnni_bench`
- `native/qihse/test_vnni_only`
- `SWORDIntel_QIHSE/qihse/qihse_hetero.h.gch`
- `SWORDIntel_QIHSE/qihse/test_all_isa`
- `SWORDIntel_QIHSE/qihse/test_amx_only`
- `SWORDIntel_QIHSE/qihse/test_avx2_only`
- `SWORDIntel_QIHSE/qihse/test_avx2_only_simple`
- `SWORDIntel_QIHSE/qihse/test_avx512_direct`
- `SWORDIntel_QIHSE/qihse/test_direct_execution`
- `SWORDIntel_QIHSE/qihse/test_simple_exec`
- `SWORDIntel_QIHSE/qihse/test_vnni_bench`
- `SWORDIntel_QIHSE/qihse/test_vnni_only`
- `native/not_stisla/test_auto_backend`
- `native/not_stisla/test_avx2_fma`
- `native/not_stisla/test_enhanced`
- `native/not_stisla/test_fortran_backend`
- `native/not_stisla/test_telemetry_processor_perf`

## Index-Only Generated Artifact Cleanup

Date: 2026-05-17

Removed the tracked generated native artifacts listed above from the Git index
with `git rm --cached`, leaving the working-tree files on disk where possible:

- `qihse/qihse_hetero.h.gch`
- `qihse/test_all_isa`
- `qihse/test_amx_only`
- `qihse/test_avx2_only`
- `qihse/test_avx2_only_simple`
- `qihse/test_avx512_direct`
- `qihse/test_direct_execution`
- `qihse/test_simple_exec`
- `qihse/test_vnni_bench`
- `qihse/test_vnni_only`
- `qihse/tests/qihse_trinary_codec_test`
- `native/qihse/qihse_hetero.h.gch`
- `native/qihse/test_all_isa`
- `native/qihse/test_amx_only`
- `native/qihse/test_avx2_only`
- `native/qihse/test_avx2_only_simple`
- `native/qihse/test_avx512_direct`
- `native/qihse/test_direct_execution`
- `native/qihse/test_simple_exec`
- `native/qihse/test_vnni_bench`
- `native/qihse/test_vnni_only`
- `SWORDIntel_QIHSE/qihse/qihse_hetero.h.gch`
- `SWORDIntel_QIHSE/qihse/test_all_isa`
- `SWORDIntel_QIHSE/qihse/test_amx_only`
- `SWORDIntel_QIHSE/qihse/test_avx2_only`
- `SWORDIntel_QIHSE/qihse/test_avx2_only_simple`
- `SWORDIntel_QIHSE/qihse/test_avx512_direct`
- `SWORDIntel_QIHSE/qihse/test_direct_execution`
- `SWORDIntel_QIHSE/qihse/test_simple_exec`
- `SWORDIntel_QIHSE/qihse/test_vnni_bench`
- `SWORDIntel_QIHSE/qihse/test_vnni_only`
- `native/not_stisla/test_auto_backend`
- `native/not_stisla/test_avx2_fma`
- `native/not_stisla/test_enhanced`
- `native/not_stisla/test_fortran_backend`
- `native/not_stisla/test_telemetry_processor_perf`

What remains:

- Generated files may still exist locally as ignored working-tree artifacts.
- Source files and stale mirror source trees remain untouched. Python runtime
  loaders have been canonicalized onto the active `qihse/` root.
- Stale mirror deletion and any runtime path audit remain later, dedicated
  cleanup passes.

## Runtime Loader Canonicalization

Date: 2026-05-17

FRAMEWERX runtime QIHSE loading now resolves the active top-level
`qihse/libqihse.so` first through `src/framewerx/state/qihse_paths.py`.
The legacy `native/qihse/libqihse.so` path is no longer a runtime fallback. It
is not an active source root or a build input for new docs/tests/config.

Updated runtime/config/test surfaces include:

- `fw_launcher.py`
- `autoresearch.sh`
- `src/framewerx/api/server.py`
- `src/framewerx/artifacts/hashing.py`
- `src/framewerx/cli/main.py`
- `src/framewerx/hardware/discovery.py`
- `src/framewerx/state/db.py`
- `src/framewerx/state/qihse_wrapper.py`
- `src/framewerx/workers/embedding_worker.py`
- direct QIHSE path assumptions in `tests/`

The remaining independent NOT_STISLA Python backend still intentionally points
at `native/not_stisla/libnot_stisla.so` for exploit/CVSS index acceleration.
Do not combine that cleanup with QIHSE stale mirror deletion.

Untracked generated/stale artifacts observed and already covered by existing
ignore rules:

- `qihse/libqihse.so`
- `native/qihse/libqihse.so`
- `SWORDIntel_QIHSE/qihse/libqihse.so`
- `qihse/tests/qihse_vector_db_persistence_test` when built by
  `make test-persist`

## Docs/Tests/Config Stale-Root Follow-Through

Date: 2026-05-17

Searched the allowed docs/config/test surfaces for stale QIHSE roots after
canonicalization: root guidance (`AGENTS.md`, `GEMINI.md`, `README.md`),
QIHSE README/docs, `docs/`, `scripts/`, tracked `tests/`, `qihse/planning/`,
and autoresearch documentation excluding generated reports.

No active stale references remain in tracked tests, root docs, QIHSE docs, or
autoresearch docs. The only remaining allowed-scope hits are in this planning
file and `qihse/planning/file_persistence_checkpoint.md`, where they are
intentional historical/provenance notes.

A generated autoresearch report,
`redteam/autoresearch/reports/TIER2_SELF_IMPROVEMENT_LATEST.json`, still quotes
an older `search_backend.py` docstring containing `$BUGBOUNTY_ROOT/../QIHSE/...`
paths. The source docstring has already been canonicalized to `qihse/` and
`native/not_stisla/`, so the report is preserved as generated historical output.

## Stale Mirror Root Removal

Date: 2026-05-17

Removed the stale QIHSE mirror roots from Git and the working tree:

- `SWORDIntel_QIHSE/qihse/`
- `native/qihse/`

Pre-removal reference audit:

- `rg` found no active FRAMEWERX runtime or test references to
  `SWORDIntel_QIHSE/qihse` or `native/qihse` under `src/`, `tests/`,
  `fw_launcher.py`, `autoresearch.sh`, or active `qihse/` files outside
  planning notes.
- The only non-planning sibling-script hit was
  `SWORDIntel_QIHSE/scripts/verify_fallback.sh`, which uses a relative
  `qihse/` path inside the stale `SWORDIntel_QIHSE` area. It was left untouched
  because this cleanup was deletion-only for the mirror roots.
- Top-level `qihse/` and `native/not_stisla/` were left untouched.

## Recommended Next Sequence

1. Keep generated report snapshots as provenance unless regenerating the
   autoresearch report set is part of a dedicated reporting pass.
2. NOT_STISLA cleanup: keep integrated anchor-search code under QIHSE, preserve
   provenance notes, and remove independent subsystem expectations from QIHSE
   docs and build instructions.

## Non-Goals For This Pass

- No file deletion.
- No production C edits.
- No test edits.
- No change to QIHSE persistence or trinary behavior.
