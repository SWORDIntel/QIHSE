# QIHSE Native Integration Cleanup Plan

Date: 2026-05-17
Branch: `master`
Scope: planning and repository metadata inspection only; no production C or test edits.

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

## Recommended Next Sequence

1. Metadata-only pass: add `.gitignore` coverage for native generated outputs
   and list currently tracked generated artifacts for removal in a later commit.
2. Documentation pass: fold still-current `SWORDIntel_QIHSE/plans/` content
   into `qihse/planning/` and retire the old absolute-path assumptions.
3. Reference audit: search build scripts, Python adapters, and docs for
   `SWORDIntel_QIHSE`, `native/qihse`, and direct `not_stisla` usage.
4. Source-root cleanup: remove or quarantine stale QIHSE mirror trees only after
   the reference audit is clean.
5. NOT_STISLA cleanup: keep integrated anchor-search code under QIHSE, preserve
   provenance notes, and remove independent subsystem expectations from QIHSE
   docs and build instructions.

## Non-Goals For This Pass

- No file deletion.
- No production C edits.
- No test edits.
- No change to QIHSE persistence or trinary behavior.
