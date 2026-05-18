# QIHSE Upstream Workflow

QIHSE is its own upstream program. The authoritative repository is:

`https://github.com/SWORDIntel/QIHSE`

FRAMEWERX carries an integrated copy under `qihse/`, but that copy is downstream
of upstream decisions and should only be updated from stable upstream changes.

## Active Workflow (QIHSE-first)

1. Make and validate QIHSE changes in `https://github.com/SWORDIntel/QIHSE`.
2. Verify against `qihse/`-level validation targets in the upstream working tree.
3. Push stable upstream changes to upstream master.
4. Import or cherry-pick upstream updates into FRAMEWERX when the file-based
   persistence work has stabilized.

## Upstream-to-FRAMEWERX Handoff Cadence

- Source-of-truth remains upstream. QIHSE feature, persistence, and storage changes
  start in `https://github.com/SWORDIntel/QIHSE` and land on upstream master first.
- FRAMEWERX integrates only committed upstream states. For each QIHSE-related
  FRAMEWERX merge, complete this order:
  1. validate on upstream (make/check gate + tests),
  2. push upstream PR,
  3. sync the validated state into FRAMEWERX,
  4. run FRAMEWERX-facing integration checks (`make validate-reference-workflow`).
- Before opening an upstream PR from a local upstream checkout, run
  `make check-upstream-workflow-strict` to enforce checkout ownership.
- FRAMEWERX can run local validation for convenience, but the strict gate is upstream
  only and must be used for upstream PR readiness.

## FRAMEWERX-aligned Validation

When you are iterating inside FRAMEWERX `qihse/`, run:

- `cd qihse`
- `make check-upstream-workflow` (or `make check` for the default)
- `make validate-reference-workflow`
- `make bench-reference-workloads`
- `make sample-vxug-pdf-workload` when the local VXUG PDF corpus is available
- `make bench-vxug-pdf-workload`
- persistence tests for storage-layer changes

For direct upstream validation from the subtree root, use:

```bash
make check-upstream-workflow-strict
```

This fails unless the checkout is an upstream root with a `SWORDIntel/QIHSE`
remote configured. Use it as a deliberate gate before tagging upstream PRs.

From FRAMEWERX, you can run the full handoff loop in one command:

```bash
export UPSTREAM_ROOT=~/some/upstream/qihse
cd /home/john/FRAMEWERX/qihse
make upstream-pr-loop
```

`make upstream-pr-loop` runs:

1. `make validate-reference-workflow` in FRAMEWERX `qihse/`
2. tracked-file sync from FRAMEWERX `qihse/` into the upstream checkout
3. `check-upstream-workflow --strict-upstream` in the upstream checkout
4. `make validate-reference-workflow` in the synced upstream checkout

If your upstream checkout does not already contain local reference artifacts
(`data/vxug_pdf_sample`, `data/sift1m/fallback`, and `data/text_embeddings`),
step 4 can fail before you can inspect it locally, which is a data-preparation
issue rather than a source-code issue.

After the loop is green, open the upstream PR from that checkout.

## Remaining Benchmark Workflow Work

1. SIFT-style `fvecs`/`ivecs` full-scale workload files are staged in `data/sift1m/`;
   complete and record the rerun decisioning using `bench-sift1m-workload`.
2. Tune default trinary candidate pools only after the VXUG sample and a larger
   SIFT-style workload both provide stable evidence.

## Workflow Check

`make check-upstream-workflow` reports whether the current QIHSE root is a
direct upstream checkout or an imported FRAMEWERX copy.
`make check-upstream-workflow-strict` adds the upstream-owner gate (`--strict-upstream`)
and is useful before opening upstream PRs from a local workspace.
