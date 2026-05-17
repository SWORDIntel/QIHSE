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

## Remaining Benchmark Workflow Work

1. Add a larger SIFT-style workload using `fvecs` and `ivecs` once local data
   is available.
2. Tune default trinary candidate pools only after the VXUG sample and a larger
   SIFT-style workload both provide stable evidence.

## Workflow Check

`make check-upstream-workflow` reports whether the current QIHSE root is a
direct upstream checkout or an imported FRAMEWERX copy.
`make check-upstream-workflow-strict` adds the upstream-owner gate (`--strict-upstream`)
and is useful before opening upstream PRs from a local workspace.
