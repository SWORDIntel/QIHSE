# QIHSE Upstream Workflow

QIHSE is its own upstream program. The authoritative repository is:

`https://github.com/SWORDIntel/QIHSE`

FRAMEWERX can carry an integrated copy under `qihse/`, but that copy should be
treated as an import target, not the long-term owner of QIHSE design decisions.

## Current Bridge

The current bridge is FRAMEWERX-driven:

1. Make QIHSE changes under FRAMEWERX `qihse/`.
2. Split the subtree.
3. Push the split to `SWORDIntel/QIHSE`.

That is acceptable for the current migration window, but it should not become
the permanent workflow once the QIHSE benchmark runner and reference workload
pipeline stabilize.

## Target Workflow

1. Develop QIHSE changes directly in `SWORDIntel/QIHSE`.
2. Run QIHSE-local validation there:
   - `make bench-reference-workloads`
   - `make sample-vxug-pdf-workload` when the FRAMEWERX VXUG PDF corpus is
     available locally
   - persistence tests for storage-layer changes
   - `make bench-vxug-pdf-workload`
3. Record benchmark summaries in QIHSE docs only after the runner is
   repeatable and result files are generated outside git by default.
4. Import the updated QIHSE state back into FRAMEWERX after upstream is stable.

## Remaining Benchmark Workflow Work

1. Record repeatable VXUG runner summaries while keeping generated result
   artifacts outside git by default.
2. Record recall@10, latency, selected candidates, rerank count, and mismatch
   details in a generated result artifact.
3. Add a larger SIFT-style workload using `fvecs` and `ivecs` once local data
   is available.
4. Tune default trinary candidate pools only after the VXUG sample and a larger
   SIFT-style workload both provide stable evidence.
