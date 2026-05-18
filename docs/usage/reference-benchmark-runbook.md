# Reference benchmark and validation runbook

Use these commands for repeatable evidence in local integration and CI-like checks.

## Fast local validation

```bash
make test-persist
make bench-reference-runner-smoke
```

- `test-persist` runs the trinary codec + persistence regression suite.
- `bench-reference-runner-smoke` validates lightweight `fvecs`/`ivecs` smoke data.

## Full reference workflow

```bash
make validate-reference-workflow
```

This chain runs, in order:
1. manifest plan validation (`bench-reference-workloads`)
2. smoke parser benchmark (`bench-reference-runner-smoke`)
3. VXUG-derived PDF workload gate (`bench-vxug-pdf-workload`)
4. SIFT workflow gate (`bench-sift1m-workload`)
5. persistence and recovery checks (`test-persist`)

Run single-workload commands during tune-up:

```bash
make bench-reference-workload REFERENCE_WORKLOAD=sparse-active-256x16
make bench-reference-workload REFERENCE_WORKLOAD=sparse-active-768x32
```

## SIFT calibration paths

```bash
make calibrate-sift1m-workload
SIFT1M_CALIBRATION_SCOPE=full make calibrate-sift1m-workload
SIFT1M_CALIBRATION_SCOPE=fallback make calibrate-sift1m-workload
```

- `full` attempts a complete 1M-scale fixture when present.
- `fallback` uses deterministic local fallback fixture for off-peak smoke.

Regenerate staged fallback fixtures explicitly:

```bash
make bench-sift1m-fallback-data
python3 benchmarks/scripts/qihse_generate_sift1m_fixture.py --force
python3 benchmarks/scripts/qihse_generate_sparse_active_fixture.py --force
```

## What to read from outputs

- generated artifacts go to `results/` (typically ignored by git),
- mismatch counts in runner JSON should be zero for your required strict modes,
- `sift1m-fallback` and VXUG runs should be checked for any regression before you
  change candidate pool policy defaults.

