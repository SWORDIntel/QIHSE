# QIHSE Finalization Plan

## 1) Scope
This plan finalizes two required areas from the repository documentation:
- Upstream-first workflow
- Persistence model and deployment/state persistence obligations

## 2) Authoritative source references
- Upstream-first workflow statement: [docs/benchmarks/reference_workloads.md:46-48](/fast/QIHSE/docs/benchmarks/reference_workloads.md)
  - "QIHSE should move to an upstream-first workflow: develop and validate QIHSE in https://github.com/SWORDIntel/QIHSE, then import stable upstream state back into FRAMEWERX."

- Validation/persistence workflow: [docs/benchmarks/reference_workloads.md:13-15](/fast/QIHSE/docs/benchmarks/reference_workloads.md)
  - `make validate-reference-workflow` includes manifest plan, smoke checks, VXUG benchmark gate, and persistence tests.

- Persistent filesystem mounts and data paths: [docs/deployment/README.md:392-423](/fast/QIHSE/docs/deployment/README.md)
  - `/var/lib/qihse` and `/var/log/qihse` are mounted, with `persistentVolumeClaim` using `claimName: qihse-data`.

- Persistent storage sizing for Helm install: [docs/architecture/qihse_whitepaper_v1.0.md:1285-1289](/fast/QIHSE/docs/architecture/qihse_whitepaper_v1.0.md)
  - Helm customization includes `--set persistence.size=100Gi`.

- In-memory persistence/retention model: [docs/architecture/phase3_optimizer.md:265](/fast/QIHSE/docs/architecture/phase3_optimizer.md)
  - Telemetry system explicitly includes `qihse_telemetry_storage_t storage` under storage and persistence concerns.

- Memory tiering + state persistence intent: [docs/architecture/phase2_memory_planner.md:39-42,59](/fast/QIHSE/docs/architecture/phase2_memory_planner.md)
  - Tier-2 entanglement fabric includes full problem state + replica storage.
  - Buffer metadata includes `qihse_memory_flags_t flags; // Access patterns, persistence`.

## 3) Finalization checklist
- [x] Upstream-first workflow captured and referenced.
- [x] Persistence requirements captured:
  - command-level validation gate (including persistence tests),
  - runtime persistence mount points / PVC path,
  - explicit persistence size example, and
  - telemetry/state persistence intent.
- [x] Required docs locations recorded with line references.
- [ ] Optional cleanup:
  - Add any missing cross-links or a short “known environment limits” note for deployment path differences.

## 4) Verification commands used
- `git status --short`
- `git pull --ff-only`
- `git log -1 --oneline`
- `rg -n "upstream-first|persistentVolumeClaim|persistence.size|validate-reference-workflow|persistence" docs/`
- `rg -n "persistence|Upstream|Persistence" docs/benchmarks/reference_workloads.md docs/deployment/README.md docs/architecture/phase2_memory_planner.md docs/architecture/phase3_optimizer.md docs/architecture/qihse_whitepaper_v1.0.md`

## 5) Closure rule
After this document is committed, finalization is considered complete when this file is merged with a reviewer-approved commit that records no unrelated file changes.
