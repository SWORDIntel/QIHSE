# QIHSE Usage Guides

This folder holds practical, how-to documentation for key runtime paths that are
used in production and are easy to miss in the monolithic architecture and API
reference docs.

## Core usage topics

- [vector-db-lifecycle-and-mutations.md](vector-db-lifecycle-and-mutations.md)
  - Runtime setup, create/open flows, add/update/delete/upsert, read paths,
    close/checkpoint hygiene.
- [trinary-and-file-backed-querying.md](trinary-and-file-backed-querying.md)
  - Exact default path, legacy scalar candidate mode, explicit `qtri` and `qmag`
    trinary modes, and persistence status interpretation.
- [memory-maintenance-runtime-loop.md](memory-maintenance-runtime-loop.md)
  - Caller-owned maintenance loop using `qihse_memory_maintenance_*` and migration
    scheduler APIs.
- [persistence-recovery-runbook.md](persistence-recovery-runbook.md)
  - Restart and corruption-aware recovery sequence with practical status checks.
- [reference-benchmark-runbook.md](reference-benchmark-runbook.md)
  - `make`-driven local validation path for persistence, reference workloads,
    and VXUG calibration evidence.

## Recommended reading order

1. `vector-db-lifecycle-and-mutations.md`
2. `trinary-and-file-backed-querying.md`
3. `memory-maintenance-runtime-loop.md`
4. `persistence-recovery-runbook.md`
5. `reference-benchmark-runbook.md`
