# Combined recovery/core candidate — local evidence, 2026-11-15

This record covers the candidate branch combining recovery commit `1bd7686`
with PR #24 head `36e3823d6a14ab2c8735ad948317d07b4feb03f6` and the
local SDK/documentation/test corrections below. It is not evidence of production
activation. The immutable source revision and artifact hashes belong in the
release manifest after this tree is committed.

## Executed locally

| Check | Result |
|---|---|
| `make -j8 lib cluster-daemon admin-cli backup-cli` | Passed against the combined source. No library installation. |
| `test-core-search-regressions`, `test-core-math-regressions`, `test-runtime-math-regressions`, `test-core-methodologies`, `test-rff-maps` | Passed. ISA-specific cases retain their explicit host-capability outcomes. |
| `test-vector-candidate-rerank` | Passed, including filtered INT8 and binary candidate admission. |
| `test-txn-durable-2pc`, `test-sql-blob-txn-2pc`, `test-shared-backup`, `test-w11-order-recovery` | Passed; generated recovery evidence retained. |
| `test-ownership-lane-abort`, `test-ownership-staging-discovery`, `test-ct-group-failover-tick` | Passed. |
| `test-ct-group-admission-recovery` | Passed real pinned-QKP target/source restarts, exact persisted SOURCE fencing, unchanged ownership/staging, restored successor admission and exact CT2 retry. This uses disposable configured groups, not imported installed stores. |
| `test-cluster-maintenance`, `test-cluster-maintenance-resp` | Passed native and authenticated RESP maintenance tests. Not proof of every installed daemon writer or startup configuration. |
| `test-ct-storage`, `test-ct-transport-daemon` | Passed native legacy source re-admission and all five real pinned-pair daemon tests, including durable write/ACK, successor restart and lost-ACK recovery. No consensus migration was needed for legacy CT1. |
| `test-public-api-install` | All three tests passed against a private staged installation, including canonical core math C/C++ headers and linked shared-backup C11/C++11 consumers. |
| `docs-api-counts`, `test-docs-api-counts` | Passed after regeneration: 415 declarations in the inventory table, including all three shared-backup entry points. This table is not an inventory of every library symbol. |
| Native symbol resolution | All 33 explicitly checked recovery/AIMEM API names in the added documentation resolved from the rebuilt library. |

No local `make test` or `make test-serial` aggregate was run. The PR author's
separate full-suite record is in [core validation](../plans/qihse_core_validation.md);
its environment, revision and explicit limitation must not be relabelled as a
full-suite pass for this combined tree. CI status is not a substitute for these
native results or a veto over successful local execution.

## Local CodeGraph execution and fixture correction

Native AF_UNIX socket creation succeeds on this host. The real CodeGraph reader,
persistence, traversal, staleness and storage checks that were blocked by the
PR environment executed successfully here, as did the subsequent component
checks through `test_codegraph_remaining_integration.py`.

The `test-codegraph` command then failed in its final Python incremental-adapter
suite: a vacuum fixture required an immediate decrease in `st_blocks * 512`.
Both sampled values were 1024 on the local ZFS filesystem, despite successful
logical compaction. An incompressible-data fixture experiment did not change
that observation; compression alone was not a sufficient explanation.

The correction does not fabricate allocated space or weaken the database
preservation checks. It retains strict free-page reclamation and logical-file
shrink, exact row IDs/values and unchanged indexes/schema. It additionally
observes the actual `lstat` samples used by accounting and checks every reported
logical/physical file value and their physical sum. Physical block accounting
may lag on ZFS; a later second sample is not the earlier report's expected value.
The focused incremental-adapter suite passed all 15 tests after this correction.
The long `test-codegraph` command was not rerun in full after that test-only edit;
its original nonzero exit is not recorded as a later aggregate pass.

## Corrections included

- Install `qihse_shared_backup.h` with the public SDK; its omission was reproduced
  by the staged-header test before the Makefile fix.
- Compile and link all three shared-backup entry points from staged C and C++
  consumers, without checkout include paths.
- Align API inventory, native durable participation/restore contracts, protocol
  boundaries, source-aware AIMEM guarantees and version-aware CT operations.
- Distinguish synthetic local fixture authentication from durable production
  authority, and current evidence from historical deployment observations.

## Live rollout boundary

The upgraded local fixture was deliberately stopped at the operator's request.
Its earlier same-state cold-recovery/read-write evidence is not a production
upgrade of the combined core candidate.

Read-only installed inventory found a concrete endpoint conflict on T320:
legacy `qihse-node1.service` owns port 7101, while the configured recovery C-owner
repeatedly fails to bind it. Those services use different data directories;
application connections to that address cannot be assumed to reach recovery C.
Resolve which data generation is authoritative and reconcile client routing
before replacing the holder or treating C's successor as redundant.

Stage immutable candidate artifacts without overwriting mapped libraries. Keep
legacy-pair binary upgrades distinct from enabling common-consensus/group
configuration; do not silently migrate authority or credentials. Rehearse the
actual retained state/configuration and verify pinned ownership, admission,
baseline/ACK/cursor and application behavior before advancing a unit. The
[version/format-aware operating procedure](../OPERATIONS.md#16-staged-installation-and-upgrade-gates)
and [native parity guide](../deployment/native_cluster_parity.md) describe those
boundaries. No production service was stopped or replaced for this record.
