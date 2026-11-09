# CodeGraph optimization results

> **Roadmap authority:** [ROADMAP.md](../../ROADMAP.md) is the sole authority for delivery status, remaining work, sequencing and acceptance. This file retains supporting design, acceptance criteria and dated evidence; historical status labels below are not an independent current checklist. Consolidated 2026-11-07.

Date: 2026-11-06. Scope: native CodeGraph only. All measurements use isolated
synthetic graphs and the real QIHSE runtime unless explicitly marked experimental.
No live repository graph was rebuilt or migrated during this optimization pass.

## Integrated changes

- An immutable, string-interned CSR query projection replaces the duplicate general
  property graph. Its handle inherits an authenticated principal and checks access
  on projection reads. Original IDs, unknown metadata, unresolved records and
  security metadata remain in the authoritative KV snapshots.
- Read-only generations release their decoded KV after construction; glibc builds
  trim freed pages once per successful generation load. Migration retains KV.
- Packed loading avoids two complete reconstruction copies. The reconstruction
  stream remains private to the authenticated KV loader, with trusted digest and
  descriptor checks in the storage wrapper and final authorization checks.
- Automatic encoding exports once and selects the smaller Zstandard/packed file.
  Level 9 remains the default: tested level 3 enlarged the larger fixture by about
  43%. No new persistent indexes or sidecars are required.
- Successful and validated unchanged imports/migrations retain current and one
  previous managed snapshot and collect abandoned leased runtimes. Active and
  unleased legacy runtimes are preserved. Compression staging is inside the lease.
- Each graph walk inspects at most 65,536 edges and reports truthful truncation;
  batch requests contain at most 32 walks. Unverified test-gap hints are suppressed.

## Measured comparisons

| Measurement | Baseline | Improved | Qualification |
| --- | ---: | ---: | --- |
| Steady reader RSS, 16k nodes / 48k edges | 65.20 MiB | 28.25 MiB | 56.7% lower; two controlled immutable-snapshot pairs; baseline already had KV release/trim |
| Peak cold RSS, same fixture | 316,492 KiB | 279,036 KiB | Single diagnostic cold run; not a universal peak-memory ratio |
| Cold process time, same fixture | 11.083 s | 10.814 s | Single diagnostic run; no reliable speedup claim |
| Packed snapshot, 8k nodes / 24k edges | 1,974,079 bytes | 1,974,079 bytes | Exact size retained by lower-copy storage changes |
| Packed authenticated load CPU, same fixture | 1,034 ms | 505 ms | Single shared-host observation; not a general latency promise |

The initial readonly-release/glibc-trim experiment separately measured median RSS
317,846 to 66,788 KiB. These are successive experiments, not one combined timing
or an assertion that every repository has the same ratio. Disk figures describe
complete encoded snapshots; they do not measure whole state-directory or ZFS usage.

## Verification

The final `make test TEST_JOBS=32` run completed **177 targets**:

- `test-codegraph`: PASS, 1,404.5 seconds. Includes codec, CSR authorization,
  native CLI, storage, automatic selection, high-degree projection, reindex and
  source-identity tests.
- `test-codegraph-memory`: PASS, 16.9 seconds.
- Three failures outside CodeGraph remain: `test-parallel-runner` (gold-pack gap
  expectation), `test-cluster-daemon-shutdown` (startup/resume ownership), and
  `test-gold` (`cluster-failover-smoke`). The full suite is therefore not green.

The cross-UID SO_PEERCRED case is skipped without root. Focused ASan/UBSan and
concurrent-reader/refresh/revocation checks passed; the shared library remained
uninstrumented and leak detection was disabled. Native query parity, exact codec
bytes and complete KV metadata fingerprints were checked independently.

Final logs: `build/codegraph_csr_storage_full_suite.log` and
`build/codegraph_combined_build_unit.log`. The earlier staging-path failure injector
was corrected to target the leased staging path and retain its publication-failure
and cleanup assertions; the final CodeGraph target passed that regression.

## Reproduce

```sh
make qihse-codegraph
make test TEST_JOBS=32
python3 benchmarks/codegraph_readonly_compare.py \
  --baseline "$BASELINE_BIN" --candidate "$CANDIDATE_BIN" \
  --library-dir "$PROJECT_ROOT" --nodes 16000 --edges 48000 --pairs 2 \
  --output ./build/codegraph-memory.json
```

The receipts pin binaries, source and library hashes. The CLI projection delta is
retained in `benchmarks/codegraph_csr_delta.patch` to reconstruct the compared
projection baseline; use matching runtime/codec versions when reproducing a stored
receipt, or record a fresh paired comparison. The storage harness and its arguments
are documented in [the storage review](codegraph_zip_storage_review.md).

See [CSR details](codegraph_csr_projection.md),
[storage review](codegraph_zip_storage_review.md), and
[the native interface](../architecture/codegraph_native.md).

## Experimental format and limits

Follow-up: the dictionary format is now integrated as packed-v3, with automatic
three-format selection and reproducible producer identities. See
[the compact-reference implementation](codegraph_compact_references.md). The
following paragraph records the earlier isolated-prototype checkpoint.

The isolated `codegraph-columnar` worktree at commit `eb5004b` contains a hardened
exact-byte dictionary-format prototype. On the 8k/24k fixture it used 1,686,048
bytes, 14.59% below packed-v2. It is not enabled in the native loader; promotion
requires integration and CI wiring. The supplied fourfold reduction was not
reproduced. The prototype's initial stale-stdio integrity flaw was reproduced,
fixed with an immutable verified copy, and independently re-reviewed.

Bulk import, a new persistent CSR format, memory mapping and incremental snapshot
mutation are not included. Blanket bulk mode removes spill limits and needs a
bounded memory policy. Git freshness still runs before and after reads; the
supplied short-window manifest cache would not prove source freshness.

This is a measured implementation pass, not proof of a global compression optimum.
Current delivery status and the remaining backlog are maintained only in [ROADMAP.md](../../ROADMAP.md#codegraph).
