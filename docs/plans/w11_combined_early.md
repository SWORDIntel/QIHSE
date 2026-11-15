# W11.6 early combined contention probe

> **Roadmap authority:** [ROADMAP.md](../../ROADMAP.md) is the sole authority for delivery status, remaining work, sequencing and acceptance. This file retains supporting design, acceptance criteria and dated evidence; historical status labels below are not an independent current checklist. Consolidated 2026-11-07.

This is a small, reproducible starting point for W11.6, not its acceptance test. It runs four threads against one authenticated public KV store: two concurrent stock reservations, finding-record ingestion, and scoped memory writes with exact-key retrieval. The two reservation threads use single-key compare-and-set; the finding and memory records use classification 5. A separate classification-0 guest must be unable to read either protected record type.

## Run

From the repository root:

```sh
bash benchmarks/w11_combined_early.sh 64 20261106 > build/w11_combined_early.json
python3 -m json.tool build/w11_combined_early.json >/dev/null
```

The first argument is logical operations per worker (1–100000); the second is a nonzero 64-bit input seed. The runner builds `libqihse.so` with the repository Makefile and compiles `benchmarks/w11_combined_early.c` with `-O2 -Wall -Wextra`. It creates an isolated temporary data directory under `build/`, removes it on exit, and measures only the workload, excluding build and setup. The JSON records input seed, workload size, machine architecture, online core count, physical RAM, elapsed time, successful operations, expected stock rejections, errors, throughput, and p50/p95/p99 operation latency. Latencies use `CLOCK_MONOTONIC` and the nearest-rank percentile. The seed controls memory key selection; thread scheduling and timings are intentionally not claimed to be deterministic.

The exit code is nonzero if any operation errors, the final stock cannot be accounted for, a finding is missing or altered on readback, or a low-clearance read discloses protected data. The two stock workers make `2 × ops` reservation attempts against `ops` initial units; exactly `ops` must succeed. A finding record is checked by authenticated readback for every generated ID.

## Measured smoke, 2026-11-06

One local smoke run used 16 operations per worker and seed 12345 on x86_64, 40 online cores, and 118,180,769,792 bytes physical RAM. The workload phase took 0.103 seconds. Stock CAS had 16 successful reservations and 16 expected sold-out results, with p95 102,059 µs. Finding ingestion and exact-key memory each completed 16 operations without errors. All three invariants passed. This is a smoke result on a mixed-purpose host, not a controlled latency baseline or evidence for the W11.0 numerical budgets.

## Coverage boundaries

- Inventory covers only one-key stock CAS. It does not write orders, reservations, or outbound-event intent atomically.
- Findings cover labeled record ingestion and ID readback. Binary blobs, version/provenance links, and cross-model atomicity are not exercised.
- Memory covers authenticated exact-key reads and writes. It does not exercise semantic search, embeddings, recall@10, or an index rebuild.
- No node restart, partition, storage fault, slow-storage profile, backup/restore, historical consistency check, or recovery-point measurement is included.
- The scale is a configurable smoke size. It does not meet the 1,000,000-record or 30-minute W11.0 reference workload.

The subsequent W11.6 harness should replace these simplified operations with the supported public SQL, blob, provenance, and AIMEM workflows as their guarantees land, then add a deterministic fault controller and isolated authenticated restore. Each new adapter path needs a low-clearance/high-data negative test under `AGENTS.md`.

## Additional partial recovery evidence, 2026-11-12–13

Local focused validation: `make test-w11-combined-recovery` passes with the v2
JSON assertions below. No aggregate suite or production operations were run.
The earlier independent-export drill has been replaced by the bounded
[shared package](../contracts/shared-backup-v1.md).

Two inventory workers contend on one KV stock key while a findings worker
inserts 32 authenticated SQL rows and an AIMEM worker stores 32 authenticated
memories. A private blob store receives one 4096-byte binary dump artifact with
tenant 0, classification 5, SCI 1, three references and two pins. Eight scoped
knowledge chains are seeded before backup, retaining all eight original version
IDs and content hashes in KV. Chain zero also gains a second version, yielding
nine source versions but still eight current heads/index candidates. Its original
version becomes SUPERSEDED with a closed ingestion interval; the revised version
retains the exact predecessor, an explicit FIXES relation and the server-added
SUPERSEDES relation. Both carry one authenticated immutable event and exact opaque
synthetic source revision/line references, with confidence 875000/925000. These
are fixture identities, not externally authenticated citations. Source-aware
create/revise and an identical retry use the existing authenticated in-process
dispatch's server KV lock/sync boundary; workers have joined and no listener runs.
Protected expectation markers retain the original event envelope and revised
metadata; field-wise SHA-256 fingerprints cover all returned provenance fields,
not struct padding or pointer values. Ordinary UWP commits remain one-phase even with
durable participants registered; the test checks an empty common journal before
explicitly enlisting a real SQL/blob transaction. Its COMMIT receipt is followed
by an allocated, rolled-back ID with no journal record.

After workers join, one retained-handle `qihse_shared_backup_export_user()`
captures KV, SQL, blob and the coordinator using all-source start/end checkpoints.
It publishes an authenticated package, verifies it, writes source-only KV and
SQL markers, then exits via `_exit()`. A fresh process verifies and unpacks the
package into a private working directory and restores native KV, SQL (including
receipts), and blob v2 state into separate destinations. Native SQL restore
creates a lock beside its input, so it must not operate on the immutable
published package. The coordinator journal is also copied into a working file.

Before constructing the application/AIMEM server, recovery registers the
manifest's SQL/blob IDs, checks both restored receipt floors, advances the
coordinator to the authenticated next-ID floor, and replays the common decision
twice. Both participant callbacks run, with no historical blob increment repeated.
The first new transaction gets the preserved floor. The fixture observed common
decision 34, receipt floors 35, manifest floor 36, five members and a 72-byte
journal. These are bounded fixture values, not scale measurements.

Recovered workload and cohort readback check exact inventory accounting, SQL rows,
AIMEM references and the blob's SHA-384, every payload byte, tenant, tag,
classification, SCI, size, references and pins. Source-only markers are absent.
A provenance token and AIMEM ID cross-resolve through SQL to the exact blob hash.
All eight original versions plus the ninth revised version are checked before
and after authenticated index rebuild. Exact-version, latest and as-of reads at
the original start, just before supersession and exactly at its boundary must
return complete matching original versions. Original event ID/envelope/time/kind/
labels and source/relation metadata remain exact; recovery creates no substitutes.
Complete candidate generations must point to the original revised head, not just
have the correct count. Four subsequent fresh processes interrupt builds after the first
candidate, after the last candidate, after all entries before private READY
cutover (native `after-entries`), and after private READY commits but before public
readiness is written (native `after-private-ready`). Each syncs the candidate
generation, writes/fsyncs a fresh phase-and-nonce witness and receives SIGKILL. The parent
requires that exact witness and the child's SIGKILL exit; watchdog expiry is a
separate failure and can never pass. Recovery always reopens the same stores
without another unpack/restore. For the first three cuts, it proves BUILDING
state with exactly one or eight durable entries, explicitly recovers to FAILED
and rebuilds to READY. The fourth cut preserves private committed
READY generation 8 with eight entries while public readiness remains false.
Explicit recovery must leave every health field unchanged, rather than marking
the committed generation FAILED or advertising it. A subsequent authenticated
rebuild publishes READY generation 9. Final fresh reopen verifies started=9,
ready=6, failed=3 and recovered=3, retained generations 2/4/6 with counts 1/8/8,
committed-unavailable generation 8 and READY generation 9 with eight entries each,
and every original source ID/version ID/hash/content, provenance and blob metadata.
Only the test executable exports the existing optional weak test hooks; no
production environment kill switch or audit suppression is introduced. These
are bounded order/provenance and interruption checks, not the full W11 invariant
or interrupted-build matrix.

The synthetic auth fixture uses `qihse_auth_maintenance` standalone
provision/recover, preserving principal IDs and authorization attributes across
processes. ML-KEM-1024/ML-DSA-87 keys, bootstrap and auth state remain in its private
fixture. A random mode-0600 48-byte key authenticates both the inner blob archive
and outer package. HMAC-SHA-384 is **not encryption**. No production credentials
or keys are imported. The recovery runner retains successful, failed and aborted
private trees and append logs for inspection. The optional
`make test-w11-combined-recovery-sanitize` runs the same workload/cuts with
ASAN, fatal UBSan and leak detection in the fixture executable against the
rebuilt remaining library; this is not whole-library instrumentation.

Low-clearance package export/verify/unpack, inner archive export/restore, SQL,
AIMEM, blob content/metadata/verification/enumeration and index rebuild/health
are denied. Added exact-version/latest/as-of/event negatives require empty output
content, IDs, metadata, source references and relation/source-event fields after
each denial. Protected event expectation markers are also unreadable to the low
principal. Wrong outer and inner keys are rejected with no destination.
`PUBLISHED_UNSYNCED` is not accepted as success or blindly retried. The original
published package is verified unchanged after native restore and replay.

The v2 JSON adds explicit `bounded_shared_restore` and `evidence` fields for
this integration, including `knowledge_source_rows=8` (the original versions),
`expected_knowledge_source_versions=9`, `knowledge_current_rows=8`,
`expected_provenance_events=1` and separate bounded
provenance/supersession/temporal-read/nondisclosure flags. The two `expected_*`
fields declare fixture size, not an authenticated all-history/event cardinality
audit: the fixture verifies each expected ID/version/event and the complete
current index count, not absence of every unrelated source record.
Historical `remaining_gaps` booleans retain their evidence-flag
meaning: `combined_cross_store_backup_atomicity`, `node_partition_faults`,
`w11_scale_gate` and `aimem_index_interrupted_build_faults` remain false, rather
than being reinterpreted as completed acceptance. Explicit `acceptance_gates`
for full node recovery, partitions, storage faults, scale and the full interrupted
index-build matrix remain false. The new bounded post-restore interruption has
separate evidence fields; it does not close that full gate. Process interruption
and publication/I/O faults exercised
by the separate shared-package fixture do not establish the combined workload's
full fault matrix, slow-storage/resource gate or distributed snapshot support.
Standalone fixture-auth recovery is not deployment authentication readiness.
Adjacent QH-08 regression checks use only the executable's weak test failpoint,
with one exact phase hit required before the intentional `_exit` without teardown;
the stale environment-failpoint dependency was removed from that test. This is
not an added production environment hook or another witnessed SIGKILL claim.
**W11.6 remains incomplete.**
