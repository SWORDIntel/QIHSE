# W11 shared-snapshot contract — bounded local implementation

**Not a W11 acceptance result.** `qihse_shared_backup_export_user()` now brackets
native KV, SQL, blob and coordinator exports, authenticates their package and
publishes it atomically. `test-shared-backup` exercises fresh-process native
restore/replay and controlled fault cases. The combined inventory/findings/AIMEM/
blob drill now uses this package too; full fault/scale/deployment gates remain
open.

## Optimistic consistency proof

A bounded exporter may establish a shared point without stopping all writers if
it can obtain a monotonic, complete change checkpoint from every source:

1. Retain the same live KV, SQL, blob and durable coordinator handles throughout
   the attempt. Recover common decisions first; unresolved participant state is
   not exportable by this protocol.
2. Authenticate the export principal and obtain **all** starting checkpoints
   before invoking **any** export callback.
3. Export each source through its authorization-aware native backup API into one
   private unpublished bundle. Include terminal participant receipts and the
   matching coordinator recovery state, not just live application rows.
4. After **all** exports finish, obtain all ending checkpoints and revalidate the
   principal. Reject the attempt if any checkpoint changed, became invalid,
   saturated, or belongs to a different handle lifetime.
5. Authenticate a manifest containing the source identities, checkpoint pairs,
   format versions, lengths and content hashes. Publish the bundle only after
   all members and the manifest are durable. Publication is one final marker;
   a visible destination with uncertain directory durability must not be blindly
   retried or removed.

For each source, unchanged checkpoints must prove that its exportable state did
not change anywhere between its two observations. Because every starting
observation precedes every export and every ending observation follows every
export, those intervals overlap. All exported states therefore coexist at a
point in that overlap. Merely hashing equal final values is insufficient: an
ABA mutation could otherwise conceal an inconsistent intermediate export.

The proof is conservative: a busy writer can cause an attempt to fail. This is
not a promised live, nonblocking backup under sustained load. Retries must be
bounded, and a rejected bundle is not a restore candidate.

## Required checkpoints

- **KV/AIMEM:** `qihse_kv_snapshot_checkpoint_user()` atomically captures the
  sequence, projection epoch and store instance for the active bootstrap Operator
  (id 0, tenant 0). It accepts only a healthy, local CT-disabled durable source;
  busy/bulk/batch, replica, inherited and memory-view handles are refused without
  changing output. Restore preserves the sequence floor while advancing the
  projection epoch, so `qihse_kv_change_seq()` alone is insufficient. The focused
  `tests/test_kv_snapshot_checkpoint.c` covers this restore counterexample,
  unauthorized disclosure, a reentrant durable-batch query and reopen identity.
  A fresh-process modern SOURCE lane is admitted through real baseline/peer
  reconciliation: the raw projection marker succeeds, but the authenticated
  checkpoint still refuses it without changing its output.
  Distributed ownership/replica snapshots are not supported by this checkpoint.
  Time-dependent export filtering must still have a defined capture point; an
  unchanged sequence does not by itself freeze logical TTL visibility.
- **SQL:** `qihse_table_store_snapshot_epoch_user()` observes a private runtime
  epoch covering committed row/catalog/retry-state publication and
  PREPARE/terminal-receipt changes. PREPARE followed by ABORT must
  change the epoch even if every visible row remains the same. Exact terminal
  replay with no state change must not change it. The query must refuse pending,
  poisoned, inherited, unauthorized or exhausted state. Epochs from different
  handle lifetimes cannot be compared.
- **Blob:** `qihse_blob_snapshot_epoch_user()` observes the durable append-only
  index length under the index lock, covering live entries, reference counts,
  pins and terminal receipts. It refuses unresolved PREPAREs, poisoned/inherited
  handles and incomplete authorization. Failed appends restore the old state and
  length or poison the handle; live-handle compaction is not supported. Snapshot
  retention references are not application state. Archive v2 captures live
  metadata and terminal receipts at one index-lock capture point, so later
  receipts cannot be appended to an older live snapshot.
- **Coordinator:** `qihse_txn_backup_checkpoint_user()` captures a runtime epoch,
  next transaction ID and journal length for the same retained manager.
  `qihse_txn_backup_export_user()` requires that starting checkpoint, validates
  CRC/membership/terminal decisions without repairing the journal, and invokes
  streaming callbacks unlocked using a frozen byte copy. It then rechecks source
  state, bytes, health and principal generation. Active/in-doubt, unrecovered,
  poisoned, exhausted, inherited and volatile managers are refused. Authorization
  matches SQL's bootstrap-Operator policy. Capture is bounded by the native
  journal's 64 MiB parse limit; journal maintenance/scale acceptance remains open.
  Exported bytes are only the portable durable 2PC journal, not an authenticated
  bundle or full MVCC registry snapshot. The manifest must authenticate the
  captured next-ID floor: raw journal bytes do not preserve unjournaled IDs.
  Do not manufacture missing decisions from participant receipts. A fresh
  journal's ID floor must exceed every restored participant receipt, including
  unresolved prepare IDs; raising the floor does not authorize resolving them.

A checkpoint API must have a documented same-handle lifetime, atomic observation,
no-wrap behavior and complete mutation coverage. File timestamps, counts of live
objects, per-table generation maxima and content hashes alone are not sufficient.

## Local package implementation and evidence

`include/qihse_shared_backup.h`, `src/tractable/qihse_shared_backup.c` and
`docs/contracts/shared-backup-v1.md` define local export, verification and fresh
unpacking. The HMAC-SHA-384 manifest binds canonical membership, member hashes,
checkpoints, declared SQL/blob engine IDs and the unjournaled next-ID floor.
It is not encryption or an in-place service restore. Only the two declared
durable participant IDs may occur in the journal; a missing engine's store cannot
silently be omitted from a supposedly replayable v1 package.

The focused `make test-shared-backup` fixture uses actual SQL/blob durable
participants under one manager, classified/SCI KV and binary blob data, COMMIT
and ABORT receipts, a deleted committed object, nontrivial refs/pins and an
unjournaled allocated ID. A fresh exec process restores all native payloads,
replays exact terminal decisions and starts a new common SQL/blob transaction.
SIGKILL immediately before and after publication rename is exercised for both
export and unpack, followed by authenticated readback and fresh-process native
restore. Pre-rename orphans are preserved and do not block a new attempt.
Post-rename packages remain immutable: native restore runs from a separate unpack
because SQL restore creates an input lock sidecar. This is process-death evidence,
not a power-loss/storage-controller drill. ASAN/UBSAN with leak detection and the
16 KiB focused stack check pass for the fixture.
Other cases cover low/foreign/NULL authority despite a correct key; signed
malformed manifests, missing/extra/traversal/duplicate/link/FIFO members; wrong
keys and altered bytes; mutations of each source, prepare/abort ABA and a common
decision during export; principal-generation changes; no-replace publication;
write/fsync/rename failure; visible-but-unsynced publication; and mutation during
unpack. Special files are rejected before nonblocking descriptor open, avoiding
FIFO hangs. `make check-shared-backup-stack` keeps core and fixture frames below
16 KiB; stream buffers and manifest/entry vectors are heap-backed.

`make test-shared-backup-enospc` separately exercises actual kernel byte
exhaustion, not the synthetic write-error interposer. A rootless private 4 MiB,
128-inode tmpfs contains only the new destination, unrelated sentinel and owned
filler. Real fill-to-ENOSPC followed by a 32 KiB filler-tail release produces a
32,768-byte partial blob member and real ENOSPC with zero free blocks/spare
inodes. A pass-through syscall observer preserves the partial member outside
tmpfs before stage cleanup and compares the exact canonical prefix. ERROR must
leave output-info/file sentinels unchanged and destination absent. Releasing only
the filler allows same-path authenticated retry and fresh-exec native restore,
including floor/receipt/deletion/refs/pins and a new common commit. Source stores,
canonical package, logs and restore files remain outside tmpfs; the supervisor
copies remaining mounted contents before unmount, including on child failure or
handled signals. Launcher-only signals are forwarded and awaited. Copy/sync
failure suspends the namespace supervisor with the mount retained for explicit
repair/CONT, never unmounting the only complete image. Separate supervisor
failure/signal/copy-refusal diagnostics verified preserved markers and failing
exit status; the failed-stage directory is also required absent before retry.
Namespace/capture/unmount errors cannot pass or skip. Normal,
fixture/shared-backup-TU ASAN/fatal-UBSan/leak detection and 16 KiB frame checks
pass. See [capacity contract](../contracts/shared-backup-v1.md#actual-filesystem-capacity-failure).
The same normal/sanitizer targets also run `--capacity-export` in a separate
namespace/fixture: release 64 KiB, complete real native KV/SQL export and receipt
sidecars, then observe 45,056 positive blob-archive bytes, a short write and real
ENOSPC (zero free blocks, 118 free inodes on the exercised 4 KiB-page tmpfs).
Both modes require unchanged authenticated KV/SQL/blob/coordinator checkpoints,
no leaked stage, same-destination retry and fresh native restore. This does not
exercise degraded-SSTable materialization or establish a general scratch budget.
This is volatile-filesystem capacity evidence, not physical storage durability.

The 3 GiB/4096-member limits bound the published package. They are not the agreed
W11 scale/resource gate or a promise that existing native KV/SQL exporters cap
all temporary scratch I/O to that budget. Verification/unpacking proves package
integrity, not arbitrary native-engine semantic validity; restore must still use
the authenticated native APIs before exposing application state.

## Further restore and validation still required

Restore must validate the manifest and every member before publication. Restore
participant terminal receipts without replaying historical COMMIT effects onto
the restored live snapshot: deleted objects must stay deleted, and current
reference counts and pin multiplicities must not be reset by old receipts.

`make test-w11-combined-recovery` now runs the bounded combined
inventory/findings/AIMEM/blob workload through this package. It restores native
SQL/blob receipts and coordinator ID floors before repeated common replay, checks
cohort provenance and post-cut marker absence, rebuilds eight current knowledge
heads backed by nine packaged versions, and verifies exact rows/READY persistence
in a later fresh process. It also kills post-restore index builds after the first
candidate, last candidate, before private READY cutover and after private READY
but before public readiness publication. Each requires an exact phase/nonce
witness and child SIGKILL without watchdog expiry, then recovers/rebuilds on the
same stores without another restore. The last cut preserves committed generation
8 as unavailable; recovery must not roll it back or advertise it. Authenticated
rebuild reaches READY generation 9, with three failed/recovered builds and exact
retained generation counts and original source rows verified after fresh reopen.
One original chain carries a second version, an immutable authenticated event,
exact opaque synthetic source references, nonzero confidence, explicit FIXES and
server-added SUPERSEDES links. Pre-export markers capture original IDs, hashes,
actors, ingestion boundaries and complete field-wise provenance fingerprints.
Authenticated exact-get/latest/as-of reads and original event-envelope checks run
through restore and each existing index recovery/rebuild; complete candidate
generations must reference the original revised head. Low-clearance calls return
no content or provenance fields. Source-aware mutations and an exact retry fence
use the existing in-process authenticated dispatch, which syncs under the server
KV write lock. Opaque source references do not attest external source bytes. Expected fixture
size fields are not an all-history/event cardinality audit. The optional combined
sanitizer target instruments this fixture executable (ASAN/fatal UBSan/leak
detection), not the whole rebuilt native library.
See [combined evidence](w11_combined_early.md). Ordinary UWP
COMMIT remains one-phase; the one common SQL/blob decision is explicitly enlisted.
This is integrated local evidence, not the full workload/failure matrix.

The [native order fixture](../contracts/w11-order-recovery-fixture.md) additionally
checks stock/order/line/ledger/event-intent atomicity in supported SQL placement,
explicit SQL/blob 2PC, SIGKILL around common decisions, stale SQL generation votes
and retries. Its real three-order cohort is exported through this package and
restored natively with receipt/floor replay before exposure. A fourth order then
commits on the restored stores, survives another reopen and resumes shared backup.
A recoverable blob COMMIT-sync fault verifies COMMITTING/ABORT/backup fencing and
same-decision retry; a separate two-sync fault preserves the poisoned-handle fence.
A separate restored IO sibling witnesses SIGKILL after returned COMMIT EIO and
before retry, then reopens the same files: pending blob state and published SQL
are inspected before common replay. Native publication is checked before direct
replay can mask a missed callback; replay keeps journal bytes unchanged and
enables a previously refused fresh backup. The source KV origin marker is not
claimed to join the SQL transaction. The adjacent SQL receipt case injects one
parent-directory fsync EIO after native C-receipt publication, then witnesses
SIGKILL after returned COMMITTING/`EAGAIN`. Blob publication proceeds normally;
fresh common replay must clear the SQL shadow before direct resolution can mask
anything, preserve row/reference counts and journal bytes, and resume SQL backup.
The matching ABORT-receipt branch keeps SQL snapshot bytes identical to the
pre-PREPARE baseline, blob evidence invisible and the common decision abort-only
through the same returned-error/SIGKILL/replay boundary. It uses real participants
and SQL-translation-unit sanitizer coverage, not a production SQL change or power-loss proof. These cases supplement, not replace,
the combined inventory/findings/AIMEM/blob drill.

Still required are the broader combined-workload process/node/partition faults,
storage exhaustion across the wider combined workload and physical storage
faults beyond the bounded real-tmpfs unpack/native-export cases, slow-storage profiles,
the wider interrupted-index-build matrix after package restore, broader
order/provenance assertions and the scale/resource gate. The shared-fixture SIGKILL boundaries,
synthetic partial-write/ENOSPC and fsync/rename injections, and real tmpfs
unpack/native-export exhaustion close only their specific local
failure cases. Rejected attempts must never be advertised as successful backups,
and failed test evidence must be retained.

This work does not close W11.6's node/partition/storage matrix, order/provenance
invariants or agreed scale/resource gate. Production authentication, TLS policy,
stopped-daemon restore and administrator-pin deployment gates remain outside the
authorized local scope.

### Inputs required for full acceptance

The capability map requires a recorded controlled storage target before measuring
the million-record, 30-minute budgets; the shared host root filesystem is not that
baseline. The 768-dimensional semantic embedding workload also needs a selected
provider rather than treating the bounded lexical fixture as equivalent. Neither
selection is established by these local recovery drills. Full independent-node
and storage-failure acceptance needs designated disposable fault-isolated targets;
process SIGKILL, loopback quorum partitions and syscall injections do not prove
host/power-loss or storage-controller behavior. Accessing production or changing
host/remote infrastructure is outside this work's authority. These prerequisites
must be supplied before closing the remaining acceptance gates; the successful
focused fixtures do not make W11.1/W11.6 or CT.1/CT.2 fully accepted. These are
acceptance prerequisites, not reasons to stop other local implementation or
isolated failure-case work.
