# AIMEM Current Issues

Status updated 2026-11-10. This note records verified blockers and risks; it contains no credential values. The Nov. 9 cluster ownership and outage observations in section 1 are historical; the later three-owner health and inventory checkpoint is in [the recovery record](plans/cluster_recovery_20261109.md). Remote KEYSTONE semantic-projection readiness remains unverified.

## 1. Durable authentication authority migration is blocked

The last authenticated, read-only authority-capabilities query (2026-11-05) reported volatile legacy mode `0`, not ready, and no export, import, or checkpoint capability. `PRINCIPAL_MIGRATION.md` explicitly blocks activation while the LAN ownership/GC conflict remains unresolved.

On 2026-11-09, the Operator credential was recovered through the existing
`systemd-creds decrypt --user` launcher path. Authenticated
`AUTHORITY.CAPABILITIES` succeeded and confirmed legacy mode `0` with no durable
authority export/import/checkpoint support. The earlier capability rejection
used `AIMEM_SERVICE`, which is intentionally limited to AIMEM commands; it did
not establish an Operator permission failure.

The user authorized a local binary deployment while retaining that authority
mode, the same Operator and AIMEM service credentials, numeric service/tenant
IDs, KV directory, QKP pins, and ONNX model. The new isolated release was tested
on a separate port before replacing the user service's `current` link. The live
service then preserved a pre-upgrade durable canary; exact reads and the new
store/forget local-fsync receipts passed. The database key count was 2,270 both
before and after canary cleanup, with healthy SST indexes and the 30-second
sweeper running. This was a binary upgrade, not activation of durable principal
authority. Runtime-created accounts and transient sessions are not persisted by
legacy mode. A future durable authority migration still requires supported
state transfer; this limitation does not prevent ordinary upgrades that retain
the explicitly configured two-principal setup.

The subsequent HAX smoke exposed unavailable scoped semantic/hybrid recall:
the default build omitted the optional KEYSTONE projection. The final local
release enables `QIHSE_ENABLE_AIMEM_KEYSTONE=1`, loads its adjacent KEYSTONE
library, and uses a private derived projection cache. A bounded UUID plus
canonical-content SHA-256 vector cache retains completed inference across
invalidated cold generations; all publication marker, label and authorization
checks remain intact. A deterministic KV mutation during inference proved that
an invalidated generation retries without repeating completed inference.

The real HAX Python QKP client now passes durable store, exact read,
wrong-project denial, BM25/semantic/hybrid recall and local-fsync forget;
disposable smoke memories were cleaned up. At the Nov. 9 checkpoint, the
broader cluster rollout was held: authenticated cluster views disagreed on
slot ownership, T320 reported FAIL, and maintenance gates were OPEN. This was
superseded by the Nov. 10 recovery deployment recorded in the linked recovery
document. Remote KEYSTONE semantic-projection readiness is still unverified;
cluster health does not establish semantic recall availability.

## 2. Historical QIHSE push-protection rejection

An earlier local QIHSE commit `52765af` was rejected by GitHub push protection
(GH013). This is historical: the functional baseline was subsequently
published to `main` as `4ca5bcd`. Secret scanning identified credential-like
environment values in these benchmark captures:

- `benchmarks/codegraph_hot_hax_suite.json`
- `benchmarks/codegraph_search_delivery_hax_suite.json`

The values were not published and are intentionally not reproduced here. Redact the captured environment values, then remove them from the unpublished commit history before retrying the push; adding a later cleanup commit alone may leave the flagged values in the pushed history. If any value is an active credential, rotate it through its issuing provider. The separate bridge commit `6654998` was pushed successfully.

## 3. Filesystem capacity (rechecked 2026-11-09)

The local deployment preflight reported 63% used and about 334 GiB available
on the filesystem containing the service data. This supersedes earlier dated
capacity observations. Continue monitoring capacity before growth; do not
delete AIMEM data as a cleanup shortcut.

## 4. Source validation and CT1/CT2 closure (2026-11-09)

**2026-11-10 review override:** the runs below are historical evidence, not
closure of the subsequently found defects. CT.1/CT.2 are partial again while
promotion dissemination, transfer ordering and fence/journal interruption
repairs are integrated. The user stopped the new full-suite run so source
review and repairs can continue. The repair branch has not been deployed;
the published functional baseline remains the live reference.

The final CT1/CT2 integration supersedes the earlier transport coverage-gap result. The required `make test TEST_JOBS=32` run completed **198 targets with zero failures**, including ten new transport targets; gold now runs 74 workloads with no declared gaps. The real pinned-QKP fixtures prove successor promotion and interrupted arbitrary-target transfer with independent successors, scoped denial, ordinary-read admission, observer convergence, historical receipts and reverse transfer. [Verification](validation/ct_transport_20261109.md) records the evidence and bounds. This closes the source transport gaps; the live authority/remote ownership rollout conditions in section 1 remain separate operational work.

The earlier required `make test TEST_JOBS=32` run completed 188 targets with two failures. `test-docs-api-counts` found a stale generated KV header count; `make docs-api-counts` refreshed the table and the focused gate now passes. At that stage, `test-parallel-runner` rejected the gold pack's explicit CT1 pinned-write-replication and CT2 fenced-slot-transfer gaps. Those guarantees still required implementation and proof; the test was kept intact. The new AIMEM atomic forget, scoped authorization, source citation, Python SDK, and CodeGraph aggregate targets passed. HAX's final full suite passed 305 tests and lint passed. The local runtime verification is recorded above. On 2026-11-09, the required standard-build full run completed 188 targets with only `test-parallel-runner` failing on the same CT1/CT2 coverage gaps; the gold pack and CodeGraph aggregate passed. The projection-enabled interruption/ranking/authorization fixture also passed against the installed library, followed by the real HAX QKP memory smoke.

## 5. Repair batch in progress (2026-11-10)

These changes are local source repairs, with focused checks in isolated
worktrees. They do not establish a new live deployment or a completed full
regression run. The existing Operator retains its authority; the work uses
the existing APIs and identities.

| Area | Confirmed defect | Current repair status |
| --- | --- | --- |
| CT ownership | Promotion announcements did not establish peer ownership; stale/partially superseded transfers and lost announcements could leave conflicting maps; fencing preceded recoverable intent. | Repairs integrated: durable intent, monotonic slot epochs, signed promotion adoption, retained original proof bounds and bounded periodic cache emissions. Focused interruption, overlap and UDP emission cases pass. Missing predecessor promotion chains remain open; see the CT runtime contract. |
| AIMEM adapters | Raw tenant KV access could read or change internal memory/grant/receipt records. | Central RESP/Python boundary, precise readiness errors and snapshot cleanup/read dispatch repairs integrated. |
| Owner backup | Inventory streams were not restorable backups; ordinary whole-store export was blocked on active CT owners. | Authenticated owner-data container, SDK streaming and QKP BACKUP mode integrated; retained tombstones, classified data and fresh CT-disabled restore checked. |
| Export lifecycle | Export could outlive its principal generation; failed private owner backup preparation could leave an orphan; a failed partial read could leave copied bytes in the output. | Native export generation checks and owner-container cleanup/read scrubbing integrated. |
| CodeGraph retention | Explicit GC omitted shared generation blocks; some failure receipts reported zero rather than unknown counts. | Shared cleanup and truthful incomplete-count receipts integrated. Chosen XXH3 snapshot formats are unchanged. |
| SDK/build tools | Missing installed public headers, Python input bounds, overlapping header names, unsafe native object reuse and inaccurate rollout script discovery. | Focused fixes integrated. Rolling script refuses immutable release-package paths; activation of new versioned releases is still separate work. |
| Generic graph engine | Property updates left stale index entries; external-ID maps were shared across graphs; analytics and fixed neighbor buffers returned wrong/truncated results. | Repairs integrated: typed full-value index checks, per-graph mappings, dynamic traversal, corrected analytics and strict ingest failures. The CodeGraph CLI uses its own CSR engine. |
| Hybrid graph/vector | Expanded neighbors lacked per-vector authorization; query-sized buffers could receive database-sized vectors. | Repairs integrated: authenticated vector visibility for every admitted vertex, dimension checks before fetch, dynamic frontiers. Focused protected-neighbor and high-degree cases pass. |
| Transactions/query results | Participant commit failures were reported as success; Cypher accepted ordering/pagination clauses without applying them. | Retryable COMMITTING/ABORTING outcomes, stable participant sets and retained OCC history integrated. Cypher applies final projected ordering/pagination; negative values and unsupported WITH modifiers are explicit errors. Durable coordinator-decision recovery remains absent. |
| Persistence | Native KV replay could truncate valid frames after an apply failure. Generic MVCC redo ignored mutation failures; sparse cache truncation retained pages; VFS WAL accepted partial replay and unchecked offset arithmetic. | Repairs integrated with focused fault cases: apply/read failures preserve the WAL; required tail-repair failures stop startup; failed generic redo inhibits checkpointing; VFS replay distinguishes completion from a valid prefix. Generic recovery is exercised through its public API/tests; no daemon caller was found. VFS WAL has no current in-tree consumers. SQLite has conditional cache calls but never creates the cache; those VFS defects are latent. |

Owner-data containers are data recovery images, not CT journal/cursor resume
images. Restore uses a fresh CT-disabled destination and then the existing
cluster admission process. Merge still opens two bounded detached input views;
it no longer builds a third full trie, but is not a fully streaming
merge. Legacy full exports do not contain deletion causality and cannot be
mixed with owner-data containers.

The generic 2PC manager retains pending decisions only in memory. Participants
must durably deduplicate commit/abort callbacks by transaction ID, including
an effect whose acknowledgement was lost. Resolve pending decisions before
destroying the manager; this repair does not supply crash recovery for them.
The dormant VFS WAL implementation uses a dense replay image capped at 1 GiB.
The dormant page cache still opens the process-global persistent KV namespace;
it must not be enabled for multiple databases without isolating that storage.

Focused graph and graph/vector ASan/UBSan runs instrumented the changed units
and passed with leak detection disabled. The separate graph LeakSanitizer run
reported existing test callers that omit freeing returned vertex/edge copies;
it is not recorded as leak-clean. The KEYSTONE-enabled AIMEM source passed a
syntax check, but the new readiness errno cases were not exercised in an
enabled projection runtime during this batch.

The combined local library and cluster daemon build successfully. Integrated
focused checks pass for transactions, 23 graph cases, VFS replay/cache/CRC,
and native WAL apply/read/tail-repair faults. The QKP backup protocol fixture
also verifies a protected record round trip to a fresh CT-disabled restore
and denial to its authenticated low-clearance peer. CT checks cover the
ownership journal, abort/replay, failover, transfer and bus paths in the
isolated repair tree; the final combined bus/journal check verifies the
periodic overlap announcement regression as well. These are focused checks,
not a full-suite result. No service was restarted or data migrated in this
repair batch.

### Additional storage and mutation repairs (2026-11-10)

The next source-review pass reproduced further correctness failures and
integrated these repairs:

| Area | Confirmed defect | Repair and focused evidence |
| --- | --- | --- |
| MVCC | Cutoff-only vacuum removed the last committed value when its superseding transaction had aborted. An update could stamp the old version before its replacement allocation failed. Commit-status callbacks ran under the store lock and could disagree about the same transaction within one read. | Committed-aware collection retains aborted/active predecessors; legacy cutoff-only entry points conservatively remove nothing. One reservation precedes mutation publication. Reads snapshot version metadata and resolve each transaction once outside the store lock. Fault-injected allocation, reentrant callback, rollback/vacuum and existing delete/transaction cases pass; the standalone fault fixture passes ASan/UBSan with leak detection enabled. |
| Arena | Size rounding/header arithmetic could wrap, returning undersized storage; block payloads did not satisfy their intended alignment. | Overflow is rejected before allocation and block payloads are explicitly aligned. Boundary/alignment checks and an isolated ASan/UBSan run with leak detection enabled pass. |
| Backup merge | Concurrent merges targeting one output could share a guessed scratch filename and mix raw records. | Each call reserves its own private scratch file and retains cleanup ownership across sealing failure. A barrier-synchronized regression verifies distinct scratch files, a complete restored union, and unchanged source containers. Concurrent calls may still collide at the output sealer; failure is reported rather than combining their scratch streams. |
| SQL DELETE | Failed table deletion was reported as a successful zero-row operation; stats refresh could append new rows after failing to clear the previous view. | Keep the existing boolean ABI and distinguish no-match from failure through errno. Propagate failure through SQL and stop refresh before appending. Instrumented generation-exhaustion tests preserve original rows and rollback state. |
| File/WAL close | File I/O could partially run before discovering an unrepresentable final offset; WAL shutdown discarded sync/close failures. | Preflight the entire offset range. Checked WAL destruction returns the first persistence/close error; the legacy void wrapper reports it. Close is attempted once, including EINTR. Focused range, sync and close-failure tests pass. |
| Replica retry | Propagating a staged WAL close error after applying its DELETE left the watermark unchanged and made retry fail on the already deleted key. | Replay now captures the validated operation, closes the stage, then applies the mutation. A real-WAL fixture injects a directory-close failure and verifies unchanged data/watermark, successful retry and duplicate no-op. |
| Vector mutation | UPDATE/UPSERT appended replacement rows as unclassified, metadata omission dropped TAGs, and duplicate IDs in a batch could create multiple live rows. A tenant could replace another tenant's global vector ID by supplying its own TAG. | Authenticated mutation forms authorize all preimages before WAL/mutation, preserve classification/SCI and omitted metadata, and reject duplicates during admission and replay. RESP checks existing TAG ownership under its vector lock and propagates the session principal. Focused persistence/replay, protected update and tenant-collision cases pass. |

MVCC collection still only unlinks obsolete versions: arena memory and delete
intents remain retained until store destruction. This repair does not supply
arena compaction, a durable transaction coordinator or an authenticated CT
promotion chain. The additional targets are wired into the existing suite for
future runs; the full suite remains stopped at the user's request.

Vector handles still require callers to synchronize shared access. The further
pass below wires a shared handle guard through primary RESP, UWP and the raw
fallback; native API users must also coordinate with that guard when sharing
an adapter's handle. Omitted batch metadata (`metadata_sizes == NULL`)
preserves existing bytes; supplied zero sizes explicitly clear them. The
single-row form distinguishes omitted NULL/0 from a supplied pointer/0.

The standalone arena, MVCC and replica-close fault checks passed ASan/UBSan
with leak detection enabled. The selected vector mutation regression passed
with its changed units instrumented by ASan/UBSan and leak detection disabled;
this is scoped sanitizer evidence, not a sanitizer run of the whole library.

The combined library and daemon build passes. Integrated focused runs pass
for vector persistence, RESP hybrid/protected mutation, tenant collision and
replica apply, alongside the MVCC/transaction, SQL and backup checks above.
The generated API-count gate passes. Suite discovery includes all seven
additional focused targets; discovery is not execution of the full suite.

Reproduce the additional checks from the checkout root:

```sh
make -j8 lib cluster-daemon
make -o lib test-arena-bounds test-mvcc-gc-failure test-file-posix-io \
  test-wal-durability test-repl-close-failure test-txn test-mvcc-delete \
  test-sql-delete-failures test-backup-merge-concurrent
make -o lib test-persist test-resp-hybrid test-vector-tenant-isolation test-repl
```

### Further failure-path review (2026-11-10)

The next pass repairs additional defects without changing the live services:

| Area | Confirmed defect | Repair and evidence |
| --- | --- | --- |
| Vector ADD | An existing-ID or dimension rejection happened after writing a committed WAL pair. A reproduced rejected duplicate added 200 WAL bytes and prevented reopen. Individual row allocations could also fail after publishing part of a batch. | Validate IDs, dimensions, sizes and the full reservation before WAL publication; apply the reserved batch without further allocations. Rejection leaves the WAL unchanged and the original vector readable after reopen. Allocation-fault tests preserve counts and allow a valid retry with different dimensions. |
| Vector row growth | Several independent reallocs could move old tracking arrays before another failed, leaving dangling pointers in the database handle. | Reserve tracking arrays together, copy existing state and publish only after the complete growth succeeds. Fault tests grow an existing eight-row database, retry failed growth, and check all previous vectors. |
| Vector WAL recovery | A failed WAL read was treated as an empty WAL. Garbage after a complete commit was not always repaired, and required repair failures were ignored. Payload-length and writer framing arithmetic could wrap. | Reject failed reads and required repairs while preserving the WAL; repair from the last valid commit to the actual section length; check payload, frame and offset arithmetic. Read/repair fault, read-only prefix, garbage-tail, oversized-payload and subsequent-write/reopen checks pass. |
| Replication stream | Single writes could leave incomplete frames; later sends could append to a failed frame, and peer closure could raise SIGPIPE. Slot growth could lose its original allocation on failure. | Loop through partial sends and EINTR, suppress SIGPIPE on supported sockets, close the stream after a failed frame, and advance the LSN only after complete transmission. Allocate slot names/capacity before publication. Deterministic send and allocation fixtures pass. |
| Table publication | Live table generations could wrap from UINT64_MAX to zero, invalidating the stale-snapshot fence. | Reject direct mutations and write-transaction publication before overflow or any durable receipt/publication. The existing private fault seam verifies unchanged rows and failed commit at the maximum generation. |
| CT transfer history | A source could start another transfer using an ID from an aborted or finalized operation; the target then rejected its conflicting immutable manifest after the source had fenced the range. | The existing locked source-journal replay rejects an ID already present in that journal before writing another intent or fencing. ABORTED/FINALIZED reuse cases preserve journal history; the source remains unfenced after rejection. This is source-history enforcement, not a new global ID registry. |
| Shared vector adapters | Concurrent UWP socket workers and RESP could access one borrowed VDB under different locks, allowing mutation/reallocation to race. | A per-handle adapter guard is shared by primary RESP, UWP and legacy fallback. Existing owner locks precede the guard; independent handles retain independent guards. Eight mixed writer threads, tenant preimage denial, metadata preservation and independent-handle progress pass in the focused fixture. Native callers still own handle lifetime and external synchronization. |
| Legacy RESP fallback | Vector fallback operations lacked tenant scoping, and direct protected reads omitted the supplied principal. Large fixed stack scratch and reply buffers truncated bulk GET/MGET output; owned KV result copies were leaked. | Tenant vector operations use the primary adapter; raw fallback rejects them explicitly while retaining system-domain classification checks and Operator access. Input scratch is heap-owned; bulk replies stream without the 1-KiB/64-KiB output ceiling and release every owned result. The raw connection frame drops from 147,824 to 1,440 bytes with GCC C99/O1 `-fstack-usage`; UWP socket routing is 448 bytes after heap staging. |

The native vector fault fixture passes strict compilation and ASan/UBSan with
leak detection enabled. Its instrumentation covers the changed vector unit;
the linked shared library is not wholly instrumented. The replication fixture
also passes a scoped ASan/UBSan run with leak detection disabled. These checks
do not supply a full-suite result or change the outstanding durable 2PC and CT
promotion-chain work.

The combined library/daemon build and focused checks pass for vector
admission/persistence, table/SQL publication, replication, mixed adapters,
tenant isolation, hybrid RESP, UWP regression (29/29), ownership journal and
abort/replay. A forced raw-fallback fixture verifies tenant/classification
denial, Operator access, a 40,000-byte GET and an 80,000-byte MGET payload.
That fixture passes ASan/UBSan with leak detection enabled. The mixed adapter
fixture passes scoped ASan/UBSan (leak detection disabled) and ThreadSanitizer
with the vector/UWP units instrumented; the whole linked library is not
instrumented. No live data was read, migrated or restarted by this review.

The first raw-fallback fixture teardown removed an active audit lock and
correctly triggered continuity enforcement. Teardown now shuts down the audit
writer before deleting its private test files. The leak check separately
exposed the owned GET/MGET result leak above; it passes after freeing those
results. The audit enforcement was kept intact.

Additional focused targets are part of future suite discovery. From a built
checkout, reproduce this pass with:

```sh
make -j8 lib cluster-daemon
make -o lib test-repl-io-alloc test-vector-wal-admission test-persist \
  test-sql-delete-failures test-repl test-resp-raw-vector-tenant \
  test-vector-adapter-concurrency test-vector-tenant-isolation \
  test-resp-hybrid test-uwp-regression test-ownership-journal \
  test-ownership-abort-replay
```

### Spill, creation and request recovery (2026-11-10)

The next review reproduced spill/snapshot data loss and repaired its connected
failure paths. These are local source changes; no live data was inspected or
migrated and no service was restarted.

| Area | Confirmed defect | Repair and focused evidence |
| --- | --- | --- |
| Spilled vectors | After spill, a subsequent mutation and flush serialized zeroed RAM instead of the spilled payload. `[1,2,3,4]` reopened as `[0,0,0,0]` in the reproducer. Budget disable ignored restore failure and deleted backing; compaction retained old positional tier state. | Materialize the payload before snapshots, compaction and index construction. A failed restore preserves backing, remaining spill markers, the prior budget and pending WAL. Successful compaction resets positional tracking. Flush/compact/reopen, injected read failure and retry tests preserve exact vectors. |
| Spill ownership and restart | Fixed `<database>.spill` paths could be truncated by another handle; persistent SPILLED hints referenced backing that does not survive restart. Missing tier hints also left tracking arrays uninitialized. | Each handle owns private anonymous temporary backing. Initialize tracking before mapping snapshots, normalize transient SPILLED hints to DRAM, and use exact-I/O helpers. Tests check two handles, an untouched fixed-path sentinel, absent tier hints, read-only mappings and derived-cache construction. |
| Container creation | Successful initial creation did not sync the inode and parent entry; the VDB constructor ignored create failure. A failed sync followed by retry could skip syncing the leftover valid header. | The explicit create path syncs file and directory, and retries re-sync both. Existing `create=false` WAL opens remain sync-free. Propagate constructor failure. File/directory fault tests cover same-path retry; container lifecycle and replacement-lock tests pass. Per-mutation vector WAL batching was retained; explicit flush remains its durability boundary. |
| Raw RESP framing | One read was treated as one request, losing fragmented and pipelined input. Length parsing and inline argument overflow could accept malformed/truncated commands; socket write failures were not consistently terminal. | Bounded incremental framing preserves incomplete input and consumes one frame at a time. Reject malformed lengths, NUL fields and excess arguments; retry interrupted receives and drain short writes. Split-array, split-inline, pipeline, bounds, send-pressure and closed-peer tests pass. |
| Transfer outcome | PREPARE could fail after durable intent/fencing but report REJECTED, which implies no prepared transfer. An errno alone cannot distinguish preflight failure from a sync error after a complete write. | Preserve existing APIs through wrappers and propagate an explicit journal-write uncertainty result to the manager's PENDING result. Keep definite pre-admission failures rejected and retain the original error reason. Fault injection performs a real fsync then returns EINVAL: replay finds the INTENT and the API reports possible writing; duplicate-ID rejection reports no write. Manager tests cover recovered/unreadable PREPARED state and definite rejection. |

Spill is best-effort logical payload residency, not a hard process-RSS cap.
Snapshot, compaction and derived-index construction can temporarily restore the
complete payload to RAM. This preserves data at the cost of temporary memory
residency; no RSS or throughput improvement is claimed. This repair cannot
reconstruct data already overwritten by an older snapshot.

The standalone spill fixture passes strict compilation and ASan/UBSan with
leak detection enabled, instrumenting the changed vector unit. The raw framing
fixture also has focused sanitizer coverage; full-library sanitizer coverage
and the full suite are separate. The scoped DDL/schema/retry-ledger review
found no additional confirmed defect and produced no patch.

The combined library and daemon build passes. Integrated spill, persistence,
creation sync/locking/lifecycle, framing, raw tenant-denial and transfer checks
pass. Both the spill and raw-framing fixtures pass scoped ASan/UBSan with leak
detection enabled. The new cases are registered for future full-suite runs.
The final integrated journal-write-status, transfer-manager and ownership-abort
replay checks pass, as does the generated API-count check. The complete suite
remains paused at the user's request; no deployment was performed.

Additional focused targets:

```sh
make -j8 lib cluster-daemon
make -o lib test-vector-spill-recovery test-persist test-container-create-sync \
  test-container-flush-locking test-container-lifecycle test-resp-wire-framing \
  test-resp-raw-vector-tenant test-cluster-transfer \
  test-ownership-journal-write-status test-ownership-abort-replay
```

### Range transfer and durability review (2026-11-10)

The follow-up review covers cluster lifecycle/placement, backup and restore,
transaction recovery, storage lifecycle, derived indexes and other protocol
adapters. These remain local changes; no live service or dataset was changed.

| Area | Confirmed defect and resulting behavior |
| --- | --- |
| CT2 capacity and restart | Remove the fixed whole-transfer 4096-row/64-MiB cap across source export, target staging and import. Import uses bounded QKV6 groups with durable QCTST003 prefix progress and reads existing QCTST002 state. An exact persisted target-fence retry can resume after process-local admission is lost on restart. The fault fixture crashes after its first group fsync, resumes to exactly two groups, and exposes 4097 transferred rows only after activation/reopen. Its source image is **67,284,039 bytes total**. |
| Migration acknowledgements | SEAL/ACTIVATE could finish durably but a lost command reply forced another manual retry before receipt lookup. The manager now checks the existing pinned, typed receipt after either command attempt. Exact receipt evidence completes that invocation; an unavailable or forged receipt cannot publish ownership. This removes an acknowledgement prerequisite by recovering the actual outcome. |
| Migration retry and restore friction | Exact COMMITTED retries now validate the durable tuple and current trusted identity/pin mapping without requiring the old source-owned slots or PRIMARY roles to remain unchanged. New-transfer admission and per-slot publication ordering still apply. Backup/restore writers reserve unique scratch inodes; restore stages in the target data directory, requiring only read access beside its input archive. A nonempty CT-disabled target can be atomically replaced; the restore command's normal store startup recovers pending intent. |
| KV compaction and exports | Failed input-file cleanup resurrected deleted and expired keys; a forgiving damaged-row scan could publish incomplete full, replica, delta and owner-data exports and then delete compaction inputs. Recovery-producing scans now stop on corruption. Publish and sync the replacement before retiring inputs; retain dead states while older files can survive, check cleanup errors and preserve accurate live-file counts. Failed export leaves an existing destination unchanged. |
| Degraded KV reads | The metadata-index fallback loaded SSTables into RAM and unlinked their only durable copies. A read/export followed by process exit lost a previously durable key. Materialization now retains original SSTables until a durable replacement retires them. Compaction also retains disk versions shadowed by RAM whose WAL replacement may not yet be fsynced. The restart regression fails before this change and passes afterward. |
| Expired delta replacements | Legacy delta export skipped an expired replacement, allowing a lagging consumer to keep an older non-expiring value after its cursor advanced. Emit a tombstone at the replacement's original sequence with its classification/SCI and no value. RAM/SST fixtures cover the later cursor and low-clearance/missing-SCI exclusion without relying on a sweeper. This is separate from CT1's grouped replication journal. |
| Native container WAL | Appending/truncating a V1 WAL rewrote length metadata in place; interruption could make the container unreadable before record-tail recovery ran. V2 keeps WAL as the final EOF extent, with no per-append table/header rewrite. Existing V1 files remain readable and convert atomically on their first WAL mutation, preserving persisted sections without publishing pending caller buffers. Partial append rolls back its tail; failed rollback requires reopen. Explicit sync covers both inode and parent entry, including a retry after uncertain migration rename. Fault tests cover failed append/rollback/rename/directory sync and reopen; vector WAL, read-only, spill and persistence fixtures pass. |
| Transactions and WAL | Terminal transaction handles/write sets were orphaned; UWP could drop pending COMMITTING/ABORTING handles. Add explicit terminal release, release consumed UWP/PG handles, and keep pending work attached for retry. A complete WAL write followed by failed fdatasync now disables that writer until reopen rather than allowing later records to make an ambiguously acknowledged operation durable. |
| Vector/HNSW lifecycle | Mutations left graph/INT8/binary candidate indexes valid and sidecar loading ignored post-WAL generations. Invalidate stale accelerators with exact fallback, validate live generations and keep read-only builds ephemeral. Fix over-aligned HNSW allocations and propagate build allocation failures instead of publishing an incomplete index. The existing void insertion API remains as a compatibility wrapper. |
| Other protocols | BSON builders could dereference failed allocations, miscount serialized terminators or partially replace fields; grouped aggregation array growth was not allocation-atomic. Bolt wrapped chunk lengths above 65535 bytes, and socket/buffer failures could lose framing. PG could emit incomplete messages after allocation failure. Preserve BSON/Bolt public struct layouts, check construction failures, split Bolt chunks, terminate failed writes and protect PG TLS writes from SIGPIPE only in the writing thread. |
| Projection identity | The SQLite cache identity included model and dimension but its filename did not. Cache files now include both, so shutdown/re-enable selects a compatible cache after a provider change. An enabled fixture uses actual KEYSTONE with deterministic provider/ONNX-active test substitution; it checks model and dimension changes without KV mutation. It does not validate a real ONNX model or remote service. Hot provider replacement still requires projection shutdown/re-enable. |
| Delayed CT1 events | A historical promotion could adopt unresolved slots after the target's node relationship had advanced. Keep those slots unresolved and preserve current roles. Tests retain the earlier replica cases and add advanced-primary coverage; this does not implement missing predecessor-chain recovery. |

The transfer has no fixed aggregate row/image cap, but still needs its configured
replication-log retention capacity, available disk/RAM and representable file
offsets. Target import materializes incoming/existing rows; memory is proportional
to the range. Compaction retains dead states until input retirement is durable,
then uses a second rewrite when needed to preserve ordinary GC behavior. Failed
cleanup retains them for retry. The unchanged projection-epoch/GC regression
caught the initial over-retention and passes after that correction. Terminal
transaction release frees the handle/write set; manager arena shells remain
until manager destruction. No throughput or RSS improvement is claimed.

The combined library/daemon build and focused checks cover protocol write and
allocation faults, PG/UWP transaction behavior, WAL durability, BSON and adapter
denials, vector lifecycle, HNSW allocation failures, compaction/recovery/export
faults, ownership replay and interrupted large transfer. Scoped protocol
ASan/UBSan passes with leak detection enabled; changed HNSW/vector and BSON
units also have focused sanitizer evidence, not whole-library coverage. The
container WAL fault fixture passes scoped ASan/UBSan with leak detection enabled.

Reproduce the principal focused checks from a built checkout:

```sh
make -j8 lib cluster-daemon
make -o lib test-protocol-io-failures test-pg-wire-txn test-sql-dml-exec \
  test-txn test-wal-durability test-mongo-bson-builder test-mongo-wire-security \
  test-vector-derived-lifecycle test-hnsw-allocation-failures
make -o lib test-kv-compaction-recovery test-ownership-journal-write-status \
  test-ct-transfer-storage test-cluster-transfer test-ct-transfer-large
make -o lib test-container-wal-recovery test-container-create-sync \
  test-container-lifecycle test-container-flush-locking test-vector-wal-admission \
  test-vector-spill-recovery test-persist
make test-aimem-projection-model-swap QIHSE_ENABLE_AIMEM_KEYSTONE=1 \
  QIHSE_AIMEM_KEYSTONE_INCLUDE=../KEYSTONE/include
```

Container migration is lazy and needs no separate conversion command. Its first
WAL mutation copies the existing container once; normal appends retain existing
batching. Explicit sync now also syncs the directory, adding that I/O at the
existing durability boundary. V1-only binaries cannot read newly written V2
containers, so a binary downgrade requires a compatible backup. Record checksums
are not cryptographic authentication; V2 repairs crash recovery, not that
separate integrity limitation. No latency improvement is claimed.

Still open: authenticated missing-promotion chains; per-range replication roles
(a daemon still has one CT role/peer and a dedicated slotless successor);
consensus-backed range arbitration for automatic balancing under divergent
partition views; durable generic 2PC coordinator decisions and general SQL WAL
redo; cryptographic binding of container section metadata and WAL records; and real remote
KEYSTONE/ONNX readiness. Automatic rebalance is opt-in in the source, not a
default cluster guarantee. No live partition incident is claimed by this
source review. The full suite remains paused at the user's request; these
repairs have not been deployed.

## Resolved: expiry sweep and SSTable compaction

The standalone daemon now defaults to a 30-second KV sweep cadence (`--kv-sweep-interval`, with `0` explicitly disabling it). In the earlier 2026-11-05 verification, authenticated QKP `PING` returned `PONG`; INFO reported sweep interval `30`, sweeper running, one live SST file, no degraded SST index, and healthy status. The previous 1,227 live SST files were compacted to one. The suite passed 164 targets at that time. The 2026-11-09 deployment obtained authenticated INFO and verified healthy SST indexing, a 30-second sweep interval and an active sweeper.

## Protected backlog

The bridge backlog was last verified as 260 blocked and 7 queued. No replay, deletion, or mutation was performed; preserve it until separately authorized and investigated.


## Cluster rollout update — 2026-11-11

Native code revision `0925649` is deployed to all six cluster daemons across
T420, 730xd and T320. Owner counts and slot maps are unchanged; all three
configured replication pairs are caught up. All nine failed non-gold targets
and the three failed gold workloads pass targeted retests. The full rerun was
stopped after 62 clean targets at the user's request; no new full-suite pass
is claimed. Historical source-only notes above retain their original scope.
The separate standalone HAX AIMEM service was not changed.

T420's online owner BACKUP creation returns a generic creation/authorization
error even though ordinary owner inventory succeeds. No fresh backup artifact
was published. This remains open alongside the documented CT cleanup and
placement residuals. The [range-group deployment record](validation/cluster_range_groups_20261110.md#live-native-deployment--2026-11-11)
contains the current evidence; [ROADMAP.md](../ROADMAP.md) remains authoritative.

### Owner-backup follow-up — 2026-11-11

Revision `8a8593e` fixes the live failure: the snapshot readiness check now
accepts completed CT2 history but still refuses active transfer states. Three
focused tests and a scoped KV sanitizer run passed; no full suite was rerun.
Native packages were rolled to all six daemons one at a time. Authenticated
owner counts and slot maps stayed identical, and all three replication pairs
remained caught up. All three owners exported data-only backup containers, and
offline verification passed for each. T420's backup restored into an isolated
CT-disabled store with the same authenticated 8,858-record count. The earlier
failure above is retained as historical evidence; CT cleanup and placement
residuals remain open. The [live repair record](validation/cluster_range_groups_20261110.md#live-owner-backup-repair--2026-11-11)
contains the exact scope.
