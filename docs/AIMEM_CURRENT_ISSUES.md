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

Vector handles still require callers to synchronize shared access. The primary
RESP server holds its existing vector lock; adding authenticated mutation
forms does not make the native handle or every legacy/UWP sharing arrangement
internally thread-safe. Omitted batch metadata (`metadata_sizes == NULL`)
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

## Resolved: expiry sweep and SSTable compaction

The standalone daemon now defaults to a 30-second KV sweep cadence (`--kv-sweep-interval`, with `0` explicitly disabling it). In the earlier 2026-11-05 verification, authenticated QKP `PING` returned `PONG`; INFO reported sweep interval `30`, sweeper running, one live SST file, no degraded SST index, and healthy status. The previous 1,227 live SST files were compacted to one. The suite passed 164 targets at that time. The 2026-11-09 deployment obtained authenticated INFO and verified healthy SST indexing, a 30-second sweep interval and an active sweeper.

## Protected backlog

The bridge backlog was last verified as 260 blocked and 7 queued. No replay, deletion, or mutation was performed; preserve it until separately authorized and investigated.
