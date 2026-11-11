# Cluster range-group repair — 2026-11-10

This is a source integration record. It is not a live deployment result.
The authoritative program checklist remains [ROADMAP.md](../../ROADMAP.md).
CT.1 and CT.2 remain partial for the documented cleanup/placement residuals.

## Integrated and verified

| Area | Evidence |
| --- | --- |
| Automatic CT2 selection | Four-daemon balance drill passed without a donor floor override or optional observation-journal signing configuration. Pending operations keep their immutable identity across source-generation changes. |
| Completed CT2 retry | Transfer-manager tests verify local completion from durable FINALIZED evidence without requiring the former target to be online. COMMITTED still requires the target's typed activation receipt. |
| Signed cluster bus | Actual production sender-to-UDP-receiver fixture verifies maximum ML-DSA-87 signatures and payloads. Sender endian selection, signature/trailer offsets and signed receive-buffer sizes were repaired. |
| Transfer size metadata | Production parser accepts 67,284,039-byte images and the signed 64-bit limit; malformed/overflow inputs remain rejected. Bounded frame and replication-log limits remain. |
| Quorum range history | Consensus mesh fixture covers follower submission, committed genesis/reserve/finalize, low-clearance denial, inherited uncommitted terminal entries, lost reply, leader loss, restart, exact retry and conflicting operations. RESERVED lookup does not disclose an uncommitted terminal decision. |
| Independent replication groups | Storage fixture has one store own A and receive B, restart both, and promote B while A remains usable. Context state uses field-wise persistent encoding and an explicit old-reader format fence. |
| Per-group retained logs | The focused fault-enabled KV fixture passed in the integration worktree: ACK collection on A preserves B's independent retained log; restart resumes at the next position; a crash after frame sync and before header publication recovers from WAL. WAL replay now uses its recovery descriptor instead of the not-yet-open append stream. The combined owner/receiver daemon path now passes the three-node transfer and promotion drills. |
| Authority adapter | Focused adapter fixture and scoped ASan/UBSan run passed for principal propagation, immutable grants, typed activation binding, sparse/empty-stream promotion and persisted readiness-marker binding. This fixture uses a mesh boundary double; it does not substitute for runtime integration. |
| Promotion lineage | Real signed A-to-B-to-C chain receiver tests passed, including reversed and conflicting chains, non-Operator denial and journal replay with role preservation. The paginated client separately passed framing, pin/auth, invalid signature/digest, no-progress and uncommitted-event filtering checks plus scoped ASan/UBSan. The real A-to-B-to-C daemon drill now passes the transport/callback path and missed-ancestry recovery. |

The integrated library and legacy daemon build succeeded. Focused legacy CT
storage and codec authorization checks also passed after the group foundation.
The complete `make test TEST_JOBS=32` run finished on 2026-11-11:
**248 targets, 238 passed, 10 failed.** The new multi-group transfer/promotion,
brain balance, consensus mesh and CodeGraph targets passed. This is not a
complete-suite pass or a live deployment result.

Failed targets: `test-ct-slot-transfer`, `test-resp-hybrid`,
`test-bus-signed-ops`, `test-public-api-install`, `test-vector-wal-admission`,
`test-resp-raw-vector-tenant`, `test-vector-spill-recovery`,
`test-vector-derived-lifecycle`, `test-hnsw-allocation-failures`, `test-gold`.
The legacy CT2 drill reaches source MOVED while its destination still reports
ownership recovery; signed-bus certificate creation fails; the installed SDK
omits the transitively required group-config header. Vector creation/flush
assertions need investigation. Gold additionally expects an obsolete graph
result line despite the underlying graph target exiting successfully; its
other two failed workloads repeat RESP hybrid and legacy CT2 failures.
These are observed failure signatures, not established root causes.

## Follow-up repairs — 2026-11-11

The first complete run above exposed four repair groups. All nine failed
non-gold targets and all three failed gold workloads now pass. The follow-up
runs seven direct targets plus the three failed gold workloads; gold runs the
failed RESP hybrid and legacy CT2 targets, avoiding duplicate executions.
The replacement full run was stopped at the user's request after 62 targets
passed with no recorded failures. This is targeted follow-up evidence, not a
new full-suite pass. Source repairs are published as `0925649` on
`candidate/cluster-recovery-20261109`; native deployment packages are being
staged separately.

- Legacy CT2 could durably finalize target activation while successor/replay
  admission was still pending. RECEIPT now retries and verifies admission before
  reporting ACTIVATED for a fenced legacy destination. The real interrupted
  transfer/restart/reverse-transfer drill passes with an immediate destination
  read after COMMITTED. Boundary tests cover ACK lag, unresolved/failed replay,
  wrong successor pin, target cursor shortfall, successful retry, historical
  receipts and unchanged group pre-FINAL readiness.
- The signed-bus fixture omitted the base seal and used topology upsert as an
  identity override. Correct fixture binding exposed a runtime signer bug:
  ordinary maximum-size datagrams incorrectly used the smaller certificate
  bound. Ordinary signed frames now permit 12,860 bytes; CT1 certificates remain
  capped at 8,192 bytes. Signed-bus, federation trust, journal and scoped
  ASan/UBSan checks pass, with leak detection disabled for the sanitizer run.
- The SDK manifest now installs its required group-config header. Staged
  consumers use the actual transitive include layout and assert those files
  exist. C/C++ install checks and API-count checks pass.
- Six vector/RESP fixtures omitted container keys and failed under isolated
  suite key directories. They now generate private real test keys with normal
  integrity verification. All six affected targets and the unchanged production
  missing-key denial target pass; no production key gate was relaxed.
- Gold's graph evidence is updated from 19 to the actual 23 successful checks;
  the real graph gold workload passes with the evidence check retained.

## Current integration checks

- The library and daemon build with the shared group transfer finish path.
  Source COMMITTED and target COMMITTED are readiness receipts; group KV
  membership changes only after the actual common FINAL decision. Source,
  destination and successor use the same local finalization helper, including
  restart and missed bus delivery. The three-node protected transfer drill passes.
- `test-ct-lane-lifecycle` passes retirement, reserved receiver preparation,
  subtractive receiver pruning and exact-generation/token source disabling,
  including low/NULL principal rejection and persisted state.
- `test-ct-lane-commands` passes the existing group authorization and command
  regressions. `test-cluster-brain` passes its long-interval shutdown regression;
  stop now wakes the observation wait instead of waiting thirty seconds.
- `test-ownership-lane-transfer` passes source-only export commit, exact target
  cursor matching (zero is not a wildcard), wrong checksum/unverified grant
  rejection and low/NULL control identity rejection. Its storage and receipt
  boundaries are doubles; this is not daemon transport evidence.
- `test-ct-lane-transfer` passes a source-export regression with source cut one
  and independently chosen target cursor seven. Both hashes and both cuts
  survive reopen; a retry that changes the chosen cursor is rejected. A scoped
  ASan/UBSan run passed with leak checking disabled.
- `test-ct-group-claim` verifies the derived 2,801-byte wire layout with canaries,
  opaque provisioned QKP identities, strict generation/digest fields and invalid
  padding rejection. Its scoped ASan/UBSan run passed.
- `test-ct-lane-baseline` covers an empty group retaining stream cut five across
  restart and rejects a nonempty image for an empty bitmap. The new nonzero-cut
  regression failed before the correction and passed afterward.
- The lifecycle fixture applies an actual receiver frame, removes its slot,
  reuses an empty staging context in the same generation and reopens it.
  Bitmap changes checkpoint the historical shared WAL before publishing the
  new context; independent source logs retain their own ACK history. The
  combined regression fails on reopen without these checkpoints and passes
  with them; scoped ASan/UBSan passes with leak checking disabled.
- An authenticated QKP loopback peer regression accepts the full five-byte
  promotion reply and rejects malformed/truncated replies. Runtime pause and
  resume state checks pass. Pausing promotion no longer pauses committed
  membership reconciliation. The producer retry fixture also passes exact
  COMMITTED retries, recovery from common FINAL despite stale health, and
  denial of a low control principal. The storage fixture verifies retry after
  admission and subsequent writes/baseline refresh.
- The three-node ring has reached writes/replication on all three owners and
  ordinary restart. The staged denial probe uses the destination successor's
  low-clearance principal, preserving the source's current full-clearance
  replica. The complete protected A-to-C drill now passes all three common
  maps, exact completed retries while another move is pending, protected
  destination reads and CT1 drain. B starts with automatic takeover paused and
  still applies common FINAL. Source and immutable baseline bitmap digests
  are bound separately: a receiver waits for common membership reconciliation
  before accepting an image from a different scope. The prior unbound
  implementation intermittently returned a missing protected value after
  ownership converged.
- `test-ownership-lane-abort` passes typed common cancellation, low-control
  denial, crash after common ABORT before fence release, restart/replay,
  zero-cut pre-fence intent, old cancellation versus a newer active fence and
  staged target cleanup. Its authority boundary is a double; this does not
  replace the real-mesh decision tests.

## Promotion, partition and restart acceptance — 2026-11-11

The real three-daemon A-to-B-to-C drill passes. Every node initially owns one
group and replicates another. A fails; B promotes the first group while its
own group stays usable. B then fails. Returned A and surviving C cannot
acquire the affected range while their consensus traffic is partitioned.
After healing, insufficient receiver clearance and SCI separately prevent
protected baseline installation. Restoring the configured receiver identity
allows C to finish. A recovers the exact original B and C certificate bytes
while B remains offline. Writes, deletes and labels survive; returned A cannot
accept stale writes.

The integration reuses configured QKP keys for native group certificate
signing and verification. It adds no principal or enrollment CLI. Existing
revoked or mismatched keys are not overwritten; interrupted pending approval
of the same configured key can resume under the startup Operator.

Promotion INTENT can bind its previously unassigned quorum epoch exactly once;
known epochs and identities remain immutable. COMMITTED retries do not append
a second COMMITTED journal frame. Recovery from actual common FINAL uses the
original readiness marker, including after subsequent source writes and a
newer baseline, without repeating an obsolete election or RESERVED bind.
Historical certificate replication validates each original request against
its own common decision rather than the current hop's transport identity.

Consensus catch-up sends referenced historical payloads before their APPEND
records. A stream surviving an election reasserts current leadership before
staging. Bounded control-message priority prevents payload starvation. The
focused consensus mesh target passes, including its existing durability,
quorum, snapshot/resume and lost-ACK cases plus the scheduling regression.

## Remaining work and limits

- Source validation is complete for the requested failure-only rerun. Package
  staging and live activation are separate deployment steps.
- A cancelled temporary incoming receiver can retain its staging bitmap.
  Reuse for a different range after ABORT needs proof-driven retirement that
  preserves a legitimate pre-existing replica. Completed empty staging reuse
  is covered; cancelled nonempty staging reuse is not closed.
- Raw peer staging files need terminal-decision garbage collection. Immutable
  QKV7 recovery images must remain until their WAL references are checkpointed.
- Rebalancing a recovered physical node with no current SOURCE group needs
  explicit acceptance or a group-creation path. The passed automatic transfer
  drill targets a node that already owns a source group.
- Quorum replay indexes transfer IDs, reserve indexes and active slots;
  historical replay still scales with retained history without a checkpoint.
- No new throughput, record-count or byte-balancing improvement is claimed.

Slot distribution is not a measurement of balanced record counts, stored
bytes or CPU load. No performance improvement is claimed without a workload
measurement. Existing node-local namespaces, including AIMEM's local records
and indexes, are outside slot-range transfer. Preserving their native access
does not implement automatic sharding or balancing of the AIMEM dataset.
