# Three-host cluster recovery and native upgrade

Date: 2026-11-09
Status: source-level range balancing is validated. All nine services are stopped;
all nine authenticated full backups verify, the three main-store deltas are
preserved, and the merged union backup verifies. Fresh-generation restore and
the new topology deployment remain pending.

Step 1 checkpoint: the demonstrated 730xd-to-T320 alias ARP failure was
repaired at the user's request using a persistent verified neighbour mapping.
T320 subsequently reported the peer connected and cluster state OK. Ownership
maps still disagree; data recovery and deployment remain in progress.
See [network evidence and repair](../validation/cluster_membership_20261109.md).

## Decision

Use one coordinated recovery, native builds on all three hosts, and CT2
redistribution. Prepare and validate the changes before the outage. Continuing
rolling restarts while nodes disagree about ownership will not repair the
cluster.

The end state is three machines owning data, with durable replicas on other
machines, automatic balancing, and tested automatic failover. There is no
permanent primary machine. Per-shard primary and successor roles remain part
of the current transport implementation.

[ROADMAP.md](../../ROADMAP.md) remains the authoritative delivery inventory.
This document records the recovery decision and execution order, not a second
completion roadmap.

## Findings established during the study

- All three cluster services still run the older versioned release. The new
  CT1/CT2 source has passed the complete 203-target suite with zero failures,
  but has not been deployed to these services.
- The three live ownership maps disagree. T320 reports 730xd failed or
  disconnected. Shared Operator credentials match; a credential-derived bus
  key mismatch was not observed. The exact cause of failed-peer reports is
  still unproved. Reachable client ports do not establish healthy bus traffic.
- The legacy `qihse_cluster_handoff_range()` / `MOVESLOTS` path is still
  fenced off. Manual `CLUSTER CT2 TRANSFER` and populated-owner brain R5 use
  the durable `qihse_cluster_transfer_range()` engine instead.
- The four-daemon `test-ct-brain-balance` drill now passes twice against the
  main build. It moves a range between two populated primary processes, each
  with an independent CT1 successor, and verifies 8,192/8,192 slot ownership,
  all-peer convergence, preserved values/TTL, writes and donor restart. The
  test retries only the documented CT1 reconciliation `TRYAGAIN` during
  startup; it still requires every peer to converge before its deadline.
- CT1 primary/successor roles belong to logical daemon processes, not physical
  hosts. The three-host placement can spread primary-owned ranges across all
  machines; the cluster has no machine-wide primary. `--replica-of` supplies
  trusted process-role metadata to each local topology because remote daemon
  roles are not currently learned dynamically. This is fixed startup
  placement metadata, so automatic replica reassignment remains a separate
  open item.
- CT2 failed-owner re-home (brain R1) remains disabled in this mode; CT1
  failover handles owner promotion. The old MOVESLOTS path must not bypass CT2
  fencing.
- Enabling the brain marks its maintenance-writer coverage incomplete;
  combining it with startup maintenance holding cannot currently seal the gate.
- Automatic CT1 promotion is disconnected. The configured election callback
  accepts only authenticated manual Operator promotion; the automatic path
  still lacks the runtime completion hook.
- CT1 roles are exclusive per process. Three data owners therefore need three
  separate successor processes, placed on other hosts. A host failure also
  requires replacement replica capacity on the surviving hosts.
- Reclamation and range probing exempt bare AIMEM prefixes but miss tenant
  scoped AIMEM keys and related state. Fix and test that classification before
  enabling reclamation around recovered memory data.

Relevant source:

- [Brain placement and movement](../../src/spinnaker/qihse_cluster_brain.c)
- [Transfer, promotion and routing integration](../../src/spinnaker/qihse_resp_engine.c)
- [Failover coordinator](../../src/spinnaker/qihse_cluster_failover.c)
- [Reclamation](../../src/spinnaker/qihse_cluster_reclaim.c)
- [Daemon startup and role configuration](../../tools/qihse_cluster_daemon.c)
- [CT1/CT2 contract](ct_transport_runtime.md)
- [Transport validation](../validation/ct_transport_20261109.md)

## Data to preserve

These are observations from the study, not cutover-time counts. Refresh them
under the coordinated write stop.

| Service | Last verified inventory | Recovery consequence |
| --- | --- | --- |
| T420 cluster service | 0 keys; 0 AIMEM records | Still take a backup and preserve configuration/identity. |
| 730xd cluster service | 271,138 keys; 309 AIMEM records | Candidate temporary recovery seed because it holds most observed cluster data. |
| T320 cluster service | 296 application/tool keys; 0 AIMEM records | Preserve and reconcile these records; they are not proven duplicates or disposable bookkeeping. |
| Separate local HAX memory service | 97 records visible in the `hax` project scope | This is a separate service and a scoped count, not its total dataset. Cluster slot transfers do not migrate it. |

Authenticated Operator QKP probes on 2026-11-09 also found six active
read-only namespace replica services outside the three main cluster units:

| Host | Service / namespace | Keys | Current upstream |
| --- | --- | ---: | --- |
| T420 | `qihse-replica-keystone` | 3 | 730xd `192.168.1.90:7115` |
| T420 | `qihse-replica-kp14` | 56 | 730xd `192.168.1.90:7115` |
| 730xd | `qihse-replica-audit` | 352 | 730xd `192.168.1.90:7115` |
| 730xd | `qihse-replica-chain` | 40 | 730xd `192.168.1.90:7115` |
| T320 | `qihse-replica-sabot` | 212 | 730xd `192.168.1.90:7115` |
| T320 | `qihse-replica-tool` | 167 | 730xd `192.168.1.90:7115` |

These 830 cached keys must be included in the cutover inventory. Their
read-only status and upstream do not prove every cached row is still present
in 730xd's main store. Take authenticated full backups of each cache while its
service is stopped, compare their records against the reconciled main-store
union, and account for any unique or conflicting rows before retiring or
reattaching the cache services. Do not leave them pointed at the old 730xd
endpoint after cutover. Authenticated `REPLSTATUS` reported `sync=ok` for all
six during the probe, but each showed `pulled=0`; this is not a record-level
equality proof. No current TCP clients were connected to their ports during
the sample, and the targeted HAX/QIHSE documentation/config search found no
endpoint references. Confirm consumers again before retiring them.

The direct T320/730xd value-comparison probe stalled and was stopped. It
produced no trustworthy comparison counts. Do not treat its result as proof
of duplication.

`qihse-backup restore` replaces the target store. Applying several full backups
to the same directory does not merge them. CT2 likewise authoritatively replaces
the transferred range and can remove target-only rows in that range. Reconcile
the datasets before using either operation to consolidate ownership.

## Execution order

### 1. Finish source preparation while services remain running

The focused transfer integration is complete: `test-ct-slot-transfer` and the
four-daemon `test-ct-brain-balance` pass, and the brain calls the same durable
CT2 range-transfer operation as the manual command. The full required suite
also passes. The transfer moves ranges between logical daemon processes; it
does not assign a permanent primary role to a physical host.

| Workstream | State and remaining result |
| --- | --- |
| Network and membership | The 730xd-to-T320 neighbor repair is in place. Reconcile the live ownership maps and prove bus membership before cutover. |
| Automatic balancing | Populated-owner R5 CT2 balancing is implemented and tested **by slot count**. It has no bytes/capacity weighting, so it must stay disabled for this uneven three-host layout until a capacity-aware policy is implemented and tested. Keep CT1 replica role mapping explicit in each process configuration; dynamic remote role discovery/reassignment remains open. |
| Automatic failover | Still open: connect an authenticated quorum/authority decision to CT1 promotion, complete generation/listener recovery, and provision successor capacity after a host failure. |
| Recovery and memory preservation | The authenticated bounded merge and transfer locality checks are tested. Refresh live inventories, preserve conflicts and scoped AIMEM state, and verify the restored union before reopening writes. |

The recovery helper must preserve distinct records, labels, SCI, tenant
attribution and absolute expiry. Deduplicate only verified identical records.
Retain and report conflicting versions with source provenance; do not compare
independent node sequence numbers as if they were a global clock or silently
overwrite a version. Resolve active-key conflicts before reopening writes.

Use existing authenticated backup/KV APIs with an explicit principal. Do not
read configured storage files directly or build a new general administration
framework for this recovery.

### 2. Publish and build one source revision

Create a reviewed source commit containing the integrated changes and tests.
Exclude credentials, generated artifacts, runtime state and private captures.
Publish that revision and build it natively on all three machines in parallel.

T320 lacks F16C; T420 supports F16C but lacks AVX2; 730xd supports AVX2/FMA/F16C.
Do not distribute one host's binary as the build for all three.

Reuse the existing per-host native build and packaging workflow in fresh
versioned staging directories, with same-host dependency reuse. Stage the
complete launcher/library/binary release and update the actual systemd release
path during activation; copying an executable into an unused install directory
does not deploy it.

Run focused checks, then the required integrated suite:

```sh
make test TEST_JOBS=32
```

Also run native transport and package checks on each host. Complete builds,
package checks and recovery-helper rehearsals before the outage.

### 3. Take one coordinated outage and back up every node

Stop all three main cluster daemons and the six read-only namespace replica
services together. Take separate authenticated full backups of all nine
stores; also export authenticated retained deltas from the three main stores
for tombstone evidence. The delta helper must receive that store's explicit
`QIHSE_DATA_DIR` (T420 `/opt/qihse-data/node0`, 730xd
`/opt/qihse-data/node5-host`, T320 `/opt/qihse/data/node1`) to avoid its
fallback selecting the wrong directory. Delta exports are evidence only, not
restorable snapshots or a complete cross-node deletion history. Verify the
full backup containers and keep the six cache backups separate until their
contents are reconciled. Preserve configured identities, pins, credentials
and service configuration separately: a KV backup is not a complete
authentication or cluster backup.

Execution checkpoint (2026-11-09): the coordinated stop is complete. All nine
full backups passed authenticated verification. The three main-store delta
exports were captured separately (`since_seq=0`) for deletion-history evidence.
The 730xd and T320 full images copied to T420 have matching source/destination
SHA-256 hashes. Original stores remain stopped and intact.

Fresh directories avoid replaying contradictory ownership journals. Keep the
original stopped stores and verified backups until the recovered dataset and
cluster pass acceptance. Do not use the historical rolling-restart script.

Retain the existing Operator and service-account configuration. Durable
authentication-authority migration is not a prerequisite for this ordinary
binary/data recovery.

### 4. Reconcile the datasets into a fresh generation

The verified 730xd full image is 1.76 GB, above the former 1 GiB merge ceiling.
The bounded merge ceiling has been raised to 3 GiB (the default remains 1 GiB),
and the focused merge test plus the required `make test TEST_JOBS=32` suite pass.

The nine full backups were reconciled into
`qihse-union-08-t320-tool.qbk` on T420. Authenticated merge accounting reports
296 added T320 records, 830 exact duplicates across the six namespace caches,
and zero conflicting live keys. T420's main backup was empty. The final union
is 1,764,599,446 bytes and passed authenticated verification. All source full
backups and three main-store deltas remain preserved; intermediate union files
also remain available. No store has been restored yet.

Next restore the verified union into a fresh generation with an Operator auth
context, then partition and transfer ranges using the tested CT2 path. Preserve
the old stores and source backups until the accepted new cluster proves the
recovered union. The restore target needs a usable Operator auth context before
the restore command runs; bootstrap it through the configured Operator
credential rather than assuming restore creates identity state.

Verify the recovered union using canonical record comparisons, including
labels and expiry, not counts alone. Expired records must be accounted for
without resurrecting them. Do not admit writes or reclamation under the old
contradictory ownership maps.

### 5. Start the replicated cluster and redistribute

Configure one coherent topology with three data owners and three separate
successor processes, each successor on another physical host. Verify capacity
for both owned data and replicas before selecting the placement.

Bring up the fresh generation with startup maintenance and failover holds
until topology and replication prerequisites are satisfied. Use the tested
Operator CT2 transfer path for initial distribution, retaining transfer IDs
for interrupted retries. Keep automatic R5 rebalancing disabled during this
uneven-capacity rollout: its current target is equal slot counts, which can
undo the capacity-weighted placement. Each transfer is bounded to 4,096 rows
and 64 MiB; subdivide ranges accordingly. An oversized individual slot
requires explicit handling, never truncation.
Set `--brain-rebalance-min-slots 0` on each brain process for this deployment;
zero disables R5. Manual Operator CT2 transfers remain available.

All three machines must own data after distribution. Choose allocation using
actual stored bytes and available capacity rather than assuming equal slot
counts produce equal storage. 730xd's temporary seed role ends after recovery
and distribution. Enable the repaired automatic balancing policy afterward.

The separate upgraded HAX memory service remains available during cluster
preparation. Its memories do not become cluster-distributed merely because
cluster slots moved; preserve its endpoint and validate its reads separately.
After the new owner/replica ring is healthy, reattach the six namespace caches
only if their consumers still require those endpoints; point them at the
appropriate new owner and verify their filters. Otherwise leave them stopped
with their verified backups retained, after confirming no configured consumer
depends on them.

### 6. Verify the finish line

Acceptance requires:

- All peers agree on ownership and remain healthy beyond failure-detection
  intervals, with no competing owner for a slot.
- Every retained record is accounted for, including T320-only data, labels,
  absolute expiry, AIMEM auxiliary state and resolved conflicts.
- All three machines own data and each owner has a durable off-host successor.
- Automatic balancing successfully moves data between populated nodes and
  recovers an interrupted transfer without violating per-host disk budgets.
  The current slot-count-only R5 policy does not meet this gate on the
  heterogeneous hosts; keep it disabled until capacity-aware behavior passes.
- Failure/rejoin testing proves automatic promotion, fencing of the old
  generation, replacement replica coverage and continued reads/writes.
- HAX exact reads and BM25/semantic/hybrid memory operations still work.
- Focused tests and the complete required suite pass without weakening tests.

Only then describe the cluster as fully repaired. If recovery succeeds before
automation is complete, report that narrower result explicitly.

## Timing and recovery boundary

Previous parallel native builds plus focused checks took 9–12 minutes across
these hosts. One previous full-suite run added about 90 minutes. Those timings
are from older source; they are estimates for planning, not measurements of
the proposed changes.

The missing integration dominates the work: this is an hours-scale repair,
not a restart-only fix. Keep compilation and validation outside the outage.
Measure backup/restore throughput and replica baseline size before estimating
the outage duration.

Before reopening application writes, the preserved original stores/backups
provide a recovery point. After new writes are accepted, simply restarting old
stores would lose those writes; use forward recovery or an explicitly reconciled
new backup instead. Do not promise an automatic rollback after cutover.

## Checkpoint

At plan creation, no live cluster stop, restart, backup, restore, transfer,
promotion or configuration change had been performed during the study. Source
transport validation is complete; see the execution checkpoint below for live
recovery progress and remaining automation work.

## Current execution checkpoint (2026-11-09)

- The T420-to-T320 persistent neighbour repair is in place. The coordinated
  outage stopped all three main services and six namespace replicas; old
  stores and ownership journals remain intact.
- Candidate source `fc4fe6cb00205dda55dcbef4327548fd755cedb5` is published and
  natively built on all three hosts. Inactive package directories are named
  with `fc4fe6c`; all three checksum manifests validate 104 files. No systemd
  unit has been changed.
- The source now includes the 3 GiB bounded backup-merge ceiling required by
  the 1.76 GB source image. Focused merge tests pass; the full required suite
  passed 203 targets with zero failures.
- Nine authenticated full backups verify. Main-store delta evidence is
  preserved separately. The merged full container verifies and accounts for
  296 new records, 830 exact duplicate cache records and zero conflicts.
- No restore, range transfer, new service activation or live ownership change
  has been performed. The next phase is fresh-generation restore and topology
  staging; capacity-weighted initial placement still requires a measured
  per-range byte inventory.
