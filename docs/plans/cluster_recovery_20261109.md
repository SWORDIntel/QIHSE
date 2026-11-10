# Three-host cluster recovery and native upgrade

Date: 2026-11-09 (updated 2026-11-10)
Status: all nine original stores were backed up and reconciled into one
authenticated union. That union was restored into a fresh generation and
independently compared as 271,434 identical records with zero additions or
conflicts. CT2 then distributed ownership across T420, 730xd and T320. Six
recovery services are enabled and active. A replay-order fix was natively
deployed on 730xd; all three owners now answer data commands and report the
same six-peer map, `cluster_state:ok`, and 16,384/16,384 assigned slots. The
required full suite passed 204 targets with zero failures. Per-owner key counts
sum to 271,462 at the latest probe, 28 above the authenticated union count;
this count difference is not yet classified by a fresh record-level backup
comparison. All 309 AIMEM records remain visible on 730xd. Keep the nine
original backups and merged union intact while reconciling this live inventory
and confirming CT1 stream health.

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

- The original live ownership maps disagreed. A verified neighbor mapping
  repaired 730xd-to-T320 discovery; the new topology now reports the same map
  and six connected peers from all three owners.
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
also remain available. Rechecking the union on 2026-11-10 produced SHA-256
`bf400593bb9157329626f8bedb0932904fc5f9c599c19a7c25be61c7fc20ea3e`.

The union was restored through the authenticated backup API into fresh 730xd
owner and T420 successor directories. An authenticated fresh backup from the
restored 730xd owner compared against the union as 271,434 identical records,
zero additions and zero conflicts. This verified the complete merged dataset
before CT2 partitioning. All source backups and the union remain preserved.

Verify the recovered union using canonical record comparisons, including
labels and expiry, not counts alone. Expired records must be accounted for
without resurrecting them. Do not admit writes or reclamation under the old
contradictory ownership maps.

### 5. Start the replicated cluster and redistribute

The fresh generation is running as one topology with three data owners and
three separate successor processes, each successor on another physical host.
The original services remain stopped. Use the tested Operator CT2 path for any
remaining data movement, retain transfer IDs for interrupted retries, and
never bypass the transfer's 4,096-row / 64 MiB bounds. The isolated slot that
exceeded the bound stays intact on 730xd.

Automatic R5 rebalancing remains disabled on the recovery units because its
current target is equal slot counts and is not capacity-aware. Manual Operator
CT2 transfers remain available. Do not enable R5 until a capacity-aware policy
has been implemented and tested.

All three machines now own data. The ownership map queried independently from
T420, 730xd and T320 is:

| Owner | Slots | Count |
| --- | --- | ---: |
| T420 A | `0–5039`, `5041–5460` | 5,460 |
| T320 C | `5461–10921` | 5,461 |
| 730xd B | `5040`, `10922–16383` | 5,463 |

All six peers report connected. Slot 5040 remains on B because the CT2 row/byte
bound rejected that isolated slot before mutation; the one-slot skew is
intentional. Each owner has an off-host successor. Slot-count automatic
rebalancing remains disabled because it is not capacity-aware. The 730xd owner
must be unfenced before the cluster is ready for ordinary use.

The separate HAX memory service remains outside this slot merge. The six
namespace cache services are stopped with their authenticated backups
preserved. Reattach a cache only if a consumer still needs it, point it at the
appropriate new owner, and verify its filters. Otherwise keep it stopped.

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

## Current execution checkpoint (2026-11-10, all six services upgraded)

- Nine authenticated original full backups, three main-store delta exports,
  and the authenticated merged union remain preserved under
  `/var/backups/qihse-recovery-20261109`. The union was re-hashed today as
  `bf400593bb9157329626f8bedb0932904fc5f9c599c19a7c25be61c7fc20ea3e`.
- The union contains 271,434 reconciled records. The fresh 730xd restored
  owner was independently backed up and compared to it: 271,434 identical,
  zero additions and zero conflicts. The six cache inputs contributed 830
  exact duplicates; the merge recorded zero conflicting live keys.
- Native recovery packages for T420, 730xd, and T320 are built from
  `cabe8dc93e1653dbfa96b0ce7b9f86b67b1beefd` with each host's own compiler and
  ISA. T420 used GCC 16.1.0 with AVX/F16C; T320 used GCC 14.2.0 with AVX only;
  730xd used GCC 14.2.0 with AVX2/FMA/F16C. Package checksums and launcher
  smoke checks passed on all three hosts. All six recovery services now point
  at their host's `native-*-cabe8dc` package and are active. Per-unit
  pre-cabe8dc backups are preserved under
  `/var/lib/qihse-maintenance/cluster-recovery-20261109/`; the original
  services and data directories remain stopped and untouched. T420's native
  build installed liboqs headers/libraries and oqsprovider under `/usr` while
  resolving its dependency prefix; the QIHSE package itself is self-contained.
- All three owners independently return the same six-peer cluster map, with
  all peers connected. Slot ownership is T420 `0–5039, 5041–5460` (5,460),
  T320 `5461–10921` (5,461), and 730xd `5040, 10922–16383` (5,463). Slot 5040
  safely stayed on 730xd after CT2 refused its isolated transfer under the
  current bound; no rows were truncated.
- The original `a7c9848` fix was insufficient: replay processes historical
  ABORTED entries before the final pending transaction, so an old abort could
  reject the later transaction's valid active fence. Commit `cabe8dc` defers
  that historical comparison, releases only a fence whose full identity/range/
  cursor matches the abort, and validates any remaining active fence against
  the final unfinished journal entry. The regression covers both the valid
  later pending transfer and an unrelated active-fence refusal.
- `make test-ownership-abort-replay` passed locally and on 730xd. The required
  `make test TEST_JOBS=32` run passed **204 targets, 0 failures** (including
  the 1,381.9-second CodeGraph aggregate and the gold parallel lane). The
  versioned `native-730xd-cabe8dc` package has verified checksums and its
  systemd unit backup is preserved at
  `/var/lib/qihse-maintenance/cluster-recovery-20261109/`.
- Authenticated QKP `PING` returns `PONG` on 730xd and `DBSIZE` succeeds. All
  three owner probes report identical membership, all six peers connected,
  and 16,384/16,384 slots assigned. Slot ownership remains T420 `0–5039,
  5041–5460` (5,460), T320 `5461–10921` (5,461), and 730xd `5040,
  10922–16383` (5,463). The three per-owner `DBSIZE` values were 8,860,
  209,941, and 52,661 (sum 271,462); compare this against the preserved union
  at record level before declaring inventory equality. No original backup was
  modified.
- After the owner and successor restarts, authenticated CT1 checks show exact
  source-acknowledgement/target-cursor matches: A 24/24, B 2389/2389, and C
  22/22. Each target reports its baseline sealed and the configured generation
  and peer IDs.
- A coordinated attempt to make fresh offline owner backups did not produce
  valid files: the CLI returned an API error for T420 and T320, and the first
  730xd attempt used a nonexistent data path (`b-owner`; its unit uses
  `owner-730xd`). All owners were restarted immediately and the cluster was
  rechecked healthy. No `live-*-owner-cabe8dc.qbk` was created. The verified
  pre-CT union and all original backups remain intact.
- `AIMEM COUNT` reports 309 on B/730xd and 0 on A/T420 and C/T320. Those 309
  records are present in the verified union and remain on a live owner; CT2
  slot transfer does not distribute node-local AIMEM state. Do not retire the
  original stores until the live inventory comparison and AIMEM access path
  are reconciled.
- Read-only authenticated recheck after rollout returned `cluster_state:ok`,
  all 16,384 slots assigned/OK, zero failed or pending-fail slots, six known
  nodes, and cluster size 3 from each of T420, T320, and 730xd. The owner
  `DBSIZE` values remain 8,860, 52,661, and 209,941 (271,462 total); `AIMEM
  COUNT` remains 0, 0, and 309. This confirms service health and preserves the
  known 28-row difference from the 271,434-row union, but it does not explain
  that difference or establish record-level equality.
- Authenticated `KEYS` checks of the recognized node-local namespaces found
  no matching rows on T420 or T320. On 730xd they found 309 `aimem:*` rows and
  323 `aimemv:*` rows; `AIMEM COUNT` reports 309 memories. The other checked
  local families (`fabric:*`, `fednode:*`, `federation/node/*`, snapshot
  manifests, and rejoin state) were empty on all three owners. These checks
  confirm the AIMEM locality but do not explain the 28-row gap, which must be
  reconciled against record identities rather than inferred from namespaces.
- Source inspection ruled out using the live replication snapshot as a
  harmless backup shortcut: `REPL.SNAPSHOT.BEGIN` requires a marked namespace
  and advances that peer's durable replication cursor. The underlying full
  `qihse_kv_save_user` backup API explicitly rejects CT-enabled stores. No
  live replica marks/cursors or data were changed for this investigation.
  Source now contains an authenticated `OWNER.SNAPSHOT.*` read-only inventory
  endpoint: it captures locally owned live rows plus node-local rows and a
  change-sequence watermark under one snapshot lock, without changing
  replication state. This is an inventory source, not a complete recovery
  backup: tombstones and expired rows are omitted. The change is not yet
  deployed to the three owners. Retain the verified union and all original
  backups; after native rollout, export each owner and reconcile record
  identities to explain the 28-row gap before changing or retiring any source.
- Automatic capacity-aware balancing, automatic failover promotion, and
  dynamic successor reassignment remain open roadmap items. Keep the current
  slot-count R5 automatic rebalancer disabled for this heterogeneous layout.
