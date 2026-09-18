# Cluster Brain — Decision Making for QIHSE Clusters

> **Status: implemented** — phase 1 (observe / journal / decide) and actuation
> are verified by `tests/test_cluster_brain.c` (phase 1),
> `tests/test_brain_actuate.c` (R1/R4), `tests/test_brain_rebalance.c`
> (R5/R6), and `tests/test_brain_fed_journal.c` (W3.4: observations and signed
> decisions on the federation journal, the no-action-without-a-pre-condition
> gate, and triage-output determinism). Acting runs only under `--brain-act` in
> `src/spinnaker/qihse_cluster_brain.c`.

## Why

The T320/t420 lab exposed the gap: when reachability went asymmetric (t420 →
T320 fine; T320 → t420 blocked at TCP), both nodes just marked each other
failed and refused to route. Nothing *decided* anything — no re-homing, no
quarantine, no record of what happened or why. Reflexes without a brain.

MEMSHADOW (SWORDIntel/MEMSHADOW) was designed for this class of problem but
was bloated for the job. This document mines it for the useful parts and
defines a lean, first-party implementation inside QIHSE.

## What we take from MEMSHADOW (and what we leave)

| MEMSHADOW concept | Verdict | Lean QIHSE version |
|---|---|---|
| Persistent event/decision memory (episodic journal) | **TAKE** | Two durable records per decision: the human-readable `qihse_event_stream` record under topic `cluster.brain`, and an HLC-stamped, hash-chained record on the F2 federation event journal under topic `federation` (W3.4) |
| Health monitor + automated long-term rollback | **TAKE** | Every brain action is journaled with its pre-conditions; if the watched metric degrades after an action, the brain reverses it (slot ranges move back) |
| Deterministic telemetry (`getrusage`-style) | **TAKE** | Decisions cite measured facts only: bus stats, health flags, probe results — never guesses |
| Signed proposals / votes / hub override | **TAKE (lite)** | Decision records are signed with the node identity key (ML-DSA-87 by default, algorithm recorded inside the signed region) and published as authenticated envelopes; quorum voting deferred until ≥3-node clusters exist |
| Gossip protocol | **Already there** | The cluster bus (MEET/PING/SLOT_UPDATE) — the brain consumes it, does not replace it |
| Semantic retrieval over past incidents | **TAKE (later)** | QIHSE's own FTS/vector indexes can store and retrieve past incidents — dogfooding; phase 3. The federation records embed the same JSON detail the local journal holds, so both are indexable |
| MOE router, quantum layer, neuromorphic, consciousness, self-modifying engine, Mamba models | **REJECT** | Bloat. A 2-node cluster needs a few hundred lines of deterministic policy, not a consciousness |

## Architecture (phase 1)

```
bus (MEET/PING/PONG/SLOT_UPDATE)          topology (health, owners)
        │                                        │
        ▼                                        ▼
  ┌─────────────────── cluster brain (periodic) ───────────────┐
  │ 1. OBSERVE: ONE topology snapshot + slot-owner triage       │
  │ 2. PUBLISH: local journal record + federation observation   │
  │    (HLC-stamped, hash-chained)                              │
  │ 3. CONSUME: read the observation back through the federation │
  │    watch — the rules act on the RECORDED bytes               │
  │ 4. DECIDE: deterministic policy rules (below)                │
  │ 5. ACT: re-home slots via the internal MOVESLOTS machinery,  │
  │    or quarantine; gated on a journaled pre-condition, every  │
  │    decision signed + journaled                               │
  └──────────────────────────────────────────────────────────────┘
```

### Federation journal records (W3.4)

Observations and decisions are published to the F2 federation event journal
(`qihse_federation_journal_append`, topic `federation`) with an HLC stamp from
the journal's own clock and a hash-chain link:

- **OBSERVATION** — event type `brain.observe`, resource
  `brain/obs/<node-id>`. The payload is the structured rule input (nodes with
  role/health/addresses, the coalesced slot runs, the observation sequence)
  plus the same detail JSON the local journal recorded. Observations are not
  signed: they are one per cycle, so a post-quantum signature there would sit
  on the hot path. Their integrity comes from the journal's hash chain.
- **DECISION** — event type `brain.decision`, resource
  `brain/decision/<action>`. The payload is an authenticated envelope: a
  192-byte header (action, evidence, the cited pre-condition, signer algorithm
  and key fingerprint) followed by the detached signature over every byte
  before it. The algorithm and signature length are *inside* the signed
  region, so an algorithm-downgrade edit invalidates the signature.
- Decisions that commit cluster state (`rehome`, `rehome-confirm`, `rollback`,
  `rebalance`, `prune`) are signed; policy records (`isolated`, `reconnected`,
  `rehome-skip`, `refused`) are not, because they occur once per cycle and
  change nothing. `quarantine` / `quarantine-release` are signed on the
  transition only — once per incident, not per cycle.
- The private key never enters a record: the envelope carries the key handle
  and the SHA-384 fingerprint of the public key. `qihse_cluster_brain_decision_verify()`
  recomputes the fingerprint from the key it is handed rather than trusting
  the stored one.
- Signing cost: ML-DSA-87 sign ~1.96 ms / verify ~0.56 ms on this host, so one
  signed decision per acting cycle is ~0.04% of a 5 s cadence. Observations and
  per-cycle policy records are never signed, which keeps the hot path free of
  post-quantum crypto.

### Rules consume the observation, not the topology

One cycle takes exactly one topology snapshot, in the observe pass. The rules
(R1–R6) then read the observation the brain published and read back through
`qihse_federation_watch_next()` — the decoded record *is* the rule input, so a
replayer with the journal has the same input the brain had. The decoded
observation is compared field-by-field against the in-memory one before any
rule runs; a mismatch means the recorded form does not reproduce the rule
input, so the cycle gets no pre-condition and nothing may act.

### No action without a journaled pre-condition

Every rule that commits cluster state calls the gate
(`qihse_cluster_brain_precondition_ok()`) before it touches the topology or
the data path. A pre-condition is valid only when the cycle's observation was
journaled, consumed back through the watch, and round-tripped. When it is not
— no federation journal, an append that failed, a record that did not read
back — the action is refused and `DECISION_REFUSED` is journaled locally with
the action name and the evidence that motivated it. The brain still observes
and journals in that state; it simply cannot act on inputs it did not record.

### Policy rules (phase 1, deterministic)

| Rule | State |
|---|---|
| **R1 — failed-owner re-home.** | **Implemented** (`--brain-act`). Evidence-gated like the failover coordinator: while any peer recently observed the owner healthy the brain only journals (asymmetry, not death). Acts only on a range the local node actually holds data for, hands it to the healthy target with the most headroom (NODE_CAP free RAM minus a load penalty, uptime tie-break), journals `REHOME` with the target's capability evidence, and refuses when it would split the cluster. |
| **R2 — quarantine asymmetry.** | **Implemented** (phase 1, journal-only). |
| **R3 — split-brain guard.** | **Implemented**: with no healthy peer the brain neither re-homes nor rebalances. |
| **R4 — rollback.** | **Implemented**: each re-home is evaluated when its window closes — `transfer-incomplete` (moved < collected) or `target-unhealthy` moves ownership back to the local node and journals `ROLLBACK`; otherwise `REHOME_CONFIRM`. |
| **R5 — rebalance on join.** | **Implemented** (`--brain-rebalance-min-slots N`): a healthy slotless primary receives a proportional share of the largest owner's largest range (never more than half of it). Deterministic — only the largest owner acts. |
| **R6 — stale-node prune.** | **Implemented** (`--brain-prune-timeout S`): a node unhealthy past the timeout with no peer reporting it healthy is pruned from this node's view. Nodes that still own slots are refused until their ranges are re-homed. |

### Safety posture

- Acting is **off by default** and gated behind `--brain-act`. A brain that
  can act is a brain that can misact; the journal earns trust first.
- Every action is evidence-gated (R2/R3/R6 use the third-party observation
  matrix), reversible (R4), and rate-limited (per-range cooldown, one data
  action per cycle).
- Every action needs a **journaled pre-condition** (W3.4): the observation it
  was derived from must be on the federation journal, read back through the
  watch and round-tripped. A decision cites that record's sequence, journal
  offset, chain hash, payload digest and HLC, so the reasoning can be replayed
  from recorded inputs.
- All actions reuse the audited MOVESLOTS machinery — the brain introduces no
  new data-path code.
- Local decision records: `{timestamp, node id, rule, inputs
  (health/owners/stats), action, result}`. Federation decision records: the
  authenticated envelope described above, signed with the node identity key
  (ML-DSA-87 by default, algorithm-agile by construction).

## Parallel slot triage

The observe pass snapshots all 16,384 slot owners in a single lock hold
(`qihse_cluster_topology_slot_owner_snapshot`), then coalesces ownership runs
lock-free across worker threads (default `min(cores, 8)`, override with
`QIHSE_BRAIN_WORKERS`). Workers own contiguous slot chunks; results merge in
chunk order, so output is identical at any worker count. Each OBSERVE record
carries its own cost telemetry (`scan_us`, `workers`). Measured on the
2-node lab: ~730–780 µs per full cycle at 8 workers before the persistent
pool, ~128 µs after (W3.5). The policy checks are O(nodes) and stay serial;
the journals are append-ordered and single-writer (the brain thread owns both
handles; the event stream serialises writers with `flock` underneath).

### Per-cycle cost of the federation publish

The federation publish adds one append plus one watch read-back per cycle.
Measured (1.5 KB observation, `QIHSE_ES_DURABILITY_NONE`, this host):

| journal length | append | watch read-back |
|---|---|---|
| 500 records (~0.7 MB) | ~0.56 ms | ~8 µs |
| 2000 records (~3 MB) | ~1.1 ms | ~10 µs |
| 4000 records (~6 MB) | ~2.2 ms | ~11 µs |

The read-back is flat; the append grows linearly because
`qihse_event_stream_append_record` scans the topic for the previous record
offset and for a duplicate event id. At the default 5 s cadence that is
~1.5 KB per cycle, so the growth is slow, but it is real: a tail-offset cache
in the event stream is the fix and belongs to the event-stream module (it
would benefit every federation consumer, not just the brain).

## Testing

- `tests/test_cluster_brain.c` (`make test-cluster-brain`): phase 1 — a
  synthetic topology runs through three health scenarios; asserts the journal
  contents (`BRAIN_START` + `OBSERVE` with no alarms when healthy,
  `ASYMMETRY` + `ISOLATED` when a peer fails, `RECONNECTED` on recovery) and
  that observe-only mode never modifies ownership.
- `tests/test_brain_actuate.c` (`make test-brain-actuate`): R1/R4 against a
  fake RESP peer — a failed owner's range moves with its keys and is confirmed
  (`REHOME` + `REHOME_CONFIRM`); a target that fails inside the rollback window
  triggers `ROLLBACK` and ownership returns to the local node; a target that
  refuses the transfer is detected as an incomplete move and rolled back.
- `tests/test_brain_rebalance.c` (`make test-brain-rebalance`): R5/R6 — a
  slotless joiner receives a proportional range (`REBALANCE`); a stale slotless
  node is pruned (`PRUNE`); a stale node that still owns slots is refused.
- `tests/test_brain_fed_journal.c` (`make test-brain-fed-journal`): W3.4 —
  observations carry HLC stamps, chain to the previous record and embed the
  same detail the local journal holds; `prune` and `quarantine` decisions
  verify against an ML-DSA-87 node key and fail on an edited action, an
  algorithm downgrade or a flipped signature byte; a decision cites the
  observation that precedes it (sequence, offset, chain hash, payload digest,
  HLC); the private key material never appears in a record; the same act
  configuration that prunes with a federation journal REFUSES the action and
  journals `DECISION_REFUSED` without one; and the triage output is
  byte-identical at 1 and 8 workers.

All four run in CI.

## Relation to the federation direction

The [federation upgrade plan](../plans/qihse_federation_upgrade_plan.md)
(accepted 2026-09-15) promotes this document's evidence-first posture to a
system-wide invariant — QIHSE records evidence and never infers safety from
absence (plan §3.6). Two consequences for the brain:

- The brain's actuation scope stays **database-internal** (slot re-homing,
  quarantine). Exclusive-infrastructure ownership — VMs, disks, floating IPs —
  is recorded by QIHSE as leases/epochs/ownership records (plan §6.3, §14),
  but activation decisions belong to the external hypervisor controller,
  never to QIHSE (plan §3.3). The brain must not grow infrastructure
  actuation.
- Brain observations and signed decisions are now on the federation event
  journal with HLC stamps and authenticated envelopes (plan §8, §12), and the
  rules consume the published observation instead of polling topology
  snapshots (plan §13). Still open on this path: the observation is published
  by the same process that consumes it (a remote consumer can watch the same
  stream, but the brain does not yet take rule input from a peer's
  observation), and the federation records are not yet replicated by F3
  anti-entropy beyond the journal's own scope.
