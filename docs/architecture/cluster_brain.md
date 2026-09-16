# Cluster Brain — Decision Making for QIHSE Clusters

> **Implementation status (2026-09-16):** phase 1 (observe / journal / decide)
> and **actuation** are implemented in `src/spinnaker/qihse_cluster_brain.c`:
> daemon flags `--brain`, `--brain-act`, `--brain-dir`, `--brain-interval`,
> `--brain-dsa-key`, `--brain-cooldown`, `--brain-rollback-window`,
> `--brain-prune-timeout`, `--brain-rebalance-min-slots`. Acting (R1 re-home,
> R4 rollback, R5 rebalance-on-join, R6 stale prune) runs only under
> `--brain-act` and every action goes through the same audited slot-handoff
> path `CLUSTER MOVESLOTS` uses. Tests: `tests/test_cluster_brain.c` (phase 1),
> `tests/test_brain_actuate.c` (R1/R4), `tests/test_brain_rebalance.c` (R5/R6).

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
| Persistent event/decision memory (episodic journal) | **TAKE** | Append decision records to `qihse_event_stream` (durable, SHA-384 event ids, torn-tail safe) under topic `cluster.brain` |
| Health monitor + automated long-term rollback | **TAKE** | Every brain action is journaled with its pre-conditions; if the watched metric degrades after an action, the brain reverses it (slot ranges move back) |
| Deterministic telemetry (`getrusage`-style) | **TAKE** | Decisions cite measured facts only: bus stats, health flags, probe results — never guesses |
| Signed proposals / votes / hub override | **TAKE (lite)** | Decision records are ML-DSA-87 signed with the node's key (tamper-evident audit); quorum voting deferred until ≥3-node clusters exist |
| Gossip protocol | **Already there** | The cluster bus (MEET/PING/SLOT_UPDATE) — the brain consumes it, does not replace it |
| Semantic retrieval over past incidents | **TAKE (later)** | QIHSE's own FTS/vector indexes can store and retrieve past incidents — dogfooding; phase 3 |
| MOE router, quantum layer, neuromorphic, consciousness, self-modifying engine, Mamba models | **REJECT** | Bloat. A 2-node cluster needs a few hundred lines of deterministic policy, not a consciousness |

## Architecture (phase 1)

```
bus (MEET/PING/PONG/SLOT_UPDATE)          topology (health, owners)
        │                                        │
        ▼                                        ▼
  ┌─────────────────── cluster brain (periodic) ───────────────┐
  │ 1. OBSERVE: per-peer reachability + slot ownership snapshot │
  │ 2. REMEMBER: append snapshots + decisions to event stream   │
  │ 3. DECIDE: deterministic policy rules (below)               │
  │ 4. ACT: re-home slots via the internal MOVESLOTS machinery, │
  │    or quarantine; every action signed (ML-DSA) + journaled  │
  └──────────────────────────────────────────────────────────────┘
```

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
- All actions reuse the audited MOVESLOTS machinery — the brain introduces no
  new data-path code.
- Decision records: `{timestamp, node id, rule, inputs (health/owners/stats),
  action, result}` signed with the node's ML-DSA-87 key.

## Parallel slot triage

The observe pass snapshots all 16,384 slot owners in a single lock hold
(`qihse_cluster_topology_slot_owner_snapshot`), then coalesces ownership runs
lock-free across worker threads (default `min(cores, 8)`, override with
`QIHSE_BRAIN_WORKERS`). Workers own contiguous slot chunks; results merge in
chunk order, so output is identical at any worker count. Each OBSERVE record
carries its own cost telemetry (`scan_us`, `workers`). Measured on the
2-node lab: ~730–780 µs per full cycle at 8 workers (thread spawn dominates;
a persistent pool is the next squeeze if cadence rises). The policy checks
(R2/R3) are O(nodes) and stay serial; the journal is append-ordered and is
deliberately single-writer.

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

All three run in CI.

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
- Brain observations and signed decisions migrate onto the federation event
  journal with HLC stamps and authenticated mutation envelopes (plan §8, §12)
  once Phase 2 lands; the R1–R4 rules then consume watch streams (plan §13)
  instead of polling topology snapshots.
