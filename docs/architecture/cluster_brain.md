# Cluster Brain — Decision Making for QIHSE Clusters

> **Implementation status (2026-09-15):** phase 1 (observe / journal / decide,
> acting gated behind `--brain-act`) is implemented in
> `src/spinnaker/qihse_cluster_brain.c` and is **pending landing** (W0 of the
> master [roadmap](../../ROADMAP.md)): daemon flags `--brain`, `--brain-act`,
> `--brain-dir`, `--brain-interval`, `--brain-dsa-key`. The smoke test
> described under "Testing" below (`tests/cluster_brain_smoke.py`) does not
> exist yet — writing it is also W0.

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

1. **R1 — failed-owner re-home.** IF a slot range's owner is unhealthy AND I
   am healthy AND I can reach a healthy target AND I hold the range's data
   reachable (probes succeed), THEN transfer the range to the healthy target
   and journal the action. Refuse (R3) when it would split the cluster.
2. **R2 — quarantine asymmetry.** IF a peer fails my probes but other peers
   report it healthy, journal an `ASYMMETRY` observation and DO NOT act on it
   (routing decisions stay with nodes that can actually reach it). This is
   exactly the T320 case.
3. **R3 — split-brain guard.** IF I cannot reach any healthy peer, act on
   nothing; journal `ISOLATED` once and keep serving read-local traffic only.
4. **R4 — rollback.** IF a re-home was journaled and the moved range's error
   rate (client CLUSTERDOWN/MOVED-storm counters) degrades vs. the journal
   baseline within the rollback window, move the range back and journal
   `ROLLBACK`.

### Safety posture

- Phase 1 ships **observe + journal + decide** with acting disabled by
  default (`--brain-act` to enable). A brain that can act is a brain that can
  misact; the journal is useful from day one, the actions earn trust.
- All actions reuse the audited MOVESLOTS machinery (key transfer, ownership
  flip, bus broadcast) — the brain introduces no new data-path code.
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

- `tests/cluster_brain_smoke.py`: boots the dynamic cluster, injects a
  failure (drop bus traffic to the seed from the joiner), asserts the brain
  journals `ASYMMETRY`/`ISOLATED` observations without acting (R2/R3), then
  asserts R1 re-home under `--brain-act` with a genuinely failed node.

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
