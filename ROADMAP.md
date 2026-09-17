# QIHSE Roadmap

**Status date:** 2026-09-16
**Role:** master sequencing document. Detailed designs live in `docs/plans/` and `docs/architecture/`; this file tracks *what is being built, in what order, and what "done" means*. It does not replace those documents.

Status marks: `[x]` implemented with repository evidence (source + build wiring + test) · `[~]` partially implemented · `[ ]` not started · `[>]` superseded

---

## 1. Where we are now (verified against the working tree, 2026-09-15)

### 1.1 Landed and committed

The database-replacement program (**Phases 1–9**) is complete and committed — see
[general database engine roadmap](docs/plans/qihse_general_db_engine_roadmap.md) for the item-by-item record:

| Area | State |
|---|---|
| Multi-model engines (KV, vector, document, columnar, time-series, FTS, event stream, spatial, graph) | `[x]` |
| SQL completeness (joins, aggregates, CTEs, window functions, subqueries) + QQL | `[x]` |
| ACID transactions, MVCC, 3 isolation levels, cross-engine 2PC, unified WAL + recovery | `[x]` |
| Secondary indexes (B+ tree, hash, composite, index-backed plans) | `[x]` |
| Replication, read replicas, CDC, coordinated snapshots, backup/restore, PITR | `[x]` |
| Wire protocols: RESP2/3, pgwire, MongoDB, Bolt/Cypher, HTTP/REST, ES-style, ClickHouse-style, InfluxDB-style | `[x]` |
| Cluster: 16,384 slots, gossip, Raft failover, zero-downtime rebalancing, scatter-gather planner | `[x]` |
| Ops: pooler, Prometheus metrics, OTel tracing, task queue/scheduler, backup | `[x]` |
| Compatibility command surfaces for 8 target databases (Phase 9) | `[x]` |

Recent committed work on top of that program:

- `[x]` Session-delivery upgrades — content-addressed blob store, export, ingest guard, per-tenant quotas, security regression suite (`7e39092`).
- `[x]` Latency/throughput tiers 1–3 and the XTREME optimization pass (`4359fc0` → `3c39778`).
- `[x]` CI: build + core test suite + security regressions (auth privilege boundary, object ACL, aggregate hardening, FTS persistence authz, security boundary) + APT41 fuzzing under ASan/UBSan.

### 1.2 Landed 2026-09-16 (was in flight)

This work was sitting outside git; it is now committed with tests and CI wiring (W0).

| Item | Evidence | State |
|---|---|---|
| Cluster brain (phase 1 + actuation) | `src/spinnaker/qihse_cluster_brain.c` (observe/journal/decide; R1 re-home, R4 rollback, R5 rebalance-on-join, R6 prune under `--brain-act`) | `[x]` tests: `test_cluster_brain.c`, `test_brain_actuate.c`, `test_brain_rebalance.c` |
| Overlay protocol phase 1 | `src/spinnaker/qihse_overlay.c` (IRC dead-drop, HMAC-SHA-384 records, replay window) + veiled bus framing in `qihse_cluster_bus.c` | `[x]` test: `test_overlay.c` |
| KEYSTONE fabric index (AI fabric item 2) | `src/spinnaker/qihse_fabric_index.c` | `[x]` test: `test_fabric_index.c` |
| AI fabric items 1 & 3 (NODE_CAP, `FABRIC.*`) | `QIHSE_BUS_MSG_NODE_CAP`, `FABRIC.CAPS/SUBMIT/RESULT` | `[x]` |
| AI fabric item 4 (capability-aware placement) | brain target selection scores NODE_CAP headroom and journals the evidence | `[x]` |
| AI fabric item 5 (local-first AI memory) | `src/spinnaker/qihse_ai_memory.c` + `include/qihse_ai_memory.h` | `[x]` test: `test_ai_memory.c` (incl. RBAC negative test) |
| Federation F0 primitives | `src/federation/qihse_federation.c` (UUID, HLC, object generation, fencing epoch) | `[x]` test: `test_federation_f0.c` |
| Slot-handoff extraction | `qihse_cluster_handoff_range()` / `qihse_cluster_set_range_owner()` / `qihse_cluster_range_has_local_keys()` shared by MOVESLOTS and the brain | `[x]` |
| Topology node removal | `qihse_cluster_topology_remove_node()` (tombstone; refuses the local node and slot owners) | `[x]` |
| Cluster smoke drills | `tests/cluster_*_smoke.py` — env-overridable hosts/ports, no absolute paths | `[x]` |
| Repo hygiene | build artifacts untracked (687 files) + ignored; runtime data/audit log/`.zcode/` kept | `[x]` |

### 1.3 Design of record — accepted, not implemented

| Direction | Design doc | Status |
|---|---|---|
| **Phase 10 — Federation data plane** (stages F0–F7, 22 acceptance criteria) | [federation upgrade plan](docs/plans/qihse_federation_upgrade_plan.md) | `[~]` F0 landed (primitives + module); F1–F7 open |
| AI compute fabric | [ai_fabric.md](docs/architecture/ai_fabric.md) | `[x]` items 1–5 implemented (embedding-backed semantic recall is the follow-up) |
| Cluster brain | [cluster_brain.md](docs/architecture/cluster_brain.md) | `[~]` observe + actuation (R1–R6) landed; federation-journal migration open |
| Overlay protocol | [overlay_protocol.md](docs/architecture/overlay_protocol.md) | `[~]` phase 1 landed; DHT (phase 2) sequenced after F5 |
| Production hardening (whitepaper near-term priorities 1–5) | [whitepaper v1.1 §12](docs/architecture/qihse_whitepaper_v1.1.md) | `[~]` partly landed (telemetry, security); optimizer governance and gold validation suite open |

---

## 2. Workstreams

### W0 — Land in-flight work (prerequisite for everything else) ✅ COMPLETE

The untracked/modified cluster work above must be committed with its tests before any federation refactor rebases onto it.

- [x] **W0.1** Review and commit the cluster brain, overlay, fabric index, NODE_CAP, and `FABRIC.*` work as scoped commits (sources + headers + Makefile + daemon + CI + docs together, so the build never references an uncommitted file).
- [x] **W0.2** Write the missing brain tests (`tests/test_cluster_brain.c`, `tests/test_brain_actuate.c`, `tests/test_brain_rebalance.c`) and register Makefile targets; the smoke test the design doc originally referenced is superseded by these deterministic unit tests.
- [x] **W0.3** Add an overlay test target (framing round-trip, signed advert verification, forged/stale record rejection) — `tests/test_overlay.c`.
- [x] **W0.4** Repo hygiene: build artifacts untracked (687 files) and ignored; runtime data, audit log, and `.zcode/` session notes explicitly kept.
- [x] **W0.5** Review the uncommitted Python SDK changes (NULL guards, libc `free`) and commit them.

### W1 — Federation data plane (Phase 10)

The accepted major direction. Governing principle: **federation must enhance a node, never become a prerequisite for that node to remain locally operable.** All stage definitions and the 22 acceptance criteria live in the [federation upgrade plan](docs/plans/qihse_federation_upgrade_plan.md); this roadmap only sequences them.

- [x] **F0 — Refactor boundaries.** Federation module skeleton, UUID/HLC/object-generation/fencing-epoch primitives, current cluster semantics documented. No behavior changes.
- [x] **F1 — Sovereign local state.** Consistency classes (LOCAL/EVENTUAL/CAUSAL/QUORUM/LINEARIZABLE), local-authority namespaces, no global quorum gate on local-safe writes, federation status API. *Unblocks acceptance criteria 1–2.*
- [x] **F2 — Event journal + watches.** Immutable mutation envelope, resumable watch API, idempotent request IDs, controller SDK. *Unblocks W2, W3-phase-2, and acceptance criteria 5, 9, 10.*
- [x] **F3 — Replication correctness.** Anti-entropy, manifests/range digests, explicit conflict objects, resumable reconciliation. *Needs F2. Unblocks criteria 6–7.*
- [x] **F4 — Strong namespace.** Scoped consensus groups, native CAS, monotonic fencing epochs, lease primitive, explicit membership. *Needs F1+F2. Unblocks criteria 3–4, 10.*
- [ ] **F5 — Trust plane.** Node enrollment, mTLS, signed replay-resistant gossip, revocation, infrastructure security scopes. *Needs F0 identity primitives. Unblocks criterion 8 and overlay phase-2 membership.*
- [ ] **F6 — Build & supply-chain substrate.** Package override/source registry, build-job state machine, worker capability records, build leases, provenance graph, SBOM/attestation records, vulnerability observations, repository snapshots, controller-facing build APIs. *Needs F2+F4+F5. Unblocks criteria 15–22.*
- [ ] **F7 — Operational hardening.** Rolling schema upgrades, federation-consistent snapshots, chaos suite, performance regression budgets, recovery tooling.

### W2 — AI compute fabric

Items 1–3 are in flight (see §1.2); items 4–5 build on federation primitives rather than ad-hoc bus messaging.

- [x] **W2.1** Land items 1–3 with tests (covered by W0).
- [x] **W2.2** Brain governance phase 2 — capability-aware placement decisions (NODE_CAP headroom + load scoring), signed and journaled with the capability evidence the choice was based on (needs F2 for the full journal migration).
- [x] **W2.3** Local-first AI memory API — episodic/semantic memory in KV with FTS recall, explicit security context on every entry point, RBAC negative test in CI (embedding-backed semantic recall remains the follow-up).
- [ ] **W2.4** Generalize NODE_CAP payloads into first-class federation node records at `federation/node/<uuid>` with trust state (needs F1+F5).
- [ ] **W2.5** KEYSTONE consumes the resumable change feed with a read/index identity — never database-admin privileges (needs F2; criterion 9).

### W3 — Cluster brain

- [x] **W3.1** Phase 1 hardening and landing (W0.1–W0.2).
- [x] **W3.2** Actuation: R1 failed-owner re-home through the shared slot-handoff path (the same audited code `CLUSTER MOVESLOTS` uses), R4 rollback on incomplete transfer or target failure, per-range cooldown, evidence gates (observation matrix) on every action.
- [x] **W3.3** Rebalance on join (R5: largest owner donates a proportional share to a healthy slotless primary) and stale-node pruning (R6: unhealthy past the timeout, no peer evidence, owns no slots).
- [ ] **W3.4** Migrate observations/signed decisions onto the federation event journal with HLC stamps and authenticated envelopes; rules consume watch streams instead of polling topology snapshots (needs F2).
- [ ] **W3.5** Persistent worker pool if cadence rises (current: ~730–780 µs/cycle at 8 workers, thread-spawn dominated).
- [ ] **W3.6** Phase 3: incident retrieval over QIHSE's own FTS/vector indexes (dogfooding).
- [x] **W3.7** Hard boundary: brain actuation stays database-internal (slot re-homing, quarantine). It must not grow hypervisor actuation — execution decisions belong to the external controller.

### W4 — Overlay protocol

- [x] **W4.1** Land phase 1a–1c (covered by W0).
- [ ] **W4.2** Phase 2: DHT peer exchange (simplified Kademlia, msg types 9/10) — **sequence after F5** so discovery hints never become membership; DHT records stay unauthenticated hints and enrollment remains the gate.
- [ ] **W4.3** Phase 3: AI memory API extensions (folds into W2.3).

### W5 — Production hardening (runs in parallel, independent of federation)

Whitepaper v1.1 §12 priorities, in its stated order:

- [ ] **W5.1** Optimizer governance: A/B or shadow-plan harness, explicit safety constraints, automatic rollback, persistent decision/outcome history, regression budgets by workload/backend.
- [ ] **W5.2** Telemetry expansion: backend availability/utilization, per-query-type latency histograms, error counters, memory/index movement, cluster/replication status, XDP counters, optimizer rollback counters.
- [ ] **W5.3** Gold validation suite: versioned workload pack (ANN + rerank, relational, graph, FTS+vector fusion, persistence/recovery, protocol compat, distributed failure, security regressions).
- [ ] **W5.4** API documentation: coherent generated/reference surface for the public C API, SDKs, protocol compatibility, configuration.
- [ ] **W5.5** Documentation labeling discipline: consistently mark implemented / experimental / partial / planned / superseded / externally validated.

---

## 3. Sequencing

**Critical path:** `W0 → F0 → F1 → F2 → {F3, F4} → F5 → F6 → F7`

| Horizon | Work | Why now |
|---|---|---|
| **Now** | W0.1–W0.5, then F0 | Uncommitted work blocks any safe refactor; F0 has no dependencies and unblocks all federation stages |
| **Next** | F1, F2 (in that order); W5.1 in parallel | F1 delivers the headline guarantee (isolated node stays read-write); F2 is the hub dependency — it unblocks W2.2–W2.5, W3.2, and the controller SDK |
| **Then** | F3 and F4 (can overlap), then F5 | Replication correctness before strong namespaces; trust plane lands before anything treats peers as authenticated |
| **Later** | F6, then F7 | Supply-chain substrate needs journal + leases + trust; chaos/regression budgets gate the whole thing |
| **Opportunistic** | W4.2 only after F5; W5.2–W5.5 whenever | DHT before trust would build unauthenticated membership; docs/telemetry are non-blocking |

Dependency notes:

- F2 is the single highest-leverage stage — four workstreams (W2.2, W2.3, W2.5, W3.2) plus acceptance criteria 5/9/10 wait on it.
- F5 depends on F0's identity primitives, not on F3/F4 — it can start as soon as F0 lands if reviewer bandwidth allows, but must land before F6.
- W5 is deliberately decoupled: nothing in W5 blocks federation, and nothing in federation blocks W5.1.

---

## 4. Gates — what "done" means

Every item, regardless of workstream:

1. Source + build wiring + at least one automated test in the same commit (W0 exists precisely because this rule was skipped).
2. Security regressions per `AGENTS.md`: new read primitives take an explicit security context; no principal creates/promotes above itself; **every new externally reachable adapter ships a low-clearance/high-data negative test in CI**.
3. No invariant violations from §5.
4. Docs updated in the same change when behavior or interfaces change.

Workstream-specific gates:

- **Federation stages:** the plan's §41 acceptance criteria are the gate, not the stage checklist. §39 testing requirements (deterministic distributed simulation, mandatory partition scenarios, fuzzing) apply per stage.
- **Brain:** journal entries are reproducible from recorded inputs; no action without a journaled pre-condition; `--brain-act` off by default.
- **Overlay:** a forged/expired IRC record never yields a MEET; a DHT record never yields membership.
- **AI fabric:** every artifact path respects the fabric index authorization model (existing CI job) and the AGENTS.md security invariants.

---

## 5. Invariants (apply to every workstream)

From `AGENTS.md` (repository rules, merge blockers):

1. No classified-capable read primitive without an explicit authenticated security context; no context-free fallback for classified-capable data; `NULL` is never an authorization bypass.
2. No principal may create or modify a principal above itself.
3. Every new protocol adapter ships a low-clearance/high-data negative authorization test in CI.

From the federation plan (§3, non-negotiable):

4. Local survivability — an isolated node stays read-write for LOCAL-consistency namespaces.
5. No global quorum gate on ordinary local writes.
6. Execution decisions (VM start/stop/migrate/fence, storage/network promotion) remain **outside** QIHSE; QIHSE stores evidence, leases, epochs, ownership records.
7. Exclusive-state transitions fail closed without bricking unrelated local operation.
8. Every federation mutation is idempotent, attributable, and HLC-stamped.
9. Never infer safety from absence — a missing heartbeat is not proof a peer is down.
10. Signing authority and build execution are external; QIHSE records provenance, it does not sign or execute.

---

## 6. Non-goals

QIHSE does not become: a Proxmox replacement UI, VM scheduler, Xen/libvirt wrapper, host fencing system, storage controller, SDN controller, secret vault, remote shell, compiler/build executor, repository signing authority, or monolithic cluster manager. It provides the durable, secure primitives those systems require.

Also explicitly rejected from MEMSHADOW: Python monolith, Postgres, Docker tiers, consciousness/Mamba/neuromorphic/quantum layers, chat-platform glue.

---

## 7. Maintaining this document

- Update §1 when work lands; keep the status date current.
- Detailed stage designs belong in `docs/plans/` — link, do not duplicate.
- When a phase completes, mark it `[x]` here and record the evidence (commit range, test name) in §1.1.
- Progress reports read this file: keep checklist items countable (one `- [ ]` per deliverable).
