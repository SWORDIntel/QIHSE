# QIHSE Roadmap

**Status date:** 2026-09-15
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

### 1.2 In flight — implemented but NOT committed

This is real, buildable, tested-in-places work sitting outside git. **A clean clone does not contain it, yet the working-tree `Makefile` builds against it** — committing the Makefile/daemon changes without these sources would break CI. Landing this is W0.

| Item | Evidence | Gap |
|---|---|---|
| Cluster brain phase 1 (observe/journal/decide, `--brain-act` gating, ML-DSA-signed decision records) | `src/spinnaker/qihse_cluster_brain.c` (345 LOC), `include/qihse_cluster_brain.h`, daemon flags `--brain*` | untracked; **no smoke test** — `docs/architecture/cluster_brain.md` references `tests/cluster_brain_smoke.py`, which does not exist; no Makefile test target |
| Overlay protocol phase 1 (veiled bus framing in `qihse_cluster_bus.c`; IRC dead-drop bootstrap with HMAC-SHA-384 record authenticity — ML-DSA signing is the phase-2 path) | `src/spinnaker/qihse_overlay.c` (918 LOC), `include/qihse_overlay.h`, bus `veil_key` wiring, `--irc-*` flags | untracked; no test target; design doc `overlay_protocol.md` corrected with an implementation-status note |
| KEYSTONE fabric index (AI fabric item 2) | `src/spinnaker/qihse_fabric_index.c` (625 LOC), `include/qihse_fabric_index.h`, `tests/test_fabric_index.c`, Makefile `test-fabric-index`, CI job | untracked |
| AI fabric items 1 & 3 (NODE_CAP capability frames; `FABRIC.CAPS/SUBMIT/RESULT` job dispatch) | `include/qihse_cluster_bus.h` (`QIHSE_BUS_MSG_NODE_CAP = 8`), `qihse_cluster_bus.c`, `qihse_resp_engine.c` | modified-but-uncommitted |
| Docs of record for the above | `docs/architecture/{ai_fabric,cluster_brain,overlay_protocol}.md`, `docs/plans/qihse_federation_upgrade_plan.md` | untracked |
| Cluster smoke tests | `tests/cluster_{smoke,discover_smoke,failover_smoke,loadshift_smoke}.py` | untracked |
| Repo hygiene debt | untracked binaries at repo root (`qihse-cluster-daemon`, `qihse-redis-server`); tracked build artifacts deleted in tree (`algorithms/qihse_rff.o`, `rust/qihse-rs/target/**`); `.zcode/` session plans | decide ignore-vs-commit policy |

### 1.3 Design of record — accepted, not implemented

| Direction | Design doc | Status |
|---|---|---|
| **Phase 10 — Federation data plane** (stages F0–F7, 22 acceptance criteria) | [federation upgrade plan](docs/plans/qihse_federation_upgrade_plan.md) | `[ ]` planning only |
| AI compute fabric items 4–5 (brain governance on federation primitives; local-first AI memory API) | [ai_fabric.md](docs/architecture/ai_fabric.md) | `[ ]` |
| Cluster brain phases 2–3 (migrate observations to federation journal; incident retrieval via FTS/vector) | [cluster_brain.md](docs/architecture/cluster_brain.md) | `[ ]` |
| Overlay phases 2–3 (DHT peer exchange; AI memory API) | [overlay_protocol.md](docs/architecture/overlay_protocol.md) | `[ ]` |
| Production hardening (whitepaper near-term priorities 1–5) | [whitepaper v1.1 §12](docs/architecture/qihse_whitepaper_v1.1.md) | `[~]` partly landed (telemetry, security); optimizer governance and gold validation suite open |

---

## 2. Workstreams

### W0 — Land in-flight work (prerequisite for everything else)

The untracked/modified cluster work above must be committed with its tests before any federation refactor rebases onto it.

- [ ] **W0.1** Review and commit the cluster brain, overlay, fabric index, NODE_CAP, and `FABRIC.*` work as scoped commits (sources + headers + Makefile + daemon + CI + docs together, so the build never references an uncommitted file).
- [ ] **W0.2** Write the missing `tests/cluster_brain_smoke.py` (spec: `docs/architecture/cluster_brain.md` §Testing — assert R2/R3 journal-only behaviour, then R1 re-home under `--brain-act`) and register a Makefile target.
- [ ] **W0.3** Add an overlay test target (framing round-trip + record verify/replay-window rejection) so `qihse_overlay.c` is not untested on merge.
- [ ] **W0.4** Repo hygiene: ignore or remove root binaries and tracked build artifacts; set an explicit policy for `.zcode/` session plans.
- [ ] **W0.5** Review the uncommitted Python SDK changes (`python/qihse/{core,event_stream,fusion,hardware,neural}.py`) and commit or discard.

### W1 — Federation data plane (Phase 10)

The accepted major direction. Governing principle: **federation must enhance a node, never become a prerequisite for that node to remain locally operable.** All stage definitions and the 22 acceptance criteria live in the [federation upgrade plan](docs/plans/qihse_federation_upgrade_plan.md); this roadmap only sequences them.

- [ ] **F0 — Refactor boundaries.** Federation module skeleton, UUID/HLC/object-generation/fencing-epoch primitives, current cluster semantics documented. No behavior changes.
- [ ] **F1 — Sovereign local state.** Consistency classes (LOCAL/EVENTUAL/CAUSAL/QUORUM/LINEARIZABLE), local-authority namespaces, no global quorum gate on local-safe writes, federation status API. *Unblocks acceptance criteria 1–2.*
- [ ] **F2 — Event journal + watches.** Immutable mutation envelope, resumable watch API, idempotent request IDs, controller SDK. *Unblocks W2, W3-phase-2, and acceptance criteria 5, 9, 10.*
- [ ] **F3 — Replication correctness.** Anti-entropy, manifests/range digests, explicit conflict objects, resumable reconciliation. *Needs F2. Unblocks criteria 6–7.*
- [ ] **F4 — Strong namespace.** Scoped consensus groups, native CAS, monotonic fencing epochs, lease primitive, explicit membership. *Needs F1+F2. Unblocks criteria 3–4, 10.*
- [ ] **F5 — Trust plane.** Node enrollment, mTLS, signed replay-resistant gossip, revocation, infrastructure security scopes. *Needs F0 identity primitives. Unblocks criterion 8 and overlay phase-2 membership.*
- [ ] **F6 — Build & supply-chain substrate.** Package override/source registry, build-job state machine, worker capability records, build leases, provenance graph, SBOM/attestation records, vulnerability observations, repository snapshots, controller-facing build APIs. *Needs F2+F4+F5. Unblocks criteria 15–22.*
- [ ] **F7 — Operational hardening.** Rolling schema upgrades, federation-consistent snapshots, chaos suite, performance regression budgets, recovery tooling.

### W2 — AI compute fabric

Items 1–3 are in flight (see §1.2); items 4–5 build on federation primitives rather than ad-hoc bus messaging.

- [ ] **W2.1** Land items 1–3 with tests (covered by W0).
- [ ] **W2.2** Brain governance phase 2 — capability-aware placement decisions, signed and journaled to the federation event journal (needs F2; consumes W3's R1–R4 rules).
- [ ] **W2.3** Local-first AI memory API — episodic/semantic memory in vectors/FTS/KV with KEYSTONE classes and quantized embeddings, queryable from any node (needs F2).
- [ ] **W2.4** Generalize NODE_CAP payloads into first-class federation node records at `federation/node/<uuid>` with trust state (needs F1+F5).
- [ ] **W2.5** KEYSTONE consumes the resumable change feed with a read/index identity — never database-admin privileges (needs F2; criterion 9).

### W3 — Cluster brain

- [ ] **W3.1** Phase 1 hardening and landing (W0.1–W0.2).
- [ ] **W3.2** Migrate observations/signed decisions onto the federation event journal with HLC stamps and authenticated envelopes; R1–R4 consume watch streams instead of polling topology snapshots (needs F2).
- [ ] **W3.3** Persistent worker pool if cadence rises (current: ~730–780 µs/cycle at 8 workers, thread-spawn dominated).
- [ ] **W3.4** Phase 3: incident retrieval over QIHSE's own FTS/vector indexes (dogfooding).
- [ ] **W3.5** Hard boundary: brain actuation stays database-internal (slot re-homing, quarantine). It must not grow hypervisor actuation — execution decisions belong to the external controller.

### W4 — Overlay protocol

- [ ] **W4.1** Land phase 1a–1c (covered by W0).
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
