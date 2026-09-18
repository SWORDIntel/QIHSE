# AI Compute Fabric — Superseding MEMSHADOW

> **Status: implemented** — items 1–5 are verified by `tests/test_fabric_index.c`
> (KEYSTONE fabric index), `tests/test_brain_actuate.c` (capability-aware
> placement), and `tests/test_ai_memory.c` (local-first AI memory, including an
> RBAC negative test). Embedding-backed semantic recall is `planned`: recall
> today is BM25 over caller-visible documents.

Design of record for the heterogeneous AI compute cluster built on QIHSE +
KEYSTONE. This document is the execution spec: subagents and future sessions
implement from here.

## The idea

MEMSHADOW bolted AI memory onto chat platforms in a Python monolith. The
replacement: **the cluster itself is the AI substrate**. Every device
advertises what it has (ISA tier, NPU/GPU, memory, load), QIHSE routes AI
work to the best-fit hardware, and every artifact (embeddings, documents,
job results, decisions) lands in QIHSE's own stores, indexed by KEYSTONE.
C runtime, SIMD/NPU paths, signed governance — no Python monolith, no
Postgres, no platform glue.

## Build items (in order)

### 1. NODE_CAP capability profiles (bus)
- New bus frame `QIHSE_BUS_MSG_NODE_CAP = 8u` in
  `include/qihse_cluster_bus.h`, payload `{node_id[41], isa_tier u8
  (0=generic,1=AVX,2=AVX2,3=AVX512,4=AMX), npu u8, gpu u8, free_ram_mb u32,
  load_pct u16}` (~90 bytes).
- Emitted alongside heartbeats (piggyback loop like NODE_OBS) every N
  heartbeats; handler stores per-node capability in the bus (arrays like
  obs_healthy_ms pattern) with getter
  `qihse_cluster_bus_node_caps(bus, idx, out)`.
- ISA tier source: `backends/cpu/qihse_cpu_detect.c` already detects AVX2/
  AVX-512/AMX. NPU: OpenVINO backend presence (`backends/npu/`). GPU:
  probe CUDA device file.
- Files: bus .h/.c, small brain/daemon wiring. No new threads.

### 2. KEYSTONE indexing hookup
- KEYSTONE (`~/Documents/KEYSTONE`, C11/SIMD/OpenMP) indexes and classifies;
  it already feeds QIHSE. Wire its ingestion API so every artifact QIHSE
  stores via the fabric (KV writes under `fabric:` prefix, job results,
  brain decisions) is classified + indexed once, searchable cluster-wide
  by semantic class.
- Read KEYSTONE's public headers first (`ls`, main header), link as needed,
  integrate at the QIHSE ingest boundary (`qihse_resp_handle_set` fabric
  prefix hook or `KEYSTONE.INGEST` path).

### 3. Fabric job model
- Job frame over the bus OR task-queue wiring:
  `{kind: embedding|inference|index-build|keystone-ingest, payload blob
  hash, cap requirement (isa/npu/gpu), priority}`.
- Dispatch: best-fit node by NODE_CAP + observation matrix (reachability)
  + load. Results land as QIHSE vectors/KV, KEYSTONE-indexed.
- Reuse: `src/spinnaker/qihse_task_queue.c`, `qihse_task_scheduler.c`.

### 4. Brain governance (phase 2 act)
- Capability-aware placement decisions, signed and journaled: the placement
  evidence (NODE_CAP headroom + load, uptime tie-break) is part of the decision
  record, and since W3.4 the decision itself is published to the federation
  event journal as an authenticated envelope citing the observation it was
  derived from (see cluster_brain.md).
- Evidence gates already specified: confirmed-failure vs asymmetry vs
  isolated (see cluster_brain.md R1-R4).

### 5. Local-first AI memory API
- Episodic/semantic memory for AI workloads stored in QIHSE vectors/FTS/KV
  with KEYSTONE classes, 4096-d quantized embeddings via QIHSE's own
  quantization module. Queryable from any node. This is the MEMSHADOW
  successor surface.
- **Implemented as** `qihse_ai_memory_store/recall/get/forget/count`
  (`include/qihse_ai_memory.h`): records in the `aimem:` KV namespace, indexed
  by the FTS engine for BM25 recall over caller-visible documents only, with
  every entry point taking an explicit security context. Embedding-backed
  semantic search (quantized vectors instead of lexical recall) remains the
  follow-up; the record layout and RBAC surface do not change when it lands.

## Rejected from MEMSHADOW
Python monolith, Postgres, Docker tiers, consciousness/Mamba/neuromorphic/
quantum layers, chat-platform glue. Kept: signed governance, health
rollback, deterministic telemetry, capability-aware dispatch.

## Lab topology (current)
- t420 seed 192.168.1.91:7100, slots 0-10922
- T320 192.168.1.250:7101, slots 10923-13653
- Container 10.200.69.2:7112 (routed via T320), slots 13654-16383
- VPS 5.63.21.230 (4th node — blocked on SSH key restoration; wireguard
  join design in memory/cluster notes)

## Relation to the federation direction

The [federation upgrade plan](../plans/qihse_federation_upgrade_plan.md)
(accepted 2026-09-15) supplies the coordination substrate this fabric was
going to have to invent. Items 3–5 above should be built on the plan's
primitives rather than ad-hoc bus messaging:

- fabric job dispatch and brain governance use the mutation envelope,
  idempotent request IDs, leases, and watch streams (plan §8, §9, §13, §14);
- item 1's NODE_CAP payloads generalize into first-class node records at
  `federation/node/<uuid>` with trust state and capabilities (plan §6.1);
- the same lease/idempotency model is what the Citadel build fabric uses
  (plan §28–30) — one set of primitives, two consumers;
- KEYSTONE consumes the plan's resumable change feed with a read/index
  identity, never database-admin privileges (plan §26).

This document remains the design of record for AI-workload dispatch
(embedding/inference/index-build jobs); the federation plan governs the
substrate those jobs run on.
