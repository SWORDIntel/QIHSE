# AI Compute Fabric — Superseding MEMSHADOW

> **Status: partial** — item 3 is the incomplete one. Item 1 is `implemented`
> and verified by `tests/test_node_cap_records.c`, with its durable
> reachability chain covered by the `gold-fabric-durable-caps` workload in
> `tests/gold/pack.v1.gold`. Item 2 is `implemented` and verified by
> `tests/test_fabric_index.c`. Item 3 is `implemented`: `FABRIC.SUBMIT` executes
> all four named job types locally, and it dispatches to a
> peer over the federation mTLS channel under a signed capability token
> (`src/federation/qihse_fabric_dispatch.c`, verified by
> `tests/test_fabric_dispatch.c`); the remaining gaps are recorded in
> `tests/gold/pack.v1.gold` under the `ai-fabric` area. Item 4 is `implemented` and verified by
> `tests/test_brain_actuate.c` (R1/R4) and `tests/test_brain_fed_journal.c`
> (W3.4). Item 5 is `implemented` and verified by `tests/test_ai_memory.c`
> (including an RBAC negative test). Embedding-backed semantic recall is no
> longer `planned`: it is `implemented` and verified by
> `tests/test_ai_memory_embed.c`.

Design of record for the heterogeneous AI compute cluster built on QIHSE +
KEYSTONE. This document is the execution spec: subagents and future sessions
implement from here. Each build item below carries its own status line,
because the items are at different stages.

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

> **Status: implemented** — `tests/test_node_cap_records.c` (durable records,
> both producer paths, trust and admissibility, malformed-record refusal), and
> the `gold-fabric-durable-caps` workload
> (`tests/gold/workloads/gold_fabric_durable_caps.c`, declared in
> `tests/gold/pack.v1.gold`) covering the topology-node-to-UUID chain that
> makes the durable record reachable at all.

- Bus frame `QIHSE_BUS_MSG_NODE_CAP = 8u` in
  `include/qihse_cluster_bus.h`, payload `{node_id[41], isa_tier u8
  (0=generic,1=AVX,2=AVX2,3=AVX-512,4=AVX-512+AMX), npu u8, gpu u8,
  free_ram_mb u32, load_pct u16}` — exactly 50 bytes, defined by
  `QIHSE_CLUSTER_BUS_NODE_CAP_PAYLOAD_SIZE`. (Earlier revisions of this
  document said "~90 bytes"; the code defines 50.)
- Emitted alongside every heartbeat (not every Nth) by
  `src/spinnaker/qihse_cluster_bus.c`, which stores the per-node capability in
  the bus's in-memory tables; the getter is
  `qihse_cluster_bus_node_caps(bus, node_index, isa, npu, gpu, free_ram, load)`.
- The frame is an UNAUTHENTICATED, in-memory hint: nothing binds the node id
  in the payload to the sender, and it is lost on restart. It updates the live
  hint table and writes no durable record.
- Capability data is now DURABLE as well. A first-class record
  (`qihse_federation_node_capability_t`) lives at `federation/node/<uuid>`,
  written by the local node's own probe
  (`qihse_federation_node_capability_record_local`, called by the bus for its
  configured local federation UUID, throttled to one write per 10 seconds) and
  by a signature-verified v3 membership statement. It is read with
  `qihse_federation_node_capability_lookup` (audit; returns the stored claim)
  or `qihse_federation_node_capability_lookup_admissible` (requires the node
  to be APPROVED right now).
- Trust semantics: the stored values are always a CLAIM, never an attested
  fact. A signature proves WHICH NODE made the claim, not that the hardware
  exists; a self-report carries `QIHSE_CAP_FLAG_ATTESTED` clear and nothing in
  the library sets that flag. The trust state stored in the record is a
  snapshot taken at admission for attribution and audit — it is NOT
  authorization, which is why the admissible accessor re-reads the identity
  record so a revocation takes effect immediately.
- ISA tier source: `backends/cpu/qihse_cpu_detect.c` (CPUID, not a kernel text
  interface that a container can mask). NPU: presence of the kernel accel
  device. GPU: a DRM render node or the NVIDIA control device. RAM and load
  are read from the kernel's memory-info and load-average interfaces. See
  `src/spinnaker/qihse_cluster_bus.c`.
- Consumers: `FABRIC.CAPS` (prefers the durable record, falls back to the
  live hint, and reports `src=durable` / `src=hint` so a caller can tell them
  apart) and the brain's placement scoring in
  `src/spinnaker/qihse_cluster_brain.c`. The topology-node-to-federation-UUID
  mapping is derived at node upsert, so no caller has to supply it.

### 2. KEYSTONE indexing hookup

> **Status: implemented** — `tests/test_fabric_index.c` (authorization
> negative test, soft-dependency fail-closed behaviour, candidate-only
> indexing).

- KEYSTONE (a separate C11/SIMD repository) indexes and classifies. It is a
  SOFT dependency: located via dlopen at first use, so QIHSE builds and runs
  without it and every index call fails closed with
  `QIHSE_FABRIC_INDEX_EUNAVAILABLE`.
- `include/qihse_fabric_index.h` wires the ingestion boundary: every artifact
  written under the `fabric:` KV prefix is classified and trigram-indexed once
  (`src/spinnaker/qihse_resp_engine.c`), and the `keystone-ingest` job
  executor calls it explicitly. The index keeps candidate postings only —
  KEYSTONE never retains artifact content, so no second copy of classified
  data exists outside the authoritative KV store.
- Lookup surfaces (`..._lookup_user`, `..._by_class_user`) require an
  authenticated context, deny NULL, and filter every candidate through
  `qihse_auth_can_access()` against the classification/SCI recorded at ingest.

### 3. Fabric job model

> **Status: implemented** — the local executors and the refusal path are
> verified by `tests/test_fabric_jobs.c`, and remote dispatch is verified by
> `tests/test_fabric_dispatch.c` (the `fabric-remote-dispatch` workload in
> `tests/gold/pack.v1.gold`). All four named job types have executors.
> Dispatch endpoint discovery is signed:
> the v4 membership statement carries the node's dispatch `host:port` inside
> the signed region, and `FABRIC.SUBMIT`/`FABRIC.FETCH` resolve the peer
> through the durable capability record (`lookup_admissible`, so revocation
> invalidates the endpoint) before falling back to the topology hint, which
> the job record marks `"ep":"topology"`.

- The command surface is RESP, not the bus job frame this item originally
  specified: `FABRIC.CAPS`, `FABRIC.SUBMIT [<type>] <min_isa> <need_npu>
  <payload>`, `FABRIC.RESULT <job-id>`, `FABRIC.FETCH <job-id>`. The FABRIC
  commands are refused outside the system tenant. The original four-argument
  form (`FABRIC.SUBMIT <min_isa> <need_npu> <payload>`) is retained and is an
  `embed` job.
- Two executors exist, both LOCAL:
  - `embed` turns the payload into an AI memory, so the result is indexed for
    lexical and semantic recall; the returned id reads the payload back.
  - `keystone-ingest` persists the payload as a `fabric:ingest:<job-id>`
    artifact and classifies/indexes it through KEYSTONE. Because the index is a
    soft dependency, "stored but not indexed" is reported as its own
    `stored-unindexed` status rather than as success.
- `inference` runs the ACTIVE embedding provider over the payload — the
  builtin lexical vector today, a real model when one is installed via
  `qihse_ai_memory_set_embedder` — and persists the result as a
  `fabric:infer:<job-id>` artifact record (`model:<name> dim:<n>
  sha384:<digest> vec:<f,f,...>`) at the caller's classification, remotely
  under `fabric:infer:r:<submitter>:<job>` at the token's claims. The output
  is a deterministic function of (payload, provider), which is what makes it
  dispatch-idempotent.
- `index-build` re-indexes a key prefix through the fabric index. The build
  unit is the namespace scan: the payload is the prefix ("fabric:" when
  empty), `qihse_fabric_index_build` iterates the records the CALLER's
  principal may read and feeds each to `qihse_fabric_index_artifact_user` —
  the same hook the ingest path uses, so a rebuild converges rather than
  duplicating. The report (`prefix: scanned: indexed: unindexed:`) is
  persisted at the deterministic `fabric:index:<job-id>` key
  (`fabric:index:r:<submitter>:<job>` remotely), which makes it
  dispatch-idempotent, and fabric bookkeeping keys (`fabric:job:`,
  `fabric:result:`, `fabric:index:`) are excluded so a rebuild never indexes
  its own report. A type with no executor is still REFUSED with
  `job type not implemented`.
- Remote dispatch is implemented (`src/federation/qihse_fabric_dispatch.c`).
  A job whose best-fit node is a peer is sent over the federation mTLS
  channel with a signed capability token binding job type, job id, payload
  digest, submitter node, principal claims, scope and expiry; the executor
  verifies it against the mTLS peer and a replay ledger, runs the job as the
  token's principal — never the executor's own — and owns the result record.
  The submitter's record is `pending-fetch` until `FABRIC.FETCH` pulls and
  caches the record locally; a tampered cache is reported `cache-corrupt`,
  not served. Both executors are dispatch-idempotent: `keystone-ingest`
  overwrites its deterministic artifact key, and the executor dedups on the
  submitter+job binding, so a retried `embed` RUN re-ACKs the existing result
  record instead of creating a second memory. `gave-up` remains distinct
  from `failed`.
  When dispatch is not configured the record stays `queued`, which is the
  truth. Placement picks the lowest `load_pct` among nodes meeting the
  ISA/NPU requirement from the live hint table, then falls back to the local
  node's durable record so a single-node fabric can place work at all;
  reachability is not consulted. The dispatch endpoint is the peer's signed
  v4 endpoint when a verified statement has been accepted (the durable
  capability record's `dispatch_endpoint`), and the topology `host:port`
  otherwise — the mTLS handshake pins the peer identity either way, so a
  forged hint can only cost a refused connection. The job record reports
  which source was used.
- Job records live at `fabric:job:<job-id>` and ARE the result `FABRIC.RESULT`
  returns. The job frame this item specified — payload blob hash, priority,
  bus or task-queue dispatch — was not built: there is no priority field, no
  blob hash, and no fabric path touches `src/spinnaker/qihse_task_queue.c` or
  `src/spinnaker/qihse_task_scheduler.c`.

### 4. Brain governance (phase 2 act)

> **Status: implemented** — R1 failed-owner re-home and R4 rollback are
> verified by `tests/test_brain_actuate.c`; the W3.4 federation decision
> envelope (signed, citing the observation it was derived from) is verified by
> `tests/test_brain_fed_journal.c`. The narrower claim that a decision record
> carries the capability evidence fields is `partial — status unverified`: the
> code journals them (`brain_caps_evidence` in
> `src/spinnaker/qihse_cluster_brain.c`) but no test asserts them.

- Capability-aware placement decisions, signed and journaled: the placement
  evidence (capability headroom + load, with the profile's source — `durable`
  or `hint` — recorded, uptime tie-break) is part of the decision record, and
  since W3.4 the decision itself is published to the federation event journal
  as an authenticated envelope citing the observation it was derived from (see
  `docs/architecture/cluster_brain.md`).
- Evidence gates already specified: confirmed-failure vs asymmetry vs
  isolated (see `docs/architecture/cluster_brain.md` R1-R4).

### 5. Local-first AI memory API

> **Status: implemented** — `tests/test_ai_memory.c` (store/recall/get/forget/
> count and the RBAC negative test) and `tests/test_ai_memory_embed.c`
> (embedding-backed recall: a semantic match with no shared tokens, clearance
> filtering on every mode, provider binding, forget, hybrid fusion).

- Episodic/semantic memory for AI workloads stored in QIHSE KV/FTS with
  KEYSTONE classes. This is the MEMSHADOW successor surface.
- **Implemented as** `qihse_ai_memory_store/recall/get/forget/count`
  (`include/qihse_ai_memory.h`): records in the `aimem:` KV namespace, indexed
  by the FTS engine for BM25 recall over caller-visible documents only, with
  every entry point taking an explicit security context. There is no
  context-free variant.
- Embedding-backed recall is implemented, not planned:
  `qihse_ai_memory_recall_mode()` supports BM25, SEMANTIC and HYBRID.
  `qihse_ai_memory_set_embedder()` installs a provider (NULL restores the
  built-in one), `qihse_ai_memory_embedding_dim()` and
  `qihse_ai_memory_embedder_name()` describe the active provider, and vectors
  are stored under `aimemv:<id>` bound to the name of the embedder that
  produced them — vectors from different providers are never compared, because
  comparing them yields confident nonsense rather than an error. HYBRID fuses
  the two rank lists (reciprocal rank fusion) rather than adding BM25 and
  cosine scores, which live on different corpus-dependent scales.
- The built-in embedder is deliberately LEXICAL and named for what it is:
  `builtin-lexical-256`, 256 dimensions, deterministic token hashing. Its
  similarity reflects shared vocabulary, not meaning. It exists so the
  storage, ranking, fusion and filtering paths are complete and testable with
  no model present; a real model plugs into the same interface and everything
  downstream is unchanged. The maximum accepted dimension is
  `QIHSE_AIMEM_MAX_DIM` (1024).
- Every ranking mode resolves candidates through the same authorization-aware
  read, so no mode can rank, score, or even count a record the principal
  cannot see. That is the property that matters here, because an embedding is
  derived from the text and can leak it.
- Correction to this item's original specification: it called for 4096-d
  quantized embeddings via QIHSE's own quantization module. What was built is
  neither — vectors are float, stored as decimal text in KV, capped at 1024
  dimensions with a 256-d built-in, and there is no quantization step. The
  record layout and RBAC surface are as specified.
- Cross-node queryability is `partial — status unverified`: recall runs
  against a server's own store and process-local vector/FTS state, and no test
  drives it from a peer node.

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
going to have to invent. What remains above should be built on the plan's
primitives rather than ad-hoc bus messaging:

- fabric job dispatch (the missing remote half of item 3) needs the mutation
  envelope, idempotent request IDs, leases, and watch streams (plan §8, §9,
  §13, §14). Brain governance already publishes to that journal (W3.4);
- item 1's NODE_CAP payloads have since been built as first-class node records
  at `federation/node/<uuid>` with trust state and capabilities (plan §6.1;
  see the W2.4 section of `include/qihse_federation.h`);
- the same lease/idempotency model is what the Citadel build fabric uses
  (plan §28–30) — one set of primitives, two consumers;
- KEYSTONE consumes the plan's resumable change feed with a read/index
  identity, never database-admin privileges (plan §26).

This document remains the design of record for AI-workload dispatch
(embedding/inference/index-build jobs); the federation plan governs the
substrate those jobs run on. All four named job kinds — `embed`,
`keystone-ingest`, `inference`, `index-build` — execute today, both locally
and on a peer over the signed dispatch channel.
