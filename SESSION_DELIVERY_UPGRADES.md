# QIHSE — Upgrades for Session-Delivery Workloads (SparkBench-class clients)

**Date:** 2026-09-11
**Status:** ✅ IMPLEMENTED — all of U1–U9 landed on 2026-09-11; see
[`docs/architecture/session_delivery.md`](docs/architecture/session_delivery.md)
for the as-built architecture, API/config reference, and test matrix. §3
below records the resolved design questions. Residual follow-ups: per-class
retention policies on top of the new sweeper (U6), per-blob content keys
wrapped under the session key once blobs gain at-rest encryption (U3), and an
HTTP face for the delivery endpoint if a non-RESP client ever needs one (U3).
**Context:** SparkBench (`~/Documents/sparkbench`, plan at
`~/Documents/driver_analysis/Volt/IMPLEMENTATION.md`) uses QIHSE as the
central server for a multi-tenant fleet of desktop clients. This document
specifies the engine upgrades that workload needs, grounded in the current
header surface (`/rpool/data/db/qihse/include/qihse/`, 97 headers).

**The workload in one paragraph:** each client session pulls one
*session bundle* (~1 MB typical: entitlement key-seed + PatchLens pattern
bundle + the tenant's encrypted script set), executes from it with
plaintext only ever materialized in the client's protected region, and
streams append-mostly telemetry back (build records, symbol contexts,
survival/burn observations). Telemetry never contains PII — by protocol,
not by policy. One tenant's catch must propagate to all tenants' kill
switches within minutes.

---

## 1. What the current surface likely already covers

| Need | Existing header(s) | Assessment |
|------|--------------------|------------|
| Tenant auth / tokens | `qihse_auth.h`, `keys/` (DSA + **KEM** keypairs) | Present. KEM keypairs are exactly what session-key issuance wants. Verify: tenant entity model, revocation list, token TTL. |
| Change propagation | `qihse_cdc.h`, `qihse_event_stream.h`, `qihse_subscription.h` | Present — burn-graph updates should ride CDC/subscriptions as server push rather than client poll. Verify push transport to remote clients (not just intra-cluster). |
| Rate limiting / quotas | `qihse_rate_limit.h` | Present. Needs per-tenant policy binding (see U2). |
| Wire protocols | `qihse_http_api.h`, `qihse_resp_wire.h`, `qihse_pg_wire.h`, `qihse_clickhouse_http.h` | Present. Delivery endpoint is a thin layer over one of these (U3). |
| Durability | `qihse_wal.h`, `qihse_mvcc.h`, `qihse_txn.h`, `qihse_recovery.h` | Present — telemetry appends are ordinary writes. |
| Vector ANN | `qihse_vector_db.h`, `qihse_hnsw.h`, `qihse_quantization.h` | Present. Symbol-context search needs tenant isolation guarantees (U5). |
| Full-text | `qihse_fts.h` | Present, incl. semantic classes. |
| Backup | `qihse_backup.h` | Present. Tenant-subset export missing (U7). |
| Scheduling jobs | `qihse_task_scheduler.h`, `qihse_task_queue.h` | Present — async commons-merge jobs run here. |

## 2. Upgrades needed (priority order)

### U1 — Object/blob tier for content-addressed blobs (HIGH)
Session bundles and script sets are ~64 KB–2 MB binary blobs; KV is
tuned for small values. Add a blob store:
- Content-addressed by SHA-256 (dedup gives delta-pull for free: "send me
  everything except these hashes I already have").
- Streaming read/write (no full-blob buffering), range reads for resume.
- Per-blob tenant binding + `class` tag (`entitlement_seed`,
  `pattern_bundle`, `script_set`, `commons_snapshot`).
- Lifecycle: `pattern_bundle` blobs immutable per client build;
  `script_set` blobs versioned per tenant (retention policy U6).

### U2 — First-class tenancy in the API path (HIGH)
Prefix conventions (`t:<id>/...`) are a client-side convention today.
Engine-side:
- Auth context carries tenant id; every KV/FTS/vector/graph call is
  tenant-scoped at the engine boundary (defense in depth against a
  mis-prefixed client).
- Per-tenant quotas on: bundle pulls/session, telemetry ingest rate,
  storage, ANN query cost (`qihse_rate_limit.h` binding).
- Revocation propagation SLA: revoked token → all surfaces refuse within
  N seconds, including in-flight bundle reads.

### U3 — Session-bundle composer + delivery endpoint (HIGH)
A service-level component (over `qihse_http_api.h` or cluster transport):
- Input: tenant id + detected client build fingerprint (+ "have-blobs"
  hash list for delta).
- Compose: entitlement key-seed (fresh per session, via KEM), current
  pattern bundle for that build, tenant script set delta.
- Output: a single encrypted, manifest-signed stream (~1 MB); chunked
  with resume; manifest lists blob hashes + per-blob key material wrapped
  under the session key.
- Server-side sanity gate before a pattern blob enters the commons
  (assertions must pass against the recorded build) — this is also the
  commons-poisoning defense.

### U4 — PII-free protocol enforcement at ingest (HIGH)
"No PII phoning home regardless of login" must be structural:
- A closed schema for telemetry record types (build_record,
  symbol_context, census, survival_observation, burn_edge) — anything
  outside the whitelist is rejected at ingest, not logged.
- Field-level validators: no free-text fields on telemetry paths (free
  text lives only in per-tenant script metadata, which the operator
  class deliberately never merges).
- No account identifiers, no machine identifiers beyond an opaque
  tenant-scoped hardware hash, no network-derived fields stored with
  commons data.

### U5 — Tenant isolation in shared vector indexes (MEDIUM)
Symbol contexts (commons) and script embeddings (private) may share HNSW
infrastructure:
- Either per-tenant indexes for private collections, or a shared index
  with hard tenant filters proven at the ANN layer (no
  cross-tenant neighbor leakage — test this; approximate search +
  filtering is a known leakage trap).
- Commons collections are world-readable to authenticated tenants by
  design (that's the network effect) — only *writes* are gated.

### U6 — Per-class retention / GC (MEDIUM)
- Censuses + survival sessions: time-windowed (e.g. 90 d raw, rolled up
  forever).
- Traces (vprobe): capped count per tenant.
- Script versions: unlimited (user content), but old *bundles* pruned
  once superseded (keep last N per build).
- Commons symbol contexts: immutable per build, pruned only when a client
  build is unreachable by any tenant (probably never — it's the asset).

### U7 — Tenant-subset backup/export (MEDIUM)
`qihse_backup.h` today presumably snapshots the store. Needed:
- Export tenant = portable artifact (script sets + private history +
  commons reference snapshot) → operator lock-in is zero, and a tenant
  can be migrated/deleted cleanly (deletion is the commercial-era
  requirement; build the export first, deletion follows trivially).

### U8 — Killswitch push channel (MEDIUM)
Burn-graph edge written → push to connected clients of *all* tenants
within minutes (subscription over CDC). Clients not connected get the
update in their next bundle pull. This is the §6.6 propagation mechanism
in the SparkBench plan — the engine piece is just "subscription fan-out
with a small SLA."

### U9 — Delivery metrics (LOW)
Per-endpoint counters for the workbench's status chips: bundle compose
latency, delta hit rate, push fan-out lag, ingest reject reasons (by
validator). `qihse_metrics.h` likely covers the primitives.

## 2a. Retrieval acceleration: KEYSTONE (no new engine work)

`~/Documents/KEYSTONE` already provides the retrieval layer these upgrades
would otherwise need — with a live `qihse_keystone_bridge` proven in the
harness enrichment pipeline. Mapping:

| Upgrade | KEYSTONE capability that serves it |
|---------|-------------------------------------|
| U3 bundle delta (have-hash resolution) | Content-addressed batch lookup (SIMD, OpenMP) |
| U5 symbol-context ANN prefilter | Trigram index → cheap candidate cut before embedding search |
| U6 commons queries at scale | Adaptive indexed lookup — retrieval cost stays flat as history grows |
| U9 metrics | Runtime backend calibration already logs decision provenance |

Rule: **storage stays QIHSE, retrieval goes through KEYSTONE.** The
upgrades above should specify QIHSE schemas/APIs and route their hot query
paths via the bridge — no parallel storage engine gets invented. Both are
Linux-side assets, consistent with the two-tier split (clients never link
either).

1. **Remote client transport:** is `qihse_http_api.h` the intended
   remote-client surface, or cluster bus? (SparkBench's Rust client needs
   one stable answer; clickhouse_http is a candidate if it already
   streams.)
2. **KEM session issuance:** confirm the KEM flow is per-session
   ephemeral (not per-tenant static) — bundle confidentiality must rot
   fast (SparkBench §3.4b honest-limit argument depends on it).
3. **Blob size ceilings in KV:** if large-value KV is actually fine
   (values >1 MB, streaming reads), U1 shrinks to content-addressing +
   lifecycle on top.
4. **ANN + filter leakage:** cite or test the isolation guarantee before
   sharing indexes across tenants (U5).

## 4. Sequencing

```
U2 (tenancy)  ─┐
U1 (blobs)    ─┼─► U3 (composer/endpoint) ─► U8 (push) ─► U9 (metrics)
U4 (PII gate) ─┘        │
                        └─► U5 (index isolation) · U6 (retention) · U7 (export) parallel
```

U2/U4 are prerequisites because retrofitting either after real tenants
exist is exactly the expensive migration this engine shouldn't need.


## 5. Status: LANDED (2026-09-11)

All phases shipped server-side. Open questions resolved by the landing:

1. **Transport:** RESP-native — BUNDLE.PREPARE/BUNDLE.CHUNK on the
   production RESP path; the HTTP layer stays a skeleton.
2. **KEM:** per-session ephemeral under the tenant client's ML-KEM-1024
   public key (verified different per session); manifests ML-DSA-signed;
   per-chunk re-authorization closes mid-transfer revocation.
3. **KV large values:** not viable — dedicated content-addressed blob
   store (U1) with streaming puts, range reads, refcounts, per-blob
   tenant binding; cross-tenant dedup refused.
4. **ANN leakage:** confirmed REAL — VECSEARCH silently ignored TAG, so
   searches swept the whole index (cross-tenant neighbor reachable).
   TAG is now a load-bearing filter with a planted-neighbor exclusion
   test. This validated the doc's original suspicion.

Highlights beyond spec: immediate revocation via per-command principal
re-validation (closed a live-connection read gap); U4 gate binds the
operator too; DBSIZE was hardcoded :0; U6 sweeper finally had a caller.

Client contract (zeus-core, aligned): AUTH password-per-connection;
killswitch = SUBSCRIBE channel + GET commons/killswitch/latest (there is
NO KILLSWITCH.CATCHUP command); telemetry = KV SET t:<id>/tlm/<kind>/<id>
against the five closed schemas.
