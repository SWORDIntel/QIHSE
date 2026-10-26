# Scoped AIMEM hybrid indexing through KEYSTONE

Status: in progress. KEYSTONE now has a sealed, filtered, dimension-aware
candidate-only vector primitive with tests. No QIHSE ingestion, durable
projection, rebaseline or production semantic/hybrid switch is implemented;
existing explicit hybrid queries still perform per-query scoped embedding.

## Evidence and boundaries

- `src/spinnaker/qihse_ai_memory.c:683`: scoped writes skip the persisted-vector
  path (`if (!scope)`). Existing unscoped vector keys are not a scoped schema.
- `src/spinnaker/qihse_ai_memory.c:1941`: scoped recall embeds matching documents
  inside the KV enumeration callback. The query embeds once, then scans the
  tenant prefix and rebuilds vector candidates on every request.
- `src/spinnaker/qihse_ai_memory.c:1880`: lexical projections are principal/scope
  specific and invalidated by the whole-store change sequence. They are loaded
  per request, and unrelated KV writes can trigger rebuilds.
- `src/spinnaker/qihse_ai_memory.c:2088`: final canonical reads and authorization
  checks are essential; preserve them regardless of index implementation.
- KEYSTONE's `include/keystone_workflow_index.h` supplies relevant patterns:
  contiguous committed watermarks, idempotent replay, staged generations,
  authenticated checkpoints, and candidate-only queries. Its workflow schema
  explicitly forbids content-derived tokens: do not put embeddings into it.
- KEYSTONE's `include/keystone_incident.h` exposes fixed 64-dimensional incident
  vectors and payload-bearing results, not a generic scoped AIMEM vector API.
  Reuse audited numerical kernels/dispatch where suitable, not that record ABI.
- QIHSE's `include/qihse_fabric_index.h` demonstrates optional dynamic KEYSTONE
  loading and authorized candidate lookup; its trigram/classification interface
  is neither BM25 nor general semantic search.
- `include/qihse_kv_store.h:282-333` already exposes bounded, principal-filtered
  incremental exports. Tombstones may be GC'd before a consumer sees them and
  a restore does not re-stamp records (lines 309-316). Thus a delta cursor alone
  is not sufficient to recover a complete vector index; perform reconciliation
  at restart and establish explicit restore/GC invalidation before enabling it.

## Decision

QIHSE owns canonical memory, grants, lifecycle, embedding policy and durable
mutation history. KEYSTONE owns the rebuildable high-speed candidate index:
scope/security postings, dimension-aware vectors, and eventually incremental
lexical postings. Do not create a competing QIHSE ANN engine or use a global
unfiltered top-k followed only by permission filtering.

First integration: explicitly configured, version/capability-checked
`libkeystone` inside the standalone AIMEM process. This follows the existing
addon model and avoids another authentication/network hop. Isolate its handles
by store identity, tenant and model generation. A separate daemon is a later
option only with authenticated projection and query bindings; never expose a
socket that accepts caller-supplied clearance as authority.

Embeddings, postings and content hashes are sensitive derived data, not harmless
metadata. Use a dedicated protected projection location, not KEYSTONE's shared
code-search index. Apply the source labels and required at-rest protections;
keep plaintext memory exclusively in QIHSE. No client reads QIHSE storage files.

## Query contract

1. Authenticate through the existing pinned QKP/AIMEM_SERVICE path. Snapshot
   current principal identity, tenant, clearance, SCI, scope, grants/policy epoch,
   requested kind, model generation and freshness requirement.
2. Select an immutable index generation with a complete watermark. A stale,
   absent, corrupt or incompatible semantic index returns a distinguishable
   error, not successful empty results or an unbounded synchronous rebuild.
3. Embed only the query. Initially do not cache query embeddings; any later
   cache must include model/preprocessing and security-domain identity.
4. KEYSTONE intersects tenant, scope hierarchy, kind and authorized visibility
   postings before ranking. Authoritative grant resolution stays in QIHSE;
   derive eligible owner/project sets from current policy, not stale feed claims.
5. Rank the eligible vectors. Start with exact SIMD dot products over normalized,
   persisted FP32 vectors; add approximate retrieval only when corpus benchmarks
   justify it. Approximate search must support eligible-set filtering and bounded
   continuation rather than letting inaccessible rows starve visible top-k.
6. Initially retain the current authorization-aware BM25 lane and RRF formula.
   Request bounded independent lexical/vector candidates, merge by full UUID,
   and use deterministic tie-breaking. Trigram substring search is not a BM25
   replacement. Move lexical ranking to KEYSTONE only after visible-corpus
   statistics and tokenizer equivalence have regression coverage.
7. Re-read each candidate through the current QIHSE user context. Check full
   UUID, source revision, existence/tombstone, tenant, ownership/grants, labels,
   kind and all scope components. Revalidate policy epoch before disclosure;
   bounded retry or error on a racing revocation. Never return index snippets.
8. Apply one end-to-end monotonic deadline across embedding, retrieval, fusion,
   candidate continuation and materialization. Preserve successful-empty versus
   unavailable/stale/deadline errors; keep the legacy reply shape on success.

BM25 remains the automatic-hook default throughout migration. Explicit semantic
and hybrid do not silently degrade to lexical-only results. A separately explicit
best-effort API could report degraded mode later; it is not needed for v1.

## Projection and persistence contract

Proposed versioned entry (not an existing API): store/history identity, full
memory UUID, source revision/content digest, tenant, owner, four scope components,
kind, classification, SCI, tombstone, model identity and normalized vector.

Model identity includes model-artifact digest, tokenizer digest, pooling,
normalization, truncation/preprocessing version, dimension and numeric encoding.
A provider name alone is insufficient. Reject mismatched dimensions, NaN/Inf,
zero-norm vectors and incompatible generations. Resolve shortened existing doc
IDs against full UUIDs; do not extend a 64-bit collision risk into a new format.

An index generation is published only after its complete source interval is
represented. Reuse suitable KEYSTONE staging/checkpoint machinery without
weakening the workflow index's metadata-only contract. Persist format version,
source history, model identity, checksums/authentication and watermark together;
fsync data and parent directory before atomic publication. A failed or corrupt
load never advances the watermark. Rebuild from the authenticated source.

Use a service-scoped AIMEM projection sequence, or a globally sequenced feed
with explicit empty covered intervals. Unrelated KV writes must not force
rebuilding the lexical/vector index. Projection writes must not feed themselves
back into endless invalidation.

## Mutation and worker path

The standalone store has `qihse_kv_export_incremental_user_bounded` with
record revisions/labels. Verify its AIMEM namespace, watermark and principal
coverage before consuming it inside the server; it is a latest-state iterator,
not an indefinitely retained event log. Use a complete backfill/reconciliation
at restart and after restores. Detect GC/restore invalidation explicitly, rather
than assuming cursor gaps reveal missing tombstones. If the required freshness
contract cannot be met with this iterator, add a durable ordered AIMEM change
interface at the canonical mutation boundary.

Do not implement canonical write followed by a best-effort queue insert: a
crash in between loses indexing work. The source mutation must carry a durable
indexable revision/change record under the existing recovery contract, or the
worker must recover it deterministically from that contract. A separate outbox
requires atomicity with the canonical write; establish that before choosing it.
Preserve existing eventual versus durable STORE acknowledgements and do not
pretend a derived-index ACK strengthens canonical durability.

Workers consume bounded batches and coalesce superseded versions. Capture
bounded authorized data under store locks, release locks, compute embeddings,
then publish only if source revision and model generation still match. No
embedding, projection write, index callback reentry or disk checkpoint under
KV enumeration locks. No raw user pointer retained beyond its safe lifetime.

Cover STORE, idempotent replay, FORGET, expiry, scope migration, import/restore,
label changes, ownership changes and grant/revocation updates. Deletes and ACL
revocations invalidate eligibility immediately through canonical rechecks even
when the worker lags. Acknowledged indexed freshness must be explicit; clients
can wait for a required sequence within their deadline. Worker failure must not
cause records to disappear from BM25 or turn errors into successful empty hits.

## KEYSTONE implementation scope

- Inventory and test existing SIMD kernels, scalar references, checkpoint and
  staged-publish code before extracting reusable pieces.
- Add a separate candidate-only vector API with configurable dimension, full
  UUID IDs, source/model generation, eligible-set filter, bounded top-k, explicit
  status and deadline/cancellation support. No incident labels/resolution text.
- Partition by tenant/model; index scope components and kinds as postings rather
  than duplicating vectors for every user/scope combination. Current policy
  constructs authorized candidate sets; never let cross-tenant statistics or
  scores influence visible output.
- Small eligible sets: exact contiguous SIMD scoring. Large sets: benchmark
  before selecting filtered ANN. Avoid quantization until FP32 correctness and
  retrieval-quality baselines exist. Check runtime ISA capability, retain tested
  scalar fallback, and report the backend actually used.
- Preserve bounded memory and generation lifetime under concurrent readers,
  writers and model switches. Do not hold index locks while calling QIHSE.

## Delivery stages and exit gates

### 0. Contract and baseline

Trace all mutation/revocation paths and prove the feed/recovery boundary. Measure
QKP/auth, query embedding, KV enumeration, lexical load/build, candidate scoring
and final authorization separately. Audit KEYSTONE ABI availability on the actual
host. Deliver the finalized feed, privilege and query-status contracts first.

### 1. Persisted projection and KEYSTONE exact-vector lane

Implement generation-safe worker ingestion and bounded exact SIMD retrieval.
Verify unchanged records are embedded once per content/model generation, not per
query. Semantic queries must perform zero document embeddings and zero full
canonical-record scans. Keep BM25 and existing hybrid fusion behavior.

### 2. Incremental lexical lane

Remove whole-store invalidation and per-request lexical reload/rebuild. Preserve
visible-corpus BM25 statistics, existing tokenization and policy semantics. Reuse
KEYSTONE posting primitives where appropriate; do not relabel trigrams as BM25.
Gate the switch with authorized ranking equivalence tests.

### 3. Authenticated backfill and shadow operation

Begin capturing changes at W0, enumerate an authorized bounded snapshot with a
real revision boundary, and replay changes through W1 before atomic publication.
If existing enumeration cannot provide this boundary, implement the needed
snapshot/change mechanism first. Coalesce tombstones and newer revisions so
backfill cannot resurrect deleted memories. Persist restartable progress bound
to history/model identity. Use a least-privileged AIMEM projection principal;
AIMEM_SERVICE should not acquire operator or generic KV access.

Run shadow reads against an isolated fixture and then authorized live queries.
Record IDs/counts/latencies, not memory text. Keep existing automatic BM25 and the
old model generation until a complete new generation passes checks. Rollback
selects the prior index/configuration without rewriting canonical memory.

### 4. Quality and performance; staged enablement

Test the current live-size corpus and synthetic 1k/10k/100k corpora, varying scope
selectivity, tenants, labels, text lengths, grant churn, cold/warm cache and
1/8/32 concurrent readers. Keep synthetic data isolated from live AIMEM.

Proposed acceptance targets, to calibrate from measured hardware baselines:
- Zero document embeddings per steady-state query; no whole-store rebuild after
  unrelated writes; bounded query memory and continuation work.
- Exact FP32 results match a scalar authorized oracle within numeric tolerance.
  If ANN is introduced, target recall@10 >= 0.95 against the same eligible corpus.
- Warm index/filter/fusion p95 <= 100 ms at 100k records on the target machine;
  separately report query-embedding and QKP/auth costs. This is a target, not an
  existing performance claim.
- Live automatic hook p95 <= 5 s and p99 below its configured deadline under
  normal load; measure fresh and persistent sessions separately.
- Publication-lag SLO must be selected from measured embedding throughput and
  arrival rates; report backlog age, not merely queue length.

Enable explicit indexed semantic/hybrid first. Only consider changing the
hook default after full latency, authorization and retrieval-quality gates pass;
that default change is a separate rollout decision.

## Required regression matrix

- Cross-tenant, low-clearance/high-data, SCI subset, owner and delegated project
  grants; NULL/inactive users; grant revoke during query; scope hierarchy and
  global-scope semantics; hidden records must not affect visible BM25 statistics.
- Forged/stale candidates, colliding shortened IDs, UUID/revision mismatch,
  forged caller metadata, unknown index format/ABI, model mismatch and corrupt
  vector/checkpoint rejection. No unauthorized IDs, counts or payloads disclosed.
- Crash after canonical mutation, during embedding, before/after index publish,
  checkpoint interruption, duplicate/out-of-order/gapped replay, disk full,
  restart during backfill, expired/delete/reinsert races, model switch mid-query.
- Concurrent reads/writes/forget, bounded lock hold time, deadlock tests,
  sanitizers and thread-safety checks appropriate to both C implementations.
- KEYSTONE missing/restarting, embedding failure, queue saturation, cancellation,
  stale watermark and deadline expiry return distinguishable bounded errors.
- Real pinned-QKP integration with HAX, Python MCP and installed Codex/ZCode
  clients. No mock-only completion and no cleartext downgrade.

Metrics: source/index watermark, per-tenant lag/backlog, embedding count and
latency, cache/generation loads, eligible/candidate/rejected counts (privileged
telemetry only), lock wait/hold time, index size, replay failures and query phase
histograms. Avoid unbounded principal/scope labels and text/query logging.

## Rollout scope

Start with the standalone AIMEM service and its explicitly configured KEYSTONE
addon. Do not redirect to the production cluster or roll this into all cluster
nodes merely because they run QIHSE. Preserve dedicated QKP pins, existing
principal restrictions, original memory store and versioned binary rollback.
