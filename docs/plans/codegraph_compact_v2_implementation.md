# CodeGraph compact v2 implementation plan

> **Roadmap authority:** [ROADMAP.md](../../ROADMAP.md) is the sole authority for delivery status, remaining work, sequencing and acceptance. This file retains supporting design, acceptance criteria and dated evidence; historical status labels below are not an independent current checklist. Consolidated 2026-11-07.

Date: 2026-11-06  
Status: supporting phased design. Delivery status is maintained only in [ROADMAP.md](../../ROADMAP.md#codegraph).
Scope: QIHSE CodeGraph storage, indexing, querying, migration and progress reporting.

## Objective

Reduce persistent graph size, temporary disk writes and query memory while preserving
exact definitions, callers, relationships, source evidence and authorization.
Support incremental workspace indexing and conversion of existing graphs. Deliver
measured improvements over the current compressed implementation, rather than
comparing a new encoding only against uncompressed JSON.

Keep this work inside CodeGraph. Do not replace QIHSE with SQLite, modify unrelated
QIHSE engines, introduce a general graph query language, or expand into HAX/KEYSTONE
product work. Define the necessary source-provider interface here; implementation
inside an editor or another product is a separate task.

## Evidence and interpretation

The supplied research summary is design input, not a verified benchmark report.
Its proposed techniques are useful, but its numerical claims must not become
acceptance criteria without a reproducible corpus and methodology.

- [GraphCodeBERT](https://arxiv.org/abs/2009.08366), first posted in 2020 and
  published at ICLR 2021, uses data-flow structure for learned code representations.
  It supports investigating useful structural relations; it does not establish a
  storage ratio or lossless pruning policy for this repository.
- [The DGMS authors' implementation](https://github.com/ryderling/DGMS) concerns
  semantic retrieval with graph matching. The summary's 300-node truncation claim
  must be checked in its experiment context. It is not evidence that a repository
  index can be capped at 300 nodes while preserving callers and definitions.
- The supplied 10–100× savings, 76% fewer reads, 10× recall and tool footprint
  estimates are unverified here. Its example size table actually makes the index
  larger than raw source, unlike its opening size claim. Do not reuse those figures
  as measured results or promises.
- Spectral sparsification, low edge frequency and PageRank do not establish that
  a call/reference edge is dispensable. A rare edge may be the relevant evidence.
- Filesystem watching sees saved files. Unsaved editor buffers require an explicit
  overlay provider; a watcher alone cannot provide them.

The resulting design decision is to retain a complete authoritative graph and
compress its representation first. Optional condensed views may improve retrieval
budgets, but must remain distinguishable from complete graph answers.

## Current baseline to retain

Existing implementation and evidence are documented in
[the native CodeGraph architecture](../architecture/codegraph_native.md) and
[the benchmark receipt](../../benchmarks/codegraph_storage_optimization.json).

| Area | Current behavior | Remaining opportunity |
|---|---|---|
| Persistent snapshots | Versioned Zstandard level-9 container over authorized KV serialization | Repeated textual IDs, keys, paths and record fields still exist before compression |
| Loading | Authenticated immutable memory load up to 64 MiB decoded / 150,000 records; larger graphs use a disk fallback | Avoid restoring still larger read-only graphs through mutable KV/SST state |
| Publication | Validated atomic manifest; identical valid imports reuse the current snapshot | Make per-file reuse possible without rewriting the full graph |
| Migration | Authenticated conversion, logical-record verification and rollback generation | Add a packed format and independently readable blocks |
| Retention | Successful import/migrate and explicit GC retain current/previous generations and clean abandoned leased runtimes | Account for shared blocks if a future format shares data between generations |
| Queries | Indexed properties, bounded traversal and bounded review output | Store compact adjacency and decode only required evidence |
| Reindex workflow | Rebuild → export → compact import; stage bar and terminal elapsed indicator | Incremental updates and measurable within-stage progress |
| Source freshness | Git-backed identity including staged state and untracked contents; safe compatibility bridge for old exporters | Explicit non-Git and editor-overlay identity modes |

The Angryier smoke run successfully migrated its old PID-named generation, then
rebuilt and published a fresh graph containing 8,853 nodes and 114,689 edges.
That establishes workflow compatibility, not a measured packed-v2 size reduction.
The previously reported 79,662,422 → 19,056,786-byte result belongs to a synthetic
level-9 compression experiment; do not extrapolate it to all live graphs.

P0's authenticated `qihse-codegraph stats` command now measures the current
generation. On the selected fresh Angryier generation it reported 7,534,503
encoded bytes, 7,545,856 allocated bytes and 54,478,835 decoded bytes. These
figures exclude rollback, historical and scratch storage. Wider folder totals
remain gated on a deliberate authorization policy for older generations.

The [synthetic P0 method](../../benchmarks/codegraph_p0_method.md) and
[machine-readable receipt](../../benchmarks/codegraph_p0_reference.json) cover
800 nodes and 2,400 edges in three alternating pairs. Authenticated legacy KV
used 1,825,299 apparent bytes; current Zstandard level 9 used 187,976 bytes
(89.7% less on this fixture). Four query shapes matched exactly, including a
truncated high-degree context and a separate untruncated caller/target/test
check. This establishes a reproducible current-format baseline, not a packed-v2
improvement or a prediction for other graphs. The
[memory-cap method and receipt](../../benchmarks/codegraph_memory_cap_compare.py)
record a separate one-graph, three-pair comparison: increasing the bounded
reader from 100,000 to 150,000 records reduced median status/query time while
raising peak RSS. Its [results](../../benchmarks/codegraph_memory_cap_angryier_20261106.json)
are specific to the selected graph and shared host.

An opt-in packed-v2 pilot now transforms the authenticated live KV export,
preserves its complete record metadata, and binds Guest reads to the current
manifest digest before decoding. The [packed comparison](../../benchmarks/codegraph_packed_method.md)
measured 182,355 bytes against current Zstandard's 187,857 bytes on the
800-node/2,400-edge fixture (2.93% less); the tiny fixture was 33 bytes larger.
Direct import and conversion returned exact native query results. The pilot
has a 64 MiB decoded limit. The original pilot retained Zstandard as default;
automatic selection now chooses the smaller candidate and uses Zstandard above
the packed limit. On the selected
fresh Angryier graph (8,853 nodes, 114,689 edges), packed-v2 used 7,798,284
bytes versus the existing 7,534,503-byte Zstandard snapshot (3.50% larger).
Four authenticated queries had identical results except for generation IDs.
The graph was migrated back to Zstandard; that new snapshot was 8,043,696
bytes because reserialization changed record order. The previous generations
were retained. This live result rules out enabling packed-v2 by default.
Separate
[Zstandard parameter measurements](../../benchmarks/codegraph_zstd_tuning_medium_20261106.json)
showed a larger size cut only with much greater encode CPU.

## Invariants

1. Every graph read, enumeration, migration, export, mapped-block access and query
   accepts or inherits an explicit authenticated principal. NULL is not a bypass.
2. Preserve classification, SCI labels, expiry and any other security-relevant
   metadata. Authorize before exposing dictionary entries, IDs, counts or payloads.
   Shared dictionaries and caches must not create cross-principal disclosure.
3. Keep symbol identity separate from display name. Equal names in different
   files, scopes or overloads do not identify the same symbol.
4. Preserve edge identity, multiplicity, direction, provenance, confidence and
   resolution. Inferred or unresolved evidence never becomes an authoritative edge.
5. Lossless migration preserves all supported values and unknown extension fields.
   It does not update the source revision or turn stale evidence into fresh evidence.
6. Readers see a complete old or new generation. Failed writes leave a usable
   generation; uncertain publication durability is reported explicitly.
7. Resource limits, checksums and bounds checks apply before allocation or mapping.
   Unsupported versions fail clearly, without attempting an unsafe fallback.

## Phase 0 — Establish a storage and retrieval baseline

Add an authenticated CodeGraph statistics operation before choosing a new layout.
Report current, rollback, historical and scratch storage separately. Include format
version, node/edge counts, encoded bytes, decoded bytes, allocated bytes and peak
temporary-space requirements. Never call apparent file size "disk space reclaimed".
Filesystem snapshots may retain blocks after deletion.

Measure section contributions: IDs, paths, names, record keys, provenance, unknown
fields, adjacency, search indexes and container overhead. Obtain classified-capable
records through the authenticated API/SDK, never by directly parsing live storage.

Use synthetic fixtures plus an explicitly selected small, medium and large graph.
Include shared names, long paths, high-degree nodes, unresolved relationships and
mixed security labels. Record the binary revision, schema, compression settings,
hardware, cache state and concurrent workload. Run repeated measurements in
alternating baseline/candidate order.

Deliverables: machine-readable receipts and a query corpus with exact expected
definitions, callers, evidence and authorization outcomes. Establish baseline
median/p95 latency, peak RSS, logical writes and temporary disk usage.

## Phase 1 — Lossless packed records

Prototype a CodeGraph-specific codec behind the existing authenticated storage
boundary. Retain the public logical graph schema and existing read format.

| Component | Proposed representation | Preservation rule |
|---|---|---|
| Stable identities | Original digest as 32 bytes rather than 64 hexadecimal characters | Reconstruct exactly at the public boundary; retain full collision-resistant identity |
| Local references | Dense generation-local integer IDs, encoded as bounded varints | Map back to stable identities; never expose local IDs as durable handles |
| Strings | Length-delimited UTF-8 dictionaries for paths, names, kinds and relations | Exact bytes; partition by authorization requirements; preserve unknown values |
| Nodes | Typed columns for ID, file, name, kind, spans and flags | Do not merge nodes by name or discard locations |
| Edges | Source/destination references, relation tags, evidence references and flags | Retain separate edge/evidence identities and unresolved endpoints |
| Numeric metadata | Exact integer encoding and sufficient floating-point precision | No lossy confidence quantization in the default codec |
| Extensions | Length-delimited opaque extension records with explicit encoding/version | Unknown fields round-trip instead of silently disappearing |
| Security metadata | Explicit labels bound to records or protected blocks | Same authorization result as the old representation |

Specify a versioned header and section directory with counts, offsets, encoded and
decoded lengths, codec identifiers and checksums. Check integer overflow, overlapping
sections, invalid references, duplicate dictionary entries where prohibited,
truncation and oversized windows. Use explicit byte order; do not serialize C structs.

Compress sections or bounded blocks independently with Zstandard. Benchmark block
sizes and compression levels against the existing level-9 container. Do not claim
that dictionaries will produce an additional fixed ratio: Zstandard already removes
much repeated text.

Do not add a second mandatory public storage engine. Prototype within
`tools/qihse_codegraph_storage.c/.h`, or split a new CodeGraph-only codec module once
its interface is concrete. Any shared KV change needs separate evidence of necessity.

## Phase 2 — Compact adjacency and selective reads

Store outgoing and incoming adjacency using compressed sparse row indexes:

```text
node offsets: N + 1 offsets
outgoing:     edge references grouped by source
incoming:     edge references grouped by destination
edge table:   endpoints, relation, provenance reference, confidence, flags
```

Sort local references to evaluate delta encoding. Measure the cost of storing both
directions against caller/callee latency; do not assume the extra index is free.
Preserve multi-edges with distinct evidence. Existing public query semantics remain
the compatibility contract.

Keep definitions, symbol lookup and bounded caller/callee traversal on small indexes.
Load evidence and extension blocks only when a result needs them. Use a bounded
cache keyed by generation and authorization context, with revocation handling.
Avoid restoring read-only packed graphs into mutable SST/WAL state.

Evaluate memory mapping only for validated immutable layouts. Mapping a compressed
file does not remove decompression. Mapped metadata and dictionaries still require
authorization, checked offsets and generation lifetime protection. Do not create a
context-free raw mapping API.

## Phase 3 — Incremental per-file generations

Introduce a file manifest containing normalized repository-relative path, content
digest, parser version, extraction options and references to immutable node/edge
chunks. Reuse chunks only when all relevant identities match.

Update algorithm:

1. Capture the input source identity and determine added, changed, renamed and
   deleted files. Include parser/configuration changes in invalidation.
2. Reparse changed files into new chunks; remove superseded file-owned records.
3. Re-resolve affected imports, definitions and references. A changed definition
   can invalidate edges owned by unchanged callers: maintain reverse dependencies
   and fall back to a broader rebuild when the affected set cannot be bounded safely.
4. Rebuild affected lookup/adjacency blocks, verify counts and structural integrity,
   and recheck source identity before atomically publishing the manifest.
5. Retain the previous generation and keep active readers pinned to their generation.

Use bounded immutable chunks rather than one tiny file per symbol or an unbounded
chain of deltas. Measure packing thresholds and compaction triggers. GC must mark
blocks reachable from every retained manifest and active reader before sweeping;
deleting an old generation must not delete blocks shared with the current graph.

Incremental correctness is the gate: an incremental result must match a clean full
rebuild for the same source snapshot, including renames, deletes and changed imports.

## Phase 4 — Explicit workspace and overlay source identity

Define a CodeGraph source-provider contract that can enumerate source paths, read
exact bytes, provide a snapshot revision and detect changes during extraction.
Providers are typed and versioned:

- Existing Git-backed provider: retain current staged/untracked checks.
- Filesystem provider: canonical file-set/content identity for non-Git workspaces,
  plus parser/configuration identity and atomic snapshot validation.
- Overlay provider: workspace/session identity, monotonically versioned buffer
  revisions and content digests layered over a validated base snapshot. Support
  unsaved additions and deletions, not just replacement bytes.

An overlay query must identify the workspace revision it represents. Keep overlays
isolated per authenticated workspace/session, with bounded lifetime and explicit
discard/save behavior. Never mark an old on-disk graph fresh merely because Git is
unavailable or a buffer has a newer revision number.

Implementation of editor hooks or HAX/KEYSTONE transport is deferred outside this
CodeGraph-only plan. A new externally reachable adapter must carry the authenticated
principal to retrieval and have low-clearance/high-data denial tests in CI.

## Phase 5 — Optional compact retrieval views

Keep the authoritative graph complete. Add optional bounded views containing file,
function/class/constant definitions and selected calls/imports/inheritance relations.
Variables, data flow, comments and documentation are optional extraction profiles,
not fields to silently delete from an existing graph during migration.

Return generation, view/profile, source identity, omitted relation types and a
truncation/completeness indicator with every limited result. Budget a response or a
local function subgraph; do not cap the repository index at 300 nodes.

Do not collapse a call chain into a direct call or merge same-named symbols. If a
summary contains a reachability relation, label it as derived and retain a route to
the original path/evidence. A missing result from a partial view is not proof that
no caller exists. Any text-search fallback remains bounded and explicitly identified.

Evaluate pruning only against a held-out query corpus and ground truth. Report
missing direct callers and definitions separately from ranking metrics. Keep lossy
views opt-in until their measured omissions are acceptable for their intended use.

## Migration and progress reporting

Extend the existing commands rather than creating an unrelated maintenance tool.
The current `tools/qihse-codegraph-reindex` wrapper already supports rebuild/import
and `--migrate-only` with completed-stage bars and elapsed terminal activity.

Proposed packed-v2 migration sequence:

1. Authenticate and lock the selected graph; validate its current manifest/version.
2. Preflight available temporary space and estimate old + new + rollback peak usage.
3. Stream authorized records into the packed writer with bounded memory.
4. Reopen through the authenticated reader; compare canonical records, all metadata,
   counts and logical digests. Exercise representative exact queries.
5. Atomically publish a versioned manifest and retain the previous generation.
6. Report encoded and allocated before/after bytes separately. Pruning history is
   a distinct retention action, not an implied part of conversion.

Support both old PID filenames and modern random suffixes. Repeated conversion is
idempotent. Cancel before publication removes owned staging files; cancel after
publication reports that the new generation committed. Never delete a potentially
published file after an uncertain directory fsync result.

Add structured progress events emitted on stderr or a dedicated event channel:

```json
{"phase":"encode","completed":42000,"total":120000,"unit":"records","elapsed_ms":1800,"state":"running"}
```

Phases include scan, parse, resolve, encode, verify, publish and optional GC. Use real
file/record/byte totals where available; otherwise display indeterminate activity.
Do not invent an overall percentage from incomparable phases. Throttle event output,
keep result JSON separate, propagate cancellation, and display completion only after
successful publication. Distinguish "converted, still stale" from "rebuilt and fresh".

## Implementation ownership and order

| Work package | Likely files | Dependency / completion gate |
|---|---|---|
| P0 measurements | `tools/qihse_codegraph.c`, `benchmarks/`, focused benchmark scripts | Authenticated statistics and reproducible baseline |
| P1 codec | `tools/qihse_codegraph_storage.c/.h`, codec tests | Exact round-trip and authorization parity; smaller measured corpus bytes |
| P2 reader/index | CodeGraph-specific storage/query modules | Exact results, bounded RSS, reduced disk writes and measured query latency |
| P3 incrementality | New CodeGraph file-manifest/chunk module; reindex helper | Incremental/full equality and crash-safe publication/GC |
| P4 source providers | `tools/qihse_codegraph_reindex_source.py`, CodeGraph source interface | Non-Git and overlay revision tests; no weakened Git path |
| P5 retrieval views | Existing CodeGraph query/result boundary | Explicit incompleteness and measured recall/precision |
| Migration/events | `tools/qihse_codegraph.c`, `tools/qihse-codegraph-reindex` | Old/new compatibility, rollback, cancellation and accurate progress |

Start with P0, then P1. P2 follows the chosen layout. Prototype P3 after the packed
format and reader are stable. P4 and P5 remain separately gated capabilities.
Use isolated worktrees for independent implementations with explicit file ownership;
keep format decisions, shared-file edits and integration sequential.

## Validation and release gates

- Compare packed v2 with both legacy KV and current Zstandard storage on identical
  logical records. Report bytes/node, bytes/edge, total bytes and metadata/index cost
  separately; a single ratio can hide large strings or evidence overhead.
- Preserve exact query results and all supported/unknown record metadata for the
  lossless phases. Test ambiguous names, overloads, unresolved edges and multi-edges.
- Exercise NULL, revoked, low-clearance and wrong-compartment principals against
  load, query, iteration, export and migration; deny without protected payloads or
  dictionary/count disclosure. Run new adapter denial tests in CI.
- Fault-inject short writes, ENOSPC, allocation failure, corruption, process death,
  interruption and fsync failures. Test concurrent readers, import, migration and GC.
- Fuzz packed decoders; run ASan/UBSan and appropriate concurrency checks. Bound
  decompression, stack frames, varints, section counts and allocation arithmetic.
- Compare cold/warm median and p95 query times, full/incremental build times, peak
  RSS, logical writes and peak temporary bytes. Include graphs above current memory
  limits. Report methodology and outliers; do not claim speedups from one run.
- Adopt a candidate only with exactness/security parity, demonstrated size or write
  savings, and explicit review of any latency/memory regression. Set numeric release
  budgets after P0 measurements instead of borrowing unrelated research percentages.
- Run focused tests, then the required complete suite: `make test TEST_JOBS=32`.
  A partial run or a passing focused subset is not a complete-suite pass.

Roll out through one disposable synthetic graph, one selected smaller existing
graph, then a larger selected graph. Retain rollback, report actual size accounting
and inspect equivalent queries before expanding migration coverage.

## Deferred ideas

Embeddings, node2vec, learned indexes, Bloom filters, spectral sparsification,
cross-repository linking and general graph query languages are not initial work.
They add storage or complexity and need evidence of a specific retrieval bottleneck.
Silently dropping authoritative edges remains unacceptable. The later approved 128-bit public-ID format uses full-preimage collision handling and is documented in [the XXH3 identity report](codegraph_xxh3_tuned.md); it supersedes the original blanket fingerprint-width restriction.

## Implementation tracking

Current completed increments CG.1–CG.9 and remaining optimization work CG.10–CG.17 are maintained only in [the authoritative roadmap](../../ROADMAP.md#codegraph). The phased specification above is a design record, not a claim that entire P0–P5 gates are complete. In-memory CSR is shipped; persisted/selective CSR, chunking and incrementality remain separate work.

The original live-graph conversion sequence is inapplicable because those graphs no longer exist. The newer focused validation and user-stopped full-suite boundary are recorded in the master roadmap; no complete-suite pass is implied.
