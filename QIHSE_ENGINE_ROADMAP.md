# QIHSE engine roadmap: prerequisites for advanced agent memory

> **Status:** QH-00 initial implementation slice (durable RESP commands + serialized idempotency) in progress; full QH-00 crash atomicity, receipt/LSN contract and QH-01–QH-10 remain planned. Integrated into the master roadmap as W10.  
> **Date:** 2026-10-20  
> **Master sequencing:** [ROADMAP.md — W10](ROADMAP.md#w10--qihse-aimem-durable-scoped-versioned-agent-memory-planned-2026-10-20) (see W10 workstream; this document is the detailed scope and acceptance criteria).  
> **Repository:** `SWORDIntel/QIHSE` (implement in separately validated stages).  
> **Source:** [akitaonrails/ai-memory](https://github.com/akitaonrails/ai-memory), `main` at `11ab1003d9ef3788f5fc40b87fff54abf7f17dc0`.  
> **Consumer:** [QIHSE-backed Supermemory](https://github.com/SWORDIntel/supermemory/tree/qihse-backend/qihse-backend). Its companion feature roadmap uses SM-XX items; this document uses QH-XX item numbers.  
> **QIHSE implementation reviewed:** [AIMEM RESP protocol](https://github.com/SWORDIntel/QIHSE/blob/main/docs/architecture/aimem_resp_protocol.md), [AIMEM C interface](https://github.com/SWORDIntel/QIHSE/blob/main/include/qihse_ai_memory.h), [AI fabric architecture](https://github.com/SWORDIntel/QIHSE/blob/main/docs/architecture/ai_fabric.md).

## Intent

Extend QIHSE AIMEM with the **minimum additional authenticated storage, indexing and atomic state operations** required to support cross-agent lifecycle capture, workstream continuity, scoped memory, temporal/versioned facts, and safe consolidation. QIHSE remains the only authoritative memory database; Supermemory is a client-facing MCP/adapter layer. The features below are proposals and are **not** assertions that the corresponding commands already exist.

The current documented AIMEM RESP commands are:

```text
AIMEM STORE <kind> <text> [idempotency-key]
AIMEM RECALL <query> <limit> [bm25|semantic|hybrid] [kind]
AIMEM GET <uuid>
AIMEM FORGET <uuid>
AIMEM COUNT [kind]
```

They already provide authenticated local storage, lexical/semantic/hybrid recall, principal-scoped idempotency and classification/SCI-filtered reads. **Do not reimplement any of those capabilities.** The missing substrate is structured scope, durable event admission, atomic coordination, version and change management, and authorized export.

## Cross-cutting invariants — non-negotiable

1. **Principal first.** Every command resolves a live authenticated `qihse_user_t` or equivalent server-owned actor context. The client must never be able to set or increase its effective tenant, clearance, classification or SCI.
2. **Conjunctive authorization.** Scope filtering (project, worktree, session, owner) must only narrow the QIHSE-authorized result set. Apply it **before top-K selection and all ranking, dedup, counts and explain traces**. Filtering a global top-K in Python is not equivalent.
3. **No covert change to result shape.** A hidden high-label memory may not affect low-label count, candidate ordering, score, pagination, related-link traversal, duplicate suppression or error shape.
4. **Stable source IDs.** External source event identity is distinct from server-generated memory UUID. Retry/replay must never change event meaning or create duplicate accepted content.
5. **Explicit durability tiers.** `accepted`, `fsync-durable` and `replicated/quorum-durable` (if available) have different meanings. Do not claim the latter two from an ordinary AIMEM ACK.
6. **Memory is data, never authority.** User, assistant, tool and document observations carry different provenance. A memory record or synthesized page cannot authorize a command, capability grant or change in classification.
7. **Reversibility before autonomous mutation.** Supersession, compaction and dedup preserve evidence and prior versions until authorized retention policy explicitly permits irreversible removal.
8. **Fail closed across identifiers.** Explicit unknown project, workstream, session, tenant or principal must not fall back to a default global scope or silently create a different scope.
9. **No second canonical store.** QIHSE WAL, KV, indexed state and existing audit mechanisms should be reused wherever appropriate; markdown/git files are derived export artifacts.
10. **Versioned protocol and additive migration.** Preserve the current five AIMEM commands and their response shape; new parameters must be explicit and backward compatible.

## Dependency and priority matrix

| ID | Priority | Engine addition | Unblocks Supermemory | Core correctness test |
| --- | --- | --- | --- | --- |
| **QH-00** | **P0** | Crash-durable admission / acknowledgement fence | SM-03, later SM-22/24 | `SIGKILL` immediately after durable ACK; data survives |
| **QH-01** | **P0** | Native project/worktree/session scope and authorization | SM-12/14/15/20/25 | Same principal, two projects: no cross-scope leakage |
| **QH-02** | **P1** | Typed, idempotent, bounded event ingestion | SM-01/11/12 | Parallel replays resolve to one stored event |
| **QH-03** | **P1** | Atomic offer/accept/cancel/expire handoffs | SM-14/25 | Two claimers, exactly one accepted |
| **QH-04** | **P1** | Immutable evidence/version lineage and typed relations | SM-20/21/22 | Replaced fact remains queryable historically |
| **QH-05** | **P1** | Scoped querying, stable paging/listing, as-of and diagnostics | SM-13/15/20/21/24 | No hidden-record contamination of any query leg |
| **QH-06** | **P2** | Conservative versioned maintenance primitives | SM-22/23 | Dedup/compaction reversible and label-safe |
| **QH-07** | **P2** | Authorized snapshot/export/import boundary | SM-24, session-history fallback | Authorized round-trip preserves hash, ACL and lineage |
| **QH-08** | **P2** | Audit, durability telemetry and index repair | All operational phases | No payload/secret leakage, recoverable failed index |
| **QH-09** | **P3** | Scoped profile/curation approval records | SM-15/23 | No agent guess promoted to approved preference |
| **QH-10** | **P3 / conditional** | Project-targeted mailbox and leases | SM-25 | Atomic inbox pop with explicit sender/recipient grants |

**Minimum useful first batch:** QH-00, QH-01 and QH-02. Versioned curated memory, cross-project inboxes and LLM dreaming are not reasons to delay the simpler lifecycle improvements in the Supermemory roadmap.

## QH-00 — Durable acknowledgement and idempotent recovery

**Implementation slice:** `AIMEM STORE-DURABLE` and `FORGET-DURABLE` are wired to `qihse_kv_sync_store()` under the RESP KV lock. Existing commands retain their old response shape and eventual durability. Idempotency key reuse with changed kind/content is refused; the key check and insertion are serialized, and a SIGKILL-after-ACK regression is included. This is **partial**: record + mapping remain two KV mutations, and crash before the mapping can create an orphan. Receipt/LSN tracking, exhaustive crash fault injection and measured overhead are still required. See [RESP protocol](docs/architecture/aimem_resp_protocol.md).

**Existing constraint:** QIHSE [explicitly documents eventual durability](https://github.com/SWORDIntel/QIHSE/blob/main/docs/architecture/aimem_resp_protocol.md): recent `STORE` or `FORGET` mutations can disappear or revert after an immediate restart, despite a successful RESP acknowledgement.

**Proposed design:** Introduce an additive durability contract. The engine should identify a committed mutation using a monotonically ordered log position/commit identifier and provide a safe method to wait until that mutation has reached the configured durability threshold. Possible APIs include an explicit `AIMEM DURABLE-WRITE` mode or `AIMEM WAIT-DURABLE <receipt>`; these are candidate shapes, **not current commands**. The implementation must reuse the real QIHSE KV/WAL/fsync mechanism, not simulate durability with an arbitrary sleep.

For both stores and deletes, the durable unit must include the memory record/tombstone, its idempotency identity and relevant index recovery state, or guarantee deterministic replay on restart. A crash must not resurrect a deletion already reported as **durable**. If an index write is asynchronous, the engine must recover/search only authoritative visible records while rebuilding the index.

Separate local fsync durability from any federation/replication claim. If no immediate durable write is affordable, expose an honest accepted/queued receipt and leave the caller's protected outbox unacknowledged until a real fence is crossed.

**Acceptance:** Kill/restart at every write and sync boundary; replay identical key/content and different content with the same key; confirm single logical memory and no resurrected durable tombstones. Run with the actual persistence directory and configured auth. Record P50/P95 sync overhead and throughput impact.

## QH-01 — Native multi-dimensional scope with QIHSE enforcement

**Problem:** Existing `AIMEM RECALL` takes query, limit, mode and kind, but no authenticated repo/project/worktree/session filter. A bridge that searches the entire principal-visible corpus then drops foreign-project hits may miss in-scope matches (top-K starvation). Classification/SCI filtering alone does not express project separation.

**Proposed minimal identity model:** `tenant_id`, `actor_id`/principal, `project_id`, `worktree_id` (or checkout fingerprint), `workstream_id`, `native_session_id`, `event_id` and `source_id`. Use immutable internal numeric or opaque IDs for indexes and allow display names to change. Maintain actor-to-project grants in QIHSE. Worktree/repo fingerprints are routing evidence, not user clearance claims.

Use server-generated/validated scopes for writes. On reads: require explicit scoped coordinates unless a trusted session identity makes them unambiguous. Reject incomplete/unknown scope; no "current global project" last-writer-wins fallback, especially under parallel HAX agents. Keep a documented deliberately scoped "operator-wide" query for users authorized to search multiple projects.

**Index plan:** Include scope dimensions on candidates; filter before BM25, semantic ANN selection, RRF and dedup; any graph links into another scope are authorization rechecked at each hop. For each query, compute result count after both scope and security filtering; never count hidden candidates.

**Compatibility:** Existing legacy text records need an explicit `legacy/unassigned` scope visible only according to operator migration policy. Do not guess project from text or search keywords. Add a permission-reviewed migration path that stamps historical records with confidence/known provenance or leaves them unassigned.

**Acceptance:** Concurrent 10-agent test with same authenticated principal and multiple repos; each scoped query returns only its own authorized hits. Repeat with another principal and disjoint SCI compartments; no cross-scope/label influence on rank, count, zero-result response or pagination. Deliberately typo the project and assert rejection, not fallback.

## QH-02 — Authenticated lifecycle event journal

Store lifecycle observations as typed events in QIHSE, rather than indistinguishable free-text `AIMEM STORE` entries. Candidate commands: `AIMEM EVENT APPEND` and `AIMEM EVENT READ` (names TBD after inspecting existing QIHSE journal APIs). The engine should bind event actor, scope and label itself and validate a versioned envelope against bounded schemas.

**Required fields:** `schema_version`, `producer_namespace`, `event_id`, `event_kind`, `session_id`, `workstream_id`, source time and server receive time, content digest, sanitized summary, optional source-evidence handle, `status`, and an authenticated idempotency composite. Event kinds are from a registered vocabulary; extensions are versioned and may be stored without activating any privileged handler.

**Data path:** Admit payload → authorize scope/labels → reject/flag maliciously long, invalid or duplicate events → persist event and stable idempotency mapping together → append to the appropriate index → emit durable receipt according to QH-00. Implement a bounded write queue and backpressure instead of accepting unbounded hook-driven data.

Retention may differ for raw observation vs curated knowledge, but a session summary must not create provenance edges to event IDs that a scheduled cleanup has already destroyed without recording that event's disposal.

**Acceptance:** 10,000 concurrent replayed events with deterministic cardinality; same event key with conflicting data fails rather than silently changing original evidence; foreign principal cannot attach its event to another actor's existing session; invalid payload cannot force memory allocation outside configured caps.

## QH-03 — Atomic typed handoff state machine

Borrow ai-memory's [claim-once handoff](https://github.com/akitaonrails/ai-memory/blob/main/docs/design-handoff-offer-not-claim.md) with its later **offer, don't automatically claim** choice.

**Handoff record:** ID, from principal/project/session, allowed recipient policy, optional named workstream/agent, created/expiry timestamps, typed task summary, evidence pointers, durable `revision`, and state:

```text
OPEN  --accept(CAS)-->  ACCEPTED
  |                       |
  |--cancel(CAS)--> CANCELLED
  |
  |--expiry-----> EXPIRED
```

An accept operation is a single server transaction/CAS requiring `state=OPEN`, current revision, unexpired offer, matching recipient, matching project grant and required SCI access. Return the accepted ID and source state; concurrent accept is deterministic. Prefer offering handoffs at session start without mutating their state. Explicit acceptance makes them claim-once. Keep an audit of acceptance without automatically importing previous agent's credentials, tools or executable instructions.

Decide a **recovery policy** for an interrupted consumer: either the accepted handoff remains accepted and is queryable by the same recipient/session, or a bounded lease permits authenticated re-offer. Never allow automatic double execution simply because an ACK was lost.

**Acceptance:** Race 100 concurrent claimers across multiple processes and two principals. Exactly one authorized acceptance; wrong-project and lower-clearance actors receive no baton or diagnostic revealing restricted content. Forced crash between state transition and reply returns the same accepted result to the same idempotent retry.

## QH-04 — Versioned curated knowledge and temporal provenance

ai-memory keeps [page/version history](https://github.com/akitaonrails/ai-memory/blob/main/docs/temporal.md) and [typed relation edges](https://github.com/akitaonrails/ai-memory/blob/main/docs/typed-edges.md). Translate that into **QIHSE-native versions**, not a Git-backed canonical wiki.

**Minimal schema:** `knowledge_id`, immutable `version_id`, scope/security label, type (decision/gotcha/procedure/architecture/rule/session capsule), content hash, content, `supersedes_version`, `source_event_ids`, `created_by`, `generated_by`, `reviewed_by`, `confidence`, `created_at`, `valid_from_ingest`, `valid_to_ingest` and status (proposed/approved/superseded/retracted). Optional external-world validity timestamps must be stored separately from ingestion timestamps. Do not infer real-world truth dates from ingestion time.

**Relations:** Start with `fixes`, `causes`, `contradicts` and `supersedes` with strict target resolution. Relations can resolve across scope boundaries **only on an explicitly authorized query**; each target retrieval rechecks its own label. An LLM must not mint an approved rule or higher-trust evidence field.

**Version update:** CAS on existing version; append successor and close predecessor validity within one atomic transaction; keep prior version recoverable under a version-aware authorized read. An authorized forget/privacy purge needs a separate explicit semantics definition; a superseded version is not "deleted".

**Acceptance:** Two writers updating the same version → one accepted, one conflict. `as_known_at` yields a reproducible previous state; latest state excludes superseded instruction from default retrieval; audit names actor and cited evidence without exposing restricted content.

## QH-05 — Rich scoped queries, listing and time travel

Add typed scoped search parameters **without breaking** existing `AIMEM RECALL` positional commands. Prefer separate versioned verbs or structured bounded parameters to an ambiguous optional-argument string. Useful operations:

- `RECALL scoped`: project/worktree/workstream filters; kind/type; status/current-only; time window; stable sort and bounded limit.
- `GET exact`: existing UUID lookup retained; version-aware read for curated knowledge, always authorization checked.
- `LIST changed-since`: keyset-paginated authorized observations/versions for incremental client sync and exact history recovery; no unbounded scan.
- `AS-OF`: ingestion-time view of versions and relations, with explicit cutoff; avoid incorrectly describing this as world-time truth.
- `EXPLAIN`: authorized retrieval diagnostic identifying ranking legs and source evidence; no non-visible candidates or forbidden counts in explain output.
- `HEALTH`: embedder name, index generation, replay/dirty status, durability mode, counters stripped of sensitive content.

Query pagination must be stable across concurrent writes using a snapshot/index generation or explicit continuation cursor. Apply label checks both to the cursor's scope and every returned record.

**Acceptance:** Pagination has no gaps/duplicates under a fixed generation; expired/superseded default filters obey declared semantics; replaying one page under a lower-clearance principal fails safely; BM25/ANN/RRF share identical authorization criteria.

## QH-06 — Conservative maintenance primitives

Only after QH-04's reversible versions exist, enable memory decay/dedup/compaction building blocks.

- Retention tiers distinguish working, episodic, semantic, procedural and pinned data.
- Access reinforcement may affect retrieval/retention scores but must be partitioned by actor/scope where required.
- Extractive cold-data compaction preserves literal file paths, hashes, error messages and source IDs.
- Near-duplicate merging is optional; contradictory records must be flagged, not merged as equivalents.
- Any synthesized replacement carries all source lineage; QIHSE enforces a security label at least as restrictive as every component and appropriate SCI compartments. When safe combination cannot be represented, **reject the merge**.
- Record a reversible source-version chain and explicit review status. Maintenance is opt-in, dry-run-first, evaluated against fixed recall and contradiction fixtures.

**Acceptance:** No cross-tenant/scope/SCI compaction; deterministic rollback reconstructs original records; abort mid-sweep leaves index and KV consistent; default settings reproduce pre-maintenance retrieval behavior.

## QH-07 — Authorized snapshot/export/import projection

Provide an authenticated scoped export that allows Supermemory to produce Markdown/OKF pages, immutable event capsules and a signed/hashed manifest. Export is **not** a raw KV filesystem dump and does not bypass the QIHSE principal or SCI policy.

Possible interface: bounded `AIMEM EXPORT START/NEXT` with an authorized snapshot/cursor, or reuse an existing authenticated QIHSE export protocol if it meets the same scope and integrity requirements. Include source/version IDs, labels allowed by the exporter, provenance hashes, index generation, schema version and semantic flags (tombstone/superseded/current). Decide explicitly whether high-label exports are even permitted for the requesting role.

Import through authenticated, idempotent QIHSE APIs; never let a supplied file self-assign higher authority or an arbitrary SCI label. Support dry run, per-scope collision policy, source hash verification and round-trip restore validation. Keep model-derived pages distinguishable from operator-approved pages.

**Acceptance:** Export with low-clearance principal contains no higher-label files, filenames, link targets, totals or metadata. Round-trip to disposable store reproduces authorized current contents, version lineage and source IDs; a malformed or tampered manifest is rejected.

## QH-08 — Audit, metrics, index repair, operational gates

Add content-free counters and logs for event admission, dedup, durable checkpoint lag, rejected scope attempts, replay, handoff CAS conflict, index generation, re-embedding backlog and maintenance version growth. A dashboard is optional; an authenticated CLI/RESP health route is sufficient initially.

Tests must prove that metrics do not disclose hidden record cardinality to an unauthorized principal. Keep security-sensitive administration counters behind an explicit privileged capability.

Expose a deterministic index-repair/rebuild workflow from authoritative QIHSE records, with generation-aware cutover and zero undocumented semantic fallback. When switching embedding providers, preserve current model-binding guarantees; plan re-embedding rather than comparing unlike vector spaces.

**Acceptance:** Kill backend during rebuild and restart safely; configured semantic model load failures remain fail-closed; fail/retry counters and logs never include bearer secrets or memory plaintext.

## QH-09 / QH-10 — Defer until justified

**Profile and curation records (QH-09):** The engine may eventually maintain typed human-approved preferences, promotions and revocations per principal/project. First prefer QH-04's versioned knowledge types and avoid a special profile engine unless measurable limitations appear. The critical feature is approval/provenance and visibility, not an extra database.

**Cross-project mailbox (QH-10):** An explicit sender/recipient-grant-aware message queue with durable `pending → claimed|cancelled|expired` state and one consumer. Reuse QH-03's atomic transition machinery and QH-01 scope. Default-deny arbitrary cross-project communication; a project name match is not permission to message or read it.

## Proposed interface / schema design rules

The actual public syntax should be finalized against QIHSE command dispatch and storage internals before implementation. Do **not** implement the candidate verb names from this document unreviewed. Use these constraints instead:

- Current `AIMEM STORE/RECALL/GET/FORGET/COUNT` behavior remains stable.
- New capabilities accept explicit versioned request formats and return machine-readable typed errors (`DENIED`, `NOT_FOUND`, `CONFLICT`, `STALE_CURSOR`, `NOT_DURABLE`), but do not reveal hidden existence on normal unprivileged reads.
- No opaque global mutable "active project" pointer; authenticated session resolution or explicit caller scope is mandatory.
- Request IDs, source IDs, authenticated actor, scope and idempotency form a documented uniqueness contract.
- All wire parsing and allocation are bounded; never trust client-supplied event totals, string lengths, timestamps or path metadata.
- Migrations are additive, idempotent, resumable and tested with realistic storage sizes; retain the ability to serve old clients during rolling upgrades.
- QIHSE remains owner of effective labels; clients may request a narrower handling policy but not escalation.

## Suggested implementation order and tests

| Wave | QIHSE work | Dependency release to Supermemory |
| --- | --- | --- |
| **Q0: crash semantics** | QH-00; durability receipts/fence and crash harness | Reliable spool finalization and replay guarantees |
| **Q1: context isolation** | QH-01 and scoped part of QH-05 | Native project/worktree isolation, corrected multi-agent recall |
| **Q2: event journal** | QH-02 plus pagination from QH-05 | Reliable complete session capsules and event backfill |
| **Q3: atomic coordination** | QH-03 | Claim-once typed handoffs; possible inbox reuse |
| **Q4: versioned semantics** | QH-04 and as-of/typed query in QH-05 | Curated pages, contradictions, temporal facts |
| **Q5: maintenance/interop** | QH-06/07/08, conditional QH-09/10 | Reviewable consolidation, OKF export and operational reporting |

### Regression harness requirements

1. **Authorization tests:** low vs high classification, disjoint SCI compartments, same actor different projects, different actor same project, nonexistent scopes, revoked principal; *legitimate control required* in each case.
2. **Crash tests:** `SIGKILL` after append, before/after durable fence, before ACK, after ACK, during tombstone, during index rebuild and concurrent import.
3. **Concurrency tests:** at least 100 simultaneous handoff accept requests, competing version writers, out-of-order event replay, duplicate source IDs and interrupted cursor handover.
4. **Retrieval A/B:** fixed LongMemEval-S-style task fixtures and internal project-specific queries; measure Recall@5/15, MRR, temporal contradiction errors, BM25 vs real ONNX semantic vs hybrid, P95 latency, footprint and index rebuild behavior. Published ai-memory benchmark figures are **not** comparable to unrelated Supermemory metrics without the same task/evaluation pipeline.
5. **Index safety:** changing model name/dimension never compares incompatible vectors; authorization-aware candidate paths remain enforced after migration.
6. **Data handling:** verify no accidental remote egress, plaintext payload logging, exposed full transcript path, unredacted exported secret, or unauthorized metadata disclosure.

## Repository implementation touchpoints (verify before editing)

These are existing QIHSE locations to inspect when implementing the W10 workstream:

- `include/qihse_ai_memory.h` — current C API and record/hit definitions.
- `src/spinnaker/qihse_ai_memory.c` — present core memory storage/retrieval/index integration.
- `tools/qihse_redis_server.c` and the existing RESP dispatch — standalone daemon and wire command entry points.
- `docs/architecture/aimem_resp_protocol.md` — authoritative current wire-contract documentation.
- `tests/test_ai_memory.c`, `tests/test_ai_memory_ext.c`, `tests/test_ai_memory_embed.c`, `tests/test_aimem_resp.c`, `tests/test_aimem_onnx_embedder.c` — existing test foundations.

Before adding a second event or transaction subsystem, inspect existing native QIHSE KV/WAL, audit and transaction/CAS facilities for direct reuse. Review each proposed protocol extension against QIHSE's broader security/federation architecture, including standalone and clustered durability guarantees.

## Non-goals

Not a port of ai-memory's full Rust stack; not a second SQL/graph/vector database; not a blanket exception to SCI isolation; not model-driven reclassification; not forced deployment of an LLM; not cloud-based persistence; not a guarantee of quorum durability without cluster-specific evidence; not automatic merging of contradictory memories; not deletion of superseded evidence under the word "forget".

**Next implementation action for QIHSE:** write QH-00's durability design and crash test first, then QH-01's scoped query semantics and authorization-negative tests. Implement the typed event API (QH-02) on those foundations. Everything else can be sequenced independently.
