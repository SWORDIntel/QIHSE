# QIHSE changes needed for native HAX AIMEM integration

This handoff records the QIHSE contracts needed by HAX's first-party AIMEM integration and the
relevant HAX implementation context. It complements
[NATIVE_HAX_MEMORY_ROADMAP.md](NATIVE_HAX_MEMORY_ROADMAP.md);
[ROADMAP.md](ROADMAP.md) remains the QIHSE delivery-status authority. This document describes
requirements and observed source behavior, not proof that a deployed service supports them.

Reviewed against the current working trees on 2026-11-08. Both trees may be changing concurrently;
recheck the source, deployed binary, capability response, and tests before relying on a status.
The QIHSE source files cited below are relative to this repository. HAX file references are relative
to the separate HAX checkout, referred to as `HAX_ROOT`.

## Required behavior

HAX uses QIHSE AIMEM as its native memory backbone. During and between sessions, capture, retrieval,
retry, contextual use, document preservation, and authorized handoffs must work autonomously.
Routine memory operations must not wait for per-memory operator approval. Proposed knowledge remains
usable as contextual evidence; its status is not a recall gate. Any optional promotion to a
different
knowledge status is a separate existing server capability, not a prerequisite for memory use.

HAX owns session capture, extraction, local retry orchestration, prompt context, citations, and its
user-facing interfaces. QIHSE owns durable memory, authenticated principals and scoped access,
record/event identity, knowledge history, query semantics, and server-side handoff transitions.
HAX must use authenticated APIs or SDK calls with an explicit principal; it must not read QIHSE's
configured storage paths directly.

## Priority 1: durable scoped forget reconciliation

### Current gap

HAX calls `AIMEM FORGET-SCOPED-DURABLE <uuid> <project> <worktree> <workstream> <session>` through
`HAX_ROOT/src/agent/memory.c`. When the response is lost or a durability fence fails, HAX reports an
unknown result. In `src/spinnaker/qihse_resp_engine.c`, this scoped operation returns `:1` after a
successful removal and local sync, but `:0` covers cases including absent, inaccessible, or already
removed records, and the current branch does not sync when no record was removed. A later `:0` is
therefore not evidence that an earlier deletion was durably committed.

`AIMEM FORGET-RECEIPT` in `docs/architecture/aimem_resp_protocol.md` is a separate legacy/global
operation. It must not be assumed to reconcile a scoped deletion. Similarly, a missing scoped GET
cannot by itself distinguish missing, denied, and an earlier deletion whose durability is unknown.

### Requested QIHSE contract

1. Add a versioned, capability-advertised scoped forget receipt or status operation. The exact wire
   name and response schema are to be chosen and documented by QIHSE; HAX should discover support
   through `AIMEM CAPABILITIES` and retain its existing unknown-outcome behavior when unsupported.
2. Bind the request and its durable identity to the authenticated tenant and principal, target UUID,
   every scope component, operation, and a caller-supplied retry key. Reject conflicting reuse of a
   key without disclosing protected data.
3. Persist enough authorized intent and tombstone/receipt information to distinguish the exact
   operation after deletion, lost responses, restart, and concurrent retries. A tombstone sequence
   alone must not be treated as proof of the former record's scope or owner.
4. Return a stable receipt for an exact confirmed retry only after the documented local durability
   fence. State precisely what durability means; a local fsync receipt is not a replication or
   quorum
   receipt. Return an explicit unresolved outcome when the server cannot prove completion.
5. Preserve the existing indistinguishability of missing and denied records where applicable. A
   caller must not claim another principal's result by changing principal, tenant, scope, or target.
6. Publish the contract for RESP/QKP and the supported authenticated SDK. Preserve existing verbs
   and
   reply shapes unless a separately versioned capability is negotiated.

Acceptance should cover the initial durable delete, a reply lost after the fence, failure before and
after mutation, failed sync, restart, exact retry, duplicate and concurrent callers, conflicting
retry payloads, missing/denied cases, and tenant/principal/scope/clearance/SCI negatives. HAX can
then
queue the exact request, reconcile it against the receipt, and retire it only on a confirmed
outcome.
Until then, the HAX parity item remains open; a queued request or `:0` must not be reported as a
confirmed durable delete.

## Priority 2: autonomous delegation handoffs

HAX exposes `memory_handoff` offer/get/accept/cancel operations, but its ordinary local delegated
workers currently share the configured `AIMEM_SERVICE` identity. The current OFFER implementation
in `src/spinnaker/qihse_resp_engine.c` rejects a recipient equal to the authenticated actor, and
ACCEPT is restricted to the named recipient with the applicable current project grant. Thus, using a
local worker label as if it were a distinct authenticated QIHSE principal cannot implement a genuine
claim-once handoff under the existing contract.

QIHSE and HAX need a documented unattended recipient-identity/claim contract. Viable directions are
server-recognized provisioned worker principals, or a narrowly scoped server-side delegation/worker
capability. A same-principal worker handoff would need an explicit server-defined atomic ownership
and claim model; HAX must not fabricate principals or impersonate recipients. Choose and document
one contract with exact identity, scope, expiry, revocation, and expected-revision semantics.
Routine per-handoff human approval is not part of the requested workflow.

The contract should specify OFFER idempotency or a safe status lookup after a lost reply, competing
claims, retries, cancel/expiry races, restart persistence, and what a recipient can read. Exercise
wrong recipient, revoked grant, cross-tenant/project, low-clearance and SCI cases through the actual
protocol. Existing HAX context-only delegation should continue when a handoff cannot be established;
a provider or model switch alone is not proof of QIHSE recipient identity.

## Priority 3: document retrieval and knowledge graph

HAX currently preserves bounded local source excerpts as event-linked architecture knowledge with
path, line range, and source hash. It can query knowledge timelines, read exact/latest/as-of
versions,
revise versions, and expose typed relationships. Those capabilities do not yet provide full document
filtering or graph exploration.

QIHSE should define authenticated, capability-advertised APIs for:

- Source-aware filtering by stable source identity and revision, with exact project/worktree/
  workstream/session semantics and enough metadata to return attributable citations.
- Bounded traversal of authorized knowledge versions, source events, and typed relations, including
  pagination/cursor lifetime, stable ordering, cycle handling, cancellation, and deletion/revision
  behavior. Define whether results are a snapshot or can change between pages.
- Stable source and chunk identities and lineage if server-side document/chunk ingestion is
  required.
  Specify replacement, stale revisions, and deletion, including links to existing knowledge/events.

Apply authorization, classification/SCI, scope, and source filters inside the server query before
ranking and top-K selection. Do not rely on HAX post-filtering a principal-wide result set as an
access boundary. Add cross-project, direct-ID, low-clearance, SCI, cursor and stale-source tests.
URL, multimodal, connector, and UI work also requires HAX-side implementation; these proposed APIs
alone do not constitute full Supermemory product parity.

## HAX capture and delivery changes relevant to QIHSE

The HAX working tree contains authenticated per-prompt recall, in-session fact capture, durable
session capsules, event provenance, knowledge/profile tools, source-excerpt preservation, a local
retry outbox, session activation intents, and an installable independent retry timer. HAX owns that
local outbox; it is separate from QIHSE storage. The memory-status and UTF-8 import commands report
local queueing, not a remote durable receipt.

Capture retry uses stable scoped store keys, event IDs, frozen activation context, and the session
writer lock. The HAX parity inventory currently records focused interruption/retry checks and a
loopback/live-timer exercise from another HAX work session; consult that inventory and its test
artifacts for the precise evidence. Those observations do not replace testing the current QIHSE
release or establish all fault and authorization cases.

Malformed queue entries are retained and reported. Current HAX scans can skip damaged entries; an
unreadable legacy record cannot always be associated with the intent or completion it once
contained.
Consequently, duplicate-free recovery in that corruption case needs further HAX design and fault
validation. Proposed per-session/per-nonce completion records would isolate new entries, but are not
a QIHSE protocol requirement and must not be represented as implemented solely by this proposal.

A previous HAX full-suite run caused recursive launches of a test binary through its background
retry entry point, contributing to host overload. A source fix and a guarded regression check were
added; do not treat that check or a subsequent full suite as passed without a recorded run against
the final source. Avoid unconstrained parallel test execution on the affected host.

## Evaluation and acceptance ownership

Coordinate a fixed authenticated fixture corpus and report separate HAX-client and QIHSE-service
results for extraction precision, citation correctness, recall quality, p50/p95 latency,
prompt-token cost, and provider independence. Cover BM25, semantic, and hybrid modes where
supported.
Report versions, configuration, fixture scope, methodology, and actual measured values.

The deployed boundary must also be checked for low-clearance/high-data and SCI denial, cross-project
and cross-principal access, direct-ID reads, handoff access, query/cursor paths, restart/retry, and
lost receipts. In-process tests and historical live observations are useful evidence but are not a
pass against a newly rebuilt running service. Do not silently weaken an existing security invariant.

QIHSE's [AGENTS.md](AGENTS.md) requires its complete final suite using `make test TEST_JOBS=32` for
QIHSE code changes. This handoff is documentation only; no QIHSE build, service restart, test suite,
live memory write, replay, deletion, or storage inspection was performed to create it.

## Coordination checklist

- [ ] QIHSE publishes and tests scoped durable forget receipt/status semantics and capability name.
- [ ] HAX integrates that exact negotiated contract and verifies lost-ACK reconciliation.
- [ ] QIHSE and HAX settle unattended delegation identity and claim semantics; HAX wires delegation.
- [ ] QIHSE specifies authorized source filters and graph query/traversal contracts; HAX consumes
  them.
- [ ] Both projects verify the running service and final HAX binary against the agreed fixture
  suite.
- [ ] HAX completes full product-surface work separately from the QIHSE core contracts.
