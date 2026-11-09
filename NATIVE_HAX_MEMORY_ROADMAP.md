# Native HAX Memory Interoperability Roadmap

> **Roadmap authority:** [ROADMAP.md](ROADMAP.md) is the sole authority for delivery status, remaining work, sequencing and acceptance. This file retains supporting design, acceptance criteria and dated evidence; historical status labels below are not an independent current checklist. Consolidated 2026-11-07.

**Status:** Planning document. HAX is replacing its optional Supermemory adapter with native,
first-party workflows over authenticated QIHSE AIMEM. This roadmap describes QIHSE-side contracts
and gaps; it does not authorize live service writes, backlog replay, or storage maintenance.

**Reviewed:** 2026-11-07 against `docs/architecture/aimem_resp_protocol.md`, the local
Supermemory bridge README and implementation status, and `docs/AIMEM_CURRENT_ISSUES.md`.

## Goal and ownership

HAX owns extraction policy, user controls, prompt integration, document selection, and
orchestration.
QIHSE owns durable records, scope, principal authorization, classification/SCI, exact retrieval,
version lineage, and atomic state transitions. HAX must call the authenticated AIMEM API and must
never inspect QIHSE storage paths directly.

Do not build a second memory database, a Supermemory service, or an implicit policy/profile
promoter. HAX should extract general durable knowledge and preference candidates automatically
during an active session. A preference or durable knowledge rule remains `PROPOSED` until an
authorized Operator explicitly approves it; `AIMEM_SERVICE` must never approve or retract records.
That review status does not gate authorized retrieval or contextual use: HAX may recall and use
`PROPOSED` knowledge as contextual evidence without treating it as policy. HAX must not wait for an
Operator to use its memory backbone.

## Existing QIHSE capabilities

The current AIMEM protocol already documents scoped BM25/semantic/hybrid recall; durable scoped
store and forget; authorized events; claim-once handoffs; versioned knowledge create/revise/get/
latest/as-of; paginated query; project grants; and server-side project/worktree/workstream/session
filtering. Reviewed preference `RULE` records are supported. There is no separate profile database
or implicit promotion path.

The bridge status document says handoff, knowledge, query, and project primitives are available
engine-side but still need client/bridge wiring. HAX should use the native protocol directly rather
than waiting for or recreating the Supermemory bridge surface.

## QIHSE work plan

### QH-HAX-01 — Pin and publish the authenticated client contract

- Keep each classified-capable read bound to an explicit authenticated `qihse_user_t` or equivalent
  typed security context through every layer.
- Verify the deployed AIMEM service's advertised protocol version/capabilities independently from
  historical deployment notes. Do not infer runtime support from a roadmap or stale status file.
- Document service-principal permissions separately for durable memory, knowledge, handoffs,
  events, project grants, and query cursors. Return typed unsupported/denied errors without leaking
  protected payloads.
- Acceptance: SDK/API examples for each supported operation plus low-clearance/high-data negative
  tests for search, direct-ID read, list/query, handoff, and knowledge paths.

### QH-HAX-02 — Durable, idempotent HAX capture

- Expose scoped durable write and receipt operations consistently to C and supported SDKs.
- Specify retry identity, accepted-vs-durable receipt meaning, duplicate handling, and recovery
  after a lost reply. Keep payloads and event IDs bounded.
- Add a scoped durable forget receipt/status operation bound to tenant, principal, all scope fields,
  target UUID, and a caller retry key. Persist the bound intent before deletion and reconcile an
  authorized scoped tombstone after restart; a tombstone sequence by itself cannot prove the
  deleted row's former scope or owner.
- Acceptance: retry, changed-payload conflict, process restart, crash-before-reply, and concurrent
  same-key tests for both store and forget; include principal/scope negatives and receipt recovery
  across a lost ACK. Receipts must not overstate replication or quorum guarantees.

### QH-HAX-03 — Evidence-linked extraction and curated knowledge

- Keep automatic general-knowledge and profile extraction in HAX during active sessions. Create
  attributed `PROPOSED` candidates using the authenticated QIHSE knowledge API, with source session
  or document events, timestamps, extractor identity, confidence, and evidence links where the
  negotiated schema supports them.
- Make proposed candidates available to normal authorized recall and contextual use, clearly
  identified as unreviewed evidence. Do not gate HAX memory use on Operator approval or treat any
  recalled candidate as policy.
- Preserve candidate-vs-approved state. Only a separately authenticated Operator may approve or
  retract durable preference rules; `AIMEM_SERVICE` must never make those transitions. Record
  version, reviewer, scope, and evidence lineage.
- Acceptance: malformed evidence rejection, unauthorized promotion denial, version-CAS races,
  authorized as-of reads, automatic capture during a live session, retrieval and contextual use of
  a proposed candidate, and no content disclosure on denied reads.

### QH-HAX-04 — Document identity and scoped retrieval

- Decide whether existing AIMEM records are sufficient for bounded document excerpts and citations.
  If a new document/chunk API is needed, define stable source identity, revision, chunk lineage,
  deletion behavior, and authorized source links before implementing it.
- Keep repository source-of-truth and code navigation in HAX/KEYSTONE; QIHSE stores extracted,
  attributable knowledge and evidence references rather than shadowing entire repositories.
- Acceptance: exact scope filtering in the server query plan, citation/source identity preservation,
  stale-revision behavior, and ACL/SCI negative tests.

### QH-HAX-05 — Native handoff and temporal knowledge contracts

- Publish existing handoff and knowledge/query commands as stable authenticated API operations,
  including revision conflicts, expiry, pagination, cursor lifecycle, and cancellation semantics.
- Ensure cursor resources are bounded and released on errors, timeouts, and client disconnects.
- Acceptance: concurrent claim-once tests, authorized recipient/owner tests, expiry persistence,
  lost-ack retry, query pagination consistency, and temporal boundary tests.

### QH-HAX-06 — Interoperability and operational readiness

- Maintain HAX contract fixtures and negative authorization tests without relying on live user data.
- Measure BM25, semantic, and hybrid recall latency/quality on a fixed authorized fixture corpus;
  publish p50/p95 latency and citation correctness. Do not enable a slow mode by default without
  measured benefit.
- Gate production writes/replay on resolved authentication-authority migration, adequate storage
  headroom, and an explicitly approved backlog recovery plan.
- Acceptance: reproducible protocol tests, disk/backlog health checks, and an operator-reviewed
  rollout/rollback procedure.

## HAX implementation order

### HAX execution status (reviewed 2026-11-07)

The HAX repository has native authenticated recall, exact reads, durable capture, count/forget,
in-session semantic fact capture, and fixture-tested autonomous proposed RULE and general-knowledge
capture. Proposed records remain available for contextual recall and use, without being treated as
approved policy. `AIMEM_SERVICE` cannot approve or retract them. The repository also contains local
slices for temporal queries, handoffs, and source-aware document knowledge; these do not certify any
deployed service's current capability or authorize live service writes.

- Completed: remove HAX's Supermemory runtime path; implement native scoped AIMEM recall, durable
  session capture, in-session semantic fact capture, and count/forget.
- Completed implementation: autonomous model-guided general-knowledge and profile-candidate
  proposals into versioned `PROPOSED` records, with proposed records available to contextual
  recall/use. Broader extraction and recall evaluation remains open. Operator approval/retraction
  remains separate; HAX's service principal must never perform either action.
- Remaining: source-aware search filters, evaluation, and recoverable delivery.
- Handoff contract: HAX under `AIMEM_SERVICE` may autonomously OFFER, GET, and CANCEL only where
  QIHSE authorizes that principal (the recipient must be a known, active same-tenant user with an
  existing project-reader grant; the offering principal must own an in-project record or be an
  Operator). The service principal cannot discover recipients or create their grants. ACCEPT is
  restricted to the named recipient's authenticated principal with a current project-reader grant;
  `AIMEM_SERVICE` cannot accept on a recipient's behalf. Provider switching is not a QIHSE recipient
  contract. Until a recipient-authenticated identity path exists, HAX integration is outgoing-only.

1. **Historical recorded implemented:** Retire HAX's Supermemory capture configuration and route; preserve existing queued outbox
   data.
2. **Historical recorded implemented:** Add native AIMEM recall mode, durable capture, scoped store/forget/count, and evidence IDs.
3. **Historical recorded implemented:** Implement autonomous model-guided general-knowledge/profile proposals, proposed-record
   contextual recall/use, and versioned knowledge history. Broader extraction/recall evaluation
   remains open. Operator approval/retraction is a separately authenticated action.
4. **Historical proposed / not evidenced complete:** Complete citation retrieval, freshness checks, and authenticated source linkage.
5. **Historical proposed / not evidenced complete:** Complete authorized outgoing AIMEM handoffs (OFFER/GET/CANCEL under `AIMEM_SERVICE`); keep
   ACCEPT restricted to a recipient-authenticated principal. Retain the implemented temporal
   knowledge query/cursor slice.
6. **Historical proposed / not evidenced complete:** Run fixture, low-clearance/SCI, latency, restart, and end-to-end tests before enabling new
   defaults.

## Current operational gate

`docs/AIMEM_CURRENT_ISSUES.md` reports an unresolved authentication-authority migration, a nearly
full filesystem, and a protected blocked/queued backlog. These are rollout blockers. Do not replay,
delete, compact, or otherwise mutate live AIMEM data as part of this roadmap. Recheck the issue
document and obtain the applicable operator approval before any live write or recovery operation.
