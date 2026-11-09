# Supermemory (QIHSE backend): ai-memory feature adoption roadmap

> **Roadmap authority:** [ROADMAP.md](../../../ROADMAP.md) is the sole authority for delivery status, remaining work, sequencing and acceptance. This file retains supporting design, acceptance criteria and dated evidence; historical status labels below are not an independent current checklist. Consolidated 2026-11-07.

> **Status:** proposed work items; what is actually shipped per item is tracked in
> [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md).  
> **Date:** 2026-10-21 (engine baseline updated; original draft 2026-10-20)  
> **Base:** `SWORDIntel/supermemory` `main` — the only branch since 2026-10-21
> (originally reviewed on `qihse-backend` at `6492260456a81320f6bb8cb75ba9b2bac6d94cf4`).  
> **Prior art:** [akitaonrails/ai-memory](https://github.com/akitaonrails/ai-memory) `main` reviewed at `11ab1003d9ef3788f5fc40b87fff54abf7f17dc0`; latest checked release `v3.1.1`.  
> **Companion roadmap:** the QIHSE engine prerequisites (QH-00 … QH-08) are
> implemented engine-side in SWORDIntel/QIHSE and **deployed** (aimem release
> `20261020-41a3bc7`, 2026-10-21). In the dependency columns below, `QH-xx`
> therefore names the engine primitive an item consumes, not an open engine
> blocker; the remaining work is bridge-side wiring. The engine roadmap
> document was retired from this tree on 2026-10-20.

## Decision and architectural constraints

**Port selected mechanisms, not the ai-memory server.** The long-term goal is a local, multi-agent memory workflow with QIHSE as the authoritative store, QIHSE as the authorization/classification/SCI policy boundary, and the Supermemory-compatible MCP surface as the agent-facing interface. HAX should be able to consume the same interfaces, not operate a second persistent memory system.

Retain the existing `search_memory`, `add_memory`, `forget_memory` and `memory_count` contracts. Add new MCP tools and optional hooks without breaking them. A Markdown/OKF knowledge view must remain an **authorized projection/export** unless a later architecture decision explicitly changes QIHSE authority. Do not adopt a second canonical wiki, git database, SQLite vector index, or hosted memory API.

Project/session/worktree metadata are routing attributes **in addition to**, never in place of, the authenticated QIHSE principal and its classification/SCI constraints. A client's claimed project, user or label must not grant privilege.

### Confirmed existing implementation

| Existing capability | Current location / caveat |
| --- | --- |
| QIHSE AIMEM over authenticated RESP; BM25, ONNX semantic, hybrid recall; episodic and semantic kinds | [`qihse-backend/README.md`](../README.md), [`mcp_server.py`](../mcp_server.py); **do not rebuild** |
| QIHSE-enforced principal, classification and SCI isolation | Native QIHSE; every ranking mode must preserve its existing hidden-record invariants |
| Idempotent JSONL ingestion, optional export manifest, resumable source position, local-only backend | [`sync.py`](../sync.py); `--backend` accepts only `qihse` |
| ZCode pre-prompt recall and Stop-hook capture | [`zcode-hooks/`](../zcode-hooks/); Stop-event envelope handoff fixed and hooks redeployed 2026-10-21 |
| `AIMEM GET` by identifier | Supported in the [QIHSE RESP protocol](https://github.com/SWORDIntel/QIHSE/blob/main/docs/architecture/aimem_resp_protocol.md) and exposed by this MCP bridge as `get_memory` over `GET-SCOPED` |
| Fully crash-durable acknowledgement | **Available**: `STORE-SCOPED-DURABLE` / `FORGET-SCOPED-DURABLE` carry the native WAL/fsync fence (QH-00, deployed). The legacy `STORE`/`FORGET` remain eventually durable only and must not back acknowledged operational memory |
| Native project-scoped recall, typed handoffs, version queries, profile record types | **Engine-side available**: scoped recall/filtering (QH-01) is already in use; `HANDOFF`, `KNOWLEDGE`, `QUERY`, `PROJECT` and `EVENT` are deployed and await bridge wiring (SM-14/15/20/21/24/25) |

The upstream Supermemory monorepo README describes hosted product facilities and benchmarks; that is **not proof** those features work through this local `qihse-backend` implementation.

## Priority summary

| ID | Priority | Feature | Owner | Depends on |
| --- | --- | --- | --- | --- |
| SM-00 | P0 | Fix detached Stop-hook losing its input | Supermemory | none |
| SM-01 | P0 | Typed capture, sanitization, bounded spool and replay | Supermemory | SM-00 |
| SM-02 | P0 | Harness simulator, lifecycle integration tests and health diagnostics | Supermemory | SM-00/01 |
| SM-03 | P0 | Durability-aware outbox, explicit offline/egress contracts | Supermemory | SM-01; durable ack via QH-00 (deployed) |
| SM-10 | P1 | Bounded L0/L1/L2 startup brief | Supermemory | SM-01, retrieval |
| SM-11 | P1 | Structured session capsules and evidence pointers | Supermemory | SM-01/03 |
| SM-12 | P1 | Multi-harness capture adapters with single capture owner | Supermemory + HAX | SM-01/11; project scope via QH-01 (deployed) |
| SM-13 | P1 | Direct `get_memory`, explicit retrieval provenance and explainability | Supermemory | `GET-SCOPED` via QH-01/02 (deployed) |
| SM-14 | P2 | Explicit cross-agent handoff workflow | Supermemory + HAX | **QH-03** (deployed: `AIMEM HANDOFF`) |
| SM-15 | P2 | Cross-project preference/profile projection | Supermemory | **QH-01/05/07** (deployed), opt-in policy |
| SM-20 | P2 | Curated knowledge pages: decisions, gotchas, fixes, procedures | Supermemory | **QH-04/05** (deployed: `AIMEM KNOWLEDGE`) |
| SM-21 | P2 | Version-aware contradiction detection and timelines | Supermemory | **QH-04/05** (deployed: `AIMEM QUERY`) |
| SM-22 | P3 | Decay, compaction, dedup, optional "dream" maintenance | Supermemory | SM-20/21; **QH-00/04/06** (deployed) |
| SM-23 | P3 | Cross-session experience distillation | Supermemory | SM-11/20, eval gate |
| SM-24 | P3 | OKF/Markdown import/export and snapshots | Supermemory | **QH-07** (deployed) |
| SM-25 | P3 | Cross-project inbox and native-history continuation | Supermemory + HAX | **QH-01/03/05** (deployed) |
| SM-26 | Conditional | Managed CLI launcher | HAX first | Only if HAX's existing orchestration cannot supply continuity |

The QH identifiers and their engine-level implementation contracts live in the SWORDIntel/QIHSE repository (the engine roadmap document was retired from this tree on 2026-10-20). All QH-00 … QH-08 primitives these items depend on are implemented and deployed as of 2026-10-21; remaining gaps are bridge-side description, wiring and evaluation.

## P0 — correctness before additional features

### SM-00: Repair detached Stop-hook capture (fixed 2026-10-21)

**Status:** the defect below is repaired and redeployed; this section is kept as
the design/acceptance record. `capture_hook.py` now persists a validated
Stop-event envelope to `lifecycle.py` before spawning the detached worker.

[`zcode-hooks/capture_hook.py`](../zcode-hooks/capture_hook.py) reads `transcript_path` and `session_id` from stdin. The parent then spawns itself as `--child` with `stdin=subprocess.DEVNULL` without passing the payload in argv, environment or a spool. The child reads an empty JSON object and exits before it can open the transcript. This prevents the intended automatic session capture.

**Plan:** Preserve a small validated Stop-event envelope across the parent/child boundary, preferably through a private mode-0600 spool record or a pipe passed to the child. Do not put transcripts, tokens or credential values in process arguments. Preserve the original event identity so duplicate Stop signals remain idempotent. Child startup must not block the hook.

**Acceptance:** (1) real Stop event → child reads the correct transcript path/session ID → exactly one new episodic record; (2) duplicate Stop event → original memory ID, no duplicate; (3) missing, unreadable, truncated, malformed and maliciously long paths → bounded no-op with diagnostic; (4) backend down → prompt completion remains unaffected; (5) detached subprocess termination/restart → event safely recoverable from spool if configured.

### SM-01: Event contract, privacy boundary and recoverable capture

Borrow the [ai-memory lifecycle event model](https://github.com/akitaonrails/ai-memory/blob/main/docs/external-lifecycle.md) rather than storing only a free-text transcript tail.

**Create a versioned event envelope:** `schema_version`, `producer`, `event_id`, `agent`, `native_session_id`, `logical_workstream_id` (optional), repository/worktree fingerprint, event type, event time, sanitized content summary, evidence pointer and stable idempotency key. QIHSE, not the client, resolves the authenticated identity and label. Keep tool failures, test results and "what changed" distinct from user requests.

**Capture vocabulary:** `session-start`, `user-prompt`, `pre-tool`, `post-tool`, `tool-failure`, `checkpoint`, `session-end`. Start with Stop and prompt integration; high-volume post-tool records are bounded/opt-in. Do not turn every token or every tool output into an independently durable memory.

**Sanitization:** Separate user-authored preferences from assistant-generated hypotheses and tool output. Mask common bearer tokens/secrets before persist; guard against prompt-injection text being reinterpreted as instructions; never promote untrusted transcript text to rules by parsing labels in the text. Treat transcript paths as trusted only after canonical path and owner/permission validation. Bound individual JSONL event length and byte budgets. Read transcript tails incrementally (the current code loads the entire file into memory before taking the last 120 events).

**Reliability:** Versioned, append-only local spool; stable hashes; acknowledged offsets; retry with exponential backoff and jitter; discard only after durable delivery when a durability primitive exists; bounded disk and quota; trace rejected/oversized events without logging payloads. Integrate with QIHSE idempotency, not an independent durable database.

**Acceptance:** 10,000-event replay is count-stable; interruption after any write resumes without duplicates; injected secrets absent from both store and logs; invalid JSON does not truncate later valid observations; a forged cross-project scope/SCI field never widens access.

### SM-02: Test and diagnostics harness

Create a deterministic no-LLM test harness that submits fake lifecycle events to the actual hook/MCP paths with a controllable QIHSE test double, then runs protected integration tests against a temporary real QIHSE server. Test failures, timeouts and broken authentication in addition to happy-path behavior.

Add a diagnostic command or script reporting hook wiring, producer identity, pending spool events, recent accepted/dropped counts, current embedder and observable durability mode, **without** revealing memory text or credentials. Proposed targets: P95 synchronous hook overhead <=150 ms and a configured bounded retrieval-injection budget; establish actual baseline before imposing thresholds.

**Acceptance:** Automated tests reproduce the SM-00 bug before its fix, then pass afterward. At least one malicious input and one unauthorized-classification negative control must gate the local suite — the fork runs no CI since the inherited workflows were removed from `main` on 2026-10-21.

### SM-03: Durable delivery and no-surprise egress

`STORE-SCOPED-DURABLE` / `FORGET-SCOPED-DURABLE` now supply the native WAL/fsync durability fence (QH-00, deployed 2026-10-21), so an ACK on those paths is known crash-durable. The legacy non-durable `STORE`/`FORGET` remain eventually durable only and must not back acknowledged operational memory. Stop-hook capture still keeps a local protected recovery spool: the hook itself can die before the server ever sees the event, and that checkpoint must not be discarded merely on a transient acknowledgement.

Default invocation remains QIHSE-only, and that is now enforced: `sync.py --backend` accepts only `qihse` (the legacy `supermemory`/`both` cloud backends were removed). Keep it that way — reintroducing a remote/secondary backend is a separate, explicit opt-in decision, not a flag default. Test that ordinary `qihse` mode and MCP invocation contact no remote endpoint. Record whether retries target exactly the original principal and payload.

Harden `zcode-hooks/aimem_client.py` env-file handling consistently with the MCP bridge (0600 file/owner and symlink rules). Never fall back to unauthenticated or unencrypted remote RESP when the authenticated local endpoint is unavailable.

**Acceptance:** Inject immediate process death after STORE/FORGET and demonstrate recovery semantics; no event incorrectly reported as crash-durable; network-deny test confirms no hosted egress in the default mode.

## P1 — cross-harness context and retrieval quality

### SM-10: Progressive L0/L1/L2 startup packet

Borrow [ai-memory's tiered brief design](https://github.com/akitaonrails/ai-memory/blob/main/docs/design-tiered-session-brief.md), not its wiki-specific storage.

- **L0:** Tiny deterministic list of active project, session/workstream, salient decisions, active blockers, pending handoff indicator, and the pointers needed to expand.
- **L1:** Short extractive context covering latest accepted decisions, known failures, test state, architecture and current tasks. Cite memory IDs/evidence pointers, not just blended prose.
- **L2:** Explicitly requested full memory/session context through `get_memory` or paged history; never inject the entire transcript by default.

Make budgets configurable; initial proposal is <=1,000 injected tokens at startup for L0+L1, with deterministic ordering to benefit prompt caches. Preserve the ability to disable injection per harness. Show uncertainty, stale timestamps and unverified observations as such. A "continue" prompt should prioritize session continuity over generic global recall.

**Acceptance:** Same project state yields byte-identical L0 until relevant state changes; output never exceeds budget; no duplicate injection per session; negative tests show no cross-project or SCI leakage.

### SM-11: Structured session capsule and evidence retention

On a completed session, produce a typed capsule with `objective`, `actions_taken`, `files_or_commits`, `tests_passed`, `tests_failed`, `decisions`, `failed_approaches`, `open_questions`, `next_steps` and source-event IDs. Distinguish observed tests from claims in assistant output. Rule-based/extractive compilation is the default; optional local LLM summarization only after fidelity checks.

Retain an authorized, bounded path to exact history for debugging and mid-task resumption rather than assuming a summarizer preserved error codes, command output and file names. Preserve immutable source references through QIHSE or a protected session-log ledger; summary-only storage is insufficient for precise recovery. Avoid exposing a raw local transcript path to remote peers.

**Acceptance:** Fixtures preserve exact error identifiers, file paths, branch/commit IDs and outstanding tasks; omitted evidence is flagged rather than invented.

### SM-12: Multiple harness adapters; one capture owner

Extend ZCode first, then HAX, Codex, Gemini CLI, Claude Code, OpenCode/Cursor where stable lifecycle surfaces exist. Use [ai-memory's support matrix](https://github.com/akitaonrails/ai-memory/blob/main/docs/support-matrix.md) as a **pattern and coverage checklist**, not as evidence of installed support here. Do not blindly graft their hooks or overwrite users' CLI configuration.

Supply: `--plan` / dry-run wiring inspection, idempotent install/uninstall, launcher-native session ID mapping and opt-out, explicit producer ownership (`capture_owner` equivalent) so HAX-mediated executions do not double-capture both harness and orchestrator events. Prefer a shared adapter protocol over one daemon per agent. HAX can remain the existing orchestrator.

**Acceptance:** Two concurrent agents in distinct repos cannot contaminate each other's memory; resuming a workstream in a new harness recovers the correct capsule; duplicate capture prevention passes across subprocess inheritance.

### SM-13: Retrieval ergonomics and explainability

Expose `get_memory(id)` over native `GET-SCOPED` and return typed errors for missing/denied records without leaking which case occurred across an authorization boundary. Add explicit `source_id`/`session_id` and time fields where supported. Server-side scoped filters are deployed (QH-01); recall/count already declare `scope`, so do not implement insecure Python-side post-filtering of a global top-K.

Capture explainable result provenance and effective ranking mode. Calibrate the current `recall_hook.py` hard-coded `MIN_SCORE = 0.005` against real score distributions, per mode; do not interpret arbitrary BM25, cosine and RRF scores as directly comparable. De-duplicate injected snippets, and optionally apply reranking only after authorized candidate selection.

**Acceptance:** Same recall hits can be fetched exactly by ID; a low-clearance caller never detects high-label hits through count, score, errors or timing-oriented disclosures; context budget enforced after reranking.

## P2 — durable knowledge and explicit coordination

### SM-14: Cross-agent typed handoffs

Borrow the [typed handoff](https://github.com/akitaonrails/ai-memory/blob/main/docs/design-handoff-offer-not-claim.md) and [managed workstream](https://github.com/akitaonrails/ai-memory/blob/main/docs/managed-workstreams.md) concepts, not their independent SQLite ledger.

Handoff fields: producer identity, source/target workstream/project, allowed recipient, summary, outstanding tasks, blockers, changed files, tests, evidence IDs, creation/expiry, revision and state. Default to **offer, not auto-claim** on session start: otherwise an unrelated CI or agent session could consume the baton. Explicit acceptance must use the atomic server-side `AIMEM HANDOFF` transition (QH-03, deployed), not read/modify/write in Python. Support cancel, expire, accepted-by audit and recovery after interrupted acceptance.

**Acceptance:** Concurrent claims admit exactly one legitimate winner; unrelated startups cannot consume handoffs; no cross-principal or SCI promotion; failed acceptance preserves a retriable offer.

### SM-15: Evidence-derived cross-project preference profile

Borrow [ai-memory's cross-project profile](https://github.com/akitaonrails/ai-memory/blob/main/docs/cross-project-profile.md). Only verified operator-authored preferences and approved rules qualify for automatic profile promotion, not assistant guesses, tool output, quoted documents or repetitions fanned out by one orchestrator session.

Profile hierarchy: current user instruction > repo rules > project-specific decisions > approved global default. Support stable vs recent profile entries, stack-specific applicability, provenance, opt-outs and review of candidates. Opt-in sharing across projects; SCI/classification controls must be applied **before** aggregating evidence, not just on output.

**Acceptance:** Contradictory project-specific rule wins for that project; a preference from restricted project A never leaks to project B without an authorized explicit promotion.

### SM-20 / SM-21: Curated knowledge pages and temporal reconciliation

Borrow the readable knowledge taxonomy: `decisions/`, `gotchas/`, `procedures/`, `architecture/`, `incidents/`, `sessions/` and operator-approved `rules/`. A page is a projection of QIHSE memory versions, not the authoritative file. Add content-addressed export manifests, source evidence, version IDs, `as_known_at` (ingestion-time) and, separately, user-supplied world-time validity where reliably known.

Use a restricted relation vocabulary (`fixes`, `causes`, `contradicts`, `supersedes`). Never silently overwrite an explicit user decision with a model's contradictory interpretation; stage a review candidate and preserve both original claims and provenance. A failed/obsolete approach stays available as history without being suggested as current procedure.

**Acceptance:** Old truth remains queryable under `as_known_at`; current query returns the accepted successor; missing source evidence is marked unknown; typed contradictions surface to a review queue.

## P3 — optional memory hygiene and portability

### SM-22: Decay, dedup and optional idle consolidation

Port the useful *principles* in [ai-memory's aging design](https://github.com/akitaonrails/ai-memory/blob/main/docs/design-memory-aging.md): short-lived working notes, longer-lived evidence, access reinforcement, conservative duplicate detection and opt-in cold-content consolidation.

Disable content-rewriting and deletion by default. Decay should affect *retrieval salience* before destroying anything. Do not compact across QIHSE tenant, principal, classification or SCI boundaries; merging must not strip provenance, version history or required labels. Treat contradictory observations as distinct until reconciled, not vector-near duplicates. Offline zero-LLM extractive mode first; optional "dream" pass runs only when idle, with bounded quotas, candidate review and replayable evidence.

**Acceptance:** A/B retrieval evaluation shows no material regression; versioned restores recover the original; malformed compaction inputs produce no destructive mutation; audit captures every operation.

### SM-23: Cross-session experience learning

Borrow [the experience pass](https://github.com/akitaonrails/ai-memory/blob/main/docs/experience.md): review several recent completed sessions to detect repeated failed approaches, reliable procedures and explicitly stated preferences. Produce **proposals**, not unreviewed permanent rules. Distinguish "assistant claimed success" from tests/commits/observations showing success. Run under strict token/CPU limits and a recall-eval gate.

### SM-24: Standard portable projection, backup and restore

Borrow the [Open Knowledge Format export approach](https://github.com/akitaonrails/ai-memory/blob/main/docs/okf.md) as an authorized QIHSE export adapter, not an alternative write authority. Export Markdown + YAML metadata + version and provenance manifest, with optional sanitized session capsules. Imports pass through authenticated QIHSE APIs with idempotency and explicit conflict policy. For sensitive compartments: default deny export, require explicit operator-approved scope and label policy, never assume "private Git repository" makes its contents suitable for unencrypted backups.

Provide dry-run import, integrity hash verification, recovery from interrupted import and a test restore into a disposable QIHSE instance.

### SM-25 / SM-26: Agent inbox and workstream launcher (conditional)

A scoped, claim-once cross-project inbox could let a HAX agent request work in a different project without importing its entire context. Preserve sender/receiver authorization, TTL, IDs, explicit acceptance and source evidence. `AIMEM HANDOFF` (QH-03) now supplies the transactional state, so build on that primitive rather than a Python-side ledger.

ai-memory also has a managed `run` launcher and private temporary projection of previous native history. Prefer integrating these semantics into **HAX**, the existing harness; build another launcher only if a concrete lifecycle/resume gap remains. No native session/transcript paths should be sent to remote agents or permanently copied by default.

## Delivery waves

| Wave | Deliverables | Objective exit gate |
| --- | --- | --- |
| **0 — repair** | SM-00/01/02 and minimal SM-03 | End-to-end ZCode event captured/replayed, sanitizer and failure tests passing |
| **1 — useful memory** | SM-10/11/13; initial HAX adapter under SM-12 | Bounded startup context, provenance-backed exact recall, cross-harness resume |
| **2 — engine extension** | QH-00/01/02/05 delivered engine-side 2026-10-21 | True server-side project isolation and durable scoped mutations; bridge consumes them |
| **3 — coordination** | SM-14/15/20/21 with QH-03/04 | Atomic handoffs, reviewable versioned knowledge, no unauthorized context crossing |
| **4 — refinement** | SM-22/23/24/25, only if evaluations justify | Recall maintained/improved, recoverable maintenance, portable authorized export |

## Eval gates and definition of done

Use [ai-memory's benchmark methodology](https://github.com/akitaonrails/ai-memory/blob/main/docs/benchmarks/README.md) for fixture provenance and pipeline-vs-ranking isolation, but do **not** compare published hit@5 with upstream Supermemory's Recall@15 as if they were the same metric. Establish local baselines on fixed, versioned corpora; compare after each ranking/consolidation change. Track Recall@5/15, MRR, answer correctness, temporal/fact-conflict mistakes, evidence attribution, injected token count, P50/P95 latency and crash recovery. Prefer at least a fixed 100-query internal task suite and the full public LongMemEval-S evaluation where practical.

Hard gates before enabling feature flags by default:

1. **Isolation:** deliberately seed higher-classification, foreign-SCI and foreign-project memories; assert zero unauthorized results, count/cardinality change or score influence (legitimate control also passes).
2. **Crash and replay:** `SIGKILL` the ingesting process/backend around every acknowledgement phase; replay from a stable spool; no silent data loss or duplicates. Durable acknowledgement exists on the `*-SCOPED-DURABLE` paths (QH-00 deployed); assert the non-durable legacy path never backs operational memory.
3. **Capture fidelity:** stable event IDs and exact reproduced errors/paths/commit IDs; real Stop-hook fixture captures a memory exactly once.
4. **Privacy:** canary secrets do not appear in indexed text, crash logs, traces, exported bundle, LLM request or Git artifacts unless an explicitly authorized exact-content workflow requires them.
5. **Context discipline:** bounded startup payload, evidence pointers, deterministic order, no stale unverified item presented as a rule.
6. **Rollback:** every opt-in layer can be disabled independently without losing existing QIHSE records; versioned maintenance is reversible.

## Traceability / exclusions

Upstream evidence: [architecture](https://github.com/akitaonrails/ai-memory/blob/main/docs/ARCHITECTURE.md), [lifecycle](https://github.com/akitaonrails/ai-memory/blob/main/docs/external-lifecycle.md), [managed workstreams](https://github.com/akitaonrails/ai-memory/blob/main/docs/managed-workstreams.md), [hand-off offer semantics](https://github.com/akitaonrails/ai-memory/blob/main/docs/design-handoff-offer-not-claim.md), [profiles](https://github.com/akitaonrails/ai-memory/blob/main/docs/cross-project-profile.md), [temporal](https://github.com/akitaonrails/ai-memory/blob/main/docs/temporal.md), [typed relations](https://github.com/akitaonrails/ai-memory/blob/main/docs/typed-edges.md), [memory aging](https://github.com/akitaonrails/ai-memory/blob/main/docs/design-memory-aging.md), [benchmarks](https://github.com/akitaonrails/ai-memory/blob/main/docs/benchmarks/README.md).

**Out of scope:** importing the Rust server as an operational dependency; using ai-memory's Markdown/git wiki as a second canonical database; copying another project's indexed memories without authorization; cloud memory as fallback; adopting all ~20 upstream harness adapters at once; unreviewed "dream" rewrites of operational rules; enabling a newly wired feature by default before its eval gates pass (the engine primitives now exist for most of them).

**Recommended next engineering change:** wire SM-14 (typed handoff) onto the deployed `AIMEM HANDOFF` primitive, then SM-20/SM-21 knowledge and versioned query. SM-00 is fixed; it only needs to stay covered by the local regression suite.
