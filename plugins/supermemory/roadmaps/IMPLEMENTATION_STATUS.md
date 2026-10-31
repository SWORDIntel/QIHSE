# Supermemory QIHSE-backend implementation status

> Vendored bridge update: pinned QKP is the default in this directory. The
> standalone service is QKP-only and the default recall mode is BM25; explicit
> semantic/hybrid projection is not enabled on the live service. The historical
> 2026-10-21 deployment and performance observations below are not current
> rollout evidence. This directory is source, not an installed MCP registration.

> Date: 2026-10-21. Tracks the bridge implementation on `main` of
> SWORDIntel/supermemory (single branch — the former `qihse-backend` and
> `roadmap/*` branches were consolidated and deleted). Canonical work
> proposals: [Supermemory roadmap](SUPERMEMORY_AI_MEMORY_ROADMAP.md).
> The QIHSE engine prerequisites (QH-00 … QH-08) are implemented **and
> deployed** engine-side (SWORDIntel/QIHSE; deployed aimem release
> `~/.local/lib/qihse-aimem/20261020-41a3bc7`). Remaining work items are
> bridge-side wiring, not engine gates.

## Deployed platform baseline (2026-10-21)

- Standalone `qihse-aimem.service` on 127.0.0.1:6401 from the release
  symlink `~/.local/lib/qihse-aimem/current`; data under
  `~/.local/share/qihse-aimem`.
- Clients authenticate as the restricted `AIMEM_SERVICE` principal
  (user ID 65000, tenant 1). The dispatch boundary allows scoped `AIMEM`
  operations and session commands only; generic KV, admin, and replication
  commands return `NOPERM`.
- Crash-durable scoped mutations are live: `STORE-SCOPED-DURABLE` /
  `FORGET-SCOPED-DURABLE` carry the native WAL/fsync fence (QH-00).
- Native project/worktree/workstream/session scope is enforced server-side
  (QH-01) via `RECALL-SCOPED`, `GET-SCOPED`, `COUNT-SCOPED`.
- The deployed server additionally exposes `AIMEM HANDOFF`, `KNOWLEDGE`,
  `QUERY`, `PROJECT`, `EVENT`, `MIGRATE`, `REBUILD`, `HEALTH` — available
  for bridge wiring (SM-14/20/21/24/25), not yet used by this bridge.
- Operator credential is a `systemd-creds` encrypted blob decrypted only in
  the start wrapper; the server cleanses password environment values after
  verifier construction. Clients only ever hold the service credential.
- Version-2 migration converted 566 legacy records to principal 65000
  (435 tenant-local `global`, 131 declared repository projects) with a
  verified post-restart preflight and an authenticated post-migration backup.

## Implemented bridge-side work

| Roadmap item | Status | Files / behavior | Verification |
| --- | --- | --- | --- |
| **SM-00** Stop-hook forward bug | **Deployed** | `capture_hook.py` persists a validated Stop-event envelope to `lifecycle.py` before spawning the detached worker | Local regression test; hooks redeployed 2026-10-21 via installer |
| **SM-01** typed capture, sanitizer, recoverable outbox | **Partial** | Private fsynced spool with blocked-event quarantine; idempotency keys; role-attributed session capsule; secret redaction; external event envelope; bounded 2 MiB scan. Capture now stores through the scoped durable path | Deterministic tests; broader harness/tool-event fixture matrix pending |
| **SM-02** diagnostics, lifecycle test harness | **Partial** | `doctor.py`, stdlib unit suite (32 tests, passing locally), installer live self-tests. Fork runs **no CI** — the inherited workflow files were removed from `main` on 2026-10-21 | Verified locally 2026-10-21 |
| **SM-03** durable delivery and no-surprise egress | **Largely implemented** | MCP writes/deletes use `STORE-SCOPED-DURABLE`/`FORGET-SCOPED-DURABLE` (native durability fence, QH-00 deployed); spool retained for replay; `sync.py` accepts only the local `qihse` backend | Idempotent-replay + SIGKILL matrix against the deployed server still pending |
| **SM-10** bounded startup/continuation context | **Partial** | Bounded prompt recall (`context.py`); opt-in L0/L1/L2 session projection (`session_brief.py`). Automatic startup brief and project-scoped selection are now **wiring work** against the deployed scope boundary | Pending |
| **SM-11** structured session capsules | **Initial implementation** | Deterministic role-tagged JSON transcript tail + memory ID, source event, timestamps; no LLM-inferred assertions | Exact tool errors/commits not yet reconstructed from all harness formats |
| **SM-12** multi-harness adapters | **Initial HAX-compatible interface** | `external_capture.py` accepts owner-declared typed events with stable source identity; ZCode remains native | Codex/Gemini/etc. direct hook wiring pending; no autowiring by design |
| **SM-13** exact retrieval and provenance | **Deployed** | `get_memory` over `AIMEM GET-SCOPED`; shared-socket transaction serialization; recall hits carry IDs, timestamps, and trust labels; scope is enforced server-side, not post-filtered | Live roundtrip verified 2026-10-21 (`COUNT-SCOPED global` = 435; `RECALL-SCOPED` returns hits) |

**Formerly engine-gated items — gates are open, wiring pending:** SM-14 typed
claim-once handoff (`AIMEM HANDOFF`), SM-15 cross-project profiles
(`PROJECT`/`QUERY`), SM-20 curated knowledge pages (`KNOWLEDGE`), SM-21
temporal reconciliation (`QUERY` versioning), SM-24 OKF round-trip
(authorized export/import), SM-25 cross-project inbox. These now require
bridge-side design and wiring only. SM-22 reversible compaction and SM-23
experience distillation additionally need product decisions and an eval
corpus. SM-26 remains conditional on HAX's orchestration.

## Behavior limitations

- The bridge speaks **only** the scoped AIMEM surface; it holds the
  `AIMEM_SERVICE` credential and no Operator material.
- Per-project semantics: `memory_count` with the default `auto` scope counts
  the current repository's project only — 0 is a normal answer; `scope=global`
  is the tenant-local global project, not "every project".
- Sanitization blocks common secret shapes but does not guarantee removal of
  all secrets; ingested text is data, never instructions.
- Durability of the hook spool is local-fsync; end-to-end durability of an
  accepted event now relies on the server's durable scoped mutations.

## Validation gates — current state

1. `python3 -m compileall -q .` — **passing locally** (verified 2026-10-21).
2. `python3 -m unittest discover -s tests -p 'test_*.py'` — **32 tests
   passing locally** (verified 2026-10-21).
3. Live authenticated scoped roundtrip (store/GET/recall/count with ONNX
   embedder) — **verified 2026-10-21** via bridge tools and installer
   self-tests.
4. Low-clearance/SCI adversarial non-disclosure and cross-project negatives
   — pending; now directly testable against the deployed scope boundary.
5. Immediate backend restart + idempotent spool replay — partially covered
   by the migration preflight; dedicated kill/restart matrix pending.
6. Prompt latency and recall quality A/B against a fixed baseline — pending.
   Measured so far: novel-query hybrid recall costs ~1–2 s server-side
   (embedding); native client overhead ~1 ms.

## Next engineering order

1. Wire the newly available engine capabilities into bridge tools: handoff
   (SM-14) first, then knowledge pages (SM-20) and versioned query (SM-21).
2. Complete the kill/restart + idempotent replay matrix and the adversarial
   cross-project/SCI negative tests against the deployed boundary.
3. Add real harness-specific adapters (SM-12) only for clients actively
   used; no generic autowiring.
4. Evaluate memory-quality and token-budget changes with fixed corpora.
5. Keep `main` as the single integration branch; push bridge changes from
   the local `bridge` branch via the subtree recipe.
