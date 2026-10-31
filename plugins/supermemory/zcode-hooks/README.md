# ZCode / HAX lifecycle integration (QIHSE-only)

QIHSE is the **sole authoritative memory store**. The hook spool is a
private recovery outbox, not a secondary search index.

## Features

- `recall_hook.py` (`UserPromptSubmit`) performs authenticated hybrid recall
  only on relevant prompts, injecting <=3,400 characters of sourced,
  timestamped and explicitly untrusted observations.
- `capture_hook.py` (`Stop`) fsyncs a small event locator to an owner-only
  spool and launches a detached worker. `lifecycle.py` reads at most 2 MiB
  from the transcript tail, redacts common secrets, and writes a bounded,
  role-attributed session capsule under a stable QIHSE idempotency key.
- `external_capture.py` receives explicitly owned, typed lifecycle events
  from HAX and other harnesses (stdlib JSON-over-stdin; no daemon).
- `doctor.py` reports hook wiring and spool counts; `--online` tests
  authenticated QIHSE connectivity. No memory text or credentials printed.
- `context.py` formats small source-ID-linked excerpts; raw assistant
  statements remain unverified. There is no automatic rule promotion.

## Install

First configure the authenticated QIHSE server as described in
[the backend README](../README.md).

```bash
install -d -m 0700 "$HOME/.zcode/hooks/supermemory"
install -m 0600 capture_hook.py recall_hook.py lifecycle.py context.py aimem_client.py external_capture.py session_brief.py doctor.py "$HOME/.zcode/hooks/supermemory/"
python3 "$HOME/.zcode/hooks/supermemory/doctor.py"
```

Add these entries to the **existing** ZCode hook arrays in
`~/.zcode/cli/config.json`; retain existing hooks and settings.
Hooks must be enabled and new sessions may be needed to load them.

```json
{
  "UserPromptSubmit": [
    {"matcher": ".*", "hooks": [
      {"type": "command", "command": "python3 \"$HOME/.zcode/hooks/supermemory/recall_hook.py\"", "timeout": 15}
    ]}
  ],
  "Stop": [
    {"hooks": [
      {"type": "command", "command": "python3 \"$HOME/.zcode/hooks/supermemory/capture_hook.py\"", "timeout": 5}
    ]}
  ]
}
```

## Recovery

For a specific local session, `python3 session_brief.py --session-id run-123 --level l1` produces a JSON context capsule. Levels `l0` and `l1` are small; `l2` explicitly exposes the fuller sanitized evidence. This is read-only and never claims an atomic cross-agent handoff.


```bash
python3 lifecycle.py status
python3 lifecycle.py drain
python3 lifecycle.py replay
python3 doctor.py --online
```

- `status` exposes only queued/staged/blocked counters, legacy accepted records,
  and spool bytes.
- `drain` sends queued/staged records and skips blocked transcripts. `replay`
  also retries blocked and legacy accepted records with unchanged idempotency keys.
- Delivery uses `STORE-SCOPED-DURABLE`. The outbox entry is removed and its
  directory fsynced only after QIHSE confirms the durability fence. Cap: 8,192
  records. Capacity must be monitored; a full spool refuses new events.
- Spool: `~/.local/state/qihse-supermemory/spool` (0700 owner-only);
  configurable with `QIHSE_AIMEM_SPOOL_DIR`. Event files are 0600.
- Hook connection timeout: `QIHSE_AIMEM_HOOK_TIMEOUT` (default 2 seconds).
  Hook failures never block the agent. Failure *classes* are logged under
  `~/.zcode/hooks/supermemory/capture.log`.

## HAX / orchestrator lifecycle events

HAX may own capture instead of the native hook. Disable the duplicate
native capture for the same event when HAX owns it.

```bash
printf '%s\n' '{"capture_owner":"external","producer":"hax","event_id":"tool-0042","session_id":"run-123","event_kind":"post-tool","summary":"cargo test exit=0, 12 passed"}' | python3 external_capture.py ingest --background
```

Kinds: `session-start`, `user-prompt`, `pre-tool`, `post-tool`,
`tool-failure`, `checkpoint`, `session-end`.
The input is <=20 KiB; summary <=12 KiB. Same event identity + different
content is refused; identical replay reuses the original key.

## Security / current limits

1. QIHSE owns authentication, classification and SCI. Source-provided
   producer/project strings are **provenance only**, not authority.
2. Memory operations use QIHSE's native project scope. Project metadata remains
   routing data and never replaces tenant, classification, or SCI authorization.
3. Every recalled or ingested item is untrusted observation data. Redaction
   is heuristic, not a complete DLP guarantee; ensure this principal is
   authorized to store the excerpts. No policy/permission escalation.
4. The raw local transcript *path* is retained in the private spool but
   the transcript is not bulk-uploaded; only bounded sanitized excerpts
   are sent to QIHSE. No remote hosted memory fallback.
5. Missing/invalid/corrupt spool files and backend failures are preserved
   for diagnostics/replay rather than claimed as a successful durable write.

## Tests

```bash
python3 -m compileall -q qihse-backend
python3 -m unittest discover -s qihse-backend/tests -p 'test_*.py' -v
```

See `.github/workflows/qihse-supermemory.yml`. Run tests locally when
GitHub Actions runners are unavailable.
