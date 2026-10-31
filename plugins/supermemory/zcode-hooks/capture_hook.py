#!/usr/bin/env python3
"""ZCode Stop hook: queue a private session locator and drain it asynchronously.

The hook parent only validates/spools the tiny Stop event and starts a worker.
The worker extracts attributed, sanitized session excerpts and stores them
through QIHSE AIMEM. No transcript body passes through process argv/env.
Network failures never block a ZCode Stop or delete the recovery spool.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys

LOG = Path.home() / ".zcode" / "hooks" / "supermemory" / "capture.log"
MAX_HOOK_INPUT = 16 * 1024


def read_stdin_json() -> dict:
    try:
        raw = sys.stdin.read(MAX_HOOK_INPUT + 1)
        if len(raw) > MAX_HOOK_INPUT:
            return {}
        value = json.loads(raw) if raw.strip() else {}
        return value if isinstance(value, dict) else {}
    except (json.JSONDecodeError, ValueError, UnicodeError):
        return {}


def _write_error(code: str) -> None:
    """Log error classes, never captured transcript or credentials."""
    try:
        LOG.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with LOG.open("a", encoding="utf-8") as file:
            file.write(f"capture: {code}\n")
    except OSError:
        pass


def main() -> int:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    if "--child" in sys.argv:
        try:
            from lifecycle import drain
            report = drain(limit=64)
            if report["failed"]:
                _write_error(f"drain failures={report['failed']}")
        except Exception as exc:
            _write_error(type(exc).__name__)
        return 0

    payload = read_stdin_json()
    transcript = payload.get("transcript_path")
    raw_session = payload.get("session_id")
    session_id = str(raw_session or "unknown")[:64]
    if not isinstance(transcript, str) or not transcript or "\x00" in transcript:
        return 0

    try:
        from lifecycle import enqueue_transcript
        enqueue_transcript(transcript, session_id)
    except Exception as exc:
        _write_error(type(exc).__name__)
        return 0

    try:
        LOG.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with LOG.open("a", encoding="utf-8") as log:
            subprocess.Popen(
                [sys.executable, __file__, "--child"],
                stdin=subprocess.DEVNULL, stdout=log, stderr=log,
                start_new_session=True, close_fds=True,
            )
    except OSError as exc:
        # The spool is already durable; the operator can run lifecycle.py drain.
        _write_error(type(exc).__name__)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
