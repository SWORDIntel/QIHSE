#!/usr/bin/env python3
"""Generic orchestrator capture endpoint for HAX and other coding harnesses.

Usage:
    printf '%s\n' '{"capture_owner":"external","producer":"hax","event_id":"42","session_id":"s1","event_kind":"post-tool","summary":"exit=0; tests: 12 pass"}' | python3 external_capture.py ingest --background
    python3 external_capture.py drain
    python3 external_capture.py replay
    python3 external_capture.py status

This local CLI is not an authenticated QIHSE service or project-scoping API:
all durable storage is performed through the configured live AIMEM principal.
Caller-provided producer/project values are provenance only.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys

MAX_INPUT_BYTES = 20 * 1024


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("ingest", "drain", "replay", "status"))
    parser.add_argument("--background", action="store_true", help="spawn detached spool drainer after ingest")
    args = parser.parse_args()
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from lifecycle import PipelineError, enqueue_event, drain, status
    try:
        if args.command == "status":
            print(json.dumps(status(), sort_keys=True))
            return 0
        if args.command in ("drain", "replay"):
            result = drain(replay_accepted=args.command == "replay")
            print(json.dumps(result, sort_keys=True))
            return 0 if not result["failed"] else 1

        raw = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
        if len(raw) > MAX_INPUT_BYTES:
            raise PipelineError("event exceeds ingress cap")
        value = json.loads(raw)
        event_id = enqueue_event(value)
        if args.background:
            try:
                subprocess.Popen(
                    [sys.executable, __file__, "drain"],
                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL, start_new_session=True,
                )
            except OSError:
                # Record is queued durably and may be recovered manually.
                pass
        print(json.dumps({"queued": True, "event_id": event_id}))
        return 0
    except (OSError, PipelineError, ValueError, TypeError):
        print(json.dumps({"queued": False, "error": "invalid event or unavailable spool"}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
