#!/usr/bin/env python3
"""ZCode UserPromptSubmit hook: inject bounded QIHSE evidence, not instructions.

Query uses QIHSE's native project scope before any record is returned.
"""
from __future__ import annotations

import json
from pathlib import Path
import sys

MAX_HOOK_INPUT = 64 * 1024
MAX_QUERY = 220


def main() -> int:
    try:
        raw = sys.stdin.read(MAX_HOOK_INPUT + 1)
        if len(raw) > MAX_HOOK_INPUT:
            return 0
        payload = json.loads(raw) if raw.strip() else {}
    except (json.JSONDecodeError, ValueError, UnicodeError):
        return 0
    if not isinstance(payload, dict):
        return 0
    prompt = payload.get("prompt")
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from context import should_recall, render_hits
    if not should_recall(prompt):
        return 0

    client = None
    try:
        from aimem_client import Aimem
        client = Aimem()
        hits = client.recall(prompt[:MAX_QUERY], limit=5, mode="bm25")
        projection = render_hits(hits)
    except Exception:
        return 0
    finally:
        if client is not None:
            client.close()
    if projection:
        print(json.dumps({"additionalContext": projection}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
