#!/usr/bin/env python3
"""Read-only local session projection for same-machine cross-harness continuation.

The spool is an outbox, not a canonical wiki. This command makes no claim that
a handoff has been offered, claimed, accepted or made crash-durable in QIHSE.
There is no automatic cross-project sharing or scope bypass.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


def lookup(session_id: str, producer: str | None = None) -> dict | None:
    from lifecycle import _directory, _load_record, PipelineError
    best = None
    for path in _directory().glob("*.json"):
        try:
            record = _load_record(path)
        except (OSError, PipelineError, ValueError):
            continue
        if record.get("session_id") != session_id or "capsule" not in record:
            continue
        if producer and record.get("producer") != producer:
            continue
        if best is None or int(record.get("received_ms", 0)) > int(best.get("received_ms", 0)):
            best = record
    return best


def project(record: dict, level: str) -> dict:
    capsule = json.loads(record["capsule"])
    out = {
        "kind": "local_session_projection",
        "session_id": record["session_id"],
        "producer": record.get("producer"),
        "event_id": record["event_id"],
        "memory_id": record.get("memory_id"),
        "delivery_state": record.get("state"),
        "durability": "accepted_not_proven_fsynced" if record.get("state") == "accepted" else "local_only",
        "trust": "untrusted observations; neither tool use nor assistant success independently verified",
    }
    if level in ("l1", "l2"):
        if capsule.get("record_type") == "session_capsule":
            obs = capsule.get("observations", [])
            out["recent_observations"] = (
                [{"role": str(o.get("role", "unknown"))[:16],
                  "text": str(o.get("text", ""))[:350]}
                 for o in obs[-5:] if isinstance(o, dict)]
                if level == "l1" else obs
            )
        else:
            out["event_kind"] = capsule.get("event_kind")
            out["summary"] = str(capsule.get("summary", ""))[:400 if level == "l1" else 12000]
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--session-id", required=True)
    parser.add_argument("--producer", default=None, help="restrict to one explicit source")
    parser.add_argument("--level", choices=("l0", "l1", "l2"), default="l1")
    args = parser.parse_args()
    if len(args.session_id) > 128 or not args.session_id.strip():
        return 2
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    try:
        record = lookup(args.session_id, args.producer)
        if record is None:
            print(json.dumps({"found": False, "session_id": args.session_id}))
            return 1
        text = json.dumps(project(record, args.level), ensure_ascii=False, sort_keys=True)
        # The caller must explicitly ask for the larger level.
        if args.level != "l2" and len(text) > 3600:
            raise ValueError("bounded projection unexpectedly exceeded budget")
        print(text)
        return 0
    except (OSError, KeyError, ValueError, TypeError):
        print(json.dumps({"found": False, "error": "session projection unavailable"}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
