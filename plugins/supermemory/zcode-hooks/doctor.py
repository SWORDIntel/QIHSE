#!/usr/bin/env python3
"""Content-free health probe for QIHSE-backed Supermemory hooks."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import stat
import sys
import time


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--online", action="store_true", help="authenticate and count this principal's visible memories")
    args = parser.parse_args()
    root = Path(__file__).resolve().parent
    sys.path.insert(0, str(root))
    from lifecycle import PipelineError, status
    result = {"schema_version": 1, "python": sys.version.split()[0], "healthy": True}
    for name in ("capture_hook.py", "recall_hook.py", "lifecycle.py", "external_capture.py", "session_brief.py", "context.py", "aimem_client.py"):
        result["module:" + name] = (root / name).is_file()
        if not result["module:" + name]:
            result["healthy"] = False
    try:
        result["spool"] = status()
    except (OSError, PipelineError):
        result["spool"] = "invalid permissions or unavailable"
        result["healthy"] = False
    env = Path(os.environ.get("QIHSE_AIMEM_ENV") or str(Path.home() / ".config" / "qihse-aimem" / "env"))
    if env.exists():
        metadata = env.lstat()
        result["credentials_protected"] = (
            stat.S_ISREG(metadata.st_mode)
            and not env.is_symlink() and metadata.st_uid == os.getuid()
            and metadata.st_mode & 0o077 == 0
        )
        if not result["credentials_protected"]:
            result["healthy"] = False
    else:
        result["credentials_protected"] = None
    if args.online:
        try:
            from aimem_client import Aimem
            started = time.monotonic()
            client = Aimem()
            try:
                # Return no records or content. This count is caller-authorized.
                result["visible_memory_count"] = int(
                    client._cmd("AIMEM", "COUNT-SCOPED", *client.scope, "0"))
            finally:
                client.close()
            result["qihse_rtt_ms"] = round((time.monotonic() - started) * 1000, 1)
            result["authenticated"] = True
        except Exception as exc:
            result["authenticated"] = False
            result["error_type"] = type(exc).__name__
            result["healthy"] = False
    print(json.dumps(result, sort_keys=True))
    return 0 if result["healthy"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
