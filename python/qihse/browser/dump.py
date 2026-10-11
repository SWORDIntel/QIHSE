"""Headless dump mode — scripts, CI, and quick terminal status.

No HTTP, no WebAuthn: credentials are supplied explicitly on the command
line or via QIHSE_OPERATOR_PASSWORD, exactly like the smoke drills.  All
data still flows through authenticated Controllers — the dump is the same
client layer the bridge serves, under the same explicit principal.
"""

from __future__ import annotations

import json
import os
import sys

from ..controller import ControllerError
from .fleet import NodeSpec, SessionFleet, api_error


def run_dump(nodes: list[NodeSpec], username: str, password: str | None,
             mode: str, pattern: str = "*", timeout_ms: int = 8000,
             qkp_identity_dir: str | None = None,
             qkp_trusted_pubs: list | None = None) -> int:
    password = password or os.environ.get("QIHSE_OPERATOR_PASSWORD", "")
    if not password:
        print("no password: pass --password or set QIHSE_OPERATOR_PASSWORD",
              file=sys.stderr)
        return 2
    fleet = SessionFleet(nodes, username, password, timeout_ms=timeout_ms,
                         qkp_identity_dir=qkp_identity_dir,
                         qkp_trusted_pubs=qkp_trusted_pubs)
    try:
        try:
            fleet.connect_seed()
        except ControllerError as exc:
            print(json.dumps({"error": api_error(exc)}, indent=2))
            return 1
        if mode == "overview":
            print(json.dumps(fleet.snapshot(), indent=2, default=str))
        elif mode == "cluster":
            print(json.dumps({"topology": fleet.topology(),
                              "owners": fleet.slot_owners()},
                             indent=2, default=str))
        elif mode == "federation":
            print(json.dumps(fleet.federation(), indent=2, default=str))
        elif mode == "keys":
            from . import keyspace
            listing = keyspace.browse(fleet, pattern=pattern)
            for entry in listing["keys"]:
                print(f"{entry['node']}\t{entry['key']}")
            if listing["truncated"]:
                print(f"-- truncated (cap reached; refine --pattern)",
                      file=sys.stderr)
        else:
            print(f"unknown dump mode {mode!r} "
                  f"(overview|cluster|federation|keys)", file=sys.stderr)
            return 2
        return 0
    finally:
        fleet.close()
