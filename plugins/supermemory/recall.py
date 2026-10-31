#!/usr/bin/env python3
"""Recall authorized QIHSE AI memories as JSON."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from sync import _qihse_connect, _qihse_command


def _load_env_file() -> None:
    env_path = os.environ.get("QIHSE_AIMEM_ENV") or str(Path.home() / ".config" / "qihse-aimem" / "env")
    path = Path(env_path)
    if not path.is_file():
        return
    st = path.lstat()
    if path.is_symlink() or st.st_uid != os.getuid() or st.st_mode & 0o077:
        raise RuntimeError("env file must be user-owned, non-symlink, and mode 0600")
    allowed = {
        "QIHSE_RESP_HOST", "QIHSE_RESP_PORT", "QIHSE_AUTH_USER",
        "QIHSE_AUTH_PASSWORD", "QIHSE_AIMEM_PROJECT",
        "QIHSE_AIMEM_TRANSPORT", "QIHSE_ADMIN_SDK", "QIHSE_ADMIN_LIB",
        "QIHSE_AIMEM_IDENTITY_DIR", "QIHSE_AIMEM_TRUSTED_PUB", "QIHSE_AIMEM_NODE_ID",
    }
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        if key in allowed:
            os.environ.setdefault(key, value.strip())

    host = os.environ.get("QIHSE_RESP_HOST", "127.0.0.1").strip()
    if host not in ("127.0.0.1", "localhost", "::1"):
        raise RuntimeError(f"Security error: non-loopback QIHSE_RESP_HOST '{host}' rejected. Must be 127.0.0.1.")


def _parse() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("query")
    parser.add_argument("--limit", type=int, default=8)
    parser.add_argument("--mode", choices=("bm25", "semantic", "hybrid"), default="bm25")
    parser.add_argument("--kind", type=int, choices=(0, 1, 2), default=0)
    parser.add_argument(
        "--scope",
        default="auto",
        help="Native project scope: auto/current repo, global project, repo/current repo, or project name",
    )
    return parser.parse_args()


class _Reader:
    MAX_HEADER = 64 * 1024
    MAX_BULK = 2 * 1024 * 1024
    MAX_TOTAL = 32 * 1024 * 1024

    def __init__(self, sock):
        self.sock = sock
        self.buf = bytearray()
        self.received = 0

    def _need(self, size: int) -> None:
        if size < 0 or size > self.MAX_BULK + 2:
            raise RuntimeError("QIHSE RESP field exceeds configured limit")
        while len(self.buf) < size:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise RuntimeError("QIHSE closed the RESP connection")
            self.received += len(chunk)
            if self.received > self.MAX_TOTAL:
                raise RuntimeError("QIHSE RESP reply exceeds total response limit")
            self.buf.extend(chunk)

    def line(self) -> bytes:
        while b"\r\n" not in self.buf:
            if len(self.buf) > self.MAX_HEADER:
                raise RuntimeError("QIHSE RESP header exceeds limit")
            self._need(len(self.buf) + 1)
        index = self.buf.index(b"\r\n")
        if index > self.MAX_HEADER:
            raise RuntimeError("QIHSE RESP header exceeds limit")
        value = bytes(self.buf[:index])
        del self.buf[:index + 2]
        return value

    def bytes(self, size: int) -> bytes:
        self._need(size)
        value = bytes(self.buf[:size])
        del self.buf[:size]
        return value

    def value(self):
        prefix = self.line()
        if prefix == b"$-1":
            return None
        if prefix.startswith(b"$"):
            size = int(prefix[1:])
            if size < 0 or size > self.MAX_BULK:
                raise RuntimeError("QIHSE RESP bulk exceeds limit")
            data = self.bytes(size)
            if self.bytes(2) != b"\r\n":
                raise RuntimeError("malformed QIHSE RESP terminator")
            return data.decode("utf-8", "replace")
        if prefix.startswith(b":"):
            return int(prefix[1:])
        if prefix.startswith(b"*"):
            count = int(prefix[1:])
            if count < 0 or count > 256:
                raise RuntimeError("QIHSE returned an invalid recall count")
            values = []
            for _ in range(count):
                values.append(self.value())
            return values
        if prefix.startswith((b"+", b"-")):
            value = prefix[1:].decode("utf-8", "replace")
            if prefix.startswith(b"-"):
                raise RuntimeError(value)
            return value
        raise RuntimeError("unsupported QIHSE RESP response")


def main() -> int:
    args = _parse()
    if args.limit < 1 or args.limit > 256:
        print("--limit must be between 1 and 256", file=sys.stderr)
        return 2
    _load_env_file()
    sock = None
    try:
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        from repo_relations import canonical_repo_name, get_current_repo, parse_memory_hit

        current_repo, _ = get_current_repo()
        requested = args.scope.strip().lower()
        project = "global" if requested == "global" else (
            current_repo if requested in ("auto", "repo") else requested)
        project = canonical_repo_name(project or "global")
        fetch_limit = min(256, max(args.limit * 4, 32))
        sock = _qihse_connect()
        value = _qihse_command(sock, "AIMEM", "RECALL-SCOPED", args.query,
                               str(fetch_limit), args.mode, str(args.kind),
                               project, "", "", "")
        records = []
        for fields in value or []:
            if not isinstance(fields, list) or len(fields) != 7:
                raise RuntimeError("QIHSE returned a malformed memory hit")
            records.append(parse_memory_hit(fields))

        hits = []
        for record in records[:args.limit]:
            record["adjusted_score"] = record["score"]
            record["matched_scope"] = project
            hits.append(record)
        print(json.dumps(hits, ensure_ascii=False))
        return 0
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"QIHSE recall failed: {exc}", file=sys.stderr)
        return 1
    finally:
        if sock is not None:
            sock.close()


if __name__ == "__main__":
    raise SystemExit(main())
