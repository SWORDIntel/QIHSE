#!/usr/bin/env python3
"""Ingest an authorized QIHSE JSONL export into local QIHSE AI memory.

The bridge intentionally has no QIHSE database reader. QIHSE data must arrive
through an authenticated export performed by a separately configured client.
100% sovereign local backend; no cloud calls or remote mirrors.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import ipaddress
import json
import os
import socket
import sys
from pathlib import Path
from typing import Any

from repo_relations import canonical_repo_name

MAX_LINE_BYTES = 1024 * 1024  # 1 MiB bounded line size


def _is_loopback(host: str) -> bool:
    if host.lower() in ("localhost", "127.0.0.1", "::1"):
        return True
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_loopback
    except ValueError:
        return False


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--input", required=True, type=Path, help="authorized QIHSE JSONL export"
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="validate without network writes"
    )
    parser.add_argument(
        "--backend",
        choices=("qihse",),
        default="qihse",
        help="authoritative destination (strictly local qihse)",
    )
    parser.add_argument(
        "--state", type=Path, help="resume ledger for completed input lines"
    )
    parser.add_argument(
        "--manifest", type=Path, help="QIHSE export manifest with principal and digest"
    )
    parser.add_argument(
        "--allow-remote-host",
        action="store_true",
        help="allow non-loopback QIHSE_RESP_HOST (default: loopback only)",
    )
    return parser


def _compute_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def _record(raw: str, line_no: int) -> dict[str, Any]:
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"line {line_no}: invalid JSON: {exc.msg}") from exc
    if (
        not isinstance(value, dict)
        or not isinstance(value.get("text"), str)
        or not value["text"].strip()
    ):
        raise ValueError(
            f"line {line_no}: expected an object with non-empty string text"
        )
    metadata = value.get("metadata", {})
    if not isinstance(metadata, dict):
        raise ValueError(f"line {line_no}: metadata must be an object")
    return value


def _iter_records(path: Path):
    """Stream records line-by-line with bounded line size to prevent OOM."""
    with path.open("rb") as f:
        line_no = 0
        while True:
            raw = f.readline(MAX_LINE_BYTES + 1)
            if not raw:
                break
            if len(raw) > MAX_LINE_BYTES:
                raise ValueError(
                    f"line {line_no + 1} exceeds maximum line size ({MAX_LINE_BYTES} bytes)"
                )
            line_no += 1
            try:
                line = raw.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise ValueError(f"line {line_no}: invalid UTF-8: {exc}") from exc
            stripped = line.strip()
            if stripped:
                yield line_no, _record(stripped, line_no)


def _resp(*parts: str) -> bytes:
    encoded = [f"*{len(parts)}\r\n".encode()]
    for part in parts:
        data = part.encode("utf-8")
        encoded.extend((f"${len(data)}\r\n".encode(), data, b"\r\n"))
    return b"".join(encoded)


def _resp_read(sock: socket.socket) -> str:
    data = bytearray()
    while b"\r\n" not in data:
        chunk = sock.recv(4096)
        if not chunk:
            raise RuntimeError("QIHSE closed the RESP connection")
        data.extend(chunk)
        if len(data) > 1_048_576:
            raise RuntimeError("QIHSE RESP reply exceeded 1 MiB")
    line, _, rest = data.partition(b"\r\n")
    if line.startswith((b"+", b"-", b":")):
        return line[1:].decode("utf-8", "replace")
    if line.startswith(b"$"):
        size = int(line[1:])
        while len(rest) < size + 2:
            chunk = sock.recv(4096)
            if not chunk:
                raise RuntimeError("QIHSE truncated RESP bulk reply")
            rest.extend(chunk)
        return bytes(rest[:size]).decode("utf-8", "replace")
    raise RuntimeError("unsupported QIHSE RESP reply")


def _qihse_send(sock, *parts: str) -> str:
    if hasattr(sock, "command"):
        result = sock.command(*parts)
        if not isinstance(result, str):
            raise RuntimeError("unexpected AIMEM reply type")
        return result
    sock.sendall(_resp(*parts))
    reply = _resp_read(sock)
    if reply.startswith(("ERR", "NOAUTH", "NOPERM")):
        raise RuntimeError(f"QIHSE refused command: {reply[:200]}")
    return reply


class _QKPConnection:
    """A pinned QKP session bound to the AIMEM_SERVICE user (never operator)."""

    def __init__(self, host: str, port: int, username: str, password: str):
        sdk_path = os.environ.get("QIHSE_ADMIN_SDK")
        lib_path = os.environ.get("QIHSE_ADMIN_LIB")
        identity = os.environ.get("QIHSE_AIMEM_IDENTITY_DIR")
        pin = os.environ.get("QIHSE_AIMEM_TRUSTED_PUB")
        node_id = os.environ.get("QIHSE_AIMEM_NODE_ID")
        if not all((sdk_path, lib_path, identity, pin, node_id)) or not Path(sdk_path).is_file() or not Path(lib_path).is_file():
            raise RuntimeError("QKP requires an installed SDK/library, identity, server pin and node ID")
        spec = importlib.util.spec_from_file_location("qihse_aimem_admin_sdk", sdk_path)
        if spec is None or spec.loader is None:
            raise RuntimeError("QKP admin SDK unavailable")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        admin = module.ClusterAdmin(node_id=node_id, identity_dir=identity,
                                    lib_path=lib_path)
        if not admin.is_native or admin._lib._qihse_lib_path != os.path.abspath(lib_path):
            raise RuntimeError("QKP admin library unavailable; refusing fallback")
        try:
            self._session = admin.session(host, port, pin, user=username, password=password,
                                          timeout_ms=60000)
        except module.QihseAdminError as exc:
            raise RuntimeError("QKP AIMEM authentication or connection failed") from exc

    def command(self, *parts: str):
        try:
            value = self._session.execute(*parts)
        except Exception as exc:
            raise RuntimeError("QKP AIMEM command failed") from exc
        def decode(item):
            if isinstance(item, bytes):
                return item.decode("utf-8")
            if isinstance(item, list):
                return [decode(child) for child in item]
            return item
        return decode(value)

    def close(self):
        self._session.close()


def _qihse_command(sock, *parts: str):
    if hasattr(sock, "command"):
        return sock.command(*parts)
    from recall import _Reader
    sock.sendall(_resp(*parts))
    return _Reader(sock).value()


def _qihse_connect(allow_remote: bool = False):
    transport = os.environ.get("QIHSE_AIMEM_TRANSPORT", "qkp")
    if transport not in ("resp", "qkp"):
        raise RuntimeError("invalid QIHSE_AIMEM_TRANSPORT")
    host = os.environ.get("QIHSE_RESP_HOST", "127.0.0.1")
    port_value = os.environ.get("QIHSE_RESP_PORT", "6401")
    username = os.environ.get("QIHSE_AUTH_USER")
    password = os.environ.get("QIHSE_AUTH_PASSWORD")
    if not host or not port_value or not username or not password:
        raise RuntimeError(
            "QIHSE_RESP_HOST, QIHSE_RESP_PORT, QIHSE_AUTH_USER, and "
            "QIHSE_AUTH_PASSWORD are required"
        )
    allow_env = os.environ.get("QIHSE_ALLOW_REMOTE", "").lower() in ("1", "true", "yes")
    if not allow_remote and not allow_env and not _is_loopback(host):
        raise RuntimeError(
            f"refusing non-loopback QIHSE_RESP_HOST {host}; set QIHSE_ALLOW_REMOTE=1 or pass --allow-remote-host to override"
        )
    try:
        port = int(port_value)
    except ValueError as exc:
        raise RuntimeError("QIHSE_RESP_PORT must be an integer") from exc
    if username != "AIMEM_SERVICE":
        raise RuntimeError("AIMEM_SERVICE principal required")
    if transport == "qkp":
        return _QKPConnection(host, port, username, password)
    sock = socket.create_connection((host, port), timeout=30)
    try:
        reply = _qihse_send(sock, "AUTH", username, password)
        if reply != "OK":
            raise RuntimeError("QIHSE authentication failed")
    except Exception:
        sock.close()
        raise
    return sock


def _qihse_payload(item: dict[str, Any]) -> str:
    envelope = {
        "source": "supermemory-qihse-bridge",
        "text": item["text"],
        "id": item.get("id"),
        "metadata": item.get("metadata", {}),
        "classification": item.get("classification"),
    }
    payload = json.dumps(envelope, separators=(",", ":"), ensure_ascii=False)
    if len(payload.encode("utf-8")) > 256 * 1024:
        raise RuntimeError("QIHSE AIMEM payload exceeds 256 KiB")
    return payload


def _qihse_store(sock: socket.socket, item: dict[str, Any]) -> str:
    source_id = item.get("id")
    if not isinstance(source_id, str) or not source_id:
        raise RuntimeError(
            "each record needs a stable source id for idempotent QIHSE storage"
        )
    kind = os.environ.get("QIHSE_AIMEM_KIND", "2")
    metadata = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
    project = os.environ.get("QIHSE_AIMEM_PROJECT", "").strip()
    if not project:
        project = str(metadata.get("repo") or metadata.get("repository") or "global").strip()
    project = canonical_repo_name(project)
    if not project:
        raise RuntimeError("QIHSE_AIMEM_PROJECT or record repository metadata is required")
    return _qihse_send(sock, "AIMEM", "STORE-SCOPED-DURABLE", kind,
                       _qihse_payload(item), project, "", "", "", source_id)


def main() -> int:
    args = _parser().parse_args()
    if args.input.is_dir():
        print(
            "refusing a directory; provide an authorized JSONL export", file=sys.stderr
        )
        return 2
    if not args.input.is_file():
        print(f"input file does not exist: {args.input}", file=sys.stderr)
        return 2

    if args.manifest:
        try:
            manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
            digest = _compute_sha256(args.input)
            principal = manifest.get("principal")
            tenant = manifest.get("tenant")
            if (
                not isinstance(principal, str)
                or not principal
                or not isinstance(tenant, int)
            ):
                raise ValueError("manifest requires principal and integer tenant")
            if manifest.get("export_sha256") != digest:
                raise ValueError("manifest digest does not match input")
            configured_user = os.environ.get("QIHSE_AUTH_USER")
            if configured_user and configured_user != principal:
                raise ValueError("manifest principal does not match QIHSE_AUTH_USER")
        except (OSError, json.JSONDecodeError, TypeError, ValueError) as exc:
            print(f"invalid export manifest: {exc}", file=sys.stderr)
            return 2

    if args.dry_run:
        count = 0
        try:
            for line_no, item in _iter_records(args.input):
                source_id = item.get("id")
                if not isinstance(source_id, str) or not source_id:
                    print(
                        f"line {line_no}: QIHSE ingestion requires a stable string id on every record",
                        file=sys.stderr,
                    )
                    return 2
                count += 1
        except (OSError, ValueError) as exc:
            print(f"validation failed: {exc}", file=sys.stderr)
            return 2
        print(f"validated {count} authorized export records; no writes performed")
        return 0

    qihse = None
    try:
        qihse = _qihse_connect(allow_remote=args.allow_remote_host)
    except (OSError, RuntimeError) as exc:
        print(f"QIHSE connection refused: {exc}", file=sys.stderr)
        return 2

    start_line = 0
    if args.state and args.state.exists():
        try:
            saved = json.loads(args.state.read_text(encoding="utf-8"))
            start_line = int(saved.get("next_line", 0))
        except (OSError, ValueError, TypeError, AttributeError):
            print("invalid resume ledger", file=sys.stderr)
            return 2

    sent = 0
    try:
        for line_no, item in _iter_records(args.input):
            if line_no < start_line:
                continue
            source_id = item.get("id")
            if not isinstance(source_id, str) or not source_id:
                print(
                    f"line {line_no}: QIHSE ingestion requires a stable string id on every record",
                    file=sys.stderr,
                )
                return 2
            _qihse_store(qihse, item)
            sent += 1
            if args.state:
                tmp = args.state.with_name(args.state.name + ".tmp")
                tmp.write_text(
                    json.dumps({"next_line": line_no + 1}) + "\n", encoding="utf-8"
                )
                tmp.replace(args.state)
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"write stopped after {sent} records: {exc}", file=sys.stderr)
        return 1
    finally:
        if qihse is not None:
            qihse.close()
    print(f"stored {sent} records using {args.backend} backend")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
