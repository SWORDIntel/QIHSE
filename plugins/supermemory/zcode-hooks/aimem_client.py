#!/usr/bin/env python3
"""Shared AIMEM RESP client for the ZCode supermemory hooks.

Loads the mode-0600 env file (QIHSE_AIMEM_ENV or
~/.config/qihse-aimem/env), authenticates once per process, and issues
AIMEM commands. Failures raise AimemError; hooks turn those into
silent no-ops so a backend outage never blocks a session.
"""

from __future__ import annotations

import importlib.util
import json
import os
import socket
from pathlib import Path


class AimemError(RuntimeError):
    pass


def load_env() -> None:
    env_path = os.environ.get("QIHSE_AIMEM_ENV") or str(
        Path.home() / ".config" / "qihse-aimem" / "env")
    path = Path(env_path)
    try:
        st = path.lstat()
    except FileNotFoundError as exc:
        raise AimemError(f"env file missing: {path}") from exc
    if not path.is_file() or path.is_symlink():
        raise AimemError("env file must be a regular non-symlink file")
    if st.st_mode & 0o077 or st.st_uid != os.getuid():
        raise AimemError("env file must be owned by this user and mode 0600")
    allowed = {
        "QIHSE_RESP_HOST", "QIHSE_RESP_PORT", "QIHSE_AUTH_USER",
        "QIHSE_AUTH_PASSWORD", "QIHSE_AIMEM_PROJECT",
        "QIHSE_AIMEM_HOOK_TIMEOUT", "QIHSE_AIMEM_TRANSPORT",
        "QIHSE_ADMIN_SDK", "QIHSE_ADMIN_LIB", "QIHSE_AIMEM_IDENTITY_DIR",
        "QIHSE_AIMEM_TRUSTED_PUB", "QIHSE_AIMEM_NODE_ID",
    }
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        if key in allowed:
            os.environ.setdefault(key, value.strip())


class Aimem:
    def __init__(self) -> None:
        load_env()
        host = os.environ["QIHSE_RESP_HOST"]
        port = int(os.environ["QIHSE_RESP_PORT"])
        try:
            timeout = max(0.2, min(10.0, float(os.environ.get("QIHSE_AIMEM_HOOK_TIMEOUT", "2"))))
        except ValueError as exc:
            raise AimemError("invalid hook timeout") from exc
        if host not in ("127.0.0.1", "localhost", "::1"):
            raise AimemError("AIMEM hook requires loopback endpoint")
        if os.environ.get("QIHSE_AUTH_USER") != "AIMEM_SERVICE":
            raise AimemError("AIMEM_SERVICE principal required")
        transport = os.environ.get("QIHSE_AIMEM_TRANSPORT", "qkp")
        if transport not in ("resp", "qkp"):
            raise AimemError("invalid AIMEM transport")
        self.sock = None
        self._session = None
        if transport == "qkp":
            sdk = os.environ.get("QIHSE_ADMIN_SDK")
            lib = os.environ.get("QIHSE_ADMIN_LIB")
            identity = os.environ.get("QIHSE_AIMEM_IDENTITY_DIR")
            pin = os.environ.get("QIHSE_AIMEM_TRUSTED_PUB")
            node_id = os.environ.get("QIHSE_AIMEM_NODE_ID")
            if not all((sdk, lib, identity, pin, node_id)) or not Path(sdk).is_file() or not Path(lib).is_file():
                raise AimemError("QKP requires installed SDK, library, identity, pin and node ID")
            spec = importlib.util.spec_from_file_location("qihse_aimem_admin_sdk", sdk)
            if not spec or not spec.loader:
                raise AimemError("QKP admin SDK unavailable")
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            admin = module.ClusterAdmin(node_id=node_id, identity_dir=identity, lib_path=lib)
            if not admin.is_native or admin._lib._qihse_lib_path != os.path.abspath(lib):
                raise AimemError("QKP admin library unavailable; refusing fallback")
            self._session = admin.session(host, port, pin, user="AIMEM_SERVICE",
                                          password=os.environ["QIHSE_AUTH_PASSWORD"],
                                          timeout_ms=60000)
        else:
            self.sock = socket.create_connection((host, port), timeout=timeout)
            self.sock.settimeout(timeout)
        self._buf = bytearray()
        project = os.environ.get("QIHSE_AIMEM_PROJECT", "").strip().lower()
        if not project:
            project = Path.cwd().name.lower() or "global"
        self.scope = (project, "", "", "")
        if self.sock is not None:
            self._cmd("AUTH", os.environ["QIHSE_AUTH_USER"],
                      os.environ["QIHSE_AUTH_PASSWORD"])

    def _send(self, *parts: str) -> None:
        out = bytearray(b"*%d\r\n" % len(parts))
        for p in parts:
            data = p.encode("utf-8")
            out += b"$%d\r\n%s\r\n" % (len(data), data)
        self.sock.sendall(out)

    def _read(self, size: int) -> bytes:
        while len(self._buf) < size:
            chunk = self.sock.recv(8192)
            if not chunk:
                raise AimemError("connection closed")
            self._buf.extend(chunk)
        out = bytes(self._buf[:size])
        del self._buf[:size]
        return out

    def _line(self) -> bytes:
        while b"\r\n" not in self._buf:
            if len(self._buf) > 65536:
                raise AimemError("RESP header too long")
            chunk = self.sock.recv(8192)
            if not chunk:
                raise AimemError("connection closed")
            self._buf.extend(chunk)
        i = self._buf.index(b"\r\n")
        line = bytes(self._buf[:i])
        del self._buf[:i + 2]
        return line

    def _value(self):
        prefix = self._line()
        if prefix == b"$-1":
            return None
        if prefix.startswith(b"$"):
            size = int(prefix[1:])
            if size < 0 or size > 2 * 1024 * 1024:
                raise AimemError("RESP bulk reply exceeds limit")
            data = self._read(size)
            if self._read(2) != b"\r\n":
                raise AimemError("malformed RESP bulk terminator")
            return data.decode("utf-8", "replace")
        if prefix.startswith(b":"):
            return int(prefix[1:])
        if prefix.startswith(b"*"):
            n = int(prefix[1:])
            if n < 0 or n > 256:
                raise AimemError("bad reply arity")
            return [self._value() for _ in range(n)]
        text = prefix[1:].decode("utf-8", "replace")
        if prefix.startswith(b"-"):
            raise AimemError(text)
        return text

    def _cmd(self, *parts: str):
        if self._session is not None:
            value = self._session.execute(*parts)
            def decode(item):
                if isinstance(item, bytes):
                    return item.decode("utf-8")
                if isinstance(item, list):
                    return [decode(child) for child in item]
                return item
            return decode(value)
        self._send(*parts)
        return self._value()

    def recall(self, query: str, limit: int = 3, mode: str = "bm25") -> list:
        value = self._cmd("AIMEM", "RECALL-SCOPED", query, str(limit), mode,
                          "0", *self.scope)
        hits = []
        for f in value or []:
            if isinstance(f, list) and len(f) == 7:
                hits.append({
                    "id": f[0], "created_ms": int(f[1]), "kind": int(f[2]),
                    "classification": int(f[3]), "sci": int(f[4]),
                    "score": float(f[5]), "text": f[6],
                })
        return hits

    def get(self, memory_id: str) -> dict | None:
        if not isinstance(memory_id, str) or not memory_id or len(memory_id) > 128:
            raise AimemError("invalid memory id")
        fields = self._cmd("AIMEM", "GET-SCOPED", memory_id, *self.scope)
        if fields is None:
            return None
        if not isinstance(fields, list) or len(fields) != 7:
            raise AimemError("malformed AIMEM GET response")
        return {
            "id": fields[0], "created_ms": int(fields[1]), "kind": int(fields[2]),
            "classification": int(fields[3]), "sci": int(fields[4]),
            "score": float(fields[5]), "text": fields[6],
        }

    def store(self, text: str, kind: int = 1, idem: str = "") -> str:
        if not isinstance(text, str) or not text.strip() or len(text.encode("utf-8")) > 256 * 1024:
            raise AimemError("memory body exceeds limit or is empty")
        if kind not in (1, 2) or not isinstance(idem, str) or len(idem.encode("utf-8")) > 128:
            raise AimemError("invalid memory kind/idempotency key")
        parts = ["AIMEM", "STORE-SCOPED-DURABLE", str(kind), text,
                 *self.scope]
        if idem:
            parts.append(idem)
        memory_id = self._cmd(*parts)
        if not isinstance(memory_id, str) or not memory_id:
            raise AimemError("store returned no id")
        return memory_id

    def close(self) -> None:
        if self._session is not None:
            self._session.close()
            self._session = None
        if self.sock is not None:
            self.sock.close()
            self.sock = None
