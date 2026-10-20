#!/usr/bin/env python3
"""Restartable authenticated migration of legacy AIMEM records.

The server inventory contract used here is::

    AIMEM LEGACY SCAN <cursor> <count>
    -> [<next-cursor>, [<legacy-uuid>, ...]]

The next cursor is ``0`` at end of scan.  A flat response containing the
cursor followed by UUIDs is also accepted to simplify staged deployments.
Record contents are never requested during inventory and are never logged.

Version 2 manifests bind every record to one non-Operator target principal.
Migration uses ``AIMEM MIGRATE-LEGACY-TO <uuid> <target-user-id> ...``; an
exact retry validates target ownership and scope without disclosing content.
"""

from __future__ import annotations

import argparse
import getpass
import hashlib
import json
import os
import re
import socket
import stat
import sys
import tempfile
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


MAX_BATCH = 1000
MAX_INVENTORY = 1_000_000
MAX_USER_ID = 65535
SCOPE_RE = re.compile(r"^[A-Za-z0-9_.-]{1,63}$")


class MigrationError(Exception):
    pass


class RespError(MigrationError):
    pass


class RespClient:
    def __init__(self, host: str, port: int, timeout: float) -> None:
        self._sock = socket.create_connection((host, port), timeout=timeout)
        self._sock.settimeout(timeout)
        self._reader = self._sock.makefile("rb")

    def close(self) -> None:
        try:
            self._reader.close()
        finally:
            self._sock.close()

    def command(self, *args: str) -> Any:
        encoded = [arg.encode("utf-8") for arg in args]
        request = [f"*{len(encoded)}\r\n".encode()]
        for value in encoded:
            request.extend((f"${len(value)}\r\n".encode(), value, b"\r\n"))
        self._sock.sendall(b"".join(request))
        return self._read_reply()

    def _line(self) -> bytes:
        line = self._reader.readline(65538)
        if not line or len(line) > 65537 or not line.endswith(b"\r\n"):
            raise RespError("truncated or oversized RESP line")
        return line[:-2]

    def _read_reply(self) -> Any:
        marker = self._reader.read(1)
        if not marker:
            raise RespError("server closed the RESP connection")
        if marker == b"+":
            return self._line().decode("utf-8", "strict")
        if marker == b"-":
            raise RespError(self._line().decode("utf-8", "replace"))
        if marker == b":":
            return int(self._line())
        if marker == b"$":
            size = int(self._line())
            if size == -1:
                return None
            if size < 0 or size > 16 * 1024 * 1024:
                raise RespError("invalid RESP bulk length")
            value = self._reader.read(size)
            if len(value) != size or self._reader.read(2) != b"\r\n":
                raise RespError("truncated RESP bulk value")
            return value.decode("utf-8", "strict")
        if marker == b"*":
            count = int(self._line())
            if count < 0 or count > MAX_BATCH + 1:
                raise RespError("invalid RESP array length")
            return [self._read_reply() for _ in range(count)]
        raise RespError("unsupported RESP reply type")


@dataclass(frozen=True, order=True)
class ManifestRecord:
    record_id: str
    project: str
    worktree: str
    workstream: str
    session: str

    @property
    def scope(self) -> tuple[str, str, str, str]:
        return self.project, self.worktree, self.workstream, self.session


@dataclass(frozen=True)
class MigrationManifest:
    target_user_id: int
    records: tuple[ManifestRecord, ...]
    digest: str


def _canonical_uuid(value: Any, ordinal: int) -> str:
    if not isinstance(value, str):
        raise MigrationError(f"manifest record {ordinal} has a non-string uuid")
    try:
        canonical = str(uuid.UUID(value))
    except (ValueError, AttributeError) as exc:
        raise MigrationError(f"manifest record {ordinal} has an invalid uuid") from exc
    if value != canonical:
        raise MigrationError(f"manifest record {ordinal} uuid is not canonical lowercase")
    return canonical


def _scope_value(item: dict[str, Any], name: str, ordinal: int, required: bool) -> str:
    value = item.get(name, "")
    if not isinstance(value, str) or (required and not value) or (value and not SCOPE_RE.fullmatch(value)):
        raise MigrationError(f"manifest record {ordinal} has an invalid {name}")
    return value


def load_manifest(path: Path) -> MigrationManifest:
    raw = path.read_bytes()
    try:
        document = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise MigrationError("manifest is not valid UTF-8 JSON") from exc
    if not isinstance(document, dict) or document.get("version") != 2:
        raise MigrationError("manifest must be an object with version 2")
    target_user_id = document.get("target_user_id")
    if (isinstance(target_user_id, bool) or not isinstance(target_user_id, int) or
            not 1 <= target_user_id <= MAX_USER_ID):
        raise MigrationError(
            f"manifest target_user_id must be an integer between 1 and {MAX_USER_ID}")
    rows = document.get("records")
    if not isinstance(rows, list) or not rows:
        raise MigrationError("manifest records must be a non-empty array")
    records: list[ManifestRecord] = []
    seen: set[str] = set()
    for ordinal, item in enumerate(rows, 1):
        if not isinstance(item, dict):
            raise MigrationError(f"manifest record {ordinal} is not an object")
        if "target_user_id" in item:
            raise MigrationError(
                f"manifest record {ordinal} must not override target_user_id")
        record_id = _canonical_uuid(item.get("uuid"), ordinal)
        if record_id in seen:
            raise MigrationError(f"manifest contains duplicate uuid at record {ordinal}")
        seen.add(record_id)
        project = _scope_value(item, "project", ordinal, True)
        worktree = _scope_value(item, "worktree", ordinal, False)
        workstream = _scope_value(item, "workstream", ordinal, False)
        session = _scope_value(item, "session", ordinal, False)
        if workstream and not worktree:
            raise MigrationError(f"manifest record {ordinal} has workstream without worktree")
        if session and not workstream:
            raise MigrationError(f"manifest record {ordinal} has session without workstream")
        records.append(ManifestRecord(record_id, project, worktree, workstream, session))
    records.sort()
    digest = hashlib.sha256(raw).hexdigest()
    return MigrationManifest(target_user_id, tuple(records), digest)


def authenticate(client: RespClient, username: str, password: str) -> None:
    reply = client.command("AUTH", username, password)
    if reply != "OK":
        raise MigrationError("authentication did not return OK")


def scan_legacy(client: RespClient, batch_size: int) -> set[str]:
    cursor = "0"
    seen_cursors: set[str] = set()
    inventory: set[str] = set()
    while True:
        reply = client.command("AIMEM", "LEGACY", "SCAN", cursor, str(batch_size))
        if not isinstance(reply, list) or len(reply) < 1:
            raise MigrationError("AIMEM LEGACY SCAN returned an invalid response")
        next_cursor = reply[0]
        values: Iterable[Any]
        if len(reply) == 2 and isinstance(reply[1], list):
            values = reply[1]
        else:
            values = reply[1:]
        if not isinstance(next_cursor, (str, int)):
            raise MigrationError("AIMEM LEGACY SCAN returned an invalid cursor")
        for value in values:
            record_id = _canonical_uuid(value, len(inventory) + 1)
            if record_id in inventory:
                raise MigrationError("AIMEM LEGACY SCAN returned a duplicate uuid")
            inventory.add(record_id)
            if len(inventory) > MAX_INVENTORY:
                raise MigrationError("legacy inventory exceeds the migration safety bound")
        cursor = str(next_cursor)
        if cursor == "0":
            return inventory
        if cursor in seen_cursors:
            raise MigrationError("AIMEM LEGACY SCAN repeated a cursor")
        seen_cursors.add(cursor)


def preflight(client: RespClient, manifest: MigrationManifest,
              batch_size: int) -> list[ManifestRecord]:
    records = manifest.records
    by_id = {record.record_id: record for record in records}
    legacy = scan_legacy(client, batch_size)
    unmanaged = legacy.difference(by_id)
    if unmanaged:
        raise MigrationError(f"preflight found {len(unmanaged)} legacy record(s) absent from manifest")

    pending: list[ManifestRecord] = []
    for ordinal, record in enumerate(records, 1):
        if record.record_id in legacy:
            pending.append(record)
            continue
        # The destination is in the target principal's tenant, so an
        # operator-side GET-SCOPED cannot address it. MIGRATE-LEGACY-TO is an
        # exact replay check when the legacy source is absent: it verifies the
        # target owner and full scope without returning record content or
        # mutating an already migrated record.
        try:
            reply = client.command(
                "AIMEM", "MIGRATE-LEGACY-TO", record.record_id,
                str(manifest.target_user_id), *record.scope)
        except RespError as exc:
            raise MigrationError(
                f"manifest record {ordinal} is neither legacy nor present at its exact destination") from exc
        if reply != record.record_id:
            raise MigrationError(
                f"manifest record {ordinal} failed exact destination validation")
    return pending


def load_checkpoint(path: Path, manifest: MigrationManifest) -> int:
    if not path.exists():
        return 0
    try:
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags)
        try:
            metadata = os.fstat(descriptor)
            if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid() or
                    metadata.st_mode & 0o077):
                raise MigrationError(
                    "checkpoint must be an owner-only regular file owned by this user")
            with os.fdopen(descriptor, "r", encoding="utf-8") as stream:
                descriptor = -1
                state = json.load(stream)
        finally:
            if descriptor >= 0:
                os.close(descriptor)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise MigrationError("checkpoint is unreadable") from exc
    if (not isinstance(state, dict) or state.get("version") != 2 or
            state.get("manifest_sha256") != manifest.digest or
            state.get("target_user_id") != manifest.target_user_id):
        raise MigrationError("checkpoint does not match this manifest")
    completed = state.get("completed", 0)
    total = len(manifest.records)
    if state.get("total") != total or not isinstance(completed, int) or not 0 <= completed <= total:
        raise MigrationError("checkpoint completed count is invalid")
    return completed


def save_checkpoint(path: Path, manifest: MigrationManifest,
                    completed: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    total = len(manifest.records)
    state = {"version": 2, "manifest_sha256": manifest.digest,
             "target_user_id": manifest.target_user_id,
             "completed": completed, "total": total}
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            descriptor = -1
            json.dump(state, stream, sort_keys=True, separators=(",", ":"))
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def emit(event: str, **counts: int) -> None:
    print(json.dumps({"event": event, **counts}, sort_keys=True, separators=(",", ":")), flush=True)


def migrate(client: RespClient, manifest: MigrationManifest,
            pending: list[ManifestRecord], batch_size: int,
            checkpoint: Path, initial_completed: int,
            max_records: int | None) -> int:
    completed = initial_completed
    limit = len(pending) if max_records is None else min(len(pending), max_records)
    for start in range(0, limit, batch_size):
        batch = pending[start:min(start + batch_size, limit)]
        for offset, record in enumerate(batch):
            reply = client.command(
                "AIMEM", "MIGRATE-LEGACY-TO", record.record_id,
                str(manifest.target_user_id), *record.scope)
            if reply != record.record_id:
                raise MigrationError(
                    f"migration failed at pending record {start + offset + 1}")
            completed += 1
        save_checkpoint(checkpoint, manifest, completed)
        emit("batch", completed=completed, remaining=len(manifest.records) - completed)
    return completed


def password_from_args(args: argparse.Namespace) -> str:
    if args.password_fd is not None:
        raw = os.read(args.password_fd, 65537)
        if len(raw) > 65536:
            raise MigrationError("password input exceeds safety bound")
        return raw.rstrip(b"\r\n").decode("utf-8", "strict")
    if args.password_env:
        value = os.environ.get(args.password_env)
        if value is None:
            raise MigrationError(f"password environment variable {args.password_env} is not set")
        return value
    if not sys.stdin.isatty():
        raise MigrationError("password source required for non-interactive execution")
    return getpass.getpass("QIHSE password: ")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Migrate legacy AIMEM records through authenticated RESP")
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--checkpoint", type=Path)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", default=6379, type=int)
    parser.add_argument("--username", required=True)
    sources = parser.add_mutually_exclusive_group()
    sources.add_argument("--password-env", default="QIHSE_AIMEM_MIGRATION_PASSWORD")
    sources.add_argument("--password-fd", type=int)
    parser.add_argument("--batch-size", default=100, type=int)
    parser.add_argument("--timeout", default=10.0, type=float)
    parser.add_argument("--max-records", type=int)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)
    if not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")
    if not 1 <= args.batch_size <= MAX_BATCH:
        parser.error(f"--batch-size must be between 1 and {MAX_BATCH}")
    if args.timeout <= 0 or args.max_records is not None and args.max_records < 1:
        parser.error("timeout and max-records must be positive")
    if args.checkpoint is None:
        args.checkpoint = args.manifest.with_suffix(args.manifest.suffix + ".checkpoint")
    return args


def main(argv: list[str] | None = None) -> int:
    try:
        args = parse_args(argv)
        manifest = load_manifest(args.manifest)
        load_checkpoint(args.checkpoint, manifest)
        password = password_from_args(args)
        client = RespClient(args.host, args.port, args.timeout)
        try:
            authenticate(client, args.username, password)
            password = ""
            pending = preflight(client, manifest, args.batch_size)
            already = len(manifest.records) - len(pending)
            emit("preflight", total=len(manifest.records), pending=len(pending),
                 already_migrated=already)
            if args.dry_run:
                emit("complete", migrated=0, remaining=len(pending))
                return 0
            completed = migrate(client, manifest, pending, args.batch_size,
                                args.checkpoint, already, args.max_records)
            remaining = already + len(pending) - completed
            emit("complete", migrated=completed - already, remaining=remaining)
            return 0 if remaining == 0 else 3
        finally:
            client.close()
    except (MigrationError, OSError, ValueError) as exc:
        print(f"qihse-aimem-migrate: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
