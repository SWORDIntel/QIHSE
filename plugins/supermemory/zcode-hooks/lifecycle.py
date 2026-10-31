#!/usr/bin/env python3
"""Durable local hook spool and deterministic, sanitized ZCode session capsules.

This is a recovery *outbox*, not a second memory database. Delivery uses QIHSE's
durable scoped admission. Acknowledged envelopes are removed only after that
fence succeeds; interrupted attempts replay with the same idempotency key.
"""
from __future__ import annotations

from collections import deque
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile
import time

MAX_SCAN_BYTES = 2 * 1024 * 1024
MAX_LINE_BYTES = 64 * 1024
MAX_OBSERVATIONS = 120
MAX_CAPSULE_CHARS = 9500
MAX_SPOOL_FILES = 8192
ENVELOPE_VERSION = 1
SPOOL_ROOT = Path(os.environ.get(
    "QIHSE_AIMEM_SPOOL_DIR",
    str(Path.home() / ".local" / "state" / "qihse-supermemory" / "spool"),
))
_PATTERNS = (
    (re.compile(r"(?i)(\bBearer\s+)[A-Za-z0-9._~+/-]{12,}"), r"\1[REDACTED]"),
    (re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|sk-(?:proj-)?[A-Za-z0-9_-]{16,}|AIza[0-9A-Za-z_-]{30,})\b"), "[REDACTED]"),
    (re.compile(r"(?i)\b((?:api[_-]?key|password|secret|token)\s*[:=]\s*)['\"]?[^ \t\r\n,;'\"]{8,}"), r"\1[REDACTED]"),
    (re.compile(r"(?is)-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----.*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"), "[REDACTED PRIVATE KEY]"),
)


class PipelineError(RuntimeError):
    """Invalid or unsafe capture input; never emit contents to logs."""


def sanitize(value: str) -> str:
    for pattern, replacement in _PATTERNS:
        value = pattern.sub(replacement, value)
    return value


def _directory() -> Path:
    path = SPOOL_ROOT
    if path.is_symlink():
        raise PipelineError("spool directory must not be a symlink")
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    st = path.lstat()
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.getuid() or st.st_mode & 0o077:
        raise PipelineError("spool directory must be user-owned and mode 0700")
    return path


def _sync_dir(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _atomic_write(path: Path, record: dict, *, create_only: bool = False) -> None:
    raw = (json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    if len(raw) > 32 * 1024:
        raise PipelineError("capture envelope exceeds spool record limit")
    fd, tmp = tempfile.mkstemp(prefix=".pending-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as file:
            file.write(raw)
            file.flush()
            os.fsync(file.fileno())
        if create_only:
            # No overwrite of a previously accepted duplicate Stop event.
            try:
                os.link(tmp, path)
            except FileExistsError:
                return
        else:
            os.replace(tmp, path)
        _sync_dir(path.parent)
    finally:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass


def _regular_owned(path: Path) -> os.stat_result:
    if path.is_symlink():
        raise PipelineError("transcript symlink refused")
    st = path.stat()
    if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid():
        raise PipelineError("transcript must be user-owned regular file")
    return st


def enqueue_transcript(transcript_path: str, session_id: str) -> str:
    """Spool tiny transcript locator without reading the transcript in the hook."""
    if not isinstance(transcript_path, str) or not transcript_path or len(transcript_path) > 4096:
        raise PipelineError("invalid transcript path")
    if not isinstance(session_id, str) or not session_id or len(session_id) > 128:
        raise PipelineError("invalid session ID")
    path = Path(transcript_path).absolute()
    st = _regular_owned(path)
    if st.st_size <= 0:
        raise PipelineError("empty transcript")
    directory = _directory()
    if len(list(directory.glob("*.json"))) >= MAX_SPOOL_FILES:
        raise PipelineError("spool full; operator intervention required")
    identity = json.dumps(
        ["zcode", session_id, str(path), st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns],
        separators=(",", ":"),
    )
    event_id = hashlib.sha256(identity.encode("utf-8")).hexdigest()
    record = {
        "schema_version": ENVELOPE_VERSION,
        "event_id": event_id,
        "producer": "zcode",
        "session_id": session_id,
        "transcript_path": str(path),
        "file_device": st.st_dev,
        "file_inode": st.st_ino,
        "file_size": st.st_size,
        "source_mtime_ns": st.st_mtime_ns,
        "received_ms": int(time.time() * 1000),
        "state": "queued",
    }
    _atomic_write(directory / (event_id + ".json"), record, create_only=True)
    return event_id



EVENT_KINDS = frozenset({
    "session-start", "user-prompt", "pre-tool", "post-tool",
    "tool-failure", "checkpoint", "session-end",
})


def enqueue_event(event: dict) -> str:
    """Queue a bounded external orchestrator event; caller is not an authority."""
    if not isinstance(event, dict) or event.get("capture_owner") != "external":
        raise PipelineError("external event requires explicit external capture ownership")
    producer = event.get("producer")
    event_id = event.get("event_id")
    session = event.get("session_id")
    kind = event.get("event_kind")
    summary = event.get("summary")
    identity = (producer, event_id, session)
    if any(not isinstance(x, str) or not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", x) for x in identity):
        raise PipelineError("invalid event identity")
    if kind not in EVENT_KINDS or not isinstance(summary, str) or not summary.strip():
        raise PipelineError("invalid event kind/summary")
    if len(summary.encode("utf-8")) > 12 * 1024:
        raise PipelineError("event exceeds summary limit")
    digest = hashlib.sha256(
        json.dumps([producer, event_id, session, kind, summary], ensure_ascii=False).encode("utf-8")
    ).hexdigest()
    key = hashlib.sha256(
        json.dumps(identity, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    capsule = json.dumps({
        "schema_version": ENVELOPE_VERSION,
        "record_type": "orchestrator_event",
        "capture_owner": "external",
        "producer": producer,
        "source_event_id": event_id,
        "event_kind": kind,
        "session_id": session,
        "observed_ms": int(time.time() * 1000),
        "attribution": "producer supplied; QIHSE has not independently verified event claims",
        "summary": sanitize(summary),
    }, sort_keys=True, ensure_ascii=False)
    directory = _directory()
    dest = directory / (key + ".json")
    if dest.exists():
        prior = _load_record(dest)
        if prior.get("payload_digest") != digest:
            raise PipelineError("same event identity used for different content")
        return key
    if len(list(directory.glob("*.json"))) >= MAX_SPOOL_FILES:
        raise PipelineError("spool full")
    record = {
        "schema_version": ENVELOPE_VERSION,
        "event_id": key,
        "payload_digest": digest,
        "producer": producer,
        "source_type": "external",
        "session_id": session,
        "event_kind": kind,
        "received_ms": int(time.time() * 1000),
        "state": "staged",
        "capsule": capsule,
    }
    _atomic_write(dest, record, create_only=True)
    # Concurrent producers can both observe the path as absent. Link is
    # create-only; verify the winner rather than accepting conflicting data.
    if _load_record(dest).get("payload_digest") != digest:
        raise PipelineError("event id collision or conflicting replay")
    return key

def _load_record(path: Path) -> dict:
    if path.is_symlink():
        raise PipelineError("symlink in spool")
    st = path.stat()
    if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid() or st.st_mode & 0o077:
        raise PipelineError("unsafe spool record mode")
    if st.st_size > 32 * 1024:
        raise PipelineError("spool record too large")
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("schema_version") != ENVELOPE_VERSION:
        raise PipelineError("invalid spool schema")
    if path.stem != data.get("event_id") or not re.fullmatch(r"[a-f0-9]{64}", path.stem):
        raise PipelineError("mismatched spool event identity")
    return data


def _role_and_text(event: object) -> tuple[str, str] | None:
    if not isinstance(event, dict):
        return None
    msg = event.get("message")
    role = event.get("role") or event.get("type")
    if role not in ("user", "human", "assistant") and isinstance(msg, dict):
        role = msg.get("role")
    if role not in ("user", "human", "assistant"):
        return None
    data = msg.get("content") if isinstance(msg, dict) else event.get("content")
    if isinstance(data, list):
        data = " ".join(
            item.get("text", "") for item in data
            if isinstance(item, dict) and isinstance(item.get("text"), str)
            and item.get("type", "text") == "text"
        )
    if not isinstance(data, str) or not data.strip():
        return None
    role = "user" if role == "human" else role
    text = sanitize(data.strip().replace("\x00", ""))
    return role, text[:600 if role == "user" else 350]


def transcript_observations(record: dict) -> list[dict]:
    path = Path(record["transcript_path"])
    st = _regular_owned(path)
    if (st.st_dev, st.st_ino) != (record["file_device"], record["file_inode"]):
        raise PipelineError("transcript changed inode since Stop")
    max_offset = int(record["file_size"])
    if st.st_size < max_offset or (st.st_size == max_offset and st.st_mtime_ns != record["source_mtime_ns"]):
        raise PipelineError("transcript truncated or rewritten since Stop")
    start = max(0, max_offset - MAX_SCAN_BYTES)
    tail = deque(maxlen=MAX_OBSERVATIONS)
    with path.open("rb") as file:
        file.seek(start)
        if start:
            file.readline(MAX_LINE_BYTES)
        while file.tell() < max_offset:
            line = file.readline(min(MAX_LINE_BYTES, max_offset - file.tell()))
            if not line:
                break
            if len(line) >= MAX_LINE_BYTES and not line.endswith(b"\n"):
                continue
            try:
                event = json.loads(line)
            except (UnicodeError, ValueError):
                continue
            obs = _role_and_text(event)
            if obs:
                tail.append({"role": obs[0], "text": obs[1]})
    return list(tail)


def compile_capsule(record: dict) -> str:
    """No inferred decisions or claims of tested success: only attributed excerpts."""
    observations = transcript_observations(record)
    if not observations or sum(len(x["text"]) for x in observations) < 200:
        raise PipelineError("insufficient session evidence")
    # Retain most recent observations, but avoid losing all user context.
    kept = []
    total = 0
    for item in reversed(observations):
        candidate = len(item["text"]) + 55
        if total + candidate > MAX_CAPSULE_CHARS - 800:
            break
        kept.append(item)
        total += candidate
    capsule = {
        "schema_version": ENVELOPE_VERSION,
        "record_type": "session_capsule",
        "source": "zcode",
        "session_id": record["session_id"],
        "event_id": record["event_id"],
        "source_size_bytes": record["file_size"],
        "observed_ms": record["received_ms"],
        "confidence": "quoted observations only; assistant statements not independently verified",
        "observations": list(reversed(kept)),
    }
    return json.dumps(capsule, ensure_ascii=False, sort_keys=True)


def drain(*, replay_accepted: bool = False, limit: int = 64) -> dict:
    """Retry queued capsules and retire them after durable admission."""
    directory = _directory()
    totals = {"accepted": 0, "skipped": 0, "failed": 0, "locked": False}
    lock_file = directory / ".drain.lock"
    fd = os.open(lock_file, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            totals["locked"] = True
            return totals
        from aimem_client import Aimem
        attempts = 0
        for path in sorted(directory.glob("*.json")):
            if attempts >= max(0, min(limit, 512)):
                break
            try:
                record = _load_record(path)
                if record.get("state") in ("accepted", "blocked") and not replay_accepted:
                    totals["skipped"] += 1
                    continue
                attempts += 1
                if "capsule" not in record:
                    try:
                        record["capsule"] = compile_capsule(record)
                    except PipelineError:
                        # Invalid/rotated transcript is recoverable only by
                        # operator action, not by hammering it on every Stop.
                        record["state"] = "blocked"
                        record["error_type"] = "PipelineError"
                        _atomic_write(path, record)
                        totals["failed"] += 1
                        continue
                    record["state"] = "staged"
                    _atomic_write(path, record)
                client = Aimem()
                try:
                    client.store(
                        record["capsule"], kind=1,
                        idem="zc-" + record["event_id"][:48],
                    )
                finally:
                    client.close()
                # Aimem.store uses STORE-SCOPED-DURABLE. If the process dies
                # before unlink, the stable key makes the replay idempotent.
                path.unlink()
                _sync_dir(directory)
                totals["accepted"] += 1
            except (OSError, KeyError, ValueError, TypeError, PipelineError, RuntimeError):
                totals["failed"] += 1
    finally:
        os.close(fd)
    return totals


def status() -> dict:
    directory = _directory()
    counts = {"queued": 0, "staged": 0, "blocked": 0, "legacy_accepted_pending": 0, "invalid": 0, "bytes": 0}
    for path in directory.glob("*.json"):
        try:
            record = _load_record(path)
            counts["bytes"] += path.stat().st_size
            state = record.get("state")
            if state == "accepted":
                counts["legacy_accepted_pending"] += 1
            elif state in ("queued", "staged", "blocked"):
                counts[state] += 1
            else:
                counts["invalid"] += 1
        except (OSError, ValueError, TypeError, PipelineError):
            counts["invalid"] += 1
    return counts


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["status", "drain", "replay"])
    parser.add_argument("--limit", type=int, default=64)
    args = parser.parse_args()
    try:
        if args.command == "status":
            print(json.dumps(status(), sort_keys=True))
        else:
            report = drain(replay_accepted=args.command == "replay", limit=args.limit)
            print(json.dumps(report, sort_keys=True))
            if report["failed"]:
                return 1
        return 0
    except (OSError, PipelineError) as exc:
        print("memory spool unavailable: " + type(exc).__name__, file=__import__("sys").stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
