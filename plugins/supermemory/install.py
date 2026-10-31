#!/usr/bin/env python3
"""Auto-installer for Supermemory backed by local sovereign QIHSE.

Detects local QIHSE installation, extracts/verifies connection credentials,
configures Codex MCP server and local lifecycle hooks (UserPromptSubmit,
PreToolUse, Stop), neutralizes cloud OAuth browser popups, and tests the
end-to-end connection without touching any remote cloud services.

If QIHSE is not installed, drops out with an error and official GitHub link:
    https://github.com/SWORDIntel/QIHSE
"""

from __future__ import annotations

import json
import os
import re
import socket
import stat
import subprocess
import sys
from pathlib import Path

QIHSE_GITHUB_URL = "https://github.com/SWORDIntel/QIHSE"


def _info(msg: str) -> None:
    print(f"\033[1;34m[INFO]\033[0m {msg}")


def _ok(msg: str) -> None:
    print(f"\033[1;32m[OK]\033[0m {msg}")


def _warn(msg: str) -> None:
    print(f"\033[1;33m[WARN]\033[0m {msg}")


def _err(msg: str) -> None:
    print(f"\033[1;31m[ERROR]\033[0m {msg}", file=sys.stderr)


# -----------------------------------------------------------------------------
# QIHSE Detection
# -----------------------------------------------------------------------------

def detect_qihse() -> dict[str, str]:
    """Detect local QIHSE installation and gather connection credentials."""
    home = Path.home()
    qihse_opt = Path(os.environ.get("QIHSE_DIR", Path(__file__).resolve().parents[2]))
    qihse_env_file = Path(os.environ.get("QIHSE_AIMEM_ENV", home / ".config" / "qihse-aimem" / "env"))

    has_opt = qihse_opt.is_dir() and (
        (qihse_opt / "qihse-redis-server").exists() or (qihse_opt / "libqihse.so").exists()
    )
    has_env = qihse_env_file.is_file()

    # Check if user systemd service is active or listening on 6401
    service_active = False
    try:
        res = subprocess.run(
            ["systemctl", "--user", "is-active", "qihse-aimem.service"],
            capture_output=True,
            text=True,
            timeout=3,
        )
        if res.returncode == 0 and "active" in res.stdout:
            service_active = True
    except Exception:
        pass

    is_installed = has_opt or has_env or service_active
    if "--test-missing-qihse" in sys.argv:
        is_installed = False

    if not is_installed:
        _err("QIHSE is not installed on this system!")
        print("\nSupermemory requires a local, sovereign QIHSE AI-memory backend.", file=sys.stderr)
        print("No external cloud memory service or remote mirror is permitted.", file=sys.stderr)
        print(f"\nPlease install QIHSE first from:\n    {QIHSE_GITHUB_URL}\n", file=sys.stderr)
        sys.exit(1)

    _ok(f"Detected QIHSE installation (service_active={service_active}, opt={has_opt})")

    # -------------------------------------------------------------------------
    # Credentials Discovery
    # -------------------------------------------------------------------------
    creds: dict[str, str] = {}

    # 1. Existing user env file
    if has_env:
        try:
            env_stat = qihse_env_file.lstat()
            if qihse_env_file.is_symlink() or env_stat.st_uid != os.getuid() or env_stat.st_mode & 0o077:
                raise RuntimeError("credential file must be user-owned, non-symlink, and mode 0600")
            for line in qihse_env_file.read_text().splitlines():
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, _, v = line.partition("=")
                    creds[k.strip()] = v.strip()
            _info(f"Loaded existing credentials from {qihse_env_file}")
        except Exception as e:
            _err(f"Protected AIMEM configuration unavailable: {e}")
            sys.exit(1)

    # 2. Process environment overrides
    for env_key in (
        "QIHSE_RESP_HOST", "QIHSE_RESP_PORT", "QIHSE_AUTH_USER",
        "QIHSE_AUTH_PASSWORD", "QIHSE_OPERATOR_PASSWORD",
        "QIHSE_AIMEM_SERVICE_PASSWORD", "QIHSE_AIMEM_SERVICE_USER_ID",
        "QIHSE_AIMEM_SERVICE_TENANT_ID", "QIHSE_AIMEM_EMBEDDER_ONNX",
        "QIHSE_AIMEM_PROJECT", "QIHSE_AIMEM_TRANSPORT",
        "QIHSE_ADMIN_SDK", "QIHSE_ADMIN_LIB", "QIHSE_ADMIN_CLI",
        "QIHSE_AIMEM_IDENTITY_DIR", "QIHSE_AIMEM_TRUSTED_PUB",
        "QIHSE_AIMEM_NODE_ID",
    ):
        if env_key in os.environ:
            if has_env and env_key in creds and creds[env_key] != os.environ[env_key]:
                _err(f"{env_key} differs from protected AIMEM env; update it explicitly")
                sys.exit(1)
            creds[env_key] = os.environ[env_key]

    # This installer targets the QKP-only standalone service. Never probe
    # or rewrite it through a cleartext authentication path.
    creds.setdefault("QIHSE_AIMEM_TRANSPORT", "qkp")
    if creds["QIHSE_AIMEM_TRANSPORT"] != "qkp":
        _err("installer requires pinned QKP; cleartext RESP is not supported")
        sys.exit(1)
    creds.setdefault("QIHSE_RESP_HOST", "127.0.0.1")
    creds.setdefault("QIHSE_RESP_PORT", "6401")
    creds.setdefault("QIHSE_AUTH_USER", "AIMEM_SERVICE")

    # Strict Loopback Security Enforcement: reject any network or internet exposure
    LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}
    host = creds["QIHSE_RESP_HOST"].strip()
    if host not in LOOPBACK_HOSTS:
        _err(
            f"SECURITY VIOLATION: QIHSE_RESP_HOST '{host}' is not a loopback address!\n"
            f"The QIHSE AIMEM backend port must NEVER be bound or exposed to the local network or internet.\n"
            f"Host must be strictly 127.0.0.1."
        )
        sys.exit(1)

    port = int(creds["QIHSE_RESP_PORT"])
    user = creds.get("QIHSE_AUTH_USER", "")
    pwd = creds.get("QIHSE_AUTH_PASSWORD", "")
    if user != "AIMEM_SERVICE":
        _err("QIHSE_AUTH_USER must be the restricted AIMEM_SERVICE principal")
        sys.exit(1)
    if not pwd:
        _err("QIHSE_AUTH_PASSWORD is required for AIMEM_SERVICE")
        sys.exit(1)

    qkp_keys = ("QIHSE_ADMIN_SDK", "QIHSE_ADMIN_LIB", "QIHSE_ADMIN_CLI",
                "QIHSE_AIMEM_IDENTITY_DIR", "QIHSE_AIMEM_TRUSTED_PUB",
                "QIHSE_AIMEM_NODE_ID")
    if not all(creds.get(key) for key in qkp_keys):
        _err("pinned QKP SDK, library, CLI, identity, server pin and node ID are required")
        sys.exit(1)

    # Verify the exact client path before touching any installed hook/config.
    from sync import _qihse_command, _qihse_connect
    keys = ("QIHSE_AIMEM_TRANSPORT", "QIHSE_RESP_HOST", "QIHSE_RESP_PORT",
            "QIHSE_AUTH_USER", "QIHSE_AUTH_PASSWORD", *qkp_keys)
    original = {key: os.environ.get(key) for key in keys}
    connection = None
    try:
        os.environ.update({key: creds[key] for key in keys})
        connection = _qihse_connect()
        if _qihse_command(connection, "PING") != "PONG":
            raise RuntimeError("QKP PING did not return PONG")
    except Exception as exc:
        _err(f"pinned QKP authentication failed: {exc}")
        sys.exit(1)
    finally:
        if connection is not None:
            connection.close()
        for key, value in original.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
    _ok(f"Verified pinned QKP as {user} on {host}:{port}")

    # Preserve an existing protected configuration, including bootstrap fields
    # which this client installer does not own. Never strip pins on reinstall.
    if not has_env:
        qihse_env_file.parent.mkdir(parents=True, exist_ok=True)
        keys = ("QIHSE_RESP_HOST", "QIHSE_RESP_PORT", "QIHSE_AUTH_USER",
                "QIHSE_AUTH_PASSWORD", "QIHSE_AIMEM_TRANSPORT", *qkp_keys)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
        fd = os.open(qihse_env_file, flags, 0o600)
        with os.fdopen(fd, "w") as output:
            for key in keys:
                output.write(f"{key}={creds[key]}\n")
            output.flush()
            os.fsync(output.fileno())
    _ok(f"Preserved protected QKP configuration: {qihse_env_file}")

    return creds


# -----------------------------------------------------------------------------
# Hook Scripts Installation
# -----------------------------------------------------------------------------

def install_hook_scripts(hooks_dir: Path, bridge_dir: Path | None = None) -> dict[str, Path]:
    """Install local QIHSE Python hooks into target hooks directory."""
    bridge_dir = bridge_dir or Path(__file__).resolve().parent
    source_dir = bridge_dir / "zcode-hooks"
    required = ("aimem_client.py", "recall_hook.py", "capture_hook.py",
                "lifecycle.py", "context.py", "external_capture.py",
                "session_brief.py", "doctor.py")
    if not all((source_dir / name).is_file() for name in required):
        raise RuntimeError("QKP hook sources missing; refusing embedded RESP fallback")
    native_bin = bridge_dir / "supermemory-bridge"
    if not native_bin.is_file():
        raise RuntimeError("native QKP hook missing; build bridge before installation")
    hooks_dir.mkdir(parents=True, exist_ok=True)

    # 1. aimem_client.py
    aimem_client_code = '''#!/usr/bin/env python3
"""Shared AIMEM RESP client for local Supermemory QIHSE hooks."""

from __future__ import annotations

import json
import os
import re
import socket
from pathlib import Path


class AimemError(RuntimeError):
    pass


def load_env() -> None:
    env_path = os.environ.get("QIHSE_AIMEM_ENV") or str(Path.home() / ".config" / "qihse-aimem" / "env")
    path = Path(env_path)
    if not path.is_file():
        raise AimemError(f"env file missing: {path}")
    allowed = {
        "QIHSE_RESP_HOST", "QIHSE_RESP_PORT", "QIHSE_AUTH_USER",
        "QIHSE_AUTH_PASSWORD", "QIHSE_AIMEM_PROJECT",
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
        raise AimemError(f"Security error: non-loopback QIHSE_RESP_HOST '{host}' rejected. Must be 127.0.0.1.")


class Aimem:
    def __init__(self, timeout: float = 10.0) -> None:
        load_env()
        host = os.environ["QIHSE_RESP_HOST"]
        port = int(os.environ["QIHSE_RESP_PORT"])
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.sock.settimeout(timeout)
        self._buf = bytearray()
        project = os.environ.get("QIHSE_AIMEM_PROJECT", "").strip().lower()
        if not project:
            project = Path.cwd().name.lower() or "global"
        self.scope = (project, "", "", "")
        self._cmd("AUTH", os.environ["QIHSE_AUTH_USER"], os.environ["QIHSE_AUTH_PASSWORD"])

    def _send(self, *parts: str) -> None:
        out = bytearray(b"*%d\\r\\n" % len(parts))
        for p in parts:
            data = p.encode("utf-8")
            out += b"$%d\\r\\n%s\\r\\n" % (len(data), data)
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
        while b"\\r\\n" not in self._buf:
            chunk = self.sock.recv(8192)
            if not chunk:
                raise AimemError("connection closed")
            self._buf.extend(chunk)
        i = self._buf.index(b"\\r\\n")
        line = bytes(self._buf[:i])
        del self._buf[:i + 2]
        return line

    def _value(self):
        prefix = self._line()
        if prefix == b"$-1":
            return None
        if prefix.startswith(b"$"):
            data = self._read(int(prefix[1:]))
            self._read(2)
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
        self._send(*parts)
        return self._value()

    def recall(self, query: str, limit: int = 3, mode: str = "hybrid", repo: str | None = None) -> list:
        fetch_limit = max(limit * 2, 6) if repo else limit
        value = self._cmd("AIMEM", "RECALL-SCOPED", query, str(fetch_limit),
                          mode, "0", *self.scope)
        records = []
        for fields in value or []:
            if isinstance(fields, list) and len(fields) == 7:
                records.append({
                    "id": fields[0],
                    "created_ms": int(fields[1]),
                    "kind": int(fields[2]),
                    "classification": int(fields[3]),
                    "sci": int(fields[4]),
                    "score": float(fields[5]),
                    "text": fields[6],
                })
        if repo and records:
            filtered = []
            repo_lower = repo.lower()
            query_lower = query.lower()
            for r in records:
                txt = r.get("text", "")
                m = re.search(r"\\[repo:\\s*([^\\]]+)\\]", txt, re.IGNORECASE)
                if m:
                    hit_repo = m.group(1).strip().lower()
                    if hit_repo != repo_lower and hit_repo not in query_lower:
                        continue
                filtered.append(r)
                if len(filtered) >= limit:
                    break
            return filtered
        return records[:limit]

    def store(self, text: str, kind: int = 2, idem: str = "") -> str:
        payload = json.dumps({"source": "supermemory-qihse-hook", "text": text}, separators=(",", ":"))
        parts = ["AIMEM", "STORE-SCOPED-DURABLE", str(kind), payload,
                 *self.scope]
        if idem:
            parts.append(idem)
        return str(self._cmd(*parts))

    def close(self) -> None:
        try:
            self.sock.close()
        except Exception:
            pass
'''

    aimem_client_file = (bridge_dir / "zcode-hooks" / "aimem_client.py") if bridge_dir else None
    if aimem_client_file and aimem_client_file.is_file():
        aimem_client_code = aimem_client_file.read_text(encoding="utf-8")

    # 2. repo_relations.py (read from disk if present, else template)
    repo_relations_file = (bridge_dir / "repo_relations.py") if bridge_dir else None
    if repo_relations_file and repo_relations_file.is_file():
        repo_relations_code = repo_relations_file.read_text(encoding="utf-8")
    else:
        repo_relations_code = r'''#!/usr/bin/env python3
"""Dynamic repository relationship & dependency graph engine for QIHSE AIMEM."""

from __future__ import annotations

import json
import os
import re
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

CACHE_DIR = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache")) / "qihse-aimem"
CACHE_FILE = CACHE_DIR / "repo_relations.json"
DEFAULT_TTL_SEC = 1800

BASELINE_CLUSTERS: List[Set[str]] = [
    {
        "qihse", "keystone", "kp15-suite", "kp14", "vexel", "dexward",
        "methra", "radare3", "isanity", "angryier", "qihse-docs", "qihse-fan-stack",
    },
    {
        "hax", "headless-linux-bridge", "headless-winrm-bridge", "infra",
        "supermemory-qihse-bridge",
    },
]

IGNORE_DIRS = {
    "bin", "data", "desktop", "documents", "downloads", "go", "info", "output",
    "plugins", "public", "templates", "tmp", "tools", "work", "scripts", "sounds",
    "raid", "misc", "sound", "toasts", "new-folder", "pycache", "__pycache__",
    "backups", "android", "intel", "orchestration", "templates", "bridge", "suite",
    "home", "target", "build", "external", "src", "docs",
}

PROJECT_MARKERS = {
    ".git", "Cargo.toml", "go.mod", "meson.build", "CMakeLists.txt",
    "package.json", "setup.py", "pyproject.toml", "Makefile",
}


def is_valid_project_dir(p: Path) -> bool:
    name = canonical_repo_name(p.name)
    if name in IGNORE_DIRS or len(name) < 3:
        return False
    if p.is_symlink():
        return True
    if not p.is_dir():
        return False
    for marker in PROJECT_MARKERS:
        if (p / marker).exists():
            return True
    return False


def canonical_repo_name(name_or_path: str | Path) -> str:
    name = Path(name_or_path).name.strip().lower()
    name = re.sub(r"[_\s]+", "-", name)
    return name


def get_current_repo(cwd: Optional[str | Path] = None) -> Tuple[str, Path]:
    start_dir = Path(cwd).resolve() if cwd else Path.cwd().resolve()
    home = Path.home().resolve()
    docs = (home / "Documents").resolve()

    for root_container in (docs, home):
        try:
            rel = start_dir.relative_to(root_container)
            if len(rel.parts) >= 1 and rel.parts[0] not in IGNORE_DIRS:
                proj_dir = root_container / rel.parts[0]
                return canonical_repo_name(proj_dir.name), proj_dir
        except ValueError:
            pass

    try:
        proc = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            cwd=start_dir,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=1,
            check=False,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            top = Path(proc.stdout.strip()).resolve()
            if top not in (home, docs) and canonical_repo_name(top.name) not in IGNORE_DIRS:
                return canonical_repo_name(top.name), top
    except Exception:
        pass

    return canonical_repo_name(start_dir.name), start_dir


def get_related_repos(repo_name_or_path: Optional[str | Path] = None, force_refresh: bool = False) -> Set[str]:
    if repo_name_or_path is None:
        target_name, _ = get_current_repo()
    else:
        target_name = canonical_repo_name(repo_name_or_path)

    for cluster in BASELINE_CLUSTERS:
        if target_name in cluster:
            return set(cluster)

    return {target_name}


def parse_memory_hit(raw_hit: Any) -> Dict[str, Any]:
    if isinstance(raw_hit, list) and len(raw_hit) == 7:
        raw_text = raw_hit[6]
        hit: Dict[str, Any] = {
            "id": raw_hit[0],
            "created_ms": int(raw_hit[1]),
            "kind": int(raw_hit[2]),
            "classification": int(raw_hit[3]),
            "sci": int(raw_hit[4]),
            "score": float(raw_hit[5]),
            "text": str(raw_text),
        }
    elif isinstance(raw_hit, dict):
        hit = dict(raw_hit)
        raw_text = hit.get("text", "")
    else:
        raise ValueError(f"Unsupported memory hit format: {type(raw_hit)}")

    if isinstance(raw_text, str) and raw_text.startswith("{") and raw_text.endswith("}"):
        try:
            doc = json.loads(raw_text)
            if isinstance(doc, dict) and "text" in doc and isinstance(doc["text"], str):
                hit["text"] = doc["text"]
                metadata = doc.get("metadata") if isinstance(doc.get("metadata"), dict) else {}
                repo = metadata.get("repo") or metadata.get("repository") or doc.get("repo") or doc.get("repository")
                scope = metadata.get("scope") or doc.get("scope")
                if metadata:
                    hit["metadata"] = metadata
                if repo:
                    hit["repo"] = canonical_repo_name(repo)
                if scope:
                    hit["scope"] = scope
        except (json.JSONDecodeError, ValueError):
            pass
    return hit


def rank_and_filter_memories(
    hits: List[Dict[str, Any]],
    current_repo: Optional[str] = None,
    related_repos: Optional[Set[str]] = None,
    min_score: float = 0.005,
) -> List[Dict[str, Any]]:
    if current_repo is None:
        current_repo, _ = get_current_repo()
    if related_repos is None:
        related_repos = get_related_repos(current_repo)

    scored: List[Tuple[float, Dict[str, Any]]] = []
    for raw in hits:
        h = parse_memory_hit(raw)
        base_score = float(h.get("score", 0.0))
        if base_score < min_score:
            continue
        text = h.get("text", "")
        low_text = text.lower()
        is_current = current_repo in low_text
        matched_related = [r for r in related_repos if r in low_text]

        multiplier = 1.0
        if is_current:
            multiplier = 1.4
        elif matched_related:
            multiplier = 1.2

        adjusted_score = base_score * multiplier
        h_copy = dict(h)
        h_copy["adjusted_score"] = adjusted_score
        h_copy["matched_scope"] = current_repo if is_current else (matched_related[0] if matched_related else "global")
        scored.append((adjusted_score, h_copy))

    scored.sort(key=lambda x: x[0], reverse=True)
    return [item[1] for item in scored]


def judge_and_filter_scope(
    hits: List[Dict[str, Any]],
    current_repo: Optional[str] = None,
    related_repos: Optional[Set[str]] = None,
    requested_scope: str = "auto",
    min_score: float = 0.005,
    limit: int = 5,
    query: str = "",
) -> Dict[str, Any]:
    if current_repo is None:
        current_repo, _ = get_current_repo()
    if related_repos is None:
        related_repos = get_related_repos(current_repo)

    norm_scope = (requested_scope or "auto").strip().lower()
    valid_hits = []
    for raw in hits:
        h = parse_memory_hit(raw)
        if float(h.get("score", 0.0)) >= min_score:
            valid_hits.append(h)
    if not valid_hits:
        return {
            "hits": [],
            "effective_scope": norm_scope,
            "scope_switched": False,
            "notification": "",
            "current_repo": current_repo,
            "related_repos": sorted(list(related_repos)),
        }

    if norm_scope == "repo":
        repo_ranked = rank_and_filter_memories(valid_hits, current_repo, related_repos, min_score=min_score)
        filtered = [
            h for h in repo_ranked
            if h.get("matched_scope") in (current_repo, "global") or h.get("matched_scope") in related_repos
        ]
        return {
            "hits": filtered[:limit],
            "effective_scope": "repo",
            "scope_switched": False,
            "notification": "",
            "current_repo": current_repo,
            "related_repos": sorted(list(related_repos)),
        }
    elif norm_scope == "global":
        global_ranked = rank_and_filter_memories(valid_hits, current_repo, related_repos, min_score=min_score)
        return {
            "hits": global_ranked[:limit],
            "effective_scope": "global",
            "scope_switched": False,
            "notification": "",
            "current_repo": current_repo,
            "related_repos": sorted(list(related_repos)),
        }

    query_low = query.lower() if isinstance(query, str) else ""
    ranked_global = rank_and_filter_memories(valid_hits, current_repo, related_repos, min_score=min_score)
    candidate_sample = ranked_global[: min(len(ranked_global), max(limit * 2, 8))]

    foreign_unrelated_count = 0
    relevant_cluster_count = 0
    top_is_foreign = False

    all_known = set()
    for cluster in BASELINE_CLUSTERS:
        all_known.update(cluster)
    disjoint_repos = all_known - related_repos - {current_repo}

    disjoint_keywords = set()
    for fr in disjoint_repos:
        if len(fr) >= 4 and fr not in IGNORE_DIRS and fr not in related_repos and fr != current_repo:
            disjoint_keywords.add(fr)

    for idx, h in enumerate(candidate_sample):
        text = str(h.get("text", "")).lower()
        metadata = h.get("metadata") or {}
        repo_tag = str(h.get("repo") or metadata.get("repo") or "").lower()

        tag_match = re.search(r"\\[repo:\\s*([a-zA-Z0-9_\\-]+)\\]", text)
        explicit_tag = canonical_repo_name(tag_match.group(1)) if tag_match else repo_tag

        is_foreign = False
        if explicit_tag and explicit_tag not in related_repos and explicit_tag != current_repo:
            if explicit_tag not in query_low:
                is_foreign = True
        else:
            for kw in disjoint_keywords:
                if re.search(rf"\\b{re.escape(kw)}\\b", text):
                    if kw not in query_low:
                        is_foreign = True
                        break

        if is_foreign:
            foreign_unrelated_count += 1
            if idx == 0:
                top_is_foreign = True
        else:
            scope = h.get("matched_scope", "global")
            if scope == current_repo or scope in related_repos:
                relevant_cluster_count += 1

    should_switch_to_repo = False
    if len(candidate_sample) >= 3:
        foreign_ratio = foreign_unrelated_count / len(candidate_sample)
        if foreign_ratio > 0.35 and relevant_cluster_count > 0:
            should_switch_to_repo = True
        elif top_is_foreign and relevant_cluster_count > 0:
            should_switch_to_repo = True

    if should_switch_to_repo:
        repo_scoped = [
            h for h in ranked_global
            if not any(re.search(rf"\\b{re.escape(kw)}\\b", str(h.get("text", "")).lower()) for kw in disjoint_keywords if kw not in query_low)
        ]
        final_hits = repo_scoped if repo_scoped else ranked_global
        notification = (
            f"Notice: Auto-switched from global to repository scope ({current_repo} cluster) "
            f"to suppress irrelevant cross-domain results."
        )
        return {
            "hits": final_hits[:limit],
            "effective_scope": "repo",
            "scope_switched": True,
            "notification": notification,
            "current_repo": current_repo,
            "related_repos": sorted(list(related_repos)),
        }
    else:
        return {
            "hits": ranked_global[:limit],
            "effective_scope": "global",
            "scope_switched": False,
            "notification": "",
            "current_repo": current_repo,
            "related_repos": sorted(list(related_repos)),
        }
'''

    # 3. recall_hook.py
    recall_hook_code = '''#!/usr/bin/env python3
"""UserPromptSubmit hook: recall relevant QIHSE memories into context."""

from __future__ import annotations

import json
import os
import re
import signal
import sys
from pathlib import Path

SIGNAL_WORDS = [
    "remember", "recall", "earlier", "previously", "last time", "yesterday",
    "prefer", "preference", "decision", "decided", "chose", "choose",
    "architecture", "pattern", "approach", "convention", "keyring",
    "keystone", "qihse", "supermemory", "kp15", "kp14", "wavlink", "openwrt",
    "taobao", "cndump", "gemini", "telegram", "bot", "router", "blocker",
    "resume", "continue", "where was", "what did", "status", "hax",
]

_ESCAPED = sorted([re.escape(w) for w in SIGNAL_WORDS], key=len, reverse=True)
SIGNAL_RE = re.compile(r"\\b(?:" + "|".join(_ESCAPED) + r")\\b", re.IGNORECASE)

MAX_QUERY = 300
MIN_SCORE = 0.005
MAX_SNIPPET = 400


def _timeout_handler(signum, frame):
    # Fail-open: exit cleanly with 0 and no output so prompt submission is not blocked
    sys.exit(0)


def gate(prompt: str) -> bool:
    if not prompt or not isinstance(prompt, str):
        return False
    if SIGNAL_RE.search(prompt):
        return True
    return len(prompt.strip()) > 300


def extract_query(prompt: str, max_chars: int = MAX_QUERY) -> str:
    """Extract substantive question/sentences rather than blindly slicing the first chars."""
    prompt = prompt.strip()
    if len(prompt) <= max_chars:
        return prompt

    lines = [line.strip() for line in prompt.splitlines() if line.strip()]
    if not lines:
        return prompt[-max_chars:].strip()

    question_lines = [l for l in lines if "?" in l]
    matched_lines = [l for l in lines if SIGNAL_RE.search(l)]

    candidates: list[str] = []
    for ql in question_lines:
        if ql not in candidates:
            candidates.append(ql)

    for ml in matched_lines:
        if ml not in candidates:
            candidates.append(ml)

    if candidates:
        combined = " ".join(candidates)
        if len(combined) > max_chars:
            return combined[-max_chars:].strip()
        return combined

    tail = prompt[-max_chars:].strip()
    first_space = tail.find(" ")
    if 0 < first_space < 30:
        tail = tail[first_space + 1:]
    return tail


def main() -> int:
    # Strict monotonic fail-open timeout: 1.2s to accommodate QIHSE password verification
    try:
        signal.signal(signal.SIGALRM, _timeout_handler)
        signal.setitimer(signal.ITIMER_REAL, 1.2)
    except (AttributeError, ValueError):
        pass

    try:
        raw = sys.stdin.read()
        payload = json.loads(raw) if raw.strip() else {}
    except (json.JSONDecodeError, ValueError):
        return 0

    prompt = payload.get("prompt") or payload.get("user_prompt") or payload.get("text") or ""
    if not isinstance(prompt, str) or not gate(prompt):
        return 0

    query = extract_query(prompt, MAX_QUERY)

    try:
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        from aimem_client import Aimem
        from repo_relations import (
            get_current_repo,
            get_related_repos,
            judge_and_filter_scope,
            parse_memory_hit,
        )

        current_repo, _ = get_current_repo()
        related_repos = get_related_repos(current_repo)

        client = Aimem(timeout=1.1)
        hits = client.recall(query, limit=16, mode="hybrid")
        client.close()

        records = [parse_memory_hit(h) for h in hits]
        judged = judge_and_filter_scope(
            records,
            current_repo=current_repo,
            related_repos=related_repos,
            requested_scope="auto",
            min_score=MIN_SCORE,
            limit=3,
            query=query,
        )
        ranked = judged["hits"]
    except Exception:
        return 0

    if not ranked:
        return 0

    lines = [
        "Relevant memories from QIHSE (auto-recalled; verify current state before relying on them):"
    ]
    if judged.get("scope_switched") and judged.get("notification"):
        lines.append(f"> {judged['notification']}")
    for h in ranked:
        text = str(h.get("text", "")).replace("\\n", " ")[:MAX_SNIPPET]
        score = float(h.get("adjusted_score", h.get("score", 0.0)))
        scope = h.get("matched_scope", "")
        scope_str = f" [{scope}]" if scope and scope != "global" else ""
        lines.append(f"- [{score:.3f}]{scope_str} {text}")

    output = {
        "hookSpecificOutput": {
            "hookEventName": "UserPromptSubmit",
            "additionalContext": "\\n".join(lines),
        }
    }
    print(json.dumps(output))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
'''

    # 4. capture_hook.py
    capture_hook_code = '''#!/usr/bin/env python3
"""Stop hook: capture substantive turn decisions into local QIHSE memory."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

MAX_TAIL_BYTES = 512 * 1024
MAX_EVENTS = 80
SNIPPET_USER = 800
SNIPPET_ASST = 1200
LOG = Path(__file__).resolve().parent / "capture.log"

FILLER_WORDS = {
    "ok", "okay", "k", "sure", "yep", "yes", "no", "nope",
    "got it", "understood", "thanks", "thank you", "thx", "ty",
    "done", "all done", "lgtm", "looks good", "great", "cool",
    "awesome", "perfect", "good", "nice", "fine", "acknowledged",
    "hi", "hello", "hey", "bye", "goodbye", "cya", "test", "testing",
}

SUBSTANTIVE_RE = re.compile(
    r"\\b("
    r"decision|decided|chose|choose|prefer|preference|architecture|design|"
    r"approach|pattern|convention|refactor|restructure|standard|policy|"
    r"config|configuration|setting|settings|endpoint|port|host|env|environment|"
    r"fix|fixed|bug|issue|error|exception|crash|patch|resolve|resolved|"
    r"always|never|rule|directive|requirement|must|should|ensure|verify|"
    r"implement|implemented|feature|workaround"
    r")\\b",
    re.IGNORECASE,
)


def read_stdin_json() -> dict:
    try:
        raw = sys.stdin.read()
        return json.loads(raw) if raw.strip() else {}
    except (json.JSONDecodeError, ValueError):
        return {}


def read_recent_events(path: str | Path, max_bytes: int = MAX_TAIL_BYTES, max_events: int = MAX_EVENTS) -> list[dict]:
    """Stream recent lines from transcript tail with bounded memory."""
    path = Path(path)
    if not path.is_file():
        return []

    try:
        file_size = path.stat().st_size
        lines: list[bytes] = []
        with path.open("rb") as f:
            if file_size > max_bytes:
                f.seek(file_size - max_bytes)
                f.readline()  # discard partial first line
            for line in f:
                line = line.strip()
                if line:
                    lines.append(line)
                    if len(lines) > max_events * 2:
                        lines = lines[-max_events:]

        events: list[dict] = []
        for line in lines[-max_events:]:
            try:
                ev = json.loads(line.decode("utf-8", "replace"))
                if isinstance(ev, dict):
                    events.append(ev)
            except json.JSONDecodeError:
                continue
        return events
    except Exception:
        return []


def extract_messages(events: list[dict]) -> tuple[list[dict], int]:
    """Extract normalized messages and count of user turns."""
    messages = []
    user_turn_count = 0
    for ev in events:
        payload = ev.get("payload") or {}
        kind = ev.get("type") or ev.get("role") or ""
        msg = ev.get("message") or ev
        if isinstance(payload, dict) and payload.get("type") == "message":
            kind = payload.get("role") or kind
            msg = payload

        if kind not in ("user", "human", "assistant"):
            continue

        content = msg.get("content")
        if isinstance(content, list):
            content = " ".join(
                c.get("text", "") for c in content
                if isinstance(c, dict) and ("text" in c or c.get("type") in (None, "text", "input_text"))
            )
        if not isinstance(content, str) or not content.strip():
            continue

        turn_id = str(ev.get("turn_id") or msg.get("turn_id") or ev.get("turn") or "")
        normalized_role = "user" if kind in ("user", "human") else "assistant"
        if normalized_role == "user":
            user_turn_count += 1

        messages.append({
            "role": normalized_role,
            "text": content.strip(),
            "turn_id": turn_id,
        })
    return messages, user_turn_count


def extract_latest_turn(messages: list[dict], user_turn_count: int) -> tuple[str, str, str]:
    """Returns (user_text, assistant_text, turn_ref)."""
    if not messages:
        return "", "", ""

    last_user_idx = -1
    for i in range(len(messages) - 1, -1, -1):
        if messages[i]["role"] == "user":
            last_user_idx = i
            break

    if last_user_idx == -1:
        assistant_texts = [m["text"] for m in messages if m["role"] == "assistant"]
        return "", "\\n".join(assistant_texts), f"turn_{user_turn_count or 1}"

    user_msg = messages[last_user_idx]
    user_text = user_msg["text"]
    turn_id = user_msg["turn_id"]

    assistant_texts = [
        m["text"] for m in messages[last_user_idx + 1:]
        if m["role"] == "assistant"
    ]
    assistant_text = "\\n".join(assistant_texts)

    turn_ref = turn_id if turn_id else f"turn_{user_turn_count}"
    return user_text, assistant_text, turn_ref


def is_filler_text(text: str) -> bool:
    clean = re.sub(r"[^\\w\\s]", "", text.strip().lower())
    clean = re.sub(r"\\s+", " ", clean).strip()
    return clean in FILLER_WORDS


def is_substantive_turn(user_text: str, assistant_text: str) -> bool:
    user_clean = user_text.strip()
    asst_clean = assistant_text.strip()

    if is_filler_text(user_clean):
        return False

    if not asst_clean or is_filler_text(asst_clean):
        return False

    combined = f"{user_clean}\\n{asst_clean}"
    if len(combined) < 40:
        return False

    if not SUBSTANTIVE_RE.search(combined):
        return False

    return True


def store(user_text: str, assistant_text: str, session_id: str, turn_ref: str) -> None:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from aimem_client import Aimem
    from repo_relations import get_current_repo, get_related_repos

    current_repo, _ = get_current_repo()
    related = get_related_repos(current_repo)
    cluster_tags = [f"repo: {current_repo}"]
    other_peers = sorted(r for r in related if r != current_repo)
    if other_peers:
        cluster_tags.append(f"cluster: {','.join(other_peers[:4])}")

    meta_tag = f" [{' '.join(cluster_tags)}]"
    safe_turn = re.sub(r"[^a-zA-Z0-9_\\-]", "_", str(turn_ref))[:32]
    idem = f"qihse-{session_id[:32]}-{safe_turn}"
    header = f"Session {session_id}{meta_tag} ({safe_turn}):\\n"

    parts = []
    if user_text:
        parts.append("USER: " + user_text.strip()[:SNIPPET_USER])
    if assistant_text:
        parts.append("ASSISTANT: " + assistant_text.strip()[:SNIPPET_ASST])
    digest = "\\n".join(parts)

    client = Aimem(timeout=5.0)
    try:
        client.store(header + digest, kind=1, idem=idem)
    finally:
        client.close()


def process_transcript(transcript_path: Path, session_id: str, payload: dict) -> None:
    events = read_recent_events(transcript_path)
    if not events:
        return

    messages, user_turn_count = extract_messages(events)
    if not messages:
        return

    user_text, assistant_text, turn_ref = extract_latest_turn(messages, user_turn_count)
    payload_turn = payload.get("turn_id") or payload.get("turn") or payload.get("turn_index")
    if payload_turn:
        turn_ref = str(payload_turn)

    if not is_substantive_turn(user_text, assistant_text):
        return

    store(user_text, assistant_text, session_id, turn_ref)


def main() -> int:
    payload = read_stdin_json()
    transcript = payload.get("transcript_path") or payload.get("transcript")
    session_id = str(payload.get("session_id") or payload.get("thread_id") or "unknown")[:64]

    if "--child" in sys.argv:
        try:
            if transcript and Path(transcript).is_file():
                process_transcript(Path(transcript), session_id, payload)
        except Exception as exc:
            try:
                with open(LOG, "a") as log:
                    log.write(f"capture failed: {exc}\\n")
            except OSError:
                pass
        return 0

    if not transcript or not Path(transcript).is_file():
        return 0

    try:
        payload_bytes = json.dumps(payload).encode("utf-8")
        proc = subprocess.Popen(
            [sys.executable, str(Path(__file__).resolve()), "--child"],
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True,
            start_new_session=True,
        )
        proc.communicate(input=payload_bytes, timeout=1)
    except Exception:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
'''

    # 5. recall_approve.py
    recall_approve_code = '''#!/usr/bin/env python3
"""PreToolUse hook: auto-approve read-only supermemory searches."""

from __future__ import annotations

import json
import sys

ALLOWED_TOOLS = {
    "mcp__supermemory__search_memory",
    "mcp__supermemory__memory_count",
    "search_memory",
    "memory_count",
}


def main() -> int:
    try:
        raw = sys.stdin.read()
        data = json.loads(raw) if raw.strip() else {}
    except Exception:
        return 0

    if not isinstance(data, dict):
        return 0

    tool_name = str(data.get("tool_name", "")).strip()
    if tool_name not in ALLOWED_TOOLS:
        return 0

    tool_input = data.get("tool_input")
    if not isinstance(tool_input, dict):
        return 0

    query = tool_input.get("query")
    if isinstance(query, str) and query.strip():
        msg = f"▪ supermemory · recalling: {query.strip()}"
    else:
        msg = "▪ supermemory · recalling memories"

    out = {
        "systemMessage": msg,
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "allow",
            "permissionDecisionReason": "QIHSE supermemory recall is read-only memory access.",
            "updatedInput": tool_input,
        },
    }
    sys.stdout.write(json.dumps(out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
'''

    scripts = {
        "aimem_client.py": aimem_client_code,
        "repo_relations.py": repo_relations_code,
        "recall_hook.py": recall_hook_code,
        "capture_hook.py": capture_hook_code,
        "recall_approve.py": recall_approve_code,
    }
    for name in required:
        scripts[name] = (source_dir / name).read_text(encoding="utf-8")

    paths: dict[str, Path] = {}
    for name, code in scripts.items():
        dst = hooks_dir / name
        dst.write_text(code, encoding="utf-8")
        dst.chmod(0o755)
        paths[name] = dst

    if bridge_dir:
        native_bin = bridge_dir / "supermemory-bridge"
        if native_bin.is_file():
            dst_bin = hooks_dir / "supermemory-bridge"
            try:
                import shutil
                shutil.copy2(native_bin, dst_bin)
                dst_bin.chmod(0o755)
                paths["supermemory-bridge"] = dst_bin
                _ok(f"Installed native high-speed binary into {dst_bin}")
            except Exception as e:
                raise RuntimeError("could not install native QKP hook") from e

    _ok(f"Installed {len(paths)} local QIHSE hook assets into {hooks_dir}")
    return paths


# -----------------------------------------------------------------------------
# Codex Configuration
# -----------------------------------------------------------------------------

def configure_codex(bridge_dir: Path) -> None:
    """Auto-configure Codex MCP server and hooks for QIHSE."""
    home = Path.home()
    codex_home = Path(os.environ.get("CODEX_HOME", home / ".codex"))
    codex_home.mkdir(parents=True, exist_ok=True)

    # 1. Update config.toml with MCP server
    config_toml = codex_home / "config.toml"
    mcp_script = bridge_dir / "mcp_server.py"
    toml_text = config_toml.read_text() if config_toml.is_file() else ""
    # The Python MCP server exposes the complete scoped read/write tool set.
    # The native binary remains the low-latency prompt hook and recall CLI.
    mcp_section = f'''[mcp_servers.supermemory]
command = "python3"
args = [ "{mcp_script}" ]
'''

    if "[mcp_servers.supermemory]" in toml_text:
        # Replace existing section
        pattern = re.compile(r"\[mcp_servers\.supermemory\][\s\S]*?(?=\n\[|\Z)")
        toml_text = pattern.sub(mcp_section.rstrip(), toml_text)
    else:
        # Append section
        toml_text = toml_text.rstrip() + "\n\n" + mcp_section

    config_toml.write_text(toml_text)
    _ok(f"Configured MCP server [mcp_servers.supermemory] in {config_toml}")

    # 2. Install local hooks into ~/.codex/hooks/supermemory
    hooks_dir = codex_home / "hooks" / "supermemory"
    installed_hooks = install_hook_scripts(hooks_dir, bridge_dir)

    # 3. Merge hooks into ~/.codex/hooks.json without clobbering existing plugins
    hooks_json_path = codex_home / "hooks.json"
    existing_cfg: dict = {}
    if hooks_json_path.is_file():
        try:
            existing_cfg = json.loads(hooks_json_path.read_text())
        except Exception:
            existing_cfg = {}
    if not isinstance(existing_cfg, dict):
        existing_cfg = {}

    hooks_map = existing_cfg.setdefault("hooks", {})
    if not isinstance(hooks_map, dict):
        hooks_map = {}
        existing_cfg["hooks"] = hooks_map

    # 3a. UserPromptSubmit
    user_prompt_list = hooks_map.setdefault("UserPromptSubmit", [])
    if not isinstance(user_prompt_list, list):
        user_prompt_list = []
        hooks_map["UserPromptSubmit"] = user_prompt_list

    new_user_prompt = []
    for entry in user_prompt_list:
        if isinstance(entry, dict):
            entry_hooks = entry.get("hooks", [])
            keep = True
            for h in entry_hooks:
                cmd = str(h.get("command", ""))
                if "supermemory" in cmd or "recall_hook" in cmd or "recall.js" in cmd:
                    keep = False
                    break
            if keep:
                new_user_prompt.append(entry)

    if "supermemory-bridge" in installed_hooks:
        prompt_cmd = f"{installed_hooks['supermemory-bridge']} hook"
    else:
        prompt_cmd = f"python3 {installed_hooks['recall_hook.py']}"

    new_user_prompt.append({
        "hooks": [
            {
                "type": "command",
                "command": prompt_cmd,
                "timeout": 15,
                "statusMessage": "Recalling QIHSE memories...",
            }
        ]
    })
    hooks_map["UserPromptSubmit"] = new_user_prompt

    # 3b. PreToolUse
    pre_tool_list = hooks_map.setdefault("PreToolUse", [])
    if not isinstance(pre_tool_list, list):
        pre_tool_list = []
        hooks_map["PreToolUse"] = pre_tool_list

    new_pre_tool = []
    for entry in pre_tool_list:
        if isinstance(entry, dict):
            matcher = str(entry.get("matcher", ""))
            entry_hooks = entry.get("hooks", [])
            if "supermemory" in matcher:
                continue
            keep = True
            for h in entry_hooks:
                cmd = str(h.get("command", ""))
                if "supermemory" in cmd or "recall_approve" in cmd:
                    keep = False
                    break
            if keep:
                new_pre_tool.append(entry)
    new_pre_tool.append({
        "matcher": "^mcp__supermemory__",
        "hooks": [
            {
                "type": "command",
                "command": f"python3 {installed_hooks['recall_approve.py']}",
                "timeout": 5,
                "statusMessage": "Approving Supermemory recall...",
            }
        ]
    })
    hooks_map["PreToolUse"] = new_pre_tool

    # 3c. Stop
    stop_list = hooks_map.setdefault("Stop", [])
    if not isinstance(stop_list, list):
        stop_list = []
        hooks_map["Stop"] = stop_list

    new_stop = []
    for entry in stop_list:
        if isinstance(entry, dict):
            entry_hooks = entry.get("hooks", [])
            keep = True
            for h in entry_hooks:
                cmd = str(h.get("command", ""))
                if "supermemory" in cmd or "capture_hook" in cmd or "flush.js" in cmd:
                    keep = False
                    break
            if keep:
                new_stop.append(entry)
    new_stop.append({
        "hooks": [
            {
                "type": "command",
                "command": f"python3 {installed_hooks['capture_hook.py']}",
                "timeout": 10,
                "statusMessage": "Saving to QIHSE memory...",
                "async": True,
            }
        ]
    })
    hooks_map["Stop"] = new_stop

    # 3d. Remove SessionStart cloud OAuth
    if "SessionStart" in hooks_map:
        session_start_list = hooks_map["SessionStart"]
        if isinstance(session_start_list, list):
            cleaned_session_start = []
            for entry in session_start_list:
                if isinstance(entry, dict):
                    entry_hooks = entry.get("hooks", [])
                    keep = True
                    for h in entry_hooks:
                        cmd = str(h.get("command", ""))
                        if "supermemory" in cmd or "session-start" in cmd:
                            keep = False
                            break
                    if keep:
                        cleaned_session_start.append(entry)
            if cleaned_session_start:
                hooks_map["SessionStart"] = cleaned_session_start
            else:
                del hooks_map["SessionStart"]

    hooks_json_path.write_text(json.dumps(existing_cfg, indent=2) + "\n")
    _ok(f"Merged local QIHSE hooks into {hooks_json_path} (preserved existing plugins, removed cloud SessionStart)")

    # 4. Neutralize legacy cloud scripts
    legacy_session_start = codex_home / "supermemory" / "session-start.js"
    if legacy_session_start.is_file():
        legacy_session_start.write_text(
            '#!/usr/bin/env node\n"use strict";\n// Local QIHSE backend is authoritative; no external browser OAuth required.\nprocess.exit(0);\n'
        )
        legacy_session_start.chmod(0o755)
        _ok(f"Neutralized legacy cloud OAuth launcher in {legacy_session_start}")


# -----------------------------------------------------------------------------
# ZCode Configuration
# -----------------------------------------------------------------------------

def configure_zcode(bridge_dir: Path) -> None:
    """Auto-configure ZCode if installed."""
    home = Path.home()
    zcode_home = Path(os.environ.get("ZCODE_HOME", home / ".zcode"))
    if not zcode_home.is_dir():
        return

    mcp_script = bridge_dir / "mcp_server.py"
    zcode_config = zcode_home / "cli" / "config.json"
    if zcode_config.is_file():
        try:
            cfg = json.loads(zcode_config.read_text())
            cfg.setdefault("mcp", {}).setdefault("servers", {})
            cfg["mcp"]["servers"]["supermemory"] = {
                "command": "python3",
                "args": [str(mcp_script)],
                "timeoutMs": 120000,
            }
            zcode_config.write_text(json.dumps(cfg, indent=2) + "\n")
            _ok(f"Configured ZCode MCP server in {zcode_config}")
        except Exception as e:
            _warn(f"Could not update {zcode_config}: {e}")

    zhooks_dir = zcode_home / "hooks" / "supermemory"
    install_hook_scripts(zhooks_dir, bridge_dir)


# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------

def main() -> int:
    bridge_dir = Path(__file__).resolve().parent

    print("==================================================================")
    print(" Supermemory Auto-Configurator for Sovereign QIHSE Memory Backend ")
    print("==================================================================")

    # Step 1 & 2: Detect QIHSE and grab credentials
    creds = detect_qihse()

    # Step 3: Configure Codex
    configure_codex(bridge_dir)

    # Step 4: Configure ZCode (if present)
    configure_zcode(bridge_dir)

    # Step 5: Enhanced Self-Test & Permissions Verification
    _info("Running enhanced installer self-tests...")
    mcp_script = bridge_dir / "mcp_server.py"
    native_bin = bridge_dir / "supermemory-bridge"
    try:
        init_req = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"capabilities": {}}})
        search_req = json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "search_memory", "arguments": {"query": "test", "limit": 1}}})
        input_payload = f"{init_req}\n{search_req}\n".encode("utf-8")

        proc = subprocess.run(
            ["python3", str(mcp_script)],
            input=input_payload,
            capture_output=True,
            timeout=10,
        )
        if proc.returncode != 0:
            _err(f"MCP server exited with code {proc.returncode}: {proc.stderr.decode()}")
            sys.exit(1)

        lines = [line.strip() for line in proc.stdout.decode().splitlines() if line.strip()]
        if len(lines) < 2:
            _err(f"MCP server returned incomplete responses: {proc.stdout.decode()}")
            sys.exit(1)

        init_resp = json.loads(lines[0])
        if init_resp.get("result", {}).get("serverInfo", {}).get("name") != "qihse-supermemory":
            _err(f"Unexpected MCP initialize response: {lines[0]}")
            sys.exit(1)
        _ok("Python MCP Server protocol check (initialize): PASS")

        search_resp = json.loads(lines[1])
        if "result" not in search_resp or "content" not in search_resp["result"]:
            _err(f"Unexpected MCP tools/call response: {lines[1]}")
            sys.exit(1)
        _ok("Python MCP Server live tools/call (search_memory): PASS")

        # Test native C binary if present
        if native_bin.is_file():
            native_proc = subprocess.run(
                [str(native_bin), "mcp"],
                input=input_payload,
                capture_output=True,
                timeout=10,
            )
            if native_proc.returncode == 0:
                nlines = [line.strip() for line in native_proc.stdout.decode().splitlines() if line.strip()]
                if len(nlines) >= 2:
                    _ok("Native C MCP Server protocol check (initialize & search_memory): PASS")
            else:
                _warn(f"Native binary self-test returned {native_proc.returncode}")
    except Exception as e:
        _err(f"MCP server self-test failed: {e}")
        sys.exit(1)

    # Permissions verification: mode 0600 on env, mode 0755 on hook scripts
    qihse_env_file = Path(os.environ.get("QIHSE_AIMEM_ENV", Path.home() / ".config" / "qihse-aimem" / "env"))
    if qihse_env_file.is_file():
        cur_mode = stat.S_IMODE(qihse_env_file.stat().st_mode)
        if cur_mode != 0o600:
            qihse_env_file.chmod(0o600)
            cur_mode = 0o600
        _ok(f"Verified permissions: mode {oct(cur_mode)} on {qihse_env_file}")

    codex_hooks_dir = Path.home() / ".codex" / "hooks" / "supermemory"
    for hook_file in ("recall_hook.py", "capture_hook.py", "recall_approve.py", "aimem_client.py", "repo_relations.py"):
        hf = codex_hooks_dir / hook_file
        if hf.is_file():
            cur_mode = stat.S_IMODE(hf.stat().st_mode)
            if cur_mode != 0o755:
                hf.chmod(0o755)
                cur_mode = 0o755
            _ok(f"Verified permissions: mode {oct(cur_mode)} on {hf.name}")

    print("\n------------------------------------------------------------------")
    _ok("Supermemory is successfully installed and wired to local QIHSE!")
    print("  - Backend: QIHSE pinned QKP (loopback, sovereign local storage)")
    print("  - MCP Server: Registered in Codex and ZCode")
    print("  - Lifecycle Hooks: Merged cleanly into ~/.codex/hooks.json")
    print("  - Dynamic Relations: repo_relations active with cluster awareness")
    print("  - Cloud Popups: Completely neutralized (no browser windows)")
    print("==================================================================\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
