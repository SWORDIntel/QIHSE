#!/usr/bin/env python3
"""Supermemory-compatible MCP server backed by QIHSE AI memory.

Exposes search/add/forget/count over stdio MCP (JSON-RPC 2.0). QIHSE is the
only backend: memories are stored and recalled through the authenticated
AIMEM RESP path under the configured principal. No cloud, no mirror.

Connection settings come from the environment (QIHSE_RESP_HOST/PORT,
QIHSE_AUTH_USER/PASSWORD) or, when absent, from an env file whose path is
QIHSE_AIMEM_ENV (default ~/.config/qihse-aimem/env, mode 0600).
"""

from __future__ import annotations

import json
import os
import socket
import sys
import threading
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from recall import _Reader
from repo_relations import (
    canonical_repo_name,
    get_current_repo,
    parse_memory_hit,
)
from sync import _qihse_connect, _qihse_command

PROTOCOL_VERSION = "2024-11-05"
SERVER_NAME = "qihse-supermemory"
SERVER_VERSION = "1.1.0"
MAX_TEXT = 256 * 1024
MAX_IDEM = 128
EMPTY_SCOPE_TAIL = ("", "", "")

_conn: socket.socket | None = None
_conn_lock = threading.Lock()  # serializes full request/reply transactions on the shared RESP socket


def _load_env_file() -> None:
    env_path = os.environ.get("QIHSE_AIMEM_ENV")
    if not env_path:
        env_path = str(Path.home() / ".config" / "qihse-aimem" / "env")
    path = Path(env_path)
    if not path.is_file():
        return
    st = path.lstat()
    if path.is_symlink() or st.st_uid != os.getuid() or st.st_mode & 0o077:
        print("qihse-supermemory: env file must be user-owned non-symlink mode 0600", file=sys.stderr)
        sys.exit(1)
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
        print(f"qihse-supermemory: security violation: non-loopback host '{host}' rejected (must be 127.0.0.1)", file=sys.stderr)
        sys.exit(1)


def _close_conn() -> None:
    global _conn
    if _conn is not None:
        try:
            _conn.close()
        except OSError:
            pass
        _conn = None


def _connection() -> socket.socket:
    global _conn
    if _conn is None:
        _conn = _qihse_connect()
    return _conn


def _send(*parts: str):
    with _conn_lock:
        command = parts[1] if len(parts) > 1 else ""
        # A lost reply leaves the outcome of a write unknown: only pure
        # reads and idempotency-keyed STOREs may reconnect and retry.
        retryable = command in ("RECALL-SCOPED", "GET-SCOPED", "COUNT-SCOPED", "PING") or (
            command in ("STORE-SCOPED", "STORE-SCOPED-DURABLE") and len(parts) >= 9
        )
        for attempt in range(2):
            try:
                sock = _connection()
                return _qihse_command(sock, *parts)
            except (OSError, RuntimeError, ValueError):
                _close_conn()
                if attempt == 1 or not retryable:
                    raise


def _tool_error(message: str) -> dict:
    return {"content": [{"type": "text", "text": message}], "isError": True}


def _hit_to_dict(fields: list) -> dict[str, Any]:
    if not isinstance(fields, list) or len(fields) != 7:
        raise RuntimeError("QIHSE returned a malformed memory hit")
    return parse_memory_hit(fields)


def _project_scope(requested: str) -> str:
    """Resolve one native AIMEM project without inspecting memory payloads."""
    value = requested.strip().lower()
    if value == "global":
        return "global"
    current_repo, _ = get_current_repo()
    if value in ("auto", "repo"):
        return canonical_repo_name(current_repo) if current_repo else "global"
    project = canonical_repo_name(value)
    if not project:
        raise ValueError("scope does not resolve to a valid AIMEM project")
    return project


def _scope_args(project: str) -> tuple[str, str, str, str]:
    return (project, *EMPTY_SCOPE_TAIL)


def search_memory(args: dict) -> dict:
    query = args.get("query")
    if not isinstance(query, str) or not query.strip():
        return _tool_error("query must be a non-empty string")
    limit = args.get("limit", 8)
    if not isinstance(limit, int) or not 1 <= limit <= 256:
        return _tool_error("limit must be an integer between 1 and 256")
    mode = args.get("mode", "bm25")
    if mode not in ("bm25", "semantic", "hybrid"):
        return _tool_error("mode must be bm25, semantic, or hybrid")
    kind = args.get("kind", 0)
    if kind not in (0, 1, 2):
        return _tool_error("kind must be 0 (any), 1 (episodic), or 2 (semantic)")
    scope = args.get("scope", "auto")
    if not isinstance(scope, str) or not scope.strip():
        return _tool_error(
            "scope must be a non-empty string ('auto', 'repo', 'global', or repo name)"
        )
    scope = scope.strip().lower()

    try:
        project = _project_scope(scope)
    except ValueError as exc:
        return _tool_error(str(exc))
    fetch_limit = min(256, max(limit * 4, 32))
    value = _send("AIMEM", "RECALL-SCOPED", query, str(fetch_limit), mode,
                  str(kind), *_scope_args(project))
    hits = [_hit_to_dict(f) for f in value or []]

    # QIHSE has already applied the authenticated project boundary.  Do not
    # reclassify or discard those authorized results by inspecting payload text.
    final_hits = []
    for hit in hits[:limit]:
        hit = dict(hit)
        hit["adjusted_score"] = hit["score"]
        hit["matched_scope"] = project
        final_hits.append(hit)
    res: dict[str, Any] = {
        "content": [{"type": "text", "text": json.dumps(final_hits, ensure_ascii=False)}],
        "effective_scope": project,
        "scope_switched": False,
    }
    return res


def get_memory(args: dict) -> dict:
    """Fetch a single authorized AIMEM record without a global search."""
    memory_id = args.get("id")
    if not isinstance(memory_id, str) or not memory_id or len(memory_id) > 128 or "\x00" in memory_id:
        return _tool_error("id must be a non-empty memory identifier (max 128 characters)")
    scope = args.get("scope", "auto")
    if not isinstance(scope, str) or not scope.strip():
        return _tool_error("scope must be a non-empty project selector")
    try:
        project = _project_scope(scope)
    except ValueError as exc:
        return _tool_error(str(exc))
    fields = _send("AIMEM", "GET-SCOPED", memory_id, *_scope_args(project))
    if fields is None:
        # Never differentiate unauthorized and absent records at this layer.
        return _tool_error("memory is not available")
    hit = _hit_to_dict(fields)
    return {"content": [{"type": "text", "text": json.dumps(hit, ensure_ascii=False)}]}


def add_memory(args: dict) -> dict:
    text = args.get("text")
    if not isinstance(text, str) or not text.strip():
        return _tool_error("text must be a non-empty string")
    if len(text.encode("utf-8")) > MAX_TEXT:
        return _tool_error(f"text exceeds {MAX_TEXT} UTF-8 bytes")
    kind = args.get("kind", 2)
    if kind not in (1, 2):
        return _tool_error("kind must be 1 (episodic) or 2 (semantic)")
    idem = args.get("idempotency_key", "")
    if not isinstance(idem, str) or len(idem.encode("utf-8")) > MAX_IDEM:
        return _tool_error(
            f"idempotency_key must be a string of at most {MAX_IDEM} bytes"
        )
    scope = args.get("scope", "auto")
    if not isinstance(scope, str) or not scope.strip():
        return _tool_error(
            "scope must be a non-empty string ('auto', 'repo', 'global', or repo name)"
        )
    scope = scope.strip().lower()
    meta = args.get("metadata")
    if meta is not None and not isinstance(meta, dict):
        return _tool_error("metadata must be an object")

    metadata = dict(meta) if isinstance(meta, dict) else {}
    current_repo, _ = get_current_repo()
    if scope != "global":
        target_repo = (
            current_repo if scope in ("auto", "repo") else canonical_repo_name(scope)
        )
        if target_repo and "repo" not in metadata and "repository" not in metadata:
            metadata["repo"] = target_repo
    if scope:
        metadata.setdefault("scope", scope)

    envelope = {
        "source": "supermemory-mcp",
        "text": text,
        "metadata": metadata,
    }
    if "repo" in metadata:
        envelope["repo"] = metadata["repo"]
    if scope:
        envelope["scope"] = scope

    stored_text = json.dumps(envelope, separators=(",", ":"), ensure_ascii=False)
    if len(stored_text.encode("utf-8")) > MAX_TEXT:
        return _tool_error(f"payload exceeds {MAX_TEXT} UTF-8 bytes")

    try:
        project = _project_scope(scope)
    except ValueError as exc:
        return _tool_error(str(exc))
    parts = ["AIMEM", "STORE-SCOPED-DURABLE", str(kind), stored_text,
             *_scope_args(project)]
    if idem:
        parts.append(idem)
    memory_id = _send(*parts)
    if not isinstance(memory_id, str) or not memory_id:
        raise RuntimeError("QIHSE did not return a memory id")
    resp_obj: dict[str, Any] = {"stored": True, "id": memory_id}
    if "repo" in metadata:
        resp_obj["repo"] = metadata["repo"]
    if scope:
        resp_obj["scope"] = scope
    return {"content": [{"type": "text", "text": json.dumps(resp_obj)}]}


def forget_memory(args: dict) -> dict:
    memory_id = args.get("id")
    if not isinstance(memory_id, str) or not memory_id:
        return _tool_error("id must be a non-empty string")
    scope = args.get("scope", "auto")
    if not isinstance(scope, str) or not scope.strip():
        return _tool_error("scope must be a non-empty project selector")
    try:
        project = _project_scope(scope)
    except ValueError as exc:
        return _tool_error(str(exc))
    result = _send("AIMEM", "FORGET-SCOPED-DURABLE", memory_id,
                   *_scope_args(project))
    forgotten = result in (1, "OK", "1")
    return {
        "content": [
            {
                "type": "text",
                "text": json.dumps({"forgotten": forgotten, "reply": result}),
            }
        ]
    }


def memory_count(args: dict) -> dict:
    kind = args.get("kind", 0)
    if kind not in (0, 1, 2):
        return _tool_error("kind must be 0 (any), 1 (episodic), or 2 (semantic)")
    scope = args.get("scope", "auto")
    if not isinstance(scope, str) or not scope.strip():
        return _tool_error("scope must be a non-empty project selector")
    try:
        project = _project_scope(scope)
    except ValueError as exc:
        return _tool_error(str(exc))
    count = _send("AIMEM", "COUNT-SCOPED", *_scope_args(project), str(kind))
    return {"content": [{"type": "text", "text": json.dumps({"count": int(count)})}]}


TOOLS = [
    {
        "name": "search_memory",
        "description": (
            "Search durable memories in QIHSE (authoritative local memory backend). "
            "Returns scored hits with provenance id, kind, classification, and SCI. "
            "Use mode=semantic for meaning-based matches, bm25 for lexical matches, "
            "hybrid (default) for fused ranking. "
            "Accepts optional scope: auto (the current repository), global (the explicit "
            "global project), repo (the current repository), "
            "or a specific repo name."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Search query"},
                "limit": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 256,
                    "default": 8,
                },
                "mode": {
                    "type": "string",
                    "enum": ["bm25", "semantic", "hybrid"],
                    "default": "bm25",
                },
                "kind": {
                    "type": "integer",
                    "enum": [0, 1, 2],
                    "default": 0,
                    "description": "0 any, 1 episodic, 2 semantic",
                },
                "scope": {
                    "type": "string",
                    "default": "auto",
                    "description": "auto/current repo, global project, repo/current repo, or a specific project",
                },
            },
            "required": ["query"],
        },
    },
    {
        "name": "get_memory",
        "description": (
            "Read one memory by QIHSE UUID under the current authenticated principal. "
            "Returns an exact authorized record with kind, classification, SCI, and created_ms."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "id": {"type": "string", "minLength": 1, "maxLength": 128},
                "scope": {"type": "string", "default": "auto"},
            },
            "required": ["id"],
        },
    },
    {
        "name": "add_memory",
        "description": (
            "Store a durable memory in QIHSE. Kind 1 = episodic (events/turns), "
            "2 = semantic (facts/preferences, default). An idempotency_key makes "
            "replays return the original id instead of duplicating. "
            "Supports optional scope ('auto', 'repo', 'global', or repo name) and metadata dict."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "text": {"type": "string", "description": "Memory content to store"},
                "kind": {"type": "integer", "enum": [1, 2], "default": 2},
                "idempotency_key": {"type": "string", "maxLength": 128},
                "scope": {
                    "type": "string",
                    "default": "auto",
                    "description": "auto (binds to current repo), repo, global, or specific repo name",
                },
                "metadata": {
                    "type": "object",
                    "description": "Structured metadata to attach to the memory",
                },
            },
            "required": ["text"],
        },
    },
    {
        "name": "forget_memory",
        "description": "Delete one memory by its QIHSE id.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "id": {"type": "string", "description": "Memory id from search/add"},
                "scope": {"type": "string", "default": "auto"},
            },
            "required": ["id"],
        },
    },
    {
        "name": "memory_count",
        "description": "Number of memories visible to the current principal.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "kind": {"type": "integer", "enum": [0, 1, 2], "default": 0},
                "scope": {"type": "string", "default": "auto"},
            },
        },
    },
]

HANDLERS = {
    "search_memory": search_memory,
    "get_memory": get_memory,
    "add_memory": add_memory,
    "forget_memory": forget_memory,
    "memory_count": memory_count,
}


def handle(message: Any) -> dict | None:
    if not isinstance(message, dict):
        return {
            "jsonrpc": "2.0",
            "id": None,
            "error": {"code": -32600, "message": "Invalid Request"},
        }

    msg_id = message.get("id")
    if msg_id is not None and not isinstance(msg_id, (str, int, float)):
        return {
            "jsonrpc": "2.0",
            "id": None,
            "error": {"code": -32600, "message": "Invalid Request"},
        }

    if message.get("jsonrpc") != "2.0":
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "error": {"code": -32600, "message": "Invalid Request"},
        }

    if "method" not in message or not isinstance(message["method"], str):
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "error": {"code": -32600, "message": "Invalid Request"},
        }

    method = message["method"]

    if "params" in message and not isinstance(message["params"], (dict, list)):
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "error": {"code": -32602, "message": "Invalid params"},
        }

    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
            },
        }

    if method == "notifications/initialized":
        return None

    if method == "ping":
        return {"jsonrpc": "2.0", "id": msg_id, "result": {}}

    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": msg_id, "result": {"tools": TOOLS}}

    if method == "tools/call":
        params = message.get("params")
        if not isinstance(params, dict):
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "error": {"code": -32602, "message": "Invalid params"},
            }
        name = params.get("name")
        if not isinstance(name, str) or not name:
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "error": {"code": -32602, "message": "Invalid params: name required"},
            }
        handler = HANDLERS.get(name)
        if handler is None:
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "error": {
                    "code": -32601,
                    "message": f"Method not found: unknown tool {name}",
                },
            }
        raw_args = params.get("arguments")
        if raw_args is None:
            raw_args = {}
        elif not isinstance(raw_args, dict):
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "error": {
                    "code": -32602,
                    "message": "Invalid params: arguments must be an object",
                },
            }
        try:
            result = handler(raw_args)
        except Exception as exc:  # tool failure must not kill the server
            result = _tool_error(f"QIHSE backend error ({type(exc).__name__})")
        return {"jsonrpc": "2.0", "id": msg_id, "result": result}

    if msg_id is not None:
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "error": {"code": -32601, "message": "Method not found"},
        }
    return None


def main() -> int:
    _load_env_file()
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            reply = {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32700, "message": "Parse error"},
            }
            sys.stdout.write(json.dumps(reply, ensure_ascii=False) + "\n")
            sys.stdout.flush()
            continue

        try:
            reply = handle(message)
        except Exception as exc:
            msg_id = message.get("id") if isinstance(message, dict) else None
            reply = {
                "jsonrpc": "2.0",
                "id": msg_id,
                "error": {"code": -32603, "message": f"Internal error: {exc}"},
            }

        if reply is not None:
            sys.stdout.write(json.dumps(reply, ensure_ascii=False) + "\n")
            sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
