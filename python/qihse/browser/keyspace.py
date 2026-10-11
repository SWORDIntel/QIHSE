"""Keyspace browsing over authenticated sessions.

The server's SCAN is single-shot (it always returns cursor "0"), so paging
happens client-side: one bounded KEYS/MATCH fetch per node, merge, sort,
flag truncation.  Key metadata (TYPE/TTL/size) is fetched for the VISIBLE
page only — no N+1 over the whole keyspace.

Classification note: the server hides under-cleared keys entirely (the KV
read layer filters by principal before anything is returned).  The browser
renders exactly what the session's principal is allowed to see and never
promises a classification column — per-key classification is not exposed
over RESP.
"""

from __future__ import annotations

from ..controller import ControllerError, ControllerServerError
from .fleet import SessionFleet, api_error

MAX_KEYS_PER_NODE = 5000
META_PAGE = 60                 # metadata lookups per visible page
PREVIEW_BYTES = 4096
PREVIEW_ELEMENTS = 50

SYSTEM_PREFIXES = [
    "fednode:", "fedns:", "fedlease:", "fedleasereq:", "fedleaseres:",
    "fedconf:", "fedreplay:", "fedepoch:", "fedgrp:", "grp:", "task:",
    "federation/",
]


def browse(fleet: SessionFleet, pattern: str = "*", node: int | None = None,
           limit: int = MAX_KEYS_PER_NODE) -> dict:
    """List keys matching pattern.  node=None fans out to all seeds and
    tags each key with the node that returned it."""
    indices = [node] if node is not None else range(len(fleet.nodes))
    keys: list[dict] = []
    truncated = False
    node_errors = []
    for idx in indices:
        try:
            reply = fleet.call(idx, "KEYS", pattern)
        except ControllerError as exc:
            node_errors.append({"node": idx, "error": api_error(exc)})
            continue
        if reply.kind != "array":
            continue
        count = 0
        for item in reply.items[:limit]:
            name = item.value.decode("utf-8", "replace") if item.kind == "bulk" else str(item.value)
            keys.append({"key": name, "node": idx})
            count += 1
        if len(reply.items) > limit:
            truncated = True
    keys.sort(key=lambda e: e["key"])
    return {"keys": keys, "truncated": truncated, "node_errors": node_errors}


def key_meta(fleet: SessionFleet, key: str) -> dict:
    """TYPE/TTL/size for one key, routed to its owner when known."""
    idx = fleet.owner_for_key(key)
    if idx is None:
        idx = fleet.healthy_indices()[0] if fleet.healthy_indices() else 0
    out = {"key": key, "node": idx, "exists": False,
           "type": None, "ttl": None, "size": None, "error": None}
    try:
        t = fleet.call(idx, "TYPE", key)
        type_name = t.value.decode() if t.kind in ("simple", "bulk") else "?"
        out["type"] = type_name
        out["exists"] = type_name != "none"
        if not out["exists"]:
            return out
        ttl = fleet.call(idx, "TTL", key)
        out["ttl"] = ttl.value if ttl.kind == "int" else None
        if type_name == "string":
            out["size"] = fleet.call(idx, "STRLEN", key).value
        elif type_name == "list":
            out["size"] = fleet.call(idx, "LLEN", key).value
        elif type_name == "hash":
            out["size"] = fleet.call(idx, "HLEN", key).value
        elif type_name == "set":
            out["size"] = fleet.call(idx, "SCARD", key).value
        elif type_name == "zset":
            out["size"] = fleet.call(idx, "ZCARD", key).value
    except ControllerError as exc:
        out["error"] = api_error(exc)
    return out


def fetch(fleet: SessionFleet, key: str) -> dict:
    """Type-aware value preview (truncated).  Routed to the slot owner;
    MOVED re-targets once, and only ever to another SEEDED node."""
    out = {"key": key, "error": None}
    idx = fleet.owner_for_key(key)
    if idx is None:
        healthy = fleet.healthy_indices()
        idx = healthy[0] if healthy else 0
    try:
        out.update(_fetch_on(fleet, idx, key))
    except ControllerServerError as exc:
        if exc.error_class == "MOVED":
            target = fleet.moved_retarget(exc.message or "")
            if target is not None and target != idx:
                out.update(_fetch_on(fleet, target, key))
                out["node"] = target
            else:
                out["error"] = {"error_class": "MOVED",
                                "message": "owner is not a seeded node"}
        else:
            out["error"] = api_error(exc)
    except ControllerError as exc:
        out["error"] = api_error(exc)
    return out


def census(fleet: SessionFleet, limit: int = MAX_KEYS_PER_NODE) -> dict:
    """Prefix census over the WHOLE keyspace: every record family the
    session's principal can see, grouped by first path segment.  This is
    the 'browse all records' index — federation records, groups, tasks,
    tenant data, everything, with per-node distribution."""
    listing = browse(fleet, pattern="*", limit=limit)
    families: dict[str, dict] = {}
    for entry in listing["keys"]:
        key = entry["key"]
        prefix = key.split(":", 1)[0] if ":" in key else "(bare)"
        fam = families.setdefault(prefix, {"prefix": prefix, "count": 0,
                                           "nodes": {}, "sample": key})
        fam["count"] += 1
        fam["nodes"][str(entry["node"])] = fam["nodes"].get(str(entry["node"]), 0) + 1
        if len(key) < len(fam["sample"]):
            fam["sample"] = key
    return {"families": sorted(families.values(),
                               key=lambda f: -f["count"]),
            "truncated": listing["truncated"],
            "total": len(listing["keys"]),
            "node_errors": listing["node_errors"]}


def _fetch_on(fleet: SessionFleet, idx: int, key: str) -> dict:
    t = fleet.call(idx, "TYPE", key)
    type_name = t.value.decode() if t.kind in ("simple", "bulk") else "?"
    result = {"node": idx, "type": type_name, "preview": None,
              "preview_kind": None, "truncated": False}
    if type_name == "string":
        raw = fleet.call(idx, "GETRANGE", key, "0", str(PREVIEW_BYTES - 1))
        if raw.kind == "bulk":
            result["preview_kind"] = "text"
            result["preview"] = raw.value.decode("utf-8", "replace")
            result["truncated"] = len(raw.value) >= PREVIEW_BYTES
            # raw hex of the first 256 bytes: every record is inspectable
            # even when it is binary (fingerprints, signatures, envelopes)
            hexhead = fleet.call(idx, "GETRANGE", key, "0", "255")
            if hexhead.kind == "bulk":
                result["hex"] = hexhead.value.hex()
                result["hex_len"] = len(hexhead.value)
    elif type_name == "list":
        reply = fleet.call(idx, "LRANGE", key, "0", str(PREVIEW_ELEMENTS - 1))
        items = [_bulk_text(i) for i in reply.items] if reply.kind == "array" else []
        result["preview_kind"] = "list"
        result["preview"] = items
        result["truncated"] = len(items) >= PREVIEW_ELEMENTS
    elif type_name == "hash":
        reply = fleet.call(idx, "HGETALL", key)
        pairs = []
        if reply.kind == "array":
            it = reply.items
            for i in range(0, len(it) - 1, 2):
                pairs.append([_bulk_text(it[i]), _bulk_text(it[i + 1])])
                if len(pairs) >= PREVIEW_ELEMENTS:
                    break
        result["preview_kind"] = "hash"
        result["preview"] = pairs
        result["truncated"] = len(pairs) >= PREVIEW_ELEMENTS
    elif type_name == "set":
        reply = fleet.call(idx, "SMEMBERS", key)
        items = [_bulk_text(i) for i in reply.items[:PREVIEW_ELEMENTS]] if reply.kind == "array" else []
        result["preview_kind"] = "set"
        result["preview"] = items
        result["truncated"] = len(items) >= PREVIEW_ELEMENTS
    elif type_name == "zset":
        reply = fleet.call(idx, "ZRANGE", key, "0", str(PREVIEW_ELEMENTS - 1), "WITHSCORES")
        items = [_bulk_text(i) for i in reply.items] if reply.kind == "array" else []
        result["preview_kind"] = "zset"
        result["preview"] = [items[i:i + 2] for i in range(0, len(items) - 1, 2)]
        result["truncated"] = len(result["preview"]) >= PREVIEW_ELEMENTS
    return result


def _bulk_text(reply) -> str:
    if reply.kind == "bulk":
        return reply.value.decode("utf-8", "replace")
    if reply.kind == "int":
        return str(reply.value)
    return str(reply.value)
