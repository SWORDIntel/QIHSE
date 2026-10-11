"""Session-scoped fleet of authenticated Controllers.

Security model:

    * Nodes are EXPLICIT seeds only (--node / QIHSE_NODE0_HOST/PORT).
      CLUSTER NODES output is parsed for *display* and is NEVER dialed:
      a spoofed node must not be able to make this process connect and
      AUTH anywhere (credential-exfiltration fix from the plan review).
    * One Controller per node per SESSION, authenticated with the
      session's own credentials.  There is no shared/background
      system-credential poller — a session can only ever see what its
      own principal can see (confused-deputy fix).
    * Command execution is serialized per node by a lock; the Controller
      is synchronous/single-socket.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field

from ..controller import (
    Controller,
    ControllerAuthenticationError,
    ControllerConnectionError,
    ControllerError,
    ControllerServerError,
    ControllerTimeoutError,
    ControllerTransportError,
)

IDLE_TIMEOUT_S = 900          # 15 minutes: then Controllers are torn down
FEDERATION_CACHE_S = 5.0      # federation tab data is on-demand, short TTL


@dataclass(frozen=True)
class NodeSpec:
    host: str
    port: int

    def addr(self) -> str:
        return f"{self.host}:{self.port}"


def parse_node_arg(text: str) -> NodeSpec:
    host, sep, port = text.rpartition(":")
    if not sep or not host or not port.isdigit() or not (1 <= int(port) <= 65535):
        raise ValueError(f"bad node address {text!r} (expected host:port)")
    return NodeSpec(host, int(port))


def api_error(exc: Exception) -> dict:
    """Translate a controller exception into a JSON-safe error object.
    The server's own error class is preserved verbatim; the bridge never
    fabricates a different refusal."""
    if isinstance(exc, ControllerServerError):
        return {"error_class": exc.error_class, "message": exc.message}
    if isinstance(exc, ControllerAuthenticationError):
        return {"error_class": "NOAUTH", "message": str(exc)}
    if isinstance(exc, (ControllerConnectionError,)):
        return {"error_class": "DOWN", "message": str(exc)}
    if isinstance(exc, (ControllerTimeoutError, ControllerTransportError)):
        return {"error_class": "UNREACHABLE", "message": str(exc)}
    if isinstance(exc, ControllerError):
        return {"error_class": "BRIDGE_CLIENT", "message": str(exc)}
    return {"error_class": "INTERNAL", "message": f"{type(exc).__name__}: {exc}"}


class _NodeState:
    __slots__ = ("controller", "lock", "last_error", "down_since")

    def __init__(self):
        self.controller: Controller | None = None
        self.lock = threading.Lock()
        self.last_error: str | None = None
        self.down_since: float | None = None


class SessionFleet:
    """All Controllers authenticated as ONE principal (the session's)."""

    def __init__(self, nodes: list[NodeSpec], username: str, password: str,
                 timeout_ms: int = 20000,
                 qkp_identity_dir: str | None = None,
                 qkp_trusted_pubs: list | None = None):
        # Default 20 s: AUTH runs the server-side CNSA 2.0 KDF (PBKDF2
        # 600k iterations), which alone can take seconds.
        self.qkp_identity_dir = qkp_identity_dir
        self.qkp_trusted_pubs = list(qkp_trusted_pubs) if qkp_trusted_pubs else []
        if not nodes:
            raise ValueError("fleet needs at least one seed node")
        self.nodes = list(nodes)
        self.username = username
        self.password = password
        self.timeout_ms = timeout_ms
        self._states = [_NodeState() for _ in self.nodes]
        self._closed = False
        self._fed_cache: tuple[float, dict] | None = None
        self._fed_lock = threading.Lock()
        self.created_at = time.time()
        self.last_used = time.time()

    # — connection management ─────────────────────────────────────────

    def connect_seed(self, timeout_ms: int | None = None) -> int:
        """Authenticate against the first reachable seed.  Raises
        ControllerAuthenticationError on bad credentials (any node that
        answers must refuse them); connection errors skip to the next
        seed.  Only ONE PBKDF2 exchange happens per login attempt
        (login-DoS bound)."""
        last_conn_error: Exception | None = None
        for idx, spec in enumerate(self.nodes):
            try:
                self._ensure(idx)
                return idx
            except ControllerAuthenticationError:
                # Credentials are cluster-wide; a refusal is final.
                for st in self._states:
                    if st.controller is not None:
                        st.controller.close()
                        st.controller = None
                raise
            except (ControllerConnectionError,) as exc:
                last_conn_error = exc
                continue
        raise last_conn_error or ControllerConnectionError("no seed reachable")

    def _ensure(self, idx: int) -> Controller:
        st = self._states[idx]
        if st.controller is not None and st.controller.connected:
            return st.controller
        spec = self.nodes[idx]
        kwargs = dict(username=self.username, password=self.password,
                      timeout_ms=self.timeout_ms, connect=False)
        if self.qkp_identity_dir:
            kwargs.update(qkp_identity_dir=self.qkp_identity_dir,
                          qkp_trusted_pubs=self.qkp_trusted_pubs)
        ctrl = Controller(spec.host, spec.port, **kwargs)
        ctrl.connect()          # AUTH happens here (PBKDF2, multi-second)
        st.controller = ctrl
        st.last_error = None
        st.down_since = None
        return ctrl

    def close(self):
        self._closed = True
        for st in self._states:
            if st.controller is not None:
                try:
                    st.controller.close()
                except Exception:
                    pass
                st.controller = None

    # — command execution (under the requesting principal's identity) ─

    def call(self, idx: int, *args, check: bool = True):
        """Run one command on node idx.  Dead connections reconnect
        (re-AUTH) once, then surface as DOWN."""
        self.last_used = time.time()
        st = self._states[idx]
        for attempt in (0, 1):
            try:
                with st.lock:
                    ctrl = self._ensure(idx)
                    return ctrl.call(*args, check=check)
            except ControllerAuthenticationError:
                raise
            except (ControllerConnectionError, ControllerTimeoutError,
                    ControllerTransportError) as exc:
                st.last_error = str(exc)
                st.down_since = st.down_since or time.time()
                with st.lock:
                    if st.controller is not None:
                        try:
                            st.controller.close()
                        except Exception:
                            pass
                        st.controller = None
                if attempt == 1:
                    raise

    def call_any(self, *args, check: bool = True):
        """Run on the first node that answers (single-node facts like
        FEDERATION.STATUS or CLUSTER topology are fleet-wide).  Returns
        (node_idx, reply) or raises the last error."""
        last: Exception | None = None
        for idx in range(len(self.nodes)):
            try:
                return idx, self.call(idx, *args, check=check)
            except ControllerAuthenticationError:
                raise
            except ControllerError as exc:
                last = exc
                continue
        raise last or ControllerConnectionError("no node answered")

    def healthy_indices(self) -> list[int]:
        out = []
        for idx in range(len(self.nodes)):
            try:
                self.call(idx, "PING")
                out.append(idx)
            except ControllerError:
                continue
        return out

    def spec_for_addr(self, host: str, port: int) -> int | None:
        """Map a host:port back to a SEEDED node index — the only
        addresses this process will ever talk to."""
        host_l = host.lower()
        for idx, spec in enumerate(self.nodes):
            if spec.host.lower() == host_l and spec.port == port:
                return idx
        return None

    def moved_retarget(self, moved_message: str) -> int | None:
        """'-MOVED 1234 10.0.0.5:7101' → seeded index or None.  A MOVED
        pointing at an unseeded address is an error, not a dial."""
        parts = moved_message.split()
        if len(parts) >= 3 and ":" in parts[2]:
            host, _, port = parts[2].rpartition(":")
            if port.isdigit():
                idx = self.spec_for_addr(host, int(port))
                if idx is not None:
                    return idx
        return None

    # — snapshots ─────────────────────────────────────────────────────

    def snapshot(self) -> dict:
        """Core per-node state (cheap commands only, ~1 RTT each)."""
        now = time.time()
        nodes = []
        cluster_summary = None
        for idx, spec in enumerate(self.nodes):
            entry = {"index": idx, "addr": spec.addr(),
                     "up": False, "latency_ms": None,
                     "role": None, "dbsize": None, "error": None,
                     "age_s": None}
            t0 = time.monotonic()
            try:
                role = self.call(idx, "ROLE")
                entry["role"] = role.value.decode() if role.kind == "simple" else (
                    [i.value.decode() if i.kind in ("simple", "bulk") else str(i.value)
                     for i in role.items] if role.kind == "array" else str(role.value))
                entry["dbsize"] = self.call(idx, "DBSIZE").value
                # cheap INFO for identity/version/clients (one blob, fixed cost)
                info = self.call(idx, "INFO", check=False)
                if info.kind == "bulk":
                    parsed = _parse_kv_blob(info.value)
                    entry["clients"] = parsed.get("connected_clients")
                    entry["version"] = parsed.get("qihse_version") \
                        or parsed.get("redis_version")
                    entry["pubsub_channels"] = parsed.get("active_channels")
                myid = self.call(idx, "CLUSTER", "MYID", check=False)
                if myid.kind in ("bulk", "simple"):
                    entry["id"] = myid.value.decode("utf-8", "replace")
                # per-node federation state (NOPERM renders as such)
                fed = self.call(idx, "FEDERATION", "STATUS", check=False)
                if fed.kind == "bulk":
                    import json as _json
                    try:
                        entry["fed_state"] = _json.loads(
                            fed.value.decode("utf-8", "replace")
                        ).get("federation_state")
                    except (ValueError, AttributeError):
                        pass
                elif fed.kind == "error":
                    entry["fed_state"] = fed.value.decode(
                        "utf-8", "replace").split(maxsplit=1)[-1][:40]
                entry["up"] = True
                entry["latency_ms"] = round((time.monotonic() - t0) * 1000.0, 2)
            except ControllerError as exc:
                entry["error"] = api_error(exc)
            nodes.append(entry)
        # Topology/summary from any one node — display-only, never dialed.
        try:
            _, info = self.call_any("CLUSTER", "INFO")
            cluster_summary = _parse_kv_blob(info.value)
        except ControllerError as exc:
            cluster_summary = {"error": api_error(exc)}
        owners = self.slot_owners()
        for entry in nodes:
            entry["slots"] = owners.get(entry["addr"].lower(), 0)
        return {"ts": now, "nodes": nodes, "cluster": cluster_summary}

    def topology(self) -> dict:
        """CLUSTER NODES + SLOTS rendered for display; the addresses in
        here are NOT connection targets for this process."""
        out = {"nodes_text": [], "slots": [], "error": None}
        try:
            _, nodes_reply = self.call_any("CLUSTER", "NODES")
            for line in nodes_reply.value.decode("utf-8", "replace").splitlines():
                if line.strip():
                    out["nodes_text"].append(_parse_cluster_node_line(line))
        except ControllerError as exc:
            out["error"] = api_error(exc)
        try:
            _, slots_reply = self.call_any("CLUSTER", "SLOTS")
            if slots_reply.kind == "array":
                for run in slots_reply.items:
                    if run.kind == "array" and len(run.items) >= 3:
                        start = int(run.items[0].value)
                        end = int(run.items[1].value)
                        owner = run.items[2]
                        host = (owner.items[0].value.decode()
                                if owner.kind == "array" and owner.items else "?")
                        port = (int(owner.items[1].value)
                                if owner.kind == "array" and len(owner.items) > 1 else 0)
                        nid = (owner.items[2].value.decode()
                               if owner.kind == "array" and len(owner.items) > 2 else "?")
                        out["slots"].append({"start": start, "end": end,
                                             "count": end - start + 1,
                                             "owner_id": nid,
                                             "owner_addr": f"{host}:{port}"})
        except ControllerError as exc:
            out["error"] = out["error"] or api_error(exc)
        return out

    def slot_owners(self) -> dict[str, int]:
        """Map 'host:port' (lowercased) → owned slot count, from SLOTS."""
        owners: dict[str, int] = {}
        for run in self.topology()["slots"]:
            owners[run["owner_addr"].lower()] = \
                owners.get(run["owner_addr"].lower(), 0) + run["count"]
        return owners

    def owner_for_key(self, key: str) -> int | None:
        """Index of the seeded node that owns key's slot, or None when
        unknown (caller falls back to first healthy node)."""
        from .slots import keyslot
        slot = keyslot(key)
        try:
            _, slots_reply = self.call_any("CLUSTER", "SLOTS")
        except ControllerError:
            return None
        if slots_reply.kind != "array":
            return None
        for run in slots_reply.items:
            if run.kind != "array" or len(run.items) < 3:
                continue
            try:
                start = int(run.items[0].value)
                end = int(run.items[1].value)
                owner = run.items[2]
                host = owner.items[0].value.decode()
                port = int(owner.items[1].value)
            except (ValueError, IndexError, AttributeError):
                continue
            if start <= slot <= end:
                return self.spec_for_addr(host, port)
        return None

    # — federation (on-demand, cached briefly; operator-tab data) ─────

    def federation(self) -> dict:
        with self._fed_lock:
            now = time.time()
            if self._fed_cache and now - self._fed_cache[0] < FEDERATION_CACHE_S:
                return self._fed_cache[1]
        out: dict = {"status": None, "error": None}
        try:
            _, reply = self.call_any("FEDERATION", "STATUS")
            import json as _json
            out["status"] = _json.loads(reply.value.decode("utf-8", "replace"))
        except ControllerError as exc:
            out["error"] = api_error(exc)
        with self._fed_lock:
            self._fed_cache = (now, out)
        return out


def _parse_kv_blob(reply_value) -> dict:
    text = reply_value.decode("utf-8", "replace") if isinstance(reply_value, (bytes, bytearray)) else str(reply_value)
    out = {}
    for line in text.splitlines():
        if line and not line.startswith("#") and ":" in line:
            k, _, v = line.partition(":")
            out[k] = v
    return out


def _parse_cluster_node_line(line: str) -> dict:
    """Redis CLUSTER NODES line → dict (display only)."""
    parts = line.split()
    flags = parts[3].split(",") if len(parts) > 3 else []
    return {
        "id": parts[0] if parts else "?",
        "addr": parts[1] if len(parts) > 1 else "?",
        "flags": flags,
        "myself": "myself" in flags,
        "master": parts[4] if len(parts) > 4 and parts[4] != "-" else None,
        "ping_sent": parts[5] if len(parts) > 5 else None,
        "pong_recv": parts[6] if len(parts) > 6 else None,
        "config_epoch": parts[7] if len(parts) > 7 else None,
        "link_state": parts[8] if len(parts) > 8 else None,
        "slots": parts[9:] if len(parts) > 9 else [],
    }
