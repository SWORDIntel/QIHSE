"""HTTP bridge: the browser's ONLY door into the fleet.

Security posture (plan + fable review, all enforced here):

    * Loopback bind only — a non-loopback --bind is refused at startup
      (shipping plaintext HTTP + non-Secure cookies off-host is not a
      configuration the bridge is willing to be).
    * No ambient credentials: the process itself never holds node
      credentials; each login creates a SessionFleet under THAT
      principal, and idle sessions are torn down (Controllers closed).
    * Login is rate-limited per source address and does exactly ONE
      PBKDF2 exchange (single-seed AUTH) per attempt; concurrent logins
      are bounded; request bodies and threads are capped.
    * With --require-webauthn (default) a login for a username with no
      enrolled credential FAILS — no silent single-factor mode.  The
      explicit break-glass flag is --allow-password-only.
    * POSTs carry an X-QIHSE-CSRF header bound to the session.
    * Reads execute on the session's own Controllers; typed server
      refusals (NOPERM/NOAUTH/...) are relayed verbatim — the UI renders
      them, never fabricates emptiness.
    * Guarded actions: allowlist + typed validation + command-bound
      single-use WebAuthn UV assertion (see actions.py / webauthn.py).
"""

from __future__ import annotations

import json
import re
import secrets
import sys
import threading
import time
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from ..controller import (
    ControllerAuthenticationError,
    ControllerConnectionError,
    ControllerError,
)
from . import actions as actions_mod
from . import keyspace as keyspace_mod
from .fleet import NodeSpec, SessionFleet, api_error
from .webauthn import (
    CredentialStore,
    RelyingParty,
    WebAuthnError,
)

MAX_BODY_BYTES = 1 << 20          # 1 MiB
MAX_THREADS = 16
LOGIN_FAILURES_PER_WINDOW = 5
LOGIN_WINDOW_S = 60.0
LOOPBACK_BINDS = {"127.0.0.1", "::1", "localhost"}

REPO_ROOT = Path(__file__).resolve().parents[3]   # python/qihse/browser/ → repo
DASHBOARD_DIST = REPO_ROOT / "dashboard" / "dist"

_STATIC_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".ico": "image/x-icon",
    ".json": "application/json",
    ".woff2": "font/woff2",
    ".map": "application/json",
}


def reply_to_json(reply) -> object:
    """Render a controller Reply as JSON-safe data, byte-exact for text,
    structure preserved for aggregates (renderer of runtime truth)."""
    kind = reply.kind
    if kind in ("simple", "bulk", "verbatim"):
        return reply.value.decode("utf-8", "replace")
    if kind in ("int", "bignum", "bool", "double"):
        return reply.value
    if kind == "nil":
        return None
    if kind == "error":
        return {"__error": reply.value.decode("utf-8", "replace")}
    if kind in ("array", "set", "push"):
        return [reply_to_json(i) for i in reply.items]
    if kind == "map":
        return [[reply_to_json(k), reply_to_json(v)] for k, v in reply.items]
    return f"<unrenderable reply kind {kind!r}>"


class Session:
    __slots__ = ("sid", "username", "csrf", "fleet", "factor", "awaiting_2fa",
                 "created", "last_seen", "action_tokens")

    def __init__(self, sid: str, username: str, fleet: SessionFleet):
        self.sid = sid
        self.username = username
        self.csrf = secrets.token_urlsafe(24)
        self.fleet = fleet
        self.factor = 1
        self.awaiting_2fa = True
        self.created = time.time()
        self.last_seen = time.time()
        # dispatch token → (canonical command, expiry): the bridge between
        # a verified touch and the actual POST /api/action
        self.action_tokens: dict[str, tuple[str, float]] = {}

    def touch(self):
        self.last_seen = time.time()

    def active(self) -> bool:
        return (not self.awaiting_2fa) and self.factor >= 1


class BridgeState:
    def __init__(self, nodes: list[NodeSpec], port: int,
                 require_webauthn: bool, allow_password_only: bool,
                 credentials_path: str,
                 mode: str = "operator",
                 operator_password: str | None = None,
                 qkp_identity_dir: str | None = None,
                 qkp_trusted_pubs: list | None = None):
        self.nodes = nodes
        self.port = port
        # mode "operator": bridge-scoped operator context — no login wall;
        # reads run under the principal configured AT STARTUP (deliberate
        # configured mode, never inferred), mutations still need a FIDO
        # touch.  mode "login": per-principal password (+WebAuthn) login.
        self.mode = mode
        self.operator_fleet: SessionFleet | None = None
        if mode == "operator":
            if not operator_password:
                raise SystemExit(
                    "operator-context mode needs the operator credential at "
                    "startup: pass --password or set QIHSE_OPERATOR_PASSWORD "
                    "(or run with --require-login for per-principal login)")
            self.operator_fleet = SessionFleet(
                nodes, "GODMODE_OP", operator_password,
                qkp_identity_dir=qkp_identity_dir,
                qkp_trusted_pubs=qkp_trusted_pubs)
            print("[browse] OPERATOR CONTEXT: reads run as GODMODE_OP from "
                  "the startup credential; loopback only; guarded actions "
                  "still require a FIDO touch", file=sys.stderr)
        self.require_webauthn = require_webauthn and not allow_password_only
        self.allow_password_only = allow_password_only
        self.cred_store = CredentialStore(credentials_path)
        self.rp = RelyingParty(port)
        self.sessions: dict[str, Session] = {}
        self.sessions_lock = threading.Lock()
        self.login_failures: dict[str, list[float]] = {}
        self.login_lock = threading.Lock()
        self.login_slots = threading.BoundedSemaphore(2)
        self.thread_slots = threading.BoundedSemaphore(MAX_THREADS)
        # (sid, purpose) → (challenge value, expiry): navigator.credentials
        # results cannot echo the challenge back, so the bridge remembers
        # the last one it issued per session+purpose.
        self.last_challenge: dict[tuple[str, str], tuple[str, float]] = {}
        # operator-context dispatch tokens (touch → dispatch), bridge-scoped
        self.op_action_tokens: dict[str, tuple[str, float]] = {}
        # the bridge log: everything that happens, newest last, bounded.
        # kinds: startup | request | auth | webauthn | action | error
        self.log_ring: deque = deque(maxlen=4000)
        self.log_lock = threading.Lock()
        self.log("startup",
                 f"bridge up mode={mode} port={port} "
                 f"nodes={','.join(n.addr() for n in nodes)}")
        self.log("startup",
                 f"credential store {credentials_path}: "
                 f"{len(self.cred_store.usernames())} enrolled user(s); "
                 f"webauthn {'required' if self.require_webauthn else 'not required'}")

    def log(self, kind: str, msg: str):
        entry = {"ts": round(time.time(), 3), "kind": kind, "msg": msg}
        with self.log_lock:
            self.log_ring.append(entry)
        print(f"[browse] {entry['ts']} [{kind}] {msg}",
              file=sys.stderr, flush=True)

    def log_tail(self, limit: int = 200) -> list:
        with self.log_lock:
            return list(self.log_ring)[-limit:]

    # — sessions ──────────────────────────────────────────────────────

    def get_session(self, sid: str | None) -> Session | None:
        if not sid:
            return None
        with self.sessions_lock:
            s = self.sessions.get(sid)
            if s is not None:
                s.touch()
            return s

    def drop_session(self, sid: str):
        with self.sessions_lock:
            s = self.sessions.pop(sid, None)
        if s is not None:
            s.fleet.close()

    def sweep_idle(self, idle_s: float):
        now = time.time()
        stale = []
        with self.sessions_lock:
            for sid, s in list(self.sessions.items()):
                if now - s.last_seen > idle_s:
                    stale.append(sid)
        for sid in stale:
            self.drop_session(sid)
            print(f"[browse] session idle-timeout, controllers torn down "
                  f"({sid[:8]}…)", file=sys.stderr)

    # — login rate limiting ───────────────────────────────────────────

    def login_blocked(self, ip: str) -> bool:
        now = time.time()
        with self.login_lock:
            window = [t for t in self.login_failures.get(ip, [])
                      if now - t < LOGIN_WINDOW_S]
            self.login_failures[ip] = window
            return len(window) >= LOGIN_FAILURES_PER_WINDOW

    def note_login_failure(self, ip: str):
        with self.login_lock:
            self.login_failures.setdefault(ip, []).append(time.time())

    def is_system_principal(self, session: Session) -> bool:
        """Server-verified predicate: the SYSTEM-domain gate on
        FEDERATION.* decides, not a username match."""
        try:
            idx, reply = session.fleet.call_any("FEDERATION", "STATUS",
                                                check=False)
            return reply.kind != "error"
        except ControllerError:
            return False


class BridgeHandler(BaseHTTPRequestHandler):
    server_version = "qihse-browser/1.0"
    protocol_version = "HTTP/1.1"
    state: BridgeState = None          # set by serve()

    # — plumbing ──────────────────────────────────────────────────────

    def log_message(self, fmt, *args):       # route errors to stderr quietly
        print(f"[browse-http] {self.address_string()} {fmt % args}",
              file=sys.stderr)

    def _json(self, code: int, payload: dict, extra_headers=None):
        self._last_status = code
        body = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self) -> dict | None:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return None
        if length <= 0 or length > MAX_BODY_BYTES:
            return None
        raw = self.rfile.read(length)
        try:
            data = json.loads(raw)
            return data if isinstance(data, dict) else None
        except json.JSONDecodeError:
            return None

    def _cookie_sid(self) -> str | None:
        raw = self.headers.get("Cookie", "")
        for part in raw.split(";"):
            k, _, v = part.strip().partition("=")
            if k == "qihse_browse":
                return v
        return None

    def _session(self) -> Session | None:
        return self.state.get_session(self._cookie_sid())

    def _csrf_ok(self, session: Session) -> bool:
        return secrets.compare_digest(self.headers.get("X-QIHSE-CSRF", ""),
                                       session.csrf)

    # — GET routes ────────────────────────────────────────────────────

    def do_GET(self):
        t0 = time.monotonic()
        with self.state.thread_slots:
            self._route_get()
        self.state.log("request",
                       f"GET {self.path.split('?')[0]} "
                       f"{getattr(self, '_last_status', 0)} {int((time.monotonic()-t0)*1000)}ms")

    def do_POST(self):
        t0 = time.monotonic()
        with self.state.thread_slots:
            self._route_post()
        self.state.log("request",
                       f"POST {self.path.split('?')[0]} "
                       f"{getattr(self, '_last_status', 0)} {int((time.monotonic()-t0)*1000)}ms")

    def _oplog(self, msg: str):
        self.state.log("action", msg)

    def _route_get(self):
        url = urlparse(self.path)
        path = url.path
        qs = {k: v[0] for k, v in parse_qs(url.query).items()}

        if path == "/" or not path.startswith("/api/"):
            return self._serve_static(path)

        if self.state.mode == "operator":
            session = None
            fleet = self.state.operator_fleet
            username = "GODMODE_OP"
        else:
            session = self._session()
            if session is None:
                return self._json(401, {"error_class": "NOAUTH",
                                        "message": "no session; log in first"})
            if session.awaiting_2fa and self.state.require_webauthn:
                return self._json(401, {"error_class": "TWO_FACTOR_PENDING",
                                        "message": "complete the WebAuthn ceremony"})
            fleet = session.fleet
            username = session.username
        try:
            if path == "/api/whoami":
                if self.state.mode == "operator":
                    return self._json(200, {
                        "mode": "operator-context",
                        "username": username, "factor": 0,
                        "nodes": [n.addr() for n in self.state.nodes],
                        "csrf": "",
                        "enrolled": bool(self.state.cred_store.usernames()),
                        "system_principal": True,
                    })
                return self._json(200, {
                    "mode": "login",
                    "username": username, "factor": session.factor,
                    "nodes": [n.addr() for n in fleet.nodes],
                    "csrf": session.csrf,
                    "enrolled": bool(self.state.cred_store.usernames()),
                    "system_principal": self.state.is_system_principal(session),
                })
            if path == "/api/overview":
                snap = fleet.snapshot()
                snap["topology"] = fleet.topology()
                return self._json(200, snap)
            if path == "/api/cluster":
                return self._json(200, {"topology": fleet.topology(),
                                        "owners": fleet.slot_owners()})
            if path in ("/api/thermal", "/api/fleet/thermal"):
                from ..thermal import get_fleet_telemetry
                return self._json(200, get_fleet_telemetry())
            if path == "/api/federation/status":
                return self._json(200, fleet.federation())
            if path == "/api/federation/trust":
                return self._json(200, self._fed_trust(fleet))
            if path == "/api/federation/namespaces":
                _, r = fleet.call_any("FEDERATION", "NS.LIST")
                return self._json(200, {"namespaces": reply_to_json(r)})
            if path == "/api/federation/leases":
                return self._json(200, self._fed_leases(fleet, qs))
            if path == "/api/federation/conflicts":
                _, r = fleet.call_any("FEDERATION", "CONFLICT.LIST")
                return self._json(200, {"conflicts": reply_to_json(r)})
            if path == "/api/federation/rejoin":
                _, status = fleet.call_any("FEDERATION", "REJOIN.STATUS")
                out = {"status": reply_to_json(status)}
                try:
                    _, steps = fleet.call_any("FEDERATION", "REJOIN.STEPS")
                    out["steps"] = reply_to_json(steps)
                except ControllerError as exc:
                    out["steps_error"] = api_error(exc)
                return self._json(200, out)
            if path == "/api/federation/repl":
                _, r = fleet.call_any("REPL.STATUS")
                return self._json(200, {"repl": reply_to_json(r)})
            if path == "/api/federation/gossip":
                node = qs.get("node", "")
                boot = qs.get("boot", "")
                if not re.fullmatch(r"[0-9a-fA-F-]{1,64}", node) or \
                        not re.fullmatch(r"[0-9a-fA-F-]{1,64}", boot):
                    return self._json(400, {"error_class": "BAD_ARG",
                                            "message": "node and boot are required"})
                _, r = fleet.call_any("FEDERATION", "GOSSIP.STATUS", node, boot)
                return self._json(200, {"gossip": reply_to_json(r)})
            if path == "/api/federation/epoch":
                out = {}
                for label, cmd in (("current", ["FEDERATION", "EPOCH.CURRENT"]),):
                    try:
                        _, r = fleet.call_any(*cmd)
                        out[label] = reply_to_json(r)
                    except ControllerError as exc:
                        out[label + "_error"] = api_error(exc)
                return self._json(200, out)
            if path == "/api/federation/groups":
                _, listing = fleet.call_any("FEDERATION", "GROUP.LIST")
                groups = []
                for name in (reply_to_json(listing) or [])[:50]:
                    record = {"name": name}
                    try:
                        _, show = fleet.call_any("FEDERATION", "GROUP.SHOW", str(name))
                        record["show"] = reply_to_json(show)
                    except ControllerError as exc:
                        record["show_error"] = api_error(exc)
                    groups.append(record)
                return self._json(200, {"groups": groups})
            if path == "/api/cluster/groups":
                _, listing = fleet.call_any("GROUP.LIST")
                groups = []
                for name in (reply_to_json(listing) or [])[:50]:
                    record = {"name": name}
                    try:
                        _, status = fleet.call_any("GROUP.STATUS", str(name))
                        record["status"] = reply_to_json(status)
                    except ControllerError as exc:
                        record["status_error"] = api_error(exc)
                    groups.append(record)
                return self._json(200, {"groups": groups})
            if path == "/api/fabric":
                _, r = fleet.call_any("FABRIC.CAPS")
                return self._json(200, {"caps": reply_to_json(r)})
            if path == "/api/tasks":
                out = {}
                for label, cmd in (("stats", ["TASK.STATS"]),
                                   ("queue", ["TASK.QUEUE"]),
                                   ("workers", ["TASK.WORKERS"]),
                                   ("schedule", ["SCHEDULE.LIST"])):
                    try:
                        _, r = fleet.call_any(*cmd)
                        out[label] = reply_to_json(r)
                    except ControllerError as exc:
                        out[label + "_error"] = api_error(exc)
                return self._json(200, out)
            if path == "/api/pubsub":
                _, r = fleet.call_any("PUBSUB", "CHANNELS")
                return self._json(200, {"channels": reply_to_json(r)})
            if path == "/api/journal":
                return self._json(200, self._journal(fleet, qs))
            if path == "/api/records/census":
                return self._json(200, keyspace_mod.census(fleet))
            if path == "/api/keys":
                node = int(qs["node"]) if qs.get("node", "").isdigit() else None
                pattern = qs.get("pattern", "*")
                if len(pattern) > 256:
                    return self._json(400, {"error_class": "BAD_ARG",
                                            "message": "pattern too long"})
                return self._json(200, keyspace_mod.browse(
                    fleet, pattern=pattern, node=node))
            if path == "/api/key":
                name = qs.get("name", "")
                if not name or len(name) > 512:
                    return self._json(400, {"error_class": "BAD_ARG",
                                            "message": "name required"})
                detail = keyspace_mod.fetch(fleet, name)
                detail["meta"] = keyspace_mod.key_meta(fleet, name)
                # W7: per-record classification/SCI straight from the
                # server (nil when the principal may not see the record —
                # indistinguishable from a miss, no oracle).
                try:
                    idx, rm = fleet.call_any("INTROSPECTION", "RECORD.META", name)
                    detail["record_meta"] = reply_to_json(rm)
                except ControllerError as exc:
                    detail["record_meta_error"] = api_error(exc)
                return self._json(200, detail)
            if path == "/api/introspection/qkp":
                return self._intros(fleet, ["INTROSPECTION", "QKP"], 10)
            if path == "/api/introspection/bus":
                return self._intros(fleet, ["INTROSPECTION", "BUS"], 12)
            if path == "/api/introspection/crl":
                return self._intros(fleet, ["INTROSPECTION", "CRL"], 3)
            if path == "/api/metrics":
                out = {}
                for label, cmd in (("node", ["METRICS.RENDER"]),
                                   ("federation", ["FEDERATION", "METRICS"])):
                    try:
                        _, r = fleet.call_any(*cmd)
                        out[label] = reply_to_json(r)
                    except ControllerError as exc:
                        out[label + "_error"] = api_error(exc)
                return self._json(200, out)
            if path == "/api/actions":
                return self._json(200, {"actions": actions_mod.schema()})
            if path == "/api/log":
                limit = qs.get("limit", "300")
                n = int(limit) if limit.isdigit() else 300
                return self._json(200, {"log": self.state.log_tail(
                    max(1, min(n, 2000)))})
            if path == "/api/logout":
                return self._json(405, {"error_class": "BAD_METHOD",
                                        "message": "POST /api/logout"})
        except ControllerError as exc:
            return self._json(200, {"error": api_error(exc)})
        return self._json(404, {"error_class": "NOT_FOUND",
                                "message": path})

    # — POST routes ───────────────────────────────────────────────────

    def _route_post(self):
        url = urlparse(self.path)
        path = url.path

        if path == "/api/login/password":
            if self.state.mode == "operator":
                return self._json(403, {
                    "error_class": "LOGIN_DISABLED",
                    "message": "bridge runs in operator-context mode — the "
                               "web UI has no password login; restart with "
                               "--require-login for per-principal login"})
            return self._login_password()

        if self.state.mode == "operator":
            return self._route_post_operator(path)

        session = self._session()
        if session is None:
            return self._json(401, {"error_class": "NOAUTH",
                                    "message": "no session; log in first"})
        if not self._csrf_ok(session):
            return self._json(403, {"error_class": "CSRF",
                                    "message": "missing or wrong X-QIHSE-CSRF"})

        try:
            if path == "/api/logout":
                self.state.drop_session(session.sid)
                return self._json(200, {"ok": True})

            if path == "/api/webauthn/begin":
                body = self._read_json() or {}
                purpose = body.get("purpose", "")
                if purpose == "login":
                    if not session.awaiting_2fa:
                        return self._json(400, {"error_class": "BAD_STATE",
                                                "message": "already authenticated"})
                    options = self.state.rp.begin_login(
                        self.state.cred_store, session.username, session.sid)
                elif purpose == "action":
                    if not self._require_2fa(session):
                        return self._json(403, self._sf_blocked())
                    canonical = actions_mod.canonical_for(
                        session.fleet, body.get("action", ""),
                        body.get("args", {}) if isinstance(body.get("args"), dict) else {})
                    options = self.state.rp.begin_action(
                        session.username, session.sid, canonical)
                    options["bound_command"] = canonical
                elif purpose == "enroll":
                    if not self._require_2fa(session):
                        return self._json(403, self._sf_blocked())
                    options = self.state.rp.begin_enroll(
                        session.username, session.sid)
                else:
                    return self._json(400, {"error_class": "BAD_ARG",
                                            "message": "purpose must be login|action|enroll"})
                options["purpose"] = purpose
                self.state.last_challenge[(session.sid, purpose)] = (
                    options["publicKey"]["challenge"], time.time() + 90)
                return self._json(200, options)

            if path == "/api/webauthn/complete":
                body = self._read_json() or {}
                purpose = body.get("purpose", "")
                credential = body.get("credential", {})
                # The browser cannot read the challenge back out of the
                # credential; bind the assertion to the last challenge
                # issued for this session+purpose.
                challenge = credential.get("_challenge", "")
                if not challenge:
                    credential = dict(credential)
                    credential["_challenge"] = self._pop_pending_challenge(
                        session, purpose)
                if purpose == "login":
                    if not session.awaiting_2fa:
                        return self._json(400, {"error_class": "BAD_STATE",
                                                "message": "already authenticated"})
                    self.state.rp.verify_login(
                        self.state.cred_store, session.username,
                        session.sid, credential)
                    session.awaiting_2fa = False
                    session.factor = 2
                    self._oplog(f"LOGIN 2FA ok principal={session.username}")
                    return self._json(200, {"ok": True, "factor": 2})
                if purpose == "action":
                    if not self._require_2fa(session):
                        return self._json(403, self._sf_blocked())
                    canonical = body.get("command", "")
                    self.state.rp.verify_action(
                        self.state.cred_store, session.username,
                        session.sid, canonical, credential)
                    token = secrets.token_urlsafe(24)
                    self._pending_action_token(session, canonical, token)
                    return self._json(200, {"ok": True, "dispatch_token": token,
                                            "command": canonical})
                if purpose == "enroll":
                    if not self._require_2fa(session):
                        return self._json(403, self._sf_blocked())
                    target_user = body.get("username") or session.username
                    if target_user != session.username and \
                            not self.state.is_system_principal(session):
                        return self._json(403, {
                            "error_class": "NOPERM",
                            "message": "only the system principal may enroll "
                                       "credentials for another user"})
                    cred = self.state.rp.verify_enroll(
                        target_user, session.sid, credential)
                    self.state.cred_store.put(cred)
                    self._oplog(f"ENROLL principal={session.username} "
                                f"for={target_user} aaguid={cred.aaguid}")
                    return self._json(200, {"ok": True,
                                            "credential_id": cred.credential_id})
                return self._json(400, {"error_class": "BAD_ARG",
                                        "message": "purpose must be login|action|enroll"})

            if path == "/api/action":
                return self._dispatch_action(session)

            if path == "/api/keys/delete" or path == "/api/exec":
                # Explicit non-goal: no arbitrary command surface.
                return self._json(403, {"error_class": "NOPERM",
                                        "message": "the bridge is not a "
                                                   "command proxy"})
        except WebAuthnError as exc:
            return self._json(403, {"error_class": exc.code,
                                    "message": exc.message})
        except actions_mod.ActionError as exc:
            return self._json(400, {"error_class": exc.code,
                                    "message": exc.message})
        except ControllerError as exc:
            return self._json(200, {"error": api_error(exc)})

        return self._json(404, {"error_class": "NOT_FOUND", "message": path})

    # — operator-context POSTs: FIDO only, no password surface ────────

    def _route_post_operator(self, path: str):
        state = self.state
        username = "GODMODE_OP"
        bridge_sid = "bridge"

        try:
            body = self._read_json() or {}

            if path == "/api/logout":
                return self._json(200, {"ok": True})

            if path == "/api/webauthn/begin":
                purpose = body.get("purpose", "")
                if purpose == "action":
                    canonical = actions_mod.canonical_for(
                        state.operator_fleet, body.get("action", ""),
                        body.get("args", {}) if isinstance(body.get("args"), dict) else {})
                    options = state.rp.begin_action(username, bridge_sid, canonical)
                    options["bound_command"] = canonical
                elif purpose == "enroll":
                    if state.cred_store.usernames():
                        return self._json(403, {
                            "error_class": "ALREADY_ENROLLED",
                            "message": "a credential is already enrolled; "
                                       "re-enrollment needs a touch-confirmed "
                                       "session (--require-login mode) or a "
                                       "fresh credentials file"})
                    options = state.rp.begin_enroll(username, bridge_sid)
                else:
                    return self._json(400, {"error_class": "BAD_ARG",
                                            "message": "purpose must be action|enroll"})
                options["purpose"] = purpose
                state.last_challenge[(bridge_sid, purpose)] = (
                    options["publicKey"]["challenge"], time.time() + 90)
                return self._json(200, options)

            if path == "/api/webauthn/complete":
                purpose = body.get("purpose", "")
                credential = dict(body.get("credential", {}))
                if not credential.get("_challenge"):
                    credential["_challenge"] = self._pop_bridge_challenge(purpose)
                if purpose == "action":
                    canonical = body.get("command", "")
                    state.rp.verify_action(
                        state.cred_store, username, bridge_sid,
                        canonical, credential)
                    token = secrets.token_urlsafe(24)
                    state.op_action_tokens[token] = (canonical,
                                                     time.time() + 30)
                    self._oplog(f"TOUCH-CONFIRM (operator context) "
                                f"cmd={canonical!r}")
                    return self._json(200, {"ok": True,
                                            "dispatch_token": token,
                                            "command": canonical})
                if purpose == "enroll":
                    cred = state.rp.verify_enroll(username, bridge_sid,
                                                  credential)
                    state.cred_store.put(cred)
                    self._oplog(f"ENROLL (operator context, first key) "
                                f"aaguid={cred.aaguid} — logged loudly")
                    return self._json(200, {"ok": True,
                                            "credential_id": cred.credential_id})
                return self._json(400, {"error_class": "BAD_ARG",
                                        "message": "purpose must be action|enroll"})

            if path == "/api/action":
                action_name = body.get("action", "")
                args = body.get("args", {})
                token = body.get("dispatch_token", "")
                toks = state.op_action_tokens
                bound = toks.get(token)
                if bound is None or time.time() > bound[1]:
                    return self._json(403, {
                        "error_class": "NO_DISPATCH_TOKEN",
                        "message": "missing or expired dispatch token — "
                                   "touch the key (Prepare) again"})
                canonical_bound, _ = bound
                canonical_now = actions_mod.canonical_for(
                    state.operator_fleet, action_name, args)
                if canonical_bound != canonical_now:
                    return self._json(403, {"error_class": "COMMAND_MISMATCH",
                                            "message": "dispatch does not match "
                                                       "the confirmed command"})
                del toks[token]
                result = actions_mod.dispatch(state.operator_fleet,
                                              action_name, args,
                                              log=lambda m: self.state.log("action", m))
                return self._json(200, result)

            if path in ("/api/exec", "/api/keys/delete"):
                return self._json(403, {"error_class": "NOPERM",
                                        "message": "the bridge is not a "
                                                   "command proxy"})
        except WebAuthnError as exc:
            return self._json(403, {"error_class": exc.code,
                                    "message": exc.message})
        except actions_mod.ActionError as exc:
            return self._json(400, {"error_class": exc.code,
                                    "message": exc.message})
        except ControllerError as exc:
            return self._json(200, {"error": api_error(exc)})
        return self._json(404, {"error_class": "NOT_FOUND", "message": path})

    def _pop_bridge_challenge(self, purpose: str) -> str:
        key = ("bridge", purpose)
        record = self.state.last_challenge.get(key)
        if record is None:
            return ""
        value, expires = record
        del self.state.last_challenge[key]
        return value if time.time() < expires else ""

    # — login ─────────────────────────────────────────────────────────

    def _login_password(self):
        ip = self.client_address[0]
        if self.state.login_blocked(ip):
            self.state.log("auth", f"login rate-limited from {ip}")
            return self._json(429, {"error_class": "RATE_LIMITED",
                                    "message": "too many failed logins; wait 60s"})
        body = self._read_json()
        if body is None:
            return self._json(400, {"error_class": "BAD_REQUEST",
                                    "message": "JSON body required"})
        username = body.get("username", "")
        password = body.get("password", "")
        if not isinstance(username, str) or not isinstance(password, str) \
                or not username or len(username) > 64 or len(password) > 256:
            self.state.note_login_failure(ip)
            return self._json(400, {"error_class": "BAD_REQUEST",
                                    "message": "username/password malformed"})

        with self.state.login_slots:                 # bound PBKDF2 fan-out
            fleet = SessionFleet(self.state.nodes, username, password)
            try:
                fleet.connect_seed()                 # ONE PBKDF2 exchange
            except ControllerAuthenticationError:
                fleet.close()
                self.state.note_login_failure(ip)
                self.state.log("auth",
                               f"login refused principal={username} bad-credentials")
                return self._json(401, {"error_class": "NOAUTH",
                                        "message": "bad credentials"})
            except ControllerConnectionError as exc:
                fleet.close()
                return self._json(503, {"error_class": "DOWN",
                                        "message": f"no seed node reachable: {exc}"})

        # Fail-closed second factor: no credential → refuse (unless the
        # explicit break-glass flag is set on the command line).
        creds = self.state.cred_store.for_username(username)
        if self.state.require_webauthn and not creds:
            fleet.close()
            self._oplog(f"LOGIN refused principal={username} "
                        f"reason=no_enrolled_credential")
            return self._json(403, {"error_class": "NO_CREDENTIAL",
                                    "message": "no WebAuthn credential enrolled "
                                               "for this user; enroll first or "
                                               "restart with "
                                               "--allow-password-only"})
        if not creds and self.state.allow_password_only:
            session = self._install_session(username, fleet)
            session.awaiting_2fa = False
            session.factor = 1
            self._oplog(f"LOGIN single-factor (break-glass) "
                        f"principal={username}")
            return self._json(200, {"status": "ok", "factor": 1,
                                    "csrf": session.csrf},
                              self._cookie_headers(session))
        # creds exist → two-step ceremony
        session = self._install_session(username, fleet)
        self.state.log("auth",
                       f"password ok principal={username}; awaiting FIDO factor")
        return self._json(200, {"status": "webauthn_required",
                                "csrf": session.csrf},
                          self._cookie_headers(session))

    def _install_session(self, username: str, fleet: SessionFleet) -> Session:
        sid = secrets.token_urlsafe(32)
        session = Session(sid, username, fleet)
        with self.state.sessions_lock:
            self.state.sessions[sid] = session
        return session

    def _cookie_headers(self, session: Session) -> dict:
        return {"Set-Cookie":
                f"qihse_browse={session.sid}; HttpOnly; SameSite=Strict; "
                f"Path=/; Max-Age=86400"}

    # — action dispatch ───────────────────────────────────────────────

    def _require_2fa(self, session: Session) -> bool:
        return session.factor >= 2 and not session.awaiting_2fa

    def _sf_blocked(self) -> dict:
        return {"error_class": "TWO_FACTOR_REQUIRED",
                "message": "guarded actions require a two-factor session"}

    def _pending_action_token(self, session: Session, canonical: str,
                              token: str):
        session.action_tokens[token] = (canonical, time.time() + 30)
        for t in [t for t, (_, exp) in session.action_tokens.items()
                  if exp < time.time()]:
            del session.action_tokens[t]

    def _pop_pending_challenge(self, session: Session, purpose: str) -> str:
        key = (session.sid, purpose)
        record = self.state.last_challenge.get(key)
        if record is None:
            return ""
        value, expires = record
        del self.state.last_challenge[key]      # single-use
        return value if time.time() < expires else ""

    def _dispatch_action(self, session: Session):
        if not self._require_2fa(session):
            return self._json(403, self._sf_blocked())
        body = self._read_json()
        if body is None:
            return self._json(400, {"error_class": "BAD_REQUEST",
                                    "message": "JSON body required"})
        action_name = body.get("action", "")
        args = body.get("args", {})
        token = body.get("dispatch_token", "")
        credential = body.get("credential", {}) if isinstance(
            body.get("credential"), dict) else {}
        toks = session.action_tokens
        bound = toks.get(token)
        if bound is None or time.time() > bound[1]:
            return self._json(403, {"error_class": "NO_DISPATCH_TOKEN",
                                    "message": "missing or expired dispatch "
                                               "token (touch confirm again)"})
        canonical_bound, _ = bound
        canonical_now = actions_mod.canonical_for(session.fleet,
                                                  action_name, args)
        if canonical_bound != canonical_now:
            return self._json(403, {"error_class": "COMMAND_MISMATCH",
                                    "message": "dispatch does not match the "
                                               "confirmed command"})
        del toks[token]
        if credential:
            # Optional second signal: re-verify the same assertion binding
            self.state.rp.verify_action(
                self.state.cred_store, session.username, session.sid,
                canonical_now, credential)
        result = actions_mod.dispatch(session.fleet, action_name, args,
                                      log=lambda m: self.state.log("action", m))
        return self._json(200, result)

    def _intros(self, fleet, cmd, expect):
        _, r = fleet.call_any(*cmd)
        vals = reply_to_json(r)
        out = {"values": vals if isinstance(vals, list) else None}
        if not isinstance(vals, list) or len(vals) != expect:
            out["shape_error"] = f"expected {expect} values"
        return self._json(200, out)

    # — federation helpers ────────────────────────────────────────────

    def _fed_trust(self, fleet: SessionFleet) -> dict:
        _, listing = fleet.call_any("FEDERATION", "NODE.LIST")
        nodes = reply_to_json(listing)
        details = []
        trips: list = nodes if isinstance(nodes, list) else []
        for trip in trips[:100]:
            if isinstance(trip, (list, tuple)) and trip:
                uuid = trip[0]
                detail = {"uuid": uuid}
                if isinstance(uuid, str) and \
                        re.fullmatch(r"[0-9a-fA-F-]{1,64}", uuid):
                    try:
                        _, show = fleet.call_any("FEDERATION", "NODE.SHOW", uuid)
                        detail["show"] = reply_to_json(show)
                    except ControllerError as exc:
                        detail["show_error"] = api_error(exc)
                details.append(detail)
        return {"nodes": details}

    def _fed_leases(self, fleet: SessionFleet, qs: dict) -> dict:
        listing = keyspace_mod.browse(fleet, pattern="fedlease:*", limit=50)
        leases = []
        for entry in listing["keys"][:50]:
            lease_id = entry["key"].split(":", 1)[-1]
            record = {"key": entry["key"], "lease_id": lease_id}
            try:
                _, r = fleet.call_any("FEDERATION", "LEASE.READ", lease_id)
                record["read"] = reply_to_json(r)
            except ControllerError as exc:
                record["read_error"] = api_error(exc)
            leases.append(record)
        return {"leases": leases, "truncated": listing["truncated"]}

    def _journal(self, fleet: SessionFleet, qs: dict) -> dict:
        cursor = qs.get("cursor", "0")
        if not re.fullmatch(r"[0-9]{1,20}", cursor):
            cursor = "0"
        count = qs.get("count", "20")
        n = int(count) if count.isdigit() else 20
        n = max(1, min(n, 100))
        _, length = fleet.call_any("FEDERATION", "EVENT.LENGTH")
        _, replay = fleet.call_any("FEDERATION", "EVENT.REPLAY", cursor)
        entries = reply_to_json(replay)
        for e in (entries if isinstance(entries, list) else []):
            _annotate_brain(e)
        return {"length": reply_to_json(length), "cursor": cursor,
                "entries": entries}

    # — static (dashboard build, if present) ──────────────────────────

    def _serve_static(self, path: str):
        self._last_status = 200
        if not DASHBOARD_DIST.is_dir():
            self._json(200, {
                "app": "qihse-browser",
                "hint": "API is live; build the UI with "
                        "(cd dashboard && npm ci && npm run build), or use "
                        "vite dev with the /api proxy",
            })
            return
        rel = "index.html" if path == "/" else path.lstrip("/")
        target = (DASHBOARD_DIST / rel).resolve()
        try:
            target.relative_to(DASHBOARD_DIST.resolve())
        except ValueError:
            self._json(403, {"error_class": "FORBIDDEN"})
            return
        if not target.is_file():
            target = DASHBOARD_DIST / "index.html"   # SPA fallback
        ctype = _STATIC_TYPES.get(target.suffix.lower(),
                                  "application/octet-stream")
        body = target.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _annotate_brain(entry) -> None:
    """Mark brain journal envelopes (QHBO/QHBD) in a rendered entry so the
    UI can show magic without claiming to verify (ML-DSA verify stays in
    the C helpers)."""
    if not isinstance(entry, (list, dict)):
        return
    text = json.dumps(entry)[:4096]
    if "QHBO" in text:
        entry_marker = entry if isinstance(entry, dict) else None
        if entry_marker is not None:
            entry_marker["_brain"] = {"magic": "QHBO", "verified": False}
    elif "QHBD" in text:
        if isinstance(entry, dict):
            entry["_brain"] = {"magic": "QHBD", "verified": False}


def serve(nodes: list[NodeSpec], port: int, bind: str,
          require_webauthn: bool, allow_password_only: bool,
          credentials_path: str,
          mode: str = "operator",
          operator_password: str | None = None,
          extra_actions: str | None = None,
          qkp_identity_dir: str | None = None,
          qkp_trusted_pubs: list | None = None):
    if bind not in LOOPBACK_BINDS:
        raise SystemExit(
            f"refusing non-loopback bind {bind!r}: the bridge serves "
            f"plaintext HTTP and non-Secure cookies; use SSH port "
            f"forwarding instead (ssh -L {port}:127.0.0.1:{port})")
    if extra_actions:
        from . import actions as _actions
        try:
            n = _actions.load_extra(extra_actions,
                                    log=lambda m: print(f"[browse] {m}",
                                                        file=sys.stderr))
            print(f"[browse] {n} extra action(s) loaded from {extra_actions}",
                  file=sys.stderr)
        except (OSError, ValueError) as exc:
            raise SystemExit(f"extra-actions file {extra_actions!r} unusable: {exc}")
        except _actions.ActionError as exc:
            raise SystemExit(f"extra-actions file {extra_actions!r}: "
                             f"{exc.code}: {exc.message}")
    state = BridgeState(nodes, port, require_webauthn, allow_password_only,
                        credentials_path, mode=mode,
                        operator_password=operator_password)
    BridgeHandler.state = state

    httpd = ThreadingHTTPServer((bind, port), BridgeHandler)
    httpd.daemon_threads = True

    def _sweeper():
        while True:
            time.sleep(30)
            state.sweep_idle(900)

    threading.Thread(target=_sweeper, daemon=True).start()
    print(f"[browse] bridge on http://localhost:{port} "
          f"(nodes: {', '.join(n.addr() for n in nodes)})", file=sys.stderr)
    print(f"[browse] open http://localhost:{port} — over SSH: "
          f"ssh -L {port}:127.0.0.1:{port}", file=sys.stderr)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        if state.operator_fleet is not None:
            state.operator_fleet.close()
        with state.sessions_lock:
            for s in state.sessions.values():
                s.fleet.close()
