#!/usr/bin/env python3
"""Browser negative-authorization test (AGENTS.md invariant 3).

Spawned by tests/qihse_browser_fixture.c, which owns the principals and
the classified data.  This script starts the REAL bridge (the adapter
under test) against the fixture node and asserts over HTTP:

  * unauthenticated requests     -> 401 on every /api/* surface
  * low-clearance login          -> classified key NAMES are absent from
                                    /api/keys and values absent from
                                    /api/key (server-side filtering must
                                    hold through the adapter)
  * FEDERATION surfaces          -> NOPERM relayed verbatim (analyst is
                                    not the system tenant), never faked
                                    emptiness
  * single-factor sessions       -> guarded actions refused (403)
  * command-proxy attempts       -> refused outright (403)
  * mandatory WebAuthn           -> login with no enrolled credential
                                    FAILS CLOSED (403 NO_CREDENTIAL)
                                    unless --allow-password-only
  * login rate limiting          -> 429 after repeated failures
  * CSRF                         -> POST without the session header -> 403

Run standalone (fixture must be running):
  PYTHONPATH=python python3 python/tests/test_browser_negative_auth.py --port 7390
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
BRIDGE_PORT = 8091          # NEVER 8000 (reserved)

OPERATOR = ("GODMODE_OP", "FixtureOpPass1!")
ANALYST = ("fixture_analyst", "AnalystPass123!")
TENANT = ("fixture_tenant", "TenantPass1234!")
SENTINELS = ["SENTINEL-VALUE-9174", "SENTINEL-VALUE-5309"]
CLASSIFIED_KEYS = ["sec:natsec-brief", "sec:codeword-roster"]
PUBLIC_KEYS = ["pub:welcome", "pub:status"]

PASS = 0


def ok(name, cond, detail=""):
    global PASS
    if not cond:
        print(f"[FAIL] {name} {detail}")
        raise SystemExit(1)
    PASS += 1
    print(f"[PASS] {name}")


class Http:
    """Tiny cookie-aware JSON client (stdlib only)."""

    def __init__(self, base: str):
        self.base = base
        self.cookie: str | None = None
        self.csrf: str | None = None

    def request(self, method: str, path: str, body: dict | None = None,
                timeout: float = 90.0, send_csrf: bool = True):
        url = f"{self.base}{path}"
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method)
        if data is not None:
            req.add_header("Content-Type", "application/json")
        if self.cookie:
            req.add_header("Cookie", self.cookie)
        if send_csrf and self.csrf and method == "POST":
            req.add_header("X-QIHSE-CSRF", self.csrf)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                setc = resp.headers.get("Set-Cookie")
                if setc and "qihse_browse=" in setc:
                    self.cookie = setc.split(";")[0]
                payload = json.loads(resp.read().decode())
                return resp.status, payload
        except urllib.error.HTTPError as e:
            try:
                payload = json.loads(e.read().decode())
            except Exception:
                payload = {}
            return e.code, payload


def start_bridge(port: int, creds_path: str, extra: list[str],
                 extra_env: dict | None = None):
    env = os.environ.copy()
    env["PYTHONPATH"] = os.path.join(REPO, "python")
    env["LD_LIBRARY_PATH"] = REPO
    env.pop("QIHSE_OPERATOR_PASSWORD", None)
    env.update(extra_env or {})
    proc = subprocess.Popen(
        [sys.executable, "-m", "qihse.browser",
         "--node", f"127.0.0.1:{port}", "--port", str(BRIDGE_PORT),
         "--credentials", creds_path] + extra,
        cwd=REPO, env=env,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    for _ in range(100):
        time.sleep(0.1)
        if proc.poll() is not None:
            out = proc.stdout.read().decode("utf-8", "replace")
            raise SystemExit(f"bridge exited rc={proc.returncode}: {out[:1600]}")
        try:
            with urllib.request.urlopen(
                    f"http://127.0.0.1:{BRIDGE_PORT}/", timeout=1) as r:
                r.read()
                return proc
        except urllib.error.HTTPError:
            return proc
        except Exception:
            continue
    proc.terminate()
    out = proc.stdout.read().decode("utf-8", "replace")
    raise SystemExit(f"bridge did not come up: {out[:1600]}")


def stop(proc):
    proc.send_signal(signal.SIGTERM)
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()


def main() -> int:
    port = 7390
    if "--port" in sys.argv:
        port = int(sys.argv[sys.argv.index("--port") + 1])

    with tempfile.TemporaryDirectory(prefix="qihse_browser_test_") as td:
        creds = os.path.join(td, "creds.json")

        # ── Phase 1: DEFAULT operator-context mode (no login wall,
        #    FIDO-only mutation gate; credential from startup env) ────
        proc = start_bridge(port, creds, [],
                            extra_env={"QIHSE_OPERATOR_PASSWORD": OPERATOR[1]})
        try:
            fresh = Http(f"http://127.0.0.1:{BRIDGE_PORT}")
            code, body = fresh.request("GET", "/api/whoami")
            ok("operator-context: whoami without login",
               code == 200 and body.get("mode") == "operator-context",
               f"code={code} body={body}")
            code, body = fresh.request("GET", "/api/overview")
            ok("operator-context: overview serves without login wall",
               code == 200 and isinstance(body.get("nodes"), list) and
               len(body["nodes"]) >= 1, f"code={code}")
            code, body = fresh.request("GET", "/api/keys?pattern=*")
            names = [e.get("key", "") for e in body.get("keys", [])]
            ok("operator-context reads run AS the operator (all keys)",
               all(k in names for k in CLASSIFIED_KEYS + PUBLIC_KEYS),
               f"names={names}")
            code, body = fresh.request("POST", "/api/login/password",
                                      {"username": OPERATOR[0],
                                       "password": OPERATOR[1]})
            ok("password login surface is disabled in operator mode",
               code == 403 and body.get("error_class") == "LOGIN_DISABLED",
               f"code={code}")
            code, body = fresh.request("POST", "/api/action",
                                      {"action": "fed_state",
                                       "args": {"state": "MAINTENANCE"},
                                       "dispatch_token": "forged"})
            ok("action without a touch-issued token refused (403)",
               code == 403 and body.get("error_class") == "NO_DISPATCH_TOKEN",
               f"code={code} {body}")
            code, body = fresh.request("POST", "/api/exec",
                                      {"args": ["GET", "sec:natsec-brief"]})
            ok("command proxy refused in operator mode", code == 403, f"{code}")
        finally:
            stop(proc)

        # ── Phase 2: --require-login, WebAuthn fail-closed ────────────
        proc = start_bridge(port, creds, ["--require-login"])
        try:
            http = Http(f"http://127.0.0.1:{BRIDGE_PORT}")
            code, body = http.request("POST", "/api/login/password",
                                      {"username": OPERATOR[0],
                                       "password": OPERATOR[1]})
            ok("mandatory webauthn: login fails closed without credential",
               code == 403 and body.get("error_class") == "NO_CREDENTIAL",
               f"code={code} body={body}")
        finally:
            stop(proc)

        # ── Phase 3: --require-login --allow-password-only (CI mode; the
        #    password-hammering runs LAST — the engine locks the operator
        #    account server-side for 300 s after 5 failures) ──────────
        proc = start_bridge(port, creds,
                            ["--require-login", "--allow-password-only"])
        try:
            base = f"http://127.0.0.1:{BRIDGE_PORT}"

            http = Http(base)
            code, body = http.request("GET", "/api/overview")
            ok("unauthenticated /api/overview -> 401", code == 401, f"{code}")
            code, body = http.request("GET", "/api/keys?pattern=*")
            ok("unauthenticated /api/keys -> 401", code == 401, f"{code}")
            code, body = http.request("GET", "/api/journal")
            ok("unauthenticated /api/journal -> 401", code == 401, f"{code}")

            # -- low-clearance session --
            code, body = http.request("POST", "/api/login/password",
                                      {"username": ANALYST[0],
                                       "password": ANALYST[1]})
            ok("analyst password login ok (break-glass, single factor)",
               code == 200 and body.get("factor") == 1, f"code={code} {body}")
            http.csrf = body.get("csrf")

            code, body = http.request("GET", "/api/keys?pattern=*")
            names = [e.get("key", "") for e in body.get("keys", [])]
            ok("analyst sees unclassified keys", all(k in names for k in PUBLIC_KEYS),
               f"names={names}")
            ok("analyst CANNOT list classified key names",
               all(k not in names for k in CLASSIFIED_KEYS), f"names={names}")

            code, body = http.request("GET", "/api/key?name=sec:natsec-brief")
            ok("classified key fetch: exists is false for analyst",
               code == 200 and body.get("exists") in (False, None),
               f"body={ {k: v for k, v in body.items() if k != 'meta'} }")
            raw = json.dumps(body)
            ok("classified VALUE absent from key detail",
               all(s not in raw for s in SENTINELS))

            # System-domain ANALYST passes the tenant gate (metadata only)
            # — assert no classified payload rides along.
            code, body = http.request("GET", "/api/federation/status")
            ok("fed status carries no classified payload",
               code == 200 and all(s not in json.dumps(body) for s in SENTINELS),
               f"body={body}")

            # Tenant-scoped principal: FEDERATION.* must render NOPERM,
            # never fabricated emptiness.
            thttp = Http(base)
            code, body = thttp.request("POST", "/api/login/password",
                                       {"username": TENANT[0],
                                        "password": TENANT[1]})
            ok("tenant analyst login ok", code == 200, f"{code}")
            thttp.csrf = body.get("csrf")
            code, body = thttp.request("GET", "/api/federation/status")
            ok("federation status relays NOPERM for tenant principal",
               code == 200 and (body.get("error", {}) or {}).get("error_class")
               in ("NOPERM", "NOAUTH"), f"body={body}")
            code, body = thttp.request("GET", "/api/federation/namespaces")
            ok("federation namespaces relays NOPERM for tenant principal",
               (body.get("error", {}) or {}).get("error_class")
               in ("NOPERM", "NOAUTH"), f"body={body}")
            code, body = thttp.request("GET", "/api/journal")
            ok("tenant journal relayed with error, no entries leak",
               code == 200 and "entries" not in body, f"body-keys={list(body)[:4]}")
            code, body = thttp.request("GET", "/api/keys?pattern=*")
            names = [e.get("key", "") for e in body.get("keys", [])]
            ok("tenant analyst sees no cross-tenant classified names",
               all(k not in names for k in CLASSIFIED_KEYS), f"names={names}")

            code, body = http.request("POST", "/api/action",
                                      {"action": "fed_state",
                                       "args": {"state": "MAINTENANCE"},
                                       "dispatch_token": "x"})
            ok("single-factor action refused (403)",
               code == 403 and body.get("error_class") == "TWO_FACTOR_REQUIRED",
               f"code={code} {body}")

            code, body = http.request("POST", "/api/exec",
                                      {"args": ["GET", "sec:natsec-brief"]})
            ok("command proxy refused outright", code == 403, f"{code}")

            # CSRF: POST without the header
            code, body = http.request("POST", "/api/logout", {},
                                      send_csrf=False)
            ok("POST without CSRF header -> 403",
               code == 403 and body.get("error_class") == "CSRF", f"{code}")

            # -- positive control: operator DOES see classified keys --
            hop = Http(base)
            code, body = hop.request("POST", "/api/login/password",
                                     {"username": OPERATOR[0],
                                      "password": OPERATOR[1]})
            ok("operator login ok", code == 200, f"{code}")
            hop.csrf = body.get("csrf")
            code, body = hop.request("GET", "/api/keys?pattern=*")
            names = [e.get("key", "") for e in body.get("keys", [])]
            ok("operator lists classified keys (positive control)",
               all(k in names for k in CLASSIFIED_KEYS), f"names={names}")
            code, body = hop.request("GET", "/api/key?name=sec:natsec-brief")
            ok("operator reads classified value (positive control)",
               body.get("meta", {}).get("exists") is True and
               "SENTINEL-VALUE-9174" in json.dumps(body.get("preview", "")),
               f"meta={body.get('meta')}")
            code, body = hop.request("GET", "/api/federation/status")
            ok("operator federation status is real data (not NOPERM)",
               code == 200 and (body.get("error") is None or
               body["error"].get("error_class") not in ("NOPERM", "NOAUTH")),
               f"body={body}")

            # -- rate limiting: hammer bad passwords from this client --
            bad = Http(base)
            limited = False
            for _ in range(8):
                code, body = bad.request("POST", "/api/login/password",
                                         {"username": OPERATOR[0],
                                          "password": "wrong-password-x"})
                if code == 429:
                    limited = True
                    break
            ok("login rate limiting kicks in (429)", limited)

            # ── W7: introspection surfaces (operator vs analyst vs tenant)
            code, body = hop.request("GET", "/api/introspection/qkp")
            ok("operator reads QKP counters (10 values)",
               code == 200 and isinstance(body.get("values"), list)
               and len(body["values"]) == 10, f"body={body}")
            code, body = hop.request("GET", "/api/introspection/crl")
            ok("operator reads CRL state (3 values)",
               code == 200 and isinstance(body.get("values"), list)
               and len(body["values"]) == 3, f"body={body}")
            code, body = hop.request("GET",
                                     "/api/key?name=sec:natsec-brief")
            rm = body.get("record_meta")
            ok("operator sees classified record META (classif 4)",
               isinstance(rm, list) and len(rm) == 4 and rm[0] == 4,
               f"record_meta={rm}")

            # system-domain ANALYST: introspection allowed, but RECORD.META
            # for the clearance-5 key is nil — same getter gate as values.
            code, body = http.request("GET", "/api/introspection/qkp")
            ok("system analyst reads QKP counters",
               code == 200 and isinstance(body.get("values"), list))
            code, body = http.request("GET",
                                      "/api/key?name=sec:natsec-brief")
            rm = body.get("record_meta")
            ok("analyst's RECORD.META for clearance-5 key is nil (no oracle)",
               isinstance(rm, list) and len(rm) == 1 and rm[0] is None,
               f"record_meta={rm}")

            # tenant-scoped principal: the whole family is NOPERM.
            code, body = thttp.request("GET", "/api/introspection/qkp")
            ok("tenant principal gets NOPERM on INTROSPECTION",
               (body.get("error", {}) or {}).get("error_class") == "NOPERM",
               f"body={body}")

            code, body = hop.request("GET", "/api/actions")
            ok("action schema available", code == 200 and
               any(a["name"] == "moveslots" for a in body.get("actions", [])))
        finally:
            stop(proc)

    print(f"\ntest_browser_negative_auth: {PASS} checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
