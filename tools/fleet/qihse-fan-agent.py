#!/usr/bin/env python3
"""
QIHSE Fleet Fan Control & Thermal Telemetry Agent
=================================================
Runs on sovereign Dell PowerEdge nodes (T420, R730xd, T320) to:
  1. Collect real-time thermal and fan tachometer telemetry via ipmitool.
  2. Compute thermal_headroom_milli (0..1000) for CITADEL workload placement.
  3. Publish observed telemetry over QKP-sealed RESP to the QIHSE cluster.
  4. Observe leased desired profiles (bedroom, balanced, performance).
  5. Provide a single-shot fleet status CLI (`--fleet`).

Each seed has a persistent native QKP-sealed RESP session, strictly pinned to
its server identity. A distinct, non-admin fan identity authenticates with a
one-use MACHINEAUTH bearer per connection. No password or plaintext fallback.
MOVED/ASK redirects remain bounded to configured seeds. Requires libqihse.so
and its runtime cryptographic dependencies, but no external Python packages.
"""

import os
import sys
import time
import socket
import subprocess
import re
import json
import argparse
import ctypes
import hashlib
import io

# Cluster topology and defaults
MACHINE_TOKEN_PATH = os.environ.get("QIHSE_MACHINE_TOKEN")
MACHINE_TENANT = int(os.environ.get("QIHSE_MACHINE_TENANT", "0"))
MACHINE_USER_ID = int(os.environ.get("QIHSE_MACHINE_USER_ID", "0"))
CLUSTER_SEEDS = [
    ("192.168.1.91", 7100, "t420"),
    ("192.168.1.90", 7115, "730xd"),
    ("192.168.1.250", 7101, "t320"),
]

NODE_PROFILES = {
    "t420": {
        "tjmax": 86.0,
        "default_port": 7100,
        "target_fans": ["Sys Fan1 RPM"],
        "quiet_pwm_hex": "0x17",   # ~23% PWM (1320-1440 RPM)
        "balanced_pwm_hex": "0x20",# ~32% PWM
        "perf_pwm_hex": "0x35",    # ~53% PWM
    },
    "730xd": {
        "tjmax": 94.0,
        "default_port": 7115,
        "target_fans": [f"Fan{i} RPM" for i in range(1, 7)],
        "quiet_pwm_hex": "0x1e",   # ~30% PWM (~5000-7200 RPM)
        "balanced_pwm_hex": "0x2e",# ~46% PWM (~9000 RPM)
        "perf_pwm_hex": "0x50",    # ~80% PWM (>13000 RPM)
    },
    "t320": {
        "tjmax": 86.0,
        "default_port": 7101,
        "target_fans": ["Sys Fan1"],
        "quiet_pwm_hex": "0x22",   # ~34% PWM (~2100 RPM)
        "balanced_pwm_hex": "0x28",# ~40% PWM (~2400 RPM)
        "perf_pwm_hex": "0x35",    # ~53% PWM (~3200 RPM)
    }
}


def detect_node_name():
    hostname = socket.gethostname().lower()
    for name in ["730xd", "t420", "t320"]:
        if name in hostname:
            return name
    return hostname


def run_cmd(cmd: list[str], timeout=5):
    try:
        result = subprocess.run(cmd, shell=False, capture_output=True, text=True, timeout=timeout, check=False)
        return result.stdout.strip() if result.returncode == 0 else ""
    except (OSError, subprocess.TimeoutExpired):
        return ""


def _read_reply(f, depth=0, budget=None):
    """Bounded RESP2 reply parser; no attacker-sized reads or recursive storms."""
    if budget is None:
        budget = [4 * 1024 * 1024]
    if depth > 16:
        raise ConnectionError("RESP nesting limit exceeded")
    line = f.readline(8193)
    if not line.endswith(b"\r\n") or len(line) > 8192 or not line:
        raise ConnectionError("malformed or oversized RESP header")
    budget[0] -= len(line)
    if budget[0] < 0:
        raise ConnectionError("RESP byte budget exceeded")
    kind = chr(line[0])
    body = line[1:-2].decode("utf-8", "strict")
    if kind == "+":
        return "ok", body
    if kind == "-":
        return "err", body
    if kind == ":":
        return "int", int(body)
    if kind == "$":
        length = int(body)
        if length == -1:
            return "null", None
        if length < 0 or length > 1048576 or length + 2 > budget[0]:
            raise ConnectionError("invalid or oversized RESP bulk")
        data = f.read(length + 2)
        if len(data) != length + 2 or not data.endswith(b"\r\n"):
            raise ConnectionError("truncated RESP bulk")
        budget[0] -= len(data)
        return "bulk", data[:-2].decode("utf-8", "replace")
    if kind == "*":
        count = int(body)
        if count == -1:
            return "null", None
        if count < 0 or count > 4096 or count > budget[0] // 3:
            raise ConnectionError("oversized RESP array")
        return "array", [_read_reply(f, depth + 1, budget) for _ in range(count)]
    raise ConnectionError("unknown RESP reply type")


def _remaining(deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("RESP operation deadline exceeded")
    return remaining


_QKP_LIB = None
_USED_TOKEN_DIGESTS = set()


class QihseCommandOutcomeUnknown(ConnectionError):
    """Native transport failed after command submission; never retry on another seed."""


def _qkp_library():
    global _QKP_LIB
    if _QKP_LIB is None:
        path = os.environ.get("QIHSE_FAN_QKP_LIB")
        if not path:
            raise ConnectionError("QIHSE_FAN_QKP_LIB is required")
        try:
            lib = ctypes.CDLL(path)
            lib.qihse_qkp_admin_open.argtypes = [
                ctypes.c_char_p, ctypes.c_uint16, ctypes.c_char_p,
                ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint,
                ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p, ctypes.c_size_t]
            lib.qihse_qkp_admin_open.restype = ctypes.c_int
            if hasattr(lib, "qihse_qkp_admin_open_strict_peer"):
                lib.qihse_qkp_admin_open_strict_peer.argtypes = [
                    ctypes.c_char_p, ctypes.c_uint16, ctypes.c_char_p,
                    ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p,
                    ctypes.c_char_p, ctypes.c_uint, ctypes.POINTER(ctypes.c_void_p),
                    ctypes.c_void_p, ctypes.c_size_t]
                lib.qihse_qkp_admin_open_strict_peer.restype = ctypes.c_int
            lib.qihse_qkp_admin_command.argtypes = [
                ctypes.c_void_p, ctypes.c_size_t,
                ctypes.POINTER(ctypes.c_char_p), ctypes.POINTER(ctypes.c_size_t),
                ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_size_t),
                ctypes.c_void_p, ctypes.c_size_t]
            lib.qihse_qkp_admin_command.restype = ctypes.c_int
            lib.qihse_qkp_admin_close.argtypes = [ctypes.c_void_p]
            lib.qihse_qkp_admin_close.restype = None
            lib.qihse_qkp_admin_free.argtypes = [ctypes.c_void_p]
            lib.qihse_qkp_admin_free.restype = None
        except (OSError, AttributeError) as exc:
            raise ConnectionError("QKP-native library unavailable or incompatible") from exc
        _QKP_LIB = lib
    return _QKP_LIB


class QihseConnection:
    """One authenticated, persistent QKP-sealed RESP connection to one node."""

    def __init__(self, host, port, timeout=10):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.client = None

    def _open_and_auth(self, deadline=None):
        self.close()
        if deadline is None:
            deadline = time.monotonic() + self.timeout
        if MACHINE_TENANT <= 0 or MACHINE_USER_ID <= 0:
            raise ConnectionError("positive QIHSE_MACHINE_TENANT and QIHSE_MACHINE_USER_ID required")
        identity = os.environ.get("QIHSE_FAN_QKP_IDENTITY_DIR")
        client_id = os.environ.get("QIHSE_FAN_QKP_CLIENT_NODE_ID")
        seed = next((name for host, port, name in CLUSTER_SEEDS
                     if (host, port) == (self.host, self.port)), None)
        suffix = seed.upper().replace("-", "_") if seed else ""
        peer_id = os.environ.get(f"QIHSE_FAN_QKP_SERVER_{suffix}_NODE_ID") if seed else None
        pin = os.environ.get(f"QIHSE_FAN_QKP_SERVER_{suffix}_DSA_PUB") if seed else None
        if not identity or not client_id or not client_id.startswith("fan-") or not peer_id or not pin or client_id == peer_id:
            raise ConnectionError("distinct fan QKP identity and exact seed peer pin required")
        lib = _qkp_library()
        client = ctypes.c_void_p()
        err = ctypes.create_string_buffer(256)
        timeout_ms = max(1, int(_remaining(deadline) * 1000))
        if hasattr(lib, "qihse_qkp_admin_open_strict_peer"):
            rc = lib.qihse_qkp_admin_open_strict_peer(
                self.host.encode(), self.port, client_id.encode(), identity.encode(),
                pin.encode(), peer_id.encode(), pin.encode(),
                timeout_ms, ctypes.byref(client), err, len(err))
        else:
            # Older deployments still verify the signed server H1 against this one
            # exact public-key pin; only the additional signed node-label check is absent.
            rc = lib.qihse_qkp_admin_open(
                self.host.encode(), self.port, client_id.encode(), identity.encode(),
                pin.encode(), timeout_ms, ctypes.byref(client), err, len(err))
        if rc or not client.value:
            raise ConnectionError("QKP pinned peer connection failed (library, key, pin or handshake)")
        self.client = client
        try:
            # Every new connection needs a fresh nonce, including after an agent restart.
            try:
                refresh = subprocess.run(
                    ["systemctl", "start", "qihse-machine-token-refresh.service"],
                    capture_output=True, timeout=_remaining(deadline), check=False)
            except (OSError, subprocess.TimeoutExpired) as exc:
                raise ConnectionError("machine token refresh unavailable") from exc
            if refresh.returncode != 0:
                raise ConnectionError("machine token refresh failed")
            token = self._load_machine_token()
            digest = (self.host, self.port, hashlib.sha256(token.encode("ascii")).digest())
            if digest in _USED_TOKEN_DIGESTS:
                raise ConnectionError("MACHINEAUTH one-use token already attempted; refresh token before reconnect")
            # Mark before sending: an ambiguous send must not replay the nonce.
            _USED_TOKEN_DIGESTS.add(digest)
            if self._roundtrip(["MACHINEAUTH", token], deadline) != ("ok", "OK"):
                raise ConnectionError("MACHINEAUTH refused")
        except Exception:
            self.close()
            raise

    @staticmethod
    def _load_machine_token():
        if not MACHINE_TOKEN_PATH:
            raise ConnectionError("QIHSE_MACHINE_TOKEN path required")
        try:
            with open(MACHINE_TOKEN_PATH, "r", encoding="ascii") as tf:
                token = tf.read(16385).strip()
            if not token or len(token) > 16384:
                raise ConnectionError("configured machine token is empty or oversized")
            return token
        except FileNotFoundError:
            raise ConnectionError("machine token required") from None
        except (OSError, UnicodeError) as exc:
            raise ConnectionError("configured machine token cannot be read") from exc

    def _roundtrip(self, args, deadline):
        _remaining(deadline)
        encoded = [str(arg).encode("utf-8") for arg in args]
        argv = (ctypes.c_char_p * len(encoded))(*encoded)
        sizes = (ctypes.c_size_t * len(encoded))(*(len(arg) for arg in encoded))
        reply = ctypes.c_void_p()
        size = ctypes.c_size_t()
        err = ctypes.create_string_buffer(256)
        rc = _qkp_library().qihse_qkp_admin_command(
            self.client, len(encoded), argv, sizes, ctypes.byref(reply),
            ctypes.byref(size), err, len(err))
        try:
            if rc or not reply.value or size.value > 4 * 1024 * 1024:
                raise QihseCommandOutcomeUnknown("QKP command outcome unknown or oversized reply; not retried")
            data = ctypes.string_at(reply, size.value)
        finally:
            if reply.value:
                _qkp_library().qihse_qkp_admin_free(reply)
        stream = io.BytesIO(data)
        try:
            result = _read_reply(stream)
            if stream.read(1):
                raise ConnectionError("trailing RESP data")
            _remaining(deadline)
        except (ConnectionError, ValueError, UnicodeError, TimeoutError) as exc:
            raise QihseCommandOutcomeUnknown("QKP command reply invalid or timed out; not retried") from exc
        return result

    def command(self, args, deadline=None, asking=False):
        """One total deadline covers opening and the command; never replay writes."""
        if deadline is None:
            deadline = time.monotonic() + self.timeout
        try:
            if self.client is None:
                self._open_and_auth(deadline)
            if asking and self._roundtrip(["ASKING"], deadline) != ("ok", "OK"):
                raise ConnectionError("ASKING refused")
            return self._roundtrip(args, deadline)
        except Exception:
            self.close()
            raise

    def close(self):
        if self.client is not None:
            _qkp_library().qihse_qkp_admin_close(self.client)
            self.client = None


def _parse_redirect(err_text):
    """'-MOVED 3456 host:port' / '-ASK 3456 host:port' → (slot, host, port) or None."""
    parts = err_text.split()
    if len(parts) == 3 and parts[0] in ("MOVED", "ASK") and ":" in parts[2]:
        host, _, port = parts[2].rpartition(":")
        if host.startswith("[") and host.endswith("]"):
            host = host[1:-1]
        try:
            return int(parts[1]), host, int(port)
        except ValueError:
            return None
    return None


class QihsePool:
    """Persistent per-node connections with transparent MOVED/ASK following."""

    MAX_HOPS = 3

    def __init__(self, timeout=10):
        self._conns = {}
        self.timeout = timeout

    def _conn_for(self, host, port):
        key = (host, port)
        conn = self._conns.get(key)
        if conn is None:
            conn = QihseConnection(host, port, self.timeout)
            self._conns[key] = conn
        return conn

    def _discard(self, host, port):
        conn = self._conns.pop((host, port), None)
        if conn is not None:
            conn.close()

    def run(self, args, hops=0):
        deadline = time.monotonic() + self.timeout
        if hops < 0 or hops > self.MAX_HOPS:
            raise ConnectionError("too many cluster redirects")
        ordered = sorted(CLUSTER_SEEDS, key=lambda s: 0 if s[0] == _local_ip_hint() else 1)
        last_err = None
        for host, port, _ in ordered:
            _remaining(deadline)
            try:
                kind, value = self._conn_for(host, port).command(args, deadline=deadline)
            except QihseCommandOutcomeUnknown:
                self._discard(host, port)
                raise
            except (OSError, ConnectionError) as exc:
                self._discard(host, port)
                last_err = exc
                continue
            redirect = _parse_redirect(value) if kind == "err" else None
            if redirect:
                return self._run_redirect(args, redirect, hops, deadline,
                                          asking=value.split()[0] == "ASK")
            return kind, value
        raise ConnectionError(f"no seed reachable: {last_err}")

    def _run_redirect(self, args, redirect, hops, deadline=None, asking=False):
        if deadline is None:
            deadline = time.monotonic() + self.timeout
        allowed = {(h, p) for h, p, _ in CLUSTER_SEEDS}
        while True:
            _remaining(deadline)
            if hops < 0 or hops >= self.MAX_HOPS:
                raise ConnectionError("too many cluster redirects")
            slot, host, port = redirect
            if slot < 0 or slot >= 16384 or (host, port) not in allowed:
                raise ConnectionError("untrusted cluster redirect refused")
            hops += 1
            try:
                kind, value = self._conn_for(host, port).command(
                    args, deadline=deadline, asking=asking)
            except (OSError, ConnectionError) as exc:
                self._discard(host, port)
                raise ConnectionError(f"redirect target {host}:{port} failed: {exc}") from exc
            redirect = _parse_redirect(value) if kind == "err" else None
            if not redirect:
                return kind, value
            asking = value.split()[0] == "ASK"

    def close_all(self):
        for conn in self._conns.values():
            conn.close()
        self._conns.clear()


_LOCAL_IP_CACHE = None


def _local_ip_hint():
    """Best-effort local address so the pool prefers the local node's seed
    (keeps publish traffic off the LAN when possible)."""
    global _LOCAL_IP_CACHE
    if _LOCAL_IP_CACHE:
        return _LOCAL_IP_CACHE
    ip = ""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("192.168.1.1", 9))  # no packets sent; routing table only
            ip = s.getsockname()[0]
        finally:
            s.close()
    except OSError:
        pass
    _LOCAL_IP_CACHE = ip
    return ip


_POOL = QihsePool()


def _read_dellfan_sidecar(age=35):
    """Read dell-fan-control's per-fan/per-core sidecar; (fresh, data) tuple."""
    base = "/run/dell-fan"
    obs = os.path.join(base, "observed.json")
    try:
        if not os.path.exists(obs) or (time.time() - os.path.getmtime(obs)) > age:
            return False, {}
        with open(obs) as f:
            o = json.load(f)
        cores, fans = [], {}
        cf = os.path.join(base, "cores.c")
        if os.path.exists(cf):
            with open(cf) as f:
                cores = [float(x) for x in f.read().split() if x]
        ff = os.path.join(base, "fans.rpm")
        if os.path.exists(ff):
            with open(ff) as f:
                for line in f:
                    line = line.strip()
                    if "=" in line:
                        n, v = line.rsplit("=", 1)
                        try:
                            fans[n.strip()] = int(v)
                        except ValueError:
                            pass
        return True, {"cpu_temps": cores, "fan_rpms": fans,
                      "inlet_temp": o.get("inlet"), "exhaust_temp": o.get("exhaust")}
    except Exception:
        return False, {}


def collect_local_telemetry(node_name):
    cfg = NODE_PROFILES.get(node_name, {"tjmax": 86.0})
    tjmax = cfg["tjmax"]

    # Check if dell-fan-telemetry.csv exists and is fresh
    csv_path = "/var/log/dell-fan-telemetry.csv"
    csv_data = {}
    if os.path.exists(csv_path) and os.path.getsize(csv_path) > 0:
        try:
            mtime = os.path.getmtime(csv_path)
            if time.time() - mtime < 35:
                tail_line = run_cmd(["tail", "-n", "1", "--", csv_path], timeout=2)
                cols = [c.strip() for c in tail_line.split(",")]
                if len(cols) >= 10:
                    # timestamp,profile,cpu_max,cpu_avg,sys_max,inlet,load,pwm,target,fan_avg,manual,dt_dt,ttc,exhaust_delta,nvme_max,prediction_boost
                    csv_data = {
                        "profile": cols[1],
                        "cpu_max": float(cols[2]),
                        "cpu_avg": float(cols[3]),
                        "sys_max": float(cols[4]),
                        "inlet_temp": float(cols[5]),
                        "load": float(cols[6]),
                        "pwm": int(cols[7]),
                        "fan_avg": int(cols[9]),
                    }
                    if len(cols) >= 14:
                        csv_data["exhaust_delta"] = float(cols[13])
                        csv_data["exhaust_temp"] = float(cols[5]) + float(cols[13])
        except Exception:
            pass

    # Prefer dell-fan-control's sidecar (single shared IPMI reader); fall back
    # to the legacy CSV + our own ipmitool read only when the sidecar is stale.
    sidecar_fresh, _sc = _read_dellfan_sidecar()

    cpu_temps = []
    inlet_temp = csv_data.get("inlet_temp")
    exhaust_temp = csv_data.get("exhaust_temp")
    fan_rpms = {}

    if sidecar_fresh:
        cpu_temps = _sc.get("cpu_temps", [])
        fan_rpms = _sc.get("fan_rpms", {})
        if inlet_temp is None:
            inlet_temp = _sc.get("inlet_temp")
        if exhaust_temp is None:
            exhaust_temp = _sc.get("exhaust_temp")
        raw_ipmi = ""
    else:
        # ipmitool sensor reads (15s timeout to handle busy BMCs)
        prefix = ["sudo", "-n"] if os.geteuid() != 0 else []
        raw_ipmi = "\n".join(
            run_cmd(prefix + ["ipmitool", "sdr", "type", kind], timeout=15)
            for kind in ("temperature", "fan")
        )

    for line in raw_ipmi.splitlines():
        parts = [p.strip() for p in line.split("|")]
        if len(parts) < 5:
            continue
        name, val_str = parts[0], parts[4]

        # Temperatures
        m_temp = re.search(r"(\d+(?:\.\d+)?)\s*degrees\s*C", val_str, re.I)
        if m_temp:
            val = float(m_temp.group(1))
            if "inlet" in name.lower() and inlet_temp is None:
                inlet_temp = val
            elif "exhaust" in name.lower() and exhaust_temp is None:
                exhaust_temp = val
            elif "temp" in name.lower():
                cpu_temps.append(val)

        # Fans
        m_fan = re.search(r"(\d+)\s*RPM", val_str, re.I)
        if m_fan:
            rpm = int(m_fan.group(1))
            if rpm > 0:
                fan_rpms[name] = rpm

    cpu_max = csv_data.get("cpu_max") or (max(cpu_temps) if cpu_temps else None)
    cpu_avg = csv_data.get("cpu_avg") or (round(sum(cpu_temps) / len(cpu_temps), 1) if cpu_temps else None)
    fan_avg = csv_data.get("fan_avg") or (int(sum(fan_rpms.values()) / len(fan_rpms)) if fan_rpms else 0)
    profile = csv_data.get("profile", "unknown")
    pwm = csv_data.get("pwm", 0)

    ambient = inlet_temp if inlet_temp is not None else 25.0
    headroom_milli = 1000
    if cpu_max is not None and tjmax > ambient:
        ratio = (cpu_max - ambient) / (tjmax - ambient)
        headroom = max(0.0, min(1.0, 1.0 - ratio))
        headroom_milli = int(headroom * 1000)

    # Active profile & pwm if available from local dell-fan-stack
    profile = "unknown"
    pwm = 0
    if os.path.exists("/run/dell-fan/desired_profile"):
        try:
            with open("/run/dell-fan/desired_profile") as pf:
                pj = json.load(pf)
                profile = pj.get("profile", "unknown")
        except Exception:
            pass

    return {
        "node": node_name,
        "ts": int(time.time()),
        "cpu_temps": cpu_temps,
        "cpu_max": cpu_max,
        "cpu_avg": cpu_avg,
        "inlet_temp": inlet_temp,
        "exhaust_temp": exhaust_temp,
        "fan_rpms": fan_rpms,
        "fan_avg": fan_avg,
        "thermal_headroom_milli": headroom_milli,
        "profile": profile,
        "tier": "T2"
    }


def publish_telemetry(data):
    """Publish telemetry to the QIHSE cluster on persistent connections.

    The three writes go over the pool (MOVED-following), each on whichever
    node owns the key's slot. Authentication happens once per connection
    lifetime — zero steady-state AUTH traffic.
    """
    if MACHINE_TENANT <= 0 or MACHINE_USER_ID <= 0:
        raise RuntimeError("QIHSE_MACHINE_TENANT and QIHSE_MACHINE_USER_ID are required")
    payload = json.dumps(data)
    node_name = data["node"]
    prefix = f"t:{MACHINE_TENANT}/machine/{MACHINE_USER_ID}"
    key_obs = f"{prefix}/thermal/{node_name}/observed"
    key_ks = f"{prefix}/keystone-thermal/{node_name}/observed"

    kind, value = _POOL.run(["SET", key_obs, payload])
    if kind != "ok":
        return False
    # Best-effort companions on the same tick.
    try:
        _POOL.run(["PUBLISH", f"{prefix}/thermal-events", payload])
        _POOL.run(["SET", key_ks, payload])
    except (OSError, ConnectionError) as e:
        sys.stderr.write(f"[fan-agent] companion publish failed: {e}\n")
    return True


def get_fleet_telemetry():
    """Return the current machine principal's own telemetry.

    Cross-machine fleet aggregation requires a separate authorized operator
    surface; a MACHINEAUTH capability is deliberately bound to one prefix.
    """
    if MACHINE_TENANT <= 0 or MACHINE_USER_ID <= 0:
        raise RuntimeError("QIHSE_MACHINE_TENANT and QIHSE_MACHINE_USER_ID are required")
    fleet = {}
    local_node = detect_node_name()
    for _, _, node_name in CLUSTER_SEEDS:
        if node_name != local_node:
            fleet[node_name] = {"status": "restricted to the owning machine principal"}
            continue
        key = (f"t:{MACHINE_TENANT}/machine/{MACHINE_USER_ID}/thermal/"
               f"{node_name}/observed")
        val = None
        try:
            kind, value = _POOL.run(["GET", key])
            if kind in ("bulk", "ok") and value:
                val = json.loads(value)
        except (OSError, ConnectionError, json.JSONDecodeError):
            val = None
        fleet[node_name] = val if val else {"status": "offline / no data"}
    return fleet


def print_fleet_table(fleet):
    print("=" * 84)
    print(f"  {'NODE':<10} {'STATUS':<8} {'CPU MAX':<10} {'INLET':<8} {'EXHAUST':<10} {'FANS (AVG)':<14} {'HEADROOM':<10} {'PROFILE':<8}")
    print("=" * 84)
    now = int(time.time())
    for node, d in fleet.items():
        if "cpu_max" not in d:
            print(f"  {node:<10} {'OFFLINE':<8} {'--':<10} {'--':<8} {'--':<10} {'--':<14} {'--':<10} {'--':<8}")
            continue

        cpu_m = f"{d.get('cpu_max', '--')} °C"
        inlet = f"{d.get('inlet_temp', '--')} °C"
        exhaust = f"{d.get('exhaust_temp', '--')} °C" if d.get("exhaust_temp") is not None else "--"
        fans = f"{d.get('fan_avg', 0)} RPM"
        hr = f"{d.get('thermal_headroom_milli', 0) / 10:.1f} %"
        prof = d.get("profile", "auto")
        age = now - d.get("ts", now)
        status = "OK" if age < 30 else f"LAG {age}s"

        print(f"  {node:<10} {status:<8} {cpu_m:<10} {inlet:<8} {exhaust:<10} {fans:<14} {hr:<10} {prof:<8}")
    print("=" * 84)


def main():
    parser = argparse.ArgumentParser(description="QIHSE Fleet Fan Control & Telemetry Agent")
    parser.add_argument("--node", help="Override node name")
    parser.add_argument("--daemon", action="store_true", help="Run in continuous daemon mode")
    parser.add_argument("--interval", type=int, default=5, help="Collection interval in seconds")
    parser.add_argument("--fleet", action="store_true", help="Print cluster-wide fleet thermal summary")
    parser.add_argument("--json", action="store_true", help="Output JSON format")
    args = parser.parse_args()

    node_name = args.node or detect_node_name()

    if args.fleet:
        try:
            fleet = get_fleet_telemetry()
        finally:
            _POOL.close_all()
        if args.json:
            print(json.dumps(fleet, indent=2))
        else:
            print_fleet_table(fleet)
        return

    if args.daemon:
        print(f"[*] Starting QIHSE Fan Agent daemon on node [{node_name}] (interval {args.interval}s)...")
        while True:
            try:
                t0 = time.time()
                data = collect_local_telemetry(node_name)
                ok = publish_telemetry(data)
                if not ok:
                    print(f"[{time.strftime('%X')}] Warning: Failed to publish telemetry to QIHSE cluster")
                time.sleep(max(1.0, args.interval - (time.time() - t0)))
            except KeyboardInterrupt:
                print("\n[*] Exiting.")
                _POOL.close_all()
                break
            except Exception as e:
                print(f"[!] Error in collection loop: {e}")
                time.sleep(args.interval)
    else:
        try:
            data = collect_local_telemetry(node_name)
            if args.json:
                print(json.dumps(data, indent=2))
            else:
                print(f"Node: {data['node']}")
                print(f"CPU Max: {data['cpu_max']}°C (Avg: {data['cpu_avg']}°C)")
                print(f"Inlet: {data['inlet_temp']}°C | Exhaust: {data['exhaust_temp']}°C")
                print(f"Fans: {data['fan_avg']} RPM ({data['fan_rpms']})")
                print(f"Thermal Headroom: {data['thermal_headroom_milli']} / 1000 ({data['thermal_headroom_milli']/10:.1f}%)")
            ok = publish_telemetry(data)
            if ok:
                print("[+] Successfully published to QIHSE cluster.")
            else:
                print("[-] Warning: Failed to write to QIHSE cluster.")
        finally:
            _POOL.close_all()


if __name__ == "__main__":
    main()
