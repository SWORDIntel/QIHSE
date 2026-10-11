#!/usr/bin/env python3
"""
QIHSE Fleet Fan Control & Thermal Telemetry Agent
=================================================
Runs on sovereign Dell PowerEdge nodes (T420, R730xd, T320) to:
  1. Collect real-time thermal and fan tachometer telemetry via ipmitool.
  2. Compute thermal_headroom_milli (0..1000) for CITADEL workload placement.
  3. Publish observed telemetry to the QIHSE cluster over the RESP wire protocol.
  4. Observe leased desired profiles (bedroom, balanced, performance).
  5. Provide a single-shot fleet status CLI (`--fleet`).

Client design (rewritten 2026-10-03, auth-storm fix):
  * PERSISTENT connections. The old agent opened a fresh TCP connection per
    command (3 per tick) and sent AUTH with the operator password on every
    one, making each cluster node run a multi-second PBKDF2 verify ~36
    times/minute, forever — one core pegged per node. This client connects
    once per target node, authenticates once per connection lifetime, and
    reuses the connection across ticks.
  * MACHINEAUTH preferred. If a machine token is present (see
    /etc/qihse/machine_token, minted by `qihse-machine-token`), the client
    authenticates with it: PQC-signed, no password KDF on the server at all,
    one token per connection (the server consumes the token nonce).
  * Password fallback: QIHSE_OPERATOR_PASSWORD from the environment. There
    is deliberately NO hardcoded default password in this file anymore.
  * MOVED/ASK cluster redirects are followed transparently (bounded hops).

Zero external Python dependencies (pure standard library).
"""

import os
import sys
import time
import socket
import subprocess
import re
import json
import argparse

# Cluster topology and defaults
MACHINE_TOKEN_PATH = os.environ.get("QIHSE_MACHINE_TOKEN", "/etc/qihse/machine_token")
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


def run_cmd(cmd, timeout=5):
    try:
        res = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return res.stdout.strip()
    except Exception as e:
        return ""


def _encode_command(args):
    lines = [f"*{len(args)}".encode()]
    for a in args:
        b = str(a).encode("utf-8")
        lines.append(f"${len(b)}".encode())
        lines.append(b)
    lines.append(b"")
    return b"\r\n".join(lines)


def _read_reply(f):
    """Read one RESP reply. Returns ('ok'|'err'|'int'|'bulk'|'null'|'array', value)."""
    line = f.readline()
    if not line:
        raise ConnectionError("empty reply (connection closed)")
    line = line.decode("utf-8", "replace").rstrip("\r\n")
    kind, body = line[0], line[1:]
    if kind == "+":
        return "ok", body
    if kind == "-":
        return "err", body
    if kind == ":":
        return "int", int(body)
    if kind == "$":
        length = int(body)
        if length < 0:
            return "null", None
        data = f.read(length)
        f.read(2)  # trailing \r\n
        return "bulk", data.decode("utf-8", "replace")
    if kind == "*":
        count = int(body)
        if count < 0:
            return "null", None
        return "array", [_read_reply(f) for _ in range(count)]
    raise ConnectionError(f"unknown reply type {kind!r}")


class QihseConnection:
    """One authenticated, persistent RESP connection to one node."""

    def __init__(self, host, port, timeout=10):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.sock = None
        self.f = None

    def _open_and_auth(self):
        self.close()
        s = socket.create_connection((self.host, self.port), timeout=self.timeout)
        s.settimeout(self.timeout)
        self.sock = s
        self.f = s.makefile("rb")

        token = self._load_machine_token()
        if token is not None:
            kind, value = self._roundtrip(["MACHINEAUTH", token])
            if kind == "ok":
                return
            # No machine trust on this node, or token refused: fall back to
            # the password path if one is configured. Never print the token.
            sys.stderr.write(
                f"[fan-agent] MACHINEAUTH on {self.host}:{self.port} refused "
                f"({value}); falling back to password AUTH\n")

        password = os.environ.get("QIHSE_OPERATOR_PASSWORD")
        if not password:
            raise ConnectionError(
                f"no machine token usable at {MACHINE_TOKEN_PATH} and "
                "QIHSE_OPERATOR_PASSWORD not set — cannot authenticate")
        kind, value = self._roundtrip(["AUTH", password])
        if kind != "ok":
            raise ConnectionError(f"AUTH refused by {self.host}:{self.port}: {value}")

    @staticmethod
    def _load_machine_token():
        try:
            with open(MACHINE_TOKEN_PATH, "r", encoding="ascii") as tf:
                token = tf.read().strip()
            return token or None
        except OSError:
            return None

    def _roundtrip(self, args):
        self.sock.sendall(_encode_command(args))
        return _read_reply(self.f)

    def command(self, args):
        """Run one command, reconnecting + re-authenticating once if the
        connection went stale between ticks."""
        for attempt in (0, 1):
            try:
                if self.sock is None:
                    self._open_and_auth()
                return self._roundtrip(args)
            except (OSError, ConnectionError, ValueError):
                self.close()
                if attempt == 1:
                    raise
                time.sleep(0.2)
        raise ConnectionError("unreachable")

    def close(self):
        try:
            if self.f:
                self.f.close()
        except OSError:
            pass
        try:
            if self.sock:
                self.sock.close()
        except OSError:
            pass
        self.f = None
        self.sock = None


def _parse_redirect(err_text):
    """'-MOVED 3456 host:port' / '-ASK 3456 host:port' → (slot, host, port) or None."""
    parts = err_text.split()
    if len(parts) == 3 and parts[0] in ("MOVED", "ASK") and ":" in parts[2]:
        host, _, port = parts[2].rpartition(":")
        try:
            return int(parts[1]), host, int(port)
        except ValueError:
            return None
    return None


class QihsePool:
    """Persistent per-node connections with transparent MOVED/ASK following."""

    MAX_HOPS = 3

    def __init__(self):
        self._conns = {}

    def _conn_for(self, host, port):
        key = (host, port)
        conn = self._conns.get(key)
        if conn is None:
            conn = QihseConnection(host, port)
            self._conns[key] = conn
        return conn

    def run(self, args, hops=0):
        if hops > self.MAX_HOPS:
            raise ConnectionError(f"too many cluster redirects for {' '.join(map(str, args[:2]))}")
        # Local seed first; other seeds as fallback for the first hop.
        if hops == 0:
            ordered = sorted(CLUSTER_SEEDS, key=lambda s: 0 if s[0] == _local_ip_hint() else 1)
        else:
            ordered = [(None, None, None)]  # redirect target chosen below
        if hops == 0:
            last_err = None
            for host, port, _ in ordered:
                try:
                    conn = self._conn_for(host, port)
                    kind, value = conn.command(args)
                except (OSError, ConnectionError) as e:
                    self._conns.pop((host, port), None)
                    last_err = e
                    continue
                if kind == "err":
                    redirect = _parse_redirect(value)
                    if redirect:
                        return self._run_redirect(args, redirect, hops)
                    return kind, value
                return kind, value
            raise ConnectionError(f"no seed reachable: {last_err}")
        raise ConnectionError("unreachable")

    def _run_redirect(self, args, redirect, hops):
        slot, host, port = redirect
        try:
            conn = self._conn_for(host, port)
            kind, value = conn.command(args)
        except (OSError, ConnectionError) as e:
            self._conns.pop((host, port), None)
            raise ConnectionError(f"redirect target {host}:{port} failed: {e}")
        if kind == "err":
            redirect2 = _parse_redirect(value)
            if redirect2:
                return self._run_redirect(args, redirect2, hops + 1)
        return kind, value

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
                tail_line = run_cmd(f"tail -n 1 {csv_path}", timeout=2)
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

    # ipmitool sensor reads (15s timeout to handle busy BMCs)
    if os.geteuid() != 0:
        cmd = "sudo ipmitool sdr type temperature; sudo ipmitool sdr type fan"
    else:
        cmd = "ipmitool sdr type temperature; ipmitool sdr type fan"

    raw_ipmi = run_cmd(cmd, timeout=15)

    cpu_temps = []
    inlet_temp = csv_data.get("inlet_temp")
    exhaust_temp = csv_data.get("exhaust_temp")
    fan_rpms = {}

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
    payload = json.dumps(data)
    node_name = data["node"]
    key_obs = f"citadel/thermal/nodes/{node_name}/observed"
    key_ks = f"keystone/thermal/nodes/{node_name}/observed"

    kind, value = _POOL.run(["SET", key_obs, payload])
    if kind != "ok":
        return False
    # Best-effort companions on the same tick.
    try:
        _POOL.run(["PUBLISH", f"citadel.thermal.{node_name}", payload])
        _POOL.run(["SET", key_ks, payload])
    except (OSError, ConnectionError) as e:
        sys.stderr.write(f"[fan-agent] companion publish failed: {e}\n")
    return True


def get_fleet_telemetry():
    """Queries the cluster for all nodes' observed state (persistent conns)."""
    fleet = {}
    for _, _, node_name in CLUSTER_SEEDS:
        key = f"citadel/thermal/nodes/{node_name}/observed"
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
