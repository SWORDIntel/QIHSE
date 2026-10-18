"""
QIHSE Thermal & Fan Control Subsystem
=====================================
Provides thermal telemetry collection, IPMI sensor parsing,
thermal headroom computation, and fleet state management across cluster nodes.
"""

from __future__ import annotations

import os
import sys
import time
import socket
import subprocess
import re
import json

DEFAULT_AUTH = os.environ.get("QIHSE_OPERATOR_PASSWORD")
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
        "quiet_pwm_hex": "0x17",
        "balanced_pwm_hex": "0x20",
        "perf_pwm_hex": "0x35",
    },
    "730xd": {
        "tjmax": 94.0,
        "default_port": 7115,
        "target_fans": [f"Fan{i} RPM" for i in range(1, 7)],
        "quiet_pwm_hex": "0x1e",
        "balanced_pwm_hex": "0x2e",
        "perf_pwm_hex": "0x50",
    },
    "t320": {
        "tjmax": 86.0,
        "default_port": 7101,
        "target_fans": ["Sys Fan1"],
        "quiet_pwm_hex": "0x22",
        "balanced_pwm_hex": "0x28",
        "perf_pwm_hex": "0x35",
    }
}


def detect_node_name() -> str:
    hostname = socket.gethostname().lower()
    for name in ["730xd", "t420", "t320"]:
        if name in hostname:
            return name
    return hostname


def run_cmd(cmd: str, timeout: int = 5) -> str:
    try:
        res = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return res.stdout.strip()
    except Exception:
        return ""


def send_resp(host: str, port: int, auth: str | None, args: list, timeout: int = 3):
    """Zero-dependency minimal RESP client."""
    if not auth:
        return None, "QIHSE_OPERATOR_PASSWORD is required; no default credential exists"
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        f = s.makefile('rb')

        # AUTH
        auth_payload = f"*2\r\n$4\r\nAUTH\r\n${len(auth)}\r\n{auth}\r\n".encode()
        s.sendall(auth_payload)
        auth_res = f.readline().decode()
        if not auth_res.startswith('+OK'):
            s.close()
            return None, f"AUTH failed: {auth_res.strip()}"

        # Command
        lines = [f"*{len(args)}".encode()]
        for a in args:
            b = str(a).encode('utf-8')
            lines.append(f"${len(b)}".encode())
            lines.append(b)
        lines.append(b"")
        s.sendall(b"\r\n".join(lines))

        # Response
        resp_line = f.readline().decode()
        if not resp_line:
            s.close()
            return None, "Empty response"

        prefix = resp_line[0]
        line = resp_line[1:].strip()

        if prefix == '+':
            val = line
        elif prefix == '-':
            val = None
        elif prefix == ':':
            val = int(line)
        elif prefix == '$':
            length = int(line)
            if length >= 0:
                content = f.read(length)
                f.read(2)
                val = content.decode('utf-8', 'replace')
            else:
                val = None
        else:
            val = line

        s.close()
        return val, None
    except Exception as e:
        return None, str(e)


def collect_local_telemetry(node_name: str | None = None) -> dict:
    if not node_name:
        node_name = detect_node_name()
    cfg = NODE_PROFILES.get(node_name, {"tjmax": 86.0})
    tjmax = cfg["tjmax"]

    # Check if local dell-fan-telemetry.csv exists and is fresh (< 35s)
    csv_path = "/var/log/dell-fan-telemetry.csv"
    csv_data = {}
    if os.path.exists(csv_path) and os.path.getsize(csv_path) > 0:
        try:
            mtime = os.path.getmtime(csv_path)
            if time.time() - mtime < 35:
                tail_line = run_cmd(f"tail -n 1 {csv_path}", timeout=2)
                cols = [c.strip() for c in tail_line.split(",")]
                if len(cols) >= 10:
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

    # IPMI sensor read (15s timeout)
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

    ambient = inlet_temp if inlet_temp is not None else 25.0
    headroom_milli = 1000
    if cpu_max is not None and tjmax > ambient:
        ratio = (cpu_max - ambient) / (tjmax - ambient)
        headroom = max(0.0, min(1.0, 1.0 - ratio))
        headroom_milli = int(headroom * 1000)

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


def publish_telemetry(data: dict, auth: str = DEFAULT_AUTH) -> bool:
    payload = json.dumps(data)
    node_name = data["node"]
    seeds_to_try = [s for s in CLUSTER_SEEDS if s[2] == node_name] + [s for s in CLUSTER_SEEDS if s[2] != node_name]

    for host, port, _ in seeds_to_try:
        key_obs = f"citadel/thermal/nodes/{node_name}/observed"
        key_ks = f"keystone/thermal/nodes/{node_name}/observed"
        res, _ = send_resp(host, port, auth, ["SET", key_obs, payload])
        if res == "OK":
            send_resp(host, port, auth, ["PUBLISH", f"citadel.thermal.{node_name}", payload])
            send_resp(host, port, auth, ["SET", key_ks, payload])
            return True
    return False


def fetch_node_telemetry(node_info: tuple[str, int, str], auth: str = DEFAULT_AUTH) -> tuple[str, dict]:
    _, _, node_name = node_info
    key = f"citadel/thermal/nodes/{node_name}/observed"
    seeds = [s for s in CLUSTER_SEEDS if s[2] == node_name] + [s for s in CLUSTER_SEEDS if s[2] != node_name]
    val = None
    for host, port, _ in seeds:
        v, _ = send_resp(host, port, auth, ["GET", key], timeout=3)
        if v:
            try:
                val = json.loads(v)
                break
            except Exception:
                pass
    now = int(time.time())
    if val:
        age = now - val.get("ts", now)
        val["age_seconds"] = age
        val["status"] = "OK" if age < 30 else f"LAG {age}s"
        return node_name, val
    return node_name, {"node": node_name, "status": "OFFLINE"}


def get_fleet_telemetry(auth: str = DEFAULT_AUTH) -> dict:
    from concurrent.futures import ThreadPoolExecutor
    fleet = {}
    with ThreadPoolExecutor(max_workers=len(CLUSTER_SEEDS)) as ex:
        futures = [ex.submit(fetch_node_telemetry, seed, auth) for seed in CLUSTER_SEEDS]
        for f in futures:
            try:
                name, data = f.result(timeout=4)
                fleet[name] = data
            except Exception:
                pass
    return {seed[2]: fleet.get(seed[2], {"node": seed[2], "status": "OFFLINE"}) for seed in CLUSTER_SEEDS}


def print_fleet_table(fleet: dict) -> None:
    print("=" * 84)
    print(f"  {'NODE':<10} {'STATUS':<8} {'CPU MAX':<10} {'INLET':<8} {'EXHAUST':<10} {'FANS (AVG)':<14} {'HEADROOM':<10} {'PROFILE':<8}")
    print("=" * 84)
    for node, d in fleet.items():
        if "cpu_max" not in d or d.get("cpu_max") is None:
            print(f"  {node:<10} {'OFFLINE':<8} {'--':<10} {'--':<8} {'--':<10} {'--':<14} {'--':<10} {'--':<8}")
            continue

        cpu_m = f"{d.get('cpu_max', '--')} °C"
        inlet = f"{d.get('inlet_temp', '--')} °C"
        exhaust = f"{d.get('exhaust_temp', '--')} °C" if d.get('exhaust_temp') is not None else "--"
        fans = f"{d.get('fan_avg', 0)} RPM"
        hr = f"{d.get('thermal_headroom_milli', 0) / 10:.1f} %"
        prof = d.get('profile', 'auto')
        status = d.get('status', 'OK')

        print(f"  {node:<10} {status:<8} {cpu_m:<10} {inlet:<8} {exhaust:<10} {fans:<14} {hr:<10} {prof:<8}")
    print("=" * 84)


def cli_main(argv: list[str] | None = None) -> int:
    import argparse
    parser = argparse.ArgumentParser(description="QIHSE Thermal & Fan Control Engine")
    parser.add_argument("--node", help="Override node name")
    parser.add_argument("--daemon", action="store_true", help="Run in continuous collection daemon mode")
    parser.add_argument("--interval", type=int, default=5, help="Collection interval in seconds")
    parser.add_argument("--fleet", action="store_true", default=True, help="Print cluster-wide fleet thermal summary (default)")
    parser.add_argument("--json", action="store_true", help="Output JSON format")
    args = parser.parse_args(argv)

    node_name = args.node or detect_node_name()

    if args.daemon:
        print(f"[*] Starting QIHSE Fan Agent daemon on node [{node_name}] (interval {args.interval}s)...")
        while True:
            try:
                t0 = time.time()
                data = collect_local_telemetry(node_name)
                ok = publish_telemetry(data)
                dt = time.time() - t0
                if not ok:
                    print(f"[{time.strftime('%X')}] Warning: Failed to publish telemetry to QIHSE cluster")
                time.sleep(max(1.0, args.interval - dt))
            except KeyboardInterrupt:
                print("\n[*] Exiting.")
                break
            except Exception as e:
                print(f"[!] Error in collection loop: {e}")
                time.sleep(args.interval)
        return 0

    fleet = get_fleet_telemetry()
    if args.json:
        print(json.dumps(fleet, indent=2))
    else:
        print_fleet_table(fleet)
    return 0


if __name__ == "__main__":
    sys.exit(cli_main(sys.argv[1:]))
