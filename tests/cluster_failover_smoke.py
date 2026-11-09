#!/usr/bin/env python3
"""Cluster failover safety drill: seed a duplicate through authenticated RESP
on the successor, SIGKILL the lead, and verify it does not claim ownership
without a proven write stream and all-writer fence. The duplicate is a local
fixture, not evidence of replication. Legacy plaintext redundancy is disabled.

Destructive by design: it kills the daemons it launched and relaunches both
nodes. Runs on a single host by default (two loopback daemon processes); for
the cross-machine lab drill point it at the peer host:

    QIHSE_NODE1_HOST=192.168.1.250 QIHSE_SSH_TARGET=root@192.168.1.250 \
        tests/cluster_failover_smoke.py

Environment (all optional):
    QIHSE_BIN               daemon binary      (default ./qihse-cluster-daemon)
    QIHSE_LIB_DIR           libqihse dir       (default .)
    QIHSE_DATA_DIR          runtime dir        (default ./build/cluster-smoke)
    QIHSE_NODE0_HOST        lead host          (default 127.0.0.1)
    QIHSE_NODE1_HOST        successor host     (default = node0 host)
    QIHSE_SSH_TARGET        ssh target for node1 (default empty = run locally)
    QIHSE_CLUSTER_PASSWORD  operator password  (default lab password)
"""
import os
import tempfile, shlex, socket, subprocess, sys, time
import atexit, signal

def log(msg): print(msg, flush=True)

PW = os.environ.get("QIHSE_CLUSTER_PASSWORD") or "SmokeTestPass123!"
BIN = os.environ.get("QIHSE_BIN", "./qihse-cluster-daemon")
LIB_DIR = os.environ.get("QIHSE_LIB_DIR", ".")
DATA_DIR = os.environ.get("QIHSE_DATA_DIR") or tempfile.mkdtemp(
    prefix="cluster-failover-", dir="./build")
N0_HOST = os.environ.get("QIHSE_NODE0_HOST", "127.0.0.1")
N1_HOST = os.environ.get("QIHSE_NODE1_HOST", N0_HOST)
SSH_TARGET = os.environ.get("QIHSE_SSH_TARGET", "")
PORT0 = int(os.environ.get("QIHSE_NODE0_PORT", "7100"))
PORT1 = int(os.environ.get("QIHSE_NODE1_PORT", "7101"))
BUS0 = int(os.environ.get("QIHSE_NODE0_BUS_PORT", "17100"))
BUS1 = int(os.environ.get("QIHSE_NODE1_BUS_PORT", "17101"))

N0 = (N0_HOST, PORT0)   # lead
N1 = (N1_HOST, PORT1)   # successor

_daemons = []


def encode(*a):
    out = f"*{len(a)}\r\n".encode()
    for x in a: out += f"${len(x)}\r\n".encode() + x.encode() + b"\r\n"
    return out

class C:
    def __init__(s, addr, timeout=10):
        s.addr = addr
        s.s = socket.create_connection(addr, timeout=timeout); s.buf = b""
    def reply(s):
        while True:
            while b"\r\n" not in s.buf:
                d = s.s.recv(65536)
                if not d: raise ConnectionError("closed")
                s.buf += d
            line, s.buf = s.buf.split(b"\r\n", 1)
            t, rest = line[:1], line[1:]
            if t in b"+-:": return (t.decode(), rest.decode())
            if t == b"$":
                n = int(rest)
                if n == -1: return ("$", None)
                while len(s.buf) < n + 2:
                    d = s.s.recv(65536)
                    if not d: raise ConnectionError
                    s.buf += d
                d, s.buf = s.buf[:n], s.buf[n+2:]
                return ("$", d.decode())
            if t == b"*": return ("*", [s.reply() for _ in range(int(rest))])
            return ("?", line.decode())
    def cmd(s, *a):
        s.s.sendall(encode(*a)); return s.reply()
    def fresh(s):
        s.s.close(); s.__init__(s.addr)


def _node_env():
    return dict(os.environ, LD_LIBRARY_PATH=LIB_DIR)


def _start_local(index, host, port, bus_port, data_sub, extra):
    node_dir = os.path.join(DATA_DIR, data_sub)
    os.makedirs(node_dir, exist_ok=True)
    cmd = [BIN, "--index", str(index), "--bind", host, "--port", str(port),
           "--bus-port", str(bus_port), "--operator-password", PW,
           "--dir", node_dir] + extra
    p = subprocess.Popen(cmd, env=_node_env(),
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    _daemons.append(p)
    return p


def _start_remote(index, host, port, bus_port, data_sub, extra):
    node_dir = os.path.join(DATA_DIR, data_sub)
    args = " ".join(shlex.quote(a) for a in
                    [BIN, "--index", str(index), "--bind", host, "--port", str(port),
                     "--bus-port", str(bus_port), "--operator-password", PW,
                     "--dir", node_dir] + extra)
    remote = (f"mkdir -p {shlex.quote(node_dir)} && "
              f"nohup env LD_LIBRARY_PATH={shlex.quote(LIB_DIR)} {args} "
              f"> {shlex.quote(node_dir + '.log')} 2>&1 &")
    subprocess.run(["ssh", "-o", "BatchMode=yes", SSH_TARGET, remote],
                   capture_output=True)


def _kill_own_daemons():
    for p in _daemons:
        if p.poll() is None:
            p.kill()
    for p in _daemons:
        p.wait()

atexit.register(_kill_own_daemons)
for _sig in (signal.SIGTERM, signal.SIGINT):
    signal.signal(_sig, lambda s, f: (sys.exit(1)))

def relaunch_cluster():
    """The drill is destructive (SIGKILLs the lead): relaunch both nodes."""
    for p in _daemons:
        if p.poll() is None:
            p.kill()
    _daemons.clear()
    # A leaked daemon from an aborted earlier run would hold our ports and
    # the new lead would die at bind. Clear loopback stalemates for OUR
    # exact ports only (the live fleet binds different addresses).
    # Bind+port: matches only loopback drill daemons — the live fleet
    # binds its LAN addresses, never this pattern.
    subprocess.run(["pkill", "-9", "-f",
                    f"cluster-daemon.*--bind 127.0.0.1 --port {PORT0}"],
                   capture_output=True)
    subprocess.run(["pkill", "-9", "-f",
                    f"cluster-daemon.*--bind 127.0.0.1 --port {PORT1}"],
                   capture_output=True)
    if SSH_TARGET:
        subprocess.run(["ssh", "-o", "BatchMode=yes", SSH_TARGET,
                        "pkill -9 qihse-cluster-d"], capture_output=True)
    time.sleep(1)
    _start_local(0, N0_HOST, PORT0, BUS0, "node0", [])
    time.sleep(2)
    join_extra = ["--join", f"{N0_HOST}:{BUS0}"]
    if SSH_TARGET:
        _start_remote(1, N1_HOST, PORT1, BUS1, "node1", join_extra)
        time.sleep(8)
    else:
        _start_local(1, N1_HOST, PORT1, BUS1, "node1", join_extra)
        # Wait until BOTH endpoints actually accept TCP: a fixed sleep
        # races a loaded machine (the daemon binds seconds late under
        # CPU contention) and the drill then fails at its first connect.
        for addr in ((N0_HOST, PORT0), (N1_HOST, PORT1)):
            for _ in range(80):           # up to 20 s each
                try:
                    s = socket.create_connection(addr, timeout=0.5)
                    s.close()
                    break
                except OSError:
                    time.sleep(0.25)
            else:
                print(f"FAIL: daemon at {addr[0]}:{addr[1]} did not come up")
                _teardown = True
        time.sleep(2)


def main():
    relaunch_cluster()
    results = []
    def check(name, cond, detail=""):
        results.append(cond); print(f"{'PASS' if cond else 'FAIL'}: {name} {detail}")

    # The old fire-and-forget RESP replay is deliberately disabled: it would
    # send the operator credential and data without pinned QKP transport.
    rejected = subprocess.run(
        [BIN, "--index", "0", "--bind", N0_HOST, "--port", str(PORT0),
         "--bus-port", str(BUS0), "--operator-password", PW,
         "--dir", os.path.join(DATA_DIR, "rejected"),
         "--redundancy-peer", f"{N1_HOST}:{PORT1}"],
        env=_node_env(), capture_output=True, text=True, timeout=10)
    check("legacy plaintext redundancy rejected",
          rejected.returncode == 2 and
          "--redundancy-peer is unavailable" in rejected.stderr)

    n0 = C(N0); n0.cmd("AUTH", "GODMODE_OP", PW)
    t, r = n0.cmd("SET", "redundant:k1", "survives-lead-death")
    check("write on lead", (t, r) == ("+", "OK"), f"{t} {r}")

    # Seed an unclassified copy over the successor's authenticated RESP
    # session. This proves failover and local duplicate survival without
    # claiming the disabled live replication path worked.
    n1 = C(N1); n1.cmd("AUTH", "GODMODE_OP", PW)
    n1.cmd("ASKING")
    seed_t, seed_r = n1.cmd("SET", "redundant:k1", "survives-lead-death")
    n1.cmd("ASKING")
    t, r = n1.cmd("GET", "redundant:k1")
    check("seeded duplicate present on successor (ASKING local read)",
          (seed_t, seed_r) == ("+", "OK") and
          (t, r) == ("$", "survives-lead-death"), f"{t} {r}")

    lead = _daemons[0] if _daemons else None
    if lead is None or lead.poll() is not None:
        log("FAIL: lead daemon is not running; cannot run the drill")
        return 1
    lead.kill()
    log(f"lead killed (SIGKILL, pid {lead.pid}).")
    # Wait for the successor endpoint, then observe a complete health window
    # so an unsafe delayed promotion cannot masquerade as a passing refusal.
    for _ in range(240):
        try:
            s = socket.create_connection((N1_HOST, PORT1), timeout=1)
            s.close()
            break
        except OSError:
            time.sleep(0.25)

    state = {}
    own_line = None
    unsafe_owned = False
    for _ in range(240):
        n1.fresh(); n1.cmd("AUTH", "GODMODE_OP", PW)
        t, info = n1.cmd("CLUSTER", "INFO")
        state = dict(line.split(":", 1) for line in info.splitlines() if ":" in line)
        t, nodes = n1.cmd("CLUSTER", "NODES")
        own_lines = [line for line in nodes.splitlines()
                     if len(line.split()) >= 8 and
                     "myself" in line.split()[2].split(",")]
        own_line = own_lines[0] if len(own_lines) == 1 else None
        unsafe_owned |= own_line is not None and any(
            slot.isdigit() or
            ("-" in slot and all(bound.isdigit() for bound in slot.split("-", 1)))
            for slot in own_line.split()[8:])
        if unsafe_owned:
            break
        time.sleep(0.25)
    check("successor remains unavailable without data proof",
          state.get("cluster_state") != "ok",
          state.get("cluster_state"))
    check("successor did not claim slots",
          not unsafe_owned and own_line is not None,
          own_line)

    t, r = n1.cmd("GET", "redundant:k1")
    n1.cmd("ASKING")
    seed_t, seed_r = n1.cmd("GET", "redundant:k1")
    check("ordinary read refused; preseeded copy remains local",
          t == "-" and r.startswith(("CLUSTERDOWN", "MOVED")) and
          "survives-lead-death" not in r and
          (seed_t, seed_r) == ("$", "survives-lead-death"),
          f"ordinary={t} {r}; ASKING={seed_t} {seed_r}")

    log(f"\nfailover guard: {sum(results)}/{len(results)} checks passed")
    return 0 if all(results) else 1

if __name__ == "__main__":
    sys.exit(main())
