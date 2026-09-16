#!/usr/bin/env python3
"""Failover + redundancy drill: write on the lead, verify the duplicate on the
peer (ASKING local read), SIGKILL the lead, then verify the most-uptime
successor owns all slots AND the duplicated key survives.

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
import os, shlex, socket, subprocess, sys, time

PW = os.environ.get("QIHSE_CLUSTER_PASSWORD", "QihseCluster2026x!")
BIN = os.environ.get("QIHSE_BIN", "./qihse-cluster-daemon")
LIB_DIR = os.environ.get("QIHSE_LIB_DIR", ".")
DATA_DIR = os.environ.get("QIHSE_DATA_DIR", "./build/cluster-smoke")
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


def relaunch_cluster():
    """The drill is destructive (SIGKILLs the lead): relaunch both nodes."""
    for p in _daemons:
        if p.poll() is None:
            p.kill()
    _daemons.clear()
    if SSH_TARGET:
        subprocess.run(["ssh", "-o", "BatchMode=yes", SSH_TARGET,
                        "pkill -9 qihse-cluster-d"], capture_output=True)
    time.sleep(1)
    _start_local(0, N0_HOST, PORT0, BUS0, "node0",
                 ["--redundancy-peer", f"{N1_HOST}:{PORT1}"])
    time.sleep(2)
    join_extra = ["--join", f"{N0_HOST}:{BUS0}",
                  "--redundancy-peer", f"{N0_HOST}:{PORT0}"]
    if SSH_TARGET:
        _start_remote(1, N1_HOST, PORT1, BUS1, "node1", join_extra)
        time.sleep(8)
    else:
        _start_local(1, N1_HOST, PORT1, BUS1, "node1", join_extra)
        time.sleep(3)
    time.sleep(2)


def main():
    relaunch_cluster()
    results = []
    def check(name, cond, detail=""):
        results.append(cond); print(f"{'PASS' if cond else 'FAIL'}: {name} {detail}")

    n0 = C(N0); n0.cmd("AUTH", "GODMODE_OP", PW)
    t, r = n0.cmd("SET", "redundant:k1", "survives-lead-death")
    check("write on lead", (t, r) == ("+", "OK"), f"{t} {r}")
    time.sleep(1)

    n1 = C(N1); n1.cmd("AUTH", "GODMODE_OP", PW)
    n1.cmd("ASKING")
    t, r = n1.cmd("GET", "redundant:k1")
    check("duplicate present on successor (ASKING local read)",
          (t, r) == ("$", "survives-lead-death"), f"{t} {r}")

    lead = _daemons[0] if _daemons else None
    if lead is None or lead.poll() is not None:
        print("FAIL: lead daemon is not running; cannot run the drill")
        return 1
    lead.kill()
    print(f"lead killed (SIGKILL, pid {lead.pid}).")
    time.sleep(8)

    n1.fresh(); n1.cmd("AUTH", "GODMODE_OP", PW)
    t, info = n1.cmd("CLUSTER", "INFO")
    state = dict(line.split(":", 1) for line in info.splitlines() if ":" in line)
    check("successor cluster_state ok", state.get("cluster_state") == "ok", state.get("cluster_state"))
    check("successor owns all 16384 slots",
          state.get("cluster_slots_assigned") == "16384" and state.get("cluster_slots_ok") == "16384",
          f"{state.get('cluster_slots_assigned')}/{state.get('cluster_slots_ok')}")

    n1.cmd("ASKING")
    t, r = n1.cmd("GET", "redundant:k1")
    check("duplicated key survives lead death", (t, r) == ("$", "survives-lead-death"), f"{t} {r}")

    print(f"\nfailover drill: {sum(results)}/{len(results)} checks passed")
    return 0 if all(results) else 1

if __name__ == "__main__":
    sys.exit(main())
