#!/usr/bin/env python3
"""Dynamic-discovery cluster smoke: node 1 is launched knowing NOTHING except
one seed bus address (--join). Verifies membership discovery (MEET + gossip),
slot-map propagation (SLOT_UPDATE re-announcements), and cross-node routing
through the joiner after the heartbeat health window has elapsed.

Two modes:
  default      Prereq: node 0 (seed, all slots) and node 1 (joiner) are up;
               endpoints default to the t420/T320 lab pair and are
               overridable with QIHSE_NODE0_HOST/PORT and QIHSE_NODE1_HOST/PORT.
  --self-spawn Hermetic (gold/CI): spawn BOTH nodes on loopback from scratch
               (seed owns 0-16383; joiner starts with --join only), run the
               checks, tear everything down. No live fleet is touched.
"""
import os, socket, subprocess, sys, time
import atexit, signal

# Hosts/ports/password are overridable (defaults are the t420/T320 lab pair).
NODE0 = (os.environ.get("QIHSE_NODE0_HOST", "192.168.1.91"),
         int(os.environ.get("QIHSE_NODE0_PORT", "7100")))
NODE1 = (os.environ.get("QIHSE_NODE1_HOST", "192.168.1.250"),
         int(os.environ.get("QIHSE_NODE1_PORT", "7101")))
PW = os.environ.get("QIHSE_CLUSTER_PASSWORD", "QihseCluster2026x!")
NODE0_EP = f"{NODE0[0]}:{NODE0[1]}"
NODE1_EP = f"{NODE1[0]}:{NODE1[1]}"

def encode(*a):
    out = f"*{len(a)}\r\n".encode()
    for x in a: out += f"${len(x)}\r\n".encode() + x.encode() + b"\r\n"
    return out

class C:
    def __init__(s, addr):
        s.s = socket.create_connection(addr, timeout=10); s.buf = b""
    def reply(s):
        while b"\r\n" not in s.buf:
            d = s.s.recv(65536)
            if not d: raise ConnectionError
            s.buf += d
        line, s.buf = s.buf.split(b"\r\n", 1)
        t, rest = line[:1], line[1:]
        if t in b"+-:": return (t.decode(), rest.decode())
        if t == b"$":
            n = int(rest)
            while len(s.buf) < n + 2: s.buf += s.s.recv(65536)
            d, s.buf = s.buf[:n], s.buf[n+2:]
            return ("$", d.decode())
        if t == b"*": return ("*", [s.reply() for _ in range(int(rest))])
        return ("?", line.decode())
    def cmd(s, *a):
        s.s.sendall(encode(*a)); return s.reply()

_SELF_SPAWN = "--self-spawn" in sys.argv
_daemons = []

def _register_teardown():
    atexit.register(_teardown_hermetic)
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda s, f: (sys.exit(1)))

def _spawn_hermetic():
    """Seed owns the full ring; the joiner knows only the seed's bus."""
    bin_path = os.environ.get("QIHSE_BIN", "./qihse-cluster-daemon")
    lib = os.environ.get("QIHSE_LIB_DIR", ".")
    # Fresh dir per run: stale state from a prior run (old slot tables,
    # leftover WALs) must never leak into a hermetic drill.
    import tempfile
    data = os.environ.get("QIHSE_DATA_DIR") or tempfile.mkdtemp(
        prefix="cluster-discover-smoke-", dir="./build")
    env = dict(os.environ, LD_LIBRARY_PATH=lib)
    d0 = os.path.join(data, "seed"); d1 = os.path.join(data, "joiner")
    os.makedirs(d0, exist_ok=True); os.makedirs(d1, exist_ok=True)
    global NODE0, NODE1, NODE0_EP, NODE1_EP
    NODE0 = ("127.0.0.1", int(os.environ.get("QIHSE_DISCOVER_PORT0", "7110")))
    NODE1 = ("127.0.0.1", int(os.environ.get("QIHSE_DISCOVER_PORT1", "7111")))
    NODE0_EP = f"{NODE0[0]}:{NODE0[1]}"
    NODE1_EP = f"{NODE1[0]}:{NODE0[1] if False else NODE1[1]}"
    seed = subprocess.Popen(
        [bin_path, "--index", "0", "--bind", "127.0.0.1",
         "--port", str(NODE0[1]), "--bus-port",
         str(NODE0[1] + 10000), "--slot-range", "0-16383",
         "--operator-password", PW, "--dir", d0],
        env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    _daemons.append(seed)
    time.sleep(2)
    joiner = subprocess.Popen(
        [bin_path, "--index", "1", "--bind", "127.0.0.1",
         "--port", str(NODE1[1]), "--bus-port",
         str(NODE1[1] + 10000),
         "--join", f"127.0.0.1:{NODE0[1] + 10000}",
         "--operator-password", PW, "--dir", d1],
        env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    _daemons.append(joiner)

def _teardown_hermetic():
    # leak-proof: a killed drill (pack timeout) still tears its daemons down
    for p in _daemons:
        if p.poll() is None:
            p.kill()
    for p in _daemons:
        p.wait()

def main():
    if _SELF_SPAWN:
        _register_teardown()
        _spawn_hermetic()
        time.sleep(8)   # heartbeat health window + discovery
    results = []
    def check(name, cond, detail=""):
        results.append(cond)
        print(f"{'PASS' if cond else 'FAIL'}: {name} {detail}")

    c = C(NODE1); c.cmd("AUTH", "GODMODE_OP", PW)
    t, nodes = c.cmd("CLUSTER", "NODES")
    check("joiner discovered both nodes", NODE0_EP in nodes and NODE1_EP in nodes)
    check("joiner learned full slot map", "0-16383" in nodes)

    c0 = C(NODE0); c0.cmd("AUTH", "GODMODE_OP", PW)
    t, nodes0 = c0.cmd("CLUSTER", "NODES")
    check("seed sees the joiner", NODE1_EP in nodes0)

    t, r = c0.cmd("SET", "dyn:test", "discovered-value")
    check("SET on seed", r == "OK", r)

    t, r = c.cmd("GET", "dyn:test")
    hops = 0
    while t == "-" and r.startswith("MOVED") and hops < 3:
        tgt = r.split()[2].rsplit(":", 1)
        c = C((tgt[0], int(tgt[1]))); c.cmd("AUTH", "GODMODE_OP", PW)
        t, r = c.cmd("GET", "dyn:test"); hops += 1
    check("GET via joiner redirects + round-trips", r == "discovered-value", r)

    print(f"\ndiscovery smoke: {sum(results)}/{len(results)} checks passed")
    if _SELF_SPAWN:
        _teardown_hermetic()
    return 0 if all(results) else 1

if __name__ == "__main__":
    sys.exit(main())
