#!/usr/bin/env python3
"""Dynamic-discovery cluster smoke: node 1 is launched knowing NOTHING except
one seed bus address (--join). Verifies membership discovery (MEET + gossip),
slot-map propagation (SLOT_UPDATE re-announcements), and cross-node routing
through the joiner after the heartbeat health window has elapsed.

Prereq: node 0 (seed, all slots) and node 1 (joiner, launched with --join) are
up; endpoints default to the t420/T320 lab pair and are overridable with
QIHSE_NODE0_HOST/PORT and QIHSE_NODE1_HOST/PORT.
"""
import os, socket, sys

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

def main():
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
    return 0 if all(results) else 1

if __name__ == "__main__":
    sys.exit(main())
