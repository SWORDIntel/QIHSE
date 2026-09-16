#!/usr/bin/env python3
"""Slot load-shift smoke: seed keys across both slot ranges on node 0, then
CLUSTER MOVESLOTS 8192-16383 -> T320. Verifies: data transfer (keys moved,
source copies deleted), ownership flip + bus propagation (both nodes agree),
routing (seed MOVED-redirects, new writes land on the T320).

Prereq: dynamic cluster up (see tests/cluster_discover_smoke.py).
Run twice-safe: previous leftovers are re-collected by the next MOVESLOTS.
"""
import os, socket, sys, time

# Hosts/ports/password are overridable (defaults are the t420/T320 lab pair).
PW = os.environ.get("QIHSE_CLUSTER_PASSWORD", "QihseCluster2026x!")
N0 = (os.environ.get("QIHSE_NODE0_HOST", "192.168.1.91"),
      int(os.environ.get("QIHSE_NODE0_PORT", "7100")))
N1 = (os.environ.get("QIHSE_NODE1_HOST", "192.168.1.250"),
      int(os.environ.get("QIHSE_NODE1_PORT", "7101")))
N0_EP = f"{N0[0]}:{N0[1]}"
N1_EP = f"{N1[0]}:{N1[1]}"

def encode(*a):
    out = f"*{len(a)}\r\n".encode()
    for x in a: out += f"${len(x)}\r\n".encode() + x.encode() + b"\r\n"
    return out

class C:
    def __init__(s, addr):
        s.addr = addr
        s.s = socket.create_connection(addr, timeout=15); s.buf = b""
    def reply(s):
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
            while len(s.buf) < n + 2: s.buf += s.s.recv(65536)
            d, s.buf = s.buf[:n], s.buf[n+2:]
            return ("$", d.decode())
        if t == b"*": return ("*", [s.reply() for _ in range(int(rest))])
        return ("?", line.decode())
    def cmd(s, *a):
        s.s.sendall(encode(*a)); return s.reply()
    def fresh(s):
        s.s.close(); s.__init__(s.addr)

def get_follow(c, key, password=PW, hops=3):
    t, r = c.cmd("GET", key)
    while t == "-" and r.startswith("MOVED") and hops:
        tgt = r.split()[2].rsplit(":", 1)
        c = C((tgt[0], int(tgt[1]))); c.cmd("AUTH", "GODMODE_OP", password)
        t, r = c.cmd("GET", key); hops -= 1
    return t, r

def set_follow(c, key, value, password=PW, hops=3):
    t, r = c.cmd("SET", key, value)
    while t == "-" and r.startswith("MOVED") and hops:
        tgt = r.split()[2].rsplit(":", 1)
        c = C((tgt[0], int(tgt[1]))); c.cmd("AUTH", "GODMODE_OP", password)
        t, r = c.cmd("SET", key, value); hops -= 1
    return t, r

def main():
    results = []
    def check(name, cond, detail=""):
        results.append(cond); print(f"{'PASS' if cond else 'FAIL'}: {name} {detail}")

    # Ensure the cluster starts from a known layout: all slots on the seed.
    # If a previous run left 8192-16383 elsewhere, drive ITS owner to move back.
    n0 = C(N0); n0.cmd("AUTH", "GODMODE_OP", PW)
    t, layout = n0.cmd("CLUSTER", "NODES")
    for line in layout.strip().splitlines():
        parts = line.split()
        if len(parts) > 8 and "myself" not in line and any(p.startswith("8192-") for p in parts[8:]):
            hostport = parts[1].split("@")[0]
            host, port = hostport.rsplit(":", 1)
            owner = C((host, int(port))); owner.cmd("AUTH", "GODMODE_OP", PW)
            t, r = owner.cmd("CLUSTER", "MOVESLOTS", "8192-16383", N0_EP)
            print(f"reset: returned 8192-16383 to seed ({r})")
            time.sleep(1)
            n0.fresh(); n0.cmd("AUTH", "GODMODE_OP", PW)
            break
    high = []
    i = 0
    while len(high) < 5:
        k = f"shift:key{i}"; i += 1
        t, slot = n0.cmd("CLUSTER", "KEYSLOT", k)
        if int(slot) >= 8192: high.append(k)
    for k in high:
        t, r = n0.cmd("SET", k, f"val-{k}")
        assert r == "OK", r
    print(f"seeded {len(high)} keys in the 8192-16383 range on the seed")

    check("pre-move: high keys served by seed",
          all(n0.cmd("GET", k) == ("$", f"val-{k}") for k in high))

    t, r = n0.cmd("CLUSTER", "MOVESLOTS", "8192-16383", N1_EP)
    moved = int(r.split()[0]) if t == "$" and "keys moved" in r else -1
    check("MOVESLOTS ran and moved >= the fresh keys", moved >= len(high), r)

    time.sleep(1)
    n0.fresh(); n0.cmd("AUTH", "GODMODE_OP", PW)
    n1 = C(N1); n1.cmd("AUTH", "GODMODE_OP", PW)

    check("high keys now served by peer",
          all(get_follow(n1, k) == ("$", f"val-{k}") for k in high))
    check("high keys no longer served by seed (nil or MOVED)",
          all((lambda r: r[1] is None or r[1].startswith("MOVED"))(n0.cmd("GET", k)) for k in high))
    check("seed MOVED-redirects the moved range to peer",
          all(N1_EP in n0.cmd("GET", k)[1] for k in high))
    t, r = n0.cmd("SET", high[0] + "-new", "post-shift")
    if t == "-":  # redirected: follow
        tgt = r.split()[2].rsplit(":", 1)
        c = C((tgt[0], int(tgt[1]))); c.cmd("AUTH", "GODMODE_OP", PW)
        t, r = c.cmd("SET", high[0] + "-new", "post-shift")
    check("new write into moved range lands on peer", (t, r) == ("+", "OK"), f"{t} {r}")
    check("peer serves the new write", n1.cmd("GET", high[0] + "-new") == ("$", "post-shift"))

    t, n1v = n1.cmd("CLUSTER", "NODES")
    check("peer sees itself owning 8192-16383", "8192-16383" in n1v)
    t, n0v = n0.cmd("CLUSTER", "NODES")
    check("seed's view updated via bus broadcast", "8192-16383" in n0v and "0-8191" in n0v)

    print(f"\nload-shift smoke: {sum(results)}/{len(results)} checks passed")
    return 0 if all(results) else 1

if __name__ == "__main__":
    sys.exit(main())
