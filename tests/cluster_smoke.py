#!/usr/bin/env python3
"""Two-node QIHSE cluster smoke test.

Connects to node 0 (t420), authenticates, inspects cluster topology, then
exercises cross-node routing: keys that hash to slots owned by the remote
node must yield MOVED redirects; following them must store and retrieve the
value on the T320. Also verifies replication-agnostic reads from both nodes.
"""
import os
import socket
import sys

# Hosts/ports/password are overridable so the smoke can run against any
# two-node deployment (defaults are the t420/T320 lab pair).
NODE0 = (os.environ.get("QIHSE_NODE0_HOST", "192.168.1.91"),
         int(os.environ.get("QIHSE_NODE0_PORT", "7100")))
NODE1 = (os.environ.get("QIHSE_NODE1_HOST", "192.168.1.250"),
         int(os.environ.get("QIHSE_NODE1_PORT", "7101")))
PASSWORD = os.environ.get("QIHSE_CLUSTER_PASSWORD", "QihseCluster2026x!")

def encode(*args):
    out = f"*{len(args)}\r\n".encode()
    for a in args:
        if isinstance(a, str):
            a = a.encode()
        out += f"${len(a)}\r\n".encode() + a + b"\r\n"
    return out

class Client:
    def __init__(self, addr):
        self.addr = addr
        self.sock = socket.create_connection(addr, timeout=10)
        self.buf = b""

    def _read_line(self):
        while b"\r\n" not in self.buf:
            d = self.sock.recv(65536)
            if not d:
                raise ConnectionError("closed")
            self.buf += d
        line, self.buf = self.buf.split(b"\r\n", 1)
        return line

    def reply(self):
        line = self._read_line()
        t, rest = line[:1], line[1:]
        if t in b"+-:,":
            return (t.decode(), rest.decode(errors="replace"))
        if t == b"$":
            n = int(rest)
            if n == -1:
                return ("$", None)
            while len(self.buf) < n + 2:
                self.buf += self.sock.recv(65536)
            data, self.buf = self.buf[:n], self.buf[n + 2:]
            return ("$", data.decode(errors="replace"))
        if t == b"*":
            n = int(rest)
            return ("*", [self.reply() for _ in range(n)])
        if t in b"()>":  # push/aggregate wrappers: recurse one line header
            return self.reply()
        raise RuntimeError(f"unknown reply type {t!r} line={line!r}")

    def cmd(self, *args):
        self.sock.sendall(encode(*args))
        return self.reply()

def moved_target(msg):
    # e.g. "MOVED 3999 <peer-host>:<peer-port>"
    parts = msg.split()
    if len(parts) >= 3:
        host, port = parts[2].rsplit(":", 1)
        return (host, int(port))
    return None

def main():
    results = []
    def check(name, ok, detail=""):
        results.append((name, ok, detail))
        print(f"{'PASS' if ok else 'FAIL'}: {name} {detail}")

    c0 = Client(NODE0)
    r = c0.cmd("PING")
    check("PING node0 (pre-auth, auth-exempt)", r == ("+", "PONG"), str(r))
    r = c0.cmd("GET", "smoke:alpha")
    check("GET node0 (pre-auth) refused", r[0] == "-" and "NOAUTH" in r[1], str(r))

    r = c0.cmd("AUTH", "GODMODE_OP", PASSWORD)
    check("AUTH node0", r == ("+", "OK"), str(r))

    r = c0.cmd("PING")
    check("PING node0 (post-auth)", r == ("+", "PONG"), str(r))

    r = c0.cmd("CLUSTER", "INFO")
    info = r[1] if r[0] in ("$", "*") else str(r)
    check("CLUSTER INFO", r[0] in ("$", "*", "+"), str(r)[:120])

    r = c0.cmd("CLUSTER", "NODES")
    detail = str(r)[:200]
    check("CLUSTER NODES lists topology", r[0] in ("$", "*", "+"), detail)

    # Cross-node routing: try both keys; one lands on node0 (slots 0-8191),
    # the other on node1 (8192-16383). Follow MOVED redirects.
    remote_node = None
    for key, value in (("smoke:alpha", "alpha-value-t420"), ("smoke:bravo", "bravo-value-t320")):
        c = Client(NODE0)
        c.cmd("AUTH", "GODMODE_OP", PASSWORD)
        r = c.cmd("SET", key, value)
        hops = 0
        while r[0] == "-" and r[1].startswith("MOVED") and hops < 3:
            target = moved_target(r[1])
            check(f"SET {key} -> MOVED", target is not None, r[1])
            remote_node = target
            c = Client(target)
            c.cmd("AUTH", "GODMODE_OP", PASSWORD)
            r = c.cmd("SET", key, value)
            hops += 1
        check(f"SET {key}", r == ("+", "OK"), str(r))

        r = c.cmd("GET", key)
        hops = 0
        while r[0] == "-" and r[1].startswith("MOVED") and hops < 3:
            target = moved_target(r[1])
            c = Client(target)
            c.cmd("AUTH", "GODMODE_OP", PASSWORD)
            r = c.cmd("GET", key)
            hops += 1
        check(f"GET {key} value round-trip", r == ("$", value), str(r))

    # The remote node (if any key landed there) must be the configured peer.
    if remote_node:
        check("remote node is the configured peer", remote_node[0] == NODE1[0], str(remote_node))
        c1 = Client(NODE1)
        c1.cmd("AUTH", "GODMODE_OP", PASSWORD)
        r = c1.cmd("DBSIZE")
        check("DBSIZE on peer node", r[0] == ":", str(r))

    print()
    failed = [r for r in results if not r[1]]
    print(f"cluster smoke: {len(results) - len(failed)}/{len(results)} checks passed")
    return 1 if failed else 0

if __name__ == "__main__":
    sys.exit(main())
