#!/usr/bin/env python3
"""Exit non-zero if the cluster seeds disagree on CLUSTER SLOTS.

A node that claims slots another node owns accepts writes with +OK instead of
MOVED, so those writes are silently invisible to the rest of the cluster.

Usage:
    QIHSE_OPERATOR_PASSWORD=... scripts/check_slot_agreement.py \
        [host:port ...]
Seeds default to QIHSE_SEEDS (comma separated) or the 3-node lab cluster.
"""
import os
import socket
import sys

DEFAULT_SEEDS = "192.168.1.91:7100,192.168.1.250:7101,192.168.1.90:7115"


def _enc(*args):
    out = b"*%d\r\n" % len(args)
    for a in args:
        a = a.encode() if isinstance(a, str) else a
        out += b"$%d\r\n%s\r\n" % (len(a), a)
    return out


def _read(f):
    line = f.readline().rstrip(b"\r\n")
    kind, rest = line[:1], line[1:]
    if kind in (b"+", b"-", b":"):
        return line.decode(errors="replace")
    if kind == b"$":
        n = int(rest)
        return None if n < 0 else f.read(n + 2)[:-2].decode(errors="replace")
    if kind == b"*":
        n = int(rest)
        return None if n < 0 else [_read(f) for _ in range(n)]
    raise ValueError("bad RESP reply: %r" % line)


def slot_map(host, port, password):
    with socket.create_connection((host, port), timeout=15) as s:
        f = s.makefile("rb")
        s.sendall(_enc("AUTH", password))
        reply = _read(f)
        if reply != "+OK":
            raise RuntimeError("AUTH failed: %s" % reply)
        s.sendall(_enc("CLUSTER", "SLOTS"))
        rows = _read(f)
    return sorted((int(r[0].lstrip(":")), int(r[1].lstrip(":")), r[2][0],
                   int(str(r[2][1]).lstrip(":"))) for r in rows)


def main(argv):
    password = os.environ.get("QIHSE_OPERATOR_PASSWORD")
    if not password:
        print("QIHSE_OPERATOR_PASSWORD not set", file=sys.stderr)
        return 2
    seeds = argv or os.environ.get("QIHSE_SEEDS", DEFAULT_SEEDS).split(",")
    maps = {}
    for seed in seeds:
        host, port = seed.rsplit(":", 1)
        try:
            maps[seed] = slot_map(host, int(port), password)
        except Exception as exc:  # unreachable seed is a failure too
            print("%s: ERROR %s" % (seed, exc), file=sys.stderr)
            return 1
    reference_seed = next(iter(maps))
    ok = True
    for seed, m in maps.items():
        same = m == maps[reference_seed]
        ok &= same
        print("%s: %s" % (seed, "agrees" if same else "DIVERGES"))
        if not same:
            for first, last, host, port in m:
                print("    %d-%d -> %s:%d" % (first, last, host, port))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
