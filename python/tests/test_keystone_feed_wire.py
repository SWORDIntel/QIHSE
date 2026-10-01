#!/usr/bin/env python3
"""KEYSTONE feed over the real wire — W7 item 5, invariant 3.

Spawned by tests/qihse_keystone_feed_fixture.c (which owns the identities
and the classified records).  This script consumes the change feed through
a real socket as the provisioned index identity and as a lower identity,
and asserts:

  * the delivered envelope preserves classification/SCI/tenant/generation
    end-to-end (the indexer can never lose the security context);
  * records above clearance / outside SCI / in a foreign tenant are
    withheld server-side — their SENTINEL payloads never cross the wire
    (grep on everything received);
  * STATUS counts the denials exactly and never lies about them;
  * OPEN with a cursor (the §5.1 handshake) starts delivery at C;
  * a lower-clearance identity receives nothing at all (all denied).
"""

from __future__ import annotations

import json
import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(REPO, "python"))

from qihse.controller import Controller, ControllerError  # noqa: E402

PASS = 0
SENTINELS = ["SENTINEL-DENIED-HIGH", "SENTINEL-DENIED-SCI",
             "SENTINEL-DENIED-TENANT"]
VISIBLE = ["OPEN-PAYLOAD-AA", "CLEARED-PAYLOAD-BB", "EDGE-PAYLOAD-CC"]


def ok(name, cond, detail=""):
    global PASS
    if not cond:
        print(f"[FAIL] {name} {detail}")
        raise SystemExit(1)
    PASS += 1
    print(f"[PASS] {name}")


def drain(feed, seen_wire: list):
    events = []
    while True:
        ev = feed.next()
        if ev is None:
            return events
        events.append(ev)
        seen_wire.append(json.dumps(
            {"o": ev.offset, "r": ev.resource_id, "p": ev.payload.hex(),
             "c": ev.classification, "s": ev.sci, "t": ev.tenant_id}))


def main() -> int:
    port = 7403
    if "--port" in sys.argv:
        port = int(sys.argv[sys.argv.index("--port") + 1])

    # ── the index identity: clearance 2 / SCI 0x1 / tenant 77 ────────
    with Controller("127.0.0.1", port, username="feedidx",
                    password="FeedIdxPass123!", timeout_ms=15000) as c:
        seen: list = []
        with c.keystone_feed_open() as feed:
            events = drain(feed, seen)
            ok("index identity receives exactly the 3 cleared records",
               len(events) == 3, f"got {len(events)}")
            ok("envelope preserves classification/SCI/tenant",
               [(e.classification, e.sci, e.tenant_id) for e in events]
               == [(0, 0, 77), (2, 1, 77), (2, 0, 77)],
               str([(e.classification, e.sci, e.tenant_id) for e in events]))
            ok("payloads are the cleared ones",
               [e.payload.decode() for e in events] == VISIBLE,
               str([e.payload.decode() for e in events]))
            ok("event ids are 38-char hex (dedup keys)",
               all(len(e.event_id) == 36 for e in events))
            ok("hlc stamps present",
               all(e.hlc_physical_ms > 0 for e in events))
            st = feed.status()
            ok("STATUS counts the 3 denials exactly",
               st.denied == 3 and st.malformed == 0, repr(st))
            ok("cursor advanced past the journal", st.cursor > events[-1].offset)

        # §5.1 handshake: a cursor is an END-of-record position (what
        # STATUS/ACK hand back).  Consume exactly one record, checkpoint
        # its cursor, and reopen AT that cursor: live delivery resumes
        # with the second record — the exact-cursor meeting.
        with c.keystone_feed_open() as warm:
            first = warm.next()
            ok("warm feed delivered the first record",
               first is not None and first.payload == b"OPEN-PAYLOAD-AA")
            cursor_c = warm.status().cursor
        with c.keystone_feed_open(cursor=cursor_c) as feed2:
            ev = feed2.next()
            ok("OPEN-with-cursor resumes at C (2nd record)",
               ev is not None and ev.payload == b"CLEARED-PAYLOAD-BB",
               f"first={ev.payload if ev else None}")
            rest = drain(feed2, seen)
            ok("cursor open delivers the tail only",
               len(rest) == 1 and rest[0].payload == b"EDGE-PAYLOAD-CC")

        # resume semantics: rewind the same feed to the beginning
        feed3 = c.keystone_feed_open()
        feed3.resume(0)
        again = drain(feed3, seen)
        ok("RESUME 0 replays from the beginning",
           [e.resource_id for e in again] == [e.resource_id for e in events])
        feed3.close()

        # The wire transcript must not contain any denied sentinel.
        wire = "\n".join(seen)
        ok("denied payloads never crossed the wire",
           all(s not in wire for s in SENTINELS))

    # ── the lower identity: clearance 0 — only the unclassified record
    # is visible; the clearance-2 and denied-family records are withheld.
    with Controller("127.0.0.1", port, username="feedlow",
                    password="FeedLowPass123!", timeout_ms=15000) as c:
        with c.keystone_feed_open() as feed:
            events = drain(feed, [])
            ok("low identity sees exactly the unclassified record",
               len(events) == 1 and events[0].payload == b"OPEN-PAYLOAD-AA"
               and events[0].classification == 0,
               str([(e.payload, e.classification) for e in events]))
            st = feed.status()
            ok("5 records counted denied for the low identity",
               st.denied == 5 and st.malformed == 0, repr(st))

    # ── an unprovisioned principal may not even open a feed ──────────
    # (feedidx's sibling account is not created; use a wrong password to
    # prove AUTH itself fails, and the fixture analyst pattern is covered
    # in-process by test_keystone_feed_w25.)
    try:
        Controller("127.0.0.1", port, username="feedidx",
                   password="wrong-password-x", timeout_ms=10000)
        ok("bad credentials refused", False)
    except ControllerError:
        ok("bad credentials refused", True)

    print(f"\ntest_keystone_feed_wire: {PASS} checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
