#!/usr/bin/env python3
"""Real four-daemon automatic CT2 balancing between populated owners.

No test command transfers data or edits ownership. The donor's brain must
initiate CT2, whose two independent CT1 successors provide durable ACKs.
"""
from __future__ import annotations

import binascii
from pathlib import Path
import re
import time

from ct_transport_drill import (
    IsolatedCluster, ROOT, ct1_receiver_status, ct1_source_status,
    new_generation, parse_resp_frame, topology_id_for,
)

NAMES = ("lead", "successor", "joiner", "forged")
IDS = {name: f"brain-ct-{name}" for name in NAMES}
RANGES = {"lead": (0, 11999), "joiner": (12000, 16383)}


def command(session, *args):
    return parse_resp_frame(session.execute_resp(*args))


def expect_ok(reply, operation):
    if not isinstance(reply, tuple) or reply[0] != "status":
        raise AssertionError(f"{operation}: {reply!r}")


def tag_for(first, last, label):
    for index in range(100000):
        tag = f"brain-ct-{label}-{index}"
        if first <= binascii.crc_hqx(tag.encode(), 0) % 16384 <= last:
            return tag
    raise AssertionError("could not construct fixture hash tag")


CT_RECONCILING = ("error", b"TRYAGAIN CT primary is fenced or waiting for successor reconciliation")


def owners(session, *, allow_reconciliation=False):
    reply = command(session, "CLUSTER", "NODES")
    # TCP/AUTH readiness precedes CT1 admission after a source restart. During
    # that window even CLUSTER NODES is deliberately fenced by the dispatcher.
    # Return no map for this exact transient; the caller must retry within its
    # existing deadline and cannot count an unavailable view as convergence.
    if allow_reconciliation and reply == CT_RECONCILING:
        return None
    if not isinstance(reply, bytes):
        raise AssertionError(f"unexpected node list: {reply!r}")
    result = {}
    for line in reply.decode().splitlines():
        fields = line.split()
        if len(fields) < 8:
            continue
        for token in fields[8:]:
            match = re.fullmatch(r"(\d+)(?:-(\d+))?", token)
            if match:
                first, last = int(match[1]), int(match[2] or match[1])
                for slot in range(first, last + 1):
                    result[slot] = fields[0]
    return result


def wait_owners(session, timeout=30):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        mapping = owners(session, allow_reconciliation=True)
        if mapping is not None:
            return mapping
        time.sleep(0.1)
    raise AssertionError("ownership view remained CT1-fenced before deadline")


def wait_read(session, key):
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        reply = command(session, "GET", key)
        if isinstance(reply, tuple) and reply[0] == "error" and b"TRYAGAIN" in reply[1]:
            time.sleep(0.1)
            continue
        return reply
    raise AssertionError("CT1 baseline did not admit reads")


def wait_drained(outbound, inbound):
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        source, target = ct1_source_status(inbound), ct1_receiver_status(outbound)
        if (source["acknowledged_lsn"] >= source["durable_lsn"] and
                target["durable_cursor"] >= source["durable_lsn"]):
            return
        time.sleep(0.1)
    raise AssertionError("CT1 successor did not drain")


def stop(cluster, name):
    cluster.processes[name].terminate()
    cluster.processes[name].wait(timeout=15)


def main():
    if not (ROOT / "qihse-cluster-daemon").is_file():
        raise AssertionError("build the integrated daemon before running this drill")
    with IsolatedCluster(prefix="ct-brain-") as cluster:
        for name in NAMES:
            cluster.reserve_endpoint(name)
        generations = {"lead": new_generation(), "joiner": new_generation()}

        def start(name, role, peer, generation, brain=False):
            # Share the trusted CT role map with every daemon. A process's
            # local primary/successor pair cannot classify other successors.
            extra = ["--replica-of", "1:0", "--replica-of", "3:2"]
            for candidate in NAMES:
                if candidate not in (name, peer):
                    extra.extend(["--replication-allowed-peer", IDS[candidate],
                                  str(cluster.identity_file(candidate, "qihse_dsa_pub.pem"))])
            if brain:
                brain_dir = cluster.root / "lead-brain"
                brain_dir.mkdir(mode=0o700, exist_ok=True)
                extra.extend(["--brain", "--brain-act", "--brain-interval", "1",
                              "--brain-cooldown", "1", "--brain-rebalance-min-slots", "1",
                              "--brain-dir", str(brain_dir), "--brain-node-key",
                              str(cluster.identity_file(name, "qihse_dsa_key.pem")),
                              "--brain-dsa-key",
                              str(cluster.identity_file(name, "qihse_dsa_key.pem"))])
            return cluster.start_ct1_node(
                name, NAMES.index(name), role, peer, IDS[name], IDS[peer], generation,
                extra_args=extra, topology_names=NAMES, slot_ranges=RANGES,
                topology_qkp_ids=IDS,
            )[1]

        admin_b = start("successor", "successor", "lead", generations["lead"])
        admin_d = start("forged", "successor", "joiner", generations["joiner"])
        admin_a = start("lead", "primary", "successor", generations["lead"])
        admin_c = start("joiner", "primary", "forged", generations["joiner"])
        a_to_b = cluster.replication_peer_client(identity_name="lead", node_id=IDS["lead"], target_name="successor")
        b_to_a = cluster.replication_peer_client(identity_name="successor", node_id=IDS["successor"], target_name="lead")
        c_to_d = cluster.replication_peer_client(identity_name="joiner", node_id=IDS["joiner"], target_name="forged")
        d_to_c = cluster.replication_peer_client(identity_name="forged", node_id=IDS["forged"], target_name="joiner")

        move_tag = tag_for(8192, 11999, "move")
        source_tag = tag_for(0, 8191, "source")
        target_tag = tag_for(12000, 16383, "target")
        source_key, target_key = f"{{{source_tag}}}:retain", f"{{{target_tag}}}:retain"
        assert wait_read(admin_a, source_key) is None
        assert wait_read(admin_c, target_key) is None
        expect_ok(command(admin_a, "SET", source_key, "source-unrelated"), "seed donor retained row")
        expect_ok(command(admin_c, "SET", target_key, "target-unrelated"), "seed populated receiver")
        payload = b"automatic-ct2-payload-" + b"p" * 1024
        move_keys = [f"{{{move_tag}}}:row:{index}" for index in range(24)]
        for key in move_keys:
            expect_ok(command(admin_a, "SET", key, payload), "seed moving row")
        expiring_key = f"{{{move_tag}}}:expiring"
        expect_ok(command(admin_a, "SET", expiring_key, "expires", "PX", "180000"), "seed absolute expiry")
        ttl_before = command(admin_a, "PTTL", expiring_key)
        assert isinstance(ttl_before, int) and ttl_before > 0
        move_slot = command(admin_a, "CLUSTER", "KEYSLOT", move_keys[0])
        assert 8192 <= move_slot <= 11999
        wait_drained(a_to_b, b_to_a)
        wait_drained(c_to_d, d_to_c)
        topology_a = topology_id_for(*cluster.endpoints["lead"])
        topology_c = topology_id_for(*cluster.endpoints["joiner"])
        initial = owners(admin_a)
        assert sum(owner == topology_a for owner in initial.values()) == 12000
        assert sum(owner == topology_c for owner in initial.values()) == 4384
        assert command(admin_c, "GET", target_key) == b"target-unrelated"

        # The only behavioral change is enabling the source brain on restart.
        # No CLUSTER CT2 TRANSFER/MOVESLOTS/SETSLOT command appears in this test.
        admin_a.close(); b_to_a.close(); stop(cluster, "lead")
        admin_a = start("lead", "primary", "successor", generations["lead"], brain=True)
        sessions = {"lead": admin_a, "successor": admin_b,
                    "joiner": admin_c, "forged": admin_d}
        deadline = time.monotonic() + 60
        maps = {}
        while time.monotonic() < deadline:
            maps = {name: owners(session, allow_reconciliation=True)
                    for name, session in sessions.items()}
            if all(mapping is not None and mapping.get(move_slot) == topology_c and
                   sum(owner == topology_a for owner in mapping.values()) == 8192 and
                   sum(owner == topology_c for owner in mapping.values()) == 8192
                   for mapping in maps.values()):
                break
            time.sleep(0.2)
        else:
            cluster.fail_with_log("lead", f"brain did not balance populated owners; sampled owners={ {name: None if mapping is None else mapping.get(move_slot) for name, mapping in maps.items()} }")

        for key in move_keys:
            assert command(admin_c, "GET", key) == payload
        assert command(admin_c, "GET", expiring_key) == b"expires"
        ttl_after = command(admin_c, "PTTL", expiring_key)
        assert isinstance(ttl_after, int) and 0 < ttl_after <= ttl_before
        assert command(admin_a, "GET", source_key) == b"source-unrelated"
        assert command(admin_c, "GET", target_key) == b"target-unrelated"
        expect_ok(command(admin_c, "SET", f"{{{move_tag}}}:after", "new-owner-write"), "write after automatic activation")
        assert command(admin_c, "GET", f"{{{move_tag}}}:after") == b"new-owner-write"
        moved = command(admin_a, "GET", move_keys[0])
        assert isinstance(moved, tuple) and moved[0] == "error" and moved[1].startswith(b"MOVED ")
        wait_drained(c_to_d, d_to_c)

        # Historical CT2 publication must survive donor restart from the old
        # static slot configuration, without stealing the activated range back.
        admin_a.close(); stop(cluster, "lead")
        admin_a = start("lead", "primary", "successor", generations["lead"], brain=True)
        assert wait_read(admin_a, source_key) == b"source-unrelated"
        assert wait_owners(admin_a).get(move_slot) == topology_c
        assert command(admin_c, "GET", move_keys[-1]) == payload
        print("PASS real automatic CT2 balance: populated owners, successor durability, all-peer convergence, payload/TTL preservation, activated writes and donor restart")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
