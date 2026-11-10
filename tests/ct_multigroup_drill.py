#!/usr/bin/env python3
"""Real three-daemon CT group ring and CT2 transfer recovery drill.

All three processes receive the same complete --ct-group map. The ring is
A -> C -> B -> A so C is already A's admitted CT1 receiver when A transfers a
subset of group A to C. This fixture is intentionally tied to the daemon's
multi-group CLI and does not emulate group state in Python.
"""
from __future__ import annotations

import binascii
from concurrent.futures import ThreadPoolExecutor, as_completed
import re
import secrets
import time

from ct_transport_drill import (
    IsolatedCluster, ROOT, ct1_receiver_status, ct1_source_status,
    new_generation, parse_resp_frame, topology_id_for,
)

NODES = ("lead", "successor", "joiner")  # A, B, C
NODE_IDS = {"lead": "ct3-node-a", "successor": "ct3-node-b",
            "joiner": "ct3-node-c"}
# A owns the largest lane; B is next; C is the least-loaded receiver. CT2 A->C
# should move a suffix that the source hook clamps to group A's admitted lane.
SLOT_RUNS = {"lead": "0-8191", "successor": "8192-13191",
             "joiner": "13192-16383"}
OWNER = {"group-a": "lead", "group-b": "successor", "group-c": "joiner"}
SUCCESSOR = {"group-a": "joiner", "group-b": "lead", "group-c": "successor"}


def command(session, *args):
    return parse_resp_frame(session.execute_resp(*args))


def expect_ok(reply, operation):
    if not isinstance(reply, tuple) or reply[0] != "status":
        raise AssertionError(f"{operation}: {reply!r}")


def tag_for(first, last, label):
    for index in range(200000):
        tag = f"ct3-{label}-{index}"
        if first <= binascii.crc_hqx(tag.encode(), 0) % 16384 <= last:
            return tag
    raise AssertionError(f"could not find hash tag in {first}-{last}")


def owner_map(session):
    reply = command(session, "CLUSTER", "NODES")
    if not isinstance(reply, bytes):
        return None
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


def wait_value(session, key, expected, timeout=45):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        reply = command(session, "GET", key)
        if reply == expected:
            return
        if isinstance(reply, tuple) and reply[0] == "error" and b"TRYAGAIN" in reply[1]:
            time.sleep(0.1)
            continue
        time.sleep(0.1)
    raise AssertionError(f"value did not converge for {key}")


def wait_drained(source_to_receiver, receiver_to_source, label):
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        source = ct1_source_status(receiver_to_source)
        receiver = ct1_receiver_status(source_to_receiver)
        if (source["acknowledged_lsn"] >= source["durable_lsn"] and
                receiver["durable_cursor"] >= source["durable_lsn"]):
            return
        time.sleep(0.1)
    raise AssertionError(f"CT1 lane {label} did not drain")


def main():
    if not (ROOT / "qihse-cluster-daemon").is_file():
        raise AssertionError("build the integrated daemon before running this drill")
    with IsolatedCluster(prefix="ct-multigroup-") as cluster:
        for name in NODES:
            cluster.reserve_endpoint(name)
        topology = {name: topology_id_for(*cluster.endpoints[name]) for name in NODES}
        group_ids = {name: secrets.token_hex(32) for name in OWNER}
        generations = {name: new_generation() for name in OWNER}

        # One common replicated configuration on every daemon. A receives B's
        # group, B receives C's group, and C receives A's group.
        group_args = []
        for group in ("group-a", "group-b", "group-c"):
            owner, successor = OWNER[group], SUCCESSOR[group]
            group_args.extend([
                "--ct-group",
                ",".join((group_ids[group], topology[owner], topology[successor],
                          generations[group], SLOT_RUNS[owner])),
            ])

        def start(name, *, brain=False, target_clearance=65535, target_sci=65535):
            extra = list(group_args)
            for candidate in NODES:
                if candidate != name:
                    extra.extend(["--replication-allowed-peer", NODE_IDS[candidate],
                                  str(cluster.identity_file(candidate, "qihse_dsa_pub.pem"))])
            # Existing service-principal knobs provide the authorization
            # negative path without adding a test-only daemon account.
            if name == "joiner":
                extra.extend(["--replication-principal-clearance", str(target_clearance),
                              "--replication-principal-sci", str(target_sci)])
            if brain:
                brain_dir = cluster.root / "brain-a"
                brain_dir.mkdir(mode=0o700, exist_ok=True)
                extra.extend(["--brain", "--brain-act", "--brain-interval", "1",
                              "--brain-cooldown", "1", "--brain-dir", str(brain_dir)])
            return cluster.start_node(name, NODES.index(name), NODE_IDS[name], extra,
                topology_names=NODES,
                slot_ranges={name: tuple(map(int, SLOT_RUNS[name].split("-")))
                             for name in NODES},
                topology_qkp_ids=NODE_IDS)[1]

        # Start concurrently: group membership is cyclic, so no node may wait
        # for a linear predecessor to be started first.
        admins = {}
        with ThreadPoolExecutor(max_workers=3) as pool:
            futures = {pool.submit(start, name): name for name in NODES}
            for future in as_completed(futures, timeout=90):
                admins[futures[future]] = future.result()

        # Build the three authenticated CT1 pairs in the configured ring.
        # Each client authenticates as the source or receiver identity pinned
        # by the destination daemon.
        def open_lane_clients():
            result = {}
            for group in ("group-a", "group-b", "group-c"):
                owner, successor = OWNER[group], SUCCESSOR[group]
                result[group] = (
                    cluster.replication_peer_client(identity_name=owner,
                        node_id=NODE_IDS[owner], target_name=successor),
                    cluster.replication_peer_client(identity_name=successor,
                        node_id=NODE_IDS[successor], target_name=owner),
                )
            return result

        lane_clients = open_lane_clients()

        tags = {
            "lead": tag_for(0, 5000, "a"),
            "successor": tag_for(8192, 13191, "b"),
            "joiner": tag_for(13192, 16383, "c"),
        }
        keys = {name: f"{{{tags[name]}}}:ring-seed" for name in NODES}
        values = {name: f"ring-value-{name}" for name in NODES}
        for name in NODES:
            expect_ok(command(admins[name], "SET", keys[name], values[name]),
                      f"write {name} owned group")
        for group, (outbound, inbound) in lane_clients.items():
            wait_drained(outbound, inbound, group)
        # Verify each data owner and its configured receiver can read the write.
        for name in NODES:
            wait_value(admins[name], keys[name], values[name])
        for group in ("group-a", "group-b", "group-c"):
            owner, successor = OWNER[group], SUCCESSOR[group]
            wait_value(admins[successor], keys[owner], values[owner])
        initial = owner_map(admins["lead"])
        if initial is None or any(sum(owner == topology[name] for owner in initial.values()) == 0
                                  for name in NODES):
            raise AssertionError("initial ownership map must show all three active owners")
        if (sum(owner == topology["lead"] for owner in initial.values()) != 8192 or
                sum(owner == topology["successor"] for owner in initial.values()) != 5000 or
                sum(owner == topology["joiner"] for owner in initial.values()) != 3192):
            raise AssertionError("initial ring ownership counts differ from the configured lane runs")

        # Restart B with the same full ring map. It must retain its own B group
        # and its receiver state for C's group before A starts balancing.
        admins["successor"].close()
        cluster.processes["successor"].terminate()
        cluster.processes["successor"].wait(timeout=15)
        admins["successor"] = start("successor")
        lane_clients = open_lane_clients()
        for name in NODES:
            wait_value(admins[name], keys[name], values[name])
        wait_value(admins["successor"], keys["joiner"], values["joiner"])

        # Add classified/SCI-bearing source data within A's owned group, then
        # restart C with a low replication service ceiling to prove the CT2
        # import path does not expose it. The existing C receiver remains a
        # durable group-A target while access is denied.
        high_id = None
        high_key = None
        for attempt in range(128):
            text = f"CT multi-group protected fixture {attempt} {secrets.token_hex(8)}"
            candidate = command(admins["lead"], "AIMEM", "STORE", "2", text)
            if not isinstance(candidate, bytes) or len(candidate) != 36:
                continue
            key = "aimem:" + candidate.decode("ascii").replace("-", "")[:16]
            slot = command(admins["lead"], "CLUSTER", "KEYSLOT", key)
            if isinstance(slot, int) and 5692 <= slot <= 8191:
                high_id, high_key = candidate.decode(), key
                break
        if high_id is None:
            raise AssertionError("could not create protected source data in group A")
        protected_value = command(admins["lead"], "GET", high_key)
        if not isinstance(protected_value, bytes):
            raise AssertionError(f"protected source record is unavailable: {protected_value!r}")
        wait_value(admins["joiner"], high_key, protected_value)
        # Reopen C with low clearance and SCI so CT2 target authorization must
        # refuse the protected group and preserve A's durable pending tuple.
        admins["joiner"].close()
        cluster.processes["joiner"].terminate()
        cluster.processes["joiner"].wait(timeout=15)
        admins["joiner"] = start("joiner", target_clearance=0, target_sci=0)

        # Start the brain only after all three groups have data and receiver
        # cursors. A->C is the only expected transfer; the lane selector clamps
        # the proposed slots to group A's current admitted range.
        admins["lead"].close()
        cluster.processes["lead"].terminate()
        cluster.processes["lead"].wait(timeout=15)
        admins["lead"] = start("lead", brain=True)
        # A denied target keeps the source fenced and the same durable tuple;
        # do not use an unavailable source read as evidence of data loss.
        time.sleep(8)
        denied_view = owner_map(admins["successor"])
        if denied_view is None or denied_view.get(7000) != topology["lead"]:
            raise AssertionError("low-clearance/SCI target changed A ownership before authorization")

        # Raise C's data principal through the existing startup configuration.
        # The source brain retries the same fenced operation and the local
        # finalized receipt path must be stable if C had already completed it.
        admins["joiner"].close()
        cluster.processes["joiner"].terminate()
        cluster.processes["joiner"].wait(timeout=15)
        admins["joiner"] = start("joiner")
        lane_clients = open_lane_clients()
        deadline = time.monotonic() + 90
        final = {}
        while time.monotonic() < deadline:
            final = {name: owner_map(admins[name]) for name in NODES}
            if all(mapping is not None for mapping in final.values()):
                owner_id = topology["joiner"]
                if (all(mapping == final["lead"] for mapping in final.values()) and
                    all(mapping.get(7000) == owner_id for mapping in final.values()) and
                    all(sum(owner == topology["lead"] for owner in mapping.values()) < 8192
                        for mapping in final.values()) and
                    all(sum(owner == topology["joiner"] for owner in mapping.values()) > 3192
                        for mapping in final.values())):
                    break
            time.sleep(0.2)
        else:
            raise AssertionError(f"CT2 multi-group transfer did not converge: {final!r}")

        # C now owns migrated group-A slots and continues owning group C, while
        # its source replica C->B and its pre-existing A receiver both remain.
        wait_value(admins["lead"], keys["lead"], values["lead"])
        wait_value(admins["successor"], keys["successor"], values["successor"])
        wait_value(admins["joiner"], keys["joiner"], values["joiner"])
        wait_value(admins["joiner"], high_key, protected_value)
        post_transfer_key = f"{{{tags['joiner']}}}:post-transfer-write"
        expect_ok(command(admins["joiner"], "SET", post_transfer_key,
                          "C remains a live owner"), "write C-owned group after CT2")
        for group, (outbound, inbound) in lane_clients.items():
            wait_drained(outbound, inbound, group)
        wait_value(admins["successor"], post_transfer_key, b"C remains a live owner")
        if any(sum(owner == topology[name] for owner in final["joiner"].values()) == 0
               for name in NODES) or \
                sum(owner == topology["lead"] for owner in final["lead"].values()) >= 8192 or \
                sum(owner == topology["joiner"] for owner in final["joiner"].values()) <= 3192:
            raise AssertionError("CT2 did not redistribute ownership from A to C")
        print("PASS three-node CT group ring: each node owns and replicates a group, restart preserves owner/receiver state, protected CT2 A→C converges, and no node is the sole owner")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
