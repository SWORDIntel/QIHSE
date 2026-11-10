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
import shutil
import subprocess
import sys
import time
import uuid

from ct_transport_drill import (
    IsolatedCluster, OPERATOR_PASSWORD, ROOT,
    _free_udp_port, new_generation, parse_resp_frame, topology_id_for,
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


def write_when_ready(session, key, value, operation, timeout=45):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        reply = command(session, "SET", key, value)
        if isinstance(reply, tuple) and reply[0] == "status":
            return
        if (isinstance(reply, tuple) and reply[0] == "error" and
                any(marker in reply[1] for marker in
                    (b"TRYAGAIN", b"CLUSTERDOWN"))):
            time.sleep(0.1)
            continue
        raise AssertionError(f"{operation}: {reply!r}")
    raise AssertionError(f"{operation}: owner lane never became writable")


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
    if isinstance(expected, str):
        expected = expected.encode()
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


def group_source_status(peer, lane_id):
    reply = command(peer, "REPL.CT1", "STATUS", lane_id)
    if not isinstance(reply, list) or len(reply) != 13 or reply[0] != lane_id.encode():
        raise AssertionError(f"unexpected CT1 source lane status: {reply!r}")
    return {
        "source_id": reply[1].decode(), "generation": reply[2].decode(),
        "peer_id": reply[3].decode(), "durable_position": int(reply[4]),
        "acknowledged_position": int(reply[5]), "baseline_row_seq": int(reply[8]),
        "baseline_stream_cut": int(reply[9]), "baseline_digest": reply[10].decode(),
        "certificate_head": reply[11].decode(), "certificate_ack": reply[12].decode(),
    }


def group_receiver_status(peer, lane_id):
    reply = command(peer, "REPL.CT1", "TARGET", lane_id, "STATUS")
    if not isinstance(reply, list) or len(reply) != 8 or reply[0] != lane_id.encode():
        raise AssertionError(f"unexpected CT1 receiver lane status: {reply!r}")
    return {
        "source_id": reply[1].decode(), "generation": reply[2].decode(),
        "peer_id": reply[3].decode(), "durable_position": int(reply[4]),
        "baseline_sealed": int(reply[5]) == 1,
        "baseline_stream_cut": int(reply[6]), "baseline_digest": reply[7].decode(),
    }


def wait_drained(source_to_receiver, receiver_to_source, lane_id, label):
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        source = group_source_status(receiver_to_source, lane_id)
        receiver = group_receiver_status(source_to_receiver, lane_id)
        if (source["source_id"] == receiver["source_id"] and
                source["peer_id"] == receiver["peer_id"] and
                source["generation"] == receiver["generation"] and
                source["baseline_digest"] == receiver["baseline_digest"] and
                source["baseline_stream_cut"] == receiver["baseline_stream_cut"] and
                source["certificate_head"] == source["certificate_ack"] and
                receiver["baseline_sealed"] and
                source["acknowledged_position"] >= source["durable_position"] and
                receiver["durable_position"] >= source["durable_position"]):
            return
        time.sleep(0.1)
    raise AssertionError(f"CT1 lane {label} did not drain with matching baseline/certificate metadata")


def pending_tuple(path):
    fields = path.read_text().splitlines()[0].split()
    if len(fields) != 8 or fields[0] != "QBP1":
        raise AssertionError(f"malformed private CT2 pending fixture record: {fields!r}")
    active, first, last = int(fields[1]), int(fields[2]), int(fields[3])
    return active, first, last, fields[4], fields[5], fields[6], fields[7]


def seed_classified_kv(cluster, node_name, key, value, classification=5, sci=1):
    """Seed an ordinary slot-owned row through the authenticated native API."""
    code = r"""
import ctypes, sys
lib = ctypes.CDLL(sys.argv[1])
lib.qihse_auth_init.restype = ctypes.c_bool
lib.qihse_auth_bootstrap_operator.argtypes = [ctypes.c_char_p]
lib.qihse_auth_bootstrap_operator.restype = ctypes.c_bool
lib.qihse_auth_get_user.argtypes = [ctypes.c_uint32]
lib.qihse_auth_get_user.restype = ctypes.c_void_p
lib.qihse_kv_store_create_user.argtypes = [ctypes.c_void_p]
lib.qihse_kv_store_create_user.restype = ctypes.c_void_p
lib.qihse_kv_set_user.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p,
                                  ctypes.c_uint16, ctypes.c_uint16, ctypes.c_void_p]
lib.qihse_kv_set_user.restype = ctypes.c_bool
lib.qihse_kv_get_user.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_void_p]
lib.qihse_kv_get_user.restype = ctypes.c_void_p
lib.qihse_auth_create_user.argtypes = [ctypes.c_void_p, ctypes.c_uint32,
    ctypes.c_uint16, ctypes.c_uint16, ctypes.c_uint16, ctypes.c_char_p, ctypes.c_bool]
lib.qihse_auth_create_user.restype = ctypes.c_void_p
lib.qihse_kv_sync_store.argtypes = [ctypes.c_void_p]
lib.qihse_kv_sync_store.restype = ctypes.c_bool
lib.qihse_kv_store_destroy.argtypes = [ctypes.c_void_p]
assert lib.qihse_auth_init()
lib.qihse_auth_bootstrap_operator(sys.argv[4].encode())
operator = lib.qihse_auth_get_user(0)
assert operator
store = lib.qihse_kv_store_create_user(operator)
assert store
try:
    assert lib.qihse_kv_set_user(store, sys.argv[2].encode(), sys.argv[3].encode(),
                                 int(sys.argv[5]), int(sys.argv[6]), operator)
    low = lib.qihse_auth_create_user(operator, 777, 2, 0, 0,
                                     b"CtMultiGroupLowUser42!", False)
    assert low
    assert not lib.qihse_kv_get_user(store, sys.argv[2].encode(), low)
    assert lib.qihse_kv_sync_store(store)
finally:
    lib.qihse_kv_store_destroy(store)
"""
    env = dict(cluster.env)
    env["QIHSE_DATA_DIR"] = str(cluster.root / node_name / "data")
    subprocess.run([sys.executable, "-c", code, str(ROOT / "libqihse.so"),
                    key, value, OPERATOR_PASSWORD, str(classification), str(sci)],
                   env=env, check=True, capture_output=True, timeout=20)


def main():
    if not (ROOT / "qihse-cluster-daemon").is_file():
        raise AssertionError("build the integrated daemon before running this drill")
    with IsolatedCluster(prefix="ct-multigroup-") as cluster:
        for name in NODES:
            cluster.reserve_endpoint(name)
        topology = {name: topology_id_for(*cluster.endpoints[name]) for name in NODES}
        mesh_members = {name: str(uuid.uuid4()) for name in NODES}
        mesh_ports = {name: _free_udp_port() for name in NODES}
        group_ids = {name: secrets.token_hex(32) for name in OWNER}
        generations = {name: new_generation() for name in OWNER}
        planned_first, planned_last = 5692, 8191
        protected_tag = tag_for(planned_first, planned_last, "protected")
        protected_slot = binascii.crc_hqx(protected_tag.encode(), 0) % 16384
        protected_key = f"{{{protected_tag}}}:slot-protected"
        protected_value = f"classified-sci-fixture-{secrets.token_hex(12)}"
        seed_classified_kv(cluster, "lead", protected_key, protected_value,
                           classification=5, sci=1)

        # Provision each member's pinned mesh peer keys beneath its own data
        # directory. Every daemon receives the same voter UUID set and its two
        # peer UUID/QKP/DSA/loopback endpoint tuples.
        for local in NODES:
            peer_dir = cluster.root / local / "data" / "consensus-peers"
            peer_dir.mkdir(mode=0o700, exist_ok=True)
            for peer in NODES:
                if peer != local:
                    shutil.copyfile(cluster.identity_file(peer, "qihse_dsa_pub.pem"),
                                    peer_dir / f"{peer}.pem")

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
            extra.extend(["--consensus-group", "ct-multigroup-ring",
                          "--consensus-self", mesh_members[name],
                          "--consensus-listen-ip", "127.0.0.1",
                          "--consensus-port", str(mesh_ports[name]),
                          "--consensus-authority-proposals",
                          "--consensus-history-id", "2a" * 32,
                          "--consensus-writer-epoch", "1",
                          "--consensus-election-base-ms", "500",
                          "--consensus-election-spread-ms", "500",
                          "--consensus-heartbeat-ms", "50"])
            for member in NODES:
                extra.extend(["--consensus-member", mesh_members[member]])
                if member != name:
                    extra.extend(["--consensus-peer",
                        f"{mesh_members[member]}:{NODE_IDS[member]}:"
                        f"consensus-peers/{member}.pem:127.0.0.1:{mesh_ports[member]}"])
            for candidate in NODES:
                if candidate != name:
                    extra.extend(["--replication-allowed-peer", NODE_IDS[candidate],
                                  str(cluster.identity_file(candidate, "qihse_dsa_pub.pem"))])
            # Existing service-principal knobs provide the authorization
            # negative path without adding a test-only daemon account.
            if name == "joiner":
                extra.extend(["--replication-principal-clearance", str(target_clearance),
                              "--replication-principal-sci", str(target_sci)])
            if not brain:
                # Group mode defaults every daemon to an acting brain. Keep
                # this setup phase observation-only so no range moves before
                # writes, replication, and the explicit authorization probe.
                extra.extend(["--brain", "--brain-interval", "30"])
            if brain:
                brain_dir = cluster.root / "brain-a"
                brain_dir.mkdir(mode=0o700, exist_ok=True)
                extra.extend(["--brain", "--brain-act", "--brain-interval", "1",
                              "--brain-cooldown", "1", "--brain-dir", str(brain_dir)])
            return cluster.start_node(name, NODES.index(name), NODE_IDS[name], extra,
                topology_names=NODES,
                slot_ranges={node: tuple(map(int, SLOT_RUNS[node].split("-")))
                             for node in NODES},
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
            write_when_ready(admins[name], keys[name], values[name],
                             f"write {name} owned group")
        for group, (outbound, inbound) in lane_clients.items():
            wait_drained(outbound, inbound, group_ids[group], group)
        # Public GET remains fenced on receiver-owned slots, including for the
        # Operator. Verify owner reads below and receiver progress via the
        # authenticated CT1 durable cursor/status contract above.
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
        # Validate restarted B's own live owner state. Its receiver-owned C
        # rows remain fenced from public GET until a durable ownership change.
        wait_value(admins["successor"], keys["successor"], values["successor"])
        # Validate A can read the protected slot while it owns it. Receiver
        # presence is established by CT1 durable-cursor progress, not GET.
        if command(admins["lead"], "GET", protected_key) != protected_value.encode():
            raise AssertionError("generic classified source row is missing on A")
        # Reopen C with low clearance and SCI so CT2 target authorization must
        # refuse the protected group and preserve A's durable pending tuple.
        admins["joiner"].close()
        cluster.processes["joiner"].terminate()
        cluster.processes["joiner"].wait(timeout=15)
        admins["joiner"] = start("joiner", target_clearance=0, target_sci=0)

        # Enable brain actuation only after all three groups have data and receiver
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
        if denied_view is None or denied_view.get(protected_slot) != topology["lead"]:
            raise AssertionError("clearance/SCI denial changed A ownership before authorization")
        durable_pending_path = cluster.root / "brain-a" / "ct2-pending"
        denied_pending = pending_tuple(durable_pending_path)
        if (denied_pending[0] != 1 or denied_pending[3] != topology["lead"] or
                denied_pending[4] != topology["joiner"] or
                not (denied_pending[1] <= protected_slot <= denied_pending[2] <= planned_last)):
            raise AssertionError(f"low-clearance target did not retain the exact A->C fenced tuple: {denied_pending!r}")

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
                    all(mapping.get(protected_slot) == owner_id for mapping in final.values()) and
                    all(sum(owner == topology["lead"] for owner in mapping.values()) < 8192
                        for mapping in final.values()) and
                    all(sum(owner == topology["joiner"] for owner in mapping.values()) > 3192
                        for mapping in final.values())):
                    break
            time.sleep(0.2)
        else:
            raise AssertionError(f"CT2 multi-group transfer did not converge: {final!r}")
        completed_pending = pending_tuple(durable_pending_path)
        if completed_pending != (0, *denied_pending[1:]):
            raise AssertionError(f"CT2 retry changed its durable tuple: {completed_pending!r} != {denied_pending!r}")

        # C now owns migrated group-A slots and continues owning group C, while
        # its source replica C->B and its pre-existing A receiver both remain.
        wait_value(admins["lead"], keys["lead"], values["lead"])
        wait_value(admins["successor"], keys["successor"], values["successor"])
        wait_value(admins["joiner"], keys["joiner"], values["joiner"])
        wait_value(admins["joiner"], protected_key, protected_value.encode())
        post_transfer_key = f"{{{tags['joiner']}}}:post-transfer-write"
        write_when_ready(admins["joiner"], post_transfer_key,
                         "C remains a live owner", "write C-owned group after CT2")
        for group, (outbound, inbound) in lane_clients.items():
            wait_drained(outbound, inbound, group_ids[group], group)
        # B is C's replica for group C, so its ordinary GET is intentionally
        # fenced. wait_drained() above checks the authenticated CT1 cursor.
        if any(sum(owner == topology[name] for owner in final["joiner"].values()) == 0
               for name in NODES) or \
                sum(owner == topology["lead"] for owner in final["lead"].values()) >= 8192 or \
                sum(owner == topology["joiner"] for owner in final["joiner"].values()) <= 3192:
            raise AssertionError("CT2 did not redistribute ownership from A to C")
        print("PASS three-node CT group ring: each node owns and replicates a group, restart preserves owner/receiver state, protected CT2 A→C converges, and no node is the sole owner")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
