#!/usr/bin/env python3
"""Real CT1 A→B→C promotions, a quorum partition, and missed ancestry.

Each daemon initially owns one group and receives another. A remains offline
through the first promotion; B is then killed before A returns. A and C regain
their quorum only after a fixture-local TCP gate opens, while QKP and the
cluster bus remain reachable throughout that partition.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import ExitStack
import hashlib
import secrets
import select
import shutil
import socket
import struct
import subprocess
import sys
import threading
import time
import uuid

from ct_multigroup_drill import (
    GroupCluster, command, group_receiver_status, group_source_status,
    owner_map, seed_classified_kv, tag_for, wait_value, write_when_ready,
)
from ct_transport_drill import (
    OPERATOR_PASSWORD, ROOT, _free_tcp_port, new_generation, topology_id_for,
)

NODES = ("lead", "successor", "joiner")  # A, B, C
NODE_IDS = {name: f"ct-promotion-{letter}" for name, letter in zip(NODES, "abc")}
RUNS = {"lead": (0, 8191), "successor": (8192, 13191),
        "joiner": (13192, 16383)}
OWNERS = {"lane-l": "lead", "lane-b": "successor", "lane-c": "joiner"}
SUCCESSORS = {"lane-l": "successor", "lane-b": "joiner", "lane-c": "lead"}


class ConsensusGate:
    """Transparent, fixture-local TCP ingress; it never decodes QKP data."""

    def __init__(self, backend_port):
        self.backend_port = backend_port
        self.enabled = threading.Event()
        self.enabled.set()
        self.stopping = threading.Event()
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.bind(("127.0.0.1", 0))
        self.port = self.listener.getsockname()[1]
        self.listener.listen(64)
        self.listener.settimeout(0.2)
        self.workers = []
        self.thread = threading.Thread(target=self._accept, daemon=True)
        self.thread.start()

    def _accept(self):
        while not self.stopping.is_set():
            try:
                client, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            if not self.enabled.is_set():
                client.close()
                continue
            worker = threading.Thread(target=self._forward, args=(client,), daemon=True)
            self.workers.append(worker)
            worker.start()

    def _forward(self, client):
        backend = None
        try:
            backend = socket.create_connection(("127.0.0.1", self.backend_port), 1)
            client.settimeout(2)
            backend.settimeout(2)
            while not self.stopping.is_set() and self.enabled.is_set():
                readable, _, _ = select.select((client, backend), (), (), 0.2)
                for source in readable:
                    data = source.recv(65536)
                    if not data:
                        return
                    if not self.enabled.is_set():
                        return
                    (backend if source is client else client).sendall(data)
        except OSError:
            pass  # A deliberately stopped fixture member may close any RPC.
        finally:
            client.close()
            if backend is not None:
                backend.close()

    def block(self):
        self.enabled.clear()

    def open(self):
        self.enabled.set()

    def close(self):
        self.stopping.set()
        self.enabled.clear()
        self.listener.close()
        self.thread.join(timeout=2)
        for worker in self.workers:
            worker.join(timeout=2)


def wait_ownership(admins, owner_id, slots, timeout=90):
    deadline = time.monotonic() + timeout
    last = {}
    while time.monotonic() < deadline:
        last = {name: owner_map(session) for name, session in admins.items()}
        values = list(last.values())
        if (values and all(value is not None and len(value) == 16384 for value in values)
                and all(value == values[0] for value in values)
                and all(values[0].get(slot) == owner_id for slot in range(*slots))):
            return values[0]
        time.sleep(0.2)
    counts = {name: {owner: sum(value == owner for value in mapping.values())
                    for owner in set(mapping.values())} if mapping else mapping
              for name, mapping in last.items()}
    status = {name: command(session, "QIHSE.CONSENSUS.STATUS") for name, session in admins.items()}
    raise AssertionError(f"ownership did not converge to {owner_id}: {counts!r}; consensus={status!r}")


def wait_lane(cluster, owner, successor, lane, timeout=60):
    to_receiver = cluster.replication_peer_client(identity_name=owner,
        node_id=NODE_IDS[owner], target_name=successor)
    to_source = cluster.replication_peer_client(identity_name=successor,
        node_id=NODE_IDS[successor], target_name=owner)
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        try:
            source = group_source_status(to_source, lane)
            receiver = group_receiver_status(to_receiver, lane)
            last = source, receiver
            if (source["source_id"] == NODE_IDS[owner] and
                    source["peer_id"] == NODE_IDS[successor] and
                    source["source_id"] == receiver["source_id"] and
                    source["peer_id"] == receiver["peer_id"] and
                    source["generation"] == receiver["generation"] and
                    source["baseline_digest"] == receiver["baseline_digest"] and
                    source["baseline_stream_cut"] == receiver["baseline_stream_cut"] and
                    source["certificate_head"] == source["certificate_ack"] and
                    receiver["baseline_sealed"] and
                    source["acknowledged_position"] >= source["durable_position"] and
                    receiver["durable_position"] >= source["durable_position"]):
                return source
        except AssertionError as exc:
            last = str(exc)
        time.sleep(0.2)
    raise AssertionError(f"lane {lane} {owner}→{successor} did not drain: {last!r}")


def certificates(cluster, identity, target, lane):
    peer = cluster.replication_peer_client(identity_name=identity,
        node_id=NODE_IDS[identity], target_name=target)
    after = bytes(32)
    result = []
    while True:
        page = command(peer, "REPL.CT1", "CERTPAGE", lane, after.hex(), "65536")
        if not isinstance(page, bytes):
            raise AssertionError(f"certificate metadata read rejected on {target}: {page!r}")
        if not page:
            return result
        offset = 0
        previous = after
        while offset < len(page):
            if len(page) - offset < 36:
                raise AssertionError("truncated certificate page header")
            length = struct.unpack_from(">I", page, offset)[0]
            digest = page[offset + 4:offset + 36]
            offset += 36
            if not 0 < length <= 8192 or length > len(page) - offset:
                raise AssertionError("invalid certificate envelope length")
            envelope = page[offset:offset + length]
            if hashlib.sha256(envelope).digest() != digest:
                raise AssertionError("certificate page digest mismatch")
            result.append(envelope)
            after = digest
            offset += length
        if after == previous:
            raise AssertionError("certificate pagination made no progress")


def stop(cluster, admins, name):
    admins.pop(name).close()
    cluster.kill(name)


def main():
    if not (ROOT / "qihse-cluster-daemon").is_file():
        raise AssertionError("build the integrated daemon before running this drill")
    with GroupCluster(prefix="ct-promotion-chain-") as cluster, ExitStack() as stack:
        for name in NODES:
            cluster.reserve_endpoint(name)
        topology = {name: topology_id_for(*cluster.endpoints[name]) for name in NODES}
        members = {name: str(uuid.uuid4()) for name in NODES}
        ports = {name: _free_tcp_port() for name in NODES}
        gates = {name: ConsensusGate(ports[name]) for name in NODES}
        for gate in gates.values():
            stack.callback(gate.close)
        lanes = {name: secrets.token_hex(32) for name in OWNERS}
        generations = {name: new_generation() for name in OWNERS}
        tags = {name: tag_for(*RUNS[name], f"promotion-{name}") for name in NODES}
        keys = {name: f"{{{tags[name]}}}:own-group" for name in NODES}
        protected = f"{{{tags['lead']}}}:protected-sci"
        protected_value = f"preserved-class5-sci1-{secrets.token_hex(12)}"
        seed_classified_kv(cluster, "lead", protected, protected_value, 5, 1)

        for local in NODES:
            peer_dir = cluster.root / local / "data" / "consensus-peers"
            peer_dir.mkdir(mode=0o700, exist_ok=True)
            for peer in NODES:
                if peer != local:
                    shutil.copyfile(cluster.identity_file(peer, "qihse_dsa_pub.pem"),
                                    peer_dir / f"{peer}.pem")
        group_args = []
        for lane in OWNERS:
            owner, successor = OWNERS[lane], SUCCESSORS[lane]
            first, last = RUNS[owner]
            group_args += ["--ct-group", ",".join((lanes[lane], topology[owner],
                topology[successor], generations[lane], f"{first}-{last}"))]

        def start(name, *, clearance=65535, sci=65535):
            args = list(group_args)
            args += ["--replication-principal-clearance", str(clearance),
                     "--replication-principal-sci", str(sci)]
            args += ["--brain", "--brain-interval", "30",
                     "--consensus-group", "ct-promotion-chain",
                     "--consensus-self", members[name],
                     "--consensus-listen-ip", "127.0.0.1",
                     "--consensus-port", str(ports[name]),
                     "--consensus-authority-proposals",
                     "--consensus-history-id", "3b" * 32,
                     "--consensus-writer-epoch", "1",
                     "--consensus-election-base-ms", "500",
                     "--consensus-election-spread-ms", "500",
                     "--consensus-heartbeat-ms", "50"]
            for peer in NODES:
                args += ["--consensus-member", members[peer]]
                if peer != name:
                    args += ["--consensus-peer",
                        f"{members[peer]}:{NODE_IDS[peer]}:consensus-peers/{peer}.pem:"
                        f"127.0.0.1:{gates[peer].port}",
                        "--replication-allowed-peer", NODE_IDS[peer],
                        str(cluster.identity_file(peer, "qihse_dsa_pub.pem"))]
            return cluster.start_node(name, NODES.index(name), NODE_IDS[name], args,
                topology_names=NODES, slot_ranges=RUNS, topology_qkp_ids=NODE_IDS)[1]

        admins = {}
        with ThreadPoolExecutor(max_workers=3) as pool:
            starts = {pool.submit(start, name): name for name in NODES}
            for future in as_completed(starts, timeout=90):
                admins[starts[future]] = future.result()
        print(f"CT promotion fixture: {cluster.root}", flush=True)
        for name in NODES:
            write_when_ready(admins[name], keys[name], f"initial-{name}",
                             f"initial write to {name}")
        deleted = f"{{{tags['lead']}}}:deleted-after-first-promotion"
        write_when_ready(admins["lead"], deleted, "delete-me", "seed deletion row")
        for lane in OWNERS:
            wait_lane(cluster, OWNERS[lane], SUCCESSORS[lane], lanes[lane])
        initial = owner_map(admins["lead"])
        if initial is None or any(not any(owner == topology[name] for owner in initial.values())
                                  for name in NODES):
            raise AssertionError("all three physical nodes must initially own a group")

        stop(cluster, admins, "lead")
        wait_ownership(admins, topology["successor"], (0, 8192))
        first_status = wait_lane(cluster, "successor", "joiner", lanes["lane-l"])
        if first_status["generation"] == generations["lane-l"]:
            raise AssertionError("first promotion retained the failed generation")
        wait_value(admins["successor"], protected, protected_value)
        wait_value(admins["successor"], keys["lead"], "initial-lead")
        write_when_ready(admins["successor"], keys["lead"], "written-by-b", "B promoted write")
        reply = command(admins["successor"], "DEL", deleted)
        if reply != 1:
            raise AssertionError(f"promoted delete did not succeed: {reply!r}")
        write_when_ready(admins["successor"], keys["successor"], "B still owns its group",
                         "unrelated B source group after promotion")
        wait_lane(cluster, "successor", "joiner", lanes["lane-l"])
        first_chain = certificates(cluster, "joiner", "successor", lanes["lane-l"])
        if not first_chain:
            raise AssertionError("first promotion has no original signed certificate")
        print("PASS A→B promotion with independent B-owned group", flush=True)

        stop(cluster, admins, "successor")
        gates["lead"].block()
        gates["joiner"].block()
        admins["lead"] = start("lead", clearance=0, sci=0)
        # A is reachable over the normal QKP and bus paths. Only consensus
        # traffic is partitioned, so a missing fresh successor is not the
        # reason C must refuse to acquire B's group.
        deadline = time.monotonic() + 20
        seen_healthy = False
        while time.monotonic() < deadline:
            nodes = command(admins["joiner"], "CLUSTER", "NODES")
            if isinstance(nodes, bytes):
                seen_healthy = any(fields[0] == topology["lead"] and fields[7] == "connected"
                    for line in nodes.decode().splitlines()
                    if len(fields := line.split()) >= 8)
            if seen_healthy:
                break
            time.sleep(0.2)
        if not seen_healthy:
            raise AssertionError("returned A did not become a healthy QKP/bus successor candidate")
        time.sleep(3)
        isolated = owner_map(admins["joiner"])
        if isolated is None or any(isolated.get(slot) != topology["successor"]
                                   for slot in range(0, 8192)):
            raise AssertionError("C changed committed ownership without a voter quorum")
        minority_write = command(admins["joiner"], "SET", keys["lead"], "minority-write")
        if not (isinstance(minority_write, tuple) and minority_write[0] == "error" and
                any(marker in minority_write[1] for marker in
                    (b"MOVED", b"TRYAGAIN", b"CLUSTERDOWN"))):
            raise AssertionError(f"minority C admitted a write: {minority_write!r}")
        print("PASS isolated C refuses promotion/write despite reachable successor A", flush=True)

        gates["lead"].open()
        gates["joiner"].open()
        # Exercise actual data-plane identities, rather than provisioning
        # users in a separate volatile auth process. A is the new receiver;
        # insufficient clearance/SCI must block its protected baseline and
        # keep common ownership on B until its real configuration is restored.
        for label in ("clearance", "SCI"):
            deadline = time.monotonic() + 45
            while time.monotonic() < deadline:
                diagnostic = (cluster.root / "lead.log").read_text(errors="replace")
                if any(f"failed at {stage}" in diagnostic for stage in
                       ("baseline validate", "baseline install")):
                    break
                time.sleep(0.2)
            else:
                raise AssertionError(f"{label} denial did not reach protected baseline validation; consensus="
                    f"{ {node: command(session, 'QIHSE.CONSENSUS.STATUS') for node, session in admins.items()}!r}")
            denied = owner_map(admins["joiner"])
            if denied is None or any(denied.get(slot) != topology["successor"]
                                     for slot in range(0, 8192)):
                raise AssertionError(f"{label} denial changed common ownership")
            print(f"PASS protected promotion baseline denied by {label}", flush=True)
            stop(cluster, admins, "lead")
            admins["lead"] = start("lead", clearance=5, sci=0) if label == "clearance" else start("lead")
        wait_ownership(admins, topology["joiner"], (0, 8192))
        second_status = wait_lane(cluster, "joiner", "lead", lanes["lane-l"])
        if second_status["generation"] in (generations["lane-l"], first_status["generation"]):
            raise AssertionError("second promotion did not advance its independent generation")
        wait_value(admins["joiner"], keys["lead"], "written-by-b")
        wait_value(admins["joiner"], deleted, None)
        wait_value(admins["joiner"], protected, protected_value)
        write_when_ready(admins["joiner"], keys["joiner"], "C still owns its group",
                         "unrelated C source group after second promotion")
        write_when_ready(admins["joiner"], keys["lead"], "written-by-c", "C promoted write")
        wait_lane(cluster, "joiner", "lead", lanes["lane-l"])
        on_c = certificates(cluster, "lead", "joiner", lanes["lane-l"])
        on_a = certificates(cluster, "joiner", "lead", lanes["lane-l"])
        if (len(on_c) < len(first_chain) + 1 or on_c[:len(first_chain)] != first_chain or
                on_a != on_c):
            raise AssertionError("missed A→B ancestry was not recovered byte-for-byte while B was offline")
        stale_key = f"{{{tags['lead']}}}:stale-old-owner"
        stale_write = command(admins["lead"], "SET", stale_key, "must-not-write")
        if not (isinstance(stale_write, tuple) and stale_write[0] == "error" and
                any(marker in stale_write[1] for marker in (b"MOVED", b"TRYAGAIN"))):
            raise AssertionError(f"returned old source admitted a stale write: {stale_write!r}")
        wait_value(admins["joiner"], stale_key, None)
        if cluster.processes["successor"].poll() is None:
            raise AssertionError("the intermediate owner B must remain offline during ancestry recovery")
        print("PASS A→B→C real group promotions, quorum partition, original ancestry recovery, "
              "independent groups, deletion/label preservation and stale-source denial", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
