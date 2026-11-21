#!/usr/bin/env python3
"""Reject CT2 while a restarted target's persisted SOURCE lane is unadmitted.

All daemons, identities, consensus traffic, and transfer data are disposable
and loopback-only. The negative attempt is followed by CT1 re-admission and an
exact retry, so the fixture exercises both the fence and its recovery path.
"""
from __future__ import annotations

import secrets
import shutil
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed

from ct_multigroup_drill import (
    GroupCluster, NODE_IDS, NODES, OWNER, SLOT_RUNS, SUCCESSOR,
    command, group_receiver_status, group_source_status, owner_map,
    tag_for, wait_drained, write_when_ready,
)
from ct_transport_drill import ROOT, _free_udp_port, new_generation, topology_id_for


def main():
    if not (ROOT / "qihse-cluster-daemon").is_file():
        raise AssertionError("build the integrated daemon before running this drill")

    with GroupCluster(prefix="ct-group-admission-recovery-") as cluster:
        for name in NODES:
            cluster.reserve_endpoint(name)
        topology = {name: topology_id_for(*cluster.endpoints[name]) for name in NODES}
        mesh_members = {name: str(uuid.uuid4()) for name in NODES}
        mesh_ports = {name: _free_udp_port() for name in NODES}
        group_ids = {name: secrets.token_hex(32) for name in OWNER}
        generations = {name: new_generation() for name in OWNER}

        group_args = []
        for group in ("group-a", "group-b", "group-c"):
            owner, successor = OWNER[group], SUCCESSOR[group]
            group_args.extend([
                "--ct-group", ",".join((group_ids[group], topology[owner],
                    topology[successor], generations[group], SLOT_RUNS[owner])),
            ])

        def start(name):
            extra = list(group_args)
            extra.append("--failover-start-paused")
            extra.extend(["--consensus-group", "ct-group-admission-recovery",
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
            extra.extend(["--replication-principal-clearance", "65535",
                          "--replication-principal-sci", "65535",
                          "--brain", "--brain-interval", "30"])
            peer_dir = cluster.root / name / "data" / "consensus-peers"
            peer_dir.mkdir(mode=0o700, exist_ok=True)
            for peer in NODES:
                if peer != name:
                    shutil.copyfile(cluster.identity_file(peer, "qihse_dsa_pub.pem"),
                                    peer_dir / f"{peer}.pem")
            return cluster.start_node(name, NODES.index(name), NODE_IDS[name], extra,
                topology_names=NODES,
                slot_ranges={node: tuple(map(int, SLOT_RUNS[node].split("-")))
                             for node in NODES}, topology_qkp_ids=NODE_IDS)[1]

        admins = {}
        with ThreadPoolExecutor(max_workers=3) as pool:
            futures = {pool.submit(start, name): name for name in NODES}
            for future in as_completed(futures, timeout=90):
                admins[futures[future]] = future.result()

        def open_lane_clients():
            clients = {}
            for group in ("group-a", "group-b", "group-c"):
                owner, successor = OWNER[group], SUCCESSOR[group]
                clients[group] = (
                    cluster.replication_peer_client(identity_name=owner,
                        node_id=NODE_IDS[owner], target_name=successor),
                    cluster.replication_peer_client(identity_name=successor,
                        node_id=NODE_IDS[successor], target_name=owner),
                )
            return clients

        lanes = open_lane_clients()
        first, last = 5692, 8191
        tag = tag_for(first, last, "restart-admission")
        key, value = f"{{{tag}}}:admission-recovery", "persisted-source-lane"
        write_when_ready(admins["lead"], key, value, "seed transferable source row")
        for group, (outbound, inbound) in lanes.items():
            wait_drained(outbound, inbound, group_ids[group], group)

        before = owner_map(admins["lead"])
        if before is None or any(owner_map(admins[name]) != before for name in NODES):
            raise AssertionError("initial owner maps did not converge")
        if any(before.get(slot) != topology["lead"] for slot in range(first, last + 1)):
            raise AssertionError("selected transfer interval is not owned by the source")

        # Group C's persisted SOURCE lane points to B. Stop B before reopening
        # C, so no CT1 successor can perform RECONCILE and re-admit that lane.
        admins["successor"].close()
        cluster.processes["successor"].terminate()
        cluster.processes["successor"].wait(timeout=15)
        admins["joiner"].close()
        cluster.processes["joiner"].terminate()
        cluster.processes["joiner"].wait(timeout=15)
        admins["joiner"] = start("joiner")

        # STATUS proves the reopened target is live and its durable SOURCE tuple
        # still names the expected source, generation, and unavailable successor.
        # GROUP-CURSOR below checks the remaining admission bit at the target.
        target_status_peer = cluster.replication_peer_client(
            identity_name="successor", node_id=NODE_IDS["successor"], target_name="joiner")
        target_lane = group_source_status(target_status_peer, group_ids["group-c"])
        source_route_peer = cluster.replication_peer_client(
            identity_name="lead", node_id=NODE_IDS["lead"], target_name="joiner")
        target_route = group_receiver_status(source_route_peer, group_ids["group-a"])
        if (target_route["source_id"] != NODE_IDS["lead"] or
                target_route["peer_id"] != NODE_IDS["joiner"]):
            raise AssertionError(f"source identity could not authenticate to the live target daemon: {target_route!r}")
        if (target_lane["source_id"] != NODE_IDS["joiner"] or
                target_lane["peer_id"] != NODE_IDS["successor"] or
                target_lane["generation"] != generations["group-c"]):
            raise AssertionError(f"reopened target did not retain its exact SOURCE lane: {target_lane!r}")

        transfer_id = "ct2-admission-" + secrets.token_hex(12)
        attempt = command(admins["lead"], "CLUSTER", "CT2", "TRANSFER",
            topology["joiner"], f"{first}-{last}", transfer_id)
        expected = ("error", b"TRYAGAIN CT2 transfer remains fenced: target successor has not durably reached the chosen target ACK cut")
        if attempt != expected:
            raise AssertionError(f"authenticated CT2 did not stop at the unadmitted target GROUP-CURSOR: {attempt!r}")
        if any(owner_map(admins[name]) != before for name in ("lead", "joiner")):
            raise AssertionError("rejected CT2 changed the live owner map")
        staged = list((cluster.root / "joiner" / "data").glob(".qihse-ctg-*.qfs"))
        if staged:
            raise AssertionError(f"rejected GROUP-CURSOR created staged images: {staged!r}")
        retry_pending = command(admins["lead"], "CLUSTER", "CT2", "TRANSFER",
            topology["joiner"], f"{first}-{last}", transfer_id)
        if retry_pending != expected:
            raise AssertionError(f"same CT2 retry did not preserve its exact fenced response: {retry_pending!r}")
        if any(owner_map(admins[name]) != before for name in ("lead", "joiner")):
            raise AssertionError("retry of rejected CT2 changed the live owner map")
        print("PASS authenticated CT2 reached the reopened target; its exact persisted SOURCE tuple was rejected before GROUP-BEGIN, repeated retry stayed fenced, ownership stayed unchanged, and no .qfs stage appeared", flush=True)

        # Restart the target after an actual fenced CT2 attempt. Its durable
        # SOURCE lane must continue to block the same operation while B is down.
        admins["joiner"].close()
        cluster.processes["joiner"].terminate()
        cluster.processes["joiner"].wait(timeout=15)
        admins["joiner"] = start("joiner")
        target_status_peer = cluster.replication_peer_client(
            identity_name="successor", node_id=NODE_IDS["successor"], target_name="joiner")
        target_lane = group_source_status(target_status_peer, group_ids["group-c"])
        if (target_lane["source_id"] != NODE_IDS["joiner"] or
                target_lane["peer_id"] != NODE_IDS["successor"] or
                target_lane["generation"] != generations["group-c"]):
            raise AssertionError(f"target restart lost or changed the persisted SOURCE tuple: {target_lane!r}")
        source_route_peer = cluster.replication_peer_client(
            identity_name="lead", node_id=NODE_IDS["lead"], target_name="joiner")
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            retry_after_target_restart = command(admins["lead"], "CLUSTER", "CT2", "TRANSFER",
                topology["joiner"], f"{first}-{last}", transfer_id)
            if retry_after_target_restart != expected:
                raise AssertionError(f"target restart changed the exact fenced CT2 reply: {retry_after_target_restart!r}")
            if all(owner_map(admins[name]) == before for name in ("lead", "joiner")):
                break
            time.sleep(0.2)
        else:
            raise AssertionError("restarted target did not restore the unchanged owner map")
        staged = list((cluster.root / "joiner" / "data").glob(".qihse-ctg-*.qfs"))
        if staged:
            raise AssertionError(f"target restart retry created staged images: {staged!r}")
        print("PASS target restart preserved the persisted SOURCE tuple, exact CT2 fence, unchanged owner map, and empty stage", flush=True)

        # A competing transfer id for the same reserved range must not bypass
        # the durable lane fence: the source refuses it without writing any
        # new journal state, and the original tuple keeps its exact reply.
        second_id = "ct2-second-" + secrets.token_hex(12)
        second_attempt = command(admins["lead"], "CLUSTER", "CT2", "TRANSFER",
            topology["joiner"], f"{first}-{last}", second_id)
        expected_second = ("error",
            b"TRYAGAIN CT2 transfer remains fenced: an existing transfer "
            b"intent/fence must recover before preparing another range")
        if second_attempt != expected_second:
            raise AssertionError(f"second transfer id was not stopped by the durable range fence: {second_attempt!r}")
        if any(owner_map(admins[name]) != before for name in ("lead", "joiner")):
            raise AssertionError("rejected second transfer id changed the live owner map")
        staged = list((cluster.root / "joiner" / "data").glob(".qihse-ctg-*.qfs"))
        if staged:
            raise AssertionError(f"rejected second transfer id created staged images: {staged!r}")
        if command(admins["lead"], "CLUSTER", "CT2", "TRANSFER",
                topology["joiner"], f"{first}-{last}", transfer_id) != expected:
            raise AssertionError("original fenced tuple changed after a competing transfer id was refused")
        # The fenced id must have no durable target-side CT2 staging record:
        # the authenticated STATUS probe fails closed when no manifest exists.
        if command(source_route_peer, "REPL.CT2", "STATUS", transfer_id) != (
                "error", b"ERR CT2 status unavailable or source identity mismatch"):
            raise AssertionError("fenced transfer id left a target-side CT2 staging record")
        print("PASS durable lane fence refused a competing transfer id without changing ownership, the original tuple, or target staging state", flush=True)

        # Restart the source itself. The fence must survive the initiator's
        # own restart: replay re-binds the same durable PREPARED tuple and the
        # same GROUP-CURSOR admission fence, with no ownership or stage drift.
        admins["lead"].close()
        cluster.processes["lead"].terminate()
        cluster.processes["lead"].wait(timeout=15)
        admins["lead"] = start("lead")
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            maps = {name: owner_map(admins[name]) for name in ("lead", "joiner")}
            if all(mapping == before for mapping in maps.values()):
                break
            time.sleep(0.2)
        else:
            raise AssertionError("restarted source did not restore the unchanged owner map")
        if command(admins["lead"], "CLUSTER", "CT2", "TRANSFER",
                topology["joiner"], f"{first}-{last}", transfer_id) != expected:
            raise AssertionError("source restart changed the durable fenced CT2 reply")
        if any(owner_map(admins[name]) != before for name in ("lead", "joiner")):
            raise AssertionError("source restart changed the live owner map")
        staged = list((cluster.root / "joiner" / "data").glob(".qihse-ctg-*.qfs"))
        if staged:
            raise AssertionError(f"source restart produced staged images before admission: {staged!r}")
        print("PASS source restart preserved the exact fenced tuple, unchanged owner map, and empty stage", flush=True)

        # Restore B and let its real CT1 receiver worker re-establish C's
        # successor admission. Retry the same durable CT2 operation and require
        # completion rather than discarding or mutating its prepared tuple.
        admins["successor"] = start("successor")
        deadline = time.monotonic() + 90
        retry = None
        while time.monotonic() < deadline:
            retry = command(admins["lead"], "CLUSTER", "CT2", "TRANSFER",
                topology["joiner"], f"{first}-{last}", transfer_id)
            if retry == ("status", b"COMMITTED"):
                break
            # After B returns, C may be admitted before the composite image
            # seal is durable on both receivers. This is a later fenced phase,
            # not a violation of the unavailable-target checks above.
            seal_pending = ("error", b"TRYAGAIN CT2 transfer remains fenced: C or D did not persist the identical composite image seal")
            if retry not in (expected, seal_pending):
                raise AssertionError(f"same fenced CT2 retry changed behavior during admission recovery: {retry!r}")
            if any(owner_map(admins[name]) != before for name in ("lead", "joiner")):
                raise AssertionError("recovery retry changed ownership before CT2 committed")
            time.sleep(0.25)
        else:
            raise AssertionError(f"restored successor did not re-admit the persisted SOURCE lane: {retry!r}")
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            maps = {name: owner_map(admins[name]) for name in NODES}
            if all(mapping is not None and mapping == maps["lead"] for mapping in maps.values()) and \
                    maps["lead"].get(first) == topology["joiner"]:
                break
            time.sleep(0.2)
        else:
            raise AssertionError("recovered CT2 owner map did not converge")
        print("PASS restored successor admission and exact CT2 retry reconciled the fixture", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
