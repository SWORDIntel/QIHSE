#!/usr/bin/env python3
"""Real four-daemon CT2 arbitrary-target transfer and recovery drill.

Node roles are A=source primary, B=A's CT1 successor, C=target primary, and
D=C's distinct CT1 successor. The fixture seeds C before attaching the shared
static topology so C contains a target-only row in the future imported range;
that row must be tombstoned while C's unrelated outside-range row survives.
"""
from __future__ import annotations

import os
import re
import secrets
import subprocess
import sys
import threading
import time
from pathlib import Path

from ct_transport_drill import (
    IsolatedCluster,
    ROOT,
    ct1_receiver_status,
    ct1_source_status,
    new_generation,
    parse_resp_frame,
    topology_id_for,
)

NODE_IDS = {"lead": "ct2-node-a", "successor": "ct2-node-b",
            "joiner": "ct2-node-c", "forged": "ct2-node-d"}
INDEXES = {"lead": 0, "successor": 1, "joiner": 2, "forged": 3}
TOPOLOGY_NAMES = ("lead", "successor", "joiner", "forged")
SLOT_RANGES = {"lead": (0, 8191), "joiner": (8192, 16383)}


def value(raw: bytes):
    return parse_resp_frame(raw)


def command(session, *args):
    return value(session.execute_resp(*args))


def resp_uint(field) -> int | None:
    if isinstance(field, int):
        return field if field >= 0 else None
    if isinstance(field, bytes) and field and field.isdigit():
        return int(field)
    return None


def expect_ok(reply, what: str) -> None:
    if not isinstance(reply, tuple) or reply[0] != "status":
        raise AssertionError(f"{what} failed: {reply!r}")


def find_tag_for_slot(session, predicate, label: str, start: int = 0) -> tuple[str, int]:
    for n in range(start, start + 200000):
        tag = f"{label}-{n}"
        key = f"{{{tag}}}:probe"
        reply = command(session, "CLUSTER", "KEYSLOT", key)
        if isinstance(reply, int) and predicate(reply):
            return tag, reply
    raise AssertionError(f"could not find hash slot for {label}")


def allowed_peer(name: str, cluster: IsolatedCluster) -> list[str]:
    return ["--replication-allowed-peer", NODE_IDS[name],
            str(cluster.identity_file(name, "qihse_dsa_pub.pem"))]


def extra_peer_pins(self_name: str, ct1_peer_name: str,
                    cluster: IsolatedCluster) -> list[str]:
    args: list[str] = []
    for name in NODE_IDS:
        if name not in (self_name, ct1_peer_name):
            args.extend(allowed_peer(name, cluster))
    return args


def close_node(cluster: IsolatedCluster, name: str) -> None:
    process = cluster.processes.get(name)
    if process and process.poll() is None:
        process.kill()
        process.wait(timeout=10)
    log = cluster.logs.get(name)
    if log:
        log.close()


def stop_node_gracefully(cluster: IsolatedCluster, name: str) -> None:
    process = cluster.processes.get(name)
    if process and process.poll() is None:
        process.terminate()
        process.wait(timeout=15)
    log = cluster.logs.get(name)
    if log:
        log.close()


def daemon_log_tail(cluster: IsolatedCluster, name: str) -> str:
    log = cluster.logs[name]
    log.flush()
    log.seek(0)
    return log.read().decode(errors="replace")[-8000:]


def same_slot_payload_keys(tag: str, count: int) -> list[str]:
    return [f"{{{tag}}}:payload:{index:04d}" for index in range(count)]


def wait_for_data_admission(admin, name: str, tag: str) -> None:
    """Wait for CT reconciliation using a harmless read, never a retried write."""
    probe_key = f"{{{tag}}}:ct2-reconcile-probe-absent:{secrets.token_hex(12)}"
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        reply = admin.execute_resp("GET", probe_key)
        if reply == b"$-1\r\n":
            return
        if not reply.startswith(b"-TRYAGAIN"):
            raise AssertionError(f"{name} CT1 readiness probe failed: {reply!r}")
        time.sleep(0.1)
    raise AssertionError(f"{name} CT1 reconciliation did not admit data reads")


def wait_for_ct1_drain(source_to_successor, successor_to_source, name: str) -> None:
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        source = ct1_source_status(successor_to_source)
        receiver = ct1_receiver_status(source_to_successor)
        if (source["acknowledged_lsn"] >= source["durable_lsn"] and
                receiver["durable_cursor"] >= source["acknowledged_lsn"]):
            return
        time.sleep(0.1)
    raise AssertionError(f"{name} CT1 successor has not acknowledged the durable cursor")


def transfer(session, transfer_id: str, target: str, first: int, last: int):
    return command(session, "CLUSTER", "CT2", "TRANSFER", target,
                   f"{first}-{last}", transfer_id)


def target_topology_id(cluster: IsolatedCluster, name: str) -> str:
    host, port = cluster.endpoints[name]
    return topology_id_for(host, port)


def transfer_until_committed(session, transfer_id: str, target: str,
                             first: int, last: int):
    deadline = time.monotonic() + 30
    last_reply = None
    while time.monotonic() < deadline:
        last_reply = transfer(session, transfer_id, target, first, last)
        if last_reply == ("status", b"COMMITTED"):
            return last_reply
        if not isinstance(last_reply, tuple) or last_reply[0] != "error" or \
                b"TRYAGAIN" not in last_reply[1]:
            raise AssertionError(f"CT2 control retry failed without pending status: {last_reply!r}")
        time.sleep(0.1)
    raise AssertionError(f"CT2 transfer did not reach COMMITTED before timeout: {last_reply!r}")


def cluster_slot_owners(admin) -> dict[int, str]:
    reply = command(admin, "CLUSTER", "NODES")
    if not isinstance(reply, bytes):
        raise AssertionError(f"CLUSTER NODES returned an unexpected frame: {reply!r}")
    owners: dict[int, str] = {}
    for line in reply.decode("ascii", "replace").splitlines():
        fields = line.split()
        if len(fields) < 8:
            continue
        node_id = fields[0]
        for token in fields[8:]:
            if token.startswith("["):
                continue
            match = re.fullmatch(r"(\d+)(?:-(\d+))?", token)
            if not match:
                continue
            first = int(match.group(1))
            last = int(match.group(2) or first)
            for slot in range(first, last + 1):
                owners[slot] = node_id
    return owners


def wait_for_peer_slot_owner(admins: dict[str, object], first: int, last: int,
                             expected_topology_id: str, label: str) -> None:
    deadline = time.monotonic() + 30
    last_maps = {}
    while time.monotonic() < deadline:
        last_maps = {name: cluster_slot_owners(admin) for name, admin in admins.items()}
        if all(all(last_maps[name].get(slot) == expected_topology_id
                   for slot in range(first, last + 1)) for name in admins):
            return
        time.sleep(0.1)
    summary = {name: {slot: owners.get(slot) for slot in (first, last)}
               for name, owners in last_maps.items()}
    raise AssertionError(f"{label} peer ownership did not converge: {summary!r}")


def assert_activated_receipt(peer, *, transfer_id: str,
                             topology_source_id: str, topology_target_id: str,
                             source_qkp_id: str, target_qkp_id: str,
                             generation: str, first: int, last: int,
                             source_lsn: int, config_epoch: int) -> None:
    receipt = command(peer, "REPL.CT2", "RECEIPT", transfer_id,
        topology_source_id, topology_target_id, source_qkp_id, target_qkp_id,
        generation, str(first), str(last), str(source_lsn), str(config_epoch))
    expected = [b"ACTIVATED", transfer_id.encode(), topology_source_id.encode(),
        topology_target_id.encode(), source_qkp_id.encode(), target_qkp_id.encode(),
        generation.encode(), str(first).encode(), str(last).encode(),
        str(source_lsn).encode()]
    if not isinstance(receipt, list) or len(receipt) != 13 or \
            receipt[:10] != expected or receipt[11] != str(config_epoch).encode() or \
            not isinstance(receipt[10], bytes) or not receipt[10].isdigit() or \
            not isinstance(receipt[12], bytes) or not re.fullmatch(rb"[0-9a-f]{64}", receipt[12]):
        raise AssertionError(f"historical CT2 ACTIVATED receipt failed tuple check: {receipt!r}")


def restart_primary(cluster: IsolatedCluster, name: str, peer_name: str,
                    extra: list[str]):
    close_node(cluster, name)
    role = "primary"
    generation = (cluster._ct2_source_generation if name == "lead"
                  else cluster._ct2_target_generation)
    return cluster.start_ct1_node(
        name, INDEXES[name], role, peer_name, NODE_IDS[name], NODE_IDS[peer_name],
        generation, extra_args=extra,
        topology_names=TOPOLOGY_NAMES, slot_ranges=SLOT_RANGES,
        topology_qkp_ids=NODE_IDS,
    )


def seed_classified_application_row(cluster, key: str, payload: str) -> None:
    """Seed only the stopped disposable source through authenticated KV APIs."""
    if "lead" in cluster.processes:
        raise AssertionError("classified fixture must precede source startup")
    program = r"""
import ctypes as c, os, sys
lib = c.CDLL(sys.argv[1])
lib.qihse_auth_init.restype = c.c_bool
lib.qihse_auth_bootstrap_operator.argtypes = [c.c_char_p]
lib.qihse_auth_bootstrap_operator.restype = c.c_bool
lib.qihse_auth_authenticate_id.argtypes = [c.c_uint32, c.c_char_p]
lib.qihse_auth_authenticate_id.restype = c.c_void_p
lib.qihse_kv_store_create_user.argtypes = [c.c_void_p]
lib.qihse_kv_store_create_user.restype = c.c_void_p
class Row(c.Structure):
    _fields_ = [("key", c.c_char_p), ("value", c.c_char_p),
                ("expiry", c.c_uint64), ("classification", c.c_uint16),
                ("sci", c.c_uint16)]
lib.qihse_kv_set_batch_durable_user.argtypes = [c.c_void_p,
    c.POINTER(Row), c.c_size_t, c.c_void_p]
lib.qihse_kv_set_batch_durable_user.restype = c.c_bool
lib.qihse_kv_store_destroy.argtypes = [c.c_void_p]
password = os.environ["QIHSE_OPERATOR_PASSWORD"].encode()
assert lib.qihse_auth_init()
lib.qihse_auth_bootstrap_operator(password)  # Environment may already provision UID 0.
principal = lib.qihse_auth_authenticate_id(0, password)
assert principal
store = lib.qihse_kv_store_create_user(principal)
assert store
try:
    row = Row(sys.argv[2].encode(), sys.argv[3].encode(), 0, 2, 4)
    assert lib.qihse_kv_set_batch_durable_user(store, c.byref(row), 1, principal)
finally:
    lib.qihse_kv_store_destroy(store)
"""
    env = dict(cluster.env, QIHSE_DATA_DIR=str(cluster.root / "lead" / "data"))
    subprocess.run([sys.executable, "-c", program, str(ROOT / "libqihse.so"),
                    key, payload], env=env, check=True, timeout=30)


def main() -> int:
    if not Path(os.environ.get("QIHSE_BIN", "./qihse-cluster-daemon")).resolve().is_file():
        raise AssertionError("build qihse-cluster-daemon before running the CT2 process drill")

    with IsolatedCluster(prefix="ct2-slot-transfer-") as cluster:
        # Pin all four endpoints before any daemon starts; C is first started
        # standalone only to seed local rows that are stale under A's map.
        for name in ("lead", "successor", "joiner", "forged"):
            cluster.reserve_endpoint(name)

        seed_target, seed_admin = cluster.start_node(
            "joiner", INDEXES["joiner"], NODE_IDS["joiner"], ["--slot-range", "0-16383"])
        stale_tag, first_slot = find_tag_for_slot(seed_admin,
            lambda slot: 128 <= slot < 8192, "ct2-first")
        second_tag, second_slot = find_tag_for_slot(seed_admin,
            lambda slot: 128 <= slot < 8192 and slot != first_slot, "ct2-second")
        outside_tag, outside_slot = find_tag_for_slot(seed_admin,
            lambda slot: slot >= 8192, "ct2-outside")
        stale_key = f"{{{stale_tag}}}:target-only"
        second_stale_key = f"{{{second_tag}}}:target-only"
        outside_key = f"{{{outside_tag}}}:preserve"
        expect_ok(command(seed_admin, "SET", stale_key, "stale-in-first-range"), "seed first stale row")
        expect_ok(command(seed_admin, "SET", second_stale_key, "stale-in-second-range"), "seed second stale row")
        expect_ok(command(seed_admin, "SET", outside_key, "outside-range-survives"), "seed outside row")
        if command(seed_admin, "GET", outside_key) != b"outside-range-survives":
            raise AssertionError("standalone target could not read outside-range seed before shutdown")
        seed_admin.close()
        # Persist this baseline fixture cleanly. The later CT2 fault phase uses
        # SIGKILL only after STATUS proves the transfer bytes are durable.
        stop_node_gracefully(cluster, "joiner")
        # Classification testing needs a shardable application row. AIMEM is
        # node-local and must survive on its source when application slots move.
        high_key = f"{{{stale_tag}}}:classified"
        high_payload = f"CT2-classified-payload-{secrets.token_hex(12)}"
        seed_classified_application_row(cluster, high_key, high_payload)

        cluster._ct2_source_generation = new_generation()
        cluster._ct2_target_generation = new_generation()
        # B and D start first; A and C validate their pinned CT1 successors
        # during primary startup. A/C also pin one another for arbitrary CT2.
        cluster.start_ct1_node("successor", 1, "successor", "lead",
            NODE_IDS["successor"], NODE_IDS["lead"], cluster._ct2_source_generation,
            extra_args=extra_peer_pins("successor", "lead", cluster),
            topology_names=TOPOLOGY_NAMES, slot_ranges=SLOT_RANGES,
            topology_qkp_ids=NODE_IDS)
        cluster.start_ct1_node("forged", 3, "successor", "joiner",
            NODE_IDS["forged"], NODE_IDS["joiner"], cluster._ct2_target_generation,
            extra_args=extra_peer_pins("forged", "joiner", cluster),
            topology_names=TOPOLOGY_NAMES, slot_ranges=SLOT_RANGES,
            topology_qkp_ids=NODE_IDS)
        source, source_admin = cluster.start_ct1_node("lead", 0, "primary", "successor",
            NODE_IDS["lead"], NODE_IDS["successor"], cluster._ct2_source_generation,
            extra_args=[*allowed_peer("joiner", cluster),
                        *extra_peer_pins("lead", "successor", cluster)],
            topology_names=TOPOLOGY_NAMES, slot_ranges=SLOT_RANGES,
            topology_qkp_ids=NODE_IDS)
        target, target_admin = cluster.start_ct1_node("joiner", 2, "primary", "forged",
            NODE_IDS["joiner"], NODE_IDS["forged"], cluster._ct2_target_generation,
            service_clearance=0, service_sci=0,
            extra_args=[*allowed_peer("lead", cluster),
                        *extra_peer_pins("joiner", "forged", cluster)],
            topology_names=TOPOLOGY_NAMES, slot_ranges=SLOT_RANGES,
            topology_qkp_ids=NODE_IDS)

        source_to_successor = cluster.replication_peer_client(
            identity_name="lead", node_id=NODE_IDS["lead"], target_name="successor")
        successor_to_source = cluster.replication_peer_client(
            identity_name="successor", node_id=NODE_IDS["successor"], target_name="lead")
        target_to_successor = cluster.replication_peer_client(
            identity_name="joiner", node_id=NODE_IDS["joiner"], target_name="forged")
        successor_to_target = cluster.replication_peer_client(
            identity_name="forged", node_id=NODE_IDS["forged"], target_name="joiner")

        if outside_slot < 8192:
            raise AssertionError("outside key unexpectedly hashes into source-owned slots")
        wait_for_data_admission(source_admin, "source", stale_tag)
        wait_for_data_admission(target_admin, "target", outside_tag)
        wait_for_ct1_drain(source_to_successor, successor_to_source, "source")
        wait_for_ct1_drain(target_to_successor, successor_to_target, "target")
        if command(target_admin, "GET", outside_key) != b"outside-range-survives":
            raise AssertionError("outside-range fixture did not survive clean target restart before CT2")
        command(source_admin, "CLUSTER", "INFO")

        local_key = None
        for attempt in range(32):
            high_text = f"CT2 high-clearance negative fixture {attempt} {secrets.token_hex(12)}"
            high_id = command(source_admin, "AIMEM", "STORE", "2", high_text)
            if not isinstance(high_id, bytes) or len(high_id) != 36:
                raise AssertionError(f"could not create classified source fixture: {high_id!r}")
            high_hex = high_id.decode("ascii").replace("-", "")
            candidate_key = f"aimem:{high_hex[:16]}"
            candidate_slot = command(source_admin, "CLUSTER", "KEYSLOT", candidate_key)
            if isinstance(candidate_slot, int) and 0 <= candidate_slot < 8192:
                if command(source_admin, "GET", candidate_key) is None:
                    raise AssertionError("AIMEM ID-derived fixture key does not exist in source KV")
                local_key = candidate_key
                break
        if local_key is None:
            raise AssertionError("AIMEM high-clearance fixture did not hash to source-owned slots")
        local_memory = command(source_admin, "AIMEM", "GET", high_id)
        if not isinstance(local_memory, list) or local_memory[-1] != high_text.encode():
            raise AssertionError("classified node-local AIMEM fixture cannot be read")
        if command(source_admin, "GET", high_key) != high_payload.encode():
            raise AssertionError("classified application fixture did not survive source baseline")

        payload_keys = same_slot_payload_keys(stale_tag, 32)
        # Keep each mutation within the bounded QKP frame; aggregate rows to
        # make CT2 exercise chunk resume without oversized CT1 fixture writes.
        payload = "p" * (8 * 1024)
        for key in payload_keys:
            reply = command(source_admin, "SET", key, payload)
            if not isinstance(reply, tuple) or reply[0] != "status":
                resolved = command(source_admin, "GET", key)
                source_status = ct1_source_status(successor_to_source)
                receiver_status = ct1_receiver_status(source_to_successor)
                cluster.fail_with_log("lead", f"seed source payload returned {reply!r}; "
                    f"read-after-uncertain={resolved!r}; source-status={source_status!r}; "
                    f"receiver-status={receiver_status!r}; B log tail:\n"
                    f"{daemon_log_tail(cluster, 'successor')}")
        expect_ok(command(source_admin, "SET", f"{{{second_tag}}}:payload", "second-source"),
                  "seed second source slot")
        wait_for_ct1_drain(source_to_successor, successor_to_source, "source-before-CT2")
        source_lsn_cut = ct1_source_status(successor_to_source)["durable_lsn"]
        cluster_info = command(source_admin, "CLUSTER", "INFO")
        if not isinstance(cluster_info, bytes):
            raise AssertionError(f"could not read topology epoch before transfer: {cluster_info!r}")
        epoch_match = re.search(rb"(?:^|\r\n)cluster_current_epoch:(\d+)", cluster_info)
        if not epoch_match:
            raise AssertionError(f"CLUSTER INFO omitted current topology epoch: {cluster_info!r}")
        transfer_config_epoch = int(epoch_match.group(1)) + 1

        transfer_id = f"ct2-{secrets.token_hex(12)}"
        # This first QKP transfer reaches a target whose replication data user
        # deliberately has clearance/SCI 0. It must refuse the high-label
        # source range before exposing any snapshot bytes. Retry the same
        # durable source transaction after restarting C with full clearance.
        joiner_topology_id = target_topology_id(cluster, "joiner")
        lead_topology_id = target_topology_id(cluster, "lead")
        denied = transfer(source_admin, transfer_id, joiner_topology_id, 0, 8191)
        if not isinstance(denied, tuple) or denied[0] != "error" or \
                b"TRYAGAIN" not in denied[1] or b"remains fenced" not in denied[1]:
            raise AssertionError(f"low-clearance QKP target did not leave CT2 fenced: {denied!r}\n"
                f"A log tail:\n{daemon_log_tail(cluster, 'lead')}\n"
                f"C log tail:\n{daemon_log_tail(cluster, 'joiner')}")
        source_peer_to_target = cluster.replication_peer_client(
            identity_name="lead", node_id=NODE_IDS["lead"], target_name="joiner")
        denied_status = command(source_peer_to_target, "REPL.CT2", "STATUS", transfer_id)
        if denied_status != ("error", b"ERR CT2 status unavailable or source identity mismatch"):
            raise AssertionError(f"low-clearance QKP STATUS was not denied without payload: {denied_status!r}")
        source_peer_to_target.close()
        successor_to_target.close()
        close_node(cluster, "joiner")
        target_admin.close()
        target, target_admin = cluster.start_ct1_node("joiner", 2, "primary", "forged",
            NODE_IDS["joiner"], NODE_IDS["forged"], cluster._ct2_target_generation,
            extra_args=[*allowed_peer("lead", cluster),
                        *extra_peer_pins("joiner", "forged", cluster)],
            topology_names=TOPOLOGY_NAMES, slot_ranges=SLOT_RANGES,
            topology_qkp_ids=NODE_IDS)
        successor_to_target = cluster.replication_peer_client(
            identity_name="forged", node_id=NODE_IDS["forged"], target_name="joiner")
        wait_for_data_admission(target_admin, "target-after-low-clearance-restart", outside_tag)
        wait_for_ct1_drain(target_to_successor, successor_to_target, "target-after-low-clearance-restart")

        command_result: list[object] = []
        command_error: list[BaseException] = []

        def do_first_transfer() -> None:
            try:
                independent_admin = cluster.admin_client("lead")
                command_result.append(transfer(independent_admin, transfer_id,
                    joiner_topology_id, 0, 8191))
                independent_admin.close()
            except BaseException as exc:
                command_error.append(exc)

        worker = threading.Thread(target=do_first_transfer, daemon=True)
        worker.start()
        source_peer_to_target = cluster.replication_peer_client(
            identity_name="lead", node_id=NODE_IDS["lead"], target_name="joiner")
        deadline = time.monotonic() + 30
        partial_status = None
        while time.monotonic() < deadline:
            # Use the authenticated CT2 status surface as the recovery cursor;
            # the drill never inspects the target's raw files or KV directory.
            status = command(source_peer_to_target, "REPL.CT2", "STATUS", transfer_id)
            offset = resp_uint(status[0]) if isinstance(status, list) and len(status) == 3 else None
            total = resp_uint(status[1]) if isinstance(status, list) and len(status) == 3 else None
            if offset is not None and total is not None and 0 < offset < total and \
                    status[2] == b"RECEIVING":
                partial_status = status
                break
            if not worker.is_alive():
                break
            time.sleep(0.01)

        if not partial_status:
            worker.join(timeout=5)
            raise AssertionError("target did not durably stage an interrupted CT2 range; "
                f"last_status={status!r}; worker_result={command_result!r}; "
                f"worker_error={command_error!r}; A log tail:\n"
                f"{daemon_log_tail(cluster, 'lead')}\nC log tail:\n"
                f"{daemon_log_tail(cluster, 'joiner')}")

        # Both old source and target must reject writes while target is staged
        # and source publication has not completed.
        source_fence = command(source_admin, "SET", f"{{{stale_tag}}}:concurrent-write", "blocked")
        target_fence = command(target_admin, "SET", f"{{{stale_tag}}}:target-concurrent-write", "blocked")
        if source_fence == ("status", b"OK") or target_fence == ("status", b"OK"):
            raise AssertionError(f"CT2 fence admitted concurrent writes: {source_fence!r} {target_fence!r}")

        # Interrupt C after bytes are durable. The source command must remain
        # pending/fenced; restart C on the same durable directory and retry the
        # same ID so STATUS resumes from its target cursor.
        close_node(cluster, "joiner")
        target_admin.close()
        source_peer_to_target.close()
        successor_to_target.close()
        worker.join(timeout=20)
        if worker.is_alive():
            raise AssertionError("source CT2 call did not return after target interruption")
        if command_error:
            raise AssertionError(f"source CT2 call failed unexpectedly: {command_error[0]}")
        if command_result and isinstance(command_result[0], tuple) and \
                command_result[0][0] == "status" and \
                b"PENDING" not in command_result[0][1].upper():
            raise AssertionError("CT2 completed before the target interruption")

        target, target_admin = cluster.start_ct1_node("joiner", 2, "primary", "forged",
            NODE_IDS["joiner"], NODE_IDS["forged"], cluster._ct2_target_generation,
            extra_args=[*allowed_peer("lead", cluster),
                        *extra_peer_pins("joiner", "forged", cluster)],
            topology_names=TOPOLOGY_NAMES, slot_ranges=SLOT_RANGES,
            topology_qkp_ids=NODE_IDS)
        successor_to_target = cluster.replication_peer_client(
            identity_name="forged", node_id=NODE_IDS["forged"], target_name="joiner")
        # The unresolved target PREPARED journal intentionally keeps ordinary
        # data reads control-only. The pinned CT1 status/drain check below is
        # the allowed readiness probe until same-ID resume and ACTIVATE.
        wait_for_ct1_drain(target_to_successor, successor_to_target, "target-after-interruption-restart")
        source_peer_to_target = cluster.replication_peer_client(
            identity_name="lead", node_id=NODE_IDS["lead"], target_name="joiner")
        resumed = transfer_until_committed(source_admin, transfer_id, joiner_topology_id, 0, 8191)
        expect_ok(resumed, "resume same CT2 transfer after target restart")
        wait_for_ct1_drain(target_to_successor, successor_to_target, "target-after-CT2-import")
        finalized_status = command(source_peer_to_target,
                                   "REPL.CT2", "STATUS", transfer_id)
        if not isinstance(finalized_status, list) or b"FINALIZED" not in finalized_status:
            raise AssertionError(f"finalized CT2 stage cleanup state was not visible: {finalized_status!r}")

        # The final owner can read source rows; target-only rows in the imported
        # slot are gone, and target's unrelated out-of-range row is unchanged.
        for key in payload_keys:
            target_value = command(target_admin, "GET", key)
            if target_value != payload.encode():
                source_value = command(source_admin, "GET", key)
                raise AssertionError(f"target missed source key {key}: target={target_value!r}; "
                    f"source={source_value!r}; A log tail:\n"
                    f"{daemon_log_tail(cluster, 'lead')}\nC log tail:\n"
                    f"{daemon_log_tail(cluster, 'joiner')}\nD status="
                    f"{ct1_receiver_status(target_to_successor)!r}")
        if command(target_admin, "GET", stale_key) is not None:
            raise AssertionError("target-only in-range key survived authoritative replacement")
        outside_value = command(target_admin, "GET", outside_key)
        if outside_value != b"outside-range-survives":
            raise AssertionError(f"target's unrelated outside-range key was lost: "
                f"slot={outside_slot}, value={outside_value!r}, expected=outside-range-survives; "
                f"C log tail:\n{daemon_log_tail(cluster, 'joiner')}\n"
                f"D status={ct1_receiver_status(target_to_successor)!r}")
        if command(target_admin, "GET", high_key) != high_payload.encode():
            raise AssertionError("classified application fixture row is absent or changed after CT2 import")
        if command(source_admin, "AIMEM", "GET", high_id) != local_memory:
            raise AssertionError("source node-local AIMEM changed after application slot transfer")
        if command(target_admin, "AIMEM", "GET", high_id) is not None:
            raise AssertionError("source node-local AIMEM was incorrectly copied to target")
        expect_ok(command(target_admin, "SET", f"{{{stale_tag}}}:after-activate", "ready"),
                  "activated target write")
        assert_activated_receipt(source_peer_to_target,
            transfer_id=transfer_id, topology_source_id=lead_topology_id,
            topology_target_id=joiner_topology_id,
            source_qkp_id=NODE_IDS["lead"], target_qkp_id=NODE_IDS["joiner"],
            generation=cluster._ct2_source_generation, first=0, last=8191,
            source_lsn=source_lsn_cut, config_epoch=transfer_config_epoch)
        if transfer(source_admin, transfer_id, joiner_topology_id, 0, 8191) != \
                ("status", b"COMMITTED"):
            raise AssertionError("same-ID finalized CT2 retry after target write was not idempotent")

        peer_admins = {name: cluster.admin_client(name)
                       for name in ("successor", "forged")}
        wait_for_peer_slot_owner(peer_admins, 0, 8191, joiner_topology_id,
                                 "B/D after A-to-C activation and target write")

        # Reboot both primaries, retain the same durable journals/CT1 successors,
        # then execute a second independent range transfer.
        source_admin.close()
        target_admin.close()
        source_peer_to_target.close()
        source, source_admin = restart_primary(cluster, "lead", "successor",
                                               extra_peer_pins("lead", "successor", cluster))
        target, target_admin = restart_primary(cluster, "joiner", "forged",
                                               extra_peer_pins("joiner", "forged", cluster))
        source_to_successor = cluster.replication_peer_client(
            identity_name="lead", node_id=NODE_IDS["lead"], target_name="successor")
        successor_to_source = cluster.replication_peer_client(
            identity_name="successor", node_id=NODE_IDS["successor"], target_name="lead")
        target_to_successor = cluster.replication_peer_client(
            identity_name="joiner", node_id=NODE_IDS["joiner"], target_name="forged")
        successor_to_target = cluster.replication_peer_client(
            identity_name="forged", node_id=NODE_IDS["forged"], target_name="joiner")
        wait_for_data_admission(target_admin, "target-before-reverse-transfer", outside_tag)
        wait_for_ct1_drain(target_to_successor, successor_to_target, "target-before-reverse-transfer")
        # Use a different contract-valid transfer ID length to cover protocol
        # paths that accidentally hard-code a 32-byte identifier buffer.
        second_id = f"ct2-reverse-{secrets.token_hex(24)}"
        expect_ok(transfer_until_committed(target_admin, second_id,
                           target_topology_id(cluster, "lead"), outside_slot, outside_slot),
                  "reverse CT2 transfer after source/target restart")
        wait_for_ct1_drain(source_to_successor, successor_to_source, "reverse-target-after-CT2-import")
        wait_for_peer_slot_owner(peer_admins, outside_slot, outside_slot, lead_topology_id,
                                 "B/D after C-to-A reverse transfer")
        historical_source_peer = cluster.replication_peer_client(
            identity_name="lead", node_id=NODE_IDS["lead"], target_name="joiner")
        assert_activated_receipt(historical_source_peer,
            transfer_id=transfer_id, topology_source_id=lead_topology_id,
            topology_target_id=joiner_topology_id,
            source_qkp_id=NODE_IDS["lead"], target_qkp_id=NODE_IDS["joiner"],
            generation=cluster._ct2_source_generation, first=0, last=8191,
            source_lsn=source_lsn_cut, config_epoch=transfer_config_epoch)
        if transfer(source_admin, transfer_id, joiner_topology_id, 0, 8191) != \
                ("status", b"COMMITTED"):
            raise AssertionError("historical same-ID CT2 retry changed after the reverse transfer")
        if command(source_admin, "GET", outside_key) != b"outside-range-survives":
            raise AssertionError("reverse transfer data is absent on the new target")

        for admin in peer_admins.values():
            admin.close()
        historical_source_peer.close()

        print("CT2 arbitrary-target drill passed: A→C with B/D CT1 successors, "
              "fence, interrupted resume, range replacement, activation, restart, and second transfer")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
