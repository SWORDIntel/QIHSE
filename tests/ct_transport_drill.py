#!/usr/bin/env python3
"""Reusable isolated real-daemon fixtures for CT1/CT2 transport drills.

This module intentionally contains no passing surrogate for replication or
slot migration. The drill entry points will be added when the source-side
durability-proof and all-writer-fence protocol APIs land. It does provide
isolated daemon, identity, RESP, restart, and polling helpers for those tests.
"""
from __future__ import annotations

import ctypes
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
from typing import Iterable
import re
import secrets

ROOT = Path(os.environ.get("QIHSE_CT_TEST_ROOT",
                          Path(__file__).resolve().parents[1])).resolve()
sys.path.insert(0, str(ROOT / "sdks/python"))
OPERATOR_PASSWORD = "CtTransportFixtureOperator93!"
SERVICE_PASSWORD = "CtTransportFixtureService28!"
DEFAULT_REPLICATION_LOG_LIMIT = 128 * 1024 * 1024
DEFAULT_REPLICATION_ACK_TIMEOUT_MS = 5000


def new_generation() -> str:
    """Return one test generation in the proposed 128-bit wire form."""
    return secrets.token_hex(16)


def topology_id_for(host: str, port: int) -> str:
    """Match the daemon's deterministic topology ID for a host/port endpoint."""
    library = ctypes.CDLL(str(ROOT / "libqihse.so"))
    derive = library.qihse_cluster_node_id_from_seed
    derive.argtypes = (ctypes.c_void_p, ctypes.c_size_t, ctypes.c_char_p)
    derive.restype = None
    seed = f"qihse-node-{host}:{port}".encode()
    out = ctypes.create_string_buffer(128)
    derive(seed, len(seed), out)
    return out.value.decode()


def validate_replication_entries(entries: list[dict], expected_start: int,
                                 expected_end: int) -> None:
    """Reject gaps, conflicting duplicate sequences, and out-of-range rows."""
    by_seq: dict[int, dict] = {}
    for entry in entries:
        seq = int(entry["seq"])
        if seq < expected_start or seq > expected_end:
            raise AssertionError(f"replication seq {seq} outside requested interval")
        previous = by_seq.setdefault(seq, entry)
        if previous != entry:
            raise AssertionError(f"conflicting duplicate replication seq {seq}")
    actual = sorted(by_seq)
    expected = list(range(expected_start, expected_end + 1))
    if actual != expected:
        raise AssertionError(f"replication sequence gap or reorder: {actual} != {expected}")


def assert_replication_entry(entry: dict, *, seq: int, op: str, key: str,
                             value: str | None, classification: int, sci: int,
                             tenant: int, expiry: int, actor: int) -> None:
    """Check full record semantics, not merely that a value appeared remotely."""
    expected = {
        "seq": seq, "op": op, "key": key, "value": value,
        "class": classification, "sci": sci, "tenant": tenant,
        "expiry": expiry, "actor": actor,
    }
    for field, value in expected.items():
        if entry.get(field) != value:
            raise AssertionError(f"replication {field} mismatch: {entry.get(field)!r} != {value!r}")


def publish_labelled_record(admin_session, *, event_type: str, resource_id: str,
                            classification: int, sci: int, tenant: int,
                            generation: int, payload: str) -> bytes:
    """Use the normal authorized feed writer to make labelled source data."""
    return admin_session.execute_resp(
        "KEYSTONE.FEED.PUBLISH", event_type, resource_id,
        str(classification), str(sci), str(tenant), str(generation), payload,
    )


def parse_resp_frame(frame: bytes):
    """Decode one complete RESP2 reply returned by qihse_admin.execute_resp."""
    def parse(pos: int):
        marker = frame[pos:pos + 1]
        end = frame.find(b"\r\n", pos + 1)
        if end < 0:
            raise ValueError("truncated RESP line")
        head = frame[pos + 1:end]
        next_pos = end + 2
        if marker == b"+":
            return ("status", head), next_pos
        if marker == b"-":
            return ("error", head), next_pos
        if marker == b":":
            return int(head), next_pos
        if marker == b"$":
            length = int(head)
            if length == -1:
                return None, next_pos
            if not 0 <= length <= 32 * 1024 * 1024:
                raise ValueError("RESP bulk outside fixture limits")
            stop = next_pos + length
            if frame[stop:stop + 2] != b"\r\n":
                raise ValueError("truncated RESP bulk")
            return frame[next_pos:stop], stop + 2
        if marker == b"*":
            count = int(head)
            if count == -1:
                return None, next_pos
            if not 0 <= count <= 100000:
                raise ValueError("RESP array outside fixture limits")
            values = []
            for _ in range(count):
                value, next_pos = parse(next_pos)
                values.append(value)
            return values, next_pos
        raise ValueError(f"unknown RESP marker {marker!r}")

    value, end = parse(0)
    if end != len(frame):
        raise ValueError("trailing bytes after RESP frame")
    return value


def parse_ct1_source_status(frame: bytes) -> dict:
    reply = parse_resp_frame(frame)
    if not isinstance(reply, list) or len(reply) != 10:
        raise AssertionError(f"unexpected CT1 source STATUS shape: {reply!r}")
    source_id, generation, successor_id = (field.decode() for field in reply[:3])
    return {
        "source_id": source_id,
        "generation": generation,
        "successor_id": successor_id,
        "durable_lsn": int(reply[3]),
        "oldest_lsn": int(reply[4]),
        "acknowledged_lsn": int(reply[5]),
        "retained_bytes": int(reply[6]),
        "limit_bytes": int(reply[7]),
        "baseline_row_seq": int(reply[8]),
        "baseline_digest": reply[9].decode(),
    }


def parse_ct1_receiver_status(frame: bytes) -> dict:
    reply = parse_resp_frame(frame)
    if not isinstance(reply, list) or len(reply) != 7:
        raise AssertionError(f"unexpected CT1 receiver STATUS shape: {reply!r}")
    source_id, target_id, generation = (field.decode() for field in reply[:3])
    digest = reply[5].decode()
    return {
        "source_id": source_id,
        "target_id": target_id,
        "generation": generation,
        "durable_cursor": int(reply[3]),
        "baseline_sealed": int(reply[4]) == 1,
        "baseline_digest": digest,
        "tenant_policy": int(reply[6]),
    }


def ct1_source_status(service_peer) -> dict:
    return parse_ct1_source_status(service_peer.execute_resp("REPL.CT1", "STATUS"))


def ct1_receiver_status(service_peer) -> dict:
    return parse_ct1_receiver_status(
        service_peer.execute_resp("REPL.CT1", "TARGET", "STATUS"))


def ct1_read(service_peer, generation: str, after_seq: int = 0,
             max_groups: int = 64, max_bytes: int = 1 << 20):
    reply = parse_resp_frame(service_peer.execute_resp(
        "REPL.CT1", "READ", generation, str(after_seq),
        str(max_groups), str(max_bytes), "v1",
    ))
    if not isinstance(reply, list) or len(reply) < 5:
        raise AssertionError(f"unexpected CT1 READ envelope: {reply!r}")
    group_count = int(reply[4])
    cursor = 5
    groups = []
    for _ in range(group_count):
        if len(reply) - cursor < 4:
            raise AssertionError("truncated CT1 group header")
        position, first_seq, last_seq, record_count = map(int, reply[cursor:cursor + 4])
        cursor += 4
        records = []
        for _ in range(record_count):
            if len(reply) - cursor < 11:
                raise AssertionError("truncated CT1 record")
            record = reply[cursor:cursor + 11]
            cursor += 11
            records.append({
                "key": record[0], "value": None if record[10] == b"1" else record[1],
                "change_seq": int(record[2]),
                "expiry": int(record[3]), "actor_id": int(record[4]),
                "actor_tenant": int(record[5]), "resource_tenant": int(record[6]),
                "class": int(record[7]), "sci": int(record[8]),
                "actor_kind": int(record[9]), "tombstone": record[10] == b"1",
            })
        if not records:
            raise AssertionError("CT1 returned an empty row group")
        if min(row["change_seq"] for row in records) != first_seq or \
                max(row["change_seq"] for row in records) != last_seq:
            raise AssertionError("CT1 group sequence bounds do not cover its rows")
        groups.append({"position": position, "first_seq": first_seq,
                       "last_seq": last_seq, "records": records})
    if cursor != len(reply):
        raise AssertionError("trailing CT1 READ fields")
    return {"source_id": reply[0].decode(), "generation": reply[1].decode(),
            "successor_id": reply[2].decode(), "resume_position": int(reply[3]),
            "groups": groups}


def replication_node_args(*, role: str, peer_node_id: str,
                          generation: str, host: str, port: int,
                          identity_public_key: Path,
                          log_limit: int = DEFAULT_REPLICATION_LOG_LIMIT,
                          ack_timeout_ms: int = DEFAULT_REPLICATION_ACK_TIMEOUT_MS,
                          service_clearance: int = 65535,
                          service_sci: int = 65535) -> list[str]:
    """Build the planned pinned CT1 peer configuration, validating inputs.

    The daemon parser/proof APIs are under development. This builder is kept
    separate from daemon startup so tests cannot silently degrade to local
    pre-seeding if the options are absent.
    """
    if role not in {"primary", "successor"}:
        raise ValueError("CT1 role must be primary or successor")
    if not re.fullmatch(r"[0-9a-f]{32}", generation):
        raise ValueError("CT1 generation must be 32 lowercase hexadecimal digits")
    if not 1 <= port <= 65535:
        raise ValueError("CT1 peer port outside TCP range")
    if not 1 <= log_limit <= 1 << 30:
        raise ValueError("CT1 retained log limit outside 1..1GiB")
    if not 1 <= ack_timeout_ms <= 300000:
        raise ValueError("CT1 ACK timeout outside daemon range")
    if not 0 <= service_clearance <= 65535 or not 0 <= service_sci <= 65535:
        raise ValueError("replication service clearance/SCI outside uint16 range")
    if not identity_public_key.is_file():
        raise ValueError("CT1 peer public key is missing")
    return [
        "--ct-role", role,
        "--ct-peer", f"{host}:{port}",
        "--ct-generation", generation,
        "--ct-log-limit", str(log_limit),
        "--ct-ack-timeout-ms", str(ack_timeout_ms),
        "--replication-allowed-peer", peer_node_id, str(identity_public_key),
        "--replication-peer-node-id", peer_node_id,
        "--replication-peer-dsa-pub", str(identity_public_key),
        "--replication-principal-clearance", str(service_clearance),
        "--replication-principal-sci", str(service_sci),
    ]


def _free_tcp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _free_udp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _resp_encode(*args: str | bytes) -> bytes:
    fields = [arg.encode() if isinstance(arg, str) else arg for arg in args]
    return b"*%d\r\n" % len(fields) + b"".join(
        b"$%d\r\n" % len(value) + value + b"\r\n" for value in fields
    )


class RespClient:
    """Small RESP2 client that preserves nested arrays, bytes, and errors."""

    def __init__(self, address: tuple[str, int], timeout: float = 5.0):
        self.sock = socket.create_connection(address, timeout=timeout)
        self.sock.settimeout(timeout)
        self._buffer = bytearray()

    def close(self) -> None:
        self.sock.close()

    def _line(self) -> bytes:
        while True:
            marker = self._buffer.find(b"\r\n")
            if marker >= 0:
                line = bytes(self._buffer[:marker])
                del self._buffer[:marker + 2]
                return line
            chunk = self.sock.recv(65536)
            if not chunk:
                raise ConnectionError("RESP peer closed the connection")
            self._buffer.extend(chunk)

    def _read(self):
        line = self._line()
        if not line:
            raise ValueError("empty RESP frame")
        kind, payload = line[:1], line[1:]
        if kind == b"+":
            return ("status", payload)
        if kind == b"-":
            return ("error", payload)
        if kind == b":":
            return int(payload)
        if kind == b"$":
            length = int(payload)
            if length == -1:
                return None
            if length < 0 or length > 32 * 1024 * 1024:
                raise ValueError("RESP bulk length outside test limit")
            while len(self._buffer) < length + 2:
                chunk = self.sock.recv(65536)
                if not chunk:
                    raise ConnectionError("RESP peer closed during bulk frame")
                self._buffer.extend(chunk)
            if self._buffer[length:length + 2] != b"\r\n":
                raise ValueError("malformed RESP bulk terminator")
            value = bytes(self._buffer[:length])
            del self._buffer[:length + 2]
            return value
        if kind == b"*":
            count = int(payload)
            if count == -1:
                return None
            if count < 0 or count > 100000:
                raise ValueError("RESP array count outside test limit")
            return [self._read() for _ in range(count)]
        raise ValueError(f"unsupported RESP type {kind!r}")

    def command(self, *args: str | bytes):
        self.sock.sendall(_resp_encode(*args))
        return self._read()


class IsolatedCluster:
    """Own only temporary daemons, identities, and data under build/."""

    def __init__(self, prefix: str = "ct-transport-"):
        build = ROOT / "build"
        build.mkdir(mode=0o700, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(prefix=prefix, dir=build)
        self.root = Path(self.temp.name)
        self.env = {
            key: value for key, value in os.environ.items()
            if not key.startswith("QIHSE_") and key != "LD_PRELOAD"
        }
        self.env.update(
            QIHSE_FIPS_MODE="disabled",
            QIHSE_OPERATOR_PASSWORD=OPERATOR_PASSWORD,
            LD_LIBRARY_PATH=str(ROOT),
        )
        self.processes: dict[str, subprocess.Popen] = {}
        self.logs: dict[str, object] = {}
        self.endpoints: dict[str, tuple[str, int]] = {}
        self.bus_ports: dict[str, int] = {}
        self.admins = []
        self.sessions = []
        for name in ("lead", "successor", "joiner", "forged", "low"):
            (self.root / name / "identity").mkdir(parents=True, mode=0o700)
            (self.root / name / "data").mkdir(mode=0o700)
        self.generate_identities("lead", "successor", "joiner", "forged")

    def generate_identities(self, *names: str) -> None:
        """Use the in-tree crypto API in a fresh process, never live key paths."""
        code = (
            "import ctypes,sys; "
            "l=ctypes.CDLL(sys.argv[1]); "
            "assert l.qihse_pqc_init_providers() >= 0; "
            "l.qihse_pqc_keygen.argtypes=[ctypes.c_char_p]; "
            "l.qihse_pqc_keygen.restype=ctypes.c_bool; "
            "assert all(l.qihse_pqc_keygen((sys.argv[2]+'/'+n+'/identity').encode()) "
            "for n in sys.argv[3:])"
        )
        subprocess.run(
            [sys.executable, "-c", code, str(ROOT / "libqihse.so"),
             str(self.root), *names],
            env=self.env, check=True, capture_output=True, timeout=45,
        )

    def identity_file(self, name: str, suffix: str) -> Path:
        if name not in {"lead", "successor", "joiner", "forged", "low"}:
            raise ValueError("identity must belong to this fixture")
        if suffix not in {"qihse_dsa_key.pem", "qihse_dsa_pub.pem",
                          "qihse_kem_key.pem", "qihse_kem_pub.pem"}:
            raise ValueError("unsupported QKP key file")
        return self.root / name / "identity" / suffix

    def reserve_endpoint(self, name: str) -> tuple[str, int]:
        """Reserve a loopback port number for an upcoming fixture daemon."""
        if name not in {"lead", "successor", "joiner", "forged"}:
            raise ValueError("unknown daemon fixture node")
        if name in self.endpoints:
            return self.endpoints[name]
        endpoint = ("127.0.0.1", _free_tcp_port())
        self.endpoints[name] = endpoint
        self.bus_ports[name] = _free_udp_port()
        return endpoint

    def start_node(self, name: str, index: int, node_id: str,
                   extra_args: Iterable[str] = (), *,
                   topology_names: Iterable[str] = (),
                   slot_ranges: dict[str, tuple[int, int]] | None = None,
                   topology_qkp_ids: dict[str, str] | None = None):
        """Start one daemon and return its process plus an admin RESP client.

        Callers provide topology/replication/migration configuration only
        after the corresponding proof protocol is implemented.
        """
        if name not in {"lead", "successor", "joiner", "forged"}:
            raise ValueError("unknown daemon fixture node")
        endpoint = self.endpoints.get(name) or self.reserve_endpoint(name)
        port, bus_port = endpoint[1], self.bus_ports[name]
        prior_log = self.logs.get(name)
        if prior_log is not None:
            prior_log.close()
        logfile = (self.root / f"{name}.log").open("w+b")
        self.logs[name] = logfile
        identity = self.root / name / "identity"
        command = [
            str(ROOT / "qihse-cluster-daemon"), "--index", str(index),
            "--bind", "127.0.0.1", "--port", str(port),
            "--bus-port", str(bus_port), "--dir", str(self.root / name / "data"),
            "--pqc-identity-dir", str(identity), "--pqc-node-id", node_id,
            "--pqc-trusted-pub", str(self.identity_file("lead", "qihse_dsa_pub.pem")),
            "--pqc-trusted-pub", str(self.identity_file("successor", "qihse_dsa_pub.pem")),
            "--pqc-trusted-pub", str(self.identity_file("joiner", "qihse_dsa_pub.pem")),
            "--pqc-trusted-pub", str(self.identity_file("forged", "qihse_dsa_pub.pem")),
            "--pqc-require", "--admin-peer-node-id", "ct-test-client",
            "--admin-peer-dsa-pub", str(self.identity_file("joiner", "qihse_dsa_pub.pem")),
        ]
        topology = tuple(topology_names)
        if topology:
            if len(set(topology)) != len(topology) or name not in topology:
                raise ValueError("topology names must be unique and include this node")
            if len(topology) > 16:
                raise ValueError("test topology exceeds daemon node limit")
            owners = slot_ranges or {topology[0]: (0, 16383)}
            if any(owner not in topology for owner in owners):
                raise ValueError("slot owner is not part of the static topology")
            for owner, (first, last) in owners.items():
                if not 0 <= first <= last < 16384:
                    raise ValueError("topology slot range is invalid")
            for peer_name in topology:
                self.reserve_endpoint(peer_name)
            for peer_index, peer_name in enumerate(topology):
                peer_host, peer_port = self.endpoints[peer_name]
                peer_bus_port = self.bus_ports[peer_name]
                command.extend(["--node", f"{peer_index}:{peer_host}:{peer_port}:{peer_bus_port}"])
                if peer_name in owners:
                    first_slot, last_slot = owners[peer_name]
                    if peer_name == name:
                        command.extend(["--slot-range", f"{first_slot}-{last_slot}"])
                    else:
                        command.extend(["--slot-range-of",
                                        f"{peer_index}:{first_slot}-{last_slot}"])
            for peer_name, qkp_id in (topology_qkp_ids or {}).items():
                if peer_name not in topology or not qkp_id:
                    raise ValueError("topology QKP map must name a topology node and identity")
                host, port = self.endpoints[peer_name]
                command.extend(["--topology-qkp-map", topology_id_for(host, port), qkp_id])
        command.extend(extra_args)
        process = subprocess.Popen(command, env=self.env, stdout=logfile, stderr=logfile)
        self.processes[name] = process
        self.wait_listening(name)
        return process, self.admin_client(name)

    def start_ct1_node(self, name: str, index: int, role: str,
                       peer_name: str, node_id: str, peer_node_id: str,
                       generation: str, *, service_clearance: int = 65535,
                       service_sci: int = 65535,
                       log_limit: int = DEFAULT_REPLICATION_LOG_LIMIT,
                       ack_timeout_ms: int = DEFAULT_REPLICATION_ACK_TIMEOUT_MS,
                       extra_args: Iterable[str] = (),
                       topology_names: Iterable[str] = (),
                       slot_ranges: dict[str, tuple[int, int]] | None = None,
                       topology_qkp_ids: dict[str, str] | None = None):
        if peer_name not in self.endpoints:
            raise ValueError("reserve all peer endpoints before starting CT1 nodes")
        peer_host, peer_port = self.endpoints[peer_name]
        peer_key = self.identity_file(peer_name, "qihse_dsa_pub.pem")
        args = replication_node_args(
            role=role, peer_node_id=peer_node_id, generation=generation,
            host=peer_host, port=peer_port, identity_public_key=peer_key,
            log_limit=log_limit, ack_timeout_ms=ack_timeout_ms,
            service_clearance=service_clearance, service_sci=service_sci,
        )
        return self.start_node(name, index, node_id, (*args, *extra_args),
                               topology_names=topology_names,
                               slot_ranges=slot_ranges,
                               topology_qkp_ids=topology_qkp_ids or {
                                   name: node_id, peer_name: peer_node_id,
                               })

    def start_ct1_pair(self, generation: str, *, primary_clearance: int = 65535,
                       primary_sci: int = 65535,
                       successor_clearance: int = 65535,
                       successor_sci: int = 65535,
                       ack_timeout_ms: int = DEFAULT_REPLICATION_ACK_TIMEOUT_MS,
                       topology_names: Iterable[str] = (),
                       slot_ranges: dict[str, tuple[int, int]] | None = None,
                       topology_qkp_ids: dict[str, str] | None = None):
        """Start a real pinned primary/successor pair with a fresh generation."""
        self.reserve_endpoint("lead")
        self.reserve_endpoint("successor")
        # The primary performs a pinned STATUS preflight before it binds its
        # listener, so bring up the slotless successor endpoint first. It
        # retries source pulls until the primary becomes available.
        successor = self.start_ct1_node(
            "successor", 1, "successor", "lead", "ct-successor", "ct-primary",
            generation, service_clearance=successor_clearance, service_sci=successor_sci,
            ack_timeout_ms=ack_timeout_ms,
            topology_names=topology_names,
            slot_ranges=slot_ranges,
            topology_qkp_ids=topology_qkp_ids,
        )
        primary = self.start_ct1_node(
            "lead", 0, "primary", "successor", "ct-primary", "ct-successor",
            generation, service_clearance=primary_clearance, service_sci=primary_sci,
            ack_timeout_ms=ack_timeout_ms,
            topology_names=topology_names,
            slot_ranges=slot_ranges,
            topology_qkp_ids=topology_qkp_ids,
        )
        return primary, successor

    def admin_client(self, name: str):
        address = self.endpoints[name]
        try:
            from qihse_admin import ClusterAdmin
            admin = ClusterAdmin(
                node_id="ct-test-client",
                identity_dir=str(self.root / "joiner" / "identity"),
                lib_path=str(ROOT / "libqihse.so"),
            )
            admin_session = admin.session(
                address[0], address[1],
                str(self.identity_file(name, "qihse_dsa_pub.pem")),
                user="GODMODE_OP", password=OPERATOR_PASSWORD,
                timeout_ms=5000,
            )
        except BaseException as exc:
            self.fail_with_log(name, f"admin QKP/AUTH failed: {exc}")
        self.admins.append(admin)
        self.sessions.append(admin_session)
        return admin_session

    def replication_peer_client(self, *, identity_name: str, node_id: str,
                                target_name: str):
        """Connect as a pinned service peer, without operator AUTH."""
        from qihse_admin import ClusterAdmin
        target_host, target_port = self.endpoints[target_name]
        admin = ClusterAdmin(
            node_id=node_id,
            identity_dir=str(self.root / identity_name / "identity"),
            lib_path=str(ROOT / "libqihse.so"),
        )
        session = admin.session(
            target_host, target_port,
            str(self.identity_file(target_name, "qihse_dsa_pub.pem")),
            timeout_ms=5000,
        )
        self.admins.append(admin)
        self.sessions.append(session)
        return session

    def wait_listening(self, name: str, timeout: float = 20.0) -> None:
        address = self.endpoints[name]
        process = self.processes[name]
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if process.poll() is not None:
                self.fail_with_log(name, f"daemon exited {process.returncode}")
            try:
                with socket.create_connection(address, timeout=0.2):
                    return
            except OSError:
                time.sleep(0.05)
        self.fail_with_log(name, "daemon did not listen before timeout")

    def wait_until(self, predicate, timeout: float = 10.0, interval: float = 0.05):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            value = predicate()
            if value:
                return value
            time.sleep(interval)
        raise AssertionError("condition was not reached before deadline")

    def kill(self, name: str) -> None:
        process = self.processes[name]
        if process.poll() is None:
            process.kill()
        process.wait(timeout=10)

    def fail_with_log(self, name: str, message: str) -> None:
        log = self.logs[name]
        log.flush()
        log.seek(0)
        detail = log.read().decode(errors="replace")[-12000:]
        raise AssertionError(f"{message}; {name} daemon log tail:\n{detail}")

    def close(self) -> None:
        for session in self.sessions:
            try:
                session.close()
            except Exception:
                pass
        self.sessions.clear()
        for admin in self.admins:
            try:
                admin.close()
            except Exception:
                pass
        self.admins.clear()
        for process in self.processes.values():
            if process.poll() is None:
                process.kill()
        for process in self.processes.values():
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
        for log in self.logs.values():
            log.close()
        self.temp.cleanup()

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        self.close()
