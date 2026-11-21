#!/usr/bin/env python3
"""Real-daemon CT1 QKP write durability and denial drills.

This test intentionally fails against a daemon without CT1 support. It never
pre-seeds the successor: every observed value must arrive through the pinned
replication stream and survive a successor process restart.
"""
from __future__ import annotations

import hashlib
import os
import shlex
import stat
import subprocess
import unittest
import time

from ct_multigroup_drill import seed_classified_kv
from ct_transport_drill import (
    IsolatedCluster,
    ROOT,
    OPERATOR_PASSWORD,
    parse_resp_frame,
    ct1_read,
    ct1_receiver_status,
    ct1_source_status,
    new_generation,
    topology_id_for,
)


class Ct1RealDaemonTests(unittest.TestCase):
    def setUp(self):
        self.cluster = IsolatedCluster("ct1-real-")
        self.addCleanup(self.cluster.close)

    def test_ct1_frozen_root_startup_rejects_untrusted_configuration(self):
        frozen = self.cluster.root / "frozen"
        frozen.mkdir(mode=0o700)
        unsafe = self.cluster.root / "unsafe"
        unsafe.mkdir(mode=0o770)
        # mkdir(2) filters the requested mode through the process umask; force
        # the group-accessible bits so the fixture is unsafe under any umask.
        unsafe.chmod(0o770)
        (unsafe / "nested").mkdir(mode=0o700)
        (unsafe / "nested").chmod(0o700)
        alias = self.cluster.root / "alias"
        alias.symlink_to(frozen, target_is_directory=True)
        nested = frozen / "nested"
        nested.mkdir(mode=0o700)
        nested_alias = self.cluster.root / "nested-alias"
        nested_alias.symlink_to(frozen, target_is_directory=True)
        peer_key = str(self.cluster.identity_file("lead", "qihse_dsa_pub.pem"))
        admin_key = str(self.cluster.identity_file("joiner", "qihse_dsa_pub.pem"))
        base = ["--ct-role", "successor", "--ct-peer", "127.0.0.1:10001",
                "--ct-generation", "a" * 32, "--ct-log-limit", "4096",
                "--ct-ack-timeout-ms", "1000", "--pqc-identity-dir",
                str(self.cluster.root / "successor/identity"),
                "--pqc-node-id", "ct-successor",
                "--replication-allowed-peer", "ct-primary", peer_key,
                "--replication-peer-node-id", "ct-primary",
                "--replication-peer-dsa-pub", peer_key,
                "--admin-peer-node-id", "ct-test-client",
                "--admin-peer-dsa-pub", admin_key,
                "--replication-principal-id", "65535"]
        same_admin = base.copy()
        same_admin[same_admin.index("ct-test-client")] = "ct-primary"
        cases = [
            (str(frozen), []),  # no legacy CT role
            (str(self.cluster.root / "missing"), base),
            (str(unsafe), base),
            (str(alias), base),
            (str(nested_alias / "nested"), base),
            (str(unsafe / "nested"), base),
            (str(frozen / "../frozen"), base),
            (str(frozen) + "/", base),
            ("frozen", base),
            (str(frozen), base[:-2]),  # no explicit replication principal
            (str(frozen), base[:-6] + base[-2:]),  # no admin peer pin
            (str(frozen), same_admin),  # admin and replication pins cannot alias
            (str(frozen), base + ["--ct1-recovery-frozen-root", str(frozen)]),
        ]
        for root, options in cases:
            with self.subTest(root=root, options=options):
                result = subprocess.run(
                    [str(ROOT / "qihse-cluster-daemon"), *options,
                     "--ct1-recovery-frozen-root", root],
                    env=self.cluster.env, capture_output=True, timeout=10)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertNotIn(str(frozen).encode(), result.stderr)

    def test_ct1_frozen_root_denies_quote_without_live_attestation(self):
        root, generation = self.frozen_roster_fixture()
        options = ("--replication-principal-id", "65535")
        successor, _ = self.cluster.start_ct1_node(
            "successor", 1, "successor", "lead", "ct-successor", "ct-primary",
            generation, extra_args=(*options, "--ct1-recovery-frozen-root",
                                    str(root / "target")),
            ack_timeout_ms=500, topology_names=self.topology_names)
        self.assertIsNone(successor.poll())
        primary, _ = self.cluster.start_ct1_node(
            "lead", 0, "primary", "successor", "ct-primary", "ct-successor",
            generation, service_clearance=0, service_sci=0,
            extra_args=(*options, "--ct1-recovery-frozen-root", str(root / "source")),
            ack_timeout_ms=500, topology_names=self.topology_names)
        self.assertIsNone(primary.poll())
        operator = self.cluster.replication_peer_client(
            identity_name="joiner", node_id="ct-test-client", target_name="lead")
        self.assertEqual(operator.execute_resp("PING"), b"+PONG\r\n")
        # The primary maps this pinned replication peer to a zero-clearance service.
        peer = self.cluster.replication_peer_client(
            identity_name="successor", node_id="ct-successor", target_name="lead")
        self.assertTrue(peer.execute_resp("PING").startswith(b"-NOPERM"))
        unpinned = self.cluster.replication_peer_client(
            identity_name="forged", node_id="ct-forged", target_name="lead")
        self.assertEqual(unpinned.execute_resp("AUTH", "GODMODE_OP",
                          self.cluster.env["QIHSE_OPERATOR_PASSWORD"]), b"+OK\r\n")
        # A password-authenticated Operator on QKP is not QKP_ADMIN.
        self.assertEqual(unpinned.execute_resp("PING"), b"+PONG\r\n")
        target_operator = self.cluster.replication_peer_client(
            identity_name="joiner", node_id="ct-test-client", target_name="successor")
        self.assertEqual(target_operator.execute_resp("PING"), b"+PONG\r\n")
        target_peer = self.cluster.replication_peer_client(
            identity_name="lead", node_id="ct-primary", target_name="successor")
        for session in (operator, peer, unpinned, target_operator, target_peer):
            for path in (("REPL.CT1", "QUOTE-V1"),
                         ("REPL.CT1", "SOURCE", "QUOTE-V1"),
                         ("REPL.CT1", "TARGET", "QUOTE-V1")):
                for wire in (b"not-a-manifest", b"\0" * 2624):
                    with self.subTest(path=path, wire_len=len(wire),
                                      session=session is operator):
                        reply = session.execute_resp(*path, bytes(range(32)), wire)
                        self.assertTrue(reply.startswith(b"-"), reply)
                        self.assertNotIn(str(root).encode(), reply)
                        self.assertNotIn(b"CT1Q", reply)

    def frozen_roster_fixture(self):
        binary = self.cluster.root / "ct1-frozen-roster"
        compiler = shlex.split(self.cluster.env.get("CC", "cc"))
        compiled = subprocess.run(compiler + [
            "-std=c99", "-D_GNU_SOURCE", "-UNDEBUG", "-Wall", "-Wextra", "-Werror",
            "-I", str(ROOT / "include"), "-o", str(binary),
            str(ROOT / "tests/test_ct1_frozen_roster.c"),
            str(ROOT / "src/black_hole/qihse_ct1_recovery_manifest.c"),
            "-L", str(ROOT), "-lqihse", "-lcrypto", "-pthread",
        ], env=self.cluster.env, capture_output=True, timeout=60)
        self.assertEqual(compiled.returncode, 0, compiled.stderr.decode(errors="replace"))
        for name in ("lead", "successor"):
            self.cluster.reserve_endpoint(name)
        owner = topology_id_for(*self.cluster.endpoints["lead"])
        for name in ("lead", "successor"):
            # Real journal API records the already-configured static owner at
            # epoch zero; no promotion, handoff or authorization is invented.
            self.assertEqual(subprocess.run([str(binary), "journal",
                str(self.cluster.root / name / "data"), owner], env=self.cluster.env,
                capture_output=True, timeout=15).returncode, 0)
        seeded = subprocess.run([str(binary), "seed"], env=dict(self.cluster.env,
            QIHSE_DATA_DIR=str(self.cluster.root / "lead/data"),
            QIHSE_OPERATOR_PASSWORD=OPERATOR_PASSWORD), capture_output=True, timeout=30)
        self.assertEqual(seeded.returncode, 0, seeded.stderr)
        generation = self.start_pair(new_generation(), ack_timeout_ms=5000)
        self.wait_for_pair(generation)
        self.assertEqual(self.primary_admin.execute_resp(
            "DEL", "ct1:freeze:pending"), b":1\r\n")
        self.cluster.wait_until(lambda: ct1_receiver_status(
            self.primary_to_successor)["durable_cursor"] >= 1, timeout=30.0)
        # The native manifest fixture measures target WAL high-water and tombstone.
        # Target applies the frame to its WAL; SAVE makes its second native SST.
        self.assertEqual(self.successor_admin.execute_resp("SAVE"), b"+OK\r\n")
        acknowledged = ct1_source_status(self.successor_to_primary)
        self.assertEqual(acknowledged["acknowledged_lsn"],
                         acknowledged["durable_lsn"])
        self.frozen_target_status = ct1_receiver_status(self.primary_to_successor)
        self.cluster.kill("successor")
        pending = self.primary_admin.execute_resp(
            "SET", "ct1:freeze:pending", "x" * 1440)
        self.assertIn(b"outcome unresolved", pending)
        retained = ct1_source_status(self.successor_to_primary)
        self.assertEqual(retained["acknowledged_lsn"], acknowledged["durable_lsn"])
        self.assertEqual(retained["durable_lsn"], acknowledged["durable_lsn"] + 1)
        self.assertEqual(retained["retained_bytes"], 1644)
        self.frozen_source_status = retained
        self.frozen_source_high_water = ct1_read(
            self.successor_to_primary, generation,
            after_seq=retained["acknowledged_lsn"])["groups"][-1]["last_seq"]
        self.cluster.kill("lead")
        frozen = self.cluster.root / "frozen"
        frozen.mkdir(mode=0o700)
        rosters = []
        zero_files = []
        for name, base in (("lead", "source"), ("successor", "target")):
            data = self.cluster.root / name / "data"
            sstables = sorted(p.name for p in data.glob("sstable_*.db"))
            self.assertEqual(len(sstables), 2, (name, sstables))
            names = (["ct-baseline.qfs"] if name == "lead" else []) + [
                "ct-state.bin", "restore-highwater.bin", "slot-ownership.journal",
                "slot-ownership.journal.lock", *sstables, "wal.log"]
            directory = frozen / base
            directory.mkdir(mode=0o700)
            for filename in names:
                original = data / filename
                self.assertTrue(original.exists(), (name, filename))
                metadata = original.lstat()
                self.assertTrue(stat.S_ISREG(metadata.st_mode) and
                                stat.S_IMODE(metadata.st_mode) == 0o600 and
                                metadata.st_nlink == 1, (name, filename))
                digest = hashlib.sha256()
                copied = hashlib.sha256()
                target = directory / filename
                # Both daemon processes are reaped: no mutable writer can race
                # this byte-for-byte copy into the independent private root.
                with original.open("rb") as src, os.fdopen(os.open(target,
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                        0o600), "wb") as dst:
                    while chunk := src.read(1 << 20):
                        digest.update(chunk)
                        dst.write(chunk)
                with target.open("rb") as src:
                    while chunk := src.read(1 << 20):
                        copied.update(chunk)
                self.assertEqual(target.stat().st_size, metadata.st_size, filename)
                self.assertEqual(copied.digest(), digest.digest(), filename)
                if filename == "slot-ownership.journal.lock":
                    self.assertEqual(metadata.st_size, 0)
                elif not metadata.st_size:
                    zero_files.append((name, filename))
            rosters.append(sstables)
        self.assertFalse(zero_files, zero_files)
        checked = subprocess.run([str(binary), "verify", str(frozen / "source"),
            str(frozen / "target"), *rosters[0], *rosters[1], generation],
            env=dict(self.cluster.env, QIHSE_DATA_DIR=str(self.cluster.root / "joiner/data")),
            capture_output=True, timeout=30)
        self.assertEqual(checked.returncode, 0, checked.stderr.decode(errors="replace"))
        self.assertIn(b"source 8/8, target 7/7", checked.stdout)
        self.frozen_rosters = rosters
        self.frozen_binary = binary
        return frozen, generation

    def test_ct1_frozen_roster_real_daemon(self):
        self.frozen_roster_fixture()

    def test_ct1_canonical_source_manifest_fixture(self):
        frozen, generation = self.frozen_roster_fixture()
        source, target = self.frozen_source_status, self.frozen_target_status
        nonce = bytes(range(32))
        manifest_path = self.cluster.root / "canonical-ct1-b.bin"
        original_data = str(self.cluster.root / "lead/data")
        args = [str(self.frozen_binary), "manifest", str(frozen / "source"),
                str(frozen / "target"), *self.frozen_rosters[0],
                *self.frozen_rosters[1], generation,
                str(self.cluster.identity_file("lead", "qihse_dsa_pub.pem")),
                str(self.cluster.identity_file("successor", "qihse_dsa_pub.pem")),
                str(self.cluster.identity_file("joiner", "qihse_dsa_pub.pem")),
                str(source["baseline_row_seq"]), source["baseline_digest"],
                str(source["acknowledged_lsn"]), str(source["durable_lsn"]),
                str(target["durable_cursor"]), nonce.hex(), str(manifest_path)]
        produced = subprocess.run(args, env=dict(self.cluster.env,
                                  QIHSE_DATA_DIR=original_data,
                                  QIHSE_OPERATOR_PASSWORD=OPERATOR_PASSWORD),
                                  capture_output=True, timeout=30)
        self.assertEqual(produced.returncode, 0, produced.stderr.decode(errors="replace"))
        manifest = manifest_path.read_bytes()
        self.assertEqual(len(manifest), 2624)
        self.assertEqual(manifest[:8], b"QCT1BR02")
        self.assertEqual(manifest[-32:], hashlib.sha256(manifest[:-32]).digest())
        self.assertEqual((frozen / "source/wal.log").stat().st_size, 1644)
        self.canonical_manifest = manifest
        self.canonical_manifest_path = manifest_path
        self.canonical_nonce = nonce
        self.canonical_frozen = frozen
        self.canonical_generation = generation

    def test_live_source_quote_v2_signed_and_denials(self):
        self.test_ct1_canonical_source_manifest_fixture()
        frozen, manifest, nonce = (self.canonical_frozen, self.canonical_manifest,
                                   self.canonical_nonce)
        # Keep the successor's STATUS listener available for the source's
        # preflight, but point its pull worker at a dead endpoint so it cannot
        # replay the pending tail and garbage-collect the retained frame before
        # the signed quote reads it.
        successor_process, _ = self.cluster.start_ct1_node(
            "successor", 1, "successor", "lead", "ct-successor", "ct-primary",
            self.canonical_generation,
            extra_args=("--replication-principal-id", "65535",
                        "--ct-peer", "127.0.0.1:1"),
            topology_names=self.topology_names, ack_timeout_ms=500)
        self.assertIsNone(successor_process.poll())
        process, _ = self.cluster.start_ct1_node(
            "lead", 0, "primary", "successor", "ct-primary", "ct-successor",
            self.canonical_generation,
            extra_args=("--replication-principal-id", "65535",
                        "--ct1-recovery-frozen-root", str(frozen / "source")),
            topology_names=self.topology_names, ack_timeout_ms=500)
        self.assertIsNone(process.poll())
        operator = self.cluster.replication_peer_client(
            identity_name="joiner", node_id="ct-test-client", target_name="lead")
        quote_request = ("REPL.CT1", "SOURCE", "QUOTE-V2")
        # The source fences data-serving quotes until its frozen-root recovery
        # completes; retry the TRYAGAIN fence until the signed quote is served.
        def _quote_reply():
            r = operator.execute_resp(*quote_request, nonce, manifest)
            return r if not r.startswith(b"-TRYAGAIN") else None
        reply = self.cluster.wait_until(_quote_reply, timeout=30.0)
        quote = parse_resp_frame(reply)
        self.assertIsInstance(quote, bytes, reply[:128])
        self.assertEqual(len(quote), 5201)
        self.assertEqual(quote[:6], b"CT1Q\x02\x01")
        self.assertEqual(quote[8:40], nonce)
        self.assertEqual(quote[40:72], hashlib.sha256(manifest).digest())
        quote_path = self.cluster.root / "source-quote.bin"
        quote_path.write_bytes(quote)
        checked = subprocess.run([str(self.frozen_binary), "quote",
            str(self.canonical_manifest_path), str(quote_path),
            str(self.cluster.identity_file("lead", "qihse_dsa_pub.pem")),
            str(self.cluster.identity_file("successor", "qihse_dsa_pub.pem")),
            nonce.hex()], env=self.cluster.env, capture_output=True, timeout=30)
        self.assertEqual(checked.returncode, 0, checked.stderr)
        self.assertIn(b"verified", checked.stdout)
        before = ct1_source_status(self.cluster.replication_peer_client(
            identity_name="successor", node_id="ct-successor", target_name="lead"))
        peer = self.cluster.replication_peer_client(
            identity_name="successor", node_id="ct-successor", target_name="lead")
        unpinned = self.cluster.replication_peer_client(
            identity_name="forged", node_id="ct-forged", target_name="lead")
        self.assertEqual(unpinned.execute_resp("AUTH", "GODMODE_OP",
                         self.cluster.env["QIHSE_OPERATOR_PASSWORD"]), b"+OK\r\n")
        wrong_label = self.cluster.replication_peer_client(
            identity_name="joiner", node_id="ct-wrong-label", target_name="lead")
        for client in (peer, unpinned, wrong_label):
            denied = client.execute_resp(*quote_request, nonce, manifest)
            self.assertTrue(denied.startswith(b"-"), denied[:128])
            self.assertNotIn(b"CT1Q", denied)
        for bad_nonce, bad_manifest in ((bytes([nonce[0] ^ 1]) + nonce[1:], manifest),
                                         (nonce, manifest[:-1] + bytes([manifest[-1] ^ 1])),
                                         (nonce, b"not-a-canonical-manifest")):
            denied = operator.execute_resp(*quote_request, bad_nonce, bad_manifest)
            self.assertTrue(denied.startswith(b"-"), denied[:128])
            self.assertNotIn(b"CT1Q", denied)
        bad_generation = bytearray(manifest)
        offset = manifest.find(self.canonical_generation.encode())
        self.assertGreaterEqual(offset, 0)
        bad_generation[offset] = ord("f") if bad_generation[offset] != ord("f") else ord("e")
        bad_generation[-32:] = hashlib.sha256(bad_generation[:-32]).digest()
        denied = operator.execute_resp(*quote_request, nonce, bytes(bad_generation))
        self.assertTrue(denied.startswith(b"-"), denied[:128])
        frozen_wal = frozen / "source/wal.log"
        original = frozen_wal.read_bytes()
        try:
            frozen_wal.write_bytes(bytes([original[0] ^ 1]) + original[1:])
            denied = operator.execute_resp(*quote_request, nonce, manifest)
            self.assertTrue(denied.startswith(b"-"), denied[:128])
            self.assertNotIn(b"CT1Q", denied)
        finally:
            frozen_wal.write_bytes(original)
        # The baseline contains a protected class-5/SCI-1 row. The exact
        # authenticated service peer has no signing authority; password AUTH
        # cannot upgrade a QKP session into QKP_ADMIN.
        secret = b"protected-fixture-baseline"
        for client in (peer, unpinned):
            self.assertNotIn(secret, client.execute_resp(*quote_request, nonce, manifest))
        self.assertEqual(ct1_source_status(peer), before)
        self.cluster.kill("lead")
        low_process, _ = self.cluster.start_ct1_node(
            "lead", 0, "primary", "successor", "ct-primary", "ct-successor",
            self.canonical_generation, service_clearance=0, service_sci=0,
            extra_args=("--replication-principal-id", "65535",
                        "--ct1-recovery-frozen-root", str(frozen / "source")),
            topology_names=self.topology_names, ack_timeout_ms=500)
        self.assertIsNone(low_process.poll())
        low_operator = self.cluster.replication_peer_client(
            identity_name="joiner", node_id="ct-test-client", target_name="lead")
        denied = low_operator.execute_resp(*quote_request, nonce, manifest)
        self.assertTrue(denied.startswith(b"-"), denied[:128])
        self.assertNotIn(secret, denied)
        self.assertNotIn(b"CT1Q", denied)
        self.cluster.kill("lead")
        no_root_process, _ = self.cluster.start_ct1_node(
            "lead", 0, "primary", "successor", "ct-primary", "ct-successor",
            self.canonical_generation, topology_names=self.topology_names,
            ack_timeout_ms=500)
        self.assertIsNone(no_root_process.poll())
        no_root_operator = self.cluster.replication_peer_client(
            identity_name="joiner", node_id="ct-test-client", target_name="lead")
        denied = no_root_operator.execute_resp(*quote_request, nonce, manifest)
        self.assertTrue(denied.startswith(b"-"), denied[:128])
        self.assertNotIn(b"CT1Q", denied)

    def test_live_target_quote_v2_signed_and_denials(self):
        self.test_ct1_canonical_source_manifest_fixture()
        frozen, manifest, nonce = (self.canonical_frozen, self.canonical_manifest,
                                   self.canonical_nonce)
        process, _ = self.cluster.start_ct1_node(
            "successor", 1, "successor", "lead", "ct-successor", "ct-primary",
            self.canonical_generation,
            extra_args=("--replication-principal-id", "65535",
                        "--ct1-recovery-frozen-root", str(frozen / "target")),
            topology_names=self.topology_names, ack_timeout_ms=500)
        self.assertIsNone(process.poll())
        operator = self.cluster.replication_peer_client(
            identity_name="joiner", node_id="ct-test-client", target_name="successor")
        request = ("REPL.CT1", "TARGET", "QUOTE-V2")
        # The target fences data-serving quotes until its frozen-root recovery
        # completes; retry the TRYAGAIN fence until the signed quote is served.
        def _quote_reply():
            r = operator.execute_resp(*request, nonce, manifest)
            return r if not r.startswith(b"-TRYAGAIN") else None
        reply = self.cluster.wait_until(_quote_reply, timeout=30.0)
        quote = parse_resp_frame(reply)
        self.assertIsInstance(quote, bytes, reply[:128])
        self.assertEqual(len(quote), 5201)
        self.assertEqual(quote[:6], b"CT1Q\x02\x02")
        self.assertEqual(quote[8:40], nonce)
        self.assertEqual(quote[40:72], hashlib.sha256(manifest).digest())
        quote_path = self.cluster.root / "target-quote.bin"
        quote_path.write_bytes(quote)
        checked = subprocess.run([str(self.frozen_binary), "quote-target",
            str(self.canonical_manifest_path), str(quote_path),
            str(self.cluster.identity_file("lead", "qihse_dsa_pub.pem")),
            str(self.cluster.identity_file("successor", "qihse_dsa_pub.pem")),
            nonce.hex()], env=self.cluster.env, capture_output=True, timeout=30)
        self.assertEqual(checked.returncode, 0, checked.stderr)
        self.assertIn(b"strict signature verified", checked.stdout)
        peer = self.cluster.replication_peer_client(
            identity_name="lead", node_id="ct-primary", target_name="successor")
        wrong_label = self.cluster.replication_peer_client(
            identity_name="joiner", node_id="ct-wrong-label", target_name="successor")
        wrong_key = self.cluster.replication_peer_client(
            identity_name="forged", node_id="ct-test-client", target_name="successor")
        unpinned = self.cluster.replication_peer_client(
            identity_name="forged", node_id="ct-forged", target_name="successor")
        self.assertEqual(unpinned.execute_resp("AUTH", "GODMODE_OP",
            self.cluster.env["QIHSE_OPERATOR_PASSWORD"]), b"+OK\r\n")
        for client in (peer, wrong_label, wrong_key, unpinned):
            denied = client.execute_resp(*request, nonce, manifest)
            self.assertTrue(denied.startswith(b"-"), denied[:128])
            self.assertNotIn(b"CT1Q", denied)
        for variant in ("generation", "cursor", "highwater", "tombstone",
                        "tombstone-row-seq"):
            altered_path = self.cluster.root / (variant + "-target-manifest.bin")
            produced = subprocess.run([str(self.frozen_binary), "tamper",
                str(self.canonical_manifest_path), str(altered_path), variant],
                env=self.cluster.env, capture_output=True, timeout=30)
            self.assertEqual(produced.returncode, 0, produced.stderr)
            altered = altered_path.read_bytes()
            if variant == "tombstone-row-seq":
                self.assertEqual(len(altered), len(manifest))
                self.assertEqual(altered[-32:], hashlib.sha256(altered[:-32]).digest())
                seq_offset = 12 + 10 * 65 + 6 * 32 + 12 * 8
                self.assertEqual(altered[:seq_offset], manifest[:seq_offset])
                self.assertEqual(altered[seq_offset + 8:-32],
                                 manifest[seq_offset + 8:-32])
                self.assertNotEqual(altered[seq_offset:seq_offset + 8],
                                    manifest[seq_offset:seq_offset + 8])
            denied = operator.execute_resp(*request, nonce, altered)
            self.assertTrue(denied.startswith(b"-"), (variant, denied[:128]))
            self.assertNotIn(b"CT1Q", denied)
        for bad_nonce, bad_manifest in ((bytes([nonce[0] ^ 1]) + nonce[1:], manifest),
                                         (nonce, b"not-a-canonical-manifest")):
            self.assertTrue(operator.execute_resp(*request, bad_nonce,
                                                  bad_manifest).startswith(b"-"))
        roster_wal = frozen / "target/wal.log"
        original = roster_wal.read_bytes()
        try:
            roster_wal.write_bytes(bytes([original[0] ^ 1]) + original[1:])
            denied = operator.execute_resp(*request, nonce, manifest)
            self.assertTrue(denied.startswith(b"-"), denied[:128])
        finally:
            roster_wal.write_bytes(original)
        self.cluster.kill("successor")
        low_process, _ = self.cluster.start_ct1_node(
            "successor", 1, "successor", "lead", "ct-successor", "ct-primary",
            self.canonical_generation, service_clearance=0, service_sci=0,
            extra_args=("--replication-principal-id", "65535",
                        "--ct1-recovery-frozen-root", str(frozen / "target")),
            topology_names=self.topology_names, ack_timeout_ms=500)
        self.assertIsNone(low_process.poll())
        low_operator = self.cluster.replication_peer_client(
            identity_name="joiner", node_id="ct-test-client", target_name="successor")
        denied = low_operator.execute_resp(*request, nonce, manifest)
        self.assertTrue(denied.startswith(b"-"), denied[:128])
        self.assertNotIn(b"protected-fixture-baseline", denied)
        self.assertNotIn(b"CT1Q", denied)
        self.cluster.kill("successor")
        no_root, _ = self.cluster.start_ct1_node(
            "successor", 1, "successor", "lead", "ct-successor", "ct-primary",
            self.canonical_generation, topology_names=self.topology_names,
            ack_timeout_ms=500)
        self.assertIsNone(no_root.poll())
        no_root_operator = self.cluster.replication_peer_client(
            identity_name="joiner", node_id="ct-test-client", target_name="successor")
        self.assertTrue(no_root_operator.execute_resp(*request, nonce,
                                                       manifest).startswith(b"-"))

    def test_live_paired_source_target_quote_v2_same_manifest_nonce(self):
        self.test_ct1_canonical_source_manifest_fixture()
        frozen, manifest, nonce = (self.canonical_frozen, self.canonical_manifest,
                                   self.canonical_nonce)
        self.assertEqual(len(manifest), 2624)
        source_pub = self.cluster.identity_file("lead", "qihse_dsa_pub.pem")
        target_pub = self.cluster.identity_file("successor", "qihse_dsa_pub.pem")
        self.assertNotEqual(source_pub.read_bytes(), target_pub.read_bytes())
        options = ("--replication-principal-id", "65535")
        target_process, _ = self.cluster.start_ct1_node(
            "successor", 1, "successor", "lead", "ct-successor", "ct-primary",
            self.canonical_generation,
            extra_args=(*options, "--ct1-recovery-frozen-root", str(frozen / "target")),
            topology_names=self.topology_names, ack_timeout_ms=500)
        self.assertIsNone(target_process.poll())
        target_admin = self.cluster.replication_peer_client(
            identity_name="joiner", node_id="ct-test-client", target_name="successor")
        target_peer = self.cluster.replication_peer_client(
            identity_name="lead", node_id="ct-primary", target_name="successor")
        before_target = ct1_receiver_status(target_peer)
        self.assertEqual(before_target, self.frozen_target_status)
        self.assertEqual(target_admin.execute_resp("PING"), b"+PONG\r\n")
        # Quote the sealed target first. Running the frozen source concurrently
        # would resume the pending tail and invalidate both snapshots.
        for role, admin, verifier in (("TARGET", target_admin, "quote-target"),
                                      ("SOURCE", None, "quote")):
            if role == "SOURCE":
                self.assertEqual(ct1_receiver_status(target_peer), before_target)
                self.cluster.kill("successor")
                # Keep STATUS available for the source preflight, but prevent
                # this target's pull worker from replaying the pending tail.
                target_host, target_port = self.cluster.endpoints["successor"]
                successor, _ = self.cluster.start_ct1_node(
                    "successor", 1, "successor", "lead", "ct-successor",
                    "ct-primary", self.canonical_generation,
                    extra_args=(*options, "--ct-peer", f"{target_host}:{target_port}"),
                    topology_names=self.topology_names, ack_timeout_ms=500)
                self.assertIsNone(successor.poll())
                source, _ = self.cluster.start_ct1_node(
                    "lead", 0, "primary", "successor", "ct-primary",
                    "ct-successor", self.canonical_generation,
                    extra_args=(*options, "--ct1-recovery-frozen-root",
                                str(frozen / "source")),
                    topology_names=self.topology_names, ack_timeout_ms=500)
                self.assertIsNone(source.poll())
                admin = self.cluster.replication_peer_client(
                    identity_name="joiner", node_id="ct-test-client", target_name="lead")
                self.assertEqual(admin.execute_resp("PING"), b"+PONG\r\n")
                source_peer = self.cluster.replication_peer_client(
                    identity_name="successor", node_id="ct-successor",
                    target_name="lead")
                self.assertEqual(ct1_source_status(source_peer),
                                 self.frozen_source_status)
            with self.subTest(role=role):
                request = ("REPL.CT1", role, "QUOTE-V2")
                reply = admin.execute_resp(*request, nonce, manifest)
                quote = parse_resp_frame(reply)
                self.assertIsInstance(quote, bytes, reply[:128])
                self.assertEqual(len(quote), 5201)
                self.assertEqual(quote[:6], b"CT1Q\x02" +
                                 (b"\x01" if role == "SOURCE" else b"\x02"))
                self.assertEqual(quote[8:40], nonce)
                self.assertEqual(quote[40:72], hashlib.sha256(manifest).digest())
                quote_path = self.cluster.root / (role.lower() + "-paired-quote.bin")
                quote_path.write_bytes(quote)
                verified = subprocess.run([str(self.frozen_binary), verifier,
                    str(self.canonical_manifest_path), str(quote_path),
                    str(source_pub), str(target_pub), nonce.hex()],
                    env=self.cluster.env, capture_output=True, timeout=30)
                self.assertEqual(verified.returncode, 0, verified.stderr)
                self.assertIn(b"signature verified", verified.stdout)
                altered_path = self.cluster.root / (role.lower() + "-cross-manifest.bin")
                altered = subprocess.run([str(self.frozen_binary), "tamper",
                    str(self.canonical_manifest_path), str(altered_path), "generation"],
                    env=self.cluster.env, capture_output=True, timeout=30)
                self.assertEqual(altered.returncode, 0, altered.stderr)
                cross_manifest = altered_path.read_bytes()
                self.assertEqual(len(cross_manifest), 2624)
                self.assertNotEqual(cross_manifest, manifest)
                for rejected_nonce, rejected_manifest in (
                        (nonce, cross_manifest),
                        (bytes([nonce[0] ^ 1]) + nonce[1:], manifest)):
                    denied = admin.execute_resp(*request, rejected_nonce,
                                                rejected_manifest)
                    self.assertTrue(denied.startswith(b"-"), denied[:128])
                    self.assertNotIn(b"CT1Q", denied)
        self.assertEqual(ct1_source_status(source_peer), self.frozen_source_status)
        self.assertEqual(ct1_receiver_status(self.cluster.replication_peer_client(
            identity_name="lead", node_id="ct-primary", target_name="successor")),
            before_target)
        self.assertEqual(self.canonical_manifest_path.read_bytes(), manifest)

        # The verified signatures and frozen rosters remain intact when the
        # real pull worker advances live cuts; this is not an atomic pair.
        self.cluster.kill("successor")
        target_process, _ = self.cluster.start_ct1_node(
            "successor", 1, "successor", "lead", "ct-successor", "ct-primary",
            self.canonical_generation,
            extra_args=(*options, "--ct1-recovery-frozen-root", str(frozen / "target")),
            topology_names=self.topology_names, ack_timeout_ms=500)
        self.assertIsNone(target_process.poll())
        target_peer = self.cluster.replication_peer_client(
            identity_name="lead", node_id="ct-primary", target_name="successor")
        advanced = self.cluster.wait_until(lambda: (
            status if (status := ct1_receiver_status(target_peer))["durable_cursor"] >
            before_target["durable_cursor"] else None), timeout=30.0)
        acknowledged = self.cluster.wait_until(lambda: (
            status if (status := ct1_source_status(source_peer))["acknowledged_lsn"] >=
            self.frozen_source_status["durable_lsn"] else None), timeout=30.0)
        self.assertEqual(advanced["durable_cursor"],
                         before_target["durable_cursor"] + 1)
        self.assertGreater(acknowledged["acknowledged_lsn"],
                           self.frozen_source_status["acknowledged_lsn"])
        self.assertEqual(self.canonical_manifest_path.read_bytes(), manifest)
        checked_rosters = subprocess.run([str(self.frozen_binary), "verify",
            str(frozen / "source"), str(frozen / "target"),
            *self.frozen_rosters[0], *self.frozen_rosters[1],
            self.canonical_generation],
            env=dict(self.cluster.env, QIHSE_DATA_DIR=str(self.cluster.root / "forged/data")),
            capture_output=True, timeout=30)
        self.assertEqual(checked_rosters.returncode, 0, checked_rosters.stderr)
        self.assertIn(b"source 8/8, target 7/7", checked_rosters.stdout)
        for role, verifier in (("TARGET", "quote-target"), ("SOURCE", "quote")):
            saved = self.cluster.root / (role.lower() + "-paired-quote.bin")
            checked = subprocess.run([str(self.frozen_binary), verifier,
                str(self.canonical_manifest_path), str(saved),
                str(source_pub), str(target_pub), nonce.hex()],
                env=self.cluster.env, capture_output=True, timeout=30)
            self.assertEqual(checked.returncode, 0, (role, checked.stderr))
            self.assertIn(b"signature verified", checked.stdout)
        target_admin = self.cluster.replication_peer_client(
            identity_name="joiner", node_id="ct-test-client", target_name="successor")
        source_admin = self.cluster.replication_peer_client(
            identity_name="joiner", node_id="ct-test-client", target_name="lead")
        for role, admin in (("TARGET", target_admin), ("SOURCE", source_admin)):
            denied = admin.execute_resp("REPL.CT1", role, "QUOTE-V2", nonce, manifest)
            self.assertTrue(denied.startswith(b"-"), (role, denied[:128]))
            self.assertNotIn(b"CT1Q", denied)

    def test_source_quote_locked_snapshot_prerequisite(self):
        binary = self.cluster.root / "source-quote-snapshot"
        # Exercise the real library in a fresh process; no daemon or fake CT state.
        compiler = shlex.split(self.cluster.env.get("CC", "cc"))
        compiled = subprocess.run(compiler + [
            "-std=c99", "-D_GNU_SOURCE", "-DQIHSE_CT1_SOURCE_SNAPSHOT_TEST",
            "-UNDEBUG", "-Wall", "-Wextra", "-Werror",
            "-I", str(ROOT / "include"), "-I", str(ROOT / "persistence"),
            "-I", str(ROOT / "backends/cpu"),
            str(ROOT / "tests/test_ct1_node_quote.c"), "-L", str(ROOT),
            "-lqihse", "-lcrypto", "-pthread", "-o", str(binary),
        ], env=self.cluster.env, capture_output=True, timeout=60)
        self.assertEqual(compiled.returncode, 0, compiled.stderr.decode(errors="replace"))
        env = dict(self.cluster.env, QIHSE_DATA_DIR=str(self.cluster.root / "lead/data"))
        env.pop("QIHSE_OPERATOR_PASSWORD", None)
        result = subprocess.run([str(binary)], env=env,
                                capture_output=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
        self.assertIn(b"locked original bytes and denial checks passed", result.stdout)

    def test_live_quote_endpoint_absent_until_full_attestation_exists(self):
        generation = self.start_pair(new_generation(), primary_clearance=0,
                                     primary_sci=0, successor_clearance=0, successor_sci=0)
        self.wait_for_pair(generation)
        # Exact pinned Operator QKP session, deliberately without password AUTH.
        operator = self.cluster.replication_peer_client(
            identity_name="joiner", node_id="ct-test-client", target_name="lead")
        self.assertEqual(operator.execute_resp("PING"), b"+PONG\r\n")
        self.assertTrue(operator.execute_resp("REPL.STATUS").startswith(b"*"))
        self.assertTrue(self.successor_to_primary.execute_resp("REPL.STATUS").startswith(b"-"))
        before = ct1_source_status(self.successor_to_primary)
        for session in (operator, self.successor_to_primary):
            for path in (("REPL.CT1", "QUOTE-V1"),
                         ("REPL.CT1", "SOURCE", "QUOTE-V1"),
                         ("REPL.CT1", "TARGET", "QUOTE-V1")):
                with self.subTest(path=path, operator=session is operator):
                    reply = session.execute_resp(*path, bytes(range(32)),
                                                 b"not-a-canonical-manifest")
                    self.assertTrue(reply.startswith(b"-"), reply)
                    self.assertNotIn(b"CT1Q", reply)
        self.assertEqual(ct1_source_status(self.successor_to_primary), before)

    def test_target_quote_is_not_a_live_adapter_even_with_protected_history(self):
        key, secret = "ct1:target-quote:high", "CT1-TARGET-QUOTE-CLASS5-PROTECTED"
        seed_classified_kv(self.cluster, "lead", key, secret, classification=5, sci=1)
        generation = self.start_pair(new_generation())
        source, _ = self.wait_for_pair(generation)
        self.assertEqual(self.primary_admin.execute_resp("DEL", key), b":1\r\n")
        def received():
            status = ct1_receiver_status(self.primary_to_successor)
            return status if status["durable_cursor"] else None
        target = self.cluster.wait_until(received, timeout=30.0)
        self.primary_to_successor.close()
        self.successor_admin.close()
        self.cluster.kill("successor")
        self.successor_process, self.successor_admin = self.cluster.start_ct1_node(
            "successor", 1, "successor", "lead", "ct-successor", "ct-primary",
            generation, service_clearance=0, service_sci=0,
            topology_names=self.topology_names)
        self.primary_to_successor = self.cluster.replication_peer_client(
            identity_name="lead", node_id="ct-primary", target_name="successor")
        self.assertEqual(ct1_receiver_status(self.primary_to_successor), target)
        denied_history = self.primary_to_successor.execute_resp(
            "REPL.CT1", "TARGET", "HISTORY-V1", generation,
            str(source["baseline_row_seq"]), target["baseline_digest"],
            str(target["durable_cursor"]), key, "0", "5", "1")
        self.assertEqual(denied_history,
                         b"-ERR CT1 target history unavailable or denied\r\n")
        self.assertNotIn(secret.encode(), denied_history)
        for client in (self.primary_to_successor, self.successor_to_primary):
            reply = client.execute_resp("REPL.CT1", "TARGET", "QUOTE-V1",
                                        generation, key, "0", "5", "1")
            self.assertTrue(reply.startswith(b"-"), reply)
            self.assertNotIn(secret.encode(), reply)

    def start_pair(self, generation: str, *, primary_clearance: int = 65535,
                   primary_sci: int = 65535, successor_clearance: int = 65535,
                   successor_sci: int = 65535, ack_timeout_ms: int = 5000):
        self.topology_names = ("lead", "successor", "joiner")
        primary, successor = self.cluster.start_ct1_pair(
            generation, primary_clearance=primary_clearance, primary_sci=primary_sci,
            successor_clearance=successor_clearance,
            successor_sci=successor_sci,
            ack_timeout_ms=ack_timeout_ms,
            topology_names=self.topology_names,
        )
        self.primary_process, self.primary_admin = primary
        self.successor_process, self.successor_admin = successor
        self.successor_to_primary = self.cluster.replication_peer_client(
            identity_name="successor", node_id="ct-successor", target_name="lead",
        )
        self.primary_to_successor = self.cluster.replication_peer_client(
            identity_name="lead", node_id="ct-primary", target_name="successor",
        )
        return generation

    def restart_successor(self, generation: str):
        return self.cluster.start_ct1_node(
            "successor", 1, "successor", "lead", "ct-successor", "ct-primary",
            generation, topology_names=self.topology_names,
        )

    def wait_for_pair(self, generation: str) -> tuple[dict, dict]:
        def ready():
            source = ct1_source_status(self.successor_to_primary)
            receiver = ct1_receiver_status(self.primary_to_successor)
            if (source["source_id"] == "ct-primary" and
                    source["successor_id"] == "ct-successor" and
                    source["generation"] == generation and
                    receiver["source_id"] == "ct-primary" and
                    receiver["target_id"] == "ct-successor" and
                    receiver["generation"] == generation and
                    receiver["baseline_sealed"]):
                return source, receiver
            return None
        result = self.cluster.wait_until(ready, timeout=30.0)
        # TARGET STATUS reports baseline installation before the primary has
        # accepted the RECONCILE proof. Poll a harmless absent-key GET until
        # the data plane is admitted; never retry a mutation whose outcome
        # might be uncertain.
        probe_key = f"ct1:reconcile-probe-absent:{generation}"
        deadline = time.monotonic() + 30.0
        while time.monotonic() < deadline:
            reply = self.primary_admin.execute_resp("GET", probe_key)
            if reply == b"$-1\r\n":
                return result
            if not reply.startswith(b"-TRYAGAIN"):
                self.cluster.fail_with_log(
                    "lead", f"CT1 readiness probe failed unexpectedly: {reply!r}")
            time.sleep(0.1)
        self.cluster.fail_with_log("successor", "CT1 reconciliation did not admit writes")
        raise AssertionError("unreachable")

    def test_target_history_v1_requires_pinned_peer_and_exact_sealed_history(self):
        generation = self.start_pair(new_generation())
        source_before, receiver_before = self.wait_for_pair(generation)
        key, secret = "ct1:history:deleted", "CT1-HISTORY-PROTECTED-PAYLOAD"
        self.assertEqual(self.primary_admin.execute_resp("SET", key, secret), b"+OK\r\n")
        self.assertEqual(self.primary_admin.execute_resp("DEL", key), b":1\r\n")

        def acknowledged():
            source = ct1_source_status(self.successor_to_primary)
            receiver = ct1_receiver_status(self.primary_to_successor)
            if (source["durable_lsn"] >= source_before["durable_lsn"] + 2 and
                    source["acknowledged_lsn"] == source["durable_lsn"] ==
                    receiver["durable_cursor"]):
                return source, receiver
            return None
        source, receiver = self.cluster.wait_until(acknowledged, timeout=30.0)
        self.assertTrue(receiver["baseline_sealed"])
        self.assertGreater(receiver["durable_cursor"], receiver_before["durable_cursor"])
        args = [generation, str(source["baseline_row_seq"]),
                receiver["baseline_digest"], str(receiver["durable_cursor"]),
                key, "0", "0", "0"]

        def query(peer, fields):
            return peer.execute_resp("REPL.CT1", "TARGET", "HISTORY-V1", *fields)

        reply = query(self.primary_to_successor, args)
        self.assertTrue(reply.startswith(b"*4\r\n"), reply)
        values = parse_resp_frame(reply)
        self.assertEqual(len(values), 4)
        self.assertTrue(all(isinstance(field, bytes) and field.isdigit()
                            for field in values), values)
        position, row_seq, cursor, high_water = map(int, values)
        self.assertEqual(position, source["durable_lsn"])
        self.assertGreater(row_seq, 0)
        self.assertEqual(cursor, receiver["durable_cursor"])
        self.assertGreaterEqual(high_water, row_seq)
        self.assertNotIn(secret.encode(), reply)

        wrong_generation = ("0" if generation[0] != "0" else "1") + generation[1:]
        invalid = (
            (0, wrong_generation), (0, generation.upper() if any(c in "abcdef" for c in generation)
                                   else "g" + generation[1:]),
            (1, "18446744073709551616"), (2, "0" * 64), (2, "g" * 64),
            (3, str(receiver["durable_cursor"] - 1)), (3, "18446744073709551616"),
            (4, "missing:ct1:history"), (4, "k" * 65536), (4, ""),
            (5, "1"), (5, "4294967296"), (6, "1"), (6, "65536"),
            (7, "1"), (7, "65536"),
        )
        for index, replacement in invalid:
            with self.subTest(index=index, replacement=replacement[:40]):
                candidate = args.copy()
                candidate[index] = replacement
                denied = query(self.primary_to_successor, candidate)
                self.assertTrue(denied.startswith(b"-"), denied)
                self.assertNotIn(secret.encode(), denied)
        for candidate in (args[:-1], args + ["extra"]):
            denied = query(self.primary_to_successor, candidate)
            self.assertTrue(denied.startswith(b"-"), denied)
            self.assertNotIn(secret.encode(), denied)

        forged = self.cluster.replication_peer_client(
            identity_name="forged", node_id="ct-forged", target_name="successor")
        for peer in (forged, self.successor_admin):
            denied = query(peer, args)
            self.assertTrue(denied.startswith(b"-"), denied)
            self.assertNotIn(secret.encode(), denied)
        self.assertEqual(ct1_receiver_status(self.primary_to_successor)["durable_cursor"],
                         receiver["durable_cursor"])

    def test_target_history_v1_rejects_inaccessible_classification(self):
        key, secret = "ct1:history:high-clearance", "CT1-HISTORY-CLASS5-SCI1-PROTECTED"
        # Seed only the primary through the authenticated native writer. The
        # successor must receive the protected row through its real baseline.
        seed_classified_kv(self.cluster, "lead", key, secret, classification=5, sci=1)
        generation = self.start_pair(new_generation())
        source, receiver = self.wait_for_pair(generation)
        self.assertGreater(source["baseline_row_seq"], 0)
        self.assertEqual(parse_resp_frame(self.primary_admin.execute_resp("GET", key)),
                         secret.encode())
        self.assertEqual(self.primary_admin.execute_resp("DEL", key), b":1\r\n")

        def acknowledged():
            st = ct1_source_status(self.successor_to_primary)
            target = ct1_receiver_status(self.primary_to_successor)
            return target if (st["acknowledged_lsn"] == st["durable_lsn"] ==
                              target["durable_cursor"] and
                              target["durable_cursor"] > receiver["durable_cursor"]) else None
        target = self.cluster.wait_until(acknowledged, timeout=30.0)
        args = [generation, str(source["baseline_row_seq"]), target["baseline_digest"],
                str(target["durable_cursor"]), key, "0", "5", "1"]
        allowed = self.primary_to_successor.execute_resp(
            "REPL.CT1", "TARGET", "HISTORY-V1", *args)
        self.assertTrue(allowed.startswith(b"*4\r\n"), allowed)
        position, row_seq, cursor, high_water = map(int, parse_resp_frame(allowed))
        self.assertEqual(position, target["durable_cursor"])
        self.assertGreater(row_seq, source["baseline_row_seq"])
        self.assertEqual(cursor, target["durable_cursor"])
        self.assertGreaterEqual(high_water, row_seq)
        self.assertNotIn(secret.encode(), allowed)

        # Reauthenticate the exact pinned service peer after reducing its
        # local principal's policy, without changing the protected store.
        for clearance, sci in ((0, 65535), (65535, 0), (65535, 65535)):
            with self.subTest(clearance=clearance, sci=sci):
                self.primary_to_successor.close()
                self.successor_admin.close()
                self.cluster.kill("successor")
                self.successor_process, self.successor_admin = self.cluster.start_ct1_node(
                    "successor", 1, "successor", "lead", "ct-successor", "ct-primary",
                    generation, service_clearance=clearance, service_sci=sci,
                    topology_names=self.topology_names)
                self.primary_to_successor = self.cluster.replication_peer_client(
                    identity_name="lead", node_id="ct-primary", target_name="successor")
                self.assertEqual(ct1_receiver_status(self.primary_to_successor), target)
                reply = self.primary_to_successor.execute_resp(
                    "REPL.CT1", "TARGET", "HISTORY-V1", *args)
                self.assertNotIn(secret.encode(), reply)
                if clearance == sci == 65535:
                    # Restoring clearance must recover the exact same proof;
                    # a corrupt or unavailable store is not an auth denial.
                    self.assertEqual(reply, allowed)
                else:
                    self.assertEqual(reply, b"-ERR CT1 target history unavailable or denied\r\n")
                    # A caller-supplied low label must not bypass stored labels.
                    denied = self.primary_to_successor.execute_resp(
                        "REPL.CT1", "TARGET", "HISTORY-V1", *args[:-2], "0", "0")
                    self.assertEqual(denied, b"-ERR CT1 target history unavailable or denied\r\n")
                    self.assertNotIn(secret.encode(), denied)

    def test_source_frame_v1_returns_original_pending_frame_only_to_pinned_successor(self):
        generation = self.start_pair(new_generation(), ack_timeout_ms=500)
        self.wait_for_pair(generation)
        self.successor_to_primary.close()
        self.cluster.kill("successor")
        key, secret = "ct1:frame:pending", "CT1-SOURCE-FRAME-PROTECTED-PAYLOAD"
        write = self.primary_admin.execute_resp("SET", key, secret, "PX", "3600000")
        self.assertIn(b"outcome unresolved", write)
        peer = self.cluster.replication_peer_client(
            identity_name="successor", node_id="ct-successor", target_name="lead")
        self.successor_to_primary = peer
        status = ct1_source_status(peer)
        self.assertGreater(status["durable_lsn"], status["acknowledged_lsn"])
        groups = ct1_read(peer, generation, after_seq=status["acknowledged_lsn"])["groups"]
        group = next(g for g in groups if any(r["key"] == key.encode()
                                             for r in g["records"]))
        self.assertEqual(len(group["records"]), 1)
        record = group["records"][0]
        self.assertEqual(record["key"], key.encode())
        self.assertEqual(record["value"], secret.encode())
        args = [generation, str(status["baseline_row_seq"]), status["baseline_digest"],
                str(status["acknowledged_lsn"]), str(status["durable_lsn"]),
                str(group["position"]), key, "0", "0", "0", str(record["change_seq"])]

        def query(client, fields):
            return client.execute_resp("REPL.CT1", "SOURCE", "FRAME-V1", *fields)

        reply = query(peer, args)
        self.assertTrue(reply.startswith(b"*9\r\n"), reply[:100])
        fields = parse_resp_frame(reply)
        self.assertEqual(len(fields), 9)
        frame, digest, returned_key, tenant, cls, sci, position, seq, expiry = fields
        self.assertEqual(hashlib.sha256(frame).hexdigest().encode(), digest)
        self.assertEqual(returned_key, key.encode())
        self.assertEqual([int(tenant), int(cls), int(sci), int(position), int(seq)],
                         [0, 0, 0, group["position"], record["change_seq"]])
        self.assertEqual(int(expiry), record["expiry"])
        self.assertIn(secret.encode(), frame)
        self.assertEqual(ct1_source_status(peer), status)

        wrong_generation = ("0" if generation[0] != "0" else "1") + generation[1:]
        for index, replacement in (
                (0, wrong_generation), (0, "g" + generation[1:]),
                (1, "18446744073709551616"), (2, "0" * 64), (2, "G" * 64),
                (3, str(status["acknowledged_lsn"] + 1)),
                (4, str(status["durable_lsn"] + 1)),
                (5, str(group["position"] + 1)), (6, "missing:frame"),
                (6, "k" * 65536), (6, ""), (7, "4294967296"),
                (8, "65536"), (9, "65536"),
                (10, str(record["change_seq"] + 1)), (10, "18446744073709551616")):
            with self.subTest(index=index, replacement=replacement[:40]):
                invalid = args.copy()
                invalid[index] = replacement
                denied = query(peer, invalid)
                self.assertEqual(denied,
                    b"-ERR CT1 source frame unavailable or denied\r\n")
                self.assertNotIn(secret.encode(), denied)
        for invalid in (args[:-1], args + ["extra"]):
            self.assertEqual(query(peer, invalid),
                b"-ERR CT1 source frame unavailable or denied\r\n")
        forged = self.cluster.replication_peer_client(
            identity_name="forged", node_id="ct-forged", target_name="lead")
        for client in (forged, self.primary_admin):
            denied = query(client, args)
            self.assertIn(denied, (
                b"-ERR CT1 source frame unavailable or denied\r\n",
                b"-NOAUTH Authentication required.\r\n"))
            self.assertNotIn(secret.encode(), denied)
        self.assertEqual(ct1_source_status(peer), status)

    def test_source_frame_v1_low_service_clearance_does_not_expose_high_data(self):
        key, secret = "ct1:frame:high", "CT1-FRAME-CLASS5-SCI1-PROTECTED"
        seed_classified_kv(self.cluster, "lead", key, secret, classification=5, sci=1)
        generation = self.start_pair(new_generation(), ack_timeout_ms=500)
        source, _ = self.wait_for_pair(generation)
        self.assertGreater(source["baseline_row_seq"], 0)
        self.assertEqual(parse_resp_frame(self.primary_admin.execute_resp("GET", key)),
                         secret.encode())
        self.successor_to_primary.close()
        self.primary_admin.close()
        self.cluster.kill("lead")
        self.primary_process, self.primary_admin = self.cluster.start_ct1_node(
            "lead", 0, "primary", "successor", "ct-primary", "ct-successor",
            generation, service_clearance=0, service_sci=0,
            ack_timeout_ms=500, topology_names=self.topology_names)
        self.cluster.wait_until(
            lambda: self.primary_admin.execute_resp("GET", key) ==
            b"$" + str(len(secret)).encode() + b"\r\n" + secret.encode() + b"\r\n",
            timeout=30.0)
        self.cluster.kill("successor")
        pending_key = "ct1:frame:low-pending"
        self.assertIn(b"outcome unresolved",
            self.primary_admin.execute_resp("SET", pending_key, "LOW-PENDING"))
        peer = self.cluster.replication_peer_client(
            identity_name="successor", node_id="ct-successor", target_name="lead")
        status = ct1_source_status(peer)
        groups = ct1_read(peer, generation, after_seq=status["acknowledged_lsn"])["groups"]
        group = next(g for g in groups if any(r["key"] == pending_key.encode()
                                             for r in g["records"]))
        row_seq = group["records"][0]["change_seq"]
        self.assertEqual(group["records"][0]["key"], pending_key.encode())
        self.successor_to_primary = peer
        args = [generation, str(status["baseline_row_seq"]), status["baseline_digest"],
                str(status["acknowledged_lsn"]), str(status["durable_lsn"]),
                str(group["position"]), key, "0", "5", "1", str(row_seq)]
        low_args = args.copy()
        low_args[6:10] = [pending_key, "0", "0", "0"]
        allowed = parse_resp_frame(peer.execute_resp(
            "REPL.CT1", "SOURCE", "FRAME-V1", *low_args))
        self.assertEqual(allowed[2], pending_key.encode())
        self.assertIn(b"LOW-PENDING", allowed[0])
        self.assertNotIn(secret.encode(), allowed[0])
        high_labels_on_low_row = low_args.copy()
        high_labels_on_low_row[8:10] = ["5", "1"]
        denied = peer.execute_resp(
            "REPL.CT1", "SOURCE", "FRAME-V1", *high_labels_on_low_row)
        self.assertEqual(denied, b"-ERR CT1 source frame unavailable or denied\r\n")
        for labels in (("5", "1"), ("0", "0")):
            denied = self.successor_to_primary.execute_resp(
                "REPL.CT1", "SOURCE", "FRAME-V1", *args[:-3], *labels,
                str(row_seq))
            self.assertEqual(denied, b"-ERR CT1 source frame unavailable or denied\r\n")
            self.assertNotIn(secret.encode(), denied)

    def test_write_is_acknowledged_only_after_durable_successor_and_survives_restart(self):
        generation = self.start_pair(new_generation())
        source_before, receiver_before = self.wait_for_pair(generation)

        # A normal KV mutation carries expiry and actor metadata. It must reach
        # the successor through the CT1 log; the successor is never pre-seeded.
        ttl_reply = self.primary_admin.execute_resp(
            "SET", "ct1:ttl:durable", "TTL-DURABLE-MARKER", "PX", "3600000",
        )
        self.assertEqual(ttl_reply, b"+OK\r\n")

        def acknowledged():
            source = ct1_source_status(self.successor_to_primary)
            receiver = ct1_receiver_status(self.primary_to_successor)
            if (source["durable_lsn"] > source_before["durable_lsn"] and
                    source["acknowledged_lsn"] >= source["durable_lsn"] and
                    receiver["durable_cursor"] >= source["acknowledged_lsn"]):
                return source, receiver
            return None
        source_after, receiver_after = self.cluster.wait_until(acknowledged, timeout=30.0)
        self.assertEqual(source_after["generation"], generation)
        self.assertGreater(receiver_after["durable_cursor"], receiver_before["durable_cursor"])

        self.primary_to_successor.close()
        self.cluster.kill("successor")
        self.successor_process, self.successor_admin = self.restart_successor(generation)
        self.primary_to_successor = self.cluster.replication_peer_client(
            identity_name="lead", node_id="ct-primary", target_name="successor",
        )
        restarted_status = ct1_receiver_status(self.primary_to_successor)
        self.assertEqual(restarted_status["generation"], generation)
        self.assertTrue(restarted_status["baseline_sealed"])
        self.assertGreaterEqual(restarted_status["durable_cursor"], receiver_after["durable_cursor"])
        # Kill the lead after the successor's cold reopen. The persisted
        # receiver cursor remains queryable; data reads remain fenced until a
        # proof-consuming promotion contract is available.
        self.cluster.kill("lead")
        self.assertEqual(ct1_receiver_status(self.primary_to_successor)["durable_cursor"],
                         restarted_status["durable_cursor"])

    def test_reopens_primary_with_exact_retained_unacked_successor_tail(self):
        generation = self.start_pair(new_generation(), ack_timeout_ms=3000)
        self.wait_for_pair(generation)
        self.assertEqual(self.primary_admin.execute_resp(
            "SET", "ct1:recovery:seed", "ACKED-SEED"), b"+OK\r\n")
        acked = ct1_source_status(self.successor_to_primary)
        self.assertEqual(acked["acknowledged_lsn"], acked["durable_lsn"])
        self.assertGreater(acked["durable_lsn"], 0)
        ack_lsn = acked["durable_lsn"]

        self.primary_to_successor.close()
        self.cluster.kill("successor")
        key, value = "ct1:recovery:pending", "UNCERTAIN-NX-VALUE"
        # This one conditional write has an uncertain outcome; never retry it.
        reply = self.primary_admin.execute_resp("SET", key, value, "NX")
        self.assertTrue(reply.startswith(b"-"), reply)
        self.assertIn(b"outcome unresolved", reply)
        pending = ct1_source_status(self.successor_to_primary)
        self.assertEqual(pending["acknowledged_lsn"], ack_lsn)
        self.assertEqual(pending["durable_lsn"], ack_lsn + 1)
        self.assertGreater(pending["retained_bytes"], 0)
        self.assertTrue(self.primary_admin.execute_resp("GET", key).startswith(b"-TRYAGAIN"))
        self.assertTrue(self.primary_admin.execute_resp(
            "SET", "ct1:recovery:fenced", "MUST-NOT-APPLY").startswith(b"-TRYAGAIN"))
        self.assertEqual(ct1_source_status(self.successor_to_primary)["durable_lsn"],
                         ack_lsn + 1)

        self.successor_to_primary.close()
        self.primary_admin.close()
        self.cluster.kill("lead")
        self.successor_process, self.successor_admin = self.restart_successor(generation)
        self.primary_to_successor = self.cluster.replication_peer_client(
            identity_name="lead", node_id="ct-primary", target_name="successor")
        receiver = ct1_receiver_status(self.primary_to_successor)
        self.assertTrue(receiver["baseline_sealed"])
        self.assertEqual(receiver["durable_cursor"], ack_lsn)
        self.primary_process, self.primary_admin = self.cluster.start_ct1_node(
            "lead", 0, "primary", "successor", "ct-primary", "ct-successor",
            generation, ack_timeout_ms=3000, topology_names=self.topology_names)
        self.successor_to_primary = self.cluster.replication_peer_client(
            identity_name="successor", node_id="ct-successor", target_name="lead")

        def caught_up():
            source = ct1_source_status(self.successor_to_primary)
            target = ct1_receiver_status(self.primary_to_successor)
            return (source, target) if (
                source["generation"] == target["generation"] == generation and
                source["durable_lsn"] == source["acknowledged_lsn"] ==
                target["durable_cursor"] == ack_lsn + 1 and
                target["baseline_sealed"] and source["retained_bytes"] == 0
            ) else None
        self.cluster.wait_until(caught_up, timeout=30.0)
        self.wait_for_pair(generation)
        self.assertEqual(parse_resp_frame(self.primary_admin.execute_resp("GET", key)),
                         value.encode())
        self.assertEqual(parse_resp_frame(self.primary_admin.execute_resp(
            "GET", "ct1:recovery:fenced")), None)
        self.assertEqual(self.primary_admin.execute_resp(
            "SET", "ct1:recovery:fresh", "POST-CATCHUP"), b"+OK\r\n")
        self.assertEqual(parse_resp_frame(self.primary_admin.execute_resp(
            "GET", "ct1:recovery:fresh")), b"POST-CATCHUP")

    def test_wrong_generation_and_forged_pin_are_denied_without_payload(self):
        generation = self.start_pair(new_generation())
        self.wait_for_pair(generation)
        write_reply = self.primary_admin.execute_resp(
            "SET", "ct1:pin:negative", "CT1-PIN-NEGATIVE-NO-LEAK",
        )
        self.assertEqual(write_reply, b"+OK\r\n")

        wrong_generation = "0" * 32 if generation != "0" * 32 else "1" * 32
        before = ct1_source_status(self.successor_to_primary)
        stale_ack = self.successor_to_primary.execute_resp(
            "REPL.CT1", "ACK", wrong_generation, str(before["durable_lsn"]),
        )
        self.assertTrue(stale_ack.startswith(b"-"), stale_ack)
        after = ct1_source_status(self.successor_to_primary)
        self.assertEqual(after["acknowledged_lsn"], before["acknowledged_lsn"])
        stale = self.successor_to_primary.execute_resp(
            "REPL.CT1", "READ", wrong_generation, "0", "64", str(1 << 20), "v1",
        )
        self.assertTrue(stale.startswith(b"-"), stale)
        self.assertNotIn(b"CT1-PIN-NEGATIVE-NO-LEAK", stale)

        forged = self.cluster.replication_peer_client(
            identity_name="forged", node_id="ct-forged", target_name="lead",
        )
        denied = forged.execute_resp(
            "REPL.CT1", "READ", generation, "0", "64", str(1 << 20), "v1",
        )
        self.assertTrue(denied.startswith(b"-"), denied)
        self.assertNotIn(b"CT1-PIN-NEGATIVE-NO-LEAK", denied)

    def test_small_then_32k_writes_ack_sequentially_after_log_gc(self):
        generation = self.start_pair(new_generation())
        self.wait_for_pair(generation)
        source_before = ct1_source_status(self.successor_to_primary)

        def acknowledged_after(previous_lsn: int):
            source = ct1_source_status(self.successor_to_primary)
            receiver = ct1_receiver_status(self.primary_to_successor)
            if (source["durable_lsn"] > previous_lsn and
                    source["acknowledged_lsn"] >= source["durable_lsn"] and
                    receiver["durable_cursor"] >= source["acknowledged_lsn"]):
                return source, receiver
            return None

        small_key = "{ct1-sequential}:seed"
        self.assertEqual(self.primary_admin.execute_resp("SET", small_key, "seed"),
                         b"+OK\r\n")
        source_one, receiver_one = self.cluster.wait_until(
            lambda: acknowledged_after(source_before["durable_lsn"]), timeout=30.0)
        self.assertEqual(source_one["durable_lsn"], 1)
        self.assertEqual(source_one["acknowledged_lsn"], 1)
        self.assertEqual(receiver_one["durable_cursor"], 1)

        large_key = "{ct1-sequential}:bulk32k"
        value = "x" * (32 * 1024)
        second_reply = self.primary_admin.execute_resp("SET", large_key, value)
        if second_reply != b"+OK\r\n":
            source_after_error = ct1_source_status(self.successor_to_primary)
            receiver_after_error = ct1_receiver_status(self.primary_to_successor)
            try:
                pending_groups = ct1_read(self.successor_to_primary, generation,
                    after_seq=receiver_after_error["durable_cursor"],
                    max_groups=1, max_bytes=1 << 20)
                pending_summary = [(group["position"], group["first_seq"],
                    group["last_seq"], [(record["key"], len(record["value"] or b""))
                                        for record in group["records"]])
                    for group in pending_groups["groups"]]
            except Exception as exc:
                pending_summary = f"READ diagnostic failed: {exc}"
            log_tails = []
            for name in ("lead", "successor"):
                log = self.cluster.logs[name]
                log.flush()
                log.seek(0)
                log_tails.append(f"{name} log={log.read().decode(errors='replace')[-6000:]}")
                log.seek(0, 2)
            self.fail("second CT1 mutation returned without ACK; "
                      f"reply={second_reply!r}; first_source={source_one!r}; "
                      f"source_after={source_after_error!r}; "
                      f"receiver_after={receiver_after_error!r}; "
                      f"pending_groups={pending_summary!r}; " + "\\n".join(log_tails))
        source_two, receiver_two = self.cluster.wait_until(
            lambda: acknowledged_after(source_one["durable_lsn"]), timeout=30.0)
        self.assertEqual(source_two["durable_lsn"], 2)
        self.assertEqual(source_two["acknowledged_lsn"], 2)
        self.assertEqual(receiver_two["durable_cursor"], 2)
        got = parse_resp_frame(self.primary_admin.execute_resp("GET", large_key))
        self.assertEqual(got, value.encode())
        print("CT1 sequential write ACKs:",
              f"small group durable={source_one['durable_lsn']} ACK={source_one['acknowledged_lsn']} "
              f"receiver={receiver_one['durable_cursor']};",
              f"32 KiB group durable={source_two['durable_lsn']} "
              f"ACK={source_two['acknowledged_lsn']} receiver={receiver_two['durable_cursor']}")

    def test_leader_does_not_report_success_when_successor_ack_is_lost(self):
        generation = self.start_pair(new_generation(), ack_timeout_ms=500)
        self.wait_for_pair(generation)
        before = ct1_source_status(self.successor_to_primary)
        self.cluster.kill("successor")

        reply = self.primary_admin.execute_resp(
            "SET", "ct1:lost-ack", "CT1-LOST-ACK-MARKER",
        )
        self.assertTrue(reply.startswith(b"-"), reply)
        self.assertIn(b"outcome unresolved", reply)

        uncertain = ct1_source_status(self.successor_to_primary)
        self.assertGreater(uncertain["durable_lsn"], before["durable_lsn"])
        self.assertLess(uncertain["acknowledged_lsn"], uncertain["durable_lsn"])

        self.successor_process, self.successor_admin = self.restart_successor(generation)
        def acknowledged():
            status = ct1_source_status(self.successor_to_primary)
            return status if status["acknowledged_lsn"] >= status["durable_lsn"] else None
        certified = self.cluster.wait_until(acknowledged, timeout=30.0)
        self.assertEqual(certified["generation"], generation)
        self.primary_to_successor = self.cluster.replication_peer_client(
            identity_name="lead", node_id="ct-primary", target_name="successor",
        )
        receiver = ct1_receiver_status(self.primary_to_successor)
        self.assertGreaterEqual(receiver["durable_cursor"], certified["acknowledged_lsn"])

    def test_killed_leader_promotes_durable_successor_and_fences_reopened_leader(self):
        generation = new_generation()
        topology = ("lead", "successor", "joiner")
        slots = {"lead": (0, 16383)}
        for name in topology:
            self.cluster.reserve_endpoint(name)
        qkp_ids = {"lead": "ct-primary", "successor": "ct-successor",
                   "joiner": "ct-joiner"}

        # C is a healthy, slotless standby with an empty store. It receives no
        # pre-seeded copy of A's data.
        joiner, joiner_admin = self.cluster.start_node(
            "joiner", 2, "ct-joiner", topology_names=topology,
            slot_ranges=slots,
            topology_qkp_ids={"joiner": "ct-joiner"},
        )
        successor_args = (
            "--replication-allowed-peer", "ct-joiner",
            str(self.cluster.identity_file("joiner", "qihse_dsa_pub.pem")),
        )
        successor, successor_admin = self.cluster.start_ct1_node(
            "successor", 1, "successor", "lead", "ct-successor", "ct-primary",
            generation, topology_names=topology, slot_ranges=slots,
            topology_qkp_ids={"lead": "ct-primary", "successor": "ct-successor",
                              "joiner": "ct-joiner"}, extra_args=successor_args,
        )
        primary, primary_admin = self.cluster.start_ct1_node(
            "lead", 0, "primary", "successor", "ct-primary", "ct-successor",
            generation, topology_names=topology, slot_ranges=slots,
            topology_qkp_ids={"lead": "ct-primary", "successor": "ct-successor"},
        )
        self.primary_process, self.primary_admin = primary, primary_admin
        self.successor_process, self.successor_admin = successor, successor_admin
        self.topology_names = topology
        b_as_source = self.cluster.replication_peer_client(
            identity_name="joiner", node_id="ct-joiner", target_name="successor")
        a_as_source = self.cluster.replication_peer_client(
            identity_name="successor", node_id="ct-successor", target_name="lead")
        b_as_target = self.cluster.replication_peer_client(
            identity_name="lead", node_id="ct-primary", target_name="successor")

        self.cluster.wait_until(
            lambda: (lambda s, r: (s, r) if s["source_id"] == "ct-primary" and
                r["baseline_sealed"] else None)(ct1_source_status(a_as_source),
                                                  ct1_receiver_status(b_as_target)),
            timeout=30.0)
        # Wait for RECONCILE admission using a read-only absent-key probe.
        deadline = time.monotonic() + 30.0
        while True:
            ready = primary_admin.execute_resp("GET", f"ct1:promotion-absent:{generation}")
            if ready == b"$-1\r\n":
                break
            self.assertTrue(ready.startswith(b"-TRYAGAIN"), ready)
            if time.monotonic() >= deadline:
                self.cluster.fail_with_log("successor", "CT1 successor did not reconcile")
            time.sleep(0.1)

        key, value = "ct1:promotion:preserved", "PROMOTED-SUCCESSOR-DURABLE-VALUE"
        self.assertEqual(primary_admin.execute_resp("SET", key, value), b"+OK\r\n")
        source_before = ct1_source_status(a_as_source)
        target_before = ct1_receiver_status(b_as_target)
        self.assertGreater(source_before["acknowledged_lsn"], 0)
        self.assertGreaterEqual(target_before["durable_cursor"],
                                source_before["acknowledged_lsn"])

        self.cluster.kill("lead")
        lead_host, lead_port = self.cluster.endpoints["lead"]
        join_host, join_port = self.cluster.endpoints["joiner"]
        failed_topology_id = topology_id_for(lead_host, lead_port)

        def failed_node_visible():
            frame = successor_admin.execute_resp("CLUSTER", "NODES")
            parsed = parse_resp_frame(frame)
            if not isinstance(parsed, bytes):
                return None
            for line in parsed.decode(errors="replace").splitlines():
                fields = line.split()
                if len(fields) >= 3 and fields[0] == failed_topology_id and \
                        ("fail" in fields[2].lower() or "noaddr" in fields[2].lower()):
                    return fields[2]
            return None

        self.cluster.wait_until(failed_node_visible, timeout=45.0, interval=0.25)
        promote = successor_admin.execute_resp(
            "CLUSTER", "CT1", "PROMOTE",
            failed_topology_id,
            topology_id_for(join_host, join_port),
        )
        if promote not in (b"+PROMOTED\r\n",
                           b"-TRYAGAIN CT1 ownership is durable; source remains control-only until trusted successor baseline is ready\r\n"):
            tails = []
            for name in ("lead", "successor", "joiner"):
                log = self.cluster.logs[name]
                log.flush()
                log.seek(0)
                tails.append(f"{name} log:\\n{log.read().decode(errors='replace')[-5000:]}")
                log.seek(0, 2)
            nodes = successor_admin.execute_resp("CLUSTER", "NODES")
            self.fail(f"CT1 promotion reply: {promote!r}; topology={nodes!r}; " +
                      "\\n".join(tails))

        # The promotion may durably commit before the successor baseline is
        # ready. B reports the new generation and C as its pinned successor;
        # restart C with its empty data directory so it can pull that baseline.
        try:
            promoted = ct1_source_status(b_as_source)
        except AssertionError as exc:
            tails = []
            for name in ("lead", "successor", "joiner"):
                log = self.cluster.logs[name]
                log.flush()
                log.seek(0)
                tails.append(f"{name} log:\\n{log.read().decode(errors='replace')[-5000:]}")
                log.seek(0, 2)
            self.fail(f"promotion reply={promote!r}; promoted STATUS failed: {exc}; " +
                      "\\n".join(tails))
        self.assertEqual(promoted["source_id"], "ct-successor")
        self.assertEqual(promoted["successor_id"], "ct-joiner")
        self.assertNotEqual(promoted["generation"], generation)
        joiner_admin.close()
        self.cluster.kill("joiner")
        self.cluster.processes["joiner"], _ = self.cluster.start_ct1_node(
            "joiner", 2, "successor", "successor", "ct-joiner", "ct-successor",
            promoted["generation"], topology_names=topology, slot_ranges=slots,
            topology_qkp_ids={"successor": "ct-successor", "joiner": "ct-joiner"},
        )
        try:
            b_to_c = self.cluster.replication_peer_client(
                identity_name="joiner", node_id="ct-joiner", target_name="successor")
            c_to_b = self.cluster.replication_peer_client(
                identity_name="successor", node_id="ct-successor", target_name="joiner")
        except Exception as exc:
            tails = []
            for name in ("lead", "successor", "joiner"):
                log = self.cluster.logs[name]
                log.flush()
                log.seek(0)
                tails.append(f"{name} log:\n{log.read().decode(errors='replace')[-5000:]}")
                log.seek(0, 2)
            self.fail(f"replication peer handshake failed: {exc}; " + "\n".join(tails))
        def reconfigured():
            source = ct1_source_status(b_to_c)
            receiver = ct1_receiver_status(c_to_b)
            return (source, receiver) if source["generation"] == promoted["generation"] and \
                receiver["baseline_sealed"] else None
        self.cluster.wait_until(reconfigured, timeout=30.0)

        # The original leader's disk was not modified by promotion. Reopening
        # it with its stale generation must fail closed before serving data.
        with self.assertRaises(AssertionError) as rejected:
            self.cluster.start_ct1_node(
                "lead", 0, "primary", "successor", "ct-primary", "ct-successor",
                generation, topology_names=topology, slot_ranges=slots,
                topology_qkp_ids=qkp_ids,
            )
        self.assertIn("daemon exited", str(rejected.exception))

        actual = parse_resp_frame(successor_admin.execute_resp("GET", key))
        self.assertEqual(actual, value.encode())


if __name__ == "__main__":
    unittest.main()
