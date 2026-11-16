#!/usr/bin/env python3
"""Real-daemon CT1 QKP write durability and denial drills.

This test intentionally fails against a daemon without CT1 support. It never
pre-seeds the successor: every observed value must arrive through the pinned
replication stream and survive a successor process restart.
"""
from __future__ import annotations

import hashlib
import unittest
import time

from ct_multigroup_drill import seed_classified_kv
from ct_transport_drill import (
    IsolatedCluster,
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
