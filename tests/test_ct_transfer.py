#!/usr/bin/env python3
"""Real-daemon CT1 QKP write durability and denial drills.

This test intentionally fails against a daemon without CT1 support. It never
pre-seeds the successor: every observed value must arrive through the pinned
replication stream and survive a successor process restart.
"""
from __future__ import annotations

import unittest
import time

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
