"""Negative protocol/redirect/credential tests for the isolated fan agents."""
import importlib.util
import io
import os
import socket
import ssl
import threading
import time
from pathlib import Path
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]

def load(name, rel):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

fan = load("qihse_fleet_fan_agent_secure_test", "tools/fleet/qihse-fan-agent.py")
thermal = load("qihse_thermal_secure_test", "python/qihse/thermal.py")

class FakeSocket:
    def __init__(self, reply=b"-ERR no machine auth\r\n"):
        self.reply = io.BytesIO(reply)
        self.sent = []
        self.closed = False
        self.timeouts = []
    def settimeout(self, seconds): self.timeouts.append(seconds)
    def connect(self, endpoint): self.endpoint = endpoint
    def recv(self, size): return self.reply.read(size)
    def makefile(self, mode): return self.reply
    def sendall(self, data): self.sent.append(data)
    def close(self): self.closed = True

class FleetSecurityTests(unittest.TestCase):
    def test_refuse_remote_plaintext_before_connect(self):
        for module in (fan, thermal):
            with patch.dict(os.environ, {}, clear=True):
                with patch.object(module.socket, "create_connection") as dial:
                    with self.assertRaises(ConnectionError):
                        module._resp_socket("192.0.2.1", 7100, 1)
                    dial.assert_not_called()

    def test_bounded_bulk_reply(self):
        self.assertEqual(fan._read_reply(io.BytesIO(b"$3\r\nabc\r\n")), ("bulk", "abc"))
        for raw in (b"$99999999\r\n", b"*99999999\r\n",
                    b"$3\r\nab\r\n", b"+HI", b"~0\r\n", b"$-2\r\n"):
            with self.subTest(raw=raw), self.assertRaises((ConnectionError, ValueError)):
                fan._read_reply(io.BytesIO(raw))

    def test_reject_untrusted_redirect(self):
        p = fan.QihsePool()
        with self.assertRaises(ConnectionError):
            p._run_redirect(["GET", "test"], (1, "198.51.100.99", 7100), 0)
        with self.assertRaises(ConnectionError):
            p._run_redirect(["GET", "test"], (16384, "192.168.1.91", 7100), 0)

    def test_no_machineauth_password_downgrade(self):
        fake = FakeSocket()
        conn = fan.QihseConnection("127.0.0.1", 7100)
        with patch.dict(os.environ, {"QIHSE_OPERATOR_PASSWORD": "test-not-real"}):
            with patch.object(fan, "_resp_socket", return_value=fake):
                with patch.object(conn, "_load_machine_token", return_value="signed-token"):
                    with self.assertRaises(ConnectionError):
                        conn._open_and_auth()
        self.assertEqual(len(fake.sent), 1)
        self.assertIn(b"MACHINEAUTH", fake.sent[0])
        self.assertNotIn(b"\r\nAUTH\r\n", fake.sent[0])

class DeadlineTests(unittest.TestCase):
    def test_literal_endpoints_and_no_hostname_resolution(self):
        for module in (fan, thermal):
            for host, family in (("127.0.0.1", socket.AF_INET), ("::1", socket.AF_INET6)):
                fake = FakeSocket()
                with patch.object(module.socket, "socket", return_value=fake) as create:
                    self.assertIs(module._resp_socket(host, 7100, 1), fake)
                    create.assert_called_once_with(family, socket.SOCK_STREAM)
                    self.assertEqual(fake.endpoint, (host, 7100))
            with patch.object(module.socket, "socket") as create:
                with self.assertRaisesRegex(ConnectionError, "literal IP"):
                    module._resp_socket("node.example", 7100, 1)
                create.assert_not_called()

    def test_connect_and_tls_share_deadline(self):
        for module in (fan, thermal):
            now = [100.0]
            fake = FakeSocket()
            def connect(endpoint):
                now[0] += 0.6
            fake.connect = connect
            ctx = Mock()
            ctx.wrap_socket.return_value = fake
            with patch.object(module.time, "monotonic", side_effect=lambda: now[0]), \
                 patch.object(module.socket, "socket", return_value=fake), \
                 patch.object(ssl, "create_default_context", return_value=ctx), \
                 patch.dict(os.environ, {"QIHSE_RESP_CA_FILE": "test-ca.pem",
                                         "QIHSE_RESP_SERVER_NAME": "node.example"}):
                self.assertIs(module._resp_socket("192.0.2.1", 7100, 1), fake)
            self.assertAlmostEqual(fake.timeouts[0], 1)
            self.assertAlmostEqual(fake.timeouts[1], 0.4)
            self.assertEqual(ctx.minimum_version, ssl.TLSVersion.TLSv1_3)
            ctx.wrap_socket.assert_called_once_with(fake, server_hostname="node.example")

    def test_connect_expiry_closes_socket_before_tls(self):
        for module in (fan, thermal):
            now = [0.0]
            fake = FakeSocket()
            fake.connect = lambda endpoint: now.__setitem__(0, 2)
            with patch.object(module.time, "monotonic", side_effect=lambda: now[0]), \
                 patch.object(module.socket, "socket", return_value=fake):
                with self.assertRaises(TimeoutError):
                    module._resp_socket("127.0.0.1", 7100, 1)
            self.assertTrue(fake.closed)

    def test_tls_expiry_closes_socket(self):
        for module in (fan, thermal):
            now = [0.0]
            fake = FakeSocket()
            ctx = Mock()
            def handshake(sock, **kwargs):
                now[0] = 2
                return sock
            ctx.wrap_socket.side_effect = handshake
            with patch.object(module.time, "monotonic", side_effect=lambda: now[0]), \
                 patch.object(module.socket, "socket", return_value=fake), \
                 patch.object(ssl, "create_default_context", return_value=ctx), \
                 patch.dict(os.environ, {"QIHSE_RESP_CA_FILE": "test-ca.pem",
                                         "QIHSE_RESP_SERVER_NAME": "node.example"}):
                with self.assertRaises(TimeoutError):
                    module._resp_socket("192.0.2.1", 7100, 1)
            self.assertTrue(fake.closed)

    def test_thermal_seed_fallback_uses_single_deadline(self):
        now = [0.0]
        def request(*args, **kwargs):
            self.assertEqual(kwargs["deadline"], 1)
            now[0] += 0.6
            return None, "failed"
        with patch.object(thermal.time, "monotonic", side_effect=lambda: now[0]), \
             patch.object(thermal, "send_resp", side_effect=request) as send:
            name, data = thermal.fetch_node_telemetry(thermal.CLUSTER_SEEDS[0], "test", deadline=1)
        self.assertEqual(send.call_count, 2)
        self.assertEqual(data["status"], "OFFLINE")

    def test_trickle_headers_and_bulk_obey_total_deadline(self):
        for module in (fan, thermal):
            for operation in (lambda r: r.readline(8193), lambda r: r.read(100)):
                now = [0.0]
                fake = FakeSocket()
                def recv(size):
                    now[0] += 0.4
                    return b"a"
                fake.recv = recv
                with patch.object(module.time, "monotonic", side_effect=lambda: now[0]):
                    with self.assertRaises(TimeoutError):
                        operation(module._DeadlineReader(fake, 1.0))
                self.assertEqual(len(fake.timeouts), 3)
                self.assertAlmostEqual(fake.timeouts[-1], 0.2)

    def test_auth_and_command_share_budget_and_close(self):
        now = [0.0]
        fake = FakeSocket()
        def recv(size):
            now[0] += 0.6
            return b"+OK\r\n"
        fake.recv = recv
        with patch.object(thermal.time, "monotonic", side_effect=lambda: now[0]), \
             patch.object(thermal, "_resp_socket", return_value=fake):
            result, error = thermal.send_resp("127.0.0.1", 7100, "test", ["GET", "x"], timeout=1)
        self.assertIsNone(result)
        self.assertIn("deadline", error)
        self.assertTrue(fake.closed)
        self.assertEqual(len(fake.sent), 2)
        self.assertAlmostEqual(fake.timeouts[-1], 0.4)

    def test_thermal_cleanup_all_response_paths(self):
        for response in (b"-ERR refused\r\n", b"+OK\r\n$99999999\r\n",
                         b"+OK\r\n$3\r\nab", b"+OK\r\n:3\r\n"):
            fake = FakeSocket(response)
            with patch.object(thermal, "_resp_socket", return_value=fake):
                thermal.send_resp("127.0.0.1", 7100, "test", ["GET", "x"])
            self.assertTrue(fake.closed)

    def test_reconnect_does_not_reset_deadline(self):
        now = [0.0]
        conn = fan.QihseConnection("127.0.0.1", 7100, timeout=1)
        def fail(deadline):
            self.assertEqual(deadline, 1)
            now[0] += 0.6
            raise OSError("stale")
        with patch.object(fan.time, "monotonic", side_effect=lambda: now[0]), \
             patch.object(fan.time, "sleep", side_effect=lambda n: now.__setitem__(0, now[0] + n)), \
             patch.object(conn, "_open_and_auth", side_effect=fail) as connect:
            with self.assertRaises(OSError):
                conn.command(["GET", "x"])
        self.assertEqual(connect.call_count, 2)
        self.assertIsNone(conn.sock)

    def test_slow_first_seed_preserves_fast_later_results(self):
        now = [0.0]
        ready = threading.Barrier(len(thermal.CLUSTER_SEEDS))
        first_name = thermal.CLUSTER_SEEDS[0][2]
        def fetch(seed, auth, deadline):
            ready.wait(timeout=1)
            name = seed[2]
            if name == first_name:
                # Model the first worker using the entire shared budget while
                # later workers have useful successful observations to return.
                now[0] = deadline
                return name, {"node": name, "status": "OFFLINE"}
            return name, {"node": name, "status": "OK", "cpu_max": 42}
        with patch.object(thermal.time, "monotonic", side_effect=lambda: now[0]), \
             patch.object(thermal, "fetch_node_telemetry", side_effect=fetch):
            fleet = thermal.get_fleet_telemetry(auth="test", timeout=1)
        self.assertEqual(fleet[first_name]["status"], "OFFLINE")
        for _, _, name in thermal.CLUSTER_SEEDS[1:]:
            self.assertEqual(fleet[name]["status"], "OK")
            self.assertEqual(fleet[name]["cpu_max"], 42)

    def test_thermal_worker_teardown_is_bounded(self):
        # A controlled socket stand-in, not a live network peer. Each receive
        # honors the timeout; repeated successful bytes must not extend it.
        created = []
        lock = threading.Lock()
        class TrickleSocket(FakeSocket):
            def recv(self, size):
                time.sleep(min(0.01, self.timeouts[-1]))
                return b"+"
        def connect(*args):
            fake = TrickleSocket()
            with lock:
                created.append(fake)
            return fake
        with patch.object(thermal, "_resp_socket", side_effect=connect):
            start = time.monotonic()
            fleet = thermal.get_fleet_telemetry(auth="test", timeout=0.05)
            elapsed = time.monotonic() - start
        self.assertLess(elapsed, 1.0)
        self.assertEqual(len(created), len(thermal.CLUSTER_SEEDS))
        self.assertTrue(all(s.closed for s in created))
        self.assertTrue(all(n["status"] == "OFFLINE" for n in fleet.values()))


class RedirectTests(unittest.TestCase):
    def test_redirect_cycle_bounded_for_moved_and_ask(self):
        host, port, _ = fan.CLUSTER_SEEDS[0]
        for kind in ("MOVED", "ASK"):
            pool = fan.QihsePool()
            conn = Mock()
            conn.command.return_value = ("err", f"{kind} 1 {host}:{port}")
            with patch.object(pool, "_conn_for", return_value=conn), \
                 patch.object(fan, "_local_ip_hint", return_value=host):
                with self.assertRaisesRegex(ConnectionError, "too many"):
                    pool.run(["GET", "x"])
            self.assertEqual(conn.command.call_count, 1 + pool.MAX_HOPS)
            calls = conn.command.call_args_list
            self.assertEqual(len({call.kwargs["deadline"] for call in calls}), 1)
            self.assertEqual(calls[-1].kwargs["asking"], kind == "ASK")

    def test_moved_then_ask_then_success(self):
        host, port, _ = fan.CLUSTER_SEEDS[0]
        pool = fan.QihsePool()
        conn = Mock()
        conn.command.side_effect = [("err", f"MOVED 1 {host}:{port}"),
                                    ("err", f"ASK 1 {host}:{port}"), ("bulk", "result")]
        with patch.object(pool, "_conn_for", return_value=conn), \
             patch.object(fan, "_local_ip_hint", return_value=host):
            self.assertEqual(pool.run(["GET", "x"]), ("bulk", "result"))
        self.assertFalse(conn.command.call_args_list[1].kwargs["asking"])
        self.assertTrue(conn.command.call_args_list[2].kwargs["asking"])

    def test_asking_precedes_command_on_same_authenticated_connection(self):
        fake = FakeSocket(b"+OK\r\n+OK\r\n$3\r\nabc\r\n")
        conn = fan.QihseConnection("127.0.0.1", 7100)
        with patch.object(fan, "_resp_socket", return_value=fake), \
             patch.object(conn, "_load_machine_token", return_value="test-token"):
            self.assertEqual(conn.command(["GET", "x"], asking=True), ("bulk", "abc"))
        self.assertIn(b"MACHINEAUTH", fake.sent[0])
        self.assertEqual(fake.sent[1], fan._encode_command(["ASKING"]))
        self.assertEqual(fake.sent[2], fan._encode_command(["GET", "x"]))
        conn.close()

    def test_asking_refusal_never_sends_original_command(self):
        conn = fan.QihseConnection("127.0.0.1", 7100)
        sockets = [FakeSocket(b"+OK\r\n-ERR refused\r\n") for _ in range(2)]
        with patch.object(fan, "_resp_socket", side_effect=sockets), \
             patch.object(fan.time, "sleep"), \
             patch.object(conn, "_load_machine_token", return_value="test-token"):
            with self.assertRaisesRegex(ConnectionError, "ASKING refused"):
                conn.command(["GET", "x"], asking=True)
        for fake in sockets:
            self.assertEqual(len(fake.sent), 2)
            self.assertTrue(fake.closed)
            self.assertEqual(fake.sent[-1], fan._encode_command(["ASKING"]))

    def test_ipv6_redirect_parser(self):
        self.assertEqual(fan._parse_redirect("MOVED 1 [::1]:7100"), (1, "::1", 7100))
        self.assertEqual(fan._parse_redirect("ASK 1 ::1:7100"), (1, "::1", 7100))

    def test_redirect_does_not_restart_deadline(self):
        host, port, _ = fan.CLUSTER_SEEDS[0]
        now = [0.0]
        conn = Mock()
        def redirect(*args, **kwargs):
            now[0] += 0.6
            return "err", f"MOVED 1 {host}:{port}"
        conn.command.side_effect = redirect
        pool = fan.QihsePool(timeout=1)
        with patch.object(fan.time, "monotonic", side_effect=lambda: now[0]), \
             patch.object(pool, "_conn_for", return_value=conn), \
             patch.object(fan, "_local_ip_hint", return_value=host):
            with self.assertRaises(TimeoutError):
                pool.run(["GET", "x"])
        self.assertEqual(conn.command.call_count, 2)
        self.assertEqual([c.kwargs["deadline"] for c in conn.command.call_args_list], [1, 1])


if __name__ == "__main__":
    unittest.main()
