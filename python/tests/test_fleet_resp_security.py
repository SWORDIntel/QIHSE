"""Negative protocol/redirect/credential tests for the isolated fan agents."""
import importlib.util
import io
import os
from pathlib import Path
import unittest
from unittest.mock import patch

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
    def settimeout(self, seconds): pass
    def makefile(self, mode): return self.reply
    def sendall(self, data): self.sent.append(data)
    def close(self): pass

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

if __name__ == "__main__":
    unittest.main()
