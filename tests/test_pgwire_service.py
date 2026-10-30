"""Executable fail-closed gate for the standalone pgwire service.

Missing prerequisites (do not replace with mocked success hooks):
* qihse_auth.h has no durable principal/verifier recovery API. The verified
  replay snapshot in core/qihse_principal_startup_replay.h explicitly does NOT
  publish authentication state or grant listener readiness (lines 7-12).
  docs/architecture/auth_persistence.md forbids persisted verifiers.
* include/qihse_pg_wire.h:78-87 accepts a PEM chain and key but provides no
  client trust/hostname verification enforcement or server identity guarantee.
  Its contract explicitly delegates identity verification to clients.
* include/qihse_uwp_sql_txn_schema.h:47-56 binds durable SQL rows/catalog,
  not the auth registry or its generation.
Until these interfaces exist, no compile flag may enable this service.
"""

import os
from pathlib import Path
import socket
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "tools" / "qihse_pgwire_service.c"

CONFIG = ("--enable-production", "--store", "state", "--cert", "cert.pem",
          "--key", "key.pem")


class PgwireServiceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.dir = Path(cls.temp.name)
        cls.disabled = cls.dir / "disabled"
        cls.flagged = cls.dir / "flagged"
        cc = os.environ.get("CC", "cc")
        base = [cc, "-std=c11", "-Wall", "-Wextra", "-Werror", str(SOURCE)]
        subprocess.run(base + ["-o", str(cls.disabled)], check=True)
        subprocess.run(base + ["-DQIHSE_PGWIRE_DURABLE_BACKEND_READY",
                               "-o", str(cls.flagged)], check=True)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def invoke(self, binary, *args, env=None):
        return subprocess.run([str(binary), *args], capture_output=True,
                              text=True, timeout=5, env=env)

    def test_missing_config_and_invalid_ports(self):
        self.assertEqual(self.invoke(self.disabled).returncode, 2)
        for port in ("0", "65536", "-1", "12junk", ""):
            with self.subTest(port=port):
                result = self.invoke(self.disabled, "--store", "state", "--cert",
                                     "cert.pem", "--key", "key.pem", "--port", port)
                self.assertEqual(result.returncode, 2)

    def test_operator_config_safety(self):
        config = CONFIG[1:]
        for args in (config, (*CONFIG, "--bind", "0.0.0.0"),
                     (*CONFIG, "--bind", "localhost"),
                     (*CONFIG, "--port", "5433", "--port", "5432"),
                     (*CONFIG, "--key", "other.pem"),
                     (*CONFIG, "--store", "cert.pem"),
                     ("--enable-production", "--store", "state", "--cert", "cert.pem",
                      "--key", "cert.pem")):
            with self.subTest(args=args):
                self.assertEqual(self.invoke(self.disabled, *args).returncode, 2)

    def test_real_missing_interfaces(self):
        auth = (ROOT / "include/qihse_auth.h").read_text()
        replay = (ROOT / "core/qihse_principal_startup_replay.h").read_text()
        listener = (ROOT / "include/qihse_pg_wire.h").read_text()
        sql = (ROOT / "include/qihse_uwp_sql_txn_schema.h").read_text()
        self.assertNotIn("qihse_auth_open_durable", auth)
        self.assertNotIn("qihse_auth_recover_durable", auth)
        self.assertIn("does not publish auth state or grant listener readiness", replay)
        self.assertIn("Clients must verify the certificate identity/chain themselves", listener)
        self.assertNotIn("trusted_ca", listener)
        self.assertNotIn("expected_server_identity", listener)
        self.assertIn("qihse_uwp_sql_open_durable", sql)
        self.assertNotIn("auth", sql.split("int qihse_uwp_sql_open_durable")[1].split(";")[0])

    def test_default_and_override_refuse_even_with_poison_and_shutdown(self):
        for binary in (self.disabled, self.flagged):
            for poison in (False, True):
                with self.subTest(binary=binary, poison=poison):
                    env = {**os.environ, "TEST_POISON_AFTER_ACCEPT": "1"} if poison else None
                    result = self.invoke(binary, *CONFIG, env=env)
                    self.assertEqual(result.returncode, 1, result.stderr)
                    self.assertIn("refusing listener", result.stderr)
                    self.assertNotIn("TLS_OPEN", result.stderr)
                    self.assertNotIn("CLOSE=", result.stderr)
        # Refusal is an immediate shutdown: no store side effects or bound port.
        # Poisoned state cannot leak to a fresh invocation.
        with tempfile.TemporaryDirectory() as scratch:
            store = Path(scratch) / "new-store"
            with socket.socket() as probe:
                probe.bind(("127.0.0.1", 0))
                port = probe.getsockname()[1]
            args = ("--enable-production", "--store", str(store), "--cert",
                    "cert.pem", "--key", "key.pem", "--port", str(port))
            result = self.invoke(self.flagged, *args)
            self.assertEqual(result.returncode, 1)
            self.assertFalse(store.exists())
            with socket.socket() as probe:
                probe.bind(("127.0.0.1", port))
            self.assertIn("refusing listener", result.stderr)


if __name__ == "__main__":
    unittest.main()
