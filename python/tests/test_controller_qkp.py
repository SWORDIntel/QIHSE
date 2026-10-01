#!/usr/bin/env python3
"""Python SDK over QKP1 — W7 item 4.

Spawns a real --pqc-require cluster daemon (same harness shape as
tests/test_pqc_handshake.c), generates identities through the library's
own keygen (ctypes), and drives the pure-Python controller SDK entirely
inside the sealed transport: connect, AUTH, SET/GET, and a FEDERATION
wrapper — proving the bounded parser and typed wrappers are unaffected by
framing.

Run from the repo root:
  LD_LIBRARY_PATH=. PYTHONPATH=python python3 python/tests/test_controller_qkp.py
"""

from __future__ import annotations

import ctypes
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(REPO, "python"))

PORT = 7396
BUS = 17396
PW = "PythonQkpPass1234!"

_lib = ctypes.CDLL(os.environ.get("QIHSE_LIB", os.path.join(REPO, "libqihse.so")))
_lib.qihse_pqc_keygen.argtypes = [ctypes.c_char_p]
_lib.qihse_pqc_keygen.restype = ctypes.c_bool


def wait_port(port: int, timeout_s: float = 15.0) -> bool:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.25)
    return False


class QKPSDKTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="pyqkp_", dir=os.path.join(REPO, "build"))
        cls.srv = os.path.join(cls.tmp, "srv")
        cls.cli = os.path.join(cls.tmp, "cli")
        for d in (cls.srv, cls.cli):
            os.makedirs(d, exist_ok=True)
            assert _lib.qihse_pqc_keygen(d.encode()), f"keygen failed for {d}"
        srv_pub = os.path.join(cls.srv, "qihse_dsa_pub.pem")
        cli_pub = os.path.join(cls.cli, "qihse_dsa_pub.pem")
        cls.daemon = subprocess.Popen(
            [os.path.join(REPO, "qihse-cluster-daemon"),
             "--index", "0", "--bind", "127.0.0.1", "--port", str(PORT),
             "--bus-port", str(BUS), "--dir", cls.srv,
             "--operator-password", PW,
             "--pqc-identity-dir", cls.srv,
             "--pqc-trusted-pub", srv_pub,
             "--pqc-trusted-pub", cli_pub,
             "--pqc-require"],
            cwd=REPO, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if not wait_port(PORT):
            cls.daemon.kill()
            raise RuntimeError("sealed daemon did not come up")

    @classmethod
    def tearDownClass(cls):
        cls.daemon.send_signal(signal.SIGKILL)
        cls.daemon.wait()
        for _ in range(5):
            try:
                shutil.rmtree(cls.tmp)
                break
            except OSError:
                time.sleep(0.2)

    def test_sealed_roundtrip(self):
        from qihse.controller import Controller, ControllerConnectionError

        with Controller("127.0.0.1", PORT,
                        username="GODMODE_OP", password=PW,
                        timeout_ms=20000,
                        qkp_identity_dir=self.cli,
                        qkp_trusted_pubs=[os.path.join(self.srv,
                                                       "qihse_dsa_pub.pem")]) as c:
            self.assertTrue(c.connected)
            r = c.call("SET", "pyqkp:probe", "sealed-from-python")
            self.assertTrue(r.is_ok())
            r = c.call("GET", "pyqkp:probe")
            self.assertEqual(r.value, b"sealed-from-python")
            # a typed federation wrapper through the sealed parser
            r = c.call("FEDERATION", "STATUS")
            self.assertIn(r.kind, ("bulk", "array", "simple"))

    def test_cleartext_refused(self):
        from qihse.controller import Controller, ControllerError
        with self.assertRaises(ControllerError):
            Controller("127.0.0.1", PORT,
                       username="GODMODE_OP", password=PW,
                       timeout_ms=8000)

    def test_rogue_identity_rejected(self):
        from qihse.controller import Controller, ControllerError
        rogue = os.path.join(self.tmp, "rogue")
        os.makedirs(rogue, exist_ok=True)
        assert _lib.qihse_pqc_keygen(rogue.encode())
        with self.assertRaises(ControllerError):
            Controller("127.0.0.1", PORT,
                       username="GODMODE_OP", password=PW,
                       timeout_ms=15000,
                       qkp_identity_dir=rogue,
                       qkp_trusted_pubs=[os.path.join(self.srv,
                                                      "qihse_dsa_pub.pem")])


if __name__ == "__main__":
    unittest.main(verbosity=2)
