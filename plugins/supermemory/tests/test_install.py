"""Installer preflight must not downgrade QKP or rewrite protected credentials."""
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import install  # noqa: E402
import sync  # noqa: E402


class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.qihse = self.root / "qihse"
        self.qihse.mkdir()
        (self.qihse / "libqihse.so").write_bytes(b"test")
        self.env_file = self.root / "env"
        self.env = {
            "QIHSE_DIR": str(self.qihse),
            "QIHSE_AIMEM_ENV": str(self.env_file),
            "QIHSE_RESP_HOST": "127.0.0.1",
            "QIHSE_RESP_PORT": "6401",
            "QIHSE_AUTH_USER": "AIMEM_SERVICE",
            "QIHSE_AUTH_PASSWORD": "test-service-password",
            "QIHSE_AIMEM_TRANSPORT": "qkp",
            "QIHSE_ADMIN_SDK": "sdk.py",
            "QIHSE_ADMIN_LIB": "lib.so",
            "QIHSE_ADMIN_CLI": "admin-cli",
            "QIHSE_AIMEM_IDENTITY_DIR": "identity",
            "QIHSE_AIMEM_TRUSTED_PUB": "server.pub",
            "QIHSE_AIMEM_NODE_ID": "client-id",
        }

    def test_existing_config_preserved_and_pin_checked(self):
        original = "".join(f"{key}={value}\n" for key, value in self.env.items()
                           if key not in ("QIHSE_DIR", "QIHSE_AIMEM_ENV"))
        original += "QIHSE_AIMEM_SERVICE_PASSWORD=bootstrap-must-remain\n"
        self.env_file.write_text(original)
        self.env_file.chmod(0o600)
        session = mock.Mock()
        with (mock.patch.dict(os.environ, self.env, clear=True),
              mock.patch.object(install.subprocess, "run") as service,
              mock.patch.object(sync, "_qihse_connect", return_value=session) as connect,
              mock.patch.object(sync, "_qihse_command", return_value="PONG") as ping,
              mock.patch.object(install.socket, "create_connection") as cleartext):
            service.return_value.returncode = 1
            creds = install.detect_qihse()
            self.assertEqual(creds["QIHSE_AIMEM_TRANSPORT"], "qkp")
            connect.assert_called_once_with()
            ping.assert_called_once_with(session, "PING")
            session.close.assert_called_once_with()
            cleartext.assert_not_called()
        self.assertEqual(self.env_file.read_text(), original)
        self.assertEqual(stat.S_IMODE(self.env_file.stat().st_mode), 0o600)

    def test_default_transport_does_not_open_cleartext(self):
        env = dict(self.env)
        env.pop("QIHSE_AIMEM_TRANSPORT")
        env.pop("QIHSE_AIMEM_TRUSTED_PUB")
        with (mock.patch.dict(os.environ, env, clear=True),
              mock.patch.object(sync.socket, "create_connection") as cleartext):
            with self.assertRaisesRegex(RuntimeError, "QKP requires"):
                sync._qihse_connect()
            cleartext.assert_not_called()

    def test_missing_pin_and_explicit_resp_fail_before_install(self):
        for change in ({"QIHSE_AIMEM_TRUSTED_PUB": ""},
                       {"QIHSE_AIMEM_TRANSPORT": "resp"}):
            env = self.env | change
            with (self.subTest(change=change), mock.patch.dict(os.environ, env, clear=True),
                  mock.patch.object(install.subprocess, "run") as service,
                  mock.patch.object(install.socket, "create_connection") as cleartext,
                  mock.patch.object(sync, "_qihse_connect") as connect):
                service.return_value.returncode = 1
                with self.assertRaises(SystemExit):
                    install.detect_qihse()
                connect.assert_not_called()
                cleartext.assert_not_called()
                self.assertFalse(self.env_file.exists())

    def test_hooks_install_only_from_current_qkp_sources(self):
        hooks = self.root / "hooks"
        result = install.install_hook_scripts(hooks, ROOT)
        self.assertEqual((hooks / "aimem_client.py").read_bytes(),
                         (ROOT / "zcode-hooks" / "aimem_client.py").read_bytes())
        self.assertEqual((hooks / "supermemory-bridge").read_bytes(),
                         (ROOT / "supermemory-bridge").read_bytes())
        self.assertIn("recall_hook.py", result)
        missing = self.root / "missing"
        with self.assertRaisesRegex(RuntimeError, "QKP hook sources missing"):
            install.install_hook_scripts(self.root / "no-hooks", missing)
        self.assertFalse((self.root / "no-hooks").exists())

    def test_new_config_is_private_and_qkp_failure_leaves_no_file(self):
        with (mock.patch.dict(os.environ, self.env, clear=True),
              mock.patch.object(install.subprocess, "run") as service,
              mock.patch.object(install.socket, "create_connection") as cleartext,
              mock.patch.object(sync, "_qihse_connect", side_effect=RuntimeError("pin refused"))):
            service.return_value.returncode = 1
            with self.assertRaises(SystemExit):
                install.detect_qihse()
            self.assertFalse(self.env_file.exists())
            cleartext.assert_not_called()

        session = mock.Mock()
        with (mock.patch.dict(os.environ, self.env, clear=True),
              mock.patch.object(install.subprocess, "run") as service,
              mock.patch.object(sync, "_qihse_connect", return_value=session),
              mock.patch.object(sync, "_qihse_command", return_value="PONG")):
            service.return_value.returncode = 1
            install.detect_qihse()
        self.assertEqual(stat.S_IMODE(self.env_file.stat().st_mode), 0o600)
        self.assertIn("QIHSE_AIMEM_TRUSTED_PUB=server.pub", self.env_file.read_text())
        self.assertNotIn("QIHSE_OPERATOR_PASSWORD", self.env_file.read_text())


if __name__ == "__main__":
    unittest.main()
