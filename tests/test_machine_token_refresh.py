"""Fleet token refresh regression tests; all keys and credentials are synthetic.

Run after `make lib`: python3 tests/test_machine_token_refresh.py
The real mint test compiles the current CLI and verifies its ML-DSA signature.
"""
import os
from pathlib import Path
import stat
import struct
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "tools/fleet/refresh-machine-token.sh"


class MachineTokenRefreshTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory(prefix="qihse-refresh-test-")
        self.addCleanup(self.scratch.cleanup)
        self.directory = Path(self.scratch.name)
        self.prefix = self.directory / "prefix with spaces"
        (self.prefix / "bin").mkdir(parents=True)
        (self.prefix / "lib").mkdir()
        self.identity = self.directory / "synthetic-key.pem"
        self.identity.write_text("not a live key\n")
        self.output = self.directory / "machine_token"
        self.output.write_bytes(b"old synthetic credential\n")
        self.output.chmod(0o640)
        self.binary = self.prefix / "bin/qihse-machine-token"
        self.env = {key: value for key, value in os.environ.items()
                    if not key.startswith("QIHSE_")}
        self.env.update(QIHSE_PREFIX=str(self.prefix),
                        QIHSE_MACHINE_IDENTITY=str(self.identity),
                        QIHSE_MACHINE_TOKEN=str(self.output),
                        QIHSE_MACHINE_USER_ID="314", QIHSE_MACHINE_TENANT="271")

    def test_installer_refuses_checkout_prefix(self):
        result = subprocess.run(["bash", str(ROOT / "scripts/install_qihse.sh"),
            "--prefix", str(ROOT), "--dry-run", "--no-scan", "--solo",
            "--non-interactive", "--no-service", "--no-launch", "--no-clean"],
            env={**os.environ, "QIHSE_OPERATOR_PASSWORD": ""},
            capture_output=True, text=True, timeout=30)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Installation prefix is the source checkout", result.stderr)

    def refresh(self):
        result = subprocess.run(["/bin/sh", str(HELPER)], env=self.env,
                                capture_output=True, timeout=75)
        self.assertEqual(result.stdout, b"")
        self.assertNotIn(b"synthetic-secret", result.stderr)
        self.assertEqual(list(self.directory.glob(".machine-token-*")), [])
        return result

    def preserved(self, inode):
        self.assertEqual(self.output.read_bytes(), b"old synthetic credential\n")
        self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o640)
        self.assertEqual(self.output.stat().st_ino, inode)

    def fake_minter(self, source):
        self.binary.write_text("#!/bin/sh\n" + source + "\n")
        self.binary.chmod(0o755)

    def test_missing_required_configuration(self):
        for name in ("QIHSE_MACHINE_USER_ID", "QIHSE_MACHINE_TENANT", "QIHSE_PREFIX",
                     "QIHSE_MACHINE_IDENTITY", "QIHSE_MACHINE_TOKEN"):
            with self.subTest(name=name):
                value = self.env.pop(name)
                inode = self.output.stat().st_ino
                result = self.refresh()
                self.assertEqual(result.returncode, 2, result.stderr)
                self.preserved(inode)
                self.env[name] = value

    def test_invalid_principal_and_tenant(self):
        for name in ("QIHSE_MACHINE_USER_ID", "QIHSE_MACHINE_TENANT"):
            original = self.env[name]
            for value in ("", "0", "-1", "+1", "1x", "1.0", " 1", "01",
                          "4294967296", "999999999999999999999999"):
                with self.subTest(name=name, value=value):
                    self.env[name] = value
                    inode = self.output.stat().st_ino
                    self.assertEqual(self.refresh().returncode, 2)
                    self.preserved(inode)
            self.env[name] = original

    def test_relative_paths_are_rejected(self):
        for name in ("QIHSE_PREFIX", "QIHSE_MACHINE_IDENTITY", "QIHSE_MACHINE_TOKEN"):
            with self.subTest(name=name):
                original = self.env[name]
                self.env[name] = "relative-path"
                inode = self.output.stat().st_ino
                self.assertEqual(self.refresh().returncode, 2)
                self.preserved(inode)
                self.env[name] = original

    def test_failed_mint_preserves_old_file_and_mode(self):
        self.fake_minter("printf synthetic-secret; printf synthetic-secret >&2; exit 2")
        inode = self.output.stat().st_ino
        self.assertEqual(self.refresh().returncode, 1)
        self.preserved(inode)

    def test_malformed_success_preserves_old_file(self):
        for data in ("", "a", "NOTHEX", "aa\\nbb"):
            with self.subTest(data=data):
                self.fake_minter("printf '" + data + "\\n'")
                inode = self.output.stat().st_ino
                self.assertEqual(self.refresh().returncode, 1)
                self.preserved(inode)

    def test_missing_executable_preserves_old_file(self):
        inode = self.output.stat().st_ino
        self.assertEqual(self.refresh().returncode, 1)
        self.preserved(inode)

    def test_refuses_identity_as_output_including_hardlink(self):
        for hardlink in (False, True):
            with self.subTest(hardlink=hardlink):
                if hardlink:
                    self.output.unlink()
                    os.link(self.identity, self.output)
                    self.env["QIHSE_MACHINE_TOKEN"] = str(self.output)
                else:
                    self.env["QIHSE_MACHINE_TOKEN"] = str(self.identity)
                self.assertEqual(self.refresh().returncode, 2)
                self.assertEqual(self.identity.read_text(), "not a live key\n")

    def test_refuses_symlink_and_shared_writable_directory(self):
        self.output.unlink()
        self.output.symlink_to(self.identity)
        self.assertEqual(self.refresh().returncode, 2)
        self.output.unlink()
        self.directory.chmod(0o777)
        self.addCleanup(self.directory.chmod, 0o700)
        self.assertEqual(self.refresh().returncode, 2)
        self.assertFalse(self.output.exists())

    def test_successful_replacement_is_private_and_atomic(self):
        self.fake_minter("test \"$(stat -Lc %a /proc/$$/fd/1)\" = 600 || exit 4\nprintf 'aabb\\n'")
        with self.output.open("rb") as old_reader:
            self.assertEqual(self.refresh().returncode, 0)
            self.assertEqual(old_reader.read(), b"old synthetic credential\n")
        self.assertEqual(self.output.read_bytes(), b"aabb\n")
        self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o600)

    def test_real_mint_with_synthetic_mldsa_key(self):
        def run(args):
            result = subprocess.run(args, capture_output=True, timeout=60)
            self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
            return result

        # Never use an installed minter or keys: compile the current source into
        # the temporary prefix, and generate a fresh ML-DSA-87 key there.
        run(["cc", "-std=c99", "-I" + str(ROOT / "include"), "-I" + str(ROOT),
             str(ROOT / "tools/qihse_machine_token.c"), "-L" + str(ROOT),
             "-lqihse", "-lcrypto", "-o", str(self.binary)])
        (self.prefix / "lib/libqihse.so").symlink_to(ROOT / "libqihse.so")
        run(["openssl", "genpkey", "-algorithm", "ML-DSA-87", "-out", str(self.identity)])
        self.assertEqual(self.refresh().returncode, 0)
        self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o600)
        token = bytes.fromhex(self.output.read_text().strip())
        self.assertEqual(len(token), 140 + 4627)
        self.assertEqual(struct.unpack_from("<H", token, 10)[0], 4)  # MACHINE
        self.assertEqual(struct.unpack_from("<IIHHI", token, 16), (0, 314, 0, 0, 271))
        issued, expires = struct.unpack_from("<QQ", token, 72)
        self.assertEqual(expires - issued, 86400000)
        region, signature = self.directory / "region", self.directory / "signature"
        region.write_bytes(token[:140])
        signature.write_bytes(token[140:])
        public = self.directory / "public.pem"
        run(["openssl", "pkey", "-in", str(self.identity), "-pubout", "-out", str(public)])
        run(["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", str(public),
             "-rawin", "-in", str(region), "-sigfile", str(signature)])
        # A real CLI key-load failure must not destroy the previously minted token.
        previous, inode = self.output.read_bytes(), self.output.stat().st_ino
        self.identity.write_text("invalid synthetic key\n")
        self.assertEqual(self.refresh().returncode, 1)
        self.assertEqual(self.output.read_bytes(), previous)
        self.assertEqual(self.output.stat().st_ino, inode)
        self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o600)


if __name__ == "__main__":
    unittest.main(verbosity=2)
