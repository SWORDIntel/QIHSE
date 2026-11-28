"""Focused, isolated checks for the versioned owner-only systemd configuration."""

from pathlib import Path
import shlex
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import owner_only_unit as units


class OwnerOnlyUnitTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.data = self.root / "qihse-data"
        self.data.mkdir()
        for _, _, _, _, _, suffix, _ in units.OWNERS.values():
            (self.data / suffix).mkdir(parents=True)
        self.runtime = self.root / "QIHSE"
        (self.runtime / "bin").mkdir(parents=True)
        (self.runtime / "lib").mkdir()
        (self.runtime / "bin/qihse-cluster-daemon").touch()
        self.daemon = str(self.runtime / "bin/qihse-cluster-daemon")

    def original(self, label):
        _, index, host, port, bus, _, _ = units.OWNERS[label]
        prefix = [self.daemon] if label != "b" else [
            shutil.which("env"), "LD_LIBRARY_PATH=" + str(self.runtime / "lib"), self.daemon]
        return prefix + ["--index", str(index), "--bind", host, "--port", str(port),
                         "--bus-port", str(bus), "--dir", str(self.root / "original"),
                         "--ct-role", "primary", "--ct-peer", "peer:7000",
                         "--replica-of", "1:0", "--pqc-require",
                         "--pqc-trusted-pub", str(self.root / "trusted.pem"),
                         "--migration-peer", "recovery-a-successor", "pin",
                         "--migration-peer", "192.168.1.90", "owner-pin",
                         "--topology-qkp-map", "old-replica-id", "recovery-a-successor",
                         "--topology-qkp-map", "owner-id", "192.168.1.90",
                         "--node", "1:peer:7000:17000", "--slot-range", "0-16383"]

    def test_three_hosts_preserve_security_and_map_exact_slots(self):
        for label in units.OWNERS:
            with self.subTest(label=label):
                config = units.render(label, self.original(label), self.data)
                self.assertIn("--pqc-require", config)
                self.assertIn("--pqc-trusted-pub", config)
                self.assertIn("--slot-range-of 7:5041-5460", config)
                self.assertIn("--slot-range-of 6:5040-5040", config)
                self.assertIn("--slot-range " + units.OWNERS[label][-1], config)
                self.assertNotIn("--ct-role", config)
                self.assertNotIn("--replica-of", config)
                self.assertNotIn("recovery-a-successor", config)
                self.assertIn("192.168.1.90", config)
                _, index, host, port, bus, suffix, slots = units.OWNERS[label]
                prefix = [self.daemon] if label != "b" else [
                    shutil.which("env"), "LD_LIBRARY_PATH=" + str(self.runtime / "lib"), self.daemon]
                expected = prefix + ["--index", str(index), "--bind", host, "--port", str(port),
                                     "--bus-port", str(bus), "--dir", str(self.data / suffix),
                                     "--pqc-require", "--pqc-trusted-pub", str(self.root / "trusted.pem"),
                                     "--migration-peer", "192.168.1.90", "owner-pin",
                                     "--topology-qkp-map", "owner-id", "192.168.1.90"]
                for peer in ("a", "b", "c"):
                    _, peer_index, peer_host, peer_port, peer_bus, _, peer_slots = units.OWNERS[peer]
                    expected += ["--node", f"{peer_index}:{peer_host}:{peer_port}:{peer_bus}"]
                    if peer != label:
                        expected += ["--slot-range-of", f"{peer_index}:{peer_slots}"]
                expected += ["--node", "7:192.168.1.91:7100:17100", "--slot-range-of", "7:5041-5460",
                             "--node", "6:192.168.1.90:7115:17115", "--slot-range-of", "6:5040-5040",
                             "--slot-range", slots]
                self.assertEqual(config, "[Service]\nExecStart=\nExecStart=" +
                                 " ".join(shlex.quote(arg) for arg in expected) + "\n")
                self.assertEqual(config, units.render(label, shlex.split(config.splitlines()[-1][10:]), self.data))

    def test_rejects_unreviewed_flags_and_ct_markers(self):
        argv = self.original("a")
        with self.assertRaisesRegex(ValueError, "unreviewed"):
            units.render("a", argv + ["--operator-password", "plaintext"], self.data)
        with self.assertRaisesRegex(ValueError, "unrecognized owner peer"):
            units.render("a", argv + ["--migration-peer", "unknown-client", "pin"], self.data)
        marker = self.data / units.OWNERS["a"][5] / "ct-state.bin"
        marker.touch()
        with self.assertRaisesRegex(ValueError, "CT-disabled"):
            units.render("a", argv, self.data)

    def test_check_and_install_only_replace_inert_unit_file(self):
        argv = self.original("a")
        unit = units.OWNERS["a"][0]
        fragment = self.root / unit
        fragment.touch()
        effective = "ExecStart={ argv[]=" + " ".join(shlex.quote(x) for x in argv) + " ; ignore_errors=no }"
        states = {}
        def systemctl(args, **kwargs):
            prop, name = args[-2:]
            if prop == "ExecStart":
                return effective
            if prop == "FragmentPath":
                return str(fragment) + "\n"
            if prop == "ActiveState":
                return states.get(name, "active" if name == unit else "inactive")
            if prop == "UnitFileState":
                return "enabled" if name == unit else "disabled"
            raise AssertionError(args)
        with patch.object(units.subprocess, "check_output", side_effect=systemctl), \
             patch.object(units.subprocess, "run") as reload, \
             patch.object(units, "__file__", str(Path(Path.cwd().anchor) / "unit.py")):
            self.assertEqual(units.main(["a", "--install", "--data-root", str(self.data)]), 0)
            reload.assert_called_once_with(["systemctl", "daemon-reload"], check=True)
            self.assertEqual(units.main(["a", "--check", "--data-root", str(self.data)]), 0)
            self.assertEqual(units.main(["a", "--install", "--data-root", str(self.data)]), 0)
            self.assertEqual(reload.call_count, 1)
            states[units.OTHER_UNITS["a"][0]] = "active"
            with self.assertRaisesRegex(ValueError, "CT/namespace service"):
                units.main(["a", "--check", "--data-root", str(self.data)])


if __name__ == "__main__":
    unittest.main()
