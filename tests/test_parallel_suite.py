"""Manifest and scheduling invariants for the complete parallel suite."""

import os
import re
import stat
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from run_gold_parallel import run_one
from run_parallel_suite import ROOT, SAFE, plan, run_target, test_targets


class ParallelSuiteTests(unittest.TestCase):
    def test_all_current_prerequisites_are_scheduled_exactly_once(self):
        makefile = (ROOT / "Makefile").read_text()
        self.assertEqual([line for line in makefile.splitlines()
                          if re.match(r"^test\s*:", line)], ["test: test-parallel"])
        targets = test_targets(makefile)
        parallel, serial = plan(targets)
        self.assertEqual(set(parallel) | set(serial), set(targets))
        self.assertEqual(len(parallel) + len(serial), len(targets))
        self.assertEqual(set(parallel), SAFE)
        self.assertEqual(serial[-1], "test-gold")
        self.assertIn("test-pgwire-app-compat", serial)
        self.assertIn("test-aimem-knowledge", serial)
        self.assertIn("test-aimem-idem-migration", serial)
        self.assertIn("test-python-aimem-sdk", serial)
        self.assertIn("test-hax-recall-fixture", serial)

    def test_admin_cli_builds_standalone_service(self):
        makefile = (ROOT / "Makefile").read_text()
        prerequisites = re.search(r"^test-admin-cli:\s*([^\n]*)", makefile, re.M)
        self.assertIsNotNone(prerequisites)
        self.assertIn("redis-server", prerequisites.group(1).split())

    def test_complete_schedule_fences_standalone_service(self):
        makefile = (ROOT / "Makefile").read_text()
        prerequisites = re.search(r"^test-parallel:\s*([^\n]*)", makefile, re.M)
        self.assertIsNotNone(prerequisites)
        self.assertTrue({"lib", "admin-cli", "redis-server", "cluster-daemon"}
                        .issubset(prerequisites.group(1).split()))
        parallel, serial = plan(test_targets(makefile))
        self.assertNotIn("test-admin-cli", parallel)
        self.assertEqual(serial.count("test-admin-cli"), 1)

    def test_public_install_builds_backup_artifact(self):
        makefile = (ROOT / "Makefile").read_text()
        for target in ("install-runtime", "test-public-api-install"):
            with self.subTest(target=target):
                prerequisites = re.search(rf"^{target}:\s*([^\n]*)", makefile, re.M)
                self.assertIsNotNone(prerequisites)
                self.assertIn("backup-cli", prerequisites.group(1).split())
                self.assertNotIn("qihse-backup", prerequisites.group(1).split())

    def test_new_target_is_serial_without_approval(self):
        parallel, serial = plan([*sorted(SAFE), "test-new-adapter", "test-gold"])
        self.assertNotIn("test-new-adapter", parallel)
        self.assertIn("test-new-adapter", serial)

    def test_missing_or_duplicate_targets_refuse_execution(self):
        with self.assertRaises(ValueError):
            test_targets("test-serial: test-one test-one\n")
        with self.assertRaises(ValueError):
            plan(["test-new-adapter", "test-gold"])
        with self.assertRaises(ValueError):
            test_targets("test-serial: $(UNKNOWN)\n")

    def test_continuation_and_repeated_rules(self):
        targets = test_targets("test-serial: test-one \\\n    test-two\ntest-serial: test-three\n")
        self.assertEqual(targets, ["test-one", "test-two", "test-three"])

    def test_target_gets_private_temporary_key_directory(self):
        captured = {}

        def fake_run(command, *, cwd, env, stdout, stderr, check):
            key_dir = Path(env["QIHSE_KEY_DIR"])
            captured.update(command=command, key_dir=key_dir,
                            mode=stat.S_IMODE(key_dir.stat().st_mode))
            return SimpleNamespace(returncode=0)

        with tempfile.TemporaryDirectory(prefix="suite-test-logs-") as logs:
            with patch.dict(os.environ, {"QIHSE_KEY_DIR": "/etc/qihse/keys"}), \
                 patch("run_parallel_suite.subprocess.run", side_effect=fake_run):
                result = run_target("test-probe", Path(logs))
        self.assertEqual(result[1], 0)
        self.assertEqual(captured["mode"], 0o700)
        self.assertNotEqual(str(captured["key_dir"]), "/etc/qihse/keys")
        self.assertFalse(captured["key_dir"].exists())

    def test_gold_workload_gets_private_temporary_key_directory(self):
        captured = {}

        def fake_run(command, *, cwd, env, stdout, stderr, check):
            key_dir = Path(env["QIHSE_KEY_DIR"])
            captured.update(command=command, key_dir=key_dir,
                            mode=stat.S_IMODE(key_dir.stat().st_mode))
            return SimpleNamespace(returncode=0)

        with tempfile.TemporaryDirectory(prefix="gold-test-keys-") as key_tmp, \
             tempfile.TemporaryDirectory(prefix="gold-test-work-", dir=ROOT / "build") as work:
            with patch.dict(os.environ, {"QIHSE_KEY_DIR": "/etc/qihse/keys"}), \
                 patch("run_gold_parallel.subprocess.run", side_effect=fake_run):
                result = run_one(("test-probe", {"area": "unit"}, "workload test-probe"),
                                 {"unit": "area unit"}, Path(work), Path(key_tmp), 1, "unit")
            self.assertEqual(result[1], 0)
            self.assertEqual(captured["mode"], 0o700)
            self.assertNotEqual(str(captured["key_dir"]), "/etc/qihse/keys")
            self.assertTrue(captured["key_dir"].is_dir())


if __name__ == "__main__":
    unittest.main()
