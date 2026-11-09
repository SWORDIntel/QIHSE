#!/usr/bin/env python3
"""Exercise the current HAX AIMEM client against a disposable QIHSE listener.

Set HAX_SOURCE_ROOT to the HAX checkout. Build libqihse.so first. This test
creates its own authenticated server and never accesses a configured QIHSE
store, installed service, or real credentials.
"""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import select
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
LIB_ROOT = Path(os.environ.get("QIHSE_TEST_LIB_ROOT", ROOT)).resolve()
SCOPE = ("hax-compat", "", "", "")


class HaxAimemCompatTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        source_root = os.environ.get("HAX_SOURCE_ROOT")
        if not source_root:
            raise unittest.SkipTest("set HAX_SOURCE_ROOT to the HAX checkout")
        script = Path(source_root).resolve() / "scripts" / "memory_hooks.py"
        if not script.is_file():
            raise AssertionError("HAX_SOURCE_ROOT lacks scripts/memory_hooks.py")
        spec = importlib.util.spec_from_file_location("hax_aimem_live_contract", script)
        if not spec or not spec.loader:
            raise AssertionError("cannot load the HAX memory client")
        cls.hax = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.hax)

        if not (LIB_ROOT / "libqihse.so").is_file():
            raise AssertionError("build libqihse.so before running this probe")
        cls.temp = tempfile.TemporaryDirectory(prefix="hax-qihse-compat-")
        cls.addClassCleanup(cls.temp.cleanup)
        base = Path(cls.temp.name)
        binary = base / "hax-aimem-compat-fixture"
        source = Path(__file__).with_name("hax_aimem_compat_fixture.c")
        build = subprocess.run(
            [os.environ.get("CC", "cc"), "-std=c99", "-D_GNU_SOURCE", "-O2",
             "-Wall", "-Wextra", "-Werror", "-I" + str(ROOT / "include"),
             "-I" + str(ROOT / "core"), str(source), "-L" + str(LIB_ROOT),
             "-lqihse", "-ldl", "-lm", "-lpthread", "-o", str(binary)],
            capture_output=True, text=True, timeout=60,
        )
        if build.returncode:
            raise AssertionError("native fixture compilation failed:\n" + build.stderr)
        data_dir = base / "data"
        data_dir.mkdir(mode=0o700)
        cls.fixture_log = (base / "fixture.log").open("w+")
        cls.addClassCleanup(cls.fixture_log.close)
        environment = os.environ.copy()
        environment["LD_LIBRARY_PATH"] = str(LIB_ROOT) + os.pathsep + environment.get("LD_LIBRARY_PATH", "")
        cls.fixture = subprocess.Popen(
            [str(binary), str(data_dir)], stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=cls.fixture_log, text=True,
            env=environment,
        )
        cls.addClassCleanup(cls._stop_fixture)
        ready, _, _ = select.select([cls.fixture.stdout], [], [], 30)
        if not ready:
            raise AssertionError("disposable AIMEM server did not become ready")
        line = cls.fixture.stdout.readline().strip()
        parts = line.split()
        if len(parts) != 4 or not parts[0].isdigit():
            cls.fixture_log.flush()
            raise AssertionError("disposable AIMEM server failed: " +
                                 (base / "fixture.log").read_text()[-2000:])
        cls.port, cls.visible_id, cls.classified_id, cls.sci_id = parts
        cls.env_file = base / "hax.env"
        cls.env_file.write_text(
            f"QIHSE_RESP_HOST=127.0.0.1\nQIHSE_RESP_PORT={cls.port}\n"
            "QIHSE_AUTH_USER=AIMEM_SERVICE\n"
            "QIHSE_AUTH_PASSWORD=SMFixtureLow123!\n"
            "QIHSE_AIMEM_TRANSPORT=resp\n", encoding="utf-8")
        cls.env_file.chmod(0o600)

    @classmethod
    def _stop_fixture(cls):
        if cls.fixture.poll() is None:
            cls.fixture.stdin.close()
            try:
                cls.fixture.wait(timeout=10)
            except subprocess.TimeoutExpired:
                cls.fixture.kill()
                cls.fixture.wait(timeout=10)
        cls.fixture.stdout.close()

    def setUp(self):
        self.env = mock.patch.dict(os.environ, {"QIHSE_AIMEM_ENV": str(self.env_file)}, clear=True)
        self.env.start()
        self.addCleanup(self.env.stop)
        self.client = self.hax.Aimem()
        self.addCleanup(self.client.close)

    def test_scoped_durable_store_replay_and_protected_reads(self):
        initial = self.client._command("AIMEM", "COUNT-SCOPED", *SCOPE, "2")
        self.assertEqual(initial, 1)
        visible = self.client._command("AIMEM", "GET-SCOPED", self.visible_id, *SCOPE)
        self.assertEqual(visible[6], "hax visible orchard")
        absent = self.client._command("AIMEM", "GET-SCOPED",
                                      "00000000-0000-0000-0000-000000000000", *SCOPE)
        for hidden_id in (self.classified_id, self.sci_id):
            self.assertEqual(self.client._command("AIMEM", "GET-SCOPED", hidden_id, *SCOPE), absent)
        self.assertIsNone(absent)
        hits = self.client.recall("orchard", 8, SCOPE)
        self.assertEqual([hit["id"] for hit in hits], [self.visible_id])
        for query in ("classified", "compartment"):
            # BM25 may return unrelated authorized records. The security
            # contract is that the protected records and payload stay hidden.
            for hit in self.client.recall(query, 8, SCOPE):
                self.assertNotIn(hit["id"], (self.classified_id, self.sci_id))
                self.assertNotIn("secret", hit["text"])
                self.assertEqual((hit["classification"], hit["sci"]), (0, 0))

        first = self.client.store("hax durable replay sample", 2, "hax-compat-replay", SCOPE)
        again = self.client.store("hax durable replay sample", 2, "hax-compat-replay", SCOPE)
        self.assertEqual(first, again)
        self.assertEqual(self.client._command("AIMEM", "COUNT-SCOPED", *SCOPE, "2"), 2)
        self.assertEqual(self.client._command("AIMEM", "GET-SCOPED", first, *SCOPE)[6],
                         "hax durable replay sample")

    def test_knowledge_provenance_query_and_handoff_shape(self):
        knowledge_id, version_id = self.client.propose_knowledge(
            SCOPE, 1, "HAX decision with provenance", "hax-compat-event-1", "hax-compat-knowledge-1")
        record = self.client.get_knowledge(SCOPE, "get", version_id)
        self.assertEqual(record["knowledge_id"], knowledge_id)
        self.assertEqual(record["content"], "HAX decision with provenance")
        current = self.client.current_knowledge(SCOPE, 1)
        self.assertIn(version_id, [item["version"] for item in current])
        history = self.client.query_history(SCOPE, "HAX decision", 0, 0)
        self.assertIn(version_id, [item["version_id"] for item in history])

        handoff_id = self.client.handoff_offer(9474, 60000, SCOPE,
                                               "Take over HAX fixture", [self.visible_id])
        handoff = self.client.handoff_get(handoff_id)
        self.assertEqual(handoff["id"], handoff_id)
        self.assertEqual(handoff["recipient_id"], 9474)
        self.assertEqual(handoff["state"], "OPEN")
        self.assertEqual(self.client.handoff_cancel(handoff_id, handoff["revision"]), "CANCELLED")
        self.assertEqual(self.client.handoff_get(handoff_id)["state"], "CANCELLED")


if __name__ == "__main__":
    unittest.main()
