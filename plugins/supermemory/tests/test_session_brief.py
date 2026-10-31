"""Explicit, bounded, non-claiming local session projection tests."""
import json
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest import mock

HOOKS = Path(__file__).resolve().parents[1] / "zcode-hooks"
sys.path.insert(0, str(HOOKS))
import lifecycle
import session_brief


class SessionProjectionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root_patch = mock.patch.object(lifecycle, "SPOOL_ROOT", Path(self.tmp.name) / "spool")
        self.root_patch.start()
        self.addCleanup(self.root_patch.stop)

    def test_selects_exact_session_only(self):
        source = {
            "producer": "hax", "capture_owner": "external",
            "event_id": "a1", "session_id": "s1",
            "event_kind": "checkpoint", "summary": "Tests pending",
        }
        lifecycle.enqueue_event(source)
        self.assertIsNone(session_brief.lookup("s2"))
        r = session_brief.lookup("s1", producer="hax")
        self.assertEqual(r["session_id"], "s1")
        self.assertIsNone(session_brief.lookup("s1", producer="other"))
        self.assertEqual(session_brief.project(r, "l0")["durability"], "local_only")

    def test_bounded_json_levels_do_not_claim_handoff(self):
        e = {
            "producer": "hax", "capture_owner": "external", "event_id": "a2",
            "session_id": "run-1", "event_kind": "post-tool",
            "summary": "a" * 8000,
        }
        lifecycle.enqueue_event(e)
        r = session_brief.lookup("run-1")
        for level in ("l0", "l1", "l2"):
            projected = session_brief.project(r, level)
            serialized = json.dumps(projected)
            self.assertEqual(json.loads(serialized), projected)
            self.assertNotIn("handoff_status", projected)
            if level != "l2":
                self.assertLessEqual(len(serialized), 3600)
        self.assertGreater(len(json.dumps(session_brief.project(r, "l2"))),
                           len(json.dumps(session_brief.project(r, "l1"))))


if __name__ == "__main__":
    unittest.main()
