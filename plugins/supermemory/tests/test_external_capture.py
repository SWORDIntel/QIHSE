"""External capture, bounded context and JSON event idempotency contracts."""
import json
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest import mock

HOOKS = Path(__file__).resolve().parents[1] / "zcode-hooks"
sys.path.insert(0, str(HOOKS))
import context
import lifecycle


class ExternalCaptureTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.patch = mock.patch.object(lifecycle, "SPOOL_ROOT", Path(self.tmp.name) / "events")
        self.patch.start()
        self.addCleanup(self.patch.stop)

    @staticmethod
    def sample():
        return {
            "capture_owner": "external",
            "producer": "hax",
            "session_id": "logical-42",
            "event_id": "observer-99",
            "event_kind": "post-tool",
            "summary": "cargo test: 12 passed, 0 failed",
        }

    def test_requires_capture_owner_and_known_event_kind(self):
        e = self.sample()
        del e["capture_owner"]
        with self.assertRaises(lifecycle.PipelineError):
            lifecycle.enqueue_event(e)
        e["capture_owner"] = "native"
        with self.assertRaises(lifecycle.PipelineError):
            lifecycle.enqueue_event(e)
        e["capture_owner"] = "external"
        e["event_kind"] = "arbitrary"
        with self.assertRaises(lifecycle.PipelineError):
            lifecycle.enqueue_event(e)

    def test_replay_idempotency_and_conflict_rejection(self):
        e = self.sample()
        first = lifecycle.enqueue_event(e)
        self.assertEqual(first, lifecycle.enqueue_event(e))
        self.assertEqual(len(list(lifecycle.SPOOL_ROOT.glob("*.json"))), 1)
        e["summary"] = "cargo test: 7 failed"
        with self.assertRaises(lifecycle.PipelineError):
            lifecycle.enqueue_event(e)

    def test_sanitized_event_roundtrip(self):
        e = self.sample()
        e["summary"] += " password=ultralongsecretkey"
        eid = lifecycle.enqueue_event(e)
        raw = json.loads((lifecycle.SPOOL_ROOT / (eid + ".json")).read_text())
        body = raw["capsule"]
        self.assertNotIn("ultralongsecretkey", body)
        self.assertIn("[REDACTED]", body)
        self.assertEqual(json.loads(body)["capture_owner"], "external")
        self.assertIn("not independently verified", body)

    def test_ingested_events_use_stable_keys(self):
        e = self.sample()
        eid = lifecycle.enqueue_event(e)
        keys = []
        class FakeAimem:
            def store(self, text, kind, idem):
                keys.append(idem)
                return "qihse-record-id"
            def close(self):
                pass
        with mock.patch.dict(sys.modules, {"aimem_client": types.SimpleNamespace(Aimem=FakeAimem)}):
            self.assertEqual(lifecycle.drain()["accepted"], 1)
            self.assertEqual(lifecycle.drain()["accepted"], 0)
            self.assertEqual(lifecycle.drain(replay_accepted=True)["accepted"], 0)
        self.assertEqual(len(set(keys)), 1)
        self.assertEqual(lifecycle.status()["legacy_accepted_pending"], 0)
        self.assertFalse((lifecycle.SPOOL_ROOT / (eid + ".json")).exists())


class ContextTests(unittest.TestCase):
    def test_prompt_gate_uses_words_not_substrings(self):
        self.assertTrue(context.should_recall("What did we decide earlier?"))
        self.assertTrue(context.should_recall("Continue the session"))
        self.assertFalse(context.should_recall("Robots are common."))
        self.assertFalse(context.should_recall("hello"))

    def test_bounded_attributed_capsule(self):
        capsule = json.dumps({
            "record_type": "session_capsule", "session_id": "zz",
            "observations": [
                {"role": "user", "text": "How does it work?"},
                {"role": "assistant", "text": "This is my guess"},
            ],
        })
        hits = [
            {"id": "ab", "created_ms": 1609459200000, "score": 0.7, "text": capsule},
            {"id": "ab", "created_ms": 1609459200000, "score": 0.7, "text": capsule},
            {"id": "cd", "score": 0.004, "text": "Evidence " * 800},
        ]
        text = context.render_hits(hits, max_chars=750)
        self.assertIn("id=ab", text)
        self.assertIn("ASSISTANT (unverified)", text)
        self.assertIn("2021-01-01", text)
        self.assertLessEqual(len(text), 750)
        self.assertEqual(text.count("id=ab"), 1)

    def test_nan_and_untrusted_structures_do_not_render(self):
        self.assertEqual(context.render_hits([{"id": "x", "score": float("nan"), "text": "x"}]), "")
        self.assertEqual(context.render_hits({"hits": []}), "")


if __name__ == "__main__":
    unittest.main()
