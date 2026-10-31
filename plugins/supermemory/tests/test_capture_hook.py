"""ZCode Stop lifecycle and durable recovery regression tests (stdlib only)."""
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1] / "zcode-hooks"
sys.path.insert(0, str(ROOT))
import lifecycle

SPEC = importlib.util.spec_from_file_location("qihse_capture_hook", ROOT / "capture_hook.py")
capture = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(capture)


class StopHookTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.path = self.base / "session.jsonl"
        self.path.write_text(
            "\n".join(
                json.dumps({"type": role, "message": {"content": text}})
                for role, text in (
                    ("user", "Please investigate failure " * 24),
                    ("assistant", "The test output was reported as " * 24),
                )
            ) + "\n", encoding="utf-8",
        )
        self.spool = self.base / "private-spool"
        self.log = self.base / "capture.log"
        self.root_patch = mock.patch.object(lifecycle, "SPOOL_ROOT", self.spool)
        self.root_patch.start()
        self.addCleanup(self.root_patch.stop)

    def _run_parent(self, payload):
        with (
            mock.patch.object(capture, "LOG", self.log),
            mock.patch.object(sys, "argv", ["capture_hook.py"]),
            mock.patch.object(sys, "stdin", io.StringIO(json.dumps(payload))),
            mock.patch.object(capture.subprocess, "Popen") as popen,
        ):
            status = capture.main()
        return status, popen

    def _payload(self):
        return {"transcript_path": str(self.path), "session_id": "session-77"}

    def _queued_records(self):
        return list(self.spool.glob("*.json"))

    def test_parent_spools_and_launches_detached_worker_without_transcript_in_env(self):
        status, popen = self._run_parent(self._payload())
        self.assertEqual(status, 0)
        popen.assert_called_once()
        args, kwargs = popen.call_args
        self.assertEqual(args[0][-1], "--child")
        self.assertEqual(kwargs["stdin"], capture.subprocess.DEVNULL)
        self.assertTrue(kwargs["start_new_session"])
        self.assertNotIn("env", kwargs)
        records = self._queued_records()
        self.assertEqual(len(records), 1)
        data = json.loads(records[0].read_text())
        self.assertEqual(data["session_id"], "session-77")
        self.assertEqual(data["state"], "queued")
        self.assertEqual(records[0].stat().st_mode & 0o077, 0)
        self.assertEqual(self.spool.stat().st_mode & 0o077, 0)

    def test_child_processes_queued_capsule(self):
        self._run_parent(self._payload())
        calls = []
        class FakeAimem:
            def store(self, text, kind, idem):
                calls.append((text, kind, idem))
                return "memory-uuid-1"
            def close(self):
                pass
        with (
            mock.patch.dict(sys.modules, {"aimem_client": types.SimpleNamespace(Aimem=FakeAimem)}),
            mock.patch.object(capture, "LOG", self.log),
            mock.patch.object(sys, "argv", ["capture_hook.py", "--child"]),
        ):
            self.assertEqual(capture.main(), 0)
        self.assertEqual(len(calls), 1)
        stored = json.loads(calls[0][0])
        self.assertEqual(stored["record_type"], "session_capsule")
        self.assertEqual(stored["session_id"], "session-77")
        self.assertEqual(len(stored["observations"]), 2)
        self.assertEqual(self._queued_records(), [])

    def test_duplicate_stop_preserves_spool_identity_and_idempotency(self):
        self._run_parent(self._payload())
        self._run_parent(self._payload())
        self.assertEqual(len(self._queued_records()), 1)
        ids = []
        class FakeAimem:
            def store(self, text, kind, idem):
                ids.append(idem)
                return "same-id"
            def close(self):
                pass
        with mock.patch.dict(sys.modules, {"aimem_client": types.SimpleNamespace(Aimem=FakeAimem)}):
            self.assertEqual(lifecycle.drain()["accepted"], 1)
            self.assertEqual(lifecycle.drain()["accepted"], 0)
            self.assertEqual(lifecycle.drain(replay_accepted=True)["accepted"], 0)
        self.assertEqual(len(set(ids)), 1)

    def test_invalid_inputs_never_launch(self):
        for payload in ({"transcript_path": []}, {"session_id": "x"}, {"transcript_path": "/nope"}):
            _, popen = self._run_parent(payload)
            popen.assert_not_called()
        self.assertEqual(self._queued_records(), [])

    def test_large_hook_envelope_is_ignored(self):
        status, popen = self._run_parent({"transcript_path": str(self.path), "noise": "x" * 20000})
        self.assertEqual(status, 0)
        popen.assert_not_called()
        self.assertFalse(self._queued_records())

    def test_redact_credentials_without_promoting_assistant_claims(self):
        self.path.write_text(json.dumps({"role": "user", "content":
            "Bearer aaaabbbbccccdddd and password=hunter123456 and sk-proj-" + "x" * 28
        }) + "\n" + json.dumps({"role": "assistant", "content":
            "I think this succeeded (not verified) " * 12
        }) + "\n")
        record_id = lifecycle.enqueue_transcript(str(self.path), "new-s")
        staged = json.loads((self.spool / (record_id + ".json")).read_text())
        capsule = json.loads(lifecycle.compile_capsule(staged))
        contents = json.dumps(capsule)
        for secret in ("aaaabbbbccccdddd", "hunter123456", "sk-proj-" + "x" * 28):
            self.assertNotIn(secret, contents)
        self.assertIn("not independently verified", contents)

    def test_unsafe_spool_permissions_refuse_capture(self):
        self.spool.mkdir(mode=0o700)
        os.chmod(self.spool, 0o777)
        with self.assertRaises(lifecycle.PipelineError):
            lifecycle.enqueue_transcript(str(self.path), "s1")
        self.assertFalse(self._queued_records())

    def test_blocked_transcript_does_not_starve_new_events(self):
        # A truncated transcript cannot be reconstructed; preserve its
        # envelope as blocked instead of retrying it on every Stop event.
        eid = lifecycle.enqueue_transcript(str(self.path), "lost-s")
        self.path.write_text("truncated\n", encoding="utf-8")
        hax = {
            "capture_owner": "external", "producer": "hax", "event_id": "next",
            "session_id": "working-s", "event_kind": "checkpoint",
            "summary": "Compiler test passed",
        }
        lifecycle.enqueue_event(hax)
        class FakeAimem:
            def store(self, text, kind, idem):
                return "accepted-event"
            def close(self):
                pass
        with mock.patch.dict(sys.modules, {"aimem_client": types.SimpleNamespace(Aimem=FakeAimem)}):
            first = lifecycle.drain(limit=8)
            self.assertEqual(first["accepted"], 1)
            self.assertEqual(first["failed"], 1)
            second = lifecycle.drain(limit=8)
            self.assertEqual(second["failed"], 0)
        record = json.loads((self.spool / (eid + ".json")).read_text())
        self.assertEqual(record["state"], "blocked")
        self.assertEqual(lifecycle.status()["blocked"], 1)

    def test_durable_ack_retires_spool_record(self):
        self._run_parent(self._payload())
        class FakeAimem:
            def store(self, text, kind, idem):
                return "durably-accepted"
            def close(self):
                pass
        with mock.patch.dict(sys.modules, {"aimem_client": types.SimpleNamespace(Aimem=FakeAimem)}):
            self.assertEqual(lifecycle.drain()["accepted"], 1)
        report = lifecycle.status()
        self.assertEqual(report["legacy_accepted_pending"], 0)
        self.assertEqual(len(self._queued_records()), 0)


if __name__ == "__main__":
    unittest.main()
