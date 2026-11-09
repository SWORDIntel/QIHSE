#!/usr/bin/env python3
"""Source producer adapter checks; no configured QIHSE storage is accessed."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import sys
import tempfile
import unittest
from contextlib import closing, contextmanager
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import qihse_codegraph_incremental as adapter


def _export(path, nodes=1):
    rows = [
        {
            "t": "h",
            "format": "qihse-codegraph-v1",
            "id_algorithm": "xxh3-128",
            "id_bits": 128,
        }
    ]
    rows += [{"t": "n", "id": f"{i:032x}", "name": "test"} for i in range(nodes)]
    raw = b"".join(
        (json.dumps(row, separators=(",", ":")) + "\n").encode() for row in rows
    )
    trailer = {
        "t": "end",
        "nodes": nodes,
        "edges": 0,
        "unresolved_edges": 0,
        "sha256": hashlib.sha256(raw).hexdigest(),
    }
    path.write_bytes(raw + (json.dumps(trailer) + "\n").encode())
    return path


class AdapterTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="qihse-producer-adapter-")
        self.root = Path(self.temp.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        self.index = self.repo / ".code-review-graph"
        self.index.mkdir()
        self.database = self.index / "graph.db"
        with closing(sqlite3.connect(self.database)) as conn, conn:
            conn.execute("CREATE TABLE facts (data BLOB)")
        self.output = self.root / "out.jsonl"
        self.identity = {
            "head": "f" * 40,
            "worktree": "a" * 64,
            "worktree_v2": "b" * 64,
        }
        self.calls = []
        owner = self

        class Store:
            def __init__(self, _path):
                self.closed = False

            def close(self):
                self.closed = True
                owner.calls.append("close")

        def build(**kwargs):
            self.calls.append(kwargs)
            return {
                "status": "ok",
                "build_type": "full" if kwargs["full_rebuild"] else "incremental",
                "files_parsed": 7 if kwargs["full_rebuild"] else 0,
                "files_updated": 0 if kwargs["full_rebuild"] else 1,
            }

        def export(_store, path, _repo, *, source_identity_provider=None):
            self.calls.append("export")
            if source_identity_provider:
                source_identity_provider(_repo)
            return _export(path)

        self.backend = {
            "build": build,
            "store": Store,
            "db_path": lambda repo: self.database,
            "export": export,
            "incomplete": lambda store: False,
            "assert_root": lambda repo, store: None,
            "exact_incremental": True,
        }

    def tearDown(self):
        self.temp.cleanup()

    def run_build(self, **kwargs):
        return adapter.build_export(
            self.repo,
            self.output,
            producer=self.backend,
            source_identity_provider=lambda repo: dict(self.identity),
            **kwargs,
        )

    def test_incremental_private_export_no_shared_file(self):
        result = self.run_build()
        self.assertEqual(result["build_type"], "incremental")
        self.assertFalse(self.calls[0]["full_rebuild"])
        self.assertEqual(result["files_updated"], 1)
        self.assertFalse(result["persistent_export_created"])
        self.assertEqual(result["nodes"], 1)
        self.assertFalse((self.index / "graph.qihse.jsonl").exists())
        self.assertEqual(list(self.root.glob(".qihse-export-*")), [])
        self.assertIn("close", self.calls)

    def test_old_producer_and_invalidation_limit_fall_back_to_full(self):
        self.backend["exact_incremental"] = False
        result = self.run_build()
        self.assertEqual(result["build_type"], "full")
        self.assertFalse(result["incremental_capable"])
        self.backend["exact_incremental"] = True
        original = self.backend["build"]
        self.backend["build"] = lambda **kwargs: (
            original(**kwargs)
            if kwargs["full_rebuild"]
            else {"status": "error", "full_rebuild_required": True}
        )
        result = self.run_build()
        self.assertEqual(result["build_type"], "full")
        self.assertTrue(result["incremental_capable"])

    def test_consistent_read_snapshot_wraps_completeness_and_export(self):
        active = []

        @contextmanager
        def snapshot(store):
            active.append(True)
            try:
                yield
            finally:
                active.pop()

        self.backend["read_snapshot"] = snapshot
        original_export = self.backend["export"]

        def checked_export(*args, **kwargs):
            self.assertEqual(active, [True])
            return original_export(*args, **kwargs)

        self.backend["incomplete"] = lambda store: (
            self.assertEqual(active, [True]) or False
        )
        self.backend["export"] = checked_export
        self.run_build()
        self.assertEqual(active, [])

    def test_full_override_and_existing_shared_output_preserved(self):
        shared = self.index / "graph.qihse.jsonl"
        shared.write_bytes(b"other consumer")
        result = self.run_build(full=True)
        self.assertTrue(self.calls[0]["full_rebuild"])
        self.assertEqual(result["files_parsed"], 7)
        self.assertEqual(shared.read_bytes(), b"other consumer")

    def test_source_changes_do_not_replace_previous_output(self):
        self.output.write_bytes(b"previous")
        self.output.chmod(0o600)
        values = iter([self.identity, self.identity, {"head": "changed"}])
        with self.assertRaisesRegex(ValueError, "Source changed during export"):
            adapter.build_export(
                self.repo,
                self.output,
                producer=self.backend,
                source_identity_provider=lambda repo: next(values),
            )
        self.assertEqual(self.output.read_bytes(), b"previous")
        self.assertEqual(list(self.root.glob(".qihse-export-*")), [])

    def test_incomplete_and_failed_builds_never_export(self):
        for result in [
            {"status": "partial"},
            {"status": "error"},
            {"status": "ok", "postprocess_contended": True},
            {"status": "ok", "errors": [{"file": "bad.c"}]},
        ]:
            self.backend["build"] = lambda result=result, **kwargs: result
            with self.assertRaisesRegex(ValueError, "incomplete"):
                self.run_build()
            self.assertNotIn("export", self.calls)
            self.assertFalse(self.output.exists())

    def test_interrupted_store_and_bad_trailer_fail_closed(self):
        self.backend["incomplete"] = lambda store: True
        with self.assertRaisesRegex(ValueError, "interrupted"):
            self.run_build()
        self.backend["incomplete"] = lambda store: False
        self.backend["export"] = lambda store, path, repo: path.write_bytes(b"{}\n")
        with self.assertRaises(ValueError):
            self.run_build()
        self.assertFalse(self.output.exists())
        self.assertEqual(list(self.root.glob(".qihse-export-*")), [])

    def test_private_destination_no_symlink_or_source_tree_overwrite(self):
        bad = self.index / "out.jsonl"
        self.index.chmod(0o700)
        with self.assertRaisesRegex(ValueError, "outside"):
            adapter.build_export(self.repo, bad, producer=self.backend)
        self.output.symlink_to(self.root / "elsewhere")
        with self.assertRaisesRegex(ValueError, "private owned"):
            self.run_build()
        self.output.unlink()
        self.root.chmod(0o755)
        with self.assertRaisesRegex(ValueError, "0700"):
            self.run_build()
        self.root.chmod(0o700)

    def test_expected_identity_and_explicit_export_provider(self):
        with self.assertRaisesRegex(ValueError, "prepared workspace"):
            self.run_build(expected_identity={"different": True})
        observed = []
        self.run_build(
            export_identity_provider=lambda repo: (
                observed.append(repo) or ("x", "y", "z")
            )
        )
        self.assertEqual(observed, [self.repo])
        self.backend["export"] = lambda store, path, repo: _export(path)
        with self.assertRaisesRegex(ValueError, "capability"):
            self.run_build(export_identity_provider=lambda repo: ("x", "y", "z"))

    def test_staged_bytes_must_match_original_effective_digest(self):
        with self.assertRaisesRegex(ValueError, "Materialized source"):
            self.run_build(
                staged_identity_provider=lambda repo: {"worktree": "bad"},
                expected_staged_digest="good",
            )
        self.assertEqual(self.calls, [])
        values = iter([{"worktree": "good"}, {"worktree": "good"}, {"worktree": "bad"}])
        with self.assertRaisesRegex(ValueError, "Materialized source"):
            self.run_build(
                staged_identity_provider=lambda repo: next(values),
                expected_staged_digest="good",
            )
        self.assertFalse(self.output.exists())

    def test_writer_lock_and_unsafe_lock(self):
        with adapter._source_lock(self.index), self.assertRaises(BlockingIOError):
            self.run_build()
        lock = self.index / ".qihse-reindex.lock"
        lock.unlink()
        lock.symlink_to(self.database)
        with self.assertRaises(OSError):
            self.run_build()

    def test_reclaim_exact_rows_and_indexes_with_reported_bytes(self):
        with closing(sqlite3.connect(self.database)) as conn, conn:
            conn.execute("CREATE INDEX facts_data ON facts(data)")
            conn.executemany(
                "INSERT INTO facts VALUES (?)",
                [(str(i).encode() * 200,) for i in range(1000)],
            )
            conn.execute("DELETE FROM facts WHERE rowid > 20")
            expected = conn.execute(
                "SELECT rowid,data FROM facts ORDER BY rowid"
            ).fetchall()
            schema = conn.execute(
                "SELECT name,sql FROM sqlite_master ORDER BY name"
            ).fetchall()
        result = adapter.reclaim_source_database(self.database)
        self.assertEqual(result["status"], "reclaimed")
        self.assertGreater(result["before"]["free_pages"], 0)
        self.assertEqual(result["after"]["free_pages"], 0)
        self.assertLess(
            result["after"]["allocated_bytes"], result["before"]["allocated_bytes"]
        )
        with closing(sqlite3.connect(self.database)) as conn, conn:
            self.assertEqual(
                conn.execute("SELECT rowid,data FROM facts ORDER BY rowid").fetchall(),
                expected,
            )
            self.assertEqual(
                conn.execute(
                    "SELECT name,sql FROM sqlite_master ORDER BY name"
                ).fetchall(),
                schema,
            )

    def test_busy_reclaim_preserves_writer_and_rows(self):
        with closing(sqlite3.connect(self.database)) as conn, conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executemany(
                "INSERT INTO facts VALUES (?)", [(b"x" * 8192,) for _ in range(40)]
            )
            conn.execute("DELETE FROM facts")
        with closing(sqlite3.connect(self.database, isolation_level=None)) as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute("INSERT INTO facts VALUES (?)", (b"held transaction",))
            result = adapter.reclaim_source_database(self.database)
            self.assertEqual(result["status"], "busy")
            conn.execute("ROLLBACK")
        with closing(sqlite3.connect(self.database)) as conn, conn:
            self.assertEqual(
                conn.execute("SELECT count(*) FROM facts").fetchone()[0], 0
            )

    def test_actual_progress_pipe_records_and_bytes(self):
        read_fd, write_fd = os.pipe2(os.O_NONBLOCK)
        try:
            with patch.dict(os.environ, QIHSE_CODEGRAPH_PROGRESS_FD=str(write_fd)):
                self.run_build()
            events = [json.loads(line) for line in os.read(read_fd, 65536).splitlines()]
            self.assertEqual(events[-1]["phase"], "verify")
            byte_events = [e for e in events if e["unit"] == "bytes"]
            self.assertEqual(byte_events[-1]["completed"], self.output.stat().st_size)
            self.assertEqual(byte_events[-1]["total"], self.output.stat().st_size)
            self.assertEqual(
                set(events[-1]), {"version", "phase", "unit", "completed", "total"}
            )
            while True:
                try:
                    os.write(write_fd, b"x" * 4096)
                except BlockingIOError:
                    break
            adapter.emit_progress(
                "verify", "bytes", 10, 10
            )  # Full pipe must not block.
        finally:
            os.close(read_fd)
            os.close(write_fd)

    def test_trailer_mutations_and_unknown_records(self):
        _export(self.output)
        raw = self.output.read_bytes()
        for damaged in [
            raw[:-1],
            raw.replace(b'"nodes": 1', b'"nodes": 2'),
            raw + b"{}\n",
            raw.replace(b'"t":"n"', b'"t":"x"'),
        ]:
            self.output.write_bytes(damaged)
            with self.assertRaises(ValueError):
                adapter.verify_export(self.output)


if __name__ == "__main__":
    unittest.main()
