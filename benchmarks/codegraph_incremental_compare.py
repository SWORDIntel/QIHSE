#!/usr/bin/env python3
"""Disposable real-producer parity and timing; never reads live CodeGraph snapshots.

Run with the producer's Python environment. Optional --producer-source selects an
isolated source checkout; otherwise the installed package is used. Incremental
runs precede full runs on the same warm workspace, so timing is diagnostic, not a
randomized hardware benchmark. Persistent native generations are not measured.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import importlib
import importlib.util
import io
import json
import os
import platform
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))


def git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True)


def check(files: int, producer_source: Path | None) -> dict:
    if producer_source:
        sys.path.insert(0, str(producer_source.resolve()))
    import qihse_codegraph_incremental as adapter
    from code_review_graph.build_state import BUILD_IN_PROGRESS, BUILD_STATE_KEY

    with tempfile.TemporaryDirectory(
        prefix="qihse-incremental-benchmark-"
    ) as temporary:
        root = Path(temporary)
        repo = root / "repo"
        repo.mkdir()
        os.environ["CRG_HOME"] = str(root / "producer-home")
        os.environ["CRG_SERIAL_PARSE"] = "1"
        # Avoid shell/user Git hooks and config affecting this synthetic workload.
        os.environ["GIT_CONFIG_GLOBAL"] = os.devnull
        os.environ["GIT_CONFIG_NOSYSTEM"] = "1"
        os.environ["GIT_AUTHOR_DATE"] = "2000-01-01T00:00:00+00:00"
        os.environ["GIT_COMMITTER_DATE"] = "2000-01-01T00:00:00+00:00"
        git(repo, "init", "-q")
        for i in range(files):
            (repo / f"m{i:04d}.py").write_text(f"def f{i:04d}():\n    return {i}\n")
        client = repo / "client.py"
        client.write_text(
            "from m0001 import f0001\n\ndef caller():\n    return f0001() + future_target()\n"
        )
        git(repo, "add", ".")
        git(
            repo,
            "-c",
            "user.name=CodeGraph fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "commit",
            "-qm",
            "baseline",
        )
        baseline = adapter.build_export(repo, root / "initial.jsonl", full=True)
        raw_initial = (root / "initial.jsonl").read_bytes()
        no_op = adapter.build_export(repo, root / "no-op.jsonl")
        assert no_op["build_type"] == "incremental" and no_op["files_updated"] == 0
        assert (root / "no-op.jsonl").read_bytes() == raw_initial
        shared = repo / ".code-review-graph" / "graph.qihse.jsonl"
        assert not shared.exists(), "Private export recreated persistent JSONL"
        # Existing shared files belong to other consumers and must survive.
        shared.write_bytes(b"other consumer output")
        pairs = []
        scenarios = [
            (
                "edit",
                lambda: (repo / "m0000.py").write_text(
                    "def f0000():\n    return 9000\n"
                ),
            ),
            ("rename", lambda: (repo / "m0001.py").rename(repo / "renamed.py")),
            ("delete", lambda: (repo / "m0002.py").unlink()),
            (
                "resolve-external",
                lambda: (repo / "future.py").write_text(
                    "def future_target():\n    return 17\n"
                ),
            ),
            (
                "revert-to-head",
                lambda: (repo / "m0000.py").write_text("def f0000():\n    return 0\n"),
            ),
        ]
        for name, mutation in scenarios:
            mutation()
            start = time.perf_counter()
            incremental = adapter.build_export(repo, root / "incremental.jsonl")
            incremental_seconds = time.perf_counter() - start
            start = time.perf_counter()
            full = adapter.build_export(repo, root / "full.jsonl", full=True)
            full_seconds = time.perf_counter() - start
            a = (root / "incremental.jsonl").read_bytes()
            b = (root / "full.jsonl").read_bytes()
            assert a == b, (name, "incremental export differs from fresh full rebuild")
            assert shared.read_bytes() == b"other consumer output"
            pairs.append(
                {
                    "scenario": name,
                    "files_updated": incremental["files_updated"],
                    "full_files_parsed": full["files_parsed"],
                    "incremental_seconds": incremental_seconds,
                    "full_seconds": full_seconds,
                    "equivalent_export_bytes": len(a),
                    "equivalent_sha256": hashlib.sha256(a).hexdigest(),
                    "nodes": incremental["nodes"],
                    "edges": incremental["edges"],
                }
            )
        backend = adapter._producer()
        store = backend["store"](backend["db_path"](repo, read_only=True))
        try:
            store.set_metadata(BUILD_STATE_KEY, BUILD_IN_PROGRESS)
        finally:
            store.close()
        recovered = adapter.build_export(repo, root / "recovered.jsonl")
        assert recovered["build_type"] == "full", "Interrupted source build was trusted"
        assert (root / "recovered.jsonl").read_bytes() == (
            root / "full.jsonl"
        ).read_bytes()
        # Demonstrate database free-page reclamation without deleting a shared
        # JSONL export or removing any index used by another producer consumer.
        source_paths = sorted(repo.glob("m*.py"))
        for path in source_paths[: len(source_paths) * 3 // 4]:
            path.unlink()
        adapter.build_export(repo, root / "before-compact.jsonl")
        compact_after = adapter.build_export(
            repo, root / "after-compact.jsonl", reclaim=True
        )
        assert (root / "before-compact.jsonl").read_bytes() == (
            root / "after-compact.jsonl"
        ).read_bytes()
        assert compact_after["reclamation"]["indexes_removed"] == 0
        assert shared.read_bytes() == b"other consumer output"
        package = importlib.import_module("code_review_graph")
        source = Path(package.__file__).parent
        return {
            "schema": "qihse-codegraph-incremental-producer-benchmark-v1",
            "python": platform.python_version(),
            "platform": platform.platform(),
            "machine": platform.machine(),
            "logical_cpus": os.cpu_count(),
            "adapter_sha256": hashlib.sha256(
                (ROOT / "tools" / "qihse_codegraph_incremental.py").read_bytes()
            ).hexdigest(),
            "files": files + 1,
            "methodology": "Warm same-workspace pairs: incremental then full; exact-byte output comparison. "
            "Source hashing, full resolution and complete export remain in both paths.",
            "producer_files_sha256": {
                name: hashlib.sha256((source / name).read_bytes()).hexdigest()
                for name in ("incremental.py", "exports.py")
            },
            "initial": baseline,
            "no_op": no_op,
            "pairs": pairs,
            "median_incremental_seconds": statistics.median(
                p["incremental_seconds"] for p in pairs
            ),
            "median_full_seconds": statistics.median(p["full_seconds"] for p in pairs),
            "interrupted_build_recovered_as_full": True,
            "reclamation": compact_after["reclamation"],
            "private_export_only": True,
            "existing_shared_export_preserved": True,
            "note": "Native snapshots still encode complete generations; producer incrementality is not native per-file storage.",
        }


def check_overlay(helper_path: Path, producer_source: Path | None) -> dict:
    """Exercise the real CLI adapter with a materialized unsaved overlay."""
    if producer_source:
        sys.path.insert(0, str(producer_source.resolve()))
    import qihse_codegraph_incremental as adapter

    spec = importlib.util.spec_from_file_location("candidate_source", helper_path)
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    previous_identity = adapter.source_identity
    adapter.source_identity = helper.source_identity
    try:
        with tempfile.TemporaryDirectory(prefix="qihse-incremental-overlay-") as raw:
            root = Path(raw)
            repo = root / "original"
            repo.mkdir()
            (repo / "alpha.py").write_text("def saved():\n    return 1\n")
            (repo / "removed.py").write_text("def obsolete():\n    return 0\n")
            os.environ["CRG_HOME"] = str(root / "producer-home")
            overlay = root / "editor.json"
            helper.write_overlay_snapshot(
                overlay,
                {
                    "alpha.py": b"def unsaved_symbol():\n    return 9\n",
                    "removed.py": None,
                    "new.py": b"def added():\n    return 3\n",
                },
            )
            staged = root / "workspace"
            identity = helper.materialize_source(repo, staged, overlay_path=overlay)
            baseline = root / "identity.json"
            baseline.write_text(json.dumps(identity))
            baseline.chmod(0o600)
            output = root / "private.jsonl"
            args = [
                "--repo",
                str(staged),
                "--identity-repo",
                str(repo),
                "--source-provider",
                "filesystem",
                "--overlay",
                str(overlay),
                "--expected-identity",
                str(baseline),
                "--output",
                str(output),
            ]
            captured = io.StringIO()
            with contextlib.redirect_stdout(captured):
                result = adapter.main(args)
            assert result == 0, captured.getvalue()
            receipt = json.loads(captured.getvalue())
            rows = [json.loads(line) for line in output.read_bytes().splitlines()]
            names = {row["name"] for row in rows if row["t"] == "n"}
            assert {"unsaved_symbol", "added"} <= names
            assert not {"saved", "obsolete"} & names
            prepared = root / "prepared.jsonl"
            helper.prepare_export(output, prepared, identity)
            header = json.loads(prepared.read_bytes().splitlines()[0])
            assert (
                header["source_effective_digest"] == identity["source_effective_digest"]
            )
            previous = output.read_bytes()
            (staged / "alpha.py").write_text("def tampered_stage():\n    pass\n")
            errors = io.StringIO()
            with contextlib.redirect_stderr(errors):
                result = adapter.main(args)
            assert result == 1 and output.read_bytes() == previous
            assert "Materialized source" in errors.getvalue()
            assert not (repo / ".git").exists() and not (staged / ".git").exists()
            return {
                "non_git_original": True,
                "no_fake_git": True,
                "overlay_edit_add_delete_exact": True,
                "staged_tamper_denied": True,
                "prepared_source_policy": header["freshness"],
                "nodes": receipt["nodes"],
                "edges": receipt["edges"],
            }
    finally:
        adapter.source_identity = previous_identity


def scrub(value):
    """Drop runtime filesystem locations from the durable receipt."""
    if isinstance(value, dict):
        return {
            k: scrub(v)
            for k, v in value.items()
            if k not in ("export_path", "source_identity")
        }
    if isinstance(value, list):
        return [scrub(v) for v in value]
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--producer-source", type=Path)
    parser.add_argument(
        "--source-helper",
        type=Path,
        help="Optional filesystem/overlay provider implementation to verify",
    )
    parser.add_argument("--files", type=int, default=40)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if not 4 <= args.files <= 5000:
        parser.error("--files must be between 4 and 5000")
    result = scrub(check(args.files, args.producer_source))
    if args.source_helper:
        result["overlay"] = check_overlay(args.source_helper, args.producer_source)
    raw = json.dumps(result, indent=2) + "\n"
    if args.output:
        args.output.write_text(raw)
    print(raw)


if __name__ == "__main__":
    main()
