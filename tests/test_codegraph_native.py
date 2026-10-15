#!/usr/bin/env python3
"""Native QIHSE CodeGraph persistence, adjacency, confidence, and stale-index tests."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile


def git(repo: Path, *args: str) -> bytes:
    return subprocess.run(["git", *args], cwd=repo, check=True,
                          capture_output=True).stdout


def node_id(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def snapshot(repo: Path, dest: Path) -> None:
    head = git(repo, "rev-parse", "HEAD").strip().decode()
    selected = ("--", ".", ":(exclude).code-review-graph")
    worktree = hashlib.sha256(
        git(repo, "status", "--porcelain=v1", "-z", "--untracked-files=normal",
            *selected) + b"\0" +
        git(repo, "diff", "--no-ext-diff", "--no-textconv", "--binary", "HEAD",
            *selected)
    ).hexdigest()
    header = {"t": "h", "format": "qihse-codegraph-v1", "version": 1,
              "head": head, "worktree": worktree}
    vertices = [
        {"t": "n", "id": node_id("target"), "file": "src/a.c", "kind": "Function",
         "name": "target", "line_start": 1, "line_end": 3,
         "language": "c", "is_test": False, "file_hash": ""},
        {"t": "n", "id": node_id("caller"), "file": "src/b.c", "kind": "Function",
         "name": "caller", "line_start": 1, "line_end": 3,
         "language": "c", "is_test": False, "file_hash": ""},
        {"t": "n", "id": node_id("test"), "file": "tests/test_a.c", "kind": "Test",
         "name": "test_target", "line_start": 1, "line_end": 3,
         "language": "c", "is_test": True, "file_hash": ""},
    ]
    edges = [
        {"t": "e", "id": node_id("call"), "source": node_id("caller"),
         "target": node_id("target"), "relation": "CALLS", "file": "src/b.c",
         "line": 2, "confidence": 1.0, "tier": "EXTRACTED",
         "resolution": "direct", "traversable": True},
        {"t": "e", "id": node_id("test_edge"), "source": node_id("test"),
         "target": node_id("target"), "relation": "CALLS", "file": "tests/test_a.c",
         "line": 2, "confidence": 1.0, "tier": "EXTRACTED",
         "resolution": "direct", "traversable": True},
        {"t": "e", "id": node_id("ambiguous"), "source": node_id("caller"),
         "target": "", "relation": "CALLS", "file": "src/b.c",
         "line": 3, "confidence": 0.5, "tier": "AMBIGUOUS",
         "resolution": "unresolved", "traversable": False},
    ]
    rows = [header, *vertices, *edges]
    data = b"".join((json.dumps(r, sort_keys=True, separators=(",", ":")) + "\n").encode()
                    for r in rows)
    trailer = {"t": "end", "nodes": len(vertices), "edges": len(edges),
               "unresolved_edges": 1, "sha256": hashlib.sha256(data).hexdigest()}
    dest.write_bytes(data + (json.dumps(trailer, sort_keys=True,
                                         separators=(",", ":")) + "\n").encode())


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--binary", required=True)
    args = p.parse_args()
    executable = Path(args.binary).resolve()
    if not executable.exists():
        raise RuntimeError("build the native QIHSE codegraph CLI first")

    with tempfile.TemporaryDirectory(prefix="qihse-codegraph-native-") as directory:
        root = Path(directory)
        repo = root / "repo"
        (repo / "src").mkdir(parents=True)
        (repo / "tests").mkdir()
        (repo / "src/a.c").write_text("int target(void) { return 1; }\n")
        (repo / "src/b.c").write_text("int caller(void) { return target(); }\n")
        (repo / "tests/test_a.c").write_text("void test_target(void) {}\n")
        git(repo, "init", "-q")
        git(repo, "add", ".")
        git(repo, "-c", "user.email=codegraph@example.invalid", "-c",
            "user.name=CodeGraphTest", "commit", "-qm", "baseline")
        env = {**os.environ, "HOME": str(root), "XDG_STATE_HOME": str(root / "state"),
               "LD_LIBRARY_PATH": str(executable.parent) + ":" +
               os.environ.get("LD_LIBRARY_PATH", "")}

        def invoke(*tokens: str, expect: int = 0):
            result = subprocess.run([str(executable), *tokens, "--repo", str(repo)],
                                    env=env, capture_output=True, text=True, timeout=40)
            assert result.returncode == expect, (
                tokens, result.returncode, result.stdout, result.stderr)
            return json.loads(result.stdout)

        source = root / "graph.jsonl"
        snapshot(repo, source)
        published = invoke("import", "--input", str(source))
        assert published["status"] == "published" and published["nodes"] == 3
        summary = invoke("status")
        assert summary["fresh"] and summary["unresolved_edges"] == 1

        impact = invoke("impact", "--symbol", "target", "--depth", "2")
        symbols = {n["symbol"] for n in impact["nodes"]}
        assert {"target", "caller", "test_target"} <= symbols, impact
        assert "tests/test_a.c" in impact["candidate_tests"], impact
        assert impact["unresolved_edges"] == 1

        # A changed file makes the old graph explicitly stale, not "clean".
        (repo / "src/a.c").write_text("int target(void) { return 2; }\n")
        assert invoke("status")["fresh"] is False
        refused = invoke("review", "--symbol", "target", expect=2)
        assert "stale" in refused["error"]
        git(repo, "checkout", "--", "src/a.c")
        assert invoke("status")["fresh"] is True

        # A pre-existing dirty file can be edited again without changing the
        # porcelain filename/status row. Tracked diff content must still make
        # the graph stale (rather than silently claim correctness).
        (repo / "src/a.c").write_text("int target(void) { return 3; }\n")
        snapshot(repo, source)
        invoke("import", "--input", str(source))
        assert invoke("status")["fresh"] is True
        (repo / "src/a.c").write_text("int target(void) { return 4; }\n")
        assert invoke("status")["fresh"] is False
        git(repo, "checkout", "--", "src/a.c")
        # Rebase on the published clean source for the next rollback test.
        snapshot(repo, source)
        invoke("import", "--input", str(source))
        assert invoke("status")["fresh"] is True

        # Reject a corrupt import without replacing the published generation.
        broken = root / "broken.jsonl"
        broken.write_bytes(source.read_bytes().replace(b'"edges":3', b'"edges":4'))
        error = invoke("import", "--input", str(broken), expect=1)
        assert "error" in error
        assert invoke("status")["fresh"] is True
        assert invoke("query", "--symbol", "target")["shown_nodes"] >= 1

    print("QIHSE CodeGraph native persistence, traversal and staleness: OK")


if __name__ == "__main__":
    main()
