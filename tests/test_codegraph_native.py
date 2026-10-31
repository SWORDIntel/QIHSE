#!/usr/bin/env python3
"""Native QIHSE CodeGraph persistence, adjacency, confidence, and stale-index tests."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time


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
        {"t": "n", "id": node_id("leaf"), "file": "src/leaf.c", "kind": "Function",
         "name": "leaf", "line_start": 1, "line_end": 3,
         "language": "c", "is_test": False, "file_hash": ""},
        {"t": "n", "id": node_id("dep"), "file": "src/dep.c", "kind": "Module",
         "name": "dependency", "line_start": 1, "line_end": 3,
         "language": "c", "is_test": False, "file_hash": ""},
        {"t": "n", "id": node_id("other"), "file": "src/other.c", "kind": "Function",
         "name": "unrelated", "line_start": 1, "line_end": 3,
         "language": "c", "is_test": False, "file_hash": ""},
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
        {"t": "e", "id": node_id("leaf_call"), "source": node_id("caller"),
         "target": node_id("leaf"), "relation": "CALLS", "file": "src/b.c",
         "line": 2, "confidence": 1.0, "tier": "EXTRACTED",
         "resolution": "direct", "traversable": True},
        {"t": "e", "id": node_id("dependency"), "source": node_id("caller"),
         "target": node_id("dep"), "relation": "DEPENDS_ON", "file": "src/b.c",
         "line": 2, "confidence": 1.0, "tier": "EXTRACTED",
         "resolution": "direct", "traversable": True},
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

        missing = invoke("status", expect=1)
        assert "repo/runtime not available" in missing["error"], missing
        assert not (root / "state").exists()

        source = root / "graph.jsonl"
        snapshot(repo, source)
        # The exporter might complete, then someone edits a source file
        # before native import. Publication must fail closed.
        (repo / "src/a.c").write_text("int target(void) { return 2; }\n")
        late = invoke("import", "--input", str(source), expect=1)
        assert "source changed" in late["error"], late
        git(repo, "checkout", "--", "src/a.c")
        published = invoke("import", "--input", str(source))
        assert published["status"] == "published" and published["nodes"] == 6
        summary = invoke("status")
        assert summary["fresh"] and summary["unresolved_edges"] == 1
        assert summary["nodes"] == 6 and summary["edges"] == 5

        impact = invoke("impact", "--symbol", "target", "--depth", "2")
        symbols = {n["symbol"] for n in impact["nodes"]}
        assert {"target", "caller", "test_target"} <= symbols, impact
        assert impact["seed_nodes"] == 1 and impact["seed_match"] == "exact"
        assert "tests/test_a.c" in impact["candidate_tests"], impact
        assert impact["unresolved_edges"] == 1

        context = invoke("context", "--symbol", "caller", "--depth", "1")
        context_symbols = {n["symbol"] for n in context["nodes"]}
        assert {"caller", "target", "leaf", "dependency"} <= context_symbols
        assert "unrelated" not in context_symbols
        assert all(n["line_end"] >= n["line_start"] for n in context["nodes"])
        relationships = {(e["from"], e["relation"], e["to"])
                         for e in context["evidence"]}
        assert {("caller", "CALLS", "target"),
                ("caller", "CALLS", "leaf"),
                ("caller", "DEPENDS_ON", "dependency")} <= relationships
        assert all("file" in e and "line" in e and "confidence" in e
                   for e in context["evidence"])
        capped = invoke("context", "--symbol", "caller", "--depth", "1",
                        "--max-tokens", "320")
        assert capped["truncated"] and len(capped["evidence"]) == 1, capped

        narrow = invoke("impact", "--symbol", "caller", "--depth", "1")
        assert {n["symbol"] for n in narrow["nodes"]} == {"caller"}, narrow

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
        broken.write_bytes(source.read_bytes().replace(b'"edges":5', b'"edges":6'))
        error = invoke("import", "--input", str(broken), expect=1)
        assert "error" in error
        assert invoke("status")["fresh"] is True
        assert invoke("query", "--symbol", "target")["shown_nodes"] >= 1

        # The importer never admits classified or SCI data into the low-clearance
        # reader realm. A denied import must leave the published public graph intact.
        high = root / "classified.jsonl"
        records = [json.loads(line) for line in source.read_text().splitlines()]
        for row in records:
            if row.get("t") == "n" and row.get("name") == "target":
                row.update(name="classified_marker", classification=3,
                           sci_compartment=1)
        body = b"".join((json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n").encode()
                        for row in records[:-1])
        records[-1]["sha256"] = hashlib.sha256(body).hexdigest()
        high.write_bytes(body + (json.dumps(records[-1], sort_keys=True,
                            separators=(",", ":")) + "\n").encode())
        denied = invoke("import", "--input", str(high), expect=1)
        assert "classified_marker" not in json.dumps(denied), denied
        assert invoke("status")["fresh"] is True

        sock = root / "reader.sock"
        token_path = root / "reader.token"
        daemon = subprocess.Popen([str(executable), "serve", "--repo", str(repo),
                                   "--socket", str(sock), "--token-file", str(token_path),
                                   "--idle-seconds", "3"], env=env, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE)
        try:
            deadline = time.monotonic() + 10
            while not sock.exists() and daemon.poll() is None and time.monotonic() < deadline:
                time.sleep(0.02)
            assert sock.exists(), daemon.communicate(timeout=1)
            token = token_path.read_text().strip()

            def request(**params):
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as peer:
                    peer.settimeout(8)
                    peer.connect(str(sock))
                    peer.sendall((json.dumps(params) + "\n").encode())
                    with peer.makefile("rb") as stream:
                        return json.loads(stream.readline())

            for cmd in ("status", "context"):
                args = {"token": "0" * 64, "command": cmd,
                        "symbol": "classified_marker"}
                response = request(**args)
                assert "denied" in response["error"]
                assert "classified_marker" not in json.dumps(response)
            result = request(token=token, command="context",
                             symbol="classified_marker")
            assert "classified_marker" not in json.dumps(result), result
            good = request(token=token, command="context", symbol="target")
            assert good["fresh"] and good["nodes"], good
            batch = request(token=token, command="context", symbols=["target", "caller"])
            assert batch["fresh"] and batch["nodes"], batch
            (repo / "src/a.c").write_text("int target(void) { return 9; }\n")
            stale = request(token=token, command="context", symbols=["target"])
            assert stale.get("fresh") is not True and "stale" in stale["error"], stale
        finally:
            daemon.terminate()
            try:
                daemon.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                daemon.kill()
                daemon.communicate(timeout=5)

    print("QIHSE CodeGraph native persistence, traversal and staleness: OK")


if __name__ == "__main__":
    main()
