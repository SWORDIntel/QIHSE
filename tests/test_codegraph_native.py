#!/usr/bin/env python3
"""Native QIHSE CodeGraph persistence, adjacency, confidence, and stale-index tests."""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import resource
import select
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path


def git(repo: Path, *args: str) -> bytes:
    return subprocess.run(["git", *args], cwd=repo, check=True,
                          capture_output=True).stdout


def node_id(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def worktree_digest(repo: Path) -> str:
    selected = ("--", ".", ":(exclude).code-review-graph")
    digest = hashlib.sha256()
    for args in (("status", "--porcelain=v1", "-z", "--untracked-files=normal"),
                 ("diff", "--no-ext-diff", "--no-textconv", "--binary", "HEAD"),
                 ("ls-files", "--stage", "-z")):
        digest.update(git(repo, *args, *selected) + b"\0")
    paths = git(repo, "ls-files", "--others", "--exclude-standard", "-z",
                *selected).split(b"\0")
    for name in filter(None, paths):
        path = repo / os.fsdecode(name)
        if path.is_symlink():
            kind, content = b"l", os.fsencode(os.readlink(path))
        else:
            assert path.is_file(), path
            kind, content = b"f", path.read_bytes()
        digest.update(name + b"\0" + kind + b"\0" +
                      hashlib.sha256(content).hexdigest().encode() + b"\0")
    return digest.hexdigest()


def write_records(dest: Path, records: list[dict]) -> None:
    body = b"".join((json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n").encode()
                    for row in records[:-1])
    records[-1]["sha256"] = hashlib.sha256(body).hexdigest()
    dest.write_bytes(body + (json.dumps(records[-1], sort_keys=True,
                                       separators=(",", ":")) + "\n").encode())


def snapshot(repo: Path, dest: Path) -> None:
    head = git(repo, "rev-parse", "HEAD").strip().decode()
    header = {"t": "h", "format": "qihse-codegraph-v1", "version": 1,
              "head": head, "worktree_v2": worktree_digest(repo),
              "freshness": "git-status-diff-index-untracked-v2",
              "worktree": hashlib.sha256(git(
                  repo, "status", "--porcelain=v1", "-z", "--untracked-files=normal", "--", ".",
                  ":(exclude).code-review-graph") + b"\0" + git(
                      repo, "diff", "--no-ext-diff", "--no-textconv", "--binary", "HEAD", "--", ".",
                      ":(exclude).code-review-graph")).hexdigest()}
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


def assert_no_graph_facts(report: dict) -> None:
    # Legacy stale summaries expose node counts, not a node-record array.
    nodes = report.get("nodes")
    assert nodes is None or (type(nodes) is int and nodes >= 0) or nodes == [], report
    assert report.get("matches") in (None, []), report


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--binary", required=True)
    args = p.parse_args()
    executable = Path(args.binary).resolve()
    if not executable.exists():
        raise RuntimeError("build the native QIHSE codegraph CLI first")
    for arguments in (("--help",), ("serve", "--help")):
        help_result = subprocess.run([str(executable), *arguments], capture_output=True,
                                     text=True, timeout=5, check=False)
        assert help_result.returncode == 0, help_result
        assert "--socket" in help_result.stdout and "--repo" in help_result.stdout, help_result

    with tempfile.TemporaryDirectory(prefix="qihse-codegraph-native-") as directory:
        root = Path(directory)
        repo = root / "repo"
        (repo / "src").mkdir(parents=True)
        (repo / "tests").mkdir()
        (repo / "src/a.c").write_text("int target(void) { return 1; }\n")
        (repo / "src/b.c").write_text("int caller(void) { return target(); }\n")
        (repo / "src/tab\tname.c").write_text("int tabbed(void) { return 1; }\n")
        (repo / "src/unicode-λ.c").write_text("int unicode_name(void) { return 1; }\n")
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
                                    env=env, capture_output=True, text=True, timeout=40,
                                    check=False)
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
        (repo / "src/a.c").write_text("int target(void) { return 1; }\n")
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
        (repo / "src/a.c").write_text("int target(void) { return 1; }\n")
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
        (repo / "src/a.c").write_text("int target(void) { return 1; }\n")
        # Rebase on the published clean source for the next rollback test.
        snapshot(repo, source)
        invoke("import", "--input", str(source))
        assert invoke("status")["fresh"] is True

        for filename, staged in (("src/a.c", False), ("src/a.c", True),
                                 ("src/new file.c", False)):
            path = repo / filename
            path.write_text("int changed(void) { return 10; }\n")
            if staged:
                git(repo, "add", filename)
            snapshot(repo, source)
            porcelain = git(repo, "status", "--porcelain=v1", "-z")
            path.write_text("int changed(void) { return 11; }\n")
            if staged:
                git(repo, "add", filename)
            assert git(repo, "status", "--porcelain=v1", "-z") == porcelain
            rejected = invoke("import", "--input", str(source), expect=1)
            assert "source changed" in rejected["error"], rejected
            snapshot(repo, source)
            invoke("import", "--input", str(source))
            assert invoke("status")["fresh"] is True
            path.write_text("int changed(void) { return 12; }\n")
            if staged:
                git(repo, "add", filename)
            assert git(repo, "status", "--porcelain=v1", "-z") == porcelain
            assert invoke("status")["fresh"] is False
            assert "stale" in invoke("query", "--symbol", "target", expect=2)["error"]
            if filename == "src/a.c":
                path.write_text("int target(void) { return 1; }\n")
                if staged:
                    git(repo, "add", filename)
            else:
                path.unlink()
        # Changing only the index keeps both porcelain and HEAD/worktree diff stable.
        tracked = repo / "src/a.c"
        for indexed in (20, 21):
            tracked.write_text(f"int target(void) {{ return {indexed}; }}\n")
            git(repo, "add", "src/a.c")
            tracked.write_text("int target(void) { return 22; }\n")
            if indexed == 20:
                snapshot(repo, source)
                invoke("import", "--input", str(source))
                porcelain = git(repo, "status", "--porcelain=v1", "-z")
                difference = git(repo, "diff", "HEAD", "--", "src/a.c")
            else:
                assert git(repo, "status", "--porcelain=v1", "-z") == porcelain
                assert git(repo, "diff", "HEAD", "--", "src/a.c") == difference
                assert invoke("status")["fresh"] is False
                rejected = invoke("import", "--input", str(source), expect=1)
                assert "source changed" in rejected["error"], rejected
                assert "stale" in invoke("query", "--symbol", "target", expect=2)["error"]
        tracked.write_text("int target(void) { return 1; }\n")
        git(repo, "add", "src/a.c")
        snapshot(repo, source)
        invoke("import", "--input", str(source))

        # Exact duplicate names are separate seeds; ambiguous edges are not callers.
        ambiguous = root / "ambiguous.jsonl"
        records = [json.loads(line) for line in source.read_text().splitlines()]
        duplicate = {**records[1], "id": node_id("duplicate"), "file": "src/other.c"}
        records.insert(2, duplicate)
        records[-1]["nodes"] += 1
        for row in records:
            if row.get("id") == node_id("ambiguous"):
                row["target"] = node_id("other")
        write_records(ambiguous, records)
        invoke("import", "--input", str(ambiguous))
        duplicates = invoke("query", "--symbol", "target", "--depth", "1")
        assert duplicates["seed_nodes"] == 2 and duplicates["seed_match"] == "exact"
        assert "test_target" not in {n["symbol"] for n in duplicates["nodes"]
                                     if n["hop"] == 0}, duplicates
        partial = invoke("query", "--symbol", "arge", "--depth", "1")
        assert partial["seed_nodes"] == 3 and partial["seed_match"] == "substring", partial
        assert {n["file"] for n in duplicates["nodes"] if n["hop"] == 0} == {
            "src/a.c", "src/other.c"}, duplicates
        unresolved = invoke("context", "--symbol", "caller", "--depth", "1")
        assert unresolved["unresolved_edges"] == 1
        assert "unrelated" not in {n["symbol"] for n in unresolved["nodes"]}, unresolved
        assert all(e["to"] != "unrelated" for e in unresolved["evidence"]), unresolved
        assert "unresolved" in unresolved["uncertainty"], unresolved
        invoke("import", "--input", str(source))

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
        for security in ({"classification": 3}, {"sci": 1}):
            records = [json.loads(line) for line in source.read_text().splitlines()]
            for row in records:
                if row.get("t") == "n" and row.get("name") == "target":
                    row.update(name="classified_marker", **security)
            write_records(high, records)
            before = invoke("status")["generation"]
            denied = invoke("import", "--input", str(high), expect=1)
            assert "classified_marker" not in json.dumps(denied), denied
            assert invoke("status")["generation"] == before
            for command in ("query", "context", "impact", "review"):
                public = invoke(command, "--symbol", "classified_marker", expect=2)
                assert public["fresh"] and public["seed_nodes"] == 0, public
                assert "classified_marker" not in json.dumps(public), public

        state = root / "state/qihse/codegraph" / hashlib.sha256(str(repo).encode()).hexdigest()
        manifest = state / "current.json"
        retained = manifest.read_bytes()
        fifo = root / "interrupted.jsonl"
        os.mkfifo(fifo)
        # Nonregular input is rejected; cancellation uses a regular source and a held
        # publication lock so it cannot race successful publication or merely kill auth.
        with fifo.open("r+b", buffering=0):
            rejected = subprocess.run(
                [str(executable), "import", "--repo", str(repo), "--input", str(fifo)],
                env=env, capture_output=True, text=True, timeout=60, check=False)
        assert rejected.returncode == 1, rejected
        lock_path = state / ".import.lock"
        with lock_path.open("a+b") as held_lock:
            fcntl.flock(held_lock, fcntl.LOCK_EX)
            interrupted = subprocess.Popen(
                [str(executable), "import", "--repo", str(repo), "--input", str(source)],
                env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                deadline = time.monotonic() + 60
                while True:
                    assert interrupted.poll() is None, interrupted.communicate(timeout=5)
                    descriptors = Path(f"/proc/{interrupted.pid}/fd")
                    try:
                        waiting = any(fd.resolve() == lock_path for fd in descriptors.iterdir())
                    except (FileNotFoundError, PermissionError):
                        waiting = False
                    if waiting:
                        break
                    assert time.monotonic() < deadline, "import did not reach publication lock"
                    time.sleep(0.02)
                interrupted.terminate()
                interrupted.communicate(timeout=5)
                assert interrupted.returncode == -signal.SIGTERM
            finally:
                if interrupted.poll() is None:
                    interrupted.kill()
                    interrupted.communicate(timeout=5)
        assert manifest.read_bytes() == retained
        assert invoke("status")["fresh"] is True
        for flag in ("assume-unchanged", "skip-worktree"):
            git(repo, "update-index", "--" + flag, "src/a.c")
            try:
                flagged = invoke("query", "--symbol", "target", expect=2)
                assert not flagged["fresh"], flagged
                assert_no_graph_facts(flagged)
                assert "flags" in flagged["stale_reason"], flagged
            finally:
                git(repo, "update-index", "--no-" + flag, "src/a.c")
            assert invoke("status")["fresh"] is True

        # Inject ENOSPC at each atomic publication boundary, without depending on a
        # privileged tiny filesystem or exhausting the machine's real disk.
        failure_source = root / "publication_failure.c"
        failure_library = root / "publication_failure.so"
        failure_source.write_text(r'''
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
static int manifest_committed, capability_committed;
static int phase(void) {
    const char *path = getenv("CODEGRAPH_TEST_ARM");
    FILE *file = path ? fopen(path, "r") : NULL;
    if (!file) return 0;
    int value = fgetc(file);
    fclose(file);
    return value;
}
int rename(const char *source, const char *destination) {
    const char *mode = getenv("CODEGRAPH_TEST_ENOSPC");
    int token = strstr(destination, "/reader.token") != NULL;
    if (mode && ((strcmp(mode,"snapshot")==0 && strstr(source,"/.snapshot-") &&
                  strstr(destination,"/graph-")) ||
                 (strcmp(mode,"manifest")==0 && strstr(destination,"/current.json")) ||
                 (strcmp(mode,"capability")==0 && token && phase()=='R'))) {
        errno=ENOSPC;
        return -1;
    }
    int (*next)(const char *, const char *) = dlsym(RTLD_NEXT, "rename");
    int result = next(source, destination);
    if (!result && strstr(destination, "/current.json")) manifest_committed = 1;
    if (!result && token) capability_committed = 1;
    return result;
}
int fsync(int fd) {
    const char *mode = getenv("CODEGRAPH_TEST_ENOSPC");
    struct stat info;
    if (mode && !fstat(fd, &info) && S_ISDIR(info.st_mode)) {
        if (!strcmp(mode,"manifest-sync") && manifest_committed) {
            errno=ENOSPC;
            return -1;
        }
        if (!strcmp(mode,"capability") && capability_committed && phase()=='S') {
            char descriptor[64], path[4096];
            snprintf(descriptor, sizeof(descriptor), "/proc/self/fd/%d", fd);
            ssize_t length = readlink(descriptor, path, sizeof(path)-1);
            if (length >= 0) {
                path[length] = 0;
                const char *expected = getenv("CODEGRAPH_TEST_TOKEN_DIR");
                if (expected && !strcmp(path, expected)) {
                    capability_committed = 0;
                    errno=ENOSPC;
                    return -1;
                }
            }
        }
    }
    int (*next)(int) = dlsym(RTLD_NEXT, "fsync");
    return next(fd);
}
''')
        subprocess.run(["cc", "-shared", "-fPIC", str(failure_source), "-o",
                        str(failure_library), "-ldl"], check=True, capture_output=True)
        for failure in ("snapshot", "manifest"):
            failed = subprocess.run(
                [str(executable), "import", "--repo", str(repo), "--input", str(source)],
                env={**env, "LD_PRELOAD": str(failure_library), "CODEGRAPH_TEST_ENOSPC": failure},
                capture_output=True, text=True, timeout=60, check=False)
            assert failed.returncode == 1, (failure, failed.stdout, failed.stderr)
            assert manifest.read_bytes() == retained, failure
            assert invoke("status")["fresh"] is True
            assert not list(state.glob("*.tmp-*")), failure

        before_sync = invoke("status")["generation"]
        uncertain = subprocess.run(
            [str(executable), "import", "--repo", str(repo), "--input", str(source)],
            env={**env, "LD_PRELOAD": str(failure_library), "CODEGRAPH_TEST_ENOSPC": "manifest-sync"},
            capture_output=True, text=True, timeout=60, check=False)
        assert uncertain.returncode == 1 and "durability" in uncertain.stdout, uncertain
        after_sync = invoke("status")
        assert after_sync["fresh"] and after_sync["generation"] != before_sync, after_sync
        assert (state / before_sync).is_file(), "old pinned generation was removed"

        sock = root / "reader.sock"
        token_path = root / "reader.token"
        pool_path = root / "resident.pool"
        def start_reader(workers=4):
            process = subprocess.Popen(
                [str(executable), "serve", "--repo", str(repo), "--socket", str(sock),
                 "--token-file", str(token_path), "--idle-seconds", "60", "--workers", str(workers),
                 "--memory-limit-mib", "1024", "--pool-file", str(pool_path),
                 "--pool-budget-mib", "1024"], env=env,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline and process.poll() is None:
                if sock.exists() and token_path.exists():
                    try:
                        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as probe:
                            probe.settimeout(8)
                            probe.connect(str(sock))
                            capability = token_path.read_text().strip()
                            probe.sendall((json.dumps({"token": capability,
                                                       "command": "ping"}) + "\n").encode())
                            with probe.makefile("rb") as stream:
                                assert json.loads(stream.readline())["status"] == "ready"
                        return process
                    except (FileNotFoundError, ConnectionRefusedError):
                        pass
                time.sleep(0.02)
            process.terminate()
            stdout, stderr = process.communicate(timeout=5)
            raise AssertionError(("reader startup exceeded 30 seconds", process.returncode,
                                  stdout, stderr))

        def stop_reader(process):
            process.terminate()
            try:
                process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.communicate(timeout=5)

        daemon = start_reader()
        try:
            token = token_path.read_text().strip()
            assert resource.prlimit(daemon.pid, resource.RLIMIT_AS) == (1 << 30, 1 << 30)
            denied_pool = invoke("serve", "--socket", str(root / "denied.sock"),
                                 "--token-file", str(root / "denied.token"),
                                 "--memory-limit-mib", "1024", "--pool-file", str(pool_path),
                                 "--pool-budget-mib", "1024", expect=1)
            assert "memory budget unavailable" in denied_pool["error"], denied_pool
            assert not (root / "denied.sock").exists()
            fragmented = root / "fragmented.pool"
            with fragmented.open("w+b") as held:
                fragmented.chmod(0o600)
                # A free first slot must not hide reservations beyond a lowered budget.
                fcntl.lockf(held, fcntl.LOCK_EX, 1024, 1024, os.SEEK_SET)
                lowered = invoke("serve", "--socket", str(root / "denied.sock"),
                                 "--token-file", str(root / "denied.token"), "--idle-seconds", "1",
                                 "--memory-limit-mib", "1024", "--pool-file", str(fragmented),
                                 "--pool-budget-mib", "1024", expect=1)
                assert "memory budget unavailable" in lowered["error"], lowered
                fcntl.lockf(held, fcntl.LOCK_UN, 1024, 1024, os.SEEK_SET)
            pool_link = root / "unsafe.pool"
            pool_link.symlink_to(pool_path)
            denied_link = invoke("serve", "--socket", str(root / "denied.sock"),
                                 "--token-file", str(root / "denied.token"),
                                 "--memory-limit-mib", "1024", "--pool-file", str(pool_link),
                                 "--pool-budget-mib", "2048", expect=1)
            assert "memory budget unavailable" in denied_link["error"], denied_link
            daemon.kill()
            daemon.communicate(timeout=5)
            daemon = start_reader()
            token = token_path.read_text().strip()
            assert len(token) == 64 and int(token, 16) >= 0
            assert stat.S_IMODE(sock.stat().st_mode) == 0o600
            assert stat.S_IMODE(token_path.stat().st_mode) == 0o600

            def request(**params):
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as peer:
                    peer.settimeout(8)
                    peer.connect(str(sock))
                    peer.sendall((json.dumps(params) + "\n").encode())
                    with peer.makefile("rb") as stream:
                        return json.loads(stream.readline())

            large_source = repo / "hash-budget.bin"
            bounded_snapshot = root / "hash-budget.jsonl"
            large_source.write_bytes(b"small source\n")
            try:
                snapshot(repo, bounded_snapshot)
                invoke("import", "--input", str(bounded_snapshot))
                assert request(token=token, command="context", symbol="target")["fresh"]
                with large_source.open("r+b") as sparse:
                    sparse.truncate(1 << 40)
                started = time.monotonic()
                bounded = request(token=token, command="context", symbol="target")
                assert time.monotonic() - started < 8, bounded
                assert bounded.get("fresh") is False or "error" in bounded, bounded
                assert_no_graph_facts(bounded)
            finally:
                large_source.unlink()
                invoke("import", "--input", str(source))
            assert request(token=token, command="context", symbol="target")["fresh"]

            for cmd in ("ping", "status", "query", "impact", "review", "context", "revoke"):
                for capability in (None, "0" * 64, "bad-token"):
                    response = request(token=capability, command=cmd,
                                       symbol="classified_marker")
                    assert "denied" in response["error"], response
                    assert "classified_marker" not in json.dumps(response)
            assert request(token=token, command="revoke")["status"] == "revoked"
            assert "denied" in request(token=token, command="ping")["error"]
            token = token_path.read_text().strip()
            assert request(token=token, command="ping")["status"] == "ready"

            if os.geteuid() == 0:
                root.chmod(0o711)
                sock.chmod(0o666)
                try:
                    script = (
                        "import json,socket,sys; "
                        "s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); "
                        "s.settimeout(8); s.connect(sys.argv[1]); "
                        "s.sendall((json.dumps({'token':sys.argv[2],"
                        "'command':'context','symbol':'classified_marker'})+'\\n').encode()); "
                        "print(s.makefile('rb').readline().decode())")
                    peer = subprocess.run([sys.executable, "-c", script, str(sock), token],
                                          user=65534, group=65534, extra_groups=[],
                                          capture_output=True, text=True, timeout=10,
                                          check=False)
                    assert peer.returncode == 0, (peer.stdout, peer.stderr)
                    response = json.loads(peer.stdout)
                    assert "peer denied" in response["error"], response
                    assert "classified_marker" not in peer.stdout
                finally:
                    sock.chmod(0o600)
                    root.chmod(0o700)
            else:
                print("SO_PEERCRED cross-UID negative test requires root: SKIP")

            # A client may abandon its response without killing the resident reader.
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as abandoned:
                abandoned.connect(str(sock))
                abandoned.sendall((json.dumps({"token": token, "command": "context",
                                              "symbol": "target"}) + "\n").encode())
                abandoned.shutdown(socket.SHUT_RDWR)
            assert request(token=token, command="ping")["status"] == "ready"

            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as slow:
                slow.settimeout(8)
                slow.connect(str(sock))
                slow.sendall(b"{")
                started = time.monotonic()
                for _ in range(8):
                    if select.select([slow], [], [], 1)[0]:
                        rejected = json.loads(slow.makefile("rb").readline())
                        assert "error" in rejected, rejected
                        break
                    slow.sendall(b" ")
                else:
                    raise AssertionError("partial bytes reset the overall request deadline")
                assert time.monotonic() - started < 7
            assert request(token=token, command="ping")["status"] == "ready"
            baseline_threads = next(line for line in Path(f"/proc/{daemon.pid}/status").read_text().splitlines()
                                    if line.startswith("Threads:"))
            partials = []
            replies = {}
            try:
                for _ in range(24):
                    partial = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    partial.settimeout(8)
                    partial.connect(str(sock))
                    partial.sendall(b"{")
                    partials.append(partial)
                ready, _, _ = select.select(partials, [], [], 2)
                assert ready, "bounded queue did not reject overload"
                for partial in ready:
                    reply = json.loads(partial.makefile("rb").readline())
                    assert "busy" in reply["error"], reply
                    replies[partial] = reply
                active_threads = next(line for line in Path(f"/proc/{daemon.pid}/status").read_text().splitlines()
                                      if line.startswith("Threads:"))
                assert active_threads == baseline_threads, (baseline_threads, active_threads)
            finally:
                for partial in partials:
                    try:
                        partial.shutdown(socket.SHUT_WR)
                    except OSError:
                        pass
                for partial in partials:
                    try:
                        if partial not in replies:
                            assert "error" in json.loads(partial.makefile("rb").readline())
                    finally:
                        partial.close()
            assert request(token=token, command="ping")["status"] == "ready"
            for command in ("query", "impact", "review", "context"):
                direct = invoke(command, "--symbol", "target", "--depth", "2")
                resident = request(token=token, command=command, symbol="target", depth=2)
                assert resident == direct, (command, resident, direct)
                fast = invoke(command, "--symbol", "target", "--depth", "2",
                              "--socket", str(sock), "--token-file", str(token_path))
                assert fast == direct, (command, fast, direct)
            fast_missing = invoke("query", "--symbol", "absent_name", "--socket", str(sock),
                                  "--token-file", str(token_path), expect=2)
            assert fast_missing["seed_nodes"] == 0, fast_missing
            unavailable = root / "unavailable.sock"
            refused = invoke("query", "--symbol", "target", "--socket", str(unavailable),
                             "--token-file", str(token_path), expect=1)
            assert "unavailable" in refused["error"], refused
            fallback = invoke("context", "--symbol", "target", "--socket", str(unavailable),
                              "--token-file", str(token_path), "--fallback", "oneshot")
            assert fallback == invoke("context", "--symbol", "target"), fallback
            token_path.chmod(0o644)
            try:
                denied = invoke("query", "--symbol", "target", "--socket", str(sock),
                                "--token-file", str(token_path), "--fallback", "oneshot",
                                expect=1)
                assert "capability" in denied["error"], denied
            finally:
                token_path.chmod(0o600)
            for command in ("query", "context", "impact", "review"):
                compact = request(token=token, command=command, symbol="target", compact=True)
                assert compact["schema"] == "qihse.codegraph.search.v1", compact
                assert compact["status"] == "ok" and compact["fresh"], compact
                assert compact["strategy"] == "exact" and compact["strategy_reason"], compact
                assert all(key in compact for key in ("matches", "relations", "unresolved",
                                                       "truncated", "generation", "timing_us"))
                assert compact["matches"] and all(node["id"] for node in compact["matches"])
                assert all(value >= 0 for value in compact["timing_us"].values()), compact
                assert compact["timing_us"]["auth"] == 0, compact
                fast = invoke(command, "--symbol", "target", "--socket", str(sock),
                              "--token-file", str(token_path), "--compact")
                assert fast["schema"] == compact["schema"], fast
                assert fast["matches"] == compact["matches"], (fast, compact)
            for command in ("impact", "review"):
                direct = invoke(command, "--file", "src/a.c")
                resident = request(token=token, command=command, files=["src/a.c"])
                assert resident == direct, (command, resident, direct)
                assert request(token=token, command=command, base="HEAD") == invoke(
                    command, "--base", "HEAD")
            result = request(token=token, command="context",
                             symbol="classified_marker")
            assert "classified_marker" not in json.dumps(result), result
            good = request(token=token, command="context", symbol="target")
            assert good["fresh"] and good["nodes"], good
            batch = request(token=token, command="context", symbols=["target", "caller"])
            assert batch["fresh"] and batch["nodes"], batch
            identities = [(n["file"], n["symbol"], n["line_start"])
                          for n in batch["nodes"]]
            assert len(identities) == len(set(identities)), batch
            expected_nodes = set()
            for symbol in ("target", "caller"):
                single = request(token=token, command="context", symbol=symbol)
                expected_nodes.update((n["file"], n["symbol"], n["line_start"])
                                      for n in single["nodes"])
            assert set(identities) == expected_nodes, batch
            assert set(batch["symbol_results"]) == {"target", "caller"}, batch
            for names, limit in ((["target", "leaf"], 2), (["target", "leaf", "caller"], 3)):
                ranked = request(token=token, command="context", symbols=names, depth=1,
                                 limit=limit, max_tokens=4000)
                assert {node["symbol"] for node in ranked["nodes"]} == set(names), ranked
                assert all(node["hop"] == 0 for node in ranked["nodes"]), ranked
                retained_ids = {node["id"] for node in ranked["nodes"]}
                assert all(edge["from_id"] in retained_ids and edge["to_id"] in retained_ids
                           for edge in ranked["evidence"]), ranked
                assert all(ranked["symbol_results"][name]["node_ids"] for name in names), ranked
                if "caller" in names:
                    expected_edges = {(node_id("caller"), node_id("target")),
                                      (node_id("caller"), node_id("leaf"))}
                    assert expected_edges <= {(edge["from_id"], edge["to_id"])
                                              for edge in ranked["evidence"]}, ranked
            for symbol, result in batch["symbol_results"].items():
                single = request(token=token, command="context", symbol=symbol)
                assert result["seed_nodes"] == single["seed_nodes"], (symbol, result, single)
                assert result["seed_match"] == single["seed_match"], (symbol, result, single)
            missing = request(token=token, command="context",
                              symbols=["caller", "not_indexed_symbol", "target"])
            assert set(missing["symbol_results"]) == {
                "caller", "not_indexed_symbol", "target"}, missing
            assert missing["symbol_results"]["not_indexed_symbol"]["seed_nodes"] == 0, missing
            assert "error" in missing["symbol_results"]["not_indexed_symbol"], missing
            assert missing["symbol_results"]["caller"]["seed_nodes"] == 1, missing
            assert missing["symbol_results"]["target"]["seed_nodes"] == 1, missing
            repeated = request(token=token, command="context",
                               symbols=["target", "caller", "target"])
            assert repeated["nodes"] == batch["nodes"], (repeated, batch)
            for limits in ({"limit": 2}, {"max_tokens": 128}):
                bounded = request(token=token, command="context",
                                  symbols=["target", "caller"], **limits)
                assert bounded["fresh"] and bounded["truncated"], bounded
                if "limit" in limits:
                    assert 0 < len(bounded["nodes"]) <= 2, bounded
                else:
                    # The shared budget includes correspondence and provenance, not
                    # only facts; a tiny budget can legitimately fit metadata alone.
                    wire = json.dumps(bounded, separators=(",", ":"), ensure_ascii=False).encode()
                    assert len(wire) <= limits["max_tokens"] * 4, bounded
                    assert len(bounded["nodes"]) <= 1, bounded
                returned_ids = {node["id"] for node in bounded["nodes"]}
                assert all(set(result["node_ids"]) <= returned_ids
                           for result in bounded["symbol_results"].values()), bounded
            base_generation = request(token=token, command="context", symbol="target")["generation"]
            published = threading.Event()
            expected_generation = []
            def read_during_publication():
                seen = []
                for _ in range(600):
                    item = request(token=token, command="context", symbol="target")
                    seen.append(item)
                    if published.is_set() and item.get("fresh") and item["generation"] == expected_generation[0]:
                        return seen
                raise AssertionError("publication readers did not converge")
            with ThreadPoolExecutor(max_workers=4) as readers:
                active = [readers.submit(read_during_publication) for _ in range(4)]
                try:
                    updated = invoke("import", "--input", str(ambiguous))
                    expected_generation.append(updated["snapshot"])
                finally:
                    if not expected_generation:
                        expected_generation.append("failed-publication")
                    published.set()
                for reader in active:
                    seen = reader.result(timeout=30)
                    assert any(item.get("generation") == base_generation and item.get("fresh") for item in seen)
                    assert seen[-1]["generation"] == updated["snapshot"] and seen[-1]["seed_nodes"] == 2
                    for item in seen:
                        if "error" in item:
                            assert item.get("fresh") is not True, item
                            assert_no_graph_facts(item)
                        else:
                            assert item["fresh"], item
                            expected = 1 if item["generation"] == base_generation else 2
                            assert item["seed_nodes"] == expected, item
            invoke("import", "--input", str(source))
            old_generation = good["generation"]
            invoke("import", "--input", str(ambiguous))
            replacement = request(token=token, command="query", symbol="target")
            assert replacement["generation"] != old_generation, replacement
            assert replacement["seed_nodes"] == 2, replacement
            ambiguous_batch = request(token=token, command="context",
                                      symbols=["target", "caller"])
            assert ambiguous_batch["symbol_results"]["target"]["seed_nodes"] == 2, ambiguous_batch
            assert ambiguous_batch["symbol_results"]["caller"]["seed_nodes"] == 1, ambiguous_batch
            assert "unrelated" not in {n["symbol"] for n in ambiguous_batch["nodes"]}
            invoke("import", "--input", str(source))
            restored = request(token=token, command="context", symbol="target")
            assert restored["seed_nodes"] == 1, restored
            current = manifest.read_bytes()
            invoke("import", "--input", str(broken), expect=1)
            assert manifest.read_bytes() == current
            assert request(token=token, command="context", symbol="target") == restored

            invalid = state / "invalid.json"
            for contents in (b"{broken", b"{}"):
                invalid.write_bytes(contents)
                invalid.replace(manifest)
                refused = request(token=token, command="context", symbol="target")
                assert "error" in refused, refused
                assert_no_graph_facts(refused)
                invalid.write_bytes(current)
                invalid.replace(manifest)
                assert request(token=token, command="context", symbol="target") == restored
            damaged = state / "graph-damaged.kv"
            damaged.write_bytes(b"not a valid QIHSE KV snapshot\n")
            corrupt_manifest = json.loads(current)
            corrupt_manifest.update(snapshot=damaged.name,
                                    sha256=hashlib.sha256(damaged.read_bytes()).hexdigest())
            invalid.write_text(json.dumps(corrupt_manifest))
            invalid.replace(manifest)
            refused = request(token=token, command="context", symbol="target")
            assert "error" in refused, refused
            assert_no_graph_facts(refused)
            invalid.write_bytes(current)
            invalid.replace(manifest)
            assert request(token=token, command="context", symbol="target") == restored

            for filename, staged in (("src/a.c", False), ("src/a.c", True),
                                     ("src/new file.c", False)):
                path = repo / filename
                path.write_text("int changed(void) { return 30; }\n")
                if staged:
                    git(repo, "add", filename)
                snapshot(repo, source)
                invoke("import", "--input", str(source))
                assert request(token=token, command="context", symbol="target")["fresh"]
                porcelain = git(repo, "status", "--porcelain=v1", "-z")
                path.write_text("int changed(void) { return 31; }\n")
                if staged:
                    git(repo, "add", filename)
                assert git(repo, "status", "--porcelain=v1", "-z") == porcelain
                for command in ("context", "query", "impact", "review"):
                    stale = request(token=token, command=command, symbol="target")
                    assert "stale" in stale["error"], stale
                    assert_no_graph_facts(stale)
                stale = request(token=token, command="context", symbols=["target", "caller"])
                assert "stale" in stale["error"], stale
                assert_no_graph_facts(stale)
                if filename == "src/a.c":
                    path.write_text("int target(void) { return 1; }\n")
                    if staged:
                        git(repo, "add", filename)
                else:
                    path.unlink()
            snapshot(repo, source)
            invoke("import", "--input", str(source))
            restored = request(token=token, command="context", symbol="target")
            assert restored["fresh"] and restored["nodes"], restored
            (repo / "src/a.c").write_text("int target(void) { return 9; }\n")
            for command in ("context", "query", "impact", "review"):
                stale = request(token=token, command=command, symbols=["target"])
                assert stale.get("fresh") is not True and "stale" in stale["error"], stale
            (repo / "src/a.c").write_text("int target(void) { return 1; }\n")
            assert request(token=token, command="context", symbol="target") == restored
        finally:
            stop_reader(daemon)

        idle = subprocess.run(
            [str(executable), "serve", "--repo", str(repo), "--socket", str(sock),
             "--token-file", str(token_path), "--idle-seconds", "1", "--memory-limit-mib", "1024",
             "--pool-file", str(pool_path), "--pool-budget-mib", "1024"],
            env=env, capture_output=True, text=True, timeout=40, check=False)
        assert idle.returncode == 0, (idle.stdout, idle.stderr)
        assert not sock.exists() and not token_path.exists(), "idle reader did not retire"

        # Inject a real edit after the pre-query Git observation, rather than racing a
        # timer. Post-query source/generation checks must discard the assembled facts.
        shim_dir = root / "git-shim"
        shim_dir.mkdir()
        arm = root / "query-mutation.json"
        shim = shim_dir / "git"
        real_git = shutil.which("git")
        assert real_git
        shim.write_text(
            f"#!{sys.executable}\n"
            "import json,subprocess,sys,time\nfrom pathlib import Path\n"
            f"result=subprocess.run([{real_git!r},*sys.argv[1:]],check=False)\n"
            f"arm=Path({str(arm)!r})\n"
            "if '--others' in sys.argv and arm.exists():\n"
            " operation=json.loads(arm.read_text()); arm.unlink()\n"
            " if operation.get('pause'):\n"
            "  with open(operation['ready'],'wb',buffering=0) as ready: ready.write(b'R')\n"
            "  with open(operation['pause'],'rb',buffering=0) as gate: gate.read(1)\n"
            " elif operation.get('hang'):\n"
            "  child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)'])\n"
            "  Path(operation['pid_path']).write_text(str(child.pid))\n"
            "  time.sleep(60)\n"
            " else:\n"
            "  Path(operation['path']).write_text(operation['content'])\n"
            "sys.exit(result.returncode)\n")
        shim.chmod(0o700)
        previous_path = env.get("PATH", "")
        env["PATH"] = str(shim_dir) + os.pathsep + previous_path
        daemon = start_reader()
        try:
            token = token_path.read_text().strip()
            for path, content in ((repo / "src/a.c", "int target(void) { return 99; }\n"),
                                  (manifest, "{}\n")):
                retained_bytes = path.read_bytes()
                try:
                    arm.write_text(json.dumps({"path": str(path), "content": content}))
                    raced = request(token=token, command="context", symbols=["target", "caller"])
                    assert not arm.exists(), "query never exercised freshness hook"
                    assert raced.get("fresh") is not True, raced
                    assert_no_graph_facts(raced)
                    assert "error" in raced, raced
                finally:
                    path.write_bytes(retained_bytes)
                assert request(token=token, command="context", symbol="target")["fresh"]
            child_pid_path = root / "hung-git-child.pid"
            arm.write_text(json.dumps({"hang": True, "pid_path": str(child_pid_path)}))
            started = time.monotonic()
            timed_out = request(token=token, command="context", symbol="target")
            assert time.monotonic() - started < 8, timed_out
            assert_no_graph_facts(timed_out)
            assert timed_out["fresh"] is False and "error" in timed_out, timed_out
            assert child_pid_path.exists(), "Git hang hook did not execute"
            if hasattr(os, "pidfd_open"):
                try:
                    child_fd = os.pidfd_open(int(child_pid_path.read_text()))
                except ProcessLookupError:
                    pass
                else:
                    try:
                        assert select.select([child_fd], [], [], 5)[0], "Git descendant survived timeout"
                    finally:
                        os.close(child_fd)
            assert request(token=token, command="context", symbol="target")["fresh"]
            ready_fifo, release_fifo = root / "git-ready", root / "git-release"
            os.mkfifo(ready_fifo)
            os.mkfifo(release_fifo)
            ready_fd = os.open(ready_fifo, os.O_RDONLY | os.O_NONBLOCK)
            release_fd = os.open(release_fifo, os.O_RDWR | os.O_NONBLOCK)
            try:
                arm.write_text(json.dumps({"pause": str(release_fifo), "ready": str(ready_fifo)}))
                with ThreadPoolExecutor(max_workers=1) as reader:
                    active = reader.submit(request, token=token, command="context", symbol="target")
                    assert select.select([ready_fd], [], [], 5)[0], "query did not reach Git barrier"
                    assert os.read(ready_fd, 1) == b"R"
                    assert request(token=token, command="revoke")["status"] == "revoked"
                    token = token_path.read_text().strip()
                    os.write(release_fd, b"R")
                    revoked = active.result(timeout=8)
                    assert "revoked" in revoked["error"], revoked
                    assert_no_graph_facts(revoked)
                assert request(token=token, command="context", symbol="target")["fresh"]
            finally:
                os.close(ready_fd)
                os.close(release_fd)
        finally:
            stop_reader(daemon)
            env["PATH"] = previous_path

        old_token = token
        capability_arm = root / "capability-failure.arm"
        env.update(LD_PRELOAD=str(failure_library), CODEGRAPH_TEST_ENOSPC="capability",
                   CODEGRAPH_TEST_ARM=str(capability_arm), CODEGRAPH_TEST_TOKEN_DIR=str(root))
        daemon = start_reader(1)
        try:
            token = token_path.read_text().strip()
            assert token != old_token
            assert "denied" in request(token=old_token, command="context",
                                       symbol="target")["error"]
            restarted = request(token=token, command="context", symbol="target")
            assert restarted == invoke("context", "--symbol", "target"), restarted
            capability_arm.write_text("R")
            failed_rotation = request(token=token, command="revoke")
            assert "error" in failed_rotation, failed_rotation
            assert token_path.read_text().strip() == token
            assert request(token=token, command="context", symbol="target")["fresh"]
            capability_arm.write_text("S")
            uncertain_rotation = request(token=token, command="revoke")
            assert "error" in uncertain_rotation, uncertain_rotation
            replacement_token = token_path.read_text().strip()
            assert replacement_token != token
            assert "denied" in request(token=token, command="context", symbol="target")["error"]
            assert request(token=replacement_token, command="context", symbol="target")["fresh"]
            capability_arm.unlink()
            assert request(token=replacement_token, command="revoke")["status"] == "revoked"
            assert request(token=token_path.read_text().strip(), command="context", symbol="target")["fresh"]
        finally:
            stop_reader(daemon)

    print("QIHSE CodeGraph native persistence, traversal and staleness: OK")


if __name__ == "__main__":
    main()
