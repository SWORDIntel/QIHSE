#!/usr/bin/env python3
"""Storage migration, deduplication, and garbage-collection CLI regressions.

All state and graph records are synthetic and confined to a temporary directory.
Legacy snapshots are produced by the authenticated QIHSE SDK, not a raw encoder.
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
from concurrent.futures import ThreadPoolExecutor

from test_codegraph_native import git, snapshot

LEGACY_WRITER = r'''
#define _GNU_SOURCE
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <json-c/json.h>
#include "qihse_auth.h"
#include "qihse_kv_store.h"
#include "qihse_codegraph_storage.h"
int main(int argc, char **argv) {
    assert(argc == 3);
    const char *password = "CodeGraphLegacyFixture1!";
    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator(password));
    qihse_user_t *user = qihse_auth_authenticate_id(0, password);
    assert(user);
    qihse_kv_store_t *store = qihse_kv_store_create_user(user);
    assert(store);
    FILE *input = fopen(argv[1], "r");
    assert(input);
    char *line = NULL; size_t capacity = 0;
    while (getline(&line, &capacity, input) >= 0) {
        struct json_object *row = json_tokener_parse(line), *value;
        assert(row && json_object_object_get_ex(row, "t", &value));
        const char *type = json_object_get_string(value);
        char key[72];
        if (!strcmp(type, "h")) strcpy(key, "_meta");
        else if (!strcmp(type, "end")) strcpy(key, "_end");
        else {
            assert(json_object_object_get_ex(row, "id", &value));
            snprintf(key, sizeof(key), "%s:%s", type, json_object_get_string(value));
        }
        int protected_node = getenv("CODEGRAPH_PROTECTED_FIXTURE") &&
                             !strncmp(key, "n:", 2);
        assert(qihse_kv_set_user(store, key, line, protected_node ? 4 : 0,
                                 protected_node ? 2 : 0, user));
        json_object_put(row);
    }
    assert(!ferror(input)); fclose(input); free(line);
    if (getenv("CODEGRAPH_PACKED_FIXTURE"))
        assert(cg_storage_save_packed(store, argv[2], user));
    else
        assert(qihse_kv_save_user(store, argv[2], user) == 0);
    qihse_kv_store_destroy(store);
    return 0;
}
'''


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True)
    args = parser.parse_args()
    binary = Path(args.binary).resolve()
    project = Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory(prefix="qihse-codegraph-storage-") as temp:
        root = Path(temp)
        repo = root / "repo"
        (repo / "src").mkdir(parents=True)
        (repo / "tests").mkdir()
        (repo / "src/a.c").write_text("int target(void) { return 1; }\n")
        (repo / "src/b.c").write_text("int caller(void) { return target(); }\n")
        (repo / "tests/test_a.c").write_text("void test_target(void) {}\n")
        git(repo, "init", "-q")
        git(repo, "add", ".")
        git(repo, "-c", "user.name=StorageTest", "-c",
            "user.email=storage@example.invalid", "commit", "-qm", "baseline")
        env = {**os.environ, "HOME": str(root), "XDG_STATE_HOME": str(root / "state"),
               "LD_LIBRARY_PATH": str(binary.parent) + ":" +
               os.environ.get("LD_LIBRARY_PATH", "")}

        def invoke(*tokens: str, expect: int = 0) -> dict:
            result = subprocess.run([str(binary), *tokens, "--repo", str(repo)],
                                    env=env, capture_output=True, text=True, timeout=90)
            assert result.returncode == expect, (tokens, result.returncode,
                                                  result.stdout, result.stderr)
            return json.loads(result.stdout)

        source = root / "source.jsonl"
        snapshot(repo, source)
        invoke("import", "--input", str(source))
        state = root / "state/qihse/codegraph" / hashlib.sha256(str(repo).encode()).hexdigest()
        manifest_path = state / "current.json"

        def manifest() -> dict:
            return json.loads(manifest_path.read_text())

        original = manifest()
        assert original["storage_format"] == "qihse-codegraph-zstd-v1", original
        current_stats = invoke("stats")
        current_file = state / original["snapshot"]
        assert current_stats["coverage"] == "authorized_current_generation", current_stats
        assert current_stats["storage_format"] == "qihse-codegraph-zstd-v1"
        assert current_stats["encoded_bytes"] == current_file.stat().st_size
        assert current_stats["allocated_bytes"] == current_file.stat().st_blocks * 512
        assert current_stats["decoded_bytes"] > current_stats["encoded_bytes"]
        baseline = invoke("context", "--symbol", "caller", "--depth", "2")
        generation_files = set(state.glob("graph-*.kv"))
        duplicate = invoke("import", "--input", str(source))
        assert duplicate["status"] == "unchanged", duplicate
        assert manifest() == original
        assert set(state.glob("graph-*.kv")) == generation_files

        # A matching input digest cannot authorize reuse of an unreadable or
        # unsupported current snapshot. Re-import must repair it by publication.
        for damage in ("unknown-format", "corrupt-snapshot"):
            damaged = manifest()
            damaged_name = damaged["snapshot"]
            if damage == "unknown-format":
                damaged["storage_format"] = "unsupported-storage-version"
                manifest_path.write_text(json.dumps(damaged))
            else:
                (state / damaged_name).write_bytes(b"damaged compact snapshot")
            repaired = invoke("import", "--input", str(source))
            assert repaired["status"] == "published", (damage, repaired)
            assert manifest()["snapshot"] != damaged_name
            assert invoke("status")["fresh"]
        original = manifest()

        # Create an independently serialized old-format snapshot using the SDK.
        helper_source = root / "legacy_writer.c"
        helper_source.write_text(LEGACY_WRITER)
        helper = root / "legacy_writer"
        json_flags = shlex.split(subprocess.check_output(
            ["pkg-config", "--cflags", "--libs", "json-c", "libzstd", "openssl"], text=True))
        subprocess.run([os.environ.get("CC", "cc"), "-std=c11", "-I" + str(project / "include"),
                        "-I" + str(project / "tools"), str(helper_source),
                        str(project / "tools/qihse_codegraph_storage.c"),
                        str(project / "tools/qihse_codegraph_packed.c"),
                        "-L" + str(binary.parent), "-lqihse", *json_flags,
                        "-o", str(helper)], check=True, capture_output=True)
        helper_data = root / "writer-state"
        helper_data.mkdir(mode=0o700)
        # Historical writers used a decimal PID, not a six-character mkstemps
        # suffix. Seven-digit PIDs exposed the original migration rejection.
        legacy_path = state / ("graph-" + "1" * 64 + "-2777935.kv")
        fixture_result = subprocess.run([str(helper), str(source), str(legacy_path)],
                                        env={**env, "QIHSE_DATA_DIR": str(helper_data)},
                                        capture_output=True, timeout=90)
        assert fixture_result.returncode == 0, (fixture_result.stdout, fixture_result.stderr)
        legacy = {k: v for k, v in original.items()
                  if k not in ("storage_format", "previous_snapshot")}
        legacy.update(snapshot=legacy_path.name,
                      sha256=hashlib.sha256(legacy_path.read_bytes()).hexdigest())
        manifest_path.write_text(json.dumps(legacy))
        assert invoke("status")["fresh"]
        legacy_stats = invoke("stats")
        assert legacy_stats["storage_format"] == "qihse-kv-legacy", legacy_stats
        assert legacy_stats["encoded_bytes"] == legacy_stats["decoded_bytes"] == legacy_path.stat().st_size

        # The CLI reader uses a guest principal. A syntactically valid graph
        # with one SCI-classified record must not disclose sizes or counts.
        protected_data = root / "protected-writer-state"
        protected_data.mkdir(mode=0o700)
        protected_path = state / ("graph-" + "4" * 64 + "-2777936.kv")
        protected_result = subprocess.run([str(helper), str(source), str(protected_path)],
                                          env={**env, "QIHSE_DATA_DIR": str(protected_data),
                                               "CODEGRAPH_PROTECTED_FIXTURE": "1"},
                                          capture_output=True, timeout=90)
        assert protected_result.returncode == 0, (protected_result.stdout, protected_result.stderr)
        protected = {**legacy, "snapshot": protected_path.name,
                     "sha256": hashlib.sha256(protected_path.read_bytes()).hexdigest()}
        manifest_path.write_text(json.dumps(protected))
        denied_stats = invoke("stats", expect=1)
        assert set(denied_stats) == {"error"}, denied_stats
        assert "bytes" not in json.dumps(denied_stats) and "nodes" not in json.dumps(denied_stats)
        manifest_path.write_text(json.dumps(legacy))
        assert invoke("stats") == legacy_stats, "unreferenced classified history affected guest statistics"

        unsupported_path = state / ("graph-" + "1" * 64 + "-letters.kv")
        unsupported_path.write_bytes(legacy_path.read_bytes())
        unsupported = {**legacy, "snapshot": unsupported_path.name}
        manifest_path.write_text(json.dumps(unsupported))
        before_failed_migrate = manifest_path.read_bytes()
        failed = invoke("migrate", expect=1)
        assert "unsupported snapshot filename" in failed["error"], failed
        assert manifest_path.read_bytes() == before_failed_migrate
        manifest_path.write_text(json.dumps(legacy))

        # Migration is physical only: changed source must remain stale.
        clean_source = (repo / "src/a.c").read_text()
        (repo / "src/a.c").write_text(clean_source + "/* changed since indexing */\n")
        assert not invoke("status")["fresh"]
        invoke("migrate")
        converted = manifest()
        assert converted["storage_format"] == "qihse-codegraph-zstd-v1"
        assert converted["snapshot"] != legacy_path.name
        legacy_bytes = legacy_path.stat().st_size
        compact_bytes = (state / converted["snapshot"]).stat().st_size
        print(f"Synthetic fixture bytes: legacy={legacy_bytes}, compact={compact_bytes}", flush=True)
        assert compact_bytes < legacy_bytes
        for key in ("head", "worktree", "freshness", "input_sha256", "nodes", "edges",
                    "unresolved_edges"):
            assert converted[key] == legacy[key], (key, converted, legacy)
        assert not invoke("status")["fresh"]
        stale = invoke("query", "--symbol", "target", expect=2)
        assert not stale["fresh"]
        assert legacy_path.is_file(), "conversion removed its rollback generation"
        (repo / "src/a.c").write_text(clean_source)
        after = invoke("context", "--symbol", "caller", "--depth", "2")
        for key in ("nodes", "evidence", "unresolved_edges", "candidate_tests"):
            assert after[key] == baseline[key], (key, baseline, after)
        before_second_migrate = manifest_path.read_bytes()
        invoke("migrate")
        assert manifest_path.read_bytes() == before_second_migrate

        # Explicit packed-v2 conversion retains freshness, complete graph
        # answers and the previous generation as rollback. The tiny fixture
        # makes no size claim against the current Zstandard format.
        invoke("migrate", "--storage-format", "packed-v2")
        packed = manifest()
        assert packed["storage_format"] == "qihse-codegraph-packed-v2", packed
        assert packed["previous_snapshot"] == converted["snapshot"]
        assert packed["snapshot"] != converted["snapshot"]
        packed_stats = invoke("stats")
        packed_file = state / packed["snapshot"]
        assert packed_stats["storage_format"] == "qihse-codegraph-packed-v2"
        assert packed_stats["encoded_bytes"] == packed_file.stat().st_size
        assert packed_stats["decoded_bytes"] > 0
        for key in ("head", "worktree", "freshness", "input_sha256", "nodes",
                    "edges", "unresolved_edges"):
            assert packed[key] == converted[key], (key, packed, converted)
        assert invoke("context", "--symbol", "caller", "--depth", "2")["evidence"] == baseline["evidence"]
        before_packed_repeat = manifest_path.read_bytes()
        invoke("migrate", "--storage-format", "packed-v2")
        assert manifest_path.read_bytes() == before_packed_repeat

        # A format label cannot redirect the verified packed payload through
        # the legacy/Zstandard loader.
        mismatched = {**packed, "storage_format": "qihse-codegraph-zstd-v1"}
        manifest_path.write_text(json.dumps(mismatched))
        assert "error" in invoke("stats", expect=1)
        wrong_magic = {**packed, "snapshot": converted["snapshot"],
                       "sha256": hashlib.sha256((state / converted["snapshot"]).read_bytes()).hexdigest()}
        manifest_path.write_text(json.dumps(wrong_magic))
        assert "error" in invoke("stats", expect=1)
        assert "error" in invoke("query", "--symbol", "caller", expect=1)
        manifest_path.write_text(json.dumps(packed))

        # New packed adapter negative: a Guest cannot read a syntactically
        # valid, Operator-produced graph with one classified/SCI node.
        protected_packed_path = state / ("graph-" + "5" * 64 + "-2777937.kv")
        protected_packed_data = root / "protected-packed-writer-state"
        protected_packed_data.mkdir(mode=0o700)
        protected_packed_result = subprocess.run(
            [str(helper), str(source), str(protected_packed_path)],
            env={**env, "QIHSE_DATA_DIR": str(protected_packed_data),
                 "CODEGRAPH_PROTECTED_FIXTURE": "1", "CODEGRAPH_PACKED_FIXTURE": "1"},
            capture_output=True, timeout=90)
        assert protected_packed_result.returncode == 0, (
            protected_packed_result.stdout, protected_packed_result.stderr)
        protected_packed = {**packed, "snapshot": protected_packed_path.name,
                            "sha256": hashlib.sha256(protected_packed_path.read_bytes()).hexdigest()}
        manifest_path.write_text(json.dumps(protected_packed))
        for action in ("status", "stats", "query"):
            report = invoke(action, *(["--symbol", "caller"] if action == "query" else []),
                            expect=1)
            assert set(report) == {"error"}, (action, report)
            assert "secret" not in json.dumps(report) and "nodes" not in json.dumps(report)
        manifest_path.write_text(json.dumps(packed))
        assert invoke("stats") == packed_stats

        # GC cannot remove current/previous, active runtime, unmanaged runtime,
        # or files not in the generation namespace.
        obsolete = state / ("graph-" + "2" * 64 + "-unused.kv")
        obsolete.write_bytes(b"obsolete synthetic generation")
        numeric_obsolete = [state / ("graph-" + "2" * 64 + f"-{suffix}.kv")
                            for suffix in ("1", "12345", "2777935", "2147483647")]
        for path in numeric_obsolete:
            path.write_bytes(b"obsolete synthetic PID generation")
        malformed_names = [state / ("graph-" + "3" * 64 + f"-{suffix}.kv")
                           for suffix in ("0", "0123456", "2147483648", "12345678901",
                                          "letters", "+1234567", "-1234567", "1.kv.extra")]
        for path in malformed_names:
            path.write_bytes(b"unmanaged synthetic file")
        unrelated = state / "operator-note.txt"
        unrelated.write_text("retain")
        malformed = state / "graph-unmanaged-fixture.kv"
        malformed.write_bytes(b"not a managed generation")
        unmanaged = state / ".runtime-legacy"
        unmanaged.mkdir(mode=0o700)
        (unmanaged / "marker").write_text("retain")
        dead = state / ".runtime-dead"
        dead.mkdir(mode=0o700)
        (dead / ".lease").touch(mode=0o600)
        (dead / "marker").write_text("reclaim")
        active = state / ".runtime-active"
        active.mkdir(mode=0o700)
        (active / ".lease").touch(mode=0o600)
        with (active / ".lease").open("w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            invoke("gc")
            assert active.is_dir(), "GC removed a locked runtime"
        assert not obsolete.exists()
        assert all(not path.exists() for path in numeric_obsolete)
        assert all(path.is_file() for path in malformed_names)
        assert unsupported_path.is_file()
        assert not legacy_path.exists(), "GC retained an obsolete legacy generation"
        assert (state / converted["snapshot"]).is_file(), "GC removed packed rollback generation"
        assert not dead.exists()
        assert unmanaged.is_dir() and unrelated.is_file() and malformed.is_file()
        current = manifest()
        assert (state / current["snapshot"]).is_file()
        if current.get("previous_snapshot"):
            assert (state / current["previous_snapshot"]).is_file()
        assert invoke("status")["fresh"]
        invoke("gc")
        assert not active.exists(), "GC did not reclaim a released runtime"
        assert invoke("context", "--symbol", "caller", "--depth", "2")["evidence"] == baseline["evidence"]
        # Reader loading and GC must coordinate across separate processes.
        def concurrent_operation(index: int) -> None:
            if index % 3 == 0:
                invoke("gc")
            else:
                report = invoke("context", "--symbol", "caller", "--depth", "2")
                assert report["evidence"] == baseline["evidence"]
        with ThreadPoolExecutor(max_workers=3) as workers:
            list(workers.map(concurrent_operation, range(9)))
        assert invoke("status")["fresh"]
    print("CodeGraph compact storage, migration, deduplication and GC: PASS")


if __name__ == "__main__":
    main()
