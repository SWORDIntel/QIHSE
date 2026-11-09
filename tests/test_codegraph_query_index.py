#!/usr/bin/env python3
"""Opt-in native query indexes: parity, fail-closed fallback and generation lifetime.

Every graph, snapshot, cache and principal in this test is disposable. No configured
QIHSE state is read. Manipulated binary bytes are the test's own synthetic .qci.
"""

from __future__ import annotations

import argparse
import ctypes
import ctypes.util
import hashlib
import json
import math
import os
import shutil
import signal
import socket
import struct
import subprocess
import tempfile
import time
from pathlib import Path

from test_codegraph_native import git, snapshot, snapshot_xxh3_fixture


class Fixture:
    def __init__(self, root: Path, binary: Path):
        self.root = root
        self.binary = root / "native-codegraph"
        shutil.copy2(binary, self.binary)
        self.repo = root / "repo"
        self.repo.mkdir()
        git(self.repo, "init", "-q")
        for name in (
            "src/a.c",
            "src/b.c",
            "src/leaf.c",
            "src/dep.c",
            "src/other.c",
            "tests/test_a.c",
        ):
            path = self.repo / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("int source(void) { return 1; }\n")
        git(self.repo, "add", ".")
        git(
            self.repo,
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=projection@example.invalid",
            "commit",
            "-qm",
            "synthetic",
        )
        self.env = dict(os.environ, XDG_STATE_HOME=str(root / "state"))
        matched = next(
            (
                parent
                for parent in (
                    binary.parent,
                    binary.parent.parent,
                    Path(__file__).resolve().parent.parent,
                )
                if (parent / "libqihse.so").is_file()
            ),
            binary.parent,
        )
        self.env["LD_LIBRARY_PATH"] = (
            str(matched) + os.pathsep + self.env.get("LD_LIBRARY_PATH", "")
        )
        self.directory = (
            root
            / "state/qihse/codegraph"
            / hashlib.sha256(os.fsencode(self.repo)).hexdigest()
        )
        self.manifest_path = self.directory / "current.json"
        self.source = root / "graph.jsonl"
        self.publish(0)

    def invoke(self, *args: str, expect: int = 0, extra_env=None):
        started = time.monotonic()
        env = self.env if not extra_env else dict(self.env, **extra_env)
        result = subprocess.run(
            [str(self.binary), *args, "--repo", str(self.repo)],
            env=env,
            capture_output=True,
            text=True,
            timeout=180,
            check=False,
        )
        assert result.returncode == expect, (
            args,
            result.returncode,
            result.stdout,
            result.stderr,
        )
        report = json.loads(result.stdout)
        return report, time.monotonic() - started

    def manifest(self):
        return json.loads(self.manifest_path.read_text())

    def save_manifest(self, data):
        self.manifest_path.write_text(json.dumps(data))
        self.manifest_path.chmod(0o600)

    def cache(self):
        return self.directory / (self.manifest()["snapshot"] + ".qci")

    def publish(self, version: int):
        (self.repo / "src/a.c").write_text(
            f"int source(void) {{ return {version}; }}\n"
        )
        snapshot(self.repo, self.source)
        report, _ = self.invoke(
            "import", "--input", str(self.source), "--storage-format", "packed-v3"
        )
        assert report["status"] == "published", report

    def query(self, action="query", symbol="caller", expect=0):
        return self.invoke(
            action,
            "--symbol",
            symbol,
            "--depth",
            "3",
            "--match",
            "exact",
            "--timings",
            expect=expect,
        )[0]


def comparable(report):
    omit = {
        "query_index_loaded",
        "query_index_resident_bytes",
        "timings",
        "timing_us",
        "runtime_spill_reclaimed_bytes",
        "runtime_spill_reclaimed_files",
    }
    return {key: value for key, value in report.items() if key not in omit}


def assert_denied(report):
    # --timings legitimately adds content-free serialization timing to errors.
    # Keep the non-disclosure check strict: no node/evidence/count payload.
    assert report.get("error") and set(report) <= {"error", "timings"}, report
    timings = report.get("timings", {})
    assert set(timings) <= {"serialization_ms"}, report
    assert all(
        type(value) in (int, float) and math.isfinite(value) and value >= 0
        for value in timings.values()
    ), report


def zstd_functions():
    library = ctypes.CDLL(ctypes.util.find_library("zstd") or "libzstd.so.1")
    library.ZSTD_compressBound.argtypes = [ctypes.c_size_t]
    library.ZSTD_compressBound.restype = ctypes.c_size_t
    library.ZSTD_compress.argtypes = [
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.c_int,
    ]
    library.ZSTD_compress.restype = ctypes.c_size_t
    library.ZSTD_decompress.argtypes = [
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.c_void_p,
        ctypes.c_size_t,
    ]
    library.ZSTD_decompress.restype = ctypes.c_size_t
    library.ZSTD_isError.argtypes = [ctypes.c_size_t]
    library.ZSTD_isError.restype = ctypes.c_uint
    return library


def negative_line_evidence(encoded: bytes) -> bytes:
    """Build an invalid but structurally sound independently compressed block."""
    library = zstd_functions()
    node_zip, topology_zip = (
        struct.unpack_from(">Q", encoded, offset)[0] for offset in (128, 144)
    )
    string_zip = struct.unpack_from(">Q", encoded, 152)[0]
    chunks = struct.unpack_from(">I", encoded, 160)[0]
    directory = 256 + node_zip + topology_zip + string_zip
    evidence = directory + chunks * 16
    count = struct.unpack_from(">I", encoded, directory)[0]
    size = struct.unpack_from(">Q", encoded, directory + 8)[0]
    assert count and chunks
    raw = ctypes.create_string_buffer(count * 24)
    got = library.ZSTD_decompress(
        raw, len(raw), encoded[evidence : evidence + size], size
    )
    assert not library.ZSTD_isError(got) and got == count * 24
    changed = bytearray(raw.raw)
    struct.pack_into(">q", changed, count * 8, -1)
    compressed = ctypes.create_string_buffer(library.ZSTD_compressBound(len(changed)))
    length = library.ZSTD_compress(
        compressed, len(compressed), bytes(changed), len(changed), 3
    )
    assert not library.ZSTD_isError(length)
    prefix = bytearray(encoded[:evidence])
    struct.pack_into(">Q", prefix, directory + 8, length)
    return bytes(prefix) + compressed.raw[:length] + encoded[evidence + size :]


def reader(fixture):
    sock, token = fixture.root / "reader.sock", fixture.root / "reader.token"
    process = subprocess.Popen(
        [
            str(fixture.binary),
            "serve",
            "--repo",
            str(fixture.repo),
            "--socket",
            str(sock),
            "--token-file",
            str(token),
            "--workers",
            "2",
            "--idle-seconds",
            "120",
        ],
        env=fixture.env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    deadline = time.monotonic() + 40
    while time.monotonic() < deadline and process.poll() is None:
        if sock.exists() and token.exists():
            try:
                ready = request(sock, token.read_text().strip(), command="ping")
                if ready.get("status") == "ready":
                    return process, sock, token.read_text().strip()
            except (FileNotFoundError, ConnectionRefusedError, OSError):
                pass
        time.sleep(0.05)
    process.terminate()
    output = process.communicate(timeout=10)
    raise AssertionError(("reader did not become ready", process.returncode, output))


def request(path, token, **fields):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as peer:
        peer.settimeout(30)
        peer.connect(str(path))
        peer.sendall((json.dumps(dict(token=token, **fields)) + "\n").encode())
        with peer.makefile("rb") as stream:
            return json.loads(stream.readline())


def check_expiring_source(fixture, binary):
    """Create a protected-policy fixture through authenticated APIs, not raw edits."""
    source = fixture.root / "expiry_fixture.c"
    helper = fixture.root / "expiry_fixture"
    output = fixture.root / "expiry_fixture.kv"
    data = fixture.root / "expiry_runtime"
    data.mkdir(mode=0o700)
    source.write_text(r"""#define _GNU_SOURCE
#include "qihse_auth.h"
#include "qihse_audit.h"
#include "qihse_kv_store.h"
#include <assert.h>
#include <json-c/json.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
  assert(argc == 3);
  assert(qihse_auth_init());
  assert(qihse_auth_bootstrap_operator("ExpiryCodeGraphFixture1!"));
  qihse_user_t *actor = qihse_auth_authenticate_id(0, "ExpiryCodeGraphFixture1!");
  assert(actor);
  qihse_kv_store_t *store = qihse_kv_store_create_user(actor); assert(store);
  FILE *input = fopen(argv[1], "rb"); assert(input);
  char *line = NULL; size_t capacity = 0; ssize_t size; int expiring = 0;
  while ((size = getline(&line, &capacity, input)) >= 0) {
    assert(size > 0 && size < 262144);
    struct json_object *row = json_tokener_parse(line), *type = NULL, *id = NULL;
    assert(row && json_object_object_get_ex(row, "t", &type));
    const char *kind = json_object_get_string(type); char key[72];
    if (!strcmp(kind, "h")) snprintf(key, sizeof key, "_meta");
    else if (!strcmp(kind, "end")) snprintf(key, sizeof key, "_end");
    else { assert(json_object_object_get_ex(row, "id", &id));
      assert(snprintf(key, sizeof key, "%s:%s", kind, json_object_get_string(id)) < (int)sizeof key); }
    assert(qihse_kv_set_user(store, key, line, 0, 0, actor));
    if (!strcmp(kind, "n") && !expiring++) assert(qihse_kv_expire(store, key, 600000, actor));
    json_object_put(row);
  }
  assert(!ferror(input) && expiring); free(line); fclose(input);
  assert(qihse_kv_save_user(store, argv[2], actor) == 0);
  qihse_kv_store_destroy(store); qihse_audit_shutdown(); return 0;
}
""")
    project = Path(__file__).resolve().parent.parent
    library = next(
        Path(part)
        for part in fixture.env["LD_LIBRARY_PATH"].split(os.pathsep)
        if part and (Path(part) / "libqihse.so").is_file()
    )
    subprocess.run(
        [
            os.environ.get("CC", "cc"),
            "-std=c11",
            "-O2",
            "-I",
            str(project / "include"),
            "-I",
            str(project / "core"),
            str(source),
            "-L",
            str(library),
            "-lqihse",
            "-ljson-c",
            "-Wl,-rpath," + str(library),
            "-o",
            str(helper),
        ],
        check=True,
        capture_output=True,
    )
    env = dict(fixture.env, QIHSE_DATA_DIR=str(data), QIHSE_FIPS_MODE="disabled")
    env.pop("QIHSE_OPERATOR_PASSWORD", None)
    subprocess.run(
        [str(helper), str(fixture.source), str(output)],
        env=env,
        check=True,
        capture_output=True,
        timeout=120,
    )
    manifest = fixture.manifest()
    primary = fixture.directory / manifest["snapshot"]
    output.replace(primary)
    primary.chmod(0o600)
    manifest = {
        key: value
        for key, value in manifest.items()
        if not key.startswith("projection_") and key != "storage_format"
    }
    manifest["snapshot_hash"] = snapshot_xxh3_fixture(binary, primary.read_bytes())
    fixture.save_manifest(manifest)
    # Prove future expiry survives a normal migration to the modern codec.
    fixture.invoke("migrate", "--storage-format", "packed-v3")
    assert fixture.manifest()["storage_format"] == "qihse-codegraph-packed-v3"
    denied, _ = fixture.invoke("query-index", expect=1)
    assert_denied(denied)
    assert fixture.query()["nodes"]


def check(binary):
    with tempfile.TemporaryDirectory(prefix="codegraph-query-index-") as temporary:
        fixture = Fixture(Path(temporary), binary)
        baseline = {
            action: fixture.query(action)
            for action in ("query", "context", "impact", "review")
        }
        assert all(not row["query_index_loaded"] for row in baseline.values())
        canonical_manifest = fixture.manifest_path.read_bytes()
        receipt, _ = fixture.invoke("query-index")
        assert receipt["status"] == "indexed", receipt
        indexed_manifest = fixture.manifest_path.read_bytes()
        data = fixture.manifest()
        assert (
            data["projection_principal_id"] == 77
            and data["projection_classification"] == 0
        )
        cache = fixture.cache()
        good_cache = cache.read_bytes()
        assert receipt["projection_encoded_bytes"] == len(good_cache)
        for action, expected_report in baseline.items():
            result = fixture.query(action)
            assert comparable(result) == comparable(expected_report), (
                action,
                result,
                expected_report,
            )
            assert (
                result["query_index_loaded"] and result["timings"]["kv_load_ms"] == 0
            ), result

        # Cache availability must never become canonical graph availability.
        saved = fixture.directory / ".saved-query-index"
        cache.rename(saved)
        try:
            fallback = fixture.query()
            assert (
                not fallback["query_index_loaded"]
                and fallback["timings"]["kv_load_ms"] > 0
            )
            assert comparable(fallback) == comparable(baseline["query"])
        finally:
            saved.rename(cache)
        cache.write_bytes(good_cache[:-1] + bytes([good_cache[-1] ^ 1]))
        fallback = fixture.query()
        assert not fallback["query_index_loaded"] and comparable(
            fallback
        ) == comparable(baseline["query"])
        cache.write_bytes(good_cache)
        changes = [
            {"projection_principal_id": 0},
            {"projection_classification": 4},
            {"projection_sci": 2},
            {"projection_tenant": 1},
            {"projection_hash": "0" * 32},
            {"projection_hash_algorithm": "unknown"},
            {"projection_principal_id": False},
            {"projection_sci": -1},
            {"projection_hash": data["projection_hash"] + "\0suffix"},
            {"projection_format": "qihse-codegraph-query-v1\0suffix"},
        ]
        for change in changes:
            fixture.save_manifest(dict(data, **change))
            fallback = fixture.query()
            assert not fallback["query_index_loaded"], (change, fallback)
            assert comparable(fallback) == comparable(baseline["query"]), (
                change,
                fallback,
            )
        fixture.manifest_path.write_bytes(indexed_manifest)

        # A recognized but false source-format declaration must not bypass the
        # canonical loader's format validation through an otherwise valid cache.
        fixture.save_manifest(dict(data, storage_format="qihse-codegraph-zstd-v1"))
        denied_format = fixture.query(expect=1)
        assert_denied(denied_format)
        fixture.manifest_path.write_bytes(indexed_manifest)

        for malformed in (
            {"snapshot": data["snapshot"] + "\0suffix"},
            {"nodes": str(data["nodes"])},
            {"edges": float(data["edges"])},
            {"unresolved_edges": -1},
            {"storage_format": "qihse-codegraph-packed-v3\0suffix"},
        ):
            fixture.save_manifest(dict(data, **malformed))
            denied_metadata = fixture.query(expect=1)
            assert_denied(denied_metadata)
        fixture.manifest_path.write_bytes(indexed_manifest)

        # Even a matching caller-supplied cache digest cannot change source binding.
        wrong_source = bytearray(good_cache)
        wrong_source[52] = ord("0") if wrong_source[52] != ord("0") else ord("1")
        cache.write_bytes(wrong_source)
        fixture.save_manifest(
            dict(
                data, projection_hash=snapshot_xxh3_fixture(binary, bytes(wrong_source))
            )
        )
        fallback = fixture.query()
        assert not fallback["query_index_loaded"] and comparable(
            fallback
        ) == comparable(baseline["query"])

        # Invalid lazy evidence must fail the request, never silently omit an edge.
        bad_cache = negative_line_evidence(good_cache)
        cache.write_bytes(bad_cache)
        fixture.save_manifest(
            dict(data, projection_hash=snapshot_xxh3_fixture(binary, bad_cache))
        )
        denied = fixture.query(symbol="target", expect=1)
        assert_denied(denied)
        cache.write_bytes(good_cache)
        fixture.manifest_path.write_bytes(indexed_manifest)

        # Inject a precommit manifest failure without filling the machine's disk.
        shim_source = fixture.root / "query_index_failure.c"
        shim_library = fixture.root / "query_index_failure.so"
        shim_source.write_text(r"""#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
int rename(const char *source, const char *destination) {
  static int (*real_rename)(const char *, const char *);
  if (!real_rename) real_rename = dlsym(RTLD_NEXT, "rename");
  const char *name = strrchr(destination, '/');
  if (getenv("QIHSE_TEST_INDEX_FAIL") && name && !strcmp(name + 1, "current.json")) {
    errno = ENOSPC; return -1;
  }
  return real_rename(source, destination);
}
""")
        subprocess.run(
            [
                os.environ.get("CC", "cc"),
                "-shared",
                "-fPIC",
                str(shim_source),
                "-o",
                str(shim_library),
                "-ldl",
            ],
            check=True,
            capture_output=True,
        )
        failed, _ = fixture.invoke(
            "query-index",
            expect=1,
            extra_env={"LD_PRELOAD": str(shim_library), "QIHSE_TEST_INDEX_FAIL": "1"},
        )
        assert (
            "error" in failed and fixture.manifest_path.read_bytes() == indexed_manifest
        )
        assert comparable(fixture.query()) == comparable(baseline["query"])
        cache.write_bytes(good_cache)
        cache.chmod(0o600)

        # A stale index build cannot publish metadata or damage the canonical graph.
        tracked = fixture.repo / "src/a.c"
        old_source = tracked.read_bytes()
        tracked.write_bytes(old_source + b"/* changed while graph is old */\n")
        failed, _ = fixture.invoke("query-index", expect=1)
        assert (
            "error" in failed and fixture.manifest_path.read_bytes() == indexed_manifest
        )
        tracked.write_bytes(old_source)
        assert comparable(fixture.query()) == comparable(baseline["query"])

        # A resident cache generation can refresh to a new canonical generation and back.
        process, sock, token = reader(fixture)
        try:
            cached = request(
                sock, token, command="query", symbol="caller", depth=3, timings=True
            )
            assert cached["query_index_loaded"], cached
            fixture.publish(1)
            refreshed = request(
                sock, token, command="query", symbol="caller", depth=3, timings=True
            )
            assert (
                not refreshed["query_index_loaded"]
                and refreshed["generation"] != cached["generation"]
            ), refreshed
            assert "error" not in refreshed
            fixture.publish(2)
            fixture.invoke("query-index")
            indexed = request(
                sock, token, command="query", symbol="caller", depth=3, timings=True
            )
            assert indexed["query_index_loaded"] and "error" not in indexed
        finally:
            process.terminate()
            stdout, stderr = process.communicate(timeout=15)
            # Existing serve uses the default SIGTERM disposition; either a
            # graceful exit or precisely our requested termination is expected.
            assert process.returncode in (0, -signal.SIGTERM), (
                process.returncode,
                stdout,
                stderr,
            )
            assert b"AddressSanitizer" not in stderr and b"runtime error:" not in stderr
        fixture.publish(3)
        fixture.invoke("query-index")
        fixture.publish(4)
        fixture.invoke("query-index")
        retained = {p.name for p in fixture.directory.glob("graph-*.kv")}
        assert len(retained) == 2
        sidecars = list(fixture.directory.glob("graph-*.kv.qci"))
        assert sidecars and all(path.name[:-4] in retained for path in sidecars), (
            retained,
            sidecars,
        )
        assert fixture.query()["query_index_loaded"]
        assert json.loads(canonical_manifest)["snapshot"] not in retained
        check_expiring_source(fixture, binary)
        return {
            "query_context_impact_review_parity": True,
            "fast_path_skips_kv": True,
            "missing_corrupt_binding_fallback": True,
            "lazy_malformed_no_partial_success": True,
            "stale_index_keeps_canonical": True,
            "resident_refresh_ownership": True,
            "paired_retention": True,
            "sidecar_opt_in": True,
            "expiring_source_not_cached": True,
        }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(check(args.binary.resolve(strict=True)), sort_keys=True))


if __name__ == "__main__":
    main()
