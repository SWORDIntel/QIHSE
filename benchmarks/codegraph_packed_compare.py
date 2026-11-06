#!/usr/bin/env python3
"""Compare CodeGraph snapshot codecs on one authenticated synthetic KV corpus."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import statistics
import subprocess
import sys
import tempfile
import time

from codegraph_p0_baseline import graph_fixture

PROJECT = Path(__file__).resolve().parents[1]
DRIVER = Path(__file__).with_name("codegraph_packed_driver.c")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def build_driver(output: Path, library_dir: Path, packed: bool) -> list[str]:
    flags = subprocess.check_output(
        ["pkg-config", "--cflags", "--libs", "json-c", "openssl", "libzstd"],
        text=True,
    ).split()
    command = [os.environ.get("CC", "cc"), "-std=c11", "-O2", "-Wall", "-Wextra",
               "-Werror", "-I" + str(PROJECT / "include"),
               "-I" + str(PROJECT / "tools")]
    if packed:
        command.append("-DCODEGRAPH_PACKED_CODEC")
    command += [str(DRIVER), str(PROJECT / "tools/qihse_codegraph_storage.c")]
    if packed:
        command.append(str(PROJECT / "tools/qihse_codegraph_packed.c"))
    command += ["-o", str(output), "-L" + str(library_dir), "-lqihse",
                *flags, "-ldl", "-lm", "-lpthread"]
    subprocess.run(command, check=True, cwd=PROJECT)
    return command


def run_driver(binary: Path, backend: str, fixture: Path, output: Path,
               library_dir: Path) -> dict:
    state = output.parent / "state"
    state.mkdir(mode=0o700)
    env = os.environ.copy()
    env["HOME"] = str(state)
    env["QIHSE_DATA_DIR"] = str(state)
    env["LD_LIBRARY_PATH"] = str(library_dir) + ":" + env.get("LD_LIBRARY_PATH", "")
    command = [str(binary), backend, str(fixture), str(output)]
    started = time.perf_counter()
    result = subprocess.run(command, env=env, text=True, capture_output=True)
    elapsed_ms = (time.perf_counter() - started) * 1000
    if result.returncode:
        raise RuntimeError(f"{backend} driver exited {result.returncode}: {result.stderr[-3000:]}")
    receipt = json.loads(result.stdout)
    receipt["process_wall_ms"] = round(elapsed_ms, 3)
    return receipt


def measure(binary: Path, library_dir: Path, nodes: int, edges: int,
            repeats: int, packed: bool) -> dict:
    with tempfile.TemporaryDirectory(prefix="qihse-codegraph-packed-") as temporary:
        base = Path(temporary)
        repo = base / "repo"
        repo.mkdir()
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
        fixture = base / "graph.jsonl"
        author_date = os.environ.get("GIT_AUTHOR_DATE")
        committer_date = os.environ.get("GIT_COMMITTER_DATE")
        os.environ["GIT_AUTHOR_DATE"] = "2024-01-01T00:00:00+00:00"
        os.environ["GIT_COMMITTER_DATE"] = "2024-01-01T00:00:00+00:00"
        try:
            graph_fixture(repo, fixture, nodes, edges)
        finally:
            for key, old in (("GIT_AUTHOR_DATE", author_date),
                             ("GIT_COMMITTER_DATE", committer_date)):
                if old is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = old
        backends = ["legacy", "zstd"] + (["packed"] if packed else [])
        runs = []
        for repeat in range(repeats):
            order = backends[repeat % len(backends):] + backends[:repeat % len(backends)]
            for backend in order:
                output_dir = base / f"run-{repeat}-{backend}"
                output_dir.mkdir()
                receipt = run_driver(binary, backend, fixture, output_dir / "snapshot",
                                     library_dir)
                receipt["raw_export_sha256"] = sha256(output_dir / "snapshot.raw")
                receipt["production_equivalent_encode_ms"] = round(
                    receipt["encode_ms"] + (receipt["raw_export_ms"] if backend == "packed" else 0), 3)
                receipt["repeat"] = repeat
                if receipt["low_clearance_denied"] is not True:
                    raise AssertionError(f"{backend}: low-clearance read was not denied")
                if receipt["raw_roundtrip"] is not True:
                    raise AssertionError(f"{backend}: exact raw roundtrip failed")
                runs.append(receipt)
        expected = (runs[0]["record_count"], runs[0]["fingerprint"],
                    runs[0]["raw_export_sha256"])
        for receipt in runs:
            actual = (receipt["record_count"], receipt["fingerprint"],
                      receipt["raw_export_sha256"])
            if actual != expected:
                raise AssertionError(f"record parity failed: {receipt['backend']}")
        keys = ["snapshot_apparent_bytes", "snapshot_allocated_bytes", "raw_export_ms",
                "encode_ms", "encode_cpu_ms", "production_equivalent_encode_ms",
                "load_ms", "load_cpu_ms",
                "peak_rss_kib", "process_wall_ms"]
        median = {backend: {key: round(statistics.median(
                    run[key] for run in runs if run["backend"] == backend), 3)
                for key in keys} for backend in backends}
        return {"fixture": {"nodes": nodes, "edges": edges,
                            "jsonl_bytes": fixture.stat().st_size,
                            "jsonl_sha256": sha256(fixture)},
                "parity": {"record_count": expected[0], "fingerprint": expected[1],
                           "raw_export_sha256": expected[2],
                           "low_clearance_denial": True,
                           "all_formats_exact_raw_roundtrip": True,
                           "native_query_parity": "not tested"},
                "runs": runs, "median": median}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--library-dir", type=Path, default=PROJECT)
    parser.add_argument("--nodes", type=int, default=800)
    parser.add_argument("--edges", type=int, default=2400)
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--baseline-only", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.repeats < 1:
        parser.error("--repeats must be positive")
    packed = not args.baseline_only
    with tempfile.TemporaryDirectory(prefix="qihse-codegraph-packed-build-") as temporary:
        binary = Path(temporary) / "codegraph_packed_driver"
        command = build_driver(binary, args.library_dir.resolve(), packed)
        result = measure(binary, args.library_dir.resolve(), args.nodes,
                         args.edges, args.repeats, packed)
        result["environment"] = {"platform": platform.platform(),
                                 "python": platform.python_version(),
                                 "compiler": command[0],
                                 "source_sha256": sha256(DRIVER),
                                 "binary_sha256": sha256(binary),
                                 "library_sha256": sha256(args.library_dir / "libqihse.so"),
                                 "storage_source_sha256": sha256(PROJECT / "tools/qihse_codegraph_storage.c"),
                                 "packed_source_sha256": sha256(PROJECT / "tools/qihse_codegraph_packed.c") if packed else None}
        result["method"] = "authenticated synthetic KV; per-backend fresh process; warm OS cache; backend order rotates; raw export measured separately; packed encode reuses exported raw; zstd/legacy save through authenticated SDK; timings may include shared-host contention"
        serialized = json.dumps(result, indent=2, sort_keys=True) + "\n"
        if args.output:
            args.output.write_text(serialized)
        print(serialized, end="")


if __name__ == "__main__":
    main()
