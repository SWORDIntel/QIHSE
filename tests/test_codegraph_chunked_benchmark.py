#!/usr/bin/env python3
"""Reproduce bounded-v4 versus Zstd storage costs on synthetic CodeGraph facts.

Optional benchmark, not a live-storage reader. It reuses the established graph
fixture, gives every public identifier 128 bits, and writes an equivalent exact
KV export in lexical key order. Every codec sees the same bytes. Timings exclude
fixture/auth setup and include codec work; reported peak RSS is process-wide.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import statistics
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "benchmarks"))
from codegraph_p0_baseline import graph_fixture


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(65536), b""):
            digest.update(block)
    return digest.hexdigest()


def fixture(directory: Path, nodes: int) -> Path:
    repo = directory / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    source = directory / "graph.jsonl"
    dates = {
        name: os.environ.get(name) for name in ("GIT_AUTHOR_DATE", "GIT_COMMITTER_DATE")
    }
    try:
        for name in dates:
            os.environ[name] = "2024-01-01T00:00:00+00:00"
        graph_fixture(repo, source, nodes, nodes * 3)
    finally:
        for name, value in dates.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
    records: list[tuple[str, bytes]] = []
    identities: set[str] = set()
    source_digest = hashlib.sha256()
    with source.open("rb") as stream:
        for line in stream:
            row = json.loads(line)
            kind = row["t"]
            if kind == "h":
                row.update(
                    identity="qihse-semantic-128-v1",
                    id_algorithm="sha256-128",
                    id_bits=128,
                    id_collision="counter-sha256-128-v1",
                    id_collision_attempts=256,
                )
                key = "_meta"
            elif kind == "end":
                row["sha256"] = source_digest.hexdigest()
                key = "_end"
            else:
                for field in ("id", "source", "target"):
                    if row.get(field):
                        row[field] = row[field][:32]
                assert row["id"] not in identities
                identities.add(row["id"])
                key = kind + ":" + row["id"]
            value = json.dumps(row, sort_keys=True, separators=(",", ":")).encode()
            if kind != "end":
                source_digest.update(value + b"\n")
            records.append((key, value))
    raw = directory / "graph.raw"
    with raw.open("wb") as stream:
        for seq, (key, value) in enumerate(sorted(records), 1):
            encoded_key = key.encode()
            stream.write(f"{len(encoded_key)} {len(value)} 0 0 0 0 {seq}\n".encode())
            stream.write(encoded_key + value + b"\n")
    return raw


def run_driver(
    driver: Path, *args: object, env: dict[str, str]
) -> subprocess.CompletedProcess[str]:
    # A small shell forks after exec, so Linux ru_maxrss does not inherit the
    # fixture-generator's large resident heap across the initial Python fork.
    return subprocess.run(
        [
            "sh",
            "-c",
            '"$@" & child=$!; wait "$child"',
            "codegraph-benchmark",
            str(driver.resolve()),
            *(str(a) for a in args),
        ],
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--driver", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--nodes", type=int, default=40000)
    parser.add_argument("--repeats", type=int, default=3)
    args = parser.parse_args()
    assert 8 <= args.nodes <= 200000 and 1 <= args.repeats <= 9
    results = []
    driver_sha256 = sha256(args.driver.resolve())
    with tempfile.TemporaryDirectory(prefix="codegraph-chunked-benchmark-") as scratch:
        directory = Path(scratch)
        raw = fixture(directory, args.nodes)
        digest = sha256(raw)
        env = dict(
            os.environ,
            TMPDIR=str(directory),
            LD_LIBRARY_PATH=str(ROOT)
            + os.pathsep
            + os.environ.get("LD_LIBRARY_PATH", ""),
        )
        modes = ["--encode-v4", "--encode-zstd"]
        for repeat in range(args.repeats):
            for mode in modes[repeat % 2 :] + modes[: repeat % 2]:
                dest = directory / (mode[2:] + ".snapshot")
                process = run_driver(args.driver, mode, raw, dest, env=env)
                result = json.loads(process.stdout)
                result["repeat"] = repeat
                results.append(result)
                print(json.dumps(result), flush=True)
        decoded = directory / "decoded.raw"
        process = run_driver(
            args.driver,
            "--decode-v4",
            directory / "encode-v4.snapshot",
            decoded,
            env=env,
        )
        decode = json.loads(process.stdout)
        assert sha256(decoded) == digest
        process = run_driver(
            args.driver,
            "--decode-zstd",
            directory / "encode-zstd.snapshot",
            decoded,
            env=env,
        )
        baseline_decode = json.loads(process.stdout)
        assert sha256(decoded) == digest
        summary = {}
        for mode in modes:
            samples = [r for r in results if r["mode"] == mode]
            summary[mode] = {
                "encoded_bytes": samples[0]["output_bytes"],
                "median_seconds": statistics.median(r["seconds"] for r in samples),
                "peak_rss_kib": max(r["peak_rss_kib"] for r in samples),
            }
        receipt = {
            "method": __doc__,
            "driver_sha256": driver_sha256,
            "host": platform.platform(),
            "python": sys.version,
            "compiler": subprocess.check_output(
                [os.environ.get("CC", "cc"), "--version"], text=True
            ).splitlines()[0],
            "nodes": args.nodes,
            "edges": args.nodes * 3,
            "source_bytes": raw.stat().st_size,
            "source_sha256": digest,
            "raw_roundtrip": True,
            "runs": results,
            "summary": summary,
            "decode": decode,
            "baseline_decode": baseline_decode,
        }
    args.output.write_text(json.dumps(receipt, indent=2) + "\n")


if __name__ == "__main__":
    main()
