#!/usr/bin/env python3
"""Shuffled end-to-end fresh-process query benchmark, including opt-in index bytes."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import random
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

PROJECT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT / "tests"))
from test_codegraph_native import node_id, write_records
from test_codegraph_query_index import Fixture, comparable


def sha(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(65536):
            digest.update(chunk)
    return digest.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--nodes", type=int, default=8000)
    parser.add_argument("--samples", type=int, default=3)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not 10 <= args.nodes <= 100000 or not 2 <= args.samples <= 20:
        parser.error("nodes10..100000; samples2..20")
    timer = shutil.which("time")
    if not timer:
        parser.error("GNU time required for independent per-process peak RSS")
    rows = []
    with tempfile.TemporaryDirectory(prefix="qcg-query-index-bench-") as temp:
        fixture = Fixture(Path(temp), args.binary.resolve(strict=True))
        header = json.loads(fixture.source.read_text().splitlines()[0])
        nodes = [
            {
                "t": "n",
                "id": node_id(f"node-{i}"),
                "file": "src/a.c",
                "name": f"function_{i:06}",
                "kind": "Function",
                "line_start": i + 1,
                "line_end": i + 2,
                "is_test": False,
            }
            for i in range(args.nodes)
        ]
        edges = [
            {
                "t": "e",
                "id": node_id(f"edge-{i}"),
                "source": nodes[i % len(nodes)]["id"],
                "target": nodes[(i * 7 + 11) % len(nodes)]["id"],
                "relation": "CALLS",
                "file": "src/a.c",
                "line": i + 1,
                "confidence": 1.0,
                "tier": "EXTRACTED",
                "resolution": "direct",
                "traversable": True,
            }
            for i in range(args.nodes * 3)
        ]
        write_records(
            fixture.source,
            [
                header,
                *nodes,
                *edges,
                {
                    "t": "end",
                    "nodes": len(nodes),
                    "edges": len(edges),
                    "unresolved_edges": 0,
                },
            ],
        )
        fixture.invoke(
            "import", "--input", str(fixture.source), "--storage-format", "packed-v3"
        )
        canonical = fixture.manifest()
        receipt, build_seconds = fixture.invoke("query-index")
        indexed = fixture.manifest()
        expected = None
        candidates = ["canonical", "indexed"] * args.samples
        random.Random(7).shuffle(candidates)
        for sample, mode in enumerate(candidates):
            fixture.save_manifest(indexed if mode == "indexed" else canonical)
            rss = fixture.root / f"peak-{sample}.txt"
            command = [
                timer,
                "-f",
                "%M",
                "-o",
                str(rss),
                str(fixture.binary),
                "query",
                "--repo",
                str(fixture.repo),
                "--symbol",
                "function_000000",
                "--match",
                "exact",
                "--depth",
                "2",
                "--timings",
            ]
            started = time.monotonic()
            process = subprocess.run(
                command,
                env=fixture.env,
                capture_output=True,
                text=True,
                timeout=180,
                check=True,
            )
            wall = time.monotonic() - started
            report = json.loads(process.stdout)
            if expected is None:
                expected = comparable(report)
            assert comparable(report) == expected, (mode, report)
            assert report["query_index_loaded"] == (mode == "indexed"), report
            assert bool(report["timings"]["kv_load_ms"]) == (mode == "canonical"), (
                report
            )
            rows.append(
                {
                    "mode": mode,
                    "wall_seconds": wall,
                    "peak_rss_kib": int(rss.read_text()),
                    "timings": report["timings"],
                }
            )
        fixture.save_manifest(indexed)
        primary, sidecar = fixture.directory / indexed["snapshot"], fixture.cache()
        results = {
            "kind": "fresh CLI process; warm OS page cache; shuffled modes; no cache drops",
            "platform": platform.platform(),
            "id_profile": "legacy256 synthetic compatibility fixture",
            "nodes": len(nodes),
            "edges": len(edges),
            "samples_per_mode": args.samples,
            "binary_sha256": sha(fixture.binary),
            "library_sha256": sha(
                next(
                    Path(part) / "libqihse.so"
                    for part in fixture.env["LD_LIBRARY_PATH"].split(os.pathsep)
                    if part and (Path(part) / "libqihse.so").is_file()
                )
            ),
            "canonical_snapshot_bytes": primary.stat().st_size,
            "query_index_bytes": sidecar.stat().st_size,
            "current_total_with_index_bytes": primary.stat().st_size
            + sidecar.stat().st_size,
            "directory_logical_bytes": sum(
                p.stat().st_size for p in fixture.directory.rglob("*") if p.is_file()
            ),
            "index_build_wall_seconds": build_seconds,
            "index_receipt": receipt,
            "samples": rows,
            "medians": {
                mode: {
                    "wall_seconds": statistics.median(
                        r["wall_seconds"] for r in rows if r["mode"] == mode
                    ),
                    "peak_rss_kib": statistics.median(
                        r["peak_rss_kib"] for r in rows if r["mode"] == mode
                    ),
                    "generation_load_ms": statistics.median(
                        r["timings"]["generation_load_ms"]
                        for r in rows
                        if r["mode"] == mode
                    ),
                    "traversal_ms": statistics.median(
                        r["timings"]["traversal_ms"] for r in rows if r["mode"] == mode
                    ),
                }
                for mode in ("canonical", "indexed")
            },
            "limitations": [
                "Synthetic256 fixture is not fresh producer128 ID size proof",
                "Index adds disk bytes and is opt-in",
                "Process RSS includes authenticated runtime startup",
                "Cold processes only; not resident daemon latency",
                "Other host work continued; no OS cache drops or CPU pinning",
            ],
        }
        args.output.write_text(json.dumps(results, indent=2) + "\n")
        print(json.dumps(results["medians"], sort_keys=True))


if __name__ == "__main__":
    main()
