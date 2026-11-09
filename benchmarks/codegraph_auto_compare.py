#!/usr/bin/env python3
"""Compare automatic CodeGraph storage selection on isolated synthetic graphs.

Example: python3 benchmarks/codegraph_auto_compare.py --nodes 8 800 \
    --repeats 3 --output build/codegraph-auto.json
No configured graph state is read. All fixture stores are temporary.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import statistics
import subprocess
import tempfile
import time

from codegraph_packed_compare import PROJECT, build_driver, graph_fixture, sha256


def measure(binary: Path, library_dir: Path, nodes: int, repeats: int) -> dict:
    edges = nodes * 3
    with tempfile.TemporaryDirectory(prefix="qihse-codegraph-auto-") as temporary:
        base = Path(temporary)
        repo = base / "repo"
        repo.mkdir()
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
        fixture = base / "graph.jsonl"
        date_keys = ("GIT_AUTHOR_DATE", "GIT_COMMITTER_DATE")
        old_dates = {key: os.environ.get(key) for key in date_keys}
        try:
            for key in date_keys:
                os.environ[key] = "2024-01-01T00:00:00+00:00"
            graph_fixture(repo, fixture, nodes, edges)
        finally:
            for key, previous in old_dates.items():
                if previous is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = previous

        rows = []
        for repeat in range(repeats):
            backends = ["zstd", "packed", "dictionary", "auto"]
            offset = repeat % len(backends)
            for backend in backends[offset:] + backends[:offset]:
                output = base / f"{repeat}-{backend}"
                output.mkdir(mode=0o700)
                state = output / "state"
                state.mkdir(mode=0o700)
                env = os.environ.copy()
                env.update(QIHSE_DATA_DIR=str(state), XDG_STATE_HOME=str(state))
                env["LD_LIBRARY_PATH"] = str(library_dir) + ":" + env.get("LD_LIBRARY_PATH", "")
                started = time.perf_counter()
                result = subprocess.run(
                    [str(binary), backend, str(fixture), str(output / "snapshot")],
                    env=env, capture_output=True, text=True, check=True,
                )
                row = json.loads(result.stdout)
                row["process_wall_ms"] = round((time.perf_counter() - started) * 1000, 3)
                row.update(nodes=nodes, edges=edges, repeat=repeat)
                # Packed's standalone encoder receives an already exported
                # stream; its comparable wall metric must include that export.
                # CPU stays separate because export CPU is not measured.
                row["production_equivalent_encode_wall_ms"] = round(
                    row["encode_ms"] + (row["raw_export_ms"] if backend == "packed" else 0), 3
                )
                assert row["raw_roundtrip"] and row["low_clearance_denied"]
                rows.append(row)
            group = {row["backend"]: row for row in rows if row["repeat"] == repeat}
            assert len({row["fingerprint"] for row in group.values()}) == 1
            assert len({row["record_count"] for row in group.values()}) == 1
            assert group["auto"]["snapshot_apparent_bytes"] == min(
                group["zstd"]["snapshot_apparent_bytes"],
                group["packed"]["snapshot_apparent_bytes"],
                group["dictionary"]["snapshot_apparent_bytes"],
            )
            expected = min(("zstd", "packed", "dictionary"),
                           key=lambda b: group[b]["snapshot_apparent_bytes"])
            assert group["auto"]["selected_format"] == expected

        keys = ("snapshot_apparent_bytes", "snapshot_allocated_bytes", "encode_ms",
                "encode_cpu_ms", "raw_export_ms", "production_equivalent_encode_wall_ms",
                "load_ms", "load_cpu_ms", "peak_rss_kib")
        return {
            "nodes": nodes, "edges": edges, "fixture_sha256": sha256(fixture),
            "runs": rows,
            "medians": {backend: {key: statistics.median(
                row[key] for row in rows if row["backend"] == backend
            ) for key in keys} for backend in ("zstd", "packed", "dictionary", "auto")},
        }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--nodes", type=int, nargs="+", default=[8, 800])
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--library-dir", type=Path, default=PROJECT)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--timing-context", default="shared host; no OS cache dropping")
    args = parser.parse_args()
    if args.repeats < 1 or any(n < 8 or n > 24000 for n in args.nodes):
        parser.error("repeats must be positive; nodes must be within 8..24000")
    library_dir = args.library_dir.resolve()
    with tempfile.TemporaryDirectory(prefix="qihse-codegraph-auto-build-") as temporary:
        binary = Path(temporary) / "driver"
        build_driver(binary, library_dir, PROJECT, packed=True)
        result = {
            "method": "Authenticated synthetic exports/loads; fresh process per backend; "
                      "rotating backend order; exact raw roundtrips, record fingerprints, "
                      "low-clearance denial and smallest-candidate selection asserted",
            "timing_context": args.timing_context,
            "cpu_note": "encode_cpu_ms for packed excludes its separately measured raw "
                        "export; auto and zstd include export. Compare the production "
                        "equivalent wall metric for complete encoding work.",
            "environment": {"driver_sha256": sha256(PROJECT / "benchmarks/codegraph_packed_driver.c"),
                            "storage_sha256": sha256(PROJECT / "tools/qihse_codegraph_storage.c"),
                            "packed_sha256": sha256(PROJECT / "tools/qihse_codegraph_packed.c"),
                            "dictionary_sha256": sha256(PROJECT / "tools/qihse_codegraph_dictionary.c"),
                            "library_sha256": sha256(library_dir / "libqihse.so")},
            "fixtures": [measure(binary, library_dir, n, args.repeats) for n in args.nodes],
        }
    output = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(output)
    print(output, end="")


if __name__ == "__main__":
    main()
