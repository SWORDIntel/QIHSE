#!/usr/bin/env python3
"""Smoke-test the manifest-backed QIHSE reference runner with mini fvecs/ivecs."""

from __future__ import annotations

import argparse
import json
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path


WORKLOAD_NAME = "mini-fvecs-smoke"


def write_fvecs(path: Path, rows: list[list[float]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as handle:
        for row in rows:
            handle.write(struct.pack("<i", len(row)))
            handle.write(struct.pack(f"<{len(row)}f", *row))


def write_ivecs(path: Path, rows: list[list[int]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as handle:
        for row in rows:
            handle.write(struct.pack("<i", len(row)))
            handle.write(struct.pack(f"<{len(row)}i", *row))


def write_manifest(path: Path) -> None:
    manifest = {
        "schema_version": 1,
        "workloads": [
            {
                "name": WORKLOAD_NAME,
                "kind": "external",
                "dataset": WORKLOAD_NAME,
                "dimensions": 4,
                "rows": 4,
                "queries": 2,
                "top_k": 2,
                "required_modes": ["float32", "qtri", "qmag"],
                "files": {
                    "base_vectors": f"data/{WORKLOAD_NAME}/base.fvecs",
                    "query_vectors": f"data/{WORKLOAD_NAME}/query.fvecs",
                    "ground_truth": f"data/{WORKLOAD_NAME}/ground_truth.ivecs",
                },
                "file_formats": {
                    "base_vectors": "fvecs",
                    "query_vectors": "fvecs",
                    "ground_truth": "ivecs",
                },
                "acceptance": {"recall_at_2_floor": 1.0},
            }
        ],
    }
    path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def run_command(command: list[str], cwd: Path) -> None:
    subprocess.run(command, cwd=cwd, check=True)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=".", help="QIHSE root")
    parser.add_argument("--keep", action="store_true", help="keep generated smoke data/results")
    args = parser.parse_args(argv)

    root = Path(args.root).resolve()
    data_dir = root / "data" / WORKLOAD_NAME
    result_path = root / "results" / WORKLOAD_NAME / "latest.json"

    try:
        with tempfile.TemporaryDirectory(prefix="qihse_reference_smoke_") as temp_dir:
            manifest_path = Path(temp_dir) / "manifest.json"
            write_manifest(manifest_path)
            write_fvecs(
                data_dir / "base.fvecs",
                [
                    [1.0, 0.0, 0.0, 0.0],
                    [0.0, 1.0, 0.0, 0.0],
                    [0.0, 0.0, 1.0, 0.0],
                    [0.0, 0.0, 0.0, 1.0],
                ],
            )
            write_fvecs(
                data_dir / "query.fvecs",
                [
                    [1.0, 0.0, 0.0, 0.0],
                    [0.0, 0.0, 1.0, 0.0],
                ],
            )
            write_ivecs(data_dir / "ground_truth.ivecs", [[0, 1], [2, 0]])

            run_command(
                [
                    sys.executable,
                    "benchmarks/scripts/qihse_reference_workloads.py",
                    "--root",
                    ".",
                    "--manifest",
                    str(manifest_path),
                    "--workload",
                    WORKLOAD_NAME,
                    "--inspect-files",
                ],
                root,
            )
            run_command(
                [
                    sys.executable,
                    "benchmarks/scripts/qihse_vxug_reference_bench.py",
                    "--root",
                    ".",
                    "--manifest",
                    str(manifest_path),
                    "--workload",
                    WORKLOAD_NAME,
                    "--iterations",
                    "1",
                    "--output-json",
                    str(result_path.relative_to(root)),
                ],
                root,
            )
    except (OSError, subprocess.CalledProcessError) as exc:
        print(f"reference runner smoke failed: {exc}", file=sys.stderr)
        return 1
    finally:
        if not args.keep:
            shutil.rmtree(data_dir, ignore_errors=True)
            shutil.rmtree(result_path.parent, ignore_errors=True)

    print("reference runner smoke passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
