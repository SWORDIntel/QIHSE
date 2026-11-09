#!/usr/bin/env python3
"""W12.0 synthetic full VectorDB comparison; no live QIHSE data is opened."""
from __future__ import annotations

import argparse
import array
import hashlib
import json
import os
from pathlib import Path
import platform
import statistics
import struct
import subprocess
import tempfile

from qihse_w12_fp32_baseline import fixture, fixture_hash, oracle, recall, ROOT

MODES = {
    "float32": 0, "trinary_scalar": 1, "trinary_magnitude": 2,
    "trinary_bypass": 3, "graph": 4, "int8": 5,
    "fp16_alias": 7, "fp32_alias": 8, "fp8_alias": 9,
    "fp4_alias": 10, "int4_alias": 11, "binary": 12,
}
METRICS = ("cosine", "dot", "l2")
SOURCE = ROOT / "benchmarks/scripts/qihse_w12_engine_baseline.c"
EXECUTABLE = ROOT / "build/w12/qihse_w12_engine_baseline"


def build() -> dict:
    EXECUTABLE.parent.mkdir(parents=True, exist_ok=True)
    command = [
        os.environ.get("CC", "cc"), "-std=c99", "-O2", "-Wall", "-Wextra",
        "-I.", "-Iinclude", "-Imemory/include", str(SOURCE.relative_to(ROOT)),
        "-L.", "-lqihse", "-lm",
        "-o", str(EXECUTABLE.relative_to(ROOT)),
    ]
    subprocess.run(command, cwd=ROOT, check=True)
    return {
        "command": command,
        "compiler": subprocess.check_output([command[0], "--version"], text=True).splitlines()[0],
        "source_sha256": hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
        "library_sha256": hashlib.sha256((ROOT / "libqihse.so").read_bytes()).hexdigest(),
    }


def write_fixture(path: Path, vectors: array.array, queries: list[array.array],
                  rows: int, dims: int) -> None:
    with path.open("wb") as stream:
        stream.write(struct.pack("<4I", 0x57313230, rows, dims, len(queries)))
        for values in [vectors, *queries]:
            copy = array.array("f", values)
            if os.sys.byteorder != "little":
                copy.byteswap()
            stream.write(copy.tobytes())


def parse_probe(output: str, mode: int, queries: int, repeats: int, k: int):
    samples = {m: [] for m in range(3)}
    rows = {m: {} for m in range(3)}
    scores = {m: {} for m in range(3)}
    stats = None
    for line in output.splitlines():
        cells = line.split(",")
        if cells[0] == "S":
            if stats is not None or int(cells[1]) != mode or len(cells) != 6:
                raise ValueError("Invalid probe summary")
            stats = dict(build_ns=int(cells[2]), fp32_resident_bytes=int(cells[3]),
                         graph_topology_bytes=int(cells[4]), spilled_rows=int(cells[5]))
        elif cells[0] == "Q":
            if len(cells) < 7 or int(cells[1]) != mode:
                raise ValueError("Invalid probe query")
            metric, qi, rep, elapsed, count = map(int, cells[2:7])
            if metric not in samples or not (0 <= qi < queries and 0 <= rep < repeats):
                raise ValueError("Probe query out of range")
            if count != k or len(cells) != 7 + 2 * count:
                raise ValueError("Incomplete query result")
            ids = [int(cells[7 + j * 2]) for j in range(count)]
            vals = [float(cells[8 + j * 2]) for j in range(count)]
            if len(set(ids)) != count:
                raise ValueError("Duplicate result IDs")
            samples[metric].append(elapsed)
            if rep == 0:
                rows[metric][qi] = ids
                scores[metric][qi] = vals
        else:
            raise ValueError("Unexpected probe output")
    if stats is None or any(len(samples[m]) != queries * repeats or
                            len(rows[m]) != queries for m in range(3)):
        raise ValueError("Missing probe rows")
    return samples, rows, scores, stats


def run(args):
    if not (1 <= args.rows <= 100000 and 1 <= args.dimensions <= 1536 and
            1 <= args.queries <= 10000 and 1 <= args.repeats <= 1000):
        raise ValueError("Invalid benchmark dimensions")
    k = min(10, args.rows)
    vectors, queries, mask = fixture(args.rows, args.dimensions, args.queries,
                                     args.seed, args.corpus)
    truths = {m: [[row + 1 for row, _ in
                   oracle(vectors, q, mask, args.dimensions, k, m)]
                  for q in queries] for m in METRICS}
    build_info = build()
    try:
        git_sha = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
        git_dirty = bool(subprocess.check_output(
            ["git", "status", "--porcelain"], cwd=ROOT, text=True).strip())
    except subprocess.CalledProcessError:
        git_sha, git_dirty = None, None
    cpu_flags = None
    cpuinfo = Path("/proc/cpuinfo")
    if cpuinfo.exists():
        cpu_flags = next((line.partition(":")[2].strip().split()
                          for line in cpuinfo.read_text().splitlines()
                          if line.startswith("flags")), None)
    report = {
        "schema": "qihse-w12-engine-baseline-v1",
        "scope": "synthetic_unclassified_full_vector_db_authenticated_operator",
        "security_note": "Existing approximate candidate paths are not qualified for classified scope.",
        "rows": args.rows, "dimensions": args.dimensions, "queries": args.queries,
        "repeats": args.repeats, "top_k": k, "seed": args.seed, "corpus": args.corpus,
        "fixture_sha256": fixture_hash(vectors, queries, mask),
        "payload_bytes": args.rows * args.dimensions * 4,
        "candidate_pool": min(64, args.rows),
        "host": {"machine": platform.machine(), "processor": platform.processor(),
                 "platform": platform.platform(), "cpu_flags": cpu_flags,
                 "allowed_cpu_set": sorted(os.sched_getaffinity(0))
                 if hasattr(os, "sched_getaffinity") else None},
        "source_commit": git_sha, "source_dirty": git_dirty,
        "build": build_info,
        "modes": {},
        "unmeasured": {
            "pq": "No VectorDB query selector.",
            "turboquant": "No VectorDB query selector.",
            "aimem_scoped": "Separate subsystem; no VectorDB route or comparable fixture contract.",
            "real_corpus": "This run uses deterministic synthetic unclassified vectors only.",
            "total_ram_and_sidecar_disk_bytes": "Public API exposes FP32 resident bytes and graph topology only.",
            "classified_auth_safety": "Approximate candidate paths require scope-first design and negative tests.",
        },
    }
    with tempfile.TemporaryDirectory(prefix="qihse_w12_engine_") as temp:
        temp = Path(temp)
        fixture_path = temp / "fixture.bin"
        write_fixture(fixture_path, vectors, queries, args.rows, args.dimensions)
        for name in args.modes:
            mode = MODES[name]
            db_path = temp / (name + ".qdb")
            auth_path = temp / ("auth_" + name)
            auth_path.mkdir(mode=0o700)
            auth_path.chmod(0o700)
            env = dict(os.environ, QIHSE_DATA_DIR=str(auth_path), LD_LIBRARY_PATH=str(ROOT),
                       QIHSE_AUTH_VOLUME_MAX="1000000")
            cmd = [str(EXECUTABLE), str(fixture_path), str(mode),
                   str(args.repeats), str(db_path)]
            probe = subprocess.run(cmd, cwd=ROOT, env=env, capture_output=True, text=True)
            if probe.returncode:
                report["modes"][name] = {"status": "failed", "exit_code": probe.returncode,
                                         "stderr": probe.stderr[-3000:]}
                continue
            samples, rows, scores, stats = parse_probe(
                probe.stdout, mode, args.queries, args.repeats, k)
            metrics = {}
            for mi, metric in enumerate(METRICS):
                data = samples[mi]
                metrics[metric] = {
                    "recall_at_k_vs_fp64": statistics.mean(
                        recall(rows[mi][qi], truths[metric][qi])
                        for qi in range(args.queries)),
                    "p50_ns": int(statistics.median(data)),
                    "p95_ns": sorted(data)[max(0, (95 * len(data) + 99) // 100 - 1)],
                    "mean_ns": statistics.mean(data),
                    "raw_samples_ns": data,
                    "first_repeat_ids": [rows[mi][qi] for qi in range(args.queries)],
                }
            report["modes"][name] = {
                "status": "measured", "implementation": "fp32_alias" if name.endswith("_alias") else name,
                "build_and_memory": stats, "metrics": metrics,
            }
            if db_path.exists():
                report["modes"][name]["container_bytes"] = db_path.stat().st_size
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(args.output)
    for name, value in report["modes"].items():
        if value["status"] == "measured":
            m = value["metrics"]["cosine"]
            print(f"{name}: cosine recall={m['recall_at_k_vs_fp64']:.3f} "
                  f"p50={m['p50_ns']/1e6:.3f} ms "
                  f"container={value.get('container_bytes')} bytes")
        else:
            print(f"{name}: FAILED: {value['stderr'].strip()}")
    return 0 if all(v["status"] == "measured" for v in report["modes"].values()) else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rows", type=int, default=256)
    parser.add_argument("--dimensions", type=int, default=128)
    parser.add_argument("--queries", type=int, default=8)
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--seed", type=int, default=0x1200)
    parser.add_argument("--corpus", choices=("isotropic", "anisotropic", "clustered",
                                             "duplicates", "high-dynamic-range",
                                             "sparse-sign"), default="isotropic")
    parser.add_argument("--modes", nargs="+", choices=MODES, default=list(MODES))
    parser.add_argument("--output", type=Path, default=ROOT / "build/w12/engine-baseline.json")
    return run(parser.parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
