#!/usr/bin/env python3
"""Generate deterministic sparse-active trinary/qmag reference workloads."""

from __future__ import annotations

import argparse
import json
import math
import random
import struct
import sys
from pathlib import Path


DEFAULT_CASES = ("256:16", "768:32")


def write_f32_matrix(path: Path, rows: list[list[float]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as handle:
        for row in rows:
            handle.write(struct.pack(f"<{len(row)}f", *row))


def write_u32_matrix(path: Path, rows: list[list[int]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as handle:
        for row in rows:
            handle.write(struct.pack(f"<{len(row)}I", *row))


def dot(left: list[float], right: list[float]) -> float:
    return sum(a * b for a, b in zip(left, right))


def normalize(vector: list[float]) -> list[float]:
    norm = math.sqrt(sum(value * value for value in vector))
    if norm == 0.0:
        return vector
    inv = 1.0 / norm
    return [value * inv for value in vector]


def parse_case(value: str) -> tuple[int, int]:
    parts = value.lower().replace("x", ":").split(":")
    if len(parts) != 2:
        raise ValueError(f"case must be DIMENSIONS:ACTIVE, got {value!r}")
    dims = int(parts[0])
    active = int(parts[1])
    if dims <= 0 or active <= 0:
        raise ValueError("case dimensions and active count must be positive")
    if active > dims:
        raise ValueError("case active count cannot exceed dimensions")
    return dims, active


def build_query(rng: random.Random, dims: int, active: int) -> tuple[list[float], list[int]]:
    active_dims = sorted(rng.sample(range(dims), active))
    vector = [0.0] * dims
    for dim in active_dims:
        sign = 1.0 if rng.randrange(2) == 0 else -1.0
        magnitude = 0.75 + (0.25 * rng.random())
        vector[dim] = sign * magnitude
    return normalize(vector), active_dims


def build_positive_row(query: list[float], active_dims: list[int], rank: int) -> list[float]:
    scale = 1.0 - (rank * 0.0125)
    row = [0.0] * len(query)
    for dim in active_dims:
        row[dim] = query[dim] * scale
    return row


def build_distractor(rng: random.Random, dims: int, active: int) -> list[float]:
    row = [0.0] * dims
    for dim in rng.sample(range(dims), active):
        sign = 1.0 if rng.randrange(2) == 0 else -1.0
        row[dim] = sign * (0.01 + (0.05 * rng.random()))
    return row


def build_ground_truth(
    base_vectors: list[list[float]],
    query_vectors: list[list[float]],
    top_k: int,
) -> list[list[int]]:
    truth: list[list[int]] = []
    for query in query_vectors:
        ranked = sorted(
            ((dot(query, base), index) for index, base in enumerate(base_vectors)),
            key=lambda item: (-item[0], item[1]),
        )
        truth.append([index for _, index in ranked[:top_k]])
    return truth


def build_case(
    rng: random.Random,
    dims: int,
    active: int,
    rows: int,
    queries: int,
    top_k: int,
) -> tuple[list[list[float]], list[list[float]], list[list[int]]]:
    planted_rows = queries * top_k
    if planted_rows > rows:
        raise ValueError("queries * top-k cannot exceed rows for planted sparse positives")

    query_vectors: list[list[float]] = []
    query_active_dims: list[list[int]] = []
    for _ in range(queries):
        query, active_dims = build_query(rng, dims, active)
        query_vectors.append(query)
        query_active_dims.append(active_dims)

    base_vectors: list[list[float]] = []
    for query, active_dims in zip(query_vectors, query_active_dims):
        for rank in range(top_k):
            base_vectors.append(build_positive_row(query, active_dims, rank))

    while len(base_vectors) < rows:
        base_vectors.append(build_distractor(rng, dims, active))

    ground_truth = build_ground_truth(base_vectors, query_vectors, top_k)
    return base_vectors, query_vectors, ground_truth


def write_case(
    out_root: Path,
    dims: int,
    active: int,
    rows: int,
    queries: int,
    top_k: int,
    seed: int,
    force: bool,
) -> None:
    out_dir = out_root / f"dims_{dims}_active_{active}"
    base_path = out_dir / "base.f32"
    query_path = out_dir / "query.f32"
    truth_path = out_dir / "ground_truth.u32"
    metadata_path = out_dir / "metadata.json"

    if base_path.exists() and query_path.exists() and truth_path.exists() and not force:
        print(f"sparse-active fixture already exists at {out_dir} (pass --force to regenerate)")
        return

    rng = random.Random(seed + (dims * 1009) + (active * 9176))
    base_vectors, query_vectors, ground_truth = build_case(
        rng,
        dims,
        active,
        rows,
        queries,
        top_k,
    )

    write_f32_matrix(base_path, base_vectors)
    write_f32_matrix(query_path, query_vectors)
    write_u32_matrix(truth_path, ground_truth)
    metadata_path.write_text(
        json.dumps(
            {
                "dimensions": dims,
                "active_query_dimensions": active,
                "rows": rows,
                "queries": queries,
                "top_k": top_k,
                "seed": seed,
                "layout": "first queries*top_k rows are planted sparse positives; remaining rows are low-amplitude sparse distractors",
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    print(
        f"wrote sparse-active workload: rows={rows} queries={queries} "
        f"dims={dims} active={active} top_k={top_k} out={out_dir}"
    )


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--out-root",
        default="data/sparse_active",
        help="output root for generated sparse-active fixtures",
    )
    parser.add_argument(
        "--case",
        action="append",
        dest="cases",
        help="case as DIMENSIONS:ACTIVE; can be repeated (default: 256:16 and 768:32)",
    )
    parser.add_argument("--rows", type=int, default=2048, help="base vector rows")
    parser.add_argument("--queries", type=int, default=128, help="query count")
    parser.add_argument("--top-k", type=int, default=10, help="ground-truth top-k")
    parser.add_argument("--seed", type=int, default=20260518, help="deterministic RNG seed")
    parser.add_argument("--force", action="store_true", help="regenerate files even if present")
    args = parser.parse_args(argv)

    if args.rows <= 0 or args.queries <= 0 or args.top_k <= 0:
        print("rows, queries, and top-k must be positive", file=sys.stderr)
        return 1
    if args.top_k > args.rows:
        print("top-k cannot exceed rows", file=sys.stderr)
        return 1

    try:
        cases = [parse_case(value) for value in (args.cases or DEFAULT_CASES)]
        for dims, active in cases:
            write_case(
                Path(args.out_root),
                dims,
                active,
                args.rows,
                args.queries,
                args.top_k,
                args.seed,
                args.force,
            )
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
