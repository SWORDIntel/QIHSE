#!/usr/bin/env python3
"""Generate a deterministic fallback workload for SIFT-style reference benchmarks."""

from __future__ import annotations

import argparse
import math
import struct
from pathlib import Path
import random
import sys


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


def random_unit_vector(rng: random.Random, dims: int) -> list[float]:
    vector = [rng.gauss(0.0, 1.0) for _ in range(dims)]
    norm = math.sqrt(sum(value * value for value in vector))
    if norm == 0.0:
        return [0.0] * dims
    inv = 1.0 / norm
    return [value * inv for value in vector]


def dot(left: list[float], right: list[float]) -> float:
    return sum(a * b for a, b in zip(left, right))


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


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--out-dir",
        default="data/sift1m/fallback",
        help="output directory (deterministic fixture staged path)",
    )
    parser.add_argument("--rows", type=int, default=2048, help="base vector rows")
    parser.add_argument("--queries", type=int, default=128, help="query count")
    parser.add_argument("--dimensions", type=int, default=128, help="vector dimensions")
    parser.add_argument("--top-k", type=int, default=10, help="ground-truth top-k")
    parser.add_argument("--seed", type=int, default=20260517, help="deterministic RNG seed")
    parser.add_argument("--force", action="store_true", help="regenerate files even if present")
    args = parser.parse_args(argv)

    if args.rows <= 0 or args.queries <= 0 or args.dimensions <= 0 or args.top_k <= 0:
        print("rows/queries/dimensions/top-k must be positive", file=sys.stderr)
        return 1
    if args.top_k > args.rows:
        print("top-k cannot exceed rows", file=sys.stderr)
        return 1

    out_dir = Path(args.out_dir)
    base_path = out_dir / "base.fvecs"
    query_path = out_dir / "query.fvecs"
    truth_path = out_dir / "ground_truth.ivecs"
    if base_path.exists() and query_path.exists() and truth_path.exists() and not args.force:
        print(f"fallback fixture already exists at {out_dir} (pass --force to regenerate)")
        return 0

    rng = random.Random(args.seed)
    base_vectors = [random_unit_vector(rng, args.dimensions) for _ in range(args.rows)]
    query_vectors = [random_unit_vector(rng, args.dimensions) for _ in range(args.queries)]
    ground_truth = build_ground_truth(base_vectors, query_vectors, args.top_k)

    write_fvecs(base_path, base_vectors)
    write_fvecs(query_path, query_vectors)
    write_ivecs(truth_path, ground_truth)
    print(
        f"wrote fallback workload: rows={args.rows} queries={args.queries} "
        f"dims={args.dimensions} top_k={args.top_k} out={out_dir}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
