#!/usr/bin/env python3
"""Compare SHA-256/128 and tuned XXH3 producer ID allocation on identical frames.

Run with the producer's Python environment. This measures resident synthetic
identity hashing/allocation, not complete graph builds, Git, disk I/O or queries.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import os
import platform
import random
import statistics
import sys
import time
from pathlib import Path
from typing import Callable


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--producer-root", type=Path,
                        default=os.environ.get("QIHSE_PRODUCER_ROOT"))
    parser.add_argument("--library", type=Path,
                        default=os.environ.get("QIHSE_CODEGRAPH_XXH3_LIBRARY"))
    parser.add_argument("--samples", type=int, default=11)
    parser.add_argument("--nodes", type=int, default=8000)
    parser.add_argument("--edges", type=int, default=24000)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not args.producer_root or not args.library:
        parser.error(
            "--producer-root and --library or corresponding environment paths are required"
        )
    if args.samples < 1 or args.nodes < 1 or args.edges < 0:
        parser.error("samples/nodes must be positive; edges must be nonnegative")
    producer = args.producer_root.resolve(strict=True)
    library = args.library.resolve(strict=True)
    os.environ["QIHSE_CODEGRAPH_XXH3_LIBRARY"] = str(library)
    sys.path.insert(0, str(producer))
    exports = importlib.import_module("code_review_graph.exports")
    native = importlib.import_module("code_review_graph.qihse_xxh3")
    if not Path(exports.__file__).resolve().is_relative_to(producer):
        raise RuntimeError("benchmark did not import the requested producer source")

    frames = [exports._qihse_node_identity(
        f"src/component_{i % 32}/package/module.py::Class.method_{i}",
    ) for i in range(args.nodes)]
    frames.extend(exports._qihse_edge_identity((
        "CALLS", f"module::{i % args.nodes}", f"module::{(i * 17) % args.nodes}",
        f"src/package_{i % 32}/module.py", str(i % 600),
    ), 0) for i in range(args.edges))

    def sha() -> list[str]:
        return [hashlib.sha256(frame).digest()[:16].hex() for frame in frames]

    def batch() -> list[str]:
        return native.hash_many(frames)

    def single() -> list[str]:
        return [native.hash_one(frame) for frame in frames]

    def allocation(function: Callable[[], list[str]]) -> dict[str, bytes]:
        registry: dict[str, bytes] = {}
        for frame, candidate in zip(frames, function(), strict=True):
            exports._qihse_checked_id(frame, registry, candidate)
        return registry

    methods = {"sha256_128": sha, "xxh3_batch": batch, "xxh3_single_ctypes": single}
    hashing: dict[str, list[float]] = {name: [] for name in methods}
    allocating: dict[str, list[float]] = {name: [] for name in ("sha256_128", "xxh3_batch")}
    # Warm the lazy native binding outside measurements and verify canonical APIs.
    assert native.hash_one(b"abc") == "06b05ab6733a618578af5f94892f3950"
    assert native.hash_many([b"", b"abc"]) == [native.hash_one(b""), native.hash_one(b"abc")]
    expected = len(frames)
    unique_identities = len(set(frames))
    for sample in range(args.samples):
        names = list(methods)
        rng = random.Random(sample)
        rng.shuffle(names)
        for name in names:
            started = time.process_time()
            result = methods[name]()
            hashing[name].append((time.process_time() - started) * 1000)
            assert len(result) == expected
            assert all(len(identity) == 32 for identity in result)
        names = list(allocating)
        rng.shuffle(names)
        for name in names:
            started = time.process_time()
            registry = allocation(methods[name])
            allocating[name].append((time.process_time() - started) * 1000)
            assert len(registry) == unique_identities
    hash_medians = {name: statistics.median(values) for name, values in hashing.items()}
    allocation_medians = {name: statistics.median(values) for name, values in allocating.items()}
    report = {
        "method": (
            "CPU-time samples, shuffled method order per phase/sample; same synthetic "
            "canonical node/edge frames and checked collision registry; "
            "lazy binding warmed before timing"
        ),
        "limits": (
            "Shared host; CPU frequency and sibling contention uncontrolled. Resident "
            "identity hashing/allocation only: excludes Git, filesystem I/O, serialization, "
            "graph construction and queries. No security-equivalence claim."
        ),
        "nodes": args.nodes, "edges": args.edges, "samples": args.samples,
        "python": sys.version, "python_executable": sys.executable,
        "platform": platform.platform(),
        "configured_backend": os.environ.get("QIHSE_CODEGRAPH_XXH3_BACKEND", "auto"),
        "sources": {
            "exports_sha256": sha256_file(Path(exports.__file__)),
            "binding_sha256": sha256_file(Path(native.__file__)),
            "library_sha256": sha256_file(library),
            "benchmark_sha256": sha256_file(Path(__file__)),
        },
        "hash_ms_median": hash_medians,
        "checked_allocation_ms_median": allocation_medians,
        "raw_hash_samples_ms": hashing,
        "raw_allocation_samples_ms": allocating,
        "hashing_speedup": hash_medians["sha256_128"] / hash_medians["xxh3_batch"],
        "checked_allocation_speedup": allocation_medians["sha256_128"] /
                                      allocation_medians["xxh3_batch"],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({key: report[key] for key in (
        "python", "hash_ms_median", "checked_allocation_ms_median", "hashing_speedup",
        "checked_allocation_speedup",
    )}, indent=2))


if __name__ == "__main__":
    main()
