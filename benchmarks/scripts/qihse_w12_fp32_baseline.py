#!/usr/bin/env python3
"""Reproducible W12.0 synthetic FP32 kernel baseline, not an engine benchmark.

Builds the real production scalar/runtime-dispatched distance kernels and a
benchmark-only exhaustive top-K loop. The independent numerical reference uses
Python binary64 accumulation over exactly the same binary32 fixture values.
No persistent VectorDB, classified records, credentials, or external data loads.
"""
from __future__ import annotations

import argparse
import array
import ctypes as C
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import shlex
import statistics
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
SOURCES = ["benchmarks/src/qihse_w12_fp32.c",
           "backends/cpu/qihse_cpu_distance.c", "backends/cpu/qihse_cpu_detect.c"]
HEADERS = ["benchmarks/include/qihse_w12_fp32.h", "backends/cpu/qihse_cpu_distance.h", "backends/cpu/qihse_cpu_detect.h"]
FLAGS = ["-std=c99", "-D_GNU_SOURCE", "-O2", "-fno-fast-math",
         "-ffp-contract=off", "-fno-tree-vectorize", "-fPIC", "-shared",
         "-Ibackends/cpu", "-pthread"]
SCORE_SCALED_ERROR_TOLERANCE = 2e-5  # Pilot contract, not a universal kernel guarantee.
CORPORA = ("isotropic", "anisotropic", "clustered", "duplicates",
           "high-dynamic-range", "sparse-sign")
METRICS = {"cosine": 0, "dot": 1, "l2": 2}
# Preconditions and scope are explicit. These are not inferred benchmark wins.
UNMEASURED = {
    "native_float32": "Full engine/auth/metadata/materialization path not measured.",
    "hnsw": "Audit blocker: graph traversal selects globally before row authorization; native measurement pending.",
    "trinary": "Audit blocker: candidate selection precedes row authorization; native measurement pending.",
    "int8": "Audit blocker: global candidate selection before row authorization.",
    "binary": "Audit blocker: row authorization absent on candidate/rerank path.",
    "fp16_fp32_fp8_fp4_int4": "Selectors currently route to authoritative FP32 scan, not compressed scoring.",
    "pq": "Built standalone prototype; not a native VectorDB query selector.",
    "turboquant": "Not implemented; no compressed-index claims.",
}


def compile_library(output: Path, *, sanitize: bool = False) -> dict:
    output.parent.mkdir(parents=True, exist_ok=True)
    compiler = shlex.split(os.environ.get("CC", "cc"))
    flags = FLAGS + (["-fsanitize=undefined", "-fno-sanitize-recover=all"] if sanitize else [])
    command = compiler + flags + SOURCES + ["-lm", "-o", str(output)]
    subprocess.run(command, cwd=ROOT, check=True, stdout=sys.stderr)
    version = subprocess.check_output(compiler + ["--version"], text=True).splitlines()[0]
    return {"compiler": version, "compiler_argv": compiler, "flags": flags, "sources": SOURCES,
            "source_sha256": {p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest()
                              for p in SOURCES + HEADERS + ["benchmarks/scripts/qihse_w12_fp32_baseline.py", "benchmarks/w12.mk"]}}


class Kernel:
    def __init__(self, path: Path):
        self.lib = C.CDLL(str(path.resolve()))
        self.search = self.lib.qihse_w12_synthetic_search
        self.search.argtypes = [C.POINTER(C.c_float), C.POINTER(C.c_uint8),
                               C.c_size_t, C.c_size_t, C.POINTER(C.c_float),
                               C.c_size_t, C.c_int, C.c_int,
                               C.POINTER(C.c_size_t), C.POINTER(C.c_float),
                               C.POINTER(C.c_size_t), C.POINTER(C.c_size_t)]
        self.search.restype = C.c_int
        self.lib.qihse_w12_dispatch_name.restype = C.c_char_p
        self.dispatch = self.lib.qihse_w12_dispatch_name().decode("ascii")

    def prepare(self, vectors, queries, mask, dims, k):
        return Prepared(self, vectors, queries, mask, dims, k)


class Prepared:
    def __init__(self, kernel, vectors, queries, mask, dims, k):
        if dims <= 0 or not mask or len(vectors) != len(mask) * dims:
            raise ValueError("Invalid synthetic fixture shape")
        if not 0 < k <= len(mask) or any(len(q) != dims for q in queries):
            raise ValueError("Invalid top-K or query dimensions")
        self.kernel, self.rows, self.dims, self.k = kernel, len(mask), dims, k
        self.vectors = (C.c_float * len(vectors))(*vectors)
        self.queries = [(C.c_float * dims)(*q) for q in queries]
        self.mask = (C.c_uint8 * len(mask))(*mask)
        self.ids, self.scores = (C.c_size_t * k)(), (C.c_float * k)()
        self.count, self.scored = C.c_size_t(), C.c_size_t()

    def run(self, query_index, metric, dispatched):
        start = time.perf_counter_ns()
        error = self.kernel.search(self.vectors, self.mask, self.rows, self.dims,
                                   self.queries[query_index], self.k, METRICS[metric],
                                   int(dispatched), self.ids, self.scores,
                                   C.byref(self.count), C.byref(self.scored))
        elapsed = time.perf_counter_ns() - start
        if error:
            raise ValueError(f"Synthetic search failed: {os.strerror(error)} ({error})")
        return list(self.ids[:self.count.value]), list(self.scores[:self.count.value]), elapsed, self.scored.value


class PRNG:
    """Fixed uint32 xorshift, exact binary fractions, never libc/Python random."""
    def __init__(self, seed):
        self.state = (seed & 0xffffffff) or 0x6d2b79f5

    def value(self):
        x = self.state
        x ^= (x << 13) & 0xffffffff
        x ^= x >> 17
        x ^= (x << 5) & 0xffffffff
        self.state = x & 0xffffffff
        return ((self.state >> 8) - (1 << 23)) / float(1 << 23)


def fixture(rows, dims, query_count, seed, corpus):
    if corpus not in CORPORA or min(rows, dims, query_count) <= 0:
        raise ValueError("Invalid synthetic fixture configuration")
    rng = PRNG(seed)
    centers = [[rng.value() for _ in range(dims)] for _ in range(8)]

    def vector(index):
        values = []
        for dim in range(dims):
            value = rng.value()
            if corpus == "anisotropic":
                value *= 16.0 if dim < max(1, dims // 16) else 0.0625
            elif corpus == "clustered":
                value = centers[index % 8][dim] + value * 0.03125
            elif corpus == "high-dynamic-range":
                value *= 1048576.0 if dim % 8 == 0 else 0.00000095367431640625
            elif corpus == "sparse-sign":
                value = (1.0 if value > 0 else -1.0) if dim % 16 == index % 16 else 0.0
            values.append(value)
        return array.array("f", values)

    vectors = array.array("f")
    previous = None
    for row in range(rows):
        if corpus != "duplicates" or row % 8 == 0:
            previous = vector(row)
        vectors.extend(previous)
    queries = [vector(rows + i) for i in range(query_count)]
    return vectors, queries, bytearray([1]) * rows


def reference_score(a, b, metric):
    if metric == "l2":
        return 1.0 / (1.0 + math.sqrt(math.fsum((x - y) ** 2 for x, y in zip(a, b))))
    dot = math.fsum(x * y for x, y in zip(a, b))
    if metric == "dot":
        return dot
    na, nb = math.fsum(x * x for x in a), math.fsum(y * y for y in b)
    return dot / (math.sqrt(na) * math.sqrt(nb)) if na and nb else 0.0


def oracle(vectors, query, mask, dims, k, metric):
    """Independent complete ranking; the ordinal tie key matches native scan order."""
    if metric not in METRICS or dims <= 0 or len(vectors) != len(mask) * dims or len(query) != dims or k <= 0:
        raise ValueError("Invalid oracle input")
    if not all(math.isfinite(v) for v in query):
        raise ValueError("Nonfinite query")
    ranked = []
    for row, selected in enumerate(mask):
        if not selected:
            continue
        vector = vectors[row * dims:(row + 1) * dims]
        if not all(math.isfinite(v) for v in vector):
            raise ValueError("Nonfinite selected vector")
        ranked.append((row, reference_score(query, vector, metric)))
    ranked.sort(key=lambda item: (-item[1], item[0]))
    return ranked[:k]


def recall(actual, expected):
    if not expected:
        return 1.0 if not actual else 0.0
    return len(set(actual) & set(expected)) / len(set(expected))


def statistics_ns(samples):
    ordered = sorted(samples)
    mean = statistics.mean(ordered)
    error = 1.96 * statistics.stdev(ordered) / math.sqrt(len(ordered)) if len(ordered) > 1 else None
    def percentile(p):
        return ordered[max(0, math.ceil(p * len(ordered)) - 1)]
    return {"samples_ns": samples, "mean_ns": mean,
            "mean_95pct_normal_ci_ns": [max(0.0, mean - error), mean + error] if error is not None else None,
            "p50_ns": percentile(.50), "p95_ns": percentile(.95), "p99_ns": percentile(.99),
            "queries_per_second": 1e9 / mean}


def fixture_hash(vectors, queries, mask):
    digest = hashlib.sha256()
    for values in [vectors] + queries:
        values = array.array("f", values)
        if sys.byteorder != "little":
            values.byteswap()
        digest.update(values.tobytes())
    digest.update(mask)
    return digest.hexdigest()


def benchmark(kernel, rows, dims, query_count, k, seed, corpus, repeats):
    started = time.perf_counter_ns()
    vectors, queries, mask = fixture(rows, dims, query_count, seed, corpus)
    prepared = kernel.prepare(vectors, queries, mask, dims, k)
    preparation_ns = time.perf_counter_ns() - started
    reports = []
    for metric in METRICS:
        truths = [oracle(vectors, query, mask, dims, k, metric) for query in queries]
        scalar_ids = [prepared.run(i, metric, False)[0] for i in range(query_count)]
        for dispatched in (False, True):
            # Warm the dispatch table and query buffers; initialization excluded.
            for i in range(query_count):
                prepared.run(i, metric, dispatched)
            samples, recalls, scalar_recalls, errors, result_rows = [], [], [], [], []
            for repeat in range(repeats):
                for i in range(query_count):
                    ids, scores, elapsed, scored = prepared.run(i, metric, dispatched)
                    if scored != rows or len(ids) != k:
                        raise RuntimeError("Incomplete exhaustive search")
                    samples.append(elapsed)
                    if repeat == 0:
                        result_rows.append(ids)
                        recalls.append(recall(ids, [row for row, _ in truths[i]]))
                        scalar_recalls.append(recall(ids, scalar_ids[i]))
                        for row, score in zip(ids, scores):
                            expected = reference_score(queries[i], vectors[row*dims:(row+1)*dims], metric)
                            errors.append(abs(score - expected) / max(1.0, abs(expected)))
            reports.append({"metric": metric, "path": "production_dispatch" if dispatched else "production_scalar",
                            "resolved_kernel": kernel.dispatch if dispatched else "scalar",
                            "candidate_pool": rows, "top_k": k,
                            "recall_at_k_vs_fp64_reference_per_query": recalls,
                            "recall_at_k_vs_fp64_reference_mean": statistics.mean(recalls),
                            "recall_at_k_vs_scalar_fp32_mean": statistics.mean(scalar_recalls),
                            "max_score_error_scaled_by_max_1_abs_reference": max(errors, default=0),
                            "score_tolerance_passed": max(errors, default=0) <= SCORE_SCALED_ERROR_TOLERANCE,
                            "result_rows": result_rows, **statistics_ns(samples)})
    return {"corpus": corpus, "generator": "xorshift32-v1", "seed": seed, "rows": rows,
            "dimensions": dims, "queries": query_count, "repeats": repeats,
            "fixture_sha256": fixture_hash(vectors, queries, mask),
            "fixture_preparation_ns": preparation_ns,
            "vector_payload_bytes": rows * dims * 4,
            "query_payload_bytes": query_count * dims * 4,
            "search_workspace_bytes": rows + k * (C.sizeof(C.c_size_t) + 4) + 2 * C.sizeof(C.c_size_t),
            "engine_resident_bytes": None, "sidecar_disk_bytes": None,
            "measurement_scope": "synthetic_exhaustive_kernel_plus_validation_topk_and_ctypes_call",
            "results": reports}


def git_output(*args):
    try:
        return subprocess.check_output(["git", *args], cwd=ROOT, text=True, stderr=subprocess.DEVNULL).strip()
    except (OSError, subprocess.CalledProcessError):
        return None


def positive(value):
    number = int(value)
    if number <= 0:
        raise argparse.ArgumentTypeError("must be positive")
    return number


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rows", type=positive, default=2048)
    parser.add_argument("--dimensions", type=positive, nargs="+", default=[128, 384, 768, 1536])
    parser.add_argument("--queries", type=positive, default=16)
    parser.add_argument("--top-k", type=positive, default=10)
    parser.add_argument("--repeats", type=positive, default=3)
    parser.add_argument("--seed", type=int, default=20261022)
    parser.add_argument("--corpora", choices=CORPORA, nargs="+", default=["isotropic", "clustered", "duplicates"])
    parser.add_argument("--output", type=Path, default=Path("build/w12/fp32-baseline.json"))
    args = parser.parse_args(argv)
    if args.top_k > args.rows or not 0 <= args.seed <= 0xffffffff:
        parser.error("top-k must not exceed rows; seed must fit uint32")
    # Bound accidental allocations. This pilot is not the large-corpus gate.
    if max(args.dimensions) > 16384 or (args.rows + args.queries) * max(args.dimensions) > 16_777_216:
        parser.error("synthetic pilot limit: dimensions <= 16384 and <= 16,777,216 total float values")
    library = ROOT / "build/w12/libqihse_w12_fp32.so"
    build = compile_library(library)
    kernel = Kernel(library)
    cpu = platform.processor()
    cpuinfo = Path(os.environ.get("PROC_ROOT", os.path.join(os.sep, "proc"))) / "cpuinfo"
    if cpuinfo.exists():
        cpu = next((line.split(":", 1)[1].strip() for line in cpuinfo.read_text().splitlines()
                    if line.startswith("model name")), cpu)
    output = {"schema": "qihse-w12-fp32-baseline-v1", "w12_0_complete": False,
              "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
              "git_commit": git_output("rev-parse", "HEAD"), "git_dirty": bool(git_output("status", "--porcelain")),
              "host": {"system": platform.system(), "release": platform.release(),
                       "machine": platform.machine(), "cpu": cpu, "logical_cpus": os.cpu_count()},
              "python": platform.python_version(), "build": build,
              "contract": {"input": "synthetic IEEE binary32 only", "oracle_accumulation": "binary64 math.fsum",
                           "tie_break": "score descending then physical fixture row ascending",
                           "threshold": "none; include negative similarities", "cache": "none",
                           "score_scaled_error_tolerance": SCORE_SCALED_ERROR_TOLERANCE,
                           "ranking_tolerance": "none; report exact row-set recall, including numerical near-tie disagreements",
                           "precision_profiles": ["FP32 scalar", "FP32 runtime dispatch"],
                           "candidate_pool": "all selected rows", "compressed_profiles": [],
                           "uncertainty": "raw warm query samples; normal-approximation mean CI, correlated repetitions; no tail CI",
                           "security": "generated fixtures only; not production auth validation"},
              "unmeasured": UNMEASURED, "runs": []}
    for dims in args.dimensions:
        for corpus in args.corpora:
            print(f"W12 synthetic FP32: {corpus}, {args.rows} x {dims}", file=sys.stderr)
            output["runs"].append(benchmark(kernel, args.rows, dims, args.queries, args.top_k, args.seed, corpus, args.repeats))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(output, indent=2, allow_nan=False) + "\n")
    print(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
