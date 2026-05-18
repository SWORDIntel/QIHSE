#!/usr/bin/env python3
"""Run a manifest-backed vector workload through QIHSE reference search modes."""

from __future__ import annotations

import argparse
import ctypes
import json
import statistics
import struct
import sys
import tempfile
import time
from pathlib import Path
from typing import Any


QIHSE_VECTOR_DB_INMEMORY = 3
QIHSE_VDB_OPEN_READ_ONLY = 1 << 1
QIHSE_VDB_OPEN_FILE_BACKED = 1 << 3
QIHSE_VDB_OPEN_MMAP = 1 << 4
QIHSE_VDB_QUERY_FLOAT32 = 0
QIHSE_VDB_QUERY_TRINARY_SCALAR = 1
QIHSE_VDB_QUERY_TRINARY_MAGNITUDE = 2
QIHSE_SCALAR_CANDIDATE_MULTIPLIER = 12
QIHSE_MAGNITUDE_CANDIDATE_MULTIPLIER = 8


class QihseVectorResult(ctypes.Structure):
    _fields_ = [
        ("id", ctypes.c_uint64),
        ("score", ctypes.c_float),
        ("vector", ctypes.POINTER(ctypes.c_float)),
        ("vector_dims", ctypes.c_size_t),
        ("metadata", ctypes.c_void_p),
        ("metadata_size", ctypes.c_size_t),
    ]


class QihseVectorQuery(ctypes.Structure):
    _fields_ = [
        ("query_vector", ctypes.POINTER(ctypes.c_float)),
        ("vector_dims", ctypes.c_size_t),
        ("top_k", ctypes.c_size_t),
        ("similarity_threshold", ctypes.c_float),
        ("include_vectors", ctypes.c_bool),
        ("include_metadata", ctypes.c_bool),
        ("use_trinary_candidates", ctypes.c_bool),
        ("candidate_count", ctypes.c_size_t),
        ("query_mode", ctypes.c_int),
        ("candidate_pool_size", ctypes.c_size_t),
    ]


def load_manifest(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        manifest = json.load(handle)
    if not isinstance(manifest, dict):
        raise ValueError("manifest root must be an object")
    return manifest


def find_workload(manifest: dict[str, Any], name: str) -> dict[str, Any]:
    workloads = manifest.get("workloads", [])
    if not isinstance(workloads, list):
        raise ValueError("manifest workloads must be a list")
    for workload in workloads:
        if isinstance(workload, dict) and workload.get("name") == name:
            return workload
    raise ValueError(f"workload not found: {name}")


def read_f32_matrix(path: Path, rows: int, dims: int) -> list[float]:
    expected_bytes = rows * dims * 4
    payload = path.read_bytes()
    if len(payload) != expected_bytes:
        raise ValueError(f"{path} is {len(payload)} bytes, expected {expected_bytes}")
    return list(struct.unpack(f"<{rows * dims}f", payload))


def read_u32_matrix(path: Path, rows: int, dims: int) -> list[list[int]]:
    expected_bytes = rows * dims * 4
    payload = path.read_bytes()
    if len(payload) != expected_bytes:
        raise ValueError(f"{path} is {len(payload)} bytes, expected {expected_bytes}")
    values = struct.unpack(f"<{rows * dims}I", payload)
    return [list(values[index * dims:(index + 1) * dims]) for index in range(rows)]


def read_fvecs(path: Path, rows: int, dims: int) -> list[float]:
    vectors: list[float] = []
    with path.open("rb") as handle:
        for row in range(rows):
            header = handle.read(4)
            if len(header) != 4:
                raise ValueError(f"{path} ended before fvecs row {row}")
            (row_dims,) = struct.unpack("<i", header)
            if row_dims != dims:
                raise ValueError(f"{path} row {row} dims {row_dims}, expected {dims}")
            payload = handle.read(dims * 4)
            if len(payload) != dims * 4:
                raise ValueError(f"{path} has truncated fvecs row {row}")
            vectors.extend(struct.unpack(f"<{dims}f", payload))
        if handle.read(1):
            raise ValueError(f"{path} has extra bytes after {rows} fvecs rows")
    return vectors


def read_ivecs(path: Path, rows: int, top_k: int) -> list[list[int]]:
    ground_truth: list[list[int]] = []
    expected_dims: int | None = None
    with path.open("rb") as handle:
        for row in range(rows):
            header = handle.read(4)
            if len(header) != 4:
                raise ValueError(f"{path} ended before ivecs row {row}")
            (row_dims,) = struct.unpack("<i", header)
            if row_dims < top_k:
                raise ValueError(f"{path} row {row} dims {row_dims}, expected at least {top_k}")
            if expected_dims is None:
                expected_dims = row_dims
            elif row_dims != expected_dims:
                raise ValueError(f"{path} row {row} dims {row_dims}, expected {expected_dims}")
            payload = handle.read(row_dims * 4)
            if len(payload) != row_dims * 4:
                raise ValueError(f"{path} has truncated ivecs row {row}")
            ground_truth.append(list(struct.unpack(f"<{row_dims}i", payload))[:top_k])
        if handle.read(1):
            raise ValueError(f"{path} has extra bytes after {rows} ivecs rows")
    return ground_truth


def read_vectors(root: Path, workload: dict[str, Any]) -> tuple[list[float], list[float], list[list[int]]]:
    rows = int(workload["rows"])
    queries = int(workload["queries"])
    dims = int(workload["dimensions"])
    top_k = int(workload["top_k"])
    files = workload["files"]
    formats = workload["file_formats"]

    base_path = root / files["base_vectors"]
    query_path = root / files["query_vectors"]
    ground_truth_path = root / files["ground_truth"]

    base_format = formats["base_vectors"]
    query_format = formats["query_vectors"]
    truth_format = formats["ground_truth"]

    if base_format == "f32_matrix":
        base_vectors = read_f32_matrix(base_path, rows, dims)
    elif base_format == "fvecs":
        base_vectors = read_fvecs(base_path, rows, dims)
    else:
        raise ValueError(f"unsupported base vector format: {base_format}")

    if query_format == "f32_matrix":
        query_vectors = read_f32_matrix(query_path, queries, dims)
    elif query_format == "fvecs":
        query_vectors = read_fvecs(query_path, queries, dims)
    else:
        raise ValueError(f"unsupported query vector format: {query_format}")

    if truth_format == "u32_matrix":
        ground_truth = read_u32_matrix(ground_truth_path, queries, top_k)
    elif truth_format == "ivecs":
        ground_truth = read_ivecs(ground_truth_path, queries, top_k)
    else:
        raise ValueError(f"unsupported ground-truth format: {truth_format}")

    return base_vectors, query_vectors, ground_truth


def active_query_dims(query_vectors: list[float], queries: int, dims: int) -> dict[str, float | int]:
    counts: list[int] = []
    for query_index in range(queries):
        offset = query_index * dims
        counts.append(
            sum(1 for value in query_vectors[offset:offset + dims] if value != 0.0)
        )
    return {
        "min": min(counts) if counts else 0,
        "mean": statistics.fmean(counts) if counts else 0.0,
        "max": max(counts) if counts else 0,
        "total_dims": dims,
    }


def bind_qihse(lib_path: Path) -> ctypes.CDLL:
    lib = ctypes.CDLL(str(lib_path))

    lib.qihse_vector_db_create.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_char_p]
    lib.qihse_vector_db_create.restype = ctypes.c_void_p

    lib.qihse_vector_db_open.argtypes = [
        ctypes.c_int,
        ctypes.c_void_p,
        ctypes.c_char_p,
        ctypes.c_uint32,
    ]
    lib.qihse_vector_db_open.restype = ctypes.c_void_p

    lib.qihse_vector_db_add_vectors.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_float),
        ctypes.c_size_t,
        ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_uint64),
        ctypes.c_void_p,
        ctypes.c_void_p,
    ]
    lib.qihse_vector_db_add_vectors.restype = ctypes.c_bool

    lib.qihse_vector_db_flush.argtypes = [ctypes.c_void_p]
    lib.qihse_vector_db_flush.restype = ctypes.c_bool

    lib.qihse_vector_db_close.argtypes = [ctypes.c_void_p]
    lib.qihse_vector_db_close.restype = ctypes.c_bool

    lib.qihse_vector_db_destroy.argtypes = [ctypes.c_void_p]
    lib.qihse_vector_db_destroy.restype = None

    lib.qihse_vector_db_search.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(QihseVectorQuery),
        ctypes.POINTER(QihseVectorResult),
        ctypes.c_size_t,
    ]
    lib.qihse_vector_db_search.restype = ctypes.c_int

    return lib


def create_file_backed_db(
    lib: ctypes.CDLL,
    db_path: Path,
    base_vectors: list[float],
    rows: int,
    dims: int,
) -> None:
    vector_array = (ctypes.c_float * len(base_vectors))(*base_vectors)
    ids = (ctypes.c_uint64 * rows)(*range(rows))
    db = lib.qihse_vector_db_create(
        QIHSE_VECTOR_DB_INMEMORY,
        None,
        str(db_path).encode("utf-8"),
    )
    if not db:
        raise RuntimeError("qihse_vector_db_create failed")
    closed = False
    try:
        if not lib.qihse_vector_db_add_vectors(
            db,
            vector_array,
            rows,
            dims,
            ids,
            None,
            None,
        ):
            raise RuntimeError("qihse_vector_db_add_vectors failed")
        if not lib.qihse_vector_db_flush(db):
            raise RuntimeError("qihse_vector_db_flush failed")
        if not lib.qihse_vector_db_close(db):
            closed = True
            raise RuntimeError("qihse_vector_db_close failed")
        closed = True
    finally:
        if not closed:
            lib.qihse_vector_db_destroy(db)


def open_search_db(lib: ctypes.CDLL, db_path: Path) -> ctypes.c_void_p:
    db = lib.qihse_vector_db_open(
        QIHSE_VECTOR_DB_INMEMORY,
        None,
        str(db_path).encode("utf-8"),
        QIHSE_VDB_OPEN_FILE_BACKED | QIHSE_VDB_OPEN_READ_ONLY | QIHSE_VDB_OPEN_MMAP,
    )
    if not db:
        raise RuntimeError("qihse_vector_db_open failed")
    return db


def run_mode(
    lib: ctypes.CDLL,
    db: ctypes.c_void_p,
    mode_name: str,
    query_mode: int,
    query_vectors: list[float],
    ground_truth: list[list[int]],
    queries: int,
    dims: int,
    top_k: int,
    iterations: int,
) -> dict[str, Any]:
    result_array_type = QihseVectorResult * top_k
    matches = 0
    total = queries * top_k
    timings_us: list[float] = []
    mismatches: list[dict[str, Any]] = []

    for _ in range(iterations):
        for query_index in range(queries):
            offset = query_index * dims
            query_array = (ctypes.c_float * dims)(*query_vectors[offset:offset + dims])
            query = QihseVectorQuery(
                query_vector=query_array,
                vector_dims=dims,
                top_k=top_k,
                similarity_threshold=ctypes.c_float(-1.0),
                include_vectors=False,
                include_metadata=False,
                use_trinary_candidates=False,
                candidate_count=0,
                query_mode=query_mode,
                candidate_pool_size=0,
            )
            results = result_array_type()
            start = time.perf_counter()
            found = lib.qihse_vector_db_search(db, ctypes.byref(query), results, top_k)
            elapsed_us = (time.perf_counter() - start) * 1_000_000.0
            if found < 0:
                raise RuntimeError(f"{mode_name} search failed")
            if found < top_k:
                raise RuntimeError(f"{mode_name} returned {found}, expected {top_k}")
            timings_us.append(elapsed_us)
            if _ == 0:
                expected = set(ground_truth[query_index][:top_k])
                actual_ids = [int(results[index].id) for index in range(top_k)]
                actual = set(actual_ids)
                matches += len(expected.intersection(actual))
                if actual != expected:
                    mismatches.append({
                        "query": query_index,
                        "expected": ground_truth[query_index][:top_k],
                        "actual": actual_ids,
                        "missing": sorted(expected.difference(actual)),
                        "extra": sorted(actual.difference(expected)),
                    })

    recall = matches / total if total else 0.0
    mean_us = statistics.fmean(timings_us) if timings_us else 0.0
    p95_us = sorted(timings_us)[max(0, int(len(timings_us) * 0.95) - 1)] if timings_us else 0.0
    return {
        "mode": mode_name,
        "recall": recall,
        "mean_us": mean_us,
        "p95_us": p95_us,
        "matches": matches,
        "total": total,
        "mismatches": mismatches,
    }


def candidate_diagnostics(mode_name: str, rows: int, dims: int, top_k: int) -> dict[str, Any]:
    requested_candidate_pool = 0
    requested_candidate_count = 0
    if mode_name == "float32":
        effective_candidate_pool = rows
        policy = "exact_float32_all_rows"
        path_label = "exact_float32_all_rows"
    elif mode_name == "qtri":
        effective_candidate_pool = rows
        policy = "default_exact_rerank_all_rows"
        path_label = "scalar_trinary_sign_full_rerank"
    else:
        multiplier = QIHSE_MAGNITUDE_CANDIDATE_MULTIPLIER
        if dims >= 1024:
            multiplier += 8
        elif dims >= 256:
            multiplier += 4
        effective_candidate_pool = min(rows, top_k * multiplier)
        policy = "default_magnitude_candidate_pool"
        path_label = "qmag_dimension_mapped_trinary_magnitude_default_pool"
    return {
        "candidate_pool": effective_candidate_pool,
        "requested_candidate_pool": requested_candidate_pool,
        "requested_candidate_count": requested_candidate_count,
        "effective_candidate_pool": effective_candidate_pool,
        "reranked_rows": effective_candidate_pool,
        "candidate_policy": policy,
        "candidate_path_label": path_label,
        "candidate_path_source": "script_inferred_from_query_mode",
    }


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=".", help="QIHSE root")
    parser.add_argument("--manifest", default="benchmarks/reference_workloads.json")
    parser.add_argument("--workload", default="vxug-pdf-sample")
    parser.add_argument("--iterations", type=int, default=3)
    parser.add_argument(
        "--output-json",
        help="optional generated result JSON path; parent directory is created",
    )
    args = parser.parse_args(argv)

    root = Path(args.root).resolve()
    manifest = load_manifest(root / args.manifest)
    workload = find_workload(manifest, args.workload)
    dims = int(workload["dimensions"])
    rows = int(workload["rows"])
    queries = int(workload["queries"])
    top_k = int(workload["top_k"])

    if args.iterations <= 0:
        print("iterations must be positive", file=sys.stderr)
        return 1

    try:
        base_vectors, query_vectors, ground_truth = read_vectors(root, workload)
        active_dims = active_query_dims(query_vectors, queries, dims)
        lib = bind_qihse(root / "libqihse.so")
        with tempfile.TemporaryDirectory(prefix="qihse_vxug_bench_") as temp_dir:
            db_path = Path(temp_dir) / "db"
            create_file_backed_db(lib, db_path, base_vectors, rows, dims)
            db = open_search_db(lib, db_path)
            try:
                results_payload: dict[str, Any] = {
                    "workload": args.workload,
                    "rows": rows,
                    "queries": queries,
                    "dimensions": dims,
                    "top_k": top_k,
                    "iterations": args.iterations,
                    "active_query_dims": active_dims,
                    "modes": [],
                }
                print(
                    f"{args.workload}: rows={rows} queries={queries} dims={dims} "
                    f"top_k={top_k} iterations={args.iterations} "
                    f"active_dims=min/{active_dims['min']} "
                    f"mean/{active_dims['mean']:.1f} max/{active_dims['max']}"
                )
                for mode_name, query_mode in (
                    ("float32", QIHSE_VDB_QUERY_FLOAT32),
                    ("qtri", QIHSE_VDB_QUERY_TRINARY_SCALAR),
                    ("qmag", QIHSE_VDB_QUERY_TRINARY_MAGNITUDE),
                ):
                    mode_result = run_mode(
                        lib,
                        db,
                        mode_name,
                        query_mode,
                        query_vectors,
                        ground_truth,
                        queries,
                        dims,
                        top_k,
                        args.iterations,
                    )
                    diagnostics = candidate_diagnostics(mode_name, rows, dims, top_k)
                    mode_result.update(diagnostics)
                    results_payload["modes"].append(mode_result)
                    print(
                        f"{mode_name}: recall@{top_k}={mode_result['recall']:.4f} "
                        f"mean_us={mode_result['mean_us']:.3f} "
                        f"p95_us={mode_result['p95_us']:.3f} "
                        f"requested_pool={mode_result['requested_candidate_pool']} "
                        f"effective_pool={mode_result['effective_candidate_pool']} "
                        f"reranked_rows={mode_result['reranked_rows']} "
                        f"candidate_policy={mode_result['candidate_policy']} "
                        f"candidate_path={mode_result['candidate_path_label']} "
                        f"mismatches={len(mode_result['mismatches'])}"
                    )
                if args.output_json:
                    output_path = Path(args.output_json)
                    if not output_path.is_absolute():
                        output_path = root / output_path
                    output_path.parent.mkdir(parents=True, exist_ok=True)
                    output_path.write_text(
                        json.dumps(results_payload, indent=2, sort_keys=True) + "\n",
                        encoding="utf-8",
                    )
                    print(f"wrote {output_path}")
            finally:
                lib.qihse_vector_db_destroy(db)
    except (OSError, RuntimeError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
