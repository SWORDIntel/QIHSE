#!/usr/bin/env python3
"""Summarize and gate generated QIHSE reference workload result JSON."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value


def find_workload(manifest: dict[str, Any], name: str) -> dict[str, Any]:
    workloads = manifest.get("workloads", [])
    if not isinstance(workloads, list):
        raise ValueError("manifest workloads must be a list")
    for workload in workloads:
        if isinstance(workload, dict) and workload.get("name") == name:
            return workload
    raise ValueError(f"workload not found in manifest: {name}")


def recall_floor(workload: dict[str, Any], top_k: int) -> float | None:
    acceptance = workload.get("acceptance", {})
    if not isinstance(acceptance, dict):
        return None
    specific_key = f"recall_at_{top_k}_floor"
    if specific_key in acceptance:
        return float(acceptance[specific_key])
    if "recall_at_top_k" in acceptance:
        return float(acceptance["recall_at_top_k"])
    return None


def mismatches_must_be_zero(workload: dict[str, Any]) -> bool:
    acceptance = workload.get("acceptance", {})
    return isinstance(acceptance, dict) and bool(acceptance.get("mismatches_must_be_zero"))


def required_metric(workload: dict[str, Any], name: str) -> bool:
    acceptance = workload.get("acceptance", {})
    return isinstance(acceptance, dict) and bool(acceptance.get(name))


def summarize(result: dict[str, Any], workload: dict[str, Any]) -> int:
    workload_name = str(result.get("workload", "<unknown>"))
    top_k = int(result.get("top_k", 0))
    floor = recall_floor(workload, top_k)
    reject_mismatches = mismatches_must_be_zero(workload)
    require_p95 = required_metric(workload, "latency_p95_us_must_be_reported")
    require_rerank = required_metric(workload, "rerank_candidates_must_be_reported")
    modes = result.get("modes", [])
    if not isinstance(modes, list) or not modes:
        raise ValueError("result JSON must include non-empty modes list")

    status = 0
    print(
        f"{workload_name}: rows={result.get('rows')} queries={result.get('queries')} "
        f"dims={result.get('dimensions')} top_k={top_k} iterations={result.get('iterations')}"
    )
    active_dims = result.get("active_query_dims")
    if isinstance(active_dims, dict):
        print(
            f"active_query_dims=min/{active_dims.get('min', 0)} "
            f"mean/{float(active_dims.get('mean', 0.0)):.1f} "
            f"max/{active_dims.get('max', 0)} "
            f"total_dims={active_dims.get('total_dims', result.get('dimensions'))}"
        )
    for mode in modes:
        if not isinstance(mode, dict):
            raise ValueError("mode result must be an object")
        name = str(mode.get("mode", "<unknown>"))
        recall = float(mode.get("recall", 0.0))
        p95_us = float(mode.get("p95_us", 0.0))
        mean_us = float(mode.get("mean_us", 0.0))
        requested_pool = int(mode.get("requested_candidate_pool", mode.get("candidate_pool", 0)))
        effective_pool = int(mode.get("effective_candidate_pool", mode.get("candidate_pool", 0)))
        reranked_rows = int(mode.get("reranked_rows", mode.get("candidate_pool", 0)))
        candidate_policy = str(mode.get("candidate_policy", "n/a"))
        candidate_path = str(mode.get("candidate_path_label", "n/a"))
        mismatches = mode.get("mismatches", [])
        mismatch_count = len(mismatches) if isinstance(mismatches, list) else 0
        recall_passed = floor is None or recall >= floor
        mismatch_passed = not reject_mismatches or mismatch_count == 0
        p95_reported = not require_p95 or "p95_us" in mode
        rerank_reported = not require_rerank or "reranked_rows" in mode or "candidate_pool" in mode
        passed = recall_passed and mismatch_passed and p95_reported and rerank_reported
        if not passed:
            status = 1
        gate = "pass" if passed else "fail"
        mismatch_gate = "zero-required" if reject_mismatches else "reported-only"
        metric_gate = (
            f"p95_reported={'yes' if p95_reported else 'no'} "
            f"rerank_reported={'yes' if rerank_reported else 'no'}"
        )
        print(
            f"{name}: {gate} recall@{top_k}={recall:.4f} "
            f"floor={floor if floor is not None else 'n/a'} "
            f"mean_us={mean_us:.3f} p95_us={p95_us:.3f} "
            f"requested_pool={requested_pool} effective_pool={effective_pool} "
            f"reranked_rows={reranked_rows} candidate_policy={candidate_policy} "
            f"candidate_path={candidate_path} mismatches={mismatch_count} "
            f"mismatch_gate={mismatch_gate} {metric_gate}"
        )
    return status


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=".", help="QIHSE root")
    parser.add_argument("--manifest", default="benchmarks/reference_workloads.json")
    parser.add_argument("--workload", help="workload name; defaults to result JSON workload")
    parser.add_argument("--result", required=True, help="generated result JSON path")
    args = parser.parse_args(argv)

    root = Path(args.root).resolve()
    result_path = Path(args.result)
    if not result_path.is_absolute():
        result_path = root / result_path
    manifest_path = Path(args.manifest)
    if not manifest_path.is_absolute():
        manifest_path = root / manifest_path

    try:
        result = load_json(result_path)
        manifest = load_json(manifest_path)
        workload_name = args.workload or str(result.get("workload", ""))
        if not workload_name:
            raise ValueError("workload name missing from arguments and result JSON")
        workload = find_workload(manifest, workload_name)
        return summarize(result, workload)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"reference result summary failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
