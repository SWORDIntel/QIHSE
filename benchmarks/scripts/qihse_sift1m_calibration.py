#!/usr/bin/env python3
"""Summarize SIFT1M calibration evidence and suggest a trinary policy."""

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


def extract_modes(result: dict[str, Any]) -> dict[str, dict[str, float | int | str]]:
    modes = result.get("modes")
    if not isinstance(modes, list):
        raise ValueError("result JSON missing modes list")
    extracted: dict[str, dict[str, float | int | str]] = {}
    for entry in modes:
        if not isinstance(entry, dict):
            continue
        mode = str(entry.get("mode", ""))
        if not mode:
            continue
        extracted[mode] = {
            "recall": float(entry.get("recall", 0.0)),
            "candidate_pool": int(entry.get("candidate_pool", 0)),
            "requested_candidate_pool": int(entry.get("requested_candidate_pool", 0)),
            "effective_candidate_pool": int(
                entry.get("effective_candidate_pool", entry.get("candidate_pool", 0))
            ),
            "mean_us": float(entry.get("mean_us", 0.0)),
            "p95_us": float(entry.get("p95_us", 0.0)),
            "reranked_rows": int(entry.get("reranked_rows", entry.get("candidate_pool", 0))),
            "candidate_policy": str(entry.get("candidate_policy", "n/a")),
            "candidate_path_label": str(entry.get("candidate_path_label", "n/a")),
            "mismatches": len(entry.get("mismatches", []))
            if isinstance(entry.get("mismatches"), list)
            else 0,
        }
    return extracted


def recommend_policy(modes: dict[str, dict[str, float | int | str]]) -> tuple[str, str]:
    required = ("float32", "qtri", "qmag")
    for key in required:
        if key not in modes:
            return (
                "keep_float32_default",
                "Missing mode measurements; keep exact float32 default until all modes run.",
            )

    float32_recall = float(modes["float32"]["recall"])
    qtri_recall = float(modes["qtri"]["recall"])
    qmag_recall = float(modes["qmag"]["recall"])
    float32_mismatches = int(modes["float32"]["mismatches"])
    qtri_mismatches = int(modes["qtri"]["mismatches"])
    qmag_mismatches = int(modes["qmag"]["mismatches"])
    float32_mean_us = float(modes["float32"]["mean_us"])
    qtri_mean_us = float(modes["qtri"]["mean_us"])
    qmag_mean_us = float(modes["qmag"]["mean_us"])

    if float32_mismatches != 0:
        return (
            "investigate_float32_baseline",
            "Exact float32 baseline has mismatches; calibration evidence is invalid.",
        )

    if qmag_mismatches == 0 and qmag_recall >= 0.95:
        if qmag_recall >= float32_recall and qmag_recall >= qtri_recall:
            if float32_mean_us == 0.0 or qmag_mean_us <= float32_mean_us:
                return (
                    "prefer_qmag",
                    "qmag QIHSE dimension-mapped trinary+magnitude candidate scoring matched recall with zero mismatches and lower/equal mean latency after exact float32 rerank.",
                )
            return (
                "qmag_candidate_only",
                "qmag QIHSE dimension-mapped trinary+magnitude candidate scoring matched recall with zero mismatches after exact float32 rerank, but is slower than exact float32 on this workload.",
            )
    if qtri_mismatches == 0 and qtri_recall >= 0.95:
        if qtri_recall >= float32_recall and qtri_recall >= qmag_recall:
            if float32_mean_us == 0.0 or qtri_mean_us <= float32_mean_us:
                return (
                    "prefer_qtri",
                    "qtri matched recall with zero mismatches and lower/equal mean latency.",
                )
            return (
                "qtri_correctness_only",
                "qtri matched recall with zero mismatches but is not faster than exact float32.",
            )
    return (
        "keep_float32_default",
        "Keep float32 default; trinary recall, mismatch, or latency evidence is not strong enough.",
    )


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=".", help="QIHSE root")
    parser.add_argument("--result", required=True, help="Calibration result JSON path")
    parser.add_argument("--workload", default="sift1m", help="Workload name")
    args = parser.parse_args(argv)

    root = Path(args.root).resolve()
    result_path = Path(args.result)
    if not result_path.is_absolute():
        result_path = root / result_path

    try:
        result = load_json(result_path)
        workload = str(result.get("workload", args.workload))
        top_k = int(result.get("top_k", 0))
        active_dims = result.get("active_query_dims")
        modes = extract_modes(result)
        policy, reason = recommend_policy(modes)

        print(f"{workload}: candidate-policy recommendation -> {policy}")
        print(f"  reason: {reason}")
        print(f"  top_k={top_k} rows={result.get('rows')} queries={result.get('queries')}")
        if isinstance(active_dims, dict):
            print(
                f"  active_query_dims=min/{active_dims.get('min', 0)} "
                f"mean/{float(active_dims.get('mean', 0.0)):.1f} "
                f"max/{active_dims.get('max', 0)} "
                f"total_dims={active_dims.get('total_dims', result.get('dimensions'))}"
            )
        for name, payload in sorted(modes.items()):
            print(
                f"  {name}: recall={payload['recall']:.4f} "
                f"candidates={payload['candidate_pool']} "
                f"requested_pool={payload['requested_candidate_pool']} "
                f"effective_pool={payload['effective_candidate_pool']} "
                f"reranked={payload['reranked_rows']} "
                f"mean_us={payload['mean_us']:.3f} "
                f"candidate_policy={payload['candidate_policy']} "
                f"candidate_path={payload['candidate_path_label']} "
                f"mismatches={payload['mismatches']}"
            )

        output = root / "results" / workload / "calibration_decision.json"
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(
            json.dumps(
                {
                    "workload": workload,
                    "policy": policy,
                    "reason": reason,
                    "modes": modes,
                    "top_k": top_k,
                    "active_query_dims": active_dims if isinstance(active_dims, dict) else None,
                    "rows": int(result.get("rows", 0)),
                    "queries": int(result.get("queries", 0)),
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        print(f"wrote {output}")
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"calibration decision failed: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
