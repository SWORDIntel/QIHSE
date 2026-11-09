#!/usr/bin/env python3
"""Offline W12.6 shadow gate. It never changes a production query mode."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import statistics
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
PROBE = ROOT / "benchmarks/scripts/qihse_w12_shadow_probe.c"
EXECUTABLE = ROOT / "build/w12/qihse_w12_shadow_probe"
SOURCES = [
    "benchmarks/scripts/qihse_w12_shadow_probe.c",
    "benchmarks/scripts/qihse_w12_shadow_gate.py",
    "quantization/include/qihse_turboquant_sidecar.h",
    "quantization/src/qihse_turboquant_sidecar.c",
    "quantization/include/qihse_turboquant.h",
    "quantization/src/qihse_turboquant.c",
    "quantization/src/qihse_turboquant_tables.c",
]
THRESHOLDS = {
    "minimum_recall_at_1": 0.99,
    "minimum_throughput_ratio_at_equal_recall": 1.5,
    "minimum_index_bytes_reduction_vs_existing_index": 2.0,
    "maximum_p95_latency_ratio_for_bytes_path": 1.05,
}
EVIDENCE_GATES = {
    "real_authorized_corpus": False,
    "source_generation_transaction_fence": False,
    "production_adapter_and_exact_mode": False,
    "low_high_negative_in_ci_for_all_adapters": False,
    "crash_recovery_and_rollback_rehearsal": False,
    "isolated_repeatable_latency": False,
}


def percentile(values: list[int], fraction: float) -> int:
    if not values:
        raise ValueError("empty samples")
    ordered = sorted(values)
    from math import ceil
    return ordered[max(0, ceil(len(ordered) * fraction) - 1)]


def evaluate(metrics: dict, gates: dict[str, bool]) -> dict:
    """Pure policy check; eligibility does not enable or publish any route."""
    reasons = []
    if not metrics["rollback_exact_verified"]:
        reasons.append("derived_sidecar_rollback_failed")
    if metrics["recall_at_1"] < THRESHOLDS["minimum_recall_at_1"]:
        reasons.append("recall_below_threshold")
    throughput = (
        metrics["throughput_ratio_vs_exact"] >=
        THRESHOLDS["minimum_throughput_ratio_at_equal_recall"]
    )
    existing_index_baseline = metrics.get("existing_index_bytes")
    index_reduction = metrics.get("index_bytes_reduction_vs_existing")
    bytes_path = (
        existing_index_baseline is not None
        and index_reduction is not None
        and index_reduction >=
        THRESHOLDS["minimum_index_bytes_reduction_vs_existing_index"]
        and metrics["p95_latency_ratio_vs_exact"] <=
        THRESHOLDS["maximum_p95_latency_ratio_for_bytes_path"]
    )
    if existing_index_baseline is None and not throughput:
        reasons.append("missing_existing_index_baseline_for_bytes_path")
    if not (throughput or bytes_path):
        reasons.append("neither_throughput_nor_bytes_gate_met")
    reasons.extend(f"missing_{name}" for name, passed in gates.items() if not passed)
    return {
        "decision": "refuse" if reasons else "promote_eligible_for_human_review",
        "reasons": reasons,
        "deployment_changed": False,
    }


def parse_probe(text: str) -> dict:
    lines = text.strip().splitlines()
    if len(lines) != 3:
        raise ValueError("probe must emit exactly META, SIDE_NS, EXACT_NS")
    meta, side, exact = (line.split(",") for line in lines)
    if len(meta) != 6 or meta[0] != "META" or side[0] != "SIDE_NS" or exact[0] != "EXACT_NS":
        raise ValueError("unexpected probe schema")
    hits, queries, sidecar_bytes, fp32_bytes, rollback_queries = map(int, meta[1:])
    side_ns, exact_ns = [int(v) for v in side[1:]], [int(v) for v in exact[1:]]
    if queries != 3 or len(side_ns) != 15 or len(exact_ns) != 15:
        raise ValueError("unexpected sample count")
    if not (0 <= hits <= queries and sidecar_bytes > 0 and fp32_bytes > 0 and
            all(v > 0 for v in side_ns + exact_ns)):
        raise ValueError("invalid measurement")
    mean_side, mean_exact = statistics.mean(side_ns), statistics.mean(exact_ns)
    return {
        "queries": queries,
        "repeats": 5,
        "recall_hits": hits,
        "recall_at_1": hits / queries,
        "rollback_queries": rollback_queries,
        "rollback_exact_verified": rollback_queries == queries,
        "sidecar_bytes": sidecar_bytes,
        "authoritative_fp32_payload_bytes": fp32_bytes,
        "total_fp32_plus_sidecar_bytes": fp32_bytes + sidecar_bytes,
        "fp32_plus_sidecar_overhead_ratio": (fp32_bytes + sidecar_bytes) / fp32_bytes,
        "existing_index_bytes": None,
        "index_bytes_reduction_vs_existing": None,
        "sidecar_raw_ns": side_ns,
        "exact_raw_ns": exact_ns,
        "sidecar_p50_ns": percentile(side_ns, 0.50),
        "sidecar_p95_ns": percentile(side_ns, 0.95),
        "exact_p50_ns": percentile(exact_ns, 0.50),
        "exact_p95_ns": percentile(exact_ns, 0.95),
        "throughput_ratio_vs_exact": mean_exact / mean_side,
        "p95_latency_ratio_vs_exact":
            percentile(side_ns, 0.95) / percentile(exact_ns, 0.95),
    }


def compile_probe() -> dict:
    if not (ROOT / "libqihse.so").is_file():
        raise FileNotFoundError("Build this checkout's libqihse.so first")
    EXECUTABLE.parent.mkdir(parents=True, exist_ok=True)
    command = [
        os.environ.get("CC", "cc"), "-std=c99", "-O2", "-Wall", "-Wextra",
        "-Werror", "-pedantic", "-fno-fast-math", "-ffp-contract=off",
        "-fno-tree-vectorize", "-I.", "-Iinclude", "-Iquantization/include",
        str(PROBE.relative_to(ROOT)),
        "quantization/src/qihse_turboquant_sidecar.c",
        "quantization/src/qihse_turboquant.c",
        "quantization/src/qihse_turboquant_tables.c",
        "-L.", "-lqihse", "-lm",
        "-o", str(EXECUTABLE.relative_to(ROOT)),
    ]
    subprocess.run(command, cwd=ROOT, check=True)
    return {
        "command": command,
        "compiler": subprocess.check_output([command[0], "--version"],
                                             text=True).splitlines()[0],
        "source_sha256": {
            name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
            for name in SOURCES
        },
        "libqihse_sha256": hashlib.sha256((ROOT / "libqihse.so").read_bytes()).hexdigest(),
    }


def run(output: Path) -> dict:
    build = compile_probe()
    with tempfile.TemporaryDirectory(prefix="qihse_w12_shadow_") as directory:
        temp = Path(directory)
        auth = temp / "auth"
        auth.mkdir()
        auth.chmod(0o700)
        derived = temp / "vectors.qtq"
        absent = temp / "missing.qtq"
        env = dict(os.environ, QIHSE_DATA_DIR=str(auth), LD_LIBRARY_PATH=str(ROOT))
        process = subprocess.run([str(EXECUTABLE), str(derived), str(absent)],
                                 cwd=ROOT, env=env, capture_output=True, text=True)
        if process.returncode:
            raise RuntimeError(f"shadow probe exit {process.returncode}: {process.stderr[-2000:]}")
        if derived.exists():
            raise RuntimeError("rollback left derived sidecar in temporary fixture")
        metrics = parse_probe(process.stdout)
    try:
        commit = subprocess.check_output(["git", "rev-parse", "HEAD"],
                                         cwd=ROOT, text=True).strip()
        dirty = bool(subprocess.check_output(["git", "status", "--porcelain"],
                                             cwd=ROOT, text=True).strip())
    except subprocess.CalledProcessError:
        commit, dirty = None, None
    cpuinfo = Path("/proc/cpuinfo")
    cpu_flags = None
    if cpuinfo.exists():
        cpu_flags = next((line.partition(":")[2].strip().split()
                          for line in cpuinfo.read_text().splitlines()
                          if line.startswith("flags")), None)
    report = {
        "schema": "qihse-w12-shadow-offline-v1",
        "mode": "disabled",
        "fixture": {
            "kind": "synthetic_unclassified_plus_one_hidden_high_row",
            "rows": 3, "dimensions": 2, "queries": 3, "repeats": 5,
            "profile": "MSE_3bit_seed_0x1206",
            "scope": {"tenant_id": 42, "project_id": 7},
        },
        "thresholds_predeclared": THRESHOLDS,
        "evidence_gates": EVIDENCE_GATES,
        "metrics": metrics,
        "policy": evaluate(metrics, EVIDENCE_GATES),
        "build": build,
        "git_commit": commit,
        "git_dirty": dirty,
        "host": {
            "machine": platform.machine(),
            "platform": platform.platform(),
            "cpu_flags": cpu_flags,
            "allowed_cpu_set": sorted(os.sched_getaffinity(0))
            if hasattr(os, "sched_getaffinity") else None,
        },
        "limitations": [
            "This is a three-row synthetic fixture, not a real corpus.",
            "Timings include auth, file open, profile comparison and callback overhead.",
            "The standalone source has no transaction fence against concurrent writes.",
            "The QTQS sidecar is additional storage; FP32 authority stays resident.",
            "No production selector, shadow switch, or deployment was changed.",
        ],
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + "\n")
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path,
                        default=ROOT / "build/w12/shadow-offline-report.json")
    args = parser.parse_args()
    report = run(args.output)
    metrics = report["metrics"]
    print(f"{args.output}: {report['policy']['decision']}; "
          f"recall@1={metrics['recall_at_1']:.3f}, "
          f"sidecar p95={metrics['sidecar_p95_ns']/1e6:.3f} ms, "
          f"exact p95={metrics['exact_p95_ns']/1e6:.3f} ms, "
          f"bytes={metrics['total_fp32_plus_sidecar_bytes']}, "
          f"rollback={metrics['rollback_exact_verified']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
