#!/usr/bin/env python3
"""Measure W12.1 reference costs; inspect, but do not select, W12.4 routes."""

import argparse
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile


def run(command, *, timeout=300):
    return subprocess.run(command, check=True, capture_output=True, text=True,
                          timeout=timeout)


def cpu_info():
    info = {"architecture": platform.machine(), "logical_cpus": os.cpu_count()}
    if shutil.which("lscpu"):
        for line in run(["lscpu"]).stdout.splitlines():
            if ":" not in line:
                continue
            key, value = (part.strip() for part in line.split(":", 1))
            if key in ("Model name", "Architecture", "CPU(s)", "Socket(s)",
                       "Core(s) per socket", "Flags"):
                info[key] = value
    return info


def vulkan_info():
    binary = shutil.which("vulkaninfo")
    if not binary:
        return {"vulkaninfo_available": False, "devices": []}
    try:
        result = run([binary, "--summary"], timeout=15)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        return {"vulkaninfo_available": True, "probe_error": str(exc), "devices": []}
    devices = [line.strip() for line in result.stdout.splitlines()
               if "deviceName" in line or "deviceType" in line]
    info = {"vulkaninfo_available": True, "devices": devices}
    if shutil.which("nvidia-smi"):
        try:
            info["nvidia_memory"] = run(
                ["nvidia-smi", "--query-gpu=name,memory.total",
                 "--format=csv,noheader"], timeout=15).stdout.splitlines()
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            pass
    return info


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path,
                        default=Path(__file__).resolve().parents[2])
    parser.add_argument("--dimensions", type=int, nargs="+", default=[128, 384, 768])
    parser.add_argument("--cc", default=os.environ.get("CC", "cc"))
    args = parser.parse_args()
    root = args.source_root.resolve()
    sources = [root / "quantization/src/qihse_turboquant.c",
               root / "quantization/src/qihse_turboquant_tables.c"]
    header = root / "quantization/include/qihse_turboquant.h"
    driver = Path(__file__).with_suffix(".c")
    if any(not p.is_file() for p in [*sources, header, driver]):
        parser.error("W12.1 codec source/header missing at --source-root")
    if any(dim < 2 or dim > 1536 for dim in args.dimensions):
        parser.error("dimensions must be in 2..1536")

    compiler = run([args.cc, "--version"]).stdout.splitlines()[0]
    revision = run(["git", "-C", str(root), "rev-parse", "HEAD"]).stdout.strip()
    dirty = bool(run(["git", "-C", str(root), "status", "--porcelain",
                      "--", "quantization/src/qihse_turboquant.c",
                      "quantization/src/qihse_turboquant_tables.c",
                      "quantization/include/qihse_turboquant.h"]).stdout.strip())
    common = ["-std=c11", "-D_POSIX_C_SOURCE=200809L",
              "-I" + str(root / "quantization/include"), "-I" + str(root)]
    variants = {"scalar_no_autovec": ["-O2", "-fno-tree-vectorize"],
                "native_compiler": ["-O3", "-march=native"]}
    results = {}
    with tempfile.TemporaryDirectory(prefix="qihse-w12-simd-") as temporary:
        for name, flags in variants.items():
            binary = Path(temporary) / name
            run([args.cc, *common, *flags, str(driver), *(str(p) for p in sources),
                 "-lm", "-o", str(binary)], timeout=120)
            measurements = []
            for dim in args.dimensions:
                encode_reps = max(8, 20000 // dim)
                score_reps = max(128, 1000000 // dim)
                result = run([str(binary), str(dim), str(encode_reps),
                              str(score_reps)], timeout=600)
                measurements.append(json.loads(result.stdout))
            results[name] = {"compiler_flags": common[:2] + flags,
                             "measurements": measurements}
    print(json.dumps({"schema": "qihse-w12-simd-investigation-v1",
                      "scope": "standalone W12.1 reference, no production route",
                      "compiler": compiler, "source_revision": revision,
                      "codec_sources_dirty": dirty, "cpu": cpu_info(),
                      "vulkan": vulkan_info(), "variants": results}, indent=2))


if __name__ == "__main__":
    main()
