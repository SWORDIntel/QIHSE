#!/usr/bin/env python3
"""Repeat the persisted-projection component fixture; not an end-to-end CLI benchmark."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import statistics
import subprocess
import tempfile


def sha(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(65536):
            digest.update(chunk)
    return digest.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--nodes", type=int, default=8000)
    parser.add_argument("--samples", type=int, default=3)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not 1 <= args.nodes <= 100000 or not 1 <= args.samples <= 20:
        parser.error("nodes must be 1..100000 and samples 1..20")
    rows = []
    with tempfile.TemporaryDirectory(prefix="codegraph-persisted-benchmark-") as temp:
        env = dict(os.environ, TMPDIR=temp)
        for _ in range(args.samples):
            result = subprocess.run([str(args.binary.resolve()), str(args.nodes)],
                                    env=env, text=True, capture_output=True,
                                    timeout=300, check=True)
            candidates = [json.loads(line) for line in result.stdout.splitlines()
                          if line.startswith('{"nodes":')]
            if len(candidates) != 1:
                raise RuntimeError("fixture did not emit exactly one measurement")
            rows.append(candidates[0])
    numeric = [key for key, value in rows[0].items()
               if isinstance(value, (float, int))]
    project = Path(__file__).resolve().parent.parent
    cpuinfo = Path("/proc/cpuinfo")
    cpu_model = next((line.split(":", 1)[1].strip() for line in cpuinfo.read_text().splitlines()
                      if line.startswith("model name")), "unknown") if cpuinfo.exists() else "unknown"
    report = {"cpu_model": cpu_model, "binary_sha256": sha(args.binary),
              "source_sha256": {str(path.relative_to(project)): sha(path)
                                for path in [project / "tools/qihse_codegraph_csr.c",
                                             project / "tools/qihse_codegraph_projection.c",
                                             project / "tests/test_codegraph_persisted.c"]},
              "library_sha256": sha(project / "libqihse.so"),
              "kind": "component diagnostic; no cache drops; shared runtime uninstrumented",
              "platform": platform.platform(), "samples": rows,
              "medians": {key: statistics.median(row[key] for row in rows)
                          for key in numeric},
              "limits": ["CSR construction excludes canonical snapshot/KV/JSON loading",
                         "baseline_csr_bytes excludes CLI nodes/search arrays",
                         "owned-byte accounting excludes allocator overhead and engine globals",
                         "sidecar bytes add to, rather than replace, canonical snapshot bytes",
                         "root integration must measure cold/warm CLI latency and RSS"]}
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report["medians"], sort_keys=True))


if __name__ == "__main__":
    main()
