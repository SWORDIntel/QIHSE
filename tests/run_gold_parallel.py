"""Schedule independent gold workloads without changing their C oracle.

The original gold runner validates the complete pack first and executes each
selected workload from a private one-workload pack. This preserves its timeout,
output evidence, strictness and exit classification. Unapproved workloads are
serial and the aggregate verdict covers every declared workload.
"""

import argparse
import concurrent.futures
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tempfile
import time

from run_parallel_suite import ROOT, SAFE

PACK = Path(os.environ.get("GOLD_PACK", "tests/gold/pack.v1.gold"))
RUNNER = ROOT / "tests/gold/gold_runner"
# Offline workloads with separate binaries and private fixtures. Network,
# cluster, browser, and remote-dispatch probes remain serial by default.
GOLD_SAFE = frozenset({
    "gold-ann-rerank", "mvcc-committed-delete", "fusion-recall-gate",
    "repl-apply-wal", "protocol-compat-probe", "null-security-context",
    "index-bytes-nonvector", "backend-busy-time", "exact-search-parity",
    "graph-engine", "graph-vector-hybrid", "fts-vector-rrf",
    "resp-hybrid-fusion", "gold-persistence-roundtrip",
    "persistence-regression-suite", "kv-security-regression",
    "tenant-security-regression", "tenant-privilege-ladder",
    "sci-compartment-regression", "vector-tenant-isolation",
    "export-regression", "vector-skip-integrity", "blob-security-regression",
    "ingest-guard-regression", "bundle-security-regression",
    "killswitch-regression", "retention-regression", "metrics-regression",
    "blob-persistence-regression", "fabric-semantic-recall",
    "fabric-job-model", "fabric-memory-kind-filter", "telemetry-w52",
})


def read_pack(text):
    joined = re.sub(r"\\\n[ \t]*", " ", text)
    areas = {}
    workloads = []
    gaps = []
    for line in joined.splitlines():
        if line.startswith("area "):
            tokens = shlex.split(line)
            areas[tokens[1]] = line
        elif line.startswith("workload "):
            tokens = shlex.split(line)
            fields = dict(word.split("=", 1) for word in tokens[2:])
            if fields["area"] not in areas:
                raise ValueError(f"undeclared gold area: {fields['area']}")
            workloads.append((tokens[1], fields, line))
        elif line.startswith("gap "):
            gaps.append(line)
    if not areas or not workloads or len({w[0] for w in workloads}) != len(workloads):
        raise ValueError("missing or duplicate gold workload")
    return areas, workloads, gaps


def independent(workload):
    name, fields, _ = workload
    run = fields["run"]
    return (run.startswith("make -s ") and run[8:] in SAFE) or name in GOLD_SAFE


def run_one(workload, areas, workspace, version, pack_id):
    name, fields, line = workload
    pack_dir = workspace / name
    pack_dir.mkdir()
    pack = pack_dir / PACK.name
    pack.write_text(f"pack-version {version}\npack-id {pack_id}\n" +
                    areas[fields["area"]] + "\n" + line + "\n")
    log = pack_dir / "result.log"
    started = time.monotonic()
    env = os.environ.copy()
    env["LD_LIBRARY_PATH"] = "." + (":" + env["LD_LIBRARY_PATH"]
                                    if env.get("LD_LIBRARY_PATH") else "")
    with log.open("wb") as output:
        result = subprocess.run([str(RUNNER), str(pack.relative_to(ROOT))],
                                cwd=ROOT, env=env, stdout=output,
                                stderr=subprocess.STDOUT, check=False)
    return name, result.returncode, time.monotonic() - started, log


def report(result):
    name, status, seconds, log = result
    # A successful one-workload pack must say it actually ran one workload.
    data = log.read_bytes()
    if status == 0 and (b"WORKLOADS: 1 total" not in data or
                        b"1 pass, 0 known-bug, 0 known-fail, 0 failed" not in data):
        status = 1
    print(f"  [{'PASS' if status == 0 else 'FAIL'}] {name}: {seconds:.1f}s (exit {status})", flush=True)
    if status:
        sys.stdout.buffer.write(data[-65536:])
        if data and not data.endswith(b"\n"):
            print()
        sys.stdout.flush()
    return status != 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--jobs", type=int, default=16)
    args = parser.parse_args(argv)
    if not 1 <= args.jobs <= 32:
        parser.error("jobs must be between 1 and 32")
    if PACK.is_absolute() or ".." in PACK.parts or not (ROOT / PACK).is_file():
        parser.error("gold pack must be an existing relative path inside the repository")
    source = (ROOT / PACK).read_text()
    try:
        areas, workloads, gaps = read_pack(source)
    except (ValueError, KeyError, IndexError) as exc:
        parser.error(str(exc))
    preflight = subprocess.run([str(RUNNER), "--list", str(PACK)], cwd=ROOT,
                              capture_output=True, text=True, check=False)
    expected = re.search(r"(\d+) areas, (\d+) workloads, (\d+) declared coverage gaps",
                         preflight.stdout)
    if preflight.returncode or not expected or tuple(map(int, expected.groups())) != (
            len(areas), len(workloads), len(gaps)):
        print(preflight.stdout, preflight.stderr, file=sys.stderr)
        return 1
    version = re.search(r"^pack-version (\d+)$", source, re.MULTILINE)
    pack_id = re.search(r"^pack-id ([a-zA-Z0-9_-]+)$", source, re.MULTILINE)
    if not version or not pack_id:
        parser.error("missing gold pack identity")
    version, pack_id = int(version.group(1)), pack_id.group(1)
    if version != 1 or gaps or any(w[1]["expect"] != "pass" for w in workloads):
        # The full runner alone can classify known defects and coverage gaps.
        return subprocess.run([str(RUNNER), str(PACK)], cwd=ROOT, check=False).returncode
    fast = [w for w in workloads if independent(w)]
    slow = [w for w in workloads if not independent(w)]
    failures = []
    with tempfile.TemporaryDirectory(prefix="gold-parallel-", dir=ROOT / "build") as tmp:
        workspace = Path(tmp)
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
            tasks = [pool.submit(run_one, w, areas, workspace, version, pack_id) for w in fast]
            for task in concurrent.futures.as_completed(tasks):
                result = task.result()
                if report(result):
                    failures.append(result[0])
        for workload in slow:
            result = run_one(workload, areas, workspace, version, pack_id)
            if report(result):
                failures.append(result[0])
    print(f"GOLD: {len(areas)} areas, {len(workloads)} workloads, "
          f"{len(failures)} failed" + (f": {', '.join(failures)}" if failures else ""))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
