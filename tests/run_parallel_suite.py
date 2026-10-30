"""Run the complete Makefile test suite with conservative, isolated parallel lanes.

Build the shared library and service binaries before invoking this script. Unknown
or resource-sharing targets remain serial; a new `test-serial:` prerequisite is never
silently omitted. The gold pack runs last because it invokes nested make targets.
"""

import argparse
import concurrent.futures
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
SAFE = frozenset({
    "test-aggregate-hardened", "test-bolt", "test-column-store",
    "test-dist-planner-hardware", "test-document-store", "test-fts-engine",
    "test-hnsw-anchor-seeding", "test-indexes", "test-mongo-wire-security",
    "test-mvcc-delete", "test-object-acl", "test-optimizer-governance",
    "test-parallel-query", "test-phase-c", "test-pgwire-service",
    "test-python-pg-sdk", "test-schema-recovery", "test-sql-completeness",
    "test-sql-dml-exec", "test-table-store-txn", "test-txn",
    "test-wal-durability", "test-kp14-artifact-contract",
    "test-federation-f0", "test-federation-f1", "test-federation-f2",
    "test-federation-f3", "test-federation-f4", "test-federation-f5",
    "test-federation-f6", "test-federation-f7", "test-federation-f8",
    "test-federation-f8-ops", "test-federation-fuzz",
    "test-consensus", "test-consensus-wire", "test-consensus-snapshot-stage",
    "test-consensus-channel", "test-consensus-blob-channel", "test-fed-sim",
    "test-incremental-export", "test-replica-security", "test-replica-qkp",
    "test-replica-crash", "test-ai-memory", "test-ai-memory-embed",
    "test-ai-memory-ext", "test-aimem-resp", "test-aimem-durable-crash",
    "test-aimem-replay-recovery", "test-aimem-qh05-08",
    "test-aimem-scope-index", "test-aimem-qh08", "test-aimem-qh08-resp",
    "test-fabric-jobs", "test-persist",
    "test-auth-durable", "test-auth-archive", "test-auth-maintenance",
})


def test_targets(text):
    text = re.sub(r"\\\n[ \t]*", " ", text)
    targets = []
    for line in text.splitlines():
        match = re.fullmatch(r"test-serial\s*:\s*([^#]*?)(?:\s*#.*)?", line)
        if match:
            targets.extend(match.group(1).split())
    if not targets or len(targets) != len(set(targets)):
        raise ValueError("test prerequisites missing or duplicated")
    if any(not re.fullmatch(r"test-[a-z0-9-]+", name) for name in targets):
        raise ValueError("unrecognized test prerequisite")
    return targets


def plan(targets):
    missing = SAFE.difference(targets)
    if missing:
        raise ValueError(f"parallel allowlist targets absent from test: {sorted(missing)}")
    parallel = [name for name in targets if name in SAFE]
    serial = [name for name in targets if name not in SAFE and name != "test-gold"]
    if "test-gold" in targets:
        serial.append("test-gold")
    if set(parallel).union(serial) != set(targets):
        raise ValueError("suite plan omitted a test target")
    return parallel, serial


def run_target(name, logs, jobs=16):
    started = time.monotonic()
    # Do not inherit a make jobserver without its file descriptors. Each child
    # compiles and runs one distinct target after the shared-library build fence.
    env = os.environ.copy()
    for key in ("MAKEFLAGS", "MFLAGS", "GNUMAKEFLAGS"):
        env.pop(key, None)
    path = logs / f"{name}.log"
    command = ([sys.executable, "tests/run_gold_parallel.py", "--jobs", str(jobs)]
               if name == "test-gold" else ["make", "--no-print-directory", "-s", name])
    with path.open("wb") as output:
        result = subprocess.run(command, cwd=ROOT, env=env, stdout=output,
                                stderr=subprocess.STDOUT, check=False)
    return name, result.returncode, time.monotonic() - started, path


def report(result):
    name, status, duration, path = result
    print(f"[{'PASS' if status == 0 else 'FAIL'}] {name}: {duration:.1f}s (exit {status})", flush=True)
    if status:
        data = path.read_bytes()[-65536:]
        sys.stdout.buffer.write(data)
        if data and not data.endswith(b"\n"):
            print()
        sys.stdout.flush()
    return status != 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--jobs", type=int, default=min(16, len(os.sched_getaffinity(0))
                                                       if hasattr(os, "sched_getaffinity")
                                                       else os.cpu_count() or 1))
    parser.add_argument("--list", action="store_true", help="show the complete test plan without running it")
    parser.add_argument("--parallel-only", action="store_true",
                        help="diagnostic run of the approved parallel lane only; not the full suite")
    args = parser.parse_args(argv)
    if not 1 <= args.jobs <= 32:
        parser.error("jobs must be between 1 and 32")
    try:
        parallel, serial = plan(test_targets((ROOT / "Makefile").read_text()))
    except ValueError as exc:
        parser.error(str(exc))
    if args.list:
        print("parallel:", " ".join(parallel))
        print("serial:", " ".join(serial))
        return 0
    if args.parallel_only:
        serial = []
        print("Diagnostic parallel lane only; not the full suite", flush=True)
    failed = []
    with tempfile.TemporaryDirectory(prefix="qihse-parallel-suite-") as scratch:
        logs = Path(scratch)
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
            futures = [pool.submit(run_target, name, logs) for name in parallel]
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if report(result):
                    failed.append(result[0])
        for name in serial:
            result = run_target(name, logs, args.jobs)
            if report(result):
                failed.append(name)
    print(f"Suite: {len(parallel) + len(serial)} targets, "
          f"{len(failed)} failed" + (f": {', '.join(failed)}" if failed else ""))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
