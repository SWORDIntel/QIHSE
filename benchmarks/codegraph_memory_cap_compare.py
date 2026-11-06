#!/usr/bin/env python3
"""Paired CodeGraph reader comparison using the authenticated CLI only.

The script never opens CodeGraph storage. Its process counters come from wait4
and, when --proc-root is supplied, the CLI process's procfs I/O counters.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import platform
import resource
import signal
import statistics
import subprocess
import tempfile
import time


def io_counters(proc_root: Path | None, pid: int) -> dict[str, int]:
    if proc_root is None:
        return {}
    try:
        values = {}
        for line in (proc_root / str(pid) / "io").read_text().splitlines():
            key, value = line.split(":", 1)
            if key in {"wchar", "write_bytes", "cancelled_write_bytes"}:
                values[key] = int(value)
        return values
    except (OSError, ValueError):
        return {}


def run(binary: Path, repo: Path, libdir: Path, arguments: list[str],
        proc_root: Path | None, timeout: float) -> dict:
    env = os.environ.copy()
    env["LD_LIBRARY_PATH"] = str(libdir) + os.pathsep + env.get("LD_LIBRARY_PATH", "")
    command = [str(binary), *arguments, "--repo", str(repo)]
    started = time.perf_counter()
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        process = subprocess.Popen(command, env=env, stdout=stdout, stderr=stderr,
                                   start_new_session=True)
        observed_io: dict[str, int] = {}
        try:
            while True:
                sample = io_counters(proc_root, process.pid)
                for key, value in sample.items():
                    observed_io[key] = max(observed_io.get(key, 0), value)
                pid, status, usage = os.wait4(process.pid, os.WNOHANG)
                if pid:
                    process.returncode = os.waitstatus_to_exitcode(status)
                    break
                if time.perf_counter() - started > timeout:
                    raise TimeoutError(f"CodeGraph CLI exceeded {timeout}s")
                time.sleep(0.02)
        except BaseException:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
            raise
        wall_ms = (time.perf_counter() - started) * 1000
        stdout.seek(0)
        stderr.seek(0)
        output = stdout.read(4 * 1024 * 1024 + 1)
        errors = stderr.read(8192)
        if len(output) > 4 * 1024 * 1024 or process.returncode:
            raise RuntimeError(f"CLI exit {process.returncode}; stderr={errors.decode(errors='replace')!r}")
        return {
            "result": json.loads(output),
            "wall_ms": wall_ms,
            "peak_rss_kib": usage.ru_maxrss,
            "output_blocks_512b": usage.ru_oublock,
            "sampled_process_io": observed_io,
        }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--library-dir", type=Path, required=True)
    parser.add_argument("--proc-root", type=Path,
                        help="Optional procfs mount for sampled process I/O counters")
    parser.add_argument("--symbol", default="main")
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--timeout", type=float, default=180.0)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.repeats < 2 or args.timeout <= 0:
        parser.error("--repeats must be >=2 and --timeout must be positive")
    binaries = {"baseline_100000": args.baseline.resolve(strict=True),
                "candidate_150000": args.candidate.resolve(strict=True)}
    repo = args.repo.resolve(strict=True)
    libdir = args.library_dir.resolve(strict=True)
    proc_root = args.proc_root.resolve(strict=True) if args.proc_root else None
    cases = {"status": ["status"], "query": ["query", "--symbol", args.symbol,
                                               "--limit", "20"]}
    runs: dict[str, list[dict]] = {name: [] for name in cases}
    # Alternate order in every pair to reduce drift from cache and background load.
    for case, command in cases.items():
        expected = None
        for name in binaries:
            warm = run(binaries[name], repo, libdir, command, proc_root, args.timeout)
            if expected is None:
                expected = warm["result"]
            elif warm["result"] != expected:
                raise AssertionError(f"{case} JSON differs during warmup for {name}")
        for pair in range(args.repeats):
            order = list(binaries)
            if pair % 2:
                order.reverse()
            for name in order:
                result = run(binaries[name], repo, libdir, command, proc_root, args.timeout)
                if expected is None:
                    expected = result["result"]
                elif result["result"] != expected:
                    raise AssertionError(f"{case} JSON differs for {name} pair {pair}")
                result.pop("result")
                runs[case].append({"variant": name, "pair": pair, **result})
                print(f"{case} pair {pair + 1}/{args.repeats} {name}: "
                      f"{result['wall_ms']:.1f}ms RSS={result['peak_rss_kib']}KiB",
                      flush=True)
    medians = {}
    for case, items in runs.items():
        medians[case] = {}
        for name in binaries:
            selected = [item for item in items if item["variant"] == name]
            medians[case][name] = {
                key: statistics.median(item[key] for item in selected)
                for key in ("wall_ms", "peak_rss_kib", "output_blocks_512b")
            }
    receipt = {
        "purpose": "100000 vs 150000 record cap with unchanged 64MiB decoded cap",
        "repo": str(repo),
        "binaries": {key: str(value) for key, value in binaries.items()},
        "platform": platform.platform(),
        "cpu_count": os.cpu_count(),
        "repeats": args.repeats,
        "symbol": args.symbol,
        "exact_json_equal": True,
        "warm_cache_method": "one untimed run per binary and case, then paired alternating CLI processes; no cache drop",
        "rss_source": "wait4 ru_maxrss; process only",
        "io_source": "wait4 ru_oublock (512-byte output blocks); optional procfs counters sampled every 20ms",
        "io_limit": "sampled procfs values can miss final writes and exclude child processes",
        "medians": medians,
        "runs": runs,
    }
    payload = json.dumps(receipt, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(payload)
    else:
        print(payload)


if __name__ == "__main__":
    main()
