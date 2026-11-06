#!/usr/bin/env python3
"""Measure current CodeGraph storage and exact queries on a synthetic repository.

The graph is generated as validated JSONL and the legacy snapshot is written by
the authenticated QIHSE SDK fixture. No configured/live CodeGraph state is read.
Results are JSON; all measured graph state lives under a temporary directory.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import resource
import socket
import subprocess
import sys
import tempfile
import threading
import time

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / "tests"))
from test_codegraph_native import git, node_id, worktree_digest  # noqa: E402
from test_codegraph_storage import LEGACY_WRITER  # noqa: E402


def graph_fixture(repo: Path, output: Path, nodes: int, edges: int) -> None:
    if not 8 <= nodes <= 100_000 or not 4 <= edges <= 200_000:
        raise ValueError("fixture limits: 8..100000 nodes and 4..200000 edges")
    paths = [
        f"src/very_long_component_name_{i:02d}/nested_package_with_repeated_"
        f"segments_for_dictionary_measurement_{i % 4:02d}/module_{i:02d}.c"
        for i in range(12)
    ]
    for path in paths:
        source = repo / path
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_text(f"int source_{paths.index(path)}(void) {{ return 1; }}\n")
    test_path = "tests/test_target.c"
    (repo / "tests").mkdir()
    (repo / test_path).write_text("void test_target(void) {}\n")
    git(repo, "add", ".")
    git(repo, "-c", "user.name=CodeGraphBenchmark", "-c",
        "user.email=benchmark@example.invalid", "commit", "-qm", "fixture")
    head = git(repo, "rev-parse", "HEAD").strip().decode()
    selected = ("--", ".", ":(exclude).code-review-graph")
    status = git(repo, "status", "--porcelain=v1", "-z", "--untracked-files=normal", *selected)
    diff = git(repo, "diff", "--no-ext-diff", "--no-textconv", "--binary", "HEAD", *selected)
    header = {
        "t": "h", "format": "qihse-codegraph-v1", "version": 1,
        "head": head, "worktree": hashlib.sha256(status + b"\0" + diff).hexdigest(),
        "freshness": "git-status-diff-index-untracked-v2",
        "worktree_v2": worktree_digest(repo),
    }
    ids = [node_id(f"benchmark-node-{i}") for i in range(nodes)]
    digest = hashlib.sha256()
    unresolved = 0
    with output.open("wb") as stream:
        def write(row: dict, *, final: bool = False) -> None:
            raw = (json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n").encode()
            if len(raw) > 262_144:
                raise ValueError("oversized fixture record")
            stream.write(raw)
            if not final:
                digest.update(raw)

        write(header)
        for i, identity in enumerate(ids):
            path = test_path if i == 3 else paths[i % len(paths)]
            name = ("caller", "target", "common", "test_target", "common")[i] if i < 5 else f"symbol_{i:06d}"
            write({
                "t": "n", "id": identity, "file": path,
                "kind": "Test" if i == 3 else "Function", "name": name,
                "line_start": i + 1, "line_end": i + 2, "language": "c",
                "is_test": i == 3, "file_hash": "",
                "opaque_extension": {"signature": "void(void)", "ordinal": i},
            })
        for i in range(edges):
            if i == 0:
                source, target, direct = 0, 1, True
            elif i == 1:
                source, target, direct = 3, 1, True
            elif i < min(nodes, 192):
                source, target, direct = 0, i, True
            else:
                source = (i * 17 + 5) % nodes
                target = (i * 29 + 11) % nodes
                direct = i % 11 != 0
            unresolved += not direct
            write({
                "t": "e", "id": node_id(f"benchmark-edge-{i}"),
                "source": ids[source], "target": ids[target] if direct else "",
                "relation": "CALLS" if i % 7 else "REFERENCES",
                "file": test_path if source == 3 else paths[source % len(paths)],
                "line": i + 1, "confidence": 1.0 if direct else 0.4,
                "tier": "EXTRACTED" if direct else "INFERRED",
                "resolution": "direct" if direct else "unresolved",
                "traversable": direct,
                "opaque_extension": {"extractor": "synthetic", "ordinal": i},
            })
        write({"t": "end", "nodes": nodes, "edges": edges,
               "unresolved_edges": unresolved, "sha256": digest.hexdigest()}, final=True)


def invocation(binary: Path, env: dict[str, str], repo: Path, *args: str,
               expect: int = 0) -> tuple[dict, dict]:
    """Capture one process's wall time, RSS and observed logical write bytes."""
    command = [str(binary), *args, "--repo", str(repo)]
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        started = time.perf_counter()
        process = subprocess.Popen(command, env=env, stdout=out, stderr=err)
        observed_wchar = [0]
        stop = threading.Event()

        def observe() -> None:
            while not stop.is_set():
                try:
                    for row in Path(f"/proc/{process.pid}/io").read_text().splitlines():
                        if row.startswith("wchar:"):
                            observed_wchar[0] = max(observed_wchar[0], int(row.split()[1]))
                            break
                except (FileNotFoundError, PermissionError):
                    break
                stop.wait(0.005)

        observer = threading.Thread(target=observe, daemon=True)
        observer.start()
        timeout = threading.Timer(120, process.kill)
        timeout.start()
        try:
            _, wait_status, usage = os.wait4(process.pid, 0)
            process.returncode = os.waitstatus_to_exitcode(wait_status)
        except BaseException:
            if process.returncode is None:
                process.kill()
                process.wait()
            raise
        finally:
            timeout.cancel()
            stop.set()
            observer.join(timeout=1)
        elapsed = (time.perf_counter() - started) * 1000
        out.seek(0)
        err.seek(0)
        stdout, stderr = out.read().decode(), err.read().decode()
    if process.returncode != expect:
        raise RuntimeError(f"{args[0]} exited {process.returncode}: {stdout} {stderr}")
    result = json.loads(stdout)
    metrics = {
        "wall_ms": round(elapsed, 3), "cpu_ms": round((usage.ru_utime + usage.ru_stime) * 1000, 3),
        "peak_rss_kib": usage.ru_maxrss,
        "filesystem_output_blocks": usage.ru_oublock,
        "observed_wchar_lower_bound": observed_wchar[0],
    }
    return result, metrics


def file_metadata(path: Path) -> dict:
    info = path.stat()
    return {"apparent_bytes": info.st_size, "allocated_bytes": info.st_blocks * 512}


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(1 << 20):
            digest.update(block)
    return digest.hexdigest()


def host_cpu() -> str:
    try:
        for row in Path("/proc/cpuinfo").read_text().splitlines():
            if row.startswith("model name"):
                return row.partition(":")[2].strip()
    except OSError:
        pass
    return platform.processor() or "unknown"


def jsonl_field_sizes(source: Path) -> dict[str, int]:
    """Account for serialized JSONL fields, not physical KV sections."""
    groups = {
        "ids": {"id", "source", "target"},
        "paths": {"file"},
        "names": {"name", "kind", "language"},
        "relation_and_evidence": {"relation", "tier", "resolution", "confidence",
                                  "traversable", "line", "line_start", "line_end", "is_test"},
    }
    sizes = {key: 0 for key in (*groups, "other_values", "field_keys", "json_punctuation")}
    with source.open("rb") as stream:
        for raw in stream:
            row = json.loads(raw)
            used = 0
            for key, value in row.items():
                key_bytes = len(json.dumps(key).encode())
                value_bytes = len(json.dumps(value, sort_keys=True, separators=(",", ":")).encode())
                sizes["field_keys"] += key_bytes
                used += key_bytes + value_bytes
                category = next((group for group, fields in groups.items() if key in fields),
                                "other_values")
                sizes[category] += value_bytes
            sizes["json_punctuation"] += len(raw) - used
    if sum(sizes.values()) != source.stat().st_size:
        raise AssertionError("JSONL category accounting did not sum to input bytes")
    return sizes


def comparable(result: dict) -> dict:
    return {key: value for key, value in result.items()
            if key not in ("generation", "timings", "timing_us")}


def legacy_writer(binary: Path, root: Path, source: Path, output: Path, env: dict[str, str]) -> None:
    code = root / "legacy_writer.c"
    helper = root / "legacy_writer"
    code.write_text(LEGACY_WRITER)
    flags = subprocess.check_output(["pkg-config", "--cflags", "--libs", "json-c"], text=True).split()
    subprocess.run([os.environ.get("CC", "cc"), "-std=c11", "-I" + str(PROJECT / "include"),
                    str(code), "-L" + str(binary.parent), "-lqihse", *flags, "-o", str(helper)],
                   check=True, capture_output=True)
    helper_data = root / "legacy-writer-state"
    helper_data.mkdir(mode=0o700)
    process = subprocess.run([str(helper), str(source), str(output)],
                             env={**env, "QIHSE_DATA_DIR": str(helper_data)},
                             capture_output=True, timeout=120)
    if process.returncode:
        raise RuntimeError(f"authenticated legacy writer failed: {process.stderr.decode()}")


def resident_queries(binary: Path, repo: Path, env: dict[str, str], root: Path,
                     cases: dict[str, tuple[str, ...]], references: dict[str, dict],
                     repeats: int) -> dict[str, list[float]]:
    """Measure first and repeated requests on an authenticated resident reader."""
    sock = root / "reader.sock"
    token_path = root / "reader.token"
    logs = tempfile.TemporaryFile()
    process = subprocess.Popen(
        [str(binary), "serve", "--repo", str(repo), "--socket", str(sock),
         "--token-file", str(token_path), "--workers", "1", "--idle-seconds", "60"],
        env=env, stdout=logs, stderr=logs, start_new_session=True)
    try:
        deadline = time.monotonic() + 60
        while not (sock.exists() and token_path.exists()):
            if process.poll() is not None or time.monotonic() > deadline:
                logs.seek(0)
                raise RuntimeError("resident reader did not start: " + logs.read().decode(errors="replace"))
            time.sleep(0.02)
        token = token_path.read_text().strip()
        if len(token) != 64:
            raise AssertionError("resident reader capability token missing")
        measurements = {}
        for case, command in cases.items():
            action = command[0]
            symbol = command[command.index("--symbol") + 1]
            request = {"token": token, "command": action, "symbol": symbol,
                       "match": "exact" if "--match" in command else "auto",
                       "depth": int(command[command.index("--depth") + 1]) if "--depth" in command else 2,
                       "limit": int(command[command.index("--limit") + 1]) if "--limit" in command else 80,
                       "max_tokens": int(command[command.index("--max-tokens") + 1])
                       if "--max-tokens" in command else 4000}
            samples = []
            for _ in range(repeats + 1):
                started = time.perf_counter()
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as peer:
                    peer.settimeout(30)
                    peer.connect(str(sock))
                    peer.sendall((json.dumps(request) + "\n").encode())
                    with peer.makefile("rb") as stream:
                        response = json.loads(stream.readline())
                samples.append(round((time.perf_counter() - started) * 1000, 3))
                if comparable(response) != references[case]:
                    raise AssertionError(f"resident query mismatch: {case}")
            measurements[case] = samples
        return measurements
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        logs.close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=PROJECT / "qihse-codegraph")
    parser.add_argument("--nodes", type=int, default=800)
    parser.add_argument("--edges", type=int, default=2400)
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--output", type=Path, help="Keep the JSON receipt at this path")
    args = parser.parse_args()
    if not 1 <= args.repeats <= 20:
        parser.error("--repeats must be 1..20")
    binary = args.binary.resolve(strict=True)
    if not os.access(binary, os.X_OK):
        parser.error("CodeGraph binary is not executable")
    with tempfile.TemporaryDirectory(prefix="qihse-codegraph-p0-") as temporary:
        root = Path(temporary)
        repo = root / "repo"
        repo.mkdir()
        git(repo, "init", "-q")
        source = root / "source.jsonl"
        graph_fixture(repo, source, args.nodes, args.edges)
        common = {**os.environ, "HOME": str(root),
                  "LD_LIBRARY_PATH": str(binary.parent) + os.pathsep + os.environ.get("LD_LIBRARY_PATH", "")}
        compact_env = {**common, "XDG_STATE_HOME": str(root / "compact-state")}
        legacy_env = {**common, "XDG_STATE_HOME": str(root / "legacy-state")}
        imported, import_metrics = invocation(binary, compact_env, repo, "import", "--input", str(source))
        assert imported["status"] == "published"
        repo_hash = hashlib.sha256(str(repo).encode()).hexdigest()
        compact_dir = root / "compact-state/qihse/codegraph" / repo_hash
        compact_manifest = json.loads((compact_dir / "current.json").read_text())
        compact_file = compact_dir / compact_manifest["snapshot"]
        legacy_dir = root / "legacy-state/qihse/codegraph" / repo_hash
        legacy_dir.mkdir(parents=True, mode=0o700)
        legacy_file = legacy_dir / f"graph-{compact_manifest['input_sha256']}-2777935.kv"
        legacy_writer(binary, root, source, legacy_file, legacy_env)
        legacy_manifest = {key: value for key, value in compact_manifest.items()
                           if key not in ("storage_format", "previous_snapshot")}
        legacy_manifest.update(snapshot=legacy_file.name,
                               sha256=file_sha256(legacy_file))
        (legacy_dir / "current.json").write_text(json.dumps(legacy_manifest))
        for label, env in (("compact", compact_env), ("legacy", legacy_env)):
            status, _ = invocation(binary, env, repo, "status")
            assert status["fresh"] is True, (label, status)
        cases = {
            "same_name_different_files": ("query", "--symbol", "common", "--match", "exact", "--limit", "256"),
            "high_degree_caller": ("context", "--symbol", "caller", "--depth", "1", "--limit", "256", "--max-tokens", "16000"),
            "target_impact": ("impact", "--symbol", "target", "--depth", "1", "--limit", "256", "--max-tokens", "16000"),
            "missing_symbol": ("query", "--symbol", "not_present", "--match", "exact"),
        }
        raw: dict[str, dict[str, list[dict]]] = {case: {label: [] for label in ("compact", "legacy")}
                                                 for case in cases}
        expected: dict[str, dict] = {}
        for case, command in cases.items():
            for attempt in range(args.repeats):
                variants = (("compact", compact_env), ("legacy", legacy_env))
                if attempt % 2:
                    variants = tuple(reversed(variants))
                for label, env in variants:
                    result, metrics = invocation(binary, env, repo, *command, "--timings",
                                                 expect=2 if case == "missing_symbol" else 0)
                    reference = expected.setdefault(case, comparable(result))
                    if comparable(result) != reference:
                        raise AssertionError(f"query mismatch: {case}, {label}, attempt {attempt}")
                    if "timings" in result:
                        metrics["native_timings_ms"] = result["timings"]
                    raw[case][label].append(metrics)
        same = expected["same_name_different_files"]
        if same.get("seed_nodes") != 2:
            raise AssertionError(f"shared-name fixture did not produce two matches: {same}")
        identities = {key: node_id(f"benchmark-node-{key}") for key in (0, 1, 2, 3, 4)}
        same_ids = {node.get("id") for node in same.get("nodes", [])}
        if not {identities[2], identities[4]} <= same_ids:
            raise AssertionError("same-name query lost one of the separate symbols")
        if expected["high_degree_caller"].get("seed_nodes") != 1:
            raise AssertionError("high-degree caller fixture was not selected exactly")
        if args.nodes >= 192 and args.edges >= 192 and expected["high_degree_caller"].get("truncated") is not True:
            raise AssertionError("high-degree case did not exercise bounded-output truncation")
        # Context intentionally omits stable IDs from its concise node rows;
        # this case verifies the caller seed and at least one shown neighbor.
        caller_symbols = {node.get("symbol") for node in expected["high_degree_caller"].get("nodes", [])}
        if "caller" not in caller_symbols or len(caller_symbols) < 2:
            raise AssertionError("caller context did not expose the seed and neighbors")
        impact_ids = {node.get("id") for node in expected["target_impact"].get("nodes", [])}
        if not {identities[0], identities[1], identities[3]} <= impact_ids:
            raise AssertionError("target impact lost the caller or direct test")
        resident = {
            "compact": resident_queries(binary, repo, compact_env, root / "compact-state",
                                        cases, expected, args.repeats),
            "legacy": resident_queries(binary, repo, legacy_env, root / "legacy-state",
                                       cases, expected, args.repeats),
        }
        report = {
            "scope": "synthetic CodeGraph only; no live data accessed",
            "binary_name": binary.name,
            "binary_sha256": file_sha256(binary),
            "benchmark_script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "platform": platform.platform(), "python": platform.python_version(),
            "cpu_model": host_cpu(), "logical_cpus": os.cpu_count(),
            "fixture": {"nodes": args.nodes, "edges": args.edges,
                        "input_jsonl": file_metadata(source), "seed": "deterministic-arithmetic-v1",
                        "input_jsonl_field_value_bytes": jsonl_field_sizes(source),
                        "long_paths": True, "duplicate_symbol_names": True,
                        "high_degree": min(args.nodes, 192) - 1, "unresolved_edges": args.edges - sum(
                            1 for i in range(args.edges) if i < min(args.nodes, 192) or i % 11 != 0)},
            "storage": {"legacy_authenticated_kv": file_metadata(legacy_file),
                        "current_zstd_level9": file_metadata(compact_file)},
            "import_compact": import_metrics,
            "queries": raw,
            "resident_queries_wall_ms": resident,
            "comparisons": {case: {"seed_nodes": value.get("seed_nodes"),
                                   "shown_nodes": value.get("shown_nodes"),
                                   "truncated": value.get("truncated"),
                                   "unresolved_edges": value.get("unresolved_edges")}
                            for case, value in expected.items()},
            "ground_truth": {"caller_id": identities[0], "target_id": identities[1],
                             "same_name_ids": [identities[2], identities[4]],
                             "test_id": identities[3],
                             "direct_caller_edge_id": node_id("benchmark-edge-0"),
                             "direct_test_edge_id": node_id("benchmark-edge-1")},
            "methodology": {
                "repeats": args.repeats,
                "order": "compact/legacy alternated by paired attempt; first process may have cold OS cache",
                "query_process": "fresh process for every query; not a resident reader benchmark",
                "resident": "first sample then repeated same-process authenticated socket requests",
                "cache": "OS page cache retained; no cold-cache claim",
                "field_breakdown": "serialized JSONL value/key bytes before KV serialization and Zstandard, not actual on-disk sections",
                "contention": os.environ.get("CODEGRAPH_BENCH_CONTENTION", "not controlled or recorded"),
                "peak_rss": "Linux per-process wait4 ru_maxrss in KiB",
                "writes": "observed /proc/PID/io wchar sampled every 5ms is a lower bound, includes stdout/stderr; ru_oublock is reported separately",
                "allocated": "st_blocks * 512 on temporary filesystem, not reclaimed-space measurement",
                "git_source": "clean temporary repository, committed synthetic files; source identity verified by native CLI",
            },
        }
        encoded = json.dumps(report, indent=2, sort_keys=True) + "\n"
        if args.output:
            args.output.write_text(encoded)
        print(encoded, end="")


if __name__ == "__main__":
    main()
