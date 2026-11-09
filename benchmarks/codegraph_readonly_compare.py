#!/usr/bin/env python3
"""Compare resident CodeGraph memory, then check refresh and authorization.

Only synthetic graph state under a temporary directory is accessed. Both binary
variants use the exact same immutable generation for every measurement pair.
"""

import argparse
import hashlib
import json
import os
import pathlib
import socket
import statistics
import subprocess
import sys
import tempfile
import time

from codegraph_p0_baseline import comparable, graph_fixture, invocation
from test_codegraph_native import git

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--baseline", type=pathlib.Path, required=True)
parser.add_argument("--candidate", type=pathlib.Path, required=True)
parser.add_argument("--baseline-source", type=pathlib.Path)
parser.add_argument("--candidate-source", type=pathlib.Path)
parser.add_argument("--patch", type=pathlib.Path)
parser.add_argument(
    "--library-dir",
    type=pathlib.Path,
    default=pathlib.Path(__file__).resolve().parents[1],
)
parser.add_argument("--nodes", type=int, default=16000)
parser.add_argument("--edges", type=int, default=48000)
parser.add_argument("--pairs", type=int, default=2)
parser.add_argument("--output", type=pathlib.Path)
args = parser.parse_args()
if not 1 <= args.pairs <= 5:
    parser.error("--pairs must be between 1 and 5")
binaries = {
    "before": args.baseline.resolve(strict=True),
    "after": args.candidate.resolve(strict=True),
}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


report = {
    "fixture": {"nodes": args.nodes, "edges": args.edges},
    "conditions": "Synthetic shared snapshot, same libqihse and compiler; current RSS after one context query, concurrent host workloads, page cache not dropped",
    "pairs": [],
}
report["binary_sha256"] = {name: sha(path) for name, path in binaries.items()}
report["source_sha256"] = {
    name: sha(path)
    for name, path in [
        ("before", args.baseline_source),
        ("after", args.candidate_source),
    ]
    if path
}
if args.patch:
    report["patch_sha256"] = sha(args.patch)
shared = args.library_dir / "libqihse.so"
if shared.is_file():
    report["shared_library_sha256"] = sha(shared)
report["measurement_order"] = (
    "All RSS pairs use the same immutable snapshot; refresh and authorization checks follow."
)
with tempfile.TemporaryDirectory(prefix="qcg-ro-bench-") as td:
    root = pathlib.Path(td)
    repo = root / "repo"
    repo.mkdir()
    git(repo, "init", "-q")
    src = root / "fixture.jsonl"
    graph_fixture(repo, src, args.nodes, args.edges)
    env = {
        **os.environ,
        "XDG_STATE_HOME": str(root / "state"),
        "LD_LIBRARY_PATH": str(args.library_dir.resolve())
        + os.pathsep
        + os.environ.get("LD_LIBRARY_PATH", ""),
    }
    pub, met = invocation(binaries["before"], env, repo, "import", "--input", str(src))
    report["import"] = met
    report["storage_format"] = pub["storage_format"]
    print("Imported synthetic fixture", file=sys.stderr, flush=True)
    cold = {}
    for name, bin in binaries.items():
        cold[name], metric = invocation(
            bin,
            env,
            repo,
            "context",
            "--symbol",
            "caller",
            "--depth",
            "1",
            "--limit",
            "256",
            "--max-tokens",
            "16000",
        )
        report["cold_" + name] = metric
    assert comparable(cold["before"]) == comparable(cold["after"])

    def running(name, iteration, check_refresh=False):
        sock = root / f"{name}{iteration}.sock"
        tokenfile = root / f"{name}{iteration}.token"
        with tempfile.TemporaryFile() as log:
            p = subprocess.Popen(
                [
                    str(binaries[name]),
                    "serve",
                    "--repo",
                    str(repo),
                    "--socket",
                    str(sock),
                    "--token-file",
                    str(tokenfile),
                    "--workers",
                    "1",
                    "--idle-seconds",
                    "60",
                ],
                env=env,
                stdout=log,
                stderr=log,
            )
            try:
                deadline = time.monotonic() + 120
                while not (sock.exists() and tokenfile.exists()):
                    if p.poll() is not None or time.monotonic() > deadline:
                        log.seek(0)
                        raise RuntimeError(log.read().decode())
                    time.sleep(0.05)
                token = tokenfile.read_text().strip()

                def req(**kw):
                    with socket.socket(socket.AF_UNIX) as s:
                        s.settimeout(30)
                        s.connect(str(sock))
                        s.sendall((json.dumps({"token": token, **kw}) + "\n").encode())
                        return json.loads(s.makefile("rb").readline())

                q = {
                    "command": "context",
                    "symbol": "caller",
                    "depth": 1,
                    "limit": 256,
                    "max_tokens": 16000,
                }
                response = req(**q)
                assert comparable(response) == comparable(cold[name])
                metrics = {}
                for line in (
                    pathlib.Path(f"/proc/{p.pid}/smaps_rollup").read_text().splitlines()
                ):
                    key, _, value = line.partition(":")
                    if key in ("Rss", "Pss", "Private_Clean", "Private_Dirty"):
                        metrics[key + "_KiB"] = int(value.split()[0])
                if check_refresh:
                    # A valid republish requires dropping and rebuilding the whole generation.
                    newformat = (
                        "zstd-v1"
                        if pub["storage_format"].endswith("packed-v2")
                        else "packed-v2"
                    )
                    migrated, _ = invocation(
                        binaries["before"],
                        env,
                        repo,
                        "migrate",
                        "--storage-format",
                        newformat,
                    )
                    assert migrated["status"] == "migrated", migrated
                    refreshed = req(**q)
                    assert (
                        refreshed["fresh"]
                        and refreshed["generation"] != response["generation"]
                    )
                    assert comparable(refreshed) == comparable(response)
                    manifest = (
                        root
                        / "state/qihse/codegraph"
                        / hashlib.sha256(os.fsencode(repo)).hexdigest()
                        / "current.json"
                    )
                    saved = manifest.read_bytes()
                    manifest.write_bytes(b"{broken")
                    denied = req(**q)
                    assert "error" in denied and not denied.get("nodes")
                    manifest.write_bytes(saved)
                    restored = req(**q)
                    assert restored["fresh"] and comparable(restored) == comparable(
                        response
                    )
                    oldtoken = token
                    assert req(command="revoke")["status"] == "revoked"
                    assert "error" in req(**q)
                    token = tokenfile.read_text().strip()
                    assert token != oldtoken and req(**q)["fresh"]
                    report["refresh_invalidation_and_revocation"] = "passed"
                return metrics
            finally:
                p.terminate()
                try:
                    p.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    p.kill()
                    p.wait()

    for iteration in range(args.pairs):
        pair = {}
        for name in ("before", "after") if iteration % 2 == 0 else ("after", "before"):
            pair[name] = running(name, iteration)
        report["pairs"].append(pair)
        print(json.dumps(pair), file=sys.stderr, flush=True)
    running("after", 99, check_refresh=True)
    report["median_rss_KiB"] = {
        n: statistics.median(x[n]["Rss_KiB"] for x in report["pairs"]) for n in binaries
    }
    report["cold_query_parity"] = True
if shared.is_file():
    assert sha(shared) == report["shared_library_sha256"], (
        "Shared library changed during measurement"
    )
if args.output:
    args.output.write_text(json.dumps(report, indent=2) + "\n")
print(json.dumps(report, indent=2), flush=True)
