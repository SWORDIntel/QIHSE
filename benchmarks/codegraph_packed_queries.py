#!/usr/bin/env python3
"""Check exact native CodeGraph query parity across all three snapshot formats."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import tempfile

from codegraph_p0_baseline import (comparable, file_sha256, graph_fixture,
                                   invocation, legacy_writer, node_id)
from test_codegraph_native import git


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--nodes", type=int, default=800)
    parser.add_argument("--edges", type=int, default=2400)
    parser.add_argument("--packed-via-migrate", action="store_true",
                        help="Import Zstd first, then validate packed migration path")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix="qihse-codegraph-packed-queries-") as temporary:
        root = Path(temporary)
        repo = root / "repo"
        repo.mkdir()
        git(repo, "init", "-q")
        source = root / "source.jsonl"
        author_date = os.environ.get("GIT_AUTHOR_DATE")
        committer_date = os.environ.get("GIT_COMMITTER_DATE")
        os.environ["GIT_AUTHOR_DATE"] = os.environ["GIT_COMMITTER_DATE"] = "2024-01-01T00:00:00+00:00"
        try:
            graph_fixture(repo, source, args.nodes, args.edges)
        finally:
            for key, old in (("GIT_AUTHOR_DATE", author_date),
                             ("GIT_COMMITTER_DATE", committer_date)):
                if old is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = old
        common = {**os.environ, "HOME": str(root),
                  "LD_LIBRARY_PATH": str(binary.parent) + os.pathsep + os.environ.get("LD_LIBRARY_PATH", "")}
        environments = {backend: {**common, "XDG_STATE_HOME": str(root / (backend + "-state"))}
                        for backend in ("legacy", "zstd", "packed")}
        manifests = {}
        snapshots = {}
        repo_hash = hashlib.sha256(str(repo).encode()).hexdigest()
        for backend in ("zstd", "packed"):
            imported, _ = invocation(binary, environments[backend], repo,
                                     "import", "--input", str(source),
                                     "--storage-format", "zstd-v1" if
                                     backend == "zstd" or args.packed_via_migrate else "packed-v2")
            if imported.get("status") != "published":
                raise AssertionError((backend, imported))
            if backend == "packed" and args.packed_via_migrate:
                migrated, _ = invocation(binary, environments[backend], repo,
                                         "migrate", "--storage-format", "packed-v2")
                if migrated.get("status") != "migrated":
                    raise AssertionError((backend, migrated))
            directory = root / (backend + "-state") / "qihse/codegraph" / repo_hash
            manifest = json.loads((directory / "current.json").read_text())
            snapshot = directory / manifest["snapshot"]
            manifests[backend] = manifest
            snapshots[backend] = snapshot.stat().st_size
        legacy_dir = root / "legacy-state/qihse/codegraph" / repo_hash
        legacy_dir.mkdir(parents=True, mode=0o700)
        legacy_file = legacy_dir / "graph-legacy.kv"
        legacy_writer(binary, root, source, legacy_file, environments["legacy"])
        legacy_manifest = {key: value for key, value in manifests["zstd"].items()
                           if key not in ("storage_format", "previous_snapshot")}
        legacy_manifest.update(snapshot=legacy_file.name, sha256=file_sha256(legacy_file))
        (legacy_dir / "current.json").write_text(json.dumps(legacy_manifest))
        snapshots["legacy"] = legacy_file.stat().st_size
        for backend, env in environments.items():
            status, _ = invocation(binary, env, repo, "status")
            if status.get("fresh") is not True:
                raise AssertionError((backend, status))
        cases = {
            "shared_names": ("query", "--symbol", "common", "--match", "exact", "--limit", "256"),
            "high_degree": ("context", "--symbol", "caller", "--depth", "1", "--limit", "256", "--max-tokens", "16000"),
            "direct_callers_and_test": ("impact", "--symbol", "target", "--depth", "1", "--limit", "256", "--max-tokens", "16000"),
            "missing_symbol": ("query", "--symbol", "not_present", "--match", "exact"),
        }
        outcomes = {}
        for case, command in cases.items():
            values = {}
            for backend in ("legacy", "zstd", "packed"):
                result, _ = invocation(binary, environments[backend], repo, *command,
                                       expect=2 if case == "missing_symbol" else 0)
                values[backend] = comparable(result)
            if values["legacy"] != values["zstd"] or values["legacy"] != values["packed"]:
                raise AssertionError(f"native query parity failed: {case}")
            outcomes[case] = values["packed"]
        identities = {i: node_id(f"benchmark-node-{i}") for i in (0, 1, 2, 3, 4)}
        same_ids = {node.get("id") for node in outcomes["shared_names"].get("nodes", [])}
        if not {identities[2], identities[4]} <= same_ids:
            raise AssertionError("shared names lost separate symbol IDs")
        impact_ids = {node.get("id") for node in outcomes["direct_callers_and_test"].get("nodes", [])}
        if not {identities[0], identities[1], identities[3]} <= impact_ids:
            raise AssertionError("direct caller or test ID missing")
        if args.nodes >= 192 and args.edges >= 192 and outcomes["high_degree"].get("truncated") is not True:
            raise AssertionError("high-degree output did not report truncation")
        report = {"scope": "synthetic authenticated native CLI; no live CodeGraph state",
                  "binary_sha256": file_sha256(binary),
                  "input_sha256": file_sha256(source),
                  "nodes": args.nodes, "edges": args.edges,
                  "packed_creation": ("zstd-v1 import followed by authenticated packed-v2 migrate"
                                      if args.packed_via_migrate else "direct packed-v2 import"),
                  "snapshot_apparent_bytes": snapshots,
                  "query_parity": True,
                  "cases": {name: {"seed_nodes": value.get("seed_nodes"),
                                   "shown_nodes": value.get("shown_nodes"),
                                   "truncated": value.get("truncated")}
                            for name, value in outcomes.items()},
                  "ground_truth": {"shared_name_ids": [identities[2], identities[4]],
                                   "direct_caller_id": identities[0],
                                   "target_id": identities[1], "test_id": identities[3]}}
        serialized = json.dumps(report, indent=2, sort_keys=True) + "\n"
        if args.output:
            args.output.write_text(serialized)
        print(serialized, end="")


if __name__ == "__main__":
    main()
