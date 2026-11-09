#!/usr/bin/env python3
"""Versioned public-ID widths, query preservation and fail-closed imports.

Only private synthetic graphs are used. Snapshot checksums remain SHA-256.
"""
from __future__ import annotations
import argparse
import copy
import json
import os
from pathlib import Path
import subprocess
import tempfile
from test_codegraph_native import git, snapshot, write_records

SHA_PROFILE = {"identity": "qihse-semantic-128-v1", "id_algorithm": "sha256-128",
           "id_bits": 128, "id_collision": "counter-sha256-128-v1",
           "id_collision_attempts": 256}

PROFILE = {"identity": "qihse-semantic-xxh3-128-v1", "id_algorithm": "xxh3-128",
           "id_bits": 128, "id_seed": 0, "id_encoding": "xxh128-canonical",
           "id_collision": "counter-xxh3-128-v1", "id_collision_attempts": 256}


def check(binary: Path) -> dict:
    with tempfile.TemporaryDirectory(prefix="qihse-ids128-") as tmp:
        root = Path(tmp)
        repo = root / "repo"
        repo.mkdir()
        git(repo, "init", "-q")
        for name in ("src/a.c", "src/b.c", "src/leaf.c", "src/dep.c", "src/other.c",
                     "tests/test_a.c"):
            path = repo / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("int source(void) { return 1; }\n")
        git(repo, "add", ".")
        git(repo, "-c", "user.name=Test", "-c", "user.email=test@example.invalid",
            "commit", "-qm", "synthetic")
        source = root / "graph.jsonl"
        snapshot(repo, source)
        legacy = [json.loads(line) for line in source.read_text().splitlines()]
        env = dict(os.environ, XDG_STATE_HOME=str(root / "state"),
                   LD_LIBRARY_PATH=str(binary.parent) + os.pathsep +
                                   os.environ.get("LD_LIBRARY_PATH", ""))

        def invoke(*args: str, expect: int = 0) -> dict:
            result = subprocess.run([str(binary), *args, "--repo", str(repo)], env=env,
                                    text=True, capture_output=True, timeout=120)
            assert result.returncode == expect, (args, result.returncode,
                                                result.stdout, result.stderr)
            return json.loads(result.stdout)

        old = invoke("import", "--input", str(source), "--storage-format", "packed-v3")
        old_query = invoke("query", "--symbol", "caller", "--match", "exact")
        assert all(len(node["id"]) == 64 for node in old_query["nodes"])
        assert len(old["source_sha256"]) == 64

        rows = copy.deepcopy(legacy)
        rows[0].update(PROFILE)
        for row in rows[1:-1]:
            for field in ("id", "source", "target"):
                if row.get(field):
                    row[field] = row[field][:32]
        write_records(source, rows)
        new = invoke("import", "--input", str(source), "--storage-format", "packed-v3")
        assert new["identity"] == PROFILE["identity"] and new["id_bits"] == 128
        assert len(new["source_sha256"]) == 64
        query = invoke("query", "--symbol", "caller", "--match", "exact")
        assert all(query[k] == v for k, v in PROFILE.items()), query
        assert all(new[k] == v for k, v in PROFILE.items()), new
        assert {n["symbol"] for n in query["nodes"]} == {n["symbol"] for n in old_query["nodes"]}
        assert {n["id"] for n in query["nodes"]} == {n["id"][:32] for n in old_query["nodes"]}
        assert all(len(n["id"]) == 32 for n in query["nodes"])
        invoke("migrate", "--storage-format", "packed-v2")
        migrated = invoke("query", "--symbol", "caller", "--match", "exact")
        assert migrated["nodes"] == query["nodes"]
        stats = invoke("stats")
        generation = stats["generation"]
        assert all(stats[k] == v for k, v in PROFILE.items()), stats

        failures = []
        for name in ("node-width", "edge-width", "endpoint-width", "unknown-profile",
                     "unknown-algorithm", "missing-collision", "boolean-width",
                     "unknown-collision", "attempts", "cross-kind-duplicate", "protected",
                     "missing-seed", "wrong-seed", "boolean-seed", "missing-encoding",
                     "wrong-encoding", "mixed-algorithm", "mixed-collision",
                     "nul-profile", "nul-algorithm", "nul-collision", "nul-encoding",
                     "nul-node-id", "nul-edge-id", "nul-endpoint-id"):
            bad = copy.deepcopy(rows)
            if name == "node-width": bad[1]["id"] = "0" * 64
            elif name == "edge-width": next(r for r in bad if r["t"] == "e")["id"] = "0" * 64
            elif name == "endpoint-width": next(r for r in bad if r["t"] == "e")["source"] = "0" * 64
            elif name == "unknown-profile": bad[0]["identity"] = "future-128-v9"
            elif name == "unknown-algorithm": bad[0]["id_algorithm"] = "eax4-v2"
            elif name == "missing-collision": del bad[0]["id_collision"]
            elif name == "boolean-width": bad[0]["id_bits"] = True
            elif name == "unknown-collision": bad[0]["id_collision"] = "merge"
            elif name == "attempts": bad[0]["id_collision_attempts"] = 0
            elif name == "missing-seed": del bad[0]["id_seed"]
            elif name == "wrong-seed": bad[0]["id_seed"] = 1
            elif name == "boolean-seed": bad[0]["id_seed"] = False
            elif name == "missing-encoding": del bad[0]["id_encoding"]
            elif name == "wrong-encoding": bad[0]["id_encoding"] = "native-struct"
            elif name == "mixed-algorithm": bad[0]["id_algorithm"] = "sha256-128"
            elif name == "mixed-collision": bad[0]["id_collision"] = "counter-sha256-128-v1"
            elif name == "nul-node-id": bad[1]["id"] += "\0suffix"
            elif name == "nul-edge-id": next(r for r in bad if r["t"] == "e")["id"] += "\0suffix"
            elif name == "nul-endpoint-id": next(r for r in bad if r["t"] == "e")["source"] += "\0suffix"
            elif name.startswith("nul-"):
                field = {"nul-profile": "identity", "nul-algorithm": "id_algorithm",
                         "nul-collision": "id_collision", "nul-encoding": "id_encoding"}[name]
                bad[0][field] += "\0suffix"
            elif name == "cross-kind-duplicate": next(r for r in bad if r["t"] == "e")["id"] = bad[1]["id"]
            else:
                bad[1].update(classification=4, sci=2, name="PROTECTED-128-PAYLOAD")
            write_records(source, bad)
            denied = invoke("import", "--input", str(source), expect=1)
            assert "error" in denied and "PROTECTED-128-PAYLOAD" not in json.dumps(denied)
            failures.append(name)
        assert invoke("stats")["generation"] == generation
        # Missing 128 declaration cannot silently reinterpret short IDs as legacy.
        undeclared = copy.deepcopy(rows)
        for field in PROFILE: undeclared[0].pop(field)
        write_records(source, undeclared)
        invoke("import", "--input", str(source), expect=1)
        # Existing SHA-256/128 fixtures retain their own explicit namespace.
        sha_rows = copy.deepcopy(rows)
        for field in PROFILE: sha_rows[0].pop(field)
        sha_rows[0].update(SHA_PROFILE)
        write_records(source, sha_rows)
        invoke("import", "--input", str(source))
        sha_query = invoke("query", "--symbol", "caller", "--match", "exact")
        assert all(sha_query[k] == v for k, v in SHA_PROFILE.items()), sha_query
        assert "id_seed" not in sha_query and "id_encoding" not in sha_query
        mixed_sha = copy.deepcopy(sha_rows)
        mixed_sha[0]["id_seed"] = 0
        write_records(source, mixed_sha)
        invoke("import", "--input", str(source), expect=1)
        # The earlier semantic-256 profile remains readable and keeps full IDs.
        legacy[0]["identity"] = "qihse-semantic-edges-v2"
        write_records(source, legacy)
        invoke("import", "--input", str(source))
        assert all(len(n["id"]) == 64 for n in
                   invoke("query", "--symbol", "caller", "--match", "exact")["nodes"])
        return {"legacy_and_128_queries": True, "migration_preserves_ids": True,
                "invalid_profiles_denied": failures, "protected_metadata_denied": True,
                "source_checksum_bits": 256, "xxh3_profile_preserved": True,
                "sha128_profile_preserved": True}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(check(args.binary.resolve(strict=True)), sort_keys=True))


if __name__ == "__main__":
    main()
