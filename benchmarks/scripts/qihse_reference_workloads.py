#!/usr/bin/env python3
"""Validate and print QIHSE reference workload benchmark plans."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any


REQUIRED_WORKLOAD_FIELDS = {
    "name",
    "kind",
    "dataset",
    "dimensions",
    "rows",
    "queries",
    "top_k",
    "required_modes",
    "acceptance",
}


def load_manifest(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        manifest = json.load(handle)
    if not isinstance(manifest, dict):
        raise ValueError("manifest root must be an object")
    return manifest


def validate_manifest(manifest: dict[str, Any], root: Path, check_files: bool) -> list[str]:
    errors: list[str] = []
    workloads = manifest.get("workloads")

    if manifest.get("schema_version") != 1:
        errors.append("schema_version must be 1")
    if not isinstance(workloads, list) or not workloads:
        errors.append("workloads must be a non-empty list")
        return errors

    seen_names: set[str] = set()
    for index, workload in enumerate(workloads):
        prefix = f"workloads[{index}]"
        if not isinstance(workload, dict):
            errors.append(f"{prefix} must be an object")
            continue

        missing = sorted(REQUIRED_WORKLOAD_FIELDS.difference(workload))
        if missing:
            errors.append(f"{prefix} missing fields: {', '.join(missing)}")

        name = workload.get("name")
        if not isinstance(name, str) or not name:
            errors.append(f"{prefix}.name must be a non-empty string")
        elif name in seen_names:
            errors.append(f"{prefix}.name is duplicated: {name}")
        else:
            seen_names.add(name)

        kind = workload.get("kind")
        if kind not in {"synthetic", "external"}:
            errors.append(f"{prefix}.kind must be synthetic or external")

        for field in ("dimensions", "rows", "queries", "top_k"):
            value = workload.get(field)
            if not isinstance(value, int) or value <= 0:
                errors.append(f"{prefix}.{field} must be a positive integer")

        modes = workload.get("required_modes")
        if not isinstance(modes, list) or not modes:
            errors.append(f"{prefix}.required_modes must be a non-empty list")
        elif "float32" not in modes:
            errors.append(f"{prefix}.required_modes must include float32")

        acceptance = workload.get("acceptance")
        if not isinstance(acceptance, dict) or not acceptance:
            errors.append(f"{prefix}.acceptance must be a non-empty object")

        files = workload.get("files")
        if kind == "external":
            if not isinstance(files, dict) or not files:
                errors.append(f"{prefix}.files must be present for external workloads")
            elif check_files:
                for label, relative in sorted(files.items()):
                    if not isinstance(relative, str) or not relative:
                        errors.append(f"{prefix}.files.{label} must be a non-empty path")
                        continue
                    if not (root / relative).exists():
                        errors.append(f"{prefix}.files.{label} missing: {relative}")

    return errors


def print_plan(manifest: dict[str, Any]) -> None:
    for workload in manifest["workloads"]:
        name = workload["name"]
        kind = workload["kind"]
        dims = workload["dimensions"]
        rows = workload["rows"]
        queries = workload["queries"]
        top_k = workload["top_k"]
        modes = ", ".join(workload["required_modes"])
        print(f"{name}: kind={kind} dims={dims} rows={rows} queries={queries} top_k={top_k} modes={modes}")
        if kind == "synthetic":
            print("  scalar sweep: make bench-trinary-search-sweep")
            print("  qmag sweep:   make bench-trinary-magnitude-sweep")
        else:
            print("  external files:")
            for label, relative in sorted(workload["files"].items()):
                print(f"    {label}: {relative}")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--manifest",
        default="benchmarks/reference_workloads.json",
        help="manifest path relative to the QIHSE root",
    )
    parser.add_argument(
        "--root",
        default=".",
        help="QIHSE root used for relative external file checks",
    )
    parser.add_argument(
        "--check-files",
        action="store_true",
        help="also require external workload files to exist locally",
    )
    parser.add_argument(
        "--plan",
        action="store_true",
        help="print the benchmark execution plan after validation",
    )
    args = parser.parse_args(argv)

    root = Path(args.root).resolve()
    manifest_path = Path(args.manifest)
    if not manifest_path.is_absolute():
        manifest_path = root / manifest_path

    try:
        manifest = load_manifest(manifest_path)
        errors = validate_manifest(manifest, root, args.check_files)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"reference workload manifest error: {exc}", file=sys.stderr)
        return 1

    if errors:
        for error in errors:
            print(f"reference workload manifest error: {error}", file=sys.stderr)
        return 1

    print(
        f"reference workload manifest OK: "
        f"{len(manifest['workloads'])} workloads from {os.path.relpath(manifest_path, root)}"
    )
    if args.plan:
        print_plan(manifest)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
