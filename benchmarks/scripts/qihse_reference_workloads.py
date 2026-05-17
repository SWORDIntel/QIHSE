#!/usr/bin/env python3
"""Validate and print QIHSE reference workload benchmark plans."""

from __future__ import annotations

import argparse
import struct
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


SUPPORTED_FILE_FORMATS = {"fvecs", "ivecs", "f32_matrix", "u32_matrix"}


def inspect_fvecs_or_ivecs(path: Path) -> tuple[int, int]:
    count = 0
    dims = -1
    offset = 0
    file_size = path.stat().st_size

    with path.open("rb") as handle:
        while offset < file_size:
            header = handle.read(4)
            if len(header) != 4:
                raise ValueError(f"{path} has a truncated vector header")
            (row_dims,) = struct.unpack("<i", header)
            if row_dims <= 0:
                raise ValueError(f"{path} has non-positive vector dimensions")
            if dims < 0:
                dims = row_dims
            elif dims != row_dims:
                raise ValueError(f"{path} has mixed vector dimensions")

            payload_size = row_dims * 4
            skipped = handle.seek(payload_size, os.SEEK_CUR)
            offset = skipped
            if offset > file_size:
                raise ValueError(f"{path} has a truncated vector payload")
            count += 1

    if count == 0 or dims <= 0:
        raise ValueError(f"{path} contains no vectors")
    return count, dims


def inspect_dense_matrix(path: Path, dims: int, scalar_bytes: int) -> tuple[int, int]:
    file_size = path.stat().st_size
    row_bytes = dims * scalar_bytes
    if row_bytes <= 0:
        raise ValueError(f"{path} has invalid row width")
    if file_size == 0 or file_size % row_bytes != 0:
        raise ValueError(f"{path} size is not divisible by row width")
    return file_size // row_bytes, dims


def inspect_workload_files(workload: dict[str, Any], root: Path) -> list[str]:
    errors: list[str] = []
    files = workload.get("files", {})
    formats = workload.get("file_formats", {})
    expected = {
        "base_vectors": (workload["rows"], workload["dimensions"]),
        "query_vectors": (workload["queries"], workload["dimensions"]),
        "ground_truth": (workload["queries"], workload["top_k"]),
    }

    for label, relative in sorted(files.items()):
        path = root / relative
        file_format = formats.get(label)
        expected_rows, expected_dims = expected.get(label, (None, None))
        try:
            if file_format in {"fvecs", "ivecs"}:
                actual_rows, actual_dims = inspect_fvecs_or_ivecs(path)
            elif file_format == "f32_matrix":
                actual_rows, actual_dims = inspect_dense_matrix(path, int(expected_dims), 4)
            elif file_format == "u32_matrix":
                actual_rows, actual_dims = inspect_dense_matrix(path, int(expected_dims), 4)
            else:
                errors.append(f"{workload['name']}.{label} unsupported format: {file_format}")
                continue
        except (OSError, ValueError) as exc:
            errors.append(f"{workload['name']}.{label} inspect failed: {exc}")
            continue

        if expected_rows is not None and actual_rows != expected_rows:
            errors.append(
                f"{workload['name']}.{label} rows {actual_rows} != expected {expected_rows}"
            )
        if expected_dims is not None and actual_dims != expected_dims:
            errors.append(
                f"{workload['name']}.{label} dims {actual_dims} != expected {expected_dims}"
            )

    return errors


def load_manifest(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        manifest = json.load(handle)
    if not isinstance(manifest, dict):
        raise ValueError("manifest root must be an object")
    return manifest


def selected_workloads(manifest: dict[str, Any], names: set[str] | None) -> list[Any]:
    workloads = manifest.get("workloads")
    if not isinstance(workloads, list) or names is None:
        return workloads if isinstance(workloads, list) else []
    return [
        workload for workload in workloads
        if isinstance(workload, dict) and workload.get("name") in names
    ]


def validate_manifest(
    manifest: dict[str, Any],
    root: Path,
    check_files: bool,
    inspect_files: bool,
    workload_names: set[str] | None,
) -> list[str]:
    errors: list[str] = []
    workloads = manifest.get("workloads")

    if manifest.get("schema_version") != 1:
        errors.append("schema_version must be 1")
    if not isinstance(workloads, list) or not workloads:
        errors.append("workloads must be a non-empty list")
        return errors
    if workload_names is not None:
        manifest_names = {
            workload.get("name")
            for workload in workloads
            if isinstance(workload, dict)
        }
        missing_names = sorted(workload_names.difference(manifest_names))
        if missing_names:
            errors.append(f"unknown workloads: {', '.join(missing_names)}")
        workloads = selected_workloads(manifest, workload_names)

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
        file_formats = workload.get("file_formats")
        if kind == "external":
            if not isinstance(files, dict) or not files:
                errors.append(f"{prefix}.files must be present for external workloads")
            if not isinstance(file_formats, dict) or not file_formats:
                errors.append(f"{prefix}.file_formats must be present for external workloads")
            elif isinstance(files, dict):
                for label in files:
                    file_format = file_formats.get(label)
                    if file_format not in SUPPORTED_FILE_FORMATS:
                        errors.append(
                            f"{prefix}.file_formats.{label} must be one of "
                            f"{', '.join(sorted(SUPPORTED_FILE_FORMATS))}"
                        )
            if isinstance(files, dict) and check_files:
                for label, relative in sorted(files.items()):
                    if not isinstance(relative, str) or not relative:
                        errors.append(f"{prefix}.files.{label} must be a non-empty path")
                        continue
                    if not (root / relative).exists():
                        errors.append(f"{prefix}.files.{label} missing: {relative}")
            if (
                isinstance(files, dict)
                and isinstance(file_formats, dict)
                and check_files
                and inspect_files
            ):
                errors.extend(inspect_workload_files(workload, root))

    return errors


def print_plan(manifest: dict[str, Any], workload_names: set[str] | None) -> None:
    for workload in selected_workloads(manifest, workload_names):
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
        "--inspect-files",
        action="store_true",
        help="inspect external file dimensions and row counts; implies --check-files",
    )
    parser.add_argument(
        "--plan",
        action="store_true",
        help="print the benchmark execution plan after validation",
    )
    parser.add_argument(
        "--workload",
        action="append",
        dest="workloads",
        help="limit validation/plan output to a named workload; can be repeated",
    )
    args = parser.parse_args(argv)

    root = Path(args.root).resolve()
    manifest_path = Path(args.manifest)
    if not manifest_path.is_absolute():
        manifest_path = root / manifest_path

    try:
        manifest = load_manifest(manifest_path)
        check_files = args.check_files or args.inspect_files
        workload_names = set(args.workloads) if args.workloads else None
        errors = validate_manifest(
            manifest,
            root,
            check_files,
            args.inspect_files,
            workload_names,
        )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"reference workload manifest error: {exc}", file=sys.stderr)
        return 1

    if errors:
        for error in errors:
            print(f"reference workload manifest error: {error}", file=sys.stderr)
        return 1

    print(
        f"reference workload manifest OK: "
        f"{len(selected_workloads(manifest, workload_names))} workloads "
        f"from {os.path.relpath(manifest_path, root)}"
    )
    if args.plan:
        print_plan(manifest, workload_names)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
