"""Validate and inspect a repository-local feature dependency DAG."""

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_MANIFEST = ROOT / "deps.json"
STATUSES = {"planned", "in_progress", "partial", "complete", "blocked"}
ID_PATTERN = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")


def load_manifest(path):
    try:
        with path.open(encoding="utf-8") as stream:
            return json.load(stream), []
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        return None, [f"cannot read {path}: {exc}"]


def validate_manifest(data, manifest_path):
    errors = []
    if not isinstance(data, dict):
        return ["manifest root must be an object"]
    if type(data.get("schema_version")) is not int or data.get("schema_version") != 1:
        errors.append("schema_version must be integer 1")
    if not isinstance(data.get("repository"), str) or not data["repository"].strip():
        errors.append("repository must be a non-empty string")
    items = data.get("items")
    if not isinstance(items, list):
        return errors + ["items must be a list"]

    root = Path(manifest_path).resolve().parent
    required = ("id", "title", "status", "description", "depends_on", "evidence", "acceptance")
    by_id = {}
    for index, item in enumerate(items):
        where = f"items[{index}]"
        if not isinstance(item, dict):
            errors.append(f"{where} must be an object")
            continue
        missing = [key for key in required if key not in item]
        if missing:
            errors.append(f"{where} missing fields: {', '.join(missing)}")
            continue
        item_id = item["id"]
        if not isinstance(item_id, str) or not ID_PATTERN.fullmatch(item_id):
            errors.append(f"{where}.id must be lowercase kebab-case")
            continue
        if item_id in by_id:
            errors.append(f"duplicate item id: {item_id}")
            continue
        by_id[item_id] = item
        for field in ("title", "description"):
            if not isinstance(item[field], str) or not item[field].strip():
                errors.append(f"{item_id}.{field} must be a non-empty string")
        if not isinstance(item["status"], str) or item["status"] not in STATUSES:
            errors.append(f"{item_id}.status must be one of {', '.join(sorted(STATUSES))}")
        for field in ("depends_on", "evidence", "acceptance"):
            values = item[field]
            if not isinstance(values, list) or any(not isinstance(value, str) for value in values):
                errors.append(f"{item_id}.{field} must be a list of strings")
        if isinstance(item["depends_on"], list) and all(
            isinstance(dep, str) for dep in item["depends_on"]
        ):
            if len(set(item["depends_on"])) != len(item["depends_on"]):
                errors.append(f"{item_id}.depends_on contains duplicates")
            if item_id in item["depends_on"]:
                errors.append(f"{item_id} depends on itself")
        if isinstance(item["evidence"], list):
            for evidence in item["evidence"]:
                if not isinstance(evidence, str):
                    continue
                candidate = Path(evidence)
                resolved = (root / candidate).resolve()
                if candidate.is_absolute() or not resolved.is_relative_to(root):
                    errors.append(f"{item_id}.evidence must stay inside the repository: {evidence}")
                elif not resolved.is_file():
                    errors.append(f"{item_id}.evidence file does not exist: {evidence}")

    graph = {}
    for item_id, item in by_id.items():
        deps = item.get("depends_on", [])
        if not isinstance(deps, list) or any(not isinstance(dep, str) for dep in deps):
            continue
        graph[item_id] = deps
        for dep in deps:
            if dep not in by_id:
                errors.append(f"{item_id} has unknown dependency: {dep}")
    if len(graph) == len(by_id):
        try:
            topological_order(graph)
        except ValueError as exc:
            errors.append(str(exc))
    return errors


def topological_order(graph):
    """Return deterministic prerequisite-first ordering or raise on cycles."""
    remaining = {node: set(deps) for node, deps in graph.items()}
    unknown = sorted({dep for deps in remaining.values() for dep in deps if dep not in remaining})
    if unknown:
        raise ValueError(f"unknown dependencies: {', '.join(unknown)}")
    order = []
    ready = sorted(node for node, deps in remaining.items() if not deps)
    while ready:
        node = ready.pop(0)
        order.append(node)
        for dependent in sorted(remaining):
            if node in remaining[dependent]:
                remaining[dependent].remove(node)
                if not remaining[dependent] and dependent not in order and dependent not in ready:
                    ready.append(dependent)
                    ready.sort()
    if len(order) != len(remaining):
        cyclic = sorted(set(remaining) - set(order))
        raise ValueError(f"dependency cycle involving: {', '.join(cyclic)}")
    return order


def read_valid(path):
    data, errors = load_manifest(path)
    if not errors:
        errors = validate_manifest(data, path)
    if errors:
        for error in errors:
            print(f"deps: {error}", file=sys.stderr)
        return None
    return data


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST,
                        help="manifest path (default: repository-root deps.json)")
    parser.add_argument("command", choices=("validate", "list", "order"))
    args = parser.parse_args(argv)
    path = args.manifest.resolve()
    data = read_valid(path)
    if data is None:
        return 1
    if args.command == "validate":
        print(f"Valid dependency manifest: {path} ({len(data['items'])} items)")
    elif args.command == "list":
        for item in data["items"]:
            deps = ",".join(item["depends_on"]) or "-"
            print(f"{item['id']}\t{item['status']}\t{deps}\t{item['title']}")
    else:
        graph = {item["id"]: item["depends_on"] for item in data["items"]}
        print("\n".join(topological_order(graph)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
