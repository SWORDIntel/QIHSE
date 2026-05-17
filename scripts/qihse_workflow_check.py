#!/usr/bin/env python3
"""Check whether QIHSE is being used upstream-first or as an imported copy."""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path


UPSTREAM_URL_HINT = "github.com/SWORDIntel/QIHSE"


def run_git(args: list[str], cwd: Path) -> tuple[int, str]:
    completed = subprocess.run(
        ["git", *args],
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
    )
    return completed.returncode, completed.stdout.strip()


def require_qihse_root(root: Path) -> list[str]:
    errors: list[str] = []
    required = [
        "Makefile",
        "qihse_vector_db.c",
        "benchmarks/reference_workloads.json",
        "planning/qihse_upstream_workflow.md",
    ]
    for relative in required:
        if not (root / relative).exists():
            errors.append(f"missing {relative}")
    return errors


def classify_checkout(root: Path) -> tuple[str, Path | None, str]:
    code, output = run_git(["rev-parse", "--show-toplevel"], root)
    if code != 0:
        return "not-git", None, output

    git_root = Path(output).resolve()
    if git_root == root:
        return "upstream", git_root, ""
    if (git_root / "qihse").resolve() == root:
        return "framewerx-import", git_root, ""
    return "nested-import", git_root, ""


def remote_summary(git_root: Path) -> tuple[bool, str]:
    code, output = run_git(["remote", "-v"], git_root)
    if code != 0:
        return False, output
    return UPSTREAM_URL_HINT in output, output


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=".", help="QIHSE root to inspect")
    parser.add_argument(
        "--strict-upstream",
        action="store_true",
        help="fail unless root is a direct SWORDIntel/QIHSE checkout",
    )
    args = parser.parse_args(argv)

    root = Path(args.root).resolve()
    errors = require_qihse_root(root)
    if errors:
        for error in errors:
            print(f"qihse workflow check failed: {error}", file=sys.stderr)
        return 1

    checkout, git_root, detail = classify_checkout(root)
    if checkout == "not-git":
        print(f"qihse workflow check failed: {detail}", file=sys.stderr)
        return 1

    assert git_root is not None
    has_upstream_remote, remotes = remote_summary(git_root)

    print(f"qihse_root={root}")
    print(f"git_root={git_root}")
    print(f"checkout_mode={checkout}")
    print(f"has_qihse_upstream_remote={str(has_upstream_remote).lower()}")

    if checkout == "upstream":
        if has_upstream_remote:
            print("workflow=upstream-first")
            return 0
        print("workflow=upstream-checkout-without-qihse-remote")
        if args.strict_upstream:
            print("qihse workflow check failed: missing SWORDIntel/QIHSE remote", file=sys.stderr)
            return 1
        return 0

    print("workflow=imported-copy")
    if remotes:
        print("remotes:")
        print(remotes)
    if args.strict_upstream:
        print("qihse workflow check failed: QIHSE root is not the git root", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
