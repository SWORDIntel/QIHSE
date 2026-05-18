#!/usr/bin/env python3
"""Run a FRAMEWERX-to-upstream validation loop for QIHSE."""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path


REQUIRED_FILES = [
    "Makefile",
    "qihse_vector_db.c",
    "benchmarks/reference_workloads.json",
    "planning/qihse_upstream_workflow.md",
]


def run(cmd: list[str], cwd: Path | str) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd,
        cwd=str(cwd),
        check=True,
        text=True,
    )


def run_output(cmd: list[str], cwd: Path | str) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd,
        cwd=str(cwd),
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )


def git_root(path: Path) -> Path:
    result = run_output(["git", "rev-parse", "--show-toplevel"], path)
    return Path(result.stdout.strip()).resolve()


def infer_upstream_qihse_root(upstream_repo: Path, qihse_subdir: str) -> Path:
    direct = upstream_repo / "Makefile"
    nested = upstream_repo / qihse_subdir / "Makefile"
    if direct.exists():
        return upstream_repo
    if nested.exists():
        return upstream_repo / qihse_subdir
    raise RuntimeError(
        f"upstream-root does not contain a QIHSE checkout: "
        f"missing {upstream_repo / 'Makefile'} and {upstream_repo / qihse_subdir / 'Makefile'}"
    )


def sync_tracked_qihse_tree(source_root: Path, upstream_root: Path, qihse_subdir: str, nested_layout: bool) -> None:
    source_repo = git_root(source_root)
    tracked = run_output(
        ["git", "ls-files", qihse_subdir],
        source_repo,
    ).stdout.splitlines()
    if not tracked:
        raise RuntimeError(f"No tracked files found under {qihse_subdir} from repository {source_repo}")

    if upstream_root.is_file():
        raise RuntimeError(f"Expected upstream target directory {upstream_root}, found file")

    # Replace destination cleanly while preserving VCS metadata for direct upstream checkouts.
    if nested_layout:
        if upstream_root.exists():
            shutil.rmtree(upstream_root)
        upstream_root.mkdir(parents=True, exist_ok=True)
    else:
        for child in upstream_root.iterdir():
            if child.name == ".git":
                continue
            if child.is_dir():
                shutil.rmtree(child)
            else:
                child.unlink()

    for rel in tracked:
        source_path = source_repo / rel
        target_rel = rel
        if not nested_layout and rel.startswith(f"{qihse_subdir}/"):
            target_rel = rel[len(f"{qihse_subdir}/") :]
        target_path = upstream_root / target_rel
        if source_path.is_dir():
            continue
        target_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source_path, target_path)

    # Copy untracked workflow artifacts used by reference validation when present.
    for rel in ("data/vxug_pdf_sample", "data/sift1m/fallback", "data/text_embeddings"):
        source_path = source_repo / rel
        target_path = upstream_root / rel
        if not source_path.exists():
            continue
        if target_path.exists():
            if target_path.is_file():
                target_path.unlink()
            else:
                shutil.rmtree(target_path)
        if source_path.is_dir():
            shutil.copytree(source_path, target_path)


def check_qihse_root(path: Path) -> None:
    missing = [name for name in REQUIRED_FILES if not (path / name).exists()]
    if missing:
        raise RuntimeError(
            "qihse_upstream_pr_loop aborted: missing required files at "
            + ", ".join(missing)
        )


def run_upstream_checks(upstream_qihse: Path, strict_upstream: bool) -> None:
    if strict_upstream:
        print(f"[loop] running strict upstream workflow check at {upstream_qihse}")
        run(
            ["python3", "scripts/qihse_workflow_check.py", "--root", ".", "--strict-upstream"],
            upstream_qihse,
        )
    else:
        print(f"[loop] running non-strict upstream workflow check at {upstream_qihse} (nested layout)")
        run(["python3", "scripts/qihse_workflow_check.py", "--root", "."], upstream_qihse)
    print(f"[loop] running validate-reference-workflow at {upstream_qihse}")
    run(["make", "validate-reference-workflow"], upstream_qihse)


def run_source_checks(source_root: Path) -> None:
    print(f"[loop] running validate-reference-workflow at {source_root}")
    run(["make", "validate-reference-workflow"], source_root)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--source-root",
        default=".",
        help="FRAMEWERX qihse directory path (default: .)",
    )
    parser.add_argument(
        "--upstream-root",
        default="",
        help="Optional FRAMEWERX-independent upstream checkout root",
    )
    parser.add_argument(
        "--qihse-subdir",
        default="qihse",
        help="Subdirectory name for FRAMEWERX tree when synced from parent checkout (default: qihse)",
    )
    args = parser.parse_args(argv)

    source_root = Path(args.source_root).resolve()
    check_qihse_root(source_root)
    run_source_checks(source_root)

    if not args.upstream_root:
        print(
            "[loop] no --upstream-root supplied; upstream sync validation skipped. "
            "Use --upstream-root to run full FRAMEWERX->upstream loop."
        )
        return 0

    upstream_root = Path(args.upstream_root).resolve()
    source_repo = git_root(source_root)
    upstream_repo = git_root(upstream_root)

    if upstream_repo == source_repo:
        raise RuntimeError("upstream-root must be a different checkout from FRAMEWERX source tree.")

    upstream_qihse = infer_upstream_qihse_root(upstream_repo, args.qihse_subdir)
    strict_upstream = upstream_qihse == upstream_repo

    print(f"[loop] syncing tracked {args.qihse_subdir}/ files from {source_repo} to {upstream_qihse}")
    sync_tracked_qihse_tree(source_root, upstream_qihse, args.qihse_subdir, nested_layout=not strict_upstream)

    print("[loop] launching upstream validation targets")
    run_upstream_checks(upstream_qihse, strict_upstream)

    print("[loop] full FRAMEWERX->upstream validation loop complete")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RuntimeError as exc:
        print(f"qihse upstream PR loop failed: {exc}", file=sys.stderr)
        raise SystemExit(1)
