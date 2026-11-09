#!/usr/bin/env python3
"""Incrementally update the source index and export only to a private staging file.

This adapter handles the source producer, not QIHSE's classified snapshot store.
Native import remains the authorization and atomic-publication boundary. Existing
QIHSE snapshots are never read, relabelled or removed here. Incremental parsing is
not per-file native snapshot storage: the final native import still encodes a
complete graph generation.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import inspect
import json
import os
import sqlite3
import stat
import sys
import tempfile
import time
from collections.abc import Callable
from contextlib import closing, contextmanager, nullcontext
from pathlib import Path
from urllib.parse import quote

from qihse_codegraph_reindex_source import MAX_LINE, _row, source_identity

IdentityProvider = Callable[[Path], dict]


def emit_progress(
    phase: str, unit: str, completed: int, total: int | None = None
) -> None:
    """Emit an atomic, nonblocking event only to an explicit progress pipe."""
    raw = os.environ.get("QIHSE_CODEGRAPH_PROGRESS_FD", "")
    if not raw.isascii() or not raw.isdecimal():
        return
    try:
        fd = int(raw)
        if fd < 3 or os.get_blocking(fd) or not stat.S_ISFIFO(os.fstat(fd).st_mode):
            return
        data = (
            json.dumps(
                {
                    "version": 1,
                    "phase": phase,
                    "unit": unit,
                    "completed": completed,
                    "total": total,
                },
                separators=(",", ":"),
            )
            + "\n"
        ).encode("ascii")
        if len(data) <= 512:
            os.write(fd, data)
    except (OSError, ValueError, OverflowError):
        pass


def _producer():
    # Imported lazily: unit tests need no producer or optional parser dependency.
    from code_review_graph.exports import export_qihse
    from code_review_graph.graph import GraphStore
    from code_review_graph.incremental import assert_graph_serves_root, get_db_path
    from code_review_graph.tools.build import (
        build_or_update_graph,
        build_was_interrupted,
    )

    return {
        "build": build_or_update_graph,
        "store": GraphStore,
        "db_path": get_db_path,
        "export": export_qihse,
        "incomplete": build_was_interrupted,
        "assert_root": assert_graph_serves_root,
        "read_snapshot": lambda store: store._read_transaction(),
        "exact_incremental": "exact_dependencies"
        in inspect.signature(build_or_update_graph).parameters,
    }


def _destination(path: Path, repo: Path) -> Path:
    if not path.name or path.name in (".", ".."):
        raise ValueError("A private output filename is required")
    parent = path.parent.resolve(strict=True)
    info = parent.stat()
    if info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise ValueError(
            "Export staging directory must be owned by this user and mode 0700"
        )
    destination = parent / path.name
    if destination.is_relative_to(repo):
        raise ValueError("Export staging must be outside the indexed source tree")
    try:
        info = destination.lstat()
    except FileNotFoundError:
        pass
    else:
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or info.st_nlink != 1
            or info.st_mode & 0o077
        ):
            raise ValueError("Existing export is not a private owned regular file")
    return destination


@contextmanager
def _source_lock(directory: Path):
    """Serialize this adapter's producers; normal SQLite locks cover other clients."""
    path = directory / ".qihse-reindex.lock"
    fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or info.st_nlink != 1
            or info.st_mode & 0o077
        ):
            raise ValueError("Unsafe producer operation lock")
        # A second producer must fail promptly, not queue a stale baseline.
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(fd)


def database_accounting(path: Path) -> dict:
    """Read source-index page/size metadata without reading QIHSE storage."""
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid():
        raise ValueError("Source index must be an owned regular file")
    uri = "file:" + quote(str(path.resolve()), safe="/") + "?mode=ro"
    with closing(sqlite3.connect(uri, uri=True, timeout=0.25)) as connection:
        page_size = connection.execute("PRAGMA page_size").fetchone()[0]
        pages = connection.execute("PRAGMA page_count").fetchone()[0]
        free = connection.execute("PRAGMA freelist_count").fetchone()[0]
        indexes = connection.execute(
            "SELECT count(*) FROM sqlite_master WHERE type='index'"
        ).fetchone()[0]
    sizes = {}
    for name, suffix in (("database", ""), ("wal", "-wal"), ("shared_memory", "-shm")):
        try:
            data = Path(str(path) + suffix).lstat()
        except FileNotFoundError:
            sizes[name] = {"logical_bytes": 0, "allocated_bytes": 0}
            continue
        if not stat.S_ISREG(data.st_mode) or data.st_uid != os.geteuid():
            raise ValueError("Unsafe source-index auxiliary file")
        sizes[name] = {
            "logical_bytes": data.st_size,
            "allocated_bytes": data.st_blocks * 512,
        }
    return {
        "page_size": page_size,
        "pages": pages,
        "free_pages": free,
        "reclaimable_page_bytes": page_size * free,
        "indexes": indexes,
        "files": sizes,
        "logical_bytes": sum(v["logical_bytes"] for v in sizes.values()),
        "allocated_bytes": sum(v["allocated_bytes"] for v in sizes.values()),
    }


def reclaim_source_database(path: Path) -> dict:
    """Explicit SQLite compaction; never unlink shared outputs or remove indexes.

    SQLite's normal transaction/reader locks remain authoritative. Busy databases
    are reported without forcing a checkpoint, replacing the inode or deleting a
    WAL. This option can require free disk comparable to the source database.
    """
    before = database_accounting(path)
    uri = "file:" + quote(str(path.resolve()), safe="/") + "?mode=rw"
    try:
        with closing(
            sqlite3.connect(uri, uri=True, timeout=0.25, isolation_level=None)
        ) as connection:
            connection.execute("PRAGMA busy_timeout=250")
            if before["free_pages"]:
                connection.execute("VACUUM")
            checkpoint = list(
                connection.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
            )
        status = "busy" if checkpoint[0] else "reclaimed"
    except sqlite3.OperationalError as exc:
        if getattr(exc, "sqlite_errorcode", None) not in (
            sqlite3.SQLITE_BUSY,
            sqlite3.SQLITE_LOCKED,
        ):
            raise
        status, checkpoint = "busy", None
    return {
        "status": status,
        "before": before,
        "after": database_accounting(path),
        "checkpoint": checkpoint,
        "indexes_removed": 0,
    }


def verify_export(path: Path) -> dict:
    """Verify the bounded source-export envelope and trailer independently."""
    digest = hashlib.sha256()
    nodes = edges = unresolved = completed = 0
    size = path.stat().st_size
    emit_progress("verify", "bytes", 0, size)
    with path.open("rb") as handle:
        raw = handle.readline(MAX_LINE + 1)
        header = _row(raw)
        if header.get("t") != "h" or header.get("format") != "qihse-codegraph-v1":
            raise ValueError("Producer did not emit a CodeGraph header")
        if header.get("id_algorithm") != "xxh3-128" or header.get("id_bits") != 128:
            raise ValueError(
                "Producer does not support the current XXH3-128 ID contract"
            )
        digest.update(raw)
        completed += len(raw)
        records = 1
        while True:
            raw = handle.readline(MAX_LINE + 1)
            if not raw:
                raise ValueError("Producer export has no trailer")
            row = _row(raw)
            records += 1
            completed += len(raw)
            kind = row.get("t")
            if kind == "end":
                if (
                    row.get("nodes") != nodes
                    or row.get("edges") != edges
                    or row.get("unresolved_edges") != unresolved
                    or row.get("sha256") != digest.hexdigest()
                    or handle.read(1)
                ):
                    raise ValueError("Producer export counts or checksum do not match")
                break
            if kind == "n":
                nodes += 1
            elif kind == "e":
                edges += 1
                unresolved += not row.get("traversable", False)
            else:
                raise ValueError("Unknown producer export record")
            digest.update(raw)
            if records % 256 == 0:
                emit_progress("verify", "bytes", completed, size)
                emit_progress("verify", "records", records)
        emit_progress("verify", "bytes", completed, size)
        emit_progress("verify", "records", records)
    return {
        "nodes": nodes,
        "edges": edges,
        "unresolved_edges": unresolved,
        "records": records,
        "export_bytes": size,
        "source_sha256": digest.hexdigest(),
    }


def build_export(
    repo: Path | str,
    output: Path | str,
    *,
    full: bool = False,
    reclaim: bool = False,
    source_identity_provider: IdentityProvider = source_identity,
    export_identity_provider=None,
    expected_identity: dict | None = None,
    staged_identity_provider: IdentityProvider | None = None,
    expected_staged_digest: str | None = None,
    producer=None,
) -> dict:
    """Build/update and atomically replace a private output after all checks.

    Source providers may wrap a staged workspace; they must validate the original
    source before/after this call. A custom export identity requires the producer's
    explicit provider hook; no global monkeypatch or SHA/identity fallback occurs.
    """
    started = time.monotonic()
    repo = Path(repo).resolve(strict=True)
    destination = _destination(Path(output), repo)
    backend = producer if producer is not None else _producer()
    if (
        export_identity_provider is not None
        and "source_identity_provider"
        not in inspect.signature(backend["export"]).parameters
    ):
        raise ValueError(
            "Producer lacks the explicit source-identity provider capability"
        )
    initial = source_identity_provider(repo)
    if expected_identity is not None and initial != expected_identity:
        raise ValueError("Source identity differs from the prepared workspace")

    def verify_stage():
        if staged_identity_provider is not None:
            observed = staged_identity_provider(repo)
            if (
                not isinstance(expected_staged_digest, str)
                or observed.get("worktree") != expected_staged_digest
            ):
                raise ValueError(
                    "Materialized source differs from the effective source identity"
                )

    verify_stage()
    database = Path(backend["db_path"](repo))
    with _source_lock(database.parent):
        exact_incremental = backend.get("exact_incremental", False)
        # Older producers silently cap dependency invalidation. Until the explicit
        # complete-walk capability is available, a full build preserves accuracy.
        build_kwargs = {"repo_root": str(repo), "postprocess": "full"}
        if exact_incremental:
            build_kwargs["exact_dependencies"] = True
        build = backend["build"](
            full_rebuild=full or not exact_incremental, **build_kwargs
        )
        if build.get("full_rebuild_required") and not full:
            if source_identity_provider(repo) != initial:
                raise ValueError("Source changed before complete rebuild fallback")
            verify_stage()
            build = backend["build"](full_rebuild=True, **build_kwargs)
        if (
            build.get("status") != "ok"
            or build.get("errors")
            or build.get("postprocess_failed")
            or build.get("postprocess_contended")
        ):
            raise ValueError(
                "Source graph build is incomplete; export was not published"
            )
        if source_identity_provider(repo) != initial:
            raise ValueError("Source changed during graph construction")
        verify_stage()
        maintenance = reclaim_source_database(database) if reclaim else None
        descriptor, temporary = tempfile.mkstemp(
            prefix=".qihse-export-", suffix=".jsonl", dir=destination.parent
        )
        os.close(descriptor)
        candidate = Path(temporary)
        try:
            store = backend["store"](database)
            try:
                with backend.get("read_snapshot", lambda _store: nullcontext())(store):
                    backend["assert_root"](repo, store)
                    if backend["incomplete"](store):
                        raise ValueError("Source graph was interrupted before export")
                    kwargs = (
                        {"source_identity_provider": export_identity_provider}
                        if export_identity_provider is not None
                        else {}
                    )
                    backend["export"](store, candidate, repo, **kwargs)
            finally:
                store.close()
            checked = verify_export(candidate)
            if source_identity_provider(repo) != initial:
                raise ValueError(
                    "Source changed during export; previous output retained"
                )
            verify_stage()
            with candidate.open("rb") as handle:
                os.fsync(handle.fileno())
            os.replace(candidate, destination)
            parent_fd = os.open(destination.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(parent_fd)
            finally:
                os.close(parent_fd)
        finally:
            candidate.unlink(missing_ok=True)
        accounting = database_accounting(database)
    return dict(
        status="ok",
        build_type=build.get("build_type"),
        requested_mode="full" if full else "incremental",
        incremental_capable=exact_incremental,
        files_parsed=build.get("files_parsed", 0),
        files_updated=build.get("files_updated", 0),
        source_identity=initial,
        export_path=str(destination),
        **checked,
        database=accounting,
        reclamation=maintenance,
        persistent_export_created=False,
        seconds=time.monotonic() - started,
    )


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument(
        "--identity-repo",
        type=Path,
        help="Original workspace when parsing an explicitly materialized overlay",
    )
    parser.add_argument(
        "--source-provider", choices=("git", "filesystem"), default="git"
    )
    parser.add_argument("--overlay", type=Path)
    parser.add_argument(
        "--expected-identity",
        type=Path,
        help="Private source-identity JSON produced by materialization",
    )
    parser.add_argument("--full", action="store_true", help="Force full source reparse")
    parser.add_argument(
        "--reclaim", action="store_true", help="Explicitly reclaim SQLite free pages"
    )
    args = parser.parse_args(argv)
    try:
        identity_repo = (args.identity_repo or args.repo).resolve(strict=True)
        expected = None
        if args.expected_identity:
            fd = os.open(
                args.expected_identity, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
            )
            try:
                info = os.fstat(fd)
                if (
                    not stat.S_ISREG(info.st_mode)
                    or info.st_uid != os.geteuid()
                    or info.st_mode & 0o077
                    or info.st_size > MAX_LINE
                ):
                    raise ValueError(
                        "Source identity must be private owned bounded JSON"
                    )
                with os.fdopen(fd, "r", closefd=False) as handle:
                    expected = json.load(handle)
            finally:
                os.close(fd)
            if not isinstance(expected, dict):
                raise ValueError("Source identity must be a JSON object")
        if (
            args.source_provider == "git"
            and args.overlay is None
            and args.identity_repo is None
        ):
            identity_provider = source_identity
            export_provider = staged_provider = None
            staged_digest = None
        else:
            if args.source_provider != "filesystem" or expected is None:
                raise ValueError(
                    "Materialized sources require filesystem identity and baseline"
                )

            def identity_provider(_repo):
                return source_identity(
                    identity_repo, provider="filesystem", overlay_path=args.overlay
                )

            export_provider = lambda _repo: tuple(
                expected[key] for key in ("head", "worktree", "worktree_v2")
            )
            staged_provider = lambda parse_repo: source_identity(
                parse_repo, provider="filesystem"
            )
            staged_digest = expected.get("source_effective_digest")
        result = build_export(
            args.repo,
            args.output,
            full=args.full,
            reclaim=args.reclaim,
            source_identity_provider=identity_provider,
            export_identity_provider=export_provider,
            expected_identity=expected,
            staged_identity_provider=staged_provider,
            expected_staged_digest=staged_digest,
        )
    except (OSError, ValueError, sqlite3.Error, ImportError, RuntimeError) as exc:
        print(f"CodeGraph source preparation failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
