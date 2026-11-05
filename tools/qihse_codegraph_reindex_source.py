"""Fresh-build bridge for CRG exports lacking native v2 source identity.

Only call prepare_export after capturing equal source_identity values before a
full CRG rebuild and after export. This is not a way to relabel an old index as
fresh. The native importer remains responsible for graph/security validation.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import tempfile
import time

POLICY = 'git-status-diff-index-untracked-v2'
MAX_LINE = 262144
GIT_LIMIT = 4 * 1024 * 1024
TIMEOUT = 5.0
SELECTED = ('--', '.', ':(exclude).code-review-graph')
HEX64 = re.compile(r'[0-9a-f]{64}\Z')
HEAD = re.compile(r'(?:[0-9a-f]{40}|[0-9a-f]{64})\Z')


def _git(repo: Path, *args: str) -> bytes:
    """Bound both time and captured output; kill Git and its children on failure."""
    process = subprocess.Popen(['git', '--no-optional-locks', *args], cwd=repo,
                               stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                               start_new_session=True)
    output = bytearray()
    deadline = time.monotonic() + TIMEOUT
    try:
        assert process.stdout is not None
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not selector.select(remaining):
                    raise ValueError('Git source verification timed out')
                chunk = os.read(process.stdout.fileno(), min(65536, GIT_LIMIT + 1 - len(output)))
                if not chunk:
                    break
                output.extend(chunk)
                if len(output) > GIT_LIMIT:
                    raise ValueError('Git source verification exceeds output limit')
        if process.wait(timeout=max(0.001, deadline-time.monotonic())):
            raise ValueError('Git source verification failed')
        return bytes(output)
    except BaseException:
        # Git can exit while a descendant keeps stdout open; terminate the
        # entire process group even if the group leader has already exited.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()
        raise
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
        if process.stdout:
            process.stdout.close()


def _untracked_digest(repo: Path, raw: bytes, deadline: float) -> tuple[bytes, bytes]:
    if (not raw or raw.startswith((b'/', b'~')) or b'\\' in raw or
            any(part in (b'', b'..', b'.git') for part in raw.split(b'/')) or
            len(os.fsencode(repo)) + len(raw) + 1 >= 4096):
        raise ValueError('Unsafe untracked source path')
    # Walk without following parent symlinks; never hash outside the repository.
    fd = os.open(repo, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        parts = raw.split(b'/')
        for component in parts[:-1]:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        info = os.stat(parts[-1], dir_fd=fd, follow_symlinks=False)
        digest = hashlib.sha256()
        if stat.S_ISLNK(info.st_mode):
            target = os.readlink(parts[-1], dir_fd=fd)
            if len(target) >= 4096:
                raise ValueError('Untracked symlink target too large')
            digest.update(target)
            kind = b'l'
        elif stat.S_ISREG(info.st_mode):
            source = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
            try:
                opened = os.fstat(source)
                if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
                    raise ValueError('Untracked source changed during verification')
                while True:
                    if time.monotonic() >= deadline:
                        raise ValueError('Untracked source verification timed out')
                    chunk = os.read(source, 65536)
                    if not chunk:
                        break
                    digest.update(chunk)
                after = os.fstat(source)
                if (opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                    raise ValueError('Untracked source changed during verification')
            finally:
                os.close(source)
            kind = b'f'
        else:
            raise ValueError('Untracked source is not a regular file or symlink')
        if time.monotonic() >= deadline:
            raise ValueError('Untracked source verification timed out')
        return kind, digest.hexdigest().encode('ascii')
    finally:
        os.close(fd)


def source_identity(repo: Path | str) -> dict[str, str]:
    """Reproduce native Git identity, rejecting unverifiable index flags/paths."""
    repo = Path(repo).resolve(strict=True)
    flags = _git(repo, 'ls-files', '--stage', '-v', '-f', '-z', *SELECTED)
    if flags and not flags.endswith(b'\0'):
        raise ValueError('Malformed Git index listing')
    index = bytearray()
    for row in flags.split(b'\0')[:-1]:
        if len(row) < 3 or row[1:2] != b' ' or row[:1] == b'S' or b'a' <= row[:1] <= b'z':
            raise ValueError('Unverifiable Git index trust flags')
        index.extend(row[2:] + b'\0')
    head = _git(repo, 'rev-parse', '--verify', 'HEAD').rstrip(b'\r\n').decode('ascii')
    if not HEAD.fullmatch(head):
        raise ValueError('Invalid Git HEAD')
    status = _git(repo, 'status', '--porcelain=v1', '-z', '--untracked-files=normal', *SELECTED)
    diff = _git(repo, 'diff', '--no-ext-diff', '--no-textconv', '--binary', 'HEAD', *SELECTED)
    legacy = hashlib.sha256(status + b'\0' + diff).hexdigest()
    digest = hashlib.sha256(status + b'\0' + diff + b'\0' + index + b'\0')
    deadline = time.monotonic() + TIMEOUT
    paths = _git(repo, 'ls-files', '--others', '--exclude-standard', '-z', *SELECTED)
    if paths and not paths.endswith(b'\0'):
        raise ValueError('Malformed untracked source listing')
    for raw in paths.split(b'\0')[:-1]:
        kind, content = _untracked_digest(repo, raw, deadline)
        digest.update(raw + b'\0' + kind + b'\0' + content + b'\0')
    return dict(head=head, worktree=legacy, worktree_v2=digest.hexdigest(), freshness=POLICY)


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate JSON object field')
        result[key] = value
    return result


def _row(line: bytes) -> dict:
    if not line or len(line) > MAX_LINE or not line.endswith(b'\n'):
        raise ValueError('Oversized or unterminated export record')
    row = json.loads(line, object_pairs_hook=_object,
                     parse_constant=lambda value: (_ for _ in ()).throw(ValueError('Nonfinite JSON value')))
    if not isinstance(row, dict):
        raise ValueError('Export record must be an object')
    return row


def _encode(row: dict) -> bytes:
    line = (json.dumps(row, ensure_ascii=True, separators=(',', ':'), allow_nan=False) + '\n').encode()
    if len(line) > MAX_LINE:
        raise ValueError('Prepared export record exceeds line limit')
    return line


def prepare_export(export_path: Path | str, destination: Path | str,
                   expected_identity: dict[str, str]) -> None:
    """Validate a fresh rebuild's export and atomically attach its checked v2 identity."""
    identity = dict(expected_identity)
    if (identity.get('freshness') != POLICY or
            not isinstance(identity.get('head'), str) or not HEAD.fullmatch(identity['head']) or
            any(not isinstance(identity.get(key), str) or not HEX64.fullmatch(identity[key])
                for key in ('worktree', 'worktree_v2'))):
        raise ValueError('Invalid expected source identity')
    source, destination = Path(export_path), Path(destination)
    if source.resolve() == destination.resolve():
        raise ValueError('Prepared export must not overwrite its source')
    fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    temporary = None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError('Export must be a regular non-symlink file')
        with os.fdopen(fd, 'rb') as input_file:
            fd = -1
            header_line = input_file.readline(MAX_LINE + 1)
            header = _row(header_line)
            if (header.get('t') != 'h' or header.get('format') != 'qihse-codegraph-v1' or
                    type(header.get('version')) is not int or header['version'] != 1 or
                    header.get('head') != identity['head'] or header.get('worktree') != identity['worktree']):
                raise ValueError('Export header/source identity mismatch')
            for key in ('freshness', 'worktree_v2'):
                if key in header and header[key] != identity[key]:
                    raise ValueError('Conflicting export v2 identity')
            if ('freshness' in header) != ('worktree_v2' in header):
                raise ValueError('Incomplete export v2 identity')
            header.update(freshness=identity['freshness'], worktree_v2=identity['worktree_v2'])
            new_header = _encode(header)
            old_digest, new_digest = hashlib.sha256(header_line), hashlib.sha256(new_header)
            counts = {'nodes': 0, 'edges': 0, 'unresolved_edges': 0}
            out_fd, temporary = tempfile.mkstemp(prefix='.' + destination.name + '-', dir=destination.parent)
            with os.fdopen(out_fd, 'wb') as output:
                output.write(new_header)
                while True:
                    line = input_file.readline(MAX_LINE + 1)
                    row = _row(line)
                    kind = row.get('t')
                    if kind == 'end':
                        if row.get('sha256') != old_digest.hexdigest() or any(
                                type(row.get(key)) is not int or row[key] != value for key, value in counts.items()):
                            raise ValueError('Export checksum/count mismatch')
                        if input_file.read(1):
                            raise ValueError('Data after export trailer')
                        row['sha256'] = new_digest.hexdigest()
                        output.write(_encode(row))
                        break
                    if kind not in ('n', 'e'):
                        raise ValueError('Unexpected export record ordering/type')
                    counts['nodes' if kind == 'n' else 'edges'] += 1
                    if kind == 'e':
                        if type(row.get('traversable')) is not bool:
                            raise ValueError('Invalid edge traversability')
                        counts['unresolved_edges'] += not row['traversable']
                    if counts['nodes'] > 2000000 or counts['edges'] > 8000000:
                        raise ValueError('Export capacity exceeded')
                    old_digest.update(line)
                    new_digest.update(line)
                    output.write(line)
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, destination)
            temporary = None
            parent = os.open(destination.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(parent)
            finally:
                os.close(parent)
    finally:
        if fd >= 0:
            os.close(fd)
        if temporary is not None:
            os.unlink(temporary)
