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
UNTRACKED_TIMEOUT = 30.0
UNTRACKED_MAX_FILES = 200000
UNTRACKED_MAX_BYTES = 64 * 1024 * 1024
UNTRACKED_MAX_PATH = 4096
SELECTED = ('--', '.', ':(exclude).code-review-graph')
HEX64 = re.compile(r'[0-9a-f]{64}\Z')
HEAD = re.compile(r'(?:[0-9a-f]{40}|[0-9a-f]{64})\Z')


def _git(repo: Path, *args: str, on_chunk=None, timeout: float | None = None) -> bytes:
    """Bound Git execution; optionally consume output without retaining it."""
    process = subprocess.Popen(['git', '--no-optional-locks', *args], cwd=repo,
                               stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                               start_new_session=True)
    output = bytearray()
    deadline = time.monotonic() + (TIMEOUT if timeout is None else timeout)
    idle_deadline = time.monotonic() + TIMEOUT
    try:
        assert process.stdout is not None
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while True:
                remaining = min(deadline, idle_deadline) - time.monotonic()
                if remaining <= 0 or not selector.select(remaining):
                    raise ValueError('Git source verification timed out')
                chunk = os.read(process.stdout.fileno(),
                                65536 if on_chunk is not None else min(65536, GIT_LIMIT + 1 - len(output)))
                if not chunk:
                    break
                if on_chunk is not None:
                    on_chunk(chunk, deadline)
                else:
                    output.extend(chunk)
                    if len(output) > GIT_LIMIT:
                        raise ValueError('Git source verification exceeds output limit')
                idle_deadline = time.monotonic() + TIMEOUT
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


def _git_source_identity(repo: Path | str) -> dict[str, str]:
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
    pending = bytearray()
    count = 0
    listing_bytes = 0

    def consume_untracked(chunk: bytes, deadline: float) -> None:
        nonlocal count, listing_bytes
        listing_bytes += len(chunk)
        if listing_bytes > UNTRACKED_MAX_BYTES:
            raise ValueError('Untracked source listing exceeds output limit')
        start = 0
        while start < len(chunk):
            end = chunk.find(b'\0', start)
            if end < 0:
                pending.extend(chunk[start:])
                if len(pending) >= UNTRACKED_MAX_PATH:
                    raise ValueError('Untracked source path exceeds limit')
                break
            pending.extend(chunk[start:end])
            if not pending or len(pending) >= UNTRACKED_MAX_PATH:
                raise ValueError('Malformed untracked source path')
            if count >= UNTRACKED_MAX_FILES:
                raise ValueError('Too many untracked source files')
            raw = bytes(pending)
            pending.clear()
            kind, content = _untracked_digest(repo, raw, deadline)
            digest.update(raw + b'\0' + kind + b'\0' + content + b'\0')
            count += 1
            start = end + 1

    _git(repo, 'ls-files', '--others', '--exclude-standard', '-z', *SELECTED,
         on_chunk=consume_untracked, timeout=UNTRACKED_TIMEOUT)
    if pending:
        raise ValueError('Malformed untracked source listing')
    return dict(head=head, worktree=legacy, worktree_v2=digest.hexdigest(), freshness=POLICY)


FILESYSTEM_POLICY = 'filesystem-content-v1'
OVERLAY_POLICY = 'filesystem-overlay-content-v1'
SOURCE_MAX_FILES = 200000
SOURCE_MAX_FILE_BYTES = 256 << 20
SOURCE_MAX_TOTAL_BYTES = 8 << 30
OVERLAY_MAX_BYTES = 16 << 20
OVERLAY_MAX_FILES = 4096
SOURCE_TIMEOUT = 30.0
SOURCE_EXCLUDES = frozenset(('.git', '.code-review-graph'))
_source_progress_files = 0
_source_progress_bytes = 0
_source_progress_last = 0.0


def _source_progress(size=0, files=0):
    """Content-free actual counters; optional progress never changes correctness."""
    global _source_progress_files, _source_progress_bytes, _source_progress_last
    _source_progress_files += files
    _source_progress_bytes += size
    setting = os.environ.get('QIHSE_CODEGRAPH_PROGRESS_FD', '')
    if (not setting.isascii() or not setting.isdecimal() or len(setting) > 10 or
            not 3 <= int(setting) <= 0x7fffffff):
        return
    now = time.monotonic()
    if not files and now - _source_progress_last < 0.1:
        return
    try:
        fd = int(setting)
        if os.get_blocking(fd):
            return
        for unit, completed in (('bytes', _source_progress_bytes),
                                ('files', _source_progress_files)):
            frame = (json.dumps(dict(version=1, phase='source-hash', unit=unit,
                                    completed=completed, total=None), separators=(',', ':')) + '\n').encode()
            if len(frame) <= 512:
                os.write(fd, frame)
        _source_progress_last = now
    except (OSError, ValueError, OverflowError):
        pass


def _source_path(path: str) -> bytes:
    if (not isinstance(path, str) or not path or '\x00' in path or
            path.startswith(('/', '~')) or '\\' in path or
            any(p in ('', '.', '..') or p in SOURCE_EXCLUDES for p in path.split('/'))):
        raise ValueError('Unsafe filesystem/overlay source path')
    raw = os.fsencode(path)
    if len(raw) >= 4096:
        raise ValueError('Source path exceeds limit')
    return raw


def _stable(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _source_scan(repo: Path) -> dict[bytes, tuple[int, str]]:
    """Directory-FD walk; no symlink following or metadata-only freshness trust."""
    records = {}
    total = 0
    deadline = time.monotonic() + SOURCE_TIMEOUT

    def walk(fd, prefix):
        nonlocal total
        if prefix.count(b'/') > 128:
            raise ValueError('Filesystem source directory depth exceeds limit')
        before = os.fstat(fd)
        for name in sorted(os.listdir(fd), key=os.fsencode):
            if name in SOURCE_EXCLUDES:
                continue
            if time.monotonic() > deadline:
                raise ValueError('Filesystem source verification timed out')
            raw = prefix + os.fsencode(name)
            _source_path(os.fsdecode(raw))
            info = os.stat(name, dir_fd=fd, follow_symlinks=False)
            if stat.S_ISDIR(info.st_mode):
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                dir_fd=fd)
                try:
                    if _stable(info) != _stable(os.fstat(child)):
                        raise ValueError('Source directory changed during verification')
                    walk(child, raw + b'/')
                finally:
                    os.close(child)
            elif stat.S_ISREG(info.st_mode):
                if len(records) >= SOURCE_MAX_FILES or info.st_size > SOURCE_MAX_FILE_BYTES:
                    raise ValueError('Filesystem source exceeds file/byte limits')
                source = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
                try:
                    opened = os.fstat(source)
                    if not stat.S_ISREG(opened.st_mode) or _stable(info) != _stable(opened):
                        raise ValueError('Source file changed during verification')
                    digest = hashlib.sha256()
                    size = 0
                    while chunk := os.read(source, 65536):
                        size += len(chunk)
                        total += len(chunk)
                        if (size > SOURCE_MAX_FILE_BYTES or total > SOURCE_MAX_TOTAL_BYTES or
                                time.monotonic() > deadline):
                            raise ValueError('Filesystem source exceeds verification budget')
                        digest.update(chunk)
                        _source_progress(size=len(chunk))
                    if size != info.st_size or _stable(opened) != _stable(os.fstat(source)):
                        raise ValueError('Source file changed during verification')
                    records[raw] = (size, digest.hexdigest())
                    _source_progress(files=1)
                finally:
                    os.close(source)
            else:
                raise ValueError('Filesystem source rejects symlinks and special files')
        if _stable(before) != _stable(os.fstat(fd)):
            raise ValueError('Source directory changed during verification')

    fd = os.open(repo, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        walk(fd, b'')
    finally:
        os.close(fd)
    return records


def _source_records_digest(records) -> str:
    digest = hashlib.sha256(b'qihse-filesystem-content-v1\0')
    for raw, (size, content) in sorted(records.items()):
        # A staged tree cannot contain both a file and its descendant.
        parts = raw.split(b'/')
        if any(b'/'.join(parts[:i]) in records for i in range(1, len(parts))):
            raise ValueError('Overlay file/directory collision')
        digest.update(raw + b'\0' + str(size).encode('ascii') + b'\0' +
                      content.encode('ascii') + b'\0')
    return digest.hexdigest()


def _overlay_bytes(files) -> bytes:
    import base64
    rows = []
    if len(files) > OVERLAY_MAX_FILES:
        raise ValueError('Overlay exceeds file limit')
    for path in sorted(files, key=os.fsencode):
        _source_path(path)
        content = files[path]
        row = {'path': path}
        if content is None:
            row['deleted'] = True
        else:
            if not isinstance(content, bytes):
                raise ValueError('Overlay contents must be bytes or None')
            row['content_b64'] = base64.b64encode(content).decode('ascii')
        rows.append(row)
    encoded = json.dumps({'version': 1, 'files': rows}, ensure_ascii=False,
                         separators=(',', ':'), allow_nan=False).encode('utf-8')
    if len(encoded) > OVERLAY_MAX_BYTES:
        raise ValueError('Overlay exceeds byte limit')
    return encoded


def write_overlay_snapshot(path: Path | str, files: dict[str, bytes | None]) -> None:
    """Atomically publish a canonical owner-private editor revision snapshot."""
    path = Path(path)
    encoded = _overlay_bytes(files)
    fd, temporary = tempfile.mkstemp(prefix='.overlay-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as output:
            output.write(encoded)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _read_overlay(repo: Path, path: Path | str):
    import base64
    path = Path(path).absolute()
    if path.resolve().is_relative_to(repo):
        raise ValueError('Overlay snapshot must be outside the source tree')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or
                info.st_nlink != 1 or info.st_mode & 0o077 or
                info.st_size > OVERLAY_MAX_BYTES):
            raise ValueError('Overlay snapshot must be owner-private, bounded and single-link')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            raw = stream.read(OVERLAY_MAX_BYTES + 1)
        if len(raw) != info.st_size or _stable(info) != _stable(os.fstat(fd)):
            raise ValueError('Overlay changed during verification')
    finally:
        os.close(fd)
    obj = json.loads(raw, object_pairs_hook=_object)
    if (not isinstance(obj, dict) or set(obj) != {'version', 'files'} or
            type(obj['version']) is not int or obj['version'] != 1 or
            not isinstance(obj['files'], list) or len(obj['files']) > OVERLAY_MAX_FILES):
        raise ValueError('Invalid overlay version/schema')
    files = {}
    for row in obj['files']:
        if not isinstance(row, dict) or not isinstance(row.get('path'), str):
            raise ValueError('Invalid overlay row')
        name = row['path']
        _source_path(name)
        if name in files:
            raise ValueError('Duplicate overlay source path')
        if set(row) == {'path', 'deleted'} and row['deleted'] is True:
            files[name] = None
        elif set(row) == {'path', 'content_b64'} and isinstance(row['content_b64'], str):
            try:
                files[name] = base64.b64decode(row['content_b64'], validate=True)
            except (ValueError, TypeError) as exc:
                raise ValueError('Invalid overlay base64') from exc
        else:
            raise ValueError('Invalid overlay row fields')
    if raw != _overlay_bytes(files):
        raise ValueError('Overlay snapshot must use canonical encoding')
    return path, raw, files


def source_identity(repo: Path | str, *, provider: str = 'git',
                    overlay_path: Path | str | None = None) -> dict[str, str]:
    """Check Git identity or explicitly selected disk/editor content identity."""
    if provider == 'git':
        if overlay_path is not None:
            raise ValueError('Editor overlays require the filesystem provider')
        return _git_source_identity(repo)
    if provider != 'filesystem':
        raise ValueError('Unknown source provider')
    repo = Path(repo).resolve(strict=True)
    records = _source_scan(repo)
    disk = _source_records_digest(records)
    result = dict(head='0' * 64, worktree=disk, worktree_v2=disk,
                  freshness=FILESYSTEM_POLICY, source_provider='filesystem',
                  source_disk_digest=disk, source_effective_digest=disk)
    if overlay_path is not None:
        path, raw, files = _read_overlay(repo, overlay_path)
        for name, data in files.items():
            if data is None:
                records.pop(os.fsencode(name), None)
            else:
                records[os.fsencode(name)] = (len(data), hashlib.sha256(data).hexdigest())
        if (len(records) > SOURCE_MAX_FILES or
                sum(v[0] for v in records.values()) > SOURCE_MAX_TOTAL_BYTES):
            raise ValueError('Effective overlay source exceeds limits')
        effective = _source_records_digest(records)
        overlay_hash = hashlib.sha256(raw).hexdigest()
        combined = hashlib.sha256(b'qihse-overlay-content-v1\0' + disk.encode() + b'\0' +
                                  overlay_hash.encode() + b'\0' + effective.encode() + b'\0').hexdigest()
        result.update(worktree=combined, worktree_v2=combined, freshness=OVERLAY_POLICY,
                      source_effective_digest=effective, source_overlay=str(path),
                      source_overlay_digest=overlay_hash)
    return result


def materialize_source(repo: Path | str, destination: Path | str, *,
                       overlay_path: Path | str | None = None) -> dict[str, str]:
    """Copy exactly the checked effective bytes into an isolated producer tree.

    Destination must be newly created outside source. Producer must parse this
    tree, not the disk checkout, then attach the returned identity only after
    checking source_identity(original, provider='filesystem', ...) again.
    """
    import shutil
    repo = Path(repo).resolve(strict=True)
    destination = Path(destination).absolute()
    if destination.resolve().is_relative_to(repo) or destination.exists():
        raise ValueError('Staged source must be a new directory outside the source tree')
    identity = source_identity(repo, provider='filesystem', overlay_path=overlay_path)
    records = _source_scan(repo)
    overlay_files = {} if overlay_path is None else _read_overlay(repo, overlay_path)[2]
    destination.mkdir(mode=0o700)
    copy_deadline = time.monotonic() + SOURCE_TIMEOUT
    copied_total = 0
    try:
        for raw in sorted(records):
            path = os.fsdecode(raw)
            if path in overlay_files:
                continue
            target = destination / path
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            source = os.open(repo, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                parts = raw.split(b'/')
                for component in parts[:-1]:
                    child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                    dir_fd=source)
                    os.close(source)
                    source = child
                fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                             dir_fd=source)
                try:
                    expected_size, expected_digest = records[raw]
                    opened = os.fstat(fd)
                    if (not stat.S_ISREG(opened.st_mode) or opened.st_size != expected_size or
                            expected_size > SOURCE_MAX_FILE_BYTES):
                        raise ValueError('Source changed before staging')
                    copied = 0
                    digest = hashlib.sha256()
                    with target.open('xb') as output:
                        while copied < expected_size:
                            if time.monotonic() > copy_deadline:
                                raise ValueError('Source staging timed out')
                            chunk = os.read(fd, min(65536, expected_size - copied))
                            if not chunk:
                                raise ValueError('Source shortened during staging')
                            copied += len(chunk)
                            copied_total += len(chunk)
                            if copied_total > SOURCE_MAX_TOTAL_BYTES:
                                raise ValueError('Source staging exceeds byte budget')
                            digest.update(chunk)
                            output.write(chunk)
                            _source_progress(size=len(chunk))
                    if (os.read(fd, 1) or _stable(opened) != _stable(os.fstat(fd)) or
                            digest.hexdigest() != expected_digest):
                        raise ValueError('Source changed during staging')
                    _source_progress(files=1)
                finally:
                    os.close(fd)
            finally:
                os.close(source)
        for path, data in overlay_files.items():
            if data is None:
                continue
            target = destination / path
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            target.write_bytes(data)
        staged = source_identity(destination, provider='filesystem')
        if staged['worktree'] != identity['source_effective_digest'] or source_identity(
                repo, provider='filesystem', overlay_path=overlay_path) != identity:
            raise ValueError('Source changed while staging; rebuild required')
        return identity
    except BaseException:
        shutil.rmtree(destination)
        raise


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
    if (identity.get('freshness') not in (POLICY, FILESYSTEM_POLICY, OVERLAY_POLICY) or
            not isinstance(identity.get('head'), str) or not HEAD.fullmatch(identity['head']) or
            any(not isinstance(identity.get(key), str) or not HEX64.fullmatch(identity[key])
                for key in ('worktree', 'worktree_v2'))):
        raise ValueError('Invalid expected source identity')
    if identity['freshness'] != POLICY:
        keys = {'head', 'worktree', 'worktree_v2', 'freshness', 'source_provider',
                'source_disk_digest', 'source_effective_digest'}
        overlay = identity['freshness'] == OVERLAY_POLICY
        if overlay:
            keys |= {'source_overlay', 'source_overlay_digest'}
        if (set(identity) != keys or identity['head'] != '0' * 64 or
                identity.get('source_provider') != 'filesystem' or
                any(not isinstance(identity.get(key), str) or not HEX64.fullmatch(identity[key])
                    for key in ('source_disk_digest', 'source_effective_digest')) or
                identity['worktree'] != identity['worktree_v2']):
            raise ValueError('Invalid filesystem source identity')
        if overlay:
            if (not isinstance(identity.get('source_overlay'), str) or
                    not Path(identity['source_overlay']).is_absolute() or
                    not isinstance(identity.get('source_overlay_digest'), str) or
                    not HEX64.fullmatch(identity['source_overlay_digest'])):
                raise ValueError('Invalid overlay source identity')
            expected = hashlib.sha256(b'qihse-overlay-content-v1\0' +
                identity['source_disk_digest'].encode() + b'\0' +
                identity['source_overlay_digest'].encode() + b'\0' +
                identity['source_effective_digest'].encode() + b'\0').hexdigest()
        else:
            if identity['source_disk_digest'] != identity['source_effective_digest']:
                raise ValueError('Invalid filesystem source digest')
            expected = identity['source_disk_digest']
        if identity['worktree'] != expected:
            raise ValueError('Invalid source content binding')
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
                    (identity['freshness'] == POLICY and
                     (header.get('head') != identity['head'] or header.get('worktree') != identity['worktree']))):
                raise ValueError('Export header/source identity mismatch')
            for key in (() if identity['freshness'] != POLICY else ('freshness', 'worktree_v2')):
                if key in header and header[key] != identity[key]:
                    raise ValueError('Conflicting export v2 identity')
            if ('freshness' in header) != ('worktree_v2' in header):
                raise ValueError('Incomplete export v2 identity')
            header.update(identity)
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
