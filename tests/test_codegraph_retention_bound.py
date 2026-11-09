#!/usr/bin/env python3
"""Bound CodeGraph generations across publication, reuse and failure.

Uses disposable source and state. It examines generation names and private
fixture manifest metadata; it never opens snapshot record payloads directly.
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time

from test_codegraph_native import git, snapshot, write_records


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--expect-checksum', choices=('xxh3-128',))
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix='qihse-retention-bound-') as temporary:
        root = Path(temporary)
        repo = root / 'repo'
        (repo / 'src').mkdir(parents=True)
        (repo / 'tests').mkdir()
        clean = 'int target(void) { return 1; }\n'
        tracked = repo / 'src/a.c'
        tracked.write_text(clean)
        (repo / 'src/b.c').write_text('int caller(void) { return target(); }\n')
        (repo / 'tests/test_a.c').write_text('void test_target(void) {}\n')
        git(repo, 'init', '-q')
        git(repo, 'add', '.')
        git(repo, '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
            'commit', '-qm', 'fixture')
        source = root / 'source.jsonl'
        env = dict(os.environ, XDG_STATE_HOME=str(root / 'state'),
                   LD_LIBRARY_PATH=str(binary.parent) + os.pathsep +
                                   os.environ.get('LD_LIBRARY_PATH', ''))
        directory = root / 'state/qihse/codegraph' / hashlib.sha256(os.fsencode(repo)).hexdigest()
        manifest_path = directory / 'current.json'

        def invoke(*tokens: str, expect: int = 0) -> dict:
            process = subprocess.run([str(binary), *tokens, '--repo', str(repo)], env=env,
                                     capture_output=True, text=True, timeout=120)
            assert process.returncode == expect, (tokens, process.returncode,
                                                   process.stdout, process.stderr)
            return json.loads(process.stdout)

        def manifest() -> dict:
            return json.loads(manifest_path.read_text())

        def generations() -> set[str]:
            return {p.name for p in directory.glob('graph-*.kv') if p.is_file()}

        def assert_exact_retention(expected: dict) -> None:
            names = {expected['snapshot']}
            if expected.get('previous_snapshot'):
                names.add(expected['previous_snapshot'])
            assert len(names) <= 2
            assert generations() == names, (generations(), names)
            assert not [p.name for p in directory.iterdir()
                        if '.codec-' in p.name or p.name.startswith(('.snapshot-', '.codegraph-codec-'))]

        prior = None
        for generation in range(4):
            tracked.write_text(clean + f'/* generation {generation} */\n')
            snapshot(repo, source)
            result = invoke('import', '--input', str(source), '--storage-format', 'packed-v3')
            assert result['status'] == 'published', result
            current = manifest()
            if prior is not None:
                assert current['previous_snapshot'] == prior
            if args.expect_checksum:
                assert current['snapshot_hash_algorithm'] == args.expect_checksum, current
                assert len(current['snapshot_hash']) == 32, current
                assert 'sha256' not in current, current
            assert_exact_retention(current)
            prior = current['snapshot']
        retained = manifest()
        baseline_names = generations()
        baseline_source = tracked.read_text()
        valid_input = source.read_bytes()

        # Repeated precommit failures must not accumulate new unmanaged generations.
        saved_manifest = directory / '.retention-manifest-fixture'
        manifest_path.rename(saved_manifest)
        manifest_path.mkdir()
        try:
            for attempt in range(2):
                tracked.write_text(clean + f'/* rejected publication {attempt} */\n')
                snapshot(repo, source)
                failed = invoke('import', '--input', str(source), '--storage-format', 'packed-v3',
                                expect=1)
                assert 'publication' in failed['error'], failed
                assert generations() == baseline_names, (attempt, generations(), baseline_names)
        finally:
            manifest_path.rmdir()
            saved_manifest.rename(manifest_path)
            tracked.write_text(baseline_source)
            source.write_bytes(valid_input)
        assert manifest() == retained
        assert_exact_retention(retained)

        # A malformed input must preserve both published generations too.
        rows = [json.loads(line) for line in valid_input.splitlines()]
        rows[1]['id'] = 'invalid'
        write_records(source, rows)
        invoke('import', '--input', str(source), expect=1)
        source.write_bytes(valid_input)
        assert manifest() == retained
        assert_exact_retention(retained)

        # Validated no-op publication collects obsolete managed generations and
        # abandoned leases, while leaving an active lease and unrelated data alone.
        orphan = directory / ('graph-' + 'f' * 64 + '-ORPHAN.kv')
        orphan.write_bytes(b'synthetic obsolete generation')
        abandoned = directory / '.runtime-retention-abandoned'
        abandoned.mkdir(mode=0o700)
        (abandoned / '.lease').touch(mode=0o600)
        (abandoned / 'snapshot.tmp.codec-fixture').write_bytes(b'reclaim')
        active = directory / '.runtime-retention-active'
        active.mkdir(mode=0o700)
        (active / '.lease').touch(mode=0o600)
        unmanaged = directory / 'unrelated-fixture'
        unmanaged.write_bytes(b'preserve')
        with (active / '.lease').open('r+') as lease:
            fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
            unchanged = invoke('import', '--input', str(source))
            assert unchanged['status'] == 'unchanged', unchanged
            assert unchanged['removed_snapshots'] == 1, unchanged
            assert not abandoned.exists() and active.exists() and unmanaged.exists()
            assert manifest() == retained
            assert_exact_retention(retained)
        collected = invoke('gc')
        assert collected['status'] == 'collected', collected
        assert not active.exists() and unmanaged.exists()
        assert_exact_retention(retained)

        before = invoke('stats')['encoded_bytes']
        converted = invoke('migrate')
        assert converted['status'] in ('unchanged', 'migrated'), converted
        assert invoke('stats')['encoded_bytes'] <= before
        assert_exact_retention(manifest())
        same = invoke('migrate', '--storage-format', manifest()['storage_format'].removeprefix('qihse-codegraph-'))
        assert same['status'] == 'unchanged', same
        assert_exact_retention(manifest())
        assert invoke('query', '--symbol', 'caller', '--match', 'exact')['nodes']
        print(json.dumps({'four_publications': True, 'retained_generations': len(generations()),
                          'precommit_failures_without_growth': 2, 'malformed_input_preserved': True,
                          'unchanged_and_gc_cleanup': True, 'migration_no_growth': True,
                          'elapsed_seconds': round(time.monotonic()-started, 3)}))


if __name__ == '__main__':
    main()
