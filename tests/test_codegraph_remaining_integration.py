#!/usr/bin/env python3
"""Exercise the remaining CodeGraph features together on disposable graphs."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

from test_codegraph_native import git, snapshot


def check(binary: Path) -> dict:
    with tempfile.TemporaryDirectory(prefix='qcg-remaining-integration-') as temp:
        root = Path(temp)
        repo = root / 'repo'
        repo.mkdir()
        for name in ('src/a.c', 'src/b.c', 'src/leaf.c', 'src/dep.c',
                     'src/other.c', 'tests/test_a.c'):
            path = repo / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('int fixture(void) { return 0; }\n')
        git(repo, 'init', '-q')
        git(repo, 'add', '.')
        git(repo, '-c', 'user.name=Fixture', '-c',
            'user.email=fixture@example.invalid', 'commit', '-qm', 'fixture')
        source = root / 'graph.jsonl'
        state = root / 'state'
        env = {**os.environ, 'XDG_STATE_HOME': str(state),
               'LD_LIBRARY_PATH': str(binary.parent) + os.pathsep +
                                  os.environ.get('LD_LIBRARY_PATH', '')}
        directory = state / 'qihse/codegraph' / hashlib.sha256(os.fsencode(repo)).hexdigest()

        def invoke(*args, expected=0):
            result = subprocess.run([str(binary), *args, '--repo', str(repo)],
                                    capture_output=True, text=True, env=env, timeout=180)
            assert result.returncode == expected, (args, result.returncode,
                                                    result.stdout, result.stderr)
            return json.loads(result.stdout)

        def retained():
            current = json.loads((directory / 'current.json').read_bytes())
            keep = {current['snapshot']}
            if current.get('previous_snapshot'):
                keep.add(current['previous_snapshot'])
            assert {p.name for p in directory.glob('graph-*.kv')} == keep
            assert len(keep) <= 2
            assert all(p.name[:-4] in keep for p in directory.glob('graph-*.kv.qci'))
            return current

        comparable_keys = ('nodes', 'evidence', 'candidate_tests', 'test_gap_candidates',
                           'truncated', 'shown_nodes', 'seed_nodes', 'affected_files')
        reference = {}
        formats = ('packed-v3', 'packed-v4', 'generations-v1', 'zstd-v1', 'packed-v2')
        for version, encoding in enumerate(formats):
            (repo / 'src/a.c').write_text(f'int fixture(void) {{ return {version}; }}\n')
            snapshot(repo, source)
            result = invoke('import', '--input', str(source), '--storage-format', encoding)
            assert result['status'] == 'published', result
            manifest = retained()
            assert manifest['snapshot_hash_algorithm'] == 'xxh3-128', manifest
            assert len(manifest['snapshot_hash']) == 32
            assert invoke('stats')['snapshot_hash'] == manifest['snapshot_hash']
            for action in ('query', 'context', 'impact', 'review'):
                report = invoke(action, '--symbol', 'caller', '--depth', '2')
                comparable = {key: report.get(key) for key in comparable_keys}
                if not reference:
                    reference[action] = comparable
                elif action not in reference:
                    reference[action] = comparable
                else:
                    assert comparable == reference[action], (encoding, action, comparable)
            if encoding == 'generations-v1':
                invoke('query-index')
                blocks = sorted((directory / 'blocks').glob('*.qgb'))
                assert blocks
                block = blocks[0]
                original = block.read_bytes()
                try:
                    block.write_bytes(original[:-1] + bytes([original[-1] ^ 1]))
                    denied = subprocess.run(
                        [str(binary), 'query', '--symbol', 'caller', '--repo', str(repo)],
                        capture_output=True, text=True, env=env, timeout=180)
                    assert denied.returncode != 0, denied.stdout
                    assert '"nodes"' not in denied.stdout, denied.stdout
                finally:
                    block.write_bytes(original)
            unchanged = invoke('import', '--input', str(source))
            assert unchanged['status'] == 'unchanged', unchanged
            invoke('gc')
            retained()
        return {'formats': list(formats), 'ordered_query_parity': True,
                'typed_checksum': True, 'bounded_retention': True,
                'unchanged_import_and_gc': True}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(check(args.binary.resolve(strict=True)), sort_keys=True))
