#!/usr/bin/env python3
"""Disposable CodeGraph XXH3 snapshots, corruption rejection and bounded history."""
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
    with tempfile.TemporaryDirectory(prefix='codegraph-snapshot-xxh3-') as temporary:
        root = Path(temporary)
        repo = root / 'repo'; repo.mkdir(); git(repo, 'init', '-q')
        for name in ('src/a.c', 'src/b.c', 'src/leaf.c', 'src/dep.c', 'src/other.c',
                     'tests/test_a.c'):
            p = repo / name; p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text('int source(void) { return 1; }\n')
        git(repo, 'add', '.')
        git(repo, '-c', 'user.name=Fixture', '-c', 'user.email=test@example.invalid',
            'commit', '-qm', 'synthetic')
        env = dict(os.environ, XDG_STATE_HOME=str(root/'state'),
                   LD_LIBRARY_PATH=str(binary.parent)+os.pathsep+os.environ.get('LD_LIBRARY_PATH',''))
        directory = root/'state/qihse/codegraph'/hashlib.sha256(os.fsencode(repo)).hexdigest()
        manifest_path = directory/'current.json'
        source = root/'graph.jsonl'

        def invoke(*args, expect=0):
            result = subprocess.run([str(binary), *args, '--repo', str(repo)], env=env,
                                    text=True, capture_output=True, timeout=120)
            assert result.returncode == expect, (args, result.returncode, result.stdout, result.stderr)
            return json.loads(result.stdout)

        def generations():
            return {p.name for p in directory.glob('graph-*.kv')}

        def verify_manifest():
            data = json.loads(manifest_path.read_bytes())
            assert data['snapshot_hash_algorithm'] == 'xxh3-128', data
            assert len(data['snapshot_hash']) == 32 and data['snapshot_hash'].islower(), data
            assert 'sha256' not in data and len(data['input_sha256']) == 64, data
            kept = {data['snapshot']}
            if data.get('previous_snapshot'): kept.add(data['previous_snapshot'])
            assert generations() == kept and len(kept) <= 2, (data, generations())
            return data

        previous = None
        for version, encoding in enumerate(('packed-v3','packed-v3','zstd-v1','packed-v2')):
            (repo/'src/a.c').write_text(f'int source(void) {{ return {version}; }}\n')
            snapshot(repo, source)
            receipt = invoke('import', '--input', str(source), '--storage-format', encoding)
            assert receipt['snapshot_hash_algorithm'] == 'xxh3-128', receipt
            data = verify_manifest()
            if previous: assert data['previous_snapshot'] == previous['snapshot'], data
            previous = data
        assert len(generations()) == 2
        stats = invoke('stats')
        assert stats['snapshot_hash_algorithm'] == 'xxh3-128'
        assert stats['snapshot_hash'] == previous['snapshot_hash']
        assert invoke('query','--symbol','caller','--match','exact')['nodes']

        # Validated unchanged imports also collect obsolete managed generations.
        obsolete = directory / ('graph-'+'f'*64+'-12345.kv')
        obsolete.write_bytes(b'synthetic obsolete snapshot')
        unchanged = invoke('import','--input',str(source))
        assert unchanged['status'] == 'unchanged' and not obsolete.exists(), unchanged
        verify_manifest()

        # A pre-commit manifest failure must not leave another managed generation.
        retained = manifest_path.read_bytes(); before = generations()
        manifest_path.unlink(); manifest_path.mkdir()
        for _ in range(3):
            invoke('import','--input',str(source),'--storage-format','packed-v3',expect=1)
            assert generations() == before, (generations(),before)
        manifest_path.rmdir(); manifest_path.write_bytes(retained); manifest_path.chmod(0o600)
        verify_manifest()

        # Corruption must be rejected before exposing graph payload.
        data = json.loads(retained); active = directory/data['snapshot']
        saved = active.read_bytes(); broken = bytearray(saved); broken[-1] ^= 1
        active.write_bytes(broken)
        denied = invoke('stats',expect=1)
        assert set(denied) == {'error'}, denied
        active.write_bytes(saved)
        invalid = []
        for change in ({'snapshot_hash_algorithm':'unknown'},
                       {'snapshot_hash_algorithm':'xxh3-128\0suffix'},
                       {'snapshot_hash':data['snapshot_hash']+'\0suffix'},
                       {'sha256':'0'*64}):
            manifest_path.write_text(json.dumps(dict(data,**change)))
            denied = invoke('stats',expect=1)
            assert set(denied) == {'error'}, denied
            invalid.append(next(iter(change)))
        manifest_path.write_bytes(retained)
        assert invoke('stats')['snapshot_hash'] == data['snapshot_hash']
        return {'snapshot_algorithm':'xxh3-128','retention':'current+one_previous',
                'four_publications':True,'unchanged_prunes':True,
                'precommit_failures_do_not_leak':True,'corruption_denied':True,
                'invalid_checksum_metadata_denied':invalid,'source_sha256_preserved':True}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary',type=Path,required=True)
    args=parser.parse_args()
    print(json.dumps(check(args.binary.resolve(strict=True)),sort_keys=True))

if __name__=='__main__': main()
