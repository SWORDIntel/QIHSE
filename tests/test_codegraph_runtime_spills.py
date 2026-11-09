#!/usr/bin/env python3
"""Prove large active CodeGraph readers shed decoded SST/WAL copies.

Only disposable source/state are used. Optional --baseline measures the same
snapshot through the preceding reader; metadata scans never read KV payloads.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time

from test_codegraph_native import git, node_id, snapshot


def make_large(repo: Path, target: Path, count: int) -> tuple[int, int]:
    snapshot(repo, target)
    initial = [json.loads(line) for line in target.read_text().splitlines()]
    nodes = [r for r in initial if r['t'] == 'n']
    digest = hashlib.sha256()
    with target.open('wb') as output:
        def row(value: dict) -> None:
            encoded = (json.dumps(value, sort_keys=True, separators=(',', ':'))+'\n').encode()
            digest.update(encoded); output.write(encoded)
        row(initial[0])
        for node in nodes: row(node)
        for index in range(count):
            row({'t': 'e', 'id': f'{index+100000:064x}', 'source': node_id('caller'),
                 'target': node_id('target'), 'relation': 'CALLS', 'file': 'fixture.c',
                 'line': index+1, 'confidence': 1.0, 'tier': 'EXTRACTED',
                 'resolution': 'direct', 'traversable': True,
                 'extension': 'uninterpreted-metadata-'+'x'*300})
        trailer = {'t': 'end', 'nodes': len(nodes), 'edges': count,
                   'unresolved_edges': 0, 'sha256': digest.hexdigest()}
        output.write((json.dumps(trailer, sort_keys=True, separators=(',', ':'))+'\n').encode())
    return len(nodes), count


def spill_metadata(runtime: Path) -> dict:
    directory = runtime/'decoded-store'
    if not directory.is_dir(): directory = runtime
    files = [p for p in directory.iterdir() if
             (p.name in ('wal.log', 'restore-highwater.bin', 'replica-cursors.bin') or
              re.fullmatch(r'sstable_[0-9]+\.db', p.name)) and p.is_file() and not p.is_symlink()]
    return {'logical_bytes': sum(p.stat().st_size for p in files),
            'allocated_bytes': sum(p.stat().st_blocks*512 for p in files),
            'files': len(files)}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--baseline', type=Path)
    parser.add_argument('--edges', type=int, default=150010)
    args = parser.parse_args()
    assert args.edges >= 150000, 'exercise both bounded immutable-load thresholds'
    binary = args.binary.resolve(strict=True)
    baseline = args.baseline.resolve(strict=True) if args.baseline else None
    with tempfile.TemporaryDirectory(prefix='codegraph-runtime-spills-') as temporary:
        root = Path(temporary)
        repo = root/'repo'; repo.mkdir()
        (repo/'fixture.c').write_text('int fixture(void) { return 1; }\n')
        git(repo, 'init', '-q'); git(repo, 'add', '.')
        git(repo, '-c', 'user.name=Fixture', '-c', 'user.email=test@example.invalid',
            'commit', '-qm', 'synthetic')
        env = {**os.environ, 'XDG_STATE_HOME': str(root/'state'),
               'LD_LIBRARY_PATH': str(binary.parent)+os.pathsep+
               os.environ.get('LD_LIBRARY_PATH', '')}
        directory = root/'state/qihse/codegraph'/hashlib.sha256(os.fsencode(repo)).hexdigest()
        source = root/'graph.jsonl'
        nodes, edges = make_large(repo, source, args.edges)
        large_source_bytes = source.stat().st_size
        assert large_source_bytes > 64 << 20
        started = time.monotonic()
        imported = subprocess.run([str(binary), 'import', '--repo', str(repo), '--input', str(source),
                                   '--storage-format', 'zstd-v1'], env=env,
                                  text=True, capture_output=True, timeout=900)
        assert imported.returncode == 0, (imported.returncode, imported.stdout, imported.stderr)
        import_seconds = time.monotonic()-started
        print(json.dumps({'phase': 'imported', 'source_bytes': source.stat().st_size,
                          'import_seconds': import_seconds}), flush=True)
        measurements = {}
        answers = {}
        for name, executable in [('baseline', baseline), ('candidate', binary)]:
            if executable is None: continue
            sock, token = root/(name+'.sock'), root/(name+'.token')
            with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
                process = subprocess.Popen([str(executable), 'serve', '--repo', str(repo),
                    '--socket', str(sock), '--token-file', str(token),
                    '--idle-seconds', '30' if name == 'candidate' else '2',
                    '--workers', '1', '--memory-limit-mib', '2048',
                    '--pool-file', str(root/(name+'.pool')), '--pool-budget-mib', '4096'],
                    env=env, stdout=stdout, stderr=stderr)
                try:
                    deadline = time.monotonic()+300
                    delay = 0.05
                    while not sock.exists() or not token.exists():
                        if process.poll() is not None or time.monotonic() >= deadline:
                            stdout.seek(0); stderr.seek(0)
                            raise AssertionError((name, 'reader failed', process.poll(),
                                                  stdout.read(), stderr.read()))
                        time.sleep(delay); delay = min(2, delay*1.5)
                    result = subprocess.run([str(executable), 'context', '--repo', str(repo),
                        '--symbol', 'target', '--depth', '1', '--socket', str(sock),
                        '--token-file', str(token), '--max-tokens', '4000'], env=env,
                        text=True, capture_output=True, timeout=120)
                    assert result.returncode == 0, (name, result.stdout, result.stderr)
                    answer = json.loads(result.stdout)
                    assert answer['nodes'] and any(n['symbol'] == 'target' for n in answer['nodes'])
                    answers[name] = {k: answer.get(k) for k in
                                     ('nodes', 'evidence', 'truncated', 'seed_nodes', 'affected_files')}
                    runtimes = [p for p in directory.glob('.runtime-*') if p.is_dir()]
                    assert len(runtimes) == 1, runtimes
                    measured = spill_metadata(runtimes[0])
                    measurements[name] = measured
                    print(json.dumps({'phase': name, 'spill_metadata': measured}), flush=True)
                    if name == 'candidate':
                        assert measured['files'] == 0 and measured['logical_bytes'] == 0, measured
                        decoded = runtimes[0]/'decoded-store'
                        assert (decoded/'qihse_audit.log').exists(), 'audit must remain active'
                        assert (runtimes[0]/'.lease').exists(), 'active lease must remain'
                        assert answer['runtime_spill_reclaimed_bytes'] > 64 << 20, answer
                        assert answer['runtime_spill_reclaimed_files'] > 0
                        # Repeated reader query after handoff still sees the graph.
                        again = subprocess.run(result.args, env=env, text=True,
                                               capture_output=True, timeout=120)
                        assert again.returncode == 0, (again.stdout, again.stderr)
                        assert json.loads(again.stdout)['nodes'] == answer['nodes']
                        # A real generation refresh holds graph_api_lock. The
                        # post-CSR cleanup must not recursively lock it or replay
                        # old decoded SST state into the replacement generation.
                        snapshot(repo, source)
                        replaced = subprocess.run([str(binary), 'import', '--repo', str(repo),
                            '--input', str(source)], env=env, text=True, capture_output=True,
                            timeout=120)
                        assert replaced.returncode == 0, (replaced.stdout, replaced.stderr)
                        refreshed = subprocess.run(result.args, env=env, text=True,
                                                   capture_output=True, timeout=30)
                        if refreshed.returncode:
                            stderr.seek(0)
                            raise AssertionError((refreshed.stdout, refreshed.stderr,
                                                  process.poll(), stderr.read()))
                        refreshed_answer = json.loads(refreshed.stdout)
                        assert refreshed_answer['edges'] == 5, refreshed_answer
                        assert refreshed_answer['generation'] != answer['generation']
                        assert spill_metadata(runtimes[0])['files'] == 0
                finally:
                    try:
                        process.wait(timeout=45)  # normal idle shutdown invokes graph_close
                    except subprocess.TimeoutExpired:
                        process.kill(); process.wait(timeout=10)
                        raise AssertionError('reader did not exit on idle timeout')
            assert not list(directory.glob('.runtime-*')), 'reader must clean up on exit'
        if baseline:
            assert measurements['baseline']['logical_bytes'] > 64 << 20, measurements
            assert answers['baseline'] == answers['candidate'], (answers['baseline'], answers['candidate'])
        print(json.dumps({'fixture_source_bytes': large_source_bytes,
                          'nodes': nodes, 'edges': edges, 'import_seconds': import_seconds,
                          'measurements': measurements, 'query_parity': bool(baseline),
                          'active_audit_and_lease_preserved': True, 'resident_refresh_passed': True}))


if __name__ == '__main__': main()
