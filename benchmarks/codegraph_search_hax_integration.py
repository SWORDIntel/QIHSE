#!/usr/bin/env python3
"""Exercise real HAX tools against a real native graph; only the LLM driver is scripted."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import resource
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--hax-root', type=Path, required=True)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--repo', type=Path, required=True)
    parser.add_argument('--export', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--hax-binary', type=Path)
    parser.add_argument('--backend-wrapper', type=Path)
    args = parser.parse_args()
    hax_root, repo = args.hax_root.resolve(), args.repo.resolve()
    sys.path.insert(0, str(hax_root / 'tests/e2e'))
    import harness

    root = Path(tempfile.mkdtemp(prefix='codegraph-hax-real-'))
    home, binaries, runtime = root / 'home', root / 'bin', root / 'runtime'
    wrappers = root / 'wrappers'
    for directory in (home, binaries, runtime, wrappers):
        directory.mkdir(mode=0o700)
    binary = args.binary.resolve()
    for name in ('qihse-codegraph', 'libqihse.so'):
        shutil.copy2(binary.parent / name, binaries / name)
    backend = args.backend_wrapper.resolve() if args.backend_wrapper else binaries / 'qihse-codegraph'
    hax_binary = args.hax_binary.resolve() if args.hax_binary else hax_root / 'build/hax'
    expected_image = binary if args.backend_wrapper else binaries / 'qihse-codegraph'
    invocation_log = root / 'native-invocations.txt'
    wrapper = wrappers / 'qihse-codegraph'
    wrapper.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "' + str(invocation_log) +
                       '"\nexec "' + str(backend) + '" "$@"\n')
    wrapper.chmod(0o755)
    context = {'query': 'get_all_nodes get_all_edges', 'path': '.', 'mode': 'trace',
               'seeds': ['get_all_nodes', 'get_all_edges'], 'include': ['definitions'], 'max_tokens': 4000}
    calls = [('code_context', context),
             ('graph_query', {'symbol': 'get_all_nodes', 'depth': 1, 'limit': 8, 'max_tokens': 4000}),
             ('graph_impact', {'path': 'code_review_graph/graph.py', 'depth': 1, 'limit': 8,
                               'max_tokens': 4000}),
             ('graph_review', {'path': 'code_review_graph/graph.py', 'depth': 1, 'limit': 8,
                               'max_tokens': 4000}),
             ('code_context', context)]
    script = ''.join(f'tool {name} {json.dumps(fields)}\nend-turn\n' for name, fields in calls)
    script += 'text Done\n'
    env = harness.mock_env(home, script, {
        'PATH': str(wrappers) + os.pathsep + str(binaries) + os.pathsep + os.environ['PATH'],
        'LD_LIBRARY_PATH': str(binaries), 'XDG_RUNTIME_DIR': str(runtime),
        'HAX_AUTO_INDEX': '0', 'HAX_AUTO_WATCH': '0', 'HAX_NO_SESSION': '0',
        'HAX_TRANSCRIPT': str(root / 'transcript.txt'),
    })
    receipt = {'schema': 'hax.codegraph.integration.v1', 'root': str(root), 'repo': str(repo),
               'qihse_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
               'library_sha256': hashlib.sha256((binary.parent / 'libqihse.so').read_bytes()).hexdigest(),
               'hax_sha256': hashlib.sha256(hax_binary.read_bytes()).hexdigest(),
               'export_sha256': hashlib.sha256(args.export.read_bytes()).hexdigest(),
               'driver': 'mock provider; actual compiled tools, native CLI/socket and source files',
               'status': 'failed'}
    try:
        imported = subprocess.run([str(backend), 'import', '--repo', str(repo),
                                   '--input', str(args.export.resolve())], env=env, cwd=repo,
                                  capture_output=True, text=True, timeout=90, check=False)
        assert imported.returncode == 0, (imported.stdout, imported.stderr)
        receipt['import'] = json.loads(imported.stdout)
        start = time.monotonic()
        completed = subprocess.run([str(hax_binary), '-p',
                                    'Verify context with the scripted real native tools.'],
                                   env=env, cwd=repo, capture_output=True, text=True, timeout=150,
                                   check=False)
        receipt['wall_ms'] = (time.monotonic() - start) * 1000
        (root / 'stdout.txt').write_text(completed.stdout)
        (root / 'stderr.txt').write_text(completed.stderr)
        assert completed.returncode == 0, completed.stderr
        session = next((home / '.local/state/hax/sessions').glob('**/*.jsonl'))
        results = [json.loads(line) for line in session.read_text().splitlines()
                   if json.loads(line).get('kind') == 'tool_result']
        assert [item['tool_name'] for item in results] == [name for name, _ in calls]
        graphs = [json.loads(item['output']) for item in results if item['tool_name'] != 'code_context']
        assert all(item.get('fresh') is True and item.get('nodes') for item in graphs), graphs
        assert len({item['generation'] for item in graphs}) == 1, graphs
        assert all(any(node['file'] == 'code_review_graph/graph.py' for node in item['nodes'])
                   for item in graphs), graphs
        contexts = [json.loads(item['output']) for item in results if item['tool_name'] == 'code_context']
        assert all(item.get('citations') for item in contexts), contexts
        for item in contexts:
            text = '\n'.join(citation.get('text', '') for citation in item['citations'])
            assert 'def get_all_nodes(' in text and 'def get_all_edges(' in text, item
        node = next(node for node in graphs[0]['nodes'] if node['symbol'] == 'get_all_nodes')
        source = (repo / node['file']).read_text().splitlines()
        snippet = '\n'.join(source[node['line_start'] - 1:node['line_end']])
        assert 'def get_all_nodes(' in snippet, node
        endpoints = list((runtime / 'hax-codegraph').glob('reader-*.sock'))
        assert len(endpoints) == 1, 'resident path was not used'
        invocations = invocation_log.read_text().splitlines()
        starts = [i for i, line in enumerate(invocations)
                  if line.startswith('serve ') and '--help' not in line]
        assert len(starts) == 1, invocations
        before = invocations[:starts[0]]
        assert sum(line.startswith('context ') for line in before) == 2, invocations
        assert sum(line.startswith('query ') for line in before) == 1, invocations
        assert not any(line.startswith(('impact ', 'review ')) for line in invocations), invocations
        assert '--idle-seconds 600' in invocations[starts[0]], invocations
        assert '--memory-limit-mib 1024' in invocations[starts[0]], invocations
        with socket.socket(socket.AF_UNIX) as peer:
            peer.connect(str(endpoints[0]))
            pid, uid, _ = struct.unpack('3i', peer.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        assert uid == os.geteuid()
        memory_limit = resource.prlimit(pid, resource.RLIMIT_AS)
        assert memory_limit == (1 << 30, 1 << 30), memory_limit
        denied = subprocess.run([str(backend), 'serve', '--repo', str(repo),
            '--socket', str(runtime / 'denied.sock'), '--token-file', str(runtime / 'denied.token'),
            '--memory-limit-mib', '1024', '--pool-budget-mib', '1024',
            '--pool-file', str(runtime / 'hax-codegraph/resident.pool')], env=env,
            capture_output=True, text=True, timeout=5, check=False)
        assert denied.returncode == 1 and 'memory budget unavailable' in denied.stdout, denied
        receipt['promotion'] = {'hits': 3, 'window_seconds': 60, 'idle_seconds': 600,
                                'native_invocations': invocations, 'reader_pid': pid,
                                'address_space_limit_bytes': list(memory_limit),
                                'pool_denial_verified': True}
        # Another repository shares this runtime pool, but has its own demand and generation.
        # With the occupied 1-GiB reservation as its whole budget it must remain functional cold.
        second_repo = root / 'capacity-repo'
        subprocess.run(['git', 'clone', '--quiet', '--no-hardlinks', str(repo), str(second_repo)],
                       check=True, capture_output=True, text=True, timeout=30)
        second_import = subprocess.run([str(backend), 'import', '--repo',
            str(second_repo), '--input', str(args.export.resolve())], env=env,
            capture_output=True, text=True, timeout=90, check=False)
        assert second_import.returncode == 0, second_import
        capacity_script = root / 'capacity-script.txt'
        capacity_script.write_text('tool graph_query ' + json.dumps(calls[1][1]) +
                                   '\nend-turn\ntext Done\n')
        sessions = home / '.local/state/hax/sessions'
        existing = set(sessions.glob('**/*.jsonl'))
        capacity_env = {**env, 'HAX_MOCK_SCRIPT': str(capacity_script),
                        'HAX_GRAPH_READER_PROMOTION_HITS': '1',
                        'HAX_GRAPH_READER_BUDGET_MIB': '1024',
                        'HAX_TRANSCRIPT': str(root / 'capacity-transcript.txt')}
        capacity = subprocess.run([str(hax_binary), '-p', 'Verify capacity fallback.'],
            env=capacity_env, cwd=second_repo, capture_output=True, text=True, timeout=90, check=False)
        assert capacity.returncode == 0, capacity.stderr
        capacity_session, = set(sessions.glob('**/*.jsonl')) - existing
        capacity_results = [json.loads(line) for line in capacity_session.read_text().splitlines()
                            if json.loads(line).get('kind') == 'tool_result']
        assert len(capacity_results) == 1, capacity_results
        cold_result = json.loads(capacity_results[0]['output'])
        assert cold_result.get('fresh') is True and cold_result.get('nodes'), cold_result
        assert len(list((runtime / 'hax-codegraph').glob('reader-*.sock'))) == 1
        receipt['capacity_fallback'] = {'status': 'passed', 'repo': str(second_repo),
                                        'session': str(capacity_session), 'result': cold_result}
        receipt.update(status='passed', session=str(session), generation=graphs[0]['generation'],
                       source_example={**node, 'source': snippet},
                       tools=[{'name': item['tool_name'], 'output_bytes': len(item['output']),
                               'result': json.loads(item['output'])} for item in results])
    finally:
        # This runtime was empty before the run: terminate only its exact owned backend image.
        for endpoint in (runtime / 'hax-codegraph').glob('reader-*.sock'):
            try:
                with socket.socket(socket.AF_UNIX) as peer:
                    peer.connect(str(endpoint))
                    pid, uid, _ = struct.unpack('3i', peer.getsockopt(socket.SOL_SOCKET,
                                                                    socket.SO_PEERCRED, 12))
                if uid == os.geteuid() and Path(f'/proc/{pid}/exe').resolve() == expected_image.resolve():
                    os.kill(pid, signal.SIGTERM)
            except (OSError, ProcessLookupError):
                pass
        args.output.write_text(json.dumps(receipt, indent=2) + '\n')
    print(f"{receipt['status']}: {args.output}")


if __name__ == '__main__':
    main()
