#!/usr/bin/env python3
"""Exercise the bounded CodeGraph projection on synthetic authenticated graphs."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile

from test_codegraph_native import git, node_id, snapshot, write_records


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True, type=Path)
    parser.add_argument('--baseline', type=Path)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    baseline = args.baseline.resolve(strict=True) if args.baseline else None
    with tempfile.TemporaryDirectory(prefix='qcg-projection-') as temporary:
        root = Path(temporary)
        repo = root / 'repo'
        repo.mkdir()
        (repo / 'fixture.c').write_text('void caller(void) {}\n')
        git(repo, 'init', '-q')
        git(repo, 'add', '.')
        git(repo, '-c', 'user.name=ProjectionTest', '-c',
            'user.email=projection@example.invalid', 'commit', '-qm', 'fixture')
        source = root / 'graph.jsonl'
        snapshot(repo, source)
        initial = [json.loads(line) for line in source.read_text().splitlines()]
        header = initial[0]
        nodes = [row for row in initial if row['t'] == 'n']
        env = {**os.environ, 'XDG_STATE_HOME': str(root / 'state'),
               'LD_LIBRARY_PATH': str(binary.parent) + os.pathsep +
                                  os.environ.get('LD_LIBRARY_PATH', '')}

        def invoke(executable, action, *arguments):
            result = subprocess.run([str(executable), action, '--repo', str(repo), *arguments],
                                    env=env, capture_output=True, timeout=180, text=True)
            assert result.returncode == 0, (result.stdout, result.stderr)
            return json.loads(result.stdout)

        def publish(edges):
            write_records(source, [header, *nodes, *edges,
                                   {'t': 'end', 'nodes': len(nodes), 'edges': len(edges),
                                    'unresolved_edges': 0}])
            assert invoke(binary, 'import', '--input', str(source))['status'] == 'published'

        def edge(index, source='caller', target='caller', relation='REFERENCES'):
            return {'t': 'e', 'id': f'{index:064x}', 'source': node_id(source),
                    'target': node_id(target), 'relation': relation, 'file': 'fixture.c',
                    'line': index + 1, 'confidence': 1.0, 'tier': 'EXTRACTED',
                    'resolution': 'direct', 'traversable': True}

        def comparable(report):
            return {key: report.get(key) for key in
                    ('nodes', 'evidence', 'candidate_tests', 'test_gap_candidates',
                     'truncated', 'shown_nodes', 'seed_nodes', 'affected_files')}

        # A self-loop must not consume the incoming neighbor cap. A late
        # TESTED_BY edge must still be found by the type-filtered review pass.
        publish([*(edge(i) for i in range(4097)),
                 edge(4097, source='target', relation='CALLS'),
                 edge(4098, target='test', relation='TESTED_BY')])
        for action in ('query', 'context', 'impact', 'review'):
            result = invoke(binary, action, '--symbol', 'caller', '--depth', '1')
            assert result['truncated'], result
            assert {'caller', 'target'} <= {node['symbol'] for node in result['nodes']}, result
            if action == 'review':
                assert not any(gap['symbol'] == 'caller' for gap in result['test_gap_candidates'])
            if baseline:
                original = invoke(baseline, action, '--symbol', 'caller', '--depth', '1')
                assert comparable(result) == comparable(original), (action, result, original)

        # Filtered/self-loop edges consume the total examined-edge budget.
        # An exhausted review must not invent a missing-test hint when it has
        # not inspected the whole relation set.
        publish([edge(i) for i in range(65537)])
        result = invoke(binary, 'review', '--symbol', 'caller', '--depth', '1')
        assert result['truncated'], result
        assert [node['symbol'] for node in result['nodes']] == ['caller'], result
        assert not result['test_gap_candidates'], result
    print('CodeGraph projection bounds and filtered-order checks passed')


if __name__ == '__main__':
    main()
