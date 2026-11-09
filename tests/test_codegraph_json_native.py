#!/usr/bin/env python3
"""Native JSON admission regressions using a disposable unclassified graph."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    'codegraph_json_native_source', ROOT/'tools/qihse_codegraph_reindex_source.py')
source = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(source)


def encode(value):
    return json.dumps(value, ensure_ascii=False, separators=(',', ':')).encode('utf-8')


def prefix(encoded_object, field):
    assert encoded_object.startswith(b'{') and field.endswith(b',')
    return b'{' + field + encoded_object[1:]


def run(binary, library_dir):
    started = time.monotonic()
    cases = []
    with tempfile.TemporaryDirectory(prefix='codegraph-json-native-') as temporary:
        root = Path(temporary)
        repo = root/'non-git-unicode'
        repo.mkdir()
        (repo/'λ.py').write_text('def λ_symbol():\n    return 7\n', encoding='utf-8')
        state = root/'state'
        env = os.environ.copy()
        env['XDG_STATE_HOME'] = str(state)
        env['LD_LIBRARY_PATH'] = str(library_dir) + os.pathsep + env.get('LD_LIBRARY_PATH', '')
        identity = source.source_identity(repo, provider='filesystem')
        header = dict(t='h', format='qihse-codegraph-v1', version=1, **identity)
        node = dict(t='n', id=hashlib.sha256(b'unicode native JSON fixture').hexdigest(),
                    file='λ.py', name='λ_symbol', kind='Function', line_start=1,
                    line_end=2, is_test=False, unknown={'text': 'quotes " : , } [ λ'})
        header_bytes, node_bytes = encode(header), encode(node)
        export = root/'input.jsonl'

        def invoke(arguments, expected=0, case=None):
            result = subprocess.run([str(binary), *arguments, '--repo', str(repo)],
                                    env=env, text=True, capture_output=True, timeout=120)
            assert result.returncode == expected, (
                case or arguments, expected, result.returncode, result.stdout, result.stderr)
            rows = result.stdout.strip().splitlines()
            assert len(rows) == 1, (arguments, result.stdout, result.stderr)
            response = json.loads(rows[0])
            if expected:
                assert 'error' in response, response
                assert 'λ_symbol' not in result.stdout, 'Rejected operation disclosed graph data'
            return response

        def write_export(h=header_bytes, n=node_bytes, trailer_prefix=b'', trailer_suffix=b''):
            body = h+b'\n'+n+b'\n'
            trailer = encode(dict(t='end', nodes=1, edges=0, unresolved_edges=0,
                                  sha256=hashlib.sha256(body).hexdigest()))
            if trailer_prefix:
                trailer = prefix(trailer, trailer_prefix)
            export.write_bytes(body+trailer+trailer_suffix+b'\n')

        write_export()
        invoke(['import', '--input', str(export)])
        response = invoke(['query', '--symbol', 'λ_symbol'])
        assert response['shown_nodes'] == 1, response
        cases.append('valid Unicode filename, symbol and escaped quote payload')
        directory = state/'qihse/codegraph'/hashlib.sha256(str(repo.resolve()).encode()).hexdigest()
        manifest = directory/'current.json'
        original = manifest.read_bytes()
        snapshots = {p.name for p in directory.glob('graph-*.kv')}
        admission_cases = [
            ('duplicate freshness', prefix(header_bytes, b'"freshness":"invalid-policy",'), node_bytes, b'', b''),
            ('escaped freshness alias', prefix(header_bytes, b'"\\u0066reshness":"invalid-policy",'), node_bytes, b'', b''),
            ('duplicate header type', prefix(header_bytes, b'"t":"e",'), node_bytes, b'', b''),
            ('duplicate node type', header_bytes, prefix(node_bytes, b'"t":"h",'), b'', b''),
            ('duplicate node ID', header_bytes, prefix(node_bytes, b'"id":"'+b'0'*64+b'",'), b'', b''),
            ('escaped node ID alias', header_bytes, prefix(node_bytes, b'"\\u0069d":"'+b'0'*64+b'",'), b'', b''),
            ('raw NUL header tail', header_bytes+b'\0ignored', node_bytes, b'', b''),
            ('raw NUL node tail', header_bytes, node_bytes+b'\0ignored', b'', b''),
            ('raw NUL trailer tail', header_bytes, node_bytes, b'', b'\0ignored'),
            ('trailing header junk', header_bytes+b' junk', node_bytes, b'', b''),
            ('trailing header object', header_bytes+b'{}', node_bytes, b'', b''),
            ('trailing node object', header_bytes, node_bytes+b'{}', b'', b''),
            ('duplicate trailer count', header_bytes, node_bytes, b'"nodes":99999,', b''),
        ]
        for label, h, n, trailer_prefix, trailer_suffix in admission_cases:
            write_export(h, n, trailer_prefix, trailer_suffix)
            invoke(['import', '--input', str(export)], expected=1, case=label)
            assert manifest.read_bytes() == original, label+' modified current generation'
            assert {p.name for p in directory.glob('graph-*.kv')} == snapshots, label+' leaked snapshot'
            cases.append(label+' denied without publication')
        assert invoke(['query', '--symbol', 'λ_symbol'])['shown_nodes'] == 1
        values = json.loads(original)
        assert 'snapshot_hash' in values and 'snapshot_hash_algorithm' in values, values
        manifest_cases = [
            ('duplicate snapshot checksum', prefix(original.lstrip(), b'"snapshot_hash":"'+b'0'*32+b'",')),
            ('escaped checksum alias', prefix(original.lstrip(), b'"snapshot\\u005fhash":"'+b'0'*32+b'",')),
            ('duplicate checksum algorithm', prefix(original.lstrip(), b'"snapshot_hash_algorithm":"invalid",')),
            ('duplicate storage format', prefix(original.lstrip(), b'"storage_format":"invalid",')),
            ('duplicate node count', prefix(original.lstrip(), b'"nodes":99999,')),
            ('escaped node count alias', prefix(original.lstrip(), b'"\\u006eodes":99999,')),
            ('manifest raw NUL tail', original+b'\0ignored'),
            ('manifest trailing object', original+b'{}'),
            ('manifest trailing junk', original+b' junk'),
        ]
        for label, damaged in manifest_cases:
            try:
                manifest.write_bytes(damaged)
                invoke(['query', '--symbol', 'λ_symbol'], expected=1, case=label)
                assert {p.name for p in directory.glob('graph-*.kv')} == snapshots, label+' changed snapshots'
                cases.append(label+' denied')
            finally:
                manifest.write_bytes(original)
        assert invoke(['query', '--symbol', 'λ_symbol'])['shown_nodes'] == 1
        cases.append('previous valid graph remains queryable after restoration')
        # Strictness targets top-level ambiguity; unknown nested payloads retain
        # the established json-c interpretation without a recursive duplicate-key policy.
        write_export(prefix(header_bytes, b'"unknown_nested":{"same":1,"same":2},'))
        invoke(['import', '--input', str(export)])
        assert invoke(['query', '--symbol', 'λ_symbol'])['shown_nodes'] == 1
        cases.append('unknown nested duplicate payload retains existing acceptance')
    report = {'native_json_checks': len(cases), 'cases': cases,
              'seconds': round(time.monotonic()-started, 3)}
    print(json.dumps(report, ensure_ascii=False, sort_keys=True))
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=ROOT/'qihse-codegraph')
    parser.add_argument('--library-dir', type=Path, default=ROOT)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    if not binary.is_file():
        parser.error('binary must be a regular executable file')
    run(binary, args.library_dir.resolve(strict=True))


if __name__ == '__main__':
    main()
