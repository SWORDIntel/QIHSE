#!/usr/bin/env python3
"""Measure real CRG exports through cold CLI and authenticated resident CodeGraph.

Example (prepare once with the official CRG exporter, then reuse the exact root):
  codegraph_search.py --prepare /path/to/real/repo --crg /path/to/code-review-graph \
    --root /tmp/codegraph-bench --binary /preserved/qihse-codegraph --output baseline.json
  codegraph_search.py --root /tmp/codegraph-bench --binary /candidate/qihse-codegraph \
    --output candidate.json

Cold means a fresh CLI process/graph, NOT an evicted filesystem page cache. CPU and
RSS are process measurements, not machine-wide utilization. No live QIHSE storage
is read; each invocation uses the benchmark's isolated XDG_STATE_HOME.
"""
from __future__ import annotations

import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import socket
import subprocess
import tempfile
import time


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def run(argv, **kwargs):
    return subprocess.run(argv, check=True, capture_output=True, **kwargs)


def percentile(values, fraction):
    values = sorted(values)
    position = (len(values) - 1) * fraction
    lower = math.floor(position)
    upper = math.ceil(position)
    return values[lower] + (values[upper] - values[lower]) * (position - lower)


def summarize(rows):
    result = {'samples': len(rows)}
    for field in ('wall_ms', 'cpu_ms', 'peak_rss_kib', 'output_bytes',
                  'client_cpu_ms', 'client_peak_rss_kib', 'server_cpu_ms'):
        values = [row[field] for row in rows if field in row]
        if values:
            result[field] = {name: percentile(values, fraction) for name, fraction in
                             (('p50', .50), ('p95', .95), ('p99', .99))}
    result['errors'] = sum(bool(row.get('error')) for row in rows)
    result['unsupported'] = sum(row.get('response_status') == 'unsupported' for row in rows)
    result['tail_warning'] = (
        'Descriptive quantiles; fewer than 100 samples cannot characterize p99.'
        if len(rows) < 100 else None)
    return result


def save(path, report):
    path = Path(path)
    with tempfile.NamedTemporaryFile(mode='w', dir=path.parent, delete=False) as stream:
        json.dump(report, stream, indent=2, sort_keys=True)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())
        temporary = stream.name
    os.replace(temporary, path)


def request(socket_path, token, fields):
    with socket.socket(socket.AF_UNIX) as peer:
        peer.settimeout(120)
        peer.connect(str(socket_path))
        peer.sendall((json.dumps({**fields, 'token': token}) + '\n').encode())
        data = bytearray()
        while not data.endswith(b'\n'):
            chunk = peer.recv(65536)
            if not chunk:
                break
            data.extend(chunk)
    return bytes(data)


def measure_output(data, elapsed, include_document=False):
    row = {'wall_ms': elapsed * 1000, 'output_bytes': len(data),
           'output_sha256': hashlib.sha256(data).hexdigest()}
    try:
        document = json.loads(data)
        if not isinstance(document, dict):
            raise ValueError('expected JSON object response')
        if include_document:
            row['example'] = dict(document)
        row['error'] = document.get('error')
        row['response_status'] = ('unsupported' if 'unsupported' in str(row['error'])
                                  else 'error' if row['error'] else 'ok')
        row['fresh'] = document.get('fresh')
        row['generation'] = document.get('generation')
        row['truncated'] = document.get('truncated')
        nodes = document.get('nodes', [])
        if not isinstance(nodes, list):
            row['graph_node_count'] = nodes
            nodes = []
        nested = any(isinstance(node, dict) and 'nodes' in node for node in nodes)
        row['response_shape'] = 'nested_batch' if nested else 'flat'
        row['node_count'] = len(nodes)
        flat_nodes = ([child for node in nodes for child in node.get('nodes', [])]
                      if nested else nodes)
        signatures = sorted({json.dumps({key: node.get(key) for key in
            ('file', 'symbol', 'kind', 'line_start', 'line_end', 'hop', 'is_test')}, sort_keys=True)
            for node in flat_nodes})
        row['unique_node_count'] = len(signatures)
        row['node_set_sha256'] = hashlib.sha256(json.dumps(signatures).encode()).hexdigest()
        row['seed_metadata'] = {key: document[key] for key in
                                ('seed_nodes', 'seed_match', 'ambiguous') if key in document}
        row['stages_ms'] = document.pop('timings', None)
        row['compact_stages_us'] = document.pop('timing_us', None)
        row['semantic_sha256'] = hashlib.sha256(json.dumps(
            document, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        document.pop('generation', None)
        row['content_sha256'] = hashlib.sha256(json.dumps(
            document, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    except (ValueError, AttributeError) as error:
        row['error'] = str(error)
    return row


def process_stats(pid):
    fields = Path(f'/proc/{pid}/stat').read_text().split(') ', 1)[1].split()
    tick_ms = 1000 / os.sysconf('SC_CLK_TCK')
    cpu_self_ms = (int(fields[11]) + int(fields[12])) * tick_ms
    cpu_children_ms = (int(fields[13]) + int(fields[14])) * tick_ms
    status = Path(f'/proc/{pid}/status').read_text().splitlines()
    rss = {line.split(':')[0]: int(line.split()[1]) for line in status
           if line.startswith(('VmRSS:', 'VmHWM:'))}
    return {'cpu_ms': cpu_self_ms + cpu_children_ms,
            'cpu_self_ms': cpu_self_ms, 'cpu_children_ms': cpu_children_ms,
            'rss_kib': rss.get('VmRSS'),
            'peak_rss_kib': rss.get('VmHWM')}


def prepare(args, env):
    repo = args.root / 'repo'
    run(['git', 'clone', '--quiet', '--no-hardlinks', str(args.prepare), str(repo)])
    run([args.crg, 'build', '--repo', str(repo), '--skip-postprocess'])
    run([args.crg, 'visualize', '--format', 'qihse', '--repo', str(repo)])
    run([str(args.binary), 'import', '--repo', str(repo), '--input',
         str(repo / '.code-review-graph/graph.qihse.jsonl')], env=env, timeout=300)


def cases_for(repo, exported=None):
    names = {}
    nodes = {}
    degree = Counter()
    unresolved = Counter()
    exported = exported or repo / '.code-review-graph/graph.qihse.jsonl'
    with exported.open() as stream:
        for line in stream:
            node = json.loads(line)
            if node.get('t') == 'n' and node.get('kind') != 'File':
                nodes[node['id']] = node
                names[node['name']] = names.get(node['name'], 0) + 1
            elif node.get('t') == 'e':
                if node.get('traversable'):
                    degree.update((node['source'], node['target']))
                else:
                    unresolved.update((node['source'],))
    unique = 'GraphStore' if names.get('GraphStore') == 1 else next(
        name for name, count in names.items() if count == 1)
    ambiguous = max(names, key=names.get)
    cases = [
        {'name': f'unique_depth_{depth}', 'symbol': unique, 'depth': depth,
         'limit': 80, 'max_tokens': 4000} for depth in (1, 2, 3, 4, 5)
    ] + [
        {'name': 'missing', 'symbol': '__codegraph_benchmark_absent_91f700__',
         'depth': 2, 'limit': 80, 'max_tokens': 4000},
        {'name': 'ambiguous', 'symbol': ambiguous, 'depth': 2,
         'limit': 80, 'max_tokens': 4000},
        {'name': 'tight_budget', 'symbol': unique, 'depth': 5,
         'limit': 1, 'max_tokens': 128},
        {'name': 'batch_valid', 'symbols': [unique, ambiguous], 'depth': 2,
         'limit': 80, 'max_tokens': 4000},
        {'name': 'batch', 'symbols': [unique, ambiguous,
          '__codegraph_benchmark_absent_91f700__'], 'depth': 2,
         'limit': 80, 'max_tokens': 4000},
    ]
    if names.get('list_memories') == 1:
        cases.extend({'name': f'narrow_depth_{depth}', 'symbol': 'list_memories',
                      'depth': depth, 'limit': 80, 'max_tokens': 4000}
                     for depth in (1, 2, 3, 4, 5))
    unique_nodes = [node for node in nodes.values() if names[node['name']] == 1]
    for label, counts in (('high_degree', degree), ('unresolved', unresolved)):
        selected = max(unique_nodes, key=lambda node: counts[node['id']])
        for command in ('query', 'impact'):
            case = {'name': f'{label}_{command}', 'command': command,
                    'depth': 2, 'limit': 80, 'max_tokens': 4000,
                    'source_evidence_count': counts[selected['id']]}
            case['symbol' if command == 'query' else 'file'] = (
                selected['name'] if command == 'query' else selected['file'])
            cases.append(case)
    return cases


def cold(binary, repo, env, case, timings=False, include_document=False, reader_args=()):
    # Batch is not a CLI operation: measure the equivalent ordered CLI calls.
    symbols = case.get('symbols', [case.get('symbol')])
    rows = []
    for symbol in symbols:
        argv = ['/usr/bin/time', '-f', '\nCG_RESOURCE %U %S %M', str(binary),
                case.get('command', 'context'), '--repo', str(repo),
                '--depth', str(case['depth']), '--limit', str(case['limit']),
                '--max-tokens', str(case['max_tokens'])]
        if symbol:
            argv.extend(('--symbol', symbol))
        if case.get('file'):
            argv.extend(('--file', case['file']))
        if timings:
            argv.append('--timings')
        argv.extend(reader_args)
        started = time.perf_counter()
        completed = subprocess.run(argv, env=env, capture_output=True, timeout=180)
        row = measure_output(completed.stdout, time.perf_counter() - started, include_document)
        row['returncode'] = completed.returncode
        if row.get('fresh') is False:
            raise RuntimeError(f"cold query refused stale generation: {row.get('error')}")
        resources = completed.stderr.decode().rsplit('CG_RESOURCE ', 1)[-1].split()
        row['cpu_ms'] = (float(resources[0]) + float(resources[1])) * 1000
        row['peak_rss_kib'] = int(resources[2])
        row['stderr'] = completed.stderr.decode().split('\nCG_RESOURCE ')[0][-1000:]
        rows.append(row)
    if len(rows) == 1:
        return rows[0]
    return {'wall_ms': sum(row['wall_ms'] for row in rows),
            'cpu_ms': sum(row['cpu_ms'] for row in rows),
            'peak_rss_kib': max(row['peak_rss_kib'] for row in rows),
            'output_bytes': sum(row['output_bytes'] for row in rows),
            'error': next((row['error'] for row in rows if row.get('error')), None),
            'members': rows}


def compare_reports(report, baseline):
    same_export = report['export_sha256'] == baseline['export_sha256']
    same_source = report['source_commit'] == baseline['source_commit']
    index = {(group['mode'], group['case'], group['concurrency']): group
             for group in baseline['measurements']}
    compared = []
    for group in report['measurements']:
        key = (group['mode'], group['case'], group['concurrency'])
        prior = index.get(key)
        if not prior:
            continue
        errors = {row.get('error') for row in group['raw']}
        prior_errors = {row.get('error') for row in prior['raw']}
        unsupported = any(row.get('response_status') == 'unsupported'
                          for row in group['raw'] + prior['raw'])
        comparable = same_export and same_source and errors == prior_errors and not unsupported
        entry = {'mode': key[0], 'case': key[1], 'concurrency': key[2],
                 'same_export': same_export, 'same_source': same_source,
                 'same_response_errors': errors == prior_errors,
                 'unsupported': unsupported, 'latency_comparable': comparable}
        for field in ('content_sha256', 'node_set_sha256'):
            before = {row[field] for row in prior['raw'] if field in row}
            after = {row[field] for row in group['raw'] if field in row}
            entry[field + '_equal'] = before == after if before and after else None
        if comparable:
            entry['wall_speedup'] = {
                quantile: prior['summary']['wall_ms'][quantile] /
                group['summary']['wall_ms'][quantile] for quantile in ('p50', 'p95', 'p99')}
        entry['output_equivalence_warning'] = (
            'Same request latency only; output contract/budget changed'
            if entry['content_sha256_equal'] is False else None)
        compared.append(entry)
    return {'same_export': same_export, 'same_source': same_source,
            'measurements': compared,
            'note': 'Ratios are before/after same-input latency, not claims of identical output work.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--export', type=Path, help='Official export used for this imported generation')
    parser.add_argument('--state-home', type=Path, help='Isolated state, default ROOT/state')
    parser.add_argument('--prepare', type=Path)
    parser.add_argument('--crg', default='code-review-graph')
    parser.add_argument('--samples', type=int, default=5)
    parser.add_argument('--concurrency', type=int, nargs='+', default=[1, 4])
    parser.add_argument('--mode', choices=['cold', 'resident', 'both'], default='both')
    parser.add_argument('--transport', choices=['socket', 'cli'], default='socket',
                        help='Warm socket requests or new fast CLI client; cold mode unaffected')
    parser.add_argument('--timings', action='store_true',
                        help='Request candidate native stage timings')
    parser.add_argument('--case', action='append', dest='selected_cases')
    parser.add_argument('--note', action='append', default=[], help='Record measurement conditions')
    parser.add_argument('--compare', type=Path, action='append', default=[],
                        help='Compare same-input latency and output hashes with a saved baseline')
    parser.add_argument('--stage-evidence', type=Path, action='append', default=[],
                        help='Attach separately measured instrumented stage-probe JSON')
    args = parser.parse_args()
    if args.samples < 1 or any(value < 1 for value in args.concurrency):
        parser.error('samples and concurrency must be positive')
    args.binary = args.binary.resolve()
    args.root = args.root.resolve()
    args.root.mkdir(parents=True, exist_ok=True)
    state_home = (args.state_home or args.root / 'state').resolve()
    env = {**os.environ, 'XDG_STATE_HOME': str(state_home),
           'LD_LIBRARY_PATH': str(args.binary.parent) + ':' + os.environ.get('LD_LIBRARY_PATH', '')}
    if args.prepare:
        prepare(args, env)
    repo = args.root / 'repo'
    exported = args.export.resolve() if args.export else repo / '.code-review-graph/graph.qihse.jsonl'
    cases = cases_for(repo, exported)
    if args.selected_cases and set(args.selected_cases) - {case['name'] for case in cases}:
        parser.error('unknown case name')
    if args.selected_cases:
        cases = [case for case in cases if case['name'] in args.selected_cases]
    report = {'schema_version': 1, 'started_at_unix': time.time(),
              'binary': str(args.binary), 'binary_sha256': digest(args.binary),
              'library_sha256': digest(args.binary.parent / 'libqihse.so'),
              'repo': str(repo), 'state_home': str(state_home), 'source_commit': run(
                  ['git', 'rev-parse', 'HEAD'], cwd=repo).stdout.decode().strip(),
              'export_sha256': digest(exported),
              'export_header': json.loads(exported.read_text().splitlines()[0]),
              'export_trailer': json.loads(exported.read_text().splitlines()[-1]),
              'harness_sha256': digest(__file__),
              'samples_per_case': args.samples, 'timings_enabled': args.timings,
              'resident_transport': args.transport,
              'platform': platform.platform(), 'logical_cpus': os.cpu_count(),
              'available_cpus': len(os.sched_getaffinity(0)) if hasattr(os, 'sched_getaffinity')
                                else os.cpu_count(), 'run_notes': args.note,
              'methodology': {'cold': 'fresh process; filesystem caches not evicted',
                              'resident': 'authenticated Unix socket; graph loaded once',
                              'batch_cold': 'ordered CLI calls; sum bytes/time, maximum RSS',
                              'cpu': 'user+system; resident self+waited children /proc phase delta',
                              'rss': 'cold GNU time max RSS; resident cumulative process VmHWM',
                              'resident_cpu_quantiles': 'only concurrency1; phase totals otherwise',
                              'fast_cli_cpu': 'client GNU time plus server /proc at concurrency1',
                              'fast_cli_batch': 'ordered client calls, not one socket batch request',
                              'percentiles': 'linear interpolation over recorded raw samples',
                              'errors': 'response errors, including expected missing-symbol failures',
                              'cpu_resolution': 'GNU time 10ms; resident /proc scheduler ticks'},
              'cases': cases, 'measurements': []}
    report['stage_evidence'] = [{'path': str(path.resolve()), 'sha256': digest(path),
                                 'measurements': json.loads(path.read_text())}
                                for path in args.stage_evidence]
    save(args.output, report)
    if args.mode in ('cold', 'both'):
        for concurrency in args.concurrency:
            for case in cases:
                started = time.perf_counter()
                with ThreadPoolExecutor(max_workers=concurrency) as pool:
                    rows = list(pool.map(lambda i: cold(args.binary, repo, env, case,
                                         args.timings, i == 0), range(args.samples)))
                for row in rows:
                    for member in row.get('members', [row]):
                        generation = member.get('generation')
                        if generation and report['export_trailer']['sha256'] not in generation:
                            raise RuntimeError('declared export does not match cold generation')
                elapsed = time.perf_counter() - started
                report['measurements'].append({'mode': 'cold', 'case': case['name'],
                    'concurrency': concurrency,
                    'effective_concurrency': min(concurrency, args.samples),
                    'summary': summarize(rows), 'raw': rows,
                    'phase_wall_ms': elapsed * 1000, 'throughput_per_second': len(rows) / elapsed})
                save(args.output, report)
                print('saved', 'cold', case['name'], concurrency, summarize(rows), flush=True)
    if args.mode in ('resident', 'both'):
        with tempfile.TemporaryDirectory(prefix='cg-socket-') as directory:
            socket_path = Path(directory) / 'reader.sock'
            token_path = Path(directory) / 'reader.token'
            with tempfile.TemporaryFile() as log:
                started = time.perf_counter()
                process = subprocess.Popen([str(args.binary), 'serve', '--repo', str(repo),
                    '--socket', str(socket_path), '--token-file', str(token_path),
                    '--idle-seconds', '3600'], env=env, stdout=log, stderr=log)
                try:
                    # Block in socket connect retries using bounded kernel waits, not busy polling.
                    deadline = time.monotonic() + 180
                    while True:
                        if process.poll() is not None:
                            log.seek(0)
                            raise RuntimeError(log.read().decode())
                        if token_path.exists():
                            token = token_path.read_text().strip()
                            try:
                                reply = request(socket_path, token, {'command': 'ping'})
                                if json.loads(reply).get('status') == 'ready':
                                    break
                            except (OSError, ValueError):
                                pass
                        if time.monotonic() > deadline:
                            raise TimeoutError('resident startup timeout')
                        import select
                        select.select([], [], [], .05)
                    report['resident_startup_ms'] = (time.perf_counter() - started) * 1000
                    report['resident_initial_resources'] = process_stats(process.pid)
                    load_started = time.perf_counter()
                    report['resident_initial_status'] = json.loads(request(
                        socket_path, token, {'command': 'status'}))
                    report['resident_generation_load_ms'] = (
                        time.perf_counter() - load_started) * 1000
                    status = report['resident_initial_status']
                    if status.get('fresh') is not True:
                        raise RuntimeError(f'resident generation not fresh: {status}')
                    if report['export_trailer']['sha256'] not in status.get('generation', ''):
                        raise RuntimeError('declared export does not match imported generation')
                    for concurrency in args.concurrency:
                        for case in cases:
                            fields = {key: value for key, value in case.items() if key in
                                      ('symbol', 'symbols', 'file', 'depth', 'limit', 'max_tokens')}
                            fields['command'] = case.get('command', 'context')
                            if args.timings:
                                fields['timings'] = True
                            warm_started = time.perf_counter()
                            warm_data = request(socket_path, token, fields)
                            warm = measure_output(
                                warm_data, time.perf_counter() - warm_started, True)
                            before = process_stats(process.pid)
                            def invoke(index):
                                initial = process_stats(process.pid) if concurrency == 1 else None
                                if args.transport == 'cli':
                                    reader_args = ('--socket', str(socket_path), '--token-file',
                                                   str(token_path), '--fallback', 'error')
                                    row = cold(args.binary, repo, env, case, args.timings,
                                               index == 0, reader_args)
                                    row['client_cpu_ms'] = row.pop('cpu_ms')
                                    row['client_peak_rss_kib'] = row.pop('peak_rss_kib')
                                else:
                                    start = time.perf_counter()
                                    data = request(socket_path, token, fields)
                                    row = measure_output(data, time.perf_counter() - start)
                                if initial:
                                    current = process_stats(process.pid)
                                    row['server_cpu_ms'] = current['cpu_ms'] - initial['cpu_ms']
                                    row['cpu_ms'] = row['server_cpu_ms'] + row.get('client_cpu_ms', 0)
                                    row['peak_rss_kib'] = current['peak_rss_kib']
                                return row
                            started = time.perf_counter()
                            with ThreadPoolExecutor(max_workers=concurrency) as pool:
                                rows = list(pool.map(invoke, range(args.samples)))
                            elapsed = time.perf_counter() - started
                            after = process_stats(process.pid)
                            mode = 'resident_cli' if args.transport == 'cli' else 'resident'
                            client_cpu = sum(row.get('client_cpu_ms', 0) for row in rows)
                            report['measurements'].append({'mode': mode, 'case': case['name'],
                                'concurrency': concurrency,
                                'effective_concurrency': min(concurrency, args.samples),
                                'summary': summarize(rows), 'raw': rows,
                                'warmup': warm, 'phase_wall_ms': elapsed * 1000,
                                'phase_server_cpu_ms': after['cpu_ms'] - before['cpu_ms'],
                                'phase_client_cpu_ms': client_cpu,
                                'phase_cpu_ms': after['cpu_ms'] - before['cpu_ms'] + client_cpu,
                                'resident_resources': after,
                                'throughput_per_second': len(rows) / elapsed})
                            save(args.output, report)
                            print('saved', mode, case['name'], concurrency,
                                  summarize(rows), flush=True)
                    report['resident_final_status'] = json.loads(request(
                        socket_path, token, {'command': 'status'}))
                finally:
                    process.terminate()
                    try:
                        process.wait(timeout=15)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()
    report['export_unchanged'] = digest(exported) == report['export_sha256']
    report['binary_unchanged'] = digest(args.binary) == report['binary_sha256']
    report['library_unchanged'] = (
        digest(args.binary.parent / 'libqihse.so') == report['library_sha256'])
    report['source_git_status'] = run(['git', 'status', '--porcelain'], cwd=repo).stdout.decode()
    report['completed_at_unix'] = time.time()
    report['comparisons'] = [{'path': str(path.resolve()), 'sha256': digest(path),
                              **compare_reports(report, json.loads(path.read_text()))}
                             for path in args.compare]
    save(args.output, report)


if __name__ == '__main__':
    main()
