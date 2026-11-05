#!/usr/bin/env python3
"""Count resident glibc allocation calls; instrumentation is not a latency benchmark."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import select
import signal
import subprocess
import tempfile
import time
from pathlib import Path

from codegraph_search import request


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--repo', type=Path, required=True)
    parser.add_argument('--state-home', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    binary = args.binary.resolve()
    with tempfile.TemporaryDirectory(prefix='cg-allocation-probe-') as directory:
        root = Path(directory)
        probe = root / 'allocations.so'
        source = Path(__file__).with_name('codegraph_search_alloc_probes.c')
        subprocess.run(['gcc', '-shared', '-fPIC', '-O2', str(source), '-o', str(probe)],
                       check=True)
        read_fd, write_fd = os.pipe()
        env = {**os.environ, 'LD_LIBRARY_PATH': str(binary.parent),
               'LD_PRELOAD': str(probe), 'CG_ALLOC_FD': str(write_fd),
               'XDG_STATE_HOME': str(args.state_home.resolve())}
        sock, token_path = root / 'reader.sock', root / 'reader.token'
        with tempfile.TemporaryFile() as log:
            process = subprocess.Popen([str(binary), 'serve', '--repo', str(args.repo.resolve()),
                '--socket', str(sock), '--token-file', str(token_path), '--idle-seconds', '300'],
                env=env, pass_fds=(write_fd,), stdout=log, stderr=log)
            os.close(write_fd)
            try:
                deadline = time.monotonic() + 120
                while True:
                    if process.poll() is not None:
                        log.seek(0)
                        raise RuntimeError(log.read().decode())
                    if token_path.exists():
                        token = token_path.read_text().strip()
                        try:
                            status = json.loads(request(sock, token, {'command': 'ping'}))
                            if status.get('status') == 'ready':
                                break
                        except OSError:
                            pass
                    if time.monotonic() > deadline:
                        raise TimeoutError('reader startup')
                    select.select([], [], [], .05)
                fields = {'command': 'context', 'symbol': 'GraphStore', 'depth': 2,
                          'limit': 80, 'max_tokens': 4000}
                assert json.loads(request(sock, token, fields))['fresh']

                def counters():
                    os.kill(process.pid, signal.SIGUSR1)
                    if not select.select([read_fd], [], [], 5)[0]:
                        raise TimeoutError('allocation counters')
                    values = list(map(int, os.read(read_fd, 4096).split()))
                    assert len(values) == 4 and values[0] == process.pid, values
                    return values

                before = counters()
                decode_ms, roundtrip_ms, response_bytes = [], [], []
                for _ in range(20):
                    started = time.perf_counter()
                    payload = request(sock, token, fields)
                    received = time.perf_counter()
                    result = json.loads(payload)
                    decoded = time.perf_counter()
                    roundtrip_ms.append((received - started) * 1000)
                    decode_ms.append((decoded - received) * 1000)
                    response_bytes.append(len(payload))
                    assert result['fresh'] and 'error' not in result, result
                after = counters()
                report = {'kind': 'instrumented resident glibc calls; not headline latency',
                          'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
                          'library_sha256': hashlib.sha256(
                              (binary.parent / 'libqihse.so').read_bytes()).hexdigest(),
                          'probe_sha256': hashlib.sha256(source.read_bytes()).hexdigest(),
                          'workload': fields, 'n': 20,
                          'client_decode_ms': decode_ms, 'socket_roundtrip_ms': roundtrip_ms,
                          'response_bytes': response_bytes,
                          'counter_before_pid_allocs_frees_bytes': before,
                          'counter_after_pid_allocs_frees_bytes': after,
                          'allocations_per_query': (after[1] - before[1]) / 20,
                          'requested_bytes_per_query': (after[3] - before[3]) / 20}
                args.output.write_text(json.dumps(report, indent=2) + '\n')
                print(json.dumps(report, indent=2))
            finally:
                process.terminate()
                try:
                    process.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
                os.close(read_fd)


if __name__ == '__main__':
    main()
