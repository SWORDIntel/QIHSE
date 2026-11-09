#!/usr/bin/env python3
"""Reproducible resident-memory measurements, with per-case atomic checkpoints."""
import argparse
from collections import defaultdict
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import statistics
import subprocess
import tempfile


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def capture(command):
    try:
        return subprocess.check_output(command, text=True, stderr=subprocess.STDOUT).strip()
    except (OSError, subprocess.CalledProcessError) as exc:
        return str(exc)


def summary(raw):
    groups = defaultdict(list)
    for row in raw['samples']:
        groups[row['candidate']].append(row)
    result = {}
    for name, rows in groups.items():
        times = [r['ns'] / r['calls'] for r in rows]
        median = statistics.median(times)
        result[name] = {
            'ns_per_hash_median': median,
            'ns_per_hash_min': min(times), 'ns_per_hash_max': max(times),
            'ns_per_hash_mad': statistics.median(abs(t-median) for t in times),
            'GB_per_s_median': statistics.median(r['bytes']/r['ns'] for r in rows),
            'samples': len(rows),
        }
    return result


def save(path, value):
    tmp = path.with_name(path.name+'.tmp')
    tmp.write_text(json.dumps(value, indent=2)+'\n')
    tmp.replace(path)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--binary', default='./build/bench')
    ap.add_argument('--corpus', default='corpus')
    ap.add_argument('--out', default='results/local.json')
    ap.add_argument('--samples', type=int, default=15)
    ap.add_argument('--ms', type=int, default=8)
    ap.add_argument('--cpu', type=int)
    ap.add_argument('--quick', action='store_true')
    ap.add_argument('--sha-control', action='store_true')
    args = ap.parse_args()
    if not 1 <= args.samples <= 1000 or not 1 <= args.ms <= 1000:
        ap.error('samples and ms must be within 1..1000')
    root = Path(__file__).resolve().parents[1]
    binary = Path(args.binary).resolve()
    corpus = Path(args.corpus).resolve()
    output = Path(args.out).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    sources = sorted(p for p in corpus.rglob('*') if p.is_file() and not p.is_symlink())
    if not sources or any('\n' in str(p) for p in sources):
        ap.error('corpus must contain files and filenames must not contain newlines')
    source_manifest = [{'path': str(p.relative_to(corpus)), 'bytes': p.stat().st_size,
                        'sha256': digest(p)} for p in sources]
    tracked = [root/'Makefile']
    for folder in ('src','include','bench','vendor'):
        tracked += sorted(p for p in (root/folder).rglob('*') if p.suffix in ('.c','.h','.py'))
    result = {
        'provenance': {
            'utc_started': datetime.now(timezone.utc).isoformat(),
            'command': ['python3', *os.sys.argv], 'platform': platform.platform(),
            'lscpu': capture(['lscpu']), 'cc': capture([os.environ.get('CC','cc'),'--version']),
            'openssl': capture(['openssl','version','-a']),
            'compile_commands': capture(['make','-B','-n',str(binary.relative_to(root))]),
            'binary_sha256': digest(binary), 'source_sha256': {str(p.relative_to(root)):digest(p) for p in tracked},
            'corpus': source_manifest,
            'openssl_ia32cap_environment': os.environ.get('OPENSSL_ia32cap'),
            'method': 'Single pinned logical CPU; resident buffers; 15 interleaved samples by default; '
                      'calibration, CPU selection, file reads and allocations excluded. '
                      'Every hash contributes to a checksum. Batch includes output stores and checksum reduction. '
                      'Inline_fixed32 uses a literal 32-byte length, not a runtime length. '
                      'Streaming reuses a state and updates in <=64 KiB chunks. '
                      'SHA256_Init/Update/Final computes all 256 output bits; normal OpenSSL CPU dispatch retained. '
                      'No filesystem-cold, graph-build, update, query, or multi-thread performance claim.'
        }, 'cases': {}
    }
    base = [str(binary),'--samples',str(args.samples),'--ms',str(args.ms)]
    if args.cpu is not None:
        base += ['--cpu',str(args.cpu)]
    sizes = [0,16,32,64,240,241,256,4096,65536,1048576]
    if args.quick:
        sizes = [32,256,65536]
    with tempfile.TemporaryDirectory(prefix='qx3-bench-') as temporary:
        listing = Path(temporary)/'files.txt'
        listing.write_text(''.join(str(p)+'\n' for p in sources))
        cases = [(f'{n}B_aligned',['--size',str(n),'--offset','0']) for n in sizes]
        cases += [('32B_unaligned',['--size','32','--offset','1']),
                  ('source_corpus_aligned',['--corpus-list',str(listing),'--offset','0']),
                  ('source_corpus_unaligned',['--corpus-list',str(listing),'--offset','1'])]
        for name, options in cases:
            print('Measuring',name,flush=True)
            raw = json.loads(subprocess.check_output(base+options, text=True))
            result['cases'][name] = {'raw':raw,'summary':summary(raw)}
            save(output,result)
        if args.sha_control:
            print('Measuring SHA-NI-disabled diagnostic (not headline baseline)',flush=True)
            env = dict(os.environ, OPENSSL_ia32cap=':~0x20000000:~0x0:~0x0:~0x0')
            raw = json.loads(subprocess.check_output(base+['--size','65536'],text=True,env=env))
            result['sha_control'] = {'mask':env['OPENSSL_ia32cap'],'raw':raw,'summary':summary(raw)}
    result['provenance']['utc_finished'] = datetime.now(timezone.utc).isoformat()
    save(output,result)
    print('Saved',output,flush=True)


if __name__ == '__main__':
    main()
