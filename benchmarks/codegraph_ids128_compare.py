#!/usr/bin/env python3
"""Isolated authenticated snapshot comparison of equivalent 256/128-bit graph IDs."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
from codegraph_packed_compare import PROJECT, build_driver, graph_fixture, sha256


def shorten(source, dest):
    rows = [json.loads(line) for line in source.read_bytes().splitlines()]
    ids = {r['id']: r['id'][:32] for r in rows if r['t'] in ('n', 'e')}
    assert len(ids) == len(set(ids.values())), 'synthetic identity collision'
    transformed = []
    for row in rows[:-1]:
        row = dict(row)
        if row['t'] == 'h':
            row.update(identity='qihse-semantic-128-v1', id_algorithm='sha256-128', id_bits=128,
                       id_collision='counter-sha256-128-v1', id_collision_attempts=256)
        for field in ('id', 'source', 'target'):
            if row.get(field):
                row[field] = ids[row[field]]
        transformed.append(row)
    body = b''.join((json.dumps(r, sort_keys=True, separators=(',', ':'))+'\n').encode()
                    for r in transformed)
    trailer = dict(rows[-1], sha256=hashlib.sha256(body).hexdigest())
    dest.write_bytes(body+(json.dumps(trailer, sort_keys=True, separators=(',', ':'))+'\n').encode())
    # Independent inverse mapping proves every graph fact survives renumbering.
    reverse = {v:k for k,v in ids.items()}
    for old, new in zip(rows[1:-1], transformed[1:]):
        back = dict(new)
        for field in ('id', 'source', 'target'):
            if back.get(field): back[field] = reverse[back[field]]
        assert old == back


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--nodes', type=int, nargs='+', default=[800,8000])
    ap.add_argument('--output', type=Path, required=True)
    args = ap.parse_args()
    results=[]
    with tempfile.TemporaryDirectory(prefix='qihse-ids128-') as temporary:
        root=Path(temporary); binary=root/'driver'
        build_driver(binary,PROJECT,PROJECT,packed=True)
        for n in args.nodes:
            case=root/str(n);case.mkdir();repo=case/'repo';repo.mkdir()
            subprocess.run(['git','init','-q',str(repo)],check=True)
            fixture=case/'legacy.jsonl'; graph_fixture(repo,fixture,n,n*3)
            compact=case/'compact.jsonl';shorten(fixture,compact)
            rows={}
            for bits, source in ((256,fixture),(128,compact)):
                folder=case/str(bits);folder.mkdir();state=folder/'state';state.mkdir(mode=0o700)
                env=dict(os.environ,QIHSE_DATA_DIR=str(state),XDG_STATE_HOME=str(state),LD_LIBRARY_PATH=str(PROJECT))
                p=subprocess.run([str(binary),'dictionary',str(source),str(folder/'snapshot')],env=env,
                                 text=True,capture_output=True,check=True)
                receipt=json.loads(p.stdout)
                assert receipt['raw_roundtrip'] and receipt['low_clearance_denied']
                assert receipt['record_count']==n*4+2
                receipt['input_sha256']=sha256(source);rows[str(bits)]=receipt
            before=rows['256']['snapshot_apparent_bytes'];after=rows['128']['snapshot_apparent_bytes']
            result={'nodes':n,'edges':n*3,'runs':rows,'smaller_percent':100*(1-after/before)}
            results.append(result);print(json.dumps(result),flush=True)
    args.output.write_text(json.dumps({'method':'one shared-host run per width, same graph facts, inverse-ID semantic check, exact authenticated export roundtrip and low-clearance denial; synthetic SHA256 prefixes, not a rebuild performance benchmark',
         'dictionary_sha256':sha256(PROJECT/'tools/qihse_codegraph_dictionary.c'),'fixtures':results},indent=2)+'\n')

if __name__=='__main__':main()
