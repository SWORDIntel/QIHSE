#!/usr/bin/env python3
"""Compare current and adapted ZIP codecs through real authenticated SDK loads."""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import statistics
import subprocess
import tempfile
import time
from codegraph_packed_compare import PROJECT, DRIVER, graph_fixture, sha256, checksum_sources

HASH_HELPER = r'''
static bool snapshot_hash(const char *path, char hex[65]) {
    FILE *f = fopen(path, "rb"); if (!f) return false;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned char buffer[4096], sum[32]; size_t n; unsigned int len = 0;
    bool ok = ctx && EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1;
    while (ok && (n = fread(buffer, 1, sizeof(buffer), f)))
        ok = EVP_DigestUpdate(ctx, buffer, n) == 1;
    ok = ok && !ferror(f) && EVP_DigestFinal_ex(ctx, sum, &len) == 1 && len == 32;
    EVP_MD_CTX_free(ctx); fclose(f);
    if (ok) for (size_t i = 0; i < 32; ++i) snprintf(hex+2*i, 3, "%02x", sum[i]);
    return ok;
}
'''

def build(output: Path, source_dir: Path, library_dir: Path, level: int) -> None:
    source = DRIVER.read_text()
    source = source.replace('    bool ok;\n} digest_set;',
        '    bool ok;\n    qihse_kv_store_t *store;\n    qihse_user_t *user;\n} digest_set;')
    source = source.replace('digest_set set = {NULL, 0, 0, true};',
        'digest_set set = {NULL, 0, 0, true, store, user};')
    source = source.replace('    uint64_t lengths[2] = ', r'''    qihse_kv_record_meta_t metadata;
    if (!qihse_kv_meta_user(set->store, key, set->user, &metadata)) return set->ok = false;
    uint64_t fields[5] = {metadata.classification, metadata.sci_compartment,
        metadata.expire_time_ms, metadata.flags, metadata.change_seq};
    unsigned char meta_bytes[40];
    for (size_t j = 0; j < 5; ++j)
        for (size_t i = 0; i < 8; ++i) meta_bytes[j*8+i] = (unsigned char)(fields[j] >> (56-8*i));
    uint64_t lengths[2] = ''')
    source = source.replace('EVP_DigestUpdate(ctx, encoded, sizeof(encoded)) == 1 &&',
        'EVP_DigestUpdate(ctx, encoded, sizeof(encoded)) == 1 &&\n              EVP_DigestUpdate(ctx, meta_bytes, sizeof(meta_bytes)) == 1 &&')
    source = source.replace('int main(int argc, char **argv) {', HASH_HELPER + '\nint main(int argc, char **argv) {')
    old = '    qihse_kv_store_t *loaded = qihse_kv_store_create_user(op);\n    if (!loaded) return 8;'
    assert old in source
    source = source.replace(old, '''    qihse_kv_store_t *loaded = NULL;
    char expected[65];
    if (!snapshot_hash(output, expected)) return 8;
    cg_storage_info_t load_info;''')
    start = source.index('    bool decoded_ok = '); end = source.index('    double load_ms = ', start)
    source = source[:start]+'''    loaded = cg_storage_open_verified_info(output, op, LIMIT_BYTES, LIMIT_RECORDS,
        !strcmp(backend, "packed") ? expected : NULL, &load_info);
    bool decoded_ok = loaded && load_info.valid && load_info.encoded_bytes == (uint64_t)snapshot.st_size;
'''+source[end:]
    old = '(!strcmp(backend, "packed") && !same_bytes(raw, decoded)) ||\n        '
    assert old in source; source = source.replace(old, '')
    source = source.replace(' || !same_bytes(raw, reexport)', '')
    source = source.replace('    if (getrusage(RUSAGE_SELF, &usage)) return 9;', r'''    if (getrusage(RUSAGE_SELF, &usage)) return 9;
    /* Verify exact standalone codec bytes after measuring load time/peak RSS.
     * Immutable KV re-export order may differ; its full metadata fingerprint
     * above is the order-independent native-load oracle. */
    if (!strcmp(backend, "packed")) {
        if (!packed_decode(output, decoded, op) || !same_bytes(raw, decoded)) return 9;
    } else {
        qihse_kv_store_t *roundtrip = qihse_kv_store_create_user(op);
        if (!roundtrip || !cg_storage_load(roundtrip, output, op) ||
            qihse_kv_save_user(roundtrip, decoded, op) || !same_bytes(raw, decoded)) return 9;
        qihse_kv_store_destroy(roundtrip);
    }''')
    old = '    if (!low_store) return 10;'
    assert old in source
    source = source.replace(old, old+'''
    char protected_sha[65];
    if (!snapshot_hash(protected_path, protected_sha)) return 10;
    qihse_kv_store_t *forbidden = cg_storage_open_verified_info(protected_path, low,
        LIMIT_BYTES, LIMIT_RECORDS, !strcmp(backend, "packed") ? protected_sha : NULL, &load_info);
    if (forbidden || load_info.valid) { if (forbidden) qihse_kv_store_destroy(forbidden); return 11; }
''')
    driver = output.with_suffix('.c'); driver.write_text(source)
    flags = subprocess.check_output(['pkg-config', '--cflags', '--libs', 'json-c', 'openssl', 'libzstd'], text=True).split()
    subprocess.run([os.environ.get('CC','cc'), '-std=c11','-O2','-Wall','-Wextra','-Werror',
        '-DCODEGRAPH_PACKED_CODEC',f'-DCG_CODEGRAPH_ZSTD_LEVEL={level}',
        '-I'+str(PROJECT/'include'),'-I'+str(source_dir/'tools'),str(driver),
        str(source_dir/'tools/qihse_codegraph_storage.c'),str(source_dir/'tools/qihse_codegraph_packed.c'),
        *([str(source_dir/'tools/qihse_codegraph_dictionary.c')] if (source_dir/'tools/qihse_codegraph_dictionary.c').exists() else []),
        *checksum_sources(source_dir),
        '-o',str(output),'-L'+str(library_dir),'-lqihse',*flags,'-ldl','-lm','-lpthread'],check=True)

def measure(binaries: dict, library_dir: Path, nodes: int, repeats: int) -> dict:
    with tempfile.TemporaryDirectory(prefix='qihse-zip-storage-fixture-') as td:
        root=Path(td); repo=root/'repo'; repo.mkdir(); subprocess.run(['git','init','-q',str(repo)],check=True)
        fixture=root/'graph.jsonl'
        old={k:os.environ.get(k) for k in ('GIT_AUTHOR_DATE','GIT_COMMITTER_DATE')}
        try:
            for k in old: os.environ[k]='2024-01-01T00:00:00+00:00'
            graph_fixture(repo,fixture,nodes,nodes*3)
        finally:
            for k,v in old.items():
                if v is None: os.environ.pop(k,None)
                else: os.environ[k]=v
        rows=[]; cases=[(v,b) for v in binaries for b in ('zstd','packed')]
        for repeat in range(repeats):
            offset=repeat%len(cases)
            for variant,backend in cases[offset:]+cases[:offset]:
                folder=root/f'{repeat}-{variant}-{backend}';folder.mkdir(mode=0o700)
                state=folder/'state';state.mkdir(mode=0o700)
                env=os.environ.copy();env.update(QIHSE_DATA_DIR=str(state),XDG_STATE_HOME=str(state))
                env['LD_LIBRARY_PATH']=str(library_dir)+':'+env.get('LD_LIBRARY_PATH','')
                start=time.perf_counter()
                p=subprocess.run([str(binaries[variant]),backend,str(fixture),str(folder/'snapshot')],env=env,capture_output=True,text=True)
                if p.returncode: raise RuntimeError(f'{variant}/{backend} exited {p.returncode}: {p.stderr[-2000:]}')
                row=json.loads(p.stdout);row.update(variant=variant,repeat=repeat,process_wall_ms=round((time.perf_counter()-start)*1000,3))
                row['raw_sha256']=sha256(folder/'snapshot.raw')
                row['complete_encode_wall_ms']=round(row['encode_ms']+(row['raw_export_ms'] if backend=='packed' else 0),3)
                assert row['raw_roundtrip'] and row['low_clearance_denied']
                rows.append(row);print(json.dumps({'nodes':nodes,**row}),flush=True)
        assert len({(r['fingerprint'],r['record_count'],r['raw_sha256']) for r in rows})==1
        keys=('snapshot_apparent_bytes','snapshot_allocated_bytes','complete_encode_wall_ms','encode_cpu_ms','load_ms','load_cpu_ms','peak_rss_kib')
        return {'nodes':nodes,'edges':nodes*3,'fixture_sha256':sha256(fixture),'runs':rows,
            'medians':{v:{b:{k:statistics.median(r[k] for r in rows if r['variant']==v and r['backend']==b) for k in keys} for b in ('zstd','packed')} for v in binaries}}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--baseline-dir',type=Path,required=True);p.add_argument('--library-dir',type=Path,default=PROJECT)
    p.add_argument('--nodes',type=int,nargs='+',default=[800,8000]);p.add_argument('--repeats',type=int,default=3)
    p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    if a.repeats<1 or any(n<8 or n>24000 for n in a.nodes):p.error('invalid repeats/nodes')
    lib=a.library_dir.resolve();base=a.baseline_dir.resolve();library_sha=sha256(lib/'libqihse.so')
    with tempfile.TemporaryDirectory(prefix='qihse-zip-storage-build-') as td:
        binaries={}
        for name,root,level in [('baseline9',base,9),('candidate9',PROJECT,9),('candidate3',PROJECT,3)]:
            binary=Path(td)/name;build(binary,root,lib,level);binaries[name]=binary
        result={'method':'Real authenticated SDK snapshot-open path; same synthetic exports; exact standalone codec roundtrip and full metadata fingerprints; low-clearance native load+codec denial; fresh process per case; peak RSS includes fixture construction and source store, captured before separate codec roundtrip; shared host, no OS cache dropping',
            'cpu_note':'Packed encode CPU excludes separately measured raw export; complete_encode_wall_ms includes that export. Zstd includes export in encode CPU.',
            'library_sha256':library_sha,'baseline_sources':{n:sha256(base/'tools'/n) for n in ('qihse_codegraph_storage.c','qihse_codegraph_packed.c')},
            'candidate_sources':{n:sha256(PROJECT/'tools'/n) for n in ('qihse_codegraph_storage.c','qihse_codegraph_packed.c')},
            'fixtures':[measure(binaries,lib,n,a.repeats) for n in a.nodes]}
    if sha256(lib/'libqihse.so')!=library_sha:raise RuntimeError('shared library changed during benchmark')
    a.output.write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
    print(json.dumps({'output':str(a.output),'medians':[f['medians'] for f in result['fixtures']]}))
if __name__=='__main__':main()
