#!/usr/bin/env python3
"""Reproduce the varied synthetic CodeGraph storage compression benchmark.

Uses libzstd via ctypes, three interleaved runs per level and byte-exact
round trips. No live graph state is read. Prints the temporary JSON receipt;
large generated files are removed after successful validation. Set
CODEGRAPH_BENCH_CONTENTION to describe concurrent host activity in the receipt.
"""
import os
import ctypes as C
import hashlib
import json
import pathlib
import random
import statistics
import struct
import tempfile
import time

root = pathlib.Path(tempfile.mkdtemp(prefix='qihse-codegraph-levels-'))
lib = C.CDLL('libzstd.so.1')
lib.ZSTD_versionString.restype = C.c_char_p
lib.ZSTD_createCCtx.restype = C.c_void_p
lib.ZSTD_freeCCtx.argtypes = [C.c_void_p]
lib.ZSTD_CCtx_setParameter.argtypes = [C.c_void_p,C.c_int,C.c_int]
lib.ZSTD_CCtx_setParameter.restype = C.c_size_t
lib.ZSTD_CCtx_setPledgedSrcSize.argtypes = [C.c_void_p,C.c_ulonglong]
lib.ZSTD_CCtx_setPledgedSrcSize.restype = C.c_size_t
class Buffer(C.Structure):
    _fields_ = [('data',C.c_void_p),('size',C.c_size_t),('pos',C.c_size_t)]
lib.ZSTD_compressStream2.argtypes = [C.c_void_p,C.POINTER(Buffer),C.POINTER(Buffer),C.c_int]
lib.ZSTD_compressStream2.restype = C.c_size_t
lib.ZSTD_decompress.argtypes = [C.c_void_p,C.c_size_t,C.c_void_p,C.c_size_t]
lib.ZSTD_decompress.restype = C.c_size_t
lib.ZSTD_isError.argtypes = [C.c_size_t]
lib.ZSTD_isError.restype = C.c_uint
lib.ZSTD_getErrorName.argtypes = [C.c_size_t]
lib.ZSTD_getErrorName.restype = C.c_char_p

def check(n):
    if lib.ZSTD_isError(n):
        raise RuntimeError(lib.ZSTD_getErrorName(n).decode())
    return n

def sha(tag, i):
    return hashlib.sha256(f'qihse-codegraph-size-benchmark-v1:{tag}:{i}'.encode()).hexdigest()

rng = random.Random(20261105)
ids = [sha('node',i) for i in range(50000)]
paths = [f'src/{["core","adapters","storage","query","security","analysis","protocols","runtime"][i%8]}/package_{i%97}/module_{sha("path",i)[:10]}.{["c","py","rs","cpp"][i%4]}' for i in range(2000)]
raw = root / 'fixture.kv'
with raw.open('wb') as f:
    seq = 0
    def record(key, value):
        global seq
        seq += 1
        key = key.encode()
        val = (json.dumps(value,separators=(',',':'),sort_keys=True)+'\n').encode()
        f.write(f'{len(key)} {len(val)} 0 0 0 0 {seq}\n'.encode()+key+val+b'\n')
    record('_meta',{'format':'qihse-codegraph-v1','version':1,'head':sha('head',0),'freshness':'git-status-diff-index-untracked-v2','worktree_v2':sha('tree',0)})
    for i in range(50000):
        line = rng.randrange(1,5000)
        record('n:'+ids[i],{'t':'n','id':ids[i],'file':paths[rng.randrange(len(paths))],
          'name':f'{["parse","load","evaluate","dispatch","serialize","validate","open","close"][i%8]}_{sha("symbol",i)[:12]}',
          'kind':['function','method','class','variable','interface'][i%5],
          'line_start':line,'line_end':line+rng.randrange(1,150),
          'extra_v2':{'language':['C','Python','Rust','C++'][i%4],'flags':rng.randrange(64),'signature_hash':sha('signature',i)}})
    unresolved = 0
    for i in range(100000):
        direct = i % 13 != 0
        unresolved += not direct
        eid = sha('edge',i)
        record('e:'+eid,{'t':'e','id':eid,'file':paths[rng.randrange(len(paths))],
          'source':ids[rng.randrange(len(ids))],'target':ids[rng.randrange(len(ids))] if direct else '',
          'relation':['calls','imports','inherits','references','contains','implements'][i%6],
          'line':rng.randrange(1,5000),'confidence':rng.choice([0.8,0.9,0.95,1.0]) if direct else 0.4,
          'resolution':'direct' if direct else 'unresolved','tier':'EXTRACTED' if direct else 'INFERRED','traversable':direct,
          'extra_v2':{'extractor':'tree-sitter','evidence_id':sha('evidence',i)[:24],'annotations':[i%11, i%29]}})
    record('_end',{'nodes':50000,'edges':100000,'unresolved_edges':unresolved,'sha256':sha('canonical-input',0)})

data = raw.read_bytes()
source = C.create_string_buffer(data)
verify = C.create_string_buffer(len(data))
outbuf = C.create_string_buffer(65536)
summary = {'fixture':'synthetic-varied-codegraph-v1','records':seq,'nodes':50000,'edges':100000,'raw_bytes':len(data),'raw_sha256':hashlib.sha256(data).hexdigest(),'zstd_version':lib.ZSTD_versionString().decode(),'window_log':23,'checksum':True,'block_bytes':65536,'cache':'No OS cache dropping; in-memory source to isolate codec','contention':os.environ.get('CODEGRAPH_BENCH_CONTENTION','Not recorded; measure ambient host activity'),'runs':[]}
print(json.dumps({k:v for k,v in summary.items() if k!='runs'}),flush=True)
orders = [[3,6,9,12],[12,9,6,3],[6,12,3,9]]
for roundno, order in enumerate(orders,1):
    for level in order:
        startwall = time.perf_counter(); startcpu = time.process_time()
        ctx = lib.ZSTD_createCCtx()
        assert ctx
        check(lib.ZSTD_CCtx_setParameter(ctx,100,level))
        check(lib.ZSTD_CCtx_setParameter(ctx,101,23))
        check(lib.ZSTD_CCtx_setParameter(ctx,201,1))
        check(lib.ZSTD_CCtx_setPledgedSrcSize(ctx,len(data)))
        compressed = bytearray()
        offset = 0
        while True:
            n = min(65536,len(data)-offset)
            inp = Buffer(C.addressof(source)+offset,n,0)
            mode = 2 if n<65536 else 0
            while True:
                out = Buffer(C.addressof(outbuf),65536,0)
                remaining = check(lib.ZSTD_compressStream2(ctx,C.byref(out),C.byref(inp),mode))
                compressed.extend(outbuf.raw[:out.pos])
                if inp.pos==inp.size and (mode!=2 or remaining==0):
                    break
            offset += n
            if mode==2:
                break
        lib.ZSTD_freeCCtx(ctx)
        cpu = time.process_time()-startcpu; wall = time.perf_counter()-startwall
        container = b'QCGZ0001'+struct.pack('>Q',len(data))+compressed
        artifact=root/f'level-{level}-round-{roundno}.kv'
        artifact.write_bytes(container)
        saved=artifact.read_bytes()
        assert saved[:8]==b'QCGZ0001' and struct.unpack('>Q',saved[8:16])[0]==len(data)
        frame=C.create_string_buffer(saved[16:])
        decoded=check(lib.ZSTD_decompress(verify,len(data),frame,len(saved)-16))
        assert decoded==len(data) and verify.raw==data
        item={'round':roundno,'level':level,'container_bytes':len(container),'ratio':len(data)/len(container),'cpu_seconds':round(cpu,6),'wall_seconds':round(wall,6),'roundtrip_exact':True,'sha256':hashlib.sha256(container).hexdigest()}
        summary['runs'].append(item)
        print(json.dumps(item),flush=True)
        artifact.unlink()
summary['medians']={str(level):{'container_bytes':statistics.median(r['container_bytes'] for r in summary['runs'] if r['level']==level),'cpu_seconds':statistics.median(r['cpu_seconds'] for r in summary['runs'] if r['level']==level),'wall_seconds':statistics.median(r['wall_seconds'] for r in summary['runs'] if r['level']==level)} for level in [3,6,9,12]}
receipt=root/'results.json';receipt.write_text(json.dumps(summary,indent=2)+'\n')
raw.unlink()
print('RECEIPT',receipt,flush=True)
print(json.dumps(summary['medians']),flush=True)
