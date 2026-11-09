#!/usr/bin/env python3
"""Compare checked canonical FFI batches; run against separately built baseline/candidate."""
import ctypes as C,time,os,json,random,statistics,hashlib
from pathlib import Path
import argparse
ap=argparse.ArgumentParser(description="Interleaved resident canonical-FFI batch comparison")
ap.add_argument('--baseline',type=Path,required=True)
ap.add_argument('--candidate',type=Path,required=True)
ap.add_argument('--variant',action='append',default=[],help='Optional additional name=library.so')
ap.add_argument('--corpus',type=Path)
ap.add_argument('--output',type=Path,required=True)
ap.add_argument('--samples',type=int,default=15)
ap.add_argument('--ms',type=int,default=5)
ap.add_argument('--cpu',type=int)
args=ap.parse_args()
if not 1<=args.samples<=1000 or not 1<=args.ms<=1000:ap.error('samples/ms out of bounds')
libs={'before':args.baseline.resolve(),'bswap':args.candidate.resolve()}
for value in args.variant:
 name,sep,path=value.partition('=')
 if not sep or not name or name in libs:ap.error('variant must be unique name=path')
 libs[name]=Path(path).resolve()
CPU=args.cpu if args.cpu is not None else max(os.sched_getaffinity(0))
if CPU not in os.sched_getaffinity(0):ap.error('CPU is outside allowed affinity')
os.sched_setaffinity(0,{CPU})
loaded={}
for name,path in libs.items():
 lib=C.CDLL(str(path));lib.qx3_backend_get.argtypes=[C.c_char_p];lib.qx3_backend_get.restype=C.c_void_p
 backend=lib.qx3_backend_get(b'sse2');assert backend
 f=lib.qx3_batch_canonical128;f.argtypes=[C.c_void_p,C.c_void_p,C.c_size_t,C.POINTER(C.c_size_t),C.c_size_t,C.c_void_p];f.restype=C.c_int
 loaded[name]=(lib,backend,f)
cases={f'1024x{n}':[bytes((i%251 for i in range(n))) for _ in range(1024)] for n in (32,96,192,256)}
if args.corpus:
 cases['source19']=[p.read_bytes() for p in sorted(args.corpus.rglob('*')) if p.is_file()]
 if not cases['source19']:ap.error('empty corpus')
rng=random.Random(71);results={}
for label,rows in cases.items():
 blob=b''.join(rows);counts=[0]
 for r in rows:counts.append(counts[-1]+len(r))
 offsets=(C.c_size_t*len(counts))(*counts);out=(C.c_ubyte*(16*len(rows)))();pointer=C.c_char_p(blob)
 baseline=None;calls={};raw={n:[] for n in libs}
 for name,(_,b,f) in loaded.items():
  assert f(b,pointer,len(blob),offsets,len(rows),out)==0
  if baseline is None:baseline=bytes(out)
  assert bytes(out)==baseline
  start=time.perf_counter_ns();repeat=0
  while time.perf_counter_ns()-start<args.ms*1_000_000: assert f(b,pointer,len(blob),offsets,len(rows),out)==0;repeat+=1
  calls[name]=max(1,repeat)
 for sample in range(args.samples):
  order=list(libs);rng.shuffle(order)
  for name in order:
   _,b,f=loaded[name];repeat=calls[name];start=time.perf_counter_ns()
   for _ in range(repeat): assert f(b,pointer,len(blob),offsets,len(rows),out)==0
   elapsed=time.perf_counter_ns()-start
   assert bytes(out)==baseline
   raw[name].append(elapsed/repeat/len(rows))
 results[label]={'count':len(rows),'bytes':len(blob),'output_sha256':hashlib.sha256(baseline).hexdigest(),'ns_per_record':{name:statistics.median(values) for name,values in raw.items()},'raw_ns_per_record':raw}
 print(label,results[label]['ns_per_record'],flush=True)
args.output.parent.mkdir(parents=True,exist_ok=True)
args.output.write_text(json.dumps({'cpu':CPU,'samples':args.samples,'ms':args.ms,'method':'shuffled interleaved samples; checked canonical FFI batch; same resident blob/output; Python call overhead shared; shared-host frequency uncontrolled','library_sha256':{name:hashlib.sha256(path.read_bytes()).hexdigest() for name,path in libs.items()},'cases':results},indent=2)+'\n')
