#!/usr/bin/env python3
"""File, pipe, invalid option, escaped name, and missing-file CLI checks."""
import pathlib, subprocess, sys, tempfile
binary=str(pathlib.Path(sys.argv[1]).resolve())
def run(*args, data=None):
    return subprocess.run([binary,*args],input=data,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=False)
empty=b'99aa06d3014798d86001c324468d497f'
abc=b'06b05ab6733a618578af5f94892f3950'
assert run(data=b'').stdout==empty+b'  -\n'
assert run(data=b'abc').stdout==abc+b'  -\n'
with tempfile.TemporaryDirectory() as t:
    base=pathlib.Path(t); a=base/'input'; a.write_bytes(b'abc')
    b=base/'odd\nname\\x'; b.write_bytes(b'')
    r=run(str(a),str(b)); assert r.returncode==0
    lines=r.stdout.splitlines(); assert len(lines)==2
    assert lines[0].startswith(abc+b'  ')
    assert lines[1].startswith(b'\\'+empty+b'  ') and b'odd\\nname\\\\x' in lines[1]
    r=run(str(base/'absent'),str(a)); assert r.returncode==1 and abc in r.stdout
    r=run('--backend','scalar','--seed','0',str(a)); assert r.returncode==0 and r.stdout.startswith(abc)
    a.write_bytes(bytes(range(256))*1000)
    ref=run('--backend','scalar',str(a)).stdout
    for name in ('sse2','avx2','avx512','auto'):
        r=run('--backend',name,str(a))
        if r.returncode==0: assert r.stdout==ref
        else: assert name!='auto' and r.returncode==2
for args in (('--backend','bogus'),('--seed','-1'),('--seed',' -1'),('--seed','+1'),('--seed','x'),('--seed','18446744073709551616'),('--bogus',)):
    assert run(*args,data=b'abc').returncode==2
assert run('--seed','0123',data=b'abc').stdout==run('--seed','123',data=b'abc').stdout
assert run('--seed','0x7b',data=b'abc').stdout==run('--seed','123',data=b'abc').stdout
assert run('--version').returncode==0
print('PASS CLI file/pipe/error/escaping checks')
