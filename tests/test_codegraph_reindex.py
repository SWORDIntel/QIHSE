#!/usr/bin/env python3
"""Wrapper subprocess tests; no real graph rebuild or QIHSE data access."""
import errno
import json
import os
from pathlib import Path
import pty
import select
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest

WRAPPER = Path(__file__).resolve().parents[1] / 'tools' / 'qihse-codegraph-reindex'
STUB = r'''
import json, os, pathlib, sys, time
stage = sys.argv[1]
with open(os.environ['CALL_LOG'], 'a') as f:
    f.write(json.dumps({'stage':stage, 'args':sys.argv[1:], 'pid':os.getpid()})+'\n')
if os.environ.get('SLEEP_STAGE') == stage:
    time.sleep(float(os.environ.get('SLEEP_SECONDS','0.6')))
if os.environ.get('FAIL_STAGE') == stage:
    print('stage failure detail', file=sys.stderr)
    sys.exit(7)
repo = pathlib.Path(sys.argv[sys.argv.index('--repo')+1])
if stage == 'visualize':
    out = pathlib.Path(os.environ.get('STUB_EXPORT_DIR', str(repo/'.code-review-graph')))/'graph.qihse.jsonl'
    out.parent.mkdir(parents=True,exist_ok=True)
    out.write_text('fresh export')
    if not os.environ.get('MISSING_RECEIPT'):
        print('QIHSE CodeGraph exported: '+str(out))
elif stage == 'import':
    path = pathlib.Path(sys.argv[sys.argv.index('--input')+1])
    assert path.read_text() == 'prepared fresh export'
    assert path.parent.stat().st_mode & 0o077 == 0
    print(json.dumps({'status':'published'}))
elif stage == 'migrate':
    print(json.dumps({'status':'migrated'}))
else:
    print('index build output')
'''
HELPER = r'''
import json, os
from pathlib import Path

def log(value):
    with open(os.environ['HELPER_LOG'],'a') as f:
        f.write(json.dumps(value)+'\n')

def source_identity(repo):
    log({'operation':'identity'})
    calls = Path(os.environ['HELPER_LOG']).read_text().count('identity')
    return {'identity':'changed' if os.environ.get('CHANGE_SOURCE') and calls>1 else 'stable'}

def prepare_export(source,destination,expected):
    log({'operation':'prepare','source':str(source),'destination':str(destination)})
    if os.environ.get('FAIL_PREPARE'):
        raise ValueError('invalid exported header')
    assert expected == {'identity':'stable'}
    destination.write_text('prepared '+source.read_text())
'''


class ReindexTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='qihse-wrapper-test-')
        self.root = Path(self.temp.name)
        (self.root/'tools').mkdir()
        self.wrapper = self.root/'tools'/'qihse-codegraph-reindex'
        shutil.copyfile(WRAPPER,self.wrapper)
        (self.root/'tools'/'qihse_codegraph_reindex_source.py').write_text(HELPER)
        self.bin = self.root/'bin'; self.bin.mkdir()
        self.native = self.root/'qihse-codegraph'
        self.crg = self.bin/'code-review-graph'
        for path in (self.native,self.crg):
            path.write_text(f'#!{sys.executable}\n'+STUB); path.chmod(0o700)
        self.repo = self.root/'repo with spaces'; self.repo.mkdir(); (self.repo/'.git').mkdir()
        self.env = os.environ.copy()
        self.env.update(PATH=str(self.bin),CALL_LOG=str(self.root/'calls'),HELPER_LOG=str(self.root/'helpers'))

    def tearDown(self):
        self.temp.cleanup()

    def run_wrapper(self,*args,env=None):
        return subprocess.run([sys.executable,str(self.wrapper),'--repo',str(self.repo),*args],
                              env=env or self.env,capture_output=True,text=True,timeout=10)

    def events(self,name='calls'):
        path=self.root/name
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def test_reindex_success(self):
        result=self.run_wrapper(); self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual([e['stage'] for e in self.events()],['build','visualize','import'])
        self.assertEqual([e['operation'] for e in self.events('helpers')],['identity','identity','prepare'])
        self.assertEqual(json.loads(result.stdout),{'status':'published'})
        self.assertIn('3/3 stages Complete',result.stderr)
        self.assertNotIn('\x1b',result.stderr); self.assertNotIn('elapsed',result.stderr)
        self.assertIn('index build output',result.stderr)
        prepared=Path(self.events('helpers')[-1]['destination'])
        self.assertFalse(prepared.exists())

    def test_custom_export_directory(self):
        env=self.env|{'STUB_EXPORT_DIR':str(self.root/'custom graph location')}
        stale=self.repo/'.code-review-graph'; stale.mkdir(); (stale/'graph.qihse.jsonl').write_text('stale')
        result=self.run_wrapper(env=env); self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(self.events('helpers')[-1]['source'],str(self.root/'custom graph location'/'graph.qihse.jsonl'))

    def test_failure_propagates_without_completion(self):
        result=self.run_wrapper(env=self.env|{'FAIL_STAGE':'visualize'})
        self.assertEqual(result.returncode,7); self.assertNotIn('Complete',result.stderr)
        self.assertIn('stage failure detail',result.stderr)
        self.assertEqual([e['stage'] for e in self.events()],['build','visualize'])

    def test_missing_cli_preflight_prevents_build(self):
        self.native.unlink(); result=self.run_wrapper()
        self.assertEqual(result.returncode,2); self.assertEqual(self.events(),[])
        self.assertEqual(self.events('helpers'),[]); self.assertNotIn('Complete',result.stderr)

    def test_missing_crg_preflight_prevents_build(self):
        self.crg.unlink(); result=self.run_wrapper()
        self.assertEqual(result.returncode,2); self.assertEqual(self.events(),[])

    def test_invalid_repository(self):
        (self.repo/'.git').rmdir(); result=self.run_wrapper()
        self.assertEqual(result.returncode,2); self.assertEqual(self.events(),[])

    def test_migrate_only_does_not_require_crg(self):
        self.crg.unlink(); result=self.run_wrapper('--migrate-only')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual([e['stage'] for e in self.events()],['migrate'])
        self.assertEqual(self.events('helpers'),[])
        self.assertEqual(json.loads(result.stdout),{'status':'migrated'})
        self.assertIn('0/1 stages Migrating',result.stderr); self.assertIn('1/1 stages Complete',result.stderr)

    def test_missing_export_receipt_prevents_import(self):
        result=self.run_wrapper(env=self.env|{'MISSING_RECEIPT':'1'})
        self.assertNotEqual(result.returncode,0); self.assertNotIn('Complete',result.stderr)
        self.assertEqual([e['stage'] for e in self.events()],['build','visualize'])

    def test_changed_source_prevents_prepare_and_import(self):
        result=self.run_wrapper(env=self.env|{'CHANGE_SOURCE':'1'})
        self.assertNotEqual(result.returncode,0); self.assertNotIn('Complete',result.stderr)
        self.assertEqual([e['operation'] for e in self.events('helpers')],['identity','identity'])
        self.assertEqual([e['stage'] for e in self.events()],['build','visualize'])

    def test_invalid_export_prevents_import(self):
        result=self.run_wrapper(env=self.env|{'FAIL_PREPARE':'1'})
        self.assertNotEqual(result.returncode,0); self.assertNotIn('Complete',result.stderr)
        self.assertEqual([e['stage'] for e in self.events()],['build','visualize'])

    def test_tty_shows_elapsed_activity(self):
        master,slave=pty.openpty()
        proc=subprocess.Popen([sys.executable,str(self.wrapper),'--repo',str(self.repo),'--migrate-only'],
            env=self.env|{'SLEEP_STAGE':'migrate'},stdout=subprocess.PIPE,stderr=slave)
        os.close(slave)
        chunks=[]; deadline=time.monotonic()+10
        try:
            while time.monotonic()<deadline:
                if select.select([master],[],[],0.1)[0]:
                    try: chunk=os.read(master,65536)
                    except OSError as exc:
                        if exc.errno==errno.EIO: break
                        raise
                    if not chunk: break
                    chunks.append(chunk)
                elif proc.poll() is not None: break
            out,_=proc.communicate(timeout=2)
            self.assertEqual(proc.returncode,0)
            self.assertEqual(json.loads(out),{'status':'migrated'})
            stderr=b''.join(chunks).decode()
            self.assertGreaterEqual(stderr.count('elapsed'),2)
            self.assertIn('0/1 stages',stderr); self.assertIn('1/1 stages Complete',stderr)
        finally:
            if proc.poll() is None: proc.kill(); proc.wait()
            os.close(master)

    def interrupt(self, signum, expected):
        proc=subprocess.Popen([sys.executable,str(self.wrapper),'--repo',str(self.repo)],
            env=self.env|{'SLEEP_STAGE':'build','SLEEP_SECONDS':'30'},stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        try:
            deadline=time.monotonic()+5
            while not self.events() and time.monotonic()<deadline: time.sleep(0.02)
            self.assertTrue(self.events())
            child=self.events()[0]['pid']; proc.send_signal(signum)
            _,err=proc.communicate(timeout=8)
            self.assertEqual(proc.returncode,expected); self.assertNotIn(b'Complete',err)
            with self.assertRaises(ProcessLookupError): os.kill(child,0)
            self.assertEqual([e['stage'] for e in self.events()],['build'])
        finally:
            if proc.poll() is None: proc.kill(); proc.wait()

    def test_interrupt_stops_child_and_has_no_completion(self):
        self.interrupt(signal.SIGINT, 130)

    def test_sigterm_stops_child_and_has_no_completion(self):
        self.interrupt(signal.SIGTERM, 143)


if __name__=='__main__':
    unittest.main()
