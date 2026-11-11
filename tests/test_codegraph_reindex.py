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
stage = 'prepare-source' if pathlib.Path(__file__).name == 'qihse_codegraph_incremental.py' else sys.argv[1]
if stage == 'stats':
    print(json.dumps({'coverage':'authorized_current_generation',
                      'encoded_bytes':int(os.environ.get('STUB_GRAPH_BYTES','1048576'))}))
    sys.exit(0)
with open(os.environ['CALL_LOG'], 'a') as f:
    f.write(json.dumps({'stage':stage, 'args':sys.argv[1:], 'pid':os.getpid()})+'\n')
if os.environ.get('SLEEP_STAGE') == stage:
    time.sleep(float(os.environ.get('SLEEP_SECONDS','0.6')))
if os.environ.get('FAIL_STAGE') == stage:
    print('stage failure detail', file=sys.stderr)
    sys.exit(7)
repo = pathlib.Path(sys.argv[sys.argv.index('--repo')+1])
if stage == 'prepare-source':
    out = pathlib.Path(sys.argv[sys.argv.index('--output')+1])
    assert not out.is_relative_to(repo)
    assert out.parent.stat().st_mode & 0o077 == 0
    assert pathlib.Path(sys.argv[sys.argv.index('--expected-identity')+1]).is_file()
    out.write_text('fresh export')
    if not os.environ.get('MISSING_RECEIPT'):
        print(json.dumps({'status':'ok','export_path':str(out)}))
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
        self.adapter = self.root/'tools'/'qihse_codegraph_incremental.py'
        for path in (self.native,self.crg,self.adapter):
            path.write_text(f'#!{sys.executable}\n'+STUB); path.chmod(0o700)
        self.repo = self.root/'repo with spaces'; self.repo.mkdir(); (self.repo/'.git').mkdir()
        self.env = os.environ.copy()
        self.env.update(PATH=str(self.bin),CALL_LOG=str(self.root/'calls'),
                        HELPER_LOG=str(self.root/'helpers'),XDG_STATE_HOME=str(self.root/'state'))

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
        self.assertEqual([e['stage'] for e in self.events()],['prepare-source','import'])
        self.assertEqual([e['operation'] for e in self.events('helpers')],['identity','identity','prepare','identity'])
        self.assertEqual(json.loads(result.stdout),{'status':'published'})
        self.assertIn('2/2 stages Complete',result.stderr)
        self.assertNotIn('\x1b',result.stderr); self.assertNotIn('elapsed',result.stderr)
        self.assertIn('export_path',result.stderr)
        prepared=Path(next(e for e in self.events('helpers') if e['operation']=='prepare')['destination'])
        self.assertFalse(prepared.exists())

    def test_shared_custom_export_directory_is_preserved(self):
        env=self.env|{'STUB_EXPORT_DIR':str(self.root/'custom graph location')}
        stale=self.repo/'.code-review-graph'; stale.mkdir(); (stale/'graph.qihse.jsonl').write_text('stale')
        result=self.run_wrapper(env=env); self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual((stale/'graph.qihse.jsonl').read_text(),'stale')
        prepared = next(e for e in self.events('helpers') if e['operation'] == 'prepare')
        self.assertFalse(Path(prepared['source']).is_relative_to(self.repo))
        self.assertFalse((self.root/'custom graph location').exists())

    def test_second_reindex_estimates_from_completed_run(self):
        first=self.run_wrapper(); self.assertEqual(first.returncode,0,first.stderr)
        self.assertIn('ETA calibrating',first.stderr)
        second=self.run_wrapper(env=self.env|{'STUB_GRAPH_BYTES':'2097152'})
        self.assertEqual(second.returncode,0,second.stderr)
        self.assertIn('Estimated total',second.stderr)
        self.assertIn('current graph 2.0 MiB',second.stderr)
        self.assertIn('ETA ~',second.stderr)
        self.assertEqual(len(self.events()),4)
        history=self.root/'state'/'qihse-codegraph-reindex'/'timings.json'
        samples=next(iter(json.loads(history.read_text()).values()))
        self.assertEqual(len(samples),2)
        self.assertGreater(samples[0]['overhead_seconds'],0)

    def test_failure_does_not_save_timing(self):
        failed=self.run_wrapper(env=self.env|{'FAIL_STAGE':'prepare-source'})
        self.assertEqual(failed.returncode,7)
        history=self.root/'state'/'qihse-codegraph-reindex'/'timings.json'
        self.assertFalse(history.exists())

    def test_failure_propagates_without_completion(self):
        result=self.run_wrapper(env=self.env|{'FAIL_STAGE':'prepare-source'})
        self.assertEqual(result.returncode,7); self.assertNotIn('Complete',result.stderr)
        self.assertIn('stage failure detail',result.stderr)
        self.assertEqual([e['stage'] for e in self.events()],['prepare-source'])

    def test_missing_cli_preflight_prevents_build(self):
        self.native.unlink(); result=self.run_wrapper()
        self.assertEqual(result.returncode,2); self.assertEqual(self.events(),[])
        self.assertEqual(self.events('helpers'),[]); self.assertNotIn('Complete',result.stderr)

    def test_missing_crg_preflight_prevents_build(self):
        self.crg.unlink(); result=self.run_wrapper()
        self.assertEqual(result.returncode,2); self.assertEqual(self.events(),[])

    def test_bundled_producer_is_used_without_path_launcher(self):
        self.crg.unlink()
        private = self.root/'libexec'/'code-review-graph'/'bin'/'python'
        private.parent.mkdir(parents=True)
        marker = self.root/'bundled-used'
        private.write_text(
            f'#!{sys.executable}\nimport os,sys\n'
            f'open({str(marker)!r}, "w").close()\n'
            f'os.execv({sys.executable!r}, [{sys.executable!r}, *sys.argv[1:]])\n'
        )
        private.chmod(0o700)
        result = self.run_wrapper()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(marker.exists())
        self.assertEqual([e['stage'] for e in self.events()], ['prepare-source', 'import'])

        marker.unlink()
        result = self.run_wrapper('--producer-python', sys.executable)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(marker.exists())

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

    def test_auto_format_reaches_native_import_and_migration(self):
        for mode in ((), ('--migrate-only',)):
            with self.subTest(mode=mode):
                result = self.run_wrapper(*mode, '--storage-format', 'auto')
                self.assertEqual(result.returncode, 0, result.stderr)
                args = self.events()[-1]['args']
                self.assertEqual(args[args.index('--storage-format') + 1], 'auto')

    def test_dictionary_format_reaches_native_import_and_migration(self):
        for mode in ((), ('--migrate-only',)):
            with self.subTest(mode=mode):
                result = self.run_wrapper(*mode, '--storage-format', 'packed-v3')
                self.assertEqual(result.returncode, 0, result.stderr)
                args = self.events()[-1]['args']
                self.assertEqual(args[args.index('--storage-format') + 1], 'packed-v3')

    def test_missing_export_receipt_prevents_import(self):
        result=self.run_wrapper(env=self.env|{'MISSING_RECEIPT':'1'})
        self.assertNotEqual(result.returncode,0); self.assertNotIn('Complete',result.stderr)
        self.assertEqual([e['stage'] for e in self.events()],['prepare-source'])

    def test_changed_source_prevents_prepare_and_import(self):
        result=self.run_wrapper(env=self.env|{'CHANGE_SOURCE':'1'})
        self.assertNotEqual(result.returncode,0); self.assertNotIn('Complete',result.stderr)
        self.assertEqual([e['operation'] for e in self.events('helpers')],['identity','identity'])
        self.assertEqual([e['stage'] for e in self.events()],['prepare-source'])

    def test_invalid_export_prevents_import(self):
        result=self.run_wrapper(env=self.env|{'FAIL_PREPARE':'1'})
        self.assertNotEqual(result.returncode,0); self.assertNotIn('Complete',result.stderr)
        self.assertEqual([e['stage'] for e in self.events()],['prepare-source'])

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
            env=self.env|{'SLEEP_STAGE':'prepare-source','SLEEP_SECONDS':'30'},stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        try:
            deadline=time.monotonic()+5
            while not self.events() and time.monotonic()<deadline: time.sleep(0.02)
            self.assertTrue(self.events())
            child=self.events()[0]['pid']; proc.send_signal(signum)
            _,err=proc.communicate(timeout=8)
            self.assertEqual(proc.returncode,expected); self.assertNotIn(b'Complete',err)
            with self.assertRaises(ProcessLookupError): os.kill(child,0)
            self.assertEqual([e['stage'] for e in self.events()],['prepare-source'])
        finally:
            if proc.poll() is None: proc.kill(); proc.wait()

    def test_interrupt_stops_child_and_has_no_completion(self):
        self.interrupt(signal.SIGINT, 130)

    def test_sigterm_stops_child_and_has_no_completion(self):
        self.interrupt(signal.SIGTERM, 143)


if __name__=='__main__':
    unittest.main()
