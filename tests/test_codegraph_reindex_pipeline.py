#!/usr/bin/env python3
"""Private source-adapter/provider wrapper integration using disposable stubs."""
import importlib.machinery
import importlib.util
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import unittest

import test_codegraph_reindex as baseline

WRAPPER = Path(__file__).resolve().parents[1] / 'tools' / 'qihse-codegraph-reindex'
sys.path.insert(0, str(WRAPPER.parent))
loader = importlib.machinery.SourceFileLoader('codegraph_pipeline_wrapper', str(WRAPPER))
spec = importlib.util.spec_from_loader(loader.name, loader)
wrapper = importlib.util.module_from_spec(spec)
loader.exec_module(wrapper)

FILESYSTEM_HELPER = baseline.HELPER.replace(
    'def source_identity(repo):',
    "def source_identity(repo, *, provider='git', overlay_path=None):") + r'''

def materialize_source(repo, destination, *, overlay_path=None):
    import shutil
    shutil.copytree(repo, destination, ignore=shutil.ignore_patterns('.git', '.code-review-graph'))
    if overlay_path is not None:
        for path, text in json.loads(Path(overlay_path).read_text())['files'].items():
            target = destination/path
            if text is None:
                target.unlink(missing_ok=True)
            else:
                target.parent.mkdir(parents=True,exist_ok=True)
                target.write_text(text)
    log({'operation':'materialize','original':str(repo),'staged':str(destination)})
    return source_identity(repo,provider='filesystem',overlay_path=overlay_path)
'''
PARSE_CHECK = r'''
if stage == 'prepare-source' and os.environ.get('EXPECT_PARSED'):
    parsed = pathlib.Path(sys.argv[sys.argv.index('--repo')+1])
    original = pathlib.Path(sys.argv[sys.argv.index('--identity-repo')+1])
    assert parsed != original
    assert not parsed.is_relative_to(original)
    assert not (parsed/'.git').exists()
    for path, text in json.loads(os.environ['EXPECT_PARSED']).items():
        target = parsed/path
        assert not target.exists() if text is None else target.read_text() == text
'''


class PipelineTests(unittest.TestCase):
    setUp = baseline.ReindexTests.setUp
    tearDown = baseline.ReindexTests.tearDown
    run_wrapper = baseline.ReindexTests.run_wrapper
    events = baseline.ReindexTests.events

    def test_default_uses_incremental_private_adapter(self):
        shared = self.repo/'.code-review-graph'
        shared.mkdir()
        sentinel = shared/'graph.qihse.jsonl'
        sentinel.write_text('do not delete another consumer output')
        result = self.run_wrapper()
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = self.events()
        self.assertEqual([row['stage'] for row in calls], ['prepare-source', 'import'])
        args = calls[0]['args']
        self.assertNotIn('--full', args)
        self.assertNotIn('--reclaim', args)
        self.assertIn('--expected-identity', args)
        raw = Path(args[args.index('--output')+1])
        self.assertFalse(raw.is_relative_to(self.repo))
        self.assertFalse(raw.exists())
        self.assertEqual(sentinel.read_text(), 'do not delete another consumer output')
        self.assertIn('2/2 stages Complete', result.stderr)

    def test_full_and_reclaim_are_explicit_producer_options(self):
        result = self.run_wrapper('--full', '--reclaim')
        self.assertEqual(result.returncode, 0, result.stderr)
        args = self.events()[0]['args']
        self.assertIn('--full', args)
        self.assertIn('--reclaim', args)
        self.assertNotIn('--full', self.events()[1]['args'])
        self.assertNotIn('--reclaim', self.events()[1]['args'])

    def test_new_storage_formats_reach_publication_and_migration(self):
        for value in ('packed-v4', 'generations-v1'):
            for options in ((), ('--migrate-only',)):
                with self.subTest(value=value, options=options):
                    result = self.run_wrapper(*options, '--storage-format', value)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    args = self.events()[-1]['args']
                    self.assertEqual(args[args.index('--storage-format')+1], value)

    def test_query_index_is_explicit_reader_owned_third_stage(self):
        result = self.run_wrapper()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn('--query-index', self.events()[-1]['args'])
        result = self.run_wrapper('--query-index')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([e['stage'] for e in self.events()][-3:],
                         ['prepare-source','import','query-index'])
        self.assertNotIn('--query-index', self.events()[-2]['args'])
        self.assertEqual(self.events()[-1]['args'][0], 'query-index')
        self.assertIn('3/3 stages Complete', result.stderr)

    def test_query_index_failure_reports_partial_plan_without_timing_sample(self):
        result = self.run_wrapper('--query-index', env=self.env | {'FAIL_STAGE':'query-index'})
        self.assertEqual(result.returncode, 7, result.stderr)
        self.assertEqual([e['stage'] for e in self.events()],
                         ['prepare-source','import','query-index'])
        self.assertIn('Building optional query index', result.stderr)
        self.assertNotIn('Complete', result.stderr)
        self.assertFalse((self.root/'state'/'qihse-codegraph-reindex'/'timings.json').exists())

    def test_old_three_stage_timings_do_not_calibrate_new_index_plan(self):
        history = self.root/'state'/'qihse-codegraph-reindex'/'timings.json'
        history.parent.mkdir(parents=True)
        key = hashlib.sha256(os.fsencode(self.repo)).hexdigest()
        history.write_text(json.dumps({key:[{'encoded_bytes':1048576,
            'seconds':[200,300,400],'overhead_seconds':100}]}))
        first = self.run_wrapper('--query-index')
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertIn('ETA calibrating', first.stderr)
        self.assertNotIn('Estimated total', first.stderr)
        second = self.run_wrapper('--query-index')
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertIn('Estimated total', second.stderr)
        self.assertIn('from 1 completed run(s)', second.stderr)

    def test_timing_history_separates_parse_reclaim_and_encoding_modes(self):
        initial = self.run_wrapper('--full', '--reclaim', '--storage-format', 'packed-v4')
        self.assertEqual(initial.returncode, 0, initial.stderr)
        for flags in (('--reclaim','--storage-format','packed-v4'),
                      ('--full','--storage-format','packed-v4'),
                      ('--full','--reclaim','--storage-format','generations-v1')):
            with self.subTest(flags=flags):
                changed = self.run_wrapper(*flags)
                self.assertEqual(changed.returncode, 0, changed.stderr)
                self.assertIn('ETA calibrating', changed.stderr)
                self.assertNotIn('Estimated total', changed.stderr)

    def test_migrate_only_needs_no_git_or_producer(self):
        (self.repo/'.git').rmdir()
        self.crg.unlink()
        self.adapter.unlink()
        result = self.run_wrapper('--migrate-only')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([e['stage'] for e in self.events()], ['migrate'])
        self.assertEqual(self.events('helpers'), [])

    def test_missing_adapter_prevents_all_source_work(self):
        self.adapter.unlink()
        result = self.run_wrapper()
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(self.events(), [])
        self.assertEqual(self.events('helpers'), [])
        self.assertNotIn('Complete', result.stderr)

    def test_wrong_private_receipt_never_reaches_import(self):
        self.adapter.write_text(self.adapter.read_text().replace(
            "'export_path':str(out)", "'export_path':str(repo/'unexpected.jsonl')"))
        result = self.run_wrapper()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual([e['stage'] for e in self.events()], ['prepare-source'])
        self.assertIn('expected private export', result.stderr)
        self.assertNotIn('Complete', result.stderr)

    def test_explicit_python_works_without_cli_launcher(self):
        self.crg.unlink()
        result = self.run_wrapper('--producer-python', sys.executable)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([e['stage'] for e in self.events()], ['prepare-source', 'import'])

    def test_producer_python_keeps_venv_symlink_spelling(self):
        venv = self.root/'producer-venv'/'bin'
        venv.mkdir(parents=True)
        python = venv/'python'
        python.symlink_to(sys.executable)
        self.crg.write_text('#!'+str(python)+'\n# launcher\n')
        self.assertEqual(wrapper.producer_interpreter(self.crg), python)
        self.assertNotEqual(wrapper.producer_interpreter(self.crg), python.resolve())

    def test_explicit_python_path_with_spaces_keeps_exact_environment(self):
        directory = self.root/'explicit producer venv'
        directory.mkdir()
        python = directory/'python'
        python.symlink_to(sys.executable)
        self.assertEqual(wrapper.producer_interpreter(None, python), python)

    def test_env_python_shebang_is_resolved_without_shell(self):
        python = self.bin/'python3'
        python.symlink_to(sys.executable)
        self.crg.write_text('#!/usr/bin/env python3\n# launcher\n')
        old = os.environ['PATH']
        try:
            os.environ['PATH'] = str(self.bin)
            self.assertEqual(wrapper.producer_interpreter(self.crg), python)
        finally:
            os.environ['PATH'] = old

    def test_unsupported_launcher_fails_without_source_work(self):
        self.crg.write_text('#!/bin/sh\nexit 0\n')
        result = self.run_wrapper()
        self.assertEqual(result.returncode, 2)
        self.assertEqual(self.events(), [])
        self.assertIn('--producer-python', result.stderr)

    def filesystem(self):
        (self.repo/'.git').rmdir()
        (self.repo/'a.py').write_text('def disk(): pass\n')
        (self.repo/'gone.py').write_text('def removed(): pass\n')
        (self.root/'tools'/'qihse_codegraph_reindex_source.py').write_text(FILESYSTEM_HELPER)
        self.adapter.write_text(self.adapter.read_text().replace(
            "if stage == 'stats':", PARSE_CHECK+"\nif stage == 'stats':"))

    def test_non_git_filesystem_input_is_parsed_from_checked_staging(self):
        self.filesystem()
        result = self.run_wrapper('--source-provider', 'filesystem', env=self.env | {
            'EXPECT_PARSED': json.dumps({'a.py':'def disk(): pass\n'})})
        self.assertEqual(result.returncode, 0, result.stderr)
        args = self.events()[0]['args']
        parsed = Path(args[args.index('--repo')+1])
        self.assertEqual(args[args.index('--identity-repo')+1], str(self.repo))
        self.assertFalse(parsed.exists())
        self.assertEqual(self.events()[-1]['args'][2], str(self.repo))

    def test_overlay_actual_bytes_are_used_and_original_is_unchanged(self):
        self.filesystem()
        overlay = self.root/'unsaved.json'
        overlay.write_text(json.dumps({'files':{'a.py':'def unsaved(): pass\n',
                                                'gone.py':None,'new.py':'def added(): pass\n'}}))
        result = self.run_wrapper('--overlay', str(overlay), env=self.env | {
            'EXPECT_PARSED': json.dumps({'a.py':'def unsaved(): pass\n',
                                         'gone.py':None,'new.py':'def added(): pass\n'})})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.repo/'a.py').read_text(), 'def disk(): pass\n')
        self.assertTrue((self.repo/'gone.py').exists())
        self.assertFalse((self.repo/'new.py').exists())
        self.assertIn('--overlay', self.events()[0]['args'])

    def test_conflicting_overlay_git_and_migration_options_fail_before_work(self):
        for flags in (('--source-provider','git','--overlay','missing.json'),
                      ('--migrate-only','--full'), ('--migrate-only','--reclaim'),
                      ('--migrate-only','--query-index')):
            with self.subTest(flags=flags):
                result = self.run_wrapper(*flags)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertEqual(self.events(), [])
                self.assertNotIn('Complete', result.stderr)


def run_real_smoke(argv):
    """Opt-in actual producer/native smoke, isolated from configured live state."""
    import argparse,importlib.util,json,os,pathlib,shutil,subprocess,tempfile,time
    p=argparse.ArgumentParser()
    p.add_argument('--real',action='store_true')
    p.add_argument('--binary',required=True,type=pathlib.Path)
    p.add_argument('--core-library',required=True,type=pathlib.Path)
    p.add_argument('--xxh3-library',required=True,type=pathlib.Path)
    p.add_argument('--producer-python',required=True,type=pathlib.Path)
    p.add_argument('--producer-source',required=True,type=pathlib.Path)
    p.add_argument('--wrapper',required=True,type=pathlib.Path)
    p.add_argument('--source-helper',required=True,type=pathlib.Path)
    p.add_argument('--adapter',required=True,type=pathlib.Path)
    p.add_argument('--report',required=True,type=pathlib.Path)
    selection=p.add_mutually_exclusive_group()
    selection.add_argument('--git-only',action='store_true')
    selection.add_argument('--filesystem-only',action='store_true')
    p.add_argument('--query-index',action='store_true')
    a=p.parse_args(argv)
    report={'cases':[]}
    with tempfile.TemporaryDirectory(prefix='qihse-wrapper-real-') as temp:
     root=pathlib.Path(temp);delivery=root/'delivery';tools=delivery/'tools';tools.mkdir(parents=True)
     shutil.copy2(a.binary,delivery/'qihse-codegraph')
     (delivery/'libqihse.so').symlink_to(a.core_library.resolve())
     shutil.copy2(a.wrapper,tools/'qihse-codegraph-reindex')
     shutil.copy2(a.source_helper,tools/'qihse_codegraph_reindex_source.py')
     shutil.copy2(a.adapter,tools/'qihse_codegraph_incremental.py')
     env=os.environ.copy();env.update(XDG_STATE_HOME=str(root/'state'),
      PYTHONPATH=str(a.producer_source),QIHSE_CODEGRAPH_XXH3_LIBRARY=str(a.xxh3_library.resolve()),
      LD_LIBRARY_PATH=str(delivery))
     def run(command,success=True):
      value=subprocess.run([str(x) for x in command],env=env,capture_output=True,text=True,timeout=180)
      if success and value.returncode:raise AssertionError(json.dumps({'command':str(command),'status':value.returncode,'stdout':value.stdout,'stderr':value.stderr}))
      return value
     def query(repo,symbol,success=True):
      result=run([delivery/'qihse-codegraph','query','--repo',repo,'--symbol',symbol],success)
      if success:
       data=json.loads(result.stdout)
       assert data.get('fresh') is True,data
       assert any(node.get('symbol')==symbol and node.get('hop')==0 for node in data.get('nodes',[])),data
       if a.query_index:assert data.get('query_index_loaded') is True,data
      return result
     def rebuild(repo,*flags):
      print('Starting real wrapper:',repo.name,*flags,flush=True)
      start=time.monotonic()
      result=run([a.producer_python,tools/'qihse-codegraph-reindex','--repo',repo,
           '--producer-python',a.producer_python,*(['--query-index'] if a.query_index else []),*flags])
      stages=3 if a.query_index else 2
      assert f'{stages}/{stages} stages Complete' in result.stderr,result.stderr
      assert '| parse ' in result.stderr or '| export ' in result.stderr,result.stderr
      assert ' files' in result.stderr or ' records' in result.stderr,result.stderr
      assert not (repo/'.code-review-graph'/'graph.qihse.jsonl').exists()
      print('Finished real wrapper:',repo.name,round(time.monotonic()-start,2),'s',flush=True)
      return result,time.monotonic()-start
     git=root/'git';git.mkdir();source=git/'sample.py';source.write_text('def live_symbol():\n    return 1\n\ndef caller():\n    return live_symbol()\n')
     run(['git','-C',git,'init','-q']);run(['git','-C',git,'add','.'])
     run(['git','-C',git,'-c','user.name=Fixture','-c','user.email=fixture@example.invalid','-c','core.hooksPath=/dev/null','commit','-qm','fixture'])
     for label in (() if a.filesystem_only else ('git-cold','git-incremental-unchanged')):
      result,seconds=rebuild(git)
      queried=query(git,'live_symbol');assert 'live_symbol' in queried.stdout,queried.stdout
      assert json.loads(queried.stdout).get('fresh') is True,queried.stdout
      stats=json.loads(run([delivery/'qihse-codegraph','stats','--repo',git]).stdout)
      report['cases'].append({'name':label,'seconds':seconds,'encoded_bytes':stats['encoded_bytes'],'actual_progress':True,'query_fresh':True,'private_export_removed':True})
     if not a.git_only:
      fs=root/'filesystem';fs.mkdir();(fs/'sample.py').write_text('def filesystem_symbol():\n    return 2\n')
      result,seconds=rebuild(fs,'--source-provider','filesystem')
      queried=query(fs,'filesystem_symbol');assert 'filesystem_symbol' in queried.stdout
      assert json.loads(queried.stdout).get('fresh') is True,queried.stdout
      (fs/'sample.py').write_text('def changed_symbol():\n    return 3\n')
      stale=query(fs,'filesystem_symbol',False);assert stale.returncode!=0,stale.stdout
      report['cases'].append({'name':'filesystem','seconds':seconds,'actual_progress':True,'query_fresh':True,'disk_edit_rejected':True,'no_git':not(fs/'.git').exists()})
      overlayrepo=root/'overlay';overlayrepo.mkdir();(overlayrepo/'sample.py').write_text('def disk_symbol():\n    return 4\n')
      spec=importlib.util.spec_from_file_location('smoke_sources',a.source_helper);helper=importlib.util.module_from_spec(spec);spec.loader.exec_module(helper)
      overlay=root/'unsaved.json';helper.write_overlay_snapshot(overlay,{'sample.py':b'def unsaved_symbol():\n    return 5\n'})
      result,seconds=rebuild(overlayrepo,'--overlay',overlay)
      queried=query(overlayrepo,'unsaved_symbol');assert 'unsaved_symbol' in queried.stdout,queried.stdout
      assert json.loads(queried.stdout).get('fresh') is True,queried.stdout
      assert (overlayrepo/'sample.py').read_text()=='def disk_symbol():\n    return 4\n'
      helper.write_overlay_snapshot(overlay,{'sample.py':b'def newer_unsaved_symbol():\n    return 6\n'})
      stale=query(overlayrepo,'unsaved_symbol',False);assert stale.returncode!=0,stale.stdout
      report['cases'].append({'name':'unsaved-overlay','seconds':seconds,'actual_progress':True,'query_fresh':True,'overlay_change_rejected':True,'disk_unchanged':True})
    report['status']='passed';a.report.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))

if __name__ == '__main__':
    if '--real' in sys.argv:
        run_real_smoke(sys.argv[1:])
    else:
        unittest.main()
