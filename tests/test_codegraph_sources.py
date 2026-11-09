#!/usr/bin/env python3
"""Explicit disk/editor source identity: independent C/Python and native checks."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('codegraph_source', ROOT/'tools/qihse_codegraph_reindex_source.py')
source = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(source)
BINARY = None
SANITIZE = False
DRIVER = r'''
#include "qihse_codegraph_source.h"
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#define PASSWORD "SourceProviderFixture7!"
int main(int argc,char **argv) {
 assert(argc==3);assert(qihse_auth_init());assert(qihse_auth_bootstrap_operator(PASSWORD));
 qihse_user_t *admin=qihse_auth_authenticate_id(0,PASSWORD);assert(admin);
 const char *overlay=!strcmp(argv[2],"-")?NULL:argv[2];
 cg_source_identity id;memset(&id,0x61,sizeof(id));
 if(!cg_source_identity_user(argv[1],overlay,admin,0,0,&id)) {
  printf("{\"denied\":true,\"errno\":%d}\n",errno);return 3;
 }
 qihse_user_t *created=qihse_auth_create_user(admin,70,QIHSE_ROLE_GUEST,0,0,PASSWORD,false);assert(created);
 qihse_user_t *low=qihse_auth_authenticate_id(70,PASSWORD);assert(low);
 created=qihse_auth_create_user(admin,71,QIHSE_ROLE_ANALYST,7,1,PASSWORD,false);assert(created);
 qihse_user_t *wrong=qihse_auth_authenticate_id(71,PASSWORD);assert(wrong);
 cg_source_identity denied,zero={0};memset(&denied,0x61,sizeof(denied));
 assert(!cg_source_identity_user(argv[1],overlay,NULL,0,0,&denied)&&errno==EACCES&&!memcmp(&denied,&zero,sizeof(zero)));
 memset(&denied,0x61,sizeof(denied));
 assert(!cg_source_identity_user(argv[1],overlay,low,7,2,&denied)&&errno==EACCES&&!memcmp(&denied,&zero,sizeof(zero)));
 memset(&denied,0x61,sizeof(denied));
 assert(!cg_source_identity_user(argv[1],overlay,wrong,5,2,&denied)&&errno==EACCES&&!memcmp(&denied,&zero,sizeof(zero)));
 printf("{\"digest\":\"%s\",\"disk\":\"%s\",\"effective\":\"%s\",\"overlay\":\"%s\",\"files\":%llu,\"bytes\":%llu,\"authorization_negatives\":3}\n",
 id.digest,id.disk_digest,id.effective_digest,id.overlay_digest,(unsigned long long)id.effective_files,(unsigned long long)id.effective_bytes);
 return 0;
}
'''


class Sources(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.compiled = tempfile.TemporaryDirectory(prefix='codegraph-source-driver-')
        parent = Path(cls.compiled.name)
        driver = parent/'driver.c'
        driver.write_text(DRIVER)
        cls.driver = parent/'source-driver'
        flags = subprocess.check_output(['pkg-config', '--cflags', '--libs', 'json-c', 'openssl'], text=True)
        command = [os.environ.get('CC', 'cc'), '-std=c11', '-O1' if SANITIZE else '-O2',
                   '-Wall', '-Wextra', '-Werror', '-D_GNU_SOURCE', '-I'+str(ROOT/'include'),
                   '-I'+str(ROOT/'tools'), str(driver), str(ROOT/'tools/qihse_codegraph_source.c'),
                   '-L'+str(ROOT), '-lqihse', '-lpthread', '-lm', '-o', str(cls.driver),
                   *shlex.split(flags)]
        if SANITIZE:
            command[1:1] = ['-fsanitize=address,undefined', '-fno-omit-frame-pointer']
        subprocess.run(command, check=True)

    @classmethod
    def tearDownClass(cls):
        cls.compiled.cleanup()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='codegraph-explicit-source-')
        self.path = Path(self.temp.name)
        self.repo = self.path/'non-git'
        self.repo.mkdir()
        (self.repo/'alpha.py').write_text('def disk_symbol():\n    return 1\n')
        (self.repo/'nested').mkdir()
        (self.repo/'nested'/'unicode-λ.txt').write_text('content\x00\n')
        self.overlay = self.path/'editor.json'

    def tearDown(self):
        self.temp.cleanup()

    def identity(self, overlay=False):
        return source.source_identity(self.repo, provider='filesystem',
                                      overlay_path=self.overlay if overlay else None)

    def native(self, overlay=False, denied=False):
        data = self.path/('auth-'+str(len(list(self.path.glob('auth-*')))))
        data.mkdir(mode=0o700)
        env = os.environ.copy()
        env['QIHSE_DATA_DIR'] = str(data)
        env['LD_LIBRARY_PATH'] = str(ROOT) + os.pathsep + env.get('LD_LIBRARY_PATH', '')
        env['ASAN_OPTIONS'] = 'detect_leaks=0:halt_on_error=1'
        result = subprocess.run([str(self.driver), str(self.repo), str(self.overlay) if overlay else '-'],
                                text=True, capture_output=True, env=env)
        self.assertEqual(result.returncode, 3 if denied else 0, result.stderr+result.stdout)
        return json.loads(result.stdout.strip().splitlines()[-1])

    def test_non_git_independent_native_parity_and_authorization(self):
        with patch.object(source, '_git', side_effect=AssertionError('Git called')):
            identity = self.identity()
        native = self.native()
        self.assertEqual(native['digest'], identity['worktree_v2'])
        self.assertEqual(native['disk'], identity['source_disk_digest'])
        self.assertEqual(native['authorization_negatives'], 3)
        self.assertEqual(native['files'], 2)

    def test_content_changes_even_when_size_and_mtime_preserved(self):
        before = self.identity()
        path = self.repo/'alpha.py'
        info = path.stat()
        path.write_bytes(path.read_bytes().replace(b'return 1', b'return 2'))
        os.utime(path, ns=(info.st_atime_ns, info.st_mtime_ns))
        self.assertNotEqual(before, self.identity())
        self.assertEqual(self.native()['digest'], self.identity()['worktree'])

    def test_add_delete_rename_and_exclusions(self):
        before = self.identity()
        (self.repo/'.git').mkdir()
        (self.repo/'.git'/'ignored').write_text('ignored')
        (self.repo/'.code-review-graph').mkdir()
        (self.repo/'.code-review-graph'/'ignored').write_text('ignored')
        self.assertEqual(before, self.identity())
        (self.repo/'new.c').write_text('int added;')
        added = self.identity()
        self.assertNotEqual(before, added)
        (self.repo/'new.c').rename(self.repo/'renamed.c')
        self.assertNotEqual(added, self.identity())
        (self.repo/'renamed.c').unlink()
        self.assertEqual(before, self.identity())
        self.assertEqual(self.native()['digest'], before['worktree'])

    def test_overlay_parity_and_actual_materialized_bytes(self):
        source.write_overlay_snapshot(self.overlay, {'alpha.py': b'def unsaved_symbol():\n    return 7\n',
            'new.py': b'def added_symbol():\n    pass\n', 'nested/unicode-λ.txt': None})
        identity = self.identity(True)
        native = self.native(True)
        self.assertEqual(native['digest'], identity['worktree'])
        self.assertEqual(native['effective'], identity['source_effective_digest'])
        staged = self.path/'effective-tree'
        self.assertEqual(source.materialize_source(self.repo, staged, overlay_path=self.overlay), identity)
        self.assertIn(b'unsaved_symbol', (staged/'alpha.py').read_bytes())
        self.assertFalse((staged/'nested'/'unicode-λ.txt').exists())
        self.assertIn(b'disk_symbol', (self.repo/'alpha.py').read_bytes())
        (self.repo/'alpha.py').write_text('def different_disk_symbol(): pass\n')
        self.assertNotEqual(identity, self.identity(True))

    def test_overlay_revision_changes_identity(self):
        source.write_overlay_snapshot(self.overlay, {'alpha.py': b'unsaved1'})
        before = self.identity(True)
        source.write_overlay_snapshot(self.overlay, {'alpha.py': b'unsaved2'})
        self.assertNotEqual(before, self.identity(True))
        self.assertEqual(self.native(True)['digest'], self.identity(True)['worktree'])

    def test_symlinks_specialfiles_and_untrusted_overlay_fail_closed(self):
        (self.path/'outside.txt').write_text('outside source sentinel')
        (self.repo/'link').symlink_to(self.path/'outside.txt')
        with self.assertRaises(ValueError):
            self.identity()
        self.native(denied=True)
        (self.repo/'link').unlink()
        os.mkfifo(self.repo/'fifo')
        with self.assertRaises(ValueError):
            self.identity()
        self.native(denied=True)
        (self.repo/'fifo').unlink()
        source.write_overlay_snapshot(self.overlay, {'alpha.py': b'x'})
        self.overlay.chmod(0o644)
        with self.assertRaises(ValueError):
            self.identity(True)
        self.native(True, denied=True)

    def test_overlay_malformed_duplicates_canonical_and_traversal(self):
        payloads = [b'{"version":1,"files":[],"files":[]}',
                    b'{"version":1,"files":[{"path":"../escape","deleted":true}]}',
                    b'{"version":1,"files":[{"path":"alpha.py","content_b64":"/x=="}]}',
                    b'{"version":1,"files":[{"path":"a","deleted":true},{"path":"a","deleted":true}]}',
                    b'{"version":2,"files":[]}', b'{"version":1,"files":[]}\n',
                    b'{"version":1,"files":[{"path":"\xc0\xaf","deleted":true}]}']
        for raw in payloads:
            with self.subTest(raw=raw):
                self.overlay.write_bytes(raw)
                self.overlay.chmod(0o600)
                with self.assertRaises((ValueError, TypeError)):
                    self.identity(True)
                self.native(True, denied=True)

    def test_overlay_file_directory_collision(self):
        source.write_overlay_snapshot(self.overlay, {'a': b'file', 'a-b': b'separator', 'a/x': b'child'})
        with self.assertRaises(ValueError):
            self.identity(True)
        self.native(True, denied=True)

    def test_staging_failure_removes_partial_copy(self):
        destination = self.path/'stage'
        with patch.object(source, '_source_scan', wraps=source._source_scan) as scan:
            old = self.identity()
            original = source.source_identity
            calls = 0
            def identity(*args, **kwargs):
                nonlocal calls
                calls += 1
                value = original(*args, **kwargs)
                if calls == 3:
                    value = dict(value, worktree='f'*64)
                return value
            with patch.object(source, 'source_identity', side_effect=identity):
                with self.assertRaises(ValueError):
                    source.materialize_source(self.repo, destination)
        self.assertFalse(destination.exists())
        self.assertEqual(old, self.identity())

    def test_growing_file_during_copy_is_bounded_and_removed(self):
        destination = self.path/'growing-stage'
        target = self.repo/'alpha.py'
        inode = target.stat().st_ino
        scan = source._source_scan
        read = source.os.read
        scans = 0
        growing = False
        copied_reads = []
        def scan_then_enable(*args):
            nonlocal scans
            result = scan(*args)
            scans += 1
            return result
        def grow_on_copy(fd, amount):
            nonlocal growing
            data = read(fd, amount)
            if scans >= 2 and os.fstat(fd).st_ino == inode:
                copied_reads.append(amount)
                if not growing:
                    growing = True
                    with target.open('ab') as output:
                        output.write(b'changed after captured copy size')
            return data
        with patch.object(source, '_source_scan', side_effect=scan_then_enable), \
                patch.object(source.os, 'read', side_effect=grow_on_copy):
            with self.assertRaisesRegex(ValueError, 'changed during staging'):
                source.materialize_source(self.repo, destination)
        self.assertTrue(growing)
        self.assertTrue(all(amount <= 65536 for amount in copied_reads))
        self.assertFalse(destination.exists())

    def test_budget_overflow_and_hardlinked_overlay_denied(self):
        oversized = self.repo/'oversized.bin'
        with oversized.open('wb') as output:
            output.truncate(source.SOURCE_MAX_FILE_BYTES + 1)
        with self.assertRaises(ValueError):
            self.identity()
        self.native(denied=True)
        oversized.unlink()
        source.write_overlay_snapshot(self.overlay, {'alpha.py': b'x'})
        os.link(self.overlay, self.path/'overlay-alias')
        with self.assertRaises(ValueError):
            self.identity(True)
        self.native(True, denied=True)

    def test_actual_progress_is_content_free_and_bad_fd_nonfatal(self):
        reader, writer = os.pipe2(os.O_NONBLOCK)
        try:
            with patch.dict(os.environ, {'QIHSE_CODEGRAPH_PROGRESS_FD': str(writer)}):
                self.identity()
            frames = [json.loads(line) for line in os.read(reader, 65536).splitlines()]
            self.assertTrue(frames)
            self.assertTrue(all(frame['phase'] == 'source-hash' and frame['total'] is None
                                for frame in frames))
            self.assertGreaterEqual(max(frame['completed'] for frame in frames
                                        if frame['unit'] == 'files'), 2)
            self.assertGreaterEqual(max(frame['completed'] for frame in frames
                                        if frame['unit'] == 'bytes'), 30)
            self.assertNotIn('alpha.py', json.dumps(frames))
            for invalid in ('9' * 10000, '-1', 'invalid'):
                with patch.dict(os.environ, {'QIHSE_CODEGRAPH_PROGRESS_FD': invalid}):
                    self.identity()
        finally:
            os.close(reader)
            os.close(writer)

    def make_export(self, identity, name='disk_symbol'):
        header = dict(t='h', format='qihse-codegraph-v1', version=1, **identity)
        node = dict(t='n', id=hashlib.sha256(name.encode()).hexdigest(), file='alpha.py',
                    name=name, kind='Function', line_start=1, line_end=2, is_test=False)
        body = b''.join((json.dumps(row, separators=(',', ':'))+'\n').encode() for row in (header,node))
        trailer = dict(t='end', nodes=1, edges=0, unresolved_edges=0, sha256=hashlib.sha256(body).hexdigest())
        path = self.path/'graph.jsonl'
        path.write_bytes(body+(json.dumps(trailer)+'\n').encode())
        return path

    def test_prepared_export_binds_checked_filesystem_identity(self):
        identity = self.identity()
        export = self.make_export(identity)
        target = self.path/'prepared.jsonl'
        source.prepare_export(export, target, identity)
        rows = [json.loads(line) for line in target.read_bytes().splitlines()]
        self.assertEqual(rows[0]['source_disk_digest'], identity['source_disk_digest'])
        self.assertEqual(rows[-1]['sha256'], hashlib.sha256(b''.join(target.read_bytes().splitlines(keepends=True)[:-1])).hexdigest())
        bad = dict(identity, worktree='f'*64, worktree_v2='f'*64)
        with self.assertRaises(ValueError):
            source.prepare_export(export, self.path/'bad.jsonl', bad)

    def test_native_non_git_overlay_query_and_stale_rejection(self):
        if not BINARY:
            self.skipTest('native integration binary not supplied')
        env = os.environ.copy()
        env['XDG_STATE_HOME'] = str(self.path/'state')
        env['LD_LIBRARY_PATH'] = str(ROOT)+os.pathsep+env.get('LD_LIBRARY_PATH','')
        def invoke(*args, expected=0):
            proc = subprocess.run([str(BINARY), *args, '--repo', str(self.repo)], env=env,
                                  text=True, capture_output=True)
            self.assertEqual(proc.returncode, expected, proc.stdout+proc.stderr)
            return json.loads(proc.stdout.strip().splitlines()[-1])
        export = self.make_export(self.identity())
        invoke('import','--input',str(export))
        self.assertGreater(invoke('query','--symbol','disk_symbol')['shown_nodes'],0)
        (self.repo/'alpha.py').write_text('def changed(): pass\n')
        invoke('query','--symbol','disk_symbol',expected=2)
        source.write_overlay_snapshot(self.overlay, {'alpha.py': b'def unsaved_symbol(): pass\n'})
        stage=self.path/'effective'
        identity=source.materialize_source(self.repo,stage,overlay_path=self.overlay)
        self.assertIn(b'unsaved_symbol',(stage/'alpha.py').read_bytes())
        export=self.make_export(identity,'unsaved_symbol')
        invoke('import','--input',str(export))
        self.assertGreater(invoke('query','--symbol','unsaved_symbol')['shown_nodes'],0)
        source.write_overlay_snapshot(self.overlay, {'alpha.py': b'def newer(): pass\n'})
        invoke('query','--symbol','unsaved_symbol',expected=2)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', type=Path)
    parser.add_argument('--sanitize', action='store_true')
    args, remaining = parser.parse_known_args()
    BINARY = args.binary.resolve() if args.binary else None
    SANITIZE = args.sanitize
    unittest.main(argv=[__file__, *remaining])
