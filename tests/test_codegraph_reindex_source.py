#!/usr/bin/env python3
"""Fresh-build identity/export adapter regression tests; isolated temporary Git only."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('reindex_source', ROOT/'tools/qihse_codegraph_reindex_source.py')
bridge = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bridge)
BINARY = None


class SourceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='codegraph-reindex-source-')
        self.root = Path(self.temp.name)
        self.repo = self.root/'repo'
        self.repo.mkdir()
        self.git('init', '-q')
        (self.repo/'tracked.c').write_text('int target(void) { return 0; }\n')
        self.git('add', '.')
        self.git('-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-qm', 'fixture')
        self.export = self.root/'old.jsonl'
        self.destination = self.root/'prepared.jsonl'

    def tearDown(self):
        self.temp.cleanup()

    def git(self, *args):
        return subprocess.check_output(['git', *args], cwd=self.repo)

    def write_export(self, identity=None, header_changes=None):
        identity = identity or bridge.source_identity(self.repo)
        header = dict(t='h', format='qihse-codegraph-v1', version=1,
                      head=identity['head'], worktree=identity['worktree'])
        header.update(header_changes or {})
        node = dict(t='n', id=hashlib.sha256(b'target').hexdigest(), file='tracked.c',
                    name='target', kind='Function', line_start=1, line_end=1, is_test=False)
        record = (json.dumps(node, indent=None, separators=(', ', ': ')) + '\n').encode()
        body = json.dumps(header).encode() + b'\n' + record
        trailer = dict(t='end', nodes=1, edges=0, unresolved_edges=0, sha256=hashlib.sha256(body).hexdigest())
        self.export.write_bytes(body + json.dumps(trailer).encode() + b'\n')
        return identity, record

    def test_identity_matches_native_formula(self):
        (self.repo/'new\tfile.c').write_bytes(b'new content')
        (self.repo/'link').symlink_to('tracked.c')
        identity = bridge.source_identity(self.repo)
        selected = bridge.SELECTED
        status = self.git('status', '--porcelain=v1', '-z', '--untracked-files=normal', *selected)
        diff = self.git('diff', '--no-ext-diff', '--no-textconv', '--binary', 'HEAD', *selected)
        index = self.git('ls-files', '--stage', '-z', *selected)
        digest = hashlib.sha256(status + b'\0' + diff + b'\0' + index + b'\0')
        for name in self.git('ls-files', '--others', '--exclude-standard', '-z', *selected).split(b'\0')[:-1]:
            path = self.repo/os.fsdecode(name)
            kind, value = (b'l', os.fsencode(os.readlink(path))) if path.is_symlink() else (b'f', path.read_bytes())
            digest.update(name+b'\0'+kind+b'\0'+hashlib.sha256(value).hexdigest().encode()+b'\0')
        self.assertEqual(identity['worktree'], hashlib.sha256(status+b'\0'+diff).hexdigest())
        self.assertEqual(identity['worktree_v2'], digest.hexdigest())

    def test_untracked_bytes_and_symlink_bound(self):
        path = self.repo/'new.c'; path.write_text('a')
        before = bridge.source_identity(self.repo)
        path.write_text('b')
        after = bridge.source_identity(self.repo)
        self.assertEqual(before['worktree'], after['worktree'])
        self.assertNotEqual(before['worktree_v2'], after['worktree_v2'])
        path.unlink(); path.symlink_to('tracked.c')
        before = bridge.source_identity(self.repo)
        path.unlink(); path.symlink_to('different.c')
        self.assertNotEqual(before['worktree_v2'], bridge.source_identity(self.repo)['worktree_v2'])

    def test_staged_only_identity(self):
        path = self.repo/'tracked.c'
        path.write_text('index-a'); self.git('add', '.'); path.write_text('working')
        before = bridge.source_identity(self.repo)
        path.write_text('index-b'); self.git('add', '.'); path.write_text('working')
        after = bridge.source_identity(self.repo)
        self.assertEqual(before['worktree'], after['worktree'])
        self.assertNotEqual(before['worktree_v2'], after['worktree_v2'])

    def test_flags_rejected(self):
        for flag in ('assume-unchanged', 'skip-worktree'):
            with self.subTest(flag=flag):
                self.git('update-index', '--'+flag, 'tracked.c')
                with self.assertRaisesRegex(ValueError, 'trust flags'):
                    bridge.source_identity(self.repo)
                self.git('update-index', '--no-'+flag, 'tracked.c')

    def test_metadata_excluded_and_unsafe_path_rejected(self):
        before = bridge.source_identity(self.repo)
        generated = self.repo/'.code-review-graph'; generated.mkdir(); (generated/'artifact').write_text('output')
        self.assertEqual(before, bridge.source_identity(self.repo))
        (self.repo/'unsafe\\name').write_text('bad')
        with self.assertRaisesRegex(ValueError, 'Unsafe'):
            bridge.source_identity(self.repo)

    def test_stream_preserves_records_and_digest(self):
        identity, record = self.write_export()
        bridge.prepare_export(self.export, self.destination, identity)
        lines = self.destination.read_bytes().splitlines(keepends=True)
        header, trailer = json.loads(lines[0]), json.loads(lines[-1])
        self.assertEqual(lines[1], record)
        self.assertEqual(header['worktree_v2'], identity['worktree_v2'])
        self.assertEqual(trailer['sha256'], hashlib.sha256(b''.join(lines[:-1])).hexdigest())
        # Already-correct v2 exports remain accepted.
        self.export.write_bytes(self.destination.read_bytes())
        bridge.prepare_export(self.export, self.destination, identity)

    def test_128_bit_graph_identity_preserved_with_sha256_source_checks(self):
        identity = bridge.source_identity(self.repo)
        node_id = hashlib.sha256(b'target').hexdigest()[:32]
        profiles = (
            dict(identity='qihse-semantic-128-v1', id_algorithm='sha256-128',
                 id_bits=128, id_collision='counter-sha256-128-v1', id_collision_attempts=256),
            dict(identity='qihse-semantic-xxh3-128-v1', id_algorithm='xxh3-128',
                 id_bits=128, id_seed=0, id_encoding='xxh128-canonical',
                 id_collision='counter-xxh3-128-v1', id_collision_attempts=256),
        )
        for profile in profiles:
            header = dict(t='h', format='qihse-codegraph-v1', version=1,
                          identity='qihse-semantic-128-v1', id_algorithm='sha256-128',
                          id_bits=128, id_collision='counter-sha256-128-v1',
                          id_collision_attempts=256, head=identity['head'],
                          worktree=identity['worktree'])
            header.update(profile)
            record = (json.dumps(dict(t='n', id=node_id, file='tracked.c', name='target',
                                      kind='Function', line_start=1, line_end=1, is_test=False))
                      + '\n').encode()
            body = json.dumps(header).encode() + b'\n' + record
            trailer = dict(t='end', nodes=1, edges=0, unresolved_edges=0,
                           sha256=hashlib.sha256(body).hexdigest())
            self.export.write_bytes(body + json.dumps(trailer).encode() + b'\n')
            for prepared_again in (False, True):
                if prepared_again:
                    self.export.write_bytes(self.destination.read_bytes())
                bridge.prepare_export(self.export, self.destination, identity)
                lines = self.destination.read_bytes().splitlines(keepends=True)
                actual_header, actual_node, actual_end = map(json.loads, lines)
                self.assertEqual(lines[1], record)
                self.assertEqual(actual_node['id'], node_id)
                self.assertEqual(len(actual_node['id']), 32)
                for key in profile:
                    self.assertEqual(actual_header[key], header[key])
                self.assertEqual(actual_header['worktree_v2'], identity['worktree_v2'])
                self.assertEqual(len(actual_header['worktree_v2']), 64)
                self.assertEqual(actual_end['sha256'], hashlib.sha256(b''.join(lines[:-1])).hexdigest())
                self.assertEqual(len(actual_end['sha256']), 64)

    def assert_failed_preserves_destination(self, identity):
        self.destination.write_bytes(b'preserve')
        with self.assertRaises((ValueError, OSError)):
            bridge.prepare_export(self.export, self.destination, identity)
        self.assertEqual(self.destination.read_bytes(), b'preserve')
        self.assertFalse(list(self.root.glob('.prepared.jsonl-*')))

    def test_reject_header_mismatch_and_v2_conflict(self):
        for change in ({'head':'0'*40}, {'worktree':'0'*64}, {'version':2},
                       {'version':True}, {'format':'other'}, {'freshness':'other'},
                       {'freshness':bridge.POLICY},
                       {'freshness':bridge.POLICY,'worktree_v2':'0'*64}):
            with self.subTest(change=change):
                identity, _ = self.write_export(header_changes=change)
                self.assert_failed_preserves_destination(identity)

    def test_reject_corrupt_order_counts_checksum_line(self):
        identity, _ = self.write_export()
        original = self.export.read_bytes()
        for mutated in (original.replace(b'target', b'TARGET'), original+b'{}\n',
                        original.replace(b'"nodes": 1', b'"nodes": 2'),
                        original[:-1], original.splitlines(keepends=True)[0],
                        b' '*bridge.MAX_LINE+b'\n',
                        original.replace(b'"version": 1', b'"version": 1, "version": 1')):
            with self.subTest(length=len(mutated)):
                self.export.write_bytes(mutated)
                self.assert_failed_preserves_destination(identity)

    def test_git_capture_bounded_and_timed(self):
        real = subprocess.Popen
        for program, setting in [("import sys;sys.stdout.write('x'*1000)", {'GIT_LIMIT':64}),
                                 ('import time;time.sleep(5)', {'TIMEOUT':0.02})]:
            def spawn(*args, **kwargs):
                return real([sys.executable, '-c', program], **kwargs)
            with patch.object(bridge.subprocess, 'Popen', side_effect=spawn), patch.multiple(bridge, **setting):
                with self.assertRaises(ValueError):
                    bridge._git(self.repo, 'ignored')

    def test_native_import(self):
        if BINARY is None:
            self.skipTest('pass --binary to validate native import')
        identity, _ = self.write_export()
        bridge.prepare_export(self.export, self.destination, identity)
        env = {**os.environ, 'HOME':str(self.root), 'XDG_STATE_HOME':str(self.root/'state'),
               'LD_LIBRARY_PATH':str(BINARY.parent)}
        for args in [('import','--input',str(self.destination)), ('status',)]:
            result = subprocess.run([str(BINARY), *args, '--repo',str(self.repo)], env=env,
                                    capture_output=True, text=True, timeout=60)
            self.assertEqual(result.returncode, 0, result.stderr+result.stdout)
            if args[0] == 'status':
                self.assertTrue(json.loads(result.stdout)['fresh'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', type=Path)
    args, remaining = parser.parse_known_args()
    BINARY = args.binary.resolve() if args.binary else None
    unittest.main(argv=[sys.argv[0], *remaining])
