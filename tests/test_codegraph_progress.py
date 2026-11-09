#!/usr/bin/env python3
"""Dedicated child-FD progress tests; disposable stubs, no QIHSE data access."""
import contextlib
import importlib.machinery
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import time
import unittest

import test_codegraph_reindex as reindex_tests

WRAPPER = Path(__file__).resolve().parents[1] / 'tools' / 'qihse-codegraph-reindex'
sys.path.insert(0, str(WRAPPER.parent))
loader = importlib.machinery.SourceFileLoader('codegraph_progress_wrapper', str(WRAPPER))
spec = importlib.util.spec_from_loader(loader.name, loader)
wrapper = importlib.util.module_from_spec(spec)
loader.exec_module(wrapper)


def event(completed=1, total=10, phase='import', unit='records'):
    return dict(version=1, phase=phase, unit=unit, completed=completed, total=total)


EMITTER = r'''
if stage == os.environ.get('EVENT_STAGE', 'migrate'):
    fd = int(os.environ['QIHSE_CODEGRAPH_PROGRESS_FD'])
    assert not os.get_blocking(fd)
    items = json.loads(os.environ.get('EVENTS', '[]'))
    for item in items:
        data = ((json.dumps(item) if not isinstance(item, str) else item)+'\n').encode()
        try:
            os.write(fd, data)
        except BlockingIOError:
            pass
        if os.environ.get('EVENT_DELAY'):
            time.sleep(float(os.environ['EVENT_DELAY']))
    if os.environ.get('CLOSE_TELEMETRY'):
        os.close(fd)
'''


class ChildProgressTests(unittest.TestCase):
    setUp = reindex_tests.ReindexTests.setUp
    tearDown = reindex_tests.ReindexTests.tearDown
    run_wrapper = reindex_tests.ReindexTests.run_wrapper
    events = reindex_tests.ReindexTests.events

    def install_emitter(self):
        for path in (self.native, self.crg):
            path.write_text(f'#!{sys.executable}\n'+reindex_tests.STUB.replace(
                "if stage == 'stats':\n", EMITTER+"\nif stage == 'stats':\n"))
            path.chmod(0o700)

    def test_actual_byte_and_record_events_are_shown(self):
        self.install_emitter()
        rows = [event(32, 64, unit='bytes'), event(5, 10), event(10, 10)]
        result = self.run_wrapper('--migrate-only', env=self.env | {'EVENTS': json.dumps(rows)})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('import', result.stderr)
        self.assertIn('10/10 records', result.stderr)
        self.assertIn('1/1 stages Complete', result.stderr)
        self.assertNotIn('100%', result.stderr)
        self.assertNotIn('\x1b', result.stderr)
        self.assertEqual(json.loads(result.stdout), {'status': 'migrated'})

    def test_partial_then_failed_work_never_completes(self):
        self.install_emitter()
        result = self.run_wrapper('--migrate-only', env=self.env | {
            'EVENTS': json.dumps([event(1, 10)]), 'FAIL_STAGE': 'migrate'})
        self.assertEqual(result.returncode, 7, result.stderr)
        self.assertIn('1/10 records', result.stderr)
        self.assertNotIn('Complete', result.stderr)
        self.assertNotIn('100%', result.stderr)
        self.assertFalse((self.root/'state'/'qihse-codegraph-reindex'/'timings.json').exists())

    def test_completed_subphase_does_not_claim_publication(self):
        self.install_emitter()
        result = self.run_wrapper('--migrate-only', env=self.env | {
            'EVENTS': json.dumps([event(10, 10)]), 'FAIL_STAGE': 'migrate'})
        self.assertEqual(result.returncode, 7, result.stderr)
        self.assertIn('10/10 records', result.stderr)
        self.assertIn('0/1 stages', result.stderr)
        self.assertNotIn('Complete', result.stderr)
        self.assertNotIn('['+'#'*24+']', result.stderr)

    def test_flooded_non_tty_counter_logs_are_bounded(self):
        self.install_emitter()
        rows = [event(n, 200) for n in range(201)]
        result = self.run_wrapper('--migrate-only', env=self.env | {'EVENTS': json.dumps(rows), 'EVENT_DELAY': '0.001'})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertLessEqual(result.stderr.count('| import'), 2)
        self.assertIn('200/200 records', result.stderr)
        self.assertLess(len(result.stderr), 2000)

    def test_quick_phase_burst_keeps_actual_parse_and_export_counters_visible(self):
        self.install_emitter()
        rows = [event(2, 2, phase='scan', unit='files'),
                event(2, 2, phase='parse', unit='files'),
                event(5, 5, phase='export'),
                event(123, 123, phase='verify', unit='bytes')]
        result = self.run_wrapper('--migrate-only', env=self.env | {'EVENTS':json.dumps(rows)})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('| parse ', result.stderr)
        self.assertIn('2/2 files', result.stderr)
        self.assertIn('| export ', result.stderr)
        self.assertIn('5/5 records', result.stderr)
        self.assertIn('123/123 bytes', result.stderr)
        self.assertLessEqual(result.stderr.count(' stages Migrating existing graph |'), 8)

    def test_child_fd_is_not_leaked_to_parent_environment(self):
        self.install_emitter()
        original = os.environ.get(wrapper.PROGRESS_FD_ENV)
        env = self.env | {'EVENTS': json.dumps([event(3, None)])}
        result = self.run_wrapper('--migrate-only', env=env)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('import 3 records', result.stderr)
        self.assertEqual(os.environ.get(wrapper.PROGRESS_FD_ENV), original)
        self.assertNotIn(wrapper.PROGRESS_FD_ENV, env)

    def test_invalid_event_content_not_disclosed(self):
        self.install_emitter()
        rows = [dict(event(), path='SECRET-PAYLOAD'),
                event(1, 2, phase='SECRET-PAYLOAD'), 'SECRET-PAYLOAD',
                'Z'*600, event(4, 10)]
        result = self.run_wrapper('--migrate-only', env=self.env | {'EVENTS': json.dumps(rows)})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('4/10 records', result.stderr)
        self.assertNotIn('SECRET-PAYLOAD', result.stderr)
        self.assertNotIn('ZZZZZZ', result.stderr)

    def test_telemetry_eof_before_stage_exit_does_not_hang(self):
        self.install_emitter()
        result = self.run_wrapper('--migrate-only', env=self.env | {
            'EVENTS': json.dumps([event(1, None)]), 'CLOSE_TELEMETRY': '1',
            'SLEEP_STAGE': 'migrate', 'SLEEP_SECONDS': '0.6'})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('1/1 stages Complete', result.stderr)
        self.assertLessEqual(result.stderr.count('| import'), 1)

    def test_long_unknown_work_does_not_invent_counter(self):
        self.install_emitter()
        result = self.run_wrapper('--migrate-only', env=self.env | {
            'EVENTS': json.dumps([event(4, None)]),
            'SLEEP_STAGE': 'migrate', 'SLEEP_SECONDS': '0.6'})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr.count('| import'), 1)
        self.assertIn('import 4 records', result.stderr)
        self.assertNotIn('/None', result.stderr)


class EventParserTests(unittest.TestCase):
    def feed(self, parser, obj):
        parser.feed(json.dumps(obj).encode()+b'\n')

    def test_fragmented_records_and_monotonic_validation(self):
        parser = wrapper.ProgressEvents()
        raw = json.dumps(event(3, None)).encode()+b'\n'
        for byte in raw:
            parser.feed(bytes([byte]))
        self.assertEqual(parser.latest['completed'], 3)
        self.feed(parser, event(2, None))
        self.assertEqual(parser.latest['completed'], 3)
        self.feed(parser, event(5, 10))
        self.assertEqual(parser.latest['total'], 10)
        self.feed(parser, event(6, None))
        self.feed(parser, event(7, 11))
        self.assertEqual(parser.latest['completed'], 5)
        self.feed(parser, event(10, 10))
        self.assertEqual(parser.latest['completed'], 10)

    def test_unknown_fields_types_duplicates_and_unsafe_phases_denied(self):
        parser = wrapper.ProgressEvents()
        invalid = [[], None, 1, 'SECRET', event(True, 10), event(1, True),
                   event(-1, 10), event(11, 10), event(1 << 63, None),
                   event(1, 10, phase='../private'), event(1, 10, unit='password'),
                   dict(event(), payload='SECRET'), dict(event(), version=True),
                   dict(event(), version=2)]
        for row in invalid:
            self.feed(parser, row)
        parser.feed(b'{"version":1,"version":1,"phase":"import","unit":"records","completed":1,"total":10}\n')
        parser.feed(b'\xff\xfe\n')
        self.assertIsNone(parser.latest)
        self.assertEqual(parser.serial, 0)
        self.feed(parser, event(1, 10))
        self.assertEqual(parser.serial, 1)
        self.feed(parser, event(1, 10))
        self.assertEqual(parser.serial, 1)

    def test_oversized_unterminated_line_cannot_grow_memory(self):
        parser = wrapper.ProgressEvents()
        for _ in range(100):
            parser.feed(b'Z'*8192)
            self.assertLessEqual(len(parser.buffer), wrapper.PROGRESS_MAX_LINE)
        self.assertTrue(parser.discarding)
        parser.feed(b'\n')
        self.feed(parser, event(5, 10))
        self.assertEqual(parser.latest['completed'], 5)
        self.assertLessEqual(len(parser.seen), len(wrapper.PROGRESS_PHASES)*len(wrapper.PROGRESS_UNITS))

    def test_generation_encoding_phase_is_supported(self):
        parser = wrapper.ProgressEvents()
        self.feed(parser, event(2, 4, phase='encode-generations', unit='files'))
        self.assertEqual(parser.latest['phase'], 'encode-generations')
        self.assertEqual(parser.latest['completed'], 2)

    def test_generation_maintenance_phases_have_independent_counters(self):
        parser = wrapper.ProgressEvents()
        for phase in ('decode-generations','gc-generations','account-generations'):
            self.feed(parser, event(1, None, phase=phase, unit='chunks'))
            self.feed(parser, event(2, None, phase=phase, unit='chunks'))
            self.assertEqual(parser.latest['phase'], phase)
            self.assertEqual(parser.latest['completed'], 2)
        self.assertEqual(len(parser.seen), 3)

    def test_unknown_total_is_count_only_and_running_bar_never_full(self):
        with contextlib.redirect_stderr(io.StringIO()) as out:
            wrapper.progress(0, 3, 'Import', detail=event(9, None))
            wrapper.progress(0, 3, 'Import', detail=event(10, 10))
        text = out.getvalue()
        self.assertIn('import 9 records', text)
        self.assertIn('10/10 records', text)
        self.assertNotIn('100%', text)
        self.assertNotIn('['+'#'*24+']', text)


if __name__ == '__main__':
    unittest.main()
