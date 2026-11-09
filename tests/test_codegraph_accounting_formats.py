#!/usr/bin/env python3
"""Authenticated section totals and shared-generation accounting through stats.

Fixtures live in disposable source/state. Block contents are created and read by
principal-bound native APIs; Python inspects private fixture metadata only.
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

from test_codegraph_accounting import ROOT, compile_driver, private_bytes
from test_codegraph_native import git, snapshot, write_records

SENTINEL = 'DO_NOT_DISCLOSE_FORMATS_SENTINEL'
GENERATION_DRIVER = r'''
#include "qihse_auth.h"
#include "qihse_audit.h"
#include "qihse_codegraph_generation.h"
#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
static void row(FILE *f, const char *key, const char *value, unsigned cls, unsigned sci) {
    assert(fprintf(f, "%zu %zu 0 %u %u 0 1\n", strlen(key), strlen(value), cls, sci) > 0);
    assert(fwrite(key, 1, strlen(key), f) == strlen(key));
    assert(fwrite(value, 1, strlen(value), f) == strlen(value));
    assert(fputc('\n', f) != EOF);
}
static void anonymous_checksum(FILE *f, qihse_user_t *user, cg_snapshot_checksum *out) {
    struct stat info;
    assert(qihse_auth_user_is_active(user) && !fflush(f) && !fstat(fileno(f), &info));
    assert(info.st_size >= 0 && (uint64_t)info.st_size <= (UINT64_C(4)<<20));
    unsigned char *bytes = malloc(info.st_size ? (size_t)info.st_size : 1);
    assert(bytes && pread(fileno(f), bytes, (size_t)info.st_size, 0) == info.st_size);
    assert(cg_snapshot_checksum_buffer_user(bytes, (size_t)info.st_size, user,
                                             CG_CHECKSUM_XXH3_128, out));
    free(bytes);
}
int main(int argc, char **argv) {
    assert(argc >= 3);
    const char *password = "AccountingFormatsFixture!123";
    assert(qihse_auth_init() && qihse_auth_bootstrap_operator(password));
    qihse_user_t *op = qihse_auth_authenticate_id(0, password);
    assert(op && qihse_auth_create_user(op, 77, QIHSE_ROLE_GUEST, 0, 0, password, false));
    qihse_user_t *low = qihse_auth_authenticate_id(77, password);
    assert(low);
    if (!strcmp(argv[1], "account")) {
        assert(argc >= 3 && argc <= 5);
        cg_generation_root roots[2] = {{0}};
        size_t count = (size_t)argc - 3;
        for (size_t i = 0; i < count; i++) {
            roots[i].parent = fopen(argv[3+i], "rb");
            assert(roots[i].parent);
            assert(cg_snapshot_checksum_stream_user(roots[i].parent, low, CG_CHECKSUM_XXH3_128,
                                                     &roots[i].checksum));
            rewind(roots[i].parent);
        }
        cg_generation_account account;
        assert(cg_generation_account_user(argv[2], low, roots, count, &account));
        printf("{\"referenced_bytes\":%" PRIu64 ",\"referenced_allocated_bytes\":%" PRIu64
               ",\"orphan_bytes\":%" PRIu64 ",\"orphan_allocated_bytes\":%" PRIu64
               ",\"referenced_blocks\":%u,\"orphan_blocks\":%u,\"coverage_complete\":%s}\n",
               account.referenced_bytes, account.referenced_allocated_bytes,
               account.orphan_bytes, account.orphan_allocated_bytes,
               account.referenced_blocks, account.orphan_blocks,
               account.coverage_complete ? "true" : "false");
        for (size_t i = 0; i < count; i++) fclose(roots[i].parent);
    } else {
        assert(!strcmp(argv[1], "orphan-public") || !strcmp(argv[1], "orphan-protected"));
        unsigned cls = !strcmp(argv[1], "orphan-protected") ? 4 : 0;
        unsigned sci = cls ? 2 : 0;
        FILE *raw = tmpfile(), *parent = tmpfile(), *verified = tmpfile();
        assert(raw && parent && verified);
        row(raw, "_meta", "{\"format\":\"orphan-fixture\"}", cls, sci);
        row(raw, "n:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "{\"t\":\"n\",\"id\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"file\":\"orphan.c\","
            "\"name\":\"DO_NOT_DISCLOSE_FORMATS_SENTINEL\"}", cls, sci);
        row(raw, "_end", "{\"orphan\":true}", cls, sci);
        assert(!fflush(raw)); rewind(raw);
        cg_generation_info info;
        assert(cg_generation_encode_snapshot(raw, parent, argv[2], op, UINT64_C(1)<<20, 32, &info));
        assert(!fflush(parent)); rewind(parent);
        cg_snapshot_checksum checksum;
        anonymous_checksum(parent, op, &checksum);
        rewind(parent);
        assert(cg_generation_decode_snapshot(parent, verified, argv[2], op, &checksum,
                                              UINT64_C(1)<<20, 32, NULL));
        printf("{\"new_blocks\":%u,\"new_block_bytes\":%" PRIu64 "}\n",
               info.new_blocks, info.new_block_bytes);
        fclose(raw); fclose(parent); fclose(verified);
    }
    qihse_audit_flush(); qihse_audit_shutdown();
    return 0;
}
'''


def section_sum(report: dict, storage: str) -> None:
    fields = ('framing_encoded_bytes', 'metadata_encoded_bytes', 'body_encoded_bytes',
              'storage_chunks', 'storage_sections')
    assert report['section_accounting_valid'] is True, report
    assert all(isinstance(report[key], int) and report[key] >= 0 for key in fields), report
    assert sum(report[key] for key in fields[:3]) == report['encoded_bytes'], report
    assert report['storage_chunks'] >= 1 and report['storage_sections'] >= 1
    if storage == 'zstd-v1':
        assert report['framing_encoded_bytes'] == 16 and report['metadata_encoded_bytes'] == 0
        assert report['storage_chunks'] == report['storage_sections'] == 1
    elif storage in ('packed-v2', 'packed-v3'):
        assert report['framing_encoded_bytes'] == (48 if storage == 'packed-v2' else 56)
        assert report['storage_chunks'] == 1 and report['storage_sections'] == 2
    elif storage == 'packed-v4':
        assert report['framing_encoded_bytes'] == 64 + 112 * report['storage_chunks']
        assert report['storage_sections'] == 9 * report['storage_chunks']
    elif storage == 'generations-v1':
        assert report['framing_encoded_bytes'] == 64, report


def generation_account(report: dict) -> dict:
    value = report.get('generation_account')
    if value is None:
        value = report['storage_accounting'].get('generation_account')
    assert isinstance(value, dict), report
    return value


def block_category_bytes(report: dict) -> tuple[int, int]:
    categories = report['storage_accounting']['categories']
    block_usage = [value for name, value in categories.items() if 'block' in name]
    assert block_usage, categories
    return (sum(value['logical_bytes'] for value in block_usage),
            sum(value['allocated_bytes'] for value in block_usage))


def assert_block_categories(report: dict, account: dict, directory: Path) -> None:
    authorized = (account['referenced_bytes'] + account['orphan_bytes'],
                  account['referenced_allocated_bytes'] + account['orphan_allocated_bytes'])
    actual = block_category_bytes(report)
    if account['coverage_complete']:
        # Complete authorized accounting may also include the directory inode.
        metadata = directory.stat()
        with_directory = (authorized[0] + metadata.st_size,
                          authorized[1] + metadata.st_blocks * 512)
        assert actual in (authorized, with_directory), (actual, authorized, with_directory)
    else:
        # A directory's size encodes its entry count on filesystems such as
        # tmpfs. Do not leak inaccessible/invalid entry counts through it.
        assert actual == authorized, (actual, authorized)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--formats', nargs='+', default=[
        'zstd-v1', 'packed-v2', 'packed-v3', 'packed-v4', 'generations-v1'])
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix='codegraph-accounting-formats-') as temporary:
        root = Path(temporary)
        repo = root/'repo'; repo.mkdir()
        tracked = repo/'fixture.c'; tracked.write_text('int fixture(void) { return 1; }\n')
        git(repo, 'init', '-q'); git(repo, 'add', '.')
        git(repo, '-c', 'user.name=Fixture', '-c', 'user.email=test@example.invalid',
            'commit', '-qm', 'synthetic')
        source = root/'source.jsonl'; snapshot(repo, source)
        environments = {fmt: {**os.environ, 'XDG_STATE_HOME': str(root/(fmt+'-state')),
                              'LD_LIBRARY_PATH': str(binary.parent)+os.pathsep+str(ROOT)}
                        for fmt in args.formats}
        reports = {}

        def invoke(fmt: str, *tokens: str, expect: int = 0) -> dict:
            result = subprocess.run([str(binary), *tokens, '--repo', str(repo)],
                                    env=environments[fmt], capture_output=True, text=True, timeout=180)
            assert result.returncode == expect, (fmt, tokens, result.returncode,
                                                result.stdout, result.stderr)
            assert SENTINEL not in result.stdout + result.stderr
            return json.loads(result.stdout)

        for fmt in args.formats:
            imported = invoke(fmt, 'import', '--input', str(source), '--storage-format', fmt)
            assert imported['status'] == 'published', imported
            report = invoke(fmt, 'stats'); reports[fmt] = report
            assert report['storage_format'] == 'qihse-codegraph-'+fmt, report
            section_sum(report, fmt)
            directory = (Path(environments[fmt]['XDG_STATE_HOME'])/'qihse/codegraph'/
                         hashlib.sha256(os.fsencode(repo)).hexdigest())
            manifest = json.loads((directory/'current.json').read_text())
            current = directory/manifest['snapshot']
            assert report['encoded_bytes'] == current.stat().st_size
            # Descriptor tampering cannot fall back to a raw metadata-only result.
            original = current.read_bytes()
            private_bytes(current, bytes([original[0] ^ 1])+original[1:])
            denied = invoke(fmt, 'stats', expect=1)
            assert 'section_accounting_valid' not in denied and 'storage_accounting' not in denied
            private_bytes(current, original)

        if 'generations-v1' in args.formats:
            fmt = 'generations-v1'
            # Force a new source/header and one changed file block; other file
            # blocks remain reusable between the current and previous roots.
            tracked.write_text('int fixture(void) { return 2; }\n')
            snapshot(repo, source)
            rows = [json.loads(line) for line in source.read_text().splitlines()]
            for value in rows:
                if value.get('t') == 'n' and value.get('name') == 'target':
                    value['name'] = 'target_v2'
            write_records(source, rows)
            invoke(fmt, 'import', '--input', str(source), '--storage-format', fmt)
            report = invoke(fmt, 'stats'); section_sum(report, fmt)
            directory = (Path(environments[fmt]['XDG_STATE_HOME'])/'qihse/codegraph'/
                         hashlib.sha256(os.fsencode(repo)).hexdigest())
            manifest = json.loads((directory/'current.json').read_text())
            current, previous = directory/manifest['snapshot'], directory/manifest['previous_snapshot']
            blocks = directory/'blocks'
            assert blocks.is_dir(), directory
            driver = compile_driver(root, driver_text=GENERATION_DRIVER)
            sequence = 0

            def helper(mode: str, *parents: Path) -> dict:
                nonlocal sequence
                sequence += 1
                realm = root/f'helper-realm-{sequence}'; realm.mkdir(mode=0o700)
                result = subprocess.run([str(driver), mode, str(blocks), *(str(p) for p in parents)],
                    env={**os.environ, 'QIHSE_DATA_DIR': str(realm), 'LD_LIBRARY_PATH': str(ROOT)},
                    capture_output=True, text=True, timeout=90)
                assert result.returncode == 0, (mode, result.returncode, result.stdout, result.stderr)
                assert SENTINEL not in result.stdout + result.stderr
                return json.loads(result.stdout)

            with (directory/'.storage.lock').open('r+b') as lease:
                fcntl.flock(lease, fcntl.LOCK_SH)
                current_only = helper('account', current)
                previous_only = helper('account', previous)
                union = helper('account', current, previous)
            expected = generation_account(report)
            # The authenticated Operator helper has complete coverage; guest
            # CLI totals stay deliberately incomplete to avoid existence leaks.
            assert union['coverage_complete'] and not expected['coverage_complete'], expected
            for key in ('referenced_blocks', 'referenced_bytes', 'referenced_allocated_bytes'):
                assert expected[key] == union[key], (key, expected, union)
            assert current_only['referenced_blocks'] + previous_only['referenced_blocks'] > union['referenced_blocks']
            assert current_only['referenced_bytes'] + previous_only['referenced_bytes'] > union['referenced_bytes']
            assert_block_categories(report, union, blocks)
            if 'required_current_generation_bytes' in report:
                assert report['required_current_generation_bytes'] == current.stat().st_size + current_only['referenced_bytes']
                assert report['referenced_current_block_bytes'] == current_only['referenced_bytes']
            assert not report['storage_accounting']['historical_authorization_complete'], report
            fixture_files = list(blocks.glob('*.qgb'))
            assert len(fixture_files) == union['referenced_blocks']
            assert sum(p.stat().st_size for p in fixture_files) == union['referenced_bytes']
            # Unknown files are not managed block records. Their bytes must
            # neither be disclosed nor silently omitted from a complete claim.
            unknown = blocks/'unmanaged-fixture.bin'
            with (directory/'.storage.lock').open('r+b') as lease:
                fcntl.flock(lease, fcntl.LOCK_EX)
                private_bytes(unknown, b'unknown-label-fixture')
            unknown_report = invoke(fmt, 'stats')
            unknown_account = generation_account(unknown_report)
            assert not unknown_account['coverage_complete']
            assert_block_categories(unknown_report, unknown_account, blocks)
            with (directory/'.storage.lock').open('r+b') as lease:
                fcntl.flock(lease, fcntl.LOCK_EX)
                unknown.unlink()
                public = helper('orphan-public')
            public_report = invoke(fmt, 'stats')
            public_account = generation_account(public_report)
            assert public_account['orphan_blocks'] == public['new_blocks'] > 0
            assert public_account['orphan_bytes'] == public['new_block_bytes']
            assert not public_account['coverage_complete']
            assert_block_categories(public_report, public_account, blocks)
            with (directory/'.storage.lock').open('r+b') as lease:
                fcntl.flock(lease, fcntl.LOCK_EX)
                protected = helper('orphan-protected')
            assert protected['new_blocks'] > 0
            protected_report = invoke(fmt, 'stats')
            protected_account = generation_account(protected_report)
            assert not protected_account['coverage_complete']
            for key in ('referenced_blocks', 'referenced_bytes', 'referenced_allocated_bytes',
                        'orphan_blocks', 'orphan_bytes', 'orphan_allocated_bytes'):
                assert protected_account[key] == public_account[key], (key, protected_account, public_account)
            assert_block_categories(protected_report, protected_account, blocks)
            # Protected or malformed block files must not leak through the
            # generic directory recursion's "other" category either.
            before_other = public_report['storage_accounting']['categories']['other_private_metadata']
            protected_other = protected_report['storage_accounting']['categories']['other_private_metadata']
            assert protected_other == before_other, (protected_other, before_other)
            with (directory/'.storage.lock').open('r+b') as lease:
                fcntl.flock(lease, fcntl.LOCK_EX)
                private_bytes(blocks/('f'*32+'.qgb'), b'invalid-fixture-block')
            invalid_report = invoke(fmt, 'stats')
            invalid_account = generation_account(invalid_report)
            assert not invalid_account['coverage_complete']
            for key in ('referenced_blocks', 'referenced_bytes', 'orphan_blocks', 'orphan_bytes'):
                assert invalid_account[key] == public_account[key], (key, invalid_account, public_account)
            assert_block_categories(invalid_report, invalid_account, blocks)
            reports[fmt] = report
            generation_result = {'shared_blocks_counted_once': True,
                                 'authorized_orphans_counted': public['new_blocks'],
                                 'protected_and_invalid_orphans_excluded': True}
        else:
            generation_result = None
        print(json.dumps({'formats': {fmt: {key: report[key] for key in
            ('encoded_bytes', 'framing_encoded_bytes', 'metadata_encoded_bytes',
             'body_encoded_bytes', 'storage_chunks', 'storage_sections')}
            for fmt, report in reports.items()}, 'generation': generation_result,
            'same_descriptor_corruption_denied': True}))


if __name__ == '__main__': main()
