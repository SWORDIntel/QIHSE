#!/usr/bin/env python3
"""Principal-bound CodeGraph disk accounting on disposable private fixtures."""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

from test_codegraph_native import git, snapshot, snapshot_xxh3_fixture

ROOT = Path(os.environ.get('QIHSE_CODEGRAPH_TEST_SOURCE_ROOT',
                           Path(__file__).resolve().parents[1])).resolve()

# Includes the real CLI so static filesystem helpers are tested without adding
# a public raw path or security-context-free accounting API to the product.
DRIVER = r'''
#define main codegraph_cli_main
#include "tools/qihse_codegraph.c"
#undef main
int main(int argc, char **argv) {
    assert(argc == 3);
    assert(qihse_auth_init());
    const char *password = "LifecycleFixtureOnly!123";
    assert(qihse_auth_bootstrap_operator(password));
    qihse_user_t *op = qihse_auth_authenticate_id(0, password);
    assert(op);
    assert(qihse_auth_create_user(op, 77, QIHSE_ROLE_GUEST, 0, 0, password, false));
    qihse_user_t *low = qihse_auth_authenticate_id(77, password);
    assert(low);
    cg_state st = {.principal = NULL, .lease_fd = -1};
    assert(storage_accounting(&st) == NULL);
    if (!strcmp(argv[1], "protected")) {
        qihse_kv_store_t *kv = qihse_kv_store_create_user(op);
        assert(kv);
        assert(qihse_kv_set_user(kv, "classified", "DO_NOT_DISCLOSE_LIFECYCLE_SENTINEL", 2, 4, op));
        assert(cg_storage_save(kv, argv[2], op));
        qihse_kv_store_destroy(kv);
    } else if (!strcmp(argv[1], "cleanup")) {
        snprintf(st.scratch, sizeof(st.scratch), "%s", argv[2]);
        assert(snprintf(st.kv_directory, sizeof(st.kv_directory), "%s/decoded-store", argv[2]) <
               (int)sizeof(st.kv_directory));
        char lease[PATH_MAX];
        assert(snprintf(lease, sizeof(lease), "%s/.lease", argv[2]) < (int)sizeof(lease));
        st.lease_fd = private_lock(lease, LOCK_EX | LOCK_NB, true);
        assert(st.lease_fd >= 0);
        st.principal = low;
        st.read_only_graph = false;
        assert(!release_decoded_spills(&st));
        st.read_only_graph = true;
        assert(release_decoded_spills(&st));
        printf("{\"reclaimed_bytes\":%" PRIu64 ",\"reclaimed_files\":%" PRIu64 "}\n",
               st.spill_reclaimed_bytes, st.spill_reclaimed_files);
        close(st.lease_fd);
    } else return 2;
    qihse_audit_flush();
    qihse_audit_shutdown();
    return 0;
}
'''


def compile_driver(destination: Path, sanitizer: bool = False,
                   driver_text: str = DRIVER) -> Path:
    source = destination / 'accounting_fixture.c'
    source.write_text(driver_text)
    binary = destination / 'accounting_fixture'
    # Native helpers have no main(); automatically include newly integrated
    # source, projection, generation and chunked modules as well as the codecs.
    dependencies = sorted((ROOT/'tools').glob('qihse_codegraph_*.c'))
    assert dependencies, 'CodeGraph helper sources unavailable'
    flags = subprocess.check_output(['pkg-config', '--cflags', '--libs', 'json-c',
                                     'openssl', 'libzstd'], text=True).split()
    sanitize = ['-fsanitize=address,undefined', '-fno-omit-frame-pointer'] if sanitizer else []
    subprocess.run([os.environ.get('CC', 'cc'), *sanitize, '-std=c11', '-O1', '-g', '-Wall', '-Wextra',
                    '-Werror', '-D_GNU_SOURCE', '-I'+str(ROOT), '-I'+str(ROOT/'include'),
                    '-I'+str(ROOT/'core'), '-I'+str(ROOT/'tools'), str(source),
                    *(str(p) for p in dependencies),
                    str(ROOT/'tools/codegraph_xxh3/build/libqihse_xxh3.a'),
                    '-L'+str(ROOT), '-lqihse', *flags, '-lpthread', '-lm', '-ldl',
                    '-o', str(binary)], check=True, capture_output=True)
    return binary


def private_bytes(path: Path, value: bytes) -> None:
    path.write_bytes(value)
    path.chmod(0o600)


def driver_run(driver: Path, mode: str, path: Path, root: Path) -> subprocess.CompletedProcess:
    realm = root / ('realm-'+mode)
    realm.mkdir(mode=0o700)
    return subprocess.run([str(driver), mode, str(path)],
                          env={**os.environ, 'QIHSE_DATA_DIR': str(realm),
                               'LD_LIBRARY_PATH': str(ROOT)},
                          capture_output=True, text=True, timeout=60, check=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--sanitizer', action='store_true')
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    if args.sanitizer:
        os.environ.setdefault('ASAN_OPTIONS', 'detect_leaks=0')
        os.environ.setdefault('UBSAN_OPTIONS', 'halt_on_error=1:print_stacktrace=1')
    with tempfile.TemporaryDirectory(prefix='codegraph-accounting-') as temporary:
        root = Path(temporary)
        driver = compile_driver(root, args.sanitizer)
        repo = root/'repo'; repo.mkdir()
        tracked = repo/'fixture.c'; tracked.write_text('int fixture(void) { return 0; }\n')
        git(repo, 'init', '-q'); git(repo, 'add', '.')
        git(repo, '-c', 'user.name=Fixture', '-c', 'user.email=test@example.invalid',
            'commit', '-qm', 'synthetic')
        env = {**os.environ, 'XDG_STATE_HOME': str(root/'state'),
               'LD_LIBRARY_PATH': str(binary.parent)+os.pathsep+str(ROOT)}
        directory = root/'state/qihse/codegraph'/hashlib.sha256(os.fsencode(repo)).hexdigest()
        source = root/'source.jsonl'

        def invoke(*tokens: str, expect: int = 0) -> dict:
            result = subprocess.run([str(binary), *tokens, '--repo', str(repo)],
                                    env=env, capture_output=True, text=True, timeout=120)
            assert result.returncode == expect, (tokens, result.returncode, result.stdout, result.stderr)
            assert 'DO_NOT_DISCLOSE_LIFECYCLE_SENTINEL' not in result.stdout + result.stderr
            return json.loads(result.stdout)

        for version in range(2):
            tracked.write_text(f'int fixture(void) {{ return {version}; }}\n')
            snapshot(repo, source)
            invoke('import', '--input', str(source), '--storage-format', 'zstd-v1')
        manifest_path = directory/'current.json'
        manifest = json.loads(manifest_path.read_text())
        current = directory/manifest['snapshot']; previous = directory/manifest['previous_snapshot']
        historical = directory/('graph-'+'f'*64+'-ABC123.kv')
        shutil.copyfile(current, historical); historical.chmod(0o600)
        auxiliary = directory/(current.name+'.qci'); private_bytes(auxiliary, b'x'*2048)
        extra = directory/'owner-private.txt'; private_bytes(extra, b'x'*257)
        active = directory/'.runtime-accounting-active'; active.mkdir(mode=0o700)
        abandoned = directory/'.runtime-accounting-abandoned'; abandoned.mkdir(mode=0o700)
        unleased = directory/'.runtime-accounting-unleased'; unleased.mkdir(mode=0o700)
        for runtime in (active, abandoned, unleased):
            private_bytes(runtime/'fixture.bin', b'x'*4096)
        private_bytes(active/'.lease', b''); private_bytes(abandoned/'.lease', b'')
        with (active/'.lease').open('r+b') as lease:
            fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
            initial = invoke('stats')
            assert initial['coverage'] == 'authorized_current_generation'
            account = initial['storage_accounting']; categories = account['categories']
            # Guest coverage cannot attest the absence of hidden history.
            assert not account['historical_authorization_complete'], account
            assert categories['current_snapshot']['logical_bytes'] == current.stat().st_size
            assert categories['current_snapshot']['allocated_bytes'] == current.stat().st_blocks*512
            assert categories['previous_snapshot']['logical_bytes'] == previous.stat().st_size
            assert categories['historical_snapshots']['logical_bytes'] == historical.stat().st_size
            assert categories['auxiliary_indexes']['logical_bytes'] == 2048
            for category in ('active_runtimes', 'abandoned_runtimes', 'unleased_runtimes'):
                assert categories[category]['logical_bytes'] >= 4096, (category, account)
            total = account['total']
            assert total['logical_bytes'] == sum(c['logical_bytes'] for c in categories.values())
            assert total['allocated_bytes'] == sum(c['allocated_bytes'] for c in categories.values())
            # A symlink cannot import the size or contents of an outside file.
            outside = root/'outside'; private_bytes(outside, b'x'*(2 << 20))
            (directory/'outside-link').symlink_to(outside)
            linked = invoke('stats')['storage_accounting']
            assert not linked['complete'] and not linked['symlinks_followed']
            assert linked['total']['logical_bytes'] < 2 << 20
            assert outside.stat().st_size == 2 << 20
        # Guest-readable current state must not authorize historical high-data bytes.
        driver_run(driver, 'protected', historical, root)
        protected = invoke('stats')['storage_accounting']
        assert not protected['historical_authorization_complete']
        assert protected['categories']['historical_snapshots']['files'] == 0
        # The same protected snapshot as current must refuse the complete stats response.
        original_manifest = manifest_path.read_bytes()
        manifest.update(snapshot=historical.name, storage_format='qihse-codegraph-zstd-v1',
                        snapshot_hash_algorithm='xxh3-128',
                        snapshot_hash=snapshot_xxh3_fixture(binary, historical.read_bytes()))
        private_bytes(manifest_path, json.dumps(manifest).encode())
        denied = invoke('stats', expect=1)
        assert 'storage_accounting' not in denied and 'error' in denied, denied
        private_bytes(manifest_path, original_manifest)
        # Cleanup only known private KV spill leaves. Preserve active lease,
        # audit state, lookalikes, shared inodes, symlinks and nested data.
        runtime = root/'.runtime-cleanup'; runtime.mkdir(mode=0o700)
        decoded = runtime/'decoded-store'; decoded.mkdir(mode=0o700)
        delete = {'wal.log': 17, 'sstable_0.db': 31, 'sstable_12.db': 47,
                  'restore-highwater.bin': 9, 'replica-cursors.bin': 19}
        for name, size in delete.items(): private_bytes(decoded/name, b'x'*size)
        retained = ['qihse_audit.log', 'qihse_integrity.chain', 'qihse_audit.writer.lock',
                    'sstable_x.db', 'sstable_1.db.bak', 'sstable_00.db',
                    'sstable_2147483648.db', 'unrelated.txt']
        for name in retained: private_bytes(decoded/name, b'sentinel')
        (decoded/'sstable_7.db').symlink_to(outside)
        nested = decoded/'nested'; nested.mkdir(mode=0o700)
        private_bytes(nested/'sstable_1.db', b'not-owned-leaf')
        private_bytes(decoded/'shared', b'shared'); os.link(decoded/'shared', decoded/'sstable_8.db')
        cleaned = json.loads(driver_run(driver, 'cleanup', runtime, root).stdout)
        assert cleaned == {'reclaimed_bytes': sum(delete.values()), 'reclaimed_files': len(delete)}, cleaned
        assert not any((decoded/name).exists() for name in delete)
        assert all((decoded/name).read_bytes() == b'sentinel' for name in retained)
        assert (runtime/'.lease').exists() and outside.stat().st_size == 2 << 20
        assert (decoded/'sstable_7.db').is_symlink() and (decoded/'sstable_8.db').exists()
        assert (nested/'sstable_1.db').exists()
        print(json.dumps({'accounting_categories': len(categories),
                          'historical_low_clearance_denied': True,
                          'current_low_clearance_denied': True,
                          'null_principal_denied': True,
                          'symlink_not_followed': True,
                          'spill_cleanup_preserves_audit_leases_sentinels': True,
                          'cleanup': cleaned}))


if __name__ == '__main__': main()
