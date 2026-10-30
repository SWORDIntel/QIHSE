#!/usr/bin/env python3
"""Isolated pinned-QKP ACK -> SIGTERM -> cold GET (never SAVE)."""
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'sdks/python'))
from qihse_admin import ClusterAdmin


class ShutdownTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='daemon-shutdown-', dir=ROOT / 'build')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for name in ('server', 'client', 'data'):
            (self.root / name).mkdir(mode=0o700)
        self.env = {k: v for k, v in os.environ.items()
                    if not k.startswith('QIHSE_') and k != 'LD_PRELOAD'}
        self.env.update(QIHSE_FIPS_MODE='disabled', LD_LIBRARY_PATH=str(ROOT),
                        QIHSE_OPERATOR_PASSWORD='ShutdownSyntheticRoot1!', QIHSE_SHUTDOWN_GRACE='5')
        # Generate synthetic identities in a separate process; never inherit auth state.
        subprocess.run([sys.executable, '-c',
                        'import ctypes,sys; l=ctypes.CDLL(sys.argv[1]); '
                        'l.qihse_pqc_init_providers(); '
                        'l.qihse_pqc_keygen.argtypes=[ctypes.c_char_p]; '
                        'l.qihse_pqc_keygen.restype=ctypes.c_bool; '
                        'assert all(l.qihse_pqc_keygen(p.encode()) for p in sys.argv[2:])',
                        str(ROOT / 'libqihse.so'), str(self.root / 'server'), str(self.root / 'client')],
                       env=self.env, check=True, capture_output=True, timeout=30)
        self.admin = ClusterAdmin(node_id='shutdown-client', identity_dir=str(self.root / 'client'),
                                  lib_path=str(ROOT / 'libqihse.so'))
        self.processes = []
        self.addCleanup(self.kill_children)

    def kill_children(self):
        for process in self.processes:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=10)

    def start(self, injection=None, extra_args=()):
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.bind(('127.0.0.1', 0))
            bus = sock.getsockname()[1]
        env = self.env.copy()
        if injection:
            env['LD_PRELOAD'] = str(self.injector())
            env['SHUTDOWN_TEST_SYNC'] = injection
        log = (self.root / ('daemon-%d.log' % len(self.processes))).open('w+b')
        self.addCleanup(log.close)
        process = subprocess.Popen([
            str(ROOT / 'qihse-cluster-daemon'), '--index', '0', '--bind', '127.0.0.1',
            '--port', str(port), '--bus-port', str(bus), '--dir', str(self.root / 'data'),
            '--pqc-identity-dir', str(self.root / 'server'), '--pqc-node-id', 'shutdown-server',
            '--pqc-trusted-pub', str(self.root / 'client/qihse_dsa_pub.pem'), '--pqc-require',
            '--admin-peer-node-id', 'shutdown-client',
            '--admin-peer-dsa-pub', str(self.root / 'client/qihse_dsa_pub.pem'), *extra_args],
            env=env, stdout=log, stderr=log)
        self.processes.append(process)
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if process.poll() is not None:
                log.seek(0)
                self.fail('isolated daemon exited before ready: ' + log.read().decode(errors='replace'))
            with socket.socket() as sock:
                if sock.connect_ex(('127.0.0.1', port)) == 0:
                    break
            time.sleep(.05)
        else:
            self.fail('isolated daemon did not listen')
        session = self.admin.session('127.0.0.1', port,
                                     str(self.root / 'server/qihse_dsa_pub.pem'),
                                     user='GODMODE_OP', password=self.env['QIHSE_OPERATOR_PASSWORD'], timeout_ms=5000)
        self.addCleanup(session.close)
        return process, session, log

    def injector(self):
        # Test-only symbol interposition: exercise real teardown without a production failpoint.
        source = self.root / 'sync-inject.c'
        library = self.root / 'sync-inject.so'
        source.write_text('''#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
void qihse_resp_server_stop(void *server) {
    if (strcmp(getenv("SHUTDOWN_TEST_SYNC"), "hang-stop") == 0)
        for (;;) pause();
    void (*stop)(void *) = dlsym(RTLD_NEXT, "qihse_resp_server_stop");
    stop(server);
}
bool qihse_kv_sync_store(void *store) {
    (void)store;
    if (strcmp(getenv("SHUTDOWN_TEST_SYNC"), "hang") == 0)
        for (;;) pause();
    return false;
}
''')
        subprocess.run(['cc', '-shared', '-fPIC', '-o', str(library), str(source)],
                       check=True, capture_output=True, timeout=30)
        return library

    def test_ack_survives_sigterm_without_save(self):
        process, session, _ = self.start()
        self.assertEqual(session.execute_resp('SET', 'shutdown:ack', 'durable-value'), b'+OK\r\n')
        # Keep the authenticated client open: stop must drain it before freeing the store.
        process.terminate()
        self.assertEqual(process.wait(timeout=15), 0)
        session.close()
        process, session, _ = self.start()
        self.assertEqual(session.execute_resp('GET', 'shutdown:ack'), b'$13\r\ndurable-value\r\n')
        process.terminate()
        self.assertEqual(process.wait(timeout=15), 0)

    def test_startup_hold_preserves_ownership_until_operator_resume(self):
        # Reserve an absent peer's endpoints so no unrelated listener can answer.
        with socket.socket() as missing, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as bus:
            missing.bind(('127.0.0.1', 0))
            bus.bind(('127.0.0.1', 0))
            peer_port = missing.getsockname()[1]
            peer_bus = bus.getsockname()[1]
            process, session, _ = self.start(extra_args=(
                '--failover-start-paused', '--slot-range', '0-8191',
                '--node', f'1:127.0.0.1:{peer_port}:{peer_bus}',
                '--slot-range-of', '1:8192-16383'))

            def nodes():
                reply = session.execute_resp('CLUSTER', 'NODES')
                self.assertTrue(reply.startswith(b'$'), reply)
                header, payload = reply.split(b'\r\n', 1)
                length = int(header[1:])
                self.assertEqual(payload[length:], b'\r\n')
                lines = payload[:length].splitlines()
                peer = next(line for line in lines if
                            f'127.0.0.1:{peer_port}@{peer_bus}'.encode() in line)
                local = next(line for line in lines if b'myself' in line)
                return peer, local

            # Default bus timeout is 5000 ms. Observe the actual failed state,
            # then keep checking ownership past another health-check cycle.
            deadline = time.monotonic() + 12
            while True:
                peer, local = nodes()
                self.assertIn(b'8192-16383', peer.split())
                self.assertIn(b'0-8191', local.split())
                if b'fail' in peer.split()[2].split(b','):
                    break
                self.assertLess(time.monotonic(), deadline, peer)
                time.sleep(.1)
            deadline = time.monotonic() + 1.5
            while time.monotonic() < deadline:
                peer, local = nodes()
                self.assertIn(b'8192-16383', peer.split())
                self.assertIn(b'0-8191', local.split())
                time.sleep(.1)
            self.assertEqual(session.execute_resp('CLUSTER', 'FAILOVER.RESUME'), b'+RESUMED\r\n')
            self.assertEqual(session.execute_resp('CLUSTER', 'FAILOVER.RESUME'), b'+ALREADY-RUNNING\r\n')
            deadline = time.monotonic() + 10
            while True:
                peer, local = nodes()
                if b'0-16383' in local.split():
                    self.assertNotIn(b'8192-16383', peer.split())
                    break
                self.assertLess(time.monotonic(), deadline, (peer, local))
                time.sleep(.1)
            process.terminate()
            self.assertEqual(process.wait(timeout=15), 0)

    def test_sync_failure_is_not_success(self):
        process, session, log = self.start('fail')
        self.assertEqual(session.execute_resp('SET', 'shutdown:ack', 'value'), b'+OK\r\n')
        process.terminate()
        self.assertNotEqual(process.wait(timeout=15), 0)
        log.seek(0)
        self.assertIn(b'KV sync failed', log.read())

    def test_stalled_server_stop_is_not_success(self):
        process, session, log = self.start('hang-stop')
        self.assertEqual(session.execute_resp('SET', 'shutdown:ack', 'value'), b'+OK\r\n')
        process.terminate()
        self.assertNotEqual(process.wait(timeout=15), 0)
        log.seek(0)
        self.assertIn(b'exiting without completing teardown', log.read())

    def test_watchdog_is_not_success(self):
        process, session, log = self.start('hang')
        self.assertEqual(session.execute_resp('SET', 'shutdown:ack', 'value'), b'+OK\r\n')
        process.terminate()
        self.assertNotEqual(process.wait(timeout=15), 0)
        log.seek(0)
        self.assertIn(b'exiting without completing teardown', log.read())


if __name__ == '__main__':
    unittest.main()
