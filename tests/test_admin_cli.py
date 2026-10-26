#!/usr/bin/env python3
"""Real pinned-QKP CLI/SDK regression tests, launched by test_qkp_admin.c."""
import ctypes
import json
import os
from pathlib import Path
import random
import socket
import subprocess
import sys
import threading
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdks" / "python"))
from qihse_admin import ClusterAdmin, QihseAdminError

PORT, IDENTITY, PIN = int(sys.argv[1]), sys.argv[2], sys.argv[3]
sys.argv = sys.argv[:1]


class AdminTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.admin = ClusterAdmin(node_id="admin-test-client", identity_dir=IDENTITY,
                                  lib_path=str(ROOT / "libqihse.so"))
        cls.pin = str(Path(PIN).resolve())
        cls.endpoint = ("127.0.0.1", PORT, cls.pin)
        # Initializes the public ctypes signatures, using a real handshake.
        with cls.admin.session(*cls.endpoint):
            pass

    def cli(self, *args, data=None, env=None):
        child_env = {k: v for k, v in os.environ.items() if not k.startswith("QIHSE_AUTH_")}
        for key in ("QIHSE_PORT", "QIHSE_HOST", "QIHSE_NODE_ID", "QIHSE_TRUSTED_PUB"):
            child_env.pop(key, None)
        child_env.update(env or {})
        return subprocess.run([str(ROOT / "qihse-admin-cli"), "--host", "127.0.0.1",
                               "--port", str(PORT), "--identity-dir", IDENTITY,
                               "--trusted-pub", self.pin, "--node-id", "admin-test-client",
                               *args], input=data, capture_output=True, env=child_env, timeout=15)

    def format_reply(self, reply, json_mode=True):
        output = ctypes.c_void_p()
        length = ctypes.c_size_t()
        error = ctypes.c_bool()
        lib = self.admin._lib
        rc = lib.qihse_qkp_admin_format(reply, len(reply), json_mode,
                                        ctypes.byref(output), ctypes.byref(length), ctypes.byref(error))
        try:
            return rc, ctypes.string_at(output, length.value) if output.value else b"", error.value
        finally:
            lib.qihse_qkp_admin_free(output)

    def test_reply_types_and_binary(self):
        reply = b'*5\r\n$-1\r\n$0\r\n\r\n:42\r\n*0\r\n$4\r\na\x00\xff\n\r\n'
        rc, output, error = self.format_reply(reply)
        self.assertEqual(rc, 0)
        self.assertFalse(error)
        self.assertEqual(json.loads(output), [None, "", 42, [], "a\x00\xff\n"])
        rc, output, error = self.format_reply(b'*2\r\n+OK\r\n*1\r\n-OOPS failure\r\n')
        self.assertEqual(json.loads(output), ["OK", [{"error": "OOPS failure"}]])
        self.assertTrue(error)
        self.assertEqual(self.format_reply(b'$8\r\nERR text\r\n')[2], False)
        self.assertEqual(self.format_reply(b':-9223372036854775808\r\n')[0], 0)
        self.assertEqual(json.loads(self.format_reply(b':0001\r\n')[1]), 1)

    def test_malformed_and_truncated_resp(self):
        bad = [b'', b'$-2\r\n', b'$x\r\n', b'$+1\r\na\r\n', b'$1\r\naXX',
               b'$18446744073709551615\r\n', b'*99999999999\r\n', b':1x\r\n',
               b':9223372036854775808\r\n', b':-9223372036854775809\r\n',
               b':\r\n', b'$1\r\na\r\nextra', b'+one\nline\r\n', b'+OK\rX',
               b'*1\r\n' * 66 + b'+OK\r\n', b'$-01\r\n', b'\x00\r\n']
        full = b'*2\r\n$3\r\nabc\r\n:23\r\n'
        bad.extend(full[:n] for n in range(len(full)))
        for reply in bad:
            with self.subTest(reply=reply):
                self.assertEqual(self.format_reply(reply), (5, b'', False))
        rng = random.Random(7)
        for _ in range(3000):
            reply = bytes(rng.randrange(256) for _ in range(rng.randrange(100)))
            rc, output, _ = self.format_reply(reply)
            if rc == 0:
                json.loads(output)
            else:
                self.assertEqual(output, b'')

    def test_cli_binary_stdin_and_large_payload(self):
        for payload in (b'', b'a\x00b\r\n', bytes(range(256)), b'x' * 70000 + b'\n'):
            result = self.cli('--resp', '-x', 'ECHO', data=payload)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, b'$' + str(len(payload)).encode() + b'\r\n' + payload + b'\r\n')

    def test_json_and_exact_error_classification(self):
        result = self.cli('--json', '--fail-on-error', 'ECHO', 'ERR ordinary data')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), 'ERR ordinary data')
        result = self.cli('--json', '--fail-on-error', 'NONEXISTENT.ADMIN.TEST')
        self.assertEqual(result.returncode, 5)
        self.assertIn('error', json.loads(result.stdout))
        result = self.cli('--json', 'COMMAND', 'INFO', 'GET', 'NOT.A.COMMAND')
        self.assertEqual(result.returncode, 0, result.stderr)
        rows = json.loads(result.stdout)
        self.assertIsInstance(rows[0], list)
        self.assertIsNone(rows[1])

    def test_quote_parser_and_batch_state(self):
        result = self.cli('--json', '--stdin', '--fail-on-error', data=(
            b'CLIENT SETNAME "persistent client"\nCLIENT GETNAME\n'
            b'ECHO ""\nECHO "a\\nb"\nECHO \'a b\'\n# comment\nPING\n'))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([json.loads(line) for line in result.stdout.splitlines()],
                         ['OK', 'persistent client', '', 'a\nb', 'a b', 'PONG'])
        result = self.cli('--json', '-c', 'ECHO', '--arg', 'exact argument')
        self.assertEqual(json.loads(result.stdout), 'exact argument')
        result = self.cli('--stdin', data=b'ECHO "unterminated\nPING\n')
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, b'')
        result = self.cli('--stdin', data=b'ECHO a\x00b\nPING\n')
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, b'')
        payload = b'q' * 20000
        result = self.cli('--json', '--stdin', data=b'ECHO ' + payload + b'\nPING\n')
        self.assertEqual([json.loads(line) for line in result.stdout.splitlines()], [payload.decode(), 'PONG'])
        result = self.cli('--stdin', '--fail-on-error', data=b'BAD.COMMAND\nPING\n')
        self.assertEqual(result.returncode, 5)
        self.assertNotIn(b'PONG', result.stdout)

    def test_invalid_options(self):
        for args in (('--port', '65536'), ('--port', '2junk'), ('--timeout-ms', '0'),
                     ('--json', '--resp'), ('--stdin', '-x'), ('--stdin', 'PING'),
                     ('--stdin', '--interactive'), ('--port',), ('-c', 'ECHO "bad')):
            result = self.cli(*args)
            self.assertEqual(result.returncode, 2, (args, result.stderr))
        self.assertEqual(self.cli('PING', env={'QIHSE_PORT': '65537'}).returncode, 2)

    def test_sdk_persistent_and_legacy(self):
        with self.admin.session(*self.endpoint) as session:
            self.assertEqual(session.execute('CLIENT', 'SETNAME', 'sdk-client'), b'OK')
            self.assertEqual(session.execute('CLIENT', 'GETNAME'), b'sdk-client')
            for payload in (b'\x00\xff\r\n', b'', 'unicode: \u03bb', b'z' * 70000):
                expected = payload.encode() if isinstance(payload, str) else payload
                self.assertEqual(session.execute('ECHO', payload), expected)
            self.assertIsNone(session.execute('GET', 'admin-test:missing'))
            self.assertEqual(session.execute('MGET', 'admin-test:secret', 'admin-test:missing'),
                             [b'CLASSIFIED-ADMIN-TEST', None])
            with self.assertRaises(QihseAdminError):
                session.execute('BAD.COMMAND')
            self.assertEqual(session.execute('PING'), b'PONG')
        with self.assertRaises(QihseAdminError):
            session.execute('PING')
        self.assertEqual(self.admin.execute(*self.endpoint, 'PING'), 'PONG')
        self.assertEqual(self.admin.execute_typed(*self.endpoint, 'ECHO', b'\x00'), b'\x00')

    def test_generic_aimem_transactions_and_shortcuts(self):
        with self.admin.session(*self.endpoint) as session:
            self.assertEqual(session.execute('AIMEM', 'COUNT'), 0)
            self.assertEqual(session.execute('MULTI'), b'OK')
            self.assertEqual(session.execute('SET', 'admin-test:transaction', 'value'), b'QUEUED')
            self.assertEqual(session.execute('GET', 'admin-test:transaction'), b'QUEUED')
            self.assertEqual(session.execute('EXEC'), [b'OK', b'value'])
            self.assertEqual(session.execute('DEL', 'admin-test:transaction'), 1)
        self.assertEqual(self.cli('--json', '--ping').stdout, b'"PONG"\n')
        shortcut = self.cli('--json', '--cluster-keyslot', 'test-key')
        positional = self.cli('--json', 'CLUSTER', 'KEYSLOT', 'test-key')
        self.assertEqual(shortcut.returncode, 0, shortcut.stderr)
        self.assertEqual(shortcut.stdout, positional.stdout)

    def test_legacy_subprocess_principal_parity(self):
        fallback = ClusterAdmin(admin_cli=str(ROOT / 'qihse-admin-cli'),
                                node_id='admin-test-client', identity_dir=IDENTITY,
                                prefer_native=False)
        saved = {key: os.environ.get(key) for key in ('QIHSE_AUTH_USER', 'QIHSE_AUTH_PASSWORD')}
        try:
            os.environ.update(QIHSE_AUTH_USER='ADMIN_LOW', QIHSE_AUTH_PASSWORD='wrong')
            self.assertEqual(fallback.execute(*self.endpoint, 'GET', 'admin-test:secret'),
                             'CLASSIFIED-ADMIN-TEST')
            self.assertEqual(self.admin.execute(*self.endpoint, 'GET', 'admin-test:secret'),
                             'CLASSIFIED-ADMIN-TEST')
        finally:
            for key, value in saved.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value
        with self.assertRaisesRegex(QihseAdminError, 'native'):
            fallback.session(*self.endpoint)
        with self.assertRaises(ValueError):
            self.admin.session('127.0.0.1', 65536, self.pin)

    def test_low_clearance_cannot_read_high_data(self):
        with self.admin.session(*self.endpoint, user='ADMIN_LOW', password='AdminTestLow1!') as session:
            self.assertIsNone(session.execute('GET', 'admin-test:secret'))
            self.assertEqual(session.execute('MGET', 'admin-test:secret'), [None])
            for command in (('KEYS', '*'), ('SCAN', '0'), ('AIMEM', 'COUNT'), ('USER', 'LIST')):
                reply = session.execute_resp(*command)
                self.assertNotIn(b'CLASSIFIED-ADMIN-TEST', reply)
                self.assertNotIn(b'admin-test:secret', reply)
        result = self.cli('--json', 'GET', 'admin-test:secret', env={
            'QIHSE_AUTH_USER': 'ADMIN_LOW', 'QIHSE_AUTH_PASSWORD': 'AdminTestLow1!'})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIsNone(json.loads(result.stdout))
        result = self.cli('--node-id', 'unmapped-client', '--fail-on-error', 'GET', 'admin-test:secret')
        self.assertEqual(result.returncode, 5)
        self.assertNotIn(b'CLASSIFIED-ADMIN-TEST', result.stdout)

    def test_failed_auth_never_runs_command(self):
        result = self.cli('--user', 'ADMIN_LOW', '--password-env', 'ADMIN_TEST_PASSWORD',
                          'GET', 'admin-test:secret', env={'ADMIN_TEST_PASSWORD': 'wrong'})
        self.assertEqual(result.returncode, 5)
        self.assertEqual(result.stdout, b'')
        with self.assertRaisesRegex(QihseAdminError, 'AUTH rejected'):
            self.admin.session(*self.endpoint, user='ADMIN_LOW', password='wrong')
        self.assertEqual(self.cli('--user', 'ADMIN_LOW', 'PING').returncode, 2)

    def test_standalone_qkp_service_principal(self):
        import tempfile
        with tempfile.TemporaryDirectory(dir=ROOT / 'build', prefix='standalone-aimem-test-') as data:
            with socket.socket() as sock:
                sock.bind(('127.0.0.1', 0))
                port = sock.getsockname()[1]
            env = os.environ.copy()
            env.update(QIHSE_FIPS_MODE='disabled', QIHSE_DATA_DIR=data,
                       QIHSE_OPERATOR_PASSWORD='StandaloneOperatorTest1!',
                       QIHSE_AIMEM_SERVICE_PASSWORD='StandaloneAimemTest1!',
                       QIHSE_AIMEM_SERVICE_USER_ID='65000',
                       QIHSE_AIMEM_SERVICE_TENANT_ID='1',
                       LD_LIBRARY_PATH=str(ROOT))
            env.pop('QIHSE_AUTH_USER', None)
            env.pop('QIHSE_AUTH_PASSWORD', None)
            cmd = [str(ROOT / 'qihse-redis-server'), '--port', str(port), '--bind', '127.0.0.1',
                   '--dir', data, '--require-auth', '--pqc-require', '--pqc-identity-dir',
                   str(Path(PIN).parent), '--pqc-trusted-pub',
                   str(Path(IDENTITY) / 'qihse_dsa_pub.pem'), '--pqc-node-id', 'standalone-aimem']
            proc = subprocess.Popen(cmd, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                for _ in range(100):
                    if proc.poll() is not None:
                        self.fail(f'standalone server exited early: {proc.returncode}')
                    try:
                        with self.admin.session('127.0.0.1', port, self.pin,
                                                user='AIMEM_SERVICE', password='StandaloneAimemTest1!') as session:
                            break
                    except (QihseAdminError, ConnectionError):
                        time.sleep(0.1)
                else:
                    self.fail('standalone QKP server did not start')
                with self.admin.session('127.0.0.1', port, self.pin) as session:
                    with self.assertRaises(QihseAdminError):
                        session.execute('AIMEM', 'COUNT-SCOPED', 'global', '', '', '')
                with self.admin.session('127.0.0.1', port, self.pin,
                                        user='AIMEM_SERVICE', password='StandaloneAimemTest1!') as session:
                    self.assertEqual(session.execute('AIMEM', 'COUNT-SCOPED', 'global', '', '', ''), 0)
                    hax_dir = os.environ.get('QIHSE_HAX_DIR')
                    if hax_dir:
                        cfg_path = Path(data).parent / (Path(data).name + '-hax-client.env')
                        cfg_values = dict(QIHSE_AIMEM_TRANSPORT='qkp', QIHSE_RESP_HOST='127.0.0.1',
                            QIHSE_RESP_PORT=str(port), QIHSE_AUTH_USER='AIMEM_SERVICE',
                            QIHSE_AUTH_PASSWORD='StandaloneAimemTest1!',
                            QIHSE_ADMIN_SDK=str(ROOT / 'sdks/python/qihse_admin.py'),
                            QIHSE_ADMIN_LIB=str(ROOT / 'libqihse.so'),
                            QIHSE_AIMEM_IDENTITY_DIR=str(Path(IDENTITY).resolve()),
                            QIHSE_AIMEM_TRUSTED_PUB=self.pin,
                            QIHSE_AIMEM_NODE_ID='admin-test-client')
                        try:
                            fd = os.open(cfg_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                            with os.fdopen(fd, 'w') as client_env:
                                client_env.write(''.join(f'{k}={v}\n' for k, v in cfg_values.items()))
                            hax_env = {**env, **cfg_values, 'QIHSE_AIMEM_ENV': str(cfg_path)}
                            client_test = subprocess.run([str(Path(hax_dir) / 'build/tests/test_memory_client'),
                                '--qkp-integration'], env={**hax_env, 'HAX_MEMORY_DEBUG': '1'},
                                capture_output=True, timeout=20)
                            self.assertEqual(client_test.returncode, 0, client_test.stderr)
                            script = (Path(hax_dir) / 'scripts/memory_hooks.py').read_text()
                            hook = subprocess.run(['python3', '-I', '-c', script,
                                'store', '1', 'hax-qkp-python-fixture', 'hax Python QKP integration'],
                                env={**hax_env, 'HAX_MEMORY_DEBUG': '1'}, cwd=ROOT,
                                capture_output=True, timeout=20)
                            self.assertEqual(hook.returncode, 0, hook.stderr)
                            self.assertEqual(hook.stderr, b'')
                            self.assertGreaterEqual(session.execute('AIMEM', 'COUNT-SCOPED', 'qihse', '', '', ''), 2)
                        finally:
                            cfg_path.unlink(missing_ok=True)
                    bridge_dir = os.environ.get('QIHSE_BRIDGE_DIR')
                    if bridge_dir:
                        sys.path.insert(0, bridge_dir)
                        from sync import _qihse_connect, _qihse_command
                        from importlib.util import spec_from_file_location, module_from_spec
                        qkp_env = dict(QIHSE_AIMEM_TRANSPORT='qkp', QIHSE_RESP_HOST='127.0.0.1',
                            QIHSE_RESP_PORT=str(port), QIHSE_AUTH_USER='AIMEM_SERVICE',
                            QIHSE_AUTH_PASSWORD='StandaloneAimemTest1!',
                            QIHSE_ADMIN_SDK=str(ROOT / 'sdks/python/qihse_admin.py'),
                            QIHSE_ADMIN_LIB=str(ROOT / 'libqihse.so'),
                            QIHSE_AIMEM_IDENTITY_DIR=str(Path(IDENTITY).resolve()),
                            QIHSE_AIMEM_TRUSTED_PUB=self.pin,
                            QIHSE_AIMEM_NODE_ID='admin-test-client')
                        with mock.patch.dict(os.environ, qkp_env):
                            conn = _qihse_connect()
                            try:
                                self.assertEqual(_qihse_command(conn, 'AIMEM', 'COUNT-SCOPED', 'global', '', '', ''), 0)
                                self.assertEqual(_qihse_command(conn, 'PING'), 'PONG')
                            finally:
                                conn.close()
                            hook_path = Path(bridge_dir) / 'zcode-hooks/aimem_client.py'
                            spec = spec_from_file_location('qkp_hook_test', hook_path)
                            hook = module_from_spec(spec)
                            spec.loader.exec_module(hook)
                            hook.Aimem().close()
                            native_env = {**env, **qkp_env,
                                'QIHSE_ADMIN_CLI': str(ROOT / 'qihse-admin-cli'),
                                'QIHSE_AIMEM_ENV': str(Path(data) / 'no-env')}
                            native = subprocess.run([str(Path(bridge_dir) / 'supermemory-bridge'),
                                'recall', 'test', '--scope', 'global'], env=native_env,
                                capture_output=True, timeout=20)
                            self.assertEqual(native.returncode, 0, native.stderr)
                            status = subprocess.run([str(Path(bridge_dir) / 'supermemory-bridge'),
                                'status'], env=native_env, capture_output=True, timeout=20)
                            self.assertEqual(status.returncode, 0, status.stderr)
                        sys.path.remove(bridge_dir)
                    with self.assertRaises(QihseAdminError):
                        session.execute('USER', 'LIST')
                    with self.assertRaises(QihseAdminError):
                        session.execute('GET', 'anything')
                with self.assertRaises(QihseAdminError):
                    self.admin.session('127.0.0.1', port, self.pin,
                                       user='AIMEM_SERVICE', password='wrong')
                with socket.create_connection(('127.0.0.1', port), timeout=2) as sock:
                    sock.sendall(b'*1\r\n$4\r\nPING\r\n')
                    self.assertNotIn(b'+PONG', sock.recv(128))
            finally:
                proc.terminate()
                try:
                    proc.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=5)

    def test_wrong_pin_and_handshake_timeout(self):
        result = self.cli('--trusted-pub', str(Path(IDENTITY) / 'qihse_dsa_pub.pem'), 'PING')
        self.assertEqual(result.returncode, 3)
        self.assertEqual(result.stdout, b'')
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            listener.listen(1)
            done = threading.Event()
            def stall():
                conn, _ = listener.accept()
                with conn:
                    done.wait(3)
            thread = threading.Thread(target=stall)
            thread.start()
            try:
                start = time.monotonic()
                result = self.cli('--port', str(listener.getsockname()[1]), '--timeout-ms', '100', 'PING')
                self.assertEqual(result.returncode, 3)
                self.assertLess(time.monotonic() - start, 2)
            finally:
                done.set()
                thread.join(4)


if __name__ == '__main__':
    unittest.main(verbosity=2)
