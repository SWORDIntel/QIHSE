"""Self-spawned authenticated TLS pgwire target and offline safety guards."""

import os
import secrets
import select
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def pgwire_target(tmp_path):
    """One private row store and TLS listener per test, never a configured DSN."""
    work = tmp_path
    cert, key = work / "cert.pem", work / "key.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                    "-keyout", str(key), "-out", str(cert), "-days", "1",
                    "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"],
                   check=True, capture_output=True, timeout=20)
    key.chmod(0o600)
    binary = work / "server"
    library = ROOT / "libqihse.so"
    if not library.is_file():
        pytest.fail("libqihse.so missing: build separately before running client fixture")
    build = subprocess.run(["gcc", "-std=c11", "-D_GNU_SOURCE", "-I" + str(ROOT / "include"),
                            "-I" + str(ROOT / "core"), "-I" + str(ROOT),
                            str(ROOT / "tests/test_pgwire_client_server.c"), "-o", str(binary),
                            "-L" + str(ROOT), "-lqihse", "-lssl", "-lcrypto", "-lpthread"],
                           capture_output=True, text=True, timeout=30)
    assert build.returncode == 0, f"pgwire fixture compile failed:\n{build.stderr}"
    password = secrets.token_urlsafe(24)
    env = {**os.environ, "LD_LIBRARY_PATH": str(ROOT), "QIHSE_DATA_DIR": str(work)}
    # qihse_auth_init() honors this setting and bootstraps before the fixture's
    # explicit random-password bootstrap; remove inherited operator state.
    env.pop("QIHSE_OPERATOR_PASSWORD", None)
    proc = subprocess.Popen([str(binary), str(work), str(cert), str(key), password],
                            env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        ready, _, _ = select.select([proc.stdout], [], [], 45)
        if not ready:
            pytest.fail(f"disposable QIHSE listener did not announce a port (exit={proc.poll()})")
        line = proc.stdout.readline().strip()
        if not line.startswith("PORT "):
            proc.terminate()
            try:
                _, error = proc.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                _, error = proc.communicate(timeout=5)
            pytest.fail(f"disposable QIHSE listener failed: {line}; "
                        f"exit={proc.returncode}; stderr={error[-4096:]}")
        port = int(line.split()[1])
        assert 0 < port < 65536
        yield {"host": "localhost", "port": port, "user": "User_1",
               "guest": "User_2", "password": password, "database": "qihse", "ca": str(cert)}
    finally:
        proc.terminate()
        try:
            proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.communicate(timeout=5)


def _dsn():
    from test_pgwire_app_compat import _dsn as check
    return check()


@pytest.fixture
def isolated(monkeypatch, tmp_path):
    ca = tmp_path / "ca.pem"
    ca.write_text("test fixture only")
    monkeypatch.setenv("QIHSE_PGWIRE_APP_COMPAT_ISOLATED", "1")
    monkeypatch.setenv("QIHSE_PGWIRE_APP_COMPAT_CA", str(ca))
    return ca


def test_target_requires_explicit_disposable_confirmation(monkeypatch):
    monkeypatch.delenv("QIHSE_PGWIRE_APP_COMPAT_ISOLATED", raising=False)
    with pytest.raises(pytest.skip.Exception, match="isolated disposable"):
        _dsn()


@pytest.mark.parametrize("dsn", [
    "postgresql://user:pass@example.com:5432/qihse",
    "postgresql://user:pass@localhost:5432/qihse?sslmode=disable",
    "postgresql://user:pass@localhost:5432/qihse#fragment",
    "postgresql://user:pass@localhost:5432/",
    "postgresql://user@localhost:5432/qihse",
])
def test_rejects_unsafe_or_incomplete_targets(isolated, monkeypatch, dsn):
    monkeypatch.setenv("QIHSE_PGWIRE_APP_COMPAT_DSN", dsn)
    with pytest.raises(pytest.fail.Exception):
        _dsn()


def test_tls_ca_is_required(isolated, monkeypatch):
    monkeypatch.setenv("QIHSE_PGWIRE_APP_COMPAT_DSN", "postgresql://user:pass@localhost:5432/qihse")
    monkeypatch.delenv("QIHSE_PGWIRE_APP_COMPAT_CA")
    with pytest.raises(pytest.skip.Exception, match="verified TLS"):
        _dsn()
    monkeypatch.setenv("QIHSE_PGWIRE_APP_COMPAT_CA", "missing-ca.pem")
    with pytest.raises(pytest.fail.Exception, match="existing CA"):
        _dsn()
    monkeypatch.setenv("QIHSE_PGWIRE_APP_COMPAT_CA", str(isolated))
