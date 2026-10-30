"""Python SDK TLS/auth regressions against a disposable real QIHSE listener."""
import importlib.util
from pathlib import Path
import socket
import ssl
import struct
import subprocess
import threading

import pytest
from test_pgwire_client_fixture import pgwire_target

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("qihse_pg_tls_sdk", ROOT / "sdks/python/qihse_pg.py")
pg = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(pg)


def options(target, **overrides):
    return {"host": target["host"], "port": target["port"],
            "user": target["user"], "password": target["password"],
            "dbname": target["database"], "sslrootcert": target["ca"], **overrides}


def test_verified_tls_and_transactions(pgwire_target):
    with pg.connect(**options(pgwire_target)) as conn:
        assert isinstance(conn._sock, ssl.SSLSocket)
        assert conn._sock.context.verify_mode == ssl.CERT_REQUIRED
        assert conn._sock.context.check_hostname
        cur = conn.cursor()
        cur.execute("SELECT note FROM protected_records WHERE id = 7")
        assert cur.fetchall() == [("DIRECTEYE-HIGH-SECRET-MARKER",)]
        assert conn._in_transaction
        conn.commit()
        assert not conn._in_transaction
        cur.execute("SELECT id FROM protected_records WHERE id = 7")
        assert cur.fetchone() == ("7",)
        conn.rollback()
        assert not conn._in_transaction


def test_explicit_hostname_and_client_certificate(pgwire_target):
    target = pgwire_target
    # The fixture does not require mTLS; this exercises client key/cert loading.
    with pg.connect(**options(target, host="127.0.0.1", sslhostname="localhost",
                              sslcert=target["ca"],
                              sslkey=str(Path(target["ca"]).with_name("key.pem")))) as conn:
        assert conn._sock.getpeercert()


@pytest.mark.parametrize("override", [{"sslhostname": "wrong.invalid"}, {"sslrootcert": None}])
def test_certificate_verification_fails_closed(pgwire_target, override):
    with pytest.raises(pg.OperationalError) as error:
        pg.connect(**options(pgwire_target, **override))
    assert isinstance(error.value.__cause__, ssl.SSLCertVerificationError)


def test_wrong_ca_fails_closed(pgwire_target, tmp_path):
    wrong_ca = tmp_path / "wrong-ca.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                    "-keyout", str(tmp_path / "wrong-key.pem"), "-out", str(wrong_ca),
                    "-days", "1", "-subj", "/CN=unrelated-ca"],
                   check=True, capture_output=True, timeout=20)
    with pytest.raises(pg.OperationalError) as error:
        pg.connect(**options(pgwire_target, sslrootcert=str(wrong_ca)))
    assert isinstance(error.value.__cause__, ssl.SSLCertVerificationError)


def test_wrong_password_cannot_claim_operator_identity(pgwire_target):
    with pytest.raises(pg.OperationalError, match="28P01"):
        pg.connect(**options(pgwire_target, password="not-the-fixture-password"))


def test_low_clearance_denied_without_payload(pgwire_target):
    with pg.connect(**options(pgwire_target, user=pgwire_target["guest"], autocommit=True)) as conn:
        cur = conn.cursor()
        for query in ("SELECT * FROM protected_records",
                      "SELECT * FROM protected_records WHERE id = 7",
                      "SELECT note FROM protected_records WHERE id = 7",
                      "SELECT note FROM protected_records WHERE id = 8"):
            with pytest.raises(pg.Error, match="42501") as error:
                cur.execute(query)
            assert "DIRECTEYE-HIGH-SECRET-MARKER" not in str(error.value)
            assert "DIRECTEYE-CROSS-TENANT-MARKER" not in str(error.value)
            assert cur.fetchall() == []
            assert conn._last_result["rows"] == []


@pytest.mark.parametrize("response", [b"N", b"?", b""])
def test_sslrequest_refusal_never_sends_startup_or_password(response):
    received, failures = [], []
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(5)

        def serve():
            try:
                with listener.accept()[0] as peer:
                    peer.settimeout(5)
                    received.append(pg.connection._read_exact(peer, 8))
                    if response:
                        peer.sendall(response)
                    else:
                        peer.shutdown(socket.SHUT_WR)
                    received.append(peer.recv(4096))
            except Exception as exc:
                failures.append(exc)

        worker = threading.Thread(target=serve, daemon=True)
        worker.start()
        try:
            with pytest.raises(pg.OperationalError):
                pg.connect(host="127.0.0.1", port=listener.getsockname()[1],
                           user="private-identity", password="private-password")
        finally:
            worker.join(timeout=6)
        assert not worker.is_alive()
        assert not failures
    assert received == [struct.pack("!II", 8, 80877103), b""]


@pytest.mark.parametrize("kwargs", [
    {"sslmode": "prefer"}, {"sslmode": "require"}, {"sslmode": "verify-ca"},
    {"sslmode": "disable", "sslrootcert": "ignored-ca"},
    {"sslmode": "disable", "sslhostname": "ignored-host"},
    {"sslcert": "missing-client-cert"}, {"sslkey": "missing-client-key"},
    {"sslhostname": ""}, {"sslhostname": "host\x00other"},
    {"user": "User_2\x00role\x00operator"}, {"dbname": "qihse\x00user\x00User_1"},
    {"password": "password\x00suffix"},
])
def test_unsafe_configuration_rejected_before_connection(kwargs):
    with pytest.raises(pg.OperationalError) as error:
        pg.connect(port=0, **kwargs)
    assert not isinstance(error.value.__cause__, OSError)


def test_disable_checks_actual_connected_peer(monkeypatch):
    class NonLoopbackPeer:
        closed = False

        def getpeername(self):
            return ("192.0.2.1", 5432)

        def close(self):
            self.closed = True

    peer = NonLoopbackPeer()
    monkeypatch.setattr(pg.socket, "create_connection", lambda *a, **kw: peer)
    with pytest.raises(pg.OperationalError, match="restricted to loopback"):
        pg.connect(host="localhost", sslmode="disable")
    assert peer.closed
