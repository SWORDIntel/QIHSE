"""Run the Rust SDK against the shared disposable authenticated TLS fixture."""
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "tests"))
from test_pgwire_client_fixture import pgwire_target  # noqa: E402,F401


def test_rust_verified_tls(pgwire_target, tmp_path):
    target = pgwire_target
    wrong_ca = tmp_path / "wrong-ca.pem"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", str(tmp_path / "wrong-key.pem"), "-out", str(wrong_ca),
         "-days", "1", "-subj", "/CN=Unrelated Rust Test CA"],
        check=True, capture_output=True, timeout=20,
    )
    env = {
        **os.environ,
        "QIHSE_RUST_TLS_CA": target["ca"],
        "QIHSE_RUST_TLS_WRONG_CA": str(wrong_ca),
        "QIHSE_RUST_TLS_PORT": str(target["port"]),
        "QIHSE_RUST_TLS_USER": target["user"],
        "QIHSE_RUST_TLS_GUEST": target["guest"],
        "QIHSE_RUST_TLS_PASSWORD": target["password"],
    }
    result = subprocess.run(
        ["cargo", "test", "--locked", "--manifest-path",
         str(ROOT / "sdks/rust/Cargo.toml"), "--test", "tls",
         "verified_tls_and_principal_authorization", "--", "--ignored", "--exact"],
        env=env, capture_output=True, text=True, timeout=180,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "1 passed" in result.stdout


# No external target/DSN is accepted: fixture supplies loopback and random auth.
