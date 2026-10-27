#!/usr/bin/env python3
"""Opt-in AIMEM projection through a disposable pinned-QKP standalone service."""
import ctypes
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parent.parent
MODEL = os.environ.get("QIHSE_AIMEM_EMBEDDER_ONNX_TEST_DIR")
KEYSTONE = os.environ.get("QIHSE_AIMEM_KEYSTONE_TEST_LIBRARY")
if not MODEL or not KEYSTONE:
    print("SKIP: configure QIHSE_AIMEM_EMBEDDER_ONNX_TEST_DIR and QIHSE_AIMEM_KEYSTONE_TEST_LIBRARY")
    sys.exit(77)

with tempfile.TemporaryDirectory(prefix="aimem-qkp-isolated-", dir=ROOT / "build") as path:
    fixture = Path(path)
    for name in ("server", "client", "rogue", "data", "keygen-data", "projection"):
        (fixture / name).mkdir(mode=0o700)
    # Set before loading the native library: its audit constructor must not see
    # the host's unrelated database location.
    os.environ.pop("QIHSE_DB", None)
    os.environ["QIHSE_DATA_DIR"] = str(fixture / "keygen-data")
    sys.path.insert(0, str(ROOT / "python"))
    from qihse.controller import Controller, ControllerError

    library = ctypes.CDLL(str(ROOT / "libqihse.so"))
    library.qihse_pqc_keygen.argtypes = [ctypes.c_char_p]
    library.qihse_pqc_keygen.restype = ctypes.c_bool
    for name in ("server", "client", "rogue"):
        assert library.qihse_pqc_keygen(str(fixture / name).encode())
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]

    env = os.environ.copy()
    env.update({
        "LD_LIBRARY_PATH": str(ROOT) + (":" + env["LD_LIBRARY_PATH"] if env.get("LD_LIBRARY_PATH") else ""),
        "QIHSE_OPERATOR_PASSWORD": "FixtureOperator1234!",
        "QIHSE_AIMEM_SERVICE_PASSWORD": "FixtureService1234!",
        "QIHSE_AIMEM_SERVICE_TENANT_ID": "17",
        "QIHSE_AIMEM_SERVICE_USER_ID": "172",
        "QIHSE_DATA_DIR": str(fixture / "data"),
    })
    for name in ("QIHSE_DB", "QIHSE_AUTH_USER", "QIHSE_AUTH_PASSWORD",
                 "QIHSE_AIMEM_TRANSPORT", "QIHSE_RESP_PORT"):
        env.pop(name, None)
    command = [str(ROOT / "qihse-redis-server"),
        "--bind", "127.0.0.1", "--port", str(port), "--dir", str(fixture / "data"),
        "--require-auth", "--pqc-require", "--pqc-identity-dir", str(fixture / "server"),
        "--pqc-trusted-pub", str(fixture / "client" / "qihse_dsa_pub.pem"),
        "--pqc-node-id", "aimem-fixture", "--embedder-onnx", MODEL,
        "--aimem-keystone-library", str(Path(KEYSTONE).resolve()),
        "--aimem-projection-dir", str(fixture / "projection")]
    with (fixture / "server.log").open("wb") as log:
        daemon = subprocess.Popen(command, cwd=ROOT, env=env,
            stdin=subprocess.DEVNULL, stdout=log, stderr=log, start_new_session=True)
        try:
            deadline = time.monotonic() + 35
            while True:
                assert daemon.poll() is None, f"fixture exited: {daemon.returncode}"
                try:
                    client = Controller("127.0.0.1", port,
                        username="AIMEM_SERVICE", password=env["QIHSE_AIMEM_SERVICE_PASSWORD"],
                        timeout_ms=5000, qkp_identity_dir=str(fixture / "client"),
                        qkp_trusted_pubs=[str(fixture / "server" / "qihse_dsa_pub.pem")])
                    break
                except Exception as exc:
                    if time.monotonic() >= deadline:
                        raise RuntimeError("pinned QKP fixture unavailable") from exc
                    time.sleep(0.2)
            for identity, password in ((None, env["QIHSE_AIMEM_SERVICE_PASSWORD"]),
                                       ("rogue", env["QIHSE_AIMEM_SERVICE_PASSWORD"]),
                                       ("client", "WrongFixturePassword1234!")):
                try:
                    refused = Controller("127.0.0.1", port, username="AIMEM_SERVICE",
                        password=password, timeout_ms=5000,
                        qkp_identity_dir=str(fixture / identity) if identity else None,
                        qkp_trusted_pubs=[str(fixture / "server" / "qihse_dsa_pub.pem")]
                            if identity else None)
                except ControllerError:
                    pass
                else:
                    refused.close()
                    raise AssertionError("missing pin, rogue identity, or wrong AUTH was accepted")
            with client:
                recall = ("AIMEM", "RECALL-SCOPED", "feline rug", "8", "semantic", "0",
                    "projection-qkp", "", "", "")
                empty = client.call(*recall, check=False)
                assert (empty.kind == "array" and len(empty.items) == 0) or (
                    empty.kind == "error" and b"projection unavailable or stale" in empty.as_bytes())
                stored = client.call("AIMEM", "STORE-SCOPED", "2", "A feline on the rug",
                    "projection-qkp", "", "", "")
                assert stored.kind == "bulk" and len(stored.as_bytes()) == 36
                memory_id = stored.as_bytes()
                source_count = client.call("AIMEM", "COUNT-SCOPED", "projection-qkp", "", "", "")
                assert source_count.as_int() == 1, source_count.value
                deadline = time.monotonic() + 35
                while True:
                    answer = client.call(*recall, check=False)
                    if answer.kind == "array":
                        break
                    assert answer.kind == "error" and b"projection unavailable or stale" in answer.as_bytes()
                    if time.monotonic() >= deadline:
                        raise AssertionError("projection did not become ready")
                    time.sleep(0.2)
                assert len(answer.items) == 1 and answer.items[0][0].as_bytes() == memory_id
                samples = []
                for _ in range(20):
                    started = time.monotonic_ns()
                    sample = client.call(*recall)
                    samples.append((time.monotonic_ns() - started) // 1000)
                    assert len(sample.items) == 1 and sample.items[0][0].as_bytes() == memory_id
                samples.sort()
                print(f"isolated pinned-QKP semantic RTT: p50={samples[10]} us p95={samples[18]} us")
                outside = client.call("AIMEM", "RECALL-SCOPED", "feline rug", "8", "hybrid", "0",
                    "other-project", "", "", "")
                assert outside.kind == "array" and len(outside.items) == 0
                deleted = client.call("AIMEM", "FORGET-SCOPED", memory_id.decode(),
                    "projection-qkp", "", "", "")
                assert deleted.kind == "int" and deleted.as_int() == 1
                deadline = time.monotonic() + 35
                while True:
                    after_delete = client.call(*recall, check=False)
                    if after_delete.kind == "array":
                        assert len(after_delete.items) == 0
                        break
                    assert after_delete.kind == "error" and b"projection unavailable or stale" in after_delete.as_bytes()
                    if time.monotonic() >= deadline:
                        raise AssertionError("projection did not reconcile deletion")
                    time.sleep(0.2)
                print("PASS isolated pinned QKP: pin and AUTH refusals, scoped semantic hit,"
                    " cross-project empty, deletion reconciliation")
        except Exception:
            log.flush()
            print("fixture diagnostics:", (fixture / "server.log").read_text(errors="replace")[-1600:],
                  file=sys.stderr)
            raise
        finally:
            if daemon.poll() is None:
                daemon.terminate()
                try:
                    daemon.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    daemon.kill()
                    daemon.wait(timeout=5)
