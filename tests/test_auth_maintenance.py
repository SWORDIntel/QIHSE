#!/usr/bin/env python3
"""Real isolated daemon/QKP/CLI acceptance, never live credentials or endpoints.

Requires built qihse-redis-server, qihse-admin-cli, libqihse.so and OpenSSL EVP
ML-KEM-1024/ML-DSA-87. This test does not compile its own replacement server.
"""
import ctypes as C
import hashlib
import os
from pathlib import Path
import shlex
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
WIRE_MAX = 8 * 1024 * 1024
AUTHORITY, HISTORY = bytes.fromhex("12" * 16), bytes.fromhex("34" * 16)
ROOT_PW, TARGET_PW = "SyntheticRootPassword123!", "SyntheticTargetPassword123!"
USER_PW = "SyntheticPrincipalPassword123!"
HIGH = "HIGH_PRINCIPAL_SYNTHETIC_ONLY"


class Position(C.Structure):
    _fields_ = [("history", C.c_ubyte * 16), ("node", C.c_ubyte * 16),
                ("epoch", C.c_uint64), ("generation", C.c_uint64)]


class Keys(C.Structure):
    _fields_ = [("recipient_public_file", C.c_char_p), ("recipient_private_file", C.c_char_p),
                ("signer_private_file", C.c_char_p), ("signer_public_file", C.c_char_p),
                ("recipient_pin", C.c_ubyte * 48), ("signer_pin", C.c_ubyte * 48)]


class Startup(C.Structure):
    _fields_ = [("mode", C.c_int), ("action", C.c_int),
                ("state_directory", C.c_char_p), ("bootstrap_file", C.c_char_p),
                ("archive_keys", Keys), ("transfer_keys", Keys),
                ("authority_id", C.c_ubyte * 16), ("minimum_generation", C.c_uint64),
                ("node", C.c_ubyte * 16), ("epoch", C.c_uint64),
                ("expected_history", C.c_ubyte * 16)]


class Binding(C.Structure):
    _fields_ = [("version", C.c_uint32), ("purpose", C.c_uint32), ("mode", C.c_int),
                ("source_authority", C.c_ubyte * 16), ("source", Position),
                ("target_authority", C.c_ubyte * 16), ("target", Position),
                ("archive_id", C.c_ubyte * 16), ("allow_node_relocation", C.c_bool)]


class ArchiveConfig(C.Structure):
    _fields_ = [("keys", Keys), ("binding", Binding)]


def decode_position(data):
    position = Position(epoch=struct.unpack_from(">Q", data, 32)[0],
                        generation=struct.unpack_from(">Q", data, 40)[0])
    position.history[:], position.node[:] = data[:16], data[16:32]
    return position


class Caps(C.Structure):
    _fields_ = [("mode", C.c_int), ("ready", C.c_bool), ("export_supported", C.c_bool),
                ("import_supported", C.c_bool), ("checkpoint_supported", C.c_bool),
                ("position", Position)]


def private_file(path, data):
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    return path


def isolated_env(directory):
    # Retain crypto providers, not operator storage/auth/endpoint configuration.
    env = {k: v for k, v in os.environ.items() if not k.startswith("QIHSE_")}
    env.update(QIHSE_DATA_DIR=str(directory), QIHSE_FIPS_MODE="disabled",
               LD_LIBRARY_PATH=str(ROOT) + (":" + env["LD_LIBRARY_PATH"]
                                           if env.get("LD_LIBRARY_PATH") else ""))
    return env


def native_helper(mode):
    """Fresh-process setup through public typed APIs; no forged user structs."""
    lib = C.CDLL(str(ROOT / "libqihse.so"))
    if mode == "keygen":
        lib.qihse_pqc_keygen.argtypes, lib.qihse_pqc_keygen.restype = [C.c_char_p], C.c_bool
        for directory in sys.argv[3:]:
            if not lib.qihse_pqc_keygen(os.fsencode(directory)):
                raise RuntimeError("synthetic QKP key generation failed")
        return

    def function(name, args, result):
        fn = getattr(lib, name)
        fn.argtypes, fn.restype = args, result
        return fn

    start = function("qihse_auth_maintenance_start", [C.POINTER(Startup), C.POINTER(C.c_void_p)], C.c_int)
    release = function("qihse_auth_maintenance_recovery_release", [C.c_void_p], None)
    auth = function("qihse_auth_authenticate_id", [C.c_uint32, C.c_char_p], C.c_void_p)
    create = function("qihse_auth_create_tenant_user", [C.c_void_p, C.c_uint32, C.c_uint32,
                      C.c_uint16, C.c_uint16, C.c_uint16, C.c_char_p, C.c_bool], C.c_void_p)
    create_system = function("qihse_auth_create_user", [C.c_void_p, C.c_uint32,
                             C.c_uint16, C.c_uint16, C.c_uint16, C.c_char_p, C.c_bool], C.c_void_p)
    modify = function("qihse_auth_modify_user", [C.c_void_p, C.c_uint32, C.c_char_p,
                      C.c_char_p, C.c_int, C.c_int, C.c_int, C.c_int], C.c_bool)
    destroy = function("qihse_auth_destroy_user", [C.c_void_p, C.c_uint32], C.c_bool)
    caps = function("qihse_auth_maintenance_capabilities", [C.c_void_p, C.POINTER(Caps)], C.c_int)

    def keys(prefix):
        result = Keys()
        for field, suffix in (("recipient_public_file", "RECIPIENT_PUBLIC_KEY"),
                              ("recipient_private_file", "RECIPIENT_PRIVATE_KEY"),
                              ("signer_private_file", "SIGNER_PRIVATE_KEY"),
                              ("signer_public_file", "SIGNER_PUBLIC_KEY")):
            setattr(result, field, os.fsencode(os.environ[prefix + suffix]))
        result.recipient_pin[:] = bytes.fromhex(os.environ[prefix + "RECIPIENT_PIN"])
        result.signer_pin[:] = bytes.fromhex(os.environ[prefix + "SIGNER_PIN"])
        return result

    cfg = Startup(mode=1, action=2,
                  state_directory=os.fsencode(os.environ["QIHSE_AUTH_STATE_DIR"]),
                  bootstrap_file=os.fsencode(os.environ["QIHSE_AUTH_BOOTSTRAP_FILE"]),
                  archive_keys=keys("QIHSE_AUTH_"), transfer_keys=keys("QIHSE_AUTH_TRANSFER_"),
                  minimum_generation=1, epoch=1)
    cfg.authority_id[:], cfg.expected_history[:] = AUTHORITY, HISTORY
    cfg.node[:] = bytes.fromhex(os.environ["QIHSE_AUTH_NODE_ID"])
    if mode == "hwt-import":
        # Enroll a protected HWT root, but never assert token presence. Only the
        # opaque pre-serve recovery capability may install existing principals.
        provision = function("qihse_auth_bootstrap_provision",
                             [C.c_char_p, C.c_char_p, C.c_char_p, C.c_bool, C.c_char_p, C.c_bool], C.c_int)
        if provision(cfg.bootstrap_file, b"HWT_ROOT", TARGET_PW.encode(),
                     True, b"synthetic-enrolled-hwt-credential", True) != 0:
            raise RuntimeError("protected HWT bootstrap enrollment failed")
        cfg.action, cfg.minimum_generation = 1, 0
    recovery = C.c_void_p()
    if start(C.byref(cfg), C.byref(recovery)) != 0:
        raise RuntimeError("isolated typed authority recovery failed")
    if mode == "hwt-import":
        descriptor = Path(sys.argv[3]).read_bytes()
        sealed = Path(sys.argv[4]).read_bytes()
        binding = Binding(version=1, purpose=2, mode=1, allow_node_relocation=True,
                          source=decode_position(descriptor[28:76]),
                          target=decode_position(descriptor[92:140]))
        binding.source_authority[:], binding.target_authority[:] = descriptor[12:28], descriptor[76:92]
        binding.archive_id[:] = descriptor[140:156]
        transfer = ArchiveConfig(keys=cfg.transfer_keys, binding=binding)
        recover_import = function("qihse_auth_maintenance_recover_import",
                                  [C.c_void_p, C.POINTER(Position), C.c_void_p,
                                   C.POINTER(ArchiveConfig), C.c_void_p, C.c_size_t,
                                   C.POINTER(Position)], C.c_int)
        result = Position()
        status = recover_import(recovery, C.byref(binding.target), b"R" * 16,
                                C.byref(transfer), sealed, len(sealed), C.byref(result))
        release(recovery)
        if status != 0:
            raise RuntimeError("HWT protected recovery import failed")
        return
    release(recovery)
    root = auth(0, ROOT_PW.encode())
    if not root:
        raise RuntimeError("durable root authentication failed")
    # High-clearance principal records are protected payload, not mock data.
    for uid, tenant, role, clearance, sci, name in (
            (100, 0, 0, 65535, 65535, "SERVICE_OPERATOR"),
            (101, 0, 1, 0, 0, "LOW"), (102, 0, 2, 0, 0, "GUEST"),
            (103, 17, 0, 65535, 65535, "TENANT_OPERATOR"),
            (104, 0, 1, 65535, 65535, HIGH), (105, 0, 0, 65535, 65535, "REVOKED_OPERATOR")):
        user = (create(root, tenant, uid, role, clearance, sci, USER_PW.encode(), False)
                if tenant else create_system(root, uid, role, clearance, sci, USER_PW.encode(), False))
        if not user:
            raise RuntimeError(f"durable principal creation failed for synthetic UID {uid}")
        if not modify(root, uid, name.encode(), None, -1, -1, -1, -1):
            raise RuntimeError(f"durable principal naming failed for synthetic UID {uid}")
    out = Caps()
    if caps(None, C.byref(out)) == 0:
        raise RuntimeError("NULL maintenance actor authorized")
    if not destroy(root, 105) or auth(105, USER_PW.encode()):
        raise RuntimeError("durable revocation failed")
    if caps(root, C.byref(out)) != 0:
        raise RuntimeError("seed authority not ready")


class Daemon:
    def __init__(self, case, directory, local_keys, node, password, username):
        self.case, self.directory = case, directory
        directory.mkdir(mode=0o700)
        for name in ("data", "authority"):
            (directory / name).mkdir(mode=0o700)
        self.password, self.username = password, username
        self.env = isolated_env(directory / "data")
        self.env.update(QIHSE_OPERATOR_PASSWORD=password, QIHSE_AUTH_MODE="standalone",
                        QIHSE_AUTH_ACTION="provision", QIHSE_AUTH_STATE_DIR=str(directory / "authority"),
                        QIHSE_AUTH_BOOTSTRAP_FILE=str(directory / "bootstrap"),
                        QIHSE_AUTH_BOOTSTRAP_USERNAME=username, QIHSE_AUTH_AUTHORITY_ID=AUTHORITY.hex(),
                        QIHSE_AUTH_HISTORY_ID=HISTORY.hex(), QIHSE_AUTH_NODE_ID=bytes([node] * 16).hex(),
                        QIHSE_AUTH_EPOCH="1")
        for prefix, keyset in (("QIHSE_AUTH_", local_keys), ("QIHSE_AUTH_TRANSFER_", case.transfer_keys)):
            self.env.update({prefix + k: v for k, v in keyset.items()})
        self.proc = None
        case.addCleanup(self.stop)

    def start(self, recover=False, selected=None, password=None, extra=None, volatile=False):
        env = self.env.copy()
        if volatile:
            env = {k: v for k, v in env.items() if not k.startswith("QIHSE_AUTH_")}
        if recover:
            env.pop("QIHSE_AUTH_BOOTSTRAP_USERNAME", None)
            env.update(QIHSE_AUTH_ACTION="recover", QIHSE_AUTH_MIN_GENERATION="1")
        if selected is not None:
            env["QIHSE_AUTH_STARTUP_USER_ID"] = str(selected)
        if password is not None:
            env["QIHSE_OPERATOR_PASSWORD"] = password
        env.update(extra or {})
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            self.port = sock.getsockname()[1]
        command = [str(ROOT / "qihse-redis-server"), "--bind", "127.0.0.1", "--port", str(self.port),
                   "--dir", str(self.directory / "data"), "--require-auth", "--pqc-require",
                   "--pqc-identity-dir", str(self.case.fixture / "server"), "--pqc-trusted-pub",
                   str(self.case.fixture / "client/qihse_dsa_pub.pem"), "--pqc-node-id", "maintenance-fixture"]
        self.proc = subprocess.Popen(command, cwd=ROOT, env=env, stdin=subprocess.DEVNULL,
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return self

    def ready(self, username=None, password=None):
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            self.case.assertIsNone(self.proc.poll(), "isolated authority exited before readiness")
            try:
                with self.session(username or self.username, password or self.password) as session:
                    self.case.assertEqual(session.execute("PING"), b"PONG")
                return self
            except (self.case.admin_error, OSError):
                time.sleep(0.1)
        self.case.fail("isolated QKP authority readiness timed out")

    def session(self, username=None, password=None):
        return self.case.admin.session("127.0.0.1", self.port, self.case.pin,
                                       user=username, password=password, timeout_ms=3000)

    def stop(self):
        if self.proc is not None and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=10)

    def capabilities(self):
        with self.session(self.username, self.password) as session:
            caps = session.execute("AUTHORITY.CAPABILITIES")
        self.case.assertEqual(caps[:6], [b"QIHSE_AUTHORITY_V1", 1, 1, 1, 1, 1])
        self.case.assertGreater(caps[6], 0)
        self.case.assertLessEqual(caps[6], WIRE_MAX)
        self.case.assertIsInstance(caps[7], bytes)
        # Only the wire position is ASCII text for CLI arguments/hex decoding;
        # descriptors, ciphertext and all other SDK string replies stay bytes.
        caps[7] = caps[7].decode("ascii")
        self.case.assertEqual(len(bytes.fromhex(caps[7])), 48)
        return caps


class MaintenanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        for name in ("qihse-redis-server", "qihse-admin-cli", "libqihse.so"):
            if not (ROOT / name).is_file():
                raise RuntimeError("build dependency missing: " + name)
        cls.temp = tempfile.TemporaryDirectory(prefix="qihse-authority-")
        cls.addClassCleanup(cls.temp.cleanup)
        cls.fixture = Path(cls.temp.name)
        # Set before the SDK's first native library load/audit constructor.
        saved = {k: v for k, v in os.environ.items() if k.startswith("QIHSE_")}
        for k in saved:
            os.environ.pop(k)
        os.environ.update(QIHSE_DATA_DIR=str(cls.fixture), QIHSE_FIPS_MODE="disabled")

        def restore():
            for k in list(os.environ):
                if k.startswith("QIHSE_"):
                    os.environ.pop(k)
            os.environ.update(saved)
        cls.addClassCleanup(restore)
        for name in ("server", "client"):
            (cls.fixture / name).mkdir(mode=0o700)
        result = subprocess.run([sys.executable, str(Path(__file__).resolve()), "--helper", "keygen",
                                 str(cls.fixture / "server"), str(cls.fixture / "client")],
                                env=isolated_env(cls.fixture), capture_output=True, timeout=90)
        if result.returncode:
            raise RuntimeError("actual QKP synthetic keygen failed; no cleartext fallback")
        sys.path.insert(0, str(ROOT / "sdks/python"))
        from qihse_admin import ClusterAdmin, QihseAdminError
        cls.admin_error = QihseAdminError
        cls.admin = ClusterAdmin(node_id="maintenance-client", identity_dir=str(cls.fixture / "client"),
                                 lib_path=str(ROOT / "libqihse.so"))
        cls.pin = str(cls.fixture / "server/qihse_dsa_pub.pem")
        cls.local_keys, cls.transfer_keys = cls.make_keys("local"), cls.make_keys("transfer")
        # Observe/fault only the real CLI's output fsync calls. No protocol,
        # authentication, archive codec or successful response is mocked.
        shim = private_file(cls.fixture / "fsync_probe.c", br'''
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
int fsync(int fd) {
    int (*real_fsync)(int) = dlsym(RTLD_NEXT, "fsync");
    struct stat st;
    if (fstat(fd, &st)) return -1;
    const char *kind = S_ISDIR(st.st_mode) ? "directory" : "file";
    const char *path = getenv(S_ISDIR(st.st_mode) ? "MAINTENANCE_FSYNC_DIR" : "MAINTENANCE_FSYNC_FILE");
    struct stat expected;
    if (!path || stat(path, &expected) || st.st_dev != expected.st_dev || st.st_ino != expected.st_ino)
        return real_fsync(fd);
    const char *trace = getenv("MAINTENANCE_FSYNC_TRACE");
    if (trace) {
        int out = open(trace, O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
        if (out < 0) return -1;
        size_t n = strlen(kind);
        if (write(out, kind, n) != (ssize_t)n || write(out, "\n", 1) != 1) {
            close(out); errno = EIO; return -1;
        }
        close(out);
    }
    const char *fail = getenv("MAINTENANCE_FSYNC_FAIL");
    if (fail && strcmp(kind, fail) == 0) { errno = EIO; return -1; }
    return real_fsync(fd);
}
''')
        cls.fsync_probe = cls.fixture / "fsync_probe.so"
        result = subprocess.run([*shlex.split(os.environ.get("CC", "cc")), "-shared", "-fPIC",
                                 "-o", str(cls.fsync_probe), str(shim), "-ldl"],
                                capture_output=True, timeout=60)
        if result.returncode:
            raise RuntimeError("CLI fsync probe build failed")

    @classmethod
    def make_keys(cls, name):
        directory = cls.fixture / name
        directory.mkdir(mode=0o700)
        fields = {}
        for kind, algorithm in (("RECIPIENT", "ML-KEM-1024"), ("SIGNER", "ML-DSA-87")):
            private, public = directory / (kind + ".key"), directory / (kind + ".pub")
            for command in (["openssl", "genpkey", "-algorithm", algorithm, "-out", str(private)],
                            ["openssl", "pkey", "-in", str(private), "-pubout", "-out", str(public)]):
                if subprocess.run(command, capture_output=True, timeout=90).returncode:
                    raise RuntimeError("synthetic EVP key generation failed for " + algorithm)
            private.chmod(0o600)
            public.chmod(0o600)
            result = subprocess.run(["openssl", "pkey", "-pubin", "-in", str(public), "-outform", "DER"],
                                    capture_output=True, timeout=20)
            if result.returncode:
                raise RuntimeError("synthetic SPKI encoding failed")
            fields[kind + "_PRIVATE_KEY"], fields[kind + "_PUBLIC_KEY"] = str(private), str(public)
            fields[kind + "_PIN"] = hashlib.sha384(result.stdout).hexdigest()
        return fields

    def setUp(self):
        self.work = Path(tempfile.mkdtemp(prefix="case-", dir=self.fixture))
        self.source = Daemon(self, self.work / "source", self.local_keys, 0x56, ROOT_PW, "SOURCE_ROOT")
        self.source.start().ready()
        self.source.capabilities()  # Discover actual running capability before materialization.
        self.source.stop()
        result = subprocess.run([sys.executable, str(Path(__file__).resolve()), "--helper", "seed"],
                                env=self.source.env, capture_output=True, timeout=90)
        diagnostic = result.stderr.decode(errors="replace")[-4096:]
        for secret in (ROOT_PW, TARGET_PW, USER_PW):
            diagnostic = diagnostic.replace(secret, "<redacted>")
        self.assertEqual(result.returncode, 0, "isolated public API enrollment failed:\n" + diagnostic)
        self.source.start(recover=True).ready()
        # Explicit destination local trust equals the transfer recipient trust;
        # the source uses distinct local persistence keys, never silent fallback.
        self.target = Daemon(self, self.work / "target", self.transfer_keys, 0x78, TARGET_PW, "TARGET_ROOT")
        self.target.start().ready()
        self.sp, self.tp = self.source.capabilities()[7], self.target.capabilities()[7]
        self.descriptor = (struct.pack(">III", 1, 2, 1) + AUTHORITY + bytes.fromhex(self.sp)
                           + AUTHORITY + bytes.fromhex(self.tp) + os.urandom(16) + b"\x01"
                           + bytes.fromhex(self.transfer_keys["RECIPIENT_PIN"])
                           + bytes.fromhex(self.transfer_keys["SIGNER_PIN"]))
        self.assertEqual(len(self.descriptor), 253)
        self.config = private_file(self.work / "descriptor", self.descriptor)

    def cli(self, daemon, *args, user=None, password=None, extra_env=None):
        env = isolated_env(self.work)
        env["MAINTENANCE_TEST_PASSWORD"] = password or daemon.password
        env.update(extra_env or {})
        return subprocess.run([str(ROOT / "qihse-admin-cli"), "--host", "127.0.0.1", "--port",
                               str(daemon.port), "--identity-dir", str(self.fixture / "client"),
                               "--trusted-pub", self.pin, "--node-id", "maintenance-client",
                               "--timeout-ms", "5000", "--user", user or daemon.username,
                               "--password-env", "MAINTENANCE_TEST_PASSWORD", *map(str, args)],
                              env=env, capture_output=True, timeout=30)

    def export(self, name="archive"):
        output = self.work / name
        result = self.cli(self.source, "--authority-export", output,
                          "--expected-position", self.sp, "--transfer-config", self.config)
        self.assertEqual(result.returncode, 0, "real CLI export failed")
        self.assertEqual(result.stdout, b"")
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
        self.assertEqual(output.stat().st_nlink, 1)
        data = output.read_bytes()
        self.assertTrue(data)
        self.assertLessEqual(len(data), WIRE_MAX)
        for value in (ROOT_PW, USER_PW, HIGH):
            self.assertNotIn(value.encode(), data)
        return output

    def import_cli(self, path, request="ab" * 16, config=None, expected=None):
        return self.cli(self.target, "--authority-import", path, "--expected-position", expected or self.tp,
                        "--request-id", request, "--transfer-config", config or self.config)

    def assert_denied(self, reply):
        self.assertTrue(reply.startswith(b"-"), "maintenance disclosed payload instead of denial")
        for secret in (HIGH, ROOT_PW, USER_PW):
            self.assertNotIn(secret.encode(), reply)

    def test_real_cli_archive_import_retry_and_recovery(self):
        archive = self.export()
        result = self.import_cli(archive)
        self.assertEqual(result.returncode, 0, "real CLI import failed")
        committed = result.stdout.strip().decode("ascii")
        self.assertEqual(len(bytes.fromhex(committed)), 48)
        self.assertEqual(self.target.capabilities()[7], committed)
        self.assertEqual(self.source.capabilities()[7], self.sp, "export mutated source")
        with self.target.session("TARGET_ROOT", TARGET_PW) as session:
            self.assertEqual(session.execute("PING"), b"PONG")
        with self.assertRaises(self.admin_error):
            self.target.session("SOURCE_ROOT", ROOT_PW)
        for name in ("LOW", "GUEST", "TENANT_OPERATOR", HIGH):
            with self.target.session(name, USER_PW) as session:
                self.assertEqual(session.execute("PING"), b"PONG")
                self.assert_denied(session.execute_resp("AUTHORITY.CAPABILITIES"))
        retry = self.import_cli(archive)
        self.assertEqual((retry.returncode, retry.stdout), (0, result.stdout))
        self.target.stop()
        self.target.start(recover=True).ready()
        retry = self.import_cli(archive)
        self.assertEqual((retry.returncode, retry.stdout), (0, result.stdout), "durable receipt lost on restart")
        self.assertEqual(self.target.capabilities()[7], committed)
        self.assertNotEqual(self.import_cli(archive, request="98" * 16).returncode, 0,
                            "fresh request accepted stale original expected position")
        checkpoint = self.cli(self.target, "--authority-checkpoint", "--expected-position", committed)
        self.assertEqual(checkpoint.returncode, 0)
        current = self.target.capabilities()[7]
        self.assertNotEqual(current, committed)
        retry = self.import_cli(archive)
        self.assertEqual((retry.returncode, retry.stdout), (0, result.stdout),
                         "retry inferred result from current position instead of receipt")
        self.assertEqual(self.target.capabilities()[7], current)

    def test_lost_ack_retry_and_revoked_session(self):
        archive = self.export()
        with self.target.session("TARGET_ROOT", TARGET_PW) as session:
            # Discard acknowledgement at caller boundary, not a fabricated
            # timing-dependent claim of crash-before/after-commit coverage.
            reply = session.execute_resp("AUTHORITY.IMPORT", self.tp, "cd" * 16,
                                         self.descriptor, archive.read_bytes())
            self.assertFalse(reply.startswith(b"-"), "initial import did not commit")
        result = self.import_cli(archive, request="cd" * 16)
        self.assertEqual(result.returncode, 0)
        committed = result.stdout.strip().decode("ascii")
        with self.target.session("SERVICE_OPERATOR", USER_PW) as old:
            self.assertIsInstance(old.execute("AUTHORITY.CAPABILITIES"), list)
            with self.target.session("TARGET_ROOT", TARGET_PW) as root:
                # Import rotates nonroot handles, testing revocation on a real
                # persistent QKP session without inventing a USER wire command.
                descriptor = (self.descriptor[:28] + bytes.fromhex(committed)
                              + self.descriptor[76:92] + bytes.fromhex(committed)
                              + self.descriptor[140:])
                blob = root.execute("AUTHORITY.EXPORT", committed, descriptor)
                reply = root.execute_resp("AUTHORITY.IMPORT", committed, "ef" * 16,
                                          descriptor, blob)
                self.assertFalse(reply.startswith(b"-"), "self import failed")
            self.assert_denied(old.execute_resp("AUTHORITY.CAPABILITIES"))

    def test_null_guest_low_tenant_multi_and_tombstone_denial(self):
        commands = (("AUTHORITY.CAPABILITIES",), ("AUTHORITY.EXPORT", self.sp, self.descriptor),
                    ("AUTHORITY.IMPORT", self.sp, "aa" * 16, self.descriptor, b"sealed"),
                    ("AUTHORITY.CHECKPOINT", self.sp))
        for name in (None, "LOW", "GUEST", "TENANT_OPERATOR", HIGH):
            with self.source.session(name, USER_PW if name else None) as session:
                for command in commands:
                    with self.subTest(actor=name, command=command[0]):
                        self.assert_denied(session.execute_resp(*command))
        for name in ("LOW", "GUEST", "TENANT_OPERATOR"):
            output = self.work / ("denied-cli-" + name)
            result = self.cli(self.source, "--authority-export", output, "--expected-position", self.sp,
                              "--transfer-config", self.config, user=name, password=USER_PW)
            self.assertEqual(result.returncode, 5, "authorization denial misreported as unsupported export")
            self.assertFalse(output.exists())
            self.assertNotIn(HIGH.encode(), result.stdout + result.stderr)
        with self.assertRaises(self.admin_error):
            self.source.session("REVOKED_OPERATOR", USER_PW)
        with self.source.session("SOURCE_ROOT", ROOT_PW) as session:
            self.assertEqual(session.execute("MULTI"), b"OK")
            for command in commands:
                self.assert_denied(session.execute_resp(*command))
            session.execute_resp("DISCARD")
        self.assertEqual(self.source.capabilities()[7], self.sp)

    def test_wrong_descriptor_generation_tamper_and_size(self):
        archive = self.export()
        with self.source.session("SOURCE_ROOT", ROOT_PW) as source:
            for offset in (0, 4, 8, 12, 28, 156, 157, 205):
                changed = bytearray(self.descriptor)
                changed[offset] ^= 0x80
                self.assert_denied(source.execute_resp("AUTHORITY.EXPORT", self.sp, bytes(changed)))
            for descriptor in (b"", self.descriptor[:-1], self.descriptor + b"x"):
                self.assert_denied(source.execute_resp("AUTHORITY.EXPORT", self.sp, descriptor))
            stale = self.sp[:-16] + "0000000000000000"
            self.assert_denied(source.execute_resp("AUTHORITY.EXPORT", stale, self.descriptor))
        data = bytearray(archive.read_bytes())
        data[len(data) // 2] ^= 1
        tampered = private_file(self.work / "tampered", data)
        truncated = private_file(self.work / "truncated", archive.read_bytes()[:-1])
        for path in (tampered, truncated):
            self.assertNotEqual(self.import_cli(path).returncode, 0)
        oversized = self.work / "oversized"
        with os.fdopen(os.open(oversized, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as f:
            f.truncate(WIRE_MAX + 1)
        self.assertNotEqual(self.import_cli(oversized).returncode, 0)
        self.assertNotEqual(self.import_cli(archive, request="00" * 16).returncode, 0)
        self.assertNotEqual(self.import_cli(archive, expected=self.sp).returncode, 0)
        for offset in (76, 92, 140, 157, 205):
            descriptor = bytearray(self.descriptor)
            descriptor[offset] ^= 0x80
            config = private_file(self.work / ("wrong-binding-" + str(offset)), descriptor)
            self.assertNotEqual(self.import_cli(archive, config=config).returncode, 0)
        self.assertEqual(self.target.capabilities()[7], self.tp, "rejected import changed authority")
        result = self.import_cli(archive)
        self.assertEqual(result.returncode, 0)
        self.assertNotEqual(self.import_cli(tampered).returncode, 0, "conflicting request ID accepted")
        self.assertEqual(self.target.capabilities()[7], result.stdout.strip().decode("ascii"))

    def test_cli_private_exclusive_files_and_checkpoint(self):
        archive = self.export()
        original, inode = archive.read_bytes(), archive.stat().st_ino
        result = self.cli(self.source, "--authority-export", archive,
                          "--transfer-config", self.config, "--expected-position", self.sp)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((archive.read_bytes(), archive.stat().st_ino), (original, inode))
        linked = self.work / "linked"
        linked.symlink_to(archive)
        self.assertNotEqual(self.import_cli(linked).returncode, 0)
        hardlink = self.work / "hardlink"
        os.link(archive, hardlink)
        self.assertNotEqual(self.import_cli(hardlink).returncode, 0)
        hardlink.unlink()
        archive.chmod(0o644)
        self.assertNotEqual(self.import_cli(archive).returncode, 0)
        archive.chmod(0o600)
        for kind in ("fifo", "directory"):
            path = self.work / kind
            if kind == "fifo":
                os.mkfifo(path, 0o600)
            else:
                path.mkdir(mode=0o700)
            self.assertNotEqual(self.import_cli(path).returncode, 0)
        parent = self.work / "linked-parent"
        parent.symlink_to(self.work, target_is_directory=True)
        shared = self.work / "shared"
        shared.mkdir(mode=0o755)
        for output in (linked, parent / "output", shared / "output"):
            result = self.cli(self.source, "--authority-export", output,
                              "--transfer-config", self.config, "--expected-position", self.sp)
            self.assertNotEqual(result.returncode, 0)
        self.assertFalse((shared / "output").exists())
        self.config.chmod(0o644)
        result = self.cli(self.source, "--authority-export", self.work / "bad-config",
                          "--transfer-config", self.config, "--expected-position", self.sp)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.work / "bad-config").exists())
        self.config.chmod(0o600)
        for config in (private_file(self.work / "short-descriptor", self.descriptor[:-1]),
                       private_file(self.work / "long-descriptor", self.descriptor + b"x")):
            self.assertNotEqual(self.import_cli(archive, config=config).returncode, 0)
        descriptor_link = self.work / "descriptor-link"
        descriptor_link.symlink_to(self.config)
        self.assertNotEqual(self.import_cli(archive, config=descriptor_link).returncode, 0)
        self.assertNotEqual(self.import_cli(parent / archive.name).returncode, 0)
        result = self.cli(self.source, "--authority-checkpoint", "--expected-position", self.sp)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(self.source.capabilities()[7], result.stdout.strip().decode("ascii"))

    def test_actual_cli_fsync_output_and_failure_cleanup(self):
        trace = self.work / "fsync-trace"
        output = self.work / "synced-archive"
        probe_env = {"LD_PRELOAD": str(self.fsync_probe), "MAINTENANCE_FSYNC_TRACE": str(trace),
                     "MAINTENANCE_FSYNC_DIR": str(self.work), "MAINTENANCE_FSYNC_FILE": str(output)}
        result = self.cli(self.source, "--authority-export", output, "--expected-position", self.sp,
                          "--transfer-config", self.config, extra_env=probe_env)
        self.assertEqual(result.returncode, 0, "real CLI fsync probe export failed")
        self.assertEqual(trace.read_text().splitlines(), ["file", "directory"])
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
        for kind in ("file", "directory"):
            failed = self.work / ("failed-sync-" + kind)
            result = self.cli(self.source, "--authority-export", failed, "--expected-position", self.sp,
                              "--transfer-config", self.config,
                              extra_env={**probe_env, "MAINTENANCE_FSYNC_FAIL": kind,
                                         "MAINTENANCE_FSYNC_FILE": str(failed)})
            self.assertNotEqual(result.returncode, 0, "fsync failure reported as success")
            self.assertFalse(failed.exists(), "failed export left a usable-looking archive")
        self.assertEqual(self.source.capabilities()[7], self.sp)

    def test_real_volatile_source_reports_unsupported_without_export(self):
        legacy = Daemon(self, self.work / "legacy", self.local_keys, 0xaa, ROOT_PW, "GODMODE_OP")
        legacy.start(volatile=True).ready()
        with legacy.session("GODMODE_OP", ROOT_PW) as session:
            before = session.execute("AUTHORITY.CAPABILITIES")
        self.assertEqual(before[0], b"QIHSE_AUTHORITY_V1")
        self.assertEqual(before[3:6], [0, 0, 0])
        output = self.work / "unsupported-archive"
        result = self.cli(legacy, "--authority-export", output, "--transfer-config", self.config)
        self.assertEqual(result.returncode, 6)
        self.assertIn(b"UNSUPPORTED_EXPORT_API", result.stderr)
        self.assertFalse(output.exists())
        self.assertIsNone(legacy.proc.poll(), "unsupported discovery stopped the source")
        with legacy.session("GODMODE_OP", ROOT_PW) as session:
            self.assertEqual(session.execute("AUTHORITY.CAPABILITIES"), before)
            self.assertEqual(session.execute("PING"), b"PONG")

    def test_hwt_root_recovery_uses_existing_service_not_token_presence(self):
        hwt = Daemon(self, self.work / "hwt", self.transfer_keys, 0x9a, TARGET_PW, "HWT_ROOT")
        # The explicitly provisioned history/epoch and initial generation are
        # defined by protected startup, not guessed from an existing live node.
        target = HISTORY + bytes([0x9a] * 16) + struct.pack(">QQ", 1, 1)
        descriptor = self.descriptor[:92] + target + self.descriptor[140:]
        config = private_file(self.work / "hwt-descriptor", descriptor)
        archive = self.work / "hwt-archive"
        result = self.cli(self.source, "--authority-export", archive,
                          "--expected-position", self.sp, "--transfer-config", config)
        self.assertEqual(result.returncode, 0)
        result = subprocess.run([sys.executable, str(Path(__file__).resolve()), "--helper", "hwt-import",
                                 str(config), str(archive)], env=hwt.env, capture_output=True, timeout=90)
        self.assertEqual(result.returncode, 0, "protected HWT recovery preparation failed")
        # UID0/password cannot satisfy readiness without actual token presence.
        hwt.start(recover=True)
        self.assertNotEqual(hwt.proc.wait(timeout=20), 0)
        hwt.start(recover=True, selected=100, password=USER_PW).ready("SERVICE_OPERATOR", USER_PW)
        with hwt.session("SERVICE_OPERATOR", USER_PW) as session:
            self.assertIsInstance(session.execute("AUTHORITY.CAPABILITIES"), list)
        with hwt.session("HWT_ROOT", TARGET_PW) as session:
            self.assert_denied(session.execute_resp("AUTHORITY.CAPABILITIES"))
        hwt.stop()
        hwt.start(recover=True, selected=100, password=TARGET_PW)
        self.assertNotEqual(hwt.proc.wait(timeout=20), 0, "root password used as service fallback")
        hwt.start(recover=True, selected=100, password=USER_PW).ready("SERVICE_OPERATOR", USER_PW)

    def test_provision_uid_zero_and_recovery_binding_fail_closed(self):
        fresh = Daemon(self, self.work / "wrong-provision", self.local_keys, 0xbb, ROOT_PW, "NEW_ROOT")
        fresh.start(selected=100)
        self.assertNotEqual(fresh.proc.wait(timeout=20), 0)
        self.assertFalse((fresh.directory / "bootstrap").exists(), "rejected provision wrote bootstrap")
        self.assertFalse((fresh.directory / "authority/authority.state").exists())
        self.source.stop()
        for extra in ({"QIHSE_AUTH_HISTORY_ID": "ff" * 16},
                      {"QIHSE_AUTH_MIN_GENERATION": str(2**63)},
                      {"QIHSE_AUTH_MODE": "consensus"}):
            self.source.start(recover=True, extra=extra)
            self.assertNotEqual(self.source.proc.wait(timeout=20), 0)
            with socket.socket() as sock:
                sock.settimeout(0.2)
                self.assertNotEqual(sock.connect_ex(("127.0.0.1", self.source.port)), 0)
        self.source.start(recover=True).ready()
        self.assertEqual(self.source.capabilities()[7], self.sp)

    def test_recover_selected_existing_operator_without_fallback(self):
        self.source.stop()
        self.source.start(recover=True, selected=100, password=USER_PW).ready("SERVICE_OPERATOR", USER_PW)
        with self.source.session("SOURCE_ROOT", ROOT_PW) as session:
            self.assertIsInstance(session.execute("AUTHORITY.CAPABILITIES"), list)
        self.source.stop()
        for selected, password in (("0", ROOT_PW), ("", ROOT_PW), ("65536", ROOT_PW),
                                   ("-1", ROOT_PW), (" 100", USER_PW), ("999", USER_PW),
                                   ("101", USER_PW), ("103", USER_PW), ("100", ROOT_PW)):
            with self.subTest(selected=selected):
                self.source.start(recover=True, selected=selected, password=password)
                self.assertNotEqual(self.source.proc.wait(timeout=20), 0)
                with socket.socket() as sock:
                    sock.settimeout(0.2)
                    self.assertNotEqual(sock.connect_ex(("127.0.0.1", self.source.port)), 0)
        self.source.start(recover=True).ready()
        self.assertEqual(self.source.capabilities()[7][:80], self.sp[:80])


if __name__ == "__main__":
    if len(sys.argv) > 2 and sys.argv[1] == "--helper":
        native_helper(sys.argv[2])
    else:
        unittest.main()
