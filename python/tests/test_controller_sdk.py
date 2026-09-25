"""
Tests for the QIHSE Python controller SDK (qihse/controller.py — the
Python half of CITADEL v3 §25).

Three layers:

  1. Unit: exact RESP framing/encoding/decoding against the same wire
     bounds as the C client (bulk <= 16 MiB, items <= 1 MiB, depth <= 32).
  2. Client semantics: error mapping, explicit-auth only, watch cursor
     handling and reconnect resumption — against a scripted loopback
     mock server (localhost, ephemeral ports only; no external service).
  3. E2E (skipped automatically when the pieces are unavailable): the
     real federation RESP server built via ctypes inside a forked child
     process (its process-global auth/data-dir state must not leak into
     this pytest run), including the invariant-3 negatives mirrored from
     tests/test_controller_api.c — an unauthenticated principal and a
     low-clearance tenant guest are refused with NOAUTH/NOPERM and NO
     protected payload is disclosed.

TODO(e2e-coverage) — the e2e layer here intentionally runs only a slice
of the full C test-controller-api surface (status/ns/epoch/object-CAS/
lease/events+watch/groups/conflicts/node-list/metrics/security-observe
plus both negatives).  NOT covered from Python, and why:

  * NODE.ENROLL / NODE.APPROVE / NODE.REVOKE / TRUST.* — enrollment is
    disabled unless the server config sets federation_key_directory; the
    C suite covers it in test_controller_api.c and the federation tests.
  * Build/supply-chain/provenance/snapshot/schema/security-profile
    commands — same server dispatch path as the covered wrappers; the
    wire shapes are pinned by the scripted-mock parity test
    (TestWireShapesMatchCClient), so a Python e2e adds no new
    authorization surface.
  * RESP3 HELLO 3 against the real server — the server speaks RESP2;
    RESP3 parsing is covered by the decoder unit tests + the mock.
"""

import ctypes
import importlib.util
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
PY_PKG_DIR = REPO_ROOT / "python"
if str(PY_PKG_DIR) not in sys.path:
    sys.path.insert(0, str(PY_PKG_DIR))


def _load_controller_module():
    """Import qihse.controller without requiring libqihse.so.

    The package __init__ imports the ctypes core (which needs the shared
    library); the controller SDK itself is pure stdlib, so the framing
    unit tests stay runnable on hosts without a build.  E2E tests use the
    real package import and are skipped when the library is absent.
    """
    try:
        from qihse import controller as mod  # noqa: PLC0415
        return mod
    except Exception:  # ImportError / RuntimeError from the ctypes core
        path = PY_PKG_DIR / "qihse" / "controller.py"
        spec = importlib.util.spec_from_file_location(
            "qihse_controller_standalone", path
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod


ctrl = _load_controller_module()


# ─────────────────────────────────────────────────────────────────────────
# Scripted loopback mock server (localhost, ephemeral port only)
# ─────────────────────────────────────────────────────────────────────────

_CLOSE = object()      # close the connection without replying
_NOREPLY = object()    # keep the connection open but never reply


class ScriptedRESPServer(threading.Thread):
    """A loopback RESP server driven by a script of
    ``(expected_prefix | None, response_bytes | _CLOSE | _NOREPLY)``
    entries, consumed in order across all connections (so a reconnect
    just continues the script).  Records every command it receives."""

    def __init__(self, script):
        super().__init__(daemon=True)
        self.script = list(script)
        self.commands = []
        self.mismatches = []
        self._lock = threading.Lock()
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))          # ephemeral port
        self._sock.listen(8)
        self.port = self._sock.getsockname()[1]
        self._stop = threading.Event()

    def run(self):
        self._sock.settimeout(0.2)
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
            except (socket.timeout, TimeoutError):
                continue
            except OSError:
                break
            try:
                self._serve(conn)
            finally:
                conn.close()

    def _serve(self, conn):
        conn.settimeout(5.0)
        buf = bytearray()

        def read_line():
            nonlocal buf
            while True:
                idx = buf.find(b"\n")
                if idx >= 0:
                    line = bytes(buf[:idx])
                    del buf[: idx + 1]
                    return line.rstrip(b"\r")
                chunk = conn.recv(65536)
                if not chunk:
                    raise ConnectionError("client closed")
                buf += chunk

        while True:
            try:
                header = read_line()
                if not header.startswith(b"*"):
                    raise ValueError("bad command header")
                argc = int(header[1:])
                cmd = []
                for _ in range(argc):
                    len_line = read_line()
                    if not len_line.startswith(b"$"):
                        raise ValueError("bad argument header")
                    arg_len = int(len_line[1:])
                    while len(buf) < arg_len + 2:
                        chunk = conn.recv(65536)
                        if not chunk:
                            raise ConnectionError("client closed mid-arg")
                        buf += chunk
                    cmd.append(bytes(buf[:arg_len]))
                    del buf[: arg_len + 2]
            except (ConnectionError, OSError, ValueError):
                return
            with self._lock:
                self.commands.append(tuple(cmd))
                if not self.script:
                    conn.sendall(b"-ERR mock script exhausted\r\n")
                    return
                prefix, response = self.script.pop(0)
                if prefix is not None and tuple(cmd[: len(prefix)]) != tuple(prefix):
                    self.mismatches.append((tuple(prefix), tuple(cmd)))
                    conn.sendall(b"-ERR mock prefix mismatch\r\n")
                    return
            if response is _CLOSE:
                return
            if response is _NOREPLY:
                continue
            conn.sendall(response)

    def stop(self):
        self._stop.set()
        try:
            self._sock.close()
        except OSError:
            pass
        self.join(timeout=3.0)


class mock_server:
    """Context manager wrapper for ScriptedRESPServer."""

    def __init__(self, script):
        self.server = ScriptedRESPServer(script)

    def __enter__(self):
        self.server.start()
        return self.server

    def __exit__(self, *exc):
        self.server.stop()
        return False


AUTH_OK = ((b"AUTH", b"op", b"pw"), b"+OK\r\n")


# ─────────────────────────────────────────────────────────────────────────
# 1. Encoding unit tests
# ─────────────────────────────────────────────────────────────────────────

class TestCommandEncoding(unittest.TestCase):
    def test_exact_frame_bytes(self):
        frame = ctrl.encode_command(
            ["FEDERATION", "OBJECT.CAS", "ns", "vm-1", b"running", 0])
        self.assertEqual(
            frame,
            b"*6\r\n$10\r\nFEDERATION\r\n$10\r\nOBJECT.CAS\r\n$2\r\nns\r\n"
            b"$4\r\nvm-1\r\n$7\r\nrunning\r\n$1\r\n0\r\n",
        )

    def test_bytes_bytearray_memoryview(self):
        frame = ctrl.encode_command(["X", b"b", bytearray(b"ba"), memoryview(b"mv")])
        self.assertEqual(
            frame, b"*4\r\n$1\r\nX\r\n$1\r\nb\r\n$2\r\nba\r\n$2\r\nmv\r\n")

    def test_unicode_is_utf8(self):
        self.assertEqual(
            ctrl.encode_command(["KEY", "ke\u0301y"]),
            b"*2\r\n$3\r\nKEY\r\n$5\r\nke\xcc\x81y\r\n",
        )

    def test_integer_args_render_decimal(self):
        self.assertIn(b"$5\r\n65536\r\n", ctrl.encode_command(["N", 65536]))
        self.assertIn(b"$2\r\n-3\r\n", ctrl.encode_command(["N", -3]))

    def test_rejects_ambiguous_or_bad_arg_types(self):
        for bad in (None, 1.5, True, object(), []):
            with self.assertRaises(ctrl.ControllerUsageError):
                ctrl.encode_command(["X", bad])

    def test_rejects_empty_command(self):
        with self.assertRaises(ctrl.ControllerUsageError):
            ctrl.encode_command([])

    def test_command_size_bound(self):
        # A 16 MiB argument's framing overhead pushes the frame past
        # MAX_BULK_BYTES, so it is refused before any socket is touched.
        with self.assertRaises(ctrl.CommandTooLargeError):
            ctrl.encode_command(["B", b"x" * ctrl.MAX_BULK_BYTES])
        # Comfortably inside the bound is accepted.
        ok = ctrl.encode_command(["B", b"x" * (ctrl.MAX_BULK_BYTES - 128)])
        self.assertLess(len(ok), ctrl.MAX_BULK_BYTES)


# ─────────────────────────────────────────────────────────────────────────
# 2. Decoder unit tests (exact frames through the bounded reader)
# ─────────────────────────────────────────────────────────────────────────

class DecoderTestBase(unittest.TestCase):
    def parse(self, data: bytes):
        return ctrl.parse_reply(ctrl._BytesReader(data))

    def assert_rejects(self, data: bytes, exc=ctrl.ControllerProtocolError):
        with self.assertRaises(exc):
            self.parse(data)


class TestDecodeRESP2(DecoderTestBase):
    def test_simple(self):
        r = self.parse(b"+OK\r\n")
        self.assertEqual(r.kind, "simple")
        self.assertTrue(r.is_ok())
        self.assertEqual(r.as_bytes(), b"OK")
        self.assertEqual(self.parse(b"+PONG\r\n").as_text(), "PONG")

    def test_error_line(self):
        r = self.parse(b"-NOPERM federation requires authentication\r\n")
        self.assertEqual(r.kind, "error")
        self.assertEqual(
            ctrl._error_detail(r.as_bytes()),
            ("NOPERM", "federation requires authentication"),
        )

    def test_error_line_without_message(self):
        self.assertEqual(ctrl._error_detail(b"ERR"), ("ERR", ""))

    def test_integers(self):
        self.assertEqual(self.parse(b":42\r\n").as_int(), 42)
        self.assertEqual(self.parse(b":0\r\n").as_int(), 0)
        self.assertEqual(self.parse(b":-7\r\n").as_int(), -7)

    def test_malformed_integers_rejected(self):
        for bad in (b": 1\r\n", b":+1\r\n", b":1_0\r\n", b":1.5\r\n",
                    b":\r\n", b":0x10\r\n"):
            self.assert_rejects(bad)

    def test_bulk(self):
        r = self.parse(b"$6\r\nfoobar\r\n")
        self.assertEqual((r.kind, r.as_bytes()), ("bulk", b"foobar"))
        self.assertEqual(self.parse(b"$0\r\n\r\n").as_bytes(), b"")
        self.assertEqual(self.parse(b"$3\r\n\r\n\x00\r\n").as_bytes(),
                         b"\r\n\x00")  # payload may contain CRLF/NUL bytes

    def test_bulk_nil(self):
        self.assertEqual(self.parse(b"$-1\r\n").kind, "nil")

    def test_bulk_requires_exact_crlf(self):
        # Truncated stream (terminator missing) is a transport error...
        with self.assertRaises(ctrl.ControllerTransportError):
            self.parse(b"$3\r\nfoo\n")
        # ...a present-but-wrong terminator is a protocol error.
        self.assert_rejects(b"$3\r\nfooXY")
        self.assert_rejects(b"$3\r\nfoo\r\r\n")

    def test_bulk_at_bound_accepted(self):
        payload = b"x" * ctrl.MAX_BULK_BYTES
        r = self.parse(b"$%d\r\n" % ctrl.MAX_BULK_BYTES + payload + b"\r\n")
        self.assertEqual(len(r.as_bytes()), ctrl.MAX_BULK_BYTES)

    def test_oversized_bulk_rejected(self):
        self.assert_rejects(b"$%d\r\n" % (ctrl.MAX_BULK_BYTES + 1))
        self.assert_rejects(b"$-2\r\n")
        self.assert_rejects(b"$abc\r\n")

    def test_array(self):
        r = self.parse(b"*2\r\n:5\r\n$3\r\nfoo\r\n")
        self.assertEqual(r.kind, "array")
        self.assertEqual(len(r), 2)
        self.assertEqual(r[0].as_int(), 5)
        self.assertEqual(r[1].as_bytes(), b"foo")

    def test_array_nil_and_empty(self):
        self.assertEqual(self.parse(b"*-1\r\n").kind, "nil")
        self.assertEqual(len(self.parse(b"*0\r\n")), 0)

    def test_nested_arrays(self):
        r = self.parse(b"*1\r\n*2\r\n*1\r\n:9\r\n$1\r\nz\r\n")
        self.assertEqual(r[0][0][0].as_int(), 9)
        self.assertEqual(r[0][1].as_bytes(), b"z")

    def test_item_bound(self):
        # 1 MiB items is the cap (1<<20); 1048577 is refused before any
        # element is read.
        self.assert_rejects(b"*1048577\r\n")

    def test_depth_bound(self):
        # 32 nested containers are allowed (leaf parsed at depth 32);
        # 33 are not — exact QIHSE_CTRL_MAX_DEPTH parity with the C client.
        self.assertEqual(self.parse(b"*1\r\n" * 32 + b"+x\r\n").kind, "array")
        self.assert_rejects(b"*1\r\n" * 33 + b"+x\r\n")

    def test_line_bound(self):
        self.assert_rejects(b"+" + b"a" * (ctrl.MAX_LINE_BYTES + 1) + b"\r\n")

    def test_unknown_type_byte(self):
        self.assert_rejects(b"?3\r\n")

    def test_empty_stream(self):
        with self.assertRaises(ctrl.ControllerTransportError):
            ctrl.parse_reply(ctrl._BytesReader(b""))


class TestDecodeRESP3(DecoderTestBase):
    def test_null_boolean_double_bignum(self):
        self.assertEqual(self.parse(b"_\r\n").kind, "nil")
        self.assertIs(self.parse(b"#t\r\n").value, True)
        self.assertIs(self.parse(b"#f\r\n").value, False)
        self.assertEqual(self.parse(b",3.5\r\n").value, 3.5)
        self.assertEqual(self.parse(b",inf\r\n").value, float("inf"))
        self.assertEqual(self.parse(b",-inf\r\n").value, float("-inf"))
        self.assertTrue(math_is_nan(self.parse(b",nan\r\n").value))
        self.assertEqual(
            self.parse(b"(123456789012345678901234567890\r\n").value,
            123456789012345678901234567890,
        )

    def test_malformed_double_and_bool_rejected(self):
        self.assert_rejects(b",3,14\r\n")
        self.assert_rejects(b",1_0\r\n")
        self.assert_rejects(b"#yes\r\n")

    def test_verbatim_keeps_prefix(self):
        r = self.parse(b"=17\r\ntxt:Hello, world!\r\n")
        self.assertEqual(r.kind, "verbatim")
        self.assertEqual(r.as_bytes(), b"txt:Hello, world!")

    def test_blob_error(self):
        r = self.parse(b"!23\r\nSYNTAX bad request line\r\n")
        self.assertEqual(r.kind, "error")
        self.assertEqual(ctrl._error_detail(r.as_bytes()),
                         ("SYNTAX", "bad request line"))

    def test_map(self):
        r = self.parse(b"%2\r\n$3\r\nfoo\r\n:1\r\n$3\r\nbar\r\n:2\r\n")
        self.assertEqual(r.kind, "map")
        pairs = r.as_pairs()
        self.assertEqual((pairs[0][0].as_bytes(), pairs[0][1].as_int()),
                         (b"foo", 1))
        self.assertEqual((pairs[1][0].as_bytes(), pairs[1][1].as_int()),
                         (b"bar", 2))
        self.assertEqual(len(r), 2)

    def test_set(self):
        r = self.parse(b"~2\r\n:1\r\n:2\r\n")
        self.assertEqual(r.kind, "set")
        self.assertEqual(sorted(x.as_int() for x in r), [1, 2])

    def test_push_shape(self):
        r = self.parse(b">1\r\n+pubsub\r\n")
        self.assertEqual(r.kind, "push")
        self.assertEqual(r[0].as_bytes(), b"pubsub")

    def test_streamed_string(self):
        r = self.parse(b"$?\r\n;4\r\nHell;6\r\no worl;1\r\nd;0\r\n")
        self.assertEqual((r.kind, r.as_bytes()), ("bulk", b"Hello world"))

    def test_streamed_string_bound(self):
        big = b"x" * (ctrl.MAX_BULK_BYTES + 1)
        frame = b"$?\r\n;" + str(len(big)).encode() + b"\r\n" + big
        with self.assertRaises(ctrl.ControllerProtocolError):
            self.parse(frame)

    def test_streamed_array(self):
        r = self.parse(b"*?\r\n:1\r\n:2\r\n.\r\n")
        self.assertEqual(r.kind, "array")
        self.assertEqual([x.as_int() for x in r], [1, 2])

    def test_streamed_map(self):
        r = self.parse(b"%?\r\n$1\r\nk\r\n$1\r\nv\r\n.\r\n")
        self.assertEqual(r.kind, "map")
        pair = r.as_pairs()[0]
        self.assertEqual((pair[0].as_bytes(), pair[1].as_bytes()), (b"k", b"v"))

    def test_attribute_attaches_to_wrapped_reply(self):
        r = self.parse(b"|1\r\n$7\r\nkey-pop\r\n:1\r\n+OK\r\n")
        self.assertEqual(r.kind, "simple")          # the wrapped reply
        self.assertTrue(r.is_ok())
        self.assertIsNotNone(r.attributes)
        self.assertEqual(r.attributes[0][0].as_bytes(), b"key-pop")
        self.assertEqual(r.attributes[0][1].as_int(), 1)


def math_is_nan(value) -> bool:
    return value != value  # NaN is the only value not equal to itself


class TestReplyShapeAccessors(unittest.TestCase):
    def test_wrong_kind_accessors_raise(self):
        r = ctrl.Reply("int", value=3)
        with self.assertRaises(ctrl.ReplyShapeError):
            r.as_bytes()
        with self.assertRaises(ctrl.ReplyShapeError):
            len(r)
        b = ctrl.Reply("bulk", value=b"x")
        with self.assertRaises(ctrl.ReplyShapeError):
            b.as_int()

    def test_repr_is_bounded(self):
        r = ctrl.Reply("bulk", value=b"x" * 1000)
        self.assertLess(len(repr(r)), 120)
        self.assertNotIn("x" * 100, repr(r))  # payload never fully dumped


# ─────────────────────────────────────────────────────────────────────────
# 3. Client semantics against the scripted mock
# ─────────────────────────────────────────────────────────────────────────

class TestClientBasics(unittest.TestCase):
    def test_no_ambient_auth_when_no_principal_given(self):
        with mock_server([(None, b"$2\r\nok\r\n")]) as srv:
            with ctrl.Controller("127.0.0.1", srv.port) as c:
                c.federation_status()
        # No AUTH was sent — the SDK never invents an identity.
        self.assertEqual(srv.commands, [(b"FEDERATION", b"STATUS")])

    def test_explicit_auth_on_connect(self):
        with mock_server([AUTH_OK, (None, b":1\r\n")]) as srv:
            with ctrl.Controller("127.0.0.1", srv.port,
                                 username="op", password="pw") as c:
                self.assertEqual(c.epoch_next().as_int(), 1)
        self.assertEqual(srv.commands[0], (b"AUTH", b"op", b"pw"))

    def test_refused_credentials_raise_and_close(self):
        with mock_server([
            ((b"AUTH", b"op", b"wrong"), b"-ERR invalid password\r\n"),
        ]) as srv:
            c = ctrl.Controller("127.0.0.1", srv.port, username="op",
                                password="wrong", connect=False)
            with self.assertRaises(ctrl.ControllerAuthenticationError) as ctx:
                c.connect()
            self.assertIn("invalid password", str(ctx.exception))
            self.assertIn("op", str(ctx.exception))
            self.assertFalse(c.connected)   # failed AUTH leaves it closed

    def test_error_reply_maps_to_typed_exception(self):
        with mock_server([
            ((b"FEDERATION", b"STATUS"),
             b"-NOPERM federation requires authentication\r\n"),
        ]) as srv:
            with ctrl.Controller("127.0.0.1", srv.port) as c:
                with self.assertRaises(ctrl.ControllerServerError) as ctx:
                    c.federation_status()
                self.assertEqual(ctx.exception.error_class, "NOPERM")
                self.assertEqual(
                    ctx.exception.message,
                    "federation requires authentication")
                self.assertEqual(
                    str(ctx.exception),
                    "NOPERM federation requires authentication")

    def test_check_false_returns_error_reply(self):
        with mock_server([(None, b"-NOAUTH AUTH required\r\n")]) as srv:
            with ctrl.Controller("127.0.0.1", srv.port) as c:
                reply = c.call("FEDERATION", "STATUS", check=False)
            self.assertEqual(reply.kind, "error")
            self.assertEqual(reply.as_bytes(), b"NOAUTH AUTH required")

    def test_resp3_hello_then_command(self):
        with mock_server([
            ((b"HELLO", b"3"), b"%1\r\n$7\r\nversion\r\n$3\r\n7.2\r\n"),
            AUTH_OK,
            ((b"FEDERATION", b"EPOCH.NEXT"), b":9\r\n"),
        ]) as srv:
            with ctrl.Controller("127.0.0.1", srv.port, protocol=3,
                                 username="op", password="pw") as c:
                self.assertEqual(c.epoch_next().as_int(), 9)
        self.assertEqual(srv.commands[0], (b"HELLO", b"3"))

    def test_push_messages_are_queued_not_returned(self):
        with mock_server([(None, b">1\r\n$7\r\npubsub!\r\n:42\r\n")]) as srv:
            with ctrl.Controller("127.0.0.1", srv.port) as c:
                reply = c.call("GET", b"k")
        self.assertEqual(reply.as_int(), 42)
        self.assertEqual(len(c.pushes), 1)
        self.assertEqual(c.pushes[0][0].as_bytes(), b"pubsub!")

    def test_server_close_marks_dead(self):
        with mock_server([(None, _CLOSE)]) as srv:
            with ctrl.Controller("127.0.0.1", srv.port) as c:
                with self.assertRaises(ctrl.ControllerTransportError):
                    c.call("PING")
                self.assertFalse(c.connected)
                with self.assertRaises(ctrl.ControllerTransportError):
                    c.call("PING")   # still dead; no zombie socket use

    def test_timeout_is_typed(self):
        with mock_server([(None, _NOREPLY)]) as srv:
            c = ctrl.Controller("127.0.0.1", srv.port, timeout_ms=300,
                                connect=False)
            c.connect()
            try:
                with self.assertRaises(ctrl.ControllerTimeoutError):
                    c.call("PING")
                self.assertFalse(c.connected)
            finally:
                c.close()

    def test_connect_refused(self):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        with self.assertRaises(ctrl.ControllerConnectionError):
            ctrl.Controller("127.0.0.1", port, timeout_ms=500)

    def test_usage_validation(self):
        c = ctrl.Controller("127.0.0.1", 1, connect=False)
        with self.assertRaises(ctrl.ControllerUsageError):
            c.object_cas("ns", "rid", b"v", -1)
        with self.assertRaises(ctrl.ControllerUsageError):
            c.object_cas("ns", "rid", b"v", True)
        with self.assertRaises(ctrl.ControllerUsageError):
            c.lease_acquire("ns", "rid", -1)
        with self.assertRaises(ctrl.ControllerUsageError):
            c.watch_ack(1, -2)
        with self.assertRaises(ctrl.ControllerUsageError):
            ctrl.Controller("127.0.0.1", 0)

    def test_context_manager_connects_once(self):
        with mock_server([(None, b"+PONG\r\n")]) as srv:
            with ctrl.Controller("127.0.0.1", srv.port, connect=False) as c:
                self.assertTrue(c.connected)
                reply = c.call("PING")
                self.assertEqual(reply.kind, "simple")   # +PONG (not +OK)
                self.assertEqual(reply.as_bytes(), b"PONG")
            self.assertFalse(c.connected)


class TestWireShapesMatchCClient(unittest.TestCase):
    """Pin the exact command vocabulary of every wrapper to the C client
    (src/controller/qihse_controller.c): same subcommands, same argument
    order, same optional-argument omission rules."""

    def test_all_wrapper_shapes(self):
        ok = b"+OK\r\n"
        cases = [
            (lambda c: c.node_list(), (b"FEDERATION", b"NODE.LIST")),
            (lambda c: c.node_get("n1"), (b"FEDERATION", b"NODE.SHOW", b"n1")),
            (lambda c: c.node_enroll("server", "h0", "b0"),
             (b"FEDERATION", b"NODE.ENROLL", b"server", b"h0", b"b0")),
            (lambda c: c.node_approve("n1"),
             (b"FEDERATION", b"NODE.APPROVE", b"n1")),
            (lambda c: c.node_approve("n1", 4),
             (b"FEDERATION", b"NODE.APPROVE", b"n1", b"4")),
            (lambda c: c.node_revoke("n1"),
             (b"FEDERATION", b"NODE.REVOKE", b"n1")),
            (lambda c: c.trust_set("n1", "attested", "attested"),
             (b"FEDERATION", b"TRUST.SET", b"n1", b"attested", b"attested")),
            (lambda c: c.trust_states(), (b"FEDERATION", b"TRUST.STATES")),
            (lambda c: c.trust_admission("n1"),
             (b"FEDERATION", b"TRUST.ADMISSION", b"n1")),
            (lambda c: c.object_get("ns", "r1"),
             (b"FEDERATION", b"OBJECT.GET", b"ns", b"r1")),
            (lambda c: c.object_cas("ns", "r1", b"v", 3),
             (b"FEDERATION", b"OBJECT.CAS", b"ns", b"r1", b"v", b"3")),
            (lambda c: c.object_cas("ns", "r1", "v", 0),
             (b"FEDERATION", b"OBJECT.CAS", b"ns", b"r1", b"v", b"0")),
            (lambda c: c.lease_acquire("ns", "r1", 7),
             (b"FEDERATION", b"LEASE.ACQUIRE", b"ns", b"r1", b"7")),
            (lambda c: c.lease_acquire("ns", "r1", 7, 60000),
             (b"FEDERATION", b"LEASE.ACQUIRE", b"ns", b"r1", b"7", b"60000")),
            (lambda c: c.lease_read("L1"),
             (b"FEDERATION", b"LEASE.READ", b"L1")),
            (lambda c: c.lease_renew("L1", 120000),
             (b"FEDERATION", b"LEASE.RENEW", b"L1", b"120000")),
            (lambda c: c.lease_release("L1"),
             (b"FEDERATION", b"LEASE.RELEASE", b"L1")),
            (lambda c: c.epoch_next(), (b"FEDERATION", b"EPOCH.NEXT")),
            (lambda c: c.epoch_current(), (b"FEDERATION", b"EPOCH.CURRENT")),
            (lambda c: c.event_append("t", "vm-1"),
             (b"FEDERATION", b"EVENT.APPEND", b"t", b"vm-1")),
            (lambda c: c.event_append("t", "vm-1", b""),
             (b"FEDERATION", b"EVENT.APPEND", b"t", b"vm-1", b"")),
            (lambda c: c.event_append("t", "vm-1", b'{"a":1}'),
             (b"FEDERATION", b"EVENT.APPEND", b"t", b"vm-1", b'{"a":1}')),
            (lambda c: c.event_replay(),
             (b"FEDERATION", b"EVENT.REPLAY", b"0")),
            (lambda c: c.event_replay(12),
             (b"FEDERATION", b"EVENT.REPLAY", b"12")),
            (lambda c: c.watch_next(3),
             (b"FEDERATION", b"WATCH.NEXT", b"3")),
            (lambda c: c.watch_ack(3, 9),
             (b"FEDERATION", b"WATCH.ACK", b"3", b"9")),
            (lambda c: c.watch_resume(3, 1),
             (b"FEDERATION", b"WATCH.RESUME", b"3", b"1")),
            (lambda c: c.conflict_list(), (b"FEDERATION", b"CONFLICT.LIST")),
            (lambda c: c.conflict_resolve("c1", "n1"),
             (b"FEDERATION", b"CONFLICT.RESOLVE", b"c1", b"n1")),
            (lambda c: c.federation_status(), (b"FEDERATION", b"STATUS")),
            (lambda c: c.rejoin_status("n1"),
             (b"FEDERATION", b"REJOIN.STATUS", b"n1")),
            (lambda c: c.metrics(), (b"FEDERATION", b"METRICS")),
            (lambda c: c.metrics("qihse_fed"),
             (b"FEDERATION", b"METRICS", b"qihse_fed")),
            (lambda c: c.ns_register("ns1", "LOCAL"),
             (b"FEDERATION", b"NS.REGISTER", b"ns1", b"LOCAL")),
            (lambda c: c.ns_register("ns1", "QUORUM", "n1"),
             (b"FEDERATION", b"NS.REGISTER", b"ns1", b"QUORUM", b"n1")),
            (lambda c: c.ns_unregister("ns1"),
             (b"FEDERATION", b"NS.UNREGISTER", b"ns1")),
            (lambda c: c.ns_list(), (b"FEDERATION", b"NS.LIST")),
            (lambda c: c.ns_writable("ns1"),
             (b"FEDERATION", b"NS.WRITABLE", b"ns1")),
            (lambda c: c.manifest("ns1"),
             (b"FEDERATION", b"MANIFEST", b"ns1")),
            (lambda c: c.group_create("g1"),
             (b"FEDERATION", b"GROUP.CREATE", b"g1")),
            (lambda c: c.group_create("g1", "LINEARIZABLE"),
             (b"FEDERATION", b"GROUP.CREATE", b"g1", b"LINEARIZABLE")),
            (lambda c: c.group_add("g1", "n1"),
             (b"FEDERATION", b"GROUP.ADD", b"g1", b"n1")),
            (lambda c: c.group_add("g1", "n1", voter=True),
             (b"FEDERATION", b"GROUP.ADD", b"g1", b"n1", b"voter")),
            (lambda c: c.group_add("g1", "n1", witness=True),
             (b"FEDERATION", b"GROUP.ADD", b"g1", b"n1", b"witness")),
            (lambda c: c.group_add("g1", "n1", True, True),
             (b"FEDERATION", b"GROUP.ADD", b"g1", b"n1", b"voter", b"witness")),
            (lambda c: c.group_remove("g1", "n1"),
             (b"FEDERATION", b"GROUP.REMOVE", b"g1", b"n1")),
            (lambda c: c.group_show("g1"),
             (b"FEDERATION", b"GROUP.SHOW", b"g1")),
            (lambda c: c.group_list(), (b"FEDERATION", b"GROUP.LIST")),
            (lambda c: c.group_advance("g1"),
             (b"FEDERATION", b"GROUP.ADVANCE", b"g1")),
            (lambda c: c.build_job_create("p", "r", "prof", "tc"),
             (b"FEDERATION", b"BUILD.CREATE", b"p", b"r", b"prof", b"tc")),
            (lambda c: c.build_job_transition("b1", "running", "req1"),
             (b"FEDERATION", b"BUILD.TRANSITION", b"b1", b"running", b"req1")),
            (lambda c: c.build_job_transition("b1", "done", "req1", "ok"),
             (b"FEDERATION", b"BUILD.TRANSITION", b"b1", b"done", b"req1",
              b"ok")),
            (lambda c: c.build_job_get("b1"),
             (b"FEDERATION", b"BUILD.SHOW", b"b1")),
            (lambda c: c.build_job_list(), (b"FEDERATION", b"BUILD.LIST")),
            (lambda c: c.build_states(), (b"FEDERATION", b"BUILD.STATES")),
            (lambda c: c.build_worker_publish("n1", 8, 64, 2),
             (b"FEDERATION", b"BUILDER.CAP", b"n1", b"8", b"64", b"2")),
            (lambda c: c.build_worker_get("n1"),
             (b"FEDERATION", b"BUILDER.SHOW", b"n1")),
            (lambda c: c.pkg_set("pkg", "quarantine", "why"),
             (b"FEDERATION", b"PKG.SET", b"pkg", b"quarantine", b"why")),
            (lambda c: c.pkg_get("pkg"), (b"FEDERATION", b"PKG.GET", b"pkg")),
            (lambda c: c.pkg_modes(), (b"FEDERATION", b"PKG.MODES")),
            (lambda c: c.supply_sbom("d1", "d2", "signer", "spdx"),
             (b"FEDERATION", b"SUPPLY.SBOM", b"d1", b"d2", b"signer", b"spdx")),
            (lambda c: c.supply_sbom_get("d2"),
             (b"FEDERATION", b"SUPPLY.SBOM.GET", b"d2")),
            (lambda c: c.supply_snapshot("repo", "dg", "rel"),
             (b"FEDERATION", b"SUPPLY.SNAPSHOT", b"repo", b"dg", b"rel")),
            (lambda c: c.supply_snapshot("repo", "dg", "rel", 4),
             (b"FEDERATION", b"SUPPLY.SNAPSHOT", b"repo", b"dg", b"rel",
              b"4")),
            (lambda c: c.supply_snapshot_list(),
             (b"FEDERATION", b"SUPPLY.SNAPSHOT.LIST")),
            (lambda c: c.supply_snapshot_list("repo"),
             (b"FEDERATION", b"SUPPLY.SNAPSHOT.LIST", b"repo")),
            (lambda c: c.supply_vuln("cd", "adv", "high", "open"),
             (b"FEDERATION", b"SUPPLY.VULN", b"cd", b"adv", b"high", b"open")),
            (lambda c: c.supply_vuln_count("cd"),
             (b"FEDERATION", b"SUPPLY.VULN.COUNT", b"cd")),
            (lambda c: c.prov_node("build", "b1"),
             (b"FEDERATION", b"PROV.NODE", b"build", b"b1")),
            (lambda c: c.prov_node("build", "b1", "lbl"),
             (b"FEDERATION", b"PROV.NODE", b"build", b"b1", b"lbl")),
            (lambda c: c.prov_edge("build:b1", "used", "artifact:a1"),
             (b"FEDERATION", b"PROV.EDGE", b"build:b1", b"used",
              b"artifact:a1")),
            (lambda c: c.prov_show("build", "b1"),
             (b"FEDERATION", b"PROV.SHOW", b"build", b"b1")),
            (lambda c: c.prov_trace("build", "b1"),
             (b"FEDERATION", b"PROV.TRACE", b"build", b"b1", b"forward")),
            (lambda c: c.prov_trace("build", "b1", False),
             (b"FEDERATION", b"PROV.TRACE", b"build", b"b1", b"reverse")),
            (lambda c: c.prov_trace("build", b"b1".decode(), True, 5),
             (b"FEDERATION", b"PROV.TRACE", b"build", b"b1", b"forward",
              b"5")),
            (lambda c: c.prov_impact("build", "b1", "deploy"),
             (b"FEDERATION", b"PROV.IMPACT", b"build", b"b1", b"deploy")),
            (lambda c: c.prov_impact("build", "b1", "deploy", 3),
             (b"FEDERATION", b"PROV.IMPACT", b"build", b"b1", b"deploy",
              b"3")),
            (lambda c: c.snapshot_create("local", 1, 2),
             (b"FEDERATION", b"SNAPSHOT.CREATE", b"local", b"1", b"2")),
            (lambda c: c.snapshot_create("coordinated", 1, 2, "key1"),
             (b"FEDERATION", b"SNAPSHOT.CREATE", b"coordinated", b"1", b"2",
              b"key1")),
            (lambda c: c.snapshot_show("s1"),
             (b"FEDERATION", b"SNAPSHOT.SHOW", b"s1")),
            (lambda c: c.snapshot_verify("s1"),
             (b"FEDERATION", b"SNAPSHOT.VERIFY", b"s1")),
            (lambda c: c.schema_status("sch", "2"),
             (b"FEDERATION", b"SCHEMA.STATUS", b"sch", b"2")),
            (lambda c: c.schema_check("3", "2", "ff", "0"),
             (b"FEDERATION", b"SCHEMA.CHECK", b"3", b"2", b"ff", b"0")),
            (lambda c: c.schema_migrate("sch", "1", "2", True),
             (b"FEDERATION", b"SCHEMA.MIGRATE", b"sch", b"1", b"2", b"1")),
            (lambda c: c.schema_migrate("sch", "1", "2", False),
             (b"FEDERATION", b"SCHEMA.MIGRATE", b"sch", b"1", b"2", b"0")),
            (lambda c: c.schema_progress("sch", "2", 5, 10),
             (b"FEDERATION", b"SCHEMA.PROGRESS", b"sch", b"2", b"5", b"10")),
            (lambda c: c.security_audit(),
             (b"FEDERATION", b"SECURITY.AUDIT")),
            (lambda c: c.security_audit("svc"),
             (b"FEDERATION", b"SECURITY.AUDIT", b"svc")),
            (lambda c: c.security_audit("svc", "1.2"),
             (b"FEDERATION", b"SECURITY.AUDIT", b"svc", b"1.2")),
            (lambda c: c.security_observe(),
             (b"FEDERATION", b"SECURITY.OBSERVE")),
            (lambda c: c.security_ifaces(),
             (b"FEDERATION", b"SECURITY.IFACES")),
            (lambda c: c.security_profile_get("svc", "1.2"),
             (b"FEDERATION", b"SECURITY.PROFILE.GET", b"svc", b"1.2")),
            (lambda c: c.security_net_get("svc", "1.2"),
             (b"FEDERATION", b"SECURITY.NET.GET", b"svc", b"1.2")),
        ]
        script = [AUTH_OK] + [(None, ok) for _ in cases]
        with mock_server(script) as srv:
            with ctrl.Controller("127.0.0.1", srv.port,
                                 username="op", password="pw") as c:
                for func, _expected in cases:
                    func(c)
        expected = [(b"AUTH", b"op", b"pw")] + [e for _, e in cases]
        self.assertEqual(srv.commands, expected)
        self.assertEqual(srv.mismatches, [])


class TestWatchSemantics(unittest.TestCase):
    EVENT_5 = b"*4\r\n:5\r\n$3\r\nevt\r\n$4\r\nvm-1\r\n$2\r\n{}\r\n"
    EVENT_6 = b"*4\r\n:6\r\n$3\r\nevt\r\n$4\r\nvm-1\r\n$2\r\n[]\r\n"

    def test_cursor_lifecycle(self):
        with mock_server([
            ((b"FEDERATION", b"WATCH.OPEN", b"vm-1"), b":1\r\n"),
            ((b"FEDERATION", b"WATCH.NEXT", b"1"), self.EVENT_5),
            ((b"FEDERATION", b"WATCH.NEXT", b"1"), b":0\r\n"),
            ((b"FEDERATION", b"WATCH.ACK", b"1", b"5"), b"+OK\r\n"),
            ((b"FEDERATION", b"WATCH.RESUME", b"1", b"0"), b"+OK\r\n"),
            ((b"FEDERATION", b"WATCH.NEXT", b"1"), self.EVENT_5),
        ]) as srv:
            with ctrl.Controller("127.0.0.1", srv.port) as c:
                watch = c.watch_open("vm-1")
                self.assertEqual(watch.watch_id, 1)
                self.assertIsNone(watch.last_delivered)
                # Nothing delivered yet -> ack refuses rather than guess.
                with self.assertRaises(ctrl.ControllerUsageError):
                    watch.ack()

                event = watch.event()
                self.assertEqual(event, (5, b"evt", b"vm-1", b"{}"))
                self.assertEqual(watch.last_delivered, 5)

                self.assertIsNone(watch.event())            # journal end
                self.assertEqual(watch.last_delivered, 5)   # cursor kept

                self.assertTrue(watch.ack().is_ok())        # acks offset 5
                self.assertEqual(watch.last_acked, 5)

                # Rewind for a second pass: the ack watermark is NOT
                # lowered (server watermark is monotonic; reconnects
                # resume from last_acked, not from a read rewind).
                self.assertTrue(watch.resume(0).is_ok())
                self.assertEqual(watch.last_acked, 5)
                self.assertEqual(watch.event(), (5, b"evt", b"vm-1", b"{}"))
        self.assertEqual(srv.mismatches, [])

    def test_watch_open_all_events_omits_prefix_argument(self):
        with mock_server([
            ((b"FEDERATION", b"WATCH.OPEN"), b":7\r\n"),
        ]) as srv:
            with ctrl.Controller("127.0.0.1", srv.port) as c:
                watch = c.watch_open()
                self.assertEqual(watch.watch_id, 7)
        self.assertEqual(srv.commands, [(b"FEDERATION", b"WATCH.OPEN")])

    def test_reconnect_reopens_and_resumes_from_acked_cursor(self):
        script = [
            # session 1: auth, open watch slot 1, deliver event@5, ack it
            AUTH_OK,
            ((b"FEDERATION", b"WATCH.OPEN", b"vm-1"), b":1\r\n"),
            ((b"FEDERATION", b"WATCH.NEXT", b"1"), self.EVENT_5),
            ((b"FEDERATION", b"WATCH.ACK", b"1", b"5"), b"+OK\r\n"),
            # session 2 (after reconnect): same principal re-authenticated,
            # watch re-opened into a NEW slot, resumed at the acked cursor,
            # delivery continues from there.
            AUTH_OK,
            ((b"FEDERATION", b"WATCH.OPEN", b"vm-1"), b":2\r\n"),
            ((b"FEDERATION", b"WATCH.RESUME", b"2", b"5"), b"+OK\r\n"),
            ((b"FEDERATION", b"WATCH.NEXT", b"2"), self.EVENT_6),
        ]
        with mock_server(script) as srv:
            c = ctrl.Controller("127.0.0.1", srv.port,
                                username="op", password="pw")
            try:
                watch = c.watch_open("vm-1")
                self.assertEqual(watch.event(), (5, b"evt", b"vm-1", b"{}"))
                watch.ack()
                c.reconnect()
                self.assertTrue(c.connected)
                self.assertEqual(watch.watch_id, 2)   # new session slot
                self.assertEqual(watch.event(), (6, b"evt", b"vm-1", b"[]"))
            finally:
                c.close()
        self.assertEqual(srv.mismatches, [])
# ─────────────────────────────────────────────────────────────────────────
# 4. E2E against the REAL federation RESP server, with the invariant-3
#    negatives from tests/test_controller_api.c
# ─────────────────────────────────────────────────────────────────────────
#
# Isolation: the server (and the auth bootstrap it needs) runs in a
# FORKED CHILD PROCESS, exactly like the C test binary gets its own
# process.  This is not just hygiene: qihse_kv_store_create() caches
# QIHSE_DATA_DIR in a library static and qihse_auth_init() wipes the
# process-global user table, so an in-process server would poison every
# later test in the same pytest run.  The parent speaks pure RESP over
# the loopback socket — which is the point: the SDK is a protocol client
# and all enforcement is server-side.

_OPERATOR_PASSWORD = "PyCtrlSdkPass1!"     # >= 12 chars, like the C test
_GUEST_PASSWORD = "PyCtrlGuest1!"

# ctypes mirror of qihse_resp_server_config_t (field order is
# ABI-significant).  Before the struct is ever handed to the library, an
# ABI probe compiled from the repo headers verifies the size and every
# field offset — a stale libqihse.so can never be fed a mismatched layout.
_RESP_CONFIG_FIELDS = [
    ("store", ctypes.c_void_p),
    ("vdb", ctypes.c_void_p),
    ("tsdb", ctypes.c_void_p),
    ("column_store", ctypes.c_void_p),
    ("fts", ctypes.c_void_p),
    ("topology", ctypes.c_void_p),
    ("bind_address", ctypes.c_char_p),
    ("advertise_address", ctypes.c_char_p),
    ("node_id", ctypes.c_char_p),
    ("port", ctypes.c_uint16),
    ("bus_port", ctypes.c_uint16),
    ("local_node_index", ctypes.c_uint16),
    ("max_clients", ctypes.c_size_t),
    ("max_request_bytes", ctypes.c_size_t),
    ("auth_required", ctypes.c_bool),
    ("require_full_coverage", ctypes.c_bool),
    ("pin_workers", ctypes.c_bool),
    ("strict_hardware_affinity", ctypes.c_bool),
    ("numa_node_id", ctypes.c_int),
    ("enable_bus", ctypes.c_bool),
    ("enable_failover", ctypes.c_bool),
    ("enable_guard_throttle", ctypes.c_bool),
    ("xdp_interface", ctypes.c_char_p),
    ("veil_key", ctypes.c_char_p),
    ("guard_window_ms", ctypes.c_uint64),
    ("guard_saturation_fraction", ctypes.c_double),
    ("enable_scatter", ctypes.c_bool),
    ("scatter_timeout_ms", ctypes.c_uint32),
    ("enable_task_queue", ctypes.c_bool),
    ("enable_task_workers", ctypes.c_bool),
    ("task_worker_count", ctypes.c_uint32),
    ("task_python_binary", ctypes.c_char_p),
    ("enable_task_scheduler", ctypes.c_bool),
    ("task_queue", ctypes.c_void_p),
    ("task_workers", ctypes.c_void_p),
    ("task_scheduler", ctypes.c_void_p),
    ("pubsub_log_directory", ctypes.c_char_p),
    ("channel_classification", ctypes.c_uint16),
    ("channel_sci", ctypes.c_uint16),
    ("federation_journal_directory", ctypes.c_char_p),
    ("federation_journal_durability", ctypes.c_int),
    ("federation_key_directory", ctypes.c_char_p),
    ("enable_uwp_bridge", ctypes.c_bool),
    ("enable_fabric_dispatch", ctypes.c_bool),
    ("fabric_dispatch_bind", ctypes.c_char_p),
    ("fabric_dispatch_port", ctypes.c_uint16),
    ("fabric_dispatch_ca_cert_path", ctypes.c_char_p),
    ("fabric_dispatch_node_cert_path", ctypes.c_char_p),
    ("fabric_dispatch_node_id", ctypes.c_char_p),
    ("quotas", ctypes.c_void_p),
    ("blobs", ctypes.c_void_p),
    ("bundle_keys_dir", ctypes.c_char_p),
    ("bundle_dsa_private_key_path", ctypes.c_char_p),
    ("enable_killswitch_channel", ctypes.c_bool),
    ("kv_sweep_interval_seconds", ctypes.c_uint32),
    ("cluster_migrate_password", ctypes.c_char_p),
    ("redundancy_peer", ctypes.c_char_p),
]

_ABI_PROBE_C = """
#include <stdio.h>
#include <stddef.h>
#include "qihse_resp_wire.h"
int main(void) {
    printf("sizeof %zu\\n", sizeof(qihse_resp_server_config_t));
#define F(f) printf("%s %zu\\n", #f, offsetof(qihse_resp_server_config_t, f));
    F(store) F(vdb) F(tsdb) F(column_store) F(fts) F(topology)
    F(bind_address) F(advertise_address) F(node_id) F(port) F(bus_port)
    F(local_node_index) F(max_clients) F(max_request_bytes) F(auth_required)
    F(require_full_coverage) F(pin_workers) F(strict_hardware_affinity)
    F(numa_node_id) F(enable_bus) F(enable_failover) F(enable_guard_throttle)
    F(xdp_interface) F(veil_key) F(guard_window_ms) F(guard_saturation_fraction)
    F(enable_scatter) F(scatter_timeout_ms) F(enable_task_queue)
    F(enable_task_workers) F(task_worker_count) F(task_python_binary)
    F(enable_task_scheduler) F(task_queue) F(task_workers) F(task_scheduler)
    F(pubsub_log_directory) F(channel_classification) F(channel_sci)
    F(federation_journal_directory) F(federation_journal_durability)
    F(federation_key_directory) F(enable_uwp_bridge) F(enable_fabric_dispatch)
    F(fabric_dispatch_bind) F(fabric_dispatch_port) F(fabric_dispatch_ca_cert_path)
    F(fabric_dispatch_node_cert_path) F(fabric_dispatch_node_id) F(quotas)
    F(blobs) F(bundle_keys_dir) F(bundle_dsa_private_key_path)
    F(enable_killswitch_channel) F(kv_sweep_interval_seconds)
    F(cluster_migrate_password) F(redundancy_peer)
    return 0;
}
"""


def _free_tcp_port() -> int:
    """Ephemeral loopback port (mirrors free_tcp_port() in the C test)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _find_c_compiler():
    for candidate in ("cc", "gcc", "clang"):
        path = shutil.which(candidate)
        if path:
            return path
    return None


def _run_server_child(status_fd, tmp_dir: str) -> None:
    """Child-process body: build and run the auth-required RESP server.

    Mirrors tests/test_controller_api.c main() — operator bootstrap, a
    low-clearance tenant guest, a KV store, and a RESP server with a
    federation journal — then reports the port to the parent over
    ``status_fd`` (stdout when spawned) and serves until killed.  Never
    returns; reports failures as an ``ERROR ...`` status line.
    """
    import select as _select

    journal_dir = os.path.join(tmp_dir, "journal")
    os.makedirs(journal_dir, exist_ok=True)
    os.environ["QIHSE_DATA_DIR"] = tmp_dir

    try:
        from qihse import core as qihse_core  # noqa: PLC0415
        lib = qihse_core._lib

        struct_cls = type(
            "RespServerConfig", (ctypes.Structure,),
            {"_fields_": _RESP_CONFIG_FIELDS})

        lib.qihse_kv_store_create.argtypes = []
        lib.qihse_kv_store_create.restype = ctypes.c_void_p
        lib.qihse_kv_store_destroy.argtypes = [ctypes.c_void_p]
        lib.qihse_kv_store_destroy.restype = None
        lib.qihse_cluster_node_id_from_seed.argtypes = [
            ctypes.c_void_p, ctypes.c_size_t, ctypes.c_char_p]
        lib.qihse_resp_server_config_init.argtypes = [
            ctypes.POINTER(struct_cls)]
        lib.qihse_resp_server_config_init.restype = None
        lib.qihse_resp_server_create.argtypes = [ctypes.POINTER(struct_cls)]
        lib.qihse_resp_server_create.restype = ctypes.c_void_p
        lib.qihse_resp_server_start.argtypes = [ctypes.c_void_p]
        lib.qihse_resp_server_start.restype = ctypes.c_bool
        lib.qihse_auth_create_tenant_user.argtypes = [
            ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint16,
            ctypes.c_uint16, ctypes.c_uint16, ctypes.c_char_p, ctypes.c_bool]
        lib.qihse_auth_create_tenant_user.restype = ctypes.c_void_p

        # Operator principal — the C test's bootstrap pattern.
        if not lib.qihse_auth_bootstrap_operator(_OPERATOR_PASSWORD.encode()):
            os.environ["QIHSE_OPERATOR_PASSWORD"] = _OPERATOR_PASSWORD
            if not lib.qihse_auth_init():
                raise RuntimeError("qihse_auth_init() failed (FIPS?)")
        op = lib.qihse_auth_get_user(0)
        if not op:
            raise RuntimeError("operator principal missing after bootstrap")

        # Low-clearance tenant guest (QIHSE_ROLE_GUEST=2, unclassified
        # only), created by the operator — never above its own level.
        if not lib.qihse_auth_create_tenant_user(
                op, 42, 109, 2, 0, 0, _GUEST_PASSWORD.encode(), False):
            raise RuntimeError("qihse_auth_create_tenant_user() failed")

        store = lib.qihse_kv_store_create()
        if not store:
            raise RuntimeError("qihse_kv_store_create() failed")

        node_id_buf = ctypes.create_string_buffer(41)
        seed = b"py-ctrl-sdk-e2e-node"
        lib.qihse_cluster_node_id_from_seed(seed, len(seed), node_id_buf)

        config = struct_cls()
        lib.qihse_resp_server_config_init(ctypes.byref(config))
        config.store = store
        config.node_id = node_id_buf.value
        config.bind_address = b"127.0.0.1"
        config.advertise_address = b"127.0.0.1"
        port = _free_tcp_port()
        config.port = port
        config.bus_port = _free_tcp_port()
        config.enable_bus = False
        config.enable_failover = False
        config.auth_required = True          # the invariant under test
        config.federation_journal_directory = journal_dir.encode()

        server = lib.qihse_resp_server_create(ctypes.byref(config))
        if not server:
            raise RuntimeError("qihse_resp_server_create() failed")
        if not lib.qihse_resp_server_start(server):
            raise RuntimeError("qihse_resp_server_start() failed")
    except Exception as exc:  # report and die — parent turns this into a skip
        try:
            os.write(status_fd, f"ERROR {type(exc).__name__}: {exc}\n".encode())
        except OSError:
            pass
        os._exit(1)

    # Report readiness, silence C-level stdout noise, serve until killed.
    try:
        os.write(status_fd, f"PORT {port}\n".encode())
    except OSError:
        os._exit(1)
    devnull = os.open(os.devnull, os.O_WRONLY)
    os.dup2(devnull, 1)
    os.dup2(devnull, 2)
    while True:
        try:
            _select.select([], [], [], 0.5)
        except (OSError, ValueError):
            os._exit(0)


class TestControllerE2E(unittest.TestCase):
    """The Python SDK against the REAL federation RESP server (spawned
    child process, loopback-only), including the invariant-3
    authorization negatives mirrored from tests/test_controller_api.c."""

    server_port = None

    @classmethod
    def setUpClass(cls):
        import select as _select

        if not hasattr(_select, "select"):
            raise unittest.SkipTest(
                "select.select unavailable; cannot supervise the server child")
        if not (REPO_ROOT / "libqihse.so").exists():
            raise unittest.SkipTest(
                "libqihse.so is not built (run `make lib`); the e2e layer "
                "needs the real RESP server")
        compiler = _find_c_compiler()
        if compiler is None:
            raise unittest.SkipTest(
                "no C compiler (cc/gcc/clang) found for the RESP-config ABI "
                "probe; refusing to feed a ctypes struct mirror to "
                "libqihse.so without verifying its layout")

        # ABI probe in the PARENT: compile from the repo headers and
        # verify the ctypes mirror matches every field offset.
        cls._tmp = tempfile.mkdtemp(prefix="qihse_py_ctrl_sdk_")
        probe_src = os.path.join(cls._tmp, "abi_probe.c")
        probe_bin = os.path.join(cls._tmp, "abi_probe")
        with open(probe_src, "w") as fh:
            fh.write(_ABI_PROBE_C)
        try:
            subprocess.run(
                [compiler, "-I", str(REPO_ROOT / "include"), probe_src,
                 "-o", probe_bin],
                check=True, capture_output=True, timeout=60)
            probe_out = subprocess.run(
                [probe_bin], check=True, capture_output=True,
                timeout=30).stdout.decode()
        except (subprocess.SubprocessError, OSError) as exc:
            cls._cleanup_tmp()
            raise unittest.SkipTest(
                f"ABI probe failed ({exc}); cannot verify "
                "qihse_resp_server_config_t layout") from exc

        struct_cls = type(
            "RespServerConfig", (ctypes.Structure,),
            {"_fields_": _RESP_CONFIG_FIELDS})
        layout = {}
        for line in probe_out.splitlines():
            name, _, value = line.partition(" ")
            layout[name.strip()] = int(value)
        mismatches = [
            f"{name}: ctypes={getattr(struct_cls, name).offset} c={offset}"
            for name, offset in layout.items()
            if name != "sizeof"
            and getattr(struct_cls, name).offset != offset
        ]
        if ctypes.sizeof(struct_cls) != layout.get("sizeof"):
            mismatches.append(
                f"sizeof: ctypes={ctypes.sizeof(struct_cls)} "
                f"c={layout.get('sizeof')}")
        if mismatches:
            cls._cleanup_tmp()
            raise unittest.SkipTest(
                "libqihse.so ABI does not match the repo headers "
                f"({'; '.join(mismatches)}); rebuild the library")

        # Spawn the server child (fork+exec via subprocess): the auth
        # bootstrap and the server's process-global library state live in
        # a pristine interpreter, never in this pytest process.
        child_code = (
            "import sys\n"
            f"sys.path.insert(0, {str(PY_PKG_DIR)!r})\n"
            "from tests.test_controller_sdk import _run_server_child\n"
            f"_run_server_child(1, {cls._tmp!r})\n"
        )
        child_env = dict(os.environ)
        child_env["QIHSE_DATA_DIR"] = cls._tmp
        cls._child = subprocess.Popen(
            [sys.executable, "-c", child_code],
            env=child_env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        status = b""
        deadline = time.monotonic() + 30.0
        try:
            while b"\n" not in status and time.monotonic() < deadline:
                ready, _, _ = _select.select([cls._child.stdout], [], [], 1.0)
                if not ready:
                    if cls._child.poll() is not None:
                        break
                    continue
                chunk = os.read(cls._child.stdout.fileno(), 4096)
                if not chunk:
                    break
                status += chunk
        finally:
            # The child silences its own stdout after the status line;
            # keep the pipe open (the child holds it) — nothing more to
            # read here.
            pass
        line = status.decode(errors="replace").strip()
        if line.startswith("ERROR"):
            cls._reap_child()
            cls._cleanup_tmp()
            raise unittest.SkipTest(f"e2e server child failed: {line[6:]}")
        if not line.startswith("PORT"):
            stderr_tail = cls._reap_child()
            cls._cleanup_tmp()
            raise unittest.SkipTest(
                f"e2e server child did not report a port ({line!r}); "
                f"stderr tail: {stderr_tail!r}")
        cls.server_port = int(line.split()[1])

        # Wait until the listener actually accepts (threads are up).
        deadline = time.monotonic() + 10.0
        while time.monotonic() < deadline:
            try:
                probe = socket.create_connection(
                    ("127.0.0.1", cls.server_port), timeout=0.5)
                probe.close()
                break
            except OSError:
                time.sleep(0.1)
        else:
            cls._reap_child()
            cls._cleanup_tmp()
            raise unittest.SkipTest("RESP server did not start listening")

    @classmethod
    def _reap_child(cls):
        """Terminate the server child; return a tail of its stderr (if
        any) for skip diagnostics."""
        child = getattr(cls, "_child", None)
        if child is None:
            return ""
        stderr_tail = ""
        try:
            child.terminate()
            child.wait(timeout=10)
        except (OSError, subprocess.SubprocessError):
            try:
                child.kill()
                child.wait(timeout=5)
            except (OSError, subprocess.SubprocessError):
                pass
        if child.stderr is not None:
            try:
                stderr_tail = child.stderr.read(4096).decode(
                    errors="replace")[-500:]
            except (OSError, ValueError):
                pass
        cls._child = None
        return stderr_tail

    @classmethod
    def _cleanup_tmp(cls):
        tmp = getattr(cls, "_tmp", None)
        if tmp:
            shutil.rmtree(tmp, ignore_errors=True)
            cls._tmp = None

    @classmethod
    def tearDownClass(cls):
        cls._reap_child()
        cls._cleanup_tmp()

    def setUp(self):
        if self.server_port is None:
            self.skipTest("e2e server not started")
        self.operator = ctrl.Controller(
            "127.0.0.1", self.server_port,
            username="GODMODE_OP", password=_OPERATOR_PASSWORD)
        self.addCleanup(self._close, self.operator)
        # Order independence for the negatives: make sure the protected
        # namespace/object exist BEFORE any low-clearance attempt, so
        # "refused" also proves "no data disclosed", not "nothing there".
        try:
            self.operator.ns_register("py-ctl-ns", "LOCAL")
        except ctrl.ControllerServerError:
            pass  # already registered by an earlier test in this class
        reply = self.operator.object_cas(
            "py-ctl-ns", "workload/vm-secret/desired", b"running", 0)
        if reply.kind == "int" and reply.value == 0:
            # Exists from an earlier test: refresh the value at its
            # current generation so the secret is deterministic.
            gen, _ = self.operator.object_get(
                "py-ctl-ns", "workload/vm-secret/desired")
            self.operator.object_cas(
                "py-ctl-ns", "workload/vm-secret/desired", b"running",
                gen.as_int())

    @staticmethod
    def _close(client):
        try:
            client.close()
        except Exception:
            pass

    # ── happy path (mirrors the C test sections) ─────────────────────

    def test_operator_round_trip(self):
        c = self.operator
        self.assertTrue(c.connected)

        status = c.federation_status()
        self.assertEqual(status.kind, "bulk")
        self.assertGreater(len(status.as_bytes()), 0)

        self.assertTrue(c.ns_register("py-ctl-ns2", "LOCAL").is_ok())
        self.assertEqual(c.ns_writable("py-ctl-ns2").as_int(), 1)

        epoch = c.epoch_next().as_int()
        self.assertGreaterEqual(epoch, 1)

        # Object CAS: create, read back, stale generation refused.
        self.assertEqual(
            c.object_cas("py-ctl-ns2", "workload/vm-1/desired",
                         b"running", 0).as_int(), 1)
        gen, value = c.object_get("py-ctl-ns2", "workload/vm-1/desired")
        self.assertEqual(gen.as_int(), 1)
        self.assertEqual(value.as_bytes(), b"running")
        self.assertEqual(
            c.object_cas("py-ctl-ns2", "workload/vm-1/desired",
                         b"stopped", 7).as_int(), 0)   # stale generation

        # Lease lifecycle.
        lease_id = c.lease_acquire("py-ctl-ns2", "vm-1", epoch, 60000).as_text()
        self.assertTrue(lease_id)
        record = c.lease_read(lease_id)
        self.assertEqual(len(record), 5)
        self.assertEqual(record[0].as_bytes(), b"vm-1")
        self.assertTrue(c.lease_renew(lease_id, 120000).is_ok())
        self.assertTrue(c.lease_release(lease_id).is_ok())

        # Event journal + resumable watch (stateful cursor handling).
        offset = c.event_append(
            "workload.observed.running", "vm-1", b'{"domain_id":7}').as_int()
        self.assertGreater(offset, 0)

        watch = c.watch_open("vm-1")
        event = watch.event()
        self.assertIsNotNone(event)
        seen_off, etype, rid, payload = event
        # NOTE: EVENT.APPEND replies with record_offset+1 (the event
        # stream's non-zero success convention), while WATCH.NEXT reports
        # the record's own byte offset — assert on the event identity.
        self.assertEqual(etype, b"workload.observed.running")
        self.assertEqual(rid, b"vm-1")
        self.assertEqual(payload, b'{"domain_id":7}')
        self.assertTrue(watch.ack().is_ok())
        # Resume rewinds: the same event is delivered again (at-least-once).
        self.assertTrue(watch.resume(0).is_ok())
        again = watch.event()
        self.assertEqual(again[1:], (etype, rid, payload))

        replay = c.event_replay(0)
        self.assertEqual(replay.kind, "array")
        self.assertGreaterEqual(len(replay), 3)  # one event = a 3-item triple

        # Groups / conflicts / nodes / metrics / posture.
        self.assertTrue(c.group_create("py-core-security", "QUORUM").is_ok())
        self.assertEqual(c.group_list().kind, "array")
        self.assertEqual(c.conflict_list().kind, "array")
        self.assertEqual(c.node_list().kind, "array")
        self.assertGreater(len(c.metrics().as_bytes()), 0)
        self.assertEqual(len(c.security_observe()), 9)

    def test_reconnect_resumes_watch_on_real_server(self):
        c = self.operator
        c.event_append("workload.observed.running", "vm-2", b"p1")
        watch = c.watch_open("vm-2")
        event = watch.event()
        self.assertIsNotNone(event)
        first_offset = event[0]
        watch.ack()                       # watermark at the delivered record
        c.reconnect()
        self.assertTrue(c.connected)
        # New session slot, resumed at the acked cursor.  The server
        # iterates FROM that byte offset, so the acked record is
        # re-delivered (at-least-once) before anything newer.
        redelivered = watch.event()
        self.assertIsNotNone(redelivered)
        self.assertEqual(redelivered[0], first_offset)
        self.assertEqual(redelivered[3], b"p1")
        # Delivery then continues past the acked point.
        c.event_append("workload.observed.running", "vm-2", b"p2")
        nxt = watch.event()
        self.assertIsNotNone(nxt)
        self.assertGreater(nxt[0], first_offset)
        self.assertEqual(nxt[3], b"p2")

    # ── invariant-3 negatives (mirror tests/test_controller_api.c) ────

    def test_unauthenticated_principal_refused_no_data(self):
        unauth = ctrl.Controller("127.0.0.1", self.server_port)
        self.addCleanup(self._close, unauth)
        self.assertTrue(unauth.connected)   # TCP ok — authority is NOT ours

        for attempt in (
            unauth.federation_status,
            lambda: unauth.object_get("py-ctl-ns", "workload/vm-secret/desired"),
            lambda: unauth.lease_acquire("py-ctl-ns", "vm-9", 1),
        ):
            with self.assertRaises(ctrl.ControllerServerError) as ctx:
                attempt()
            self.assertIn(ctx.exception.error_class, ("NOAUTH", "NOPERM"))
            # No protected payload rides along in the refusal.
            self.assertNotIn("running", ctx.exception.message)
            self.assertNotIn("py-ctl-ns", ctx.exception.message)

    def test_low_clearance_guest_refused_no_data(self):
        guest = ctrl.Controller(
            "127.0.0.1", self.server_port,
            username="User_109", password=_GUEST_PASSWORD)
        self.addCleanup(self._close, guest)
        self.assertTrue(guest.connected)   # AUTH succeeded — still no data

        with self.assertRaises(ctrl.ControllerServerError) as ctx:
            guest.federation_status()
        self.assertEqual(ctx.exception.error_class, "NOPERM")

        with self.assertRaises(ctrl.ControllerServerError) as ctx:
            guest.lease_acquire("py-ctl-ns", "vm-1", 1, 60000)
        self.assertEqual(ctx.exception.error_class, "NOPERM")

        with self.assertRaises(ctrl.ControllerServerError) as ctx:
            guest.watch_open(None)
        self.assertEqual(ctx.exception.error_class, "NOPERM")

        with self.assertRaises(ctrl.ControllerServerError) as ctx:
            guest.object_get("py-ctl-ns", "workload/vm-secret/desired")
        self.assertNotIn("running", ctx.exception.message)
        self.assertNotIn("py-ctl-ns", ctx.exception.message)


if __name__ == "__main__":
    unittest.main()
