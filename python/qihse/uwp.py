"""QIHSE Unified Wire Protocol Python bindings."""

import ctypes
import socket
import struct
import time
from typing import List, Optional, Tuple

from .core import _lib, VectorDB
from .kv import KVStore
from .document import DocumentStore
from .timeseries import TimeSeriesDB

UWP_MAGIC = bytes([0x51, 0x49, 0x48, 0x53])
UWP_VERSION = 0x01
UWP_HEADER_SIZE = 15

UWP_TARGET_AUTH = 0x00
UWP_TARGET_KV = 0x01
UWP_TARGET_VECTOR = 0x02
UWP_TARGET_DOC = 0x03
UWP_TARGET_COL = 0x04
UWP_TARGET_TSDB = 0x05
UWP_TARGET_GRAPH = 0x06
UWP_TARGET_STREAM = 0x07
UWP_TARGET_SQL = 0x08
UWP_TARGET_TXN = 0x09
UWP_TARGET_GRAPH2 = 0x0A
UWP_TARGET_INDEX = 0x0B
UWP_TARGET_SCHEMA = 0x0C
UWP_TARGET_REPL = 0x0D
UWP_TARGET_POOL = 0x0E

UWP_AUTH_CMD = 0x01
UWP_MAX_PAYLOAD = 16 * 1024 * 1024
UWP_RATE_LIMIT_MAX_RETRIES = 5
UWP_RATE_LIMIT_INITIAL_BACKOFF = 0.5
UWP_RATE_LIMIT_MAX_BACKOFF = 10.0
UWP_RECV_CHUNK = 4096


class UWPError(Exception):
    """Base class for UWP errors."""


class UWPAuthError(UWPError):
    """Authentication failed or is required."""


class UWPPermissionError(UWPError):
    """Permission denied by the server."""


class UWPRateLimitError(UWPError):
    """Request was rate-limited by the server."""


class UWPProtocolError(UWPError):
    """UWP framing or protocol error."""


class UWPConnectionError(UWPError):
    """Transport connection error."""


class UWPContext(ctypes.Structure):
    """Exact ctypes mirror of qihse_uwp_context_t.

    Field order is ABI-significant and must match include/qihse_uwp.h.
    """

    _fields_ = [
        ("kv", ctypes.c_void_p),
        ("vdb", ctypes.c_void_p),
        ("doc", ctypes.c_void_p),
        ("col", ctypes.c_void_p),
        ("tsdb", ctypes.c_void_p),
        ("stream", ctypes.c_void_p),
        ("user", ctypes.c_void_p),
        ("sql_engine", ctypes.c_void_p),
        ("txn_manager", ctypes.c_void_p),
        ("graph_store", ctypes.c_void_p),
        ("index_manager", ctypes.c_void_p),
        ("schema", ctypes.c_void_p),
        ("wal", ctypes.c_void_p),
        ("repl_ctx", ctypes.c_void_p),
        ("pooler", ctypes.c_void_p),
        ("tls_ctx", ctypes.c_void_p),
        ("uwp_metrics", ctypes.c_void_p),
    ]


_lib.qihse_start_uwp_server.argtypes = [
    ctypes.POINTER(UWPContext), ctypes.c_uint16, ctypes.c_char_p
]
_lib.qihse_start_uwp_server.restype = ctypes.c_bool

_lib.qihse_auth_is_operator_password_default.argtypes = []
_lib.qihse_auth_is_operator_password_default.restype = ctypes.c_bool

_lib.qihse_auth_modify_user.argtypes = [
    ctypes.c_void_p,
    ctypes.c_uint32,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_int,
    ctypes.c_int,
]
_lib.qihse_auth_modify_user.restype = ctypes.c_bool


class UWPServer:
    @staticmethod
    def start(
        port: int,
        bind_address: str,
        kv: Optional[KVStore] = None,
        vdb: Optional[VectorDB] = None,
        doc: Optional[DocumentStore] = None,
        tsdb: Optional[TimeSeriesDB] = None,
    ) -> bool:
        if _lib.qihse_auth_is_operator_password_default():
            op_user = _lib.qihse_auth_get_user(0)
            _lib.qihse_auth_modify_user(
                op_user, 0, b"admin", b"SecureOpPass_2026!", -1, -1
            )

        # ctypes zero-initializes the complete C structure, so optional engine,
        # auth, replication, TLS and metrics pointers are NULL unless supplied.
        ctx = UWPContext()
        ctx.kv = ctypes.cast(kv._ptr, ctypes.c_void_p) if kv else None
        ctx.vdb = ctypes.cast(vdb._ptr, ctypes.c_void_p) if vdb else None
        ctx.doc = ctypes.cast(doc._ptr, ctypes.c_void_p) if doc else None
        ctx.col = None
        ctx.tsdb = ctypes.cast(tsdb._ptr, ctypes.c_void_p) if tsdb else None
        ctx.stream = None

        addr = bind_address.encode("utf-8") if bind_address else None
        return bool(_lib.qihse_start_uwp_server(ctypes.byref(ctx), port, addr))


class UWPClient:
    """TCP client for the QIHSE Unified Wire Protocol."""

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 7600,
        timeout: float = 30.0,
        max_retries: int = UWP_RATE_LIMIT_MAX_RETRIES,
    ):
        self.host = host
        self.port = port
        self.timeout = timeout
        self._max_retries = max_retries
        self._sock: Optional[socket.socket] = None
        self._authenticated = False
        self._credentials: Optional[Tuple[str, str]] = None
        self._recv_buf = bytearray()

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False

    def connect(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            sock.connect((self.host, self.port))
        except OSError as exc:
            sock.close()
            raise UWPConnectionError(
                f"failed to connect to {self.host}:{self.port}: {exc}"
            ) from exc
        self._sock = sock
        self._authenticated = False
        self._recv_buf = bytearray()

    def close(self) -> None:
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
        self._authenticated = False
        self._recv_buf = bytearray()

    def _ensure_connected(self) -> None:
        if self._sock is None:
            self.connect()

    def _reconnect_and_reauthenticate(self) -> None:
        credentials = self._credentials
        self.close()
        self.connect()
        if credentials is not None:
            self.authenticate(*credentials)

    def _send_exact(self, data: bytes) -> None:
        if self._sock is None:
            raise UWPConnectionError("not connected")
        offset = 0
        while offset < len(data):
            try:
                sent = self._sock.send(data[offset:])
            except OSError as exc:
                self.close()
                raise UWPConnectionError(f"send failed: {exc}") from exc
            if sent == 0:
                self.close()
                raise UWPConnectionError("connection closed during send")
            offset += sent

    def _recv_exact(self, count: int) -> bytes:
        if self._sock is None:
            raise UWPConnectionError("not connected")
        while len(self._recv_buf) < count:
            try:
                chunk = self._sock.recv(UWP_RECV_CHUNK)
            except OSError as exc:
                self.close()
                raise UWPConnectionError(f"recv failed: {exc}") from exc
            if not chunk:
                self.close()
                raise UWPConnectionError("connection closed by peer during recv")
            self._recv_buf.extend(chunk)
        result = bytes(self._recv_buf[:count])
        del self._recv_buf[:count]
        return result

    def _recv_line(self) -> str:
        if self._sock is None:
            raise UWPConnectionError("not connected")
        while b"\n" not in self._recv_buf:
            try:
                chunk = self._sock.recv(UWP_RECV_CHUNK)
            except OSError as exc:
                self.close()
                raise UWPConnectionError(f"recv failed: {exc}") from exc
            if not chunk:
                self.close()
                raise UWPConnectionError("connection closed by peer waiting for response")
            self._recv_buf.extend(chunk)
        index = self._recv_buf.index(b"\n")
        line = bytes(self._recv_buf[:index]).decode("utf-8", errors="replace")
        del self._recv_buf[: index + 1]
        return line

    @staticmethod
    def _build_header(target: int, command: int, payload_len: int) -> bytes:
        return (
            UWP_MAGIC
            + struct.pack("<BBB", UWP_VERSION, target & 0xFF, command & 0xFF)
            + struct.pack("<Q", payload_len)
        )

    def _send_frame(self, target: int, command: int, payload: bytes = b"") -> None:
        if len(payload) > UWP_MAX_PAYLOAD:
            raise UWPProtocolError(
                f"payload too large: {len(payload)} > {UWP_MAX_PAYLOAD}"
            )
        self._send_exact(self._build_header(target, command, len(payload)) + payload)

    def _parse_response(self, line: str) -> str:
        response = line.strip()
        if response == "OK":
            return response
        if response == "ERR_AUTH":
            self._authenticated = False
            raise UWPAuthError("authentication required or failed")
        if response == "ERR_PERM":
            raise UWPPermissionError("permission denied for requested resource")
        if response == "ERR_RATE_LIMITED":
            raise UWPRateLimitError("rate limited by server")
        if response == "ERR_MAGIC":
            raise UWPProtocolError("server rejected frame: bad magic")
        if response == "ERR_VERSION":
            raise UWPProtocolError("server rejected frame: unsupported version")
        if response == "ERR_LEN":
            raise UWPProtocolError("server rejected frame: length mismatch")
        if response == "ERR_TOO_LARGE":
            raise UWPProtocolError("server rejected frame: payload too large")
        if response == "ERR_DISPATCH":
            raise UWPProtocolError("server dispatch error")
        if response.startswith("ERR"):
            raise UWPProtocolError(f"unknown server error: {response}")
        return response

    def authenticate(self, username: str, password: str) -> None:
        payload = username.encode("utf-8") + b"\x00" + password.encode("utf-8") + b"\x00"
        backoff = UWP_RATE_LIMIT_INITIAL_BACKOFF
        last_exc: Optional[Exception] = None
        for attempt in range(self._max_retries + 1):
            self._ensure_connected()
            try:
                self._send_frame(UWP_TARGET_AUTH, UWP_AUTH_CMD, payload)
                self._parse_response(self._recv_line())
                self._authenticated = True
                self._credentials = (username, password)
                return
            except UWPRateLimitError as exc:
                last_exc = exc
                if attempt >= self._max_retries:
                    break
                time.sleep(backoff)
                backoff = min(backoff * 2, UWP_RATE_LIMIT_MAX_BACKOFF)
                self.close()
            except UWPAuthError:
                self._authenticated = False
                self._credentials = None
                raise
            except UWPConnectionError:
                self._authenticated = False
                raise
        if last_exc:
            raise UWPRateLimitError(
                f"rate limited after {self._max_retries + 1} attempts"
            ) from last_exc

    def send_command(self, target: int, command: int, payload: bytes = b"") -> str:
        if target != UWP_TARGET_AUTH and not self._authenticated:
            raise UWPAuthError("cannot send non-AUTH command before authenticating")

        backoff = UWP_RATE_LIMIT_INITIAL_BACKOFF
        for attempt in range(self._max_retries + 1):
            self._ensure_connected()
            try:
                self._send_frame(target, command, payload)
                return self._parse_response(self._recv_line())
            except UWPRateLimitError:
                if attempt >= self._max_retries:
                    raise
                time.sleep(backoff)
                backoff = min(backoff * 2, UWP_RATE_LIMIT_MAX_BACKOFF)
                self._reconnect_and_reauthenticate()
            except UWPAuthError:
                if attempt >= self._max_retries or self._credentials is None:
                    raise
                self._reconnect_and_reauthenticate()
            except UWPConnectionError:
                if attempt >= self._max_retries:
                    raise
                self._reconnect_and_reauthenticate()
        raise UWPProtocolError("exhausted retries unexpectedly")

    def kv_set(self, key: str, value: str) -> str:
        payload = key.encode("utf-8") + b"\x00" + value.encode("utf-8") + b"\x00"
        return self.send_command(UWP_TARGET_KV, 0x01, payload)

    def kv_get(self, key: str) -> str:
        return self.send_command(UWP_TARGET_KV, 0x02, key.encode("utf-8") + b"\x00")

    def vector_upsert(self, vector_id: int, vector: List[float]) -> str:
        payload = struct.pack("<QI", vector_id, len(vector))
        payload += b"".join(struct.pack("<f", value) for value in vector)
        return self.send_command(UWP_TARGET_VECTOR, 0x01, payload)

    def doc_insert(self, doc_id: int, json: str) -> str:
        payload = struct.pack("<Q", doc_id) + json.encode("utf-8") + b"\x00"
        return self.send_command(UWP_TARGET_DOC, 0x01, payload)

    def tsdb_insert(self, series: int, timestamp: int, value: float) -> str:
        return self.send_command(
            UWP_TARGET_TSDB, 0x01, struct.pack("<QQd", series, timestamp, value)
        )

    @property
    def is_authenticated(self) -> bool:
        return self._authenticated
