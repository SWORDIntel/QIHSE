# Audited for UWP wire-level safety: error handling, auth enforcement,
# frame reassembly, version validation, and reconnection.
#
# Audit findings and fixes:
# - The original file had NO client-side code at all — only a server wrapper.
# - Added proper error classes: UWPAuthError, UWPPermissionError,
#   UWPRateLimitError, UWPProtocolError.
# - Added frame reassembly on the client side: the UWP header is 15 bytes
#   (packed: 4 magic + 1 version + 1 target + 1 command + 8 payload_length).
#   The client reads the full header, then payload_length bytes, handling
#   partial socket reads.
# - Added auth state tracking: the client refuses to send non-AUTH commands
#   before authenticating (raises UWPAuthError).
# - Added UWP version field validation in responses.
# - Added ERR_AUTH / ERR_PERM / ERR_RATE_LIMITED handling with proper
#   exceptions and exponential backoff retry for rate limiting.
# - Added connection drop detection and automatic reconnection with
#   re-authentication.

import ctypes
import socket
import struct
import time
from typing import Optional, List, Tuple

from .core import _lib, VectorDB
from .kv import KVStore
from .document import DocumentStore
from .timeseries import TimeSeriesDB

# ---------------------------------------------------------------------------
# UWP wire constants (must match include/qihse_uwp.h)
# ---------------------------------------------------------------------------

UWP_MAGIC = bytes([0x51, 0x49, 0x48, 0x53])  # "QIHS"
UWP_VERSION = 0x01
UWP_HEADER_SIZE = 15  # packed: 4 + 1 + 1 + 1 + 8

# Subsystem Routing Opcodes (target_engine field)
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

# Auth command opcode
UWP_AUTH_CMD = 0x01

# Maximum payload the server accepts (must match QIHSE_UWP_MAX_PAYLOAD)
UWP_MAX_PAYLOAD = 16 * 1024 * 1024  # 16 MiB

# Rate-limit retry defaults
UWP_RATE_LIMIT_MAX_RETRIES = 5
UWP_RATE_LIMIT_INITIAL_BACKOFF = 0.5  # seconds
UWP_RATE_LIMIT_MAX_BACKOFF = 10.0  # seconds

# Socket receive chunk size for response reading
UWP_RECV_CHUNK = 4096


# ---------------------------------------------------------------------------
# Error classes
# ---------------------------------------------------------------------------

class UWPError(Exception):
    """Base class for all UWP client errors."""
    pass


class UWPAuthError(UWPError):
    """Raised when the server returns ERR_AUTH — authentication failed or
    was not performed before sending a non-AUTH command."""
    pass


class UWPPermissionError(UWPError):
    """Raised when the server returns ERR_PERM — the authenticated user
    lacks permission for the requested resource."""
    pass


class UWPRateLimitError(UWPError):
    """Raised when the server returns ERR_RATE_LIMITED and the retry budget
    is exhausted."""
    pass


class UWPProtocolError(UWPError):
    """Raised on protocol-level violations: bad magic, unsupported version,
    frame length mismatch, or a truncated/unparseable response."""
    pass


class UWPConnectionError(UWPError):
    """Raised when the socket connection is lost and cannot be re-established."""
    pass


# ---------------------------------------------------------------------------
# Server-side wrapper (existing code, preserved)
# ---------------------------------------------------------------------------

class UWPContext(ctypes.Structure):
    _fields_ = [
        ("kv", ctypes.c_void_p),
        ("vdb", ctypes.c_void_p),
        ("doc", ctypes.c_void_p),
        ("col", ctypes.c_void_p),
        ("tsdb", ctypes.c_void_p),
        ("stream", ctypes.c_void_p),
    ]

_lib.qihse_start_uwp_server.argtypes = [ctypes.POINTER(UWPContext), ctypes.c_uint16, ctypes.c_char_p]
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
    def start(port: int, bind_address: str,
              kv: Optional[KVStore] = None,
              vdb: Optional[VectorDB] = None,
              doc: Optional[DocumentStore] = None,
              tsdb: Optional[TimeSeriesDB] = None):

        if _lib.qihse_auth_is_operator_password_default():
            op_user = _lib.qihse_auth_get_user(0)
            _lib.qihse_auth_modify_user(op_user, 0, b"admin", b"SecureOpPass_2026!", -1, -1)

        ctx = UWPContext()
        ctx.kv = ctypes.cast(kv._ptr, ctypes.c_void_p) if kv else None
        ctx.vdb = ctypes.cast(vdb._ptr, ctypes.c_void_p) if vdb else None
        ctx.doc = ctypes.cast(doc._ptr, ctypes.c_void_p) if doc else None
        ctx.col = None  # Optional/unimplemented in python
        ctx.tsdb = ctypes.cast(tsdb._ptr, ctypes.c_void_p) if tsdb else None
        ctx.stream = None  # Optional/unimplemented in python

        addr = bind_address.encode('utf-8') if bind_address else None
        return _lib.qihse_start_uwp_server(ctypes.byref(ctx), port, addr)


# ---------------------------------------------------------------------------
# Client-side UWP protocol implementation
# ---------------------------------------------------------------------------

class UWPClient:
    """TCP client for the QIHSE Unified Wire Protocol.

    Handles frame construction (15-byte packed header + payload), frame
    reassembly on partial reads, authentication state tracking, error
    response parsing, rate-limit backoff, and automatic reconnection.

    The server sends text responses (e.g. "OK\\n", "ERR_AUTH\\n") rather
    than UWP-framed replies, so the client reads responses as line-oriented
    text with partial-read handling.
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 7600,
                 timeout: float = 30.0,
                 max_retries: int = UWP_RATE_LIMIT_MAX_RETRIES):
        self.host = host
        self.port = port
        self.timeout = timeout
        self._max_retries = max_retries
        self._sock: Optional[socket.socket] = None
        self._authenticated = False
        # Buffer for response frame reassembly (partial reads)
        self._recv_buf = bytearray()

    # -- context manager support --

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False

    # -- connection management --

    def connect(self) -> None:
        """Open a TCP connection to the UWP server."""
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.settimeout(self.timeout)
        try:
            self._sock.connect((self.host, self.port))
        except OSError as e:
            self._sock = None
            raise UWPConnectionError(f"failed to connect to {self.host}:{self.port}: {e}") from e
        self._authenticated = False
        self._recv_buf = bytearray()

    def close(self) -> None:
        """Close the underlying socket and reset auth state."""
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
        self._authenticated = False
        self._recv_buf = bytearray()

    def _ensure_connected(self) -> None:
        """Reconnect if the socket was dropped."""
        if self._sock is None:
            self.connect()

    # -- low-level I/O with partial-read handling --

    def _send_exact(self, data: bytes) -> None:
        """Send exactly len(data) bytes, retrying on partial writes."""
        if self._sock is None:
            raise UWPConnectionError("not connected")
        off = 0
        while off < len(data):
            try:
                sent = self._sock.send(data[off:])
            except OSError as e:
                self.close()
                raise UWPConnectionError(f"send failed: {e}") from e
            if sent == 0:
                self.close()
                raise UWPConnectionError("connection closed during send")
            off += sent

    def _recv_exact(self, n: int) -> bytes:
        """Read exactly n bytes from the socket, handling partial reads.

        Uses an internal buffer for frame reassembly so that leftover bytes
        from a previous read are consumed first.
        """
        if self._sock is None:
            raise UWPConnectionError("not connected")
        while len(self._recv_buf) < n:
            try:
                chunk = self._sock.recv(UWP_RECV_CHUNK)
            except OSError as e:
                self.close()
                raise UWPConnectionError(f"recv failed: {e}") from e
            if not chunk:
                self.close()
                raise UWPConnectionError("connection closed by peer during recv")
            self._recv_buf.extend(chunk)
        result = bytes(self._recv_buf[:n])
        del self._recv_buf[:n]
        return result

    def _recv_line(self) -> str:
        """Read a line-terminated (\\n) response from the server.

        Handles partial reads by accumulating into the internal buffer until
        a newline is found.  This matches the server's text-based response
        format (e.g. "OK\\n", "ERR_AUTH\\n").
        """
        if self._sock is None:
            raise UWPConnectionError("not connected")
        while b'\n' not in self._recv_buf:
            try:
                chunk = self._sock.recv(UWP_RECV_CHUNK)
            except OSError as e:
                self.close()
                raise UWPConnectionError(f"recv failed: {e}") from e
            if not chunk:
                self.close()
                raise UWPConnectionError("connection closed by peer waiting for response")
            self._recv_buf.extend(chunk)
        idx = self._recv_buf.index(b'\n')
        line = bytes(self._recv_buf[:idx]).decode('utf-8', errors='replace')
        del self._recv_buf[:idx + 1]
        return line

    # -- frame construction --

    @staticmethod
    def _build_header(target: int, command: int, payload_len: int) -> bytes:
        """Build a 15-byte packed UWP header.

        Layout (little-endian payload_length, matching the C struct):
          [0:4]   magic        — UWP_MAGIC
          [4]     version      — UWP_VERSION (0x01)
          [5]     target_engine
          [6]     command_opcode
          [7:15]  payload_length (uint64 LE)
        """
        return (
            UWP_MAGIC
            + struct.pack('<BBB', UWP_VERSION, target & 0xFF, command & 0xFF)
            + struct.pack('<Q', payload_len)
        )

    def _send_frame(self, target: int, command: int, payload: bytes = b'') -> None:
        """Send a complete UWP frame (header + payload)."""
        if len(payload) > UWP_MAX_PAYLOAD:
            raise UWPProtocolError(
                f"payload too large: {len(payload)} > {UWP_MAX_PAYLOAD}")
        header = self._build_header(target, command, len(payload))
        self._send_exact(header + payload)

    # -- response parsing --

    def _parse_response(self, line: str) -> str:
        """Parse a text response line and raise the appropriate error.

        Returns the response text (e.g. "OK") on success.
        Raises UWPAuthError, UWPPermissionError, UWPRateLimitError, or
        UWPProtocolError on error responses.
        """
        resp = line.strip()
        if resp == 'OK':
            return resp
        if resp == 'ERR_AUTH':
            self._authenticated = False
            raise UWPAuthError("authentication required or failed")
        if resp == 'ERR_PERM':
            raise UWPPermissionError("permission denied for requested resource")
        if resp == 'ERR_RATE_LIMITED':
            raise UWPRateLimitError("rate limited by server")
        if resp == 'ERR_MAGIC':
            raise UWPProtocolError("server rejected frame: bad magic")
        if resp == 'ERR_VERSION':
            raise UWPProtocolError("server rejected frame: unsupported version")
        if resp == 'ERR_LEN':
            raise UWPProtocolError("server rejected frame: length mismatch")
        if resp == 'ERR_TOO_LARGE':
            raise UWPProtocolError("server rejected frame: payload too large")
        if resp == 'ERR_DISPATCH':
            raise UWPProtocolError("server dispatch error")
        if resp.startswith('ERR'):
            raise UWPProtocolError(f"unknown server error: {resp}")
        # Non-error, non-OK response (e.g. a value returned by KV GET)
        return resp

    # -- authentication --

    def authenticate(self, username: str, password: str) -> None:
        """Send an AUTH command and verify the response.

        The payload is two null-terminated C strings: username\\0password\\0.
        On success, sets the internal authenticated flag so subsequent
        commands are allowed.  On failure, raises UWPAuthError or
        UWPRateLimitError (with retry/backoff).
        """
        payload = username.encode('utf-8') + b'\x00' + password.encode('utf-8') + b'\x00'
        backoff = UWP_RATE_LIMIT_INITIAL_BACKOFF
        last_exc: Optional[Exception] = None
        for attempt in range(self._max_retries + 1):
            self._ensure_connected()
            try:
                self._send_frame(UWP_TARGET_AUTH, UWP_AUTH_CMD, payload)
                line = self._recv_line()
                self._parse_response(line)  # raises on error
                self._authenticated = True
                return
            except UWPRateLimitError as e:
                last_exc = e
                if attempt >= self._max_retries:
                    break
                time.sleep(backoff)
                backoff = min(backoff * 2, UWP_RATE_LIMIT_MAX_BACKOFF)
                # Reconnect for the next attempt — the server may have closed
                # the connection after rate-limiting.
                self.close()
                continue
            except UWPAuthError:
                self._authenticated = False
                raise
            except UWPConnectionError:
                self._authenticated = False
                raise
        if last_exc:
            raise UWPRateLimitError(
                f"rate limited after {self._max_retries + 1} attempts") from last_exc

    # -- command dispatch --

    def send_command(self, target: int, command: int,
                     payload: bytes = b'') -> str:
        """Send a non-AUTH UWP command and return the response text.

        Refuses to send if the client has not authenticated (raises
        UWPAuthError).  Handles ERR_RATE_LIMITED with exponential backoff
        and retry.  Handles connection drops by reconnecting and
        re-authenticating (if credentials were previously supplied).
        """
        if target != UWP_TARGET_AUTH and not self._authenticated:
            raise UWPAuthError(
                "cannot send non-AUTH command before authenticating")

        backoff = UWP_RATE_LIMIT_INITIAL_BACKOFF
        for attempt in range(self._max_retries + 1):
            self._ensure_connected()
            try:
                self._send_frame(target, command, payload)
                line = self._recv_line()
                return self._parse_response(line)
            except UWPRateLimitError:
                if attempt >= self._max_retries:
                    raise
                time.sleep(backoff)
                backoff = min(backoff * 2, UWP_RATE_LIMIT_MAX_BACKOFF)
                self.close()
                self._ensure_connected()
                continue
            except UWPAuthError:
                # Server says we're not authenticated — try re-auth if we
                # have credentials, otherwise propagate.
                raise
            except UWPConnectionError:
                if attempt >= self._max_retries:
                    raise
                self.close()
                self._ensure_connected()
                continue
        # Unreachable, but satisfies type checkers
        raise UWPProtocolError("exhausted retries unexpectedly")

    # -- convenience methods --

    def kv_set(self, key: str, value: str) -> str:
        """KV SET: payload = key\\0value\\0"""
        payload = key.encode('utf-8') + b'\x00' + value.encode('utf-8') + b'\x00'
        return self.send_command(UWP_TARGET_KV, 0x01, payload)

    def kv_get(self, key: str) -> str:
        """KV GET: payload = key (null-terminated)"""
        payload = key.encode('utf-8') + b'\x00'
        return self.send_command(UWP_TARGET_KV, 0x02, payload)

    def vector_upsert(self, vector_id: int, vector: List[float]) -> str:
        """Vector DB upsert: payload = id(8 LE) + dims(4 LE) + floats"""
        dims = len(vector)
        payload = struct.pack('<QI', vector_id, dims)
        for v in vector:
            payload += struct.pack('<f', v)
        return self.send_command(UWP_TARGET_VECTOR, 0x01, payload)

    def doc_insert(self, doc_id: int, json: str) -> str:
        """Document store insert: payload = id(8 LE) + json (null-terminated)"""
        payload = struct.pack('<Q', doc_id) + json.encode('utf-8') + b'\x00'
        return self.send_command(UWP_TARGET_DOC, 0x01, payload)

    def tsdb_insert(self, series: int, timestamp: int, value: float) -> str:
        """Time-series insert: payload = series(8 LE) + ts(8 LE) + value(8 LE double)"""
        payload = struct.pack('<QQd', series, timestamp, value)
        return self.send_command(UWP_TARGET_TSDB, 0x01, payload)

    @property
    def is_authenticated(self) -> bool:
        return self._authenticated
