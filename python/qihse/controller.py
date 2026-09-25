"""
QIHSE controller SDK — the Python half of the CITADEL v3 §25
controller-facing client API (the C reference is include/qihse_controller.h
+ src/controller/qihse_controller.c).

A synchronous RESP client with a bounded, exact parser plus named wrappers
for the federation surface a controller actually needs: node inventory and
trust, namespaces and replication groups, object CAS, leases and epochs,
the event journal with resumable watches, conflicts, rejoin/metrics, build
coordination, supply chain, provenance, snapshots, schema evolution, and
security posture.

Authority model — this SDK CONFERS NO AUTHORITY:

    * Authentication is always explicit: a principal name and its
      credentials are passed to the constructor (or to
      :meth:`Controller.authenticate`) and are used only for that
      connection's ``AUTH`` exchange.  Nothing is read from the
      environment, a config file, or global state; there is no ambient
      identity anywhere in this module.
    * Every wrapper is a pure wire mapping.  The SERVER enforces
      authentication, the system-domain gate, scopes, classification and
      replay.  Refusals come back as typed exceptions carrying the
      server's own error class and message (e.g. ``NOAUTH``/``NOPERM``)
      and never as fabricated success.

Wire bounds — identical to the C client, so a hostile or corrupt peer
cannot turn this decoder into a memory sink:

    * bulk payloads                  <= MAX_BULK_BYTES   (16 MiB)
    * array/set/map element counts   <= MAX_ARRAY_ITEMS  (1 MiB)
    * reply nesting                  <= MAX_DEPTH        (32)
    * type/length header lines       <= MAX_LINE_BYTES   (64 KiB)

Parsing is exact, not heuristic: every value is framed by its declared
length and terminating CRLF, integers/doubles are validated before
conversion, and any deviation raises :class:`ControllerProtocolError`
and marks the connection dead (a desynchronised stream can never be
"recovered" by guessing).

RESP2 is the wire default (like the C client); pass ``protocol=3`` to
send ``HELLO 3`` — the decoder understands both regardless, including
the RESP3 extensions (null, booleans, doubles, big numbers, verbatim
strings, blob errors, maps, sets, pushes, attributes, and streamed
aggregates).
"""

from __future__ import annotations

import re
import socket

from typing import Sequence

__all__ = [
    "MAX_BULK_BYTES",
    "MAX_ARRAY_ITEMS",
    "MAX_DEPTH",
    "MAX_LINE_BYTES",
    "DEFAULT_TIMEOUT_MS",
    "Reply",
    "Watch",
    "Controller",
    "ControllerError",
    "ControllerUsageError",
    "CommandTooLargeError",
    "ControllerConnectionError",
    "ControllerTransportError",
    "ControllerTimeoutError",
    "ControllerProtocolError",
    "ControllerAuthenticationError",
    "ControllerServerError",
    "ReplyShapeError",
]

# ── Wire bounds (mirror QIHSE_CTRL_* in qihse_controller.h) ────────────────

MAX_BULK_BYTES = 16 * 1024 * 1024       # QIHSE_CTRL_MAX_BULK
MAX_ARRAY_ITEMS = 1 << 20               # QIHSE_CTRL_MAX_ITEMS
MAX_DEPTH = 32                          # QIHSE_CTRL_MAX_DEPTH
DEFAULT_TIMEOUT_MS = 5000               # QIHSE_CTRL_DEFAULT_TIMEOUT_MS

# Bound for a type/length header line ("$16777216", "-ERR ...", ...).  The
# C client caps these at 128 bytes; Python error strings can be longer, so
# we use a generous but hard cap.
MAX_LINE_BYTES = 64 * 1024

_RECV_CHUNK = 65536                     # per-recv() read size (CTRL_RX_CAP)


# ── Exceptions ─────────────────────────────────────────────────────────────

class ControllerError(Exception):
    """Base class for every error raised by this SDK."""


class ControllerUsageError(ControllerError, ValueError):
    """The caller supplied an invalid argument (bad type, negative unsigned
    field, oversized command, ...).  Nothing was sent on the wire."""


class CommandTooLargeError(ControllerUsageError):
    """The encoded command would exceed MAX_BULK_BYTES on the wire."""


class ControllerConnectionError(ControllerError):
    """The TCP connection could not be established."""


class ControllerTransportError(ControllerError):
    """I/O failure on an established connection (peer reset, EOF mid-reply,
    dead connection).  The connection is marked dead — call
    :meth:`Controller.reconnect` to re-establish it."""


class ControllerTimeoutError(ControllerTransportError):
    """The socket timeout expired while waiting for the server."""


class ControllerProtocolError(ControllerError):
    """The peer violated RESP framing or the decoder bounds (oversized bulk,
    too many items, nesting too deep, unterminated line, trailing garbage).
    The stream is desynchronised; the connection is marked dead."""


class ControllerAuthenticationError(ControllerError):
    """The server refused the explicit AUTH exchange (bad principal or
    credentials).  Connect-time authentication failure closes the
    connection, mirroring qihse_controller_connect()."""


class ControllerServerError(ControllerError):
    """The server replied with an error (RESP ``-`` inline error or RESP3
    ``!`` blob error).  Carries the server's own detail:

    Attributes:
        error_class: first token of the error line, e.g. ``"ERR"``,
            ``"NOAUTH"``, ``"NOPERM"`` (empty when the line has no token).
        message: the remainder of the error line after the class token.
    """

    def __init__(self, error_class: str, message: str):
        self.error_class = error_class
        self.message = message
        super().__init__(f"{error_class} {message}".strip())


class ReplyShapeError(ControllerError):
    """A reply-shape accessor was applied to a reply of the wrong kind
    (e.g. ``as_int()`` on a bulk).  The connection stays usable."""


# ── Replies ────────────────────────────────────────────────────────────────

class Reply:
    """One decoded RESP value.

    ``kind`` is one of:

        ``"simple"``    ``+text``                        — value: bytes
        ``"error"``     ``-text`` / RESP3 ``!len blob``  — value: bytes
        ``"int"``       ``:123``                         — value: int
        ``"bulk"``      ``$len payload``                 — value: bytes
        ``"nil"``       RESP2 ``$-1``/``*-1``, RESP3 ``_`` — value: None
        ``"array"``     ``*n``                           — items: list[Reply]
        ``"bool"``      RESP3 ``#t``/``#f``              — value: bool
        ``"double"``    RESP3 ``,3.14``                  — value: float
        ``"bignum"``    RESP3 ``(12345``                 — value: int
        ``"verbatim"``  RESP3 ``=len txt:...``           — value: bytes
        ``"map"``       RESP3 ``%n``                     — items: [(Reply, Reply)]
        ``"set"``       RESP3 ``~n``                     — items: list[Reply]
        ``"push"``      RESP3 ``>n``                     — items: list[Reply]

    Map items are ``(key, value)`` pairs of Replies.  ``attributes`` holds
    RESP3 attribute (``|n``) pairs attached to the wrapped reply, or None.

    Text payloads are kept as bytes (byte-exact); use :meth:`as_text` to
    decode.  Arrays/sets/maps support ``len()``, iteration, and indexing.
    """

    __slots__ = ("kind", "value", "items", "attributes")

    def __init__(self, kind: str, value=(), items=None, attributes=None):
        self.kind = kind
        self.value = value
        self.items: list = [] if items is None else items
        self.attributes = attributes

    # — shape helpers (mirror qihse_ctrl_reply_* in the C client) ————

    def is_ok(self) -> bool:
        """True for the ``+OK`` simple reply (qihse_ctrl_reply_ok)."""
        return self.kind == "simple" and self.value == b"OK"

    def is_nil(self) -> bool:
        return self.kind == "nil"

    def as_int(self) -> int:
        if self.kind not in ("int", "bignum"):
            raise ReplyShapeError(f"reply kind {self.kind!r} is not an integer")
        return int(self.value)

    def as_bytes(self) -> bytes:
        if self.kind not in ("simple", "error", "bulk", "verbatim"):
            raise ReplyShapeError(f"reply kind {self.kind!r} carries no text")
        return bytes(self.value)

    def as_text(self) -> str:
        """Decode the text payload as UTF-8 (byte-exact bytes are in
        ``as_bytes()``)."""
        return self.as_bytes().decode("utf-8")

    def as_pairs(self) -> list[tuple["Reply", "Reply"]]:
        """(key, value) pairs of a map reply."""
        if self.kind != "map":
            raise ReplyShapeError(f"reply kind {self.kind!r} is not a map")
        return list(self.items)

    def as_list(self) -> list["Reply"]:
        if self.kind not in ("array", "set", "push"):
            raise ReplyShapeError(f"reply kind {self.kind!r} is not a sequence")
        return list(self.items)

    # — container conveniences ——————————————————————————————

    def __len__(self) -> int:
        if self.kind not in ("array", "set", "push", "map"):
            raise ReplyShapeError(f"reply kind {self.kind!r} has no length")
        return len(self.items)

    def __iter__(self):
        if self.kind not in ("array", "set", "push"):
            raise ReplyShapeError(f"reply kind {self.kind!r} is not iterable")
        return iter(self.items)

    def __getitem__(self, index):
        if self.kind not in ("array", "set", "push"):
            raise ReplyShapeError(f"reply kind {self.kind!r} is not a sequence")
        return self.items[index]

    def __repr__(self) -> str:  # bounded — never dump a 16 MiB payload
        v = self.value
        if isinstance(v, (bytes, bytearray)):
            shown = bytes(v[:48])
            v = repr(shown + (b"..." if len(v) > 48 else b""))
        elif isinstance(v, list):
            v = f"[{len(v)} items]"
        return f"Reply(kind={self.kind!r}, value={v})"


# ── Strict token parsers (no int()/float() leniency) ──────────────────────

_INT_TOKEN_RE = re.compile(rb"\A-?[0-9]+\Z")
_DOUBLE_TOKEN_RE = re.compile(
    rb"\A-?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][-+]?[0-9]+)?\Z"
)
_DOUBLE_SPECIAL = (b"inf", b"-inf", b"nan", b"-nan")


def _parse_int_token(token: bytes, what: str) -> int:
    if not _INT_TOKEN_RE.match(token):
        raise ControllerProtocolError(f"malformed {what}: {token[:64]!r}")
    return int(token)


def _parse_count_token(token: bytes, what: str, bound: int) -> int:
    """Parse an element/byte count with the RESP2 nil convention (-1)."""
    n = _parse_int_token(token, what)
    if n == -1:
        return -1
    if n < -1:
        raise ControllerProtocolError(f"negative {what}: {n}")
    if n > bound:
        raise ControllerProtocolError(
            f"{what} {n} exceeds decoder bound {bound}"
        )
    return n


# ── Bounded readers ────────────────────────────────────────────────────────

class _SocketReader:
    """Bounded buffered reader over a connected socket (the Python mirror
    of the C client's CTRL_RX_CAP receive buffer)."""

    __slots__ = ("_sock", "_buf", "_pos")

    def __init__(self, sock: socket.socket):
        self._sock = sock
        self._buf = bytearray()
        self._pos = 0

    def _compact(self) -> None:
        if self._pos:
            del self._buf[: self._pos]
            self._pos = 0

    def _recv_more(self) -> None:
        if self._pos == len(self._buf):
            self._buf.clear()
            self._pos = 0
        try:
            chunk = self._sock.recv(_RECV_CHUNK)
        except TimeoutError as exc:
            raise ControllerTimeoutError(
                f"timeout waiting for server after {self._sock.gettimeout()}s"
            ) from exc
        except OSError as exc:
            raise ControllerTransportError(f"socket read failed: {exc}") from exc
        if not chunk:
            raise ControllerTransportError("connection closed by peer")
        self._buf += chunk

    def read_line(self, cap: int = MAX_LINE_BYTES) -> bytes:
        """Read one CRLF-terminated line; the terminator is consumed and the
        trailing CR is stripped.  Lines longer than ``cap`` are a protocol
        error (never an unbounded buffer)."""
        while True:
            idx = self._buf.find(b"\n", self._pos)
            if idx >= 0:
                line = bytes(self._buf[self._pos:idx])
                if line.endswith(b"\r"):
                    line = line[:-1]
                self._pos = idx + 1
                self._compact()
                if len(line) > cap:
                    raise ControllerProtocolError(
                        f"line of {len(line)} bytes exceeds {cap}-byte bound"
                    )
                return line
            if len(self._buf) - self._pos > cap + 2:
                raise ControllerProtocolError(
                    f"no CRLF within {cap}-byte line bound"
                )
            self._recv_more()

    def read_exact(self, n: int) -> bytes:
        """Read exactly ``n`` bytes (0 <= n <= MAX_BULK_BYTES)."""
        if n == 0:
            return b""
        out = bytearray(n)
        view = memoryview(out)
        got = 0
        buffered = len(self._buf) - self._pos
        if buffered:
            take = min(buffered, n)
            view[0:take] = self._buf[self._pos:self._pos + take]
            self._pos += take
            got = take
        while got < n:
            try:
                r = self._sock.recv_into(view[got:], min(_RECV_CHUNK, n - got))
            except TimeoutError as exc:
                raise ControllerTimeoutError(
                    "timeout mid-bulk waiting for server"
                ) from exc
            except OSError as exc:
                raise ControllerTransportError(
                    f"socket read failed: {exc}"
                ) from exc
            if r == 0:
                raise ControllerTransportError(
                    "connection closed by peer mid-bulk"
                )
            got += r
        self._compact()
        return bytes(out)

    def peek_line(self) -> bytes:
        """Peek the next CRLF line without consuming it (buffered data
        only).  Used to spot the ``.`` terminator of streamed aggregates;
        a partial line is returned as-is, which simply fails to match
        ``.`` and lets the normal read path fetch more."""
        idx = self._buf.find(b"\n", self._pos)
        if idx < 0:
            return bytes(self._buf[self._pos:])
        line = bytes(self._buf[self._pos:idx])
        return line[:-1] if line.endswith(b"\r") else line


class _BytesReader:
    """In-memory reader with the same contract as _SocketReader — used by
    tests to feed exact frames without a socket."""

    __slots__ = ("_data", "_pos")

    def __init__(self, data: bytes):
        self._data = data
        self._pos = 0

    def read_line(self, cap: int = MAX_LINE_BYTES) -> bytes:
        idx = self._data.find(b"\n", self._pos)
        if idx < 0:
            if len(self._data) - self._pos > cap + 2:
                raise ControllerProtocolError(
                    f"no CRLF within {cap}-byte line bound"
                )
            raise ControllerTransportError("connection closed by peer")
        line = self._data[self._pos:idx]
        if line.endswith(b"\r"):
            line = line[:-1]
        self._pos = idx + 1
        if len(line) > cap:
            raise ControllerProtocolError(
                f"line of {len(line)} bytes exceeds {cap}-byte bound"
            )
        return line

    def read_exact(self, n: int) -> bytes:
        if self._pos + n > len(self._data):
            raise ControllerTransportError("connection closed by peer mid-bulk")
        out = self._data[self._pos:self._pos + n]
        self._pos += n
        return out

    def peek_line(self) -> bytes:
        idx = self._data.find(b"\n", self._pos)
        if idx < 0:
            return self._data[self._pos:]
        line = self._data[self._pos:idx]
        return line[:-1] if line.endswith(b"\r") else line


# ── Decoder ────────────────────────────────────────────────────────────────

def _read_bulk_body(reader, n: int) -> bytes:
    """Read ``n`` payload bytes plus the mandatory trailing CRLF."""
    data = reader.read_exact(n)
    tail = reader.read_exact(2)
    if tail != b"\r\n":
        raise ControllerProtocolError("bulk payload not CRLF-terminated")
    return data


def parse_reply(reader, depth: int = 0) -> Reply:
    """Parse exactly one RESP2/RESP3 value from ``reader``.

    Depth counts container nesting; a reply nested deeper than
    MAX_DEPTH is rejected (QIHSE_CTRL_MAX_DEPTH parity).
    """
    if depth > MAX_DEPTH:
        raise ControllerProtocolError(f"reply nesting exceeds {MAX_DEPTH}")
    line = reader.read_line()
    if not line:
        raise ControllerProtocolError("empty reply line")
    kind = line[0:1]
    rest = line[1:]

    if kind == b"+":
        return Reply("simple", value=rest)

    if kind == b"-":
        return Reply("error", value=rest)

    if kind == b":":
        return Reply("int", value=_parse_int_token(rest, "integer reply"))

    if kind == b"$":
        if rest == b"?":  # RESP3 streamed string: chunks until ";0"
            chunks = bytearray()
            while True:
                cline = reader.read_line()
                if not cline.startswith(b";"):
                    raise ControllerProtocolError(
                        f"malformed streamed-string chunk: {cline[:32]!r}"
                    )
                n = _parse_count_token(
                    cline[1:], "streamed-string chunk length", MAX_BULK_BYTES
                )
                if n == 0:
                    if chunks and len(chunks) > MAX_BULK_BYTES:
                        raise ControllerProtocolError(
                            "streamed string exceeds bulk bound"
                        )
                    return Reply("bulk", value=bytes(chunks))
                if len(chunks) + n > MAX_BULK_BYTES:
                    raise ControllerProtocolError(
                        "streamed string exceeds bulk bound"
                    )
                chunks += reader.read_exact(n)
        n = _parse_count_token(rest, "bulk length", MAX_BULK_BYTES)
        if n == -1:
            return Reply("nil", value=None)
        return Reply("bulk", value=_read_bulk_body(reader, n))

    if kind == b"*":
        if rest == b"?":  # RESP3 streamed array: elements until "."
            items: list[Reply] = []
            while True:
                peek = reader.peek_line()
                if peek == b".":
                    reader.read_line()
                    return Reply("array", items=items)
                if len(items) >= MAX_ARRAY_ITEMS:
                    raise ControllerProtocolError(
                        "streamed array exceeds item bound"
                    )
                items.append(parse_reply(reader, depth + 1))
        n = _parse_count_token(rest, "array length", MAX_ARRAY_ITEMS)
        if n == -1:
            return Reply("nil", value=None)
        return Reply(
            "array", items=[parse_reply(reader, depth + 1) for _ in range(n)]
        )

    if kind == b"~":  # RESP3 set
        if rest == b"?":
            items = []
            while True:
                peek = reader.peek_line()
                if peek == b".":
                    reader.read_line()
                    return Reply("set", items=items)
                if len(items) >= MAX_ARRAY_ITEMS:
                    raise ControllerProtocolError(
                        "streamed set exceeds item bound"
                    )
                items.append(parse_reply(reader, depth + 1))
        n = _parse_count_token(rest, "set cardinality", MAX_ARRAY_ITEMS)
        if n == -1:
            return Reply("nil", value=None)
        return Reply(
            "set", items=[parse_reply(reader, depth + 1) for _ in range(n)]
        )

    if kind == b"%":  # RESP3 map: n key/value pairs
        if rest == b"?":
            pairs: list[tuple[Reply, Reply]] = []
            while True:
                peek = reader.peek_line()
                if peek == b".":
                    reader.read_line()
                    return Reply("map", items=pairs)
                if len(pairs) >= MAX_ARRAY_ITEMS:
                    raise ControllerProtocolError(
                        "streamed map exceeds item bound"
                    )
                pairs.append(
                    (parse_reply(reader, depth + 1), parse_reply(reader, depth + 1))
                )
        n = _parse_count_token(rest, "map cardinality", MAX_ARRAY_ITEMS)
        if n == -1:
            return Reply("nil", value=None)
        pairs = []
        for _ in range(n):
            k = parse_reply(reader, depth + 1)
            v = parse_reply(reader, depth + 1)
            pairs.append((k, v))
        return Reply("map", items=pairs)

    if kind == b">":  # RESP3 push (out-of-band; queued by Controller.call)
        n = _parse_count_token(rest, "push length", MAX_ARRAY_ITEMS)
        if n == -1:
            return Reply("nil", value=None)
        return Reply(
            "push", items=[parse_reply(reader, depth + 1) for _ in range(n)]
        )

    if kind == b"|":  # RESP3 attribute: pairs wrapping the next reply
        n = _parse_count_token(rest, "attribute cardinality", MAX_ARRAY_ITEMS)
        if n == -1:
            raise ControllerProtocolError("nil attribute section")
        pairs = []
        for _ in range(n):
            k = parse_reply(reader, depth + 1)
            v = parse_reply(reader, depth + 1)
            pairs.append((k, v))
        wrapped = parse_reply(reader, depth)
        wrapped.attributes = pairs
        return wrapped

    if kind == b"_":  # RESP3 null
        if rest:
            raise ControllerProtocolError("malformed null reply")
        return Reply("nil", value=None)

    if kind == b"#":  # RESP3 boolean
        if rest == b"t":
            return Reply("bool", value=True)
        if rest == b"f":
            return Reply("bool", value=False)
        raise ControllerProtocolError(f"malformed boolean reply: {rest!r}")

    if kind == b",":  # RESP3 double
        if rest in _DOUBLE_SPECIAL:
            value = float(rest.replace(b"-nan", b"nan"))
        elif _DOUBLE_TOKEN_RE.match(rest):
            value = float(rest)
        else:
            raise ControllerProtocolError(f"malformed double reply: {rest!r}")
        return Reply("double", value=value)

    if kind == b"(":  # RESP3 big number
        return Reply("bignum", value=_parse_int_token(rest, "big number"))

    if kind == b"!":  # RESP3 blob error
        n = _parse_count_token(rest, "blob-error length", MAX_BULK_BYTES)
        return Reply("error", value=_read_bulk_body(reader, n))

    if kind == b"=":  # RESP3 verbatim string ("txt:..." prefix kept verbatim)
        n = _parse_count_token(rest, "verbatim length", MAX_BULK_BYTES)
        if n == -1:
            return Reply("nil", value=None)
        return Reply("verbatim", value=_read_bulk_body(reader, n))

    raise ControllerProtocolError(f"unknown reply type byte {kind!r}")


def _error_detail(payload: bytes) -> tuple[str, str]:
    """Split a server error line into (class, message), e.g.
    b"NOPERM federation requires authentication" -> ("NOPERM",
    "federation requires authentication")."""
    token, sep, message = payload.partition(b" ")
    if not sep:
        return payload.decode("utf-8", "replace"), ""
    return token.decode("utf-8", "replace"), message.decode("utf-8", "replace")


def raise_on_error(reply: Reply) -> None:
    if reply.kind == "error":
        error_class, message = _error_detail(reply.as_bytes())
        raise ControllerServerError(error_class, message)


# ── Command encoding ───────────────────────────────────────────────────────

def _encode_arg(arg) -> bytes:
    if isinstance(arg, str):
        return arg.encode("utf-8")
    if isinstance(arg, (bytes, bytearray, memoryview)):
        return bytes(arg)
    if isinstance(arg, bool):  # noqa: FBT001 - explicitness by refusal
        raise ControllerUsageError(
            "bool command arguments are ambiguous; pass b'1'/b'0' explicitly"
        )
    if isinstance(arg, int):
        return b"%d" % arg
    raise ControllerUsageError(
        f"command argument of type {type(arg).__name__} is not "
        "str/bytes/bytearray/memoryview/int"
    )


def encode_command(args: Sequence) -> bytes:
    """Encode ``args`` as one RESP command frame (``*N`` + ``$len`` bulks).

    The frame is bounded exactly like the C client: a command whose wire
    size would exceed MAX_BULK_BYTES is refused before anything is sent.
    """
    encoded = [_encode_arg(a) for a in args]
    if not encoded:
        raise ControllerUsageError("a command needs at least one argument")
    total = 16 + sum(32 + len(a) for a in encoded)
    if total > MAX_BULK_BYTES:
        raise CommandTooLargeError(
            f"encoded command of ~{total} bytes exceeds {MAX_BULK_BYTES}"
        )
    parts = [b"*%d\r\n" % len(encoded)]
    for a in encoded:
        parts.append(b"$%d\r\n" % len(a))
        parts.append(a)
        parts.append(b"\r\n")
    return b"".join(parts)


def _u64(value: int, what: str) -> str:
    """Validate an unsigned wire field and render it as a decimal string."""
    if not isinstance(value, int) or isinstance(value, bool):
        raise ControllerUsageError(f"{what} must be an int, got {type(value).__name__}")
    if value < 0:
        raise ControllerUsageError(f"{what} must be >= 0, got {value}")
    return str(value)


# ── Watch: stateful cursor handling (§25 resumable watches) ────────────────

class Watch:
    """A resumable watch session opened with WATCH.OPEN.

    Watch ids are session-scoped server state.  This object carries the
    client-side cursor bookkeeping needed to resume across reconnects:

        * ``watch_id``       — the server slot for the CURRENT session;
            :meth:`Controller.reconnect` re-opens the watch and updates it.
        * ``last_delivered`` — journal offset of the most recent event
            handed out by :meth:`next`.
        * ``last_acked``     — the ack watermark (monotonic, like the
            server's).  :meth:`Controller.reconnect` resumes each watch
            from THIS value.

    Offsets are journal byte offsets; ``resume(cursor)`` rewinds so the
    record AT ``cursor`` is delivered again — delivery is at-least-once,
    exactly as the server implements it.
    """

    def __init__(self, controller: "Controller", watch_id: int, prefix: str | None):
        self._ctrl = controller
        self.watch_id = watch_id
        self.prefix = prefix
        self.last_delivered: int | None = None
        self.last_acked: int | None = None

    def next(self) -> Reply:
        """WATCH.NEXT — the raw reply: an int 0 at journal end, or the
        event array [offset, event_type, resource_id, payload]."""
        reply = self._ctrl.watch_next(self.watch_id)
        if reply.kind == "int" and reply.value == 0:
            return reply
        if reply.kind == "array" and len(reply.items) >= 1 \
                and reply.items[0].kind == "int":
            self.last_delivered = int(reply.items[0].value)
        return reply

    def event(self) -> tuple[int, bytes, bytes, bytes] | None:
        """WATCH.NEXT as a typed tuple ``(offset, event_type, resource_id,
        payload)``; ``None`` at journal end."""
        reply = self.next()
        if reply.kind == "int" and reply.value == 0:
            return None
        if reply.kind != "array" or len(reply) != 4:
            raise ReplyShapeError(
                f"unexpected WATCH.NEXT shape: kind={reply.kind}"
            )
        offset = reply.items[0].as_int()
        return (
            offset,
            reply.items[1].as_bytes(),
            reply.items[2].as_bytes(),
            reply.items[3].as_bytes(),
        )

    def ack(self, offset: int | None = None) -> Reply:
        """WATCH.ACK — advance the ack watermark to ``offset`` (default:
        the last delivered event's offset).  Like the server, the
        watermark never moves backwards."""
        target = self.last_delivered if offset is None else offset
        if target is None:
            raise ControllerUsageError(
                "no delivered offset to ack; pass an explicit offset"
            )
        reply = self._ctrl.watch_ack(self.watch_id, target)
        if self.last_acked is None or target > self.last_acked:
            self.last_acked = target
        return reply

    def resume(self, cursor: int) -> Reply:
        """WATCH.RESUME — rewind the read cursor to ``cursor`` (e.g. 0 for
        a full second pass).  The record AT ``cursor`` is re-delivered
        next (the server iterates from that byte offset).  The ack
        watermark is untouched: reconnects resume from
        :attr:`last_acked`, not from a read rewind."""
        return self._ctrl.watch_resume(self.watch_id, cursor)


# ── Controller client ──────────────────────────────────────────────────────

class Controller:
    """Synchronous QIHSE controller client (Python mirror of
    qihse_controller.h).

    Authentication is explicit and per-connection: pass ``username`` (and
    ``password``) to authenticate during :meth:`connect`, or call
    :meth:`authenticate` yourself.  With ``username=None`` the client
    connects unauthenticated and the SERVER refuses protected commands —
    this SDK never invents an identity.

    Example::

        with Controller("127.0.0.1", 6390,
                        username="GODMODE_OP", password="...") as ctrl:
            ctrl.ns_register("fleet", "LOCAL")
            gen = ctrl.object_cas("fleet", "vm-1/desired", b"running", 0)
            watch = ctrl.watch_open("vm-1")
            event = watch.event()      # (offset, type, rid, payload)

    Transport/protocol failures mark the connection dead; :meth:`reconnect`
    re-establishes it, re-authenticates with the SAME explicit principal,
    re-opens every :class:`Watch` and resumes each from its last acked
    cursor.
    """

    def __init__(
        self,
        host: str,
        port: int,
        *,
        username: str | None = None,
        password: str | None = None,
        timeout_ms: int = DEFAULT_TIMEOUT_MS,
        protocol: int = 2,
        connect: bool = True,
    ):
        if not host:
            raise ControllerUsageError("host is required")
        if not (1 <= int(port) <= 65535):
            raise ControllerUsageError(f"port {port} out of range")
        if protocol not in (2, 3):
            raise ControllerUsageError("protocol must be 2 or 3")
        if timeout_ms <= 0:
            timeout_ms = DEFAULT_TIMEOUT_MS
        self.host = host
        self.port = int(port)
        self.username = username
        self.password = password
        self.timeout_ms = timeout_ms
        self.protocol = protocol
        self.pushes: list[Reply] = []      # RESP3 push messages received
        self._watches: list[Watch] = []
        self._sock: socket.socket | None = None
        self._reader: _SocketReader | None = None
        self._dead = True
        if connect:
            self.connect()

    # — lifecycle ─—————————————————————————————————————

    def connect(self) -> None:
        """Open the TCP connection and, when a principal was supplied,
        authenticate with it.  Refused AUTH raises
        :class:`ControllerAuthenticationError` and closes the socket
        (qihse_controller_connect parity)."""
        if self.connected:
            raise ControllerUsageError("already connected")
        try:
            sock = socket.create_connection(
                (self.host, self.port), timeout=self.timeout_ms / 1000.0
            )
        except OSError as exc:
            raise ControllerConnectionError(
                f"cannot connect to {self.host}:{self.port}: {exc}"
            ) from exc
        self._sock = sock
        self._reader = _SocketReader(sock)
        self._dead = False
        try:
            if self.protocol == 3:
                self._hello3()
            if self.username is not None:
                self.authenticate(self.username, self.password or "")
        except ControllerError:
            self.close()
            raise

    def reconnect(self) -> None:
        """Close, re-connect, re-authenticate with the same explicit
        principal, and re-open all watches (resuming each from its last
        acked cursor).  Watch ids change — they are session-scoped."""
        self.close()
        self.connect()  # re-authenticates via stored explicit credentials
        for watch in list(self._watches):
            # Re-open the watch IN PLACE (never a second registry entry):
            # ids are session-scoped, so the new session gets a new slot.
            args = [] if watch.prefix is None else [watch.prefix]
            reply = self._fed("WATCH.OPEN", *args)
            if reply.kind != "int":
                raise ReplyShapeError(
                    f"WATCH.OPEN did not return an id on reconnect: "
                    f"kind={reply.kind}"
                )
            watch.watch_id = int(reply.value)
            if watch.last_acked is not None:
                self._fed("WATCH.RESUME", str(watch.watch_id),
                          str(watch.last_acked))

    def close(self) -> None:
        """Close the connection (idempotent).  Watch cursor state is kept
        so a subsequent reconnect() can resume."""
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
        self._sock = None
        self._reader = None
        self._dead = True

    @property
    def connected(self) -> bool:
        return self._sock is not None and not self._dead

    def __enter__(self) -> "Controller":
        if not self.connected:
            self.connect()
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def __del__(self):  # best-effort
        try:
            self.close()
        except Exception:
            pass

    # — auth ─────────────────────────────────────────────────────────

    def authenticate(self, username: str, password: str) -> Reply:
        """Explicit ``AUTH username password`` exchange.  The principal and
        credentials must be provided by the caller — never ambient.  A
        refusal raises :class:`ControllerAuthenticationError` carrying the
        server's error class and message."""
        reply = self._call_raw(["AUTH", username, password])
        if reply.kind == "error":
            error_class, message = _error_detail(reply.as_bytes())
            raise ControllerAuthenticationError(
                f"authentication refused for principal {username!r}: "
                f"{error_class} {message}".strip()
            )
        self.username = username
        self.password = password
        return reply

    def _hello3(self) -> None:
        reply = self._call_raw(["HELLO", "3"])
        if reply.kind == "error":
            error_class, message = _error_detail(reply.as_bytes())
            raise ControllerProtocolError(
                f"server refused HELLO 3: {error_class} {message}".strip()
            )

    # — command path ──────────────────────────────────────────────────

    def call(self, *args, check: bool = True) -> Reply:
        """Send an arbitrary command (escape hatch; the named wrappers are
        the intended surface).  With ``check=True`` (default) an error
        reply raises :class:`ControllerServerError`; with ``check=False``
        the error Reply is returned for inspection."""
        reply = self._call_raw(list(args))
        if check:
            raise_on_error(reply)
        return reply

    def _call_raw(self, args: list) -> Reply:
        if not self.connected:
            raise ControllerTransportError(
                "connection is dead; call reconnect() to re-establish"
            )
        wire = encode_command(args)
        try:
            self._sock.sendall(wire)
        except TimeoutError as exc:
            self._dead = True
            raise ControllerTimeoutError("timeout sending command") from exc
        except OSError as exc:
            self._dead = True
            raise ControllerTransportError(f"socket write failed: {exc}") from exc
        try:
            while True:
                reply = parse_reply(self._reader, 0)
                if reply.kind == "push":     # out-of-band: queue, keep reading
                    self.pushes.append(reply)
                    continue
                return reply
        except ControllerTransportError:
            self._dead = True
            raise
        except ControllerProtocolError:
            self._dead = True
            raise

    def _fed(self, sub: str, *args, check: bool = True) -> Reply:
        """Prepend FEDERATION and forward (C fed_call parity)."""
        return self.call("FEDERATION", sub, *args, check=check)

    # ── §25: Node inventory and trust ────────────────────────────────

    def node_list(self) -> Reply:
        """FEDERATION NODE.LIST — array of triples
        [node_uuid, trust_state, identity_kind]."""
        return self._fed("NODE.LIST")

    def node_get(self, node_uuid: str) -> Reply:
        """FEDERATION NODE.SHOW <uuid> — array [hostname, trust, kind,
        scopes, enroll_epoch, capabilities, fingerprint_hex, key_handle,
        sig_alg, pubkey_len]."""
        return self._fed("NODE.SHOW", node_uuid)

    def node_enroll(self, identity_kind: str, hostname: str, boot_id: str) -> Reply:
        """FEDERATION NODE.ENROLL — enroll a node; the server generates the
        keypair in its configured key directory and returns the new node
        UUID (bulk)."""
        return self._fed("NODE.ENROLL", identity_kind, hostname, boot_id)

    def node_approve(self, node_uuid: str, enrollment_epoch: int = 0) -> Reply:
        """FEDERATION NODE.APPROVE — +OK; ``enrollment_epoch`` 0 lets the
        server assign one."""
        args = [node_uuid] + ([] if enrollment_epoch == 0
                              else [_u64(enrollment_epoch, "enrollment_epoch")])
        return self._fed("NODE.APPROVE", *args)

    def node_revoke(self, node_uuid: str) -> Reply:
        """FEDERATION NODE.REVOKE — +OK."""
        return self._fed("NODE.REVOKE", node_uuid)

    def trust_set(self, node_uuid: str, trust_state: str, result: str) -> Reply:
        """FEDERATION TRUST.SET — +OK; ``result`` is the verification
        verdict ("attested", ...)."""
        return self._fed("TRUST.SET", node_uuid, trust_state, result)

    def trust_states(self) -> Reply:
        """FEDERATION TRUST.STATES — array of state names."""
        return self._fed("TRUST.STATES")

    def trust_admission(self, node_uuid: str) -> Reply:
        """FEDERATION TRUST.ADMISSION <uuid> — the admission verdict array."""
        return self._fed("TRUST.ADMISSION", node_uuid)

    # ── §25: Object / desired-vs-observed (CAS) ──────────────────────

    def object_get(self, ns: str, resource_id: str) -> Reply:
        """FEDERATION OBJECT.GET — array [generation, value]."""
        return self._fed("OBJECT.GET", ns, resource_id)

    def object_cas(self, ns: str, resource_id: str, value, expected_generation: int) -> Reply:
        """FEDERATION OBJECT.CAS — compare-and-swap.

        The generation precondition is explicit and never hidden:
        ``expected_generation`` 0 means create-only; any other value must
        match the stored generation.  Replies :1 on swap, :0 on generation
        mismatch (a mismatch is NOT an error reply).
        """
        gen = _u64(expected_generation, "expected_generation")
        return self._fed("OBJECT.CAS", ns, resource_id, value, gen)

    # ── §25: Lease / epoch ───────────────────────────────────────────

    def lease_acquire(self, ns: str, resource_id: str, fencing_epoch: int,
                      expires_ms: int = 0) -> Reply:
        """FEDERATION LEASE.ACQUIRE — bulk lease UUID.  ``fencing_epoch`` is
        the epoch the caller already advanced to (EPOCH.NEXT);
        ``expires_ms`` 0 = server default (omitted from the wire)."""
        epoch = _u64(fencing_epoch, "fencing_epoch")
        args = [ns, resource_id, epoch]
        if expires_ms:
            args.append(_u64(expires_ms, "expires_ms"))
        return self._fed("LEASE.ACQUIRE", *args)

    def lease_read(self, lease_id: str) -> Reply:
        """FEDERATION LEASE.READ — array [resource_id, state,
        fencing_epoch, generation, expires_hlc_physical]."""
        return self._fed("LEASE.READ", lease_id)

    def lease_renew(self, lease_id: str, expires_ms: int) -> Reply:
        """FEDERATION LEASE.RENEW — +OK."""
        return self._fed("LEASE.RENEW", lease_id, _u64(expires_ms, "expires_ms"))

    def lease_release(self, lease_id: str) -> Reply:
        """FEDERATION LEASE.RELEASE — +OK."""
        return self._fed("LEASE.RELEASE", lease_id)

    def epoch_next(self) -> Reply:
        """FEDERATION EPOCH.NEXT — :new fencing epoch."""
        return self._fed("EPOCH.NEXT")

    def epoch_current(self) -> Reply:
        """FEDERATION EPOCH.CURRENT — :current epoch."""
        return self._fed("EPOCH.CURRENT")

    # ── §25: Event journal + resumable watches ───────────────────────

    def event_append(self, event_type: str, resource_id: str,
                     payload: bytes | None = None) -> Reply:
        """FEDERATION EVENT.APPEND — :journal offset (the resumable
        cursor).  ``payload`` bytes are transmitted byte-exact; ``None``
        omits the payload argument (C parity).

        Wire note: the server replies with ``record_offset + 1`` (the
        event stream's non-zero-success convention), while WATCH.NEXT
        reports the record's own byte offset — treat the append reply as
        "succeeded" (> 0), not as the WATCH.NEXT offset."""
        args: list = [event_type, resource_id]
        if payload is not None:
            if not isinstance(payload, (bytes, bytearray, memoryview)):
                raise ControllerUsageError("payload must be bytes or None")
            args.append(bytes(payload))
        return self._fed("EVENT.APPEND", *args)

    def event_replay(self, from_cursor: int = 0) -> Reply:
        """FEDERATION EVENT.REPLAY — flat array of triples
        [offset, event_type, resource_id] from ``from_cursor``."""
        return self._fed("EVENT.REPLAY", _u64(from_cursor, "from_cursor"))

    def watch_open(self, prefix: str | None = None) -> Watch:
        """FEDERATION WATCH.OPEN — open a resumable watch and return the
        stateful :class:`Watch`.  ``prefix`` is a RESOURCE_ID prefix
        filter; ``None`` receives all events (argument omitted, C parity)."""
        args = [] if prefix is None else [prefix]
        reply = self._fed("WATCH.OPEN", *args)
        if reply.kind != "int":
            raise ReplyShapeError(
                f"WATCH.OPEN did not return an id: kind={reply.kind}"
            )
        watch = Watch(self, int(reply.value), prefix)
        self._watches.append(watch)
        return watch

    def watch_next(self, watch_id: int) -> Reply:
        """FEDERATION WATCH.NEXT — :0 at journal end, or the event array
        [offset, event_type, resource_id, payload].  Prefer
        :meth:`Watch.next` (it tracks the cursor)."""
        return self._fed("WATCH.NEXT", str(watch_id))

    def watch_ack(self, watch_id: int, offset: int) -> Reply:
        """FEDERATION WATCH.ACK — +OK; drops backlog up to ``offset``."""
        return self._fed("WATCH.ACK", str(watch_id), _u64(offset, "offset"))

    def watch_resume(self, watch_id: int, cursor: int) -> Reply:
        """FEDERATION WATCH.RESUME — +OK; rewinds to ``cursor``."""
        return self._fed("WATCH.RESUME", str(watch_id), _u64(cursor, "cursor"))

    # ── §25: Conflicts, status, reconciliation ───────────────────────

    def conflict_list(self) -> Reply:
        """FEDERATION CONFLICT.LIST — flat array of pairs
        [conflict_uuid, namespace]."""
        return self._fed("CONFLICT.LIST")

    def conflict_resolve(self, conflict_uuid: str, resolver_uuid: str) -> Reply:
        """FEDERATION CONFLICT.RESOLVE — +OK; ``resolver_uuid`` is an
        enrolled node id."""
        return self._fed("CONFLICT.RESOLVE", conflict_uuid, resolver_uuid)

    def federation_status(self) -> Reply:
        """FEDERATION STATUS — bulk status object text (§5 status shape)."""
        return self._fed("STATUS")

    def rejoin_status(self, node_uuid: str) -> Reply:
        """FEDERATION REJOIN.STATUS — array [step, events_transferred,
        conflicts_applied, may_publish_ownership, last_error]."""
        return self._fed("REJOIN.STATUS", node_uuid)

    def metrics(self, prefix: str | None = None) -> Reply:
        """FEDERATION METRICS — bulk rendered metrics text; ``prefix``
        None = all federation metrics (argument omitted, C parity)."""
        args = [] if prefix is None else [prefix]
        return self._fed("METRICS", *args)

    # ── §15: Namespaces and replication groups ───────────────────────

    def ns_register(self, name: str, consistency: str,
                    authority_node_uuid: str | None = None) -> Reply:
        """FEDERATION NS.REGISTER — +OK.  ``consistency`` is a
        case-sensitive class name (LOCAL/EVENTUAL/CAUSAL/QUORUM/
        LINEARIZABLE); ``authority_node_uuid`` None = this node."""
        args = [name, consistency]
        if authority_node_uuid is not None:
            args.append(authority_node_uuid)
        return self._fed("NS.REGISTER", *args)

    def ns_unregister(self, name: str) -> Reply:
        """FEDERATION NS.UNREGISTER — +OK."""
        return self._fed("NS.UNREGISTER", name)

    def ns_list(self) -> Reply:
        """FEDERATION NS.LIST — array of namespace records."""
        return self._fed("NS.LIST")

    def ns_writable(self, name: str) -> Reply:
        """FEDERATION NS.WRITABLE — :1/:0: can this principal write the
        namespace now?"""
        return self._fed("NS.WRITABLE", name)

    def manifest(self, ns: str) -> Reply:
        """FEDERATION MANIFEST — the namespace anti-entropy manifest
        (range digests)."""
        return self._fed("MANIFEST", ns)

    def group_create(self, group_id: str, consistency: str | None = None) -> Reply:
        """FEDERATION GROUP.CREATE — +OK; ``consistency`` None = QUORUM."""
        args = [group_id]
        if consistency is not None:
            args.append(consistency)
        return self._fed("GROUP.CREATE", *args)

    def group_add(self, group_id: str, member_uuid: str,
                  voter: bool = False, witness: bool = False) -> Reply:
        """FEDERATION GROUP.ADD — +OK; appends the flags "voter"/"witness"
        exactly as the C client does."""
        args = [group_id, member_uuid]
        if voter:
            args.append("voter")
        if witness:
            args.append("witness")
        return self._fed("GROUP.ADD", *args)

    def group_remove(self, group_id: str, member_uuid: str) -> Reply:
        """FEDERATION GROUP.REMOVE — +OK."""
        return self._fed("GROUP.REMOVE", group_id, member_uuid)

    def group_show(self, group_id: str) -> Reply:
        """FEDERATION GROUP.SHOW — the group record."""
        return self._fed("GROUP.SHOW", group_id)

    def group_list(self) -> Reply:
        """FEDERATION GROUP.LIST — group ids."""
        return self._fed("GROUP.LIST")

    def group_advance(self, group_id: str) -> Reply:
        """FEDERATION GROUP.ADVANCE — :new term."""
        return self._fed("GROUP.ADVANCE", group_id)

    # ── §28–§30: Build coordination (STATE ONLY; QIHSE never executes) ──

    def build_job_create(self, package: str, revision: str, profile: str,
                         toolchain: str) -> Reply:
        """FEDERATION BUILD.CREATE — the new build id (bulk)."""
        return self._fed("BUILD.CREATE", package, revision, profile, toolchain)

    def build_job_transition(self, build_id: str, state: str, request_id: str,
                             reason: str | None = None) -> Reply:
        """FEDERATION BUILD.TRANSITION — +OK; ``request_id`` is the
        idempotency key."""
        args = [build_id, state, request_id]
        if reason is not None:
            args.append(reason)
        return self._fed("BUILD.TRANSITION", *args)

    def build_job_get(self, build_id: str) -> Reply:
        """FEDERATION BUILD.SHOW — the build record."""
        return self._fed("BUILD.SHOW", build_id)

    def build_job_list(self) -> Reply:
        """FEDERATION BUILD.LIST — array of build records."""
        return self._fed("BUILD.LIST")

    def build_states(self) -> Reply:
        """FEDERATION BUILD.STATES — array of state names."""
        return self._fed("BUILD.STATES")

    def build_worker_publish(self, node_uuid: str, cores_available: int,
                             ram_available_gb: int, queue_depth: int) -> Reply:
        """FEDERATION BUILDER.CAP — +OK: the worker's capability snapshot."""
        return self._fed(
            "BUILDER.CAP", node_uuid,
            _u64(cores_available, "cores_available"),
            _u64(ram_available_gb, "ram_available_gb"),
            _u64(queue_depth, "queue_depth"),
        )

    def build_worker_get(self, node_uuid: str) -> Reply:
        """FEDERATION BUILDER.SHOW — the worker capability record."""
        return self._fed("BUILDER.SHOW", node_uuid)

    # ── §31–§34: Supply chain ────────────────────────────────────────

    def pkg_set(self, package: str, mode: str, reason: str) -> Reply:
        """FEDERATION PKG.SET — +OK; ``mode`` is one of the registry
        modes (see :meth:`pkg_modes`)."""
        return self._fed("PKG.SET", package, mode, reason)

    def pkg_get(self, package: str) -> Reply:
        """FEDERATION PKG.GET — the package record."""
        return self._fed("PKG.GET", package)

    def pkg_modes(self) -> Reply:
        """FEDERATION PKG.MODES — array of mode names."""
        return self._fed("PKG.MODES")

    def supply_sbom(self, artifact_digest: str, sbom_digest: str,
                    signing_identity: str, format: str) -> Reply:  # noqa: A002
        """FEDERATION SUPPLY.SBOM — +OK (attestation record)."""
        return self._fed("SUPPLY.SBOM", artifact_digest, sbom_digest,
                         signing_identity, format)

    def supply_sbom_get(self, sbom_digest: str) -> Reply:
        """FEDERATION SUPPLY.SBOM.GET — the SBOM record."""
        return self._fed("SUPPLY.SBOM.GET", sbom_digest)

    def supply_snapshot(self, repository: str, digest: str, release: str,
                        package_count: int = 0) -> Reply:
        """FEDERATION SUPPLY.SNAPSHOT — +OK; ``package_count`` 0 omits the
        field from the wire (C parity)."""
        args = [repository, digest, release]
        if package_count:
            args.append(_u64(package_count, "package_count"))
        return self._fed("SUPPLY.SNAPSHOT", *args)

    def supply_snapshot_list(self, repository: str | None = None) -> Reply:
        """FEDERATION SUPPLY.SNAPSHOT.LIST — array; ``repository`` None =
        all repositories (argument omitted)."""
        args = [] if repository is None else [repository]
        return self._fed("SUPPLY.SNAPSHOT.LIST", *args)

    def supply_vuln(self, component_digest: str, advisory: str, severity: str,
                    status: str) -> Reply:
        """FEDERATION SUPPLY.VULN — +OK (vulnerability observation, §33)."""
        return self._fed("SUPPLY.VULN", component_digest, advisory, severity,
                         status)

    def supply_vuln_count(self, component_digest: str) -> Reply:
        """FEDERATION SUPPLY.VULN.COUNT — :n."""
        return self._fed("SUPPLY.VULN.COUNT", component_digest)

    def prov_node(self, entity: str, id: str, label: str | None = None) -> Reply:  # noqa: A002
        """FEDERATION PROV.NODE — +OK; ``label`` None omits it."""
        args = [entity, id]
        if label is not None:
            args.append(label)
        return self._fed("PROV.NODE", *args)

    def prov_edge(self, from_ref: str, edge: str, to_ref: str) -> Reply:
        """FEDERATION PROV.EDGE — +OK."""
        return self._fed("PROV.EDGE", from_ref, edge, to_ref)

    def prov_show(self, entity: str, id: str) -> Reply:  # noqa: A002
        """FEDERATION PROV.SHOW — the provenance record."""
        return self._fed("PROV.SHOW", entity, id)

    def prov_trace(self, entity: str, id: str, forward: bool = True,  # noqa: A002
                   depth: int = 0) -> Reply:
        """FEDERATION PROV.TRACE — records along the graph;
        ``forward``/``reverse`` direction; ``depth`` 0 = default bound
        (omitted from the wire)."""
        args = [entity, id, "forward" if forward else "reverse"]
        if depth:
            args.append(_u64(depth, "depth"))
        return self._fed("PROV.TRACE", *args)

    def prov_impact(self, entity: str, id: str, want_entity: str,  # noqa: A002
                    depth: int = 0) -> Reply:
        """FEDERATION PROV.IMPACT — impacted entities; ``depth`` 0 =
        default bound (omitted)."""
        args = [entity, id, want_entity]
        if depth:
            args.append(_u64(depth, "depth"))
        return self._fed("PROV.IMPACT", *args)

    # ── §23/§24/§36–§39: Operational admin ───────────────────────────

    def snapshot_create(self, kind: str, max_generation: int, wal_offset: int,
                        key_id: str | None = None) -> Reply:
        """FEDERATION SNAPSHOT.CREATE — the snapshot id; ``kind`` is
        "local" or "coordinated"; ``key_id`` None = unencrypted manifest."""
        args = [kind, _u64(max_generation, "max_generation"),
                _u64(wal_offset, "wal_offset")]
        if key_id is not None:
            args.append(key_id)
        return self._fed("SNAPSHOT.CREATE", *args)

    def snapshot_show(self, snapshot_id: str) -> Reply:
        """FEDERATION SNAPSHOT.SHOW — the snapshot record."""
        return self._fed("SNAPSHOT.SHOW", snapshot_id)

    def snapshot_verify(self, snapshot_id: str) -> Reply:
        """FEDERATION SNAPSHOT.VERIFY — the verification verdict."""
        return self._fed("SNAPSHOT.VERIFY", snapshot_id)

    def schema_status(self, schema_id: str, version: str) -> Reply:
        """FEDERATION SCHEMA.STATUS — status of a schema version."""
        return self._fed("SCHEMA.STATUS", schema_id, version)

    def schema_check(self, writer_version: str, min_reader: str,
                     required_hex: str, optional_hex: str) -> Reply:
        """FEDERATION SCHEMA.CHECK — compatibility verdict for a
        writer/min-reader column-mask pair."""
        return self._fed("SCHEMA.CHECK", writer_version, min_reader,
                         required_hex, optional_hex)

    def schema_migrate(self, schema_id: str, from_version: str, to_version: str,
                       resumable: bool) -> Reply:
        """FEDERATION SCHEMA.MIGRATE — start migration; ``resumable`` is
        transmitted as "1"/"0" (C parity)."""
        return self._fed("SCHEMA.MIGRATE", schema_id, from_version, to_version,
                         "1" if resumable else "0")

    def schema_progress(self, schema_id: str, version: str, completed: int,
                        total: int) -> Reply:
        """FEDERATION SCHEMA.PROGRESS — report the resumable progress
        record."""
        return self._fed("SCHEMA.PROGRESS", schema_id, version,
                         _u64(completed, "completed"), _u64(total, "total"))

    def security_audit(self, service: str | None = None,
                       version: str | None = None) -> Reply:
        """FEDERATION SECURITY.AUDIT — the runtime self-audit report;
        service/version are optional filters (omitted when None)."""
        args: list[str] = []
        if service is not None:
            args.append(service)
        if version is not None:
            args.append(version)
        return self._fed("SECURITY.AUDIT", *args)

    def security_observe(self) -> Reply:
        """FEDERATION SECURITY.OBSERVE — the node's runtime observation
        (uid/gid/caps/core-dump/seccomp/listeners)."""
        return self._fed("SECURITY.OBSERVE")

    def security_ifaces(self) -> Reply:
        """FEDERATION SECURITY.IFACES — the kernel-interface
        classification."""
        return self._fed("SECURITY.IFACES")

    def security_profile_get(self, service: str, version: str) -> Reply:
        """FEDERATION SECURITY.PROFILE.GET — the declared runtime profile."""
        return self._fed("SECURITY.PROFILE.GET", service, version)

    def security_net_get(self, service: str, version: str) -> Reply:
        """FEDERATION SECURITY.NET.GET — the declared network profile."""
        return self._fed("SECURITY.NET.GET", service, version)
