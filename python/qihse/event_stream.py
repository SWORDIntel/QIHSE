"""
QIHSE Event Stream Python bindings (ctypes-based).

Record-framed commit log with SHA-384 integrity, durability modes,
replay, torn-tail recovery, and duplicate event-ID rejection.

Usage:
    import qihse

    es = qihse.EventStream("/tmp/qihse_events")
    es.append("bgp_updates", b'{"prefix":"1.2.3.0/24","asn":64512}')
    es.append_record("bgp_updates", schema_id=2,
                     event_id=bytes(48),
                     payload=b'{"prefix":"1.2.3.0/24","asn":64512}')

    # Iterate
    for record in es.iterate("bgp_updates"):
        print(record.schema_id, record.payload)

    # Replay after restart
    count = es.replay("bgp_updates", callback=lambda r: print(r.payload))

    # Torn-tail recovery
    es.truncate_torn_tail("bgp_updates")
"""

import ctypes
import hashlib
import os
from enum import IntEnum
from typing import Iterator, Optional, Callable, NamedTuple, Sequence
from .core import _lib

# ctypes has no free(); libc does (same idiom as core.py/kv.py)
_libc = ctypes.CDLL(None)
_libc.free.argtypes = [ctypes.c_void_p]
_libc.free.restype = None

# ---------------------------------------------------------------------------
# C type definitions
# ---------------------------------------------------------------------------

class _EventStream(ctypes.Structure):
    pass

_EventStream_p = ctypes.POINTER(_EventStream)

# Record header: 88 bytes
class _RecordHeader(ctypes.Structure):
    _fields_ = [
        ("magic", ctypes.c_uint32),
        ("format_version", ctypes.c_uint32),
        ("flags", ctypes.c_uint32),
        ("schema_id", ctypes.c_uint32),
        ("stream_offset", ctypes.c_uint64),
        ("payload_size", ctypes.c_uint64),
        ("prev_record_offset", ctypes.c_uint64),
        ("event_id", ctypes.c_uint8 * 48),
    ]

_RecordHeader_p = ctypes.POINTER(_RecordHeader)

class _Scope(ctypes.Structure):
    _fields_ = [("topic", ctypes.c_char_p),
                ("classification", ctypes.c_uint16),
                ("sci", ctypes.c_uint16)]

class _BatchRecord(ctypes.Structure):
    _fields_ = [("schema_id", ctypes.c_uint32),
                ("event_id", ctypes.POINTER(ctypes.c_uint8)),
                ("payload", ctypes.POINTER(ctypes.c_uint8)),
                ("payload_size", ctypes.c_size_t)]

class _BatchResult(ctypes.Structure):
    _fields_ = [("stream_offset", ctypes.c_uint64),
                ("duplicate", ctypes.c_bool)]

class _ReadRecord(ctypes.Structure):
    _fields_ = [("header", _RecordHeader),
                ("payload", ctypes.POINTER(ctypes.c_uint8)),
                ("payload_size", ctypes.c_size_t)]

# Durability enum
class Durability(IntEnum):
    NONE = 0
    FDATASYNC = 1
    FULL = 2

# Constants
EVENT_ID_SIZE = 48
RECORD_HEADER_SIZE = 88
F_COMMITTED = 0x01
F_CORRUPT = 0x02

# ---------------------------------------------------------------------------
# C function signatures
# ---------------------------------------------------------------------------

_lib.qihse_event_stream_create.argtypes = [ctypes.c_char_p]
_lib.qihse_event_stream_create.restype = _EventStream_p

_lib.qihse_event_stream_open.argtypes = [ctypes.c_char_p, ctypes.c_uint32, ctypes.c_bool]
_lib.qihse_event_stream_open.restype = _EventStream_p

_lib.qihse_event_stream_destroy.argtypes = [_EventStream_p]
_lib.qihse_event_stream_destroy.restype = None

_lib.qihse_event_stream_flush.argtypes = [_EventStream_p]
_lib.qihse_event_stream_flush.restype = ctypes.c_bool

_lib.qihse_event_stream_append.argtypes = [_EventStream_p, ctypes.c_char_p,
                                             ctypes.c_char_p, ctypes.c_size_t]
_lib.qihse_event_stream_append.restype = ctypes.c_bool

_lib.qihse_event_stream_append_record.argtypes = [
    _EventStream_p, ctypes.c_char_p, ctypes.c_uint32,
    ctypes.c_char_p,  # event_id (48 bytes)
    ctypes.c_char_p, ctypes.c_size_t  # payload
]
_lib.qihse_event_stream_append_record.restype = ctypes.c_uint64

_lib.qihse_event_stream_read.argtypes = [
    _EventStream_p, ctypes.c_char_p, ctypes.c_uint64,
    _RecordHeader_p, ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_size_t)
]
_lib.qihse_event_stream_read.restype = ctypes.c_bool

_lib.qihse_event_stream_iterate.argtypes = [
    _EventStream_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_uint64),
    _RecordHeader_p, ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_size_t)
]
_lib.qihse_event_stream_iterate.restype = ctypes.c_bool

_lib.qihse_event_stream_length.argtypes = [_EventStream_p, ctypes.c_char_p]
_lib.qihse_event_stream_length.restype = ctypes.c_uint64

_lib.qihse_event_stream_has_event_id.argtypes = [
    _EventStream_p, ctypes.c_char_p, ctypes.c_char_p
]
_lib.qihse_event_stream_has_event_id.restype = ctypes.c_bool

_lib.qihse_event_stream_truncate_torn_tail.argtypes = [_EventStream_p, ctypes.c_char_p]
_lib.qihse_event_stream_truncate_torn_tail.restype = ctypes.c_bool

_lib.qihse_event_stream_consume_zero_copy.argtypes = [
    _EventStream_p, ctypes.c_char_p, ctypes.c_uint64, ctypes.c_int, ctypes.c_size_t
]
_lib.qihse_event_stream_consume_zero_copy.restype = ctypes.c_bool

_lib.qihse_event_stream_append_batch.argtypes = [
    _EventStream_p, ctypes.c_void_p, ctypes.POINTER(_Scope),
    ctypes.POINTER(_BatchRecord), ctypes.c_size_t, ctypes.POINTER(_BatchResult),
]
_lib.qihse_event_stream_append_batch.restype = ctypes.c_bool
_lib.qihse_event_stream_read_batch.argtypes = [
    _EventStream_p, ctypes.c_void_p, ctypes.POINTER(_Scope),
    ctypes.POINTER(ctypes.c_uint64), ctypes.POINTER(_ReadRecord), ctypes.c_size_t,
    ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t),
]
_lib.qihse_event_stream_read_batch.restype = ctypes.c_bool
_lib.qihse_event_stream_batch_free.argtypes = [ctypes.POINTER(_ReadRecord), ctypes.c_size_t]
_lib.qihse_event_stream_batch_free.restype = None
_lib.qihse_event_stream_archive_id.argtypes = [
    ctypes.c_void_p, ctypes.c_size_t, ctypes.c_char_p, ctypes.c_uint32,
    ctypes.POINTER(ctypes.c_uint8),
]
_lib.qihse_event_stream_archive_id.restype = ctypes.c_bool
_lib.qihse_event_stream_member_id.argtypes = [
    ctypes.POINTER(ctypes.c_uint8), ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint32,
    ctypes.POINTER(ctypes.c_uint8),
]
_lib.qihse_event_stream_member_id.restype = ctypes.c_bool


# ---------------------------------------------------------------------------
# Python wrapper classes
# ---------------------------------------------------------------------------

class EventScope(NamedTuple):
    """Tenant is derived from ``user``; class/SCI are explicit scope labels."""
    topic: str
    classification: int
    sci: int


class EventRecord:
    """A record read from the event stream."""
    __slots__ = ("schema_id", "stream_offset", "payload_size",
                 "prev_record_offset", "event_id", "payload", "flags")

    def __init__(self, header: _RecordHeader, payload: bytes):
        self.schema_id = header.schema_id
        self.stream_offset = header.stream_offset
        self.payload_size = header.payload_size
        self.prev_record_offset = header.prev_record_offset
        self.event_id = bytes(header.event_id)
        self.payload = payload
        self.flags = header.flags

    @property
    def is_committed(self) -> bool:
        return bool(self.flags & F_COMMITTED)

    @property
    def is_corrupt(self) -> bool:
        return bool(self.flags & F_CORRUPT)

    def __repr__(self) -> str:
        return (f"EventRecord(schema_id={self.schema_id}, "
                f"offset={self.stream_offset}, "
                f"size={self.payload_size}, "
                f"committed={self.is_committed})")


class EventStream:
    """
    QIHSE Event Stream — a record-framed commit log with SHA-384 integrity,
    durability modes, replay, torn-tail recovery, and duplicate event-ID rejection.

    Args:
        log_directory: Path to store immutable topic log files.
        durability: Durability mode (NONE, FDATASYNC, or FULL).
        read_only: Open in read-only mode (rejects writes).
    """

    def __init__(self, log_directory: str,
                 durability: Durability = Durability.FDATASYNC,
                 read_only: bool = False):
        self._ptr = _lib.qihse_event_stream_open(
            log_directory.encode("utf-8"),
            ctypes.c_uint32(int(durability)),
            ctypes.c_bool(read_only)
        )
        if not self._ptr:
            raise RuntimeError(f"Failed to open event stream at {log_directory}")
        self._read_only = read_only

    @classmethod
    def create(cls, log_directory: str) -> "EventStream":
        """Create an event stream with default (FDATASYNC) durability."""
        return cls(log_directory, Durability.FDATASYNC, False)

    def close(self):
        if self._ptr:
            _lib.qihse_event_stream_destroy(self._ptr)
            self._ptr = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def flush(self) -> bool:
        return _lib.qihse_event_stream_flush(self._ptr)

    def append(self, topic: str, payload: bytes) -> bool:
        """Append a record. Event ID is computed as SHA-384(topic || payload)."""
        if self._read_only:
            raise PermissionError("EventStream is read-only")
        return _lib.qihse_event_stream_append(
            self._ptr, topic.encode("utf-8"), payload, len(payload)
        )

    def append_record(self, topic: str, schema_id: int,
                      event_id: bytes, payload: bytes) -> Optional[int]:
        """Append a V1 record; return its physical byte offset or ``None`` on failure.

        The native C ABI retains its historical offset-plus-one return encoding; this
        Python method normalizes successful offsets (including offset zero).
        """
        if self._read_only:
            raise PermissionError("EventStream is read-only")
        if len(event_id) != EVENT_ID_SIZE:
            raise ValueError(f"event_id must be {EVENT_ID_SIZE} bytes, got {len(event_id)}")
        offset_plus_one = _lib.qihse_event_stream_append_record(
            self._ptr, topic.encode("utf-8"), ctypes.c_uint32(schema_id),
            event_id, payload, len(payload)
        )
        return int(offset_plus_one - 1) if offset_plus_one else None

    def append_batch(self, scope: EventScope, records: Sequence[dict], *, user) -> list:
        """Append a bounded authenticated V2 batch; ``user`` must be an active native principal.

        Each record mapping has ``schema_id``, ``payload`` and optional 48-byte ``event_id``.
        Duplicate IDs are idempotent only for identical schema and payload. A conflicting ID
        raises ``RuntimeError``; no scoped read/write path accepts a missing user context.
        """
        if self._read_only:
            raise PermissionError("EventStream is read-only")
        if user is None:
            raise ValueError("scoped event batches require an authenticated user")
        if not isinstance(scope, EventScope):
            scope = EventScope(*scope)
        c_scope = _Scope(scope.topic.encode("utf-8"), int(scope.classification), int(scope.sci))
        native_records = (_BatchRecord * len(records))()
        native_results = (_BatchResult * len(records))()
        keepalive = []
        for i, item in enumerate(records):
            payload = bytes(item["payload"])
            event_id = item.get("event_id")
            if event_id is not None:
                event_id = bytes(event_id)
                if len(event_id) != EVENT_ID_SIZE:
                    raise ValueError(f"event_id must be {EVENT_ID_SIZE} bytes")
                id_buf = (ctypes.c_uint8 * EVENT_ID_SIZE).from_buffer_copy(event_id)
                keepalive.append(id_buf)
                id_ptr = ctypes.cast(id_buf, ctypes.POINTER(ctypes.c_uint8))
            else:
                id_ptr = ctypes.POINTER(ctypes.c_uint8)()
            if payload:
                payload_buf = (ctypes.c_uint8 * len(payload)).from_buffer_copy(payload)
                keepalive.append(payload_buf)
                payload_ptr = ctypes.cast(payload_buf, ctypes.POINTER(ctypes.c_uint8))
            else:
                payload_ptr = ctypes.POINTER(ctypes.c_uint8)()
            native_records[i] = _BatchRecord(int(item["schema_id"]), id_ptr,
                                             payload_ptr, len(payload))
        if not _lib.qihse_event_stream_append_batch(
                self._ptr, user, ctypes.byref(c_scope), native_records,
                len(records), native_results):
            raise RuntimeError("authenticated event batch rejected or durability failed")
        return [(int(r.stream_offset), bool(r.duplicate)) for r in native_results]

    def read_batch(self, scope: EventScope, cursor: int = 0, *, user,
                   capacity: int = 256, max_payload_bytes: int = 4 * 1024 * 1024):
        """Read a bounded authenticated page; returns ``(records, next_byte_cursor)``."""
        if user is None:
            raise ValueError("scoped event reads require an authenticated user")
        if not isinstance(scope, EventScope):
            scope = EventScope(*scope)
        if capacity <= 0:
            raise ValueError("capacity must be positive")
        c_scope = _Scope(scope.topic.encode("utf-8"), int(scope.classification), int(scope.sci))
        native = (_ReadRecord * capacity)()
        c_cursor = ctypes.c_uint64(cursor)
        count = ctypes.c_size_t()
        if not _lib.qihse_event_stream_read_batch(
                self._ptr, user, ctypes.byref(c_scope), ctypes.byref(c_cursor), native,
                capacity, max_payload_bytes, ctypes.byref(count)):
            raise RuntimeError("authenticated event batch read failed")
        try:
            result = []
            for i in range(count.value):
                row = native[i]
                payload = ctypes.string_at(row.payload, row.payload_size) if row.payload_size else b""
                result.append(EventRecord(row.header, payload))
            return result, int(c_cursor.value)
        finally:
            _lib.qihse_event_stream_batch_free(native, count.value)

    def read(self, topic: str, stream_offset: int) -> Optional[EventRecord]:
        """Read a single record by stream offset."""
        header = _RecordHeader()
        payload_ptr = ctypes.c_void_p()
        payload_size = ctypes.c_size_t(0)
        ok = _lib.qihse_event_stream_read(
            self._ptr, topic.encode("utf-8"), ctypes.c_uint64(stream_offset),
            ctypes.byref(header), ctypes.byref(payload_ptr), ctypes.byref(payload_size)
        )
        if not ok:
            return None
        payload = ctypes.string_at(payload_ptr, payload_size.value) if payload_ptr and payload_size.value > 0 else b""
        if payload_ptr:
            _libc.free(payload_ptr)
        return EventRecord(header, payload)

    def iterate(self, topic: str) -> Iterator[EventRecord]:
        """Iterate over all committed records in a topic."""
        cursor = ctypes.c_uint64(0)
        header = _RecordHeader()
        payload_ptr = ctypes.c_void_p()
        payload_size = ctypes.c_size_t(0)
        while _lib.qihse_event_stream_iterate(
            self._ptr, topic.encode("utf-8"), ctypes.byref(cursor),
            ctypes.byref(header), ctypes.byref(payload_ptr), ctypes.byref(payload_size)
        ):
            payload = ctypes.string_at(payload_ptr, payload_size.value) if payload_ptr and payload_size.value > 0 else b""
            if payload_ptr:
                _libc.free(payload_ptr)
            yield EventRecord(header, payload)

    def length(self, topic: str) -> int:
        """Get the current byte length of a topic log."""
        return _lib.qihse_event_stream_length(self._ptr, topic.encode("utf-8"))

    def has_event_id(self, topic: str, event_id: bytes) -> bool:
        """Check if an event ID exists in the topic."""
        if len(event_id) != EVENT_ID_SIZE:
            raise ValueError(f"event_id must be {EVENT_ID_SIZE} bytes, got {len(event_id)}")
        return _lib.qihse_event_stream_has_event_id(
            self._ptr, topic.encode("utf-8"), event_id
        )

    def replay(self, topic: str,
               callback: Callable[[EventRecord], bool]) -> int:
        """
        Replay all committed records in order.
        Callback receives an EventRecord and returns True to continue, False to stop.
        Returns the number of records replayed.
        """
        count = 0
        for record in self.iterate(topic):
            count += 1
            if not callback(record):
                break
        return count

    def truncate_torn_tail(self, topic: str) -> bool:
        """Truncate any uncommitted (torn) tail records after the last valid commit."""
        if self._read_only:
            raise PermissionError("EventStream is read-only")
        return _lib.qihse_event_stream_truncate_torn_tail(
            self._ptr, topic.encode("utf-8")
        )

    def consume_zero_copy(self, topic: str, offset: int,
                          socket_fd: int, count: int) -> bool:
        """
        Stream log data directly to a network socket using zero-copy sendfile.
        The CPU does not touch the payload.
        """
        return _lib.qihse_event_stream_consume_zero_copy(
            self._ptr, topic.encode("utf-8"),
            ctypes.c_uint64(offset), ctypes.c_int(socket_fd),
            ctypes.c_size_t(count)
        )

    @staticmethod
    def compute_archive_id(archive: bytes, scan_version: str, schema_id: int) -> bytes:
        """Return the stable archive SHA-384 identity bound to scan/schema version."""
        data = bytes(archive)
        buffer = (ctypes.c_uint8 * EVENT_ID_SIZE)()
        source = (ctypes.c_uint8 * len(data)).from_buffer_copy(data) if data else None
        if not _lib.qihse_event_stream_archive_id(source, len(data), scan_version.encode("utf-8"),
                                                   int(schema_id), buffer):
            raise ValueError("archive identity inputs rejected")
        return bytes(buffer)

    @staticmethod
    def compute_member_id(archive_id: bytes, member_name: str,
                          scan_version: str, schema_id: int) -> bytes:
        """Return member identity bound to archive ID, exact name, scan and schema versions."""
        archive = bytes(archive_id)
        if len(archive) != EVENT_ID_SIZE:
            raise ValueError(f"archive_id must be {EVENT_ID_SIZE} bytes")
        source = (ctypes.c_uint8 * EVENT_ID_SIZE).from_buffer_copy(archive)
        buffer = (ctypes.c_uint8 * EVENT_ID_SIZE)()
        if not _lib.qihse_event_stream_member_id(source, member_name.encode("utf-8"),
                                                  scan_version.encode("utf-8"),
                                                  int(schema_id), buffer):
            raise ValueError("member identity inputs rejected")
        return bytes(buffer)

    @staticmethod
    def compute_event_id(topic: str, payload: bytes) -> bytes:
        """Compute SHA-384(topic || payload) — the default event ID."""
        h = hashlib.sha384()
        h.update(topic.encode("utf-8"))
        h.update(payload)
        return h.digest()
