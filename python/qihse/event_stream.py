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
from typing import Iterator, Optional, Callable
from .core import _lib

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


# ---------------------------------------------------------------------------
# Python wrapper classes
# ---------------------------------------------------------------------------

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
                      event_id: bytes, payload: bytes) -> int:
        """
        Append a record with explicit schema ID and event ID.
        Returns the stream offset, or 0 on failure (e.g. duplicate event ID).
        """
        if self._read_only:
            raise PermissionError("EventStream is read-only")
        if len(event_id) != EVENT_ID_SIZE:
            raise ValueError(f"event_id must be {EVENT_ID_SIZE} bytes, got {len(event_id)}")
        return _lib.qihse_event_stream_append_record(
            self._ptr, topic.encode("utf-8"), ctypes.c_uint32(schema_id),
            event_id, payload, len(payload)
        )

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
            ctypes.free(payload_ptr)
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
                ctypes.free(payload_ptr)
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
    def compute_event_id(topic: str, payload: bytes) -> bytes:
        """Compute SHA-384(topic || payload) — the default event ID."""
        h = hashlib.sha384()
        h.update(topic.encode("utf-8"))
        h.update(payload)
        return h.digest()
