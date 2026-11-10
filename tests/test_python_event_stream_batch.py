import ctypes
import os
from pathlib import Path

from qihse import (DocumentSourceRef, DurableReceipt, EventScope, EventStream,
                   ExtendedKnowledgeVersion, KnowledgeProvenance,
                   KnowledgeRelation, RecallMode)
from qihse.core import _lib


def main():
    # The package-root lazy exports must cover the public AIMEM model types.
    assert all(value is not None for value in (
        DocumentSourceRef, DurableReceipt, ExtendedKnowledgeVersion,
        KnowledgeProvenance, KnowledgeRelation, RecallMode))
    password = b"PythonEventStreamOperator1!"
    _lib.qihse_auth_init.argtypes = []
    _lib.qihse_auth_init.restype = ctypes.c_bool
    _lib.qihse_auth_bootstrap_operator.argtypes = [ctypes.c_char_p]
    _lib.qihse_auth_bootstrap_operator.restype = ctypes.c_bool
    _lib.qihse_auth_authenticate_id.argtypes = [ctypes.c_uint32, ctypes.c_char_p]
    _lib.qihse_auth_authenticate_id.restype = ctypes.c_void_p

    assert _lib.qihse_auth_init()
    assert _lib.qihse_auth_bootstrap_operator(password)
    user = _lib.qihse_auth_authenticate_id(0, password)
    assert user

    root = Path(os.environ["QIHSE_EVENT_STREAM_TEST_DIR"])
    stream = EventStream(str(root / "events"))
    scope = EventScope("python-firmware", 0, 0)

    # Reject narrowing and oversize batches before entering the native ABI.
    for bad_scope in (EventScope("python-firmware", 65536, 0),
                      EventScope("python-firmware", 0, -1),
                      EventScope("python-firmware", True, 0),
                      EventScope("python-firmware\0other", 0, 0)):
        try:
            stream.append_batch(bad_scope, [{"schema_id": 1, "payload": b"x"}], user=user)
        except ValueError:
            pass
        else:
            raise AssertionError("invalid EventScope was accepted")
    for bad_records in ([{"schema_id": 1, "payload": 100_000_000}],
                        [{"schema_id": 1, "payload": b""}] * 1025):
        try:
            stream.append_batch(scope, bad_records, user=user)
        except (TypeError, ValueError):
            pass
        else:
            raise AssertionError("invalid/oversized event batch was accepted")
    try:
        stream.read_batch(scope, user=user, capacity=1025)
    except ValueError:
        pass
    else:
        raise AssertionError("oversized read capacity was accepted")
    event_id = bytes(range(48))
    appended = stream.append_batch(scope, [
        {"schema_id": 3, "event_id": event_id, "payload": b"archive"},
        {"schema_id": 3, "payload": memoryview(b"member")},
    ], user=user)
    assert appended[0] == (0, False)
    assert appended[1][1] is False
    retry = stream.append_batch(scope, [
        {"schema_id": 3, "event_id": event_id, "payload": b"archive"},
    ], user=user)
    assert retry == [(0, True)]

    page, cursor = stream.read_batch(scope, user=user, capacity=1, max_payload_bytes=128)
    assert len(page) == 1 and page[0].payload == b"archive" and page[0].stream_offset == 0
    final, cursor = stream.read_batch(scope, cursor, user=user, capacity=2,
                                      max_payload_bytes=128)
    assert len(final) == 1 and final[0].payload == b"member"
    end, _ = stream.read_batch(scope, cursor, user=user, capacity=2, max_payload_bytes=128)
    assert end == []

    legacy_payload = b"legacy record"
    legacy_offset = stream.append_record(
        "python-v1", 1, EventStream.compute_event_id("python-v1", legacy_payload), legacy_payload)
    assert legacy_offset == 0

    archive_id = EventStream.compute_archive_id(b"firmware", "scanner-v3", 3)
    member_id = EventStream.compute_member_id(archive_id, "boot.bin", "scanner-v3", 3)
    assert len(archive_id) == len(member_id) == 48
    assert archive_id != EventStream.compute_archive_id(b"firmware", "scanner-v4", 3)
    stream.close()
    print("Python scoped event batch: append/retry/cursor/identity passed", flush=True)
    return 0


if __name__ == "__main__":
    # The native audit signer is process-scoped; terminate it with this test process.
    os._exit(main())
