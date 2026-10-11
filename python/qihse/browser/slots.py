"""Redis-compatible CRC16 slot math (XMODEM/CCITT, 16384 slots).

Local computation avoids a round trip per key; vectors are pinned against
the server's CLUSTER KEYSLOT in python/tests/test_browser_slots.py.
"""

SLOT_COUNT = 16384

_CRC16_TABLE = []


def _build_table():
    for i in range(256):
        crc = i << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) if (crc & 0x8000) else (crc << 1)
            crc &= 0xFFFF
        _CRC16_TABLE.append(crc)


_build_table()


def crc16(data: bytes) -> int:
    crc = 0
    for byte in data:
        crc = ((crc << 8) & 0xFFFF) ^ _CRC16_TABLE[(crc >> 8) ^ byte]
    return crc


def hash_tag(key: bytes) -> bytes:
    """Return the hashed substring: the first {…} block when a well-formed
    hash tag exists, otherwise the whole key (Redis semantics)."""
    start = key.find(b"{")
    if start != -1:
        end = key.find(b"}", start + 1)
        if end != -1 and end > start + 1:
            return key[start + 1:end]
    return key


def keyslot(key) -> int:
    if isinstance(key, str):
        key = key.encode("utf-8", "surrogateescape")
    return crc16(hash_tag(key)) % SLOT_COUNT
