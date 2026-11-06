#!/usr/bin/env python3
"""Measure production-style Zstd streaming on an authenticated CodeGraph KV export.

The input must have been exported by the authenticated CodeGraph/SDK path. This
benchmark reads only that explicit export; it never opens configured KV storage.
"""

import argparse
import ctypes as c
import hashlib
import json
import statistics
import struct
import time
from pathlib import Path


class Buffer(c.Structure):
    _fields_ = [("src", c.c_void_p), ("size", c.c_size_t), ("pos", c.c_size_t)]


def zstd_library():
    lib = c.CDLL("libzstd.so.1")
    lib.ZSTD_versionString.restype = c.c_char_p
    lib.ZSTD_createCCtx.restype = c.c_void_p
    lib.ZSTD_freeCCtx.argtypes = [c.c_void_p]
    lib.ZSTD_CCtx_setParameter.argtypes = [c.c_void_p, c.c_int, c.c_int]
    lib.ZSTD_CCtx_setParameter.restype = c.c_size_t
    lib.ZSTD_CCtx_setPledgedSrcSize.argtypes = [c.c_void_p, c.c_ulonglong]
    lib.ZSTD_CCtx_setPledgedSrcSize.restype = c.c_size_t
    lib.ZSTD_compressStream2.argtypes = [c.c_void_p, c.POINTER(Buffer), c.POINTER(Buffer), c.c_int]
    lib.ZSTD_compressStream2.restype = c.c_size_t
    lib.ZSTD_decompress.argtypes = [c.c_void_p, c.c_size_t, c.c_void_p, c.c_size_t]
    lib.ZSTD_decompress.restype = c.c_size_t
    lib.ZSTD_isError.argtypes = [c.c_size_t]
    lib.ZSTD_isError.restype = c.c_uint
    lib.ZSTD_getErrorName.argtypes = [c.c_size_t]
    lib.ZSTD_getErrorName.restype = c.c_char_p
    return lib


def checked(lib, result):
    if lib.ZSTD_isError(result):
        raise RuntimeError(lib.ZSTD_getErrorName(result).decode())
    return result


def compress(lib, source, size, level, window_log, ldm):
    ctx = lib.ZSTD_createCCtx()
    if not ctx:
        raise MemoryError("ZSTD_createCCtx")
    try:
        for parameter, value in ((100, level), (101, window_log), (160, int(ldm)), (201, 1)):
            checked(lib, lib.ZSTD_CCtx_setParameter(ctx, parameter, value))
        checked(lib, lib.ZSTD_CCtx_setPledgedSrcSize(ctx, size))
        output = c.create_string_buffer(65536)
        encoded = bytearray()
        offset = 0
        while True:
            count = min(65536, size - offset)
            incoming = Buffer(c.addressof(source) + offset, count, 0)
            mode = 2 if count < 65536 else 0  # ZSTD_e_end / ZSTD_e_continue
            while True:
                outgoing = Buffer(c.addressof(output), 65536, 0)
                remaining = checked(lib, lib.ZSTD_compressStream2(ctx, c.byref(outgoing), c.byref(incoming), mode))
                encoded.extend(output.raw[: outgoing.pos])
                if incoming.pos == incoming.size and (mode != 2 or remaining == 0):
                    break
            offset += count
            if mode == 2:
                break
        return b"QCGZ0001" + struct.pack(">Q", size) + encoded
    finally:
        lib.ZSTD_freeCCtx(ctx)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--authenticated-export", required=True, type=Path)
    parser.add_argument("--receipt", required=True, type=Path)
    parser.add_argument("--repeats", type=int, default=3)
    args = parser.parse_args()
    if args.repeats < 1:
        parser.error("--repeats must be positive")
    raw = args.authenticated_export.read_bytes()
    if not raw:
        parser.error("export is empty")
    lib = zstd_library()
    source = c.create_string_buffer(raw)
    decoded = c.create_string_buffer(len(raw))
    expected_sha = hashlib.sha256(raw).hexdigest()
    # A window 24 setting can produce a window >23 on larger exports, which the
    # current CodeGraph decoder rejects. The small fixture may not exercise it.
    configs = [
        ("baseline", 9, 23, False),
        ("level12", 12, 23, False),
        ("level15", 15, 23, False),
        ("level19", 19, 23, False),
        ("level22", 22, 23, False),
        ("window20", 9, 20, False),
        ("window24", 9, 24, False),
        ("ldm23", 9, 23, True),
        ("ldm24", 9, 24, True),
    ]
    runs = []
    for round_no in range(args.repeats):
        order = configs if round_no % 2 == 0 else list(reversed(configs))
        for name, level, window, ldm in order:
            wall_start = time.perf_counter()
            cpu_start = time.process_time()
            container = compress(lib, source, len(raw), level, window, ldm)
            encode_cpu = time.process_time() - cpu_start
            encode_wall = time.perf_counter() - wall_start
            assert container[:8] == b"QCGZ0001"
            assert struct.unpack(">Q", container[8:16])[0] == len(raw)
            frame = c.create_string_buffer(container[16:])
            decode_start = time.perf_counter()
            length = checked(lib, lib.ZSTD_decompress(decoded, len(raw), frame, len(container) - 16))
            decode_wall = time.perf_counter() - decode_start
            actual_sha = hashlib.sha256(decoded.raw[:length]).hexdigest()
            if length != len(raw) or actual_sha != expected_sha:
                raise AssertionError(f"lossy round trip: {name}")
            item = {
                "round": round_no + 1,
                "configuration": name,
                "level": level,
                "window_log": window,
                "long_distance_matching": ldm,
                "guaranteed_current_decoder_compatible": window <= 23,
                "container_bytes": len(container),
                "encode_cpu_seconds": round(encode_cpu, 6),
                "encode_wall_seconds": round(encode_wall, 6),
                "decode_wall_seconds": round(decode_wall, 6),
                "decoded_sha256": actual_sha,
            }
            runs.append(item)
            print(json.dumps(item), flush=True)
    medians = {}
    for name, _, _, _ in configs:
        subset = [item for item in runs if item["configuration"] == name]
        medians[name] = {
            key: statistics.median(item[key] for item in subset)
            for key in ("container_bytes", "encode_cpu_seconds", "encode_wall_seconds", "decode_wall_seconds")
        }
    receipt = {
        "fixture": "authenticated-800-node-2400-edge-synthetic-CodeGraph-KV-export",
        "raw_bytes": len(raw),
        "raw_sha256": expected_sha,
        "zstd_version": lib.ZSTD_versionString().decode(),
        "production_comparator": "level9-window23-checksum-stream64KiB-16ByteHeader",
        "runs": runs,
        "medians": medians,
    }
    args.receipt.parent.mkdir(parents=True, exist_ok=True)
    args.receipt.write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps({"medians": medians}), flush=True)


if __name__ == "__main__":
    main()
