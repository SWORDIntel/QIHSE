"""
QIHSE Hardware Backend Detection & Profiling (ctypes binding).
"""

import ctypes
import os
from dataclasses import dataclass

# Find libqihse.so
_LIB_PATHS = [
    os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "libqihse.so"),
    "/usr/local/lib/libqihse.so",
    "/usr/lib/libqihse.so",
]

_lib = None
for p in _LIB_PATHS:
    if os.path.exists(p):
        _lib = ctypes.CDLL(p)
        break

if _lib is None:
    raise ImportError("libqihse.so not found. Build with: make lib")


class _CacheTopology(ctypes.Structure):
    _fields_ = [
        ("cache_line_size", ctypes.c_uint32),
        ("_pad", ctypes.c_uint32),
        ("l1_data_size", ctypes.c_size_t),
        ("l2_size", ctypes.c_size_t),
        ("l3_size", ctypes.c_size_t),
        ("numa_nodes", ctypes.c_uint32),
        ("_pad2", ctypes.c_uint32),
    ]


class _HWProfile(ctypes.Structure):
    _fields_ = [
        ("cpu_features", ctypes.c_uint64),
        ("cache", _CacheTopology),
        ("sse42_available", ctypes.c_bool),
        ("avx_available", ctypes.c_bool),
        ("avx2_available", ctypes.c_bool),
        ("avx512_available", ctypes.c_bool),
        ("blas_available", ctypes.c_bool),
        ("_pad", ctypes.c_uint8 * 3),
        ("preferred", ctypes.c_int),
    ]


_lib.qihse_hw_profile_create.argtypes = []
_lib.qihse_hw_profile_create.restype = ctypes.POINTER(_HWProfile)

_lib.qihse_hw_profile_destroy.argtypes = [ctypes.POINTER(_HWProfile)]
_lib.qihse_hw_profile_destroy.restype = None

_lib.qihse_hw_backend_name.argtypes = [ctypes.c_int]
_lib.qihse_hw_backend_name.restype = ctypes.c_char_p


@dataclass
class HardwareProfile:
    preferred_backend: str
    avx: bool
    avx2: bool
    avx512: bool
    sse42: bool
    blas: bool
    l1_kb: int
    l2_kb: int
    l3_mb: float
    cache_line_bytes: int
    numa_nodes: int


class HardwareProfiler:
    """
    Probes host CPU SIMD features, cache hierarchy, and selects optimal math kernel dispatch.
    """

    @staticmethod
    def get_profile() -> HardwareProfile:
        ptr = _lib.qihse_hw_profile_create()
        if not ptr:
            raise RuntimeError("Failed to create hardware profile")
        try:
            hw = ptr.contents
            name = _lib.qihse_hw_backend_name(hw.preferred).decode("utf-8")
            return HardwareProfile(
                preferred_backend=name,
                avx=bool(hw.avx_available),
                avx2=bool(hw.avx2_available),
                avx512=bool(hw.avx512_available),
                sse42=bool(hw.sse42_available),
                blas=bool(hw.blas_available),
                l1_kb=int(hw.cache.l1_data_size // 1024),
                l2_kb=int(hw.cache.l2_size // 1024),
                l3_mb=float(hw.cache.l3_size / (1024 * 1024)),
                cache_line_bytes=int(hw.cache.cache_line_size),
                numa_nodes=int(hw.cache.numa_nodes),
            )
        finally:
            _lib.qihse_hw_profile_destroy(ptr)
