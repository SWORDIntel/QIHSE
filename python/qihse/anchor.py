"""
QIHSE Keystone Anchor Spline Interpolation Search (ctypes binding).
"""

import ctypes
import os
import numpy as np
from typing import Union

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


_lib.qihse_keystone_anchor_lower_bound.argtypes = [
    ctypes.POINTER(ctypes.c_int64),
    ctypes.c_size_t,
    ctypes.c_int64,
]
_lib.qihse_keystone_anchor_lower_bound.restype = ctypes.c_size_t

_lib.qihse_keystone_anchor_search.argtypes = [
    ctypes.POINTER(ctypes.c_int64),
    ctypes.c_size_t,
    ctypes.c_int64,
]
_lib.qihse_keystone_anchor_search.restype = ctypes.c_int64


class AnchorIndex:
    """
    High-performance Keystone spline interpolation search over 1D sorted int64 arrays.
    Replaces O(log N) bisection with bounded spline prediction (down to 18ns in hot cache).
    """

    @staticmethod
    def lower_bound(arr: Union[np.ndarray, list], key: int) -> int:
        """
        Returns index of first element >= key in a sorted int64 array.
        """
        if not isinstance(arr, np.ndarray):
            arr = np.array(arr, dtype=np.int64)
        elif arr.dtype != np.int64:
            arr = arr.astype(np.int64)

        if not arr.flags.c_contiguous:
            arr = np.ascontiguousarray(arr)

        c_ptr = arr.ctypes.data_as(ctypes.POINTER(ctypes.c_int64))
        return int(_lib.qihse_keystone_anchor_lower_bound(c_ptr, len(arr), int(key)))

    @staticmethod
    def search(arr: Union[np.ndarray, list], key: int) -> int:
        """
        Returns index of exact match, or -1 if key is not found.
        """
        if not isinstance(arr, np.ndarray):
            arr = np.array(arr, dtype=np.int64)
        elif arr.dtype != np.int64:
            arr = arr.astype(np.int64)

        if not arr.flags.c_contiguous:
            arr = np.ascontiguousarray(arr)

        c_ptr = arr.ctypes.data_as(ctypes.POINTER(ctypes.c_int64))
        return int(_lib.qihse_keystone_anchor_search(c_ptr, len(arr), int(key)))
