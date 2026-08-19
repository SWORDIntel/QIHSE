"""
QIHSE Keystone Neural Micro-Model Context Classifier (ctypes binding).
"""

import ctypes
import os
from enum import IntEnum
from typing import Tuple

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


class KeystoneClass(IntEnum):
    UNKNOWN = 0
    FINANCIAL = 1
    CORPORATE = 2
    GOVERNMENT = 3
    INFRASTRUCTURE = 4
    CONSUMER = 5


_lib.qihse_keystone_classify_context.argtypes = [
    ctypes.c_char_p,
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_int),
    ctypes.POINTER(ctypes.c_float),
]
_lib.qihse_keystone_classify_context.restype = None

_lib.qihse_keystone_class_name.argtypes = [ctypes.c_int]
_lib.qihse_keystone_class_name.restype = ctypes.c_char_p


class NeuralClassifier:
    """
    Real-time 6-class neural micro-model classifier (260->64->6 Feedforward).
    Runs sub-3-microsecond inference in pure C without heap allocations.
    """

    @staticmethod
    def classify(context: str) -> Tuple[KeystoneClass, str, float]:
        """
        Classifies input context text into one of 6 semantic classes.
        Returns (class_enum, class_name, confidence).
        """
        encoded = context.encode("utf-8")
        cls_val = ctypes.c_int(0)
        conf_val = ctypes.c_float(0.0)

        _lib.qihse_keystone_classify_context(
            encoded,
            len(encoded),
            ctypes.byref(cls_val),
            ctypes.byref(conf_val),
        )

        cls_enum = KeystoneClass(cls_val.value)
        name = _lib.qihse_keystone_class_name(cls_val.value).decode("utf-8")
        return cls_enum, name, float(conf_val.value)
