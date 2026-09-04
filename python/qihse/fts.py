"""
QIHSE Full-Text Search (FTS) Index with BM25 & Neural Classification (ctypes binding).
"""

import ctypes
import os
from typing import List, Optional
from dataclasses import dataclass
from .neural import KeystoneClass

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


class _FTSIndex(ctypes.Structure):
    pass

_FTSIndex_p = ctypes.POINTER(_FTSIndex)


class _CFTSResult(ctypes.Structure):
    _fields_ = [
        ("doc_id", ctypes.c_uint64),
        ("bm25_score", ctypes.c_float),
        ("semantic_class", ctypes.c_int),
    ]


_lib.qihse_fts_create.argtypes = []
_lib.qihse_fts_create.restype = _FTSIndex_p

_lib.qihse_fts_destroy.argtypes = [_FTSIndex_p]
_lib.qihse_fts_destroy.restype = None

_lib.qihse_fts_add_document.argtypes = [
    _FTSIndex_p,
    ctypes.c_uint64,
    ctypes.c_char_p,
    ctypes.c_size_t,
    ctypes.c_uint16,
    ctypes.c_uint16,
    ctypes.c_int,
]
_lib.qihse_fts_add_document.restype = ctypes.c_bool

_lib.qihse_fts_search_user_filtered.argtypes = [
    _FTSIndex_p,
    ctypes.c_char_p,
    ctypes.c_void_p,
    ctypes.POINTER(_CFTSResult),
    ctypes.c_int,
    ctypes.c_uint8,
]
_lib.qihse_fts_search_user_filtered.restype = ctypes.c_int

_lib.qihse_fts_get_doc_semantic_class.argtypes = [_FTSIndex_p, ctypes.c_uint64]
_lib.qihse_fts_get_doc_semantic_class.restype = ctypes.c_int

_lib.qihse_fts_save.argtypes = [_FTSIndex_p, ctypes.c_char_p, ctypes.c_void_p]
_lib.qihse_fts_save.restype = ctypes.c_bool

_lib.qihse_fts_load.argtypes = [ctypes.c_char_p, ctypes.c_void_p]
_lib.qihse_fts_load.restype = _FTSIndex_p


@dataclass
class FTSResult:
    doc_id: int
    score: float
    semantic_class: KeystoneClass


class FTSIndex:
    """
    Trinary Trie Inverted Index with BM25 ranking, RBAC security filters,
    and 6-class Keystone neural semantic classification.
    """

    def __init__(self):
        self._ptr = _lib.qihse_fts_create()
        if not self._ptr:
            raise RuntimeError("Failed to create FTS index")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def close(self):
        if self._ptr:
            _lib.qihse_fts_destroy(self._ptr)
            self._ptr = None

    def __del__(self):
        self.close()

    @property
    def handle(self):
        return self._ptr

    def add_document(
        self,
        doc_id: int,
        text: str,
        classification: int = 0,
        sci_compartment: int = 0,
        semantic_class: KeystoneClass = KeystoneClass.UNKNOWN,
    ) -> bool:
        """
        Tokenizes and indexes a document with classification metadata.
        """
        encoded = text.encode("utf-8")
        return bool(
            _lib.qihse_fts_add_document(
                self._ptr,
                int(doc_id),
                encoded,
                len(encoded),
                int(classification),
                int(sci_compartment),
                int(semantic_class),
            )
        )

    def search(
        self,
        query: str,
        top_k: int = 10,
        semantic_mask: int = 0,
        user=None,
    ) -> List[FTSResult]:
        """
        Searches the FTS index using BM25 with optional neural class bitmask filtering.
        """
        if top_k <= 0:
            return []

        c_results = (_CFTSResult * top_k)()
        query_enc = query.encode("utf-8")
        found = _lib.qihse_fts_search_user_filtered(
            self._ptr,
            query_enc,
            user,
            c_results,
            top_k,
            ctypes.c_uint8(semantic_mask),
        )

        out = []
        for i in range(found):
            out.append(
                FTSResult(
                    doc_id=c_results[i].doc_id,
                    score=c_results[i].bm25_score,
                    semantic_class=KeystoneClass(c_results[i].semantic_class),
                )
            )
        return out

    def get_semantic_class(self, doc_id: int) -> KeystoneClass:
        """
        Retrieves the 6-class neural semantic class assigned to a document ID.
        """
        cls_val = _lib.qihse_fts_get_doc_semantic_class(self._ptr, int(doc_id))
        return KeystoneClass(cls_val)

    def save(self, filepath: str, user=None) -> bool:
        """Saves the FTS index to a binary file on disk.

        For unclassified indexes (all documents at classification=0), user
        may be None. For classified indexes, a user with sufficient clearance
        is required; the save is denied if any document exceeds the user's
        clearance.
        """
        return bool(_lib.qihse_fts_save(self._ptr, filepath.encode("utf-8"), user))

    @classmethod
    def load(cls, filepath: str, user=None) -> "FTSIndex":
        """Loads an FTS index from a binary file created by save().

        For unclassified files, user may be None. For classified files,
        a user with sufficient clearance is required; the load is denied
        if any document in the file exceeds the user's clearance.

        Returns a new FTSIndex instance. Raises RuntimeError if the file
        cannot be loaded or authorization is denied.
        """
        ptr = _lib.qihse_fts_load(filepath.encode("utf-8"), user)
        if not ptr:
            raise RuntimeError(f"Failed to load FTS index from {filepath}")
        obj = cls.__new__(cls)
        obj._ptr = ptr
        return obj
