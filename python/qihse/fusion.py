"""
QIHSE Multimodal Reciprocal Rank Fusion (RRF) with Neural Semantic Masking (ctypes binding).
"""

import ctypes
import os
import numpy as np
from typing import List, Optional
from dataclasses import dataclass
from .neural import KeystoneClass
from .fts import FTSIndex

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


class _CMultimodalQuery(ctypes.Structure):
    _fields_ = [
        ("vector", ctypes.POINTER(ctypes.c_float)),
        ("dim", ctypes.c_size_t),
        ("modality", ctypes.c_char_p),
        ("weight", ctypes.c_float),
    ]


class _CMultimodalRequest(ctypes.Structure):
    _fields_ = [
        ("queries", ctypes.POINTER(_CMultimodalQuery)),
        ("num_queries", ctypes.c_size_t),
        ("top_k", ctypes.c_int),
        ("user", ctypes.c_void_p),
        ("fts_index", ctypes.c_void_p),
        ("fts_query", ctypes.c_char_p),
        ("fts_weight", ctypes.c_float),
        ("semantic_class_mask", ctypes.c_uint8),
    ]


class _CFusionResult(ctypes.Structure):
    _fields_ = [
        ("id", ctypes.c_uint64),
        ("score", ctypes.c_float),
        ("semantic_class", ctypes.c_int),
    ]


_lib.qihse_vector_db_search_multimodal.argtypes = [
    ctypes.c_void_p,
    ctypes.POINTER(_CMultimodalRequest),
    ctypes.POINTER(ctypes.c_size_t),
]
_lib.qihse_vector_db_search_multimodal.restype = ctypes.POINTER(_CFusionResult)


@dataclass
class FusionResult:
    id: int
    score: float
    semantic_class: KeystoneClass


class MultimodalFusion:
    """
    Unified Reciprocal Rank Fusion (RRF) combining vector search modalities with FTS BM25
    and applying 6-class neural classification filters in-process.
    """

    @staticmethod
    def search(
        vector_db,
        vector_queries: List[dict],
        top_k: int = 10,
        fts_index: Optional[FTSIndex] = None,
        fts_query: Optional[str] = None,
        fts_weight: float = 1.0,
        semantic_mask: int = 0,
        user=None,
    ) -> List[FusionResult]:
        """
        Executes hybrid fusion across all modalities.
        vector_queries: list of dicts with keys: {'vector': np.ndarray, 'modality': str, 'weight': float}
        """
        c_queries = (_CMultimodalQuery * len(vector_queries))()
        keep_alive = []

        for idx, q in enumerate(vector_queries):
            vec = q["vector"]
            if not isinstance(vec, np.ndarray) or vec.dtype != np.float32:
                vec = np.array(vec, dtype=np.float32)
            if not vec.flags.c_contiguous:
                vec = np.ascontiguousarray(vec)

            keep_alive.append(vec)
            c_queries[idx].vector = vec.ctypes.data_as(ctypes.POINTER(ctypes.c_float))
            c_queries[idx].dim = len(vec)
            mod_b = q.get("modality", "text").encode("utf-8")
            keep_alive.append(mod_b)
            c_queries[idx].modality = mod_b
            c_queries[idx].weight = float(q.get("weight", 1.0))

        req = _CMultimodalRequest()
        req.queries = c_queries
        req.num_queries = len(vector_queries)
        req.top_k = top_k
        req.user = ctypes.cast(user, ctypes.c_void_p) if user else None
        req.fts_index = ctypes.cast(fts_index.handle, ctypes.c_void_p) if fts_index else None

        fts_b = fts_query.encode("utf-8") if fts_query else None
        req.fts_query = fts_b
        req.fts_weight = float(fts_weight)
        req.semantic_class_mask = ctypes.c_uint8(semantic_mask)

        out_count = ctypes.c_size_t(0)
        vdb_handle = getattr(vector_db, "_ptr", getattr(vector_db, "_handle", None))

        res_ptr = _lib.qihse_vector_db_search_multimodal(
            vdb_handle,
            ctypes.byref(req),
            ctypes.byref(out_count),
        )

        results = []
        if res_ptr:
            try:
                for i in range(out_count.value):
                    results.append(
                        FusionResult(
                            id=res_ptr[i].id,
                            score=res_ptr[i].score,
                            semantic_class=KeystoneClass(res_ptr[i].semantic_class),
                        )
                    )
            finally:
                libc = ctypes.CDLL(None)
                libc.free(res_ptr)

        return results
