"""
QIHSE Python ctypes wrapper for libqihse.so vector database.
"""

import ctypes
import os
import sys
import numpy as np
from enum import IntEnum
from typing import List, Optional, Tuple, Union

# Find libqihse.so
_LIB_PATHS = [
    os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "libqihse.so"),
    os.path.join(os.getcwd(), "libqihse.so"),
    "libqihse.so",
]

_lib = None
for p in _LIB_PATHS:
    if os.path.exists(p):
        _lib = ctypes.CDLL(p)
        break

if _lib is None:
    raise ImportError("libqihse.so not found. Build with: make lib")


# ---------------------------------------------------------------------------
# C type aliases
# ---------------------------------------------------------------------------
class _VectorDB(ctypes.Structure):
    pass


_VectorDB_p = ctypes.POINTER(_VectorDB)


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------
class DistanceMetric(IntEnum):
    COSINE = 0
    EUCLIDEAN = 1
    DOT_PRODUCT = 2


# ---------------------------------------------------------------------------
# C function signatures
# ---------------------------------------------------------------------------
_lib.qihse_vector_db_create.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_char_p]
_lib.qihse_vector_db_create.restype = _VectorDB_p

_lib.qihse_vector_db_open.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_char_p, ctypes.c_uint32]
_lib.qihse_vector_db_open.restype = _VectorDB_p

_lib.qihse_vector_db_destroy.argtypes = [_VectorDB_p]
_lib.qihse_vector_db_destroy.restype = None

_lib.qihse_vector_db_add_vectors.argtypes = [
    _VectorDB_p,
    ctypes.POINTER(ctypes.c_float),
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_uint64),
    ctypes.POINTER(ctypes.c_void_p),
    ctypes.POINTER(ctypes.c_size_t),
]
_lib.qihse_vector_db_add_vectors.restype = ctypes.c_bool

_lib.qihse_vector_db_search.argtypes = [
    _VectorDB_p,
    ctypes.POINTER(ctypes.c_float),
    ctypes.c_size_t,
    ctypes.c_size_t,
    ctypes.c_int,
    ctypes.POINTER(ctypes.c_float),
    ctypes.c_size_t,
]
_lib.qihse_vector_db_search.restype = ctypes.c_int

_lib.qihse_vector_db_build_graph.argtypes = [_VectorDB_p, ctypes.c_size_t, ctypes.c_size_t]
_lib.qihse_vector_db_build_graph.restype = ctypes.c_bool

_lib.qihse_vector_db_build_int8.argtypes = [_VectorDB_p]
_lib.qihse_vector_db_build_int8.restype = ctypes.c_bool

_lib.qihse_vector_db_get_persistence_stats.argtypes = [_VectorDB_p, ctypes.c_void_p]
_lib.qihse_vector_db_get_persistence_stats.restype = ctypes.c_bool

_lib.qihse_vector_db_flush.argtypes = [_VectorDB_p]
_lib.qihse_vector_db_flush.restype = ctypes.c_bool

_lib.qihse_vector_db_get_stats.argtypes = [_VectorDB_p, ctypes.c_void_p]
_lib.qihse_vector_db_get_stats.restype = ctypes.c_bool


# ---------------------------------------------------------------------------
# Python classes
# ---------------------------------------------------------------------------
class VectorResult:
    def __init__(self, id: int, score: float, vector: Optional[np.ndarray] = None):
        self.id = id
        self.score = score
        self.vector = vector

    def __repr__(self):
        return f"VectorResult(id={self.id}, score={self.score:.4f})"


class VectorQuery:
    def __init__(
        self,
        vector: np.ndarray,
        top_k: int = 10,
        metric: DistanceMetric = DistanceMetric.COSINE,
        include_vectors: bool = False,
        include_metadata: bool = False,
        similarity_threshold: float = 0.0,
    ):
        self.vector = np.asarray(vector, dtype=np.float32)
        self.top_k = top_k
        self.metric = metric
        self.include_vectors = include_vectors
        self.include_metadata = include_metadata
        self.similarity_threshold = similarity_threshold


class VectorDB:
    def __init__(self, ptr: _VectorDB_p):
        self._ptr = ptr
        self._dims = 0

    @staticmethod
    def create(path: str, dims: int) -> "VectorDB":
        """Create a new file-backed vector database."""
        ptr = _lib.qihse_vector_db_create(0, None, path.encode("utf-8"))
        if not ptr:
            raise RuntimeError(f"Failed to create VectorDB at {path}")
        db = VectorDB(ptr)
        db._dims = dims
        return db

    @staticmethod
    def open(path: str, read_only: bool = False) -> "VectorDB":
        """Open an existing vector database."""
        flags = 0
        if read_only:
            flags |= 0x00000001
        ptr = _lib.qihse_vector_db_open(0, None, path.encode("utf-8"), flags)
        if not ptr:
            raise RuntimeError(f"Failed to open VectorDB at {path}")
        return VectorDB(ptr)

    def close(self):
        if self._ptr:
            _lib.qihse_vector_db_destroy(self._ptr)
            self._ptr = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def add_vectors(
        self,
        vectors: np.ndarray,
        ids: Optional[List[int]] = None,
        metadata: Optional[List[bytes]] = None,
    ) -> None:
        """Add vectors to the database."""
        vectors = np.asarray(vectors, dtype=np.float32)
        if vectors.ndim == 1:
            vectors = vectors.reshape(1, -1)
        n, dims = vectors.shape
        self._dims = dims

        ids_arr = None
        if ids is not None:
            ids_arr = (ctypes.c_uint64 * n)(*ids)

        meta_ptrs = None
        meta_sizes = None
        if metadata is not None:
            meta_ptrs = (ctypes.c_void_p * n)()
            meta_sizes = (ctypes.c_size_t * n)()
            for i, m in enumerate(metadata):
                meta_ptrs[i] = ctypes.cast(ctypes.create_string_buffer(m), ctypes.c_void_p)
                meta_sizes[i] = len(m)

        ok = _lib.qihse_vector_db_add_vectors(
            self._ptr,
            vectors.ctypes.data_as(ctypes.POINTER(ctypes.c_float)),
            n,
            ids_arr,
            meta_ptrs,
            meta_sizes,
        )
        if not ok:
            raise RuntimeError("Failed to add vectors")

    def search(
        self,
        query: Union[np.ndarray, VectorQuery],
        k: Optional[int] = None,
        metric: Optional[DistanceMetric] = None,
        include_vectors: bool = False,
    ) -> List[VectorResult]:
        """Search for nearest neighbors."""
        if isinstance(query, VectorQuery):
            qvec = query.vector
            top_k = query.top_k
            metric = query.metric
            include_vectors = query.include_vectors
        else:
            qvec = np.asarray(query, dtype=np.float32)
            top_k = k if k is not None else 10
            metric = metric if metric is not None else DistanceMetric.COSINE

        dims = len(qvec)
        out_scores = (ctypes.c_float * top_k)()
        out_ids = (ctypes.c_uint64 * top_k)()

        count = _lib.qihse_vector_db_search(
            self._ptr,
            qvec.ctypes.data_as(ctypes.POINTER(ctypes.c_float)),
            dims,
            top_k,
            int(metric),
            out_scores,
            top_k,
        )
        if count < 0:
            raise RuntimeError("Search failed")

        results = []
        for i in range(count):
            results.append(VectorResult(int(out_ids[i]), float(out_scores[i])))
        return results

    def build_graph(self, M: int = 16, ef_construction: int = 200) -> None:
        """Build the graph index sidecar."""
        ok = _lib.qihse_vector_db_build_graph(self._ptr, M, ef_construction)
        if not ok:
            raise RuntimeError("Failed to build graph index")

    def build_int8(self) -> None:
        """Build the INT8 scalar quantization sidecar."""
        ok = _lib.qihse_vector_db_build_int8(self._ptr)
        if not ok:
            raise RuntimeError("Failed to build INT8 index")

    def flush(self) -> None:
        """Persist all pending changes to disk."""
        ok = _lib.qihse_vector_db_flush(self._ptr)
        if not ok:
            raise RuntimeError("Flush failed")

    @property
    def dims(self) -> int:
        return self._dims
