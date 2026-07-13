"""
QIHSE Python ctypes wrapper for libqihse.so vector database.
"""

import ctypes
import os
import sys
import numpy as np
import threading
from enum import IntEnum
from typing import List, Optional, Tuple, Union

# Find libqihse.so — use absolute paths only to prevent CWD hijacking
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
    DOT_PRODUCT = 1
    EUCLIDEAN = 2


# ---------------------------------------------------------------------------
# C function signatures
# ---------------------------------------------------------------------------
_lib.qihse_vector_db_create.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_char_p]
_lib.qihse_vector_db_create.restype = _VectorDB_p

_lib.qihse_vector_db_open.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_char_p, ctypes.c_uint32]
_lib.qihse_vector_db_open.restype = _VectorDB_p

_lib.qihse_vector_db_destroy.argtypes = [_VectorDB_p]
_lib.qihse_vector_db_destroy.restype = None
_lib.qihse_vector_db_close.argtypes = [_VectorDB_p]
_lib.qihse_vector_db_close.restype = ctypes.c_bool

_lib.qihse_vector_db_add_vectors.argtypes = [
    _VectorDB_p,
    ctypes.POINTER(ctypes.c_float),
    ctypes.c_size_t,
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_uint64),
    ctypes.POINTER(ctypes.c_void_p),
    ctypes.POINTER(ctypes.c_size_t),
]
_lib.qihse_vector_db_add_vectors.restype = ctypes.c_bool

class CVectorQuery(ctypes.Structure):
    _fields_ = [
        ("query_vector", ctypes.POINTER(ctypes.c_float)),
        ("vector_dims", ctypes.c_size_t),
        ("top_k", ctypes.c_size_t),
        ("similarity_threshold", ctypes.c_float),
        ("include_vectors", ctypes.c_bool),
        ("include_metadata", ctypes.c_bool),
        ("use_trinary_candidates", ctypes.c_bool),
        ("candidate_count", ctypes.c_size_t),
        ("query_mode", ctypes.c_int),
        ("candidate_pool_size", ctypes.c_size_t),
        ("distance_metric", ctypes.c_int),
        ("metadata_filter", ctypes.c_void_p),
        ("metadata_filter_opaque", ctypes.c_void_p),
    ]

class CVectorResult(ctypes.Structure):
    _fields_ = [
        ("id", ctypes.c_uint64),
        ("score", ctypes.c_float),
        ("vector", ctypes.POINTER(ctypes.c_float)),
        ("vector_dims", ctypes.c_size_t),
        ("metadata", ctypes.c_void_p),
        ("metadata_size", ctypes.c_size_t),
    ]

class CEdgeInput(ctypes.Structure):
    _fields_ = [
        ("from_id", ctypes.c_uint64), ("to_id", ctypes.c_uint64),
        ("edge_type", ctypes.c_char_p), ("metadata", ctypes.c_void_p),
        ("metadata_size", ctypes.c_size_t),
    ]

class CEdgeResult(ctypes.Structure):
    _fields_ = [
        ("from_id", ctypes.c_uint64), ("to_id", ctypes.c_uint64),
        ("edge_type", ctypes.c_char * 32), ("metadata", ctypes.c_void_p),
        ("metadata_size", ctypes.c_size_t),
    ]

_lib.qihse_vector_db_add_edges.argtypes = [_VectorDB_p, ctypes.POINTER(CEdgeInput), ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
_lib.qihse_vector_db_add_edges.restype = ctypes.c_bool
_lib.qihse_vector_db_replace_edge.argtypes = [_VectorDB_p, ctypes.c_uint64, ctypes.c_uint64, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_size_t]
_lib.qihse_vector_db_replace_edge.restype = ctypes.c_bool
_lib.qihse_vector_db_remove_edge.argtypes = [_VectorDB_p, ctypes.c_uint64, ctypes.c_uint64, ctypes.c_char_p]
_lib.qihse_vector_db_remove_edge.restype = ctypes.c_bool
_lib.qihse_vector_db_get_typed_neighbors.argtypes = [_VectorDB_p, ctypes.c_uint64, ctypes.c_char_p, ctypes.c_int, ctypes.POINTER(ctypes.c_uint64), ctypes.c_size_t]
_lib.qihse_vector_db_get_typed_neighbors.restype = ctypes.c_int
_lib.qihse_vector_db_get_edge_records.argtypes = [_VectorDB_p, ctypes.c_uint64, ctypes.c_char_p, ctypes.c_int, ctypes.POINTER(CEdgeResult), ctypes.c_size_t]
_lib.qihse_vector_db_get_edge_records.restype = ctypes.c_int
_lib.qihse_vector_db_free_edge_records.argtypes = [ctypes.POINTER(CEdgeResult), ctypes.c_size_t]
_lib.qihse_vector_db_free_edge_records.restype = None

_lib.qihse_vector_db_search.argtypes = [
    _VectorDB_p,
    ctypes.POINTER(CVectorQuery),
    ctypes.POINTER(CVectorResult),
    ctypes.c_size_t,
]
_lib.qihse_vector_db_search.restype = ctypes.c_int

_lib.qihse_vector_db_build_graph.argtypes = [_VectorDB_p, ctypes.c_size_t, ctypes.c_size_t]
_lib.qihse_vector_db_build_graph.restype = ctypes.c_bool

_lib.qihse_vector_db_build_int8.argtypes = [_VectorDB_p]
_lib.qihse_vector_db_build_int8.restype = ctypes.c_bool

_lib.qihse_vector_db_flush.argtypes = [_VectorDB_p]
_lib.qihse_vector_db_flush.restype = ctypes.c_bool

_lib.qihse_start_pg_wire_server.argtypes = [_VectorDB_p, ctypes.c_uint16, ctypes.c_char_p]
_lib.qihse_start_pg_wire_server.restype = ctypes.c_bool

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
        self._lock = threading.RLock()

    @staticmethod
    def create(path: str, dims: int) -> "VectorDB":
        ptr = _lib.qihse_vector_db_create(0, None, path.encode("utf-8"))
        if not ptr:
            raise RuntimeError(f"Failed to create VectorDB at {path}")
        db = VectorDB(ptr)
        db._dims = dims
        return db

    @staticmethod
    def open(path: str, read_only: bool = False) -> "VectorDB":
        flags = 0x00000008
        if read_only:
            flags |= 0x00000002
        ptr = _lib.qihse_vector_db_open(0, None, path.encode("utf-8"), flags)
        if not ptr:
            raise RuntimeError(f"Failed to open VectorDB at {path}")
        return VectorDB(ptr)

    def close(self):
        with self._lock:
            if self._ptr:
                if not _lib.qihse_vector_db_close(self._ptr):
                    self._ptr = None
                    raise RuntimeError("Failed to flush and close VectorDB")
                self._ptr = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def add_vectors(
        self,
        vectors: np.ndarray,
        ids: Optional[list[int]] = None,
        metadata: Optional[list[bytes]] = None,
    ) -> None:
        with self._lock:
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
                dims,
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
    ) -> list[VectorResult]:
        with self._lock:
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
            
            c_query = CVectorQuery()
            c_query.query_vector = qvec.ctypes.data_as(ctypes.POINTER(ctypes.c_float))
            c_query.vector_dims = dims
            c_query.top_k = top_k
            c_query.similarity_threshold = 0.0
            c_query.include_vectors = include_vectors
            c_query.include_metadata = False
            c_query.use_trinary_candidates = False
            c_query.candidate_count = top_k * 2
            c_query.query_mode = 4 # QIHSE_VDB_QUERY_GRAPH
            c_query.candidate_pool_size = top_k * 20
            c_query.distance_metric = metric.value
            c_query.metadata_filter = None
            c_query.metadata_filter_opaque = None
            
            out_results = (CVectorResult * top_k)()
    
            count = _lib.qihse_vector_db_search(
                self._ptr,
                ctypes.byref(c_query),
                out_results,
                top_k
            )
            if count < 0:
                raise RuntimeError("Search failed")
    
            results = []
            for i in range(count):
                results.append(VectorResult(int(out_results[i].id), float(out_results[i].score)))
            return results

    @staticmethod
    def _edge_type_bytes(edge_type: str) -> bytes:
        if not isinstance(edge_type, str):
            raise TypeError("edge_type must be a string")
        encoded = edge_type.encode("utf-8")
        if not encoded or len(encoded) > 31 or b"\x00" in encoded:
            raise ValueError("edge_type must encode to 1..31 non-NUL bytes")
        return encoded

    def add_edges(self, edges: list[tuple[int, int, str, Optional[bytes]]]) -> int:
        if not isinstance(edges, list) or not edges:
            raise ValueError("edges must be a non-empty list")
        with self._lock:
            c_edges = (CEdgeInput * len(edges))()
            keepalive = []
            for index, edge in enumerate(edges):
                if not isinstance(edge, tuple) or len(edge) != 4:
                    raise ValueError("each edge must be (from_id, to_id, edge_type, metadata)")
                from_id, to_id, edge_type, metadata = edge
                encoded_type = self._edge_type_bytes(edge_type)
                if metadata is not None and not isinstance(metadata, bytes):
                    raise TypeError("edge metadata must be bytes or None")
                c_edges[index].from_id = from_id
                c_edges[index].to_id = to_id
                c_edges[index].edge_type = encoded_type
                keepalive.append(encoded_type)
                if metadata:
                    buffer = ctypes.create_string_buffer(metadata)
                    keepalive.append(buffer)
                    c_edges[index].metadata = ctypes.cast(buffer, ctypes.c_void_p)
                    c_edges[index].metadata_size = len(metadata)
            changed = ctypes.c_size_t()
            if not _lib.qihse_vector_db_add_edges(self._ptr, c_edges, len(edges), ctypes.byref(changed)):
                raise RuntimeError("failed to add edges")
            return changed.value

    def add_edge(self, from_id: int, to_id: int, edge_type: str,
                 metadata: Optional[bytes] = None) -> bool:
        return self.add_edges([(from_id, to_id, edge_type, metadata)]) != 0

    def replace_edge(self, from_id: int, to_id: int, edge_type: str,
                     metadata: Optional[bytes] = None) -> None:
        encoded_type = self._edge_type_bytes(edge_type)
        if metadata is not None and not isinstance(metadata, bytes):
            raise TypeError("edge metadata must be bytes or None")
        with self._lock:
            buffer = ctypes.create_string_buffer(metadata) if metadata else None
            pointer = ctypes.cast(buffer, ctypes.c_void_p) if buffer else None
            if not _lib.qihse_vector_db_replace_edge(
                self._ptr, from_id, to_id, encoded_type, pointer,
                len(metadata) if metadata else 0,
            ):
                raise RuntimeError("failed to replace edge")

    def remove_edge(self, from_id: int, to_id: int, edge_type: str) -> None:
        encoded_type = self._edge_type_bytes(edge_type)
        with self._lock:
            if not _lib.qihse_vector_db_remove_edge(self._ptr, from_id, to_id, encoded_type):
                raise RuntimeError("failed to remove edge")

    def neighbors(self, node_id: int, edge_type: Optional[str] = None,
                  direction: int = 0, limit: int = 1024) -> list[int]:
        if direction not in (0, 1, 2) or limit <= 0:
            raise ValueError("direction must be 0, 1, or 2 and limit must be positive")
        encoded_type = self._edge_type_bytes(edge_type) if edge_type is not None else None
        with self._lock:
            output = (ctypes.c_uint64 * limit)()
            count = _lib.qihse_vector_db_get_typed_neighbors(
                self._ptr, node_id, encoded_type, direction, output, limit
            )
            if count < 0:
                raise RuntimeError("failed to retrieve neighbors")
            return list(output[:count])

    def edge_records(self, node_id: int, edge_type: Optional[str] = None,
                     direction: int = 0, limit: int = 1024) -> list[tuple[int, int, str, bytes]]:
        if direction not in (0, 1, 2) or limit <= 0:
            raise ValueError("direction must be 0, 1, or 2 and limit must be positive")
        encoded_type = self._edge_type_bytes(edge_type) if edge_type is not None else None
        with self._lock:
            output = (CEdgeResult * limit)()
            count = _lib.qihse_vector_db_get_edge_records(
                self._ptr, node_id, encoded_type, direction, output, limit
            )
            if count < 0:
                raise RuntimeError("failed to retrieve edge records")
            try:
                return [
                    (output[index].from_id, output[index].to_id,
                     bytes(output[index].edge_type).split(b"\x00", 1)[0].decode("utf-8"),
                     ctypes.string_at(output[index].metadata, output[index].metadata_size)
                     if output[index].metadata_size else b"")
                    for index in range(count)
                ]
            finally:
                _lib.qihse_vector_db_free_edge_records(output, count)

    def build_graph(self, M: int = 16, ef_construction: int = 200) -> None:
        """Build the graph index sidecar."""
        with self._lock:
            ok = _lib.qihse_vector_db_build_graph(self._ptr, M, ef_construction)
            if not ok:
                raise RuntimeError("Failed to build graph index")

    def build_int8(self) -> None:
        """Build the INT8 scalar quantization sidecar."""
        with self._lock:
            ok = _lib.qihse_vector_db_build_int8(self._ptr)
            if not ok:
                raise RuntimeError("Failed to build INT8 index")

    def flush(self) -> None:
        """Persist all pending changes to disk."""
        with self._lock:
            ok = _lib.qihse_vector_db_flush(self._ptr)
            if not ok:
                raise RuntimeError("Flush failed")

    @property
    def dims(self) -> int:
        return self._dims

    def start_pg_wire(self, port: int = 5432, bind_address: str = "127.0.0.1") -> bool:
        """Starts the PG wire protocol server in the background."""
        with self._lock:
            return _lib.qihse_start_pg_wire_server(
                self._ptr,
                ctypes.c_uint16(port),
                bind_address.encode("utf-8")
            )
