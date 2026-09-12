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
    "/opt/qihse/libqihse.so",
    "/opt/qihse/lib/libqihse.so",
    "/opt/parrotagent/libqihse.so",
    "/usr/local/lib/libqihse.so",
    "/usr/lib/libqihse.so",
]

_lib = None
for p in _LIB_PATHS:
    if os.path.exists(p):
        # RTLD_GLOBAL is critical: qihse_vfs.so links libqihse.so as a NEEDED
        # dependency. If we load with RTLD_LOCAL (default), the VFS extension
        # loads a SECOND copy with fresh global state → segfault.
        _lib = ctypes.CDLL(p, mode=getattr(os, "RTLD_GLOBAL", 0) | getattr(os, "RTLD_NOW", 0))
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
# Open flags (must match qihse_vector_db_open_flags_t in qihse_vector_db.h)
# ---------------------------------------------------------------------------
QIHSE_VDB_OPEN_CREATE      = 1 << 0
QIHSE_VDB_OPEN_READ_ONLY   = 1 << 1
QIHSE_VDB_OPEN_TRUNCATE    = 1 << 2
QIHSE_VDB_OPEN_FILE_BACKED = 1 << 3
QIHSE_VDB_OPEN_MMAP        = 1 << 4


# ---------------------------------------------------------------------------
# Query modes (must match qihse_vector_db_query_mode_t in qihse_vector_db.h)
# ---------------------------------------------------------------------------
class QueryMode(IntEnum):
    """Search query mode. Lower-precision modes use less RAM but are approximate."""
    FLOAT32 = 0                # Exact float32 search (3 GB for 196K×4096)
    TRINARY_SCALAR = 1         # Sign-only candidate selection + float32 rerank
    TRINARY_MAGNITUDE = 2      # Sign + magnitude candidate selection + rerank
    TRINARY_MAGNITUDE_BYPASS = 3  # Approximate, no float32 rerank (fastest)
    GRAPH = 4                  # HNSW graph candidate selection + rerank
    INT8 = 5                   # INT8 quantized candidates (0.75 GB)
    SPARSE = 6                 # Sparse inverted index (BM25)
    FP16 = 7                   # FP16 candidates (1.5 GB)
    FP32 = 8                   # Explicit FP32
    FP8 = 9                    # FP8 candidates (375 MB)
    FP4 = 10                   # FP4 candidates (188 MB)
    INT4 = 11                  # INT4 candidates (94 MB)


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
        ("user", ctypes.c_void_p),
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

_lib.qihse_vector_db_build_fp8.argtypes = [_VectorDB_p]
_lib.qihse_vector_db_build_fp8.restype = ctypes.c_bool

_lib.qihse_vector_db_build_fp4.argtypes = [_VectorDB_p]
_lib.qihse_vector_db_build_fp4.restype = ctypes.c_bool

_lib.qihse_vector_db_build_int4.argtypes = [_VectorDB_p]
_lib.qihse_vector_db_build_int4.restype = ctypes.c_bool

_lib.qihse_vector_db_flush.argtypes = [_VectorDB_p]
_lib.qihse_vector_db_flush.restype = ctypes.c_bool

_lib.qihse_vector_db_run_memory_maintenance.argtypes = [_VectorDB_p]
_lib.qihse_vector_db_run_memory_maintenance.restype = ctypes.c_bool

_lib.qihse_vector_db_set_memory_budget.argtypes = [_VectorDB_p, ctypes.c_size_t]
_lib.qihse_vector_db_set_memory_budget.restype = ctypes.c_bool

_lib.qihse_vector_db_get_memory_usage.argtypes = [
    _VectorDB_p,
    ctypes.POINTER(ctypes.c_size_t),
    ctypes.POINTER(ctypes.c_size_t),
    ctypes.POINTER(ctypes.c_size_t),
]
_lib.qihse_vector_db_get_memory_usage.restype = ctypes.c_bool

_lib.qihse_vector_db_get_dims.argtypes = [_VectorDB_p]
_lib.qihse_vector_db_get_dims.restype = ctypes.c_size_t

_lib.qihse_auth_init.argtypes = []
_lib.qihse_auth_init.restype = ctypes.c_bool

_lib.qihse_auth_get_user.argtypes = [ctypes.c_uint32]
_lib.qihse_auth_get_user.restype = ctypes.c_void_p

_lib.qihse_auth_bootstrap_operator.argtypes = [ctypes.c_char_p]
_lib.qihse_auth_bootstrap_operator.restype = ctypes.c_bool

_lib.qihse_auth_is_operator_password_default.argtypes = []
_lib.qihse_auth_is_operator_password_default.restype = ctypes.c_bool

_lib.qihse_auth_init()

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
    def open(path: str, read_only: bool = False, mmap: bool = False) -> "VectorDB":
        """Open an existing VectorDB.

        Args:
            path: Path to .qdb file
            read_only: Open in read-only mode (required for mmap)
            mmap: Memory-map the file instead of copying into RAM.
                  Requires read_only=True. Drops search-time RSS from
                  ~3 GB to ~0 (kernel page cache manages it).
        """
        flags = QIHSE_VDB_OPEN_FILE_BACKED
        if read_only:
            flags |= QIHSE_VDB_OPEN_READ_ONLY
        if mmap:
            if not read_only:
                raise ValueError("mmap requires read_only=True")
            flags |= QIHSE_VDB_OPEN_MMAP
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
        mode: Optional[QueryMode] = None,
    ) -> list[VectorResult]:
        """Search for nearest neighbors.

        Args:
            query: Query vector or VectorQuery object
            k: Number of results (default 10)
            metric: Distance metric (default COSINE)
            include_vectors: Return vectors in results
            mode: Query mode for approximate search. Default is GRAPH (HNSW).
                  Use INT8/FP8/FP4 for lower memory on constrained hardware.
        """
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
            # Use provided mode, default to GRAPH (HNSW + float32 rerank)
            c_query.query_mode = int(mode) if mode is not None else 4
            c_query.candidate_pool_size = top_k * 20
            c_query.distance_metric = metric.value
            c_query.metadata_filter = None
            c_query.metadata_filter_opaque = None
            c_query.user = _lib.qihse_auth_get_user(0)
            
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
        """Build the INT8 scalar quantization sidecar (4x compression)."""
        with self._lock:
            ok = _lib.qihse_vector_db_build_int8(self._ptr)
            if not ok:
                raise RuntimeError("Failed to build INT8 index")

    def build_fp8(self) -> None:
        """Build the FP8 quantization sidecar (8x compression, 375 MB for 196K×4096)."""
        with self._lock:
            ok = _lib.qihse_vector_db_build_fp8(self._ptr)
            if not ok:
                raise RuntimeError("Failed to build FP8 index")

    def build_fp4(self) -> None:
        """Build the FP4 quantization sidecar (16x compression, 188 MB for 196K×4096)."""
        with self._lock:
            ok = _lib.qihse_vector_db_build_fp4(self._ptr)
            if not ok:
                raise RuntimeError("Failed to build FP4 index")

    def build_int4(self) -> None:
        """Build the INT4 quantization sidecar (32x compression, 94 MB for 196K×4096)."""
        with self._lock:
            ok = _lib.qihse_vector_db_build_int4(self._ptr)
            if not ok:
                raise RuntimeError("Failed to build INT4 index")

    def flush(self) -> None:
        """Persist all pending changes to disk."""
        with self._lock:
            ok = _lib.qihse_vector_db_flush(self._ptr)
            if not ok:
                raise RuntimeError("Flush failed")

    def run_memory_maintenance(self) -> None:
        """Run memory maintenance: recompute row temperatures, promote/demote
        tiers, and spill cold rows to disk if a memory budget is set."""
        with self._lock:
            ok = _lib.qihse_vector_db_run_memory_maintenance(self._ptr)
            if not ok:
                raise RuntimeError("Memory maintenance failed")

    def set_memory_budget(self, budget_bytes: int) -> None:
        """Set the maximum in-RAM vector buffer size. When exceeded, cold
        rows are spilled to a sidecar file (``<db_path>.spill``) and paged
        back in on demand during search. A budget of 0 means unlimited
        (legacy behavior). The budget applies only to the float32 vector
        buffer, not metadata or quantized sidecars.

        Args:
            budget_bytes: Maximum bytes for in-RAM vectors (0=unlimited).
        """
        if budget_bytes < 0:
            raise ValueError("budget_bytes must be >= 0")
        with self._lock:
            ok = _lib.qihse_vector_db_set_memory_budget(
                self._ptr, ctypes.c_size_t(budget_bytes)
            )
            if not ok:
                raise RuntimeError("Failed to set memory budget")

    def get_memory_usage(self) -> tuple[int, int, int]:
        """Return (budget_bytes, in_ram_bytes, spilled_count).

        - ``budget_bytes``: configured budget (0 = unlimited).
        - ``in_ram_bytes``: bytes currently resident in the float32 buffer.
        - ``spilled_count``: number of rows evicted to the spill file.
        """
        budget = ctypes.c_size_t()
        in_ram = ctypes.c_size_t()
        spilled = ctypes.c_size_t()
        with self._lock:
            ok = _lib.qihse_vector_db_get_memory_usage(
                self._ptr,
                ctypes.byref(budget),
                ctypes.byref(in_ram),
                ctypes.byref(spilled),
            )
            if not ok:
                raise RuntimeError("Failed to get memory usage")
        return (int(budget.value), int(in_ram.value), int(spilled.value))

    @property
    def dims(self) -> int:
        with self._lock:
            if self._ptr:
                d = _lib.qihse_vector_db_get_dims(self._ptr)
                if d > 0:
                    return int(d)
            return self._dims

    def start_pg_wire(self, port: int = 5432, bind_address: str = "127.0.0.1") -> bool:
        """Starts the PG wire protocol server in the background."""
        with self._lock:
            return _lib.qihse_start_pg_wire_server(
                self._ptr,
                ctypes.c_uint16(port),
                bind_address.encode("utf-8")
            )


# ---------------------------------------------------------------------------
# .qdb Container format — packs all QIHSE files into a single file
# ---------------------------------------------------------------------------

# Section IDs (must match qihse_container.h)
QIHSE_CTR_SEC_MANIFEST  = 0x0001
QIHSE_CTR_SEC_WAL       = 0x0002
QIHSE_CTR_SEC_INDEX     = 0x0003
QIHSE_CTR_SEC_IDMAP     = 0x0004
QIHSE_CTR_SEC_VECTORS   = 0x0005
QIHSE_CTR_SEC_METADATA  = 0x0006
QIHSE_CTR_SEC_TRINARY   = 0x0007
QIHSE_CTR_SEC_MAGNITUDE = 0x0008
QIHSE_CTR_SEC_GRAPH     = 0x0009
QIHSE_CTR_SEC_INT8      = 0x000A
QIHSE_CTR_SEC_TIER      = 0x000B
QIHSE_CTR_SEC_EDGES     = 0x000C
QIHSE_CTR_SEC_KEY       = 0x1000
QIHSE_CTR_SEC_SIGNATURE = 0x1001

QIHSE_CTR_MAX_SECTIONS  = 14
QIHSE_MLKEM_CIPHERTEXT_SIZE = 1568

# File → section mapping for pack/unpack
_QDB_FILE_SECTIONS = {
    "qihse.db":            QIHSE_CTR_SEC_WAL,
    "tool_vectors.db":     QIHSE_CTR_SEC_VECTORS,
    "tool_graph.json":     QIHSE_CTR_SEC_GRAPH,
    "research_graph.json": QIHSE_CTR_SEC_EDGES,
    "tool_cards.json":     QIHSE_CTR_SEC_METADATA,
    "qihse_fts_map.json":  QIHSE_CTR_SEC_IDMAP,
    "tool_idf.json":       QIHSE_CTR_SEC_INT8,
}
# Reverse mapping for unpack
_QDB_SECTION_FILES = {v: k for k, v in _QDB_FILE_SECTIONS.items()}


class _PQCCtx(ctypes.Structure):
    _fields_ = [
        ("aes_key", ctypes.c_uint8 * 32),
        ("initialized", ctypes.c_bool),
    ]


class _CtrSection(ctypes.Structure):
    _fields_ = [
        ("section_id", ctypes.c_uint16),
        ("flags", ctypes.c_uint16),
        ("reserved", ctypes.c_uint32),
        ("offset", ctypes.c_uint64),
        ("length", ctypes.c_uint64),
        ("hmac_sha384", ctypes.c_uint8 * 48),
    ]


class _Container(ctypes.Structure):
    _fields_ = [
        ("fd", ctypes.c_int),
        ("path", ctypes.c_char_p),
        ("locked", ctypes.c_bool),
        ("read_only", ctypes.c_bool),
        ("skip_integrity", ctypes.c_bool),
        ("parallel_crc", ctypes.c_bool),
        ("use_crc32c", ctypes.c_bool),
        ("crc_threads", ctypes.c_int),
        ("sections", _CtrSection * QIHSE_CTR_MAX_SECTIONS),
        ("section_count", ctypes.c_uint32),
        ("pqc_ctx", _PQCCtx),
    ]


class _CtrSectionBuf(ctypes.Structure):
    _fields_ = [
        ("section_id", ctypes.c_uint16),
        ("data", ctypes.c_void_p),
        ("size", ctypes.c_size_t),
    ]


# Container C function signatures
_lib.qihse_ctr_open_read.argtypes = [ctypes.c_char_p, ctypes.POINTER(_Container)]
_lib.qihse_ctr_open_read.restype = ctypes.c_bool

_lib.qihse_ctr_open_write.argtypes = [ctypes.c_char_p, ctypes.c_bool, ctypes.POINTER(_Container)]
_lib.qihse_ctr_open_write.restype = ctypes.c_bool

_lib.qihse_ctr_close.argtypes = [ctypes.POINTER(_Container)]
_lib.qihse_ctr_close.restype = None

_lib.qihse_ctr_find_section.argtypes = [ctypes.POINTER(_Container), ctypes.c_uint16]
_lib.qihse_ctr_find_section.restype = ctypes.POINTER(_CtrSection)

_lib.qihse_ctr_read_section_alloc.argtypes = [
    ctypes.POINTER(_Container),
    ctypes.c_uint16,
    ctypes.POINTER(ctypes.POINTER(ctypes.c_uint8)),
    ctypes.POINTER(ctypes.c_size_t),
]
_lib.qihse_ctr_read_section_alloc.restype = ctypes.c_bool

_lib.qihse_ctr_section_length.argtypes = [ctypes.POINTER(_Container), ctypes.c_uint16]
_lib.qihse_ctr_section_length.restype = ctypes.c_uint64

_lib.qihse_ctr_flush.argtypes = [
    ctypes.POINTER(_Container),
    ctypes.POINTER(_CtrSectionBuf),
    ctypes.c_size_t,
]
_lib.qihse_ctr_flush.restype = ctypes.c_bool

_lib.qihse_ctr_fsync.argtypes = [ctypes.POINTER(_Container)]
_lib.qihse_ctr_fsync.restype = ctypes.c_bool

# C free for the allocated section buffer (qihse_ctr_read_section_alloc uses malloc)
_libc = ctypes.CDLL("libc.so.6")
_libc.free.argtypes = [ctypes.c_void_p]
_libc.free.restype = None


class Container:
    """Python wrapper for the QIHSE .qdb container format.

    Packs all QIHSE database files (qihse.db, tool_vectors.db, graphs,
    cards, FTS map, IDF) into a single .qdb file with HMAC-SHA-384
    integrity, atomic flush, and POSIX file locking.

    Usage:
        # Pack a directory of loose files into a .qdb
        Container.pack("/opt/qihse-data", "/opt/qihse-data/data.qdb")

        # Unpack a .qdb back to loose files
        Container.unpack("/opt/qihse-data/data.qdb", "/opt/qihse-data")

        # Inspect sections
        with Container.open_read("/opt/qihse-data/data.qdb") as c:
            print(c.list_sections())
    """

    def __init__(self, _ctr: _Container, _owns: bool = True):
        self._ctr = _ctr
        self._owns = _owns

    @staticmethod
    def open_read(path: str) -> "Container":
        ctr = _Container()
        if not _lib.qihse_ctr_open_read(path.encode("utf-8"), ctypes.byref(ctr)):
            raise RuntimeError(f"Failed to open .qdb container: {path}")
        return Container(ctr)

    @staticmethod
    def open_write(path: str, create: bool = False) -> "Container":
        ctr = _Container()
        if not _lib.qihse_ctr_open_write(path.encode("utf-8"), create, ctypes.byref(ctr)):
            raise RuntimeError(f"Failed to open .qdb container for writing: {path}")
        return Container(ctr)

    def close(self):
        if self._owns and self._ctr is not None:
            _lib.qihse_ctr_close(ctypes.byref(self._ctr))
            self._ctr = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def section_length(self, section_id: int) -> int:
        return int(_lib.qihse_ctr_section_length(ctypes.byref(self._ctr), section_id))

    def list_sections(self) -> list:
        result = []
        for name, sid in _QDB_FILE_SECTIONS.items():
            length = self.section_length(sid)
            if length > 0:
                result.append({"section_id": sid, "name": name, "length": length})
        return result

    def read_section(self, section_id: int) -> bytes:
        buf_ptr = ctypes.POINTER(ctypes.c_uint8)()
        size = ctypes.c_size_t(0)
        if not _lib.qihse_ctr_read_section_alloc(
            ctypes.byref(self._ctr),
            section_id,
            ctypes.byref(buf_ptr),
            ctypes.byref(size),
        ):
            raise RuntimeError(f"Failed to read section {section_id:#06x}")
        try:
            return ctypes.string_at(buf_ptr, size.value)
        finally:
            _libc.free(buf_ptr)

    def flush(self, sections: list) -> None:
        """Write sections atomically. sections is a list of (section_id, bytes)."""
        bufs = (_CtrSectionBuf * len(sections))()
        for i, (sid, data) in enumerate(sections):
            bufs[i].section_id = sid
            bufs[i].data = ctypes.cast(
                ctypes.c_char_p(data), ctypes.c_void_p
            )
            bufs[i].size = len(data)
        if not _lib.qihse_ctr_flush(
            ctypes.byref(self._ctr), bufs, len(sections)
        ):
            raise RuntimeError("Failed to flush container")

    @staticmethod
    def pack(src_dir: str, qdb_path: str) -> dict:
        """Pack all QIHSE files from src_dir into a single .qdb container.

        Returns a manifest dict with file names, sizes, and section IDs.
        """
        import json

        manifest = {"files": {}, "section_count": 0}
        sections = []

        for filename, section_id in _QDB_FILE_SECTIONS.items():
            filepath = os.path.join(src_dir, filename)
            if not os.path.exists(filepath):
                continue
            with open(filepath, "rb") as f:
                data = f.read()
            sections.append((section_id, data))
            manifest["files"][filename] = {
                "section_id": section_id,
                "size": len(data),
            }
            manifest["section_count"] += 1

        # Write manifest as SEC_MANIFEST
        manifest_bytes = json.dumps(manifest, indent=2).encode("utf-8")
        sections.append((QIHSE_CTR_SEC_MANIFEST, manifest_bytes))

        # Create and write the container
        c = Container.open_write(qdb_path, create=True)
        try:
            c.flush(sections)
        finally:
            c.close()

        total_size = sum(s[1].__len__() for s in sections)
        manifest["qdb_path"] = qdb_path
        manifest["total_size"] = total_size
        return manifest

    @staticmethod
    def unpack(qdb_path: str, dst_dir: str) -> dict:
        """Unpack a .qdb container back to loose files in dst_dir.

        Returns the manifest dict.
        """
        import json

        os.makedirs(dst_dir, exist_ok=True)

        with Container.open_read(qdb_path) as c:
            # Read manifest first
            manifest_len = c.section_length(QIHSE_CTR_SEC_MANIFEST)
            manifest = None
            if manifest_len > 0:
                manifest_bytes = c.read_section(QIHSE_CTR_SEC_MANIFEST)
                manifest = json.loads(manifest_bytes)

            # Unpack each known section
            extracted = {}
            for filename, section_id in _QDB_FILE_SECTIONS.items():
                length = c.section_length(section_id)
                if length == 0:
                    continue
                data = c.read_section(section_id)
                filepath = os.path.join(dst_dir, filename)
                with open(filepath, "wb") as f:
                    f.write(data)
                extracted[filename] = len(data)

        return manifest or {"files": {}, "extracted": extracted}

