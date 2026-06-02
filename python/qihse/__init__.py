"""
QIHSE Python bindings (ctypes-based).

Usage:
    import qihse
    db = qihse.VectorDB.create("/tmp/mydb", dims=128)
    db.add_vectors(vectors, ids=[1, 2, 3])
    db.build_graph()
    results = db.search(query_vector, k=10)
"""

from .core import VectorDB, VectorQuery, VectorResult, DistanceMetric

__all__ = ["VectorDB", "VectorQuery", "VectorResult", "DistanceMetric"]
__version__ = "0.1.0"
