"""
QIHSE Python bindings (ctypes-based).

Usage:
    import qihse
    
    # Vector DB
    db = qihse.VectorDB.create("/tmp/mydb", dims=128)
    db.add_vectors(vectors, ids=[1, 2, 3])
    db.build_graph()
    results = db.search(query_vector, k=10)
    
    # KV Store
    kv = qihse.KVStore()
    kv.set("hello", "world")
    
    # Time-Series DB
    ts = qihse.TimeSeriesDB()
    ts.insert(series_id=1, timestamp=1600000000, value=42.0)
    
    # Document DB
    doc = qihse.DocumentStore(kv)
    doc.insert_json(1, '{"user": "alice", "age": 30}')
    
    # Full-Text Search (FTS) Index with Neural Semantic Classification
    fts = qihse.FTSIndex()
    fts.add_document(1, "pentagon classified intelligence document", semantic_class=qihse.KeystoneClass.GOVERNMENT)
    results = fts.search("pentagon intelligence", top_k=5)
    
    # Neural Micro-Model Classification (260->64->6 Feedforward)
    cls, name, conf = qihse.NeuralClassifier.classify("auth_failure admin@pentagon.af.mil token=TOPSECRET")
    
    # Keystone Spline Interpolation Anchor Search
    idx = qihse.AnchorIndex.lower_bound(sorted_timestamps, 1600000000)
    
    # Hardware Backend Profiler
    hw = qihse.HardwareProfiler.get_profile()
    print(f"Active Backend: {hw.preferred_backend} (AVX={hw.avx}, AVX2={hw.avx2})")
    
    # Hybrid FTS + Vector RRF Multimodal Fusion
    fused = qihse.MultimodalFusion.search(
        vector_db=db,
        vector_queries=[{"vector": qvec, "modality": "text", "weight": 1.0}],
        fts_index=fts,
        fts_query="defense credential alert",
        semantic_mask=(1 << qihse.KeystoneClass.GOVERNMENT)
    )
"""

from .core import VectorDB, VectorQuery, VectorResult, DistanceMetric
from .kv import KVStore
from .timeseries import TimeSeriesDB
from .document import DocumentStore
from .event_stream import EventStream, EventRecord, Durability
from .uwp import UWPServer
from .neural import NeuralClassifier, KeystoneClass
from .anchor import AnchorIndex
from .hardware import HardwareProfiler, HardwareProfile
from .fts import FTSIndex, FTSResult
from .fusion import MultimodalFusion, FusionResult

__all__ = [
    "VectorDB", "VectorQuery", "VectorResult", "DistanceMetric",
    "KVStore", "TimeSeriesDB", "DocumentStore",
    "EventStream", "EventRecord", "Durability",
    "UWPServer",
    "NeuralClassifier", "KeystoneClass",
    "AnchorIndex",
    "HardwareProfiler", "HardwareProfile",
    "FTSIndex", "FTSResult",
    "MultimodalFusion", "FusionResult",
]
__version__ = "0.3.0"
