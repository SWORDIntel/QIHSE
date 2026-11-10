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

from importlib import import_module as _import_module

# Remote clients must not initialize embedded authentication or audit storage.
# Import the native bindings only when an embedded API is actually requested.
_EXPORT_MODULES = {
    name: module
    for module, names in {
        "core": ("VectorDB", "VectorQuery", "VectorResult", "DistanceMetric", "QueryMode"),
        "kv": ("KVStore",),
        "timeseries": ("TimeSeriesDB",),
        "document": ("DocumentStore",),
        "event_stream": ("EventStream", "EventRecord", "EventScope", "Durability"),
        "uwp": ("UWPServer",),
        "neural": ("NeuralClassifier", "KeystoneClass"),
        "anchor": ("AnchorIndex",),
        "hardware": ("HardwareProfiler", "HardwareProfile"),
        "fts": ("FTSIndex", "FTSResult"),
        "fusion": ("MultimodalFusion", "FusionResult"),
        "controller": ("Controller", "Reply", "Watch", "ControllerError", "ControllerServerError"),
        "aimem": ("AIMEMClient", "Scope", "MemoryHit", "DurableReceipt",
                  "KnowledgeVersion", "KnowledgeRelation", "KnowledgeProvenance",
                  "ExtendedKnowledgeVersion", "DocumentSourceRef", "Handoff",
                  "QueryHit", "RecallMode"),
        "thermal": ("get_fleet_telemetry", "collect_local_telemetry", "publish_telemetry"),
    }.items()
    for name in names
}


def __getattr__(name):
    module = _EXPORT_MODULES.get(name)
    if module is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    value = getattr(_import_module(f".{module}", __name__), name)
    globals()[name] = value
    return value


def __dir__():
    return sorted(set(globals()) | set(__all__))

__all__ = [
    "VectorDB", "VectorQuery", "VectorResult", "DistanceMetric", "QueryMode",
    "KVStore", "TimeSeriesDB", "DocumentStore",
    "EventStream", "EventRecord", "EventScope", "Durability",
    "UWPServer",
    "NeuralClassifier", "KeystoneClass",
    "AnchorIndex",
    "HardwareProfiler", "HardwareProfile",
    "FTSIndex", "FTSResult",
    "MultimodalFusion", "FusionResult",
    "Controller", "Reply", "Watch", "ControllerError", "ControllerServerError",
    "AIMEMClient", "Scope", "MemoryHit", "DurableReceipt", "KnowledgeVersion",
    "KnowledgeRelation", "KnowledgeProvenance", "ExtendedKnowledgeVersion",
    "DocumentSourceRef", "Handoff", "QueryHit", "RecallMode",
    "get_fleet_telemetry", "collect_local_telemetry", "publish_telemetry",
]
__version__ = "0.3.0"

