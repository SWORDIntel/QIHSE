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
    
    # Event Stream (record-framed commit log with SHA-384 integrity)
    es = qihse.EventStream("/tmp/qihse_events")
    es.append("bgp_updates", b'{"prefix":"1.2.3.0/24","asn":64512}')
    for record in es.iterate("bgp_updates"):
        print(record.schema_id, record.payload)
    es.truncate_torn_tail("bgp_updates")
    
    # Start Unified Wire Protocol Server
    qihse.UWPServer.start(port=8080, bind_address="0.0.0.0", kv=kv, doc=doc, tsdb=ts)
"""

from .core import VectorDB, VectorQuery, VectorResult, DistanceMetric
from .kv import KVStore
from .timeseries import TimeSeriesDB
from .document import DocumentStore
from .event_stream import EventStream, EventRecord, Durability
from .uwp import UWPServer

__all__ = ["VectorDB", "VectorQuery", "VectorResult", "DistanceMetric",
           "KVStore", "TimeSeriesDB", "DocumentStore",
           "EventStream", "EventRecord", "Durability",
           "UWPServer"]
__version__ = "0.2.0"
