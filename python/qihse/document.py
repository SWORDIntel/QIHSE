import ctypes
from typing import Optional
from .core import _lib
from .kv import KVStore

class _DocumentStore(ctypes.Structure):
    pass

_DocumentStore_p = ctypes.POINTER(_DocumentStore)

_lib.qihse_doc_store_create.argtypes = [ctypes.c_void_p]
_lib.qihse_doc_store_create.restype = _DocumentStore_p

_lib.qihse_doc_store_destroy.argtypes = [_DocumentStore_p]
_lib.qihse_doc_store_destroy.restype = None

_lib.qihse_doc_store_insert_json.argtypes = [_DocumentStore_p, ctypes.c_uint64, ctypes.c_char_p]
_lib.qihse_doc_store_insert_json.restype = ctypes.c_bool

class DocumentStore:
    def __init__(self, kv: KVStore):
        self._kv = kv  # Keep reference alive
        self._ptr = _lib.qihse_doc_store_create(kv._ptr)
        if not self._ptr:
            raise RuntimeError("Failed to create DocumentStore")

    def close(self):
        if self._ptr:
            _lib.qihse_doc_store_destroy(self._ptr)
            self._ptr = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def insert_json(self, doc_id: int, json_payload: str) -> bool:
        return _lib.qihse_doc_store_insert_json(self._ptr, doc_id, json_payload.encode('utf-8'))
