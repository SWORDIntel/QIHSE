import ctypes
import json
from typing import Optional
from .core import _lib

class _KVStore(ctypes.Structure):
    pass

_KVStore_p = ctypes.POINTER(_KVStore)

_lib.qihse_kv_store_create.argtypes = []
_lib.qihse_kv_store_create.restype = _KVStore_p

_lib.qihse_kv_store_destroy.argtypes = [_KVStore_p]
_lib.qihse_kv_store_destroy.restype = None

_lib.qihse_kv_set.argtypes = [_KVStore_p, ctypes.c_char_p, ctypes.c_char_p]
_lib.qihse_kv_set.restype = ctypes.c_bool

_lib.qihse_kv_get.argtypes = [_KVStore_p, ctypes.c_char_p]
_lib.qihse_kv_get.restype = ctypes.POINTER(ctypes.c_char)

_lib.qihse_kv_del.argtypes = [_KVStore_p, ctypes.c_char_p]
_lib.qihse_kv_del.restype = ctypes.c_bool

_lib.qihse_kv_exists.argtypes = [_KVStore_p, ctypes.c_char_p]
_lib.qihse_kv_exists.restype = ctypes.c_bool

_lib.qihse_kv_expire.argtypes = [_KVStore_p, ctypes.c_char_p, ctypes.c_uint64]
_lib.qihse_kv_expire.restype = ctypes.c_bool

_lib.qihse_kv_save.argtypes = [_KVStore_p, ctypes.c_char_p]
_lib.qihse_kv_save.restype = ctypes.c_int

_lib.qihse_kv_load.argtypes = [_KVStore_p, ctypes.c_char_p]
_lib.qihse_kv_load.restype = ctypes.c_int

class KVStore:
    def __init__(self):
        self._ptr = _lib.qihse_kv_store_create()
        if not self._ptr:
            raise RuntimeError("Failed to create KVStore")

    def close(self):
        if self._ptr:
            _lib.qihse_kv_store_destroy(self._ptr)
            self._ptr = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def set(self, key: str, value: str) -> bool:
        return _lib.qihse_kv_set(self._ptr, key.encode('utf-8'), value.encode('utf-8'))

    def get(self, key: str) -> Optional[str]:
        c_str_ptr = _lib.qihse_kv_get(self._ptr, key.encode('utf-8'))
        if not c_str_ptr:
            return None
        c_str = ctypes.cast(c_str_ptr, ctypes.c_char_p).value
        # Use libc to free the malloc'd string returned by qihse_kv_get
        libc = ctypes.CDLL(None)
        libc.free(c_str_ptr)
        return c_str.decode('utf-8')

    def delete(self, key: str) -> bool:
        return _lib.qihse_kv_del(self._ptr, key.encode('utf-8'))

    def exists(self, key: str) -> bool:
        return _lib.qihse_kv_exists(self._ptr, key.encode('utf-8'))
        
    def expire(self, key: str, ttl_ms: int) -> bool:
        return _lib.qihse_kv_expire(self._ptr, key.encode('utf-8'), ttl_ms)
        
    def save(self, filepath: str) -> bool:
        return _lib.qihse_kv_save(self._ptr, filepath.encode('utf-8')) == 0

    def load(self, filepath: str) -> bool:
        return _lib.qihse_kv_load(self._ptr, filepath.encode('utf-8')) == 0

    def get_shard(self, shard_id: str) -> Optional[str]:
        """Retrieve a shard blob by shard name."""
        return self.get(f"shard:{shard_id}")

    def lookup_ip(self, ip: str) -> bool:
        """Check if an individual IP exists in the KV store."""
        return self.exists(f"ip:{ip}")

    def record_finding(self, finding: dict) -> bool:
        """Record a scan finding to the KV store."""
        cve = finding.get("cve_id", "unknown")
        ip_addr = finding.get("ip", "unknown")
        port = finding.get("port", "unknown")
        key = f"finding:{cve}:{ip_addr}:{port}"
        return self.set(key, json.dumps(finding))
