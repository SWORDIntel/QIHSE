import ctypes
import json
from typing import Optional, Callable
from .core import _lib


class _KVStore(ctypes.Structure):
    pass


_KVStore_p = ctypes.POINTER(_KVStore)

_lib.qihse_kv_store_create.argtypes = []
_lib.qihse_kv_store_create.restype = _KVStore_p
_lib.qihse_kv_store_destroy.argtypes = [_KVStore_p]
_lib.qihse_kv_store_destroy.restype = None

_lib.qihse_kv_set_user.argtypes = [
    _KVStore_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_uint16,
    ctypes.c_uint16,
    ctypes.c_void_p,
]
_lib.qihse_kv_set_user.restype = ctypes.c_bool
_lib.qihse_kv_get_user.argtypes = [_KVStore_p, ctypes.c_char_p, ctypes.c_void_p]
_lib.qihse_kv_get_user.restype = ctypes.POINTER(ctypes.c_char)
_lib.qihse_kv_del_user.argtypes = [_KVStore_p, ctypes.c_char_p, ctypes.c_void_p]
_lib.qihse_kv_del_user.restype = ctypes.c_bool
_lib.qihse_kv_exists_user.argtypes = [_KVStore_p, ctypes.c_char_p, ctypes.c_void_p]
_lib.qihse_kv_exists_user.restype = ctypes.c_bool
_lib.qihse_kv_expire.argtypes = [_KVStore_p, ctypes.c_char_p, ctypes.c_uint64, ctypes.c_void_p]
_lib.qihse_kv_expire.restype = ctypes.c_bool

_KV_ITER_CB = ctypes.CFUNCTYPE(
    ctypes.c_bool,
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_void_p,
)

_lib.qihse_kv_foreach_user.argtypes = [
    _KVStore_p,
    ctypes.c_void_p,
    _KV_ITER_CB,
    ctypes.c_void_p,
]
_lib.qihse_kv_foreach_user.restype = ctypes.c_bool
_lib.qihse_kv_clear_user.argtypes = [_KVStore_p, ctypes.c_void_p]
_lib.qihse_kv_clear_user.restype = ctypes.c_size_t
_lib.qihse_kv_count_user.argtypes = [_KVStore_p, ctypes.c_void_p]
_lib.qihse_kv_count_user.restype = ctypes.c_size_t
_lib.qihse_kv_save_user.argtypes = [_KVStore_p, ctypes.c_char_p, ctypes.c_void_p]
_lib.qihse_kv_save_user.restype = ctypes.c_int
_lib.qihse_kv_load_user.argtypes = [_KVStore_p, ctypes.c_char_p, ctypes.c_void_p]
_lib.qihse_kv_load_user.restype = ctypes.c_int

_libc = ctypes.CDLL(None)
_libc.free.argtypes = [ctypes.c_void_p]
_libc.free.restype = None


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

    def set(
        self,
        key: str,
        value: str,
        classification: int = 0,
        sci_compartment: int = 0,
        user=None,
    ) -> bool:
        return bool(
            _lib.qihse_kv_set_user(
                self._ptr,
                key.encode("utf-8"),
                value.encode("utf-8"),
                int(classification),
                int(sci_compartment),
                user,
            )
        )

    def get(self, key: str, user=None) -> Optional[str]:
        ptr = _lib.qihse_kv_get_user(self._ptr, key.encode("utf-8"), user)
        if not ptr:
            return None
        try:
            raw = ctypes.cast(ptr, ctypes.c_char_p).value
            return raw.decode("utf-8") if raw is not None else ""
        finally:
            _libc.free(ptr)

    def delete(self, key: str, user=None) -> bool:
        return bool(_lib.qihse_kv_del_user(self._ptr, key.encode("utf-8"), user))

    def exists(self, key: str, user=None) -> bool:
        return bool(_lib.qihse_kv_exists_user(self._ptr, key.encode("utf-8"), user))

    def expire(self, key: str, ttl_ms: int, user=None) -> bool:
        return bool(_lib.qihse_kv_expire(self._ptr, key.encode("utf-8"), int(ttl_ms), user))

    def foreach(self, callback: Callable[[str, str], bool], user=None) -> int:
        count = [0]

        def _cb(key_ptr, value_ptr, _user_data):
            if not key_ptr or not value_ptr:
                return True
            key_raw = ctypes.cast(key_ptr, ctypes.c_char_p).value
            value_raw = ctypes.cast(value_ptr, ctypes.c_char_p).value
            if key_raw is None or value_raw is None:
                return True
            count[0] += 1
            return bool(callback(key_raw.decode("utf-8"), value_raw.decode("utf-8")))

        c_cb = _KV_ITER_CB(_cb)
        if not _lib.qihse_kv_foreach_user(self._ptr, user, c_cb, None):
            raise RuntimeError("KV enumeration failed")
        return count[0]

    def keys(self, prefix: str = None, user=None) -> list:
        result = []

        def _cb(key, _value):
            if prefix is None or key.startswith(prefix):
                result.append(key)
            return True

        self.foreach(_cb, user=user)
        return result

    def items(self, prefix: str = None, user=None) -> list:
        """Return all (key, value) pairs, optionally filtered by prefix.

        Warning: builds a full in-memory list. For large stores, use
        iteritems() instead to stream one pair at a time.
        """
        result = []

        def _cb(key, value):
            if prefix is None or key.startswith(prefix):
                result.append((key, value))
            return True

        self.foreach(_cb, user=user)
        return result

    def iteritems(self, prefix: str = None, user=None):
        """Yield (key, value) pairs one at a time without building a full list.

        Uses a background thread + queue to bridge the blocking C
        qihse_kv_foreach_user call to a Python generator. This avoids the
        memory spike that items() causes for large stores (e.g. 196K
        function metadata records).

        The ``user`` security context is propagated to the underlying
        authorization-aware bulk API so classified-capable data is never
        enumerated without an authenticated principal.

        Args:
            prefix: Optional key prefix filter
            user: Authenticated security context (qihse_user_t *). Required
                  for stores that may contain classified data.

        Yields:
            (key, value) tuples as strings
        """
        import queue
        import threading

        _SENTINEL = object()
        q: queue.Queue = queue.Queue(maxsize=256)

        def _cb(key, val):
            if prefix is None or key.startswith(prefix):
                q.put((key, val))
            return True

        def _run():
            try:
                self.foreach(_cb, user=user)
            except Exception as e:
                q.put(e)
            finally:
                q.put(_SENTINEL)

        t = threading.Thread(target=_run, daemon=True)
        t.start()

        while True:
            item = q.get()
            if item is _SENTINEL:
                break
            if isinstance(item, Exception):
                raise item
            yield item

        t.join(timeout=5)

    def size(self, user=None) -> int:
        return int(_lib.qihse_kv_count_user(self._ptr, user))

    def clear(self, user=None) -> int:
        return int(_lib.qihse_kv_clear_user(self._ptr, user))

    def save(self, filepath: str, user=None) -> bool:
        return _lib.qihse_kv_save_user(self._ptr, filepath.encode("utf-8"), user) == 0

    def load(self, filepath: str, user=None) -> bool:
        return _lib.qihse_kv_load_user(self._ptr, filepath.encode("utf-8"), user) == 0

    def get_shard(self, shard_id: str, user=None) -> Optional[str]:
        return self.get(f"shard:{shard_id}", user=user)

    def lookup_ip(self, ip: str, user=None) -> bool:
        return self.exists(f"ip:{ip}", user=user)

    def record_finding(self, finding: dict, user=None) -> bool:
        cve = finding.get("cve_id", "unknown")
        ip_addr = finding.get("ip", "unknown")
        port = finding.get("port", "unknown")
        key = f"finding:{cve}:{ip_addr}:{port}"
        return self.set(key, json.dumps(finding), user=user)
