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

_lib.qihse_kv_set.argtypes = [
    _KVStore_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_uint16,
    ctypes.c_uint16,
]
_lib.qihse_kv_set.restype = ctypes.c_bool

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

_lib.qihse_kv_save.argtypes = [_KVStore_p, ctypes.c_char_p]
_lib.qihse_kv_save.restype = ctypes.c_int

_lib.qihse_kv_load.argtypes = [_KVStore_p, ctypes.c_char_p]
_lib.qihse_kv_load.restype = ctypes.c_int

_lib.qihse_auth_can_access.argtypes = [ctypes.c_void_p, ctypes.c_uint16, ctypes.c_uint16]
_lib.qihse_auth_can_access.restype = ctypes.c_bool

# Treat iterator key/value arguments as opaque addresses. Using c_char_p here
# would make ctypes dereference classified bytes before the callback has applied
# the caller's authorization context.
_KV_ITER_CB = ctypes.CFUNCTYPE(
    ctypes.c_bool,
    ctypes.c_void_p,  # const char *key
    ctypes.c_void_p,  # const char *value
    ctypes.c_void_p,  # user_data
)

_lib.qihse_kv_foreach.argtypes = [_KVStore_p, _KV_ITER_CB, ctypes.c_void_p]
_lib.qihse_kv_foreach.restype = None

_lib.qihse_kv_clear.argtypes = [_KVStore_p]
_lib.qihse_kv_clear.restype = ctypes.c_size_t

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

    @staticmethod
    def _authorized(user, classification: int, sci_compartment: int) -> bool:
        return bool(
            _lib.qihse_auth_can_access(
                user,
                ctypes.c_uint16(int(classification)),
                ctypes.c_uint16(int(sci_compartment)),
            )
        )

    def set(
        self,
        key: str,
        value: str,
        classification: int = 0,
        sci_compartment: int = 0,
        user=None,
    ) -> bool:
        """Set a value using an explicit authorization context.

        NULL/None is intentionally only sufficient for data that QIHSE itself
        considers unclassified and uncompartmented. The SDK performs the target
        classification check before entering the storage mutation path so a
        missing context cannot create a classified record through Python.
        """
        if not self._authorized(user, classification, sci_compartment):
            return False
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
        key_bytes = key.encode("utf-8")
        c_str_ptr = _lib.qihse_kv_get_user(self._ptr, key_bytes, user)
        if not c_str_ptr:
            return None
        try:
            c_str = ctypes.cast(c_str_ptr, ctypes.c_char_p).value
            return c_str.decode("utf-8") if c_str else None
        finally:
            _libc.free(c_str_ptr)

    def delete(self, key: str, user=None) -> bool:
        return bool(_lib.qihse_kv_del_user(self._ptr, key.encode("utf-8"), user))

    def exists(self, key: str, user=None) -> bool:
        return bool(_lib.qihse_kv_exists_user(self._ptr, key.encode("utf-8"), user))

    def expire(self, key: str, ttl_ms: int, user=None) -> bool:
        return bool(
            _lib.qihse_kv_expire(
                self._ptr, key.encode("utf-8"), int(ttl_ms), user
            )
        )

    def _authorized_value_bytes(self, key_bytes: bytes, user):
        value_ptr = _lib.qihse_kv_get_user(self._ptr, key_bytes, user)
        if not value_ptr:
            return None
        try:
            raw = ctypes.cast(value_ptr, ctypes.c_char_p).value
            return bytes(raw) if raw is not None else b""
        finally:
            _libc.free(value_ptr)

    def foreach(self, callback: Callable[[str, str], bool], user=None) -> int:
        """Iterate only over key/value pairs visible to ``user``.

        The raw C iterator is used strictly as an internal traversal mechanism.
        Its value pointer is never dereferenced. Each key is re-resolved through
        qihse_kv_get_user() and only an authorized copy is decoded or exposed to
        the Python callback.
        """
        count = [0]

        def _cb(key_ptr, _value_ptr, _user_data):
            if not key_ptr:
                return True
            key_bytes = ctypes.cast(key_ptr, ctypes.c_char_p).value
            if key_bytes is None:
                return True

            value_bytes = self._authorized_value_bytes(key_bytes, user)
            if value_bytes is None:
                return True

            key = key_bytes.decode("utf-8")
            value = value_bytes.decode("utf-8")
            count[0] += 1
            return bool(callback(key, value))

        c_cb = _KV_ITER_CB(_cb)
        _lib.qihse_kv_foreach(self._ptr, c_cb, None)
        return count[0]

    def keys(self, prefix: str = None, user=None) -> list:
        """Return only keys visible to ``user``, optionally by prefix."""
        result = []

        def _cb(key, _val):
            if prefix is None or key.startswith(prefix):
                result.append(key)
            return True

        self.foreach(_cb, user=user)
        return result

    def items(self, prefix: str = None, user=None) -> list:
        """Return only key/value pairs visible to ``user``."""
        result = []

        def _cb(key, val):
            if prefix is None or key.startswith(prefix):
                result.append((key, val))
            return True

        self.foreach(_cb, user=user)
        return result

    def size(self, user=None) -> int:
        """Return the number of live keys visible to ``user``."""
        count = [0]

        def _cb(_key, _val):
            count[0] += 1
            return True

        self.foreach(_cb, user=user)
        return count[0]

    def clear(self, user=None) -> int:
        """Delete only entries visible to ``user``.

        The context-free qihse_kv_clear() primitive is intentionally not
        exposed here because it cannot enforce per-record authorization.
        """
        keys = self.keys(user=user)
        removed = 0
        for key in keys:
            if self.delete(key, user=user):
                removed += 1
        return removed

    def save(self, filepath: str, user=None) -> bool:
        """Export the KV store only when ``user`` can access every live entry.

        QIHSE's legacy C snapshot function has no security-context parameter.
        The SDK therefore performs a deny-all preflight first; selective export
        is not attempted because that would change snapshot semantics and can
        create inference channels.
        """
        unauthorized = [False]

        def _probe(key_ptr, _value_ptr, _user_data):
            if not key_ptr:
                unauthorized[0] = True
                return False
            key_bytes = ctypes.cast(key_ptr, ctypes.c_char_p).value
            if key_bytes is None:
                unauthorized[0] = True
                return False
            value_ptr = _lib.qihse_kv_get_user(self._ptr, key_bytes, user)
            if not value_ptr:
                unauthorized[0] = True
                return False
            _libc.free(value_ptr)
            return True

        c_cb = _KV_ITER_CB(_probe)
        _lib.qihse_kv_foreach(self._ptr, c_cb, None)
        if unauthorized[0]:
            return False
        return _lib.qihse_kv_save(self._ptr, filepath.encode("utf-8")) == 0

    def load(
        self,
        filepath: str,
        user=None,
        *,
        allow_legacy_nontransactional: bool = False,
    ) -> bool:
        """Load a legacy KV snapshot only with explicit insecure compatibility.

        The current C loader destroys the live store before it has fully parsed
        and authorized the replacement snapshot. That cannot be made fail-safe
        from ctypes. Until the C transactional/user-aware loader lands, callers
        must deliberately opt into this legacy behavior.
        """
        if not allow_legacy_nontransactional:
            raise RuntimeError(
                "KVStore.load is blocked by default: the legacy C loader is "
                "non-transactional and has no authorization context"
            )
        return _lib.qihse_kv_load(self._ptr, filepath.encode("utf-8")) == 0

    def get_shard(self, shard_id: str, user=None) -> Optional[str]:
        """Retrieve a shard blob by shard name."""
        return self.get(f"shard:{shard_id}", user=user)

    def lookup_ip(self, ip: str, user=None) -> bool:
        """Check if an individual IP exists in the KV store."""
        return self.exists(f"ip:{ip}", user=user)

    def record_finding(self, finding: dict, user=None) -> bool:
        """Record a scan finding to the KV store."""
        cve = finding.get("cve_id", "unknown")
        ip_addr = finding.get("ip", "unknown")
        port = finding.get("port", "unknown")
        key = f"finding:{cve}:{ip_addr}:{port}"
        return self.set(key, json.dumps(finding), user=user)
