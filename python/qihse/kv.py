import ctypes
import json
from typing import Optional, Callable
from .core import _lib


class _KVStore(ctypes.Structure):
    pass


_KVStore_p = ctypes.POINTER(_KVStore)


class _KVRecordMeta(ctypes.Structure):
    _fields_ = [
        ("classification", ctypes.c_uint16),
        ("sci_compartment", ctypes.c_uint16),
        ("expire_time_ms", ctypes.c_uint64),
        ("flags", ctypes.c_uint8),
    ]

_lib.qihse_kv_store_create.argtypes = []
_lib.qihse_kv_store_create.restype = _KVStore_p
_lib.qihse_kv_store_create_user.argtypes = [ctypes.c_void_p]
_lib.qihse_kv_store_create_user.restype = _KVStore_p
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

_KV_BATCH_MAX_RECORDS = 4096
_KV_BATCH_MAX_BYTES = 64 * 1024 * 1024

class _KVBatchSetRecord(ctypes.Structure):
    _fields_ = [
        ("key", ctypes.c_char_p),
        ("value", ctypes.c_char_p),
        ("expire_time_ms", ctypes.c_uint64),
        ("classification", ctypes.c_uint16),
        ("sci_compartment", ctypes.c_uint16),
    ]

_lib.qihse_kv_set_batch_durable_user.argtypes = [
    _KVStore_p,
    ctypes.POINTER(_KVBatchSetRecord),
    ctypes.c_size_t,
    ctypes.c_void_p,
]
_lib.qihse_kv_set_batch_durable_user.restype = ctypes.c_bool
_lib.qihse_kv_get_user.argtypes = [_KVStore_p, ctypes.c_char_p, ctypes.c_void_p]
_lib.qihse_kv_get_user.restype = ctypes.POINTER(ctypes.c_char)
_lib.qihse_kv_meta_user.argtypes = [
    _KVStore_p, ctypes.c_char_p, ctypes.c_void_p,
    ctypes.POINTER(_KVRecordMeta),
]
_lib.qihse_kv_meta_user.restype = ctypes.c_bool
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
_foreach_prefix_native = getattr(_lib, "qihse_kv_foreach_prefix_user", None)
if _foreach_prefix_native is not None:
    _foreach_prefix_native.argtypes = [
        _KVStore_p,
        ctypes.c_char_p,
        ctypes.c_void_p,
        _KV_ITER_CB,
        ctypes.c_void_p,
    ]
    _foreach_prefix_native.restype = ctypes.c_bool
_lib.qihse_kv_clear_user.argtypes = [_KVStore_p, ctypes.c_void_p]
_lib.qihse_kv_clear_user.restype = ctypes.c_size_t
_lib.qihse_kv_count_user.argtypes = [_KVStore_p, ctypes.c_void_p]
_lib.qihse_kv_count_user.restype = ctypes.c_size_t
_lib.qihse_kv_save_user.argtypes = [_KVStore_p, ctypes.c_char_p, ctypes.c_void_p]
_lib.qihse_kv_save_user.restype = ctypes.c_int
_lib.qihse_kv_load_user.argtypes = [_KVStore_p, ctypes.c_char_p, ctypes.c_void_p]
_lib.qihse_kv_load_user.restype = ctypes.c_int
_lib.qihse_user_get_tenant_id.argtypes = [ctypes.c_void_p]
_lib.qihse_user_get_tenant_id.restype = ctypes.c_uint32
_lib.qihse_user_get_role.argtypes = [ctypes.c_void_p]
_lib.qihse_user_get_role.restype = ctypes.c_uint16
_lib.qihse_kv_bulk_load_begin.argtypes = [_KVStore_p]
_lib.qihse_kv_bulk_load_begin.restype = None
_lib.qihse_kv_bulk_load_end.argtypes = [_KVStore_p]
_lib.qihse_kv_bulk_load_end.restype = None

_libc = ctypes.CDLL(None)
_libc.free.argtypes = [ctypes.c_void_p]
_libc.free.restype = None

_QIHSE_ROLE_OPERATOR = 0
_QIHSE_TENANT_SYSTEM = 0


def _aimem_internal_key(key: str) -> bool:
    scoped = key
    if key.startswith("t:"):
        slash = key.find("/")
        if slash < 3 or not key[2:slash].isdigit():
            return False
        scoped = key[slash + 1:]
    return scoped.startswith(("aimem:", "aimemv:", "aimem-"))


def _validate_key_scope(key: str, user, *, operation: str) -> None:
    if not isinstance(key, str):
        raise TypeError("KV keys must be strings")
    if not key or "\0" in key:
        raise ValueError("KV keys must be nonempty and cannot contain NUL")
    operator = bool(user) and _lib.qihse_user_get_role(user) == _QIHSE_ROLE_OPERATOR and \
        _lib.qihse_user_get_tenant_id(user) == _QIHSE_TENANT_SYSTEM
    if operator:
        return
    if _aimem_internal_key(key):
        raise PermissionError("AIMEM records require the typed AIMEM interface")
    if bool(user):
        tenant = int(_lib.qihse_user_get_tenant_id(user))
        if tenant != _QIHSE_TENANT_SYSTEM and not (
                key.startswith(f"t:{tenant}/") or key.startswith("commons/")):
            raise PermissionError(f"KV key outside tenant namespace for {operation}")
    elif key.startswith("t:"):
        raise PermissionError("tenant-scoped KV access requires an authenticated principal")


def _is_system_operator(user) -> bool:
    return bool(user) and _lib.qihse_user_get_role(user) == _QIHSE_ROLE_OPERATOR and \
        _lib.qihse_user_get_tenant_id(user) == _QIHSE_TENANT_SYSTEM


class KVStore:
    def __init__(self, *, user=None):
        self._ptr = (_lib.qihse_kv_store_create_user(user) if user is not None
                     else _lib.qihse_kv_store_create())
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

    def set_batch_durable(self, records, *, user) -> bool:
        """Persist a bounded batch of SETs through the authenticated WAL path.

        Each record is a mapping with ``key`` and ``value`` strings, plus
        optional ``expire_time_ms``, ``classification`` and ``sci_compartment``.
        The native operation is not an atomic transaction; a false result may
        leave a recoverable prefix and fences the store until reopen.
        """
        if user is None:
            raise ValueError("durable KV batch requires an authenticated principal")
        bounded_records = []
        for record in records:
            if len(bounded_records) == _KV_BATCH_MAX_RECORDS:
                raise ValueError("durable KV batch record count exceeds native bound")
            bounded_records.append(record)
        records = bounded_records
        if not records:
            raise ValueError("durable KV batch must contain at least one record")
        encoded = []
        native = (_KVBatchSetRecord * len(records))()
        total_bytes = 0
        for i, record in enumerate(records):
            key = record["key"]
            value = record["value"]
            if not isinstance(key, str) or not isinstance(value, str):
                raise TypeError("durable KV keys and values must be strings")
            if not key or "\0" in key or "\0" in value:
                raise ValueError("durable KV keys must be nonempty and keys/values cannot contain NUL")
            _validate_key_scope(key, user, operation="durable batch")
            remaining = _KV_BATCH_MAX_BYTES - total_bytes
            if remaining < 40 or len(key) + len(value) > remaining - 40:
                raise ValueError("durable KV batch exceeds native byte bound")
            key_bytes = key.encode("utf-8")
            value_bytes = value.encode("utf-8")
            expire = int(record.get("expire_time_ms", 0))
            classification = int(record.get("classification", 0))
            sci = int(record.get("sci_compartment", 0))
            record_bytes = 40 + len(key_bytes) + len(value_bytes)
            if record_bytes > remaining:
                raise ValueError("durable KV batch exceeds native byte bound")
            if not 0 <= expire < 1 << 64:
                raise ValueError("expire_time_ms is outside uint64 range")
            if not 0 <= classification < 1 << 16 or not 0 <= sci < 1 << 16:
                raise ValueError("classification and sci_compartment must fit uint16")
            total_bytes += 40 + len(key_bytes) + len(value_bytes)
            encoded.append((key_bytes, value_bytes))
            native[i] = _KVBatchSetRecord(
                key_bytes, value_bytes, expire, classification, sci)
        if total_bytes > _KV_BATCH_MAX_BYTES:
            raise ValueError("durable KV batch exceeds native byte bound")
        return bool(_lib.qihse_kv_set_batch_durable_user(
            self._ptr, native, len(records), user))

    def set(
        self,
        key: str,
        value: str,
        classification: int = 0,
        sci_compartment: int = 0,
        user=None,
    ) -> bool:
        _validate_key_scope(key, user, operation="set")
        if not isinstance(value, str) or "\0" in value:
            raise ValueError("KV values must be strings and cannot contain NUL")
        classification = int(classification)
        sci_compartment = int(sci_compartment)
        if not 0 <= classification < (1 << 16) or not 0 <= sci_compartment < (1 << 16):
            raise ValueError("classification and sci_compartment must fit uint16")
        return bool(
            _lib.qihse_kv_set_user(
                self._ptr,
                key.encode("utf-8"),
                value.encode("utf-8"),
                classification,
                sci_compartment,
                user,
            )
        )

    def get(self, key: str, user=None) -> Optional[str]:
        _validate_key_scope(key, user, operation="get")
        ptr = _lib.qihse_kv_get_user(self._ptr, key.encode("utf-8"), user)
        if not ptr:
            return None
        try:
            raw = ctypes.cast(ptr, ctypes.c_char_p).value
            return raw.decode("utf-8") if raw is not None else ""
        finally:
            _libc.free(ptr)

    def meta(self, key: str, *, user) -> Optional[tuple[int, int]]:
        """Read class/SCI for a live row under an explicit principal."""
        if user is None:
            raise ValueError("QIHSE metadata read requires a principal")
        _validate_key_scope(key, user, operation="metadata read")
        record = _KVRecordMeta()
        if not _lib.qihse_kv_meta_user(
                self._ptr, key.encode("utf-8"), user,
                ctypes.byref(record)):
            return None
        return int(record.classification), int(record.sci_compartment)

    def delete(self, key: str, user=None) -> bool:
        _validate_key_scope(key, user, operation="delete")
        return bool(_lib.qihse_kv_del_user(self._ptr, key.encode("utf-8"), user))

    def exists(self, key: str, user=None) -> bool:
        _validate_key_scope(key, user, operation="exists")
        return bool(_lib.qihse_kv_exists_user(self._ptr, key.encode("utf-8"), user))

    def expire(self, key: str, ttl_ms: int, user=None) -> bool:
        _validate_key_scope(key, user, operation="expire")
        return bool(_lib.qihse_kv_expire(self._ptr, key.encode("utf-8"), int(ttl_ms), user))

    def foreach(self, callback: Callable[[str, str], bool], user=None) -> int:
        return self._foreach(callback, user=user, prefix=None)

    def foreach_prefix(self, prefix: str,
                       callback: Callable[[str, str], bool], user=None) -> int:
        """Enumerate one prefix with native filtering before row authorization."""
        if not isinstance(prefix, str):
            raise TypeError("prefix must be a string")
        if "\x00" in prefix:
            raise ValueError("prefix cannot contain NUL")
        if _foreach_prefix_native is None:
            raise RuntimeError("QIHSE native prefix enumeration is required")
        return self._foreach(callback, user=user, prefix=prefix)

    def _foreach(self, callback: Callable[[str, str], bool], *, user, prefix) -> int:
        count = [0]

        def _cb(key_ptr, value_ptr, _user_data):
            if not key_ptr or not value_ptr:
                return True
            key_raw = ctypes.cast(key_ptr, ctypes.c_char_p).value
            value_raw = ctypes.cast(value_ptr, ctypes.c_char_p).value
            if key_raw is None or value_raw is None:
                return True
            key_text = key_raw.decode("utf-8")
            try:
                _validate_key_scope(key_text, user, operation="enumeration")
            except PermissionError:
                return True
            count[0] += 1
            return bool(callback(key_text, value_raw.decode("utf-8")))

        c_cb = _KV_ITER_CB(_cb)
        if prefix is None:
            ok = _lib.qihse_kv_foreach_user(self._ptr, user, c_cb, None)
        else:
            ok = _foreach_prefix_native(
                self._ptr, prefix.encode("utf-8"), user, c_cb, None)
        if not ok:
            raise RuntimeError("KV enumeration failed")
        return count[0]

    def keys(self, prefix: str = None, user=None) -> list:
        result = []

        def _cb(key, _value):
            if prefix is None or key.startswith(prefix):
                result.append(key)
            return True

        if prefix is None:
            self.foreach(_cb, user=user)
        else:
            self.foreach_prefix(prefix, _cb, user=user)
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

        if prefix is None:
            self.foreach(_cb, user=user)
        else:
            self.foreach_prefix(prefix, _cb, user=user)
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
                if prefix is None:
                    self.foreach(_cb, user=user)
                else:
                    self.foreach_prefix(prefix, _cb, user=user)
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
        count = [0]
        self._foreach(lambda _key, _value: count.__setitem__(0, count[0] + 1) or True,
                      user=user, prefix=None)
        return count[0]

    def clear(self, user=None) -> int:
        if not _is_system_operator(user):
            raise PermissionError("KV clear requires the system Operator")
        return int(_lib.qihse_kv_clear_user(self._ptr, user))

    def save(self, filepath: str, user=None) -> bool:
        if not _is_system_operator(user):
            raise PermissionError("KV export requires the system Operator")
        return _lib.qihse_kv_save_user(self._ptr, filepath.encode("utf-8"), user) == 0

    def load(self, filepath: str, user=None) -> bool:
        if not _is_system_operator(user):
            raise PermissionError("KV import requires the system Operator")
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

    def bulk_load_begin(self) -> None:
        if self._ptr:
            _lib.qihse_kv_bulk_load_begin(self._ptr)

    def bulk_load_end(self) -> None:
        if self._ptr:
            _lib.qihse_kv_bulk_load_end(self._ptr)
