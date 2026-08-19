import ctypes
from typing import Optional
from .core import _lib, VectorDB
from .kv import KVStore
from .document import DocumentStore
from .timeseries import TimeSeriesDB

class UWPContext(ctypes.Structure):
    _fields_ = [
        ("kv", ctypes.c_void_p),
        ("vdb", ctypes.c_void_p),
        ("doc", ctypes.c_void_p),
        ("col", ctypes.c_void_p),
        ("tsdb", ctypes.c_void_p),
        ("stream", ctypes.c_void_p),
    ]

_lib.qihse_start_uwp_server.argtypes = [ctypes.POINTER(UWPContext), ctypes.c_uint16, ctypes.c_char_p]
_lib.qihse_start_uwp_server.restype = ctypes.c_bool

_lib.qihse_auth_is_operator_password_default.argtypes = []
_lib.qihse_auth_is_operator_password_default.restype = ctypes.c_bool

_lib.qihse_auth_modify_user.argtypes = [
    ctypes.c_void_p,
    ctypes.c_uint32,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_int,
    ctypes.c_int,
]
_lib.qihse_auth_modify_user.restype = ctypes.c_bool

class UWPServer:
    @staticmethod
    def start(port: int, bind_address: str, 
              kv: Optional[KVStore] = None,
              vdb: Optional[VectorDB] = None,
              doc: Optional[DocumentStore] = None,
              tsdb: Optional[TimeSeriesDB] = None):
        
        if _lib.qihse_auth_is_operator_password_default():
            op_user = _lib.qihse_auth_get_user(0)
            _lib.qihse_auth_modify_user(op_user, 0, b"admin", b"SecureOpPass_2026!", -1, -1)

        ctx = UWPContext()
        ctx.kv = ctypes.cast(kv._ptr, ctypes.c_void_p) if kv else None
        ctx.vdb = ctypes.cast(vdb._ptr, ctypes.c_void_p) if vdb else None
        ctx.doc = ctypes.cast(doc._ptr, ctypes.c_void_p) if doc else None
        ctx.col = None # Optional/unimplemented in python
        ctx.tsdb = ctypes.cast(tsdb._ptr, ctypes.c_void_p) if tsdb else None
        ctx.stream = None # Optional/unimplemented in python
        
        addr = bind_address.encode('utf-8') if bind_address else None
        return _lib.qihse_start_uwp_server(ctypes.byref(ctx), port, addr)
