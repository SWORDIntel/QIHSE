import ctypes
from typing import Optional
from .core import _lib

class _TimeSeriesDB(ctypes.Structure):
    pass

_TimeSeriesDB_p = ctypes.POINTER(_TimeSeriesDB)

_lib.qihse_tsdb_create.argtypes = []
_lib.qihse_tsdb_create.restype = _TimeSeriesDB_p

_lib.qihse_tsdb_destroy.argtypes = [_TimeSeriesDB_p]
_lib.qihse_tsdb_destroy.restype = None

_lib.qihse_tsdb_insert.argtypes = [_TimeSeriesDB_p, ctypes.c_uint32, ctypes.c_uint64, ctypes.c_double, ctypes.c_uint16, ctypes.c_uint16]
_lib.qihse_tsdb_insert.restype = ctypes.c_bool

_lib.qihse_tsdb_compress_flush.argtypes = [_TimeSeriesDB_p]
_lib.qihse_tsdb_compress_flush.restype = None

_lib.qihse_tsdb_average_range.argtypes = [_TimeSeriesDB_p, ctypes.c_uint64, ctypes.c_uint64, ctypes.c_void_p]
_lib.qihse_tsdb_average_range.restype = ctypes.c_double

class TimeSeriesDB:
    def __init__(self):
        self._ptr = _lib.qihse_tsdb_create()
        if not self._ptr:
            raise RuntimeError("Failed to create TimeSeriesDB")

    def close(self):
        if self._ptr:
            _lib.qihse_tsdb_destroy(self._ptr)
            self._ptr = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def insert(self, series_id: int, timestamp: int, value: float, classification: int = 0, sci_compartment: int = 0) -> bool:
        return _lib.qihse_tsdb_insert(self._ptr, series_id, timestamp, value, int(classification), int(sci_compartment))

    def flush(self):
        _lib.qihse_tsdb_compress_flush(self._ptr)

    def average_range(self, start_ts: int, end_ts: int, user=None) -> float:
        return _lib.qihse_tsdb_average_range(self._ptr, start_ts, end_ts, user)
