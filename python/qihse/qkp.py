"""ctypes bindings for the QKP1 sealed transport (client role).

The Python controller SDK stays pure-socket for cleartext RESP; when a
QKP identity is configured these bindings drive the SAME in-library
handshake and seal primitives the C controller uses (ML-KEM-1024 +
ML-DSA-87 + ChaCha20-Poly1305), doing the socket I/O through the fd the
caller already owns.  No crypto exists in this file on purpose: the
validated module in libqihse is the only implementation.

Loading: libqihse.so is resolved the same way the native SDK resolves it
(LD_LIBRARY_PATH or the system library path).  Import failure of the
library is deferred until a QKP session is actually requested, so
cleartext-only users need no native library at all.
"""

from __future__ import annotations

import ctypes
import os

__all__ = ["QKPLibraryError", "QKPHandshakeError", "QKPSealError", "negotiate_client"]

QIHSE_QKP_MAX_PAYLOAD = 16384


class QKPLibraryError(RuntimeError):
    """libqihse could not be loaded for QKP use."""


class QKPHandshakeError(ConnectionError):
    """The CNSA 2.0 handshake failed or was refused; the fd is dead."""


class QKPSealError(ConnectionError):
    """A sealed frame could not be sent or opened; the stream is dead."""


class _QkpConfig(ctypes.Structure):
    _fields_ = [
        ("dsa_key_path", ctypes.c_char_p),
        ("kem_key_path", ctypes.c_char_p),
        ("kem_pub_path", ctypes.c_char_p),
        ("trusted_pubs", ctypes.POINTER(ctypes.c_char_p)),
        ("trusted_count", ctypes.c_size_t),
        ("node_id", ctypes.c_char_p),
        ("require", ctypes.c_bool),
    ]


_lib_cache: ctypes.CDLL | None = None


def _load() -> ctypes.CDLL:
    global _lib_cache
    if _lib_cache is not None:
        return _lib_cache
    errors = []
    for candidate in ("libqihse.so", os.path.join(
            os.environ.get("QIHSE_LIB_DIR", ""), "libqihse.so") if os.environ.get("QIHSE_LIB_DIR") else None):
        if not candidate:
            continue
        try:
            lib = ctypes.CDLL(candidate)
            _bind(lib)
            _lib_cache = lib
            return lib
        except OSError as exc:
            errors.append(f"{candidate}: {exc}")
    raise QKPLibraryError(
        "cannot load libqihse.so for QKP (set LD_LIBRARY_PATH or "
        "QIHSE_LIB_DIR): " + "; ".join(errors))


def _bind(lib: ctypes.CDLL):
    lib.qihse_qkp_client_negotiate.restype = ctypes.c_int
    lib.qihse_qkp_client_negotiate.argtypes = [
        ctypes.c_int,                       # fd
        ctypes.POINTER(_QkpConfig),
        ctypes.POINTER(ctypes.c_void_p),    # out session
    ]
    lib.qihse_qkp_send_sealed.restype = ctypes.c_bool
    lib.qihse_qkp_send_sealed.argtypes = [ctypes.c_void_p, ctypes.c_int,
                                          ctypes.c_char_p, ctypes.c_size_t]
    lib.qihse_qkp_recv_sealed.restype = ctypes.c_ssize_t
    lib.qihse_qkp_recv_sealed.argtypes = [ctypes.c_void_p, ctypes.c_int,
                                          ctypes.c_char_p, ctypes.c_size_t]
    lib.qihse_qkp_session_free.argtypes = [ctypes.c_void_p]


QIHSE_QKP_SECURE = 0
QIHSE_QKP_CLEARTEXT = 1
QIHSE_QKP_REJECTED = 2


class QKPSession:
    """A sealed session bound to the caller's socket fd.  The socket must
    already be connected; the handshake is run on construction."""

    __slots__ = ("_lib", "_handle", "_fd")

    def __init__(self, lib: ctypes.CDLL, handle: int, fd: int):
        self._lib = lib
        self._handle = ctypes.c_void_p(handle)
        self._fd = fd

    def send(self, data: bytes) -> None:
        if not self._lib.qihse_qkp_send_sealed(self._handle, self._fd,
                                               data, len(data)):
            raise QKPSealError("sealed send failed; stream is dead")

    def recv(self, size: int = QIHSE_QKP_MAX_PAYLOAD) -> bytes:
        cap = max(1, min(size, QIHSE_QKP_MAX_PAYLOAD))
        buf = ctypes.create_string_buffer(cap)
        n = self._lib.qihse_qkp_recv_sealed(self._handle, self._fd, buf, cap)
        if n < 0:
            raise QKPSealError(
                f"sealed recv failed ({n}): crypto/replay refusal or dead fd")
        return buf.raw[:n]

    def close(self) -> None:
        if self._handle:
            self._lib.qihse_qkp_session_free(self._handle)
            self._handle = ctypes.c_void_p(0)


def negotiate_client(sock_fd: int, *,
                     identity_dir: str,
                     trusted_pubs: list[str],
                     node_id: str | None = None) -> QKPSession:
    """Run the client side of QKP1 over an already-connected fd.

    identity_dir is a qihse_keygen output directory; trusted_pubs are the
    server's ML-DSA-87 public PEM paths.  Any non-SECURE outcome raises
    (this client never downgrades to cleartext) and leaves the fd dead.
    """
    lib = _load()
    dsa_key = os.path.join(identity_dir, "qihse_dsa_key.pem").encode()
    pubs = [p.encode() for p in trusted_pubs]
    arr = (ctypes.c_char_p * max(1, len(pubs)))(*(pubs or [b""]))
    cfg = _QkpConfig(
        dsa_key_path=dsa_key,
        kem_key_path=None,
        kem_pub_path=None,
        trusted_pubs=arr if pubs else None,
        trusted_count=len(pubs),
        node_id=(node_id or f"pyctrl[{os.getpid()}]").encode(),
        require=True,
    )
    handle = ctypes.c_void_p(0)
    rc = lib.qihse_qkp_client_negotiate(sock_fd, ctypes.byref(cfg),
                                        ctypes.byref(handle))
    if rc != QIHSE_QKP_SECURE or not handle:
        raise QKPHandshakeError(
            f"QKP handshake refused (rc={rc}); fd is dead")
    return QKPSession(lib, handle.value, sock_fd)
