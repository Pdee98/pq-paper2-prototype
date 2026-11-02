from __future__ import annotations

import ctypes
import os
from pathlib import Path
from typing import Callable


class LibOQSStatefulError(RuntimeError):
    pass


_StoreCallback = ctypes.CFUNCTYPE(
    ctypes.c_int,
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_size_t,
    ctypes.c_void_p,
)


class _StatefulSignature(ctypes.Structure):
    _fields_ = [
        ("oid", ctypes.c_uint32),
        ("method_name", ctypes.c_char_p),
        ("alg_version", ctypes.c_char_p),
        ("euf_cma", ctypes.c_bool),
        ("suf_cma", ctypes.c_bool),
        ("length_public_key", ctypes.c_size_t),
        ("length_secret_key", ctypes.c_size_t),
        ("length_signature", ctypes.c_size_t),
    ]


class LibOQSStatefulSigner:
    """Small ctypes binding to liboqs's experimental stateful C API."""

    def __init__(
        self,
        mechanism: str,
        *,
        persist_callback: Callable[[bytes], None] | None = None,
        library_path: str | os.PathLike[str] | None = None,
    ) -> None:
        self.mechanism = mechanism
        self._lib = _load_library(library_path)
        self._persist_callback = persist_callback
        self._persisted_state = b""
        self._sig = self._lib.OQS_SIG_STFL_new(mechanism.encode("ascii"))
        if not self._sig:
            raise LibOQSStatefulError("Requested liboqs stateful mechanism is unavailable.")
        self._secret = self._lib.OQS_SIG_STFL_SECRET_KEY_new(mechanism.encode("ascii"))
        if not self._secret:
            self._lib.OQS_SIG_STFL_free(self._sig)
            raise LibOQSStatefulError("liboqs stateful secret-key allocation failed.")
        details = self._sig.contents
        self.public_key_size = int(details.length_public_key)
        self.private_key_size = int(details.length_secret_key)
        self.signature_size = int(details.length_signature)
        self.algorithm_version = details.alg_version.decode("ascii", errors="replace")
        self._store_cb = _StoreCallback(self._store_state)
        # liboqs 0.16.0's LMS callback setter rejects a null context even when
        # the callback itself does not need application context.
        self._store_context = ctypes.c_void_p(1)
        self._lib.OQS_SIG_STFL_SECRET_KEY_SET_store_cb(
            self._secret, self._store_cb, self._store_context
        )
        self.public_key = b""

    def _store_state(self, buffer, length, _context) -> int:
        try:
            state = ctypes.string_at(buffer, length)
            self._persisted_state = state
            if self._persist_callback is not None:
                self._persist_callback(state)
            return 0
        except Exception:
            return -1

    def keygen(self) -> bytes:
        output = (ctypes.c_uint8 * self.public_key_size)()
        if self._lib.OQS_SIG_STFL_keypair(self._sig, output, self._secret) != 0:
            raise LibOQSStatefulError("liboqs stateful key generation failed.")
        self.public_key = bytes(output)
        return self.public_key

    def sign(self, message: bytes) -> bytes:
        if not self.public_key:
            raise LibOQSStatefulError("A stateful key pair must be generated before signing.")
        output = (ctypes.c_uint8 * self.signature_size)()
        output_length = ctypes.c_size_t(self.signature_size)
        message_buffer = (ctypes.c_uint8 * len(message)).from_buffer_copy(message)
        status = self._lib.OQS_SIG_STFL_sign(
            self._sig,
            output,
            ctypes.byref(output_length),
            message_buffer,
            len(message),
            self._secret,
        )
        if status != 0:
            raise LibOQSStatefulError("liboqs stateful signing failed.")
        return bytes(output[: output_length.value])

    def verify(self, message: bytes, signature: bytes, public_key: bytes | None = None) -> bool:
        key = self.public_key if public_key is None else public_key
        if len(key) != self.public_key_size:
            return False
        message_buffer = (ctypes.c_uint8 * len(message)).from_buffer_copy(message)
        signature_buffer = (ctypes.c_uint8 * len(signature)).from_buffer_copy(signature)
        key_buffer = (ctypes.c_uint8 * len(key)).from_buffer_copy(key)
        return self._lib.OQS_SIG_STFL_verify(
            self._sig,
            message_buffer,
            len(message),
            signature_buffer,
            len(signature),
            key_buffer,
        ) == 0

    def close(self) -> None:
        secret, self._secret = self._secret, None
        signature, self._sig = self._sig, None
        if secret:
            self._lib.OQS_SIG_STFL_SECRET_KEY_free(secret)
        if signature:
            self._lib.OQS_SIG_STFL_free(signature)

    def __enter__(self) -> "LibOQSStatefulSigner":
        return self

    def __exit__(self, *_args) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass


def _load_library(path: str | os.PathLike[str] | None) -> ctypes.CDLL:
    if path is None:
        prefix = os.environ.get("OQS_INSTALL_PATH")
        if not prefix:
            raise LibOQSStatefulError("OQS_INSTALL_PATH is not configured.")
        candidates = [Path(prefix) / "lib" / "liboqs.so", Path(prefix) / "lib64" / "liboqs.so"]
        path = next((candidate for candidate in candidates if candidate.is_file()), None)
    if path is None:
        raise LibOQSStatefulError("The project-local liboqs shared library was not found.")
    library = ctypes.CDLL(str(path))
    library.OQS_SIG_STFL_keygen_and_sign_supported.restype = ctypes.c_int
    if library.OQS_SIG_STFL_keygen_and_sign_supported() != 1:
        raise LibOQSStatefulError("liboqs stateful key generation and signing are disabled.")
    library.OQS_SIG_STFL_new.argtypes = [ctypes.c_char_p]
    library.OQS_SIG_STFL_new.restype = ctypes.POINTER(_StatefulSignature)
    library.OQS_SIG_STFL_free.argtypes = [ctypes.POINTER(_StatefulSignature)]
    library.OQS_SIG_STFL_SECRET_KEY_new.argtypes = [ctypes.c_char_p]
    library.OQS_SIG_STFL_SECRET_KEY_new.restype = ctypes.c_void_p
    library.OQS_SIG_STFL_SECRET_KEY_free.argtypes = [ctypes.c_void_p]
    library.OQS_SIG_STFL_SECRET_KEY_SET_store_cb.argtypes = [ctypes.c_void_p, _StoreCallback, ctypes.c_void_p]
    library.OQS_SIG_STFL_keypair.argtypes = [ctypes.POINTER(_StatefulSignature), ctypes.c_void_p, ctypes.c_void_p]
    library.OQS_SIG_STFL_keypair.restype = ctypes.c_int
    library.OQS_SIG_STFL_sign.argtypes = [
        ctypes.POINTER(_StatefulSignature), ctypes.c_void_p, ctypes.POINTER(ctypes.c_size_t),
        ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p,
    ]
    library.OQS_SIG_STFL_sign.restype = ctypes.c_int
    library.OQS_SIG_STFL_verify.argtypes = [
        ctypes.POINTER(_StatefulSignature), ctypes.c_void_p, ctypes.c_size_t,
        ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p,
    ]
    library.OQS_SIG_STFL_verify.restype = ctypes.c_int
    return library
