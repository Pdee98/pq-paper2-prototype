from __future__ import annotations

import ctypes
from dataclasses import dataclass

from src.crypto.slh_dsa_openssl_backend import _load_libcrypto


@dataclass(frozen=True)
class OpenSSLSignatureParameters:
    algorithm: str
    signature_size: int
    public_key_size: int


PARAMETERS = {
    item.algorithm: item
    for item in (
        OpenSSLSignatureParameters("SLH-DSA-SHA2-128f", 17_088, 32),
        OpenSSLSignatureParameters("SLH-DSA-SHA2-192s", 16_224, 48),
        OpenSSLSignatureParameters("SLH-DSA-SHA2-192f", 35_664, 48),
        OpenSSLSignatureParameters("SLH-DSA-SHA2-256s", 29_792, 64),
        OpenSSLSignatureParameters("SLH-DSA-SHA2-256f", 49_856, 64),
        OpenSSLSignatureParameters("ML-DSA-44", 2_420, 1_312),
        OpenSSLSignatureParameters("ML-DSA-65", 3_309, 1_952),
        OpenSSLSignatureParameters("ML-DSA-87", 4_627, 2_592),
    )
}


class OpenSSLEVPError(RuntimeError):
    pass


class OpenSSLEVPBackend:
    def __init__(self, algorithm: str) -> None:
        if algorithm not in PARAMETERS:
            raise OpenSSLEVPError("Unsupported OpenSSL signature parameter set.")
        self.parameters = PARAMETERS[algorithm]
        self._lib = _load_libcrypto()
        self._key: int | None = None
        probe = self._new_keygen_context()
        self._lib.EVP_PKEY_CTX_free(probe)

    def _new_keygen_context(self) -> int:
        context = self._lib.EVP_PKEY_CTX_new_from_name(
            None, self.parameters.algorithm.encode("ascii"), b"provider=default"
        )
        if not context:
            raise OpenSSLEVPError("Requested OpenSSL signature algorithm is unavailable.")
        return context

    def keygen(self) -> bytes:
        context = self._new_keygen_context()
        key = ctypes.c_void_p()
        try:
            if self._lib.EVP_PKEY_keygen_init(context) != 1:
                raise OpenSSLEVPError("OpenSSL key-generation initialization failed.")
            if self._lib.EVP_PKEY_keygen(context, ctypes.byref(key)) != 1 or not key.value:
                raise OpenSSLEVPError("OpenSSL key generation failed.")
        finally:
            self._lib.EVP_PKEY_CTX_free(context)
        if self._key is not None:
            self._lib.EVP_PKEY_free(self._key)
        self._key = int(key.value)
        public_key = self.public_key()
        if len(public_key) != self.parameters.public_key_size:
            raise OpenSSLEVPError("OpenSSL returned an unexpected public-key size.")
        return public_key

    def public_key(self) -> bytes:
        if self._key is None:
            raise OpenSSLEVPError("Generate a key before exporting it.")
        length = ctypes.c_size_t()
        if self._lib.EVP_PKEY_get_raw_public_key(self._key, None, ctypes.byref(length)) != 1:
            raise OpenSSLEVPError("OpenSSL public-key export failed.")
        output = ctypes.create_string_buffer(length.value)
        if self._lib.EVP_PKEY_get_raw_public_key(self._key, output, ctypes.byref(length)) != 1:
            raise OpenSSLEVPError("OpenSSL public-key export failed.")
        return output.raw[: length.value]

    def sign(self, message: bytes) -> bytes:
        if self._key is None:
            raise OpenSSLEVPError("Generate a key before signing.")
        context = self._lib.EVP_MD_CTX_new()
        try:
            if not context or self._lib.EVP_DigestSignInit_ex(context, None, None, None, None, self._key, None) != 1:
                raise OpenSSLEVPError("OpenSSL signing initialization failed.")
            length = ctypes.c_size_t()
            data = ctypes.c_char_p(message)
            if self._lib.EVP_DigestSign(context, None, ctypes.byref(length), data, len(message)) != 1:
                raise OpenSSLEVPError("OpenSSL signature sizing failed.")
            output = ctypes.create_string_buffer(length.value)
            if self._lib.EVP_DigestSign(context, output, ctypes.byref(length), data, len(message)) != 1:
                raise OpenSSLEVPError("OpenSSL signing failed.")
            signature = output.raw[: length.value]
            if len(signature) != self.parameters.signature_size:
                raise OpenSSLEVPError("OpenSSL returned an unexpected signature size.")
            return signature
        finally:
            if context:
                self._lib.EVP_MD_CTX_free(context)

    def verify(self, message: bytes, signature: bytes) -> bool:
        if self._key is None:
            raise OpenSSLEVPError("Generate a key before verification.")
        context = self._lib.EVP_MD_CTX_new()
        try:
            if not context or self._lib.EVP_DigestVerifyInit_ex(context, None, None, None, None, self._key, None) != 1:
                raise OpenSSLEVPError("OpenSSL verification initialization failed.")
            return self._lib.EVP_DigestVerify(
                context, ctypes.c_char_p(signature), len(signature), ctypes.c_char_p(message), len(message)
            ) == 1
        finally:
            if context:
                self._lib.EVP_MD_CTX_free(context)

    def close(self) -> None:
        key, self._key = self._key, None
        if key is not None:
            self._lib.EVP_PKEY_free(key)

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass
