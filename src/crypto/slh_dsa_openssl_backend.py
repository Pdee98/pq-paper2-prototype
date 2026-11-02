from __future__ import annotations

import ctypes
import ctypes.util
from typing import Any

from src.crypto.base import BackendInfo, CryptoBackend, message_to_bytes


ALGORITHM_NAME = "SLH-DSA-SHA2-128s"
ALGORITHM_OID = "2.16.840.1.101.3.4.3.20"
EXPECTED_SIGNATURE_SIZE = 7_856
EXPECTED_PUBLIC_KEY_SIZE = 32
EXPECTED_PRIVATE_KEY_SIZE = 64


class OpenSSLSLHDSAError(RuntimeError):
    """Raised when the required OpenSSL SLH-DSA operation is unavailable."""


class OpenSSLSLHDSABackend(CryptoBackend):
    """FIPS 205 SLH-DSA-SHA2-128s using OpenSSL's default provider."""

    def __init__(self, *, provider: str = "default") -> None:
        if provider != "default":
            raise OpenSSLSLHDSAError("Only the OpenSSL default provider is supported.")
        self.provider = provider
        self._lib = _load_libcrypto()
        self._keys: dict[int, int] = {}
        self._signature_size = EXPECTED_SIGNATURE_SIZE
        self._public_key_size = EXPECTED_PUBLIC_KEY_SIZE
        self._private_key_size: int | None = None

        probe = self._new_keygen_context()
        self._lib.EVP_PKEY_CTX_free(probe)

    def _new_keygen_context(self) -> int:
        context = self._lib.EVP_PKEY_CTX_new_from_name(
            None, ALGORITHM_NAME.encode("ascii"), b"provider=default"
        )
        if not context:
            raise OpenSSLSLHDSAError("OpenSSL SLH-DSA-SHA2-128s is unavailable.")
        return context

    def _ensure_keypair(self, signer_id: int) -> int:
        existing = self._keys.get(signer_id)
        if existing is not None:
            return existing

        context = self._new_keygen_context()
        key = ctypes.c_void_p()
        try:
            if self._lib.EVP_PKEY_keygen_init(context) != 1:
                raise OpenSSLSLHDSAError("OpenSSL SLH-DSA key generation initialization failed.")
            if self._lib.EVP_PKEY_keygen(context, ctypes.byref(key)) != 1 or not key.value:
                raise OpenSSLSLHDSAError("OpenSSL SLH-DSA key generation failed.")
        finally:
            self._lib.EVP_PKEY_CTX_free(context)

        key_value = int(key.value)
        signature_size = int(self._lib.EVP_PKEY_get_size(key_value))
        public_key = self._raw_key_bytes(key_value, public=True)
        private_key = self._raw_key_bytes(key_value, public=False)
        if (
            signature_size != EXPECTED_SIGNATURE_SIZE
            or len(public_key) != EXPECTED_PUBLIC_KEY_SIZE
            or len(private_key) != EXPECTED_PRIVATE_KEY_SIZE
        ):
            self._lib.EVP_PKEY_free(key_value)
            raise OpenSSLSLHDSAError("OpenSSL returned unexpected SLH-DSA parameter sizes.")
        self._signature_size = signature_size
        self._public_key_size = len(public_key)
        self._private_key_size = len(private_key)
        self._keys[signer_id] = key_value
        return key_value

    def _raw_key_bytes(self, key: int, *, public: bool) -> bytes:
        function = self._lib.EVP_PKEY_get_raw_public_key if public else self._lib.EVP_PKEY_get_raw_private_key
        length = ctypes.c_size_t()
        if function(key, None, ctypes.byref(length)) != 1 or length.value <= 0:
            raise OpenSSLSLHDSAError("OpenSSL raw SLH-DSA key export failed.")
        output = ctypes.create_string_buffer(length.value)
        if function(key, output, ctypes.byref(length)) != 1:
            raise OpenSSLSLHDSAError("OpenSSL raw SLH-DSA key export failed.")
        return output.raw[: length.value]

    def prepare_signer(self, signer_id: int) -> None:
        self._ensure_keypair(signer_id)

    def sign(self, message: str | bytes, signer_id: int) -> bytes:
        key = self._ensure_keypair(signer_id)
        data = message_to_bytes(message)
        context = self._lib.EVP_MD_CTX_new()
        if not context:
            raise OpenSSLSLHDSAError("OpenSSL signing context allocation failed.")
        try:
            if self._lib.EVP_DigestSignInit_ex(context, None, None, None, None, key, None) != 1:
                raise OpenSSLSLHDSAError("OpenSSL SLH-DSA signing initialization failed.")
            signature_length = ctypes.c_size_t()
            message_buffer = ctypes.c_char_p(data)
            if self._lib.EVP_DigestSign(
                context, None, ctypes.byref(signature_length), message_buffer, len(data)
            ) != 1:
                raise OpenSSLSLHDSAError("OpenSSL SLH-DSA signature sizing failed.")
            signature = ctypes.create_string_buffer(signature_length.value)
            if self._lib.EVP_DigestSign(
                context, signature, ctypes.byref(signature_length), message_buffer, len(data)
            ) != 1:
                raise OpenSSLSLHDSAError("OpenSSL SLH-DSA signing failed.")
            result = signature.raw[: signature_length.value]
            if len(result) != EXPECTED_SIGNATURE_SIZE:
                raise OpenSSLSLHDSAError("OpenSSL returned an unexpected SLH-DSA signature size.")
            self._signature_size = len(result)
            return result
        finally:
            self._lib.EVP_MD_CTX_free(context)

    def verify(self, message: str | bytes, signature: bytes, signer_id: int) -> bool:
        key = self._ensure_keypair(signer_id)
        data = message_to_bytes(message)
        context = self._lib.EVP_MD_CTX_new()
        if not context:
            raise OpenSSLSLHDSAError("OpenSSL verification context allocation failed.")
        try:
            if self._lib.EVP_DigestVerifyInit_ex(context, None, None, None, None, key, None) != 1:
                raise OpenSSLSLHDSAError("OpenSSL SLH-DSA verification initialization failed.")
            result = self._lib.EVP_DigestVerify(
                context,
                ctypes.c_char_p(bytes(signature)),
                len(signature),
                ctypes.c_char_p(data),
                len(data),
            )
            return result == 1
        finally:
            self._lib.EVP_MD_CTX_free(context)

    def get_name(self) -> str:
        return "slh_dsa_sha2_128s_openssl"

    def get_signature_size(self) -> int:
        return self._signature_size

    def get_public_key_size(self) -> int:
        return self._public_key_size

    def get_private_key_size(self) -> int:
        if self._private_key_size is None:
            self._ensure_keypair(0)
        assert self._private_key_size is not None
        return self._private_key_size

    def get_public_key_bytes(self, signer_id: int) -> bytes:
        return self._raw_key_bytes(self._ensure_keypair(signer_id), public=True)

    def provider_metadata(self) -> dict[str, Any]:
        return {
            "provider": "OpenSSL",
            "provider_version": self._openssl_version(),
            "provider_name": self._provider_name(),
            "algorithm": ALGORITHM_NAME,
            "algorithm_oid": ALGORITHM_OID,
            "signature_size": self.get_signature_size(),
            "public_key_size": self.get_public_key_size(),
            "standards_status": (
                "FIPS 205 algorithm implementation; FIPS-validated module certification not established"
            ),
        }

    def get_info(self) -> BackendInfo:
        metadata = self.provider_metadata()
        return BackendInfo(
            name=self.get_name(),
            parameter_set=ALGORITHM_NAME,
            implementation=(
                f"{metadata['provider_version']} EVP implementation from the "
                f"{metadata['provider_name']} provider; OID={ALGORITHM_OID}"
            ),
            language="OpenSSL C via Python ctypes",
            signature_size=self.get_signature_size(),
            public_key_size=self.get_public_key_size(),
            conformance_status=(
                "FIPS 205 algorithm implementation; FIPS-validated module certification not established"
            ),
        )

    def _openssl_version(self) -> str:
        value = self._lib.OpenSSL_version(0)
        return value.decode("ascii", errors="replace") if value else "unknown"

    def _provider_name(self) -> str:
        if not self._keys:
            self._ensure_keypair(0)
        key = next(iter(self._keys.values()))
        provider = self._lib.EVP_PKEY_get0_provider(key)
        name = self._lib.OSSL_PROVIDER_get0_name(provider) if provider else None
        return name.decode("ascii", errors="replace") if name else "unknown"

    def close(self) -> None:
        keys, self._keys = self._keys, {}
        for key in keys.values():
            self._lib.EVP_PKEY_free(key)

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass


def _load_libcrypto() -> ctypes.CDLL:
    library_name = ctypes.util.find_library("crypto")
    if not library_name:
        raise OpenSSLSLHDSAError("OpenSSL libcrypto is unavailable.")
    library = ctypes.CDLL(library_name)

    library.EVP_PKEY_CTX_new_from_name.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]
    library.EVP_PKEY_CTX_new_from_name.restype = ctypes.c_void_p
    library.EVP_PKEY_CTX_free.argtypes = [ctypes.c_void_p]
    library.EVP_PKEY_keygen_init.argtypes = [ctypes.c_void_p]
    library.EVP_PKEY_keygen_init.restype = ctypes.c_int
    library.EVP_PKEY_keygen.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
    library.EVP_PKEY_keygen.restype = ctypes.c_int
    library.EVP_PKEY_free.argtypes = [ctypes.c_void_p]
    library.EVP_PKEY_get_size.argtypes = [ctypes.c_void_p]
    library.EVP_PKEY_get_size.restype = ctypes.c_int
    for name in ("EVP_PKEY_get_raw_public_key", "EVP_PKEY_get_raw_private_key"):
        function = getattr(library, name)
        function.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_size_t)]
        function.restype = ctypes.c_int

    library.EVP_MD_CTX_new.restype = ctypes.c_void_p
    library.EVP_MD_CTX_free.argtypes = [ctypes.c_void_p]
    for name in ("EVP_DigestSignInit_ex", "EVP_DigestVerifyInit_ex"):
        function = getattr(library, name)
        function.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.c_char_p,
            ctypes.c_void_p,
            ctypes.c_char_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
        ]
        function.restype = ctypes.c_int
    library.EVP_DigestSign.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_size_t),
        ctypes.c_void_p,
        ctypes.c_size_t,
    ]
    library.EVP_DigestSign.restype = ctypes.c_int
    library.EVP_DigestVerify.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.c_void_p,
        ctypes.c_size_t,
    ]
    library.EVP_DigestVerify.restype = ctypes.c_int
    library.OpenSSL_version.argtypes = [ctypes.c_int]
    library.OpenSSL_version.restype = ctypes.c_char_p
    library.EVP_PKEY_get0_provider.argtypes = [ctypes.c_void_p]
    library.EVP_PKEY_get0_provider.restype = ctypes.c_void_p
    library.OSSL_PROVIDER_get0_name.argtypes = [ctypes.c_void_p]
    library.OSSL_PROVIDER_get0_name.restype = ctypes.c_char_p
    return library
