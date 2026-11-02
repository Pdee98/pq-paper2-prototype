"""Load one primitive provider per worker; imported frozen adapters own ctypes ABI."""

import ctypes
import hashlib
import time
from pathlib import Path


def loaded_path(library):
    """Resolve a loader soname from Linux's actual mapped-library paths."""
    name=str(library._name)
    if Path(name).is_absolute():return str(Path(name).resolve())
    maps=Path("/proc/self/maps")
    if maps.is_file():
        for row in maps.read_text().splitlines():
            path=row.split()[-1]
            if path.startswith("/") and Path(path).name==Path(name).name:return path
    return "UNVERIFIED resolved path; loader name="+name


class Signer:
    def __init__(self, backend):
        self.backend = backend
        self.leaf = 0
        if backend in ("ed25519", "sleep"):
            from src.crypto.classical_baseline import ClassicalBaselineBackend
            from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
            self.key = ClassicalBaselineBackend()
            self.key.prepare_signer(0)
            self.public_key = self.key.public_keys[0].public_bytes(Encoding.Raw, PublicFormat.Raw)
            self.signature_size = 64
        elif backend == "xmss":
            from src.crypto.liboqs_stateful_ctypes import LibOQSStatefulSigner
            self.key = LibOQSStatefulSigner("XMSS-SHA2_10_256")
            self.public_key = self.key.keygen()
            self.signature_size = self.key.signature_size
        elif backend == "ml_dsa_44":
            from src.crypto.openssl_evp_signature import OpenSSLEVPBackend
            self.key = OpenSSLEVPBackend("ML-DSA-44")
            self.public_key = self.key.keygen()
            self.signature_size = self.key.parameters.signature_size
        elif backend == "slh_dsa_sha2_128s":
            from src.crypto.slh_dsa_openssl_backend import OpenSSLSLHDSABackend
            self.key = OpenSSLSLHDSABackend()
            self.key.prepare_signer(0)
            self.public_key = self.key.get_public_key_bytes(0)
            self.signature_size = self.key.get_signature_size()
        else:
            raise ValueError("unsupported backend: " + backend)

    def sign(self, message):
        if self.backend == "xmss" and self.leaf >= 1024:
            raise ValueError("XMSS H10 exhausted; never reuse a leaf")
        signature = (self.key.sign(message, 0) if self.backend in ("slh_dsa_sha2_128s","ed25519","sleep")
                     else self.key.sign(message))
        if self.backend == "xmss":
            # RFC XMSS index is the first four network-order bytes.
            if int.from_bytes(signature[:4], "big") != self.leaf:
                raise ValueError("native leaf index differs from monotone ledger")
        self.leaf += 1
        return signature

    def close(self):
        if hasattr(self.key, "close"):
            self.key.close()


class Verifier:
    def __init__(self, backend, sleep_seconds=0):
        self.backend, self.sleep_seconds = backend, sleep_seconds
        self.keys = {}
        if backend in ("ed25519", "sleep"):
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            self.import_key = Ed25519PublicKey.from_public_bytes
        elif backend == "xmss":
            from src.crypto.liboqs_stateful_ctypes import LibOQSStatefulSigner
            # Constructor allocates an API context, not an XMSS key/tree.
            self.native = LibOQSStatefulSigner("XMSS-SHA2_10_256")
        elif backend in ("ml_dsa_44", "slh_dsa_sha2_128s"):
            from src.crypto.slh_dsa_openssl_backend import _load_libcrypto
            self.lib = _load_libcrypto()
            f = self.lib.EVP_PKEY_new_raw_public_key_ex
            f.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p,
                          ctypes.c_void_p, ctypes.c_size_t]
            f.restype = ctypes.c_void_p
            self.algorithm = (b"ML-DSA-44" if backend == "ml_dsa_44" else b"SLH-DSA-SHA2-128s")
        else:
            raise ValueError("unsupported backend: " + backend)

    def register(self, public):
        if public in self.keys:
            return
        if self.backend in ("ed25519", "sleep"):
            self.keys[public] = self.import_key(public)
        elif self.backend == "xmss":
            self.keys[public] = public
        else:
            key = self.lib.EVP_PKEY_new_raw_public_key_ex(
                None, self.algorithm, b"provider=default", ctypes.c_char_p(public), len(public))
            if not key:
                raise RuntimeError("native public-key import failed")
            self.keys[public] = key

    def prepare(self, message, signature, public):
        if public not in self.keys:
            raise ValueError("public key must be registered before primitive timing")
        if self.backend in ("ed25519","sleep"):
            return message,signature,public
        if self.backend=="xmss":
            if len(signature)!=self.native.signature_size:return None
            return ((ctypes.c_uint8*len(message)).from_buffer_copy(message),len(message),
                    (ctypes.c_uint8*len(signature)).from_buffer_copy(signature),len(signature),
                    (ctypes.c_uint8*len(public)).from_buffer_copy(public))
        context=self.lib.EVP_MD_CTX_new()
        if not context or self.lib.EVP_DigestVerifyInit_ex(context,None,None,None,None,self.keys[public],None)!=1:
            if context:self.lib.EVP_MD_CTX_free(context)
            raise RuntimeError("EVP verification initialisation failed")
        return context,ctypes.c_char_p(signature),len(signature),ctypes.c_char_p(message),len(message)

    def primitive(self,prepared):
        if self.backend == "sleep":
            time.sleep(self.sleep_seconds)
        if self.backend in ("ed25519", "sleep"):
            message,signature,public=prepared
            from cryptography.exceptions import InvalidSignature
            try:
                self.keys[public].verify(signature, message)
                return True
            except (InvalidSignature, ValueError, TypeError):
                return False
        if self.backend == "xmss":
            return prepared is not None and self.native._lib.OQS_SIG_STFL_verify(self.native._sig,*prepared)==0
        return self.lib.EVP_DigestVerify(*prepared)==1

    def release(self,prepared):
        if self.backend in ("ml_dsa_44","slh_dsa_sha2_128s"):
            self.lib.EVP_MD_CTX_free(prepared[0])

    def verify(self,message,signature,public):
        prepared=self.prepare(message,signature,public)
        try:
            return self.primitive(prepared)
        finally:
            self.release(prepared)

    def metadata(self):
        if self.backend in ("ed25519", "sleep"):
            import cryptography
            return dict(backend=self.backend, implementation="pyca Ed25519" if self.backend == "ed25519"
                        else "deterministic sleep + Ed25519 outcome", version=cryptography.__version__)
        if self.backend == "xmss":
            lib = self.native._lib
            lib.OQS_version.restype = ctypes.c_char_p
            return dict(backend=self.backend, version=lib.OQS_version().decode(),
                        library_path=loaded_path(lib),
                        implementation="frozen liboqs ABI loader + preframed verify-only primitive")
        return dict(backend=self.backend, version=self.lib.OpenSSL_version(0).decode(),
                    library_path=loaded_path(self.lib),
                    implementation="frozen ctypes loader + verify-only EVP public-key import")

    def close(self):
        if self.backend == "xmss":
            self.native.close()
        elif self.backend not in ("ed25519", "sleep"):
            for key in self.keys.values():
                self.lib.EVP_PKEY_free(key)


def negative(signature, label, identity):
    if label == "valid":
        return signature
    if not signature:
        raise ValueError("cannot mutate an empty signature")
    if label == "bit_flip":
        return bytes([signature[0] ^ 1]) + signature[1:]
    if label == "random_bytes":
        return hashlib.shake_256(identity.encode()).digest(len(signature))
    raise ValueError("unsupported invalid label")
