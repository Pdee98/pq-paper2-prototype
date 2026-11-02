from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from src.crypto.base import BackendInfo, CryptoBackend, message_to_bytes


class ClassicalBaselineBackend(CryptoBackend):
    def __init__(self):
        self.private_keys = {}
        self.public_keys = {}
        self._last_signature_size = 64

    def _ensure_keypair(self, signer_id: int) -> None:
        if signer_id in self.private_keys:
            return
        private_key = Ed25519PrivateKey.generate()
        self.private_keys[signer_id] = private_key
        self.public_keys[signer_id] = private_key.public_key()

    def sign(self, message: str | bytes, signer_id: int) -> bytes:
        self._ensure_keypair(signer_id)
        signature = self.private_keys[signer_id].sign(message_to_bytes(message))
        self._last_signature_size = len(signature)
        return signature

    def verify(self, message: str | bytes, signature: bytes, signer_id: int) -> bool:
        self._ensure_keypair(signer_id)
        try:
            self.public_keys[signer_id].verify(signature, message_to_bytes(message))
            return True
        except InvalidSignature:
            return False

    def prepare_signer(self, signer_id: int) -> None:
        self._ensure_keypair(signer_id)

    def get_name(self) -> str:
        return "ed25519_classical"

    def get_signature_size(self) -> int:
        return self._last_signature_size

    def get_public_key_size(self) -> int:
        self._ensure_keypair(0)
        return len(
            self.public_keys[0].public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
        )

    def get_private_key_size(self) -> int:
        self._ensure_keypair(0)
        return len(
            self.private_keys[0].private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    def get_info(self) -> BackendInfo:
        return BackendInfo(
            name=self.get_name(),
            parameter_set="Ed25519",
            implementation="cryptography.hazmat.primitives.asymmetric.ed25519",
            language="Python binding to cryptography backend",
            signature_size=self.get_signature_size(),
            public_key_size=self.get_public_key_size(),
            conformance_status="library-provided Ed25519 baseline; not post-quantum",
        )
