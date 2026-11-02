from dataclasses import dataclass, field
import hashlib
import math
import time


TX_SIGNATURE_DOMAIN = b"PQ_BLOCKCHAIN_SIM_TX_SIGNATURE_V1"
TX_SERIALIZATION_DOMAIN = b"PQ_BLOCKCHAIN_SIM_TX_SERIALIZED_V1"


def _u32(value: int) -> bytes:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0 or value > 0xFFFFFFFF:
        raise ValueError("value must fit in uint32")
    return value.to_bytes(4, "big")


def _u64(value: int) -> bytes:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0 or value > 0xFFFFFFFFFFFFFFFF:
        raise ValueError("value must fit in uint64")
    return value.to_bytes(8, "big")


def _field(data: bytes) -> bytes:
    return _u32(len(data)) + data


def _text(value: str) -> bytes:
    if not isinstance(value, str):
        raise ValueError("transaction text fields must be strings")
    return _field(value.encode("utf-8"))


def _canonical_amount(value: float | int) -> str:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("transaction amount must be numeric")
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("transaction amount must be finite")
        if value.is_integer():
            return str(int(value))
        return format(value, ".17g")
    return str(value)


@dataclass
class Transaction:
    sender: str
    receiver: str
    amount: float
    timestamp: float = field(default_factory=time.time)
    sender_id: int = -1
    transaction_id: str = ""
    signature: bytes = b""
    signing_time: float = 0.0
    signing_wall_time: float = 0.0
    verification_time: float = 0.0
    verification_wall_time: float = 0.0
    signer_public_key_identity: str = ""
    signer_leaf_index: int | None = None
    signer_rotation_generation: int = 0
    stateful_persistence_overhead: float = 0.0
    stateful_registration_delay: float = 0.0

    def compute_hash(self) -> str:
        return hashlib.sha256(self.signed_payload()).hexdigest()

    def signed_payload(self) -> bytes:
        return b"".join(
            (
                _field(TX_SIGNATURE_DOMAIN),
                _u32(1),
                _u32(self.sender_id if self.sender_id >= 0 else 0xFFFFFFFF),
                _text(self.sender),
                _text(self.receiver),
                _text(_canonical_amount(self.amount)),
                _text(repr(float(self.timestamp))),
                _text(self.transaction_id),
            )
        )

    def serialize(self) -> bytes:
        return b"".join(
            (
                _field(TX_SERIALIZATION_DOMAIN),
                _field(self.signed_payload()),
                _u64(self.sender_id if self.sender_id >= 0 else 0xFFFFFFFFFFFFFFFF),
                _field(bytes(self.signature)),
            )
        )

    def serialized_size(self) -> int:
        return len(self.serialize())

    def sign(self, crypto_backend, signer_id: int) -> None:
        if crypto_backend is None:
            raise ValueError("transaction signing requires a crypto backend")
        if isinstance(signer_id, bool) or not isinstance(signer_id, int) or signer_id < 0:
            raise ValueError("transaction signer_id must be a non-negative integer")
        self.sender_id = signer_id
        start_time = time.perf_counter()
        try:
            self.signature = crypto_backend.sign(self.signed_payload(), signer_id, purpose="transaction")
        except TypeError:
            self.signature = crypto_backend.sign(self.signed_payload(), signer_id)
        self.signing_time = time.perf_counter() - start_time
        self.signing_wall_time = self.signing_time
        metadata_getter = getattr(crypto_backend, "get_last_signature_metadata", None)
        if metadata_getter is not None:
            metadata = metadata_getter(signer_id)
            if metadata is not None:
                self.signer_public_key_identity = metadata.public_key_identity
                self.signer_leaf_index = metadata.leaf_index
                self.signer_rotation_generation = metadata.rotation_generation
                self.stateful_persistence_overhead = metadata.persistence_overhead
                self.stateful_registration_delay = metadata.registration_delay

    def verify_signature(self, crypto_backend) -> bool:
        if crypto_backend is None or self.sender_id < 0 or not self.signature:
            return False
        start_time = time.perf_counter()
        try:
            result = crypto_backend.verify(
                self.signed_payload(),
                bytes(self.signature),
                self.sender_id,
                public_key_identity=self.signer_public_key_identity or None,
                leaf_index=self.signer_leaf_index,
            )
        except TypeError:
            result = crypto_backend.verify(self.signed_payload(), bytes(self.signature), self.sender_id)
        self.verification_time = time.perf_counter() - start_time
        self.verification_wall_time = self.verification_time
        return result is True
