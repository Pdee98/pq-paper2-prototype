import hashlib
import time
from typing import List
from src.blockchain.transaction import Transaction
from src.blockchain.merkle import compute_merkle_root


class Block:
    def __init__(
        self,
        index: int,
        transactions: List[Transaction],
        previous_hash: str,
        proposer_id: int = -1,
        timestamp: float | None = None,
        nonce: int = 0,
        signature: bytes = b"",
        signer_public_key_identity: str = "",
        signer_leaf_index: int | None = None,
        signer_rotation_generation: int = 0,
        stateful_persistence_overhead: float = 0.0,
        stateful_registration_delay: float = 0.0,
        signing_time: float = 0.0,
        signing_wall_time: float = 0.0,
        verification_wall_time: float = 0.0,
    ):
        self.index = index
        self.timestamp = time.time() if timestamp is None else timestamp
        self.transactions = transactions
        self.previous_hash = previous_hash
        self.proposer_id = proposer_id
        self.nonce = nonce
        self.merkle_root = compute_merkle_root(transactions)
        self.hash = self.compute_hash()
        self.signature = signature
        self.signer_public_key_identity = signer_public_key_identity
        self.signer_leaf_index = signer_leaf_index
        self.signer_rotation_generation = signer_rotation_generation
        self.stateful_persistence_overhead = stateful_persistence_overhead
        self.stateful_registration_delay = stateful_registration_delay
        self.signing_time = signing_time
        self.signing_wall_time = signing_wall_time
        self.verification_wall_time = verification_wall_time

    def compute_hash(self) -> str:
        current_merkle_root = compute_merkle_root(self.transactions)
        block_string = (
            str(self.index)
            + str(self.timestamp)
            + current_merkle_root
            + self.previous_hash
            + str(self.proposer_id)
            + str(self.nonce)
        )
        return hashlib.sha256(block_string.encode()).hexdigest()

    def get_signable_message(self) -> str:
        return self.hash

    def estimate_size(self) -> int:
        return len(self.serialize())

    def header_bytes(self) -> bytes:
        fields = [
            str(self.index).encode("utf-8"),
            repr(float(self.timestamp)).encode("utf-8"),
            self.previous_hash.encode("utf-8"),
            str(self.proposer_id).encode("utf-8"),
            str(self.nonce).encode("utf-8"),
            self.merkle_root.encode("utf-8"),
            self.hash.encode("utf-8"),
        ]
        return b"".join(len(field).to_bytes(4, "big") + field for field in fields)

    def serialize(self) -> bytes:
        transactions = [tx.serialize() for tx in self.transactions]
        return b"".join(
            (
                len(b"PQ_BLOCKCHAIN_SIM_BLOCK_V1").to_bytes(4, "big"),
                b"PQ_BLOCKCHAIN_SIM_BLOCK_V1",
                len(self.header_bytes()).to_bytes(4, "big"),
                self.header_bytes(),
                len(transactions).to_bytes(4, "big"),
                b"".join(len(tx).to_bytes(4, "big") + tx for tx in transactions),
                len(self.signature).to_bytes(4, "big"),
                bytes(self.signature),
            )
        )

    def clone(self) -> "Block":
        cloned_transactions = [
            Transaction(
                sender=tx.sender,
                receiver=tx.receiver,
                amount=tx.amount,
                timestamp=tx.timestamp,
                sender_id=tx.sender_id,
                transaction_id=tx.transaction_id,
                signature=bytes(tx.signature),
                signing_time=tx.signing_time,
                signing_wall_time=getattr(tx, "signing_wall_time", tx.signing_time),
                verification_time=tx.verification_time,
                verification_wall_time=getattr(tx, "verification_wall_time", tx.verification_time),
                signer_public_key_identity=tx.signer_public_key_identity,
                signer_leaf_index=tx.signer_leaf_index,
                signer_rotation_generation=tx.signer_rotation_generation,
                stateful_persistence_overhead=tx.stateful_persistence_overhead,
                stateful_registration_delay=tx.stateful_registration_delay,
            )
            for tx in self.transactions
        ]

        cloned = Block(
            index=self.index,
            transactions=cloned_transactions,
            previous_hash=self.previous_hash,
            proposer_id=self.proposer_id,
            timestamp=self.timestamp,
            nonce=self.nonce,
            signature=bytes(self.signature),
            signer_public_key_identity=self.signer_public_key_identity,
            signer_leaf_index=self.signer_leaf_index,
            signer_rotation_generation=self.signer_rotation_generation,
            stateful_persistence_overhead=self.stateful_persistence_overhead,
            stateful_registration_delay=self.stateful_registration_delay,
            signing_time=getattr(self, "signing_time", 0.0),
            signing_wall_time=getattr(self, "signing_wall_time", getattr(self, "signing_time", 0.0)),
            verification_wall_time=getattr(self, "verification_wall_time", 0.0),
        )
        cloned.hash = self.hash
        return cloned
