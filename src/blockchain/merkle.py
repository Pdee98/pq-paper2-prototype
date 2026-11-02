import hashlib
from typing import List
from src.blockchain.transaction import Transaction


def hash_data(data: str | bytes) -> str:
    if isinstance(data, bytes):
        return hashlib.sha256(data).hexdigest()
    return hashlib.sha256(data.encode()).hexdigest()


def compute_merkle_root(transactions: List[Transaction]) -> str:
    if not transactions:
        return hash_data("")

    tx_hashes = [hash_data(b"PQ_BLOCKCHAIN_SIM_TX_MERKLE_V1" + tx.serialize()) for tx in transactions]

    while len(tx_hashes) > 1:
        if len(tx_hashes) % 2 == 1:
            tx_hashes.append(tx_hashes[-1])

        new_level = []
        for i in range(0, len(tx_hashes), 2):
            combined = tx_hashes[i] + tx_hashes[i + 1]
            new_level.append(hash_data(combined))

        tx_hashes = new_level

    return tx_hashes[0]
