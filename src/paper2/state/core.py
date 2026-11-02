"""Phase 2 state components. Signature IDs are model labels, not real bytes."""

import copy
import heapq
import itertools
import hashlib
import json
import math
from collections import OrderedDict


LABELS = ("valid", "bit_flip", "random_bytes")
CONTEXT = dict(domain_tag="paper2-transaction-v1", chain_id="model-chain",
               alg_id="model-algorithm", param_set_id="model-parameters")


def integer(value, name, minimum=0):
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ValueError(f"{name} must be an integer >= {minimum}")
    return value


def normalize_tx(value, context=None):
    tx = dict(CONTEXT, **(context or {}))
    tx.update(value)
    for field in ("tx_id", "sender", "receiver"):
        if not isinstance(tx.get(field), str) or not tx[field]:
            raise ValueError(f"transaction requires {field}")
    for field in ("nonce", "amount", "fee_rate"):
        integer(tx.get(field), field)
    integer(tx.get("size_bytes"), "size_bytes", 1)
    timestamp = tx.get("timestamp", 0)
    if isinstance(timestamp, bool) or not isinstance(timestamp, (int, float)) or not math.isfinite(timestamp):
        raise ValueError("timestamp must be finite")
    tx["timestamp"] = float(timestamp)
    tx.setdefault("transaction_id", tx["tx_id"])
    tx.setdefault("sig_label", "valid")
    if tx["sig_label"] not in LABELS:
        raise ValueError("unknown sig_label")
    tx.setdefault("public_key_id", "model-key:" + tx["sender"])
    tx.setdefault("signature_id", "model-signature:" + tx["tx_id"] + ":" + tx["sig_label"])
    tx.setdefault("structurally_valid", True)
    if not isinstance(tx["structurally_valid"], bool):
        raise ValueError("structurally_valid must be boolean")
    for field in (*CONTEXT, "public_key_id", "signature_id", "transaction_id"):
        if not isinstance(tx[field], str) or not tx[field]:
            raise ValueError(f"invalid {field}")
    return tx


def cache_key(tx):
    fields = [tx["sender"], tx["receiver"], str(tx["amount"]), repr(float(tx["timestamp"])),
              tx["transaction_id"], tx["nonce"]]
    payload = [tx["domain_tag"], tx["chain_id"], tx["alg_id"], tx["param_set_id"],
               tx["public_key_id"], fields, tx["signature_id"]]
    return hashlib.sha256(json.dumps(payload, ensure_ascii=True, separators=(",", ":"),
                                     allow_nan=False).encode("ascii")).hexdigest()


class SignatureCache:
    def __init__(self, capacity=0, policy="lru", ttl=None, rng=None,
                 value="signature verified valid"):
        if capacity is not None:
            integer(capacity, "cache capacity")
        if policy not in ("lru", "random"):
            raise ValueError("cache policy must be lru or random")
        if ttl is not None and (isinstance(ttl, bool) or not isinstance(ttl, (int, float))
                                or not math.isfinite(ttl) or ttl <= 0):
            raise ValueError("cache TTL must be finite and positive")
        if policy == "random" and rng is None:
            raise ValueError("random cache requires dedicated eviction stream")
        self.capacity, self.policy, self.ttl, self.rng, self.value = capacity, policy, ttl, rng, value
        self.entries = OrderedDict()
        self.context = None
        self.expiry = []
        self.versions = itertools.count()

    @property
    def enabled(self):
        return self.capacity != 0

    def _maintenance(self, now, context):
        removed = []
        if self.context is not None and context != self.context:
            removed.extend((key, "context") for key in self.entries)
            self.entries.clear()
            self.expiry.clear()
        self.context = context
        while self.expiry and self.expiry[0][0] <= now:
            expires, key, version = heapq.heappop(self.expiry)
            entry = self.entries.get(key)
            if entry is not None and entry["version"] == version:
                del self.entries[key]
                removed.append((key, "ttl"))
        return removed

    def lookup(self, key, now, context):
        removed = self._maintenance(now, context)
        entry = self.entries.get(key)
        if entry is not None:
            self.entries.move_to_end(key)
        return entry, removed

    def insert(self, key, proof_job_id, now, context):
        removed = self._maintenance(now, context)
        if not self.enabled:
            return False, removed
        version = next(self.versions)
        self.entries[key] = dict(value=self.value, proof_job_id=proof_job_id, version=version,
                                 expires_t=None if self.ttl is None else now + self.ttl)
        self.entries.move_to_end(key)
        if self.ttl is not None:
            heapq.heappush(self.expiry, (now + self.ttl, key, version))
        if self.capacity is not None and len(self.entries) > self.capacity:
            victim = (next(iter(self.entries)) if self.policy == "lru"
                      else self.rng.choice(tuple(self.entries)))
            del self.entries[victim]
            removed.append((victim, "capacity"))
        return key in self.entries, removed

    def erase(self, key):
        return self.entries.pop(key, None)


class TransactionPool:
    def __init__(self, enabled=False, capacity_bytes=None):
        if not isinstance(enabled, bool):
            raise ValueError("pool enabled must be boolean")
        if capacity_bytes is not None:
            integer(capacity_bytes, "pool capacity_bytes")
        self.enabled, self.capacity_bytes = enabled, capacity_bytes
        self.entries = OrderedDict()
        self.nonces = {}
        self.by_sender = {}
        self.bytes = self.evicted_before_inclusion = 0
        self.eviction_heap = []
        self.insertion_seq = itertools.count()
        self.live_versions = {}

    def contains_nonce(self, sender, nonce):
        return (sender, nonce) in self.nonces

    def remove(self, key):
        tx = self.entries.pop(key, None)
        if tx is not None:
            self.live_versions.pop(key)
            self.bytes -= tx["size_bytes"]
            self.nonces.pop((tx["sender"], tx["nonce"]), None)
            sender_entries = self.by_sender[tx["sender"]]
            del sender_entries[key]
            if not sender_entries:
                del self.by_sender[tx["sender"]]
        return tx

    def insert(self, key, tx):
        if not self.enabled:
            return []
        if key in self.entries or self.contains_nonce(tx["sender"], tx["nonce"]):
            raise ValueError("duplicate pool insertion")
        self.entries[key] = dict(tx)
        version = next(self.insertion_seq)
        self.live_versions[key] = version
        heapq.heappush(self.eviction_heap, (tx["fee_rate"], version, key))
        self.nonces[tx["sender"], tx["nonce"]] = key
        self.by_sender.setdefault(tx["sender"], {})[key] = None
        self.bytes += tx["size_bytes"]
        removed = []
        while self.capacity_bytes is not None and self.bytes > self.capacity_bytes:
            while True:
                _, version, victim = heapq.heappop(self.eviction_heap)
                if self.live_versions.get(victim) == version:
                    break
            removed.append((victim, self.remove(victim)))
            self.evicted_before_inclusion += 1
        return removed


class Ledger:
    def __init__(self, genesis):
        if set(genesis) != {"balances", "next_nonces"}:
            raise ValueError("genesis requires balances and next_nonces")
        self.balances = dict(genesis["balances"])
        self.next_nonces = dict(genesis["next_nonces"])
        for account in set(self.balances) | set(self.next_nonces):
            if not isinstance(account, str) or not account:
                raise ValueError("invalid ledger account")
            integer(self.balances.setdefault(account, 0), "balance")
            integer(self.next_nonces.setdefault(account, 0), "next nonce")

    def record(self):
        return dict(balances=dict(self.balances), next_nonces=dict(self.next_nonces))

    def admission_check(self, tx, pool):
        if tx["nonce"] < self.next_nonces.get(tx["sender"], 0):
            return "stale_nonce"
        if pool.contains_nonce(tx["sender"], tx["nonce"]):
            return "pool_nonce_duplicate"
        if self.balances.get(tx["sender"], 0) < tx["amount"] + tx["fee_rate"] * tx["size_bytes"]:
            return "insufficient_balance"
        return None

    def check_block(self, transactions):
        trial = Ledger(copy.deepcopy(self.record()))
        checks = []
        for tx in transactions:
            sender, receiver = tx["sender"], tx["receiver"]
            debit = tx["amount"] + tx["fee_rate"] * tx["size_bytes"]
            reason = None
            if tx["nonce"] != trial.next_nonces.get(sender, 0):
                reason = "nonce"
            elif trial.balances.get(sender, 0) < debit:
                reason = "insufficient_balance"
            if reason is None:
                trial.balances.setdefault(sender, 0)
                trial.balances.setdefault(receiver, 0)
                trial.next_nonces.setdefault(receiver, 0)
                trial.balances[sender] -= debit
                trial.balances[receiver] += tx["amount"]
                trial.next_nonces[sender] = tx["nonce"] + 1
            checks.append(dict(tx_id=tx["tx_id"], passed=reason is None, reason=reason))
        return trial, checks
