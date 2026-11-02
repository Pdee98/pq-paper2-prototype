from __future__ import annotations

import hashlib
import random
import re
from dataclasses import dataclass, field
from typing import Sequence, TypeVar


DERIVATION_VERSION = "workload-rng-sha256-v1"
STREAM_NAME_PATTERN = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
MAX_MASTER_SEED = (1 << 256) - 1


class WorkloadRNGError(ValueError):
    """Raised when workload RNG configuration is invalid."""


T = TypeVar("T")


class WorkloadStream:
    """Restricted workload sampling interface.

    The underlying random.Random instance is intentionally not exposed through
    the normal API. This protects against accidental reseeding or state
    replacement by workload consumers; it is not a defense against hostile
    Python introspection.
    """

    __slots__ = ("_rng",)

    def __init__(self, seed: int):
        self._rng = random.Random(seed)

    def random(self) -> float:
        return self._rng.random()

    def randint(self, a: int, b: int) -> int:
        return self._rng.randint(a, b)

    def randrange(self, *args: int) -> int:
        return self._rng.randrange(*args)

    def choice(self, sequence: Sequence[T]) -> T:
        return self._rng.choice(sequence)

    def uniform(self, a: float, b: float) -> float:
        return self._rng.uniform(a, b)


def validate_master_seed(master_seed: int) -> int:
    """Validate a workload-only deterministic seed.

    This seed is for simulation workload choices such as arrivals, transaction
    selection, network delay sampling, and validator scheduling. It must not be
    used for cryptographic key generation, signing, or security decisions.
    """

    if isinstance(master_seed, bool) or not isinstance(master_seed, int):
        raise WorkloadRNGError("Workload master seed must be an integer.")
    if master_seed < 0 or master_seed > MAX_MASTER_SEED:
        raise WorkloadRNGError("Workload master seed must be between 0 and 2^256 - 1.")
    return master_seed


def validate_stream_name(name: str) -> str:
    if not isinstance(name, str) or STREAM_NAME_PATTERN.fullmatch(name) is None:
        raise WorkloadRNGError("Workload RNG stream name is invalid.")
    if "__" in name or name.endswith("_"):
        raise WorkloadRNGError("Workload RNG stream name is ambiguous.")
    return name


def derive_stream_seed(master_seed: int, stream_name: str) -> int:
    """Derive an order-independent stream seed with stable SHA-256 encoding."""

    seed = validate_master_seed(master_seed)
    name = validate_stream_name(stream_name)
    payload = b"\x00".join(
        (
            DERIVATION_VERSION.encode("ascii"),
            str(seed).encode("ascii"),
            name.encode("ascii"),
        )
    )
    return int.from_bytes(hashlib.sha256(payload).digest(), "big")


@dataclass
class WorkloadRNG:
    """Named deterministic RNG streams for workload simulation only.

    Repeated calls to stream(name) return the same advancing WorkloadStream
    wrapper for that name. Independent WorkloadRNG instances with the same
    master seed and stream name reproduce the same sampling sequence. Stream
    seed derivation is independent of stream creation order and does not use
    Python's process-randomized hash().
    """

    master_seed: int
    _streams: dict[str, WorkloadStream] = field(default_factory=dict, init=False, repr=False)

    def __post_init__(self) -> None:
        self.master_seed = validate_master_seed(self.master_seed)

    @property
    def derivation_version(self) -> str:
        return DERIVATION_VERSION

    def stream_seed(self, name: str) -> int:
        return derive_stream_seed(self.master_seed, name)

    def stream(self, name: str) -> WorkloadStream:
        valid_name = validate_stream_name(name)
        if valid_name not in self._streams:
            self._streams[valid_name] = WorkloadStream(self.stream_seed(valid_name))
        return self._streams[valid_name]
