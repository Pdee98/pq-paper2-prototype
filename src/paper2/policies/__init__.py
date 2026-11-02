"""Scheduling uses immutable observations, never sampled future service."""

from dataclasses import dataclass
from types import MappingProxyType

from src.paper2.model.service_times import JOB_CLASSES, nonnegative
from src.paper2.state.core import integer


@dataclass(frozen=True, slots=True)
class WaitingJob:
    job_id: str
    job_class: str
    block_id: str
    enqueue_t: float
    age: float
    fee_rate: int | None = None
    size_bytes: int | None = None


@dataclass(frozen=True, slots=True)
class RunningJob:
    job_id: str
    job_class: str
    block_id: str
    worker_id: int
    elapsed: float


@dataclass(frozen=True, slots=True)
class PendingBlock:
    block_id: str
    arrival_t: float
    deadline_t: float
    waiting: tuple
    running: tuple


@dataclass(frozen=True, slots=True)
class AggregateBlock:
    block_id: str
    arrival_t: float
    deadline_t: float
    waiting: tuple
    running: tuple
    waiting_counts: object


@dataclass(frozen=True, slots=True)
class View:
    waiting: tuple
    blocks: tuple
    k: int
    free_workers: tuple
    worker_pools: tuple
    running: tuple
    estimates: object
    admission_busy: float = 0
    total_busy: float = 0

    @property
    def share(self):
        return self.admission_busy / self.total_busy if self.total_busy else 0.0


def immutable_estimates(values):
    return MappingProxyType(dict(values))


def fifo(job):
    # Engine tuple order is stable creation/enqueue order for equal timestamps.
    return job.enqueue_t


def slack(block, now, view):
    counts = block.waiting_counts if isinstance(block, AggregateBlock) else {
        c: sum(j.job_class == c for j in block.waiting) for c in JOB_CLASSES}
    waiting_work = sum(view.estimates[c] * counts[c] for c in JOB_CLASSES)
    residual = max((max(0, view.estimates[j.job_class] - j.elapsed)
                    for j in block.running), default=0)
    return block.deadline_t - now - waiting_work / view.k - residual


class Policy:
    def __init__(self, spec, k, pool_mode="shared", k_a=None, k_b=None):
        if not isinstance(spec, dict) or "name" not in spec:
            raise ValueError("policy requires name and explicit supported parameters")
        self.name = spec["name"]
        parameters = {
            "fifo": set(), "block_priority": set(), "static_split": {"k_a", "k_b"},
            "priority_floor": {"beta", "W"},
            "deadline_slack": {"m", "beta", "W", "admission_order"},
        }
        if self.name not in parameters or set(spec) - {"name"} - parameters[self.name]:
            raise ValueError("unknown policy or policy parameter")
        if self.name == "static_split":
            self.k_a, self.k_b = spec.get("k_a", k_a), spec.get("k_b", k_b)
            integer(self.k_a, "k_a", 1)
            integer(self.k_b, "k_b", 1)
            if k < 2 or self.k_a + self.k_b != k:
                raise ValueError("static_split requires k>=2 and k_a+k_b=k")
        elif pool_mode != "shared":
            raise ValueError("only static_split supports pool_mode=split")
        self.beta = self.W = self.m = None
        if self.name in ("priority_floor", "deadline_slack"):
            self.beta = nonnegative(spec["beta"], "beta")
            self.W = nonnegative(spec["W"], "W")
            if self.beta > 1 or self.W <= 0:
                raise ValueError("beta must be in [0,1] and W > 0")
        self.admission_order = spec.get("admission_order", "fifo")
        if self.name == "deadline_slack":
            self.m = nonnegative(spec["m"], "m")
            if self.admission_order not in ("fifo", "fee"):
                raise ValueError("admission_order must be fifo or fee")

    def diagnostics(self, now, view):
        values = {}
        if self.W is not None:
            values.update(share=view.share, admission_busy=view.admission_busy,
                          total_busy=view.total_busy, deficit=max(0, self.beta - view.share))
            pairs = [(slack(b, now, view), b.block_id) for b in view.blocks]
            minimum = min(pairs, default=(None, ""))
            values.update(min_slack=minimum[0], min_slack_block_id=minimum[1])
        if self.name == "deadline_slack":
            values.update(est_block_tx=view.estimates["block_tx"], est_block_sig=view.estimates["block_sig"])
        return values

    def choose(self, now, view):
        eligible = list(view.waiting)
        if self.name == "static_split":
            free_pools = {view.worker_pools[w] for w in view.free_workers}
            eligible = [j for j in eligible if ("admission" if j.job_class == "admission" else "block") in free_pools]
        if not eligible or not view.free_workers:
            return None
        admissions = [j for j in eligible if j.job_class == "admission"]
        blocks = [j for j in eligible if j.job_class != "admission"]
        if self.name in ("fifo", "static_split"):
            return min(eligible, key=fifo).job_id
        floor = self.W is not None and view.share < self.beta and admissions
        if self.name in ("block_priority", "priority_floor"):
            return min(admissions if floor else blocks or admissions, key=fifo).job_id
        admission_key = (lambda j: (-j.fee_rate, j.enqueue_t)) if self.admission_order == "fee" else fifo
        urgent = sorted((slack(b, now, view), b.arrival_t, b.block_id) for b in view.blocks if b.waiting)
        if admissions and (floor or not urgent or urgent[0][0] >= self.m):
            return min(admissions, key=admission_key).job_id
        if urgent:
            bid = urgent[0][2]
            ids = {j.job_id for b in view.blocks if b.block_id == bid for j in b.waiting}
            return min((j for j in blocks if j.job_id in ids), key=fifo).job_id
        return min(blocks or admissions, key=fifo).job_id
