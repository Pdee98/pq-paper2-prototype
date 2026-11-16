"""Phase A literal dispatcher schema and a serial, non-preemptive resource.

There are no calibration tables, random streams or replay adapters here.
The resource drives one callback generator; nested stages retain that callback.
"""
from dataclasses import dataclass
import heapq
import itertools
import math


SCHEMA = "paper2-dispatcher-literal-v1"
COSTS = frozenset(("arrival_pre", "arrival_tail", "block_build", "block_lookup",
    "block_tail", "send_pre", "send_tail", "complete_admission", "complete_block_tx",
    "complete_block_sig", "complete_tail", "accept", "accept_tail"))
BLOCK_FIELDS = frozenset(("build", "lookups", "tail", "accept", "accept_tail"))


def seconds(value):
    if isinstance(value, bool) or not isinstance(value, (float, int)) or not math.isfinite(value) or value < 0:
        raise ValueError("dispatcher costs must be finite nonnegative numbers")
    return value


class LiteralCosts:
    def __init__(self, spec):
        if not isinstance(spec, dict) or set(spec)-{"schema", "mode", "costs", "jobs", "blocks"}:
            raise ValueError("unknown dispatcher schema fields")
        if spec.get("schema") != SCHEMA or spec.get("mode") not in ("legacy", "explicit"):
            raise ValueError("dispatcher requires a supported schema and explicit mode")
        self.mode = spec["mode"]
        self.defaults = self._costs(spec.get("costs", {}))
        self.jobs, self.blocks = {}, {}
        jobs, blocks = spec.get("jobs", {}), spec.get("blocks", {})
        if not isinstance(jobs, dict) or not isinstance(blocks, dict):
            raise ValueError("dispatcher jobs/blocks must be mappings")
        for identity, values in jobs.items():
            self._identity(identity)
            self.jobs[identity] = self._costs(values)
        for identity, values in blocks.items():
            self._identity(identity)
            if not isinstance(values, dict) or set(values)-BLOCK_FIELDS:
                raise ValueError("unknown literal block stage fields")
            result = {}
            for key, value in values.items():
                if key == "lookups":
                    if not isinstance(value, list):
                        raise ValueError("block lookups must be a literal list")
                    result[key] = [seconds(x) for x in value]
                else:
                    result[key] = seconds(value)
            self.blocks[identity] = result
        values = list(self.defaults.values())
        values.extend(v for costs in self.jobs.values() for v in costs.values())
        for costs in self.blocks.values():
            for value in costs.values():
                values.extend(value if isinstance(value, list) else [value])
        self.positive = any(v > 0 for v in values)
        if self.mode == "legacy" and self.positive:
            raise ValueError("legacy dispatcher mode cannot take positive explicit costs")

    @staticmethod
    def _identity(value):
        if not isinstance(value, str) or not value:
            raise ValueError("dispatcher identities must be nonempty strings")

    @staticmethod
    def _costs(values):
        if not isinstance(values, dict) or set(values)-COSTS:
            raise ValueError("unknown literal dispatcher cost")
        return {k: seconds(v) for k, v in values.items()}

    def cost(self, name, job=None):
        return self.jobs.get(job.job_id if job else "", {}).get(name, self.defaults.get(name, 0))

    def block(self, bid, name, n, index=None):
        profile = self.blocks.get(bid, {})
        lookups = profile.get("lookups")
        if lookups is not None and len(lookups) != n:
            raise ValueError("literal lookup count must equal block transaction count")
        if name == "lookups":
            return lookups[index] if lookups is not None else self.defaults.get("block_lookup", 0)
        return profile.get(name, self.defaults.get({"build": "block_build", "tail": "block_tail"}.get(name, name), 0))


@dataclass(frozen=True)
class Stage:
    kind: str
    duration: float
    job_id: str = ""
    block_id: str = ""


class Dispatcher:
    """Callbacks queue while a generator owns the dispatcher across its stages."""
    def __init__(self, owner):
        self.owner = owner
        self.pending = []
        self.serial = itertools.count()
        self.active = None
        self.pump_scheduled = False
        self.stages, self.callbacks = [], []
        self.current_stage = None

    def submit(self, family, identity, iterator, *, completion_order=None):
        serial = next(self.serial)
        rank = 0 if completion_order is not None else 2
        order = completion_order if completion_order is not None else serial
        heapq.heappush(self.pending, (rank, self.owner.t, order, serial, family, identity, iterator))
        self._wake()

    def _wake(self):
        if self.active is None and self.pending and not self.pump_scheduled:
            self.pump_scheduled = True
            self.owner._schedule(self.owner.t, 1, self._pump)

    def _pump(self):
        self.pump_scheduled = False
        if self.active is not None or not self.pending:
            return
        _, release, _, serial, family, identity, iterator = heapq.heappop(self.pending)
        row = dict(id=serial, family=family, identity=identity, release_t=release,
                   start_t=self.owner.t, end_t=None)
        self.callbacks.append(row)
        self.active = (iterator, row)
        self.owner._control("callback_start", **row)
        self._resume()

    def _resume(self):
        if self.current_stage is not None:
            self.current_stage["end_t"] = self.owner.t
            if hasattr(self.stages,'sync'):self.stages.sync(self.current_stage)
            self.owner._control("stage_end", **self.current_stage)
            self.current_stage = None
        iterator, callback = self.active
        while True:
            try:
                stage = next(iterator)
            except StopIteration:
                callback["end_t"] = self.owner.t
                if hasattr(self.callbacks,'sync'):self.callbacks.sync(callback)
                self.owner._control("callback_end", **callback)
                self.active = None
                self._wake()
                return
            if not isinstance(stage, Stage):
                raise TypeError("dispatcher callbacks must yield literal Stage objects")
            duration = seconds(stage.duration)
            row = dict(id=len(self.stages), callback_id=callback["id"], family=callback["family"],
                kind=stage.kind, job_id=stage.job_id, block_id=stage.block_id,
                start_t=self.owner.t, end_t=None, duration=duration)
            self.stages.append(row)
            self.current_stage = row
            self.owner._control("stage_start", **row)
            if duration:
                self.owner._schedule(self.owner.t+duration, 1, self._resume)
                return
            row["end_t"] = self.owner.t
            if hasattr(self.stages,'sync'):self.stages.sync(row)
            self.owner._control("stage_end", **row)
            self.current_stage = None


def route(config, model_type):
    """Legacy/default and all-zero requests enter the unchanged legacy engine."""
    from .engine import Model
    if model_type is not Model:
        raise ValueError("dispatcher schema cannot be combined with a custom model_type")
    costs = LiteralCosts(config["dispatcher"])
    clean = {k: v for k, v in config.items() if k != "dispatcher"}
    for block in clean.get("blocks", []):
        costs.block(block["block_id"], "build", len(block["tx_ids"]))
    if not costs.positive:
        return clean, Model
    if seconds(clean.get("structural_cost", 0)) or seconds(clean.get("state_cost", 0)):
        raise ValueError("positive legacy structural/state charges cannot be combined with positive explicit charges")
    from .explicit import ExplicitModel
    return config, ExplicitModel
