"""Heap event loop with explicit non-preemptive workers and observable policy dispatch."""

from __future__ import annotations

import csv
import heapq
import itertools
import json
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

from .service_times import (ROOT, JOB_CLASSES, STREAM_NAMES, SEED_VERSION,
                            WorkloadStream, CalibrationService, ConstantService,
                            derive_seed, nonnegative, sha256_file)
from .service_times import job_draw_integer
from src.paper2.state import SignatureCache, TransactionPool, Ledger, cache_key, normalize_tx
from .service_times import JOB_DRAW_VERSION, LABEL_SELECTORS
from .dispatch_state import WaitingIndex, BlockIndex, BusyWindow


EVENT_FIELDS = (
    "run_id", "seq", "t", "event", "job_id", "job_class", "tx_id", "block_id",
    "worker_id", "service_time", "q_admission", "q_block", "busy_workers",
    "enqueue_t", "start_t", "end_t", "outcome", "arrival_t", "accept_t", "deadline_t",
)


@dataclass
class Job:
    job_id: str
    job_class: str
    tx_id: str = ""
    block_id: str = ""
    structurally_valid: bool = True
    enqueue_t: float | None = None
    start_t: float | None = None
    end_t: float | None = None
    worker_id: int | None = None
    service_time: float | None = None
    outcome: str | None = None
    status: str = "created"
    sig_label: str = "valid"
    tx: dict | None = None
    cache_key: str = ""
    created_t: float = 0.0
    service_class: str = ""
    admission_origin: bool = False
    block_waiters: list = field(default_factory=list)
    proof_job_id: str = ""


class WorkerPool:
    """Shared FIFO or representable static split (no lending between pools)."""

    def __init__(self, k, mode="shared", k_a=None, k_b=None):
        if isinstance(k, bool) or not isinstance(k, int) or k < 1:
            raise ValueError("k must be a positive integer")
        if mode not in ("shared", "split"):
            raise ValueError("pool mode must be shared or split")
        if mode == "split":
            if any(isinstance(v, bool) or not isinstance(v, int) or v < 1 for v in (k_a, k_b)):
                raise ValueError("split requires positive k_a and k_b")
            if k_a + k_b != k:
                raise ValueError("k_a + k_b must equal k")
        elif k_a is not None or k_b is not None:
            raise ValueError("shared pool does not take split sizes")
        self.k, self.mode, self.k_a = k, mode, k_a
        self.running = {}
        self.waiting = WaitingIndex()
        self.waiting_counts = dict.fromkeys(JOB_CLASSES, 0)

    def available_worker(self, job):
        eligible = range(self.k)
        if self.mode == "split":
            eligible = range(self.k_a) if job.job_class == "admission" else range(self.k_a, self.k)
        return next((w for w in eligible if w not in self.running), None)

    def counts(self):
        return (self.waiting_counts["admission"],
                self.waiting_counts["block_tx"] + self.waiting_counts["block_sig"],
                len(self.running))


EVENT_FIELDS += ("sig_label", "cache_key", "reject_t", "reject_reason", "reject_reasons", "detail", "policy", "chosen_job_id", "share",
                 "admission_busy", "total_busy", "deficit", "min_slack", "min_slack_block_id",
                 "est_block_tx", "est_block_sig", "ewma_alpha")
EVENT_INDEX = {name:i for i,name in enumerate(EVENT_FIELDS)}
JOB_LOG_FIELDS = tuple((EVENT_INDEX[name],name) for name in
    ("job_id","job_class","tx_id","block_id","worker_id","service_time","enqueue_t","start_t","end_t","sig_label","cache_key"))


class Model:
    def __init__(self, config):
        self.config = json.loads(json.dumps(config))
        allowed = {"run_id", "replicate", "k", "pool_mode", "k_a", "k_b", "q_max",
                   "structural_cost", "state_cost", "block_period", "block_start", "deadline",
                   "admissions", "blocks", "service", "output_dir", "transactions", "genesis",
                   "context", "cache", "pool", "generator_manifest", "coalesce_inflight", "policy", "ewma_alpha", "initial_estimates", "policy_view", "block_times", "output", "summary"}
        if set(config) - allowed:
            raise ValueError("unknown config fields: " + str(sorted(set(config) - allowed)))
        self.run_id, self.replicate = config.get("run_id", "phase2"), config.get("replicate", 0)
        self.seeds = {n: derive_seed(self.run_id, n, self.replicate) for n in STREAM_NAMES}
        from src.paper2.policies import Policy
        spec = config.get("policy", {"name": "fifo"})
        self.policy = Policy(spec, config.get("k", 1), config.get("pool_mode", "shared"),
                             config.get("k_a"), config.get("k_b"))
        split = self.policy.name == "static_split"
        self.pool = WorkerPool(config.get("k", 1), "split" if split else "shared",
                               self.policy.k_a if split else None, self.policy.k_b if split else None)
        self.ewma_alpha = nonnegative(config.get("ewma_alpha", 0.2), "ewma_alpha")
        if not 0 < self.ewma_alpha <= 1:
            raise ValueError("ewma_alpha must be in (0,1]")
        estimates = config.get("initial_estimates", dict.fromkeys(JOB_CLASSES, 1))
        if set(estimates) != set(JOB_CLASSES):
            raise ValueError("initial_estimates requires all job classes")
        self.estimates = {c: nonnegative(estimates[c], "initial estimate") for c in JOB_CLASSES}
        self.policy_view = config.get("policy_view", "incremental")
        if self.policy_view not in ("incremental", "full"):
            raise ValueError("policy_view must be incremental or full")
        self.window = BusyWindow(self.policy.W) if self.policy.W is not None else None
        self.block_index = {}
        self.undecided = {}
        self.choose_overheads = []
        self.config.update(policy=spec, ewma_alpha=self.ewma_alpha, initial_estimates=dict(self.estimates),
                           coalesce_inflight=config.get("coalesce_inflight", False))
        self.q_max = config.get("q_max", 1000)
        if isinstance(self.q_max, bool) or not isinstance(self.q_max, int) or self.q_max < 0:
            raise ValueError("q_max must be a nonnegative integer")
        self.structural_cost = nonnegative(config.get("structural_cost", 0), "structural_cost")
        self.state_cost = nonnegative(config.get("state_cost", 0), "state_cost")
        self.period = nonnegative(config.get("block_period", 1), "block_period")
        if not self.period:
            raise ValueError("block_period must be positive")
        self.block_start = nonnegative(config.get("block_start", 0), "block_start")
        self.deadline = nonnegative(config.get("deadline", 1), "deadline")
        service = config.get("service", {"mode": "constant", "seconds": dict.fromkeys(JOB_CLASSES, 1)})
        if service.get("mode") == "constant":
            if set(service) != {"mode", "seconds"}:
                raise ValueError("constant service requires mode and per-class/label seconds")
            self.service = ConstantService(service["seconds"])
        elif service.get("mode") == "calibration":
            if set(service) != {"mode", "selectors"}:
                raise ValueError("calibration requires mode and selectors")
            self.service = CalibrationService(service["selectors"])
        else:
            raise ValueError("unknown service mode")
        self.context = config.get("context", {})
        self.transactions = {tx_id: normalize_tx(dict(tx, tx_id=tx_id), self.context)
                             for tx_id, tx in config.get("transactions", {}).items()}
        self.tx_keys = {}
        self.ledger = Ledger(config["genesis"])
        cp = config.get("cache", {})
        if set(cp) - {"capacity", "policy", "ttl", "erase_on_inclusion", "negative_capacity", "negative_ttl"}:
            raise ValueError("unknown cache configuration")
        self.erase_on_inclusion = cp.get("erase_on_inclusion", False)
        if not isinstance(self.erase_on_inclusion, bool):
            raise ValueError("erase_on_inclusion must be boolean")
        self.cache = SignatureCache(cp.get("capacity", 0), cp.get("policy", "lru"),
                                    cp.get("ttl"), WorkloadStream(self.seeds["cache_evict"]))
        negative_capacity = cp.get("negative_capacity", 0)
        if negative_capacity is None or (negative_capacity and cp.get("negative_ttl") is None):
            raise ValueError("negative cache must be bounded with an explicit TTL")
        self.negative = SignatureCache(negative_capacity, "lru", cp.get("negative_ttl"),
                                       value="signature rejected invalid")
        self.tx_pool = TransactionPool(**config.get("pool", {}))
        self.events, self.rows, self.jobs, self.blocks = [], [], {}, {}
        self.event_writer = None
        self.output = config.get("output", "full")
        if self.output not in ("full", "summary"):
            raise ValueError("output must be full or summary")
        from .summary import OnlineSummary
        self.summary = OnlineSummary(config) if self.output == "summary" else None
        self.row_count = 0
        self.block_transactions, self.block_reasons = {}, {}
        self.pending_admissions = set()
        self.inflight_admissions = {}
        self.accepted_keys = set()
        self.coalesce_inflight = config.get("coalesce_inflight", False)
        if not isinstance(self.coalesce_inflight, bool):
            raise ValueError("coalesce_inflight must be boolean")
        self.proofs, self.verification_history, self.accepted_transactions = {}, [], []
        self.admission_checks = []
        self.serial = itertools.count()
        self.t = self.dispatcher_free = 0.0
        key_labels = {}
        def check_label(tx):
            key = self._key(tx)
            if key in key_labels and key_labels[key] != tx["sig_label"]:
                raise ValueError("identical signature identity cannot have different validity labels")
            key_labels[key] = tx["sig_label"]
        for tx in self.transactions.values():
            check_label(tx)
        for i, admission in enumerate(config.get("admissions", [])):
            tx = self._transaction(admission)
            check_label(tx)
            self._schedule(nonnegative(admission["arrival_t"], "arrival_t"), 2, self._admission, i, tx)
        block_ids = set()
        explicit = config.get("block_times")
        if explicit is not None:
            if len(explicit) != len(config.get("blocks", [])):
                raise ValueError("block_times length must match blocks")
            explicit = [nonnegative(t, "block time") for t in explicit]
            if explicit != sorted(explicit):
                raise ValueError("block_times must be nondecreasing")
        for i, block in enumerate(config.get("blocks", [])):
            self._identifier(block.get("block_id"))
            if block["block_id"] in block_ids:
                raise ValueError("duplicate block_id")
            block_ids.add(block["block_id"])
            if not isinstance(block.get("tx_ids"), list):
                raise ValueError("tx_ids must be a list")
            txs = [self.transactions[tx_id] for tx_id in block["tx_ids"]]
            if block.get("block_sig_label", "valid") not in LABEL_SELECTORS:
                raise ValueError("unknown block_sig_label")
            if not isinstance(block.get("structurally_valid", True), bool):
                raise ValueError("structurally_valid must be boolean")
            self._schedule(explicit[i] if explicit is not None else self.block_start + i * self.period,
                           2, self._block, i, block, txs)

    @staticmethod
    def _identifier(value):
        if not isinstance(value, str) or not value:
            raise ValueError("IDs must be nonempty strings")

    def _key(self, tx):
        # Normalized transaction dictionaries are immutable within a model run.
        identity = id(tx)
        if identity not in self.tx_keys:
            self.tx_keys[identity] = cache_key(tx)
        return self.tx_keys[identity]

    def _transaction(self, spec):
        tx = dict(self.transactions.get(spec["tx_id"], {}))
        if spec.get("sig_label", tx.get("sig_label", "valid")) != tx.get("sig_label", "valid") and "signature_id" not in spec:
            tx.pop("signature_id", None)
        tx.update({k: v for k, v in spec.items() if k != "arrival_t"})
        return normalize_tx(tx, self.context)

    def _schedule(self, t, priority, callback, *args):
        nonnegative(t, "event time")
        heapq.heappush(self.events, (t, priority, next(self.serial), callback, args))

    def _dispatcher(self, cost, callback, *args):
        finish = max(self.t, self.dispatcher_free) + cost
        self.dispatcher_free = finish
        if finish == self.t:
            callback(*args)
        else:
            self._schedule(finish, 1, callback, *args)

    def _log(self, event, job=None, block_id="", **extra):
        qa, qb, busy = self.pool.counts()
        if self.summary is not None:
            counts = [self.pool.waiting_counts[c] for c in JOB_CLASSES]
            # Direct enqueue rows exclude the instantaneous dispatch reservation.
            if "q_admission" in extra and job:
                counts[JOB_CLASSES.index(job.job_class)] -= 1
            bid = job.block_id if job else block_id
            self.summary.observe(self.t, event, counts, job, bid,
                                 self.blocks.get(bid), extra)
            self.row_count += 1
            return
        row = [None]*len(EVENT_FIELDS)
        row[:4] = self.run_id, self.row_count, self.t, event
        row[10:13] = qa, qb, busy
        if job:
            for index, name in JOB_LOG_FIELDS:
                row[index] = getattr(job, name)
            if event == "end":
                row[EVENT_INDEX["outcome"]] = job.outcome
            block_id = job.block_id
        if block_id:
            block = self.blocks[block_id]
            row[EVENT_INDEX["block_id"]] = block_id
            for name in ("arrival_t","accept_t","deadline_t","reject_t","reject_reason","reject_reasons"):
                row[EVENT_INDEX[name]] = block[name]
        for name,value in extra.items():
            row[EVENT_INDEX[name]] = value
        if self.event_writer is None:
            self.rows.append(dict(zip(EVENT_FIELDS,row)))
        else:
            self.event_writer.writerow(row)
        self.row_count += 1

    def _new_job(self, job_id, job_class, tx=None, block_id="", sig_label="valid"):
        job = Job(job_id, job_class, tx_id=tx["tx_id"] if tx else "", block_id=block_id,
                  structurally_valid=tx["structurally_valid"] if tx else True,
                  sig_label=tx["sig_label"] if tx else sig_label, tx=tx,
                  cache_key=self._key(tx) if tx else "", created_t=self.t,
                  service_class=job_class, admission_origin=job_class == "admission")
        self.jobs[job_id] = job
        return job

    def _admission(self, index, tx):
        job = self._new_job(f"admission:{index}", "admission", tx)
        self._log("tx_arrive", job)
        self._dispatcher(self.structural_cost, self._admit_ready, job)

    def _cache_events(self, removed, job, kind):
        for key, reason in removed:
            self._log("cache_evict", job, cache_key=key, detail=kind + ":" + reason)

    @staticmethod
    def _context(tx):
        return tx["domain_tag"], tx["param_set_id"]

    def _lookup(self, cache, job, negative=False):
        if not cache.enabled:
            return None
        entry, removed = cache.lookup(job.cache_key, self.t, self._context(job.tx))
        self._cache_events(removed, job, "negative" if negative else "positive")
        if entry is not None:
            self._log("neg_hit" if negative else "cache_hit", job)
        elif not negative:
            self._log("cache_miss", job)
        return entry

    def _insert_cache(self, job, valid):
        cache = self.cache if valid else self.negative
        if not cache.enabled:
            return
        _, removed = cache.insert(job.cache_key, job.job_id, self.t, self._context(job.tx))
        self._log("cache_insert", job, detail="positive" if valid else "negative")
        self._cache_events(removed, job, "positive" if valid else "negative")

    def _admit_ready(self, job):
        if not job.tx["structurally_valid"]:
            job.status = "struct_reject"
            self._log("struct_reject", job)
            return
        if job.cache_key in self.pending_admissions or job.cache_key in self.tx_pool.entries:
            job.status = "dup_drop"
            self._log("dup_drop", job)
            return
        if self._lookup(self.negative, job, negative=True):
            job.status = "neg_hit"
            return
        self.pending_admissions.add(job.cache_key)
        hit = self._lookup(self.cache, job)
        if hit:
            job.status = "cache_hit"
            self._dispatcher(self.state_cost, self._admit_state, job)
        else:
            self._enqueue(job)

    def _admit_state(self, job):
        reason = ("already_included" if job.cache_key in self.accepted_keys else
                  self.ledger.admission_check(job.tx, self.tx_pool))
        self.pending_admissions.discard(job.cache_key)
        self.admission_checks.append(dict(job_id=job.job_id, key=job.cache_key, t=self.t,
                                           passed=reason is None, reason=reason))
        if reason:
            self._log("state_reject", job, reject_reason="state", reject_reasons="state", detail=reason)
            return
        if self.tx_pool.enabled:
            evicted = self.tx_pool.insert(job.cache_key, job.tx)
            self._log("pool_insert", job)
            for key, tx in evicted:
                self._log("pool_evict", job, cache_key=key, tx_id=tx["tx_id"], detail="capacity")

    def _block(self, index, spec, txs):
        bid = spec["block_id"]
        self.blocks[bid] = dict(arrival_t=self.t, accept_t=None, reject_t=None,
                               deadline_t=self.t + self.deadline, pending=0, valid=False,
                               structurally_rejected=False, reject_reason="", reject_reasons="",
                               state_checks=[])
        self.undecided[bid] = None
        self.block_index[bid] = BlockIndex()
        self.block_transactions[bid] = txs
        self.block_reasons[bid] = set()
        self._log("block_arrive", block_id=bid)
        structurally_valid = spec.get("structurally_valid", True) and all(tx["structurally_valid"] for tx in txs)
        jobs = []
        if structurally_valid:
            jobs = [self._new_job(f"block:{index}:tx:{i}", "block_tx", tx, bid) for i, tx in enumerate(txs)]
            jobs.append(self._new_job(f"block:{index}:sig", "block_sig", block_id=bid,
                                      sig_label=spec.get("block_sig_label", "valid")))
        self.blocks[bid]["pending"] = len(jobs)
        self._dispatcher(self.structural_cost * (len(txs) + 1), self._block_ready,
                         bid, jobs, structurally_valid)

    def _block_ready(self, bid, jobs, structurally_valid):
        if not structurally_valid:
            self.blocks[bid]["structurally_rejected"] = True
            self._log("struct_reject", block_id=bid)
            self._reject(bid, {"structural"})
            return
        for job in jobs:
            if job.job_class == "block_tx" and self._lookup(self.cache, job):
                job.status = "cache_hit"
                self.blocks[bid]["pending"] -= 1
            elif job.job_class == "block_tx" and self._coalesce(job):
                pass
            else:
                self._enqueue(job)

    def _coalesce(self, logical):
        source = self.inflight_admissions.get(logical.cache_key)
        if not self.coalesce_inflight or source is None or source.status not in ("queued", "running"):
            return False
        source.block_waiters.append(logical.block_id)
        logical.status, logical.proof_job_id = "coalesced", source.job_id
        if source.status == "queued" and source.job_class == "admission":
            self.pool.waiting_counts["admission"] -= 1
            self.pool.waiting_counts["block_tx"] += 1
            source.job_class, source.block_id = "block_tx", logical.block_id
            self.pool.waiting.index(source)
            self._log("coalesce_promote", source, detail=logical.job_id)
        else:
            self._log("coalesce_wait", logical, detail=source.job_id)
        if source.status == "queued":
            self.block_index[logical.block_id].enqueue(source, self.pool.waiting.sequence[source.job_id])
        else:
            self.block_index[logical.block_id].running[source.job_id] = source
        return True

    def _enqueue(self, job):
        qa, _, _ = self.pool.counts()
        if job.job_class == "admission" and qa >= self.q_max and self.pool.available_worker(job) is None:
            job.status = "drop"
            self.pending_admissions.discard(job.cache_key)
            self._log("drop", job, detail="queue_capacity")
            return
        key = (["admission", job.tx_id] if job.job_class == "admission" else
               ["block_tx", job.block_id, job.tx_id] if job.job_class == "block_tx" else
               ["block_sig", job.block_id])
        draw = job_draw_integer(self.run_id, self.replicate, "service_" + job.job_class, key)
        job.service_time, job.outcome = self.service.sample(job.job_class, job.sig_label, draw)
        job.enqueue_t, job.status = self.t, "queued"
        if job.admission_origin:
            self.inflight_admissions[job.cache_key] = job
        direct = self.pool.available_worker(job) is not None
        before = self.pool.counts()
        self.pool.waiting.append(job)
        if not job.admission_origin:
            self.block_index[job.block_id].enqueue(job, self.pool.waiting.sequence[job.job_id])
        self.pool.waiting_counts[job.job_class] += 1
        if direct:
            self._log("enqueue", job, q_admission=before[0], q_block=before[1])
        else:
            self._log("enqueue", job)
        self._dispatch()

    def _full_view(self):
        from src.paper2.policies import (WaitingJob, RunningJob, PendingBlock, View, immutable_estimates)
        waiting = tuple(WaitingJob(j.job_id, j.job_class, j.block_id, j.enqueue_t, self.t - j.enqueue_t,
                                   j.tx["fee_rate"] if j.job_class == "admission" else None,
                                   j.tx["size_bytes"] if j.job_class == "admission" else None)
                        for j in self.pool.waiting)
        running = tuple(RunningJob(j.job_id, j.job_class, j.block_id, w, self.t - j.start_t)
                        for w, j in self.pool.running.items())
        pending = []
        # Group once rather than scanning all jobs separately for each block.
        by_block_wait, by_block_run = {}, {}
        for j, original in zip(waiting, self.pool.waiting):
            bids = original.block_waiters if original.admission_origin else [j.block_id]
            for bid in set(bids):
                if bid:
                    by_block_wait.setdefault(bid, []).append(j)
        for r in running:
            job = self.pool.running[r.worker_id]
            bids = job.block_waiters if job.admission_origin else [job.block_id]
            for bid in set(bids):
                by_block_run.setdefault(bid, []).append(r)
        for bid in self.undecided:
            b = self.blocks[bid]
            if b["accept_t"] is None and b["reject_t"] is None:
                pending.append(PendingBlock(bid, b["arrival_t"], b["deadline_t"],
                    tuple(by_block_wait.get(bid, ())), tuple(by_block_run.get(bid, ()))))
        admission_busy, total_busy = self.window.totals(self.t) if self.window else (0.0, 0.0)
        worker_pools = tuple("admission" if w < (self.pool.k_a or 0) else "block"
                             for w in range(self.pool.k)) if self.pool.mode == "split" else ("shared",) * self.pool.k
        return View(waiting, tuple(pending), self.pool.k,
                    tuple(w for w in range(self.pool.k) if w not in self.pool.running), worker_pools,
                    running, immutable_estimates(self.estimates), admission_busy, total_busy)

    def _view(self):
        if self.policy_view == "full":
            return self._full_view()
        from src.paper2.policies import (WaitingJob, RunningJob, AggregateBlock, View, immutable_estimates)
        def observed(j):
            return WaitingJob(j.job_id, j.job_class, j.block_id, j.enqueue_t, self.t-j.enqueue_t,
                              j.tx["fee_rate"] if j.job_class == "admission" else None,
                              j.tx["size_bytes"] if j.job_class == "admission" else None)
        def running(j):
            return RunningJob(j.job_id, j.job_class, j.block_id, j.worker_id, self.t-j.start_t)
        candidates = {}
        for cls in JOB_CLASSES:
            j = self.pool.waiting.head(cls)
            if j is not None:
                candidates[j.job_id] = j
        if self.policy.admission_order == "fee":
            j = self.pool.waiting.head("admission", fee=True)
            if j is not None:
                candidates[j.job_id] = j
        pending = []
        for bid in (self.undecided if self.policy.W is not None else ()):
            b, idx = self.blocks[bid], self.block_index[bid]
            head = idx.head()
            if head is not None:
                candidates[head.job_id] = head
            pending.append(AggregateBlock(bid, b["arrival_t"], b["deadline_t"],
                (observed(head),) if head else (), tuple(running(j) for j in idx.running.values()),
                immutable_estimates(idx.counts)))
        candidates = sorted(candidates.values(), key=lambda j:self.pool.waiting.sequence[j.job_id])
        admission_busy, total_busy = self.window.totals(self.t) if self.window else (0.0, 0.0)
        pools = tuple("admission" if w < self.pool.k_a else "block" for w in range(self.pool.k)) if self.pool.mode == "split" else ("shared",)*self.pool.k
        return View(tuple(observed(j) for j in candidates), tuple(pending), self.pool.k,
            tuple(w for w in range(self.pool.k) if w not in self.pool.running), pools,
            tuple(running(j) for j in self.pool.running.values()), immutable_estimates(self.estimates),
            admission_busy, total_busy)

    def _dispatch(self):
        while self.pool.waiting and len(self.pool.running) < self.pool.k:
            view = self._view()
            begin = time.perf_counter_ns()
            chosen = self.policy.choose(self.t, view)
            self.choose_overheads.append(time.perf_counter_ns() - begin)
            diagnostics = self.policy.diagnostics(self.t, view)
            if chosen is None:
                self._log("dispatch", policy=self.policy.name, chosen_job_id=None,
                          ewma_alpha=self.ewma_alpha, **diagnostics)
                return
            job = self.pool.waiting.items[chosen]
            worker = self.pool.available_worker(job)
            if worker is None:
                raise RuntimeError("policy chose an ineligible job")
            self.pool.waiting.remove(job)
            self.pool.waiting_counts[job.job_class] -= 1
            self._log("dispatch", policy=self.policy.name, chosen_job_id=chosen,
                      ewma_alpha=self.ewma_alpha, **diagnostics)
            self._start(job, worker)

    def _start(self, job, worker):
        job.start_t, job.worker_id, job.status = self.t, worker, "running"
        self.pool.running[worker] = job
        for bid in (job.block_waiters if job.admission_origin else [job.block_id]):
            self.block_index[bid].start(job)
        if self.window:
            self.window.change(self.t, int(job.job_class == "admission"), 1)
        self._log("start", job)
        self._schedule(self.t + job.service_time, 0, self._finish, job)

    def _finish(self, job):
        del self.pool.running[job.worker_id]
        job.end_t, job.status = self.t, "end"
        self._log("end", job)
        self.estimates[job.job_class] = (self.ewma_alpha * (self.t - job.start_t) +
                                          (1 - self.ewma_alpha) * self.estimates[job.job_class])
        if self.window:
            self.window.change(self.t, -int(job.job_class == "admission"), -1)
        for bid in (job.block_waiters if job.admission_origin else [job.block_id]):
            self.block_index[bid].end(job)
        if job.tx:
            if job.outcome == "valid":
                self.proofs[job.cache_key] = job.job_id
                self.verification_history.append(dict(key=job.cache_key, job_id=job.job_id,
                                                       t=self.t, outcome="valid"))
            self._insert_cache(job, job.outcome == "valid")
        if job.admission_origin:
            self.inflight_admissions.pop(job.cache_key, None)
            if job.outcome == "valid":
                self._dispatcher(self.state_cost, self._admit_state, job)
            else:
                self.pending_admissions.discard(job.cache_key)
                self._log("drop", job, detail="invalid_signature")
        bids = list(job.block_waiters)
        if not job.admission_origin:
            bids.append(job.block_id)
        for bid in bids:
            block = self.blocks[bid]
            block["pending"] -= 1
            if job.outcome != "valid":
                self.block_reasons[bid].add("invalid_signature")
            if block["pending"] == 0:
                self._dispatcher(self.state_cost * len(self.block_transactions[bid]),
                                 self._decide_block, bid)
        self._dispatch()

    def _reject(self, bid, reasons):
        ordered = [r for r in ("structural", "invalid_signature", "state") if r in reasons]
        block = self.blocks[bid]
        self.undecided.pop(bid, None)
        self.block_index.pop(bid, None)
        block.update(reject_t=self.t, reject_reason=ordered[0], reject_reasons=";".join(ordered), valid=False)
        self._log("block_reject", block_id=bid, outcome="invalid")

    def _decide_block(self, bid):
        block = self.blocks[bid]
        txs = self.block_transactions[bid]
        trial, checks = self.ledger.check_block(txs)
        block["state_checks"] = checks
        self._log("state_check", block_id=bid, outcome="valid" if all(c["passed"] for c in checks) else "invalid")
        reasons = set(self.block_reasons[bid])
        if any(not c["passed"] for c in checks):
            reasons.add("state")
            self._log("state_reject", block_id=bid, reject_reason="state", reject_reasons="state")
        if reasons:
            self._reject(bid, reasons)
            return
        for tx in txs:
            key = self._key(tx)
            if key not in self.proofs:
                raise RuntimeError("accepted transaction lacks identical-key verification in this run")
            self.accepted_keys.add(key)
            self.accepted_transactions.append(dict(tx=tx, key=key, proof_job_id=self.proofs[key],
                                                   block_id=bid, state_passed=True))
        self.ledger = trial
        for tx in txs:
            key = self._key(tx)
            self.tx_pool.remove(key)
            if self.erase_on_inclusion and self.cache.erase(key):
                self._log("cache_evict", block_id=bid, cache_key=key, detail="positive:inclusion")
        # Committed nonces invalidate conflicting pool entries too.
        stale_candidates = [(key, self.tx_pool.entries[key])
            for sender in dict.fromkeys(tx["sender"] for tx in txs)
            for key in tuple(self.tx_pool.by_sender.get(sender, {}))]
        stale_candidates.sort(key=lambda item: self.tx_pool.live_versions[item[0]])
        for key, tx in stale_candidates:
            if tx["nonce"] < self.ledger.next_nonces.get(tx["sender"], 0):
                self.tx_pool.remove(key)
                self.tx_pool.evicted_before_inclusion += 1
                self._log("pool_evict", block_id=bid, cache_key=key, tx_id=tx["tx_id"], detail="committed_nonce")
        self.undecided.pop(bid, None)
        self.block_index.pop(bid, None)
        block.update(accept_t=self.t, valid=True)
        self._log("block_accept", block_id=bid, outcome="valid")

    def run(self):
        while self.events:
            self.t, _, _, callback, args = heapq.heappop(self.events)
            callback(*args)
        if self.pool.running or self.pool.waiting:
            raise RuntimeError("unfinished worker jobs")


def _git_state():
    bundle_manifest = ROOT / "BUNDLE_MANIFEST.json"
    git = shutil.which("git")
    if git is None:
        candidate = Path("C:/Program Files/Git/cmd/git.exe")
        git = str(candidate) if candidate.is_file() else None
    if git is None:
        raise RuntimeError("Git is required for run manifest provenance")
    try:
        commit = subprocess.run([git, "rev-parse", "HEAD"], cwd=ROOT, capture_output=True,
                                text=True, check=True).stdout.strip()
    except subprocess.CalledProcessError:
        if not bundle_manifest.is_file():
            raise
        bundle = json.loads(bundle_manifest.read_text(encoding="utf-8"))
        return dict(commit=bundle["source_commit"], dirty=bundle["source_dirty"], exported=True)
    dirty = bool(subprocess.run([git, "status", "--porcelain"], cwd=ROOT, capture_output=True,
                                text=True, check=True).stdout.strip())
    return dict(commit=commit, dirty=dirty)


def run_model(config, *, model_type=Model) -> tuple[Path, Path]:
    """One finite workload, schema-v4 CSV and provenance JSON outside the repo."""
    model = model_type(config)
    directory = Path(config.get("output_dir") or tempfile.mkdtemp(prefix="paper2-phase2-")).resolve()
    if directory == ROOT or ROOT in directory.parents:
        raise ValueError("run outputs must be outside the repository")
    log, manifest, job_file = directory / "events.csv", directory / "manifest.json", directory / "jobs.csv"
    summary_file = directory / "summary.json"
    if any(p.exists() for p in (log, manifest, job_file, summary_file)):
        raise FileExistsError("refusing to overwrite run artifacts")
    git = _git_state()
    directory.mkdir(parents=True, exist_ok=True)
    if model.output == "summary":
        model.run()
        summary_file.write_text(json.dumps(model.summary.finish(),separators=(",",":"),allow_nan=False),encoding="utf-8")
    else:
        with log.open("x", encoding="utf-8", newline="", buffering=8*1024*1024) as stream:
            writer = model.csv_writer(stream) if hasattr(model, "csv_writer") else csv.writer(stream)
            writer.writerow(getattr(model, "event_fields", EVENT_FIELDS))
            model.event_writer = model.wrap_writer(writer) if hasattr(model, "wrap_writer") else writer
            model.run()
            if hasattr(model.event_writer, "flush"):
                model.event_writer.flush()
            if hasattr(writer, "flush"): writer.flush()
        with job_file.open("x", encoding="utf-8", newline="", buffering=8*1024*1024) as stream:
            writer = model.csv_writer(stream) if hasattr(model, "csv_writer") else csv.writer(stream)
            writer.writerow(("job_id","record"))
            for job in model.jobs.values():
                writer.writerow((job.job_id,json.dumps(vars(job),
                    ensure_ascii=True, separators=(",", ":"), allow_nan=False)))
            if hasattr(writer, "flush"): writer.flush()
    provenance = dict(schema_version=4, config=model.config, git=git,
        seed_derivation=SEED_VERSION, job_draw_version=JOB_DRAW_VERSION,
        sample_index_mapping="SHA256 unsigned integer modulo selected sample count",
        seeds=model.seeds, input_files=model.service.inputs,
        source_sha256={str(p.relative_to(ROOT)): sha256_file(p)
                       for p in sorted((ROOT / "src/paper2").rglob("*.py"))},
        event_log_sha256=sha256_file(log) if model.output == "full" else None,
        job_records=dict(path="jobs.csv", sha256=sha256_file(job_file), count=len(model.jobs)) if model.output == "full" else None,
        event_count=model.row_count,
        blocks=model.blocks, verification_history=model.verification_history,
        accepted_transactions=model.accepted_transactions, admission_checks=model.admission_checks,
        ledger=model.ledger.record(), pool=dict(bytes=model.tx_pool.bytes,
        entries=list(model.tx_pool.entries), evicted_before_inclusion=model.tx_pool.evicted_before_inclusion),
        generator_manifest=config.get("generator_manifest"),
        final_estimates=model.estimates, choose_overhead_ns=dict(count=len(model.choose_overheads),
            total=sum(model.choose_overheads), minimum=min(model.choose_overheads, default=0),
            maximum=max(model.choose_overheads, default=0),
            mean=sum(model.choose_overheads) / len(model.choose_overheads) if model.choose_overheads else 0))
    if hasattr(model, "extra_manifest"):
        provenance.update(model.extra_manifest(directory))
    if hasattr(model, "write_manifest"):
        model.write_manifest(manifest, provenance)
    else:
        with manifest.open("x", encoding="utf-8") as stream:
            stream.write(json.dumps(provenance, separators=(",", ":"), allow_nan=False))
            stream.write("\n")
    return (log if model.output == "full" else summary_file), manifest
