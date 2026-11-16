"""Phase A explicit dispatcher model; literal costs only, no replay/calibration.

Functional state/cache/policy logic reuses the legacy model. Positive dispatcher
work is driven by callback generators; sampled worker end is abstract receive.
Explicit evidence is checked independently under verify/explicit.py.
"""
from dataclasses import replace
import itertools
import json
from .engine import Model, WorkerPool
from .dispatcher import Dispatcher, LiteralCosts, Stage, SCHEMA


class ControlPool(WorkerPool):
    def __init__(self, *args):
        super().__init__(*args)
        self.reserved, self.completion_pending = {}, {}

    @property
    def unavailable(self):
        return set(self.running) | set(self.reserved) | set(self.completion_pending)

    def available_worker(self, job):
        eligible = range(self.k)
        if self.mode == "split":
            eligible = range(self.k_a) if job.job_class == "admission" else range(self.k_a, self.k)
        return next((w for w in eligible if w not in self.unavailable), None)


class ExplicitModel(Model):
    def __init__(self, config):
        self.literal = LiteralCosts(config["dispatcher"])
        if self.literal.mode != "explicit" or not self.literal.positive:
            raise ValueError("use the legacy route for legacy/all-zero dispatcher requests")
        clean = {k: v for k, v in config.items() if k != "dispatcher"}
        if clean.get("structural_cost", 0) or clean.get("state_cost", 0):
            raise ValueError("explicit mode replaces legacy structural/state charges")
        for b in clean.get("blocks", []):
            self.literal.block(b["block_id"], "build", len(b["tx_ids"]))
        super().__init__(clean)
        self.config["dispatcher"] = config["dispatcher"]
        old = self.pool
        self.pool = ControlPool(old.k, old.mode, old.k_a,
                                old.k-old.k_a if old.mode == "split" else None)
        self.dispatcher = Dispatcher(self)
        self.control_rows = []
        self.send_serial = itertools.count()
        self.send_order = {}
        self.prepared_block = None
        # Full runs can have millions of observation rows. Keep them on disk;
        # fixture-only in-memory construction retains its original list route.
        if config.get('output_dir'):
            from pathlib import Path
            from src.paper2.artifact_stream import Spool
            from .service_times import ROOT
            directory=Path(config['output_dir']).resolve()
            if directory==ROOT or ROOT in directory.parents:raise ValueError('run outputs must be outside the repository')
            if any((directory/n).exists() for n in ('events.csv','jobs.csv','manifest.json','summary.json')):
                raise FileExistsError('refusing to overwrite run artifacts')
            directory.mkdir(parents=True,exist_ok=True)
            self.dispatcher.stages=Spool(directory/'dispatcher-stages.sqlite',by_id=True)
            self.dispatcher.callbacks=Spool(directory/'dispatcher-callbacks.sqlite',by_id=True)
            self.control_rows=Spool(directory/'dispatcher-transitions.sqlite')

    def _control(self, event, **values):
        row = dict(t=self.t, event=event, **values)
        row["reserved_workers"] = sorted(self.pool.reserved)
        row["completion_pending_workers"] = sorted(self.pool.completion_pending)
        self.control_rows.append(row)
        self._log("dispatcher_"+event, detail=json.dumps(row, separators=(",", ":")))

    def _log(self, event, job=None, block_id="", **extra):
        # A declared prepared queue is waiting, not an instantaneous selection.
        # Ordinary enqueue callbacks retain the registered direct-row convention.
        if event == "enqueue" and self.dispatcher.active is None:
            extra.pop("q_admission", None)
            extra.pop("q_block", None)
        Model._log(self, event, job, block_id, **extra)

    def _work(self, kind, job=None):
        return Stage(kind, self.literal.cost(kind, job), job.job_id if job else "", job.block_id if job else "")

    def _block_work(self, bid, kind, n, index=None):
        return Stage("block_"+kind, self.literal.block(bid, kind, n, index), block_id=bid)

    def _dispatcher(self, cost, callback, *args):
        if cost:
            raise RuntimeError("legacy charge reached explicit dispatcher")
        callback(*args)

    def _dispatch(self):
        # Legacy functional enqueue/coalesce hooks must not send outside the
        # owning generator. Its caller immediately yields from _dispatch_jobs.
        pass

    def _view(self):
        view = super()._view()
        return replace(view, free_workers=tuple(w for w in view.free_workers if w not in self.pool.unavailable))

    def _admission(self, index, tx):
        self.dispatcher.submit("arrival", f"admission:{index}", self._arrival(index, tx, self.t))

    def _arrival(self, index, tx, release):
        job = self._new_job(f"admission:{index}", "admission", tx)
        self._log("tx_arrive", job)
        self._control("release", family="arrival", identity=job.job_id, offered_t=release)
        yield self._work("arrival_pre", job)
        Model._admit_ready(self, job)
        yield from self._dispatch_jobs()
        yield self._work("arrival_tail", job)

    def _block(self, index, spec, txs):
        self.dispatcher.submit("block_arrival", spec["block_id"], self._block_arrival(index, spec, txs, self.t))

    def _admit_state(self, job):
        Model._admit_state(self, job)
        result = self.admission_checks[-1]
        self._control("admission_state_commit", job_id=job.job_id,
                      passed=result['passed'], reason=result['reason'])

    def _block_ready(self, bid, jobs, valid):
        # Capture legacy block construction, then execute its functional checks
        # at measured stage milestones instead of running them all inline.
        self.prepared_block = bid, jobs, valid

    def _block_arrival(self, index, spec, txs, release):
        Model._block(self, index, spec, txs)
        bid, jobs, valid = self.prepared_block
        self.prepared_block = None
        self._control("release", family="block_arrival", identity=bid, offered_t=release)
        yield self._block_work(bid, "build", len(txs))
        if not valid:
            self.blocks[bid]["structurally_rejected"] = True
            self._log("struct_reject", block_id=bid)
            self._reject(bid, {"structural"})
        else:
            for i, job in enumerate(jobs):
                if job.job_class == "block_tx":
                    yield self._block_work(bid, "lookups", len(txs), i)
                    if self._lookup(self.cache, job):
                        job.status = "cache_hit"
                        self.blocks[bid]["pending"] -= 1
                        self._control("block_check_complete", block_id=bid, job_id=job.job_id,
                            source_job_id=self.proofs.get(job.cache_key), via="cache",
                            remaining=self.blocks[bid]["pending"])
                        continue
                    if self._coalesce(job):
                        yield from self._dispatch_jobs()
                        continue
                self._enqueue(job)
                yield from self._dispatch_jobs()
        yield self._block_work(bid, "tail", len(txs))

    def _dispatch_jobs(self):
        while self.pool.waiting:
            view = self._view()
            if not view.free_workers:
                return
            chosen = self.policy.choose(self.t, view)
            diagnostics = self.policy.diagnostics(self.t, view)
            if chosen is None:
                self._log("dispatch", policy=self.policy.name, chosen_job_id=None,
                          ewma_alpha=self.ewma_alpha, **diagnostics)
                return
            job = self.pool.waiting.items[chosen]
            worker = self.pool.available_worker(job)
            if worker is None:
                raise RuntimeError("policy chose a worker blocked by control work")
            self.pool.waiting.remove(job)
            self.pool.waiting_counts[job.job_class] -= 1
            self.pool.reserved[worker] = job
            self._log("dispatch", policy=self.policy.name, chosen_job_id=chosen,
                      ewma_alpha=self.ewma_alpha, **diagnostics)
            self._control("reserve", job_id=job.job_id, worker_id=worker)
            yield self._work("send_pre", job)
            if self.pool.reserved.pop(worker) is not job:
                raise RuntimeError("lost selected-worker reservation")
            self._start(job, worker)
            yield self._work("send_tail", job)

    def _start(self, job, worker):
        if worker in self.pool.unavailable:
            raise RuntimeError("no prefetch: worker is unavailable")
        self.send_order[job.job_id] = next(self.send_serial)
        Model._start(self, job, worker)

    def _finish(self, job):
        worker = job.worker_id
        if self.pool.running.pop(worker) is not job:
            raise RuntimeError("worker end ownership mismatch")
        job.end_t, job.status = self.t, "end"
        self.pool.completion_pending[worker] = job
        if self.window:
            self.window.change(self.t, -int(job.job_class == "admission"), -1)
        for bid in (job.block_waiters if job.admission_origin else [job.block_id]):
            self.block_index[bid].end(job)
        self._log("end", job)
        self._control("receive_pending", job_id=job.job_id, worker_id=worker)
        self.dispatcher.submit("completion_"+job.job_class, job.job_id, self._completion(job),
                               completion_order=self.send_order[job.job_id])

    def _completion(self, job):
        yield self._work("complete_"+job.job_class, job)
        self.estimates[job.job_class] = (self.ewma_alpha * (job.end_t-job.start_t)
            + (1-self.ewma_alpha) * self.estimates[job.job_class])
        if job.tx:
            if job.outcome == "valid":
                self.proofs[job.cache_key] = job.job_id
                self.verification_history.append(dict(key=job.cache_key, job_id=job.job_id,
                                                       t=self.t, outcome="valid"))
            self._insert_cache(job, job.outcome == "valid")
        if job.admission_origin:
            self.inflight_admissions.pop(job.cache_key, None)
            if job.outcome == "valid":
                self._admit_state(job)
            else:
                self.pending_admissions.discard(job.cache_key)
                self._log("drop", job, detail="invalid_signature")
        bids = list(job.block_waiters)
        if not job.admission_origin:
            bids.append(job.block_id)
        for bid in bids:
            block = self.blocks[bid]
            block["pending"] -= 1
            self._control("block_check_complete", block_id=bid, job_id=job.job_id,
                source_job_id=job.job_id, via="service", remaining=block["pending"])
            if job.outcome != "valid":
                self.block_reasons[bid].add("invalid_signature")
            if block["pending"] == 0:
                n = len(self.block_transactions[bid])
                self._control("acceptance_trigger", block_id=bid, job_id=job.job_id, job_class=job.job_class)
                yield self._block_work(bid, "accept", n)
                Model._decide_block(self, bid)
                yield self._block_work(bid, "accept_tail", n)
        if self.pool.completion_pending.pop(job.worker_id) is not job:
            raise RuntimeError("lost completion-pending ownership")
        self._control("completion_commit", job_id=job.job_id, worker_id=job.worker_id)
        yield from self._dispatch_jobs()
        yield self._work("complete_tail", job)

    def run(self):
        super().run()
        if (self.dispatcher.active or self.dispatcher.pending or self.pool.reserved
                or self.pool.completion_pending):
            raise RuntimeError("unfinished dispatcher work")

    def extra_manifest(self, directory):
        from .service_times import sha256_file
        path = directory / "dispatcher.json"
        from src.paper2.artifact_stream import write_arrays
        write_arrays(path,SCHEMA,dict(stages=self.dispatcher.stages,
            callbacks=self.dispatcher.callbacks,transitions=self.control_rows))
        for seq in (self.dispatcher.stages,self.dispatcher.callbacks,self.control_rows):
            if hasattr(seq,'close'):seq.close()
        return dict(dispatcher=dict(schema=SCHEMA, mode="explicit", costs="literal",
            receive="abstract sampled occupancy end; collection-wait correlation not separately resolved",
            evidence=dict(path=path.name, sha256=sha256_file(path)),
            independent_checker="independent-explicit-v1"))
