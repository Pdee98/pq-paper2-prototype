"""Reuse Model decisions/state/indexes; replace its clock and service-completion loop."""

import csv
import heapq
import json
import os
from pathlib import Path
import time
from multiprocessing.connection import wait

from src.paper2.model.engine import Model, EVENT_FIELDS, run_model
from src.paper2.model.service_times import JOB_CLASSES, sha256_file
from src.paper2.state import Ledger
from .corpus import cache_key, signed_parts, validate_entry, validate
from .workers import Workers

PROTOTYPE_FIELDS=("monotonic_ns","scheduled_t","dispatcher_span_id","send_ns","receive_ns",
                  "worker_start_ns","worker_end_ns","occupancy_ns","primitive_ns","dispatch_to_start_ns",
                  "dispatch_to_worker_start_ns")


class ObservedLedger:
    def __init__(self,ledger,owner):self.base,self.owner=ledger,owner
    def __getattr__(self,name):return getattr(self.base,name)
    def admission_check(self,tx,pool):
        begin=time.monotonic_ns();result=self.base.admission_check(tx,pool)
        self.owner.costs.append(dict(kind="state",items=1,duration_ns=time.monotonic_ns()-begin))
        return result
    def check_block(self,transactions):
        begin=time.monotonic_ns();trial,checks=self.base.check_block(transactions)
        self.owner.costs.append(dict(kind="state",items=len(transactions),duration_ns=time.monotonic_ns()-begin))
        return ObservedLedger(trial,self.owner),checks


class EventWriter:
    def __init__(self,writer,model):self.writer,self.model=writer,model
    def writerow(self,row):self.writer.writerow(row+[self.model.extra_row.get(k,"") for k in PROTOTYPE_FIELDS])


class RealtimeModel(Model):
    event_fields=EVENT_FIELDS+PROTOTYPE_FIELDS

    def __init__(self,config,corpus_path,sleep_seconds=0,stop_t=None):
        self.corpus_path=Path(corpus_path).resolve()
        self.corpus=json.loads(self.corpus_path.read_text(encoding="utf-8"))
        validate(self.corpus)
        self.costs=[];self.spans=[];self.span_id="";self.extra_row={};self.epoch=None
        self.ipc_ns=0;self.idle_ns=0;self.stop_t=stop_t;self.sleep_seconds=sleep_seconds
        self.released=[];self.dispatch_ns={};self.incomplete=False
        if config.get("coalesce_inflight",False):raise ValueError("G3 requires coalescing off")
        if config.get("output","full")!="full":raise ValueError("prototype requires full output")
        if config.get("structural_cost",0) or config.get("state_cost",0):
            raise ValueError("prototype measures actual costs; simulated costs must be zero")
        config=dict(config,service=dict(mode="constant",seconds={c:dict(valid=0,bit_flip=0,random_bytes=0) for c in JOB_CLASSES}))
        super().__init__(config)
        self.ledger=ObservedLedger(self.ledger,self)
        self.config["prototype"]=dict(mode="real-time-v1",backend=self.corpus["backend"],
            cache_key_version="paper2-real-cache-key-v1",sleep_seconds=sleep_seconds)

    def wrap_writer(self,writer):return EventWriter(writer,self)

    def _key(self,tx):
        e=self.corpus["transactions"][tx["tx_id"]]
        payload,signature,public=signed_parts(e)
        return cache_key(self.corpus["context"],public,payload,tx["nonce"],signature)

    def _schedule(self,t,priority,callback,*args):
        if getattr(callback,"__func__",None) is Model._finish:return
        super()._schedule(t,priority,callback,*args)

    def _dispatcher(self,cost,callback,*args):
        # Decision methods are the simulator's; their real work runs on this serial thread.
        self.t=(time.monotonic_ns()-self.epoch)/1e9
        callback(*args)

    def _log(self,event,job=None,block_id="",**extra):
        if event=="start":now=job.send_ns
        elif event=="end":now=job.receive_ns
        elif event.startswith("dispatcher_busy_"):now=self.marker_ns
        else:now=time.monotonic_ns()
        self.t=(now-self.epoch)/1e9
        if event=="enqueue" and job:job.enqueue_t=self.t
        if event=="block_arrive":
            self.blocks[block_id].update(arrival_t=self.t,deadline_t=self.t+self.deadline)
        if event in ("block_accept","block_reject"):
            self.blocks[block_id]["accept_t" if event=="block_accept" else "reject_t"]=self.t
        self.extra_row=dict(monotonic_ns=now,dispatcher_span_id=self.span_id)
        if job:
            self.extra_row.update({k:getattr(job,k,"") for k in PROTOTYPE_FIELDS if hasattr(job,k)})
        if event in ("tx_arrive","block_arrive"):
            self.extra_row["scheduled_t"]=self.scheduled_t
            self.released.append(dict(event=event,identity=job.tx_id if job else block_id,
                scheduled_t=self.scheduled_t,release_t=self.t,lateness=self.t-self.scheduled_t))
        if event=="dispatch" and extra.get("chosen_job_id"):
            self.dispatch_ns[extra["chosen_job_id"]]=now
        super()._log(event,job,block_id,**extra)

    def _admit_ready(self,job):
        begin=time.monotonic_ns()
        validate_entry(self.corpus["transactions"][job.tx_id],self.corpus["context"],job.tx)
        self.costs.append(dict(kind="structural",items=1,duration_ns=time.monotonic_ns()-begin))
        super()._admit_ready(job)

    def _block_ready(self,bid,jobs,structurally_valid):
        begin=time.monotonic_ns()
        for tx in self.block_transactions[bid]:
            validate_entry(self.corpus["transactions"][tx["tx_id"]],self.corpus["context"],tx)
        self.costs.append(dict(kind="structural",items=len(self.block_transactions[bid])+1,
                               duration_ns=time.monotonic_ns()-begin))
        super()._block_ready(bid,jobs,structurally_valid)

    def _start(self,job,worker):
        e=self.corpus["transactions"][job.tx_id] if job.tx else self.corpus["blocks"][job.block_id]
        payload,signature,public=signed_parts(e)
        job.send_ns=time.monotonic_ns()
        self.workers.pipes[worker].send(("verify",job.job_id,payload,signature,public))
        self.ipc_ns+=time.monotonic_ns()-job.send_ns
        job.dispatch_to_start_ns=job.send_ns-self.dispatch_ns[job.job_id]
        job.dispatch_decision_ns=self.dispatch_ns[job.job_id]
        job.scheduled_service_unknown=True
        self.t=(job.send_ns-self.epoch)/1e9
        super()._start(job,worker)

    def _receive(self,worker):
        begin=time.monotonic_ns();reply=self.workers.pipes[worker].recv();receive=time.monotonic_ns()
        self.ipc_ns+=receive-begin
        if reply[0]!="result":raise RuntimeError("worker failure: "+str(reply))
        _,identity,start,end,valid=reply
        job=self.pool.running[worker]
        if identity!=job.job_id:raise RuntimeError("worker replied to a different job")
        job.receive_ns,job.worker_start_ns,job.worker_end_ns=receive,start,end
        job.occupancy_ns,job.primitive_ns=receive-job.send_ns,end-start
        probes=next(r["probes"] for r in self.workers.clock_records if r["worker_id"]==worker and r["phase"]=="before")
        probe=min(probes,key=lambda r:r["uncertainty_ns"])
        job.worker_clock_offset_estimate_ns=probe["offset_ns"]
        job.worker_clock_uncertainty_ns=probe["uncertainty_ns"]
        job.dispatch_to_worker_start_ns=start-probe["offset_ns"]-job.dispatch_decision_ns
        self.t=(receive-self.epoch)/1e9
        job.service_time=self.t-job.start_t
        job.outcome="valid" if valid else "invalid"
        super()._finish(job)

    def _handle(self,callback,*args):
        self.span_id=len(self.spans);begin=time.monotonic_ns();self.marker_ns=begin
        self._log("dispatcher_busy_start")
        callback(*args)
        end=time.monotonic_ns();self.marker_ns=end;self._log("dispatcher_busy_end")
        self.spans.append(dict(id=self.span_id,start_ns=begin,end_ns=end,
                              start_t=(begin-self.epoch)/1e9,end_t=(end-self.epoch)/1e9))
        self.span_id=""

    def run(self):
        publics={bytes.fromhex(e["public_key_hex"]) for group in ("transactions","blocks")
                 for e in self.corpus[group].values()}
        self.workers=Workers(self.pool.k,self.corpus["backend"],list(publics),self.sleep_seconds)
        self.epoch=time.monotonic_ns()
        self.scheduled_t=0
        try:
            while self.events or self.pool.running:
                now=(time.monotonic_ns()-self.epoch)/1e9
                if self.stop_t is not None and now>self.stop_t:
                    self.incomplete=True;break
                poll_begin=time.monotonic_ns()
                ready=[i for i in self.pool.running if self.workers.pipes[i].poll()]
                self.ipc_ns+=time.monotonic_ns()-poll_begin
                if ready:
                    for i in ready:self._handle(self._receive,i)
                    continue
                if self.events and self.events[0][0]<=now:
                    self.scheduled_t,_,_,callback,args=heapq.heappop(self.events)
                    self._handle(callback,*args);continue
                delay=min(.01,max(0,self.events[0][0]-now)) if self.events else .01
                begin=time.monotonic_ns()
                pipes=[self.workers.pipes[i] for i in self.pool.running]
                if pipes:wait(pipes,timeout=delay)
                else:time.sleep(delay)
                self.idle_ns+=time.monotonic_ns()-begin
            self.finish_ns=time.monotonic_ns()
            if not self.incomplete and (self.pool.running or self.pool.waiting):
                raise RuntimeError("unfinished worker jobs")
            if not self.incomplete:self.workers.handshake("after")
        finally:
            self.workers.close()

    def extra_manifest(self,directory):
        spans=directory/"dispatcher_spans.json"
        spans.write_bytes(json.dumps(self.spans,separators=(",",":")).encode()+b"\n")
        active=max(0,self.finish_ns-self.epoch-self.idle_ns)
        structural=sum(c["duration_ns"] for c in self.costs if c["kind"]=="structural")
        state=sum(c["duration_ns"] for c in self.costs if c["kind"]=="state")
        return dict(prototype=dict(mode="real-time-v1",epoch_ns=self.epoch,finish_ns=self.finish_ns,
            incomplete=self.incomplete,corpus_path=os.path.relpath(self.corpus_path,directory),
            corpus_sha256=sha256_file(self.corpus_path),
            spans=dict(path=spans.name,sha256=sha256_file(spans)),worker_metadata=self.workers.metadata,
            worker_clock_offsets=self.workers.clock_records,dispatcher_costs=self.costs,
            dispatcher_active_ns=active,dispatcher_ipc_ns=self.ipc_ns,
            dispatcher_non_ipc_ns=max(0,active-self.ipc_ns),
            unmodelled_dispatcher_ns=max(0,active-structural-state),releases=self.released))


def run(config,corpus_path,*,sleep_seconds=0,stop_t=None):
    return run_model(config,model_type=lambda c:RealtimeModel(c,corpus_path,sleep_seconds,stop_t))
