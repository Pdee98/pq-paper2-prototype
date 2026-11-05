"""Reuse Model decisions/state/indexes; replace its clock and service-completion loop."""

import csv
import heapq
import json
import os
from pathlib import Path
import time
from multiprocessing.connection import wait

from src.paper2.model.engine import Model, EVENT_FIELDS, EVENT_INDEX, run_model
from src.paper2.model.service_times import JOB_CLASSES, sha256_file
from src.paper2.state import Ledger
from .corpus import cache_key, signed_parts, validate_entry, validate
from .workers import Workers
from .progress import Progress, phase_times, read_progress, peak_rss
from .serialisation import CSVWriter, write_json
from .dispatch_runtime import EvidenceList, SlicedCache
from .validity import Validity
from .pause_attribution import PauseRecorder, labelled, CODES, measure_callback_cost

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


class LegacyRealtimeModel(Model):
    """Pre-Deviation-2 implementation, retained for decision equivalence tests."""
    event_fields=EVENT_FIELDS+PROTOTYPE_FIELDS

    def __init__(self,config,corpus_path,sleep_seconds=0,stop_t=None,validated_sha256=None,progress=None):
        self.corpus_path=Path(corpus_path).resolve()
        self.progress=progress
        raw=self.corpus_path.read_bytes()
        if validated_sha256 is not None:
            import hashlib
            if hashlib.sha256(raw).hexdigest()!=validated_sha256:raise ValueError("validated corpus SHA-256 mismatch")
        self.corpus=json.loads(raw)
        if validated_sha256 is None:validate(self.corpus)
        else:
            for field in ("transactions","admissions","blocks","context"):
                if config.get(field)!=self.corpus["workload"].get(field):raise ValueError("binding differs from validated corpus: "+field)
        self.validated_sha256=validated_sha256
        self.costs=[];self.spans=[];self.span_id="";self.extra_row={};self.epoch=None
        self.ipc_ns=0;self.idle_ns=0;self.stop_t=stop_t;self.sleep_seconds=sleep_seconds
        self.released=[];self.dispatch_ns={};self.incomplete=False
        if config.get("coalesce_inflight",False):raise ValueError("G3 requires coalescing off")
        if config.get("output","full")!="full":raise ValueError("prototype requires full output")
        if config.get("structural_cost",0) or config.get("state_cost",0):
            raise ValueError("prototype measures actual costs; simulated costs must be zero")
        config=dict(config,service=dict(mode="constant",seconds={c:dict(valid=0,bit_flip=0,random_bytes=0) for c in JOB_CLASSES}))
        from .cycle_protocol import model_config
        super().__init__(model_config(config))
        self.config.update({k:v for k,v in config.items() if k not in model_config(config)})
        self.ledger=ObservedLedger(self.ledger,self)
        self.config["prototype"]=dict(mode="real-time-v1",backend=self.corpus["backend"],
            cache_key_version=self.corpus.get('cache_key_version','paper2-real-cache-key-v1'),sleep_seconds=sleep_seconds)

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

    def _admit_state(self,job):
        super()._admit_state(job)
        if self.progress and self.admission_checks[-1]["passed"]:
            self.progress.advance(self.t);self.progress.counts["admitted"]+=1

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

    def worker_publics(self):
        return {bytes.fromhex(e["public_key_hex"]) for group in ("transactions","blocks") for e in self.corpus[group].values()}

    def run(self):
        publics=self.worker_publics()
        if self.progress:self.progress.phase("prototype_window_start", event_rows=self.row_count)
        control=getattr(self,'gc_window',None)
        worker_args=() if control is None else (60,str(control.directory))
        self.workers=Workers(self.pool.k,self.corpus["backend"],list(publics),self.sleep_seconds,*worker_args)
        sampler=None
        if control:
            from .gc_control import MemorySampler
            sampler=MemorySampler(self.progress,control.directory,[p.pid for p in getattr(self.workers,'processes',[])])
            control.enter()
        if self.progress:self.progress.phase("workers_ready", workers=self.pool.k)
        self.epoch=time.monotonic_ns()
        if self.progress:self.progress.phase("epoch", epoch_ns=self.epoch)
        warmup_done=measurement_done=False
        self.scheduled_t=0
        try:
            while self.events or self.pool.running:
                if sampler:sampler.sample()
                now=(time.monotonic_ns()-self.epoch)/1e9
                if self.progress:
                    self.progress.advance(min(now,self.stop_t) if self.stop_t is not None else now)
                    if now>=30 and not warmup_done:
                        self.progress.phase("warmup_end", event_rows=self.row_count);warmup_done=True
                    if now>=90 and not measurement_done:
                        self.progress.phase("measurement_end", event_rows=self.row_count);measurement_done=True
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
            if self.progress:self.progress.phase("drain_end", drain_complete=not self.incomplete,
                q_admission=self.pool.counts()[0],q_block=self.pool.counts()[1],running=len(self.pool.running),event_rows=self.row_count)
            if control:control.leave(partial=self.incomplete)
            if not self.incomplete:self.workers.handshake("after")
        finally:
            if control:control.leave(partial=True)
            self.workers.close()

    def extra_manifest(self,directory):
        spans=directory/"dispatcher_spans.json"
        if isinstance(self,RealtimeModel):write_json(spans,self.spans)
        else:spans.write_bytes(json.dumps(self.spans,separators=(",",":")).encode()+b"\n")
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


class BufferedEventWriter:
    """Bounded fixed-width snapshots; CSV work occurs after run/drain finishes.

    Capacity is reserved before the epoch. Overflow aborts, never drops rows.
    A slot contains immutable scalar values, never a mutable Job/ledger object.
    """
    def __init__(self,writer,capacity,encode=None):
        if isinstance(capacity,bool) or not isinstance(capacity,int) or capacity<1:
            raise ValueError("positive event buffer capacity required")
        self.writer=writer;self.records=[None]*capacity;self.encode=encode
        self.count=0;self.flushed=0

    def writerow(self,row):
        if self.count==len(self.records):raise BufferError("prototype event buffer capacity exceeded")
        self.records[self.count]=tuple(row);self.count+=1

    def flush(self):
        while self.flushed<self.count:
            record=self.records[self.flushed]
            self.writer.writerow(self.encode(record) if self.encode else record)
            self.records[self.flushed]=None;self.flushed+=1


class RealtimeModel(LegacyRealtimeModel):
    """Same decisions/transport, prepared bytes and deferred schema-v4 records."""
    MAX_EVENT_ROWS=8_000_000

    def __init__(self,config,corpus_path,sleep_seconds=0,stop_t=None,validated_sha256=None,progress=None):
        super().__init__(config,corpus_path,sleep_seconds,stop_t,validated_sha256,progress)
        # The corpus has already been checked against the frozen wire objects.
        # Bind every normalized internal transaction (including admission
        # overrides) to it ONCE, before the epoch. Model never mutates these.
        self.prepared_tx={name:signed_parts(e) for name,e in self.corpus["transactions"].items()}
        self.prepared_blocks={name:signed_parts(e) for name,e in self.corpus["blocks"].items()}
        self.validated_tx=set()
        txs=list(self.transactions.values())
        for _,_,_,callback,args in self.events:
            if getattr(callback,"__func__",None) is Model._admission:txs.append(args[1])
        for tx in txs:
            if validated_sha256 is None:validate_entry(self.corpus["transactions"][tx["tx_id"]],self.corpus["context"],tx)
            self.validated_tx.add(id(tx))
        # Block composition/signature labels must also match the prepared corpus.
        expected={b["block_id"]:b for b in self.corpus["workload"]["blocks"]}
        for b in config.get("blocks",[]):
            reference=expected.get(b["block_id"])
            if reference is None or b["tx_ids"]!=reference["tx_ids"] or b.get("block_sig_label","valid")!=reference.get("block_sig_label","valid"):
                raise ValueError("block metadata differs from prepared corpus")
        logical=sum(len(b["tx_ids"])+1 for b in config.get("blocks",[]))
        self.event_capacity=min(self.MAX_EVENT_ROWS,max(1024,24*(len(config.get("admissions",[]))+logical)))
        self.block_snapshots={};self.job_snapshots={}

    csv_writer=staticmethod(CSVWriter)

    def write_manifest(self,path,value):write_json(path,value,exclusive=True)

    def run(self):
        super().run()
        if self.progress:self.progress.phase("serialisation_start", event_rows=self.row_count,jobs=len(self.jobs))

    def wrap_writer(self,writer):return BufferedEventWriter(writer,self.event_capacity,self.serialize_event)

    def _key(self,tx):
        return self.corpus["transactions"][tx["tx_id"]]["cache_key"]

    def _admit_ready(self,job):
        begin=time.monotonic_ns()
        if id(job.tx) not in self.validated_tx:raise ValueError("unprepared transaction metadata")
        self.costs.append(dict(kind="structural",items=1,duration_ns=time.monotonic_ns()-begin))
        Model._admit_ready(self,job)

    def _block_ready(self,bid,jobs,structurally_valid):
        begin=time.monotonic_ns();txs=self.block_transactions[bid]
        if any(id(tx) not in self.validated_tx for tx in txs):raise ValueError("unprepared block metadata")
        self.costs.append(dict(kind="structural",items=len(txs)+1,duration_ns=time.monotonic_ns()-begin))
        Model._block_ready(self,bid,jobs,structurally_valid)

    def _start(self,job,worker):
        payload,signature,public=self.prepared_tx[job.tx_id] if job.tx else self.prepared_blocks[job.block_id]
        job.send_ns=time.monotonic_ns()
        self.workers.pipes[worker].send(("verify",job.job_id,payload,signature,public))
        self.ipc_ns+=time.monotonic_ns()-job.send_ns
        job.dispatch_to_start_ns=job.send_ns-self.dispatch_ns[job.job_id]
        job.dispatch_decision_ns=self.dispatch_ns[job.job_id]
        job.scheduled_service_unknown=True
        self.t=(job.send_ns-self.epoch)/1e9
        Model._start(self,job,worker)

    def _log(self,event,job=None,block_id="",**extra):
        if event=="start":now=job.send_ns
        elif event=="end":now=job.receive_ns
        elif event.startswith("dispatcher_busy_"):now=self.marker_ns
        else:now=time.monotonic_ns()
        self.t=(now-self.epoch)/1e9
        if event=="enqueue" and job:job.enqueue_t=self.t
        if event=="block_arrive":self.blocks[block_id].update(arrival_t=self.t,deadline_t=self.t+self.deadline)
        if event in ("block_accept","block_reject"):
            self.blocks[block_id]["accept_t" if event=="block_accept" else "reject_t"]=self.t
        scheduled=""
        if event in ("tx_arrive","block_arrive"):
            scheduled=self.scheduled_t
            self.released.append(dict(event=event,identity=job.tx_id if job else block_id,
                scheduled_t=scheduled,release_t=self.t,lateness=self.t-scheduled))
        if event=="dispatch" and extra.get("chosen_job_id"):self.dispatch_ns[extra["chosen_job_id"]]=now
        qa,qb,busy=self.pool.counts()
        bid=job.block_id if job else block_id
        # Immutable job snapshots change only at enqueue/start/end. No mutable
        # object enters the buffer and no future state leaks into earlier rows.
        snapshot=None
        if job:
            snapshot=self.job_snapshots.get(job.job_id)
            if snapshot is None or event in ("enqueue","start","end"):
                values=job.__dict__
                snapshot=(job.job_id,job.job_class,job.tx_id,job.block_id,job.worker_id,
                    job.service_time,job.enqueue_t,job.start_t,job.end_t,job.sig_label,job.cache_key,job.outcome,
                    values.get("send_ns",""),values.get("receive_ns",""),values.get("worker_start_ns",""),
                    values.get("worker_end_ns",""),values.get("occupancy_ns",""),values.get("primitive_ns",""),
                    values.get("dispatch_to_start_ns",""),values.get("dispatch_to_worker_start_ns",""))
                self.job_snapshots[job.job_id]=snapshot
        block=None
        if bid:
            if event in ("block_arrive","block_accept","block_reject"):
                b=self.blocks[bid]
                self.block_snapshots[bid]=(bid,b["arrival_t"],b["accept_t"],b["deadline_t"],
                    b["reject_t"],b["reject_reason"],b["reject_reasons"])
            block=self.block_snapshots[bid]
        record=(self.row_count,self.t,event,qa,qb,busy,snapshot,block,tuple(extra.items()),now,scheduled,self.span_id)
        self._record(record)
        self.row_count+=1

    def _record(self,record):
        """Commit a captured immutable row; overridable after successor send."""
        if self.event_writer is None:self.rows.append(dict(zip(self.event_fields,self.serialize_event(record))))
        else:self.event_writer.writerow(record)
        if self.progress:
            _,t,event,qa,qb,_,job,*_=record
            self.progress.event(t,event,job[1] if job else "",(qa,qb))

    def serialize_event(self,record):
        seq,t,event,qa,qb,busy,job,block,extra,now,scheduled,span=record
        row=[None]*len(EVENT_FIELDS)
        row[:4]=self.run_id,seq,t,event;row[10:13]=qa,qb,busy
        if job:
            for index,value in zip((4,5,6,7,8,9,13,14,15,20,21),job):row[index]=value
            if event=="end":row[16]=job[11]
        if block:
            for index,value in zip((7,17,18,19,22,23,24),block):row[index]=value
        for name,value in extra:row[EVENT_INDEX[name]]=value
        return row+[now,scheduled,span]+(list(job[12:]) if job else [""]*8)

    def extra_manifest(self,directory):
        result=super().extra_manifest(directory)
        result["prototype"]["event_buffer"]=dict(capacity=self.event_capacity,rows=self.row_count,
            serialization="after finish_ns and drain; fixed-width immutable snapshots; overflow aborts")
        result["prototype"]["preparation"]=dict(validation="validated corpus SHA-256 binding" if self.validated_sha256 else "before epoch against frozen wire objects",
            cache_keys="validated corpus keys",payloads="decoded before epoch",
            online_structural_check="membership of immutable, prevalidated normalized transactions")
        return result


# Preserve the exact pre-Deviation-5 decision/clock implementation for fixtures.
PreDeviation5Model=RealtimeModel
class CompletionFirstModel(PreDeviation5Model):
    SLICE_NS=200_000

    def __init__(self,*args,**kwargs):
        self.pause_monitor=None
        self.completion_evidence=None;self.maintenance_context=None
        self.pending_sends=set();self.active_span=None;self.slice_start=None
        self.slice_stats={};self.servicing=False
        super().__init__(*args,**kwargs)
        self.validity=Validity(self.pool.k,self.pool.mode,self.pool.k_a)
        if self.progress:self.progress.diagnostics=lambda:self.validity.report(self.validity.previous)
        for name in ("verification_history","accepted_transactions","choose_overheads","costs"):
            setattr(self,name,EvidenceList(self,getattr(self,name)))
        for cache in (self.cache,self.negative):
            cache.__class__=SlicedCache;cache.owner=self

    def _record(self,record):
        if self.completion_evidence is not None:
            self.completion_evidence.append(("row",record))
        else:self._commit_record(record)

    def _commit_record(self,record):
        _,t,event,qa,qb,busy,job,_,extra,*_=record
        overrides=dict(extra)
        self.validity.observe(t,event,overrides.get("q_admission",qa),overrides.get("q_block",qb),
            overrides.get("busy_workers",busy),job[4] if job else None,
            job[12] if job and event=="start" else None,job[13] if job and event=="end" else None)
        super()._record(record)

    @labelled("admission_state")
    def _admit_state(self,job):
        Model._admit_state(self,job)
        if self.progress and self.admission_checks[-1]["passed"]:
            if self.completion_evidence is not None:
                self.completion_evidence.append(("admitted",self.t))
            else:
                self.progress.advance(self.t);self.progress.counts["admitted"]+=1

    @labelled("cache_lookup_ttl")
    def _lookup(self,cache,job,negative=False):
        previous=self.maintenance_context
        self.maintenance_context=(job,"negative" if negative else "positive")
        try:return Model._lookup(self,cache,job,negative)
        finally:self.maintenance_context=previous

    @labelled("send_start")
    def _start(self,job,worker):
        if worker in self.pending_sends or worker in self.pool.running:
            raise AssertionError("no prefetch: previous worker result not returned")
        self.pending_sends.add(worker)
        super()._start(job,worker)

    def _receive(self,worker):
        self._pause_step("receive_result")
        begin=time.monotonic_ns();reply=self.workers.pipes[worker].recv();receive=time.monotonic_ns()
        self.ipc_ns+=receive-begin
        if reply[0]!="result":raise RuntimeError("worker failure: "+str(reply))
        _,identity,start,end,valid=reply
        job=self.pool.running[worker]
        if identity!=job.job_id:raise RuntimeError("worker replied to a different job")
        if worker not in self.pending_sends:raise AssertionError("result without outstanding send")
        self.pending_sends.remove(worker)
        job.receive_ns,job.worker_start_ns,job.worker_end_ns=receive,start,end
        job.occupancy_ns,job.primitive_ns=receive-job.send_ns,end-start
        self.t=(receive-self.epoch)/1e9
        job.service_time=self.t-job.start_t;job.outcome="valid" if valid else "invalid"
        self.completion_evidence=[]
        try:
            # Includes cache/pool/ledger/eligibility and EWMA/busy-window updates
            # in the simulator's exact order, followed by _dispatch/_start.
            # All selected jobs have been sent before evidence commits below.
            self._pause_step("completion_state")
            Model._finish(self,job)
        finally:
            pending=self.completion_evidence;self.completion_evidence=None
            # Clock-handshake diagnostics do not affect selection. Fill their
            # captured end snapshots only after the successor has been sent.
            self._pause_step("completion_clock_diagnostics")
            probe=min(next(r["probes"] for r in self.workers.clock_records
                if r["worker_id"]==worker and r["phase"]=="before"),key=lambda r:r["uncertainty_ns"])
            job.worker_clock_offset_estimate_ns=probe["offset_ns"]
            job.worker_clock_uncertainty_ns=probe["uncertainty_ns"]
            job.dispatch_to_worker_start_ns=start-probe["offset_ns"]-job.dispatch_decision_ns
            self._pause_step("completion_evidence_commit")
            for item in pending:
                if item[0]=="row":
                    record=item[1];snapshot=record[6]
                    if snapshot and snapshot[0]==job.job_id:
                        snapshot=snapshot[:-1]+(job.dispatch_to_worker_start_ns,)
                        record=record[:6]+(snapshot,)+record[7:]
                        self.job_snapshots[job.job_id]=snapshot
                    self._commit_record(record)
                elif item[0]=="append":list.append(item[1],item[2])
                else:
                    self.progress.advance(item[1]);self.progress.counts["admitted"]+=1

    def _begin_span(self,kind):
        self.span_id=len(self.spans);self.marker_ns=time.monotonic_ns()
        self.active_span=(kind,self.marker_ns);self.slice_start=self.marker_ns
        if self.pause_monitor:self.pause_monitor.begin_span(self.span_id,kind,self.marker_ns)
        self._log("dispatcher_busy_start")

    def _end_span(self):
        kind,begin=self.active_span;end=time.monotonic_ns();self.marker_ns=end
        if self.pause_monitor:self.pause_monitor.end_span(end)
        self._log("dispatcher_busy_end")
        self.spans.append(dict(id=self.span_id,start_ns=begin,end_ns=end,
            start_t=(begin-self.epoch)/1e9,end_t=(end-self.epoch)/1e9,kind=kind))
        stats=self.slice_stats.setdefault(kind,dict(count=0,total_ns=0,max_ns=0,over_target=0))
        duration=end-begin;stats["count"]+=1;stats["total_ns"]+=duration
        stats["max_ns"]=max(stats["max_ns"],duration);stats["over_target"]+=duration>self.SLICE_NS
        self.active_span=None;self.span_id=""

    def _handle(self,callback,*args):
        self._begin_span(callback.__name__)
        try:callback(*args)
        finally:self._end_span()

    def _checkpoint(self,reason):
        if (self.epoch is None or self.active_span is None or self.servicing or
                self.completion_evidence is not None or time.monotonic_ns()-self.slice_start<self.SLICE_NS):return
        previous_step=self.pause_monitor.current_step if self.pause_monitor else None
        kind=self.active_span[0];self._end_span()
        self._pause_step("slice_poll_results")
        self.servicing=True
        try:
            begin=time.monotonic_ns()
            ready=[w for w in self.pool.running if self.workers.pipes[w].poll()]
            self.ipc_ns+=time.monotonic_ns()-begin
            for worker in ready:self._handle(self._receive,worker)
        finally:
            self.servicing=False;self._begin_span(kind)
            if self.pause_monitor and previous_step is not None:self.pause_monitor.step(previous_step)

    @labelled("job_preparation")
    def _new_job(self,*args,**kwargs):
        self._checkpoint("block_prepare")
        return super()._new_job(*args,**kwargs)

    @labelled("block_job_eligibility")
    def _enqueue(self,job):
        Model._enqueue(self,job)
        self._checkpoint("block_ready_or_admission")

    @labelled("admission_structural")
    def _admit_ready(self,job):
        super()._admit_ready(job)
        self._checkpoint("admission")

    @labelled("block_structural")
    def _block_ready(self,bid,jobs,structurally_valid):
        duration=0
        for tx in self.block_transactions[bid]:
            begin=time.monotonic_ns()
            if id(tx) not in self.validated_tx:raise ValueError("unprepared block metadata")
            duration+=time.monotonic_ns()-begin
            self._checkpoint("block_structural")
        self.costs.append(dict(kind="structural",items=len(self.block_transactions[bid])+1,duration_ns=duration))
        if not structurally_valid:
            self.blocks[bid]["structurally_rejected"]=True
            self._log("struct_reject",block_id=bid);self._reject(bid,{"structural"});return
        self._pause_step("block_job_eligibility")
        for job in jobs:
            if job.job_class=="block_tx" and self._lookup(self.cache,job):
                job.status="cache_hit";self.blocks[bid]["pending"]-=1
            elif job.job_class=="block_tx" and self._coalesce(job):pass
            else:self._enqueue(job)
            # Warm-cache blocks have no _enqueue for their transactions, so
            # they need this checkpoint as well as the cold enqueue path.
            self._checkpoint("block_ready")

    def _pause_step(self,name):
        if self.pause_monitor:self.pause_monitor.step(CODES[name])

    @labelled("policy_view")
    def _view(self):return super()._view()

    @labelled("select_dispatch")
    def _dispatch(self):return Model._dispatch(self)

    @labelled("cache_insert_evidence")
    def _insert_cache(self,job,valid):return Model._insert_cache(self,job,valid)

    @labelled("block_state")
    def _decide_block(self,bid):return Model._decide_block(self,bid)

    def extra_manifest(self,directory):
        value=super().extra_manifest(directory)
        value["prototype"]["completion_dispatch"]=dict(deviation=5,
            completion_first=True,no_prefetch=True,slice_target_ns=self.SLICE_NS,slices=self.slice_stats,
            atomic="selection-relevant completion/cache/pool/ledger transitions",
            deferred="event-buffer/progress commits; verification/accepted/cost/choose evidence appends")
        value["prototype"]["validity"]=self.validity.report((self.finish_ns-self.epoch)/1e9,final=True)
        value["prototype"]["pause_attribution"]=dict(gc="gc_pauses.json",long_spans="long_spans.json",
            scope="registered dispatcher capture prefix, ending before attribution JSON encoding",
            gc_controls_changed=False)
        return value

    def run(self):
        owned=self.pause_monitor is None
        if owned:
            directory=self.config.get("output_dir")
            if directory is None:directory=Path(self.event_writer.writer.stream.name).parent
            self.pause_monitor=PauseRecorder(directory);self.pause_monitor.register()
        complete=False
        try:
            super().run();self._pause_step("serialisation");complete=True
        finally:
            if owned:self.pause_monitor.finish(partial=not complete)
        if self.progress:self.progress.phase("prototype_validity",
            **self.validity.report((self.finish_ns-self.epoch)/1e9,final=True))


class CycleRealtimeModel(PreDeviation5Model):
    """Deviation 4 dispatch order; optional diagnostics never slice/reorder work."""
    def __init__(self,*args,**kwargs):
        self.pause_monitor=None
        super().__init__(*args,**kwargs)
        self.detailed=self.config.get('diagnostic_instrumentation',False)
        if self.detailed:
            from types import MethodType
            labels=dict(_view='policy_view',_dispatch='select_dispatch',_admit_state='admission_state',
                _insert_cache='cache_insert_evidence',_decide_block='block_state',_lookup='cache_lookup_ttl',
                _admit_ready='admission_structural',_block_ready='block_structural',_new_job='job_preparation',
                _start='send_start',_receive='receive_result')
            for method,label in labels.items():
                base=getattr(self,method).__func__
                setattr(self,method,MethodType(labelled(label)(base),self))

    def _handle(self,callback,*args):
        if not self.detailed:return super()._handle(callback,*args)
        self.span_id=len(self.spans);begin=time.monotonic_ns();self.marker_ns=begin
        if self.pause_monitor:self.pause_monitor.begin_span(self.span_id,callback.__name__,begin)
        self._log('dispatcher_busy_start')
        try:callback(*args)
        finally:
            end=time.monotonic_ns();self.marker_ns=end
            if self.pause_monitor:self.pause_monitor.end_span(end)
            self._log('dispatcher_busy_end')
            self.spans.append(dict(id=self.span_id,start_ns=begin,end_ns=end,start_t=(begin-self.epoch)/1e9,
                end_t=(end-self.epoch)/1e9,kind=callback.__name__))
            self.span_id=''

    def run(self):
        owned=self.pause_monitor is None
        directory=self.config.get('output_dir') or Path(self.event_writer.writer.stream.name).parent
        if owned:
            self.pause_monitor=PauseRecorder(directory,detailed=self.detailed)
        from .gc_control import WindowGC
        self.gc_window=WindowGC(directory,self.pause_monitor)
        own_progress=self.progress is None
        if own_progress:self.progress=Progress(directory)
        complete=False
        try:
            super().run();complete=True
            if self.progress and self.config.get('g3_input_version')==6:
                from .cycle_validity import from_records
                waiting={}
                for i in range(self.event_writer.count):
                    row=self.event_writer.records[i]
                    if row[2]=='end':waiting[row[6][0]]=row[3]+row[4]>0
                self.progress.phase('cycle_stationarity',prototype_validity=from_records(
                    [vars(j) for j in self.jobs.values()],waiting,self.config,self.blocks))
        finally:
            self.gc_window.leave(partial=not complete)
            if owned:self.pause_monitor.finish(partial=not complete)
            if not complete:
                # A memory stop must retain completed buffer records and job
                # state, even though run_model cannot write a normal manifest.
                writer=self.event_writer
                if writer is not None and getattr(writer,'writer',None) is not None:
                    writer.flush()
                    if hasattr(writer.writer,'flush'):writer.writer.flush()
                write_json(Path(directory)/'partial-jobs.json',[vars(j) for j in self.jobs.values()])
                write_json(Path(directory)/'partial-state.json',dict(status='INVALID',
                    event_rows=self.row_count,q_admission=self.pool.counts()[0],q_block=self.pool.counts()[1],
                    running=len(self.pool.running)))
            if own_progress:self.progress.close()

    def extra_manifest(self,directory):
        value=super().extra_manifest(directory)
        value['prototype'].update(dispatch_path='Deviation 4 (no completion-first/slicing)',
            validity_scheme='cycle-calibration-v6',cache_key_version='paper2-cache-key-v2',
            gc_control=dict(version=7,state='gc_state.json',memory_guard='12 GiB per process / 2 GiB available'),
            pause_attribution=dict(gc='gc_pauses.json',detailed=self.detailed,gc_controls_changed=True,
                **({'long_spans':'long_spans.json'} if self.detailed else {})))
        return value


RealtimeModel=CycleRealtimeModel


def run(config,corpus_path,*,sleep_seconds=0,stop_t=None,validated_sha256=None):
    progress=Progress(config["output_dir"]) if config.get("output_dir") else None
    holder=[];monitor=None
    def create(c):
        model=RealtimeModel(c,corpus_path,sleep_seconds,stop_t,validated_sha256,progress)
        model.pause_monitor=monitor;holder.append(model);return model
    try:
        if config.get("output_dir"):
            monitor=PauseRecorder(config["output_dir"],detailed=config.get('diagnostic_instrumentation',False))
        e,m=run_model(config,model_type=create)
        if monitor:
            monitor.finish()
            write_json(e.parent/"callback_overhead.json",measure_callback_cost())
        if progress:
            model=holder[0]
            progress.phase("serialisation_end",event_rows=model.row_count,jobs=len(model.jobs),peak_parent_rss_bytes=peak_rss())
            progress.phase("exit",drain_complete=not model.incomplete,event_rows=model.row_count,jobs=len(model.jobs))
        return e,m
    finally:
        try:
            if monitor and not monitor.closed:monitor.finish(partial=True)
        finally:
            if progress:progress.close()
