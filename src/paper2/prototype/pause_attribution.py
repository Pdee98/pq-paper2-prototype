"""Observational GC/span receipts, recoverable after a killed dispatcher.

Only register/remove our callback. Never collect, disable, freeze or configure GC.
Callbacks write fixed-width records to already allocated file-backed memory.
JSON encoding and attribution run outside the measured dispatcher loop.
"""

import bisect
import gc
import json
import mmap
import os
from pathlib import Path
import struct
import time
import statistics
import tempfile
import platform
from functools import wraps

from .serialisation import write_json

LABELS=("unknown","preparation","handler:_admission","handler:_block","handler:_receive",
    "handler:other","admission_arrival","block_arrival_prepare","job_preparation",
    "admission_structural","block_structural","block_job_eligibility","cache_lookup_ttl",
    "cache_insert_evidence","admission_state","block_state","select_dispatch","policy_view",
    "send_start","receive_result","completion_state","completion_clock_diagnostics",
    "completion_evidence_commit","slice_poll_results","between_callbacks","serialisation")
CODES={s:i for i,s in enumerate(LABELS)}
KINDS=("other","_admission","_block","_receive")
HEADER=64
FILES=(".pause_gc.bin",".pause_spans.bin",".pause_steps.bin")
FORMATS=(struct.Struct("<QQqqq"),struct.Struct("<QQQQQ"),struct.Struct("<QQQ"))
MAGICS=(b"P2GCPA01",b"P2SPNA01",b"P2STPA01")


class Buffer:
    def __init__(self,path,fmt,magic,capacity):
        self.path,self.fmt,self.capacity,self.count=Path(path),fmt,capacity,0
        self.file=self.path.open("x+b");self.file.truncate(HEADER+capacity*fmt.size)
        self.memory=mmap.mmap(self.file.fileno(),0,access=mmap.ACCESS_WRITE)
        # Fault pages in during preparation, never on the first hot-path write.
        for offset in range(0,len(self.memory),mmap.PAGESIZE):self.memory[offset]=0
        struct.pack_into("<8sQQQ",self.memory,0,magic,capacity,0,0)
    def append(self,*values):
        i=self.count
        if i==self.capacity:
            struct.pack_into("<Q",self.memory,24,1);return None
        self.fmt.pack_into(self.memory,HEADER+i*self.fmt.size,*values)
        self.count=i+1
        # Publish only after the complete start/step record has been written.
        struct.pack_into("<Q",self.memory,16,self.count)
        return i
    def close(self):self.memory.close();self.file.close()


def labelled(name):
    code=CODES[name]
    def decorate(function):
        @wraps(function)
        def call(self,*args,**kwargs):
            monitor=getattr(self,"pause_monitor",None)
            if monitor is None:return function(self,*args,**kwargs)
            previous=monitor.step(code)
            try:return function(self,*args,**kwargs)
            finally:monitor.step(previous)
        return call
    return decorate


class PauseRecorder:
    def __init__(self,directory,*,gc_capacity=131072,span_capacity=1048576,step_capacity=8388608):
        from src.paper2.model.service_times import ROOT
        self.directory=Path(directory).resolve()
        if self.directory==ROOT or ROOT in self.directory.parents:raise ValueError("pause buffers must be outside checkout")
        self.directory.mkdir(parents=True,exist_ok=True)
        capacities=(gc_capacity,span_capacity,step_capacity)
        if any(isinstance(c,bool) or not isinstance(c,int) or c<1 for c in capacities):raise ValueError("positive pause capacities required")
        self.buffers=[]
        try:
            for n,f,m,c in zip(FILES,FORMATS,MAGICS,capacities):self.buffers.append(Buffer(self.directory/n,f,m,c))
        except BaseException:
            for b in self.buffers:b.close()
            raise
        self.gc,self.spans,self.steps=self.buffers
        self.active_gc=None;self.active_span=None;self.current_span=-1
        self.current_step=CODES["preparation"];self.registered=False;self.closed=False
        self._callback=self.callback
        self._gc_memory=self.gc.memory;self._gc_count=0;self._gc_capacity=gc_capacity
        self._gc_start=FORMATS[0].pack_into;self._gc_stop=struct.Struct("<Qqqq").pack_into
        self._gc_publish=struct.Struct("<Q").pack_into;self._gc_time=time.monotonic_ns

    def callback(self,phase,info):
        now=self._gc_time()
        if phase=="start":
            index=self._gc_count
            if index==self._gc_capacity:
                self._gc_publish(self._gc_memory,24,1);self.active_gc=None;return
            offset=HEADER+index*40
            self._gc_start(self._gc_memory,offset,now,0,info["generation"],-1,-1)
            self.active_gc=offset;self._gc_count=index+1
            self._gc_publish(self._gc_memory,16,index+1)
        elif phase=="stop" and self.active_gc is not None:
            self._gc_stop(self._gc_memory,self.active_gc+8,now,
                info["generation"],info["collected"],info["uncollectable"])
            self.active_gc=None

    def register(self):
        if self.registered:raise RuntimeError("pause callback already registered")
        self.original_thresholds=gc.get_threshold();self.original_enabled=gc.isenabled()
        struct.pack_into("<Q",self.gc.memory,32,time.monotonic_ns())
        self.registered=True;gc.callbacks.append(self._callback)

    def step(self,code,now=None):
        previous=self.current_step
        if self.closed:return previous
        self.current_step=code
        self.steps.append(time.monotonic_ns() if now is None else now,self.current_span+1,code)
        return previous

    def begin_span(self,identity,kind,now):
        code=KINDS.index(kind) if kind in KINDS else 0
        self.current_span=identity;self.active_span=self.spans.append(identity,now,0,code,0)
        self.step(CODES["handler:"+kind] if kind in KINDS[1:] else CODES["handler:other"],now)

    def end_span(self,now):
        if self.active_span is not None:
            offset=HEADER+self.active_span*self.spans.fmt.size
            struct.pack_into("<Q",self.spans.memory,offset+16,now)
            struct.pack_into("<Q",self.spans.memory,offset+32,1)
        self.active_span=None;self.current_span=-1
        self.step(CODES["between_callbacks"],now)

    def finish(self,*,partial=False):
        if self.closed:return
        if self.registered:
            gc.callbacks.remove(self._callback);self.registered=False
        struct.pack_into("<Q",self.gc.memory,40,time.monotonic_ns())
        for buffer in self.buffers:buffer.close()
        self.closed=True
        result=recover(self.directory,partial=partial)
        if not partial:
            for name in FILES:(self.directory/name).unlink()
        if result["overflow"]:raise BufferError("pause attribution preallocated buffer overflow; evidence retained")
        if result["error"] and not partial:raise ValueError("pause attribution evidence unavailable: "+result["error"])
        return result


def _read(path,fmt,magic):
    file=Path(path).open("rb");memory=None
    try:
        memory=mmap.mmap(file.fileno(),0,access=mmap.ACCESS_READ)
        actual,capacity,count,overflow=struct.unpack_from("<8sQQQ",memory)
        if actual!=magic or count>capacity or len(memory)!=HEADER+capacity*fmt.size:
            raise ValueError("invalid pause buffer header")
    except BaseException:
        if memory is not None:memory.close()
        file.close();raise
    return file,memory,count,bool(overflow)


def recover(directory,*,partial=True,write_missing=False):
    """Parent-side recovery after terminate/join; never reconstruct invented ends."""
    directory=Path(directory)
    present=[(directory/n).exists() for n in FILES]
    if not all(present):
        # Finish writes BOTH snapshots before unlinking buffers. A kill during
        # that unlink sequence must not replace good JSON with missing-header
        # error receipts. A capture that already stopped remains complete even
        # if the process later times out in cleanup.
        try:
            gdoc=json.loads((directory/"gc_pauses.json").read_bytes())
            ldoc=json.loads((directory/"long_spans.json").read_bytes())
            if (gdoc.get("schema")=="paper2-pause-attribution-v1" and
                    ldoc.get("schema")=="paper2-pause-attribution-v1" and
                    isinstance(gdoc.get("records"),list) and isinstance(ldoc.get("spans"),list) and
                    not gdoc.get("error") and not ldoc.get("error")):
                return dict(partial=gdoc["partial"],overflow=gdoc["overflow"],gc_records=len(gdoc["records"]),
                    long_spans=len(ldoc["spans"]),open_spans=len(ldoc["open_spans"]),error=None)
        except (OSError,ValueError,KeyError,TypeError):pass
    if not any(present) and not write_missing:return None
    opened=[]
    try:
        for n,f,m in zip(FILES,FORMATS,MAGICS):opened.append(_read(directory/n,f,m))
        _,gm,gn,go=opened[0];_,sm,sn,so=opened[1];_,tm,tn,to=opened[2]
        started,stopped=struct.unpack_from("<QQ",gm,32)
        pauses=[]
        for i in range(gn):
            a,b,g,c,u=FORMATS[0].unpack_from(gm,HEADER+i*FORMATS[0].size)
            complete=c>=0 and u>=0 and b>=a
            pauses.append(dict(start_ns=a,end_ns=b if complete else None,generation=g,
                collected=c if complete else None,uncollectable=u if complete else None,complete=complete))
        longs={};incomplete=[]
        for i in range(sn):
            identity,a,b,k,complete=FORMATS[1].unpack_from(sm,HEADER+i*FORMATS[1].size)
            row=dict(id=identity,kind=KINDS[k],start_ns=a,end_ns=b if complete else None,
                complete=bool(complete),steps=[])
            if not complete:incomplete.append(row);longs[identity]=row
            elif b-a>1_000_000:row["duration_ns"]=b-a;longs[identity]=row
        outside=[];last=None
        for i in range(tn):
            now,encoded,code=FORMATS[2].unpack_from(tm,HEADER+i*FORMATS[2].size)
            if last is not None:
                a,prior_id,prior_code=last
                end=now
                if prior_id and prior_id-1 in longs:
                    row=longs[prior_id-1];end=min(end,row["end_ns"]) if row["end_ns"] is not None else end
                    if end>a:row["steps"].append(dict(label=LABELS[prior_code],start_ns=a,end_ns=end))
                elif not prior_id and now-a>1_000_000:
                    outside.append(dict(label=LABELS[prior_code],start_ns=a,end_ns=now))
            last=(now,encoded,code)
        if last is not None:
            a,encoded,code=last
            if encoded and encoded-1 in longs:
                row=longs[encoded-1]
                if row["end_ns"] is not None and row["end_ns"]>a:
                    row["steps"].append(dict(label=LABELS[code],start_ns=a,end_ns=row["end_ns"]))
                elif row["end_ns"] is None:
                    row["active_step"]=dict(label=LABELS[code],start_ns=a,end_ns=None)
            elif not encoded and stopped and stopped-a>1_000_000:
                outside.append(dict(label=LABELS[code],start_ns=a,end_ns=stopped))
        common=dict(schema="paper2-pause-attribution-v1",partial=partial,overflow=go or so or to,
            capture_start_ns=started,capture_stop_ns=stopped or None,
            semantics="elapsed overlap only; labelled steps do not establish CPU/OS cause")
        gdoc=dict(common,records=pauses)
        ldoc=dict(common,span_records=sn,step_records=tn,
            spans=[r for r in longs.values() if r["complete"]],open_spans=incomplete,outside_steps=outside)
    except (ValueError,OSError,struct.error) as exc:
        # An extremely early kill can leave a not-yet-initialized header. Keep
        # explicit unavailable receipts rather than claiming zero observations.
        common=dict(schema="paper2-pause-attribution-v1",partial=True,overflow=False,error=str(exc))
        gdoc=dict(common,records=[]);ldoc=dict(common,spans=[],open_spans=[],outside_steps=[])
    finally:
        for file,memory,_,_ in opened:memory.close();file.close()
    write_json(directory/"gc_pauses.json",gdoc);write_json(directory/"long_spans.json",ldoc)
    return dict(partial=gdoc["partial"],overflow=gdoc["overflow"],gc_records=len(gdoc["records"]),
        long_spans=len(ldoc["spans"]),open_spans=len(ldoc["open_spans"]),error=gdoc.get("error"))


def _union(intervals):
    result=[]
    for a,b in sorted(intervals):
        if b<=a:continue
        if result and a<=result[-1][1]:result[-1]=(result[-1][0],max(b,result[-1][1]))
        else:result.append((a,b))
    return result


class Integral:
    def __init__(self,intervals):
        self.intervals=_union(intervals);self.starts=[a for a,b in self.intervals]
        self.ends=[b for a,b in self.intervals];self.prefix=[0]
        for a,b in self.intervals:self.prefix.append(self.prefix[-1]+b-a)
    def at(self,t):
        i=bisect.bisect_right(self.ends,t)
        return self.prefix[i]+(max(0,t-self.starts[i]) if i<len(self.starts) else 0)
    def overlap(self,a,b):return self.at(b)-self.at(a)


def summarise(gc_doc,long_doc,spans,gaps):
    """Time-weighted, disjoint GC-first partition; gaps are integer ns pairs."""
    generations={str(g):dict(count=0,total_ns=0,max_ns=0,collected=0,uncollectable=0,incomplete=0) for g in range(3)}
    gc_intervals=[]
    for row in gc_doc["records"]:
        group=generations.setdefault(str(row["generation"]),dict(count=0,total_ns=0,max_ns=0,collected=0,uncollectable=0,incomplete=0))
        if not row["complete"]:group["incomplete"]+=1;continue
        duration=row["end_ns"]-row["start_ns"];group["count"]+=1;group["total_ns"]+=duration
        group["max_ns"]=max(group["max_ns"],duration)
        group["collected"]+=row["collected"];group["uncollectable"]+=row["uncollectable"]
        gc_intervals.append((row["start_ns"],row["end_ns"]))
    identified=[(s["start_ns"],s["end_ns"]) for r in long_doc["spans"] for s in r["steps"] if s["label"]!="unknown"]
    identified += [(s["start_ns"],s["end_ns"]) for s in long_doc.get("outside_steps",[]) if s["label"]!="unknown"]
    # Short callbacks have an identified callback type; fine substeps are saved
    # for all >1 ms callbacks. Missing long-span labels stay unattributed.
    identified += [(s["start_ns"],s["end_ns"]) for s in spans
        if s["end_ns"]-s["start_ns"]<=1_000_000 and s.get("kind") in KINDS[1:]]
    gi=Integral(gc_intervals);ui=Integral(gc_intervals+identified)
    selected=[(a,b) for a,b in gaps if b-a>1_000_000]
    total=sum(b-a for a,b in selected);gc_ns=sum(gi.overlap(a,b) for a,b in selected)
    union_ns=sum(ui.overlap(a,b) for a,b in selected);step_ns=union_ns-gc_ns;unknown_ns=total-union_ns
    errors=[d["error"] for d in (gc_doc,long_doc) if d.get("error")]
    status=("UNAVAILABLE" if errors else "OVERFLOW" if gc_doc.get("overflow") or long_doc.get("overflow")
            else "PARTIAL" if gc_doc.get("partial") or long_doc.get("partial") else "RECORDED")
    return dict(status=status,evidence_errors=errors,
        gc_by_generation=generations,gaps_over_1ms=dict(count=len(selected),total_ns=total,
            gc_ns=gc_ns,identified_step_ns=step_ns,unattributed_ns=unknown_ns,
            gc_share=gc_ns/total if total else None,identified_step_share=step_ns/total if total else None,
            unattributed_share=unknown_ns/total if total else None),
        partition="elapsed time; union overlaps; GC first, then identified step excluding GC, then unattributed",
        caveat="Step coverage does not prove CPU execution or rule out OS preemption inside a step.")


def measure_callback_cost(*,batches=5,per_batch=5000):
    """Post-window calibration in the dispatcher process, never real GC rows.

    Two direct invocations represent one collection. Buffer preparation and
    cleanup are excluded; Python loop/call cost is included conservatively.
    No callback registration or GC control/explicit collection is performed.
    """
    rows=[];info=dict(generation=0,collected=0,uncollectable=0)
    with tempfile.TemporaryDirectory(prefix="paper2-callback-cost-") as td:
        recorder=PauseRecorder(td,gc_capacity=batches*per_batch+1,span_capacity=1,step_capacity=1)
        try:
            for batch in range(batches):
                begin=time.perf_counter_ns()
                for _ in range(per_batch):recorder.callback("start",info);recorder.callback("stop",info)
                elapsed=time.perf_counter_ns()-begin
                rows.append(dict(batch=batch,callback_invocations=2*per_batch,elapsed_ns=elapsed,
                    mean_per_call_ns=elapsed/(2*per_batch)))
        finally:
            for buffer in recorder.buffers:buffer.close()
            recorder.closed=True
    return dict(schema="paper2-callback-cost-v1",purpose="SYNTHETIC post-window callback calibration",
        platform=platform.platform(),machine=platform.machine(),python=platform.python_version(),
        batches=rows,mean_per_call_ns=sum(r["elapsed_ns"] for r in rows)/sum(r["callback_invocations"] for r in rows),
        median_batch_per_call_ns=statistics.median(r["mean_per_call_ns"] for r in rows),
        estimator="amortized wall time, two direct callback invocations per synthetic collection; no GC work",
        timing_assertion=False)


def estimate_overhead(gc_doc,cost,epoch_ns,finish_ns,dispatcher_active_ns):
    invocations=[]
    for r in gc_doc["records"]:
        invocations.append(r["start_ns"])
        if r["complete"]:invocations.append(r["end_ns"])
    count=sum(epoch_ns<=t<=finish_ns for t in invocations);per_call=cost["mean_per_call_ns"]
    estimate=count*per_call
    return dict(status="ESTIMATED FROM MEASURED CALLBACK COST",total_capture_invocations=len(invocations),
        timed_dispatcher_invocations=count,measured_per_call_ns=per_call,estimated_timed_callback_ns=estimate,
        total_dispatcher_time_ns=dispatcher_active_ns,
        estimated_dispatcher_share=estimate/dispatcher_active_ns if dispatcher_active_ns else None,
        denominator="unchanged prototype.dispatcher_active_ns (window elapsed minus recorded idle wait)",
        numerator="recorded start/complete-stop callback timestamps within epoch..finish x calibrated mean per-call cost",
        calibration=cost,caveat="microbenchmark estimate, not separately timed production callbacks; no timing pass/fail gate")
